//! Deposit tokens at the peer (ext-deposit-tokens.md): anonymous,
//! single-use tokens that pay for deposits in device mailboxes, drawn
//! against a library's allowance.
//!
//! A peer with the extension on (`FRASIL_EXTENSIONS`, which needs
//! `libraries` too) lists service 6, `deposit`, reads message types 40 to
//! 43 and `MailboxPut` key 7, takes `Authorization: Frasil-Token` on the
//! deposit route, and lists its keys in discovery as `deposit_keys`. Off,
//! it does none of these and reads and writes none of the records below.
//!
//! - **Keys** (2.2 Deposit keys, 3.9 Spent tokens and key rotation): at
//!   most two live, the issuing one first, one record each in the keys'
//!   shard ([`crate::shards::KEYS_SHARD`]), which every node reads and the
//!   node that keeps it rotates, on the upper estimate of its timeline. A
//!   key's seed is a secret: in memory only inside
//!   [`frasil_deposit_tokens::DepositKey`], which zeroizes it, never
//!   logged, and at rest sealed with XChaCha20-Poly1305 under the peer's
//!   sealing key ([`SealKey`]), its key ID as associated data. A retired
//!   key's record goes at once, and the records of the tokens spent under
//!   it at the next sweep of each mailbox shard.
//! - **Issuance** (3.4 Issuing): `TokenKeysGet` and `TokenRequest` on a
//!   space-traffic connection, checked by `frasil_deposit_tokens`'
//!   `check_request` over the libraries ([`crate::libraries::Draws`]). The
//!   batch is evaluated, then the library's window, the space's share and
//!   the grant used are written in one commit that expects the window as it
//!   was read and the grant unused, so that two nodes drawing against one
//!   library never both count from the same window; a commit those
//!   expectations refuse is checked again from the records.
//! - **Redemption** (3.7 Redeeming): a token deposit is decided by the node
//!   that keeps its mailbox. The token's record, in the mailbox shard its
//!   nonce names, is first reserved for the deposit, `SHA-256(address ||
//!   item)` and its mailbox, by a commit that expects it absent; then the
//!   item is kept under the token budget (crate `device_mail`); then the
//!   reservation becomes the spent record with the item's ID, or is
//!   released if the item was not kept. A deposit of the token while its
//!   reservation is undecided is answered `busy`. A reservation older than
//!   [`RESERVATION`] seconds of its shard's timeline is settled by the next
//!   deposit of its token: spent if its mailbox holds an item of its
//!   deposit, released otherwise.
//!
//! The settings are [`DepositSettings`].

pub mod records;
#[cfg(test)]
mod tests;

use crate::config::ConfigError;
use crate::records::{DEPOSIT_KEY, Records, SPENT};
use crate::state::{Core, Grant, Outgoing, Reason, lock, refused};
use crate::util::log;
use frasil_base::cbor::Map;
use frasil_base::time::{Reading, upper};
use frasil_crypto::primitives::{sha256, xchacha20poly1305_open, xchacha20poly1305_seal};
use frasil_deposit_tokens::rotation::LiveKey;
use frasil_deposit_tokens::{
    DepositKey, Draw, KeyId, KeyShard, Redemption, SpentRecord, SpentTokens, TokenClass,
    TokenDeposit, TokenKeys, TokenKeysGet, TokenRequest, TokenRoom, check_request, issue, redeem,
};
use frasil_events::EventId;
use frasil_libraries::LibraryId;
use frasil_store::{Commit, StoreError};
use frasil_transport::Closed;
use records::{KeyRecord, SEALED_BYTES, SpentState};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// How long, in seconds of its shard's timeline, a spent-token record
/// reserved for a deposit waits for that deposit before the next deposit
/// of its token settles it.
pub const RESERVATION: u64 = 60;

/// How long a node that does not keep the keys' shard uses the keys it
/// read before it reads them again.
const REREAD: Duration = Duration::from_secs(10);

/// The token budget (ext-deposit-tokens.md, 3.8 The token budget): what
/// every device mailbox holds together of items that tokens paid for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenBudget {
    /// Items, at most.
    pub items: u64,
    /// Bytes of items, at most.
    pub bytes: u64,
}

/// The key that seals deposit keys' seeds at rest: never printed, compared
/// in constant time, zeroized when dropped. The peer takes it from
/// `deposit.key` in its data directory, a file of 32 random bytes that
/// only its user reads, as it keeps `iroh.key`; in a cluster every node
/// derives it from the cluster key.
#[derive(Clone)]
pub struct SealKey(Zeroizing<[u8; 32]>);

impl SealKey {
    /// A sealing key of these bytes.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// The sealing key every node of a cluster derives from the cluster
    /// key.
    pub fn from_cluster_key(cluster_key: &[u8; 32]) -> Self {
        let derived = frasil_crypto::primitives::hkdf(
            Some(b"frasil-relay/deposit-seal/v1"),
            cluster_key,
            b"seal key",
        );
        Self(Zeroizing::new(*derived))
    }
}

impl core::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SealKey(..)")
    }
}

impl PartialEq for SealKey {
    fn eq(&self, other: &Self) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |differ, (a, b)| differ | (a ^ b))
            == 0
    }
}

impl Eq for SealKey {}

/// The operator's settings of deposit tokens (ext-deposit-tokens.md, 2.6
/// Settings).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositSettings {
    /// The `deposit_allowance` of a library that sets none: 64 tokens per
    /// window by default, 0 to 65,536.
    pub deposit_allowance: u64,
    /// The `space_share` of a library that sets none: 16 by default, 0 to
    /// `deposit_allowance`.
    pub space_share: u64,
    /// `token_period`, in seconds: 7 days by default, 1 to 30 days.
    pub token_period: u64,
    /// The token budget: 65,536 items and 256 MiB by default, split among
    /// the mailbox shards as the anonymous budget is.
    pub budget: TokenBudget,
    /// The tokens one source may have refused in a minute before its
    /// token deposits are refused `rate_limited`: 60 by default.
    pub refused_per_minute: usize,
    /// The key that seals the keys' seeds at rest; a fresh one each time
    /// the peer opens if none, so that keys sealed before do not open.
    pub seal: Option<SealKey>,
}

impl Default for DepositSettings {
    fn default() -> Self {
        Self {
            deposit_allowance: frasil_deposit_tokens::settings::DEPOSIT_ALLOWANCE,
            space_share: frasil_deposit_tokens::settings::SPACE_SHARE,
            token_period: frasil_deposit_tokens::settings::TOKEN_PERIOD,
            budget: TokenBudget {
                items: 65_536,
                bytes: 256 << 20,
            },
            refused_per_minute: 60,
            seal: None,
        }
    }
}

impl DepositSettings {
    /// The variables these settings read.
    pub const NAMES: [&'static str; 6] = [
        "FRASIL_DEPOSIT_ALLOWANCE",
        "FRASIL_SPACE_SHARE",
        "FRASIL_TOKEN_PERIOD",
        "FRASIL_TOKEN_BUDGET_ITEMS",
        "FRASIL_TOKEN_BUDGET_BYTES",
        "FRASIL_REFUSED_TOKENS_PER_MINUTE",
    ];

    /// Reads the settings from `FRASIL_*` variables:
    ///
    /// - `FRASIL_DEPOSIT_ALLOWANCE` and `FRASIL_SPACE_SHARE`: the default
    ///   `deposit_allowance` (0 to 65,536) and `space_share` (0 to the
    ///   allowance) of a library that sets none;
    /// - `FRASIL_TOKEN_PERIOD`: `token_period`, in seconds, 1 to 30 days;
    /// - `FRASIL_TOKEN_BUDGET_ITEMS` (at least 16) and
    ///   `FRASIL_TOKEN_BUDGET_BYTES` (at least 4 MiB): the token budget;
    /// - `FRASIL_REFUSED_TOKENS_PER_MINUTE` (at least 1): the refused
    ///   tokens a source may have in a minute.
    ///
    /// # Errors
    ///
    /// A variable that does not read, or is out of its range.
    pub fn from_lookup(get: &impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        use frasil_deposit_tokens::settings::{DEPOSIT_ALLOWANCE_RANGE, TOKEN_PERIOD_RANGE};
        let mut settings = Self::default();
        let count = |name: &str, low: u64, high: u64| -> Result<Option<u64>, ConfigError> {
            get(name)
                .map(|text| {
                    text.parse::<u64>()
                        .ok()
                        .filter(|n| (low..=high).contains(n))
                        .ok_or_else(|| {
                            ConfigError(format!("{name} is not a count from {low} to {high}"))
                        })
                })
                .transpose()
        };
        if let Some(n) = count("FRASIL_DEPOSIT_ALLOWANCE", 0, DEPOSIT_ALLOWANCE_RANGE.1)? {
            settings.deposit_allowance = n;
            settings.space_share = settings.space_share.min(n);
        }
        if let Some(n) = count("FRASIL_SPACE_SHARE", 0, settings.deposit_allowance)? {
            settings.space_share = n;
        }
        if let Some(n) = count(
            "FRASIL_TOKEN_PERIOD",
            TOKEN_PERIOD_RANGE.0,
            TOKEN_PERIOD_RANGE.1,
        )? {
            settings.token_period = n;
        }
        let min_items = crate::config::DeviceMailLimits::MIN_ITEMS as u64;
        let min_bytes = crate::config::DeviceMailLimits::MIN_BYTES as u64;
        if let Some(n) = count("FRASIL_TOKEN_BUDGET_ITEMS", min_items, u64::MAX)? {
            settings.budget.items = n;
        }
        if let Some(n) = count("FRASIL_TOKEN_BUDGET_BYTES", min_bytes, u64::MAX)? {
            settings.budget.bytes = n;
        }
        if let Some(n) = count("FRASIL_REFUSED_TOKENS_PER_MINUTE", 1, u32::MAX.into())? {
            settings.refused_per_minute = usize::try_from(n).unwrap_or(usize::MAX);
        }
        Ok(settings)
    }

    /// A library's allowance and share where it sets none.
    pub fn defaults(&self) -> frasil_deposit_tokens::settings::DepositSettings {
        frasil_deposit_tokens::settings::DepositSettings {
            deposit_allowance: self.deposit_allowance,
            space_share: self.space_share.min(self.deposit_allowance),
        }
    }
}

/// The peer's deposit keys in memory, and its sealing key.
pub(crate) struct Keys {
    seal: SealKey,
    held: Mutex<Held>,
}

#[derive(Default)]
struct Held {
    /// The keys, once read.
    shard: Option<KeyShard>,
    /// When they were read, at a node that does not keep their shard.
    read_at: Option<Instant>,
    /// Whether the node kept the keys' shard when it read them: a node
    /// that takes the shard up reads them again from the records, rather
    /// than rotate a copy it read as another node's reader.
    kept: bool,
    /// The live keys when the spent tokens of the mailbox shards this node
    /// keeps were last swept against them.
    swept: Option<Vec<KeyId>>,
}

impl Keys {
    /// No key read yet, under the settings' sealing key or a fresh one.
    pub(crate) fn new(settings: &DepositSettings) -> Self {
        let seal = settings.seal.clone().unwrap_or_else(|| {
            SealKey::new(
                frasil_crypto::random_bytes::<32>()
                    .map(|bytes| *bytes)
                    .unwrap_or([0; 32]),
            )
        });
        Self {
            seal,
            held: Mutex::new(Held::default()),
        }
    }
}

/// The associated data a seed is sealed under.
fn seal_aad(id: &KeyId) -> Vec<u8> {
    [&b"frasil-relay/deposit-seed/v1"[..], &id[..]].concat()
}

/// A key's seed sealed under `key`: a fresh 24-byte nonce, then the
/// ciphertext.
fn seal_seed(key: &SealKey, id: &KeyId, seed: &[u8; 32]) -> Result<Vec<u8>, StoreError> {
    let nonce = frasil_crypto::random_bytes::<24>()
        .map_err(|_| StoreError::new("no randomness to seal a deposit key"))?;
    let sealed = xchacha20poly1305_seal(&key.0, &nonce, &seal_aad(id), seed);
    Ok([&nonce[..], &sealed].concat())
}

/// A sealed seed opened, if it opens under `key`.
fn open_seed(key: &SealKey, id: &KeyId, sealed: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    if sealed.len() != SEALED_BYTES {
        return None;
    }
    let nonce: [u8; 24] = sealed[..24].try_into().ok()?;
    let seed = xchacha20poly1305_open(&key.0, &nonce, &seal_aad(id), &sealed[24..]).ok()?;
    let mut out = Zeroizing::new([0; 32]);
    out.copy_from_slice(seed.get(..32)?);
    Some(out)
}

/// A key's address: `q` and its key ID.
pub(crate) fn key_address(id: &KeyId) -> Vec<u8> {
    [&[DEPOSIT_KEY][..], &id[..]].concat()
}

/// A spent token's address: `p`, its nonce, then its key ID, so that its
/// shard is the mailbox shard its nonce names.
pub(crate) fn spent_address(nonce: &[u8; 32], id: &KeyId) -> Vec<u8> {
    [&[SPENT][..], &nonce[..], &id[..]].concat()
}

fn busy() -> Reason {
    ("busy".to_owned(), 503)
}

/// A class as a reason and its status.
pub(crate) fn reason(class: TokenClass) -> Reason {
    (
        class.code().unwrap_or("malformed").to_owned(),
        class.status().unwrap_or(400),
    )
}

/// What section 3.7, step 6, reads, as read before the checks: the token's
/// record. A reservation reads as spent by this very deposit, so that the
/// checks end there and the caller answers `busy` (section 3.10).
struct Known {
    state: Option<SpentState>,
    deposit: [u8; 32],
}

impl SpentTokens for Known {
    fn spent(&self, _: &KeyId, _: &[u8; 32]) -> Option<SpentRecord> {
        match self.state? {
            SpentState::Spent { deposit, item } => Some(SpentRecord { deposit, item }),
            SpentState::Reserved { .. } => Some(SpentRecord {
                deposit: self.deposit,
                item: [0; 16],
            }),
        }
    }
}

/// What section 3.7, step 7, reads, as found before the checks.
struct Room(bool);

impl TokenRoom for Room {
    fn room(&self, _: &[u8; 32], _: u64) -> bool {
        self.0
    }
}

/// The keys as a node uses them.
#[derive(Debug, Clone)]
pub(crate) struct Live {
    /// The live keys, the issuing one first.
    pub keys: KeyShard,
    /// Whether the first issues now: false at a node that does not keep the
    /// keys' shard while their keeper has not yet rotated them.
    pub issuing: bool,
}

impl Core {
    /// The reading of the keys' shard's timeline at the node's `now`.
    fn keys_now(&self, now: Reading) -> Reading {
        self.shard_now(crate::shards::KEYS_SHARD, now)
    }

    /// The reading of the timeline of the shard that keeps `address`.
    fn address_now(&self, address: &[u8], now: Reading) -> Reading {
        let Some(shards) = &self.shards else {
            return now;
        };
        crate::spaces::blocking_here(|| shards.reading(address, now)).unwrap_or(now)
    }

    /// Whether this node keeps the keys' shard, and so rotates the keys.
    fn keeps_keys(&self) -> bool {
        self.shards
            .as_ref()
            .is_none_or(|shards| shards.keeps_shard(crate::shards::KEYS_SHARD))
    }

    /// The live keys at rest, the issuing one first. A record that does not
    /// read or open is left out, and logged without its bytes. Blocking.
    fn read_keys(&self) -> Result<Vec<LiveKey>, StoreError> {
        let mut keys: Vec<(u8, LiveKey)> = Vec::new();
        for (address, bytes) in self.records.scan(&[DEPOSIT_KEY])? {
            let Some(id) = address.get(1..).and_then(|id| KeyId::try_from(id).ok()) else {
                log("a deposit key at an address of another length");
                continue;
            };
            let Some(record) = KeyRecord::decode(&bytes) else {
                log("a deposit key record that does not read");
                continue;
            };
            let Some(seed) = open_seed(&self.deposit_keys.seal, &id, &record.sealed) else {
                log("a deposit key that does not open under this peer's sealing key");
                continue;
            };
            let key = DepositKey::from_seed(&seed);
            if key.id() != &id {
                log("a deposit key whose seed gives another key ID");
                continue;
            }
            keys.push((
                record.role,
                LiveKey {
                    key,
                    began: record.began,
                },
            ));
        }
        keys.sort_by(|(a, x), (b, y)| a.cmp(b).then(y.began.timeline.cmp(&x.began.timeline)));
        Ok(keys.into_iter().map(|(_, live)| live).collect())
    }

    /// Writes the live keys, each with its role, and deletes every other
    /// key record. Blocking.
    fn write_keys(&self, keys: &KeyShard) -> Result<(), StoreError> {
        let mut puts = Vec::new();
        for entry_and_live in keys.entries().iter().zip(keys.live_keys()) {
            let (entry, live) = entry_and_live;
            let record = KeyRecord {
                sealed: seal_seed(&self.deposit_keys.seal, &entry.key_id, live.key.seed())?,
                role: u8::try_from(entry.role.code()).unwrap_or(2),
                began: live.began,
            };
            puts.push((key_address(&entry.key_id), record.encode()));
        }
        let deletes = self
            .records
            .scan(&[DEPOSIT_KEY])?
            .into_iter()
            .map(|(address, _)| address)
            .filter(|address| !puts.iter().any(|(put, _)| put == address))
            .collect();
        self.writer.commit_blocking(puts, deletes)
    }

    /// The keys as they hold at `now` (ext-deposit-tokens.md, 3.9 Spent
    /// tokens and key rotation): at the node that keeps their shard,
    /// rotated first, a key begun and one retired written before they are
    /// used; at another node, those it read lately, as the rule holds them.
    ///
    /// # Errors
    ///
    /// `busy` when the keys cannot be read, rotated or written.
    pub(crate) fn current_keys(&self, now: Reading) -> Result<Live, Reason> {
        let period = self.settings.deposit_tokens.token_period;
        let reading = self.keys_now(now);
        let keeper = self.keeps_keys();
        let mut held = lock(&self.deposit_keys.held);
        let stale = if keeper {
            !held.kept
        } else {
            held.read_at.is_none_or(|at| at.elapsed() >= REREAD)
        };
        if held.shard.is_none() || stale {
            let keys = crate::spaces::blocking_here(|| self.read_keys()).map_err(|error| {
                log(format_args!("the deposit keys were not read: {error}"));
                busy()
            })?;
            held.shard = Some(KeyShard::from_keys(period, keys).map_err(|_| busy())?);
            held.read_at = Some(Instant::now());
            held.kept = keeper;
        }
        let Some(shard) = held.shard.as_mut() else {
            return Err(busy());
        };
        if keeper {
            let before = shard.clone();
            let rotation = shard.advance(reading).map_err(|_| busy())?;
            if (rotation.begun.is_some() || !rotation.retired.is_empty())
                && let Err(error) = crate::spaces::blocking_here(|| self.write_keys(shard))
            {
                log(format_args!("the deposit keys were not kept: {error}"));
                *shard = before;
                return Err(busy());
            }
            return Ok(Live {
                keys: shard.clone(),
                issuing: shard.issuing().is_some(),
            });
        }
        let live: Vec<LiveKey> = shard
            .live_keys()
            .iter()
            .filter(|live| !upper(&live.began, &reading).at_least(period.saturating_mul(2)))
            .cloned()
            .collect();
        let issuing = shard.live_keys().first().is_some_and(|first| {
            !upper(&first.began, &reading).at_least(period)
                && live.first().is_some_and(|l| l.key.id() == first.key.id())
        });
        if !issuing {
            // Their keeper rotates them: read them again next time.
            held.read_at = None;
        }
        Ok(Live {
            keys: KeyShard::from_keys(period, live).map_err(|_| busy())?,
            issuing,
        })
    }

    /// Begins the first key, or rotates the keys, at the node that keeps
    /// their shard, as it takes the shard up: so that the other nodes, which
    /// answer `busy` until their keeper wrote a key, issue at once rather
    /// than at the keeper's first use or sweep. Whether a key is live after.
    /// Blocking.
    pub(crate) fn begin_deposit_keys(&self, now: Reading) -> bool {
        if !self.settings.extensions.deposit_tokens || !self.keeps_keys() {
            return false;
        }
        self.current_keys(now)
            .is_ok_and(|live| live.keys.issuing().is_some())
    }

    /// Deletes every key record and forgets the keys read, so that the
    /// next use begins a new key ([`crate::Peer::forget_deposit_keys`]).
    /// Blocking.
    pub(crate) fn forget_deposit_keys(&self) -> Result<(), StoreError> {
        let deletes = self
            .records
            .scan(&[DEPOSIT_KEY])?
            .into_iter()
            .map(|(address, _)| address)
            .collect();
        self.writer.commit_blocking(Vec::new(), deletes)?;
        *lock(&self.deposit_keys.held) = Held::default();
        Ok(())
    }

    /// The spent-token records this node keeps, each with its key ID.
    /// Blocking.
    pub(crate) fn spent_records(&self) -> Result<Vec<KeyId>, StoreError> {
        let found = match &self.shards {
            Some(shards) => shards.scan_kept_mailboxes(&[SPENT])?,
            None => self.records.scan(&[SPENT])?,
        };
        Ok(found
            .into_iter()
            .filter_map(|(address, _)| KeyId::try_from(address.get(33..)?).ok())
            .collect())
    }

    /// At a node that does not keep the keys' shard, forgets the keys it
    /// read, so that they are read again: true then, false at their
    /// keeper, whose keys are the records'.
    fn reread_keys(&self) -> bool {
        if self.keeps_keys() {
            return false;
        }
        let mut held = lock(&self.deposit_keys.held);
        let fresh = held
            .read_at
            .is_some_and(|at| at.elapsed() < Duration::from_secs(1));
        held.read_at = None;
        !fresh
    }

    /// The live keys as `TokenKeys` and discovery list them.
    pub(crate) fn deposit_key_entries(
        &self,
        now: Reading,
    ) -> Vec<frasil_deposit_tokens::messages::KeyEntry> {
        self.current_keys(now)
            .map(|live| live.keys.entries())
            .unwrap_or_default()
    }

    /// `TokenKeysGet` (ext-deposit-tokens.md, 3.2 Learning a peer's keys):
    /// `TokenKeys`, or `busy` while the keys cannot be read.
    ///
    /// # Errors
    ///
    /// `Malformed`, which closes the connection, for a message that does
    /// not read.
    pub(crate) fn token_keys(&self, map: &Map, now: Reading) -> Result<Outgoing, Closed> {
        let get =
            TokenKeysGet::read(map).map_err(|_| Closed::of(frasil_base::ErrorClass::Malformed))?;
        let entries = self.deposit_key_entries(now);
        if entries.is_empty() {
            return Ok(refused(get.request, "busy"));
        }
        Ok(Outgoing::Control(
            TokenKeys {
                request: get.request,
                keys: entries,
            }
            .encode(),
        ))
    }

    /// A ledger's `tokens_drawn` as it stands now: 0 once its window has
    /// passed (ext-deposit-tokens.md, 2.6 Settings), on the lower estimate
    /// of the library's timeline.
    pub(crate) fn window_passed(
        &self,
        mut ledger: crate::libraries::Ledger,
    ) -> crate::libraries::Ledger {
        if let Some(deposit) = &mut ledger.deposit
            && let Some(start) = deposit.window_start
        {
            let now = self.window_now(&ledger.library, self.clock.now()).timeline;
            if now.saturating_sub(start) >= frasil_deposit_tokens::settings::ALLOWANCE_WINDOW {
                deposit.tokens_drawn = 0;
            }
        }
        ledger
    }

    /// The library a `TokenRequest` draws against, as far as it reads:
    /// the grant's, or the space's.
    fn draw_library(&self, map: &Map) -> Option<LibraryId> {
        match TokenRequest::read(map).ok()?.draw {
            Draw::Grant(grant) => {
                frasil_libraries::ticket::SignedTicket::decode_with_grants(&grant, true)
                    .ok()
                    .map(|signed| signed.ticket.library)
            }
            Draw::Space(space) => lock(&self.libraries)
                .attachment(&EventId(space))
                .map(|attachment| attachment.library.clone()),
        }
    }

    /// The reading of a library's timeline: the timeline of the shard that
    /// keeps its window (crate `shards`).
    pub(crate) fn window_now(&self, library: &LibraryId, now: Reading) -> Reading {
        let address = Records::library_address(
            crate::libraries::records::WINDOW,
            library.as_str().as_bytes(),
        );
        self.address_now(&address, now)
    }

    /// Reads a library's settings, its window and a grant again from the
    /// records, after a commit their expectations refused. Blocking.
    fn reread_draw(&self, library: &LibraryId, grant: Option<&[u8; 16]>) {
        use crate::libraries::records::{GRANT, LIBRARY, WINDOW, grant_key};
        let window_key = library.as_str().as_bytes().to_vec();
        match self
            .records
            .get(&Records::library_address(LIBRARY, &window_key))
        {
            Ok(Some(bytes)) => {
                if let Some(record) = crate::libraries::Record::decode(LIBRARY, &window_key, &bytes)
                {
                    lock(&self.libraries).learn(record);
                }
            }
            Ok(None) => {}
            Err(error) => log(format_args!("a library's settings were not read: {error}")),
        }
        let window = self
            .records
            .get(&Records::library_address(WINDOW, &window_key));
        let grant = grant.map(|id| {
            let key = grant_key(library, id);
            (
                key.clone(),
                self.records.get(&Records::library_address(GRANT, &key)),
            )
        });
        let mut libraries = lock(&self.libraries);
        match window {
            Ok(Some(bytes)) => {
                if let Some(record) = crate::libraries::Record::decode(WINDOW, &window_key, &bytes)
                {
                    libraries.learn(record);
                }
            }
            Ok(None) => libraries.drop_window(library),
            Err(error) => log(format_args!("a library's window was not read: {error}")),
        }
        if let Some((key, Ok(Some(bytes)))) = grant
            && let Some(record) = crate::libraries::Record::decode(GRANT, &key, &bytes)
        {
            libraries.learn(record);
        }
    }

    /// `TokenRequest` (ext-deposit-tokens.md, 3.4 Issuing), in order:
    /// `TokenIssue`, or `Refused` with the class of the first step that
    /// refuses. The batch is counted in the same commit that marks a
    /// grant used; a grant refused at any step stays unused.
    ///
    /// # Errors
    ///
    /// `Malformed`, which closes the connection, for a request whose
    /// number does not read.
    pub(crate) async fn token_request(
        &self,
        grants: &BTreeMap<EventId, Grant>,
        map: &Map,
        now: Reading,
    ) -> Result<Outgoing, Closed> {
        let Some(request) = map.get(&1).and_then(|value| value.as_unsigned().ok()) else {
            return Err(Closed::of(frasil_base::ErrorClass::Malformed));
        };
        let refuse = |class: TokenClass| refused(request, class.code().unwrap_or("malformed"));
        let library = self.draw_library(map);
        let reading = library
            .as_ref()
            .map_or(now, |library| self.window_now(library, now))
            .timeline;
        let store_right = |space: &[u8; 32]| {
            grants
                .get(&EventId(*space))
                .is_some_and(|grant| grant.rights.store)
        };
        for _ in 0..3 {
            // The keys are read again on each try, so that a rotation that
            // happens meanwhile is seen.
            let Ok(live) = self.current_keys(now) else {
                return Ok(refuse(TokenClass::Busy));
            };
            // The checks, and the window and the library's settings they
            // read, from one view of the libraries: the commit expects
            // exactly what the checks counted from, so that a draw counted
            // from a window or under an allowance that changed since, here
            // or at another node, is checked again (section 3.10: one
            // count per library).
            let (approved, read) = {
                let libraries = lock(&self.libraries);
                let approved = check_request(
                    map,
                    store_right,
                    now.wall,
                    reading,
                    &self.settings.libraries.issuers,
                    &live.keys,
                    &libraries.draws(now.wall),
                );
                let read = library.as_ref().map(|library| {
                    let window = libraries.window(library).map(|window| {
                        crate::libraries::Record::Window(library.clone(), window.clone())
                            .encode()
                            .2
                    });
                    let settings = libraries.library(library).map(|settings| {
                        crate::libraries::Record::Library(library.clone(), *settings)
                            .encode()
                            .2
                    });
                    (library.clone(), window, settings)
                });
                (approved, read)
            };
            let approved = match approved {
                Ok(approved) => approved,
                // A node whose copy of the keys may be behind their
                // keeper's reads them again before it refuses a key.
                Err(TokenClass::TokenExpired) if self.reread_keys() => continue,
                Err(class) => return Ok(refuse(class)),
            };
            // A node whose copy of the keys is behind their keeper's.
            let Some(key) = live.keys.issuing().filter(|_| live.issuing) else {
                return Ok(refuse(TokenClass::Busy));
            };
            let issued = match issue(&approved, key) {
                Ok(issued) => issued,
                Err(class) => return Ok(refuse(class)),
            };
            let (expected, settings) = match read {
                Some((library, window, settings)) if library == issued.library => {
                    (window, settings)
                }
                // The library the checks found is the one the request names.
                _ => return Ok(refuse(TokenClass::Busy)),
            };
            let puts = lock(&self.libraries).drawn(&issued);
            let mut commit = Commit::new(
                puts.iter()
                    .map(|record| {
                        let (table, key, bytes) = record.encode();
                        (Records::library_address(table, &key), bytes)
                    })
                    .collect(),
                Vec::new(),
            );
            for (address, _) in commit.puts.clone() {
                let expect = if address[1] == crate::libraries::records::WINDOW {
                    expected.clone()
                } else {
                    None
                };
                commit = commit.expecting(&address, expect.as_deref());
            }
            let settings_address = Records::library_address(
                crate::libraries::records::LIBRARY,
                issued.library.as_str().as_bytes(),
            );
            if !commit
                .puts
                .iter()
                .any(|(address, _)| *address == settings_address)
            {
                commit = commit.expecting(&settings_address, settings.as_deref());
            }
            match self.writer.submit(commit).await {
                Ok(true) => {
                    let mut libraries = lock(&self.libraries);
                    for record in puts {
                        libraries.learn(record);
                    }
                    return Ok(Outgoing::Control(issued.answer.encode()));
                }
                Ok(false) => {
                    let grant = issued.grant.map(|(id, _)| id);
                    crate::spaces::blocking_here(|| {
                        self.reread_draw(&issued.library, grant.as_ref());
                    });
                }
                Err(error) => {
                    log(format_args!("a batch's count was not kept: {error}"));
                    return Ok(refuse(TokenClass::Busy));
                }
            }
        }
        Ok(refuse(TokenClass::Busy))
    }

    /// A spent token's record. Blocking.
    fn spent_state(&self, address: &[u8]) -> Result<Option<SpentState>, TokenClass> {
        match crate::spaces::blocking_here(|| self.records.get(address)) {
            Ok(None) => Ok(None),
            Ok(Some(bytes)) => match SpentState::decode(&bytes) {
                Some(state) => Ok(Some(state)),
                None => {
                    log("a spent token's record that does not read");
                    Err(TokenClass::Busy)
                }
            },
            Err(error) => {
                log(format_args!("a spent token's record was not read: {error}"));
                Err(TokenClass::Busy)
            }
        }
    }

    /// Settles a reservation older than [`RESERVATION`]: spent, with its
    /// item's ID, if its mailbox holds an item of its deposit; released
    /// otherwise. Returns the record as it then stands.
    async fn settle(
        &self,
        spent: &[u8],
        reserved: SpentState,
        now: Reading,
    ) -> Result<Option<SpentState>, TokenClass> {
        let SpentState::Reserved {
            deposit,
            address,
            at,
        } = reserved
        else {
            return Ok(Some(reserved));
        };
        if self.address_now(spent, now).timeline.saturating_sub(at) < RESERVATION {
            return Ok(Some(reserved));
        }
        let mut prefix = vec![crate::records::MAILBOX];
        prefix.extend_from_slice(&address);
        let found = crate::spaces::blocking_here(|| self.records.scan(&prefix))
            .map_err(|_| TokenClass::Busy)?;
        let item = found.into_iter().find_map(|(at, record)| {
            let (_, item) = Records::read_mailbox_record(&record)?;
            (sha256(&[&address, &item]) == deposit)
                .then(|| at.get(33..).and_then(|id| <[u8; 16]>::try_from(id).ok()))
                .flatten()
        });
        let settled = item.map(|item| SpentState::Spent { deposit, item });
        let commit = match settled {
            Some(state) => Commit::new(vec![(spent.to_vec(), state.encode())], Vec::new()),
            None => Commit::new(Vec::new(), vec![spent.to_vec()]),
        }
        .expecting(spent, Some(&reserved.encode()));
        match self.writer.submit(commit).await {
            Ok(true) => Ok(settled),
            Ok(false) => self.spent_state(spent),
            Err(_) => Err(TokenClass::Busy),
        }
    }

    /// A token deposit at the node that keeps its mailbox
    /// (ext-deposit-tokens.md, 3.7 Redeeming, steps 2 to 7, and 3.10 In a
    /// cluster): the item's ID, the first deposit's for a repeat.
    ///
    /// # Errors
    ///
    /// The class of the first step that refuses; `Busy` while the token's
    /// record is undecided, or when the keys or records cannot be read.
    pub(crate) async fn token_put(
        &self,
        deposit: &TokenDeposit,
        now: Reading,
    ) -> Result<[u8; 16], TokenClass> {
        let mut live = self.current_keys(now).map_err(|_| TokenClass::Busy)?;
        // A node whose copy of the keys may be behind their keeper's reads
        // them again before it refuses a key as not live.
        if live.keys.live(&deposit.token.key_id()).is_none() && self.reread_keys() {
            live = self.current_keys(now).map_err(|_| TokenClass::Busy)?;
        }
        let token = &deposit.token;
        let spent = spent_address(&token.nonce(), &token.key_id());
        let digest = deposit.digest();
        for _ in 0..2 {
            let mut state = self.spent_state(&spent)?;
            if let Some(reserved @ SpentState::Reserved { .. }) = state {
                state = self.settle(&spent, reserved, now).await?;
            }
            let room = self.device_room(&deposit.address, deposit.item.len(), now);
            let known = Known {
                state,
                deposit: digest,
            };
            match redeem(deposit, &live.keys, &known, &Room(room))? {
                Redemption::Repeat { item } => {
                    return match state {
                        Some(SpentState::Reserved { .. }) => Err(TokenClass::Busy),
                        _ => Ok(item),
                    };
                }
                Redemption::Keep { .. } => {}
            }
            let reserved = SpentState::Reserved {
                deposit: digest,
                address: deposit.address,
                at: self.address_now(&spent, now).timeline,
            }
            .encode();
            let reserve = Commit::new(vec![(spent.clone(), reserved.clone())], Vec::new())
                .expecting(&spent, None);
            match self.writer.submit(reserve).await {
                Ok(true) => {}
                // Another deposit of the token came first: read it again.
                Ok(false) => continue,
                Err(_) => return Err(TokenClass::Busy),
            }
            let kept = self
                .device_put(&deposit.address, &deposit.item, true, now)
                .await;
            let (commit, answer) = match kept {
                Ok(item) => (
                    Commit::new(
                        vec![(
                            spent.clone(),
                            SpentState::Spent {
                                deposit: digest,
                                item,
                            }
                            .encode(),
                        )],
                        Vec::new(),
                    ),
                    Ok(item),
                ),
                Err(_) => (
                    Commit::new(Vec::new(), vec![spent.clone()]),
                    Err(TokenClass::Busy),
                ),
            };
            match self
                .writer
                .submit(commit.expecting(&spent, Some(&reserved)))
                .await
            {
                Ok(true) => {}
                Ok(false) => log("a token's reservation was settled before its deposit ended"),
                Err(error) => log(format_args!("a token's record was not settled: {error}")),
            }
            return answer;
        }
        Err(TokenClass::Busy)
    }

    /// The sweep of deposit tokens: the keys rotated where this node keeps
    /// them, and the records of tokens spent under keys no longer live
    /// deleted from the mailbox shards this node keeps, once each time the
    /// live keys change (ext-deposit-tokens.md, 3.9 Spent tokens and key
    /// rotation).
    pub(crate) async fn sweep_deposit_tokens(&self, now: Reading) {
        let Ok(live) = self.current_keys(now) else {
            return;
        };
        let ids: Vec<KeyId> = live
            .keys
            .live_keys()
            .iter()
            .map(|live| *live.key.id())
            .collect();
        if lock(&self.deposit_keys.held).swept.as_ref() == Some(&ids) {
            return;
        }
        let found = crate::spaces::blocking_here(|| match &self.shards {
            Some(shards) => shards.scan_kept_mailboxes(&[SPENT]),
            None => self.records.scan(&[SPENT]),
        });
        let found = match found {
            Ok(found) => found,
            Err(error) => {
                log(format_args!("the spent tokens were not read: {error}"));
                return;
            }
        };
        let deletes: Vec<Vec<u8>> = found
            .into_iter()
            .map(|(address, _)| address)
            .filter(|address| {
                address
                    .get(33..)
                    .and_then(|id| KeyId::try_from(id).ok())
                    .is_none_or(|id| !ids.contains(&id))
            })
            .collect();
        if !deletes.is_empty()
            && let Err(error) = self.writer.commit(Vec::new(), deletes).await
        {
            log(format_args!(
                "the spent tokens of retired keys were not deleted: {error}"
            ));
            return;
        }
        lock(&self.deposit_keys.held).swept = Some(ids);
    }
}
