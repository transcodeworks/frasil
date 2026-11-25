//! Libraries at the peer (ext-libraries.md): what an operator bills and
//! limits, the tickets by which a writer's device attaches a space to a
//! library, and the ledger the peer keeps per library.
//!
//! A peer with the extension on (`FRASIL_EXTENSIONS`) lists service 5,
//! `library`, reads message type 21, `LibraryAttach`, and stores into a
//! space only while the space is attached to an open library.
//!
//! - [`Libraries`] is what the peer keeps (section 2.5) and the rules that
//!   read it: attaching by create, import and move (section 3.3), the
//!   checks before a store (section 3.4), detaching and deleting (section
//!   3.5), the ledgers (sections 2.5 and 3.6), and the holds by which a
//!   space uses an object another space of its library stores (sections
//!   3.7 to 3.9). It reads no clock and does no IO: the peer gives it each
//!   space's usage and the readings.
//! - The peer's procedures around it, under its one lock, are in `core`;
//!   what the operator and the issuer read and set is on [`crate::Peer`].
//! - [`records`] is its records at rest.
//!
//! Tickets themselves, `LibraryAttach` and `check_ticket` are
//! `frasil-libraries`'.

pub mod bundle;
mod core;
pub(crate) mod handover;
pub(crate) mod moves;
pub mod operator;
mod peer;
pub mod records;
#[cfg(test)]
mod tests;

use crate::config::ConfigError;
use frasil_base::time::{Reading, lower};
use frasil_deposit_tokens::settings::DepositSettings;
use frasil_events::EventId;
use frasil_libraries::settings::{
    DETACHED_GRACE_DEFAULT, ERASURE_TIMEOUT_DEFAULT, TICKET_SKEW, detached_grace_allowed,
    erasure_timeout_allowed,
};
use frasil_libraries::{
    LibraryClass, LibraryId, LibraryState, PeerRecords, Purpose, Ticket, TicketId, TrustedIssuers,
    check_ticket,
};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) use core::usage_record;
pub use operator::{IssuedTicket, OperatorIssuer, TicketRequest};
pub use records::{Attachment, Copy, Hold, Library, Record, UsageRecord, Window};

/// Where a library's copies keep their pieces among the object pieces
/// (ext-libraries.md, 3.8 Keeping a held object): 32 bytes in place of a
/// space ID, from a hash of the library ID, so that no space's pieces share
/// their keys.
pub fn copy_home(library: &LibraryId) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"frasil-relay/copy/v1\0");
    hash.update(library.as_str().as_bytes());
    hash.finalize().into()
}

/// The peer's settings of this extension (ext-libraries.md, 2.4 Settings),
/// which the operator sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibrarySettings {
    /// The issuers the peer trusts: at most 16 Ed25519 keys; none by
    /// default, so that no ticket passes. With [`Self::operator`], its key
    /// alone ([`Self::use_operator`]).
    pub issuers: TrustedIssuers,
    /// The operator's own issuer, when the peer trusts no other: it signs
    /// the tickets `frasil-relay ticket` prints, and names the default
    /// library (crate `operator`). [`crate::run`] sets it from `issuer.key`
    /// or the cluster key.
    pub operator: Option<OperatorIssuer>,
    /// `detached_grace`, in seconds: 30 days by default, 1 to 365 days.
    pub detached_grace: u64,
    /// The operator's default quota for each kind of library ID, the text
    /// before its first `:`, such as `personal`. A library of another kind
    /// has no quota until one is set.
    pub default_quotas: BTreeMap<String, u64>,
    /// The operator's own hosting: a library that a create without a
    /// ticket attaches its space to, while the peer's hosting is open
    /// ([`crate::Hosting::Open`]); none by default, so that a genesis
    /// stored without a `LibraryAttach` is `no_library`. No library is
    /// open unless the operator names it. An import is never taken
    /// without a ticket.
    pub open_library: Option<LibraryId>,
    /// The operator's bearer token for its routes: usage, settings and
    /// hand-over, under `/frasil/p1/libraries/{library}/`; none by default,
    /// so that they refuse every request.
    pub operator_token: Option<OperatorToken>,
}

impl Default for LibrarySettings {
    fn default() -> Self {
        Self {
            issuers: TrustedIssuers::default(),
            operator: None,
            detached_grace: DETACHED_GRACE_DEFAULT,
            default_quotas: BTreeMap::new(),
            open_library: None,
            operator_token: None,
        }
    }
}

/// The operator's bearer token: never printed, compared in constant time.
#[derive(Clone, PartialEq, Eq)]
pub struct OperatorToken(String);

impl std::fmt::Debug for OperatorToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OperatorToken(..)")
    }
}

impl OperatorToken {
    /// A token of at least 16 bytes.
    ///
    /// # Errors
    ///
    /// A token shorter than 16 bytes.
    pub fn new(token: &str) -> Result<Self, ConfigError> {
        if token.len() < 16 {
            return Err(ConfigError(
                "FRASIL_OPERATOR_TOKEN is shorter than 16 bytes".into(),
            ));
        }
        Ok(Self(token.to_owned()))
    }

    /// Whether `presented` is the token, compared in constant time over
    /// the token's length.
    pub fn matches(&self, presented: &str) -> bool {
        let (a, b) = (self.0.as_bytes(), presented.as_bytes());
        let mut differ = u8::from(a.len() != b.len());
        for (index, byte) in a.iter().enumerate() {
            differ |= byte ^ b.get(index).copied().unwrap_or(0);
        }
        differ == 0
    }
}

/// A library's usage as the usage route hands it over (ext-libraries.md,
/// 3.6 Usage and refusals).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibraryUsage {
    /// `used_bytes`: the usage of its spaces.
    pub used_bytes: u64,
    /// Its quota, if it has one.
    pub quota_bytes: Option<u64>,
    /// How many spaces it holds.
    pub spaces: u64,
}

/// A library's usage at the peer; `None` for a library it does not know.
pub(crate) async fn library_usage(
    shared: &crate::Shared,
    library: &LibraryId,
) -> Option<LibraryUsage> {
    let ledger = shared.core.ledger(library).await?;
    Some(LibraryUsage {
        used_bytes: ledger.used_bytes(),
        quota_bytes: ledger.settings.quota,
        spaces: ledger.spaces.len() as u64,
    })
}

/// The settings route (ext-libraries.md, 2.4 Settings, and 3.6 Usage and
/// refusals): a library's settings read, or changed by `change`, the
/// route's JSON body, and written before the answer. Answers the HTTP
/// status and the JSON body: `{"library", "quota_bytes",
/// "erasure_timeout", "state", "open_until", "open"}`, where `state` is the
/// setting and `open` whether the library takes stores at the peer's wall
/// clock now; `not_found` (404) for a read of a library the peer does not
/// know; `malformed` (400) for a change that does not read or is out of
/// range; `handing_over` (409) for a change while the library is being
/// handed over; `not_kept` (503) when the record could not be written.
pub(crate) fn library_settings(
    shared: &crate::Shared,
    library: &LibraryId,
    change: Option<&[u8]>,
) -> (u16, Vec<u8>) {
    let fail = |status: u16, code: &str| {
        (
            status,
            serde_json::to_vec(&serde_json::json!({ "code": code })).unwrap_or_default(),
        )
    };
    let deposit = shared.settings.extensions.deposit_tokens;
    let update = match change.map(|change| read_update(change, deposit)) {
        Some(Some(update)) => Some(update),
        Some(None) => return fail(400, "malformed"),
        None => None,
    };
    let core = &shared.core;
    let settings = {
        let mut libraries = crate::state::lock(&core.libraries);
        if let Some(update) = update {
            if libraries.handing().contains(library) {
                return fail(409, "handing_over");
            }
            let Ok(record) = libraries.update(library, update) else {
                return fail(400, "malformed");
            };
            if core
                .commit_libraries_blocking(&mut libraries, vec![record], Vec::new())
                .is_err()
            {
                return fail(503, "not_kept");
            }
        }
        libraries
            .library(library)
            .copied()
            .map(|settings| (settings, libraries.deposit_settings(library)))
    };
    let Some((settings, tokens)) = settings else {
        return fail(404, "not_found");
    };
    let wall = shared.clock.now().wall;
    let mut body = serde_json::json!({
        "library": library.as_str(),
        "quota_bytes": settings.quota,
        "erasure_timeout": settings.erasure_timeout,
        "state": settings.state.name(),
        "open_until": settings.open_until,
        "open": settings.state_at(wall) == LibraryState::Open,
    });
    // ext-deposit-tokens.md, 2.6 Settings: the values that hold, the
    // operator's defaults where the library sets none.
    if let Some(tokens) = tokens {
        body["deposit_allowance"] = tokens.deposit_allowance.into();
        body["space_share"] = tokens.space_share.into();
    }
    (200, serde_json::to_vec(&body).unwrap_or_default())
}

/// The settings route's JSON body: an object of any of `quota_bytes` (bytes
/// or `null`), `erasure_timeout` (seconds), `state` (`"open"` or
/// `"suspended"`) and `open_until` (seconds since 1970, or `null`), and, with
/// ext-deposit-tokens on (`deposit`), `deposit_allowance` and `space_share`
/// (tokens per window, or `null` for the operator's default), and no other
/// field. `None` for a body that does not read. The ranges are
/// [`Libraries::update`]'s to check.
pub(crate) fn read_update(body: &[u8], deposit: bool) -> Option<LibraryUpdate> {
    use serde_json::Value;
    let Value::Object(fields) = serde_json::from_slice::<Value>(body).ok()? else {
        return None;
    };
    let count_or_none = |value: &Value| match value {
        Value::Null => Some(None),
        value => value.as_u64().map(Some),
    };
    let mut update = LibraryUpdate::default();
    for (name, value) in &fields {
        match name.as_str() {
            "quota_bytes" => update.quota = Some(count_or_none(value)?),
            "erasure_timeout" => update.erasure_timeout = Some(value.as_u64()?),
            "state" => update.state = Some(LibraryState::from_name(value.as_str()?)?),
            "open_until" => update.open_until = Some(count_or_none(value)?),
            "deposit_allowance" if deposit => {
                update.deposit_allowance = Some(count_or_none(value)?);
            }
            "space_share" if deposit => update.space_share = Some(count_or_none(value)?),
            _ => return None,
        }
    }
    Some(update)
}

impl LibrarySettings {
    /// Reads the settings from `FRASIL_*` variables:
    ///
    /// - `FRASIL_LIBRARY_ISSUERS`: the trusted issuers' Ed25519 keys, in
    ///   lowercase hex, separated by white space;
    /// - `FRASIL_DETACHED_GRACE`: `detached_grace`, in seconds;
    /// - `FRASIL_LIBRARY_QUOTAS`: `kind=bytes` pairs, separated by white
    ///   space, such as `personal=10000000000`;
    /// - `FRASIL_OPEN_LIBRARY`: the library a create without a ticket
    ///   attaches its space to;
    /// - `FRASIL_OPERATOR_TOKEN`: the operator's bearer token for the
    ///   usage, settings and hand-over routes, at least 16 bytes.
    ///
    /// # Errors
    ///
    /// A variable that does not read, or is out of its range.
    pub fn from_lookup(get: &impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let mut settings = Self::default();
        if let Some(text) = get("FRASIL_LIBRARY_ISSUERS") {
            let keys = text
                .split_whitespace()
                .map(|key| {
                    crate::util::unhex::<32>(key).ok_or_else(|| {
                        ConfigError("FRASIL_LIBRARY_ISSUERS holds a key that is not hex".into())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            settings.issuers = TrustedIssuers::new(keys).map_err(|_| {
                ConfigError("FRASIL_LIBRARY_ISSUERS: at most 16 valid Ed25519 keys".into())
            })?;
        }
        if let Some(text) = get("FRASIL_DETACHED_GRACE") {
            settings.detached_grace = text
                .parse()
                .ok()
                .filter(|&seconds| detached_grace_allowed(seconds))
                .ok_or_else(|| ConfigError("FRASIL_DETACHED_GRACE is not 1 to 365 days".into()))?;
        }
        if let Some(text) = get("FRASIL_LIBRARY_QUOTAS") {
            for pair in text.split_whitespace() {
                let (kind, bytes) = pair
                    .split_once('=')
                    .filter(|(kind, _)| !kind.is_empty() && !kind.contains(':'))
                    .ok_or_else(|| {
                        ConfigError(
                            "FRASIL_LIBRARY_QUOTAS holds a pair that is not kind=bytes".into(),
                        )
                    })?;
                let bytes = bytes.parse().map_err(|_| {
                    ConfigError("FRASIL_LIBRARY_QUOTAS holds a quota that is not a count".into())
                })?;
                settings.default_quotas.insert(kind.to_owned(), bytes);
            }
        }
        if let Some(text) = get("FRASIL_OPEN_LIBRARY") {
            settings.open_library = Some(
                LibraryId::new(&text)
                    .map_err(|_| ConfigError("FRASIL_OPEN_LIBRARY is not a library ID".into()))?,
            );
        }
        if let Some(text) = get("FRASIL_OPERATOR_TOKEN") {
            settings.operator_token = Some(OperatorToken::new(&text)?);
        }
        Ok(settings)
    }

    /// Trusts the operator's own issuer, and it alone.
    pub fn use_operator(&mut self, issuer: OperatorIssuer) {
        self.issuers =
            TrustedIssuers::new([*issuer.public()]).expect("one key that passes ed25519_valid");
        self.operator = Some(issuer);
    }

    /// The operator's default library, when it trusts its own issuer.
    pub fn default_library(&self) -> Option<LibraryId> {
        self.operator.as_ref().map(OperatorIssuer::default_library)
    }

    /// A new library's settings (section 2.4): open, with the operator's
    /// default quota for its kind, and `erasure_timeout` the operator's T
    /// for the peer, 7 days by default.
    pub fn new_library(&self, library: &LibraryId, erasure_timeout: u64) -> Library {
        let kind = library.as_str().split_once(':').map(|(kind, _)| kind);
        Library {
            quota: kind.and_then(|kind| self.default_quotas.get(kind).copied()),
            erasure_timeout,
            state: LibraryState::Open,
            open_until: None,
            deposit_allowance: None,
            space_share: None,
        }
    }
}

/// A change to a library's settings, by the operator or by the issuer for
/// its libraries; the last write stands (ext-libraries.md, 2.4 Settings).
/// A field left `None` keeps its value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LibraryUpdate {
    /// The new quota: some bytes, or none.
    pub quota: Option<Option<u64>>,
    /// The new `erasure_timeout`, 1 hour to 90 days.
    pub erasure_timeout: Option<u64>,
    /// The new state.
    pub state: Option<LibraryState>,
    /// The new `open_until`: an instant, or none.
    pub open_until: Option<Option<u64>>,
    /// ext-deposit-tokens.md: the new `deposit_allowance`, or none for the
    /// operator's default.
    pub deposit_allowance: Option<Option<u64>>,
    /// ext-deposit-tokens.md: the new `space_share`, or none for the
    /// operator's default.
    pub space_share: Option<Option<u64>>,
}

/// A connection's `LibraryAttach` for one space that a store must follow:
/// a create or an import accepted, whose genesis is not yet stored; then an
/// import in progress.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attaching {
    /// The purpose, the library, the ticket and the reading of a create or
    /// import accepted and not yet hosted.
    pending: Option<(Purpose, LibraryId, TicketId, Reading)>,
    /// The import is in progress: its genesis is stored, and its importer
    /// has not yet stored outside the log it imports.
    importing: bool,
}

impl Attaching {
    /// Whether this connection is the space's import in progress (peers.md,
    /// "Hosting a space").
    pub(crate) fn importing(&self) -> bool {
        self.importing
    }

    /// Whether an import is in progress or a create or an import is
    /// pending: a stopping peer waits for it before it closes the
    /// connection (transport.md, 3.10, "Reconnecting elsewhere").
    pub(crate) fn in_progress(&self) -> bool {
        self.importing || self.pending.is_some()
    }

    /// A create or an import accepted whose genesis was refused lapses
    /// (section 3.3 Attaching); its ticket stays used.
    pub(crate) fn lapse(&mut self) {
        self.pending = None;
    }

    /// Before a store: whether it is a store of the import in progress. The
    /// import stores the log it imports until the importer holds the store
    /// right, by a present of the current state's upload key; its first
    /// store after that is outside the log, and ends the import. A create
    /// or an import accepted for a space that another connection has since
    /// made hosted lapses.
    pub(crate) fn importing_store(
        &mut self,
        rights: &frasil_peers::entries::Rights,
        hosted: bool,
    ) -> bool {
        if self.pending.is_some() {
            if hosted {
                self.pending = None;
            } else {
                return matches!(self.pending, Some((Purpose::Import, ..)));
            }
        }
        if self.importing && rights.store {
            self.importing = false;
        }
        self.importing
    }
}

/// What a `LibraryAttach` is checked against (ext-libraries.md, 3.3
/// Attaching): the space as the peer holds it, the connection's right,
/// and the peer's wall clock.
#[derive(Debug, Clone, Copy)]
pub struct Request<'r> {
    /// The purpose the message names.
    pub purpose: Purpose,
    /// The space.
    pub space: EventId,
    /// The signed ticket.
    pub signed: &'r [u8],
    /// The peer's wall clock, if known.
    pub wall: Option<u64>,
    /// Whether the peer hosts the space.
    pub hosted: bool,
    /// Whether the connection holds the store right for the space.
    pub store_right: bool,
}

/// A space's bytes, as its library's ledger counts them (ext-libraries.md,
/// 2.5 What a peer keeps).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SpaceUsage {
    /// Its stored events and objects, as peers.md's usage counts them,
    /// without its invite drops.
    pub stored_bytes: u64,
    /// Its invite drops held, and their bytes.
    pub drops: u64,
    /// The bytes of its invite drops.
    pub drop_bytes: u64,
    /// Released and not reclaimed.
    pub released_bytes: u64,
    /// Covered and not collected.
    pub covered_bytes: u64,
    /// Named by erasures that wait.
    pub erasing_bytes: u64,
    /// Its stream count.
    pub streams: u64,
    /// The wall-clock instant of its last store, if known.
    pub last_store: Option<u64>,
    /// The bytes of its objects that only other spaces' holds keep
    /// (section 3.8), counted in `stored_bytes`.
    pub held_bytes: u64,
    /// The holds it registered.
    pub holds: u64,
}

impl SpaceUsage {
    /// `used_bytes`: its usage, its invite drops counted in.
    pub fn used_bytes(&self) -> u64 {
        self.stored_bytes.saturating_add(self.drop_bytes)
    }
}

/// One space of a ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceLedger {
    /// The space ID.
    pub space: [u8; 32],
    /// Its usage, with its usage numbers below.
    pub usage: SpaceUsage,
}

/// A library's ledger, as the issuer reads it (ext-libraries.md, 2.5 What a
/// peer keeps). Per-author usage never appears in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    /// The library.
    pub library: LibraryId,
    /// Its settings.
    pub settings: Library,
    /// Its spaces, by ID.
    pub spaces: Vec<SpaceLedger>,
    /// The bytes of the copies it keeps (section 3.8), counted once in its
    /// `used_bytes` and `held_bytes` and in no space's usage.
    pub copy_bytes: u64,
    /// ext-deposit-tokens.md, 2.7 What a peer keeps: the tokens drawn in
    /// its current allowance window and its `deposit_allowance`, with the
    /// extension on. Never a space's draws.
    pub deposit: Option<DepositLedger>,
}

/// What a library's ledger shows of its deposit tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositLedger {
    /// `tokens_drawn`: the tokens drawn in its current window, 0 once the
    /// window has passed.
    pub tokens_drawn: u64,
    /// Its `deposit_allowance`.
    pub deposit_allowance: u64,
    /// When its window opened, on the library's timeline, if one did.
    pub window_start: Option<u64>,
}

fn sum(spaces: &[SpaceLedger], field: impl Fn(&SpaceUsage) -> u64) -> u64 {
    spaces.iter().fold(0u64, |total, space| {
        total.saturating_add(field(&space.usage))
    })
}

impl Ledger {
    /// `used_bytes`: the usage of its spaces and its copies.
    pub fn used_bytes(&self) -> u64 {
        sum(&self.spaces, SpaceUsage::used_bytes).saturating_add(self.copy_bytes)
    }

    /// `headroom_bytes`: the quota less `used_bytes`, below zero once a
    /// lowered quota no longer holds the usage; none without a quota.
    pub fn headroom_bytes(&self) -> Option<i64> {
        self.settings.quota.map(|quota| {
            let room = i128::from(quota) - i128::from(self.used_bytes());
            i64::try_from(room).unwrap_or(if room < 0 { i64::MIN } else { i64::MAX })
        })
    }

    /// The ledger as the operator's interface hands it over: section 2.5's
    /// fields, by name.
    pub fn json(&self) -> serde_json::Value {
        use serde_json::json;
        let spaces: Vec<serde_json::Value> = self
            .spaces
            .iter()
            .map(|space| {
                let usage = &space.usage;
                json!({
                    "space": crate::util::hex(&space.space),
                    "used_bytes": usage.used_bytes(),
                    "drops": usage.drops,
                    "drop_bytes": usage.drop_bytes,
                    "released_bytes": usage.released_bytes,
                    "covered_bytes": usage.covered_bytes,
                    "held_bytes": usage.held_bytes,
                    "holds": usage.holds,
                    "streams": usage.streams,
                    "last_store_day": usage.last_store.map(day),
                })
            })
            .collect();
        let mut ledger = json!({
            "library": self.library.as_str(),
            "used_bytes": self.used_bytes(),
            "released_bytes": sum(&self.spaces, |u| u.released_bytes),
            "covered_bytes": sum(&self.spaces, |u| u.covered_bytes),
            "erasing_bytes": sum(&self.spaces, |u| u.erasing_bytes),
            "drops": sum(&self.spaces, |u| u.drops),
            "drop_bytes": sum(&self.spaces, |u| u.drop_bytes),
            "held_bytes": sum(&self.spaces, |u| u.held_bytes).saturating_add(self.copy_bytes),
            "quota_bytes": self.settings.quota,
            "headroom_bytes": self.headroom_bytes(),
            "erasure_timeout": self.settings.erasure_timeout,
            "state": self.settings.state.name(),
            "spaces": spaces,
        });
        if let Some(deposit) = &self.deposit {
            ledger["tokens_drawn"] = deposit.tokens_drawn.into();
            ledger["deposit_allowance"] = deposit.deposit_allowance.into();
        }
        ledger
    }
}

/// The UTC day of a wall-clock instant, `YYYY-MM-DD` (the proleptic
/// Gregorian calendar, from days since 1970-01-01).
pub fn day(wall: u64) -> String {
    let days = i64::try_from(wall / 86_400).unwrap_or(i64::MAX / 2);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

/// What a peer keeps of its libraries (ext-libraries.md, 2.5 What a peer
/// keeps), and the rules that read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Libraries {
    settings: LibrarySettings,
    /// A new library's `erasure_timeout`.
    erasure_timeout: u64,
    libraries: BTreeMap<LibraryId, Library>,
    attachments: BTreeMap<EventId, Attachment>,
    /// Each library's spaces.
    members: BTreeMap<LibraryId, BTreeSet<EventId>>,
    used: BTreeMap<TicketId, u64>,
    deleted: BTreeSet<EventId>,
    detached: BTreeMap<EventId, Reading>,
    /// Holds, by holding space and locator (section 3.7).
    holds: BTreeMap<(EventId, [u8; 64]), Hold>,
    /// Copies of held objects, by library and locator (section 3.8).
    copies: BTreeMap<(LibraryId, [u8; 64]), Copy>,
    /// Libraries being handed over to another peer (peers.md, 3.1 Hosting
    /// a space, "Hand-over").
    handing: BTreeSet<LibraryId>,
    /// The spaces each library's shard kept as its hand-over froze it.
    frozen: BTreeMap<LibraryId, BTreeSet<EventId>>,
    /// ext-deposit-tokens.md: the operator's default allowance and share,
    /// while the extension is on; `None` reads and keeps none of its
    /// records.
    deposit: Option<DepositSettings>,
    /// ext-deposit-tokens.md: each library's allowance window.
    windows: BTreeMap<LibraryId, Window>,
    /// ext-deposit-tokens.md: the deposit grants used, with their library's
    /// hash and `not_after`.
    grants: BTreeMap<TicketId, ([u8; 32], u64)>,
}

/// What `check_ticket` reads of the peer's libraries, at the peer's wall
/// clock: a library's state is its state at that instant (section 2.4).
struct At<'l> {
    libraries: &'l Libraries,
    wall: Option<u64>,
}

impl PeerRecords for At<'_> {
    fn ticket_used(&self, id: &TicketId) -> bool {
        self.libraries.used.contains_key(id) || self.libraries.grants.contains_key(id)
    }

    fn deposit_tokens(&self) -> bool {
        self.libraries.deposit.is_some()
    }

    fn library_state(&self, library: &LibraryId) -> Option<LibraryState> {
        self.libraries
            .libraries
            .get(library)
            .map(|library| library.state_at(self.wall))
    }
}

/// What ext-deposit-tokens.md, 3.4 Issuing, reads of the libraries.
pub struct Draws<'l> {
    at: At<'l>,
}

impl PeerRecords for Draws<'_> {
    fn ticket_used(&self, id: &TicketId) -> bool {
        self.at.ticket_used(id)
    }

    fn library_state(&self, library: &LibraryId) -> Option<LibraryState> {
        self.at.library_state(library)
    }

    fn deposit_tokens(&self) -> bool {
        self.at.deposit_tokens()
    }
}

impl frasil_deposit_tokens::IssuanceRecords for Draws<'_> {
    fn space_library(&self, space: &[u8; 32]) -> Option<LibraryId> {
        self.at
            .libraries
            .attachments
            .get(&EventId(*space))
            .map(|attachment| attachment.library.clone())
    }

    fn deposit_settings(&self, library: &LibraryId) -> DepositSettings {
        self.at
            .libraries
            .deposit_settings(library)
            .unwrap_or_default()
    }

    fn window(&self, library: &LibraryId) -> Option<frasil_deposit_tokens::Window> {
        self.at
            .libraries
            .windows
            .get(library)
            .map(|window| frasil_deposit_tokens::Window {
                start: window.start,
                drawn: window.drawn,
            })
    }

    fn space_drawn(&self, library: &LibraryId, space: &[u8; 32]) -> u64 {
        self.at.libraries.windows.get(library).map_or(0, |window| {
            window
                .spaces
                .binary_search_by(|(at, _)| at.cmp(space))
                .map_or(0, |index| window.spaces[index].1)
        })
    }
}

impl Libraries {
    /// Empty, under the operator's settings; a new library's
    /// `erasure_timeout` is 7 days.
    pub fn new(settings: LibrarySettings) -> Self {
        Self {
            settings,
            erasure_timeout: ERASURE_TIMEOUT_DEFAULT,
            libraries: BTreeMap::new(),
            attachments: BTreeMap::new(),
            members: BTreeMap::new(),
            used: BTreeMap::new(),
            deleted: BTreeSet::new(),
            detached: BTreeMap::new(),
            holds: BTreeMap::new(),
            copies: BTreeMap::new(),
            handing: BTreeSet::new(),
            frozen: BTreeMap::new(),
            deposit: None,
            windows: BTreeMap::new(),
            grants: BTreeMap::new(),
        }
    }

    /// ext-deposit-tokens.md on, with the operator's default allowance and
    /// share for a library that sets none: the extension's records are read
    /// and kept.
    #[must_use]
    pub fn with_deposit_tokens(mut self, defaults: DepositSettings) -> Self {
        self.deposit = Some(defaults);
        self
    }

    /// The `erasure_timeout` a new library takes: the operator's T for the
    /// peer.
    #[must_use]
    pub fn with_erasure_timeout(mut self, erasure_timeout: u64) -> Self {
        self.erasure_timeout = erasure_timeout;
        self
    }

    fn new_library(&self, library: &LibraryId) -> Library {
        self.settings.new_library(library, self.erasure_timeout)
    }

    /// From its records, under the operator's settings, with
    /// ext-deposit-tokens' defaults while it is on. A record that does not
    /// read is skipped.
    pub fn from_records(
        settings: LibrarySettings,
        deposit: Option<DepositSettings>,
        records: impl IntoIterator<Item = Record>,
    ) -> Self {
        let mut libraries = Self::new(settings);
        libraries.deposit = deposit;
        for record in records {
            libraries.apply(record);
        }
        libraries
    }

    /// Applies a record to the state.
    fn apply(&mut self, record: Record) {
        match record {
            Record::Library(id, library) => {
                self.libraries.insert(id, library);
            }
            Record::Attachment(space, attachment) => {
                let space = EventId(space);
                self.unlink(&space);
                self.members
                    .entry(attachment.library.clone())
                    .or_default()
                    .insert(space);
                self.attachments.insert(space, attachment);
            }
            Record::Ticket(id, not_after) => {
                self.used.insert(id, not_after);
            }
            Record::Deleted(space) => {
                self.deleted.insert(EventId(space));
            }
            Record::Detached(space, at) => {
                self.detached.insert(EventId(space), at);
            }
            Record::Hold(space, locator, hold) => {
                self.holds.insert((EventId(space), locator), hold);
            }
            Record::Copy(locator, library, copy) => {
                self.copies.insert((library, locator), copy);
            }
            Record::HandingOver(library, spaces) => {
                self.handing.insert(library.clone());
                self.frozen
                    .insert(library, spaces.into_iter().map(EventId).collect());
            }
            // ext-deposit-tokens.md's records, only while it is on.
            Record::Window(library, window) if self.deposit.is_some() => {
                self.windows.insert(library, window);
            }
            Record::Grant(hash, id, not_after) if self.deposit.is_some() => {
                self.grants.insert(id, (hash, not_after));
            }
            Record::Window(..) | Record::Grant(..) => {}
        }
    }

    /// Takes in a record another node wrote, as reading it again would.
    pub fn learn(&mut self, record: Record) {
        self.apply(record);
    }

    /// Takes a space out of its library's members.
    fn unlink(&mut self, space: &EventId) {
        if let Some(old) = self.attachments.get(space)
            && let Some(members) = self.members.get_mut(&old.library)
        {
            members.remove(space);
        }
    }

    /// The libraries being handed over to another peer.
    pub fn handing(&self) -> &BTreeSet<LibraryId> {
        &self.handing
    }

    /// Marks a library as being handed over, with the spaces its shard
    /// keeps now. Returns its record.
    pub fn begin_handing(&mut self, library: &LibraryId, spaces: &BTreeSet<EventId>) -> Record {
        self.handing.insert(library.clone());
        self.frozen.insert(library.clone(), spaces.clone());
        Record::HandingOver(
            library.clone(),
            spaces.iter().map(|space| *space.as_bytes()).collect(),
        )
    }

    /// The spaces a library's shard kept as its hand-over froze it.
    pub fn frozen(&self, library: &LibraryId) -> Option<&BTreeSet<EventId>> {
        self.frozen.get(library)
    }

    /// Ends a library's hand-over. Returns the address of its record.
    pub fn end_handing(&mut self, library: &LibraryId) -> (u8, Vec<u8>) {
        self.handing.remove(library);
        self.frozen.remove(library);
        (records::HANDING_OVER, library.as_str().as_bytes().to_vec())
    }

    /// The operator's settings.
    pub fn settings(&self) -> &LibrarySettings {
        &self.settings
    }

    /// A library's settings, if the peer knows it.
    pub fn library(&self, library: &LibraryId) -> Option<&Library> {
        self.libraries.get(library)
    }

    /// Every library the peer knows.
    pub fn libraries(&self) -> impl Iterator<Item = &LibraryId> {
        self.libraries.keys()
    }

    /// A space's attachment.
    pub fn attachment(&self, space: &EventId) -> Option<&Attachment> {
        self.attachments.get(space)
    }

    /// Every attachment.
    pub fn attachments(&self) -> &BTreeMap<EventId, Attachment> {
        &self.attachments
    }

    /// A library's spaces.
    pub fn members(&self, library: &LibraryId) -> impl Iterator<Item = &EventId> {
        self.members.get(library).into_iter().flatten()
    }

    /// The ticket IDs used, with their `not_after`.
    pub fn tickets_used(&self) -> &BTreeMap<TicketId, u64> {
        &self.used
    }

    /// Whether the operator deleted a space's data.
    pub fn is_deleted(&self, space: &EventId) -> bool {
        self.deleted.contains(space)
    }

    /// When a space was detached, if it is.
    pub fn detached_at(&self, space: &EventId) -> Option<&Reading> {
        self.detached.get(space)
    }

    /// The `erasure_timeout` of a space's library, if it is attached to
    /// one.
    pub fn erasure_timeout(&self, space: &EventId) -> Option<u64> {
        let attachment = self.attachments.get(space)?;
        self.libraries
            .get(&attachment.library)
            .map(|library| library.erasure_timeout)
    }

    /// A library's usage: its spaces' `used_bytes`, and its copies'.
    pub fn usage(&self, library: &LibraryId, usage_of: &impl Fn(&EventId) -> u64) -> u64 {
        self.members(library)
            .fold(self.copy_bytes(library), |total, space| {
                total.saturating_add(usage_of(space))
            })
    }

    /// The bytes of a library's copies (section 3.8).
    pub fn copy_bytes(&self, library: &LibraryId) -> u64 {
        self.copies_of(library)
            .fold(0u64, |total, (_, copy)| total.saturating_add(copy.bytes))
    }

    /// A library's copies, by locator.
    pub fn copies_of<'a>(
        &'a self,
        library: &'a LibraryId,
    ) -> impl Iterator<Item = (&'a [u8; 64], &'a Copy)> + 'a {
        self.copies
            .range((library.clone(), [0; 64])..=(library.clone(), [0xff; 64]))
            .map(|((_, locator), copy)| (locator, copy))
    }

    /// Every copy, by library and locator.
    pub fn copies(&self) -> &BTreeMap<(LibraryId, [u8; 64]), Copy> {
        &self.copies
    }

    /// The copy a library keeps of an object, if any.
    pub fn copy(&self, library: &LibraryId, locator: &[u8; 64]) -> Option<&Copy> {
        self.copies.get(&(library.clone(), *locator))
    }

    /// Keeps a copy. Returns its record.
    pub fn add_copy(&mut self, library: LibraryId, locator: [u8; 64], copy: Copy) -> Record {
        self.copies.insert((library.clone(), locator), copy.clone());
        Record::Copy(locator, library, copy)
    }

    /// Forgets copies. Returns the addresses to delete.
    pub fn drop_copies(&mut self, gone: &[(LibraryId, [u8; 64])]) -> Vec<(u8, Vec<u8>)> {
        gone.iter()
            .filter(|key| self.copies.remove(key).is_some())
            .map(|(library, locator)| {
                (
                    records::COPY,
                    [&locator[..], library.as_str().as_bytes()].concat(),
                )
            })
            .collect()
    }

    /// The library a hold's holding space is billed to and the copy it
    /// keeps of the held object, when the hold's source is billed to
    /// another library (section 3.8, "Holds across a move"): the hold then
    /// points at that copy.
    pub fn hold_copy(&self, space: &EventId, locator: &[u8; 64]) -> Option<(&LibraryId, &Copy)> {
        let hold = self.holds.get(&(*space, *locator))?;
        if !self.points_at_copy(space, hold) {
            return None;
        }
        let library = &self.attachments.get(space)?.library;
        self.copy(library, locator).map(|copy| (library, copy))
    }

    /// A library's headroom: its quota less its usage; none without a
    /// quota. A library the peer does not know has section 2.4's
    /// defaults.
    pub fn headroom(
        &self,
        library: &LibraryId,
        usage_of: &impl Fn(&EventId) -> u64,
    ) -> Option<i128> {
        let quota = match self.libraries.get(library) {
            Some(known) => known.quota,
            None => self.new_library(library).quota,
        }?;
        Some(i128::from(quota) - i128::from(self.usage(library, usage_of)))
    }

    /// ext-libraries.md, 3.3 Attaching, in order, for each purpose, up to
    /// the record: returns the ticket, or the class that refuses. A create
    /// or an import is then accepted, and its first stored event must be
    /// the genesis; a genesis of a space this peer erased, deleted (for a
    /// create) or handed over is refused `Erased` when it is stored
    /// (peers.md, 3.2 Storing an event, step 3), so that the space ID alone
    /// tells nothing.
    ///
    /// ```text
    /// Create: 1. not hosted (SpaceExists); 2. check_ticket.
    /// Import: 1. not hosted (SpaceExists); 2. check_ticket.
    /// Move:   1. the store right (NotAuthorized); 2. check_ticket;
    ///         3. the target library's headroom holds the space's current
    ///            usage (QuotaExceeded).
    /// ```
    ///
    /// `usage_of` gives each hosted space's `used_bytes`.
    ///
    /// # Errors
    ///
    /// The class of the first step that refuses.
    pub fn check(
        &self,
        request: &Request<'_>,
        usage_of: &impl Fn(&EventId) -> u64,
    ) -> Result<Ticket, LibraryClass> {
        match request.purpose {
            Purpose::Create | Purpose::Import => {
                if request.hosted {
                    return Err(LibraryClass::SpaceExists);
                }
            }
            Purpose::Move => {
                if !request.store_right {
                    return Err(LibraryClass::NotAuthorized);
                }
            }
            // `LibraryAttach` never carries purpose 4, a deposit grant.
            Purpose::Deposit => return Err(frasil_base::ErrorClass::Malformed.into()),
        }
        let ticket = check_ticket(
            request.signed,
            request.purpose,
            request.wall,
            &self.settings.issuers,
            &At {
                libraries: self,
                wall: request.wall,
            },
        )?;
        if request.purpose == Purpose::Move
            && let Some(room) = self.headroom(&ticket.library, usage_of)
            && room < i128::from(usage_of(&request.space))
        {
            return Err(LibraryClass::QuotaExceeded);
        }
        Ok(ticket)
    }

    /// Spends a ticket: its ID is used at this peer until its `not_after`
    /// and `ticket_skew` have passed. A library the peer does not yet know
    /// is created at its first ticket, with section 2.4's defaults.
    /// Returns the records to write.
    pub fn spend(&mut self, ticket: &Ticket) -> Vec<Record> {
        let mut out = vec![Record::Ticket(ticket.id, ticket.not_after)];
        if !self.libraries.contains_key(&ticket.library) {
            let library = self.new_library(&ticket.library);
            out.push(Record::Library(ticket.library.clone(), library));
        }
        for record in &out {
            self.apply(record.clone());
        }
        out
    }

    /// Records a space's attachment to a library, by a ticket or by the
    /// operator's open library: the space's usage leaves its old library's
    /// ledger and joins the new one's in one step. A library the peer does
    /// not yet know is created with section 2.4's defaults. A detached
    /// space is attached again; an imported space the operator deleted is
    /// hosted again. Returns the records to write; the keys to delete are
    /// [`Self::cleared`]'s.
    pub fn attach(
        &mut self,
        space: EventId,
        library: &LibraryId,
        ticket: Option<TicketId>,
        at: Reading,
    ) -> Vec<Record> {
        let mut out = Vec::new();
        if !self.libraries.contains_key(library) {
            out.push(Record::Library(library.clone(), self.new_library(library)));
        }
        out.push(Record::Attachment(
            *space.as_bytes(),
            Attachment {
                library: library.clone(),
                ticket,
                at,
            },
        ));
        for record in &out {
            self.apply(record.clone());
        }
        self.detached.remove(&space);
        self.deleted.remove(&space);
        out
    }

    /// The keys of a space's detachment and deletion records, which an
    /// attachment clears.
    pub fn cleared(space: &EventId) -> [(u8, Vec<u8>); 2] {
        [
            (records::DETACHED, space.as_bytes().to_vec()),
            (records::DELETED, space.as_bytes().to_vec()),
        ]
    }

    /// ext-libraries.md, 3.4 Storing, at peers.md's step "The space is
    /// hosted here": the space is attached to a library, and the library's
    /// state is open at the peer's wall clock `wall`.
    ///
    /// # Errors
    ///
    /// `NoLibrary` or `LibraryClosed`.
    pub fn hosts(&self, space: &EventId, wall: Option<u64>) -> Result<(), LibraryClass> {
        let attachment = self.attachments.get(space).ok_or(LibraryClass::NoLibrary)?;
        match self
            .libraries
            .get(&attachment.library)
            .map(|library| library.state_at(wall))
        {
            Some(LibraryState::Suspended) => Err(LibraryClass::LibraryClosed),
            _ => Ok(()),
        }
    }

    /// ext-libraries.md, 3.4 Storing, at peers.md's quota step: the
    /// library's quota over all its spaces holds `adds` more bytes.
    ///
    /// # Errors
    ///
    /// `QuotaExceeded`; `NoLibrary` for a space attached to none.
    pub fn quota(
        &self,
        space: &EventId,
        adds: u64,
        usage_of: &impl Fn(&EventId) -> u64,
    ) -> Result<(), LibraryClass> {
        let attachment = self.attachments.get(space).ok_or(LibraryClass::NoLibrary)?;
        match self.headroom(&attachment.library, usage_of) {
            Some(room) if room < i128::from(adds) => Err(LibraryClass::QuotaExceeded),
            _ => Ok(()),
        }
    }

    /// ext-libraries.md, 3.5: a space detached from its library through the
    /// operator's interface. It then accepts no store (`NoLibrary`) and
    /// still serves fetches. Returns the record to write and the key to
    /// delete, or `None` for a space attached to no library.
    pub fn detach(&mut self, space: &EventId, at: Reading) -> Option<(Record, (u8, Vec<u8>))> {
        self.attachments.get(space)?;
        self.unlink(space);
        self.attachments.remove(space);
        let record = Record::Detached(*space.as_bytes(), at);
        self.apply(record.clone());
        Some((record, (records::ATTACHMENT, space.as_bytes().to_vec())))
    }

    /// The detached spaces whose `detached_grace` has passed, on the lower
    /// estimate of the peer's timeline: the operator MAY delete their data.
    pub fn past_grace(&self, now: &Reading) -> Vec<EventId> {
        self.detached
            .iter()
            .filter(|(_, at)| lower(at, now) >= self.settings.detached_grace)
            .map(|(space, _)| *space)
            .collect()
    }

    /// ext-libraries.md, 3.5: the operator deletes a space's data at this
    /// peer and keeps its ID, so that a later create of it is `Erased`.
    /// Returns the record to write and the keys to delete.
    pub fn delete(&mut self, space: &EventId) -> (Record, Vec<(u8, Vec<u8>)>) {
        self.unlink(space);
        self.attachments.remove(space);
        self.detached.remove(space);
        let record = Record::Deleted(*space.as_bytes());
        self.apply(record.clone());
        let deletes = vec![
            (records::ATTACHMENT, space.as_bytes().to_vec()),
            (records::DETACHED, space.as_bytes().to_vec()),
        ];
        (record, deletes)
    }

    /// Forgets a library whose spaces are all deleted, with its allowance
    /// window. Returns the keys to delete, or `None` while it still has
    /// spaces.
    pub fn forget(&mut self, library: &LibraryId) -> Option<Vec<(u8, Vec<u8>)>> {
        if self.members(library).next().is_some() {
            return None;
        }
        self.members.remove(library);
        self.libraries.remove(library)?;
        let key = library.as_str().as_bytes().to_vec();
        let mut deletes = vec![(records::LIBRARY, key.clone())];
        if self.windows.remove(library).is_some() {
            deletes.push((records::WINDOW, key));
        }
        Some(deletes)
    }

    /// Changes a library's settings; a library the peer does not know is
    /// created with the defaults first. Returns the record to write.
    ///
    /// # Errors
    ///
    /// An `erasure_timeout` outside 1 hour to 90 days, which changes
    /// nothing.
    pub fn update(
        &mut self,
        library: &LibraryId,
        update: LibraryUpdate,
    ) -> Result<Record, LibraryClass> {
        let mut settings = self
            .libraries
            .get(library)
            .copied()
            .unwrap_or_else(|| self.new_library(library));
        if let Some(quota) = update.quota {
            settings.quota = quota;
        }
        if let Some(timeout) = update.erasure_timeout {
            if !erasure_timeout_allowed(timeout) {
                return Err(frasil_base::ErrorClass::Malformed.into());
            }
            settings.erasure_timeout = timeout;
        }
        if let Some(state) = update.state {
            settings.state = state;
        }
        if let Some(until) = update.open_until {
            settings.open_until = until;
        }
        // ext-deposit-tokens.md, 2.6 Settings: an allowance of 0 to 65,536,
        // and a share of 0 to the allowance.
        if update.deposit_allowance.is_some() || update.space_share.is_some() {
            let Some(defaults) = self.deposit else {
                return Err(frasil_base::ErrorClass::Malformed.into());
            };
            if let Some(allowance) = update.deposit_allowance {
                settings.deposit_allowance = allowance;
            }
            if let Some(share) = update.space_share {
                settings.space_share = share;
            }
            let allowance = settings
                .deposit_allowance
                .unwrap_or(defaults.deposit_allowance);
            if allowance > records::MAX_ALLOWANCE
                || settings.space_share.is_some_and(|share| share > allowance)
            {
                return Err(frasil_base::ErrorClass::Malformed.into());
            }
        }
        let record = Record::Library(library.clone(), settings);
        self.apply(record.clone());
        Ok(record)
    }

    /// Ticket IDs and deposit grant IDs past their `not_after` and
    /// `ticket_skew` at the wall clock `wall`: forgotten, since
    /// `check_ticket` refuses them as expired first. Returns the keys to
    /// delete.
    pub fn expire(&mut self, wall: u64) -> Vec<(u8, Vec<u8>)> {
        let past = |not_after: u64| wall > not_after.saturating_add(TICKET_SKEW);
        let old: Vec<TicketId> = self
            .used
            .iter()
            .filter(|(_, not_after)| past(**not_after))
            .map(|(id, _)| *id)
            .collect();
        let mut deletes: Vec<(u8, Vec<u8>)> = old
            .into_iter()
            .map(|id| {
                self.used.remove(&id);
                (records::TICKET, id.to_vec())
            })
            .collect();
        let grants: Vec<(TicketId, [u8; 32])> = self
            .grants
            .iter()
            .filter(|(_, (_, not_after))| past(*not_after))
            .map(|(id, (hash, _))| (*id, *hash))
            .collect();
        for (id, hash) in grants {
            self.grants.remove(&id);
            deletes.push((records::GRANT, [&hash[..], &id[..]].concat()));
        }
        deletes
    }

    /// Drops the attachments of spaces the peer no longer hosts, erased
    /// at the peer. Returns the keys to delete.
    pub fn drop_spaces(&mut self, gone: &[EventId]) -> Vec<(u8, Vec<u8>)> {
        let mut deletes = Vec::new();
        for space in gone {
            if self.attachments.contains_key(space) {
                self.unlink(space);
                self.attachments.remove(space);
                deletes.push((records::ATTACHMENT, space.as_bytes().to_vec()));
            }
            if self.detached.remove(space).is_some() {
                deletes.push((records::DETACHED, space.as_bytes().to_vec()));
            }
        }
        deletes
    }

    // -- Holds (sections 3.7 to 3.9)

    /// Whether two spaces are attached to the same library, neither of them
    /// detached (section 3.7, step 6).
    pub fn same_library(&self, space: &EventId, source: &EventId) -> bool {
        match (self.attachments.get(space), self.attachments.get(source)) {
            (Some(a), Some(b)) => a.library == b.library,
            _ => false,
        }
    }

    /// Every hold, by holding space and locator.
    pub fn holds(&self) -> &BTreeMap<(EventId, [u8; 64]), Hold> {
        &self.holds
    }

    /// A space's hold of a locator.
    pub fn hold(&self, space: &EventId, locator: &[u8; 64]) -> Option<&Hold> {
        self.holds.get(&(*space, *locator))
    }

    /// Whether a hold of the locator was registered with this access key
    /// (section 3.7, step 4).
    pub fn vouches(&self, locator: &[u8; 64], access: &[u8; 32]) -> bool {
        self.holds
            .iter()
            .any(|((_, held), hold)| held == locator && hold.access == *access)
    }

    /// Whether a hold keeps a source's object: one that points at the
    /// source, its holding space billed to the source's library. A hold
    /// that points at a copy keeps the copy instead (section 3.8).
    pub fn is_held(&self, source: &EventId, locator: &[u8; 64]) -> bool {
        self.holds.iter().any(|((holder, held), hold)| {
            held == locator
                && hold.source == *source.as_bytes()
                && !self.points_at_copy(holder, hold)
        })
    }

    /// Whether a hold points at a copy: its holding space and its source
    /// are billed to two libraries (section 3.8, "Holds across a move"). A
    /// detached source still serves its held objects.
    fn points_at_copy(&self, holder: &EventId, hold: &Hold) -> bool {
        match (
            self.attachments.get(holder),
            self.attachments.get(&EventId(hold.source)),
        ) {
            (Some(holder), Some(source)) => holder.library != source.library,
            _ => false,
        }
    }

    /// The copies of a library no hold points at, or whose source the
    /// peer erased: what a sweep collects (section 3.8).
    pub fn unheld_copies(
        &self,
        library: &LibraryId,
        erased: impl Fn(&EventId) -> bool,
    ) -> Vec<[u8; 64]> {
        self.copies_of(library)
            .filter(|(locator, copy)| {
                erased(&EventId(copy.source))
                    || !self.holds.iter().any(|((holder, held), hold)| {
                        held == *locator
                            && self.points_at_copy(holder, hold)
                            && self
                                .attachments
                                .get(holder)
                                .is_some_and(|a| &a.library == library)
                    })
            })
            .map(|(locator, _)| *locator)
            .collect()
    }

    /// How many holds a space registered.
    pub fn holds_of(&self, space: &EventId) -> u64 {
        self.holds
            .keys()
            .filter(|(holder, _)| holder == space)
            .count() as u64
    }

    /// Records a hold; one the peer already has changes nothing. Returns
    /// the record to write, if any.
    pub fn add_hold(&mut self, space: EventId, locator: [u8; 64], hold: Hold) -> Option<Record> {
        if self.holds.contains_key(&(space, locator)) {
            return None;
        }
        let record = Record::Hold(*space.as_bytes(), locator, hold);
        self.apply(record.clone());
        Some(record)
    }

    /// The holds that are no longer live at `now` (section 3.8): a hold is
    /// live while its space stores a unit that lists its locator, or, until
    /// one does, for `grace` (`orphan_grace`) from its registration; it ends
    /// once its space or its source is no longer hosted. `hosted` and
    /// `listed` read the peer's spaces.
    pub fn ended_holds(
        &self,
        now: &Reading,
        grace: u64,
        hosted: impl Fn(&EventId) -> bool,
        listed: impl Fn(&EventId, &[u8; 64]) -> bool,
    ) -> Vec<(EventId, [u8; 64])> {
        self.holds
            .iter()
            .filter(|((space, locator), hold)| {
                let live = listed(space, locator) || lower(&hold.at, now) < grace;
                !(hosted(space) && hosted(&EventId(hold.source)) && live)
            })
            .map(|(key, _)| *key)
            .collect()
    }

    /// Drops holds. Returns the keys to delete.
    pub fn drop_holds(&mut self, gone: &[(EventId, [u8; 64])]) -> Vec<(u8, Vec<u8>)> {
        gone.iter()
            .filter(|key| self.holds.remove(key).is_some())
            .map(|(space, locator)| (records::HOLD, records::hold_key(space.as_bytes(), locator)))
            .collect()
    }

    // -- Deposit tokens (ext-deposit-tokens.md)

    /// A library's `deposit_allowance` and `space_share` as they hold: its
    /// own, or the operator's defaults, the share at most the allowance;
    /// `None` while ext-deposit-tokens is off.
    pub fn deposit_settings(&self, library: &LibraryId) -> Option<DepositSettings> {
        let defaults = self.deposit?;
        let own = self.libraries.get(library);
        let allowance = own
            .and_then(|own| own.deposit_allowance)
            .unwrap_or(defaults.deposit_allowance);
        let share = own
            .and_then(|own| own.space_share)
            .unwrap_or(defaults.space_share)
            .min(allowance);
        Some(DepositSettings {
            deposit_allowance: allowance,
            space_share: share,
        })
    }

    /// A library's allowance window, as last kept.
    pub fn window(&self, library: &LibraryId) -> Option<&Window> {
        self.windows.get(library)
    }

    /// What ext-deposit-tokens.md, 3.4 Issuing, reads of the libraries, at
    /// the peer's wall clock `wall`.
    pub fn draws(&self, wall: Option<u64>) -> Draws<'_> {
        Draws {
            at: At {
                libraries: self,
                wall,
            },
        }
    }

    /// The records a batch issued writes, in one step (section 3.4): the
    /// library's window after it, with the space's share for a space draw,
    /// and the grant used for a grant draw.
    pub fn drawn(&self, issued: &frasil_deposit_tokens::Issued) -> Vec<Record> {
        let mut spaces: BTreeMap<[u8; 32], u64> = match self.windows.get(&issued.library) {
            Some(window) if window.start == issued.window.start => {
                window.spaces.iter().copied().collect()
            }
            _ => BTreeMap::new(),
        };
        if let Some((space, drawn)) = issued.space {
            spaces.insert(space, drawn);
        }
        let mut out = Vec::new();
        // A library the peer does not yet know is created at its first
        // draw, with section 2.4's defaults, as at its first ticket.
        if !self.libraries.contains_key(&issued.library) {
            out.push(Record::Library(
                issued.library.clone(),
                self.new_library(&issued.library),
            ));
        }
        out.push(Record::Window(
            issued.library.clone(),
            Window {
                start: issued.window.start,
                drawn: issued.window.drawn,
                spaces: spaces.into_iter().filter(|(_, n)| *n > 0).collect(),
            },
        ));
        if let Some((id, not_after)) = issued.grant {
            out.push(Record::Grant(
                records::library_hash(&issued.library),
                id,
                not_after,
            ));
        }
        out
    }

    /// Forgets a library's window, as a record read again finds none.
    pub fn drop_window(&mut self, library: &LibraryId) {
        self.windows.remove(library);
    }

    /// A library's ledger, with each of its spaces' usage from `usage_of`;
    /// `None` for a library the peer does not know.
    pub fn ledger(
        &self,
        library: &LibraryId,
        usage_of: &impl Fn(&EventId) -> SpaceUsage,
    ) -> Option<Ledger> {
        let settings = *self.libraries.get(library)?;
        let spaces = self
            .members(library)
            .map(|space| SpaceLedger {
                space: *space.as_bytes(),
                usage: usage_of(space),
            })
            .collect();
        let deposit = self.deposit_settings(library).map(|tokens| {
            let window = self.windows.get(library);
            DepositLedger {
                tokens_drawn: window.map_or(0, |window| window.drawn),
                deposit_allowance: tokens.deposit_allowance,
                window_start: window.map(|window| window.start),
            }
        });
        Some(Ledger {
            library: library.clone(),
            settings,
            spaces,
            copy_bytes: self.copy_bytes(library),
            deposit,
        })
    }
}
