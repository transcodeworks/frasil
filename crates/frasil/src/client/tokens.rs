//! Deposit tokens at a device (ext-deposit-tokens.md): learning a peer's
//! keys, drawing tokens ahead of need, keeping them, and spending one on
//! each deposit in a device mailbox there.
//!
//! - **Learning keys** (3.2): by `TokenKeysGet` on a connection of the
//!   device's own that presents nothing ([`Bare`](crate::peer::Bare)),
//!   never on one that draws or presents a credential. Each list passes the
//!   protocol crate's checks into the peer's key history, kept at rest in
//!   the `deposit_keys` table (at-rest.md, "Tables"). A list that is
//!   `KeyInconsistent` stops drawing and spending there, drops the tokens
//!   held for the peer, and is reported ([`Event::DepositPeerDistrusted`]);
//!   the stop lasts until [`Device::trust_deposit_keys`]. A token of a key
//!   the latest list does not show is dropped.
//! - **Drawing ahead of need** (3.3, 3.12): at each upkeep, for each peer
//!   where the device has a way to draw, a grant the application handed
//!   over ([`Device::give_deposit_grant`]) or the store right in a space
//!   the peer grants it, and fewer tokens of the issuing key than the low
//!   mark, 4, the device picks a random moment in the next hour of its
//!   timeline and draws a batch, 16 by default ([`Options::deposit_batch`]),
//!   then. A new way to draw holds no token, so the first batch comes
//!   within the hour, whether or not the device has deposited. It never
//!   draws in answer to a deposit. It holds at most 256. A grant draw goes
//!   on a connection that presents nothing else; a space draw on one that
//!   presents that space's upload key alone and stores nothing. A draw
//!   answered `allowance_exhausted` pauses drawing there for
//!   `allowance_window`; a `BadProof` drops the batch and is reported.
//! - **Keeping** (3.5): each token sealed in its own `token` record; the
//!   blinds and inputs live in a [`Batch`] in memory until the answer. A
//!   grant is held in memory only, zeroized when dropped, and never shown.
//! - **Spending** (3.6): see the deposits module. Tokens of the older live
//!   key go first.
//!
//! [`Options::deposit_batch`]: super::Options::deposit_batch

use super::Device;
use super::deposits::{Answer, answer_of};
use super::events::Event;
use crate::error::Result;
use crate::hints::same_peer;
use frasil_base::errors::Class;
use frasil_base::time::{Reading, lower};
use frasil_deposit_tokens::settings::{ALLOWANCE_WINDOW, BATCH, LOW_MARK};
use frasil_deposit_tokens::{Batch, Draw, KeyHistory, KeyList, Role, TokenClass};
use frasil_deposit_tokens::{MAX_BATCH, Token, TokenKeysGet, TokenPut};
use frasil_store::{DepositKeysRecord, DepositRecord, Table, TableValue, TokenBytes};
use frasil_transport::codes::{Right, Service};
use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use zeroize::Zeroizing;

/// The hour within which a device draws, at a random moment.
const DRAW_SPREAD: u64 = 3_600;

/// The most tokens a device holds of one peer.
const MAX_HELD: usize = MAX_BATCH;

/// How often the device asks again for the keys of a peer whose tokens
/// it holds, so that it drops those of a retired key.
const KEYS_EVERY: u64 = 3_600;

/// The most issuing keys kept in a `deposit_keys` record.
const MAX_SEEN: usize = frasil_store::tables::MAX_SEEN_KEYS;

/// What a device holds in memory for deposit tokens.
#[derive(Debug)]
pub(crate) struct Tokens {
    peers: Mutex<BTreeMap<String, PeerTokens>>,
    batch: usize,
}

impl Tokens {
    /// With a batch of `batch` tokens, 1 to 256.
    pub(crate) fn new(batch: Option<usize>) -> Self {
        Self {
            peers: Mutex::default(),
            batch: batch.unwrap_or(BATCH).clamp(1, MAX_BATCH),
        }
    }

    fn with<R>(&self, origin: &str, f: impl FnOnce(&mut PeerTokens) -> R) -> R {
        let mut peers = self.peers.lock().unwrap_or_else(PoisonError::into_inner);
        f(peers.entry(origin.to_owned()).or_default())
    }
}

/// What a device holds in memory for one peer.
#[derive(Default)]
struct PeerTokens {
    /// The grant the application handed over, until a draw uses it.
    grant: Option<Zeroizing<Vec<u8>>>,
    /// The timeline's `T` at which the next draw is due.
    draw_at: Option<u64>,
    /// When the device last asked the peer's keys.
    keys_at: Option<u64>,
    /// Whether a draw is under way.
    drawing: bool,
}

impl core::fmt::Debug for PeerTokens {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerTokens")
            .field("grant", &self.grant.is_some())
            .field("draw_at", &self.draw_at)
            .finish_non_exhaustive()
    }
}

/// How many deposit tokens a device holds for a peer, and whether it
/// draws there ([`Device::deposit_tokens`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct DepositTokens {
    /// The unspent tokens of the peer's live keys the device holds.
    pub held: usize,
    /// Whether the peer answered a draw `allowance_exhausted` less than
    /// `allowance_window`, 24 hours, ago: the device draws none there
    /// meanwhile.
    pub paused: bool,
    /// Whether the peer's key lists contradicted one another: the device
    /// draws and spends none there until
    /// [`Device::trust_deposit_keys`].
    pub distrusted: bool,
    /// Whether the device holds a grant for the peer that no draw used
    /// yet.
    pub grant: bool,
}

/// The peer's ID, as at-rest.md names an always-on peer reached by its
/// origin: the server binding's `channel` of that origin.
fn peer_id(origin: &str) -> [u8; 32] {
    frasil_transport::peer::server_channel(origin.trim_end_matches('/'))
}

fn origin(url: &str) -> String {
    url.trim_end_matches('/').to_owned()
}

/// The peer's key history and latest list, as kept at rest.
struct Kept {
    history: KeyHistory,
    latest: Option<KeyList>,
    record: DepositKeysRecord,
}

impl Kept {
    /// The key IDs of the latest list, the older (accepting only) first.
    fn live(&self) -> Vec<[u8; 32]> {
        let mut keys: Vec<_> = self
            .latest
            .iter()
            .flat_map(|list| list.keys().iter())
            .map(|key| (key.role == Role::Issuing, key.id))
            .collect();
        keys.sort();
        keys.into_iter().map(|(_, id)| id).collect()
    }

    fn issuing(&self) -> Option<[u8; 32]> {
        self.latest.as_ref().map(|list| list.issuing().id)
    }

    fn paused(&self, now: &Reading) -> bool {
        self.record
            .paused
            .is_some_and(|at| lower(&at, now) < ALLOWANCE_WINDOW)
    }
}

/// Reads the peer's `deposit_keys` record.
async fn kept(device: &Device, origin: &str) -> Option<Kept> {
    let value = device
        .engine()
        .device_record(Table::DepositKeys, &peer_id(origin))
        .await
        .ok()??;
    let TableValue::DepositKeys(record) = value else {
        return None;
    };
    let entries: Vec<(&[u8], &[u8], u64)> = record
        .latest
        .iter()
        .map(|(id, public, role)| (&id[..], &public[..], *role))
        .collect();
    let latest = KeyList::check(&entries).ok();
    let mut history = KeyHistory::from_parts(record.seen.clone(), record.inconsistent);
    // The latest list names the last issuing key seen, so taking it again
    // only restores which keys the device keeps tokens of.
    if let (Some(list), Some((_, first))) = (&latest, record.seen.last()) {
        let _ = history.observe(list, *first);
    }
    Some(Kept {
        history,
        latest,
        record,
    })
}

/// The tokens held for the peer: each with its record's item.
async fn held(device: &Device, origin: &str) -> Vec<(Vec<u8>, TokenBytes)> {
    let id = peer_id(origin);
    device
        .engine()
        .device_records(Table::Token)
        .await
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(item, value)| match value {
            TableValue::Token(token) if item.starts_with(&id) => Some((item, token)),
            _ => None,
        })
        .collect()
}

/// The key ID of a token's bytes.
fn key_of(token: &TokenBytes) -> [u8; 32] {
    let mut id = [0; 32];
    id.copy_from_slice(&token.expose()[1..33]);
    id
}

/// The item of a token's record: the peer's ID and the token's nonce.
fn token_item(origin: &str, token: &TokenBytes) -> Vec<u8> {
    [&peer_id(origin)[..], &token.expose()[33..65]].concat()
}

/// Takes a token of the peer for a deposit (ext-deposit-tokens.md, 3.6):
/// one of the older live key first. It leaves the `token` table and
/// enters the deposit's record in one commit. None when the device holds
/// none, or has stopped spending there.
pub(super) async fn take(
    device: &Device,
    id: &[u8; 16],
    record: &DepositRecord,
    keep_at_rest: bool,
) -> Option<TokenBytes> {
    let kept = kept(device, &record.peer).await?;
    if kept.history.stopped() {
        return None;
    }
    let live = kept.live();
    let mut tokens = held(device, &record.peer).await;
    tokens.retain(|(_, token)| live.contains(&key_of(token)));
    tokens.sort_by_key(|(_, token)| live.iter().position(|key| *key == key_of(token)));
    let (item, token) = tokens.into_iter().next()?;
    let mut paid = record.clone();
    paid.token = Some(token.clone());
    // Only while the deposit is kept: one dropped meanwhile, as that of a
    // welcome that ended, takes no token.
    if keep_at_rest {
        device
            .engine()
            .keep_deposit_again(id, &paid, vec![(Table::Token, item)])
            .await
            .ok()
            .filter(|kept| *kept)?;
    } else {
        if !device.kept_in_memory(id) {
            return None;
        }
        device
            .engine()
            .commit_device(Vec::new(), vec![(Table::Token, item)])
            .await
            .ok()?;
        // Dropped while the token left the store: the token goes back.
        if let Ok(false) = device.keep_again(id, &paid, false).await {
            give_back(device, &record.peer, token).await;
            return None;
        }
    }
    Some(token)
}

/// Puts back a token a deposit did not spend: the peer refused the
/// deposit for another reason than the token (ext-deposit-tokens.md, 3.7
/// Redeeming: a refusal leaves it unspent).
pub(super) async fn give_back(device: &Device, peer: &str, token: TokenBytes) {
    let item = token_item(peer, &token);
    let _ = device
        .engine()
        .commit_device(
            vec![(Table::Token, item, TableValue::Token(token))],
            Vec::new(),
        )
        .await;
}

/// Deposits with a token (ext-deposit-tokens.md, 3.6): a `MailboxPut` of
/// kind 3 with key 7, on a connection of the device's own that presents
/// nothing. A peer that no longer lists service 6 is answered as for a
/// token of a key it does not have: `token_expired`.
pub(super) async fn spend(device: &Device, record: &DepositRecord, token: &TokenBytes) -> Answer {
    let mut bare = match device.bare(&record.peer).await {
        Ok(bare) => bare,
        Err(error) => return Answer::Unanswered(error.to_string()),
    };
    if !bare.services().contains(&Service::Deposit) {
        return Answer::Refused(TokenClass::TokenExpired.wire_name().to_owned());
    }
    let Ok(token) = Token::from_bytes(token.expose()) else {
        return Answer::Refused(TokenClass::TokenRefused.wire_name().to_owned());
    };
    let request = bare.next_request();
    let message = TokenPut {
        request,
        address: record.address,
        item: record.item.clone(),
        token,
    }
    .encode();
    answer_of(bare.put(&message, request).await)
}

/// What a peer's keys were, once asked.
enum Learned {
    /// The checked list, which the history took.
    Keys(KeyList),
    /// The peer does not list service 6, or did not answer: nothing to
    /// draw there now.
    Nothing,
    /// The peer is `KeyInconsistent`.
    Inconsistent,
}

/// Asks the peer's live keys by `TokenKeysGet` on a connection of the
/// device's own that presents nothing (ext-deposit-tokens.md, 3.2), takes
/// a list into its history, keeps it at rest, and drops the tokens of keys
/// it does not show. On `KeyInconsistent` it drops every token held for
/// the peer and reports it.
async fn learn(device: &Device, origin: &str) -> Learned {
    let Ok(mut bare) = device.bare(origin).await else {
        return Learned::Nothing;
    };
    if !bare.services().contains(&Service::Deposit) {
        return Learned::Nothing;
    }
    let request = bare.next_request();
    let message = TokenKeysGet { request }.encode();
    let Ok(answer) = bare.ask(&message, request).await else {
        return Learned::Nothing;
    };
    drop(bare);
    let Ok(list) = KeyList::read(&answer.map, request) else {
        return Learned::Nothing;
    };
    let Ok(now) = device.engine().reading().await else {
        return Learned::Nothing;
    };
    let previous = kept(device, origin).await;
    let (mut history, paused) = match &previous {
        Some(kept) => (kept.history.clone(), kept.record.paused),
        None => (KeyHistory::new(), None),
    };
    let verdict = history.observe(&list, now.timeline);
    let mut seen = history.seen().to_vec();
    if seen.len() > MAX_SEEN {
        seen.drain(..seen.len() - MAX_SEEN);
    }
    let latest = match (&verdict, &previous) {
        (Ok(()), _) => list
            .keys()
            .iter()
            .map(|key| (key.id, key.public, key.role.code()))
            .collect(),
        (Err(_), Some(kept)) => kept.record.latest.clone(),
        (Err(_), None) => return Learned::Nothing,
    };
    let record = DepositKeysRecord {
        seen,
        latest,
        inconsistent: history.stopped(),
        paused,
    };
    let shown: Vec<[u8; 32]> = list.keys().iter().map(|key| key.id).collect();
    let dropped: Vec<_> = held(device, origin)
        .await
        .into_iter()
        .filter(|(_, token)| history.stopped() || !shown.contains(&key_of(token)))
        .map(|(item, _)| (Table::Token, item))
        .collect();
    let _ = device
        .engine()
        .commit_device(
            vec![(
                Table::DepositKeys,
                peer_id(origin).to_vec(),
                TableValue::DepositKeys(record),
            )],
            dropped,
        )
        .await;
    device
        .inner
        .tokens
        .with(origin, |peer| peer.keys_at = Some(now.timeline));
    match verdict {
        Ok(()) => Learned::Keys(list),
        Err(_) => {
            device.report(Event::DepositPeerDistrusted {
                peer: origin.to_owned(),
                reason: "key_inconsistent".into(),
            });
            Learned::Inconsistent
        }
    }
}

/// How a device draws at a peer (ext-deposit-tokens.md, 3.1 Two ways in).
enum Way {
    /// With the grant the application handed over.
    Grant(Zeroizing<Vec<u8>>),
    /// As a writer of a space the peer hosts.
    Space(frasil_events::EventId),
}

/// Each token's nonce and blind.
type Draws = Zeroizing<Vec<([u8; 32], [u8; 32])>>;

/// A batch's nonces and blinds, from the device's randomness.
fn draws(device: &Device, count: usize) -> Result<Draws> {
    let platform = device.engine().platform();
    let mut draws = Zeroizing::new(Vec::with_capacity(count));
    while draws.len() < count {
        let nonce = platform.draw::<32>()?;
        let wide = platform.draw::<64>()?;
        if let Some(blind) = frasil_deposit_tokens::suite::scalar_from_wide(&wide) {
            draws.push((*nonce, *blind));
        }
    }
    Ok(draws)
}

/// Draws one batch at the peer (ext-deposit-tokens.md, 3.3 and 3.5): its
/// keys first, on a connection that presents nothing; then the request,
/// on another connection that presents the grant alone, or the space's
/// upload key alone. Returns whether the way to draw is spent: a grant
/// that a draw used or the peer refused for good.
async fn draw(device: &Device, origin: &str, way: &Way) -> bool {
    let list = match learn(device, origin).await {
        Learned::Keys(list) => list,
        Learned::Nothing | Learned::Inconsistent => return false,
    };
    let held = held(device, origin).await.len();
    let count = device.inner.tokens.batch.min(MAX_HELD.saturating_sub(held));
    if count == 0 {
        return false;
    }
    let Ok(draws) = draws(device, count) else {
        return false;
    };
    let Ok(batch) = Batch::new_with(list.issuing(), &draws) else {
        return false;
    };
    drop(draws);
    let Ok(mut bare) = device.bare(origin).await else {
        return false;
    };
    let request_draw = match way {
        Way::Grant(grant) => Draw::Grant(grant.to_vec()),
        Way::Space(space) => {
            if !matches!(bare.present_upload(device.engine(), *space).await, Ok(true)) {
                return false;
            }
            Draw::Space(space.0)
        }
    };
    let request = bare.next_request();
    let mut message = batch.request(request, request_draw).encode();
    let answer = bare.ask(&message, request).await;
    zeroize::Zeroize::zeroize(&mut message);
    drop(bare);
    let Ok(answer) = answer else {
        return false;
    };
    if answer.kind == frasil_transport::frame::MessageType::Refused {
        let code = frasil_transport::messages::Refused::read(&answer)
            .map(|refused| refused.code)
            .unwrap_or_default();
        if code == TokenClass::AllowanceExhausted.wire_name() {
            pause(device, origin).await;
        }
        // A grant refused for its own sake is spent; one refused for the
        // peer's state goes again.
        return matches!(way, Way::Grant(_))
            && matches!(
                code.as_str(),
                "ticket_refused"
                    | "ticket_expired"
                    | "ticket_used"
                    | "malformed"
                    | "library_closed"
                    | "no_library"
            );
    }
    match batch.finish(&answer.map, request) {
        Ok(tokens) => {
            let puts = tokens
                .iter()
                .map(|token| {
                    let token = TokenBytes::new(*token.as_bytes());
                    (
                        Table::Token,
                        token_item(origin, &token),
                        TableValue::Token(token),
                    )
                })
                .collect();
            let _ = device.engine().commit_device(puts, Vec::new()).await;
            true
        }
        Err(TokenClass::BadProof) => {
            device.report(Event::DepositPeerDistrusted {
                peer: origin.to_owned(),
                reason: "bad_proof".into(),
            });
            matches!(way, Way::Grant(_))
        }
        Err(_) => matches!(way, Way::Grant(_)),
    }
}

/// Pauses drawing at the peer for `allowance_window` from now
/// (ext-deposit-tokens.md, 3.11 A device without tokens).
async fn pause(device: &Device, origin: &str) {
    let (Some(mut kept), Ok(now)) = (kept(device, origin).await, device.engine().reading().await)
    else {
        return;
    };
    kept.record.paused = Some(now);
    let _ = device
        .engine()
        .commit_device(
            vec![(
                Table::DepositKeys,
                peer_id(origin).to_vec(),
                TableValue::DepositKeys(kept.record),
            )],
            Vec::new(),
        )
        .await;
}

/// The peers where the device has a way to draw now: those it holds a
/// grant for, and those that grant it the store right in a space, with
/// that space.
fn ways(device: &Device) -> Vec<(String, Option<frasil_events::EventId>)> {
    let mut ways: Vec<(String, Option<frasil_events::EventId>)> = device
        .inner
        .tokens
        .peers
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|(_, peer)| peer.grant.is_some())
        .map(|(origin, _)| (origin.clone(), None))
        .collect();
    for peer in device.peers() {
        if !peer.status().connected {
            continue;
        }
        let store = peer
            .handle()
            .status()
            .granted
            .into_iter()
            .find(|(_, rights)| rights.contains(&Right::Store))
            .map(|(space, _)| space);
        let url = origin(peer.url());
        match ways.iter_mut().find(|(known, _)| same_peer(known, &url)) {
            Some(way) => way.1 = way.1.or(store),
            None if store.is_some() => ways.push((url, store)),
            None => {}
        }
    }
    ways
}

/// Draws ahead of need where it is due (ext-deposit-tokens.md, 3.12): the
/// device's upkeep runs it.
pub(super) async fn upkeep(device: &Device) {
    let Ok(now) = device.engine().reading().await else {
        return;
    };
    for (origin, space) in ways(device) {
        let kept = kept(device, &origin).await;
        if kept
            .as_ref()
            .is_some_and(|kept| kept.history.stopped() || kept.paused(&now))
        {
            continue;
        }
        let issuing = kept.as_ref().and_then(Kept::issuing);
        let count = held(device, &origin)
            .await
            .iter()
            .filter(|(_, token)| Some(key_of(token)) == issuing)
            .count();
        let due = device.inner.tokens.with(&origin, |peer| {
            if count >= LOW_MARK || peer.drawing {
                peer.draw_at = None;
                return false;
            }
            match peer.draw_at {
                Some(at) if at <= now.timeline => {
                    peer.draw_at = None;
                    peer.drawing = true;
                    true
                }
                Some(_) => false,
                None => {
                    let random = device.engine().platform().nonce::<8>().unwrap_or([0; 8]);
                    peer.draw_at = Some(
                        now.timeline
                            .saturating_add(super::deposits::wait_with(DRAW_SPREAD, random)),
                    );
                    false
                }
            }
        });
        if !due {
            continue;
        }
        let grant = device.inner.tokens.with(&origin, |peer| peer.grant.clone());
        let way = match (grant, space) {
            (Some(grant), _) => Way::Grant(grant),
            (None, Some(space)) => Way::Space(space),
            (None, None) => {
                device
                    .inner
                    .tokens
                    .with(&origin, |peer| peer.drawing = false);
                continue;
            }
        };
        let spent = draw(device, &origin, &way).await;
        device.inner.tokens.with(&origin, |peer| {
            peer.drawing = false;
            if spent && matches!(way, Way::Grant(_)) {
                peer.grant = None;
            }
        });
    }
    // The keys of the peers whose tokens it holds, once an hour, so that
    // it drops those of a retired key (3.9).
    let mut origins: Vec<String> = device
        .peers()
        .iter()
        .map(|peer| origin(peer.url()))
        .collect();
    origins.extend(
        device
            .inner
            .tokens
            .peers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keys()
            .cloned(),
    );
    origins.sort();
    origins.dedup();
    for url in origins {
        let stale = device.inner.tokens.with(&url, |peer| {
            peer.keys_at
                .is_none_or(|at| now.timeline.saturating_sub(at) >= KEYS_EVERY)
        });
        if stale && !held(device, &url).await.is_empty() {
            let _ = learn(device, &url).await;
        }
    }
}

impl Device {
    /// Hands the device a deposit grant for the peer at `peer`, as the
    /// library's issuer gave it to the application (ext-deposit-tokens.md,
    /// 3.1.1 Getting a grant): opaque bytes, which the device never reads,
    /// stores at rest or shows. Within the hour, at a random moment, the
    /// device draws one batch with it at that peer, unless it holds enough
    /// tokens there already, and then forgets it; a grant draws once.
    /// A grant handed over again replaces one not used yet. The batch is
    /// [`Options::deposit_batch`](super::Options::deposit_batch), 16 by
    /// default: ask the issuer for grants of at least that many tokens.
    pub fn give_deposit_grant(&self, peer: &str, grant: Vec<u8>) {
        let grant = Zeroizing::new(grant);
        self.inner
            .tokens
            .with(&origin(peer), |state| state.grant = Some(grant));
    }

    /// How many deposit tokens the device holds for the peer at `peer`,
    /// and whether it draws there (ext-deposit-tokens.md, 3.12).
    pub async fn deposit_tokens(&self, peer: &str) -> DepositTokens {
        let peer = origin(peer);
        let kept = kept(self, &peer).await;
        let now = self.engine().reading().await.ok();
        let live = kept.as_ref().map(Kept::live).unwrap_or_default();
        let held = held(self, &peer)
            .await
            .iter()
            .filter(|(_, token)| live.contains(&key_of(token)))
            .count();
        DepositTokens {
            held,
            paused: matches!((&kept, &now), (Some(kept), Some(now)) if kept.paused(now)),
            distrusted: kept.is_some_and(|kept| kept.history.stopped()),
            grant: self.inner.tokens.with(&peer, |state| state.grant.is_some()),
        }
    }

    /// Trusts the deposit keys of the peer at `peer` again after
    /// [`Event::DepositPeerDistrusted`] with `key_inconsistent`
    /// (ext-deposit-tokens.md, 3.2 Learning a peer's keys): the device
    /// forgets the keys it saw there and learns them anew, as if it had
    /// never drawn there. Call it only when a person decided so, as when
    /// the peer's operator says it restored its keys from a backup: a
    /// peer that shows devices different keys can tell their deposits
    /// apart.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn trust_deposit_keys(&self, peer: &str) -> Result<()> {
        let peer = origin(peer);
        self.engine()
            .commit_device(
                Vec::new(),
                vec![(Table::DepositKeys, peer_id(&peer).to_vec())],
            )
            .await?;
        self.inner.tokens.with(&peer, |state| state.keys_at = None);
        Ok(())
    }
}
