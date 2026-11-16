//! The peer's side: issuing and redeeming (ext-deposit-tokens.md, 3.4
//! Issuing and 3.7 Redeeming), as pure functions over the state the peer
//! keeps (2.7 What a peer keeps), which it reads through
//! [`IssuanceRecords`] and [`SpentTokens`] and updates from what each
//! function returns, in one step.
//!
//! ```text
//! A TokenRequest, in order:
//!  1. Keys 0, 1, 3 and 4, and exactly one of 2 and 5, and no other;
//!     request unsigned; grant a byte string of at most 512 bytes, or
//!     space of 32 bytes; key ID of 32 bytes; blinded an array of 1
//!     to 256 byte strings of 32 bytes.                             else Malformed
//!  2. Each blinded element passes DeserializeElement.              else Malformed
//! a grant draw:
//!  3. ext-libraries.md's check_ticket(grant, 4).                   else its class
//!  4. len(blinded) <= the grant's tokens.                          else TicketRefused
//! a space draw:
//!  5. The connection holds the store right for space.              else CredentialRefused
//!  6. The space is attached to a library at this peer.             else NoLibrary
//!  7. The library's state is open.                                 else LibraryClosed
//! either:
//!  8. key ID names the peer's issuing key.                         else TokenExpired
//!  9. The library has drawn fewer than deposit_allowance tokens in
//!     its current window.                                          else AllowanceExhausted
//! 10. For a space draw: the space has drawn fewer than space_share
//!     tokens in that window.                                       else AllowanceExhausted
//!
//! A MailboxPut of kind 3 with key 7, or a POST of kind 3 with a token, in order:
//! 1. Exactly keys 0, 1, 2, 3, 6 and 7; address of 32 bytes; token
//!    of 129 bytes. On the server binding: the header reads as one
//!    token of 129 bytes in lowercase hex.                          else Malformed
//! 2. Byte 0 of the token is 0x01.                                  else UnsupportedVersion
//! 3. The item is at most 262,144 bytes.                            else TooLarge
//! 4. The token's key ID names a live key of this peer.             else TokenExpired
//! 5. The authenticator equals Evaluate(skS, input), compared in
//!    constant time.                                                else TokenRefused
//! 6. The token is not spent, or it was spent by a deposit of this
//!    address with these item bytes.                                else TokenSpent
//! 7. The token budget has room for the item (section 3.8).         else Busy
//! ```

use frasil_base::ErrorClass;
use frasil_base::cbor::Map;
use frasil_crypto::primitives::sha256;
use frasil_libraries::Purpose;
use frasil_libraries::{
    LibraryId, LibraryState, PeerRecords, TicketId, TrustedIssuers, check_ticket,
};
use zeroize::Zeroizing;

use crate::budget::Mailboxes;
use crate::errors::{TokenClass, malformed};
use crate::key::{DepositKey, KeyId};
use crate::messages::{Draw, TokenIssue, TokenPut, TokenRequest};
use crate::rotation::KeyShard;
use crate::settings::{ALLOWANCE_WINDOW, DepositSettings};
use crate::suite::{self, ELEMENT_BYTES, SCALAR_BYTES, SuiteError};
use crate::token::{NONCE_BYTES, TOKEN_VERSION, Token};

/// A library's current allowance window as the peer keeps it: its start on
/// the library's timeline, in seconds, and the tokens drawn in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Window {
    /// The reading at which the window opened.
    pub start: u64,
    /// The tokens drawn in it, by grant draws and space draws alike.
    pub drawn: u64,
}

/// What section 3.4 reads of what a peer keeps, besides what
/// `check_ticket` reads.
pub trait IssuanceRecords: PeerRecords {
    /// The library a hosted space is billed to, or `None` for a space
    /// attached to no library.
    fn space_library(&self, space: &[u8; 32]) -> Option<LibraryId>;

    /// A library's `deposit_allowance` and `space_share`; a library the
    /// peer does not know yet has the defaults.
    fn deposit_settings(&self, library: &LibraryId) -> DepositSettings;

    /// The library's window as last kept, if one opened.
    fn window(&self, library: &LibraryId) -> Option<Window>;

    /// The tokens a space's writers drew by space draws in the window
    /// [`window`](Self::window) returns.
    fn space_drawn(&self, library: &LibraryId, space: &[u8; 32]) -> u64;
}

/// What a request draws against: the grant's ID and `not_after`, which the
/// peer keeps as used, or the space whose share counts it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Drawn {
    /// A grant draw.
    Grant {
        /// The grant's ID, used once the batch is issued.
        id: TicketId,
        /// Its `not_after`, which the peer keeps the ID until.
        not_after: u64,
    },
    /// A space draw.
    Space([u8; 32]),
}

/// A request that passed section 3.4's checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    /// Key 1.
    pub request: u64,
    /// The library the batch counts against.
    pub library: LibraryId,
    /// The grant or the space.
    pub drawn: Drawn,
    /// The blinded elements, as sent.
    pub blinded: Vec<[u8; ELEMENT_BYTES]>,
    /// `m`: the elements the peer evaluates, the first ones.
    pub count: usize,
    /// The window as the first point of section 3.4 opens it: kept, or new
    /// at this reading.
    pub window: Window,
    /// The tokens the space drew in that window before, for a space draw.
    pub space_drawn: u64,
}

/// A batch issued: the answer, and what the peer records in the same
/// step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issued {
    /// The `TokenIssue`.
    pub answer: TokenIssue,
    /// The library.
    pub library: LibraryId,
    /// The library's window after the batch: its start and the tokens
    /// drawn in it.
    pub window: Window,
    /// For a space draw, the space and the tokens it has drawn in the
    /// window after the batch.
    pub space: Option<([u8; 32], u64)>,
    /// For a grant draw, the grant's ID and `not_after`, to keep as used.
    pub grant: Option<(TicketId, u64)>,
}

/// Section 3.4's checks of a `TokenRequest`, in order.
///
/// `store_right` says whether the connection holds the store right for a
/// space (transport.md, 3.11); `now_wall` is the peer's wall clock, for
/// `check_ticket`; `reading` is the library's timeline, in seconds, on its
/// lower estimate. `records` must say the peer implements this extension
/// ([`PeerRecords::deposit_tokens`]), or a grant is `Malformed`.
///
/// # Errors
///
/// The class of the first step that refuses.
pub fn check_request<R: IssuanceRecords + ?Sized>(
    map: &Map,
    store_right: impl Fn(&[u8; 32]) -> bool,
    now_wall: Option<u64>,
    reading: u64,
    issuers: &TrustedIssuers,
    keys: &KeyShard,
    records: &R,
) -> Result<Approved, TokenClass> {
    // 1.
    let request = TokenRequest::read(map)?;
    // 2.
    for element in &request.blinded {
        suite::deserialize_element(element).map_err(|_| malformed())?;
    }
    let (library, drawn) = match &request.draw {
        Draw::Grant(grant) => {
            // 3.
            let ticket = check_ticket(grant, Purpose::Deposit, now_wall, issuers, records)?;
            // 4.
            if request.blinded.len() as u64 > ticket.tokens.unwrap_or(0) {
                return Err(TokenClass::TicketRefused);
            }
            let drawn = Drawn::Grant {
                id: ticket.id,
                not_after: ticket.not_after,
            };
            (ticket.library, drawn)
        }
        Draw::Space(space) => {
            // 5.
            if !store_right(space) {
                return Err(TokenClass::CredentialRefused);
            }
            // 6.
            let library = records.space_library(space).ok_or(TokenClass::NoLibrary)?;
            // 7.
            if records.library_state(&library).unwrap_or_default() != LibraryState::Open {
                return Err(TokenClass::LibraryClosed);
            }
            (library, Drawn::Space(*space))
        }
    };
    // 8.
    if keys.issuing().map(DepositKey::id) != Some(&request.key_id) {
        return Err(TokenClass::TokenExpired);
    }
    // 9 and 10, on the window as section 3.4's first point opens it.
    let settings = records.deposit_settings(&library);
    let kept = records
        .window(&library)
        .filter(|w| reading.saturating_sub(w.start) < ALLOWANCE_WINDOW);
    let window = kept.unwrap_or(Window {
        start: reading,
        drawn: 0,
    });
    if window.drawn >= settings.deposit_allowance {
        return Err(TokenClass::AllowanceExhausted);
    }
    let mut left = settings.deposit_allowance - window.drawn;
    let mut space_drawn = 0;
    if let Drawn::Space(space) = &drawn {
        space_drawn = kept.map_or(0, |_| records.space_drawn(&library, space));
        if space_drawn >= settings.space_share {
            return Err(TokenClass::AllowanceExhausted);
        }
        left = left.min(settings.space_share - space_drawn);
    }
    let count = request
        .blinded
        .len()
        .min(usize::try_from(left).unwrap_or(usize::MAX));
    Ok(Approved {
        request: request.request,
        library,
        drawn,
        blinded: request.blinded,
        count,
        window,
        space_drawn,
    })
}

/// Section 3.4's step that issues, with the proof's random scalar given:
/// evaluates the first `m` elements under the issuing key with one proof,
/// and says what the peer records with the answer, in one step: the grant
/// used, and `m` tokens drawn in the library's window and, for a space
/// draw, in the space's share.
///
/// # Errors
///
/// `Malformed` for a proof scalar that is not a canonical, non-zero scalar.
pub fn issue_with(
    approved: &Approved,
    key: &DepositKey,
    proof_scalar: &[u8; SCALAR_BYTES],
) -> Result<Issued, TokenClass> {
    let (evaluated, proof) = key
        .evaluate_batch_with(&approved.blinded[..approved.count], proof_scalar)
        .map_err(|_| malformed())?;
    let count = approved.count as u64;
    Ok(Issued {
        answer: TokenIssue {
            request: approved.request,
            evaluated,
            proof,
        },
        library: approved.library.clone(),
        window: Window {
            start: approved.window.start,
            drawn: approved.window.drawn + count,
        },
        space: match approved.drawn {
            Drawn::Space(space) => Some((space, approved.space_drawn + count)),
            Drawn::Grant { .. } => None,
        },
        grant: match approved.drawn {
            Drawn::Grant { id, not_after } => Some((id, not_after)),
            Drawn::Space(_) => None,
        },
    })
}

/// [`issue_with`], the proof's scalar drawn from the platform.
///
/// # Errors
///
/// `Busy` when the platform has no working source of randomness, so the
/// peer cannot answer now; nothing is recorded then.
pub fn issue(approved: &Approved, key: &DepositKey) -> Result<Issued, TokenClass> {
    match suite::random_scalar() {
        Ok(scalar) => issue_with(approved, key, &scalar),
        Err(SuiteError::NoRandomness) => Err(TokenClass::Busy),
        Err(_) => Err(malformed()),
    }
}

/// A deposit paid with a token, read by section 3.7's step 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenDeposit {
    /// Key 1 of the `MailboxPut`; `None` on the server binding.
    pub request: Option<u64>,
    /// The device mailbox's address.
    pub address: [u8; 32],
    /// The item.
    pub item: Vec<u8>,
    /// The token.
    pub token: Token,
}

impl TokenDeposit {
    /// Step 1 on the WebSocket and the iroh binding: a `MailboxPut` of kind
    /// 3 with key 7.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn read_put(map: &Map) -> Result<Self, TokenClass> {
        let put = TokenPut::read(map)?;
        Ok(Self {
            request: Some(put.request),
            address: put.address,
            item: put.item,
            token: put.token,
        })
    }

    /// Step 1 on the server binding: `POST /frasil/p1/mailbox/3/{address}`
    /// with this body and this `Authorization` value.
    ///
    /// # Errors
    ///
    /// `Malformed` for a value that does not read as one token.
    pub fn read_post(
        address: [u8; 32],
        item: Vec<u8>,
        authorization: &str,
    ) -> Result<Self, TokenClass> {
        Ok(Self {
            request: None,
            address,
            item,
            token: Token::from_header(authorization)?,
        })
    }

    /// `SHA-256(address || item)`: what the spent-token record keeps of
    /// the deposit.
    pub fn digest(&self) -> [u8; 32] {
        sha256(&[&self.address, &self.item])
    }
}

/// A spent token's record: the deposit it paid for and the item ID the
/// peer assigned it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SpentRecord {
    /// `SHA-256(address || item)` of the deposit.
    pub deposit: [u8; 32],
    /// The item ID.
    pub item: [u8; 16],
}

/// What section 3.7, step 6, reads: the spent-token records, by key ID and
/// nonce, until the key retires.
pub trait SpentTokens {
    /// The record of a spent token, if it is spent.
    fn spent(&self, key_id: &KeyId, nonce: &[u8; NONCE_BYTES]) -> Option<SpentRecord>;
}

/// What section 3.7, step 7, reads: whether the token budget has room for
/// an item in a mailbox (section 3.8).
pub trait TokenRoom {
    /// Whether a token deposit of `bytes` into the mailbox at `address`
    /// has room, with the evictions section 3.8 allows.
    fn room(&self, address: &[u8; 32], bytes: u64) -> bool;
}

impl TokenRoom for Mailboxes {
    fn room(&self, address: &[u8; 32], bytes: u64) -> bool {
        Mailboxes::room(self, address, bytes)
    }
}

/// What a deposit that passed section 3.7's checks does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redemption {
    /// The token was spent by this very deposit: answered as the first
    /// was, with its item ID, and nothing more is kept.
    Repeat {
        /// The item ID the first deposit was given.
        item: [u8; 16],
    },
    /// The peer keeps the item and records the token spent, in one step.
    Keep {
        /// The token's key ID.
        key_id: KeyId,
        /// The token's nonce.
        nonce: Zeroizing<[u8; NONCE_BYTES]>,
        /// `SHA-256(address || item)`, for the record.
        deposit: [u8; 32],
    },
}

/// Section 3.7's steps 2 to 7, in order, of a deposit step 1 read.
///
/// # Errors
///
/// The class of the first step that refuses.
pub fn redeem(
    deposit: &TokenDeposit,
    keys: &KeyShard,
    spent: &(impl SpentTokens + ?Sized),
    budget: &(impl TokenRoom + ?Sized),
) -> Result<Redemption, TokenClass> {
    let token = &deposit.token;
    // 2.
    if token.version() != TOKEN_VERSION {
        return Err(ErrorClass::UnsupportedVersion.into());
    }
    // 3.
    if deposit.item.len() > crate::messages::MAX_ITEM_BYTES {
        return Err(ErrorClass::TooLarge.into());
    }
    // 4.
    let key_id = token.key_id();
    let key = keys.live(&key_id).ok_or(TokenClass::TokenExpired)?;
    // 5.
    if !key.verify(&token.input(), token.authenticator()) {
        return Err(TokenClass::TokenRefused);
    }
    // 6.
    let nonce = token.nonce();
    let digest = deposit.digest();
    if let Some(record) = spent.spent(&key_id, &nonce) {
        if record.deposit != digest {
            return Err(TokenClass::TokenSpent);
        }
        return Ok(Redemption::Repeat { item: record.item });
    }
    // 7.
    if !budget.room(&deposit.address, deposit.item.len() as u64) {
        return Err(TokenClass::Busy);
    }
    Ok(Redemption::Keep {
        key_id,
        nonce: Zeroizing::new(nonce),
        deposit: digest,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use frasil_base::time::Reading;

    use super::*;
    use crate::device::{Batch, KeyList};
    use crate::rotation::LiveKey;
    use crate::settings::TOKEN_PERIOD;

    const SPACE: [u8; 32] = [5; 32];

    struct Records {
        settings: DepositSettings,
        window: Option<Window>,
        shares: BTreeMap<[u8; 32], u64>,
    }

    impl PeerRecords for Records {
        fn ticket_used(&self, _: &TicketId) -> bool {
            false
        }

        fn library_state(&self, _: &LibraryId) -> Option<LibraryState> {
            Some(LibraryState::Open)
        }

        fn deposit_tokens(&self) -> bool {
            true
        }
    }

    impl IssuanceRecords for Records {
        fn space_library(&self, _: &[u8; 32]) -> Option<LibraryId> {
            Some(LibraryId::new("project:1").unwrap())
        }

        fn deposit_settings(&self, _: &LibraryId) -> DepositSettings {
            self.settings
        }

        fn window(&self, _: &LibraryId) -> Option<Window> {
            self.window
        }

        fn space_drawn(&self, _: &LibraryId, space: &[u8; 32]) -> u64 {
            self.shares.get(space).copied().unwrap_or(0)
        }
    }

    fn shard() -> KeyShard {
        let began = Reading {
            timeline: 0,
            wall: None,
            run: 1,
        };
        let key = DepositKey::from_seed(&[1; 32]);
        KeyShard::from_keys(TOKEN_PERIOD, vec![LiveKey { key, began }]).unwrap()
    }

    fn request(keys: &KeyShard, count: usize) -> Map {
        let issuing = keys.issuing().unwrap();
        let list =
            KeyList::check(&[(issuing.id().as_slice(), issuing.public().as_slice(), 1)]).unwrap();
        let draws: Vec<_> = (0..count)
            .map(|i| ([i as u8; 32], [i as u8 + 1; 32]))
            .collect();
        let batch = Batch::new_with(list.issuing(), &draws).unwrap();
        let bytes = batch.request(1, Draw::Space(SPACE)).encode();
        frasil_base::cbor::decode(&bytes)
            .unwrap()
            .as_map()
            .unwrap()
            .clone()
    }

    fn check(records: &Records, count: usize, reading: u64) -> Result<Approved, TokenClass> {
        let keys = shard();
        check_request(
            &request(&keys, count),
            |_| true,
            None,
            reading,
            &TrustedIssuers::default(),
            &keys,
            records,
        )
    }

    fn records(allowance: u64, share: u64, window: Option<(u64, u64)>, drawn: u64) -> Records {
        Records {
            settings: DepositSettings {
                deposit_allowance: allowance,
                space_share: share,
            },
            window: window.map(|(start, drawn)| Window { start, drawn }),
            shares: BTreeMap::from([(SPACE, drawn)]),
        }
    }

    #[test]
    fn the_window_opens_afresh_at_its_end_and_not_before() {
        // A full allowance a second before the window ends; at its end, a
        // new window, its shares begun afresh.
        let full = records(10, 10, Some((100, 10)), 10);
        assert_eq!(
            check(&full, 1, 100 + ALLOWANCE_WINDOW - 1).unwrap_err(),
            TokenClass::AllowanceExhausted
        );
        let approved = check(&full, 3, 100 + ALLOWANCE_WINDOW).unwrap();
        assert_eq!(approved.window.start, 100 + ALLOWANCE_WINDOW);
        assert_eq!((approved.window.drawn, approved.space_drawn), (0, 0));
        assert_eq!(approved.count, 3);
        // No window yet opens one at this reading.
        let fresh = check(&records(10, 10, None, 0), 1, 7).unwrap();
        assert_eq!(fresh.window, Window { start: 7, drawn: 0 });
    }

    #[test]
    fn the_batch_is_cut_to_the_smaller_of_what_is_left() {
        // 6 left of the allowance, 4 of the share: 4.
        let r = records(64, 16, Some((0, 58)), 12);
        assert_eq!(check(&r, 10, 1).unwrap().count, 4);
        // 2 left of the allowance, 16 of the share: 2.
        let r = records(64, 16, Some((0, 62)), 0);
        assert_eq!(check(&r, 10, 1).unwrap().count, 2);
        // A share of 0: a space draws nothing without a grant.
        let r = records(64, 0, None, 0);
        assert_eq!(check(&r, 1, 1).unwrap_err(), TokenClass::AllowanceExhausted);
        // An allowance of 0: nothing at all.
        let r = records(0, 0, None, 0);
        assert_eq!(check(&r, 1, 1).unwrap_err(), TokenClass::AllowanceExhausted);
    }

    #[test]
    fn issuing_counts_the_batch_in_the_window_and_the_share() {
        let keys = shard();
        let r = records(64, 16, Some((0, 10)), 3);
        let approved = check(&r, 5, 1).unwrap();
        let issued = issue_with(&approved, keys.issuing().unwrap(), &[9; 32]).unwrap();
        assert_eq!(
            issued.window,
            Window {
                start: 0,
                drawn: 15
            }
        );
        assert_eq!(issued.space, Some((SPACE, 8)));
        assert_eq!(issued.grant, None);
        assert_eq!(issued.answer.evaluated.len(), 5);
        // A proof scalar that is not a canonical scalar is refused.
        assert!(issue_with(&approved, keys.issuing().unwrap(), &[0xff; 32]).is_err());
        assert!(issue(&approved, keys.issuing().unwrap()).is_ok());
    }

    struct NoneSpent;

    impl SpentTokens for NoneSpent {
        fn spent(&self, _: &KeyId, _: &[u8; NONCE_BYTES]) -> Option<SpentRecord> {
            None
        }
    }

    struct Room(bool);

    impl TokenRoom for Room {
        fn room(&self, _: &[u8; 32], _: u64) -> bool {
            self.0
        }
    }

    #[test]
    fn redemption_checks_run_in_order() {
        let keys = shard();
        let key = keys.issuing().unwrap();
        let nonce = [4; 32];
        let input = crate::token::token_input(key.id(), &nonce);
        let token = Token::new(key.id(), &nonce, &key.evaluate(&input).unwrap());
        let deposit = |item: usize, token: Token| TokenDeposit {
            request: Some(1),
            address: [8; 32],
            item: vec![0; item],
            token,
        };
        assert!(matches!(
            redeem(&deposit(10, token.clone()), &keys, &NoneSpent, &Room(true)),
            Ok(Redemption::Keep { .. })
        ));
        assert_eq!(
            redeem(&deposit(10, token.clone()), &keys, &NoneSpent, &Room(false)),
            Err(TokenClass::Busy)
        );
        // Version 2 and an item too large: the version first.
        let mut v2 = *token.as_bytes();
        v2[0] = 2;
        let v2 = Token::from_bytes(&v2).unwrap();
        assert_eq!(
            redeem(&deposit(1 << 20, v2), &keys, &NoneSpent, &Room(true)),
            Err(ErrorClass::UnsupportedVersion.into())
        );
        // Too large, before an unknown key.
        let unknown = Token::new(&[0; 32], &nonce, &[0; 64]);
        assert_eq!(
            redeem(
                &deposit(1 << 20, unknown.clone()),
                &keys,
                &NoneSpent,
                &Room(true)
            ),
            Err(ErrorClass::TooLarge.into())
        );
        assert_eq!(
            redeem(&deposit(10, unknown), &keys, &NoneSpent, &Room(true)),
            Err(TokenClass::TokenExpired)
        );
        let forged = Token::new(key.id(), &nonce, &[0; 64]);
        assert_eq!(
            redeem(&deposit(10, forged), &keys, &NoneSpent, &Room(true)),
            Err(TokenClass::TokenRefused)
        );
    }
}
