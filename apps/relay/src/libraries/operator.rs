//! The operator's own issuer (ext-libraries.md, 1 Overview: the issuer is
//! a service the operator trusts, here the peer's operator itself), and
//! the default library it signs tickets for.
//!
//! A peer whose operator names no issuer (`FRASIL_LIBRARY_ISSUERS`) trusts
//! this one alone. Its Ed25519 seed is a secret: kept in the data
//! directory as `issuer.key`, 32 random bytes the peer writes at its first
//! start with mode 0600, as it keeps `iroh.key`; in memory only inside
//! [`OperatorIssuer`], which zeroizes it and never prints it. In a cluster
//! every node derives the same seed from the cluster key, as it derives the
//! key that seals the deposit keys, so that a ticket signed on any node,
//! or by `frasil-relay ticket` on any machine with the cluster's settings,
//! passes at every node, and no file has to be copied between them.
//!
//! The **default library** is the operator's library for the people it
//! gives access to: its ID is `operator:` and 16 hex digits of a hash of
//! the issuer's key, so that the same key always names the same library,
//! and two peers never name theirs alike. Its quota is the operator's
//! default for kind `operator` (`FRASIL_LIBRARY_QUOTAS`), and its deposit
//! allowance and share the operator's defaults, as for any library new to
//! the peer (section 2.4). [`crate::Peer::ensure_default_library`] records
//! it at the first start of a peer on one machine; in a cluster it is
//! created at its first ticket (section 3.2).
//!
//! [`issue`] is what `frasil-relay ticket` runs: a ticket of a purpose, for
//! the default library or another, within `ticket_lifetime`, as bytes, as
//! base64url text, and as a link to the peer's origin
//! ([`frasil_libraries::TicketLink`]).

use crate::PeerError;
use frasil_crypto::primitives::{ed25519_public, ed25519_sign, sha256};
use frasil_libraries::settings::TICKET_LIFETIME;
use frasil_libraries::ticket::{MAX_GRANT_TOKENS, encode_signed, signed_message};
use frasil_libraries::{LibraryId, Purpose, Ticket, TicketId, TicketLink};
use zeroize::Zeroizing;

/// The operator's issuer: its Ed25519 seed and public key.
#[derive(Clone)]
pub struct OperatorIssuer {
    seed: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl core::fmt::Debug for OperatorIssuer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OperatorIssuer")
            .field("public", &crate::util::hex(&self.public))
            .finish_non_exhaustive()
    }
}

/// Two issuers are the same when their public keys are: a seed gives one
/// key, so the seed is never compared.
impl PartialEq for OperatorIssuer {
    fn eq(&self, other: &Self) -> bool {
        self.public == other.public
    }
}

impl Eq for OperatorIssuer {}

impl OperatorIssuer {
    /// The issuer of an Ed25519 seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Zeroizing::new(seed);
        let public = ed25519_public(&seed);
        Self { seed, public }
    }

    /// The issuer every node of a cluster derives from the cluster key.
    pub fn from_cluster_key(cluster_key: &[u8; 32]) -> Self {
        let derived = frasil_crypto::primitives::hkdf(
            Some(b"frasil-relay/operator-issuer/v1"),
            cluster_key,
            b"issuer seed",
        );
        Self::from_seed(*derived)
    }

    /// The issuer's public key, which the peer trusts and each ticket
    /// carries as key 6.
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// The default library's ID: `operator:` and the first 8 bytes, in
    /// hex, of SHA-256 over a label and the public key.
    pub fn default_library(&self) -> LibraryId {
        let hash = sha256(&[b"frasil-relay/default-library/v1\0", &self.public[..]]);
        let id = format!("operator:{}", crate::util::hex(&hash[..8]));
        LibraryId::new(&id).expect("a library ID of 25 printable characters")
    }

    /// Signs a ticket (ext-libraries.md, 2.2 The library ticket): `id`
    /// drawn by the caller, `not_after` within `ticket_lifetime` of
    /// `now_wall`, and for purpose 4 `tokens`, 1 to 256.
    ///
    /// # Errors
    ///
    /// A lifetime of none or past `ticket_lifetime`, or a token count out
    /// of range or given for another purpose.
    pub fn sign_with(
        &self,
        request: &TicketRequest,
        library: &LibraryId,
        now_wall: u64,
        id: TicketId,
    ) -> Result<Vec<u8>, PeerError> {
        if request.lifetime == 0 || request.lifetime > TICKET_LIFETIME {
            return Err(PeerError(format!(
                "a ticket lives 1 to {TICKET_LIFETIME} seconds (ticket_lifetime)"
            )));
        }
        let tokens = match (request.purpose, request.tokens) {
            (Purpose::Deposit, Some(tokens)) if (1..=MAX_GRANT_TOKENS).contains(&tokens) => {
                Some(tokens)
            }
            (Purpose::Deposit, _) => {
                return Err(PeerError(format!(
                    "a deposit grant names 1 to {MAX_GRANT_TOKENS} tokens"
                )));
            }
            (_, None) => None,
            (_, Some(_)) => {
                return Err(PeerError("only a deposit grant names tokens".into()));
            }
        };
        let ticket = Ticket {
            library: library.clone(),
            id,
            purpose: request.purpose,
            not_after: now_wall.saturating_add(request.lifetime),
            issuer: self.public,
            tokens,
        }
        .encode();
        let signature = ed25519_sign(&self.seed, &signed_message(&ticket));
        Ok(encode_signed(&ticket, &signature))
    }
}

/// What `frasil-relay ticket` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketRequest {
    /// The library; the default library if none.
    pub library: Option<LibraryId>,
    /// The purpose: create, import, move, or a deposit grant.
    pub purpose: Purpose,
    /// For a deposit grant, its tokens.
    pub tokens: Option<u64>,
    /// Seconds from now to `not_after`, 1 to `ticket_lifetime`.
    pub lifetime: u64,
}

impl Default for TicketRequest {
    /// A ticket that creates a space in the default library, living
    /// `ticket_lifetime`.
    fn default() -> Self {
        Self {
            library: None,
            purpose: Purpose::Create,
            tokens: None,
            lifetime: TICKET_LIFETIME,
        }
    }
}

/// A ticket signed by the operator's issuer.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedTicket {
    /// The library it names.
    pub library: LibraryId,
    /// Its purpose.
    pub purpose: Purpose,
    /// Its `not_after`, in seconds since 1970.
    pub not_after: u64,
    /// The signed ticket's bytes, which the client takes as they are.
    pub ticket: Vec<u8>,
    /// The same bytes as a link to the peer's origin, when the peer has one
    /// (`FRASIL_ORIGIN`).
    pub link: Option<TicketLink>,
}

impl core::fmt::Debug for IssuedTicket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IssuedTicket")
            .field("library", &self.library)
            .field("purpose", &self.purpose)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl IssuedTicket {
    /// The ticket as text: base64url without padding, as the link carries
    /// it.
    pub fn text(&self) -> String {
        frasil_libraries::link::base64url::encode(&self.ticket)
    }
}

/// Issues a ticket as the operator: `frasil-relay ticket`'s work, with the
/// peer's wall clock at `now_wall` and the ticket's ID drawn at random. The
/// link names `origin`.
///
/// # Errors
///
/// As [`OperatorIssuer::sign_with`]; an origin a link cannot carry; or no
/// randomness for the ticket's ID.
pub fn issue(
    issuer: &OperatorIssuer,
    request: &TicketRequest,
    origin: Option<&str>,
    now_wall: u64,
) -> Result<IssuedTicket, PeerError> {
    let id = frasil_crypto::random_bytes::<16>()
        .map_err(|_| PeerError("no randomness for the ticket's ID".into()))?;
    issue_with(issuer, request, origin, now_wall, *id)
}

/// [`issue`] with the ticket's ID given.
///
/// # Errors
///
/// As [`issue`].
pub fn issue_with(
    issuer: &OperatorIssuer,
    request: &TicketRequest,
    origin: Option<&str>,
    now_wall: u64,
    id: TicketId,
) -> Result<IssuedTicket, PeerError> {
    let library = request
        .library
        .clone()
        .unwrap_or_else(|| issuer.default_library());
    let ticket = issuer.sign_with(request, &library, now_wall, id)?;
    let link = origin
        .map(|origin| {
            TicketLink::new(origin, &ticket)
                .map_err(|_| PeerError(format!("{origin} is no origin a link can carry")))
        })
        .transpose()?;
    Ok(IssuedTicket {
        library,
        purpose: request.purpose,
        not_after: now_wall.saturating_add(request.lifetime),
        ticket,
        link,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_libraries::SignedTicket;

    #[test]
    fn the_seed_is_never_printed_and_the_default_library_follows_the_key() {
        let issuer = OperatorIssuer::from_seed([3; 32]);
        let printed = format!("{issuer:?}");
        assert!(!printed.contains("0303"), "{printed}");
        assert_eq!(issuer.default_library(), issuer.default_library());
        let id = issuer.default_library();
        assert!(id.as_str().starts_with("operator:"));
        assert_eq!(id.as_str().len(), "operator:".len() + 16);
        assert_ne!(
            OperatorIssuer::from_seed([4; 32]).default_library(),
            id,
            "another key names another library"
        );
        let a = OperatorIssuer::from_cluster_key(&[7; 32]);
        assert_eq!(a, OperatorIssuer::from_cluster_key(&[7; 32]));
        assert_ne!(a, OperatorIssuer::from_cluster_key(&[8; 32]));
    }

    #[test]
    fn a_ticket_reads_as_the_request_asked() {
        let issuer = OperatorIssuer::from_seed([3; 32]);
        let now = 1_800_000_000;
        let issued = issue_with(
            &issuer,
            &TicketRequest::default(),
            Some("https://peer.example.org"),
            now,
            [9; 16],
        )
        .unwrap();
        let read = SignedTicket::decode(&issued.ticket).unwrap().ticket;
        assert_eq!(read.library, issuer.default_library());
        assert_eq!(read.purpose, Purpose::Create);
        assert_eq!(read.not_after, now + TICKET_LIFETIME);
        assert_eq!(read.issuer, *issuer.public());
        let link = issued.link.clone().unwrap();
        assert_eq!(link.origin(), "https://peer.example.org");
        assert_eq!(link.ticket(), &issued.ticket[..]);
        assert_eq!(
            link.to_string(),
            format!("https://peer.example.org/#library-ticket={}", issued.text())
        );
        let grant = TicketRequest {
            library: Some(LibraryId::new("operator:team").unwrap()),
            purpose: Purpose::Deposit,
            tokens: Some(32),
            lifetime: 3600,
        };
        let issued = issue_with(&issuer, &grant, None, now, [8; 16]).unwrap();
        assert!(issued.link.is_none());
        let read = SignedTicket::decode_with_grants(&issued.ticket, true)
            .unwrap()
            .ticket;
        assert_eq!((read.tokens, read.not_after), (Some(32), now + 3600));
        for bad in [
            TicketRequest {
                lifetime: TICKET_LIFETIME + 1,
                ..TicketRequest::default()
            },
            TicketRequest {
                lifetime: 0,
                ..TicketRequest::default()
            },
            TicketRequest {
                tokens: Some(1),
                ..TicketRequest::default()
            },
            TicketRequest {
                tokens: Some(257),
                ..grant.clone()
            },
            TicketRequest {
                tokens: None,
                ..grant.clone()
            },
        ] {
            assert!(
                issue_with(&issuer, &bad, None, now, [1; 16]).is_err(),
                "{bad:?}"
            );
        }
        assert!(
            issue_with(
                &issuer,
                &TicketRequest::default(),
                Some("peer"),
                now,
                [1; 16]
            )
            .is_err()
        );
    }
}
