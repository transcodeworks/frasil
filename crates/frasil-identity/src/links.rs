//! Account links (identity.md, "Account links" and "Checking an account
//! link").
//!
//! ```text
//! statement = "frasil/account-link/v1" || field(origin) || field(subject)
//!             || field(person_id) || field(nonce)
//! link      = CBOR map {0: 1, 1: origin (text), 2: subject (text), 3: person_id (bytes 32),
//!                       4: nonce (bytes 16), 5: signer (bytes 64), 6: signature (bytes 64)}
//! link ID   = SHA-256(statement)
//! unlink    = CBOR map {0: 1, 1: link ID (bytes 32), 2: signer (bytes 64), 3: signature (bytes 64)}
//! ```
//!
//! `signer` is the signer's `ed || kc` (crypto.md, "A device's keys"): the
//! Ed25519 key that signs, then the keys commitment, from which a checker
//! computes the signer's device ID.
//!
//! A link is signed under scheme 0 by an active device or passkey member of
//! the person, over `statement`; an unlink under scheme 0 over
//! `"frasil/account-unlink/v1" || field(link ID)`. An account's server, which
//! holds no list, checks a link with [`AccountLink::verify`]; a client checks
//! it against the person's merged list with [`check_link`].

use crate::IdentityClass;
use crate::keys::Kind;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_base::notation::push_field;
use frasil_crypto::device::{DeviceId, Signatory};
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::labels::{ACCOUNT_LINK, ACCOUNT_UNLINK};
use frasil_crypto::primitives::sha256;
use frasil_crypto::schemes::{Scheme, Signer, ed25519_verify_strict};

/// The version of a link and of an unlink, key 0.
pub const VERSION: u64 = 1;

/// The longest origin or subject, in bytes of UTF-8.
pub const MAX_TEXT_BYTES: usize = 256;

/// What a list says of the keys a link names: the person's merged list, as
/// "Checking an account link" reads it.
pub trait ListView {
    /// The list's person ID.
    fn person_id(&self) -> &[u8; 32];

    /// The kind of the active list member of this device ID, or `None` if
    /// no active list member has it.
    fn active_kind(&self, device: &DeviceId) -> Option<Kind>;

    /// The kind of the list member of this device ID that a valid `add` of
    /// the list ever named, revoked or not, or `None` if none did.
    fn listed_kind(&self, device: &DeviceId) -> Option<Kind>;
}

/// Whether an origin or subject follows the rules: 1 to 256 bytes of UTF-8,
/// not only white space, with no control character (Unicode category Cc).
pub fn text_ok(text: &str) -> bool {
    frasil_base::notation::text_ok(text, MAX_TEXT_BYTES)
}

/// The statement a link's signer signs.
pub fn statement(origin: &str, subject: &str, person_id: &[u8; 32], nonce: &[u8; 16]) -> Vec<u8> {
    let mut out = ACCOUNT_LINK.to_vec();
    push_field(&mut out, origin.as_bytes());
    push_field(&mut out, subject.as_bytes());
    push_field(&mut out, person_id);
    push_field(&mut out, nonce);
    out
}

/// The statement an unlink's signer signs: `"frasil/account-unlink/v1" ||
/// field(link ID)`.
pub fn unlink_statement(link_id: &[u8; 32]) -> Vec<u8> {
    let mut out = ACCOUNT_UNLINK.to_vec();
    push_field(&mut out, link_id);
    out
}

/// An account link: from a person ID to a subject at an identity provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLink {
    /// The identity provider's origin.
    pub origin: String,
    /// The provider's subject for the person.
    pub subject: String,
    /// The person ID.
    pub person_id: [u8; 32],
    /// A random nonce, so that a link signed again after an unlink is a new
    /// link.
    pub nonce: [u8; 16],
    /// The signer's `ed || kc`.
    pub signer: Signatory,
    /// The scheme-0 signature over [`statement`].
    pub signature: [u8; 64],
}

impl AccountLink {
    /// Signs a link with an active device's or passkey member's keys. The
    /// caller draws `nonce` from its random source.
    ///
    /// # Errors
    ///
    /// `Malformed` if the origin or the subject breaks the text rules.
    pub fn sign(
        origin: &str,
        subject: &str,
        person_id: &[u8; 32],
        nonce: &[u8; 16],
        signer: &Signer,
    ) -> Result<Self, IdentityClass> {
        if !text_ok(origin) || !text_ok(subject) {
            return Err(IdentityClass::Shared(ErrorClass::Malformed));
        }
        let signature = signer.sign(
            Scheme::Ed25519,
            &statement(origin, subject, person_id, nonce),
        );
        Ok(Self {
            origin: origin.to_owned(),
            subject: subject.to_owned(),
            person_id: *person_id,
            nonce: *nonce,
            signer: signer.signatory(),
            signature: signature
                .try_into()
                .expect("a scheme-0 signature is 64 bytes"),
        })
    }

    /// The statement the link's signature covers.
    pub fn statement(&self) -> Vec<u8> {
        statement(&self.origin, &self.subject, &self.person_id, &self.nonce)
    }

    /// The link ID: `SHA-256(statement)`.
    pub fn id(&self) -> [u8; 32] {
        sha256(&[&self.statement()])
    }

    /// The link's one encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(0, Value::Unsigned(VERSION));
        map.insert(1, Value::from(self.origin.as_str()));
        map.insert(2, Value::from(self.subject.as_str()));
        map.insert(3, Value::from(self.person_id));
        map.insert(4, Value::from(self.nonce));
        map.insert(5, Value::from(self.signer.to_bytes()));
        map.insert(6, Value::from(self.signature));
        Value::Map(map).encode()
    }

    /// Step 1 of `check_link`: the link is the map, deterministic, with
    /// exactly its keys, version 1, and its types, lengths and texts.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityClass> {
        decode_link(bytes).map_err(|_| IdentityClass::Shared(ErrorClass::Malformed))
    }

    /// Steps 1 to 3 of `check_link`, what an account's server, which holds
    /// no list, checks: the shape, then the signer's Ed25519 key passes
    /// `ed25519_valid`, then the signature verifies strictly over the
    /// statement under it.
    ///
    /// # Errors
    ///
    /// `Malformed`, `InvalidKey` and `BadSignature`, in that order.
    pub fn verify(bytes: &[u8]) -> Result<Self, IdentityClass> {
        let link = Self::decode(bytes)?;
        ed25519_valid(&link.signer.ed.0)?;
        if !ed25519_verify_strict(&link.signer.ed.0, &link.statement(), &link.signature) {
            return Err(IdentityClass::Shared(ErrorClass::BadSignature));
        }
        Ok(link)
    }
}

fn decode_link(bytes: &[u8]) -> Result<AccountLink, cbor::Malformed> {
    let value = cbor::decode(bytes)?;
    let map = value.as_map()?;
    if map.len() != 7 || !(0..7).all(|key| map.contains_key(&key)) {
        return Err(cbor::Malformed);
    }
    if map[&0].as_unsigned()? != VERSION {
        return Err(cbor::Malformed);
    }
    let origin = map[&1].as_text()?;
    let subject = map[&2].as_text()?;
    if !text_ok(origin) || !text_ok(subject) {
        return Err(cbor::Malformed);
    }
    Ok(AccountLink {
        origin: origin.to_owned(),
        subject: subject.to_owned(),
        person_id: map[&3].as_byte_array()?,
        nonce: map[&4].as_byte_array()?,
        signer: Signatory::from_bytes(map[&5].as_bytes()?).map_err(|_| cbor::Malformed)?,
        signature: map[&6].as_byte_array()?,
    })
}

/// An unlink: a signed statement that ends a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unlink {
    /// The ID of the link it ends.
    pub link_id: [u8; 32],
    /// The signer's `ed || kc`.
    pub signer: Signatory,
    /// The scheme-0 signature over [`unlink_statement`].
    pub signature: [u8; 64],
}

impl Unlink {
    /// Signs an unlink of `link_id` with a device's or passkey member's keys.
    pub fn sign(link_id: &[u8; 32], signer: &Signer) -> Self {
        let signature = signer.sign(Scheme::Ed25519, &unlink_statement(link_id));
        Self {
            link_id: *link_id,
            signer: signer.signatory(),
            signature: signature
                .try_into()
                .expect("a scheme-0 signature is 64 bytes"),
        }
    }

    /// The unlink's one encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut map = Map::new();
        map.insert(0, Value::Unsigned(VERSION));
        map.insert(1, Value::from(self.link_id));
        map.insert(2, Value::from(self.signer.to_bytes()));
        map.insert(3, Value::from(self.signature));
        Value::Map(map).encode()
    }

    /// Reads an unlink: the map, deterministic, with exactly its keys,
    /// version 1, and its types and lengths.
    ///
    /// # Errors
    ///
    /// `Malformed`.
    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityClass> {
        decode_unlink(bytes).map_err(|_| IdentityClass::Shared(ErrorClass::Malformed))
    }

    /// Whether the signature verifies strictly under the signer's Ed25519
    /// key, which passes `ed25519_valid`.
    pub fn verifies(&self) -> bool {
        ed25519_valid(&self.signer.ed.0).is_ok()
            && ed25519_verify_strict(
                &self.signer.ed.0,
                &unlink_statement(&self.link_id),
                &self.signature,
            )
    }
}

fn decode_unlink(bytes: &[u8]) -> Result<Unlink, cbor::Malformed> {
    let value = cbor::decode(bytes)?;
    let map = value.as_map()?;
    if map.len() != 4 || !(0..4).all(|key| map.contains_key(&key)) {
        return Err(cbor::Malformed);
    }
    if map[&0].as_unsigned()? != VERSION {
        return Err(cbor::Malformed);
    }
    Ok(Unlink {
        link_id: map[&1].as_byte_array()?,
        signer: Signatory::from_bytes(map[&2].as_bytes()?).map_err(|_| cbor::Malformed)?,
        signature: map[&3].as_byte_array()?,
    })
}

/// `check_link(link, list, unlinks)`, in order:
/// 1. the link is the map, deterministic, with exactly its keys, version 1,
///    and its types, lengths and texts;
/// 2. the signer's Ed25519 key passes `ed25519_valid`;
/// 3. the signature verifies strictly over the statement, under the
///    signer's Ed25519 key;
/// 4. `person_id` is the list's person ID;
/// 5. the signer's device ID is an active device or passkey member of the
///    merged list;
/// 6. no unlink held names the link ID, with a signature that verifies
///    strictly by a device or passkey member that a valid `add` of the list
///    ever named.
///
/// An unlink that does not read is not held.
///
/// # Errors
///
/// `Malformed`, `InvalidKey`, `BadSignature`, `WrongPerson`,
/// `UntrustedSigner` and `Unlinked`, in that order.
pub fn check_link<L: ListView + ?Sized>(
    link: &[u8],
    list: &L,
    unlinks: &[&[u8]],
) -> Result<AccountLink, IdentityClass> {
    let link = AccountLink::verify(link)?;
    if link.person_id != *list.person_id() {
        return Err(IdentityClass::WrongPerson);
    }
    let writes = |kind: Option<Kind>| matches!(kind, Some(Kind::Device | Kind::PasskeyMember));
    if !writes(list.active_kind(&link.signer.device_id())) {
        return Err(IdentityClass::UntrustedSigner);
    }
    let id = link.id();
    let unlinked = unlinks
        .iter()
        .filter_map(|raw| Unlink::decode(raw).ok())
        .any(|unlink| {
            unlink.link_id == id
                && writes(list.listed_kind(&unlink.signer.device_id()))
                && unlink.verifies()
        });
    if unlinked {
        return Err(IdentityClass::Unlinked);
    }
    Ok(link)
}
