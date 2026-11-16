//! The way in (ext-space-files.md, "The way in"): rotation secrets, invite
//! fragments, or nothing, in the clear or sealed under the file key.
//!
//! ```text
//! way-in body = CBOR {1: 1,
//!                     2: [[rotation ID (32), k_R (32)], ...],        0 to 64, ascending by ID
//!                     3: [fragment (97), ...],                         0 to 64
//!                     4: label (text, 1 to 255 bytes; optional)}
//!
//! sealing key = HKDF(salt = none, ikm = file key, info = "frasil/space-file/key/v1")
//! sealed form = nonce (24) || XChaCha20-Poly1305(sealing key, nonce, way-in body,
//!                            aad = "frasil/space-file/way-in/v1" || space ID)
//! ```

use crate::record::MAX_TEXT_BYTES;
use frasil_base::ErrorClass;
use frasil_base::cbor::{self, Map, Value};
use frasil_crypto::labels::{SPACE_FILE_KEY, SPACE_FILE_WAY_IN};
use frasil_crypto::primitives::{hkdf, xchacha20poly1305_open, xchacha20poly1305_seal};
use frasil_events::EventId;
use zeroize::Zeroizing;

/// The body's version.
pub const VERSION: u64 = 1;
/// The most rotation secrets, or fragments, a way in carries.
pub const MAX_ITEMS: usize = 64;
/// A fragment's bytes: `u8(1) || secret (32) || invite entry (32) || space
/// ID (32)` (ext-invite-links.md, "The secret, its keys and the link").
pub const FRAGMENT_BYTES: usize = 97;
/// A sealed form is at least a nonce and a tag.
pub const MIN_SEALED_BYTES: usize = 24 + 16;

/// An invite fragment, read from its 97 bytes.
#[derive(Clone)]
pub struct Fragment {
    /// The invite's secret.
    pub secret: Zeroizing<[u8; 32]>,
    /// The invite entry.
    pub entry: EventId,
    /// The space.
    pub space: EventId,
}

impl core::fmt::Debug for Fragment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fragment")
            .field("entry", &self.entry)
            .field("space", &self.space)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Fragment {
    fn eq(&self, other: &Self) -> bool {
        *self.secret == *other.secret && self.entry == other.entry && self.space == other.space
    }
}

impl Eq for Fragment {}

impl Fragment {
    /// The fragment's 97 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![1u8];
        out.extend_from_slice(&*self.secret);
        out.extend_from_slice(&self.entry.0);
        out.extend_from_slice(&self.space.0);
        out
    }

    /// Reads a fragment's bytes, as ext-invite-links.md reads the decoded
    /// link: byte 0 is 1 (`UnsupportedVersion`); 97 bytes (`Malformed`).
    ///
    /// # Errors
    ///
    /// As above.
    pub fn read(raw: &[u8]) -> Result<Self, ErrorClass> {
        match raw.first() {
            None => return Err(ErrorClass::Malformed),
            Some(1) => {}
            Some(_) => return Err(ErrorClass::UnsupportedVersion),
        }
        if raw.len() != FRAGMENT_BYTES {
            return Err(ErrorClass::Malformed);
        }
        let array = |range: core::ops::Range<usize>| -> [u8; 32] {
            raw[range].try_into().expect("32 bytes")
        };
        Ok(Self {
            secret: Zeroizing::new(array(1..33)),
            entry: EventId(array(33..65)),
            space: EventId(array(65..97)),
        })
    }
}

/// A way-in body.
#[derive(Clone, PartialEq, Eq)]
pub struct WayInBody {
    /// Key 2: each rotation's ID and content key `k_R`, ascending by ID.
    pub secrets: Vec<(EventId, Zeroizing<[u8; 32]>)>,
    /// Key 3: invite fragments, each admitting one claimant.
    pub fragments: Vec<Fragment>,
    /// Key 4: a label the application shows.
    pub label: Option<String>,
}

impl core::fmt::Debug for WayInBody {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WayInBody")
            .field("secrets", &self.secrets.len())
            .field("fragments", &self.fragments.len())
            .field("label", &self.label)
            .finish()
    }
}

impl WayInBody {
    /// The body's one encoding.
    pub fn encode(&self) -> Vec<u8> {
        let mut secrets: Vec<&(EventId, Zeroizing<[u8; 32]>)> = self.secrets.iter().collect();
        secrets.sort_by_key(|(id, _)| *id);
        let mut map = Map::new();
        map.insert(1, VERSION.into());
        map.insert(
            2,
            Value::from(
                secrets
                    .into_iter()
                    .map(|(id, key)| {
                        Value::from(vec![Value::from(id.0.as_slice()), Value::from(&key[..])])
                    })
                    .collect::<Vec<_>>(),
            ),
        );
        map.insert(
            3,
            Value::from(
                self.fragments
                    .iter()
                    .map(|fragment| Value::from(fragment.encode()))
                    .collect::<Vec<_>>(),
            ),
        );
        if let Some(label) = &self.label {
            map.insert(4, label.as_str().into());
        }
        Value::Map(map).encode()
    }

    /// Reads a body, in order: deterministic CBOR, keys 1 to 4 only, keys 1
    /// to 3 present, the types and limits (`Malformed`); key 1 is 1
    /// (`UnsupportedVersion`); each fragment reads and names `space`
    /// (`Malformed`).
    ///
    /// # Errors
    ///
    /// As above.
    pub fn read(body: &[u8], space: &EventId) -> Result<Self, ErrorClass> {
        let malformed = ErrorClass::Malformed;
        let value = cbor::decode(body)?;
        let map = value.as_map()?;
        if !map.keys().all(|k| (1..=4).contains(k))
            || ![1, 2, 3].iter().all(|k| map.contains_key(k))
        {
            return Err(malformed);
        }
        let version = map[&1].as_unsigned()?;
        let pairs = map[&2].as_array()?;
        let raws = map[&3].as_array()?;
        if pairs.len() > MAX_ITEMS || raws.len() > MAX_ITEMS {
            return Err(malformed);
        }
        let mut secrets = Vec::with_capacity(pairs.len());
        for pair in pairs {
            let pair = pair.as_array()?;
            if pair.len() != 2 {
                return Err(malformed);
            }
            secrets.push((
                EventId(pair[0].as_byte_array::<32>()?),
                Zeroizing::new(pair[1].as_byte_array::<32>()?),
            ));
        }
        if !secrets.windows(2).all(|w| w[0].0 < w[1].0) {
            return Err(malformed);
        }
        let label = match map.get(&4) {
            None => None,
            Some(value) => {
                let text = value.as_text()?;
                if text.is_empty() || text.len() > MAX_TEXT_BYTES {
                    return Err(malformed);
                }
                Some(text.to_owned())
            }
        };
        if version != VERSION {
            return Err(ErrorClass::UnsupportedVersion);
        }
        let mut fragments = Vec::with_capacity(raws.len());
        for raw in raws {
            let raw = raw.as_bytes()?;
            if raw.len() != FRAGMENT_BYTES {
                return Err(malformed);
            }
            let fragment = Fragment::read(raw)?;
            if fragment.space != *space {
                return Err(malformed);
            }
            fragments.push(fragment);
        }
        Ok(Self {
            secrets,
            fragments,
            label,
        })
    }
}

/// `sealing key = HKDF(none, file key, "frasil/space-file/key/v1")`.
pub fn sealing_key(file_key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf(None, file_key, SPACE_FILE_KEY)
}

/// The sealed form's associated data: the label and the space ID.
pub fn way_in_aad(space: &EventId) -> Vec<u8> {
    [SPACE_FILE_WAY_IN, &space.0[..]].concat()
}

/// Seals a way-in body under the file key, with the nonce given: a caller
/// draws it with `frasil_crypto::random_bytes`, anew for every seal.
pub fn seal_way_in_with(
    file_key: &[u8; 32],
    nonce: &[u8; 24],
    body: &[u8],
    space: &EventId,
) -> Vec<u8> {
    let key = sealing_key(file_key);
    let mut out = nonce.to_vec();
    out.extend_from_slice(&xchacha20poly1305_seal(
        &key,
        nonce,
        &way_in_aad(space),
        body,
    ));
    out
}

/// Opens a sealed way in under the file key: the body.
///
/// # Errors
///
/// `Malformed` for fewer than 40 bytes; `Decrypt` when the AEAD does not
/// open.
pub fn open_way_in(
    file_key: &[u8; 32],
    sealed: &[u8],
    space: &EventId,
) -> Result<Zeroizing<Vec<u8>>, ErrorClass> {
    if sealed.len() < MIN_SEALED_BYTES {
        return Err(ErrorClass::Malformed);
    }
    let nonce: &[u8; 24] = sealed[..24].try_into().expect("24 bytes");
    xchacha20poly1305_open(
        &sealing_key(file_key),
        nonce,
        &way_in_aad(space),
        &sealed[24..],
    )
    .map_err(|_| ErrorClass::Decrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_round_trips_and_seals() {
        let space = EventId([7; 32]);
        let body = WayInBody {
            secrets: vec![
                (EventId([2; 32]), Zeroizing::new([9; 32])),
                (EventId([1; 32]), Zeroizing::new([8; 32])),
            ],
            fragments: vec![Fragment {
                secret: Zeroizing::new([3; 32]),
                entry: EventId([4; 32]),
                space,
            }],
            label: Some("keys".into()),
        };
        let encoded = body.encode();
        let read = WayInBody::read(&encoded, &space).unwrap();
        assert_eq!(read.secrets[0].0, EventId([1; 32]), "sorted");
        assert_eq!(read.fragments, body.fragments);
        assert_eq!(
            WayInBody::read(&encoded, &EventId([8; 32])),
            Err(ErrorClass::Malformed),
            "a fragment of another space"
        );
        let sealed = seal_way_in_with(&[5; 32], &[6; 24], &encoded, &space);
        assert_eq!(
            open_way_in(&[5; 32], &sealed, &space).map(|p| p.to_vec()),
            Ok(encoded)
        );
        assert_eq!(
            open_way_in(&[0; 32], &sealed, &space),
            Err(ErrorClass::Decrypt)
        );
        assert_eq!(
            open_way_in(&[5; 32], &sealed[..39], &space),
            Err(ErrorClass::Malformed)
        );
    }
}
