//! The recipient bundle (keys.md, "The recipient bundle"): every secret one
//! recipient is entitled to for one state, in one wrap.
//!
//! ```text
//! bundle  = u8(flags) || slot(k(S)) || slot(w(S)) || slot(g(G))      97 bytes
//! flags:    0x01 content key, 0x02 upload seed, 0x04 grant seed
//! slot(x) = x when its flag is set, else 32 zero bytes
//! ```
//!
//! Every bundle is 97 bytes, so every wrap is the same size and a peer
//! cannot tell a recipient's level or whether it propagates.

use crate::KeyClass;
use crate::limits::BUNDLE_BYTES;
use frasil_base::ErrorClass;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The content key's flag.
pub const FLAG_CONTENT: u8 = 0x01;
/// The upload seed's flag.
pub const FLAG_UPLOAD: u8 = 0x02;
/// The grant seed's flag.
pub const FLAG_GRANT: u8 = 0x04;

/// A recipient bundle's secrets. Its slots are wiped when it is dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Bundle {
    content: Option<[u8; 32]>,
    upload: Option<[u8; 32]>,
    grant: Option<[u8; 32]>,
}

impl core::fmt::Debug for Bundle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Bundle")
            .field("flags", &self.flags())
            .finish_non_exhaustive()
    }
}

impl Bundle {
    /// A bundle of these secrets.
    ///
    /// # Errors
    ///
    /// `Malformed` for a bundle with no secret, or an upload seed without
    /// the content key: shapes a reader refuses.
    pub fn new(
        content: Option<[u8; 32]>,
        upload: Option<[u8; 32]>,
        grant: Option<[u8; 32]>,
    ) -> Result<Self, KeyClass> {
        let bundle = Self {
            content,
            upload,
            grant,
        };
        check_flags(bundle.flags())?;
        Ok(bundle)
    }

    /// The content key `k(S)`, if the bundle carries it.
    pub fn content(&self) -> Option<&[u8; 32]> {
        self.content.as_ref()
    }

    /// The upload seed `w(S)`, if the bundle carries it.
    pub fn upload(&self) -> Option<&[u8; 32]> {
        self.upload.as_ref()
    }

    /// The grant seed `g(G)`, if the bundle carries it.
    pub fn grant(&self) -> Option<&[u8; 32]> {
        self.grant.as_ref()
    }

    /// Which slots it carries.
    pub fn slots(&self) -> Slots {
        Slots {
            content: self.content.is_some(),
            upload: self.upload.is_some(),
            grant: self.grant.is_some(),
        }
    }

    /// Its flags byte.
    pub fn flags(&self) -> u8 {
        self.slots().flags()
    }

    /// Its 97 bytes.
    pub fn encode(&self) -> Zeroizing<[u8; BUNDLE_BYTES]> {
        let mut out = Zeroizing::new([0; BUNDLE_BYTES]);
        out[0] = self.flags();
        for (index, slot) in [&self.content, &self.upload, &self.grant]
            .into_iter()
            .enumerate()
        {
            if let Some(secret) = slot {
                out[1 + 32 * index..33 + 32 * index].copy_from_slice(secret);
            }
        }
        out
    }

    /// Reads a bundle, in keys.md's order (section 3.1, "A bundle"): exactly
    /// 97 bytes; no flag outside `0x07`; at least one flag; the upload flag
    /// only with the content flag; every slot whose flag is clear is zero.
    ///
    /// # Errors
    ///
    /// `Malformed` for a bundle any step refuses.
    pub fn read(data: &[u8]) -> Result<Self, KeyClass> {
        let data: &[u8; BUNDLE_BYTES] = data
            .try_into()
            .map_err(|_| KeyClass::from(ErrorClass::Malformed))?;
        let flags = data[0];
        check_flags(flags)?;
        let mut slots = [None; 3];
        for (index, flag) in [FLAG_CONTENT, FLAG_UPLOAD, FLAG_GRANT]
            .into_iter()
            .enumerate()
        {
            let slot: [u8; 32] = data[1 + 32 * index..33 + 32 * index]
                .try_into()
                .map_err(|_| KeyClass::from(ErrorClass::Malformed))?;
            if flags & flag != 0 {
                slots[index] = Some(slot);
            } else if slot != [0; 32] {
                return Err(ErrorClass::Malformed.into());
            }
        }
        let [content, upload, grant] = slots;
        Ok(Self {
            content,
            upload,
            grant,
        })
    }

    /// The check a taker runs on an opened wrap's bundle: it holds the
    /// content key exactly when the delivery names a state, and a grant
    /// seed only when it names a grant state.
    ///
    /// # Errors
    ///
    /// `Malformed` otherwise.
    pub fn check_names(&self, names_state: bool, names_grant_state: bool) -> Result<(), KeyClass> {
        if self.content.is_some() != names_state || (self.grant.is_some() && !names_grant_state) {
            return Err(ErrorClass::Malformed.into());
        }
        Ok(())
    }
}

fn check_flags(flags: u8) -> Result<(), KeyClass> {
    if flags & !(FLAG_CONTENT | FLAG_UPLOAD | FLAG_GRANT) != 0
        || flags == 0
        || (flags & FLAG_UPLOAD != 0 && flags & FLAG_CONTENT == 0)
    {
        return Err(ErrorClass::Malformed.into());
    }
    Ok(())
}

/// Which slots a bundle carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Slots {
    /// The content key.
    pub content: bool,
    /// The upload seed.
    pub upload: bool,
    /// The grant seed.
    pub grant: bool,
}

impl Slots {
    /// The flags byte of these slots.
    pub fn flags(self) -> u8 {
        (if self.content { FLAG_CONTENT } else { 0 })
            | (if self.upload { FLAG_UPLOAD } else { 0 })
            | (if self.grant { FLAG_GRANT } else { 0 })
    }
}

/// A member's level (roster.md): what its bundle carries depends on whether
/// it writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Level {
    /// `read`.
    Read,
    /// `write`.
    Write,
    /// `administer`, which also writes.
    Administer,
}

/// What a member's bundle of a state carries (keys.md, "The recipient
/// bundle"): every member the content key; a member whose level writes the
/// upload seed; a member whose grant propagates the grant seed. An invite
/// key's bundle is ext-invite-links.md's.
pub fn bundle_contents(level: Level, propagates: bool) -> Slots {
    Slots {
        content: true,
        upload: level >= Level::Write,
        grant: propagates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bundle_round_trips() {
        let bundle = Bundle::new(Some([1; 32]), None, Some([3; 32])).unwrap();
        let bytes = bundle.encode();
        assert_eq!(bytes[0], 0x05);
        assert_eq!(&bytes[33..65], &[0; 32]);
        assert_eq!(Bundle::read(&bytes[..]), Ok(bundle));
    }

    #[test]
    fn shapes_a_reader_refuses_are_not_made() {
        assert!(Bundle::new(None, None, None).is_err());
        assert!(Bundle::new(None, Some([1; 32]), None).is_err());
        assert!(Bundle::new(None, None, Some([1; 32])).is_ok());
    }

    #[test]
    fn who_gets_what() {
        let writer = bundle_contents(Level::Write, true);
        assert_eq!(writer.flags(), 0x07);
        assert_eq!(bundle_contents(Level::Read, true).flags(), 0x05);
        assert_eq!(bundle_contents(Level::Administer, false).flags(), 0x03);
    }
}
