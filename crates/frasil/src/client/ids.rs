//! The names an application keeps: of spaces, streams, members and blobs.
//! Each shows as lowercase hexadecimal and parses from it.

use crate::error::Error;

macro_rules! id {
    ($(#[$doc:meta])* $name:ident, $len:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; $len]);

        impl $name {
            /// The ID of these bytes.
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// The ID's bytes.
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                for byte in self.0 {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self)
            }
        }

        impl core::str::FromStr for $name {
            type Err = Error;

            fn from_str(text: &str) -> Result<Self, Error> {
                let mut out = [0u8; $len];
                let bytes = text.as_bytes();
                if bytes.len() != 2 * $len {
                    return Err(Error::Invalid(concat!(
                        "a ",
                        stringify!($name),
                        " is ",
                        stringify!($len),
                        " bytes in hexadecimal"
                    )));
                }
                for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
                    let digit = |c: u8| (c as char).to_digit(16);
                    match (digit(pair[0]), digit(pair[1])) {
                        (Some(high), Some(low)) => *slot = (high * 16 + low) as u8,
                        _ => {
                            return Err(Error::Invalid(concat!(
                                "a ",
                                stringify!($name),
                                " is hexadecimal"
                            )));
                        }
                    }
                }
                Ok(Self(out))
            }
        }
    };
}

id!(
    /// A space's ID: the ID of its genesis event.
    SpaceId,
    32
);

id!(
    /// A stream's ID within its space.
    StreamId,
    16
);

id!(
    /// A member's ID: a device's device ID, the hash of its Ed25519 key and
    /// the commitment to its other keys, or a person's ID. Applications
    /// show and compare members by it, never by a device's Ed25519 key,
    /// which one key set's holder can pair with keys of its own under
    /// another device ID (roster.md, "A device's keys").
    MemberId,
    32
);

id!(
    /// A blob's ID within its blob stream: it stays the same when the blob
    /// is put again under it.
    BlobId,
    16
);

id!(
    /// A change's ID: the ID of the unit that carried it.
    UnitId,
    32
);

id!(
    /// A version's ID: its row's key in the space's versions stream.
    VersionId,
    16
);

id!(
    /// A checkpoint's ID: the ID of the roster event that is the checkpoint
    /// (roster.md, 3.15 Checkpoints), or of a device-list event of action 3
    /// (identity.md, 3.16 List checkpoints).
    CheckpointId,
    32
);

id!(
    /// A space event's ID, such as a roster event that changes members.
    ChangeId,
    32
);

impl MemberId {
    /// The member ID of a device: its device ID.
    pub(crate) fn device(device: frasil_crypto::device::DeviceId) -> Self {
        Self(device.0)
    }
}

impl SpaceId {
    pub(crate) fn event(self) -> frasil_events::EventId {
        frasil_events::EventId(self.0)
    }

    pub(crate) fn of(event: frasil_events::EventId) -> Self {
        Self(event.0)
    }
}
