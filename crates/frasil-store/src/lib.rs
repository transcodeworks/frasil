//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's store at rest.
//!
//! Specified by `docs/spec/at-rest.md`. Its vectors are
//! `docs/spec/vectors/at-rest.json`.
//!
//! - [`device_keys`]: the sealed device keys, the 235-byte blob that holds a
//!   device's three seeds and its store secret under an unlock key
//!   (at-rest.md, "Sealed device keys", "Sealing and opening the device
//!   keys").
//! - [`keys`]: the seal, tag and application keys of the store secret and of
//!   a log key, scope tags, item tags and addresses (at-rest.md, "Keys,
//!   addresses and records", "Application keys").
//! - [`tables`]: the tables, each table's item rule, and each table's value
//!   (at-rest.md, "Tables", "The head, events and keys", "Held objects",
//!   "Retention").
//! - [`record`]: sealing a record and opening one (at-rest.md, "Opening a
//!   record").
//! - [`continuity`](mod@continuity): the mark, the restore modes,
//!   `continuity`, and the head after a restore (at-rest.md, "The mark",
//!   "Continuity", "After a restore").
//! - [`store`]: the [`Store`] trait the application provides (`get`, `scan`,
//!   `commit`), the device-bound slot, and both in memory.
//! - `sqlite` (feature `sqlite`, on by default): a [`Store`] in a SQLite
//!   database in WAL mode: one writer, whose batches of commits share one
//!   transaction, and a pool of read-only connections.
//!
//! Everything but the SQLite backend is sans-IO: it reads no clock and
//! draws no randomness. Every procedure that needs random bytes (a nonce, a
//! store ID, a log key) takes them as an argument; a caller draws them with
//! `frasil_crypto::random_bytes`.

pub mod checkpoint_state;
pub mod continuity;
pub mod device_keys;
pub mod expressed_again;
#[cfg(feature = "ext-guests")]
pub mod ext_guests;
#[cfg(feature = "ext-invite-links")]
pub mod ext_invite_links;
pub mod keys;
pub mod record;
#[cfg(feature = "sqlite")]
pub mod sqlite;
pub mod store;
pub mod tables;

pub use continuity::{
    Continuity, RestoreMode, after_restore, continuity, open_mark, seal_mark_with,
};
pub use device_keys::{DeviceKeys, KeyKind, open_device_keys, seal_device_keys_with};
pub use keys::{Address, LogKeys, StoreKeys, app_key};
pub use record::{
    Opened, OpenedObject, SealedRecord, open_object_record, open_record, seal_record_with,
};
#[cfg(feature = "sqlite")]
pub use sqlite::{Durability, SqliteStore};
pub use store::{
    BoxFuture, Commit, DeviceBoundSlot, MemorySlot, MemoryStore, Sizes, Store, StoreError,
    forget_log,
};
pub use tables::{
    DepositKeysRecord, DepositRecord, Head, Restore, Table, TableValue, Tip, TokenBytes,
};

frasil_base::error_classes! {
    /// The error classes at-rest.md defines ("Error classes"), with every
    /// shared class.
    pub enum StoreClass {
        /// Sealed device keys of another kind than the caller asked for.
        WrongKeyKind = "wrong_key_kind", Final;
        /// Sealed device keys of another person than the caller expects.
        WrongPerson = "wrong_person", Final;
        /// Sealed device keys that name another device than the caller
        /// expects.
        WrongDevice = "wrong_device", Final;
    }
}

impl StoreClass {
    /// The shared class this is, if it is one.
    pub fn shared(self) -> Option<frasil_base::ErrorClass> {
        match self {
            Self::Shared(class) => Some(class),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::StoreClass;
    use frasil_base::errors::{Class, ErrorClass, Sort, snake_case};

    #[test]
    fn own_classes_are_final_and_snake_cased() {
        for &class in StoreClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
            assert_eq!(class.sort(), Sort::Final);
            assert_eq!(StoreClass::from_name(class.name()), Some(class));
        }
        assert_eq!(
            StoreClass::from_name("Decrypt"),
            Some(StoreClass::Shared(ErrorClass::Decrypt))
        );
    }
}
