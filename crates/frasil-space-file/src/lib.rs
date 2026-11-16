//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Space files (ext-space-files.md): one space, or the part of it an
//! exporter chose, in a file any implementation of protocol 1 reads, with a
//! **way in**: rotation secrets, invite fragments, or nothing, sealed under
//! a file key or in the clear.
//!
//! - [`record`]: the records and their encoding (ext-space-files.md,
//!   "Records", "The manifest").
//! - [`way_in`]: the way-in body, its seal under the file key and its
//!   opening ("The way in").
//! - [`file`]: a file read whole with the order rules, its last manifest
//!   and a truncated tail ("The file", "Order and limits", "Appending and
//!   truncation"), sniffing, and a writer.
//!
//! Everything here is sans-IO: the file is bytes, a path is the client's.
//! Nothing draws randomness: a seal takes its nonce as an argument.

pub mod file;
pub mod record;
pub mod way_in;

pub use file::{Read, Sniffed, Writer, read, sniff};
pub use record::{History, MAGIC, MAX_RECORD_BYTES, Manifest, Record, Section, WayIn};
pub use way_in::{Fragment, WayInBody, open_way_in, seal_way_in_with, sealing_key};

frasil_base::error_classes! {
    /// The error classes ext-space-files.md defines ("Labels and error
    /// classes"), with every shared class.
    pub enum SpaceFileClass {
        /// The file does not begin with the magic.
        NotASpaceFile = "not_a_space_file", Decision;
        /// The manifest's kind is not one the reader accepts.
        WrongKind = "wrong_kind", Decision;
        /// The reader holds the space neither as a member, nor can claim a
        /// fragment, nor derive its keys.
        NoWayIn = "no_way_in", Decision;
        /// The file is of another space than the one an append is for.
        OtherSpace = "other_space", Decision;
    }
}

#[cfg(test)]
mod tests {
    use super::SpaceFileClass;
    use frasil_base::errors::{Class, Sort, snake_case};

    #[test]
    fn own_classes_are_decisions_and_snake_cased() {
        for &class in SpaceFileClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
            assert_eq!(class.sort(), Sort::Decision);
            assert_eq!(SpaceFileClass::from_name(class.name()), Some(class));
        }
    }
}
