//! Section 2.4, Error classes.

use std::fmt;

/// Why a drive refused a change, or a document is not one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The document's `document` map does not name the kind `frasil:drive`.
    NotADrive,
    /// A value of the wrong form: what it is.
    InvalidValue(&'static str),
    /// The change names an entry the drive does not hold.
    NoSuchEntry,
    /// An entry added under an entry ID the drive holds.
    EntryExists,
    /// An entry added or moved into an entry that is not a folder.
    CannotHold,
    /// A folder moved into itself or into an entry inside it.
    MoveIntoItself,
    /// A document entry for a stream that has an entry, or whose entry was
    /// purged.
    AlreadyListed,
    /// An entry trashed itself already.
    AlreadyTrashed,
    /// An entry restored that was not trashed itself.
    NotTrashed,
    /// A Set blob or Forget version of an entry whose kind is not `file`.
    NotAFile,
    /// A Set blob under a handle that has a record already.
    VersionExists,
    /// A Forget version of a handle that has no record.
    NoSuchVersion,
    /// A Forget version of a head.
    VersionIsHead,
    /// A Forget version of a record one of whose parents has a record.
    VersionHasParents,
    /// Loro refused an operation.
    Loro(String),
}

impl Error {
    /// The class's name, as ext-drive.md writes it; `Loro` for Loro's own
    /// refusals, which no vector names.
    pub fn class(&self) -> &'static str {
        match self {
            Error::NotADrive => "NotADrive",
            Error::InvalidValue(_) => "InvalidValue",
            Error::NoSuchEntry => "NoSuchEntry",
            Error::EntryExists => "EntryExists",
            Error::CannotHold => "CannotHold",
            Error::MoveIntoItself => "MoveIntoItself",
            Error::AlreadyListed => "AlreadyListed",
            Error::AlreadyTrashed => "AlreadyTrashed",
            Error::NotTrashed => "NotTrashed",
            Error::NotAFile => "NotAFile",
            Error::VersionExists => "VersionExists",
            Error::NoSuchVersion => "NoSuchVersion",
            Error::VersionIsHead => "VersionIsHead",
            Error::VersionHasParents => "VersionHasParents",
            Error::Loro(_) => "Loro",
        }
    }

    /// What happened, for a person.
    pub fn message(&self) -> &'static str {
        match self {
            Error::NotADrive => "the document is not a drive",
            Error::InvalidValue(what) => what,
            Error::NoSuchEntry => "the drive holds no such entry",
            Error::EntryExists => "the drive holds an entry with this ID already",
            Error::CannotHold => "only a folder holds entries",
            Error::MoveIntoItself => "a folder cannot move into itself or into a folder inside it",
            Error::AlreadyListed => {
                "the stream has an entry in the drive, or had one that was purged"
            }
            Error::AlreadyTrashed => "the entry is in the trash already",
            Error::NotTrashed => "the entry was not sent to the trash itself",
            Error::NotAFile => "only a file has versions",
            Error::VersionExists => "the file has a version under this handle already",
            Error::NoSuchVersion => "the file has no version under this handle",
            Error::VersionIsHead => "a head of the file cannot be forgotten",
            Error::VersionHasParents => "a version with recorded parents cannot be forgotten yet",
            Error::Loro(_) => "the drive's Loro document refused the change",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Loro(reason) => write!(f, "drive document: {reason}"),
            other => f.write_str(other.message()),
        }
    }
}

impl std::error::Error for Error {}

impl From<loro::LoroError> for Error {
    fn from(error: loro::LoroError) -> Self {
        Error::Loro(error.to_string())
    }
}
