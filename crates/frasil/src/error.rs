//! The client's errors.
//!
//! A client's interface may merge error classes (overview.md, "Error
//! classes"); this one keeps the class a check named wherever one did, so
//! an application can tell `Malformed` from `BadSignature`, and adds the
//! failures that are the client's own: its store, its randomness, and the
//! acts it refuses to sign. Each error's message says what happened and
//! what to do about it.

use frasil_base::errors::Class;
use frasil_store::StoreError;

/// A failure of the client.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A check of the specification failed with this class, named in
    /// UpperCamelCase as the specification writes it: what another party
    /// sent, or the store held, was refused.
    Class(&'static str),
    /// The store or the device-bound slot failed: its medium did, not a
    /// record (at-rest.md, "What the application provides").
    Store(String),
    /// The store's head moved under this device: another process of the
    /// same device committed first (at-rest.md, "Committing").
    Conflict,
    /// The platform has no working source of randomness, so the client
    /// signs, seals and wraps nothing (crypto.md, "Primitives").
    NoRandomness,
    /// The device does not hold this space.
    UnknownSpace,
    /// The device does not hold this stream, or no adapter reads it.
    UnknownStream,
    /// The device may not act as asked in the space at its current view:
    /// it is not a member, or its level does not allow it. Nothing was
    /// signed.
    NotAllowed(&'static str),
    /// The device was restored, and has not synced this log since, so it
    /// must not sign there yet (at-rest.md, "After a restore"; events.md,
    /// "Restored devices sync before writing").
    SyncBeforeWriting,
    /// The device knows of a change that cost the space a device, and the
    /// space has not rotated since: it writes nothing there until it has
    /// (keys.md, "Cascades", "Before the cascade").
    RotationDue,
    /// An adapter refused the change before it was written.
    Adapter(String),
    /// A connection failed.
    Connection(String),
    /// A deadline passed.
    Timeout,
    /// A deposit in a device mailbox, such as a welcome, was not accepted
    /// yet: the peer answered `busy` or `rate_limited`, or was not reached
    /// (the message says which). The device keeps the item at rest and
    /// deposits it again by itself, with a growing wait, for up to 30 days
    /// (transport.md, "A sender keeps what was refused");
    /// [`Event::Delivered`](crate::Event::Delivered) tells when a peer took
    /// it.
    Delayed(String),
    /// A comparison's time limit passed, and the caller asked to stop
    /// there rather than replace the text: nothing was written.
    LimitPassed,
    /// An argument does not read: the message says which.
    Invalid(&'static str),
    /// This build of the client does not do what was asked: the message
    /// names the feature that does.
    Unsupported(&'static str),
    /// The stream is released (peers.md, "Release and restore"): peers
    /// answer `released` (410) for it and refuse its new units, so the
    /// device writes none until a writer restores it.
    Released,
    /// The device's store, or a space file, was written under another
    /// protocol revision, so what it holds may not open under this one
    /// (overview.md, "Version policy"; at-rest.md, "Continuity"). Nothing
    /// of it was read or changed. Such a store is not usable by this
    /// revision: a new device, on an empty store, gets what peers and
    /// members of this revision hold by sync.
    IncompatibleData,
    /// The peer or member at the other end runs another protocol
    /// revision (`RevisionMismatch`, overview.md, "Version policy"): the
    /// connection ended, and connecting again meets the same refusal.
    OtherRevision,
    /// The space uses a hook a later document of protocol 1 defines, which
    /// this build does not implement (roster.md, "The space descriptor",
    /// 2.8 The checkpoint record and 3.16): this device holds what uses it,
    /// and signs nothing more in the space. Nothing was signed;
    /// [`Event::NeedsLaterVersion`](crate::Event::NeedsLaterVersion) told
    /// the application.
    NeedsLaterVersion,
}

impl Error {
    /// The failure of a check of the specification.
    pub fn class(class: impl Class) -> Self {
        Self::Class(class.name())
    }

    /// The class's name, for a failure of a check of the specification.
    pub fn class_name(&self) -> Option<&'static str> {
        match self {
            Self::Class(name) => Some(name),
            _ => None,
        }
    }

    /// What to do about it, in a sentence an application can show or log.
    pub fn what_to_do(&self) -> &'static str {
        match self {
            Self::Class(_) => {
                "nothing was taken; check that both sides run the same protocol, and report it if it persists"
            }
            Self::Store(_) => {
                "check that the store's location is writable and has space, then open the device again"
            }
            Self::Conflict => {
                "another process opened this device's store; open each device in one process only"
            }
            Self::NoRandomness => "run on a platform with a working source of randomness",
            Self::UnknownSpace => {
                "create the space, join it, or open one that Device::spaces lists"
            }
            Self::UnknownStream => {
                "open a stream that Space::streams lists, or wait until its first change arrives"
            }
            Self::NotAllowed(_) => {
                "ask a member who administers the space for the level this needs"
            }
            Self::SyncBeforeWriting => {
                "connect to a peer or another member and let the space sync, then write again"
            }
            Self::RotationDue => {
                "stay connected: the space rotates its keys by itself, then writes go through"
            }
            Self::Adapter(_) => "change the edit so that it makes a valid change, then write again",
            Self::Connection(_) => "check the address and the network, then connect again",
            Self::Timeout => "try again, or check the connection",
            Self::Delayed(_) => {
                "nothing to do: the device delivers it by itself once the peer takes it"
            }
            Self::LimitPassed => {
                "give the comparison a longer limit, or let it replace the changed part past the limit"
            }
            Self::Invalid(_) => "pass a value of the form the message names",
            Self::Unsupported(_) => "build the client with the feature the message names",
            Self::Released => "restore the stream first, or write in another one",
            Self::IncompatibleData => {
                "open a new device on an empty store; this revision does not read the old one"
            }
            Self::OtherRevision => "update this app or the peer, so that both run the same release",
            Self::NeedsLaterVersion => {
                "update this app: the space needs a version of Frasil that this build is not"
            }
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Class(name) => write!(f, "refused: {name}"),
            Self::Store(message) => write!(f, "the store failed: {message}"),
            Self::Conflict => f.write_str("another process of this device committed first"),
            Self::NoRandomness => f.write_str("the platform has no working source of randomness"),
            Self::UnknownSpace => f.write_str("this device does not hold the space"),
            Self::UnknownStream => f.write_str("this device does not hold the stream"),
            Self::NotAllowed(why) => write!(f, "not allowed: {why}"),
            Self::SyncBeforeWriting => {
                f.write_str("the device was restored and must sync this space before it writes")
            }
            Self::RotationDue => f.write_str("the space must rotate before this device writes"),
            Self::Adapter(message) => write!(f, "the adapter refused the change: {message}"),
            Self::Connection(message) => write!(f, "the connection failed: {message}"),
            Self::Timeout => f.write_str("a deadline passed"),
            Self::Delayed(why) => write!(f, "delivery delayed: {why}"),
            Self::LimitPassed => {
                f.write_str("the comparison's time limit passed, and nothing was written")
            }
            Self::Invalid(why) => write!(f, "invalid: {why}"),
            Self::Unsupported(why) => write!(f, "not in this build: {why}"),
            Self::Released => f.write_str("the stream is released"),
            Self::IncompatibleData => {
                f.write_str("the data was written under another protocol revision")
            }
            Self::OtherRevision => f.write_str("the other end runs another protocol revision"),
            Self::NeedsLaterVersion => {
                f.write_str("the space needs a later version of Frasil than this build")
            }
        }?;
        if f.alternate() {
            write!(f, "; {}", self.what_to_do())?;
        }
        Ok(())
    }
}

impl std::error::Error for Error {}

impl From<StoreError> for Error {
    fn from(error: StoreError) -> Self {
        Self::Store(error.message().to_owned())
    }
}

impl From<frasil_crypto::NoRandomness> for Error {
    fn from(_: frasil_crypto::NoRandomness) -> Self {
        Self::NoRandomness
    }
}

impl From<frasil_base::ErrorClass> for Error {
    fn from(class: frasil_base::ErrorClass) -> Self {
        Self::class(class)
    }
}

impl Error {
    /// Whether data or a party the device met follows another protocol
    /// revision: `IncompatibleData` or `OtherRevision`.
    pub fn is_other_revision(&self) -> bool {
        matches!(self, Self::IncompatibleData | Self::OtherRevision)
    }
}

/// The client's result.
pub type Result<T, E = Error> = core::result::Result<T, E>;
