//! Error classes and their sorts (overview.md, "Error classes").
//!
//! Every check names the class it fails with, in UpperCamelCase
//! ([`Class::name`]). On the wire a class is written in snake case
//! ([`Class::wire_name`]), and that is how a class renders with `Display`.
//!
//! [`ErrorClass`] holds the classes several documents share. A crate whose
//! document defines classes of its own declares them with
//! [`error_classes!`](crate::error_classes), which builds an enum that also
//! carries every shared class:
//!
//! ```
//! frasil_base::error_classes! {
//!     /// The classes events.md defines.
//!     pub enum EventClass {
//!         /// An event, or one of its parents, of another log.
//!         WrongLog = "wrong_log", Final;
//!         /// A proof whose two events show no fork.
//!         NotEquivocation = "not_equivocation", Decision;
//!     }
//! }
//!
//! use frasil_base::errors::{Class, ErrorClass, Sort};
//! assert_eq!(EventClass::WrongLog.to_string(), "wrong_log");
//! assert_eq!(EventClass::from(ErrorClass::Malformed).name(), "Malformed");
//! assert_eq!(EventClass::from_name("NotEquivocation").map(Class::sort), Some(Sort::Decision));
//! ```

use core::fmt;

/// The sort of a class: what a failure means for the input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Sort {
    /// The input is invalid for every replica that holds it.
    Final,
    /// The decision waits for an event of this or another log, or a record
    /// that names a key. The input is kept, never applied and never cited,
    /// and decided again when that arrives.
    Pending,
    /// The replica cannot open or interpret the input. It is not a verdict.
    Held,
    /// The unit is valid, but an adapter refuses its content, which has no
    /// effect.
    ContentRefused,
    /// A receiver refuses one frame, message, request or connection. It says
    /// nothing about any event's validity.
    Decision,
    /// A client tells its application something. It changes no verdict.
    Report,
}

/// An error class: its name, its wire name and its sort.
pub trait Class: Copy + Eq + fmt::Debug + fmt::Display {
    /// The class's name in UpperCamelCase, as the documents and the vectors
    /// write it, such as `TooLarge`.
    fn name(self) -> &'static str;

    /// The class's name on the wire, in snake case, such as `too_large`.
    fn wire_name(self) -> &'static str;

    /// The class's sort. For the few classes whose sort depends on what is
    /// judged, this is the sort for an event; the class's documentation
    /// names the other.
    fn sort(self) -> Sort;
}

macro_rules! shared_classes {
    ($( $(#[$doc:meta])* $variant:ident = $wire:literal, $sort:ident; )*) => {
        /// The classes several documents share (overview.md, "Error
        /// classes"). Every other class is defined in the document whose
        /// procedure raises it.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum ErrorClass {
            $( $(#[$doc])* $variant, )*
        }

        impl ErrorClass {
            /// Every shared class, in the order of overview.md's table.
            pub const ALL: &'static [ErrorClass] = &[ $( ErrorClass::$variant, )* ];

            /// The class of this UpperCamelCase name, such as `Malformed`.
            pub fn from_name(name: &str) -> Option<Self> {
                match name {
                    $( stringify!($variant) => Some(Self::$variant), )*
                    _ => None,
                }
            }

            /// The class of this wire name, such as `malformed`.
            pub fn from_wire_name(name: &str) -> Option<Self> {
                match name {
                    $( $wire => Some(Self::$variant), )*
                    _ => None,
                }
            }
        }

        impl Class for ErrorClass {
            fn name(self) -> &'static str {
                match self {
                    $( Self::$variant => stringify!($variant), )*
                }
            }

            fn wire_name(self) -> &'static str {
                match self {
                    $( Self::$variant => $wire, )*
                }
            }

            fn sort(self) -> Sort {
                match self {
                    $( Self::$variant => Sort::$sort, )*
                }
            }
        }
    };
}

shared_classes! {
    /// Over a size or count limit.
    TooLarge = "too_large", Final;
    /// Not exactly one valid encoding, or a field rule broken.
    Malformed = "malformed", Final;
    /// A version, suite or scheme this reader does not know.
    UnsupportedVersion = "unsupported_version", Final;
    /// A public key that crypto.md's validation refuses.
    InvalidKey = "invalid_key", Final;
    /// A signature that does not verify.
    BadSignature = "bad_signature", Final;
    /// A possession proof that does not verify.
    BadPossession = "bad_possession", Final;
    /// Public keys carried as a holder's that do not hash to the device ID or
    /// keys commitment they are named under (crypto.md, "A device's keys").
    NotCommitted = "not_committed", Final;
    /// A scheme the structure may not carry.
    SchemeNotAllowed = "scheme_not_allowed", Final;
    /// A sealed part that does not match or open under a key derived from
    /// checked secrets.
    BadSeal = "bad_seal", Final;
    /// An AEAD or a wrap that does not open under the key tried. Final, for
    /// that key.
    Decrypt = "decrypt", Final;
    /// The author forked its chain at or before this event. Final; also a
    /// decision to detach a connection.
    Forked = "forked", Final;
    /// Over 4,096 valid events of the log's own kind (roster events, or list
    /// events) in the valid past of one place.
    Full = "full", Final;
    /// The verifier holds no ML-DSA-65 key yet that, with an X-Wing key,
    /// hashes to the signer's keys commitment; it says nothing against the
    /// signer.
    NoHybridKey = "no_hybrid_key", Pending;
    /// After the classical sunset, a scheme-0 event no scheme-2 event
    /// covers.
    Uncovered = "uncovered", Pending;
    /// Waits for an event of this or another log.
    Pending = "pending", Pending;
    /// No key held opens it.
    Sealed = "sealed", Held;
    /// Uses a reserved hook that no extension this implementation has
    /// defines; it and everything after it are held.
    ExtensionRequired = "extension_required", Held;
    /// The signer is not a member where it is judged. Final for an event; a
    /// decision for a frame.
    NotAMember = "not_a_member", Final;
    /// The author does not hold `administer` at the event's place; in the
    /// skeleton, its administrator slot is not in.
    NotAnAdministrator = "not_an_administrator", Final;
    /// A stranger's event, or one no held record lets the replica check; not
    /// kept.
    Dropped = "dropped", Decision;
    /// An adapter's capability check refuses a unit's content.
    CapabilityRefused = "capability_refused", ContentRefused;
    /// A unit of a type this replica has no adapter for; its content is
    /// ignored.
    UnknownAdapter = "unknown_adapter", Report;
    /// Content of a version its adapter does not know; it is ignored.
    UnknownContentVersion = "unknown_content_version", Report;
    /// A snapshot unit whose cover, stubs or state do not match; it is never
    /// used.
    BadCompaction = "bad_compaction", Report;
    /// A message type the receiver does not know.
    UnknownMessage = "unknown_message", Decision;
    /// A message, request or nonce the receiver has already taken or
    /// answered.
    Replayed = "replayed", Decision;
    /// An exchanged instant is past, or the receiver's wall clock is not
    /// known.
    Expired = "expired", Decision;
    /// The other end runs another revision (overview.md, "Version
    /// policy").
    RevisionMismatch = "revision_mismatch", Decision;
}

impl fmt::Display for ErrorClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.wire_name())
    }
}

impl std::error::Error for ErrorClass {}

impl From<crate::cbor::Malformed> for ErrorClass {
    fn from(_: crate::cbor::Malformed) -> Self {
        Self::Malformed
    }
}

/// A class's wire name from its UpperCamelCase name: each capital after the
/// first starts a new word, joined by `_`, all lower case. For checking the
/// wire names a crate declares.
pub fn snake_case(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    for (index, c) in name.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if index > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

/// Declares a document's own error classes as an enum that also carries
/// every [`ErrorClass`], through a `Shared` variant.
///
/// Each class gives its documentation, its UpperCamelCase variant, its wire
/// name and its [`Sort`]:
///
/// ```text
/// error_classes! {
///     /// What the enum is.
///     pub enum Name {
///         /// What the class means.
///         Variant = "wire_name", Final;
///     }
/// }
/// ```
///
/// The enum implements [`Class`], `Display` (the wire name),
/// `std::error::Error`, and `From<ErrorClass>` and
/// `From<cbor::Malformed>`, so `?` lifts the shared classes. It has
/// `OWN` (its own classes, in order), `from_name` and `from_wire_name`,
/// which look up its own classes and then the shared ones. A crate's tests
/// should check each own class's wire name against [`snake_case`] of its
/// name.
#[macro_export]
macro_rules! error_classes {
    (
        $(#[$enum_doc:meta])*
        $vis:vis enum $name:ident {
            $( $(#[$doc:meta])* $variant:ident = $wire:literal, $sort:ident; )*
        }
    ) => {
        $(#[$enum_doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        $vis enum $name {
            /// A class several documents share (overview.md, "Error
            /// classes").
            Shared($crate::errors::ErrorClass),
            $( $(#[$doc])* $variant, )*
        }

        impl $name {
            /// This document's own classes, in the order it lists them.
            pub const OWN: &'static [$name] = &[ $( $name::$variant, )* ];

            /// The class of this UpperCamelCase name: one of this
            /// document's own, or a shared one.
            pub fn from_name(name: &str) -> ::core::option::Option<Self> {
                match name {
                    $( stringify!($variant) => ::core::option::Option::Some(Self::$variant), )*
                    _ => $crate::errors::ErrorClass::from_name(name).map(Self::Shared),
                }
            }

            /// The class of this wire name: one of this document's own, or
            /// a shared one.
            pub fn from_wire_name(name: &str) -> ::core::option::Option<Self> {
                match name {
                    $( $wire => ::core::option::Option::Some(Self::$variant), )*
                    _ => $crate::errors::ErrorClass::from_wire_name(name).map(Self::Shared),
                }
            }
        }

        impl $crate::errors::Class for $name {
            fn name(self) -> &'static str {
                match self {
                    Self::Shared(class) => $crate::errors::Class::name(class),
                    $( Self::$variant => stringify!($variant), )*
                }
            }

            fn wire_name(self) -> &'static str {
                match self {
                    Self::Shared(class) => $crate::errors::Class::wire_name(class),
                    $( Self::$variant => $wire, )*
                }
            }

            fn sort(self) -> $crate::errors::Sort {
                match self {
                    Self::Shared(class) => $crate::errors::Class::sort(class),
                    $( Self::$variant => $crate::errors::Sort::$sort, )*
                }
            }
        }

        impl ::core::fmt::Display for $name {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str($crate::errors::Class::wire_name(*self))
            }
        }

        impl ::std::error::Error for $name {}

        impl ::core::convert::From<$crate::errors::ErrorClass> for $name {
            fn from(class: $crate::errors::ErrorClass) -> Self {
                Self::Shared(class)
            }
        }

        impl ::core::convert::From<$crate::cbor::Malformed> for $name {
            fn from(_: $crate::cbor::Malformed) -> Self {
                Self::Shared($crate::errors::ErrorClass::Malformed)
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_are_the_snake_case_names() {
        assert_eq!(ErrorClass::ALL.len(), 28);
        for &class in ErrorClass::ALL {
            assert_eq!(class.wire_name(), snake_case(class.name()));
            assert_eq!(class.to_string(), class.wire_name());
            assert_eq!(ErrorClass::from_name(class.name()), Some(class));
            assert_eq!(ErrorClass::from_wire_name(class.wire_name()), Some(class));
        }
        assert_eq!(
            ErrorClass::NotAnAdministrator.to_string(),
            "not_an_administrator"
        );
        assert_eq!(ErrorClass::from_name("malformed"), None);
        assert_eq!(ErrorClass::from_wire_name("Malformed"), None);
    }

    #[test]
    fn sorts_follow_the_table() {
        assert_eq!(ErrorClass::Malformed.sort(), Sort::Final);
        assert_eq!(ErrorClass::NoHybridKey.sort(), Sort::Pending);
        assert_eq!(ErrorClass::Uncovered.sort(), Sort::Pending);
        assert_eq!(ErrorClass::Pending.sort(), Sort::Pending);
        assert_eq!(ErrorClass::Sealed.sort(), Sort::Held);
        assert_eq!(ErrorClass::ExtensionRequired.sort(), Sort::Held);
        assert_eq!(ErrorClass::Dropped.sort(), Sort::Decision);
        assert_eq!(ErrorClass::CapabilityRefused.sort(), Sort::ContentRefused);
        assert_eq!(ErrorClass::UnknownAdapter.sort(), Sort::Report);
        assert_eq!(ErrorClass::BadCompaction.sort(), Sort::Report);
        assert_eq!(ErrorClass::Expired.sort(), Sort::Decision);
        assert_eq!(ErrorClass::RevisionMismatch.sort(), Sort::Decision);
    }

    crate::error_classes! {
        /// A document's own classes, for the test.
        enum Sample {
            /// An event of another log.
            WrongLog = "wrong_log", Final;
            /// A kind this replica does not know.
            UnknownKind = "unknown_kind", Held;
        }
    }

    #[test]
    fn declared_classes_carry_the_shared_ones() {
        for &class in Sample::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
        }
        assert_eq!(Sample::WrongLog.to_string(), "wrong_log");
        assert_eq!(Sample::UnknownKind.sort(), Sort::Held);
        assert_eq!(
            Sample::from_name("Malformed"),
            Some(Sample::Shared(ErrorClass::Malformed))
        );
        assert_eq!(
            Sample::from_wire_name("unknown_kind"),
            Some(Sample::UnknownKind)
        );
        assert_eq!(Sample::from_name("Absent"), None);
        let lifted: Sample = crate::cbor::Malformed.into();
        assert_eq!(lifted.name(), "Malformed");
        assert_eq!(Sample::from(ErrorClass::TooLarge).to_string(), "too_large");
    }
}
