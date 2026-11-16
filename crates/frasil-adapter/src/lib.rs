//! An internal building block of Frasil: applications use the `frasil`
//! crate, not this one. Its interface follows the specification and changes
//! with it.
//!
//! Frasil's adapter interface: the trait, the context, capability checks
//! and content refusals.
//!
//! Specified by `docs/spec/units.md`, section 3.17 (The adapter
//! interface), and the content classes of section 3.18, "Error classes". It
//! has no vector file of its own; the adapters' vector files prove it.
//!
//! - [`context`]: what an adapter may read of a unit besides its content.
//! - [`capabilities`]: the capabilities a writer holds at a unit's place,
//!   and the `suggest` capability every built-in adapter checks.
//! - [`checks`]: capability checks an application registers by name, on
//!   units and, with their own context, on ephemeral data.
//! - [`interface`]: the [`Adapter`] trait, the outcome of handing it a
//!   unit, and what compaction returns.
//!
//! Every function here is a pure function of its inputs: no clock,
//! randomness, network, other stream or other space (units.md, section
//! 3.17, "Determinism").

pub mod capabilities;
pub mod checks;
pub mod context;
pub mod interface;

pub use capabilities::{Capabilities, Capability, Mode, SUGGEST};
pub use checks::{CapabilityChecks, Check};
pub use context::Supersession;
pub use context::{
    Author, Context, CopiedFrom, EphemeralContext, EphemeralKind, EventId, LOCATOR_BYTES, Level,
    Locator, Role, SpaceId, StreamId, Writer,
};
pub use interface::{Adapter, Compaction, Outcome, StreamUnit, suggest_check_snapshot};

frasil_base::error_classes! {
    /// The content classes of units.md, section 3.18, "Error classes", that an
    /// adapter itself reports, beside the shared classes `Malformed`,
    /// `UnknownContentVersion`, `CapabilityRefused` and `BadCompaction`.
    pub enum ContentClass {
        /// Content names an object its unit does not list (units.md,
        /// section 3.17, "Object references").
        ObjectNotListed = "object_not_listed", ContentRefused;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_base::errors::{Class, ErrorClass, Sort, snake_case};

    #[test]
    fn content_classes_are_named_as_the_spec_names_them() {
        for class in ContentClass::OWN {
            assert_eq!(class.wire_name(), snake_case(class.name()));
        }
        assert_eq!(
            ContentClass::from_name("ObjectNotListed").map(Class::sort),
            Some(Sort::ContentRefused)
        );
        assert_eq!(
            ContentClass::from(ErrorClass::CapabilityRefused).name(),
            "CapabilityRefused"
        );
    }
}
