//! Capability checks (units.md, section 3.17, "Capability checks").
//!
//! An adapter registers checks by capability name:
//!
//! ```text
//! check(capabilities, context, content) → accept | refuse
//! ```
//!
//! - A check runs at every replica, after the unit is decrypted and found
//!   valid by the write rule and before `apply`, on every unit, snapshot
//!   units and seeds included.
//! - It reads the capabilities, the context and the content, never the
//!   stream's state, which would depend on arrival order. The signature
//!   enforces that: a check is handed nothing else.
//! - A unit it refuses is refused as content (`CapabilityRefused`).
//!
//! Every registered check runs on every unit, whichever capabilities its
//! author holds, so that a check can refuse what only an extending
//! capability would allow. They run in ascending order of name, and the
//! first refusal decides.
//!
//! ext-ephemeral.md runs the same interface on ephemeral messages and slot
//! values, with its own context ([`EphemeralContext`]): an application
//! registers those checks by name too ([`CapabilityChecks::register_ephemeral`]),
//! and [`CapabilityChecks::run_ephemeral`] runs them alike.

use crate::capabilities::Capabilities;
use crate::context::{Context, EphemeralContext};
use frasil_base::errors::ErrorClass;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

/// A check's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Check {
    /// The content passes this check.
    Accept,
    /// The content is refused (`CapabilityRefused`).
    Refuse,
}

/// A registered check: a pure function of the author's capabilities, the
/// unit's context and its content.
pub type CheckFn = dyn Fn(&Capabilities, &Context, &[u8]) -> Check + Send + Sync;

/// A registered check on ephemeral data: a pure function of the sender's
/// capabilities, the frame's context and its `data`.
pub type EphemeralCheckFn = dyn Fn(&Capabilities, &EphemeralContext, &[u8]) -> Check + Send + Sync;

/// The checks registered with one adapter, by capability name.
#[derive(Clone, Default)]
pub struct CapabilityChecks {
    checks: BTreeMap<String, Arc<CheckFn>>,
    ephemeral: BTreeMap<String, Arc<EphemeralCheckFn>>,
}

impl CapabilityChecks {
    /// No checks.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a check under a capability name, in place of any check
    /// already registered under it.
    pub fn register(
        &mut self,
        name: impl Into<String>,
        check: impl Fn(&Capabilities, &Context, &[u8]) -> Check + Send + Sync + 'static,
    ) {
        self.checks.insert(name.into(), Arc::new(check));
    }

    /// Registers a check on ephemeral data under a capability name, in
    /// place of any such check already registered under it.
    pub fn register_ephemeral(
        &mut self,
        name: impl Into<String>,
        check: impl Fn(&Capabilities, &EphemeralContext, &[u8]) -> Check + Send + Sync + 'static,
    ) {
        self.ephemeral.insert(name.into(), Arc::new(check));
    }

    /// Removes the checks registered under a name, on units and on
    /// ephemeral data, if any.
    pub fn unregister(&mut self, name: &str) {
        self.checks.remove(name);
        self.ephemeral.remove(name);
    }

    /// The names checks are registered under, ascending.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.checks.keys().map(String::as_str)
    }

    /// Whether no check is registered, on units or on ephemeral data.
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty() && self.ephemeral.is_empty()
    }

    /// Runs every check, in ascending order of name, on a unit's content.
    /// The first refusal is `CapabilityRefused`.
    pub fn run(&self, context: &Context, content: &[u8]) -> Result<(), ErrorClass> {
        for check in self.checks.values() {
            if check(&context.capabilities, context, content) == Check::Refuse {
                return Err(ErrorClass::CapabilityRefused);
            }
        }
        Ok(())
    }

    /// Runs every check on ephemeral data, in ascending order of name, on a
    /// frame's `data` (ext-ephemeral.md, step 16). The first refusal is
    /// `CapabilityRefused`.
    pub fn run_ephemeral(&self, context: &EphemeralContext, data: &[u8]) -> Result<(), ErrorClass> {
        for check in self.ephemeral.values() {
            if check(&context.capabilities, context, data) == Check::Refuse {
                return Err(ErrorClass::CapabilityRefused);
            }
        }
        Ok(())
    }
}

impl fmt::Debug for CapabilityChecks {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names: std::collections::BTreeSet<&String> =
            self.checks.keys().chain(self.ephemeral.keys()).collect();
        f.debug_set().entries(names).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capabilities::{Capability, Mode};
    use crate::context::Role;

    fn context(capabilities: Capabilities) -> Context {
        Context::new([1; 32], [2; 16], [3; 32], [4; 32], 1, 1, Role::Log)
            .with_capabilities(capabilities)
    }

    #[test]
    fn no_checks_accept_everything() {
        let checks = CapabilityChecks::new();
        assert!(checks.is_empty());
        assert_eq!(checks.run(&context(Capabilities::none()), b"x"), Ok(()));
    }

    #[test]
    fn every_check_runs_and_any_refusal_refuses() {
        let mut checks = CapabilityChecks::new();
        // Only a writer extended by "edit-others" may write content that
        // starts with 0xff.
        checks.register("edit-others", |capabilities, _, content| {
            if content.first() == Some(&0xff) && !capabilities.extends("edit-others") {
                Check::Refuse
            } else {
                Check::Accept
            }
        });
        checks.register("read-only", |capabilities, context, _| {
            if capabilities.narrows("read-only") && context.role == Role::Log {
                Check::Refuse
            } else {
                Check::Accept
            }
        });
        assert_eq!(
            checks.names().collect::<Vec<_>>(),
            ["edit-others", "read-only"]
        );
        let plain = context(Capabilities::none());
        assert_eq!(checks.run(&plain, &[0x01]), Ok(()));
        assert_eq!(
            checks.run(&plain, &[0xff]),
            Err(ErrorClass::CapabilityRefused)
        );
        let extended = context(Capabilities::new([Capability::new(
            "edit-others",
            Mode::Extends,
        )]));
        assert_eq!(checks.run(&extended, &[0xff]), Ok(()));
        let narrowed = context(Capabilities::new([Capability::new(
            "read-only",
            Mode::Narrows,
        )]));
        assert_eq!(
            checks.run(&narrowed, &[0x01]),
            Err(ErrorClass::CapabilityRefused)
        );
        checks.unregister("read-only");
        assert_eq!(checks.run(&narrowed, &[0x01]), Ok(()));
        assert_eq!(format!("{checks:?}"), "{\"edit-others\"}");
    }

    #[test]
    fn ephemeral_checks_run_on_their_own_context() {
        use crate::context::{EphemeralContext, EphemeralKind, Level};
        let mut checks = CapabilityChecks::new();
        // Only a sender at write or above may send a cursor slot.
        checks.register_ephemeral("cursors", |_, context, _| {
            if context.kind == EphemeralKind::Slot && context.level < Level::Write {
                Check::Refuse
            } else {
                Check::Accept
            }
        });
        assert!(!checks.is_empty());
        // A unit check under another name does not run on ephemeral data.
        checks.register("units-only", |_, _, _| Check::Refuse);
        let frame = |level| EphemeralContext {
            space: [1; 32],
            kind: EphemeralKind::Slot,
            name: "app/cursor".into(),
            stream: Some([2; 16]),
            targets: None,
            sender: [3; 32],
            level,
            capabilities: Capabilities::none(),
        };
        assert_eq!(checks.run_ephemeral(&frame(Level::Write), b"x"), Ok(()));
        assert_eq!(
            checks.run_ephemeral(&frame(Level::Read), b"x"),
            Err(ErrorClass::CapabilityRefused)
        );
        assert_eq!(format!("{checks:?}"), "{\"cursors\", \"units-only\"}");
        checks.unregister("cursors");
        assert_eq!(checks.run_ephemeral(&frame(Level::Read), b"x"), Ok(()));
    }
}
