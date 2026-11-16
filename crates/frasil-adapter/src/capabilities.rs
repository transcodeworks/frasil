//! Capabilities, as an adapter reads them (units.md, section 3.17, "The adapter
//! interface", "Capability checks" and "`suggest`").
//!
//! A capability is an application-defined name with a mode, extends or
//! narrows (roster.md, the grant's `capabilities`). A writer's capabilities
//! at a unit's place are those of its strongest path, merged as roster.md
//! merges concurrent grants; the replica computes them and hands them over
//! in the [`Context`](crate::Context).

/// The capability every built-in adapter checks (units.md, section 3.17, "The
/// adapter interface", "`suggest`").
pub const SUGGEST: &str = "suggest";

/// A capability's mode: code 0 extends a grant, code 1 narrows it
/// (roster.md, the grant's `capabilities`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Mode {
    /// Code 0: the capability extends what an adapter accepts, never
    /// `write`.
    Extends,
    /// Code 1: the capability narrows what its holder may do.
    Narrows,
}

impl Mode {
    /// The mode of a code, or `None` for a code that is neither 0 nor 1.
    pub fn from_code(code: u64) -> Option<Self> {
        match code {
            0 => Some(Self::Extends),
            1 => Some(Self::Narrows),
            _ => None,
        }
    }

    /// The mode's code.
    pub fn code(self) -> u64 {
        match self {
            Self::Extends => 0,
            Self::Narrows => 1,
        }
    }
}

/// One capability: a name and its mode.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Capability {
    /// The capability's name.
    pub name: String,
    /// Its mode.
    pub mode: Mode,
}

impl Capability {
    /// A capability of this name and mode.
    pub fn new(name: impl Into<String>, mode: Mode) -> Self {
        Self {
            name: name.into(),
            mode,
        }
    }
}

/// The capabilities a writer holds at a unit's place, sorted by name and
/// then mode, each once.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct Capabilities {
    list: Vec<Capability>,
}

impl Capabilities {
    /// No capabilities: a writer with a plain grant.
    pub fn none() -> Self {
        Self::default()
    }

    /// These capabilities, sorted, each once.
    pub fn new(capabilities: impl IntoIterator<Item = Capability>) -> Self {
        let mut list: Vec<Capability> = capabilities.into_iter().collect();
        list.sort();
        list.dedup();
        Self { list }
    }

    /// The capabilities, sorted by name and then mode.
    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.list.iter()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// Whether the writer holds this name with this mode.
    pub fn has(&self, name: &str, mode: Mode) -> bool {
        self.list
            .iter()
            .any(|capability| capability.name == name && capability.mode == mode)
    }

    /// Whether the writer holds this name with mode narrows.
    pub fn narrows(&self, name: &str) -> bool {
        self.has(name, Mode::Narrows)
    }

    /// Whether the writer holds this name with mode extends.
    pub fn extends(&self, name: &str) -> bool {
        self.has(name, Mode::Extends)
    }

    /// Whether the writer is a **suggester**: its grant carries `suggest`
    /// with mode narrows (units.md, section 3.17, "`suggest`"). With mode
    /// extends, `suggest` means nothing to the built-in adapters.
    pub fn is_suggester(&self) -> bool {
        self.narrows(SUGGEST)
    }
}

impl FromIterator<Capability> for Capabilities {
    fn from_iter<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        Self::new(iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes_have_their_codes() {
        assert_eq!(Mode::from_code(0), Some(Mode::Extends));
        assert_eq!(Mode::from_code(1), Some(Mode::Narrows));
        assert_eq!(Mode::from_code(2), None);
        assert_eq!(Mode::Narrows.code(), 1);
    }

    #[test]
    fn only_a_narrowing_suggest_makes_a_suggester() {
        assert!(!Capabilities::none().is_suggester());
        let extends = Capabilities::new([Capability::new(SUGGEST, Mode::Extends)]);
        assert!(!extends.is_suggester());
        assert!(extends.extends(SUGGEST));
        let narrows: Capabilities = [
            Capability::new("tag", Mode::Extends),
            Capability::new(SUGGEST, Mode::Narrows),
            Capability::new("tag", Mode::Extends),
        ]
        .into_iter()
        .collect();
        assert!(narrows.is_suggester());
        assert_eq!(narrows.iter().count(), 2);
        assert_eq!(
            narrows.iter().next().map(|c| c.name.as_str()),
            Some(SUGGEST)
        );
    }
}
