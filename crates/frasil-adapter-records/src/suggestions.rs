//! Suggestions (adapter-records.md, sections 2.2 and 3.4), which
//! adapter-blobs.md shares: keys 4 to 6 of a changeset, the `suggest`
//! check, and the suggestion layer.

use crate::read;
use frasil_adapter::{Author, Context, EventId};
use frasil_base::cbor::{Map, Value};
use frasil_base::errors::ErrorClass;
use std::collections::{BTreeMap, BTreeSet};

/// The most event IDs `accepts` or `dismisses` names.
pub const MAX_TARGETS: usize = 64;

/// Keys 4 to 6 of a changeset: whether it is a suggestion, and the
/// suggestions it accepts or dismisses.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct SuggestionKeys {
    /// Key 4: the changeset is a suggestion.
    pub suggestion: bool,
    /// Key 5: the suggestions it accepts, strictly ascending; empty when
    /// the key is absent.
    pub accepts: Vec<EventId>,
    /// Key 6: the suggestions it dismisses, strictly ascending; empty when
    /// the key is absent.
    pub dismisses: Vec<EventId>,
}

impl SuggestionKeys {
    /// Reads keys 4 to 6 of a changeset's map: key 4 is 1; keys 5 and 6 are 1
    /// to 64 event IDs, strictly ascending; and keys 5 and 6 never appear with
    /// key 4 (adapter-records.md, section 3.2, "The checks", steps 2 and 3).
    pub fn read(map: &Map) -> Result<Self, ErrorClass> {
        let suggestion = match map.get(&4) {
            None => false,
            Some(Value::Unsigned(1)) => true,
            Some(_) => return Err(ErrorClass::Malformed),
        };
        let accepts = read_targets(map.get(&5))?;
        let dismisses = read_targets(map.get(&6))?;
        if suggestion && (map.contains_key(&5) || map.contains_key(&6)) {
            return Err(ErrorClass::Malformed);
        }
        Ok(Self {
            suggestion,
            accepts,
            dismisses,
        })
    }

    /// Writes keys 4 to 6 into a changeset's map.
    pub fn write(&self, map: &mut Map) {
        if self.suggestion {
            map.insert(4, Value::Unsigned(1));
        }
        for (key, targets) in [(5, &self.accepts), (6, &self.dismisses)] {
            if !targets.is_empty() {
                let ids = targets.iter().map(|id| Value::from(*id)).collect();
                map.insert(key, Value::Array(ids));
            }
        }
    }

    /// The suggestions an applied changeset closes: those it accepts and
    /// those it dismisses.
    pub fn targets(&self) -> impl Iterator<Item = &EventId> {
        self.accepts.iter().chain(&self.dismisses)
    }

    /// The `suggest` check on a log unit: a writer narrowed by `suggest`
    /// writes only changesets with key 4 and without keys 5 and 6. Anything
    /// else from it is `CapabilityRefused` (adapter-records.md, section
    /// 3.4).
    pub fn suggest_check(&self, context: &Context) -> Result<(), ErrorClass> {
        let only_a_suggestion =
            self.suggestion && self.accepts.is_empty() && self.dismisses.is_empty();
        if context.capabilities.is_suggester() && !only_a_suggestion {
            return Err(ErrorClass::CapabilityRefused);
        }
        Ok(())
    }
}

fn read_targets(value: Option<&Value>) -> Result<Vec<EventId>, ErrorClass> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = value.as_array()?;
    if !(1..=MAX_TARGETS).contains(&items.len()) {
        return Err(ErrorClass::Malformed);
    }
    let ids = items
        .iter()
        .map(|item| Ok(item.as_byte_array::<32>()?))
        .collect::<Result<Vec<EventId>, ErrorClass>>()?;
    read::strictly_ascending(&ids)?;
    Ok(ids)
}

/// One open suggestion: its author and its changeset's content.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Suggestion {
    /// The suggestion's author.
    pub author: Author,
    /// Its changeset's content, as written.
    pub content: Vec<u8>,
}

/// A stream's suggestion layer: the open suggestions by event ID, and the
/// suggestions an applied accept or dismiss named (adapter-records.md,
/// section 3.4). A suggestion that an applied accept or dismiss names
/// leaves the layer, or never enters it, whatever the order of arrival.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Layer {
    open: BTreeMap<EventId, Suggestion>,
    closed: BTreeSet<EventId>,
}

impl Layer {
    /// An empty layer.
    pub fn new() -> Self {
        Self::default()
    }

    /// A suggestion arrives: it enters the layer unless an applied accept
    /// or dismiss already named it.
    pub fn suggest(&mut self, event_id: EventId, suggestion: Suggestion) {
        if !self.closed.contains(&event_id) {
            self.open.insert(event_id, suggestion);
        }
    }

    /// An applied accept or dismiss names a suggestion: it leaves the
    /// layer, or never enters it.
    pub fn close(&mut self, event_id: EventId) {
        self.closed.insert(event_id);
        self.open.remove(&event_id);
    }

    /// The open suggestions, ascending by event ID.
    pub fn open(&self) -> &BTreeMap<EventId, Suggestion> {
        &self.open
    }

    /// Whether a suggestion is open.
    pub fn is_open(&self, event_id: &EventId) -> bool {
        self.open.contains_key(event_id)
    }

    /// The snapshot state's key 4: `[event ID, author, changeset content]`
    /// per open suggestion, strictly ascending by event ID; `None` when no
    /// suggestion is open.
    pub fn to_value(&self) -> Option<Value> {
        if self.open.is_empty() {
            return None;
        }
        let rows = self
            .open
            .iter()
            .map(|(event_id, suggestion)| {
                Value::Array(vec![
                    Value::from(*event_id),
                    Value::from(suggestion.author),
                    Value::from(suggestion.content.clone()),
                ])
            })
            .collect();
        Some(Value::Array(rows))
    }

    /// Reads a snapshot state's key 4, given how to check that a content is
    /// a suggestion of the adapter's. Absent, the layer is empty; present,
    /// it holds 1 or more suggestions, strictly ascending by event ID.
    pub fn from_value(
        value: Option<&Value>,
        is_suggestion: impl Fn(&[u8]) -> bool,
    ) -> Result<Self, ErrorClass> {
        let mut layer = Self::new();
        let Some(value) = value else {
            return Ok(layer);
        };
        let rows = value.as_array()?;
        if rows.is_empty() {
            return Err(ErrorClass::Malformed);
        }
        let mut previous: Option<EventId> = None;
        for row in rows {
            let [event_id, author, content] = row.as_array()? else {
                return Err(ErrorClass::Malformed);
            };
            let event_id = event_id.as_byte_array::<32>()?;
            if previous.is_some_and(|previous| previous >= event_id) {
                return Err(ErrorClass::Malformed);
            }
            previous = Some(event_id);
            let content = content.as_bytes()?;
            if !is_suggestion(content) {
                return Err(ErrorClass::Malformed);
            }
            layer.open.insert(
                event_id,
                Suggestion {
                    author: author.as_byte_array::<32>()?,
                    content: content.to_vec(),
                },
            );
        }
        Ok(layer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use frasil_adapter::{Capabilities, Capability, Mode, Role, SUGGEST};

    fn keys(entries: &[(u64, Value)]) -> Result<SuggestionKeys, ErrorClass> {
        SuggestionKeys::read(&entries.iter().cloned().collect())
    }

    fn ids(n: &[u8]) -> Value {
        Value::Array(n.iter().map(|b| Value::from([*b; 32])).collect())
    }

    #[test]
    fn reads_and_writes_keys_4_to_6() {
        let read = keys(&[(5, ids(&[1, 2])), (6, ids(&[3]))]).unwrap();
        assert_eq!(read.accepts, vec![[1; 32], [2; 32]]);
        assert_eq!(read.targets().count(), 3);
        let mut map = Map::new();
        read.write(&mut map);
        assert_eq!(SuggestionKeys::read(&map), Ok(read));
        assert!(keys(&[(4, Value::Unsigned(1))]).unwrap().suggestion);
    }

    #[test]
    fn refuses_what_section_2_2_forbids() {
        for bad in [
            vec![(4, Value::Unsigned(2))],
            vec![(4, Value::Unsigned(1)), (5, ids(&[1]))],
            vec![(4, Value::Unsigned(1)), (6, ids(&[1]))],
            vec![(5, ids(&[]))],
            vec![(5, ids(&[2, 1]))],
            vec![(6, ids(&[1, 1]))],
            vec![(5, Value::Array(vec![Value::from([1u8; 31])]))],
        ] {
            assert_eq!(keys(&bad), Err(ErrorClass::Malformed), "{bad:?}");
        }
        let many: Vec<u8> = (0..64).collect();
        assert_eq!(keys(&[(5, ids(&many))]).unwrap().accepts.len(), 64);
        let too_many: Vec<u8> = (0..65).collect();
        assert_eq!(keys(&[(5, ids(&too_many))]), Err(ErrorClass::Malformed));
    }

    #[test]
    fn a_suggester_writes_only_suggestions() {
        let suggester = Context::new([0; 32], [1; 16], [2; 32], [3; 32], 1, 1, Role::Log)
            .with_capabilities(Capabilities::new([Capability::new(SUGGEST, Mode::Narrows)]));
        let suggestion = SuggestionKeys {
            suggestion: true,
            ..SuggestionKeys::default()
        };
        assert_eq!(suggestion.suggest_check(&suggester), Ok(()));
        let accept = SuggestionKeys {
            accepts: vec![[1; 32]],
            ..SuggestionKeys::default()
        };
        assert_eq!(
            accept.suggest_check(&suggester),
            Err(ErrorClass::CapabilityRefused)
        );
        assert_eq!(
            SuggestionKeys::default().suggest_check(&suggester),
            Err(ErrorClass::CapabilityRefused)
        );
    }

    #[test]
    fn a_closed_suggestion_never_enters_the_layer() {
        let suggestion = Suggestion {
            author: [7; 32],
            content: vec![1],
        };
        let mut first = Layer::new();
        first.suggest([1; 32], suggestion.clone());
        first.close([1; 32]);
        let mut second = Layer::new();
        second.close([1; 32]);
        second.suggest([1; 32], suggestion.clone());
        assert_eq!(first.open(), second.open());
        assert!(first.to_value().is_none());
        let mut open = Layer::new();
        open.suggest([2; 32], suggestion);
        assert!(open.is_open(&[2; 32]));
        let value = open.to_value().unwrap();
        let read = Layer::from_value(Some(&value), |c| c == [1]).unwrap();
        assert_eq!(read.open(), open.open());
        assert!(Layer::from_value(Some(&value), |_| false).is_err());
        assert!(Layer::from_value(Some(&Value::Array(vec![])), |_| true).is_err());
    }
}
