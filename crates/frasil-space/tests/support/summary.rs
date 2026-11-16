use frasil_events::EventId;
use frasil_space::record_stream::RecordSink;
use frasil_space::{
    CheckpointPart, ReadRecord, RecordFault, RecordMode, RecordObject, RecordObjects, RecordStream,
};
use std::{collections::BTreeMap, sync::Arc};

pub struct Summaries(pub BTreeMap<EventId, RecordObject>);
impl Summaries {
    pub fn new(records: &BTreeMap<EventId, Vec<u8>>) -> Self {
        Self(
            records
                .iter()
                .map(|(id, bytes)| {
                    let mut sink = RecordStream::new(RecordMode::Summary);
                    for fragment in bytes.chunks(137) {
                        sink.feed(fragment);
                    }
                    let result = match sink.finish() {
                        Ok(ReadRecord::Summary(summary)) => {
                            RecordObject::Summary(Arc::new(summary))
                        }
                        Err(RecordFault::Extension(link)) => RecordObject::Extension(link),
                        _ => RecordObject::Refused,
                    };
                    (*id, result)
                })
                .collect(),
        )
    }
}
impl RecordObjects for Summaries {
    /// As a replica's finished read gives it: a record of another epoch
    /// than the roster part's is refused, and a held record's link kept
    /// only at that epoch.
    fn record_object(&self, id: EventId, part: &CheckpointPart) -> RecordObject {
        match self.0.get(&id).cloned() {
            Some(RecordObject::Summary(summary)) if summary.epoch != part.epoch => {
                RecordObject::Refused
            }
            Some(RecordObject::Extension(link)) => {
                RecordObject::Extension(link.filter(|(epoch, _)| *epoch == part.epoch))
            }
            other => other.unwrap_or(RecordObject::Missing),
        }
    }
}
pub fn same(left: &frasil_space::Judged, right: &frasil_space::Judged) {
    assert_eq!(left.statuses, right.statuses);
    assert_eq!(left.chain, right.chain);
    assert_eq!(left.roster, right.roster);
    assert_eq!(left.policy, right.policy);
    assert_eq!(left.needs_later_rules, right.needs_later_rules);
}
