//! A skeleton cut's standing entries (peers.md, "Storage events"; roster.md,
//! 3.15.4 Votes and effect): what a peer, which reads no roster, needs to
//! know whose votes a cut waits for and who may excuse whom, as replicas
//! read it from the checkpoint's record.
//!
//! A standing entry is `[slot reference, order, dormant, pseudonym]`, one
//! for the administrator slot each administrator of the record holds there
//! (its member entry's key 13), and one for the most senior slot made for
//! each member the checkpoint hears, which is out in the skeleton of the
//! checkpoint's past. A member with no such slot has no entry:
//!
//! - `order`, from 1, is the entry's place among the entries, by the rank of
//!   each one's member, highest first, then by its seniority, most senior
//!   first, as the record gives them: the orders are 1 to the number of
//!   entries, with no gap for a member that has none;
//! - `dormant` is 0 for a member whose capabilities do not extend
//!   `frasil.dormant`, and for a heard member; otherwise 1, or 2 when the
//!   predecessor's record lists it so too (a recovery member), or `2 + k`
//!   when, without a predecessor, its grant in the checkpoint's past was
//!   signed by a member that exactly `k - 1` entries outrank, whether or not
//!   that member has an entry itself;
//! - `pseudonym`, for a slot that is out, the root or enrolment of the
//!   pseudonym enrolled in it, which votes for it; none for one of the
//!   cut's own slots, whose slot entry names it.
//!
//! [`standing_entries`] derives them from a record; a client builds a cut
//! with them ([`Checkpointed::standing_naming`]), and a replica checks a
//! cut's own against them (roster.md, 3.15.2, step 9).

use super::{AuthorityKey, Checkpointed, Outcome, entry_key, extends_dormant};
use crate::checkpoint_record::Record;
use crate::member::{Level, MemberRef, MemberType};
use frasil_base::collect::CollectMap;
use frasil_crypto::device::DeviceId;
use frasil_events::EventId;
use frasil_peers::body::{SlotId, StandingEntry};
use frasil_peers::cut::{Dormancy, StandingMember};
use std::collections::{BTreeMap, BTreeSet};

/// The slot a member's standing entry names, with the root or enrolment of
/// the pseudonym enrolled in it when it is out.
type Named = (SlotId, Option<EventId>);

/// The standing entries `record` gives (peers.md, "Storage events"),
/// strictly ascending by the bytes of their slot references. This reads
/// the record into the peers crate's [`StandingMember`]s, and
/// [`frasil_peers::cut::standing_entries`] orders them, so that one
/// derivation serves the client that builds a cut, the replica that checks
/// it and the peer:
///
/// - `space`, the space ID, which the seniority hash reads;
/// - `previous`, the predecessor's record when the record names one and
///   the replica reads it: a dormant member it lists at `administer` with
///   `frasil.dormant` too is a recovery member (2);
/// - `granter`, the author of an event of the checkpoint's past, by ID:
///   without a predecessor, a dormant member whose grant another member of
///   the record signed, an administrator or a heard member with or without
///   an entry, is `3 + n`, `n` the entries that outrank the granter; a grant
///   it cannot name leaves it 1;
/// - `heard_slots`, for each member the record hears, the most senior slot
///   made for it that is out in the skeleton of the checkpoint's past, with
///   the root or enrolment of the pseudonym enrolled in it. A heard member
///   without one has no entry.
///
/// An administrator without a `slot` entry (key 13) has no entry either,
/// and takes no order. A member both kept at `administer` and heard has one
/// entry: the heard member's rank and seniority, and its out slot when it
/// has one, else its administrator slot; its `dormant` is its
/// administrator entry's.
pub fn standing_entries(
    record: &Record,
    previous: Option<&Record>,
    space: &EventId,
    granter: impl Fn(EventId) -> Option<DeviceId>,
    heard_slots: &BTreeMap<DeviceId, Named>,
) -> Vec<StandingEntry> {
    frasil_peers::cut::standing_entries(&standing_members(
        record,
        previous,
        space,
        granter,
        heard_slots,
    ))
}

/// The members a standing entry may name, as the peers crate reads them:
/// the record's administrators and the members it hears, each once.
fn standing_members(
    record: &Record,
    previous: Option<&Record>,
    space: &EventId,
    granter: impl Fn(EventId) -> Option<DeviceId>,
    heard_slots: &BTreeMap<DeviceId, Named>,
) -> Vec<StandingMember<AuthorityKey>> {
    let administrators: BTreeMap<DeviceId, &crate::MemberEntry> = record
        .members
        .iter()
        .filter(|entry| entry.member.kind == MemberType::Device && entry.level == Level::Administer)
        .filter_map(|entry| Some((entry.member.device_id()?, entry)))
        .collect_map();
    // Every member's order of authority: an administrator's from its entry,
    // a heard member's from its heard row, which wins for one that is both.
    let mut keys: BTreeMap<DeviceId, AuthorityKey> = administrators
        .iter()
        .map(|(device, entry)| (*device, entry_key(space, entry)))
        .collect_map();
    for heard in &record.heard {
        keys.insert(
            heard.device,
            (
                crate::change::MAX_RANK - heard.rank,
                heard.full_seniority(space),
            ),
        );
    }
    // The slot each member's entry names: its administrator slot, or, for
    // a member heard with a slot out, that slot.
    let mut named: BTreeMap<DeviceId, Named> = administrators
        .iter()
        .filter_map(|(device, entry)| {
            let slot = entry.slot.as_ref()?;
            let index = u8::try_from(slot.index).ok()?;
            Some((
                *device,
                (SlotId::new(slot.commitment, index, slot.maker), None),
            ))
        })
        .collect_map();
    for heard in &record.heard {
        if let Some(&slot) = heard_slots.get(&heard.device) {
            named.insert(heard.device, slot);
        }
    }
    let index: BTreeMap<DeviceId, usize> = keys
        .keys()
        .enumerate()
        .map(|(n, device)| (*device, n))
        .collect_map();
    keys.iter()
        .map(|(device, &key)| {
            let dormancy = match administrators.get(device) {
                Some(entry) if extends_dormant(&entry.capabilities) => match record.previous {
                    Some(_) => {
                        let listed = previous.is_some_and(|previous| {
                            previous
                                .entry(&MemberRef::device(*device))
                                .is_some_and(|p| {
                                    p.level == Level::Administer && extends_dormant(&p.capabilities)
                                })
                        });
                        match listed {
                            true => Dormancy::Recovery,
                            false => Dormancy::Dormant,
                        }
                    }
                    None => match granter(entry.seniority.2).and_then(|by| index.get(&by)) {
                        Some(&k) => Dormancy::GrantedBy(k),
                        None => Dormancy::Dormant,
                    },
                },
                _ => Dormancy::Votes,
            };
            let (slot, pseudonym) = match named.get(device) {
                Some(&(slot, pseudonym)) => (Some(slot), pseudonym),
                None => (None, None),
            };
            StandingMember {
                key,
                slot,
                pseudonym,
                dormancy,
            }
        })
        .collect()
}

impl Checkpointed<'_> {
    /// The standing entries of the cut of a checkpoint over `past` that
    /// names `previous` (peers.md, "Storage events"): those
    /// [`standing_entries`] gives for the record
    /// [`Self::record_naming`] derives, with the slots out in the skeleton
    /// of that past for its heard members. What a client that proposes a
    /// checkpoint puts in its cut's key 8. `None` as for the record.
    pub fn standing_naming(
        &self,
        past: &BTreeSet<EventId>,
        previous: Option<EventId>,
    ) -> Option<Vec<StandingEntry>> {
        let outcome = self.outcome_naming(past, previous)?;
        let record = self.record_of(&outcome, previous)?;
        Some(self.standing_of(&record, &outcome))
    }

    /// The standing entries of the cut of a checkpoint over `past` that
    /// names the last checkpoint in effect there, as an honest client names
    /// it ([`Self::record_for`]).
    pub fn standing_for(&self, past: &BTreeSet<EventId>) -> Option<Vec<StandingEntry>> {
        let judged = self.judge(past);
        let previous = judged.chain.last().copied();
        self.standing_naming(past, previous)
    }

    /// The standing entries `record` gives, the record of a checkpoint
    /// whose past resolved to `outcome`.
    pub(super) fn standing_of(&self, record: &Record, outcome: &Outcome) -> Vec<StandingEntry> {
        let previous = record.previous.and_then(|p| self.record(p));
        let log = self.log();
        let heard_slots: BTreeMap<DeviceId, Named> = outcome
            .out_slots
            .iter()
            .map(|(device, (_, slot, pseudonym))| (*device, (*slot, *pseudonym)))
            .collect_map();
        standing_entries(
            record,
            previous.as_deref(),
            &log.id(),
            |grant| log.event(grant).map(|event| *event.author()),
            &heard_slots,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::DORMANT;
    use crate::checkpoint_record::{HeardMember, MemberEntry, SlotEntry};
    use crate::member::{Capability, CapabilityMode, HistoryMode, Via};
    use crate::policy::Policy;
    use frasil_crypto::device::DeviceKeys;
    use frasil_crypto::fixtures::FixtureKeys;
    use std::sync::Arc;

    const SPACE: EventId = EventId([0xee; 32]);

    fn keys(n: u8) -> Arc<DeviceKeys> {
        let signer = FixtureKeys::from_identity_seed(&[n; 32]).signer();
        Arc::new(DeviceKeys {
            ed: *signer.identity_key(),
            keys: signer.keys().clone(),
        })
    }

    fn device(n: u8) -> DeviceId {
        keys(n).device_id()
    }

    fn slot_of(n: u8) -> SlotEntry {
        SlotEntry {
            commitment: [n; 32],
            index: 0,
            maker: EventId([n; 32]),
            pseudonym: vec![n; 32],
        }
    }

    fn slot_id(n: u8) -> SlotId {
        SlotId::new([n; 32], 0, EventId([n; 32]))
    }

    /// The entry of an administrator `n`, granted by event `[n + 100; 32]`
    /// at height `height`, of rank `rank`; dormant with `dormant`.
    fn administrator(n: u8, rank: u8, height: u64, dormant: bool) -> MemberEntry {
        let capabilities = match dormant {
            true => vec![Capability {
                name: DORMANT.into(),
                mode: CapabilityMode::Extends,
            }],
            false => Vec::new(),
        };
        MemberEntry {
            member: MemberRef::device(device(n)),
            level: Level::Administer,
            capabilities,
            label: None,
            history: HistoryMode::WithHistory,
            via: Via::Code,
            session: None,
            replaces: None,
            seniority: (0, height, EventId([n + 100; 32])),
            keys: Some(keys(n)),
            slot: Some(slot_of(n)),
            expires_at: None,
            claims: None,
            invite: None,
            claimant: None,
            notices: Vec::new(),
            floor: false,
            named: Vec::new(),
            rank: Some(rank),
        }
    }

    fn record(members: Vec<MemberEntry>, heard: Vec<HeardMember>) -> Record {
        Record {
            epoch: 1,
            previous: None,
            members,
            policy: Policy::default(),
            tips: BTreeMap::new(),
            forks: BTreeMap::new(),
            heard,
        }
    }

    fn by_slot(entries: &[StandingEntry]) -> BTreeMap<SlotId, (u64, u64)> {
        entries
            .iter()
            .map(|e| (e.slot, (e.order, e.dormant)))
            .collect()
    }

    #[test]
    fn orders_by_rank_then_seniority() {
        // 2 has the highest rank; 1 and 3 share one, 1 the more senior.
        let r = record(
            vec![
                administrator(1, 100, 2, false),
                administrator(2, 200, 5, false),
                administrator(3, 100, 4, false),
            ],
            Vec::new(),
        );
        let entries = standing_entries(&r, None, &SPACE, |_| None, &BTreeMap::new());
        let got = by_slot(&entries);
        assert_eq!(got[&slot_id(2)], (1, 0));
        assert_eq!(got[&slot_id(1)], (2, 0));
        assert_eq!(got[&slot_id(3)], (3, 0));
        let bytes: Vec<Vec<u8>> = entries.iter().map(StandingEntry::sort_bytes).collect();
        assert!(bytes.windows(2).all(|w| w[0] < w[1]), "ascending");
    }

    #[test]
    fn equal_ranks_and_heights_order_by_the_seniority_hash() {
        let r = record(
            vec![
                administrator(1, 100, 3, false),
                administrator(2, 100, 3, false),
            ],
            Vec::new(),
        );
        let entries = standing_entries(&r, None, &SPACE, |_| None, &BTreeMap::new());
        let got = by_slot(&entries);
        let hash = |n: u8| crate::state::seniority_hash(&SPACE, &device(n).0);
        let first = if hash(1) < hash(2) { 1 } else { 2 };
        assert_eq!(got[&slot_id(first)].0, 1);
        assert_eq!(got[&slot_id(3 - first)].0, 2);
    }

    fn heard(n: u8, rank: u8, height: u64) -> HeardMember {
        HeardMember {
            device: device(n),
            seniority: (0, height, EventId([n + 100; 32])),
            rank,
            keys: keys(n),
        }
    }

    #[test]
    fn a_heard_member_names_its_out_slot_and_one_without_takes_no_order() {
        // 9 is heard, of rank 150 and older than 1, its out slot enrolled by
        // event 0x99; 8 is heard of the highest rank with no slot out, and
        // has no entry and no order.
        let r = record(
            vec![
                administrator(1, 150, 4, false),
                administrator(2, 100, 2, false),
            ],
            vec![heard(9, 150, 1), heard(8, 255, 9)],
        );
        let enrolment = EventId([0x99; 32]);
        let slots = BTreeMap::from([(device(9), (slot_id(9), Some(enrolment)))]);
        let entries = standing_entries(&r, None, &SPACE, |_| None, &slots);
        let got = by_slot(&entries);
        assert_eq!(entries.len(), 3);
        assert_eq!(got[&slot_id(9)], (1, 0));
        assert_eq!(got[&slot_id(1)], (2, 0));
        assert_eq!(got[&slot_id(2)], (3, 0));
        let pseudonyms: BTreeMap<SlotId, Option<EventId>> =
            entries.iter().map(|e| (e.slot, e.pseudonym)).collect();
        assert_eq!(pseudonyms[&slot_id(9)], Some(enrolment));
        assert_eq!(pseudonyms[&slot_id(1)], None, "a slot of the cut's own");
    }

    #[test]
    fn a_member_kept_at_administer_dormant_and_heard_has_one_entry() {
        // 3 is in the record at `administer` with `frasil.dormant`, granted
        // by 1, and heard at rank 255, older than 1, with an out slot: one
        // entry, its out slot, its heard rank and seniority, and its
        // administrator entry's dormancy.
        let r = record(
            vec![
                administrator(1, 255, 2, false),
                administrator(3, 100, 5, true),
            ],
            vec![heard(3, 255, 1)],
        );
        let out = SlotId::new([0x33; 32], 1, EventId([0x33; 32]));
        let slots = BTreeMap::from([(device(3), (out, Some(EventId([0x98; 32]))))]);
        let granter = |grant: EventId| (grant.0[0] == 103).then(|| device(1));
        let entries = standing_entries(&r, None, &SPACE, granter, &slots);
        let got = by_slot(&entries);
        assert_eq!(entries.len(), 2);
        assert!(!got.contains_key(&slot_id(3)), "its administrator slot");
        // Its granter, 1, is outranked by one entry, its own: 3 + 1.
        assert_eq!(got[&out], (1, 4));
        assert_eq!(got[&slot_id(1)], (2, 0));
    }

    #[test]
    fn dormant_and_first_epoch_recovery_members() {
        // 3 and 4 are dormant: 1 signed 3's grant, 4 signed its own (a
        // founder's own grant), 5's granter is unknown.
        let r = record(
            vec![
                administrator(1, 255, 1, false),
                administrator(2, 200, 2, false),
                administrator(3, 200, 3, true),
                administrator(4, 100, 4, true),
                administrator(5, 100, 5, true),
            ],
            Vec::new(),
        );
        let granter = |grant: EventId| match grant.0[0] {
            103 => Some(device(1)),
            104 => Some(device(4)),
            _ => None,
        };
        let got = by_slot(&standing_entries(
            &r,
            None,
            &SPACE,
            granter,
            &BTreeMap::new(),
        ));
        assert_eq!(got[&slot_id(1)], (1, 0));
        assert_eq!(got[&slot_id(2)], (2, 0));
        assert_eq!(got[&slot_id(3)], (3, 3));
        assert_eq!(got[&slot_id(4)], (4, 1));
        assert_eq!(got[&slot_id(5)], (5, 1));
    }

    #[test]
    fn a_recovery_member_after_a_predecessor() {
        // With a predecessor, a dormant member is a recovery member when the
        // predecessor lists it so, whoever granted it.
        let mut earlier = record(
            vec![
                administrator(1, 255, 1, false),
                administrator(3, 200, 3, true),
            ],
            Vec::new(),
        );
        earlier.epoch = 1;
        let mut r = record(
            vec![
                administrator(1, 255, 1, false),
                administrator(3, 200, 3, true),
                administrator(4, 200, 4, true),
            ],
            Vec::new(),
        );
        r.epoch = 2;
        r.previous = Some(EventId([0x77; 32]));
        let granter = |_| Some(device(1));
        let got = by_slot(&standing_entries(
            &r,
            Some(&earlier),
            &SPACE,
            granter,
            &BTreeMap::new(),
        ));
        assert_eq!(got[&slot_id(3)], (2, 2));
        assert_eq!(got[&slot_id(4)], (3, 1));
        // A predecessor the replica cannot read leaves them dormant.
        let got = by_slot(&standing_entries(
            &r,
            None,
            &SPACE,
            granter,
            &BTreeMap::new(),
        ));
        assert_eq!(got[&slot_id(3)], (2, 1));
    }

    #[test]
    fn an_administrator_without_a_slot_takes_no_order() {
        let mut slotless = administrator(2, 200, 2, false);
        slotless.slot = None;
        let r = record(
            vec![
                administrator(1, 255, 1, false),
                slotless,
                administrator(3, 100, 3, false),
            ],
            Vec::new(),
        );
        let got = by_slot(&standing_entries(
            &r,
            None,
            &SPACE,
            |_| None,
            &BTreeMap::new(),
        ));
        assert_eq!(got.len(), 2);
        assert_eq!(got[&slot_id(1)], (1, 0));
        assert_eq!(got[&slot_id(3)], (2, 0), "no gap for the one without");
    }

    #[test]
    fn a_granter_without_an_entry_still_counts() {
        // 2 has no slot and outranks 3, whose grant it signed: 3 is excused
        // by the slots at least as far down as the one entry that outranks
        // 2, 1's: 3 + 1. 4's granter is 1, which nothing outranks: 3 + 0.
        let mut slotless = administrator(2, 200, 2, false);
        slotless.slot = None;
        let r = record(
            vec![
                administrator(1, 255, 1, false),
                slotless,
                administrator(3, 100, 3, true),
                administrator(4, 100, 4, true),
            ],
            Vec::new(),
        );
        let granter = |grant: EventId| match grant.0[0] {
            103 => Some(device(2)),
            104 => Some(device(1)),
            _ => None,
        };
        let got = by_slot(&standing_entries(
            &r,
            None,
            &SPACE,
            granter,
            &BTreeMap::new(),
        ));
        assert_eq!(got[&slot_id(1)], (1, 0));
        assert_eq!(got[&slot_id(3)], (2, 4));
        assert_eq!(got[&slot_id(4)], (3, 3));
    }
}
