//! An `add` signed again by another list member (identity.md, "The
//! possession statement", "Checking a list event alone" and "The merge").
//!
//! A possession proof names its adder, so a list member that copies the
//! body of another member's `add`, proof included, and signs it on its own
//! chain makes an `add` whose proof does not verify: `BadPossession` at
//! step 5 of `check_alone`. The honest `add` alone roots the list member,
//! which keeps its rank whether the copy is concurrent with the honest
//! `add` or after it, before or after it in canonical order, and in every
//! order of arrival.

mod common;

use common::{bytes, check_summary, device, device_names, family, text};
use frasil_base::ErrorClass;
use frasil_crypto::device::DeviceId;
use frasil_crypto::schemes::Scheme;
use frasil_events::kind::DEVICE_LIST;
use frasil_events::{Envelope, EventId, decode};
use frasil_identity::body::ListBody;
use frasil_identity::{DeviceList, IdentityClass, Kind, MemberKeys, Rank, Rootedness};
use serde_json::Value as Json;
use std::collections::BTreeMap;

const PREFIX: &str = "identity/replayed-adds";

/// A list built event by event, each with the parents it is given.
struct Builder {
    list: DeviceList,
    keys: BTreeMap<&'static str, MemberKeys>,
    /// Each author's latest event: its `seq` and ID.
    chains: BTreeMap<DeviceId, (u64, EventId)>,
    signed: Vec<Vec<u8>>,
}

impl Builder {
    fn new() -> Self {
        let laptop = device(PREFIX, "laptop");
        let first = DeviceList::first_event(&laptop);
        let list = DeviceList::new(&first).unwrap();
        let chains = BTreeMap::from([(*laptop.device_id(), (1, list.first()))]);
        Self {
            list,
            keys: BTreeMap::from([("laptop", laptop)]),
            chains,
            signed: vec![first],
        }
    }

    fn first(&self) -> EventId {
        self.list.first()
    }

    fn keys(&mut self, name: &'static str) -> &MemberKeys {
        self.keys.entry(name).or_insert_with(|| {
            // An agent has no X-Wing key.
            if name == "agent" {
                common::agent(PREFIX, name)
            } else {
                device(PREFIX, name)
            }
        })
    }

    /// `signer` adds `name` as `kind` with the proof `name` signs for
    /// `signer`, citing `parents` and its own latest event.
    fn add(
        &mut self,
        signer: &'static str,
        name: &'static str,
        kind: Kind,
        parents: &[EventId],
    ) -> EventId {
        let person = self.list.person_id();
        let adder = *self.keys(signer).device_id();
        let added = self.keys(name);
        let body = ListBody::add(
            kind,
            &added.public(kind),
            added.prove_possession(&person, &adder, kind),
        );
        self.sign(signer, &body, parents)
    }

    /// `signer` signs the body of `add` again, on its own chain, citing
    /// `parents` and its own latest event.
    fn replay(&mut self, signer: &'static str, add: EventId, parents: &[EventId]) -> EventId {
        let body = ListBody::decode(self.list.log().event(add).unwrap().unverified_body()).unwrap();
        self.sign(signer, &body, parents)
    }

    fn sign(&mut self, signer: &'static str, body: &ListBody, parents: &[EventId]) -> EventId {
        let keys = self.keys(signer);
        let author = *keys.device_id();
        let (ed, kc) = (*keys.identity(), *keys.signer().kc());
        let prev = self.chains.get(&author).copied();
        let mut cited: Vec<EventId> = parents.to_vec();
        cited.extend(prev.map(|(_, id)| id));
        cited.sort();
        cited.dedup();
        let signed = Envelope {
            kind: DEVICE_LIST,
            log: Some(self.list.first()),
            ed,
            kc,
            seq: prev.map_or(1, |(seq, _)| seq + 1),
            prev: prev.map(|(_, id)| id),
            parents: cited,
            cuts: Vec::new(),
            body: body.encode(),
            scheme: Scheme::Hybrid,
        }
        .sign(self.keys[signer].signer());
        let id = decode(&signed).unwrap().id();
        self.list.insert(&signed).unwrap();
        self.chains
            .insert(author, (prev.map_or(1, |(seq, _)| seq + 1), id));
        self.signed.push(signed);
        id
    }

    fn identity(&self, name: &str) -> DeviceId {
        *self.keys[name].device_id()
    }
}

/// Every order of `items`.
fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let head = rest.remove(i);
        for mut tail in permutations(&rest) {
            tail.insert(0, head.clone());
            out.push(tail);
        }
    }
    out
}

/// Inserts the list's events after the first in every order, and checks
/// each merge: the copy fails `BadPossession` alone and is void; the target
/// is active, rooted as the honest `add` roots it, and of `rank`.
fn check_every_order(b: &Builder, replayed: EventId, target: &str, rank: Rank, case: &str) {
    let identity = b.identity(target);
    let rest: Vec<&Vec<u8>> = b.signed[1..].iter().collect();
    for order in permutations(&rest) {
        let mut list = DeviceList::new(&b.signed[0]).unwrap();
        for signed in &order {
            list.insert(signed).unwrap();
        }
        assert_eq!(
            list.log().len(),
            b.signed.len(),
            "{case}: every event placed"
        );
        assert_eq!(
            list.check_alone(replayed),
            Some(IdentityClass::Shared(ErrorClass::BadPossession)),
            "{case}: the copy's proof names another adder",
        );
        let merged = list.merge();
        assert!(!merged.is_valid(replayed), "{case}: the copy is void");
        let member = merged
            .active(&identity)
            .unwrap_or_else(|| panic!("{case}: {target} is active"));
        assert_eq!(member.adds.len(), 1, "{case}: only the honest add names it");
        assert_eq!(member.rooted(), Rootedness::None, "{case}: not rooted");
        assert_eq!(member.rank(), rank, "{case}: rank");
    }
}

/// How the copy relates to the honest `add`.
#[derive(Clone, Copy, Debug)]
enum Timing {
    /// Concurrent, and first in canonical order: it is lower.
    ConcurrentBefore,
    /// Concurrent, and after in canonical order: it is higher.
    ConcurrentAfter,
    /// The honest `add` is in its past.
    After,
}

const TIMINGS: [Timing; 3] = [
    Timing::ConcurrentBefore,
    Timing::ConcurrentAfter,
    Timing::After,
];

/// The laptop names an agent, then adds `target` as `kind`; the agent
/// signs the copy, through `copier` (the agent, or a device it added).
fn agent_case(kind: Kind, copier: &'static str, timing: Timing) -> (Builder, EventId) {
    let mut b = Builder::new();
    let first = b.first();
    let named = b.add("laptop", "agent", Kind::RecoveryAgent, &[first]);
    // The agent's own device, when it is the one that copies.
    let mut agent_side = named;
    if copier != "agent" {
        agent_side = b.add("agent", copier, Kind::Device, &[named]);
    }
    // The honest add, made after the agent was named. For a copy first in
    // canonical order, the laptop adds another device before it.
    let before_honest = match timing {
        Timing::ConcurrentBefore => b.add("laptop", "tablet", Kind::Device, &[named]),
        _ => named,
    };
    let honest = b.add("laptop", "target", kind, &[before_honest]);
    let replayed = match timing {
        Timing::ConcurrentBefore => b.replay(copier, honest, &[agent_side]),
        Timing::ConcurrentAfter => {
            // The copier's side grows first, so the copy is higher.
            let other = if copier == "agent" {
                b.add("agent", "other", Kind::Device, &[agent_side])
            } else {
                b.add(copier, "other", Kind::Device, &[agent_side])
            };
            b.replay(copier, honest, &[other])
        }
        Timing::After => b.replay(copier, honest, &[agent_side, honest]),
    };
    (b, replayed)
}

/// The laptop adds a passkey member, then `target` as `kind`; the passkey
/// member signs the copy.
fn passkey_case(kind: Kind, timing: Timing) -> (Builder, EventId) {
    let mut b = Builder::new();
    let first = b.first();
    let passkey = b.add("laptop", "passkey", Kind::PasskeyMember, &[first]);
    let before_honest = match timing {
        Timing::ConcurrentBefore => b.add("laptop", "tablet", Kind::Device, &[passkey]),
        _ => passkey,
    };
    let honest = b.add("laptop", "target", kind, &[before_honest]);
    let replayed = match timing {
        Timing::ConcurrentBefore => b.replay("passkey", honest, &[passkey]),
        Timing::ConcurrentAfter => {
            let other = b.add("passkey", "other", Kind::Device, &[passkey]);
            b.replay("passkey", honest, &[other])
        }
        Timing::After => b.replay("passkey", honest, &[passkey, honest]),
    };
    (b, replayed)
}

/// The rank of a list member that is not rooted.
fn unrooted_rank(kind: Kind) -> Rank {
    match kind {
        Kind::RecoveryKey => Rank::RecoveryKey,
        _ => Rank::Device,
    }
}

#[test]
fn an_agent_cannot_root_a_device_by_signing_its_add_again() {
    for timing in TIMINGS {
        let (b, replayed) = agent_case(Kind::Device, "agent", timing);
        let case = format!("the agent copies a device's add, {timing:?}");
        check_every_order(&b, replayed, "target", Rank::Device, &case);
    }
}

#[test]
fn a_device_rooted_in_an_agent_cannot_root_a_recovery_key_by_signing_its_add_again() {
    for kind in [Kind::RecoveryKey, Kind::Device] {
        for timing in TIMINGS {
            let (b, replayed) = agent_case(kind, "helped", timing);
            let case = format!("the agent's device copies a {kind:?}'s add, {timing:?}");
            check_every_order(&b, replayed, "target", unrooted_rank(kind), &case);
        }
    }
}

#[test]
fn a_passkey_member_cannot_root_a_list_member_by_signing_its_add_again() {
    for kind in [Kind::Device, Kind::RecoveryKey] {
        for timing in TIMINGS {
            let (b, replayed) = passkey_case(kind, timing);
            let case = format!("the passkey member copies a {kind:?}'s add, {timing:?}");
            check_every_order(&b, replayed, "target", unrooted_rank(kind), &case);
        }
    }
}

/// A device that two list members each add with a proof for itself, one
/// of them an agent, concurrently: both `add`s stand and describe one list
/// member, which takes the most rooted of them (identity.md, "The merge").
#[test]
fn a_device_two_list_members_add_with_a_proof_for_each_takes_the_most_rooted() {
    let mut b = Builder::new();
    let first = b.first();
    let named = b.add("laptop", "agent", Kind::RecoveryAgent, &[first]);
    let by_laptop = b.add("laptop", "target", Kind::Device, &[named]);
    let by_agent = b.add("agent", "target", Kind::Device, &[named]);
    let merged = b.list.merge();
    assert!(merged.is_valid(by_laptop) && merged.is_valid(by_agent));
    let member = merged.active(&b.identity("target")).unwrap();
    assert_eq!(member.adds.len(), 2);
    assert_eq!(member.rooted(), Rootedness::Agent);
    assert_eq!(member.rank(), Rank::Agent);
}

/// `identity.json`: `replayed_adds`. Each list, inserted in canonical order
/// and in reverse, merges as the vectors say: the copy is `BadPossession`
/// and the list member keeps the rank the honest `add` gives it.
#[test]
fn replayed_adds() {
    let f = family("replayed_adds");
    let cases = f.as_array().unwrap();
    assert_eq!(cases.len(), 7);
    for (i, case) in cases.iter().enumerate() {
        let name = text(case, "name");
        let prefix = format!("identity/replayed/{i}");
        let members = device_names(&prefix, case);
        let rows: Vec<&Json> = case["log"].as_array().unwrap().iter().collect();
        let (list, names) = common::list_of(&rows);
        check_summary(name, &list.merge(), &names, &members, case);
        let mut reversed = DeviceList::new(&bytes(rows[0], "signed")).unwrap();
        for row in rows[1..].iter().rev() {
            reversed.insert(&bytes(row, "signed")).unwrap();
        }
        check_summary(name, &reversed.merge(), &names, &members, case);
        let copies: Vec<_> = case["events"]
            .as_object()
            .unwrap()
            .iter()
            .filter(|(event, _)| event.contains("again"))
            .collect();
        assert_eq!(copies.len(), 1, "{name}");
        assert_eq!(copies[0].1, "BadPossession", "{name}");
    }
}
