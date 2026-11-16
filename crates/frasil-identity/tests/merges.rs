//! `identity.json`: `merges` (identity.md, "The merge").
//!
//! Each merge carries its events in canonical order (`log`), its statuses,
//! list members and result. The tests replay the logged events, in their
//! order and in reverse, and check the merge. They also build each list
//! again, as the reference builds it: each device signs onto its own view of
//! the list, on its own chain, citing the heads of its view, and views merge
//! when devices sync. Scheme-2 signing is deterministic, so the built events
//! are the logged ones byte for byte. The builder is checked first against
//! the other families that carry their events: `list`, the base of
//! `list_refusals`, and `pins`.

mod common;

use common::{bytes, check_summary, device, device_names, family, text};
use frasil_crypto::schemes::Scheme;
use frasil_events::kind::DEVICE_LIST;
use frasil_events::{Envelope, EventId, decode};
use frasil_identity::body::ListBody;
use frasil_identity::possession;
use frasil_identity::{DeviceList, Kind, MemberKeys};
use serde_json::Value as Json;
use std::collections::{BTreeMap, BTreeSet};

/// A person's list being built: the reference's `Person` over its
/// `History`.
struct Person {
    prefix: String,
    linear: bool,
    list: DeviceList,
    keys: BTreeMap<String, MemberKeys>,
    kinds: BTreeMap<String, Kind>,
    views: BTreeMap<String, BTreeSet<EventId>>,
    names: BTreeMap<EventId, String>,
}

impl Person {
    fn new(first: &str, prefix: &str, linear: bool) -> Self {
        let laptop = device(prefix, first);
        let signed = DeviceList::first_event(&laptop);
        let list = DeviceList::new(&signed).unwrap();
        let id = list.first();
        let mut person = Self {
            prefix: prefix.to_string(),
            linear,
            list,
            keys: BTreeMap::new(),
            kinds: BTreeMap::new(),
            views: BTreeMap::new(),
            names: BTreeMap::from([(id, format!("{first} starts the list"))]),
        };
        person.keys.insert(first.to_string(), laptop);
        person.kinds.insert(first.to_string(), Kind::Device);
        person.views.insert(first.to_string(), BTreeSet::from([id]));
        person
    }

    fn keys(&mut self, name: &str) -> &MemberKeys {
        let prefix = self.prefix.clone();
        self.views.entry(name.to_string()).or_default();
        self.keys
            .entry(name.to_string())
            .or_insert_with(|| device(&prefix, name))
    }

    fn add(&mut self, signer: &str, name: &str, kind: Kind) -> EventId {
        self.add_as(signer, name, kind, &format!("{signer} adds {name}"), None)
    }

    /// An add of `name`, with its own proof; `xwing` names another X-Wing
    /// key than its own.
    fn add_as(
        &mut self,
        signer: &str,
        name: &str,
        kind: Kind,
        label: &str,
        xwing: Option<String>,
    ) -> EventId {
        let person = self.list.person_id();
        let adder = *self.keys(signer).device_id();
        let other = xwing.map(|other| *self.keys(&other).xwing().unwrap());
        if kind == Kind::RecoveryAgent && !self.keys.contains_key(name) {
            // An agent has no X-Wing key.
            let agent = common::agent(&self.prefix, name);
            self.keys.insert(name.to_string(), agent);
        }
        let added = self.keys(name);
        let mut public = added.public(kind);
        if let Some(other) = other {
            public.xwing = Some(Box::new(other));
        }
        let statement = possession::statement(
            &person,
            &adder,
            kind,
            &public.identity,
            &public.mldsa,
            public.xwing.as_deref(),
        );
        let proof = possession::prove(added.signer(), &statement);
        self.kinds.insert(name.to_string(), kind);
        self.act(signer, ListBody::add(kind, &public, proof), label)
    }

    fn revoke(&mut self, signer: &str, name: &str) -> EventId {
        self.revoke_as(signer, name, &format!("{signer} revokes {name}"))
    }

    fn revoke_as(&mut self, signer: &str, name: &str, label: &str) -> EventId {
        let device = *self.keys(name).device_id();
        let body = ListBody::revoke(self.kinds[name], device);
        self.act(signer, body, label)
    }

    fn confirm_as(&mut self, signer: &str, name: &str, label: &str) -> EventId {
        let device = *self.keys(name).device_id();
        let body = ListBody::confirm(self.kinds[name], device);
        self.act(signer, body, label)
    }

    /// `signer` signs `body` onto its view: on its own chain, citing the
    /// heads of its view.
    fn act(&mut self, signer: &str, body: ListBody, label: &str) -> EventId {
        self.keys(signer);
        if self.linear {
            let all: BTreeSet<EventId> = self.list.log().canonical().into_iter().collect();
            self.views.insert(signer.to_string(), all);
        }
        let log = self.list.log();
        let view = &self.views[signer];
        let author = *self.keys[signer].device_id();
        let last = view
            .iter()
            .filter_map(|&id| log.event(id).map(|e| (e, id)))
            .filter(|(e, _)| *e.author() == author)
            .map(|(e, id)| (e.seq(), id))
            .max();
        let (seq, prev) = last.map_or((1, None), |(seq, id)| (seq + 1, Some(id)));
        let mut parents: BTreeSet<EventId> = log.heads_in(view).into_iter().collect();
        parents.extend(prev);
        let signed = Envelope {
            kind: DEVICE_LIST,
            log: Some(log.id()),
            ed: *self.keys[signer].identity(),
            kc: *self.keys[signer].signer().kc(),
            seq,
            prev,
            parents: parents.into_iter().collect(),
            cuts: Vec::new(),
            body: body.encode(),
            scheme: Scheme::Hybrid,
        }
        .sign(self.keys[signer].signer());
        let id = decode(&signed).unwrap().id();
        self.list.insert(&signed).unwrap();
        self.names.insert(id, label.to_string());
        let mut seen = self.list.log().past(id);
        seen.insert(id);
        self.views.get_mut(signer).unwrap().extend(seen);
        id
    }

    fn sync(&mut self, names: &[&str]) {
        let mut union = BTreeSet::new();
        for name in names {
            union.extend(
                self.views
                    .entry(name.to_string())
                    .or_default()
                    .iter()
                    .copied(),
            );
        }
        for name in names {
            self.views.insert(name.to_string(), union.clone());
        }
    }

    /// The events as the vectors describe them: name and signed bytes, by
    /// ID.
    fn signed(&self) -> BTreeMap<String, Vec<u8>> {
        self.list
            .log()
            .events()
            .map(|e| (self.names[&e.id()].clone(), e.signed()))
            .collect()
    }
}

/// The signed bytes of each described event, by name.
fn described(rows: &Json) -> BTreeMap<String, Vec<u8>> {
    rows.as_array()
        .unwrap()
        .iter()
        .map(|row| (text(row, "name").to_string(), bytes(row, "signed")))
        .collect()
}

#[test]
fn the_builder_makes_the_reference_events() {
    // `list`: a linear list, every event named.
    let mut p = Person::new("laptop", "identity", true);
    p.add("laptop", "phone", Kind::Device);
    p.add("laptop", "passkey", Kind::PasskeyMember);
    p.add_as(
        "passkey",
        "browser",
        Kind::Device,
        "passkey adds browser, rooted in a passkey",
        None,
    );
    p.add("laptop", "recovery", Kind::RecoveryKey);
    p.confirm_as("laptop", "browser", "laptop confirms browser");
    p.add("laptop", "agent", Kind::RecoveryAgent);
    p.add_as(
        "agent",
        "helped",
        Kind::Device,
        "agent adds helped, rooted in the agent",
        None,
    );
    p.revoke("phone", "browser");
    assert_eq!(p.signed(), described(&family("list")["events"]));

    // The base of `list_refusals`.
    let mut q = Person::new("laptop", "identity/refusals", true);
    q.add("laptop", "phone", Kind::Device);
    q.add("laptop", "passkey", Kind::PasskeyMember);
    q.add_as(
        "passkey",
        "browser",
        Kind::Device,
        "passkey adds browser, rooted in a passkey",
        None,
    );
    q.add("laptop", "recovery", Kind::RecoveryKey);
    q.add("laptop", "agent", Kind::RecoveryAgent);
    assert_eq!(q.signed(), described(&family("list_refusals")["base"]));

    // `pins`: branching views, and a device restored to an older view.
    let mut r = Person::new("laptop", "identity/pins", false);
    r.add("laptop", "phone", Kind::Device);
    r.sync(&["laptop", "phone"]);
    let tablet = r.add("phone", "tablet", Kind::Device);
    r.views.get_mut("phone").unwrap().remove(&tablet);
    r.add_as(
        "phone",
        "watch",
        Kind::Device,
        "phone, restored, adds watch at the same seq",
        None,
    );
    assert_eq!(r.signed(), described(&family("pins")["events"]));
}

/// The two devices most merges start from: the laptop adds the phone, and
/// a third list member if any, and they sync.
fn two_devices(q: &mut Person, third: Option<(&str, Kind)>) {
    q.add("laptop", "phone", Kind::Device);
    let mut names = vec!["laptop", "phone"];
    if let Some((name, kind)) = third {
        q.add("laptop", name, kind);
        names.push(name);
    }
    q.sync(&names);
}

/// Each merge of the family, built as the reference builds it.
fn build(i: usize, q: &mut Person) {
    use Kind::{Device, PasskeyMember, RecoveryAgent, RecoveryKey};
    match i {
        0 => {
            two_devices(q, None);
            q.add("laptop", "tablet", Device);
            q.add("phone", "watch", Device);
        }
        1 => {
            two_devices(q, None);
            q.add("laptop", "tablet", Device);
            q.add("phone", "tablet", Device);
        }
        2 => {
            two_devices(q, None);
            q.add("laptop", "tablet", Device);
            q.add_as(
                "phone",
                "watch",
                Device,
                "phone adds watch with the tablet's X-Wing key",
                Some("tablet".into()),
            );
        }
        3 => {
            two_devices(q, Some(("recovery", RecoveryKey)));
            q.revoke("laptop", "phone");
            q.revoke("phone", "laptop");
        }
        4 => {
            two_devices(q, None);
            q.revoke("laptop", "phone");
            q.revoke("phone", "laptop");
        }
        5 => {
            two_devices(q, Some(("passkey", PasskeyMember)));
            q.add_as(
                "passkey",
                "browser",
                Device,
                "passkey adds browser, rooted in a passkey",
                None,
            );
            q.sync(&["laptop", "phone", "passkey", "browser"]);
            q.revoke("laptop", "browser");
            q.revoke("browser", "laptop");
        }
        6 => {
            two_devices(q, Some(("recovery", RecoveryKey)));
            q.revoke("recovery", "phone");
            q.revoke("phone", "recovery");
        }
        7 => {
            two_devices(q, None);
            q.revoke("laptop", "phone");
            q.add("phone", "tablet", Device);
        }
        8 => {
            q.add("laptop", "passkey", PasskeyMember);
            q.sync(&["laptop", "passkey"]);
            q.add_as(
                "passkey",
                "browser",
                Device,
                "passkey adds browser, rooted in a passkey",
                None,
            );
            q.add("laptop", "phone", Device);
            q.sync(&["laptop", "passkey", "browser", "phone"]);
            q.confirm_as("phone", "browser", "phone confirms browser");
            q.revoke("laptop", "phone");
        }
        9 => {
            q.add("laptop", "phone", Device);
            q.add("laptop", "tablet", Device);
            q.sync(&["laptop", "phone", "tablet"]);
            q.revoke("laptop", "phone");
            q.revoke("phone", "tablet");
            q.revoke("tablet", "laptop");
        }
        10 => {
            two_devices(q, Some(("tablet", Device)));
            q.revoke_as("phone", "phone", "phone revokes itself");
            q.revoke("laptop", "phone");
        }
        11 => {
            two_devices(q, Some(("tablet", Device)));
            let backup = q.views["phone"].clone();
            q.add("phone", "watch", Device);
            q.views.insert("phone".into(), backup);
            q.revoke_as(
                "phone",
                "phone",
                "phone, restored, revokes itself at the same seq",
            );
            q.sync(&["laptop", "phone", "tablet"]);
        }
        12 => {
            q.add("laptop", "agent", RecoveryAgent);
            q.sync(&["laptop", "agent"]);
            q.add_as("agent", "helped", Device, "agent adds helped", None);
            q.sync(&["laptop", "agent", "helped"]);
            q.add_as("helped", "helped2", Device, "helped adds helped2", None);
            q.revoke_as(
                "helped",
                "helped2",
                "helped revokes helped2, rooted in the same agent",
            );
            q.revoke_as("helped", "laptop", "helped revokes laptop");
            q.sync(&["laptop", "agent", "helped"]);
            q.revoke_as("laptop", "helped", "laptop revokes helped");
        }
        13 => {
            q.add("laptop", "agent", RecoveryAgent);
            q.add("laptop", "phone", Device);
            q.sync(&["laptop", "agent", "phone"]);
            q.add_as("agent", "helped", Device, "agent adds helped", None);
            q.sync(&["laptop", "agent", "helped", "phone"]);
            q.confirm_as("laptop", "helped", "laptop confirms helped");
            q.sync(&["laptop", "helped", "phone"]);
            q.revoke_as("helped", "phone", "helped, confirmed, revokes phone");
        }
        _ => unreachable!(),
    }
}

#[test]
fn merges() {
    let f = family("merges");
    let merges = f.as_array().unwrap();
    assert_eq!(merges.len(), 14);
    for (i, case) in merges.iter().enumerate() {
        let name = text(case, "name");
        let prefix = format!("identity/merge/{i}");
        let members = device_names(&prefix, case);
        let rows: Vec<&Json> = case["log"].as_array().unwrap().iter().collect();
        for row in &rows {
            let id = decode(&bytes(row, "signed")).unwrap().id();
            assert_eq!(id, EventId(common::array(row, "id")), "{name}");
        }

        // The logged events, inserted in canonical order.
        let (list, names) = common::list_of(&rows);
        let canonical: Vec<String> = list
            .log()
            .canonical()
            .into_iter()
            .map(|id| names[&id].clone())
            .collect();
        let logged: Vec<String> = rows.iter().map(|r| text(r, "name").to_string()).collect();
        assert_eq!(canonical, logged, "{name}: canonical order");
        let merged = list.merge();
        check_summary(name, &merged, &names, &members, case);
        if i == 11 {
            // The forked phone's path ends at its self-revocation and at the
            // later of the two events at its fork point.
            let id = |label: &str| *names.iter().find(|(_, n)| *n == label).unwrap().0;
            let revoke = id("phone, restored, revokes itself at the same seq");
            let watch = id("phone adds watch");
            let log = list.log();
            let later = [revoke, watch]
                .into_iter()
                .max_by_key(|&e| (log.height(e), e))
                .unwrap();
            let phone = common::device(&prefix, "phone");
            assert_eq!(merged.ends(phone.device_id()), vec![revoke, later]);
        }

        // The same events, inserted in reverse, merge alike.
        let mut reversed = DeviceList::new(&bytes(rows[0], "signed")).unwrap();
        for row in rows[1..].iter().rev() {
            reversed.insert(&bytes(row, "signed")).unwrap();
        }
        check_summary(name, &reversed.merge(), &names, &members, case);

        // Built as the reference builds it, the list is the logged one.
        let mut q = Person::new("laptop", &prefix, false);
        build(i, &mut q);
        assert_eq!(q.signed(), described(&case["log"]), "{name}: built");
    }
}
