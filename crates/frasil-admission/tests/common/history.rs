//! A space's history, built as the reference's builders build theirs
//! (`docs/spec/reference/roster.py`, `Roster`; `admission.py`,
//! `admission_event`), so that the welcome's and the top-up's events can be
//! rebuilt byte for byte from their labels: admission.json gives the welcome's
//! admitting event, which checks the rebuilding, and names the top-up's
//! events.
//!
//! Every input is an example under the history's prefix: a device's Ed25519
//! seed (`<prefix>/<name>/ed25519`), from which crypto.md's fixture
//! derivations give its ML-DSA-65 and X-Wing seeds, and each event's
//! content key, seal nonce, grant commitment and upload key
//! (`<prefix>/<label>/...`).

use super::{eseed, example};
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_crypto::fixtures::FixtureKeys;
use frasil_crypto::primitives::ed25519_public;
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_crypto::wrap::xwing_public;
use frasil_events::{Envelope, EventId, Log, decode};
use frasil_keys::body::{Delivery, GrantSlot, Inner, RotationKeys, Seal, VisiblePart};
use frasil_keys::bundle::Bundle;
use frasil_keys::derive::{GrantKey, body_commitment, body_key, read_credential, upload_key};
use frasil_keys::wraps::seal_bundle_wrap_to;
use frasil_keys::{KeyName, RotationSet, SelfRef};
use frasil_space::part::{Genesis, RosterPart, Update};
use frasil_space::{
    Change, Descriptor, KeyEventChecks, Keyring, Limits, Options, OtherLogs, Policy, Space, Status,
    Twins, UnitBodies, UnitBody, Valid,
};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// An X-Wing key that is no device's of these histories: roster.py's
/// `roster/<name>/xwing` example.
#[allow(dead_code)]
pub fn other_xwing_seed(name: &str) -> [u8; 32] {
    example(&format!("roster/{name}/xwing"))
}

/// Units open with no refs: these histories' units are roster.py's
/// stand-ins, `unit: <label>`.
pub struct NoUnits;

impl UnitBodies for NoUnits {
    fn open(&self, _unit: &frasil_events::Event) -> UnitBody {
        UnitBody::Opened(Vec::new())
    }
}

/// A delivery's recipient: its three public keys, and whether it writes.
pub struct Recipient {
    pub keys: DeviceKeys,
    pub writes: bool,
}

/// A participant's own seeds: Ed25519, ML-DSA-65 and X-Wing.
pub type Seeds = ([u8; 32], [u8; 32], [u8; 32]);

/// A space's history being built.
pub struct History {
    pub prefix: String,
    pub log: Log,
    pub names: BTreeMap<EventId, String>,
    pub view: BTreeMap<String, BTreeSet<EventId>>,
    /// Each rotation's content key, by its event ID.
    pub krot: BTreeMap<EventId, [u8; 32]>,
    pub genesis: EventId,
    /// Participants that sign with seeds of their own, `(Ed25519,
    /// ML-DSA-65, X-Wing)`, by name: an invite key, whose seeds the link's
    /// secret derives.
    pub seeds: BTreeMap<String, Seeds>,
}

fn seal_nonce(label: &str) -> [u8; 24] {
    let mut out = [0; 24];
    out.copy_from_slice(&example(&format!("{label}/seal-nonce"))[..24]);
    out
}

impl History {
    /// A device's Ed25519 seed.
    pub fn seed(prefix: &str, name: &str) -> [u8; 32] {
        example(&format!("{prefix}/{name}/ed25519"))
    }

    /// A device's signer: of its own seeds, when it signs with seeds of
    /// its own, else of the example under the prefix and crypto.md's
    /// fixture derivations.
    pub fn signer(&self, name: &str) -> Signer {
        match self.seeds.get(name) {
            Some((ed25519, mldsa, xwing)) => {
                Signer::from_seeds(ed25519, mldsa, Some(&xwing_public(xwing)))
            }
            None => FixtureKeys::from_identity_seed(&Self::seed(&self.prefix, name)).signer(),
        }
    }

    /// A device's device ID.
    pub fn device(&self, name: &str) -> DeviceId {
        *self.signer(name).device_id()
    }

    /// Gives a device of this history the Ed25519 seed of another, with
    /// the fixture ML-DSA-65 and X-Wing seeds crypto.md derives from it:
    /// the same keys sign in both histories.
    #[allow(dead_code)]
    pub fn share_seed(&mut self, name: &str, ed25519: [u8; 32]) {
        let keys = FixtureKeys::from_identity_seed(&ed25519);
        self.seeds.insert(
            name.to_owned(),
            (ed25519, *keys.mldsa_seed, *keys.xwing_seed),
        );
    }

    /// A device's three public keys, as a grant names them.
    pub fn device_keys(&self, name: &str) -> DeviceKeys {
        let signer = self.signer(name);
        DeviceKeys {
            ed: *signer.identity_key(),
            keys: signer.keys().clone(),
        }
    }

    /// A device as a delivery's recipient.
    #[allow(dead_code)]
    pub fn recipient(&self, name: &str, writes: bool) -> Recipient {
        Recipient {
            keys: self.device_keys(name),
            writes,
        }
    }

    /// The space's genesis by `founder`.
    pub fn new(founder: &str, prefix: &str) -> Self {
        Self::new_with(founder, prefix, Descriptor::ORDINARY)
    }

    /// The space's genesis by `founder`, with a descriptor.
    pub fn new_with(founder: &str, prefix: &str, descriptor: Descriptor) -> Self {
        let signer = FixtureKeys::from_identity_seed(&Self::seed(prefix, founder)).signer();
        let author = *signer.device_id();
        let mut system_stream = [0; 16];
        system_stream.copy_from_slice(&example(&format!("{prefix}/system-stream"))[..16]);
        let mut genesis = Genesis::new(
            DeviceKeys {
                ed: *signer.identity_key(),
                keys: signer.keys().clone(),
            },
            Policy::default(),
            system_stream,
        );
        genesis.descriptor = descriptor;
        let part = RosterPart::Genesis(Box::new(genesis));
        let label = format!("{prefix}/genesis");
        let secret = example(&format!("{label}/content-key"));
        let mut nonce = [0; 16];
        nonce.copy_from_slice(&example(&format!("{prefix}/nonce"))[..16]);
        let inner = Inner {
            grant: Some(GrantSlot::Rotation),
            roster: Some(part.encode()),
            ..Inner::default()
        };
        let body = sealed_body(
            Seal::Rotation(rotation_keys(&label, &secret)),
            Vec::new(),
            &inner,
            &secret,
            &nonce,
            &author,
            1,
            &seal_nonce(&label),
            Some(nonce),
        );
        let signed = Envelope {
            kind: frasil_events::kind::SPACE,
            log: None,
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq: 1,
            prev: None,
            parents: Vec::new(),
            cuts: Vec::new(),
            body,
            scheme: Scheme::Hybrid,
        }
        .sign(&signer);
        let event = decode(&signed).expect("the genesis decodes");
        let id = event.id();
        let log = Log::new(event).expect("a genesis");
        Self {
            prefix: prefix.to_owned(),
            log,
            names: BTreeMap::from([(id, format!("{founder} creates the space"))]),
            view: BTreeMap::from([(founder.to_owned(), BTreeSet::from([id]))]),
            krot: BTreeMap::from([(id, secret)]),
            genesis: id,
            seeds: BTreeMap::new(),
        }
    }

    /// The space ID.
    pub fn id(&self) -> EventId {
        self.log.id()
    }

    fn view_of(&mut self, name: &str) -> BTreeSet<EventId> {
        self.view.entry(name.to_owned()).or_default().clone()
    }

    /// The heads of a device's view.
    pub fn heads(&mut self, name: &str) -> Vec<EventId> {
        let view = self.view_of(name);
        self.log.heads_in(&view)
    }

    /// Merges views, as a room does.
    pub fn sync(&mut self, names: &[&str]) {
        let union: BTreeSet<EventId> = names.iter().flat_map(|n| self.view_of(n)).collect();
        for name in names {
            self.view.insert((*name).to_owned(), union.clone());
        }
    }

    /// Signs a space event onto `by`'s view, following its own chain.
    fn act(
        &mut self,
        by: &str,
        label: &str,
        body: impl FnOnce(&EventId, &DeviceId, u64) -> Vec<u8>,
    ) -> EventId {
        self.act_as(by, label, frasil_events::kind::SPACE, Scheme::Hybrid, body)
    }

    /// A unit, roster.py's `Roster.unit`: its body `unit: <label>`, signed
    /// with Ed25519 onto `by`'s view.
    #[allow(dead_code)]
    pub fn unit(&mut self, by: &str, label: &str) -> EventId {
        let body = format!("unit: {label}").into_bytes();
        self.act_as(
            by,
            label,
            frasil_events::kind::UNIT,
            Scheme::Ed25519,
            |_, _, _| body,
        )
    }

    /// Signs an event of this kind and scheme onto `by`'s view, following
    /// its own chain.
    fn act_as(
        &mut self,
        by: &str,
        label: &str,
        kind: u8,
        scheme: Scheme,
        body: impl FnOnce(&EventId, &DeviceId, u64) -> Vec<u8>,
    ) -> EventId {
        let signer = self.signer(by);
        let author = *signer.device_id();
        let view = self.view_of(by);
        let last = view
            .iter()
            .filter_map(|id| self.log.event(*id))
            .filter(|e| *e.author() == author)
            .max_by_key(|e| (e.seq(), e.id()))
            .map(|e| (e.seq(), e.id()));
        let (seq, prev) = match last {
            Some((seq, id)) => (seq + 1, Some(id)),
            None => (1, None),
        };
        let mut parents = self.log.heads_in(&view);
        parents.extend(prev);
        let space = self.id();
        let signed = Envelope {
            kind,
            log: Some(space),
            ed: *signer.identity_key(),
            kc: *signer.kc(),
            seq,
            prev,
            parents,
            cuts: Vec::new(),
            body: body(&space, &author, seq),
            scheme,
        }
        .sign(&signer);
        let event = decode(&signed).expect("the event decodes");
        let id = event.id();
        self.log.place(event).expect("placed");
        self.names.insert(id, label.to_owned());
        let mut new_view = self.log.past(id);
        new_view.insert(id);
        self.view.entry(by.to_owned()).or_default().extend(new_view);
        id
    }

    /// A roster event that rotates and delivers nothing: roster.py's
    /// `Roster.act` for a change that is no break and no grant rotation.
    pub fn rotate(&mut self, by: &str, changes: Vec<Change>, label: &str) -> EventId {
        self.rotate_with(by, changes, label, false)
    }

    /// `Roster.act` for a change that is a grant rotation when `grant`:
    /// a removal of a member that propagates, say.
    pub fn rotate_with(
        &mut self,
        by: &str,
        changes: Vec<Change>,
        label: &str,
        grant: bool,
    ) -> EventId {
        self.rotate_flags(by, changes, label, grant, false)
    }

    /// `Roster.act` with both of keys.md's flags: a grant rotation when
    /// `grant`, a break when `brk` (an admission from now on, a guest's).
    pub fn rotate_flags(
        &mut self,
        by: &str,
        changes: Vec<Change>,
        label: &str,
        grant: bool,
        brk: bool,
    ) -> EventId {
        let full = format!("{}/{label}", self.prefix);
        let secret = example(&format!("{full}/content-key"));
        let inner = Inner {
            grant: grant.then_some(GrantSlot::Rotation),
            is_break: brk,
            roster: Some(RosterPart::Update(Update { changes }).encode()),
            ..Inner::default()
        };
        let keys = rotation_keys(&full, &secret);
        let nonce = seal_nonce(&full);
        let id = self.act(by, label, |space, author, seq| {
            sealed_body(
                Seal::Rotation(keys),
                Vec::new(),
                &inner,
                &secret,
                &space.0,
                author,
                seq,
                &nonce,
                None,
            )
        });
        self.krot.insert(id, secret);
        id
    }

    /// A key event that rotates: roster.py's `Roster.heal` with no refs.
    pub fn heal(&mut self, by: &str, label: &str) -> EventId {
        let full = format!("{}/{label}", self.prefix);
        let secret = example(&format!("{full}/content-key"));
        let keys = rotation_keys(&full, &secret);
        let nonce = seal_nonce(&full);
        let id = self.act(by, label, |space, author, seq| {
            sealed_body(
                Seal::Rotation(keys),
                Vec::new(),
                &Inner::default(),
                &secret,
                &space.0,
                author,
                seq,
                &nonce,
                None,
            )
        });
        self.krot.insert(id, secret);
        id
    }

    /// admission.py's `admission_event`: a roster event that rotates, a
    /// break when `brk`, and no grant rotation (its grants carry a
    /// session), whose own delivery wraps the content key and upload seed
    /// for `recipients`.
    pub fn admit(
        &mut self,
        by: &str,
        changes: Vec<Change>,
        label: &str,
        brk: bool,
        recipients: &[Recipient],
    ) -> EventId {
        self.admit_with(by, changes, label, brk, false, recipients)
    }

    /// admission.py's `admission_event` for an admission that is a grant
    /// rotation when `granting` (its grants carry no session): its
    /// delivery then names the grant state too, and wraps the grant seed
    /// for every recipient.
    pub fn admit_with(
        &mut self,
        by: &str,
        changes: Vec<Change>,
        label: &str,
        brk: bool,
        granting: bool,
        recipients: &[Recipient],
    ) -> EventId {
        self.admit_refs(by, changes, label, brk, granting, recipients, Vec::new())
    }

    /// [`History::admit_with`] whose sealed part carries `refs`, the heads
    /// of the other logs its changes name as its author holds them.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_refs(
        &mut self,
        by: &str,
        changes: Vec<Change>,
        label: &str,
        brk: bool,
        granting: bool,
        recipients: &[Recipient],
        refs: Vec<frasil_events::Ref>,
    ) -> EventId {
        let full = format!("{}/{label}", self.prefix);
        let secret = example(&format!("{full}/content-key"));
        let upload_seed = example(&format!("{full}/upload-seed"));
        let grant_seed = example(&format!("{full}/grant-seed"));
        let keys = RotationKeys {
            grant_commitment: GrantKey::derive(&grant_seed).commitment(brk),
            read: read_credential(&secret).public,
            upload: upload_key(&upload_seed).public,
        };
        let inner = Inner {
            grant: granting.then_some(GrantSlot::Rotation),
            is_break: brk,
            roster: Some(RosterPart::Update(Update { changes }).encode()),
            refs,
            ..Inner::default()
        };
        let nonce = seal_nonce(&full);
        let id = self.act(by, label, |space, author, seq| {
            let name = KeyName::SelfRef(SelfRef::new(*author, seq));
            let grant_name = granting.then(|| name.clone());
            let wraps = recipients
                .iter()
                .enumerate()
                .map(|(k, r)| {
                    let bundle = Bundle::new(
                        Some(secret),
                        r.writes.then_some(upload_seed),
                        granting.then_some(grant_seed),
                    )
                    .unwrap();
                    seal_bundle_wrap_to(
                        &space.0,
                        Some(&name),
                        grant_name.as_ref(),
                        &r.keys,
                        &bundle,
                        &eseed(&format!("{full}/wrap/{k}")),
                    )
                    .unwrap()
                })
                .collect();
            let deliveries = if recipients.is_empty() {
                Vec::new()
            } else {
                vec![Delivery {
                    key_name: Some(name.clone()),
                    grant_name: grant_name.clone(),
                    wraps,
                    space_wraps: Vec::new(),
                }]
            };
            sealed_body(
                Seal::Rotation(keys),
                deliveries,
                &inner,
                &secret,
                &space.0,
                author,
                seq,
                &nonce,
                None,
            )
        });
        self.krot.insert(id, secret);
        id
    }

    /// A key event that does not rotate, sealed under the current state of
    /// `by`'s view, which is one rotation here.
    pub fn deliver(&mut self, by: &str, label: &str) -> EventId {
        self.sealed_under_current(by, label, Inner::default())
    }

    /// A roster event that does not rotate, sealed under the current state
    /// of `by`'s view: roster.py's `space_event` with `rotates` false.
    pub fn roster_event(&mut self, by: &str, changes: Vec<Change>, label: &str) -> EventId {
        let inner = Inner {
            roster: Some(RosterPart::Update(Update { changes }).encode()),
            ..Inner::default()
        };
        self.sealed_under_current(by, label, inner)
    }

    /// A roster event that does not rotate, sealed under the current state
    /// of `by`'s view, with one delivery that wraps that state's content
    /// key for each recipient: an invite that need not rotate
    /// (ext-invite-links.md, "Making an invite and keeping drops").
    #[allow(dead_code)]
    pub fn roster_event_delivering(
        &mut self,
        by: &str,
        changes: Vec<Change>,
        label: &str,
        recipients: &[Recipient],
    ) -> EventId {
        let inner = Inner {
            roster: Some(RosterPart::Update(Update { changes }).encode()),
            ..Inner::default()
        };
        self.sealed_under_current_to(by, label, inner, recipients)
    }

    /// A space event that does not rotate, sealed under the current state
    /// of `by`'s view, which is one rotation here.
    fn sealed_under_current(&mut self, by: &str, label: &str, inner: Inner) -> EventId {
        self.sealed_under_current_to(by, label, inner, &[])
    }

    /// [`History::sealed_under_current`], delivering that state's content
    /// key to `recipients`.
    fn sealed_under_current_to(
        &mut self,
        by: &str,
        label: &str,
        inner: Inner,
        recipients: &[Recipient],
    ) -> EventId {
        let full = format!("{}/{label}", self.prefix);
        let view = self.view_of(by);
        let rotations: Vec<EventId> = view
            .iter()
            .copied()
            .filter(|i| self.krot.contains_key(i))
            .collect();
        let state: Vec<EventId> = rotations
            .iter()
            .copied()
            .filter(|&i| !rotations.iter().any(|&j| j != i && self.log.precedes(i, j)))
            .collect();
        assert_eq!(state.len(), 1, "one rotation at the top of the view");
        let secret = self.krot[&state[0]];
        let set = RotationSet::single(state[0]);
        let nonce = seal_nonce(&full);
        self.act(by, label, |space, author, seq| {
            let name = KeyName::Set(set.clone());
            let wraps: Vec<Vec<u8>> = recipients
                .iter()
                .enumerate()
                .map(|(k, r)| {
                    seal_bundle_wrap_to(
                        &space.0,
                        Some(&name),
                        None,
                        &r.keys,
                        &Bundle::new(Some(secret), None, None).unwrap(),
                        &eseed(&format!("{full}/wrap/{k}")),
                    )
                    .unwrap()
                })
                .collect();
            let deliveries = if wraps.is_empty() {
                Vec::new()
            } else {
                vec![Delivery {
                    key_name: Some(name),
                    grant_name: None,
                    wraps,
                    space_wraps: Vec::new(),
                }]
            };
            sealed_body(
                Seal::Under(set),
                deliveries,
                &inner,
                &secret,
                &space.0,
                author,
                seq,
                &nonce,
                None,
            )
        })
    }

    /// Resolves a view with these keys, as roster.md's order of
    /// verification does, with no other log.
    pub fn resolve<'a>(
        &'a self,
        view: Option<&BTreeSet<EventId>>,
        keys: &'a Keyring,
        others: &'a OtherLogs<'a>,
    ) -> Space<'a> {
        let options = Options {
            keys,
            limits: Limits::PROTOCOL,
            others,
            units: &NoUnits,
            twins: Twins::Assumed,
            key_checks: KeyEventChecks::StaleSeal,
            notices: None,
        };
        Space::resolve(&self.log, view, options).expect("the space resolves")
    }

    /// Every rotation's content key.
    pub fn keyring(&self) -> Keyring {
        let mut keys = Keyring::default();
        for (id, secret) in &self.krot {
            keys.rotations.insert(*id, Zeroizing::new(*secret));
        }
        keys
    }

    /// An event's status, as the vectors write it.
    pub fn show(&self, status: &Status) -> String {
        match status {
            Status::Valid(Valid::Agreed) => "valid (agreed)".into(),
            Status::Valid(Valid::Seniority) => "valid (seniority)".into(),
            Status::Valid(_) => "valid".into(),
            Status::Void { class, by } => {
                use frasil_base::errors::Class;
                match by {
                    Some(by) => format!("{} by {}", class.name(), self.names[by]),
                    None => class.name().to_owned(),
                }
            }
        }
    }

    /// Every event's status but the genesis's, by name.
    pub fn events(&self, space: &Space<'_>) -> BTreeMap<String, String> {
        self.log
            .canonical_in(space.view())
            .into_iter()
            .filter(|id| *id != self.genesis)
            .map(|id| {
                (
                    self.names[&id].clone(),
                    self.show(space.status(id).unwrap()),
                )
            })
            .collect()
    }
}

/// A rotation's visible keys, as roster.py's `rotation_payload` derives
/// them.
fn rotation_keys(label: &str, secret: &[u8; 32]) -> RotationKeys {
    RotationKeys {
        grant_commitment: example(&format!("{label}/grant-commitment")),
        read: read_credential(secret).public,
        upload: ed25519_public(&example(&format!("{label}/upload"))),
    }
}

/// A space event's body, its sealed part sealed under its body key.
#[allow(clippy::too_many_arguments)]
fn sealed_body(
    seal: Seal,
    deliveries: Vec<Delivery>,
    inner: &Inner,
    secret: &[u8; 32],
    log: &[u8],
    author: &DeviceId,
    seq: u64,
    nonce: &[u8; 24],
    genesis_nonce: Option<[u8; 16]>,
) -> Vec<u8> {
    let key = body_key(secret, log, author, seq);
    VisiblePart {
        seal,
        deliveries,
        sealed: inner.seal_with(&key, log, author, seq, nonce),
        nonce: genesis_nonce,
        commitment: body_commitment(&key),
        twin: None,
    }
    .encode()
}
