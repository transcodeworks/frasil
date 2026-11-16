//! Signing what the device publishes: the genesis and its skeleton root,
//! roster events and key events, and units.
//!
//! The formats are the protocol crates'; this module only assembles them
//! in the order the documents give, with secrets and nonces the device
//! draws from its platform:
//!
//! - **A rotation** draws `k_R`, `w_R` and `g_R` (keys.md, "Rotations and
//!   states"). Every rotation this client makes is a grant rotation: its
//!   author propagates, and a grant rotation is what a genesis, a removal of
//!   a member that propagates and a response require (keys.md, "Checks
//!   against the event and its place", step 6), and what a heal may be
//!   (step 7). It publishes its read credential, upload key and grant
//!   commitment, delivers its own state in a delivery named by its self
//!   reference to every device of the merged roster and to its author
//!   (keys.md, "Deliveries"), and links back to the previous content and
//!   grant states where it is no break.
//! - **An event that does not rotate** is sealed under its author's current
//!   content state (`StaleSeal`), and may deliver that state and the grant
//!   state to a newcomer admitted with history.
//! - **The genesis** binds its 16-byte nonce in place of its log
//!   (events.md, "Field rules"), and its founder signs the skeleton's root
//!   under a fresh administrator pseudonym (peers.md, "Skeleton
//!   derivations").
//! - **A unit** is sealed under the writer's current state and signed under
//!   scheme 0 (units.md, "The envelope").

use crate::error::{Error, Result};
use crate::platform::Platform;
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_crypto::schemes::{Scheme, Signer};
use frasil_crypto::sizes::XWING_PUBLIC;
use frasil_crypto::wrap::ENCAPSULATION_RANDOMNESS;
use frasil_events::{Envelope, EventId, Ref, kind};
use frasil_keys::body::{Delivery, GrantSlot, Inner, Notice, RotationKeys, Seal, VisiblePart};
use frasil_keys::bundle::Bundle;
use frasil_keys::derive::{
    GrantKey, Secret, body_commitment, body_key, read_credential, upload_key,
};
use frasil_keys::links::{GapRecord, Link, LinkKind};
use frasil_keys::wraps::{seal_bundle_wrap_to, seal_removal_wrap_with, seal_space_wrap_with};
use frasil_keys::{KeyName, RotationSet, SelfRef};
use frasil_peers::body::StorageBody;
use frasil_peers::derive::{root_statement, twin_commitment, twin_secret};
use frasil_space::part::{Genesis, RosterPart, Update};
use frasil_space::{Change, Policy};
use zeroize::Zeroizing;

/// A device a delivery wraps for: its keys, whose device ID its wrap's
/// `info` binds and whose X-Wing key it seals to (crypto.md, "The X-Wing
/// wrap"), and what its bundle carries.
#[derive(Clone)]
pub(crate) struct Recipient {
    /// Its three public keys, as a grant or a list `add` names them.
    pub keys: DeviceKeys,
    /// Whether it writes: its bundle carries the upload seed.
    pub writes: bool,
    /// Whether its grant propagates: its bundle carries the grant seed.
    pub propagates: bool,
}

impl core::fmt::Debug for Recipient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Recipient")
            .field("device", &self.keys.device_id())
            .field("writes", &self.writes)
            .field("propagates", &self.propagates)
            .finish_non_exhaustive()
    }
}

/// A rotation's fresh secrets.
pub(crate) struct Fresh {
    /// `k_R`.
    pub content: Secret,
    /// `w_R`.
    pub upload: Secret,
    /// `g_R`.
    pub grant: Secret,
}

impl Fresh {
    /// Draws a rotation's secrets.
    pub fn draw(platform: &Platform) -> Result<Self> {
        Ok(Self {
            content: platform.draw::<32>()?,
            upload: platform.draw::<32>()?,
            grant: platform.draw::<32>()?,
        })
    }

    /// The visible keys a grant rotation publishes.
    fn keys(&self, is_break: bool) -> RotationKeys {
        RotationKeys {
            grant_commitment: GrantKey::derive(&self.grant).commitment(is_break),
            read: read_credential(&self.content).public,
            upload: upload_key(&self.upload).public,
        }
    }
}

/// A state the device holds, with its secrets.
#[derive(Clone)]
pub(crate) struct HeldState {
    /// The state.
    pub state: RotationSet,
    /// Its content key `k(S)`.
    pub content: Secret,
    /// Its upload seed `w(S)`, if the device holds it.
    pub upload: Option<Secret>,
}

/// A grant state the device holds, with its seed.
#[derive(Clone)]
pub(crate) struct HeldGrant {
    /// The grant state.
    pub state: RotationSet,
    /// Its grant seed `g(G)`.
    pub grant: Secret,
}

/// How a space event is sealed.
pub(crate) enum Sealing {
    /// The event rotates.
    Rotate {
        /// Its fresh secrets.
        fresh: Fresh,
        /// Whether it is a break: no link back.
        is_break: bool,
        /// Whether it is a grant rotation (keys.md, "Checks against the
        /// event and its place", steps 5 to 7). Otherwise its own delivery's
        /// grant slots carry the previous grant state, and its grant
        /// commitment is random.
        grant_rotation: bool,
        /// Whom its own delivery wraps for, its author included.
        recipients: Vec<Recipient>,
        /// The devices its roster changes remove, each sealed a removal
        /// wrap of the event's body key (keys.md, "Deliveries").
        removed: Vec<Recipient>,
        /// The previous content state, which it links back to unless it
        /// breaks.
        previous: Option<HeldState>,
        /// The previous grant state, likewise.
        previous_grant: Option<HeldGrant>,
    },
    /// The event does not rotate: sealed under the author's current state.
    Under {
        /// The current content state.
        state: HeldState,
        /// The current grant state, delivered with the content state.
        grant: Option<HeldGrant>,
        /// Whom it delivers the current states to: newcomers admitted with
        /// history.
        recipients: Vec<Recipient>,
        /// Other content states it delivers, each to its recipients, in
        /// deliveries that name no grant state (keys.md, "Deliveries").
        others: Vec<(HeldState, Vec<Recipient>)>,
    },
}

/// A space event to sign.
pub(crate) struct SpaceEventPlan {
    /// The space.
    pub space: EventId,
    /// The author's `seq` in the log.
    pub seq: u64,
    /// The author's previous event.
    pub prev: Option<EventId>,
    /// The parents, `prev` among them.
    pub parents: Vec<EventId>,
    /// The checkpoints it follows (events.md, 3.11 Cuts): the maximal ones
    /// its parents reach, which [`Replica::cuts_for`](crate::replica::Replica::cuts_for)
    /// gives.
    pub cuts: Vec<EventId>,
    /// The changes of a roster event; `None` for a key event or a
    /// checkpoint.
    pub changes: Option<Vec<Change>>,
    /// The roster part of a checkpoint (roster.md, 2.2 The roster part,
    /// type 2), in place of changes.
    pub checkpoint: Option<frasil_space::CheckpointPart>,
    /// How it is sealed, and what it delivers.
    pub sealing: Sealing,
    /// Its sealed refs.
    pub refs: Vec<Ref>,
    /// Its twin, for a roster event that changes who administers: named in
    /// visible key 15 and cited among its parents.
    pub twin: Option<EventId>,
    /// Its notices of granted spaces' grant keys (keys.md, "Notices and
    /// space principals").
    pub notices: Vec<Notice>,
    /// The space principals in force, each sealed one space wrap of what
    /// the event delivers.
    pub principals: Vec<SpacePrincipal>,
    /// Whether the space has no grant state, as a restricted space has
    /// none: its space wraps carry no grant slot.
    pub grantless: bool,
}

/// A space principal a delivery seals a space wrap to: a granted space and
/// one grant rotation of it, with that rotation's grant key.
#[derive(Clone)]
pub(crate) struct SpacePrincipal {
    /// The granted space.
    pub space: EventId,
    /// The grantee rotation a valid notice names.
    pub rotation: EventId,
    /// `grant_public` of that rotation.
    pub public: Box<[u8; XWING_PUBLIC]>,
    /// Whether the granted space writes here: its wrap carries the upload
    /// seed.
    pub writes: bool,
}

/// Space wraps of one state to principals, added to the delivery that
/// names the state and the grant state, or to a new one.
#[allow(clippy::too_many_arguments)]
fn add_space_wraps(
    platform: &Platform,
    deliveries: &mut Vec<Delivery>,
    log: &[u8],
    key_name: &KeyName,
    grant_name: Option<&KeyName>,
    principals: &[SpacePrincipal],
    content: &[u8; 32],
    upload: Option<&[u8; 32]>,
    grant: Option<&[u8; 32]>,
) -> Result<()> {
    if principals.is_empty() {
        return Ok(());
    }
    let mut wraps = Vec::new();
    for principal in principals {
        let bundle = Bundle::new(
            Some(*content),
            upload.filter(|_| principal.writes).copied(),
            grant.copied(),
        )
        .map_err(Error::class)?;
        wraps.push(
            seal_space_wrap_with(
                log,
                Some(key_name),
                grant_name,
                &principal.space,
                &principal.rotation,
                &principal.public[..],
                &bundle,
                &*encapsulation(platform)?,
            )
            .map_err(Error::class)?,
        );
    }
    match deliveries
        .iter_mut()
        .find(|d| d.key_name.as_ref() == Some(key_name) && d.grant_name.as_ref() == grant_name)
    {
        Some(delivery) => delivery.space_wraps.extend(wraps),
        None => deliveries.push(Delivery {
            key_name: Some(key_name.clone()),
            grant_name: grant_name.cloned(),
            wraps: Vec::new(),
            space_wraps: wraps,
        }),
    }
    Ok(())
}

/// Removal wraps of a rotation's body key, one per removed device, at
/// random positions among the bundle wraps of its first own delivery, as
/// far as the limit on wraps allows (keys.md, "Deliveries").
fn add_removal_wraps(
    platform: &Platform,
    deliveries: &mut [Delivery],
    log: &[u8],
    removed: &[Recipient],
    body_key: &[u8; 32],
) -> Result<()> {
    let Some(first) = deliveries.first() else {
        return Ok(());
    };
    let (Some(key_name), grant_name) = (first.key_name.clone(), first.grant_name.clone()) else {
        return Ok(());
    };
    let mut room = frasil_keys::limits::MAX_WRAPS_PER_EVENT.saturating_sub(
        deliveries
            .iter()
            .map(|d| d.wraps.len() + d.space_wraps.len())
            .sum(),
    );
    for recipient in removed {
        if room == 0 {
            break;
        }
        // A holder whose keys hold no X-Wing key receives no wrap
        // (crypto.md, "The X-Wing wrap").
        let Some(xwing) = recipient.keys.keys.xwing() else {
            continue;
        };
        let wrap = seal_removal_wrap_with(
            log,
            &key_name,
            grant_name.as_ref(),
            &recipient.keys.device_id(),
            &xwing[..],
            body_key,
            &*encapsulation(platform)?,
        )
        .map_err(Error::class)?;
        let wraps = &mut deliveries[0].wraps;
        let at = u64::from_be_bytes(platform.nonce::<8>()?) % (wraps.len() as u64 + 1);
        wraps.insert(at as usize, wrap);
        room -= 1;
    }
    Ok(())
}

impl SpaceEventPlan {
    /// The body key the event will be sealed under: from `k_R` when it
    /// rotates, from `k(S)` of its state otherwise. A twin's commitment
    /// derives from it before the event exists.
    pub fn body_key(&self, author: &DeviceId) -> Secret {
        let secret = match &self.sealing {
            Sealing::Rotate { fresh, .. } => &fresh.content,
            Sealing::Under { state, .. } => &state.content,
        };
        body_key(secret, &self.space.0, author, self.seq)
    }
}

/// A storage event signed by a pseudonym: a twin, an enrolment or an
/// acknowledgement. `cuts` are the checkpoints it follows (events.md, 3.11
/// Cuts): a twin declares its roster event's.
pub(crate) fn storage_event(
    pseudonym: &Signer,
    space: EventId,
    seq: u64,
    prev: Option<EventId>,
    parents: Vec<EventId>,
    cuts: Vec<EventId>,
    body: &StorageBody,
) -> Vec<u8> {
    let mut parents = parents;
    parents.extend(prev);
    Envelope {
        kind: kind::STORAGE,
        log: Some(space),
        ed: *pseudonym.identity_key(),
        kc: *pseudonym.kc(),
        seq,
        prev,
        parents,
        cuts,
        body: body.encode(),
        scheme: Scheme::Hybrid,
    }
    .sign(pseudonym)
}

/// An enrolment (peers.md, "Enrolment"): a fresh pseudonym enrolls in a
/// slot granted to this device, with the slot keys' authorization and the
/// device's binding sealed under `twin_secret(R)`. `cuts` are the
/// checkpoints its parents follow (events.md, 3.11 Cuts).
#[allow(clippy::too_many_arguments)]
pub(crate) fn enrolment(
    platform: &Platform,
    device: &Signer,
    pseudonym: &Signer,
    space: EventId,
    slot: frasil_peers::body::SlotId,
    token: &[u8; 32],
    twin_secret: &[u8; 32],
    parents: Vec<EventId>,
    cuts: Vec<EventId>,
) -> Result<Vec<u8>> {
    use frasil_peers::derive::{SlotKeys, enrol_statement, seal_binding_with};
    let keys = SlotKeys::from_token(token);
    let pseudonym_id = *pseudonym.device_id();
    let mldsa = pseudonym.mldsa_public().to_vec();
    let authorization = keys.signer.sign(
        Scheme::Hybrid,
        &enrol_statement(&space, slot.reference, &pseudonym_id),
    );
    let binding = seal_binding_with(
        twin_secret,
        &space,
        slot.reference,
        &pseudonym_id,
        device,
        &platform.nonce::<24>()?,
    );
    let body = StorageBody::Enrol {
        slot,
        mldsa,
        slot_mldsa: keys.signer.mldsa_public().to_vec(),
        authorization,
        binding,
    };
    Ok(storage_event(
        pseudonym, space, 1, None, parents, cuts, &body,
    ))
}

/// The wrap a delivery made for one recipient, under the delivery's names,
/// as a welcome carries it (admission.md, "The welcome").
#[cfg_attr(not(feature = "iroh"), allow(dead_code))]
#[derive(Clone)]
pub(crate) struct WrapOf {
    /// The delivery's key name.
    pub key_name: KeyName,
    /// The delivery's grant key name, if it names one.
    pub grant_name: Option<KeyName>,
    /// The wrap.
    pub wrap: Vec<u8>,
}

/// Each recipient's wrap, by device ID.
type RecipientWraps = Vec<(DeviceId, WrapOf)>;

/// A signed space event, and what the device keeps of it.
pub(crate) struct SignedSpaceEvent {
    /// The signed event.
    pub signed: Vec<u8>,
    /// Its event ID.
    pub id: EventId,
    /// The rotation's secrets, when it rotates.
    pub fresh: Option<Fresh>,
    /// Whether it is a grant rotation: its fresh grant seed counts.
    pub grant_rotation: bool,
    /// Each recipient's wrap, by device ID.
    pub wraps: std::collections::BTreeMap<DeviceId, WrapOf>,
}

fn encapsulation(platform: &Platform) -> Result<Zeroizing<[u8; ENCAPSULATION_RANDOMNESS]>> {
    platform.draw::<ENCAPSULATION_RANDOMNESS>()
}

#[allow(clippy::too_many_arguments)]
fn wrap_for(
    platform: &Platform,
    log: &[u8],
    key_name: &KeyName,
    grant_name: Option<&KeyName>,
    recipient: &Recipient,
    content: &[u8; 32],
    upload: Option<&[u8; 32]>,
    grant: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    let bundle = Bundle::new(
        Some(*content),
        upload.filter(|_| recipient.writes).copied(),
        grant.filter(|_| recipient.propagates).copied(),
    )
    .map_err(Error::class)?;
    // A wrap carries g(G) only when its delivery names a grant state.
    let grant_name = grant_name.filter(|_| bundle.grant().is_some());
    seal_bundle_wrap_to(
        log,
        Some(key_name),
        grant_name,
        &recipient.keys,
        &bundle,
        &*encapsulation(platform)?,
    )
    .map_err(Error::class)
}

/// The deliveries of one state to some recipients: one naming the grant
/// state for those whose bundle carries the grant seed, one naming none for
/// the others (keys.md, "Bundle wraps and space wraps": a wrap carries
/// `g(G)` only when its delivery names a grant state and the recipient
/// propagates).
#[allow(clippy::too_many_arguments)]
fn deliveries_for(
    platform: &Platform,
    log: &[u8],
    key_name: &KeyName,
    grant_name: Option<&KeyName>,
    recipients: &[Recipient],
    content: &[u8; 32],
    upload: Option<&[u8; 32]>,
    grant: Option<&[u8; 32]>,
) -> Result<(Vec<Delivery>, RecipientWraps)> {
    let mut with_grant = Vec::new();
    let mut without = Vec::new();
    let mut of = Vec::new();
    for recipient in recipients {
        let wrap = wrap_for(
            platform, log, key_name, grant_name, recipient, content, upload, grant,
        )?;
        let carries_grant = recipient.propagates && grant_name.is_some() && grant.is_some();
        of.push((
            recipient.keys.device_id(),
            WrapOf {
                key_name: key_name.clone(),
                grant_name: grant_name.filter(|_| carries_grant).cloned(),
                wrap: wrap.clone(),
            },
        ));
        if carries_grant {
            with_grant.push(wrap);
        } else {
            without.push(wrap);
        }
    }
    let mut deliveries = Vec::new();
    if !with_grant.is_empty() {
        deliveries.push(Delivery {
            key_name: Some(key_name.clone()),
            grant_name: grant_name.cloned(),
            wraps: with_grant,
            space_wraps: Vec::new(),
        });
    }
    if !without.is_empty() {
        deliveries.push(Delivery {
            key_name: Some(key_name.clone()),
            grant_name: None,
            wraps: without,
            space_wraps: Vec::new(),
        });
    }
    Ok((deliveries, of))
}

/// Signs a space event of an existing space (keys.md, "The space event's
/// body"; roster.md, "The roster part").
pub(crate) fn space_event(
    platform: &Platform,
    signer: &Signer,
    plan: SpaceEventPlan,
) -> Result<SignedSpaceEvent> {
    let author = *signer.device_id();
    let log = plan.space.0;
    let roster = match (plan.checkpoint, plan.changes) {
        (Some(part), _) => Some(RosterPart::Checkpoint(part).encode()),
        (None, changes) => changes.map(|changes| RosterPart::Update(Update { changes }).encode()),
    };
    let own = KeyName::SelfRef(SelfRef::new(author, plan.seq));
    let mut wraps_of = std::collections::BTreeMap::new();
    let (seal, deliveries, inner, secret, fresh) = match plan.sealing {
        Sealing::Rotate {
            fresh,
            is_break,
            grant_rotation,
            recipients,
            removed,
            previous,
            previous_grant,
        } => {
            // The grant seed its own delivery carries: its own in a grant
            // rotation, the previous grant state's otherwise.
            let grant_secret: Option<Secret> = if grant_rotation {
                Some(fresh.grant.clone())
            } else {
                previous_grant.as_ref().map(|g| g.grant.clone())
            };
            let mut links = Vec::new();
            let mut gaps = Vec::new();
            if is_break {
                // A break carries the gap records of the states it cuts
                // off, and no link back (keys.md, "The space event's body").
                if let Some(previous) = &previous {
                    gaps.push(GapRecord {
                        kind: LinkKind::Content,
                        state: previous.state.clone(),
                    });
                }
                if let Some(previous) = previous_grant.as_ref().filter(|_| grant_rotation) {
                    gaps.push(GapRecord {
                        kind: LinkKind::Grant,
                        state: previous.state.clone(),
                    });
                }
            } else {
                if let Some(previous) = &previous {
                    links.push(
                        Link::seal_with(
                            LinkKind::Content,
                            &log,
                            own.clone(),
                            previous.state.clone(),
                            &fresh.content,
                            &previous.content,
                            &platform.nonce::<24>()?,
                        )
                        .map_err(Error::class)?,
                    );
                }
                if let Some(previous) = previous_grant.as_ref().filter(|_| grant_rotation) {
                    links.push(
                        Link::seal_with(
                            LinkKind::Grant,
                            &log,
                            own.clone(),
                            previous.state.clone(),
                            &fresh.grant,
                            &previous.grant,
                            &platform.nonce::<24>()?,
                        )
                        .map_err(Error::class)?,
                    );
                }
            }
            let (mut deliveries, of) = deliveries_for(
                platform,
                &log,
                &own,
                Some(&own),
                &recipients,
                &fresh.content,
                Some(&fresh.upload),
                grant_secret.as_deref(),
            )?;
            wraps_of.extend(of);
            // A restricted space's space wraps carry no grant slot
            // (ext-restricted-spaces.md, "A restricted space's secrets and
            // keys").
            if grant_secret.is_some() || plan.grantless {
                add_space_wraps(
                    platform,
                    &mut deliveries,
                    &log,
                    &own,
                    grant_secret.is_some().then_some(&own),
                    &plan.principals,
                    &fresh.content,
                    Some(&fresh.upload),
                    grant_secret.as_deref(),
                )?;
            }
            add_removal_wraps(
                platform,
                &mut deliveries,
                &log,
                &removed,
                &body_key(&fresh.content, &log, &author, plan.seq),
            )?;
            let seal = if grant_rotation {
                fresh.keys(is_break)
            } else {
                RotationKeys {
                    grant_commitment: platform.nonce::<32>()?,
                    ..fresh.keys(false)
                }
            };
            let inner = Inner {
                grant: if grant_rotation {
                    Some(GrantSlot::Rotation)
                } else {
                    previous_grant.map(|g| GrantSlot::State(g.state))
                },
                is_break,
                links,
                gaps,
                notices: plan.notices.clone(),
                roster,
                refs: plan.refs.clone(),
                ..Inner::default()
            };
            let secret = fresh.content.clone();
            (
                Seal::Rotation(seal),
                deliveries,
                inner,
                secret,
                Some((fresh, grant_rotation)),
            )
        }
        Sealing::Under {
            state,
            grant,
            recipients,
            others,
        } => {
            let mut deliveries = if recipients.is_empty() {
                Vec::new()
            } else {
                let grant_name = grant.as_ref().map(|g| KeyName::Set(g.state.clone()));
                let (deliveries, of) = deliveries_for(
                    platform,
                    &log,
                    &KeyName::Set(state.state.clone()),
                    grant_name.as_ref(),
                    &recipients,
                    &state.content,
                    state.upload.as_deref(),
                    grant.as_ref().map(|g| &*g.grant),
                )?;
                wraps_of.extend(of);
                deliveries
            };
            for (other, recipients) in &others {
                let (more, of) = deliveries_for(
                    platform,
                    &log,
                    &KeyName::Set(other.state.clone()),
                    None,
                    recipients,
                    &other.content,
                    other.upload.as_deref(),
                    None,
                )?;
                deliveries.extend(more);
                wraps_of.extend(of);
            }
            if grant.is_some() || plan.grantless {
                let grant_name = grant.as_ref().map(|g| KeyName::Set(g.state.clone()));
                add_space_wraps(
                    platform,
                    &mut deliveries,
                    &log,
                    &KeyName::Set(state.state.clone()),
                    grant_name.as_ref(),
                    &plan.principals,
                    &state.content,
                    state.upload.as_deref(),
                    grant.as_ref().map(|g| &*g.grant),
                )?;
            }
            let inner = Inner {
                notices: plan.notices.clone(),
                roster,
                refs: plan.refs.clone(),
                ..Inner::default()
            };
            (
                Seal::Under(state.state.clone()),
                deliveries,
                inner,
                state.content.clone(),
                None,
            )
        }
    };
    let key = body_key(&secret, &log, &author, plan.seq);
    let body = VisiblePart {
        seal,
        deliveries,
        sealed: inner.seal_with(&key, &log, &author, plan.seq, &platform.nonce::<24>()?),
        nonce: None,
        commitment: body_commitment(&key),
        twin: plan.twin.map(|twin| twin.0),
    }
    .encode();
    let mut parents = plan.parents;
    parents.extend(plan.twin);
    let envelope = Envelope {
        kind: kind::SPACE,
        log: Some(plan.space),
        ed: *signer.identity_key(),
        kc: *signer.kc(),
        seq: plan.seq,
        prev: plan.prev,
        parents,
        cuts: plan.cuts,
        body,
        scheme: Scheme::Hybrid,
    };
    let (fresh, grant_rotation) = match fresh {
        Some((fresh, grant_rotation)) => (Some(fresh), grant_rotation),
        None => (None, false),
    };
    Ok(SignedSpaceEvent {
        signed: envelope.sign(signer),
        id: envelope.id(),
        fresh,
        grant_rotation,
        wraps: wraps_of,
    })
}

/// A new space: its genesis, and the skeleton's root under a fresh
/// administrator pseudonym.
pub(crate) struct NewSpace {
    /// The genesis.
    pub genesis: SignedSpaceEvent,
    /// The skeleton's root.
    pub root: Vec<u8>,
    /// The pseudonym's Ed25519 and ML-DSA-65 seeds.
    pub pseudonym: (Secret, Secret),
    /// The founder's administrator slot: the genesis's twin commitment.
    pub slot: [u8; 32],
}

/// Makes a space (roster.md, "The roster part": the genesis; peers.md, "The
/// skeleton": the root).
///
/// A restricted space's genesis (ext-restricted-spaces.md, "A restricted
/// space's secrets and keys") names its parent in the descriptor and draws
/// no grant seed: its grant commitment is 32 random bytes, its own delivery
/// names no grant state, and its sealed part carries no grant slot.
pub(crate) fn new_space(
    platform: &Platform,
    signer: &Signer,
    keys: &DeviceKeys,
    policy: Policy,
    descriptor: frasil_space::Descriptor,
) -> Result<NewSpace> {
    let restricted = descriptor.kind == frasil_space::DescriptorKind::Restricted;
    let author = *signer.device_id();
    let system_stream = loop {
        let drawn = platform.nonce::<16>()?;
        if drawn != [0; 16] {
            break drawn;
        }
    };
    let nonce = platform.nonce::<16>()?;
    let fresh = Fresh::draw(platform)?;
    // The founder's grant carries its three keys, which its member ID
    // commits to (roster.md, "A device's keys").
    let mut genesis = Genesis::new(keys.clone(), policy, system_stream);
    genesis.descriptor = descriptor;
    let part = RosterPart::Genesis(Box::new(genesis));
    let own = KeyName::SelfRef(SelfRef::new(author, 1));
    let me = Recipient {
        keys: keys.clone(),
        writes: true,
        propagates: true,
    };
    let grant_name = (!restricted).then(|| own.clone());
    let wrap = wrap_for(
        platform,
        &nonce,
        &own,
        grant_name.as_ref(),
        &me,
        &fresh.content,
        Some(&fresh.upload),
        (!restricted).then_some(&*fresh.grant),
    )?;
    let inner = Inner {
        grant: (!restricted).then_some(GrantSlot::Rotation),
        roster: Some(part.encode()),
        ..Inner::default()
    };
    let key = body_key(&fresh.content, &nonce, &author, 1);
    let seal = if restricted {
        RotationKeys {
            grant_commitment: platform.nonce::<32>()?,
            ..fresh.keys(false)
        }
    } else {
        fresh.keys(false)
    };
    let body = VisiblePart {
        seal: Seal::Rotation(seal),
        deliveries: vec![Delivery {
            key_name: Some(own.clone()),
            grant_name,
            wraps: vec![wrap],
            space_wraps: Vec::new(),
        }],
        sealed: inner.seal_with(&key, &nonce, &author, 1, &platform.nonce::<24>()?),
        nonce: Some(nonce),
        commitment: body_commitment(&key),
        twin: None,
    }
    .encode();
    let envelope = Envelope {
        kind: kind::SPACE,
        log: None,
        ed: *signer.identity_key(),
        kc: *signer.kc(),
        seq: 1,
        prev: None,
        parents: Vec::new(),
        cuts: Vec::new(),
        body,
        scheme: Scheme::Hybrid,
    };
    let genesis_id = envelope.id();
    let genesis = SignedSpaceEvent {
        signed: envelope.sign(signer),
        id: genesis_id,
        fresh: Some(fresh),
        grant_rotation: !restricted,
        wraps: std::collections::BTreeMap::new(),
    };

    // The root, signed by a fresh pseudonym P0, names the genesis's twin
    // commitment and carries the founder's signature over the root
    // statement.
    let ed_seed = platform.draw::<32>()?;
    let mldsa_seed = platform.draw::<32>()?;
    // A pseudonym has no X-Wing key (peers.md, "Skeleton derivations").
    let pseudonym = Signer::from_seeds(&ed_seed, &mldsa_seed, None);
    // The root carries no salt (peers.md, "Skeleton derivations").
    let twin = twin_commitment(&author, 1, &twin_secret(&key), &[]);
    let statement = root_statement(&genesis_id, pseudonym.device_id());
    // The root carries the founder's ML-DSA-65 and X-Wing keys, which a peer
    // checks against the genesis's `kc` (peers.md, "Storage events").
    let body = StorageBody::Root {
        twin,
        mldsa: pseudonym.mldsa_public().to_vec(),
        duel_policy: 0,
        founder_mldsa: signer.mldsa_public().to_vec(),
        founder_signature: signer.sign(Scheme::Hybrid, &statement),
        founder_xwing: keys
            .keys
            .xwing()
            .map(|xwing| xwing.to_vec())
            .unwrap_or_default(),
    }
    .encode();
    let root = Envelope {
        kind: kind::STORAGE,
        log: Some(genesis_id),
        ed: *pseudonym.identity_key(),
        kc: *pseudonym.kc(),
        seq: 1,
        prev: None,
        parents: vec![genesis_id],
        cuts: Vec::new(),
        body,
        scheme: Scheme::Hybrid,
    };
    Ok(NewSpace {
        root: root.sign(&pseudonym),
        genesis,
        pseudonym: (ed_seed, mldsa_seed),
        slot: twin,
    })
}
