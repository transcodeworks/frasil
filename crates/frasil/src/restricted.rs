//! Restricted spaces and moved documents at a device
//! (ext-restricted-spaces.md, feature `ext-restricted-spaces`).
//!
//! - **Creating** ("The parent of a restricted space"): a device creates a
//!   restricted space F only under a space P it reaches whose descriptor is
//!   not itself restricted. F's genesis names P and draws no grant seed.
//! - **Keys** ("A restricted space's secrets and keys"): the device keeps
//!   F's own secrets `f_R` and `fw_R` where it keeps any space's content and
//!   upload secrets, so F's space events, read credential, upload key and
//!   member key derive from them alone. A unit or object of F is sealed
//!   under `k_F(S_F, S_P)` and names both states by the restricted key
//!   reference, P's sealed under `f(S_F)` ([`sealing`]). F never makes a
//!   grant rotation, and its deliveries reach only devices that also reach
//!   P.
//! - **Mirrors** ("Mirroring P's removals"): when P removes a member that
//!   F's roster grants, F's administrator devices that reach P wait their
//!   rank delay with P's removal as the trigger; the first removes the
//!   member from F, citing P's removal in its refs.
//! - **Moved documents** ("Moved documents"): [`Engine::move_stream`] seeds
//!   a new stream of the target space with the document's history-free
//!   snapshot and ends the original stream with a move unit. A unit of the
//!   original stream in the past of no accepted move unit is a late write:
//!   its author alone re-applies it in the new stream, once, in a unit of
//!   its own whose `copied_from` names the late write.
//! - **Carve-outs** ("Creating a carve-out", "Carve-out administration and
//!   the guest"): [`Engine::create_carve_out`] makes a space N that grants
//!   P, administered by P's administrator devices, and moves one document
//!   of P into it; a guest is then admitted to N "from now on", and a
//!   creator that does not administer P steps down
//!   ([`Engine::step_down_in_carve_out`]). N's administrator devices that
//!   reach P mirror the administrators P grants and ends
//!   ([`Engine::mirror_administrators`]).

use crate::device::{Engine, State, UnitParts};
use crate::error::{Error, Result};
use crate::platform::Platform;
use crate::replica::Replica;
use frasil_base::time::Reading;
use frasil_crypto::device::{DeviceId, KeySource};
use frasil_events::{EventId, Ref};
use frasil_keys::RotationSet;
use frasil_keys::derive::{Secret, SecretKind, state_secret};
use frasil_keys::ext_restricted_spaces::{RestrictedReference, restricted_key};
use frasil_space::ext_restricted_spaces::mirror_candidates;
use frasil_space::{
    Change, Descriptor, DescriptorKind, Keyring, Level, MemberRef, MemberType, Policy, Standing,
};
use frasil_units::UnitError;
use frasil_units::body::Compacts;
use frasil_units::ext_restricted_spaces::{MoveRecord, late_writes, reapplier};
use frasil_units::inner::CopiedFrom;
use frasil_units::objects::seal_object;
use frasil_units::snapshot::StreamSnapshot;
use frasil_units::stream::{Opening, StreamId};
use std::collections::{BTreeMap, BTreeSet};

/// What [`Engine::create_carve_out`] made.
#[derive(Debug, Clone)]
pub struct CarveOut {
    /// The carve-out N.
    pub space: EventId,
    /// The document's new stream in N.
    pub opening: Opening,
}

/// What a replica keeps of ext-restricted-spaces.md: its descriptor's
/// parent, its parent's keys, and its moved streams.
#[derive(Debug, Default)]
pub(crate) struct RestrictedPart {
    /// The space's descriptor kind, once its genesis opened.
    pub kind: Option<DescriptorKind>,
    /// A restricted space's parent, once its genesis opened.
    pub parent: Option<EventId>,
    /// A carve-out's space P, once its genesis opened.
    pub carve_out_of: Option<EventId>,
    /// The parent's content keys as of the last refresh, which open the
    /// parent's state in a reference.
    pub parent_keys: Keyring,
    /// The valid move units of each moved stream whose record reads, in
    /// canonical order.
    pub moves: BTreeMap<StreamId, Vec<(EventId, MoveRecord)>>,
    /// The late writes valid units of this space re-apply:
    /// `(original space, late write)`.
    pub copied: BTreeSet<(EventId, EventId)>,
    /// The devices a valid roster event of this space ever granted
    /// `administer`, the founder included: what a carve-out of it reads to
    /// tell its creator that administered it from one that never did
    /// ("Carve-out administration and the guest").
    pub administered: BTreeSet<[u8; 32]>,
}

impl RestrictedPart {
    /// Forgets what the units of the last refresh said, before they are
    /// handed over again.
    pub fn clear_units(&mut self) {
        self.moves.clear();
        self.copied.clear();
    }

    /// Takes a move unit ("Reading a move record"): a record that fails is
    /// a content refusal with its class, and the stream is not moved; a
    /// valid unit whose record reads moves its stream.
    ///
    /// # Errors
    ///
    /// `Malformed` or `UnsupportedVersion`.
    pub fn take_move(
        &mut self,
        id: EventId,
        stream: StreamId,
        content: &[u8],
        valid: bool,
    ) -> core::result::Result<(), UnitError> {
        let record = MoveRecord::read(content)?;
        if valid {
            self.moves.entry(stream).or_default().push((id, record));
        }
        Ok(())
    }
}

/// The devices a valid roster event of the resolved space ever granted
/// `administer`, or set at `administer`, the genesis's founder included.
pub(crate) fn administered(space: &frasil_space::Space<'_>) -> BTreeSet<[u8; 32]> {
    space
        .valid_roster()
        .iter()
        .filter_map(|id| space.opened(*id))
        .flat_map(|opened| opened.changes().iter())
        .filter(|change| change.level == Some(Level::Administer))
        .filter_map(|change| change.member)
        .filter(|member| member.kind == MemberType::Device)
        .map(|member| member.id)
        .collect()
}

/// The content key of a state from a keyring: derived from the rotation
/// keys held, or a merged state's key received whole (provisional).
fn keyring_state(
    keyring: &Keyring,
    space: &EventId,
    state: &RotationSet,
) -> Option<(Secret, bool)> {
    let inputs: Option<zeroize::Zeroizing<Vec<[u8; 32]>>> = state
        .ids()
        .iter()
        .map(|id| keyring.rotations.get(id).map(|key| **key))
        .collect::<Option<Vec<_>>>()
        .map(zeroize::Zeroizing::new);
    match inputs {
        Some(inputs) => state_secret(SecretKind::Content, space, state, &inputs)
            .ok()
            .map(|key| (key, false)),
        None => keyring.states.get(state).map(|key| (key.clone(), true)),
    }
}

impl Replica {
    /// A restricted space's parent, once its genesis opened.
    pub fn restricted_parent(&self) -> Option<EventId> {
        self.restricted.parent
    }

    /// Whether the space is restricted, as far as this replica has read its
    /// genesis.
    pub(crate) fn is_restricted(&self) -> bool {
        self.restricted.kind == Some(DescriptorKind::Restricted)
    }

    /// Where a stream moved, once this replica holds an accepted move unit
    /// of it ("Moved documents", "A moved stream").
    pub fn moved(&self, stream: &StreamId) -> Option<&MoveRecord> {
        self.restricted
            .moves
            .get(stream)
            .and_then(|moves| moves.first())
            .map(|(_, record)| record)
    }

    /// The late writes of a moved stream: its valid units, the move units
    /// aside, in the past of no accepted move unit, in canonical order.
    pub fn late_writes(&self, stream: &StreamId) -> Vec<EventId> {
        let (Some(moves), Some(log)) = (self.restricted.moves.get(stream), self.log()) else {
            return Vec::new();
        };
        let moves: BTreeSet<EventId> = moves.iter().map(|(id, _)| *id).collect();
        let units: Vec<EventId> = log
            .canonical()
            .into_iter()
            .filter(|id| self.valid().contains(id) && self.unit_stream(id) == Some(*stream))
            .collect();
        late_writes(&units, &moves, |a, b| log.precedes(*a, *b))
    }

    /// Whether a valid unit of this space re-applies a late write.
    pub(crate) fn reapplied(&self, original: &EventId, late: &EventId) -> bool {
        self.restricted.copied.contains(&(*original, *late))
    }

    /// The content key a key reference names, and whether it is
    /// provisional: a rotation set's, or in a restricted space the
    /// restricted reference's `k_F(S_F, S_P)` ("Reading a restricted key
    /// reference", steps 1 to 5: an object's reference is not checked
    /// against the logs).
    pub(crate) fn reference_key(&self, reference: &[u8]) -> Option<(Secret, bool)> {
        if let Ok(state) = RotationSet::decode(reference) {
            return self.state_key(&state);
        }
        let parent = self.restricted.parent?;
        let read = RestrictedReference::read(reference).ok()?;
        let (own, own_provisional) = self.state_key(&read.own)?;
        let parent_state = read.open(&self.space(), &own).ok()?;
        let (parent_key, parent_provisional) =
            keyring_state(&self.restricted.parent_keys, &parent, &parent_state)?;
        Some((
            restricted_key(&self.space(), &parent, &own, &parent_key).key,
            own_provisional || parent_provisional,
        ))
    }
}

/// `k_F` and the restricted key reference of a state of F, this device's
/// current one by default, and of its current state of the parent P
/// (sections 2.2 and 2.3).
pub(crate) fn sealing(
    platform: &Platform,
    state: &State,
    space: &EventId,
    parent: &EventId,
    under: Option<&RotationSet>,
) -> Result<(Vec<u8>, Secret)> {
    let replica = state.replicas.get(space).ok_or(Error::UnknownSpace)?;
    let own = match under {
        Some(under) => crate::writer::HeldState {
            state: under.clone(),
            content: replica
                .state_key(under)
                .ok_or(Error::NotAllowed("the device lacks the state's key"))?
                .0,
            upload: None,
        },
        None => Engine::held_state(replica)?,
    };
    let parent_replica = state
        .replicas
        .get(parent)
        .ok_or(Error::NotAllowed("the device does not hold the parent"))?;
    let parent_held = Engine::held_state(parent_replica)?;
    let reference = RestrictedReference::seal_with(
        space,
        &own.state,
        &parent_held.state,
        &own.content,
        &platform.nonce::<24>()?,
    );
    let key = restricted_key(space, parent, &own.content, &parent_held.content).key;
    Ok((reference.encode(), key))
}

/// Whether a device reaches the parent of a restricted space, which it
/// must to receive anything of it ("Membership of a restricted space").
/// For any other space, every device does.
pub(crate) fn reaches_parent(
    replica: &Replica,
    others: &BTreeMap<EventId, Replica>,
    device: &DeviceId,
) -> bool {
    match replica.restricted_parent() {
        None => true,
        Some(parent) => others
            .get(&parent)
            .is_some_and(|p| p.level_of(device).is_some()),
    }
}

/// Learns a restricted space's parent from a restricted key reference
/// before the space's log arrives, as a newcomer's snapshot needs: the
/// held space whose log holds every rotation of the parent's state the
/// reference seals.
pub(crate) fn learn_parent(state: &mut State, space: &EventId, reference: &[u8]) {
    let Some(replica) = state.replicas.get(space) else {
        return;
    };
    if replica.restricted.parent.is_some() {
        return;
    }
    let Ok(read) = RestrictedReference::read(reference) else {
        return;
    };
    let Some((own, _)) = replica.state_key(&read.own) else {
        return;
    };
    let Ok(parent_state) = read.open(space, &own) else {
        return;
    };
    let found = state
        .replicas
        .iter()
        .filter(|(id, _)| *id != space)
        .find(|(_, r)| {
            r.log()
                .is_some_and(|log| parent_state.ids().iter().all(|id| log.contains(*id)))
        })
        .map(|(id, r)| (*id, r.keyring()));
    if let (Some((parent, keys)), Some(replica)) = (found, state.replicas.get_mut(space)) {
        replica.restricted.kind = Some(DescriptorKind::Restricted);
        replica.restricted.parent = Some(parent);
        replica.restricted.parent_keys = keys;
    }
}

impl Engine {
    /// Creates a restricted space under `parent` (ext-restricted-spaces.md,
    /// "The parent of a restricted space"): its genesis names the parent,
    /// grants this device `administer`, and draws no grant seed.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`] for a parent the device does not hold;
    /// [`Error::NotAllowed`] when the device does not reach the parent, or
    /// the parent is itself restricted; as [`Engine::create_space`].
    pub async fn create_restricted(&self, parent: EventId) -> Result<EventId> {
        {
            let state = self.lock().await;
            let replica = state.replicas.get(&parent).ok_or(Error::UnknownSpace)?;
            if replica.level_of(&self.device_id()).is_none() {
                return Err(Error::NotAllowed("the device does not reach the parent"));
            }
            if replica.is_restricted() {
                return Err(Error::NotAllowed(
                    "restricted spaces do not nest: the parent is restricted",
                ));
            }
        }
        self.create_space_as(
            Policy::default(),
            Descriptor {
                kind: DescriptorKind::Restricted,
                parent: Some(parent.0),
                application: None,
            },
        )
        .await
    }

    /// The proven keys a roster of a space this device holds names for a
    /// device: what a grant of it carries.
    fn keys_of(state: &State, device: &DeviceId) -> Option<frasil_space::DeviceKeys> {
        state
            .replicas
            .values()
            .find_map(|replica| {
                replica
                    .roster()
                    .state(&MemberRef::device(*device))
                    .and_then(|member| member.keys.as_deref().cloned())
            })
            .or_else(|| state.keys().device_keys(device))
            .filter(|keys| keys.device_id() == *device)
    }

    /// Creates a carve-out of `parent` for one of its documents
    /// (ext-restricted-spaces.md, "Creating a carve-out"): N's genesis,
    /// whose descriptor names P, grants this device `administer`; its first
    /// update grants P at `write`, "with history", and each other
    /// administrator device of P `administer` with the keys of P's grant of
    /// it; then the document's history-free state seeds a new stream of N,
    /// and a move unit ends its stream in P. The guest is admitted to N
    /// next, "from now on", by an admission code: its grant is the break.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`] for a parent the device does not hold;
    /// [`Error::NotAllowed`] unless this device writes in P and its grant
    /// propagates, or when P is restricted; as [`Engine::move_stream`].
    pub async fn create_carve_out(&self, parent: EventId, stream: StreamId) -> Result<CarveOut> {
        let me = self.device_id();
        let administrators = {
            let state = self.lock().await;
            let replica = state.replicas.get(&parent).ok_or(Error::UnknownSpace)?;
            if replica.level_of(&me) < Some(Level::Write) || !replica.propagates(&me) {
                return Err(Error::NotAllowed(
                    "a carve-out is made by a writer of the space whose grant propagates",
                ));
            }
            if replica.is_restricted() {
                return Err(Error::NotAllowed(
                    "a carve-out is never made under a restricted space",
                ));
            }
            if replica.opening_of(&stream).is_none() {
                return Err(Error::UnknownStream);
            }
            replica
                .devices()
                .into_iter()
                .filter(|(device, level)| *level == Level::Administer && *device != me)
                .filter_map(|(device, _)| {
                    // Each administrator keeps its rank in P.
                    let rank = replica
                        .roster()
                        .state(&MemberRef::device(device))
                        .and_then(|state| state.rank)
                        .unwrap_or(frasil_space::change::MAX_RANK);
                    Self::keys_of(&state, &device).map(|k| (rank, k))
                })
                .collect::<Vec<_>>()
        };
        let space = self
            .create_space_as(
                Policy::default(),
                Descriptor {
                    kind: DescriptorKind::CarveOut,
                    parent: Some(parent.0),
                    application: None,
                },
            )
            .await?;
        let mut changes = vec![Change::grant(
            MemberRef::space(parent.0),
            Level::Write,
            frasil_space::HistoryMode::WithHistory,
            frasil_space::Via::None,
        )];
        for (rank, keys) in administrators {
            changes.push(Change::grant_administrator(
                keys,
                rank,
                frasil_space::HistoryMode::WithHistory,
                frasil_space::Via::None,
            ));
        }
        self.sign_roster(space, changes).await?;
        let opening = self.move_stream(parent, stream, space).await?;
        Ok(CarveOut { space, opening })
    }

    /// Ends a carve-out's creation for a creator that does not administer
    /// P (ext-restricted-spaces.md, "Creating a carve-out", step 3): once
    /// the guest is admitted, it lowers its own grant in N to `write`, in a
    /// self-lowering event. Returns the event, or `None` for a creator that
    /// administers P, which keeps `administer`.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a space that is no carve-out this device
    /// administers; as [`Engine::sign_roster`].
    pub async fn step_down_in_carve_out(&self, space: EventId) -> Result<Option<EventId>> {
        let me = self.device_id();
        {
            let state = self.lock().await;
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            let parent = replica
                .restricted
                .carve_out_of
                .ok_or(Error::NotAllowed("the space is no carve-out"))?;
            if replica.level_of(&me) != Some(Level::Administer) {
                return Err(Error::NotAllowed("the device does not administer it"));
            }
            if state
                .replicas
                .get(&parent)
                .is_some_and(|p| p.level_of(&me) == Some(Level::Administer))
            {
                return Ok(None);
            }
        }
        self.sign_roster(
            space,
            vec![Change::set_level(MemberRef::device(me), Level::Write)],
        )
        .await
        .map(Some)
    }

    /// Mirrors P's administrators in a carve-out N
    /// (ext-restricted-spaces.md, "Carve-out administration and the
    /// guest"): for each device P's merged roster has made an
    /// administrator that N does not grant `administer`, and each device N
    /// grants `administer` directly that P has removed or lowered, N's
    /// administrator devices that reach P are the candidates, ranked with
    /// P's event as the trigger; once its delay has passed from its first
    /// sight of that event, this device grants the new administrator with
    /// the keys of P's grant, or removes the old one, citing P's event. A
    /// candidate drops its mirror once an event of N cites P's event.
    ///
    /// # Errors
    ///
    /// As [`Engine::sign_roster`].
    pub async fn mirror_administrators(&self, space: EventId) -> Result<Option<EventId>> {
        let me = self.device_id();
        let due = {
            let mut state = self.lock().await;
            let now = self.read_timeline(&mut state).await?;
            let Some(replica) = state.replicas.get(&space) else {
                return Ok(None);
            };
            let Some(parent_id) = replica.restricted.carve_out_of else {
                return Ok(None);
            };
            let Some(parent) = state.replicas.get(&parent_id) else {
                return Ok(None);
            };
            if replica.level_of(&me) != Some(Level::Administer)
                || parent.level_of(&me).is_none()
                || Self::check_may_sign(&state, &space).is_err()
            {
                return Ok(None);
            }
            administrator_mirror_due(replica, parent, &space, &parent_id, &me, &now)
                .map(|(change, trigger)| (change, parent_id, trigger))
        };
        let Some((change, parent, trigger)) = due else {
            return Ok(None);
        };
        self.sign_roster_citing(
            space,
            vec![change],
            vec![Ref {
                log: parent,
                id: trigger,
            }],
        )
        .await
        .map(Some)
    }

    /// Grants a device that a roster this device holds names, such as a
    /// member of a restricted space's parent, at `level`, "with history",
    /// with the keys that roster proves for it.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device outside a restricted space's
    /// parent, or one whose keys no roster the device holds names; as
    /// [`Engine::sign_roster`].
    pub async fn grant_member(
        &self,
        space: EventId,
        device: DeviceId,
        level: Level,
    ) -> Result<EventId> {
        let keys = {
            let state = self.lock().await;
            let replica = state.replicas.get(&space).ok_or(Error::UnknownSpace)?;
            if !reaches_parent(replica, &state.replicas, &device) {
                return Err(Error::NotAllowed(
                    "the device does not reach the restricted space's parent",
                ));
            }
            Self::keys_of(&state, &device).ok_or(Error::NotAllowed(
                "no roster this device holds names the device's keys",
            ))?
        };
        self.grant_device(
            space,
            keys,
            level,
            frasil_space::HistoryMode::WithHistory,
            frasil_space::Via::None,
        )
        .await
    }

    /// Mirrors the parent's removals in a restricted space
    /// ("Mirroring P's removals"): for each member F's roster grants that
    /// P's merged roster has removed, F's administrator devices that reach
    /// P are the candidates, ranked with P's removal as the trigger; once
    /// its delay has passed from its first sight of that removal, this
    /// device removes the member from F, citing the removal. A candidate
    /// drops its mirror once an event of F cites the removal.
    ///
    /// # Errors
    ///
    /// As [`Engine::sign_roster`].
    pub async fn mirror_parent(&self, space: EventId) -> Result<Option<EventId>> {
        let me = self.device_id();
        let due = {
            let mut state = self.lock().await;
            let now = self.read_timeline(&mut state).await?;
            let Some(replica) = state.replicas.get(&space) else {
                return Ok(None);
            };
            let Some(parent_id) = replica.restricted_parent() else {
                return Ok(None);
            };
            let Some(parent) = state.replicas.get(&parent_id) else {
                return Ok(None);
            };
            if replica.level_of(&me) != Some(Level::Administer)
                || parent.level_of(&me).is_none()
                || Self::check_may_sign(&state, &space).is_err()
            {
                return Ok(None);
            }
            mirror_due(replica, parent, &space, &parent_id, &me, &now)
                .map(|(member, trigger)| (member, parent_id, trigger))
        };
        let Some((member, parent, trigger)) = due else {
            return Ok(None);
        };
        self.sign_roster_citing(
            space,
            vec![Change::remove(member)],
            vec![Ref {
                log: parent,
                id: trigger,
            }],
        )
        .await
        .map(Some)
    }

    /// Moves a document's stream to another space this device writes in
    /// ("Moved documents"): seals the stream's history-free snapshot under
    /// the target's state as the seed of a new stream, with a fresh salt
    /// and the same adapter type, then writes the move unit in the original
    /// stream. Returns the new stream's opening.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownStream`] for a stream the device does not read;
    /// [`Error::Unsupported`] for a stream whose state references objects;
    /// [`Error::NotAllowed`] unless the device writes in both spaces, for a
    /// stream moved already, or when the stream's adapter refuses its
    /// history-free export, as past the limits of what a replica loads; as
    /// [`Engine::write_unit`].
    pub async fn move_stream(
        &self,
        from: EventId,
        stream: StreamId,
        to: EventId,
    ) -> Result<Opening> {
        // A lent document's operations reach a unit before the export.
        #[cfg(feature = "adapter-loro")]
        self.flush_lent_in(from).await?;
        let mut state = self.lock().await;
        let me = self.device_id();
        let (original, type_, history_free, metadata) = {
            let replica = state.replicas.get(&from).ok_or(Error::UnknownSpace)?;
            if replica.moved(&stream).is_some() {
                return Err(Error::NotAllowed("the document has moved already"));
            }
            let original = replica.opening_of(&stream).ok_or(Error::UnknownStream)?;
            let runtime = replica.stream(&stream).ok_or(Error::UnknownStream)?;
            let cover: BTreeSet<[u8; 32]> = replica
                .log()
                .map(|log| {
                    log.canonical()
                        .into_iter()
                        .filter(|id| replica.unit_stream(id) == Some(stream))
                        .map(|id| id.0)
                        .collect()
                })
                .unwrap_or_default();
            let compaction = runtime
                .compact(&cover)
                .ok_or(Error::NotAllowed("the adapter cannot compact this stream"))?;
            if !compaction.objects.is_empty() {
                return Err(Error::Unsupported(
                    "moving a document whose state references objects",
                ));
            }
            (
                original,
                runtime.adapter_type().to_owned(),
                runtime.export_history_free().ok_or(Error::NotAllowed(
                    "the document's adapter refuses its history-free export",
                ))?,
                compaction.metadata,
            )
        };
        let target = state.replicas.get(&to).ok_or(Error::UnknownSpace)?;
        if target.level_of(&me) < Some(Level::Write) {
            return Err(Error::NotAllowed(
                "the device does not write in the target space",
            ));
        }
        let opening = self.new_stream(&type_)?;
        let new = opening.stream();
        // The seed's stream snapshot object, sealed under the target's
        // state and kept before the unit that names it.
        let (reference, key) = self.sealing(&state, &to)?;
        let plaintext = StreamSnapshot {
            type_: type_.clone(),
            stream: new,
            history_free: true,
            state: history_free,
            moved: None,
        }
        .encode();
        let object = seal_object(&to, &key, &reference, &plaintext).map_err(Error::class)?;
        let parts = crate::objects::parts_of(&object.locator, &object.bytes)?;
        Self::keep_parts_in(&mut state, to, &parts.iter().collect::<Vec<_>>()).await?;
        self.write_parts(
            &mut state,
            to,
            new,
            Some(opening.clone()),
            &type_,
            |_, _, _| {
                Ok(UnitParts {
                    content: metadata,
                    objects: vec![object.locator],
                    compacts: Some(Compacts {
                        object: object.locator,
                        covers: Vec::new(),
                        stubs: Vec::new(),
                    }),
                    ..UnitParts::default()
                })
            },
        )
        .await?;
        let record = MoveRecord {
            to_space: to,
            to_stream: new,
            name: None,
        };
        self.write_parts(
            &mut state,
            from,
            stream,
            Some(original),
            frasil_units::types::MOVE,
            |_, _, _| {
                Ok(UnitParts {
                    content: record.encode(),
                    ..UnitParts::default()
                })
            },
        )
        .await?;
        Ok(opening)
    }

    /// Re-applies this device's own late writes of the space's moved
    /// streams ("Moved documents", "Re-applying a late write"): each one
    /// whose new space this device reaches at `write`, unless a unit of the
    /// new stream already re-applies it. No device re-applies another's
    /// late write, so each shows once in the new stream. Returns the units
    /// written.
    ///
    /// # Errors
    ///
    /// As [`Engine::write_unit`].
    pub async fn reapply_late_writes(&self, space: EventId) -> Result<Vec<EventId>> {
        let me = self.device_id();
        let mut written = Vec::new();
        let mut state = self.lock().await;
        let due = {
            let Some(replica) = state.replicas.get(&space) else {
                return Ok(written);
            };
            reapplications_due(&state, replica, &me)
        };
        for (late, record) in due {
            let Some(content) = reapplied_content(&state, &space, &late, &record, &me) else {
                continue;
            };
            let opening = state
                .replicas
                .get(&record.to_space)
                .and_then(|r| r.opening_of(&record.to_stream));
            let Some(opening) = opening else {
                continue;
            };
            let type_ = opening.type_.clone();
            let id = self
                .write_parts(
                    &mut state,
                    record.to_space,
                    record.to_stream,
                    Some(opening),
                    &type_,
                    |_, _, _| {
                        Ok(UnitParts {
                            content,
                            copied_from: Some(CopiedFrom { space, event: late }),
                            ..UnitParts::default()
                        })
                    },
                )
                .await?;
            written.push(id);
        }
        Ok(written)
    }
}

/// The first member P removed that F still grants, with P's removal, if
/// this device's mirror of it is due.
fn mirror_due(
    replica: &Replica,
    parent: &Replica,
    space: &EventId,
    parent_id: &EventId,
    me: &DeviceId,
    now: &Reading,
) -> Option<(MemberRef, EventId)> {
    let administrators: Vec<[u8; 32]> = replica
        .devices()
        .into_iter()
        .filter(|(d, level)| *level == Level::Administer && parent.level_of(d).is_some())
        .map(|(d, _)| d.0)
        .collect();
    let cited = replica.named_in(parent_id);
    let step = crate::maintenance::rotation_step();
    for (member, _) in replica.roster().members_in() {
        if !matches!(member.kind, MemberType::Device | MemberType::Person) {
            continue;
        }
        let Some(Standing::Out { removed_by }) = parent.roster().standing(member) else {
            continue;
        };
        let Some(trigger) = removed_by.first().copied() else {
            continue;
        };
        if cited.contains(&trigger) {
            continue;
        }
        let candidates = mirror_candidates(space, &trigger, &administrators, step);
        let Some(mine) = candidates.iter().find(|c| c.device == me.0) else {
            continue;
        };
        let first = parent.first_sight(&trigger).copied().unwrap_or(*now);
        if frasil_space::keygraph::rank::due(&first, now, mine.position, step) {
            return Some((*member, trigger));
        }
    }
    None
}

/// The first change that mirrors P's administrators in the carve-out
/// `replica`, with P's event, if this device's mirror of it is due.
fn administrator_mirror_due(
    replica: &Replica,
    parent: &Replica,
    space: &EventId,
    parent_id: &EventId,
    me: &DeviceId,
    now: &Reading,
) -> Option<(Change, EventId)> {
    let administrators: Vec<[u8; 32]> = replica
        .devices()
        .into_iter()
        .filter(|(d, level)| *level == Level::Administer && parent.level_of(d).is_some())
        .map(|(d, _)| d.0)
        .collect();
    let cited = replica.named_in(parent_id);
    let direct_administer = |device: &[u8; 32]| {
        replica
            .roster()
            .state(&MemberRef::device(DeviceId(*device)))
            .is_some_and(|s| s.level == Level::Administer)
    };
    let mut wanted: Vec<(Change, EventId)> = Vec::new();
    // A new administrator of P, with the keys of P's grant of it.
    for (member, member_state) in parent.roster().members_in() {
        if member.kind != MemberType::Device
            || member_state.level != Level::Administer
            || direct_administer(&member.id)
        {
            continue;
        }
        let Some(keys) = member_state.keys.as_deref().cloned() else {
            continue;
        };
        wanted.push((
            // At its rank in P.
            Change::grant_administrator(
                keys,
                member_state.rank.unwrap_or(frasil_space::change::MAX_RANK),
                frasil_space::HistoryMode::WithHistory,
                frasil_space::Via::None,
            ),
            member_state.source.1,
        ));
    }
    // An administrator of N whose administer P ended: removed, or lowered.
    // N's creator is mirrored too: while N grants it `administer`, as any
    // administrator once it administered P, and otherwise only once P
    // removes it or leaves it below `write`, since a creator that never
    // administered P steps down by itself ("Creating a carve-out", step 3);
    // once N grants it `write`, when P removes it or leaves it below
    // `write`. A guest, which P never granted, is never mirrored.
    let creator = replica.log().map(|log| *log.genesis().author());
    for (member, member_state) in replica.roster().members_in() {
        if member.kind != MemberType::Device {
            continue;
        }
        let is_creator = Some(DeviceId(member.id)) == creator;
        let floor = match member_state.level {
            Level::Administer
                if !is_creator || parent.restricted.administered.contains(&member.id) =>
            {
                Level::Administer
            }
            Level::Administer | Level::Write if is_creator => Level::Write,
            _ => continue,
        };
        let trigger = match parent.roster().standing(member) {
            Some(Standing::Out { removed_by }) => removed_by.first().copied(),
            _ => parent
                .roster()
                .state(member)
                .filter(|s| s.level < floor)
                .map(|s| s.source.1),
        };
        if let Some(trigger) = trigger {
            wanted.push((Change::remove(*member), trigger));
        }
    }
    let step = crate::maintenance::rotation_step();
    for (change, trigger) in wanted {
        if cited.contains(&trigger) {
            continue;
        }
        let candidates = mirror_candidates(space, &trigger, &administrators, step);
        let Some(mine) = candidates.iter().find(|c| c.device == me.0) else {
            continue;
        };
        let first = parent.first_sight(&trigger).copied().unwrap_or(*now);
        if frasil_space::keygraph::rank::due(&first, now, mine.position, step) {
            return Some((change, trigger));
        }
    }
    None
}

/// The late writes of `replica`'s moved streams this device re-applies
/// now, each with its move record.
fn reapplications_due(
    state: &State,
    replica: &Replica,
    me: &DeviceId,
) -> Vec<(EventId, MoveRecord)> {
    let space = replica.space();
    let mut out = Vec::new();
    let Some(log) = replica.log() else {
        return out;
    };
    for (stream, moves) in &replica.restricted.moves {
        let Some((_, record)) = moves.first() else {
            continue;
        };
        let Some(target) = state.replicas.get(&record.to_space) else {
            continue;
        };
        if target.level_of(me) < Some(Level::Write) || target.stream(&record.to_stream).is_none() {
            continue;
        }
        // The devices that reach the new space at `write`.
        let writers: Vec<DeviceId> = target
            .devices()
            .into_iter()
            .filter(|(_, level)| *level >= Level::Write)
            .map(|(device, _)| device)
            .collect();
        for late in replica.late_writes(stream) {
            if target.reapplied(&space, &late) {
                continue;
            }
            let Some(author) = log.event(late).map(|e| *e.author()) else {
                continue;
            };
            // Only the late write's author re-applies it, once.
            if reapplier(&author, &writers) == Some(*me) {
                out.push((late, record.clone()));
            }
        }
    }
    out
}

/// The adapter's `reapply` of a late write as this device's own unit in
/// the new stream: `None` when the adapter re-applies nothing.
fn reapplied_content(
    state: &State,
    space: &EventId,
    late: &EventId,
    record: &MoveRecord,
    me: &DeviceId,
) -> Option<Vec<u8>> {
    let original = state.replicas.get(space)?;
    let target = state.replicas.get(&record.to_space)?;
    let stream = original.unit_stream(late)?;
    let new = target.stream(&record.to_stream)?;
    // The seq the re-applier's unit takes in its chain.
    let seq = Engine::next(state, &record.to_space, me).0;
    let writer = frasil_adapter::Writer {
        space: record.to_space.0,
        stream: record.to_stream,
        author: me.0,
        seq,
    };
    original.stream(&stream)?.reapply(&late.0, new, &writer)
}
