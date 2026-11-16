//! Recovery (identity.md): recovery keys and passkey members, their
//! recovery entries, and a device that returns with a recovery sheet or a
//! passkey.
//!
//! - **Setting up** (identity.md, "Adding list members"): a device of the
//!   person adds a recovery key or a passkey member to the list, publishes
//!   the `add` in each space that grants the person, delivers each such
//!   space's current state to the new list member, and records its
//!   recovery entry in the personal space. Each other space that grants
//!   the person gets a recovery entry of its own, under a fetch key from a
//!   fresh seed kept in the personal space. The device's peer connections
//!   register every fetch key at the peers they use.
//! - **Recovering** (identity.md, "Recovery"): a device that holds only the
//!   sheet or the passkey follows the personal space, presents the list
//!   member's fetch key, opens the wraps for the list member in what
//!   catch-up serves, merges the list, has the list member sign its own
//!   `add`, publishes it, and then reaches each space the personal space
//!   records a recovery entry of in the same way.

use crate::device::{Engine, State};
use crate::error::{Error, Result};
use crate::writer::Recipient;
use frasil_crypto::device::{DeviceId, DeviceKeys};
use frasil_events::EventId;
use frasil_identity::body::ListBody;
use frasil_identity::entries::{Holder, RecoveryEntry};
use frasil_identity::passkey::{PasskeyMember, UserHandle};
use frasil_identity::recovery::{RecoveryKey, RecoverySecret};
use frasil_identity::{Kind, MemberKeys, PublicKeys};
use frasil_keys::derive::Secret;
use frasil_space::{Level, MemberRef, MemberType};
use frasil_store::device_keys::SEALED_DEVICE_KEYS_BYTES;
use frasil_store::tables::{Table, TableValue};
use frasil_units::types::RECOVERY_ENTRY;
use std::collections::{BTreeMap, BTreeSet};
use zeroize::Zeroizing;

/// A list member a device recovers with: a recovery key from a sheet, or a
/// passkey member from a passkey's PRF output, with its fetch key, for one
/// person and personal space.
pub struct RecoveryMember {
    kind: Kind,
    member: MemberKeys,
    fetch: Secret,
    person: [u8; 32],
    personal_space: EventId,
}

impl core::fmt::Debug for RecoveryMember {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryMember")
            .field("kind", &self.kind)
            .field("member", &self.member)
            .finish_non_exhaustive()
    }
}

/// A copy of a list member's keys, from its seeds.
fn copy_keys(keys: &MemberKeys) -> MemberKeys {
    match keys.xwing_seed() {
        Some(xwing) => MemberKeys::from_seeds(keys.identity_seed(), xwing, keys.mldsa_seed()),
        None => MemberKeys::without_xwing(keys.identity_seed(), keys.mldsa_seed()),
    }
}

impl RecoveryMember {
    /// The recovery key of a sheet's printed secret (identity.md, "Recovery
    /// keys"), for the person and the personal space the sheet shows.
    ///
    /// # Errors
    ///
    /// `InvalidSheet` for text that is not a recovery secret.
    pub fn from_sheet(printed: &str, person: [u8; 32], personal_space: EventId) -> Result<Self> {
        let secret = RecoverySecret::read_sheet(printed).map_err(Error::class)?;
        let key = RecoveryKey::derive(&secret);
        Ok(Self {
            kind: Kind::RecoveryKey,
            member: copy_keys(key.member()),
            fetch: Zeroizing::new(*key.fetch().seed()),
            person,
            personal_space,
        })
    }

    /// The passkey member of an assertion's user handle and PRF output
    /// (identity.md, "Using a passkey member", steps 1 and 2).
    ///
    /// # Errors
    ///
    /// `Malformed` for a handle that is not 64 bytes; `InvalidPrfOutput`.
    pub fn from_passkey(user_handle: &[u8], output: &[u8]) -> Result<Self> {
        let handle = UserHandle::parse(user_handle).map_err(Error::class)?;
        let member = PasskeyMember::derive(&handle.person_id, output).map_err(Error::class)?;
        Ok(Self {
            kind: Kind::PasskeyMember,
            member: copy_keys(member.member()),
            fetch: Zeroizing::new(*member.fetch().seed()),
            person: handle.person_id,
            personal_space: EventId(handle.personal_space),
        })
    }

    /// The list member's kind: a recovery key or a passkey member.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The person ID.
    pub fn person(&self) -> [u8; 32] {
        self.person
    }

    /// The personal space.
    pub fn personal_space(&self) -> EventId {
        self.personal_space
    }

    /// The list member's device ID, by which the list names it.
    pub fn device_id(&self) -> DeviceId {
        *self.member.device_id()
    }

    /// The fetch key it presents for the personal space.
    pub fn fetch_key(&self) -> [u8; 32] {
        frasil_crypto::primitives::ed25519_public(&self.fetch)
    }

    fn public(&self) -> PublicKeys {
        self.member.public(self.kind)
    }
}

/// What a recovering device holds: the list member, and the fetch seeds of
/// the other spaces the personal space records entries of.
pub(crate) struct Recovering {
    member: RecoveryMember,
    seeds: BTreeMap<EventId, Secret>,
}

impl Recovering {
    /// The list member's device ID and X-Wing seed, whose wraps the device
    /// opens while it recovers; `None` for a member with no X-Wing key,
    /// which receives no wrap.
    pub(crate) fn opener(&self) -> Option<(DeviceId, Secret)> {
        let xwing = self.member.member.xwing_seed()?;
        Some((*self.member.member.device_id(), Zeroizing::new(*xwing)))
    }
}

/// A recovery key this device added: what its sheet shows. The secret is
/// shown once and then forgotten.
pub struct MadeRecoveryKey {
    /// The person ID.
    pub person: [u8; 32],
    /// The personal space.
    pub personal_space: EventId,
    /// The secret in its printed form (identity.md, "Recovery keys").
    pub printed: Zeroizing<String>,
    /// The `add` of the recovery key.
    pub add: EventId,
}

impl core::fmt::Debug for MadeRecoveryKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MadeRecoveryKey")
            .field("person", &self.person)
            .field("personal_space", &self.personal_space)
            .field("add", &self.add)
            .finish_non_exhaustive()
    }
}

/// Where a recovery stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStatus {
    /// The device is not recovering.
    NotRecovering,
    /// The device waits for the personal space and the list it carries.
    Fetching,
    /// The merged list holds the list member, active, of its kind, with its
    /// keys: [`Engine::complete_recovery`] can sign the device in.
    Ready,
    /// The device holds the person's list, and the list member is not an
    /// active list member of it: so far, or for good once the personal
    /// space is fetched whole (`NotOnList`).
    NotListed,
}

/// A device that recovered: its person, and the sealed device keys that
/// now name the person.
pub struct Recovered {
    /// The person ID.
    pub person: [u8; 32],
    /// The personal space.
    pub personal_space: EventId,
    /// The `add` of this device, signed by the list member.
    pub add: EventId,
    /// The other spaces the personal space records recovery entries of,
    /// which the device now follows.
    pub others: Vec<EventId>,
    /// The device's keys, sealed again to name the person: what the
    /// application keeps from now on.
    pub sealed: [u8; SEALED_DEVICE_KEYS_BYTES],
}

impl core::fmt::Debug for Recovered {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Recovered")
            .field("person", &self.person)
            .field("personal_space", &self.personal_space)
            .field("add", &self.add)
            .field("others", &self.others)
            .finish_non_exhaustive()
    }
}

/// The recovery entries a personal space records that count: valid units
/// of its system stream whose entry reads, and whose list member, for the
/// personal space's own entries, is an active passkey member or recovery
/// key of the person's merged list (identity.md, "Fetch keys and recovery
/// entries").
fn entries_of(state: &State, person: &[u8; 32], personal_space: &EventId) -> Vec<RecoveryEntry> {
    let Some(replica) = state.replicas.get(personal_space) else {
        return Vec::new();
    };
    let merged = state.lists.get(person).map(crate::lists::PersonList::merge);
    replica
        .system_contents(RECOVERY_ENTRY)
        .iter()
        .filter_map(|content| RecoveryEntry::read(content, &personal_space.0).ok())
        .filter(|entry| merged.as_ref().is_some_and(|m| m.entry_counts(entry)))
        .collect()
}

impl Engine {
    /// The person's personal space, once this device knows it: it made the
    /// person, recovered into it, or holds the space that records a list
    /// member's recovery entry of itself.
    pub async fn personal_space(&self) -> Option<EventId> {
        self.lock().await.personal_space
    }

    /// Keeps the person's personal space known, and marks its log's
    /// `state` record so that a restart finds it (at-rest.md, "Tables",
    /// `state` key 5).
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn keep_personal_space(
        &self,
        state: &mut State,
        space: EventId,
    ) -> Result<()> {
        state.personal_space = Some(space);
        if !state.vault.has_log(&space.0) {
            return Ok(());
        }
        let mut held = state
            .vault
            .scan(&space.0, Table::State)
            .await?
            .into_iter()
            .find_map(|(_, value)| match value {
                TableValue::State(held) => Some(held),
                _ => None,
            })
            .unwrap_or_default();
        if held.personal {
            return Ok(());
        }
        held.personal = true;
        let mut batch = crate::at_rest::Batch::default();
        state.vault.put(
            &mut batch,
            &space.0,
            Table::State,
            &[],
            &TableValue::State(held),
        )?;
        state.vault.commit(batch).await
    }

    /// Finds the personal space among the spaces this device holds, after
    /// a start: the space whose recovery entries name itself with a list
    /// member (identity.md, "Fetch keys and recovery entries"); failing
    /// that, the one space that grants the person and nobody else but the
    /// person's own devices (identity.md, "The person ID and the personal
    /// space").
    pub(crate) async fn find_personal_space(&self) {
        let mut state = self.lock().await;
        let Some(person) = state.person else {
            return;
        };
        if state.personal_space.is_some() {
            return;
        }
        let merged = state
            .lists
            .get(&person)
            .map(crate::lists::PersonList::merge);
        let mut own = Vec::new();
        let mut alone = Vec::new();
        for (space, replica) in &state.replicas {
            let records = replica
                .system_contents(RECOVERY_ENTRY)
                .iter()
                .filter_map(|content| RecoveryEntry::read(content, &space.0).ok())
                .any(|entry| entry.space == space.0 && matches!(entry.holder, Holder::Member(_)));
            if records {
                own.push(*space);
                continue;
            }
            let roster = replica.roster();
            let grants = roster
                .members_in()
                .any(|(m, _)| m.kind == MemberType::Person && m.id == person);
            let only_person = roster.members_in().all(|(m, _)| match m.kind {
                MemberType::Person => m.id == person,
                MemberType::Device => merged
                    .as_ref()
                    .is_some_and(|merged| merged.member(&DeviceId(m.id)).is_some()),
                _ => false,
            });
            if grants && only_person {
                alone.push(*space);
            }
        }
        state.personal_space = match (own.as_slice(), alone.as_slice()) {
            ([space], _) | ([], [space]) => Some(*space),
            _ => None,
        };
    }

    /// This device's person and personal space.
    async fn own_person(&self) -> Result<([u8; 32], EventId)> {
        let person = self
            .person()
            .await
            .ok_or(Error::NotAllowed("the device is no person's"))?;
        self.find_personal_space().await;
        let personal = self.personal_space().await.ok_or(Error::NotAllowed(
            "the device does not know its personal space",
        ))?;
        Ok((person, personal))
    }

    /// The spaces that grant the person in which this device writes, with
    /// the person's level there.
    async fn spaces_granting(&self, person: &[u8; 32]) -> Vec<(EventId, Level)> {
        let me = self.device_id();
        let state = self.lock().await;
        state
            .replicas
            .iter()
            .filter_map(|(space, replica)| {
                let level = replica.roster().level(&MemberRef::person(*person))?;
                (replica.level_of(&me) >= Some(Level::Write)).then_some((*space, level))
            })
            .collect()
    }

    /// Keeps a list event this device signed, and checks that it is valid.
    async fn keep_own_list_event(&self, person: &[u8; 32], signed: Vec<u8>) -> Result<EventId> {
        let id = frasil_events::decode(&signed).map_err(Error::class)?.id();
        let mut state = self.lock().await;
        self.keep_lists(&mut state, vec![signed]).await?;
        let valid = state
            .lists
            .get(person)
            .is_some_and(|list| list.merge().is_valid(id));
        if valid {
            Ok(id)
        } else {
            Err(Error::Class("NotInList"))
        }
    }

    /// Adds a recovery key to this device's person (identity.md, "Adding
    /// list members", a recovery key): draws the secret, derives the keys,
    /// has them sign their possession proof with this device as adder, and
    /// signs the `add`. Then, as
    /// after any recovery key or passkey member, it publishes the `add` in
    /// each space that grants the person, delivers each such space's
    /// current state to the recovery key, and records the recovery entries
    /// in the personal space ([`Engine::ensure_recovery_entries`]). The
    /// secret is returned once, in its printed form, and forgotten.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of no person, or one that does not
    /// know its personal space; [`Error::NoRandomness`]; the list's
    /// classes; the store's.
    pub async fn add_recovery_key(&self) -> Result<MadeRecoveryKey> {
        let (person, personal_space) = self.own_person().await?;
        let drawn = self.platform().draw::<32>()?;
        let secret = RecoverySecret::from_bytes(&drawn);
        let key = RecoveryKey::derive(&secret);
        let public = key.member().public(Kind::RecoveryKey);
        let proof = key
            .member()
            .prove_possession(&person, &self.device_id(), Kind::RecoveryKey);
        let signed = {
            let state = self.lock().await;
            let list = state
                .lists
                .get(&person)
                .ok_or(Error::NotAllowed("the device holds no list of its person"))?;
            list.sign(
                &ListBody::add(Kind::RecoveryKey, &public, proof),
                self.signer(),
            )
        };
        let add = self.keep_own_list_event(&person, signed).await?;
        self.after_member_added(&person, personal_space, key.member(), key.fetch().public())
            .await?;
        Ok(MadeRecoveryKey {
            person,
            personal_space,
            printed: secret.printed(),
            add,
        })
    }

    /// Adds a passkey member to this device's person (identity.md, "Adding
    /// list members", a passkey member) from two evaluations of the PRF:
    /// a registration's output and one assertion's, or two assertions'.
    /// Then publishes, delivers and records entries as
    /// [`Engine::add_recovery_key`] does.
    ///
    /// # Errors
    ///
    /// `InvalidPrfOutput`, `UnstablePrf`, `AlreadyListed`; as
    /// [`Engine::add_recovery_key`].
    pub async fn add_passkey_member(&self, first: &[u8], second: &[u8]) -> Result<EventId> {
        let (person, personal_space) = self.own_person().await?;
        let signer = self.member_keys();
        let (signed, member) = {
            let state = self.lock().await;
            let list = state
                .lists
                .get(&person)
                .ok_or(Error::NotAllowed("the device holds no list of its person"))?;
            list.whole()
                .ok_or(Error::NotAllowed(
                    "the device holds this list from a checkpoint on",
                ))?
                .add_passkey_member(first, second, &signer)
                .map_err(Error::class)?
        };
        let add = self.keep_own_list_event(&person, signed).await?;
        self.after_member_added(
            &person,
            personal_space,
            member.member(),
            member.fetch().public(),
        )
        .await?;
        Ok(add)
    }

    /// After adding a passkey member or a recovery key (identity.md,
    /// "Adding list members"): publish the `add` where the person is
    /// granted, deliver the current state to the new list member, write its
    /// recovery entry, and record the other spaces' entries.
    async fn after_member_added(
        &self,
        person: &[u8; 32],
        personal_space: EventId,
        member: &MemberKeys,
        fetch: &[u8; 32],
    ) -> Result<()> {
        let keys = DeviceKeys {
            ed: *member.identity(),
            keys: member.signer().keys().clone(),
        };
        for (space, level) in self.spaces_granting(person).await {
            self.publish_list(space, person).await?;
            self.deliver(
                space,
                vec![Recipient {
                    keys: keys.clone(),
                    writes: level >= Level::Write,
                    propagates: true,
                }],
            )
            .await?;
        }
        let entry = RecoveryEntry::for_member(personal_space.0, *fetch, *member.device_id());
        self.write_system(personal_space, RECOVERY_ENTRY, entry.encode())
            .await?;
        self.ensure_recovery_entries().await?;
        Ok(())
    }

    /// Gives each other space that grants the person, where this device
    /// writes, a recovery entry under a fetch key from a fresh seed, kept in
    /// the personal space (identity.md, "Fetch keys and recovery entries"),
    /// so that a recovered device reaches it too. Only while the person
    /// holds an active recovery key or passkey member. Returns the units
    /// written.
    ///
    /// # Errors
    ///
    /// [`Error::NoRandomness`]; as [`Engine::write_system`].
    pub async fn ensure_recovery_entries(&self) -> Result<Vec<EventId>> {
        let (Some(person), Some(personal)) = (self.person().await, self.personal_space().await)
        else {
            return Ok(Vec::new());
        };
        let (has_member, covered) = {
            let state = self.lock().await;
            let entries = entries_of(&state, &person, &personal);
            let has_member = entries
                .iter()
                .any(|entry| matches!(entry.holder, Holder::Member(_)));
            let covered: BTreeSet<[u8; 32]> = entries.iter().map(|entry| entry.space).collect();
            (has_member, covered)
        };
        if !has_member {
            return Ok(Vec::new());
        }
        let mut written = Vec::new();
        for (space, _) in self.spaces_granting(&person).await {
            if space == personal || covered.contains(&space.0) {
                continue;
            }
            let seed = self.platform().draw::<32>()?;
            let entry = RecoveryEntry::for_seed(space.0, &seed);
            written.push(
                self.write_system(personal, RECOVERY_ENTRY, entry.encode())
                    .await?,
            );
        }
        Ok(written)
    }

    /// The recovery entries of this device's person that count: each
    /// space and its fetch key.
    pub async fn recovery_entries(&self) -> Vec<(EventId, [u8; 32])> {
        let (Some(person), Some(personal)) = (self.person().await, self.personal_space().await)
        else {
            return Vec::new();
        };
        let state = self.lock().await;
        entries_of(&state, &person, &personal)
            .into_iter()
            .map(|entry| (EventId(entry.space), entry.key))
            .collect()
    }

    // -- Recovering

    /// Begins a recovery (identity.md, "Recovery"): follows the personal
    /// space, and holds the list member, so that this device's peer
    /// connections present its fetch key there and the device opens the
    /// wraps for it. Returns the personal space.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device that is already a person's.
    pub async fn begin_recovery(&self, member: RecoveryMember) -> Result<EventId> {
        if self.person().await.is_some() {
            return Err(Error::NotAllowed("the device is already a person's"));
        }
        let space = member.personal_space;
        self.follow(space).await;
        self.lock().await.recovering = Some(Recovering {
            member,
            seeds: BTreeMap::new(),
        });
        Ok(space)
    }

    /// The fetch seed a recovering device presents for a space: the list
    /// member's for the personal space, an entry's for another.
    #[cfg_attr(
        not(any(feature = "server", feature = "iroh", feature = "server-socket")),
        allow(dead_code)
    )]
    pub(crate) async fn fetch_seed(&self, space: &EventId) -> Option<Secret> {
        let state = self.lock().await;
        let recovering = state.recovering.as_ref()?;
        if *space == recovering.member.personal_space {
            Some(recovering.member.fetch.clone())
        } else {
            recovering.seeds.get(space).cloned()
        }
    }

    /// Where the recovery stands (identity.md, "Recovery", step 4).
    pub async fn recovery_status(&self) -> RecoveryStatus {
        let state = self.lock().await;
        let Some(recovering) = state.recovering.as_ref() else {
            return RecoveryStatus::NotRecovering;
        };
        let member = &recovering.member;
        let Some(list) = state.lists.get(&member.person) else {
            return RecoveryStatus::Fetching;
        };
        match list.merge().check_on_list(member.kind, &member.public()) {
            Ok(()) => RecoveryStatus::Ready,
            Err(_) => RecoveryStatus::NotListed,
        }
    }

    /// Signs this device in (identity.md, "Recovery", steps 4 to 6): the
    /// list member, active on the merged list, signs the `add` of this
    /// device with the device's possession proof over the person ID, which
    /// names the list member as adder; the
    /// device publishes the new list events in the personal space, and
    /// follows each other space the personal space records a recovery
    /// entry of, whose fetch key its connections then present. Its keys
    /// are sealed again under `unlock_key` to name the person.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device that is not recovering;
    /// `NotOnList`; the list's classes; the store's.
    pub async fn complete_recovery(&self, unlock_key: &[u8; 32]) -> Result<Recovered> {
        let me = self.device_id();
        let (person, personal_space, signed) = {
            let state = self.lock().await;
            let recovering = state
                .recovering
                .as_ref()
                .ok_or(Error::NotAllowed("the device is not recovering"))?;
            let member = &recovering.member;
            let list = state
                .lists
                .get(&member.person)
                .ok_or(Error::Class("NotOnList"))?;
            let merged = list.merge();
            merged
                .check_on_list(member.kind, &member.public())
                .map_err(Error::class)?;
            let signed = merged.active(&me).is_none().then(|| {
                let (keys, proof) = self.list_keys(&member.person, member.member.device_id());
                list.sign(
                    &ListBody::add(Kind::Device, &keys, proof),
                    member.member.signer(),
                )
            });
            (member.person, member.personal_space, signed)
        };
        let add = match signed {
            Some(signed) => self.keep_own_list_event(&person, signed).await?,
            None => {
                let state = self.lock().await;
                state
                    .lists
                    .get(&person)
                    .map(crate::lists::PersonList::merge)
                    .and_then(|m| m.active(&me).map(|member| member.adds[0]))
                    .ok_or(Error::Class("NotInList"))?
            }
        };
        {
            let mut state = self.lock().await;
            state.person = Some(person);
            self.keep_personal_space(&mut state, personal_space).await?;
        }
        self.publish_list(personal_space, &person).await?;
        // The other spaces: each recovery entry of another space gives the
        // fetch seed to present there.
        let others: Vec<(EventId, Secret)> = {
            let state = self.lock().await;
            entries_of(&state, &person, &personal_space)
                .into_iter()
                .filter_map(|entry| match entry.holder {
                    Holder::Seed(seed) => Some((EventId(entry.space), seed)),
                    Holder::Member(_) => None,
                })
                .collect()
        };
        let mut followed = Vec::new();
        for (space, seed) in others {
            self.follow(space).await;
            if let Some(recovering) = self.lock().await.recovering.as_mut() {
                recovering.seeds.insert(space, seed);
            }
            followed.push(space);
        }
        let sealed = self.seal_again(&person, unlock_key)?;
        Ok(Recovered {
            person,
            personal_space,
            add,
            others: followed,
            sealed,
        })
    }

    /// Whether a recovered device reaches a space: it holds the current
    /// state's key and writes there through the person's grant. It then
    /// publishes the list's new events there ([`Engine::publish_list`]).
    pub async fn reaches(&self, space: &EventId) -> bool {
        let me = self.device_id();
        self.read(space, |replica| {
            replica
                .current()
                .is_some_and(|state| replica.state_key(state).is_some())
                && replica.level_of(&me) >= Some(Level::Write)
        })
        .await
        .unwrap_or(false)
    }

    /// Ends a recovery: the device forgets the list member and the fetch
    /// seeds. What it opened with them stays.
    pub async fn end_recovery(&self) {
        self.lock().await.recovering = None;
    }
}
