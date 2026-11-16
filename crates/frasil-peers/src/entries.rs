//! A peer's entries and recovery entries for one space (peers.md,
//! "Entries", "Learning a rotation's credentials", "Merge statements",
//! "Retirement and the cap", "Presenting a credential", "Credentials
//! requests"), and the store right ("Storing an event", step 2).
//!
//! [`Entries`] changes in the order the peer meets each operation. The log
//! the operations read is the space's log as the peer holds it; an entry's
//! rotations are events of it. The peer's first sights are counted in one
//! sequence, of entries, recovery entries and the requests it carries out.

use crate::PeersClass;
use crate::body::{EntryName, StorageBody};
use crate::limits::{CREDENTIAL_CAP, MAX_RECOVERY_ENTRIES, MERGE_PER_STATE};
use crate::merge::MergeStatement;
use crate::proof::{Credential, Purpose, presented, verify};
use crate::{Code, PeersClass as C};
use frasil_base::ErrorClass;
use frasil_crypto::device::{DeviceId, IdentityKey};
use frasil_crypto::keys::ed25519_valid;
use frasil_crypto::schemes::ed25519_verify_strict;
use frasil_events::{Event, EventId, ForkPoints, Log, kind};
use frasil_keys::RotationSet;
use frasil_keys::body::VisiblePart;

/// What the entries read of the space's log: whether one event is in
/// another's past. A [`Log`] answers it.
pub trait Ancestry {
    /// Whether `earlier` is in the past of `later`.
    fn precedes(&self, earlier: EventId, later: EventId) -> bool;
}

impl Ancestry for Log {
    fn precedes(&self, earlier: EventId, later: EventId) -> bool {
        Log::precedes(self, earlier, later)
    }
}

/// An entry's or a recovery entry's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntryStatus {
    /// Live.
    Live,
    /// Retired: its read credential still grants catch-up.
    Retired,
}

/// Where an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// A stored space event that rotates.
    Rotation,
    /// A merge statement.
    Merge,
    /// A rotation of an imported log, added retired until its importer
    /// presents its upload key.
    Import,
}

impl Source {
    /// The source's name, as the vectors write it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Rotation => "rotation",
            Self::Merge => "merge",
            Self::Import => "import",
        }
    }
}

/// An entry: a state, its read credential's and upload key's public halves,
/// and its status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// One rotation, or a merged state of 2 to 64.
    pub state: RotationSet,
    /// The Ed25519 public key of `read_seed(state)`.
    pub read: [u8; 32],
    /// The Ed25519 public key of `upload_seed(state)`.
    pub upload: [u8; 32],
    /// Live or retired.
    pub status: EntryStatus,
    /// Rotation, merge or import.
    pub source: Source,
    /// The peer's first sight of the entry, in its sequence of sights.
    pub seen: u64,
    /// Whether a successful present has proved it.
    pub proved: bool,
}

impl Entry {
    /// The entry's name, `[encode_set(state), read]`.
    pub fn name(&self) -> EntryName {
        EntryName {
            state: self.state.clone(),
            read: self.read,
        }
    }

    /// Whether the entry is live.
    pub fn is_live(&self) -> bool {
        self.status == EntryStatus::Live
    }

    /// The rotation of an entry of one rotation.
    fn rotation(&self) -> EventId {
        self.state.ids()[0]
    }
}

/// A recovery entry: a fetch key and its status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryEntry {
    /// The fetch key, an Ed25519 public key.
    pub key: [u8; 32],
    /// Live or retired.
    pub status: EntryStatus,
    /// The peer's first sight of the registration.
    pub seen: u64,
}

/// The rights a connection's presents for a space were granted (peers.md,
/// "Presenting a credential").
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Rights {
    /// Fetch: every stored event and object of the space.
    pub fetch: bool,
    /// Live delivery.
    pub live: bool,
    /// Catch-up only: the space's events of kinds 2 and 6, parents by ID,
    /// and the system stream's units.
    pub catch_up: bool,
    /// Store events and objects, present merge statements, learn the live
    /// entries.
    pub store: bool,
    /// Store writer requests.
    pub release: bool,
    /// Erase: the pseudonym's skeleton events and acknowledgements, on its
    /// administration connection.
    pub erase: bool,
}

impl Rights {
    /// A live read credential's: fetch and live delivery.
    pub const FETCH_AND_LIVE: Self = Self {
        fetch: true,
        live: true,
        catch_up: false,
        store: false,
        release: false,
        erase: false,
    };
    /// A retired read credential's, or a live fetch key's: catch-up.
    pub const CATCH_UP: Self = Self {
        fetch: false,
        live: false,
        catch_up: true,
        store: false,
        release: false,
        erase: false,
    };
    /// A live upload key's: store and release.
    pub const STORE_AND_RELEASE: Self = Self {
        fetch: false,
        live: false,
        catch_up: false,
        store: true,
        release: true,
        erase: false,
    };
    /// An administrator pseudonym's: erase.
    pub const ERASE: Self = Self {
        fetch: false,
        live: false,
        catch_up: false,
        store: false,
        release: false,
        erase: true,
    };

    /// Both sets of rights.
    pub fn union(self, other: Self) -> Self {
        Self {
            fetch: self.fetch || other.fetch,
            live: self.live || other.live,
            catch_up: self.catch_up || other.catch_up,
            store: self.store || other.store,
            release: self.release || other.release,
            erase: self.erase || other.erase,
        }
    }

    /// The names of the rights held, as the vectors write them, in order.
    pub fn names(self) -> Vec<&'static str> {
        [
            (self.catch_up, "catch-up"),
            (self.erase, "erase"),
            (self.fetch, "fetch"),
            (self.live, "live"),
            (self.release, "release"),
            (self.store, "store"),
        ]
        .into_iter()
        .filter_map(|(held, name)| held.then_some(name))
        .collect()
    }
}

/// A connection, as a present or a store sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connection {
    /// transport.md's `binding` of the connection.
    pub binding: [u8; 32],
    /// The connection's purpose.
    pub purpose: Purpose,
    /// Whether it is the import in progress for the space (peers.md,
    /// "Hosting a space").
    pub importing: bool,
}

/// A present (transport.md's `Present`), as the peer reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Present<'p> {
    /// The credential's code, 1 to 4.
    pub credential: u64,
    /// The space.
    pub space: EventId,
    /// The credential's public half: for credential 3, the pseudonym's
    /// device ID.
    pub public: [u8; 32],
    /// The proof.
    pub proof: &'p [u8],
}

/// Why a present or a registration is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// A class, answered with its code.
    Class(PeersClass),
    /// A code with no class of peers.md's: `erased`, `no_library`, or
    /// `credential_refused` for a registration without the store right.
    Code(Code),
    /// transport.md's `purpose_violation`: a credential the connection's
    /// purpose does not allow.
    PurposeViolation,
}

impl Refusal {
    /// The code a peer answers with, as transport.md carries it.
    pub fn code_name(self) -> Option<&'static str> {
        match self {
            Self::Class(class) => class.code().map(Code::name),
            Self::Code(code) => Some(code.name()),
            Self::PurposeViolation => Some("purpose_violation"),
        }
    }
}

impl From<PeersClass> for Refusal {
    fn from(class: PeersClass) -> Self {
        Self::Class(class)
    }
}

impl From<ErrorClass> for Refusal {
    fn from(class: ErrorClass) -> Self {
        Self::Class(class.into())
    }
}

/// A peer's entries and recovery entries for one space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entries {
    entries: Vec<Entry>,
    recovery: Vec<RecoveryEntry>,
    cap: usize,
    sight: u64,
    reports: Vec<PeersClass>,
    erased: bool,
}

impl Default for Entries {
    fn default() -> Self {
        Self::new(CREDENTIAL_CAP)
    }
}

impl Entries {
    /// No entries, under a `credential_cap` of `cap` live entries.
    pub fn new(cap: usize) -> Self {
        Self {
            entries: Vec::new(),
            recovery: Vec::new(),
            cap,
            sight: 0,
            reports: Vec::new(),
            erased: false,
        }
    }

    /// The entries, in the order the peer added them.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The live entries.
    pub fn live(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter().filter(|e| e.is_live())
    }

    /// The recovery entries, in the order the peer added them.
    pub fn recovery(&self) -> &[RecoveryEntry] {
        &self.recovery
    }

    /// The classes the peer recorded in its own log: `KeyStateFull`.
    pub fn reports(&self) -> &[PeersClass] {
        &self.reports
    }

    /// The `credential_cap`.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Marks the space erased: every later present answers `erased`, and
    /// its recovery entries go.
    pub fn erase(&mut self) {
        self.erased = true;
        self.recovery.clear();
    }

    /// The peer's next first sight, in its sequence of sights.
    pub fn first_sight(&mut self) -> u64 {
        self.sight += 1;
        self.sight
    }

    /// The entry of this name, if the peer holds it.
    pub fn find(&self, name: &EntryName) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|e| e.state == name.state && e.read == name.read)
    }

    // -- Adding and retiring

    /// Whether no other stored rotation's entry has this rotation in its
    /// past.
    fn maximal<A: Ancestry + ?Sized>(&self, log: &A, rotation: EventId) -> bool {
        !self
            .entries
            .iter()
            .filter(|e| e.source != Source::Merge)
            .any(|e| log.precedes(rotation, e.rotation()))
    }

    /// Adds an entry, under `merge_per_state` and the cap (peers.md,
    /// "Retirement and the cap").
    fn add<A: Ancestry + ?Sized>(&mut self, log: &A, mut entry: Entry) {
        entry.seen = self.first_sight();
        entry.proved = false;
        if entry.is_live() && entry.source == Source::Merge {
            let same: Vec<usize> = (0..self.entries.len())
                .filter(|&i| {
                    let e = &self.entries[i];
                    e.is_live() && e.source == Source::Merge && e.state == entry.state
                })
                .collect();
            if same.len() >= MERGE_PER_STATE {
                let oldest = self.oldest(&same);
                self.retire_at(oldest);
            }
        }
        if entry.is_live() && self.live().count() >= self.cap {
            let merges: Vec<usize> = (0..self.entries.len())
                .filter(|&i| {
                    let e = &self.entries[i];
                    e.is_live() && e.source == Source::Merge && !e.proved
                })
                .collect();
            let superseded: Vec<usize> = (0..self.entries.len())
                .filter(|&i| {
                    let e = &self.entries[i];
                    e.is_live() && e.source != Source::Merge && !self.maximal(log, e.rotation())
                })
                .collect();
            let candidates = if merges.is_empty() {
                superseded
            } else {
                merges
            };
            match candidates.into_iter().min_by_key(|&i| self.entries[i].seen) {
                Some(i) => self.retire_at(i),
                None => {
                    entry.status = EntryStatus::Retired;
                    self.reports.push(PeersClass::KeyStateFull);
                }
            }
        }
        self.entries.push(entry);
    }

    /// Of these entries, the oldest never proved by a successful present,
    /// or, if all were proved, the oldest.
    fn oldest(&self, of: &[usize]) -> usize {
        let unproved: Vec<usize> = of
            .iter()
            .copied()
            .filter(|&i| !self.entries[i].proved)
            .collect();
        let pool = if unproved.is_empty() {
            of.to_vec()
        } else {
            unproved
        };
        pool.into_iter()
            .min_by_key(|&i| self.entries[i].seen)
            .expect("a state's merge entries")
    }

    /// Retires an entry and, for a rotation's entry, every merge entry that
    /// rests on it.
    fn retire_at(&mut self, index: usize) {
        self.entries[index].status = EntryStatus::Retired;
        if self.entries[index].source != Source::Merge {
            let rotation = self.entries[index].rotation();
            for e in &mut self.entries {
                if e.source == Source::Merge && e.state.contains(&rotation) {
                    e.status = EntryStatus::Retired;
                }
            }
        }
    }

    /// Retires the entry of this name, and the merge entries that rest on
    /// it. Returns whether the peer holds it.
    pub fn retire(&mut self, name: &EntryName) -> bool {
        match self
            .entries
            .iter()
            .position(|e| e.state == name.state && e.read == name.read)
        {
            Some(index) => {
                self.retire_at(index);
                true
            }
            None => false,
        }
    }

    /// peers.md, "Learning a rotation's credentials": a stored rotation
    /// adds the entry `({R}, key 11, key 12)`, live, source `rotation`; or,
    /// from an import, retired, source `import`. A rotation by an author
    /// that forked at or before it adds a retired entry.
    pub fn add_rotation_keys<A: Ancestry + ?Sized>(
        &mut self,
        log: &A,
        rotation: EventId,
        read: [u8; 32],
        upload: [u8; 32],
        source: Source,
        forked: bool,
    ) {
        let live = source == Source::Rotation && !forked;
        self.add(
            log,
            Entry {
                state: RotationSet::single(rotation),
                read,
                upload,
                status: if live {
                    EntryStatus::Live
                } else {
                    EntryStatus::Retired
                },
                source,
                seen: 0,
                proved: false,
            },
        );
    }

    /// A stored space event: if its visible part rotates, its entry
    /// ([`add_rotation_keys`](Self::add_rotation_keys)), with `forks` the
    /// peer's evidence of forks. A space event that does not rotate adds
    /// nothing. Returns whether it added an entry.
    ///
    /// # Errors
    ///
    /// `Malformed` if the event is not a placed space event; the visible
    /// part's classes (keys.md, "Checking a space event's body").
    pub fn add_rotation(
        &mut self,
        log: &Log,
        rotation: EventId,
        source: Source,
        forks: &ForkPoints,
    ) -> Result<bool, PeersClass> {
        let event = log
            .event(rotation)
            .filter(|e| e.kind() == kind::SPACE)
            .ok_or(C::Shared(ErrorClass::Malformed))?;
        // A peer checks only an event's Ed25519 half (peers.md, 3.2 Storing
        // an event), and reads a rotation's keys from it as stored.
        let visible = VisiblePart::read(event.unverified_body(), event.author(), event.seq())?;
        let Some(keys) = visible.rotation() else {
            return Ok(false);
        };
        let forked = forks.is_void(event);
        self.add_rotation_keys(log, rotation, keys.read, keys.upload, source, forked);
        Ok(true)
    }

    /// peers.md, "Merge statements", in order, on a connection that proved
    /// a live upload entry: the statement reads (steps 1 and 2) and is for
    /// this space; every rotation of the state is a stored rotation of this
    /// space whose entry is live, and none is in another's past (step 3);
    /// each signature verifies strictly under its rotation's upload key
    /// (step 4); then the live entry, source merge (step 5).
    ///
    /// # Errors
    ///
    /// `Malformed`, `UnsupportedVersion`, `InvalidKey`, `UnknownState` or
    /// `BadSignature`.
    pub fn merge<A: Ancestry + ?Sized>(
        &mut self,
        log: &A,
        space: &EventId,
        statement: &[u8],
    ) -> Result<(), PeersClass> {
        let statement = MergeStatement::read(statement)?;
        if statement.space != *space {
            return Err(ErrorClass::Malformed.into());
        }
        let mut uploads = Vec::with_capacity(statement.state.len());
        for &rotation in statement.state.ids() {
            let single = RotationSet::single(rotation);
            match self.entries.iter().find(|e| e.state == single) {
                Some(entry) if entry.is_live() => uploads.push(entry.upload),
                _ => return Err(C::UnknownState),
            }
        }
        let ids = statement.state.ids();
        if ids
            .iter()
            .any(|&a| ids.iter().any(|&b| a != b && log.precedes(a, b)))
        {
            return Err(C::UnknownState);
        }
        let message = statement.message();
        if !uploads
            .iter()
            .zip(&statement.signatures)
            .all(|(upload, signature)| ed25519_verify_strict(upload, &message, signature))
        {
            return Err(ErrorClass::BadSignature.into());
        }
        self.add(
            log,
            Entry {
                state: statement.state,
                read: statement.read,
                upload: statement.upload,
                status: EntryStatus::Live,
                source: Source::Merge,
                seen: 0,
                proved: false,
            },
        );
        Ok(())
    }

    /// peers.md, "Learning a rotation's credentials", a fork: every entry of
    /// a rotation by an author at or after its fork point retires, with the
    /// merge entries that rest on it.
    pub fn fork(&mut self, log: &Log, forks: &ForkPoints) {
        for index in 0..self.entries.len() {
            let entry = &self.entries[index];
            if entry.source == Source::Merge {
                continue;
            }
            if log
                .event(entry.rotation())
                .is_some_and(|event| forks.is_void(event))
            {
                self.retire_at(index);
            }
        }
    }

    // -- Credentials requests

    /// A credentials request carried out (peers.md, "Credentials
    /// requests"). With `live` (key 3), every named entry the peer holds
    /// becomes live, and every other live entry whose state's rotations are
    /// all in the request's past retires; without it, no entry changes.
    /// With `keep` (key 4), every named recovery entry becomes live, and
    /// every other one the peer added before `seen`, its first sight of the
    /// request, retires; without it, no recovery entry changes.
    pub fn execute<A: Ancestry + ?Sized>(
        &mut self,
        log: &A,
        request: EventId,
        live: Option<&[EntryName]>,
        keep: Option<&[[u8; 32]]>,
        seen: Option<u64>,
    ) {
        if let Some(names) = live {
            let named = |e: &Entry| names.iter().any(|n| n.state == e.state && n.read == e.read);
            for e in &mut self.entries {
                if named(e) {
                    e.status = EntryStatus::Live;
                }
            }
            for index in 0..self.entries.len() {
                let e = &self.entries[index];
                if !named(e)
                    && e.is_live()
                    && e.state.ids().iter().all(|&r| log.precedes(r, request))
                {
                    self.retire_at(index);
                }
            }
        }
        if let Some(keep) = keep {
            for e in &mut self.recovery {
                if keep.contains(&e.key) {
                    e.status = EntryStatus::Live;
                } else if seen.is_none_or(|seen| e.seen < seen) {
                    e.status = EntryStatus::Retired;
                }
            }
        }
    }

    /// A credentials request's event carried out, from its body
    /// ([`execute`](Self::execute)).
    ///
    /// # Errors
    ///
    /// The body's classes, or `Malformed` if it is not a credentials
    /// request.
    pub fn execute_event<A: Ancestry + ?Sized>(
        &mut self,
        log: &A,
        request: &Event,
        seen: Option<u64>,
    ) -> Result<(), PeersClass> {
        match StorageBody::read(request.unverified_body())? {
            StorageBody::Credentials { live, recovery } => {
                self.execute(
                    log,
                    request.id(),
                    live.as_deref(),
                    recovery.as_deref(),
                    seen,
                );
                Ok(())
            }
            _ => Err(ErrorClass::Malformed.into()),
        }
    }

    // -- Recovery entries

    /// Registers a fetch key (peers.md, "Presenting a credential", recovery
    /// entries), on a connection that holds `rights` in the space. A key the
    /// space holds already, live or retired, is accepted and changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// `credential_refused` without the store right; `InvalidKey`;
    /// `RecoveryEntriesFull` past 64 live recovery entries.
    pub fn register(&mut self, key: &[u8; 32], rights: Rights) -> Result<(), Refusal> {
        if !rights.store {
            return Err(Refusal::Code(Code::CredentialRefused));
        }
        ed25519_valid(key)?;
        if self.recovery.iter().any(|e| e.key == *key) {
            return Ok(());
        }
        let live = self
            .recovery
            .iter()
            .filter(|e| e.status == EntryStatus::Live)
            .count();
        if live >= MAX_RECOVERY_ENTRIES {
            return Err(C::RecoveryEntriesFull.into());
        }
        let seen = self.first_sight();
        self.recovery.push(RecoveryEntry {
            key: *key,
            status: EntryStatus::Live,
            seen,
        });
        Ok(())
    }

    // -- Presenting a credential

    /// Checks a present, in order (peers.md, "Presenting a credential"):
    ///
    /// ```text
    /// 1. credential is 1 to 4, and the connection's purpose allows it.     else Malformed / purpose_violation
    /// 2. The space is hosted here and not erased.                          else erased
    /// 3. public is, for 1, the read key of an entry of the space; for 2,
    ///    the upload key of one; for 3, the device ID of a pseudonym of the
    ///    space; for 4, the key of a recovery entry of the space.           else UnknownCredential
    /// 4. The proof verifies strictly under public, or for 3 under the
    ///    pseudonym's Ed25519 key, over this connection's presented.        else BadProof
    /// 5. For 2: the entry is live, or it is a retired import entry and
    ///    this connection is the import in progress. For 4: the recovery
    ///    entry is live.                                                    else RetiredCredential
    /// ```
    ///
    /// Of the entries whose key is `public`, steps 3 to 5 take a live one
    /// first.
    ///
    /// `pseudonym` is, for credential 3, the Ed25519 key of the pseudonym
    /// whose device ID `public` is: the `ed` of the envelope of the root or
    /// enrolment the peer accepted for it, or of the enrolment that is the
    /// first event this connection stores; `None` when `public` names no
    /// such pseudonym. Whether the peer hosts the space
    /// is the caller's. A success marks the entry proved, makes a retired
    /// import entry live for its importer, and returns the rights granted.
    ///
    /// # Errors
    ///
    /// The step's refusal.
    pub fn present(
        &mut self,
        present: &Present<'_>,
        connection: &Connection,
        pseudonym: Option<&IdentityKey>,
    ) -> Result<Rights, Refusal> {
        // 1.
        let credential = Credential::from_code(present.credential).ok_or(ErrorClass::Malformed)?;
        if !connection.purpose.allows(credential) {
            return Err(Refusal::PurposeViolation);
        }
        // 2.
        if self.erased {
            return Err(Refusal::Code(Code::Erased));
        }
        // 3.
        let public = present.public;
        let entry = self.lookup(credential, &public, connection.importing);
        let recovery = match credential {
            Credential::Fetch => self.recovery.iter().position(|e| e.key == public),
            _ => None,
        };
        let known = match credential {
            Credential::Read | Credential::Upload => entry.is_some(),
            Credential::Pseudonym => pseudonym.is_some(),
            Credential::Fetch => recovery.is_some(),
        };
        if !known {
            return Err(C::UnknownCredential.into());
        }
        // 4.
        let presented = presented(
            &connection.binding,
            present.space.as_bytes(),
            credential.code(),
            &public,
        );
        let key = match (credential, pseudonym) {
            (Credential::Pseudonym, Some(ed)) => ed.0,
            _ => public,
        };
        if !verify(&key, &presented, present.proof) {
            return Err(C::BadProof.into());
        }
        // 5.
        match credential {
            Credential::Read => {
                let e = &mut self.entries[entry.expect("found")];
                e.proved = true;
                Ok(if e.is_live() {
                    Rights::FETCH_AND_LIVE
                } else {
                    Rights::CATCH_UP
                })
            }
            Credential::Upload => {
                let e = &mut self.entries[entry.expect("found")];
                if !e.is_live() {
                    if connection.importing && e.source == Source::Import {
                        e.status = EntryStatus::Live;
                    } else {
                        return Err(C::RetiredCredential.into());
                    }
                }
                e.proved = true;
                Ok(Rights::STORE_AND_RELEASE)
            }
            Credential::Pseudonym => Ok(Rights::ERASE),
            Credential::Fetch => {
                if self.recovery[recovery.expect("found")].status == EntryStatus::Live {
                    Ok(Rights::CATCH_UP)
                } else {
                    Err(C::RetiredCredential.into())
                }
            }
        }
    }

    /// The entry a present of credential 1 or 2 names (peers.md, 3.7
    /// Presenting a credential, steps 3 to 5): of the entries whose key is
    /// `public`, a live one; failing that, for an upload key on the import
    /// in progress, a retired import entry; otherwise the first the peer
    /// added. A retired entry that carries a live one's keys never shadows
    /// it.
    fn lookup(&self, credential: Credential, public: &[u8; 32], importing: bool) -> Option<usize> {
        let matches = |e: &Entry| match credential {
            Credential::Read => e.read == *public,
            Credential::Upload => e.upload == *public,
            _ => false,
        };
        let entries = &self.entries;
        entries
            .iter()
            .position(|e| matches(e) && e.is_live())
            .or_else(|| {
                (importing && credential == Credential::Upload)
                    .then(|| {
                        entries
                            .iter()
                            .position(|e| matches(e) && e.source == Source::Import)
                    })
                    .flatten()
            })
            .or_else(|| entries.iter().position(matches))
    }

    /// What a present of `credential` and `public`, whose proof verified on
    /// a connection, grants now (peers.md, 2.2 The credential proof: a
    /// proof holds while its entry is live; 3.6 Retirement and the cap,
    /// "Connections"): what [`present`](Self::present) would grant it, read
    /// without changing anything. A read credential whose every entry
    /// retired grants catch-up; an upload key or a fetch key whose entry
    /// retired grants nothing; a pseudonym grants erase; an erased space
    /// grants nothing.
    pub fn standing(&self, credential: Credential, public: &[u8; 32]) -> Rights {
        if self.erased {
            return Rights::default();
        }
        match credential {
            Credential::Read => match self.lookup(credential, public, false) {
                Some(i) if self.entries[i].is_live() => Rights::FETCH_AND_LIVE,
                Some(_) => Rights::CATCH_UP,
                None => Rights::default(),
            },
            Credential::Upload => match self.lookup(credential, public, false) {
                Some(i) if self.entries[i].is_live() => Rights::STORE_AND_RELEASE,
                _ => Rights::default(),
            },
            Credential::Pseudonym => Rights::ERASE,
            Credential::Fetch => {
                if self
                    .recovery
                    .iter()
                    .any(|e| e.key == *public && e.status == EntryStatus::Live)
                {
                    Rights::CATCH_UP
                } else {
                    Rights::default()
                }
            }
        }
    }
}

/// A connection, as the store right sees it (peers.md, "Storing an event",
/// step 2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Storer {
    /// The rights the connection's presents for the space were granted.
    pub rights: Rights,
    /// Whether the connection creates the space and has stored nothing of
    /// it.
    pub creating: bool,
    /// Whether it is the import in progress.
    pub importing: bool,
    /// The administrator pseudonym, by device ID, its administration
    /// present proved.
    pub pseudonym: Option<DeviceId>,
}

/// peers.md, "Storing an event", step 2: the connection may store in this
/// space when it holds the store right; or it creates the space and the
/// event is the genesis, or imports it; or it holds the erase right and the
/// event is its pseudonym's skeleton event.
///
/// # Errors
///
/// `NotAuthorized`, answered `not_authorized`; the body's class for a
/// storage event of its pseudonym's whose body does not read.
pub fn may_store(event: &Event, storer: &Storer) -> Result<(), PeersClass> {
    if storer.rights.store || storer.importing {
        return Ok(());
    }
    if storer.creating {
        return if event.is_genesis() {
            Ok(())
        } else {
            Err(C::NotAuthorized)
        };
    }
    if storer.rights.erase
        && event.kind() == kind::STORAGE
        && storer.pseudonym.as_ref() == Some(event.author())
        && match StorageBody::read(event.unverified_body()) {
            Ok(body) => body.storage_type().is_skeleton(),
            Err(class) if class.shared() == Some(ErrorClass::ExtensionRequired) => true,
            Err(class) => return Err(class),
        }
    {
        return Ok(());
    }
    Err(C::NotAuthorized)
}

/// The entries at rest, for the peer's own records: so that a peer reopens a
/// space without replaying what made them.
///
/// ```text
/// state    = [1, cap, sight, erased, [* entry], [* recovery], [* report]]
/// entry    = [encode_set(state), read, upload, status, source, seen, proved]
/// recovery = [key, status, seen]
/// ```
///
/// in deterministic CBOR, positional, version first: `status` is 0 live or
/// 1 retired; `source` 0 rotation, 1 merge, 2 import; `erased` and `proved`
/// 0 or 1; a report is a class's wire name. Entries and recovery entries
/// keep the order the peer added them in.
impl Entries {
    /// The version [`Entries::encode_state`] writes.
    pub const STATE_VERSION: u64 = 1;

    /// The entries' state at rest.
    pub fn encode_state(&self) -> Vec<u8> {
        use frasil_base::cbor;
        use frasil_base::errors::Class;
        let status = |status: EntryStatus| match status {
            EntryStatus::Live => 0,
            EntryStatus::Retired => 1,
        };
        let mut out = Vec::with_capacity(160 * self.entries.len() + 64);
        cbor::array_head(&mut out, 7);
        cbor::unsigned(&mut out, Self::STATE_VERSION);
        cbor::unsigned(&mut out, self.cap as u64);
        cbor::unsigned(&mut out, self.sight);
        cbor::unsigned(&mut out, u64::from(self.erased));
        cbor::array_head(&mut out, self.entries.len());
        for entry in &self.entries {
            cbor::array_head(&mut out, 7);
            cbor::bytes(&mut out, &entry.state.encode());
            cbor::bytes(&mut out, &entry.read);
            cbor::bytes(&mut out, &entry.upload);
            cbor::unsigned(&mut out, status(entry.status));
            cbor::unsigned(
                &mut out,
                match entry.source {
                    Source::Rotation => 0,
                    Source::Merge => 1,
                    Source::Import => 2,
                },
            );
            cbor::unsigned(&mut out, entry.seen);
            cbor::unsigned(&mut out, u64::from(entry.proved));
        }
        cbor::array_head(&mut out, self.recovery.len());
        for recovery in &self.recovery {
            cbor::array_head(&mut out, 3);
            cbor::bytes(&mut out, &recovery.key);
            cbor::unsigned(&mut out, status(recovery.status));
            cbor::unsigned(&mut out, recovery.seen);
        }
        cbor::array_head(&mut out, self.reports.len());
        for report in &self.reports {
            cbor::text(&mut out, report.wire_name());
        }
        out
    }

    /// Entries from their state at rest, if `bytes` are one state of this
    /// version in its one encoding.
    pub fn decode_state(bytes: &[u8]) -> Option<Self> {
        use frasil_base::cbor::Reader;
        let mut reader = Reader::new(bytes);
        let flag = |reader: &mut Reader<'_>| match reader.unsigned().ok()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        };
        let status = |reader: &mut Reader<'_>| match reader.unsigned().ok()? {
            0 => Some(EntryStatus::Live),
            1 => Some(EntryStatus::Retired),
            _ => None,
        };
        if reader.array_len().ok()? != 7 || reader.unsigned().ok()? != Self::STATE_VERSION {
            return None;
        }
        let cap = usize::try_from(reader.unsigned().ok()?).ok()?;
        let sight = reader.unsigned().ok()?;
        let erased = flag(&mut reader)?;
        let count = reader.array_len().ok()?;
        let mut entries = Vec::with_capacity(count.min(1 << 12));
        for _ in 0..count {
            if reader.array_len().ok()? != 7 {
                return None;
            }
            let state = RotationSet::decode(reader.bytes().ok()?).ok()?;
            let read = reader.byte_array::<32>().ok()?;
            let upload = reader.byte_array::<32>().ok()?;
            let status = status(&mut reader)?;
            let source = match reader.unsigned().ok()? {
                0 => Source::Rotation,
                1 => Source::Merge,
                2 => Source::Import,
                _ => return None,
            };
            let seen = reader.unsigned().ok()?;
            let proved = flag(&mut reader)?;
            entries.push(Entry {
                state,
                read,
                upload,
                status,
                source,
                seen,
                proved,
            });
        }
        let count = reader.array_len().ok()?;
        let mut recovery = Vec::with_capacity(count.min(1 << 12));
        for _ in 0..count {
            if reader.array_len().ok()? != 3 {
                return None;
            }
            recovery.push(RecoveryEntry {
                key: reader.byte_array::<32>().ok()?,
                status: status(&mut reader)?,
                seen: reader.unsigned().ok()?,
            });
        }
        let count = reader.array_len().ok()?;
        let mut reports = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            reports.push(PeersClass::from_wire_name(reader.text().ok()?)?);
        }
        reader.finish().ok()?;
        Some(Self {
            entries,
            recovery,
            cap,
            sight,
            reports,
            erased,
        })
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;

    #[test]
    fn entries_read_back_from_their_state() {
        let mut entries = Entries::new(32);
        entries.sight = 9;
        entries.entries.push(Entry {
            state: RotationSet::single(EventId([3; 32])),
            read: [1; 32],
            upload: [2; 32],
            status: EntryStatus::Retired,
            source: Source::Import,
            seen: 4,
            proved: true,
        });
        entries.recovery.push(RecoveryEntry {
            key: [5; 32],
            status: EntryStatus::Live,
            seen: 7,
        });
        entries.reports.push(PeersClass::NotAuthorized);
        let state = entries.encode_state();
        assert_eq!(Entries::decode_state(&state), Some(entries));
        assert!(Entries::decode_state(&state[1..]).is_none());
    }
}
