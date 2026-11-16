//! Space files through the client (ext-space-files.md): a space exported
//! to a file, appended to as the application saves, and imported on
//! another device by one of the roads in.
//!
//! The file is generic to every Frasil implementation. What an application
//! expects to find in the space is its [`SpaceFileFormat`]: a kind string
//! the manifest names, which a `SpaceFile<F>` checks before it reads an
//! event, and how the format opens the space's streams, which it does
//! for a member, a claimant and a reader alike.

use super::{Device, Space, SpaceId, StreamId};
use crate::error::{Error, Result};
use crate::space_file::{Embed, ExportOptions, Road, WayInOption};
#[cfg(feature = "ext-invite-links")]
use frasil_events::EventId;
use frasil_space::Level;
use frasil_space_file::file::{self, Read, Sniffed};
use frasil_space_file::record::{History, Manifest, Section};
use frasil_store::store::MaybeSend;
use std::future::Future;
use std::marker::PhantomData;
use std::time::Duration;
use zeroize::Zeroizing;

/// What an application's space holds, and how to open it.
pub trait SpaceFileFormat: Send + Sync + 'static {
    /// The kind string the space's files name, such as `example.drawing`: 1 to
    /// 64 bytes without white space.
    const KIND: &'static str;

    /// The application's handle on an opened space: its streams, typed.
    type Opened;

    /// Finds the format's streams in the space; `WrongKind` when they are
    /// not there. Works for a member, a claimant and a reader alike.
    fn open(space: Space) -> impl Future<Output = Result<Self::Opened>> + MaybeSend;
}

/// Which objects an export embeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Objects {
    /// Every blob the device holds whose stored bytes fit, in locator
    /// order, within this many bytes in all. The default is 32 MiB.
    UpTo(u64),
    /// Every object the device holds.
    All,
    /// None: the objects are fetched later, from members, a peer, or the
    /// application's own object provider.
    None,
}

/// One part of the way in an export writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WayIn {
    /// The rotation secrets of every state the file's units name: whoever
    /// holds the file reads the space as this device could at export, for
    /// as long as the file exists.
    Keys,
    /// A fresh invite this device grants, whose fragment admits one
    /// claimant with nobody online, at `level` (`read` or `write`), for
    /// `lifetime`, 15 minutes to 7 days.
    Invite {
        /// The level.
        level: Level,
        /// The lifetime.
        lifetime: Duration,
    },
}

/// What an export writes: `Export { ..Export::default() }` with what the
/// application changes.
#[derive(Debug, Clone)]
pub struct Export {
    /// Full history (the default), or from a space snapshot at this
    /// device's heads.
    pub history: History,
    /// The streams whose units the file holds; `None` (the default) for
    /// every stream.
    pub streams: Option<Vec<StreamId>>,
    /// Which objects to embed.
    pub objects: Objects,
    /// The way in: by default the keys, so that a copy opens anywhere.
    pub way_in: Vec<WayIn>,
    /// The file key the way in is sealed under; `None` (the default) for
    /// the clear. How the application derives it, from a passphrase
    /// through a memory-hard derivation or from a keychain item, is its
    /// own; a key kept beside the file protects nothing.
    pub seal: Option<Zeroizing<[u8; 32]>>,
    /// The application's sections: opaque bytes under its kind string, for
    /// what is not in the space.
    pub sections: Vec<Section>,
}

impl Default for Export {
    fn default() -> Self {
        Self {
            history: History::Full,
            streams: None,
            objects: Objects::UpTo(32 * 1024 * 1024),
            way_in: vec![WayIn::Keys],
            seal: None,
            sections: Vec::new(),
        }
    }
}

/// How a file was opened.
pub enum Opened<F: SpaceFileFormat> {
    /// This device held the space as a member already: the file was
    /// merged in.
    Member(F::Opened),
    /// This device held the space by keys alone already, as a reader: the
    /// file was merged in, and it still has no grant.
    Rereading(F::Opened),
    /// A fragment in the file admits this device, and the claim waits for
    /// the person's consent: show what [`Invited::invitation`] says, then
    /// [`Invited::accept`] or [`Invited::decline`].
    #[cfg(feature = "ext-invite-links")]
    Invited(Invited<F>),
    /// This device holds the space by the file's keys, with no grant: it
    /// reads everything, and writes fail `NotAMember`. Continuing the
    /// work elsewhere is a fork, which the application makes with a new
    /// space.
    Reading(F::Opened),
}

impl<F: SpaceFileFormat> Opened<F> {
    /// The format's handle, on a road that opened the space; `None` for an
    /// invitation that waits for consent.
    pub fn into_inner(self) -> Option<F::Opened> {
        match self {
            Self::Member(opened) | Self::Rereading(opened) | Self::Reading(opened) => Some(opened),
            #[cfg(feature = "ext-invite-links")]
            Self::Invited(_) => None,
        }
    }

    /// The format's handle, on a road that opened the space; `None` for an
    /// invitation that waits for consent.
    pub fn inner(&self) -> Option<&F::Opened> {
        match self {
            Self::Member(opened) | Self::Rereading(opened) | Self::Reading(opened) => Some(opened),
            #[cfg(feature = "ext-invite-links")]
            Self::Invited(_) => None,
        }
    }

    /// The road in.
    pub fn road(&self) -> Road {
        match self {
            Self::Member(_) => Road::Member,
            Self::Rereading(_) => Road::Rereading,
            #[cfg(feature = "ext-invite-links")]
            Self::Invited(invited) => invited.invitation.road(),
            Self::Reading(_) => Road::Reading,
        }
    }
}

impl<F: SpaceFileFormat> core::fmt::Debug for Opened<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Opened::{:?}", self.road())
    }
}

/// An invite a file carries for this device, prepared and checked, waiting
/// for the person's consent before the device signs itself in
/// (ext-space-files.md, "Import", step 5; "The claim from a file", step
/// 4). Show the inviter, the level and the label, then [`accept`](Self::accept)
/// or [`decline`](Self::decline). Dropped undecided, the claim waits in
/// the device: [`Device::spaces`] does not list the space, no peer is
/// told of it, importing the file again offers it again, and a device
/// stopped meanwhile forgets it when it next opens
/// (ext-invite-links.md, "Records at rest"). An `accept` that fails
/// leaves the invitation in hand, to decline.
#[cfg(feature = "ext-invite-links")]
#[derive(Clone)]
pub struct Invitation {
    device: Device,
    space: EventId,
    offer: crate::invite_links::ClaimOffer,
    label: Option<String>,
    placed: usize,
}

#[cfg(feature = "ext-invite-links")]
impl core::fmt::Debug for Invitation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Invitation")
            .field("space", &self.space)
            .field("level", &self.offer.level)
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "ext-invite-links")]
impl Invitation {
    /// The space the file carries.
    pub fn space(&self) -> SpaceId {
        SpaceId::of(self.space)
    }

    /// The inviting device, by its device ID: the invite entry's author.
    pub fn inviter(&self) -> super::MemberId {
        super::MemberId::device(self.offer.inviter)
    }

    /// The level the claim gives, `read` or `write`.
    pub fn level(&self) -> Level {
        self.offer.level
    }

    /// When the invite expires, as seconds since 1970-01-01T00:00:00Z.
    pub fn expires_at(&self) -> u64 {
        self.offer.expires_at
    }

    /// The way in's label, if the exporter wrote one: what the file is for.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// The road, as the engine reports it.
    pub fn road(&self) -> Road {
        Road::Invited {
            offer: self.offer.clone(),
            label: self.label.clone(),
        }
    }

    /// How many events the file carried that the device placed anew.
    pub fn placed(&self) -> usize {
        self.placed
    }

    /// The person consents: the device signs the successor and is a member
    /// from now on; its successor reaches the others when it next meets a
    /// member or a peer.
    ///
    /// # Errors
    ///
    /// A claim's classes, should the invite have been spent meanwhile; the
    /// store's.
    pub async fn accept(&self) -> Result<Space> {
        self.device.engine().claim(self.space).await?;
        self.device.present(self.space);
        Ok(Space::new(self.device.clone(), SpaceId::of(self.space)))
    }

    /// The person declines: the claim is dropped, and nothing of the file
    /// is kept.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn decline(&self) -> Result<()> {
        self.device.engine().abandon_claim(&self.space).await
    }
}

/// An [`Invitation`] under an application's format: accepting it opens
/// the space as the format does.
#[cfg(feature = "ext-invite-links")]
pub struct Invited<F: SpaceFileFormat> {
    invitation: Invitation,
    format: PhantomData<fn() -> F>,
}

#[cfg(feature = "ext-invite-links")]
impl<F: SpaceFileFormat> core::fmt::Debug for Invited<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.invitation.fmt(f)
    }
}

#[cfg(feature = "ext-invite-links")]
impl<F: SpaceFileFormat> Invited<F> {
    /// What the person is shown.
    pub fn invitation(&self) -> &Invitation {
        &self.invitation
    }

    /// [`Invitation::accept`], then the format opens the space.
    ///
    /// # Errors
    ///
    /// As [`Invitation::accept`]; the format's.
    pub async fn accept(&self) -> Result<F::Opened> {
        F::open(self.invitation.accept().await?).await
    }

    /// [`Invitation::decline`].
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn decline(&self) -> Result<()> {
        self.invitation.decline().await
    }
}

/// A space file of an application's format: the bytes of a file exported
/// from a space, or read from a path, with its manifest and sections.
pub struct SpaceFile<F: SpaceFileFormat> {
    bytes: Vec<u8>,
    read: Read,
    format: PhantomData<fn() -> F>,
}

impl<F: SpaceFileFormat> core::fmt::Debug for SpaceFile<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpaceFile")
            .field("kind", &F::KIND)
            .field("space", &self.read.manifest.space)
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

fn refused(refusal: file::Refusal) -> Error {
    match refusal {
        // A file of another revision (ext-space-files.md, "The
        // manifest").
        file::Refusal::Class(frasil_base::ErrorClass::RevisionMismatch) => Error::IncompatibleData,
        file::Refusal::Class(class) => Error::class(class),
        file::Refusal::NotASpaceFile => Error::Class("NotASpaceFile"),
    }
}

/// Reads a whole file.
#[cfg(not(target_arch = "wasm32"))]
fn read_path(path: &std::path::Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(|error| Error::Store(format!("{}: {error}", path.display())))
}

/// How old a file aside must be, by its modification time, for a writer
/// of the same path to take it as left by a writer that stopped and
/// remove it. A writer still writing touches its file aside as it goes.
#[cfg(not(target_arch = "wasm32"))]
const STALE_PARTIAL: Duration = Duration::from_secs(60 * 60);

/// Writes a file aside, then renames it over `path`: a crash leaves the
/// old file or the whole new one. The file aside is synced to the disk
/// before the rename, and its directory after, as far as the platform
/// allows, so that a power loss after the rename does not leave a short
/// file. Its name is the writer's own, `<name>.<pid>-<n>.partial`, so two
/// writers of one path never stage in one place; what writers that
/// stopped left aside ([`STALE_PARTIAL`] old, `<name>.partial` included)
/// is removed first. The staging file is made new, never opened where
/// something, a link included, already is; on Unix it takes the
/// permissions of the file it replaces.
#[cfg(not(target_arch = "wasm32"))]
fn write_path(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    static WRITES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let failed = |error: std::io::Error| Error::Store(format!("{}: {error}", path.display()));
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    remove_stale_partials(&dir, &name);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if let Ok(replaced) = std::fs::symlink_metadata(path)
        && replaced.is_file()
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(replaced.permissions().mode() & 0o777);
    }
    // A name some other process took is passed over, a few times.
    let (partial, mut file) = {
        let mut tries = 0;
        loop {
            let n = WRITES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let partial = path.with_file_name(format!("{name}.{}-{n}.partial", std::process::id()));
            match options.open(&partial) {
                Ok(file) => break (partial, file),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && tries < 16 => {
                    tries += 1;
                }
                Err(error) => return Err(failed(error)),
            }
        }
    };
    let written = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&partial, path)
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&partial);
        return Err(failed(error));
    }
    sync_dir(&dir).map_err(failed)
}

/// Syncs a directory, so that a rename in it reaches the disk. Where the
/// platform does not open or sync a directory, the rename is left to it.
#[cfg(not(target_arch = "wasm32"))]
fn sync_dir(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        match std::fs::File::open(dir).and_then(|dir| dir.sync_all()) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Unsupported | std::io::ErrorKind::InvalidInput
                ) =>
            {
                Ok(())
            }
            result => result,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// Removes the files aside that writers of `name` in `dir` left behind:
/// `<name>.<anything>.partial` and `<name>.partial`, untouched for
/// [`STALE_PARTIAL`]. A file that does not read or remove is left.
#[cfg(not(target_arch = "wasm32"))]
fn remove_stale_partials(dir: &std::path::Path, name: &str) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();
        let aside = file_name.ends_with(".partial")
            && file_name
                .strip_prefix(name)
                .is_some_and(|rest| rest.starts_with('.'));
        if !aside {
            continue;
        }
        let stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= STALE_PARTIAL);
        if stale {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

impl<F: SpaceFileFormat> SpaceFile<F> {
    /// A file from its bytes, checked as far as its records go: the kind
    /// must be `F::KIND`.
    ///
    /// # Errors
    ///
    /// `NotASpaceFile`, `UnsupportedVersion`, `Malformed`, `TooLarge`;
    /// `WrongKind`.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let read = file::read(&bytes).map_err(refused)?;
        if read.manifest.kind != F::KIND {
            return Err(Error::Class("WrongKind"));
        }
        Ok(Self {
            bytes,
            read,
            format: PhantomData,
        })
    }

    /// Reads a file at a path.
    ///
    /// # Errors
    ///
    /// [`Error::Store`] when the path does not read; as
    /// [`SpaceFile::from_bytes`].
    #[cfg(not(target_arch = "wasm32"))]
    pub fn read(path: &std::path::Path) -> Result<Self> {
        Self::from_bytes(read_path(path)?)
    }

    /// Sniffs a file: its magic, the way in's presence and whether it is
    /// sealed, and its first manifest, with no event read and nothing
    /// opened. It refuses a file of another kind as `WrongKind`.
    ///
    /// # Errors
    ///
    /// [`Error::Store`] when the path does not read; the file's classes;
    /// `WrongKind`.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn sniff(path: &std::path::Path) -> Result<Sniffed> {
        Self::sniff_bytes(&read_path(path)?)
    }

    /// [`SpaceFile::sniff`] on a file's bytes, which need not be whole:
    /// the magic and the first segment suffice.
    ///
    /// # Errors
    ///
    /// The file's classes; `WrongKind`.
    pub fn sniff_bytes(bytes: &[u8]) -> Result<Sniffed> {
        let sniffed = dynamic::sniff(bytes)?;
        if sniffed.manifest.kind != F::KIND {
            return Err(Error::Class("WrongKind"));
        }
        Ok(sniffed)
    }

    /// Exports a space (ext-space-files.md, "Export"), under `F::KIND`.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] when this device holds no current state of
    /// the space, which a snapshot or an invite needs; [`Error::Invalid`]
    /// for an invite at `administer` or beyond 7 days;
    /// [`Error::Unsupported`] for an invite without `ext-invite-links`;
    /// `TooLarge` for a section over a record's limit; the store's.
    pub async fn export(space: &Space, options: Export) -> Result<Self> {
        Self::from_bytes(dynamic::export(space, F::KIND, options).await?)
    }

    /// Writes the file at a path, atomically: a file aside, synced, then a
    /// rename, and the directory synced. Two writers of one path stage
    /// apart; what a writer that stopped left aside is removed once it is
    /// an hour old.
    ///
    /// # Errors
    ///
    /// [`Error::Store`] when the path does not write.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn write(&self, path: &std::path::Path) -> Result<()> {
        write_path(path, &self.bytes)
    }

    /// Appends what the device holds of the space since the file's last
    /// manifest to the file at a path (ext-space-files.md, "Append"), and
    /// writes it back atomically. The file must have been exported from
    /// this space, under `F::KIND`.
    ///
    /// # Errors
    ///
    /// [`Error::Store`] when the path does not read or write; the file's
    /// classes; `WrongKind`; `OtherSpace`.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn append(space: &Space, path: &std::path::Path) -> Result<()> {
        let grown = Self::append_bytes(space, &read_path(path)?).await?;
        write_path(path, &grown.bytes)
    }

    /// [`SpaceFile::append`] on a file's bytes: the file, grown.
    ///
    /// # Errors
    ///
    /// The file's classes; `WrongKind`; `OtherSpace`.
    pub async fn append_bytes(space: &Space, bytes: &[u8]) -> Result<Self> {
        Self::sniff_bytes(bytes)?;
        Self::from_bytes(dynamic::append(space, bytes).await?)
    }

    /// Imports the file at a path (ext-space-files.md, "Import"): the road
    /// in, with the format's handle on the space. `key` opens a sealed way
    /// in.
    ///
    /// # Errors
    ///
    /// [`Error::Store`] when the path does not read; the file's classes;
    /// `WrongKind`; `Sealed` for a sealed way in without a key, `Decrypt`
    /// with the wrong one; the last fragment's refusal when none claims
    /// and the file carries no keys; a reader's first refusal, or
    /// `Pending` for a head the file does not reach; `NoWayIn`; the
    /// format's.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn import(
        device: &Device,
        path: &std::path::Path,
        key: Option<&[u8; 32]>,
    ) -> Result<Opened<F>> {
        Self::import_bytes(device, &read_path(path)?, key).await
    }

    /// [`SpaceFile::import`] on a file's bytes.
    ///
    /// # Errors
    ///
    /// As [`SpaceFile::import`].
    pub async fn import_bytes(
        device: &Device,
        bytes: &[u8],
        key: Option<&[u8; 32]>,
    ) -> Result<Opened<F>> {
        match dynamic::import(device, &[F::KIND], bytes, key).await? {
            dynamic::Import::Opened { road, space } => {
                let opened = F::open(space).await?;
                Ok(match road {
                    Road::Rereading => Opened::Rereading(opened),
                    Road::Reading => Opened::Reading(opened),
                    _ => Opened::Member(opened),
                })
            }
            #[cfg(feature = "ext-invite-links")]
            dynamic::Import::Invited(invitation) => Ok(Opened::Invited(Invited {
                invitation,
                format: PhantomData,
            })),
        }
    }

    /// The file's bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The file's bytes, taken.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// The last manifest: what the file holds.
    pub fn manifest(&self) -> &Manifest {
        &self.read.manifest
    }

    /// The application's sections, the later of two of one kind and name
    /// winning.
    pub fn sections(&self) -> &[Section] {
        &self.read.sections
    }

    /// Whether a tail after the last manifest, from an append that did
    /// not finish, was ignored.
    pub fn was_truncated(&self) -> bool {
        self.read.truncated
    }
}

/// Space files for a caller that chooses the kind at run time, such as the
/// browser package: no [`SpaceFileFormat`], bytes in and out, and the road
/// in with the space. Every check of [`SpaceFile`] but the kind's runs
/// here too.
pub mod dynamic {
    use super::{
        Device, Embed, Export, ExportOptions, Objects, Result, Road, Space, SpaceId, WayIn,
        WayInOption, file, refused,
    };
    use frasil_space_file::file::Sniffed;

    /// Sniffs a file's bytes, which need not be whole: the magic, the way
    /// in's presence and whether it is sealed, and the first manifest,
    /// with no event read and nothing opened.
    ///
    /// # Errors
    ///
    /// The file's classes.
    pub fn sniff(bytes: &[u8]) -> Result<Sniffed> {
        file::sniff(bytes).map_err(refused)
    }

    /// Exports a space (ext-space-files.md, "Export") under `kind`: the
    /// file's bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`](crate::Error::Invalid) for a kind that is not 1
    /// to 64 bytes without white space; otherwise as
    /// [`SpaceFile::export`](super::SpaceFile::export).
    pub async fn export(space: &Space, kind: &str, options: Export) -> Result<Vec<u8>> {
        let way_in = options
            .way_in
            .into_iter()
            .map(|way| match way {
                WayIn::Keys => WayInOption::Keys,
                WayIn::Invite { level, lifetime } => WayInOption::Invite {
                    level,
                    lifetime: lifetime.as_secs(),
                },
            })
            .collect();
        space
            .device()
            .engine()
            .export_space_file(
                space.id().event(),
                ExportOptions {
                    kind: kind.to_owned(),
                    history: options.history,
                    streams: options
                        .streams
                        .map(|s| s.iter().map(|id| *id.as_bytes()).collect()),
                    objects: match options.objects {
                        Objects::UpTo(bytes) => Embed::UpTo(bytes),
                        Objects::All => Embed::All,
                        Objects::None => Embed::None,
                    },
                    way_in,
                    seal: options.seal,
                    sections: options.sections,
                },
            )
            .await
    }

    /// Appends what the device holds of the space since the file's last
    /// manifest (ext-space-files.md, "Append"): the file's bytes, grown.
    /// The file must have been exported from this space, under any kind.
    ///
    /// # Errors
    ///
    /// The file's classes; `OtherSpace`.
    pub async fn append(space: &Space, bytes: &[u8]) -> Result<Vec<u8>> {
        space
            .device()
            .engine()
            .append_space_file(space.id().event(), bytes)
            .await
    }

    /// What an import did: the space, opened by a road in, or an
    /// invitation that waits for the person's consent.
    #[derive(Debug)]
    pub enum Import {
        /// The space is held: as a member, as a reader again, or as a
        /// reader by the file's keys.
        Opened {
            /// The road in.
            road: Road,
            /// The space.
            space: Space,
        },
        /// A fragment in the file admits this device, on consent.
        #[cfg(feature = "ext-invite-links")]
        Invited(super::Invitation),
    }

    /// Imports a file's bytes (ext-space-files.md, "Import") whose kind is
    /// one of `kinds`: the road in with the space, or an invitation. `key`
    /// opens a sealed way in.
    ///
    /// # Errors
    ///
    /// As [`SpaceFile::import`](super::SpaceFile::import).
    pub async fn import(
        device: &Device,
        kinds: &[&str],
        bytes: &[u8],
        key: Option<&[u8; 32]>,
    ) -> Result<Import> {
        let imported = device.engine().import_space_file(bytes, kinds, key).await?;
        match imported.road {
            #[cfg(feature = "ext-invite-links")]
            Road::Invited { offer, label } => Ok(Import::Invited(super::Invitation {
                device: device.clone(),
                space: imported.space,
                offer,
                label,
                placed: imported.placed,
            })),
            road => {
                device.present(imported.space);
                let space = Space::new(device.clone(), SpaceId::of(imported.space));
                Ok(Import::Opened { road, space })
            }
        }
    }
}
