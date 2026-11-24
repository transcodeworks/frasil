//! Space files through the client (ext-space-files.md): a space exported
//! with each way in and imported on another device by the matching road;
//! a sealed way in with the wrong key; a tampered event refused; an append
//! then an import; and an export without objects whose blob is fetched
//! later through the application's object provider.
#![cfg(all(
    feature = "space-files",
    feature = "adapter-loro",
    feature = "adapter-blobs",
    feature = "ext-invite-links",
    feature = "iroh"
))]

#[path = "support/provider.rs"]
mod provider;

use frasil::advanced::ManualClock;
use frasil::advanced::held::ObjectPolicy;
use frasil::space_files::{Export, History, Objects, Opened, WayIn};
use frasil::{
    Blobs, Device, Document, Error, Level, Options, Space, SpaceFile, SpaceFileFormat, Storage,
    StreamKind,
};
use frasil_space_file::record::{Record, WayIn as WayInRecord};
use provider::{DirProvider, temp_dir};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEADLINE: Duration = Duration::from_secs(60);

async fn within<T>(future: impl Future<Output = T>) -> T {
    tokio::time::timeout(DEADLINE, future)
        .await
        .expect("within the deadline")
}

async fn until<F, Fut>(mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    within(async {
        while !check().await {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
}

async fn device(key: u8, options: Options) -> Device {
    Device::open_with(
        Storage::Memory,
        &[key; 32],
        options.loopback().never_restored(),
    )
    .await
    .expect("a device")
}

/// The application's format: one note and one blob stream.
struct Notes;

/// What the format opens.
struct Opened_ {
    space: Space,
    note: Document,
    files: Blobs,
}

impl SpaceFileFormat for Notes {
    const KIND: &'static str = "example.notes";
    type Opened = Opened_;

    async fn open(space: Space) -> frasil::Result<Opened_> {
        let streams = space.streams().await?;
        let note = streams
            .iter()
            .find(|s| s.kind == StreamKind::Document)
            .ok_or(Error::Class("WrongKind"))?;
        let files = streams
            .iter()
            .find(|s| s.kind == StreamKind::Blobs)
            .ok_or(Error::Class("WrongKind"))?;
        Ok(Opened_ {
            note: space.document(note.id).await?,
            files: space.blobs(files.id).await?,
            space,
        })
    }
}

/// Alice's space with a note and a blob.
async fn alices_space(alice: &Device) -> (Space, Document, Blobs, frasil::BlobId) {
    let space = alice.create_space().await.unwrap();
    let note = space.create_document().unwrap();
    note.edit(|doc| doc.get_text("body").insert(0, "hello"))
        .await
        .unwrap();
    let files = space.create_blobs().unwrap();
    let blob = files.put(Some("photo"), &[7u8; 70_000]).await.unwrap();
    (space, note, files, blob)
}

async fn text(note: &Document) -> String {
    note.read().await.unwrap().get_text("body").to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_with_keys_opens_anywhere_as_a_reader() {
    let alice = device(11, Options::new()).await;
    let (space, _, _, blob) = alices_space(&alice).await;
    let file = SpaceFile::<Notes>::export(&space, Export::default())
        .await
        .unwrap();
    assert_eq!(file.manifest().kind, "example.notes");
    assert_eq!(file.manifest().history, History::Full);
    assert_eq!(file.manifest().objects.len(), 1, "the blob is embedded");
    let sniffed = SpaceFile::<Notes>::sniff_bytes(file.bytes()).unwrap();
    assert_eq!(sniffed.way_in, Some(false), "a way in, in the clear");

    // Bob reads it by its keys: everything, and writes nothing.
    let bob = device(12, Options::new()).await;
    let opened = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap();
    let Opened::Reading(bobs) = opened else {
        panic!("a reader by keys");
    };
    assert_eq!(text(&bobs.note).await, "hello");
    assert_eq!(bobs.space.level().await, None);
    assert_eq!(
        bobs.files
            .get(blob, &frasil::Read::new())
            .await
            .unwrap()
            .as_deref(),
        Some(&[7u8; 70_000][..]),
        "the embedded blob"
    );
    let refused = bobs
        .note
        .edit(|doc| doc.get_text("body").insert(0, "x"))
        .await;
    assert!(refused.is_err(), "a reader writes nothing");

    // Another format refuses the file before reading an event.
    struct Other;
    impl SpaceFileFormat for Other {
        const KIND: &'static str = "example.other";
        type Opened = ();
        async fn open(_: Space) -> frasil::Result<()> {
            Ok(())
        }
    }
    let carol = device(13, Options::new()).await;
    assert_eq!(
        SpaceFile::<Other>::import_bytes(&carol, file.bytes(), None)
            .await
            .unwrap_err(),
        Error::Class("WrongKind")
    );
    assert!(carol.spaces().await.is_empty());

    // Alice imports her own file: a member, nothing new.
    let again = SpaceFile::<Notes>::import_bytes(&alice, file.bytes(), None)
        .await
        .unwrap();
    assert!(matches!(again, Opened::Member(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_with_an_invite_admits_a_claimant_who_writes() {
    let alice = device(21, Options::new()).await;
    let (space, note, _, _) = alices_space(&alice).await;
    let file = SpaceFile::<Notes>::export(
        &space,
        Export {
            way_in: vec![WayIn::Invite {
                level: Level::Write,
                lifetime: Duration::from_secs(3600),
            }],
            ..Export::default()
        },
    )
    .await
    .unwrap();
    let bob = device(22, Options::new()).await;
    let opened = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap();
    let Opened::Invited(invited) = opened else {
        panic!("an invitation: {opened:?}");
    };
    assert_eq!(invited.invitation().level(), Level::Write);
    assert_eq!(invited.invitation().inviter(), alice.id());
    assert_eq!(invited.invitation().space(), space.id());
    let bobs = invited.accept().await.unwrap();
    assert_eq!(text(&bobs.note).await, "hello");
    assert_eq!(bobs.space.level().await, Some(Level::Write));
    bobs.note
        .edit(|doc| doc.get_text("body").insert(5, ", bob"))
        .await
        .unwrap();
    // Bob's file carries his successor and his edit back to Alice, who is
    // a member already: she merges it.
    let bobs_file = SpaceFile::<Notes>::export(&bobs.space, Export::default())
        .await
        .unwrap();
    let merged = SpaceFile::<Notes>::import_bytes(&alice, bobs_file.bytes(), None)
        .await
        .unwrap();
    assert!(matches!(merged, Opened::Member(_)));
    until(|| async { text(&note).await == "hello, bob" }).await;
    let members = space.members().await.unwrap();
    assert!(
        members
            .iter()
            .any(|m| m.id == bob.id() && m.level == Level::Write),
        "{members:?}"
    );

    // One fragment, one admission: a file exported once the claim is in
    // carries the used invite, and Carol is refused. (Two devices that
    // claim from the same file before either claim is seen race, and both
    // claims are void until an administrator closes one, as
    // ext-invite-links.md says.)
    let used = SpaceFile::<Notes>::export(
        &space,
        Export {
            way_in: vec![WayIn::Keys],
            ..Export::default()
        },
    )
    .await
    .unwrap();
    let carol = device(23, Options::new()).await;
    let opened = SpaceFile::<Notes>::import_bytes(&carol, used.bytes(), None)
        .await
        .unwrap();
    assert!(matches!(opened, Opened::Reading(_)), "keys only: a reader");
    let dan = device(24, Options::new()).await;
    let refused = SpaceFile::<Notes>::import_bytes(&dan, file.bytes(), None).await;
    let _ = refused;
    let invite_used = {
        // The original file's fragment, against the space as Alice holds
        // it now: Dan reads the used invite in a file that carries both.
        let mut carrying = frasil_space_file::file::read(file.bytes()).unwrap();
        let newer = frasil_space_file::file::read(used.bytes()).unwrap();
        carrying.events = newer.events;
        let mut writer = frasil_space_file::file::Writer::new();
        if let Some(way_in) = &carrying.way_in {
            writer
                .record(&Record::WayIn(match way_in {
                    WayInRecord::Clear(body) => WayInRecord::Clear(body.clone()),
                    WayInRecord::Sealed(body) => WayInRecord::Sealed(body.clone()),
                }))
                .unwrap();
        }
        for signed in &carrying.events {
            writer.record(&Record::Event(signed.clone())).unwrap();
        }
        let mut manifest = newer.manifest.clone();
        manifest.objects = Vec::new();
        writer.record(&Record::Manifest(manifest)).unwrap();
        writer.finish()
    };
    let erin = device(25, Options::new()).await;
    assert_eq!(
        SpaceFile::<Notes>::import_bytes(&erin, &invite_used, None)
            .await
            .unwrap_err(),
        Error::Class("InviteUsed")
    );
    assert!(erin.spaces().await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sealed_way_in_needs_its_key() {
    let alice = device(31, Options::new()).await;
    let (space, _, _, _) = alices_space(&alice).await;
    let key = [0x5a; 32];
    let file = SpaceFile::<Notes>::export(
        &space,
        Export {
            seal: Some(zeroize::Zeroizing::new(key)),
            ..Export::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(
        SpaceFile::<Notes>::sniff_bytes(file.bytes())
            .unwrap()
            .way_in,
        Some(true)
    );
    let bob = device(32, Options::new()).await;
    assert_eq!(
        SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
            .await
            .unwrap_err(),
        Error::Class("Sealed")
    );
    assert_eq!(
        SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), Some(&[1; 32]))
            .await
            .unwrap_err(),
        Error::Class("Decrypt")
    );
    assert!(bob.spaces().await.is_empty(), "nothing kept");
    let opened = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), Some(&key))
        .await
        .unwrap();
    assert!(matches!(opened, Opened::Reading(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_tampered_event_is_refused_and_nothing_is_kept() {
    let alice = device(41, Options::new()).await;
    let (space, _, _, _) = alices_space(&alice).await;
    let file = SpaceFile::<Notes>::export(
        &space,
        Export {
            objects: Objects::None,
            ..Export::default()
        },
    )
    .await
    .unwrap();
    // The same file with one byte of its last event changed: the event's
    // signature fails, so the frame does not check through to the heads.
    let read = frasil_space_file::file::read(file.bytes()).unwrap();
    let mut writer = frasil_space_file::file::Writer::new();
    if let Some(way_in) = &read.way_in {
        writer
            .record(&Record::WayIn(match way_in {
                WayInRecord::Clear(body) => WayInRecord::Clear(body.clone()),
                WayInRecord::Sealed(body) => WayInRecord::Sealed(body.clone()),
            }))
            .unwrap();
    }
    let last = read.events.len() - 1;
    for (index, signed) in read.events.iter().enumerate() {
        let mut signed = signed.clone();
        if index == last {
            let middle = signed.len() / 2;
            signed[middle] ^= 0x01;
        }
        writer.record(&Record::Event(signed)).unwrap();
    }
    writer
        .record(&Record::Manifest(read.manifest.clone()))
        .unwrap();
    let tampered = writer.finish();
    let bob = device(42, Options::new()).await;
    let refused = SpaceFile::<Notes>::import_bytes(&bob, &tampered, None).await;
    assert!(refused.is_err(), "{refused:?}");
    assert!(bob.spaces().await.is_empty(), "a reader keeps nothing");
    // The untouched file still opens.
    let opened = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap();
    assert!(matches!(opened, Opened::Reading(_)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_append_carries_what_came_after_and_a_truncated_tail_is_ignored() {
    let dir = temp_dir("space-file-append");
    let path = dir.join("notes.frasil");
    let alice = device(51, Options::new()).await;
    let (space, note, _, _) = alices_space(&alice).await;
    let file = SpaceFile::<Notes>::export(&space, Export::default())
        .await
        .unwrap();
    file.write(&path).await.unwrap();
    let exported = std::fs::read(&path).unwrap();
    note.edit(|doc| doc.get_text("body").insert(5, " again"))
        .await
        .unwrap();
    SpaceFile::<Notes>::append(&space, &path).await.unwrap();
    let appended = std::fs::read(&path).unwrap();
    assert!(
        appended.starts_with(&exported),
        "an append rewrites nothing"
    );
    let grown = SpaceFile::<Notes>::read(&path).unwrap();
    assert!(!grown.was_truncated());
    assert_ne!(grown.manifest().heads, file.manifest().heads);

    // Bob reads the appended file: both edits.
    let bob = device(52, Options::new()).await;
    let opened = SpaceFile::<Notes>::import(&bob, &path, None).await.unwrap();
    let Opened::Reading(bobs) = opened else {
        panic!("a reader");
    };
    assert_eq!(text(&bobs.note).await, "hello again");

    // A tail cut short is the file as the first manifest described it.
    let cut = &appended[..exported.len() + 7];
    let read = SpaceFile::<Notes>::from_bytes(cut.to_vec()).unwrap();
    assert!(read.was_truncated());
    assert_eq!(read.manifest().heads, file.manifest().heads);
    let carol = device(53, Options::new()).await;
    let Opened::Reading(carols) = SpaceFile::<Notes>::import_bytes(&carol, cut, None)
        .await
        .unwrap()
    else {
        panic!("a reader");
    };
    assert_eq!(text(&carols.note).await, "hello");
    // Another space's file cannot be appended to this space.
    let other = alice.create_space().await.unwrap();
    assert_eq!(
        SpaceFile::<Notes>::append(&other, &path).await.unwrap_err(),
        Error::Class("OtherSpace")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_without_objects_fetches_them_later_into_the_provider() {
    let dir = temp_dir("space-file-objects");
    let alice = device(61, Options::new().local_discovery()).await;
    let (space, _, _, blob) = alices_space(&alice).await;
    let file = SpaceFile::<Notes>::export(
        &space,
        Export {
            objects: Objects::None,
            way_in: vec![WayIn::Invite {
                level: Level::Read,
                lifetime: Duration::from_secs(3600),
            }],
            ..Export::default()
        },
    )
    .await
    .unwrap();
    assert!(file.manifest().objects.is_empty());

    // Bob holds his blobs through a provider, fetches one only when he
    // asks, so that his own request and its hint name the file, and claims
    // the file's invite.
    let provider = DirProvider::new(dir.join("bob"));
    let bob = device(
        62,
        Options::new()
            .local_discovery()
            .object_provider(provider.clone()),
    )
    .await;
    let Opened::Invited(invited) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("an invitation");
    };
    let bobs = invited.accept().await.unwrap();
    assert_eq!(bobs.space.object_policy().await, ObjectPolicy::Held);
    assert_eq!(
        bobs.files.get(blob, &frasil::Read::new()).await.unwrap(),
        None,
        "not embedded"
    );
    assert_eq!(
        std::fs::read_dir(provider.dir.as_path()).unwrap().count(),
        0
    );

    // Alice learns of Bob's claim from his file, so both count each other
    // as members.
    let bobs_file = SpaceFile::<Notes>::export(
        &bobs.space,
        Export {
            objects: Objects::None,
            ..Export::default()
        },
    )
    .await
    .unwrap();
    // The file's invite placed no drop at any peer: nothing is deleted
    // once it is spent, so a peer without ext-invite-links, which closes
    // the connection on `MailboxDelete`, is sent none.
    let made = alice.engine().made_invites().await;
    assert_eq!(made.len(), 1, "{made:?}");
    let (invite_space, entry) = made[0];
    assert_eq!(&invite_space.0, space.id().as_bytes());
    assert_eq!(
        alice.engine().drops_of(&entry).await.as_deref(),
        Some(&[][..])
    );
    assert!(alice.engine().spent_invites().await.is_empty());
    assert!(matches!(
        SpaceFile::<Notes>::import_bytes(&alice, bobs_file.bytes(), None)
            .await
            .unwrap(),
        Opened::Member(_)
    ));
    // Bob's claim spends it. A spent invite with no drop is forgotten at
    // Alice's next upkeep, which may come at once: the invite is listed as
    // spent, with no drop, or already let go, which only a spent invite's
    // upkeep does here.
    within(async {
        loop {
            let spent = alice.engine().spent_invites().await;
            if let Some(invite) = spent.iter().find(|s| s.entry == entry) {
                assert_eq!(spent.len(), 1, "{spent:?}");
                assert_eq!(invite.kept_at.as_deref(), Some(&[][..]));
                break;
            }
            if !alice.engine().made_invites().await.contains(&made[0]) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;

    // Once the two members find each other on the local network, Bob
    // materialises the blob: Alice serves it, and Bob's provider gets the
    // file.
    let token = within(async {
        loop {
            match bobs.files.materialise(blob, b"photo.bin").await {
                Ok(token) => break token,
                Err(_) => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    })
    .await;
    assert_eq!(token, b"photo.bin");
    assert_eq!(provider.read(&token), vec![7u8; 70_000]);
    assert_eq!(
        bobs.files
            .get(blob, &frasil::Read::new())
            .await
            .unwrap()
            .as_deref(),
        Some(&[7u8; 70_000][..])
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invitation_declined_keeps_nothing() {
    let alice = device(71, Options::new()).await;
    let (space, _, _, _) = alices_space(&alice).await;
    let file = SpaceFile::<Notes>::export(
        &space,
        Export {
            objects: Objects::None,
            way_in: vec![WayIn::Invite {
                level: Level::Read,
                lifetime: Duration::from_secs(900),
            }],
            ..Export::default()
        },
    )
    .await
    .unwrap();
    let bob = device(72, Options::new()).await;
    let Opened::Invited(invited) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("an invitation");
    };
    assert_eq!(invited.invitation().level(), Level::Read);
    assert!(
        bob.spaces().await.is_empty(),
        "nothing listed while undecided"
    );
    invited.decline().await.unwrap();
    assert!(bob.spaces().await.is_empty());
    // The invite is still open: a second import offers it again.
    assert!(matches!(
        SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
            .await
            .unwrap(),
        Opened::Invited(_)
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_embedded_object_goes_to_the_provider_under_the_held_policy() {
    let dir = temp_dir("space-file-held");
    let alice = device(73, Options::new()).await;
    let (space, _, _, blob) = alices_space(&alice).await;
    let file = SpaceFile::<Notes>::export(&space, Export::default())
        .await
        .unwrap();
    assert_eq!(file.manifest().objects.len(), 1, "the blob is embedded");

    // Bob holds his blobs through a provider: the embedded object's parts
    // are partitioned there, not into the sealed store.
    let provider = DirProvider::new(dir.join("bob"));
    let bob = device(74, Options::new().object_provider(provider.clone())).await;
    let Opened::Reading(bobs) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("a reader by keys");
    };
    assert_eq!(bobs.space.object_policy().await, ObjectPolicy::Held);
    assert_eq!(
        bobs.files
            .get(blob, &frasil::Read::new())
            .await
            .unwrap()
            .as_deref(),
        Some(&[7u8; 70_000][..])
    );
    assert_eq!(
        std::fs::read_dir(provider.dir.as_path()).unwrap().count(),
        1,
        "one held file"
    );
    // Held: the provider's copy is the blob's plaintext.
    let held = std::fs::read_dir(provider.dir.as_path())
        .unwrap()
        .next()
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::read(held.path()).unwrap(), vec![7u8; 70_000]);
}

/// Alice's file with an invite at `level`, open for `lifetime` seconds,
/// and no object.
async fn invite_file(space: &Space, level: Level, lifetime: u64) -> SpaceFile<Notes> {
    SpaceFile::<Notes>::export(
        space,
        Export {
            objects: Objects::None,
            way_in: vec![WayIn::Invite {
                level,
                lifetime: Duration::from_secs(lifetime),
            }],
            ..Export::default()
        },
    )
    .await
    .unwrap()
}

/// An invite's lifetime is 15 minutes to 7 days (overview.md, "Every
/// timer", `link_lifetime`): an export with one outside it is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invite_lifetime_out_of_range_is_refused() {
    let alice = device(86, Options::new()).await;
    let (space, _, _, _) = alices_space(&alice).await;
    for lifetime in [1, 899, 604_801] {
        let refused = SpaceFile::<Notes>::export(
            &space,
            Export {
                objects: Objects::None,
                way_in: vec![WayIn::Invite {
                    level: Level::Read,
                    lifetime: Duration::from_secs(lifetime),
                }],
                ..Export::default()
            },
        )
        .await;
        assert!(
            matches!(refused, Err(Error::Invalid(_))),
            "{lifetime} s: {:?}",
            refused.err()
        );
    }
    invite_file(&space, Level::Read, 900).await;
    invite_file(&space, Level::Read, 604_800).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invitation_dropped_undecided_is_offered_again() {
    let alice = device(81, Options::new()).await;
    let (space, _, _, _) = alices_space(&alice).await;
    let file = invite_file(&space, Level::Write, 900).await;
    let bob = device(82, Options::new()).await;
    let Opened::Invited(invited) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("an invitation");
    };
    let id = invited.invitation().space();
    drop(invited);
    // Undecided: listed nowhere, and not a space the device hands out.
    assert!(bob.spaces().await.is_empty());
    assert!(matches!(bob.space(id).await, Err(Error::UnknownSpace)));
    // The same file again: the offer again, not a reader's merge.
    let Opened::Invited(again) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("offered again");
    };
    let bobs = again.accept().await.unwrap();
    assert_eq!(bobs.space.level().await, Some(Level::Write));
    assert_eq!(bob.spaces().await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refused_acceptance_leaves_the_invitation_to_decline() {
    let alice = device(83, Options::new()).await;
    let (space, _, _, _) = alices_space(&alice).await;
    let file = invite_file(&space, Level::Read, 900).await;
    // Bob's clock reads the wall now, and moves past the invite's expiry
    // between the offer and his consent.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let clock = Arc::new(ManualClock::new(1_000, Some(now)));
    let bob = device(84, Options::new().clock(clock.clone())).await;
    let Opened::Invited(invited) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("an invitation");
    };
    clock.advance(1_000);
    match invited.accept().await {
        Err(error) => assert_eq!(error, Error::Class("Expired"), "too late"),
        Ok(_) => panic!("accepted after the expiry"),
    }
    // The handle is still in hand: the person declines, and nothing stays.
    invited.decline().await.unwrap();
    assert!(bob.spaces().await.is_empty());
    assert!(bob.engine().spaces().await.is_empty(), "the log is gone");
}

#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_claim_left_pending_is_forgotten_when_the_device_reopens() {
    let dir = temp_dir("space-file-pending-claim");
    let alice = device(85, Options::new()).await;
    let (space, _, _, _) = alices_space(&alice).await;
    let file = invite_file(&space, Level::Write, 900).await;
    let store = dir.join("bob");
    let bob = Device::open_with(
        frasil::Storage::Directory(store.clone()),
        &[86; 32],
        Options::new().loopback().never_restored(),
    )
    .await
    .unwrap();
    let Opened::Invited(invited) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("an invitation");
    };
    assert_eq!(bob.engine().spaces().await.len(), 1, "held for the claim");
    drop(invited);
    bob.close().await.unwrap();
    drop(bob);

    // Reopened: the claim's log, which no claim record backs, is forgotten.
    let bob = Device::open_with(
        frasil::Storage::Directory(store),
        &[86; 32],
        Options::new().loopback().never_restored(),
    )
    .await
    .unwrap();
    assert!(bob.spaces().await.is_empty());
    assert!(bob.engine().spaces().await.is_empty(), "no ghost log");
    // The invite is still open: the file offers it again, and the claim
    // signed now survives a restart.
    let Opened::Invited(again) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("offered again");
    };
    again.accept().await.unwrap();
    bob.close().await.unwrap();
    drop(bob);
    let bob = Device::open_with(
        frasil::Storage::Directory(dir.join("bob")),
        &[86; 32],
        Options::new().loopback().never_restored(),
    )
    .await
    .unwrap();
    assert_eq!(bob.spaces().await.len(), 1, "a signed claim is kept");
    assert_eq!(bob.spaces().await[0].level().await, Some(Level::Write));
}

/// Background work held until the test lets it run: a device opened with
/// it does no upkeep meanwhile.
#[cfg(feature = "sqlite")]
#[derive(Default)]
struct HeldTasks(std::sync::Mutex<Vec<frasil::BoxFuture<'static, ()>>>);

#[cfg(feature = "sqlite")]
impl HeldTasks {
    /// Runs what was held, and drops it with the device.
    fn release(&self) {
        for task in std::mem::take(&mut *self.0.lock().unwrap()) {
            tokio::spawn(task);
        }
    }
}

#[cfg(feature = "sqlite")]
impl frasil::advanced::Tasks for HeldTasks {
    fn spawn(&self, task: frasil::BoxFuture<'static, ()>) {
        self.0.lock().unwrap().push(task);
    }

    fn sleep(&self, duration: Duration) -> frasil::BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

/// The same file opened again before the device's upkeep forgot the
/// claim left pending: the claim begun now is not forgotten in its place.
#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_file_opened_again_before_a_pending_claim_is_forgotten_keeps_the_new_claim() {
    let dir = temp_dir("space-file-pending-claim-again");
    let alice = device(88, Options::new()).await;
    let (space, _, _, _) = alices_space(&alice).await;
    let file = invite_file(&space, Level::Write, 900).await;
    let store = dir.join("bob");
    let open = |tasks: Option<Arc<HeldTasks>>| {
        let store = store.clone();
        async move {
            let options = Options::new().loopback().never_restored();
            let options = match tasks {
                Some(tasks) => options.tasks(tasks),
                None => options,
            };
            Device::open_with(frasil::Storage::Directory(store), &[89; 32], options)
                .await
                .unwrap()
        }
    };
    let bob = open(None).await;
    let Opened::Invited(invited) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("an invitation");
    };
    drop(invited);
    bob.close().await.unwrap();
    drop(bob);

    // Reopened with no upkeep yet: the file is opened again first, then
    // the claim left pending is forgotten.
    let tasks = Arc::new(HeldTasks::default());
    let bob = open(Some(tasks.clone())).await;
    let Opened::Invited(again) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("offered again");
    };
    bob.engine().forget_stale_claims().await.unwrap();
    assert_eq!(bob.engine().spaces().await.len(), 1, "the new claim's log");
    tasks.release();
    again.accept().await.unwrap();
    bob.close().await.unwrap();
    drop(bob);
    let bob = open(None).await;
    assert_eq!(bob.spaces().await.len(), 1, "a signed claim is kept");
    assert_eq!(bob.spaces().await[0].level().await, Some(Level::Write));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_invitation_accepted_twice_is_one_claim() {
    let alice = device(87, Options::new()).await;
    let (space, _, _, _) = alices_space(&alice).await;
    let file = invite_file(&space, Level::Write, 900).await;
    let bob = device(88, Options::new()).await;
    let Opened::Invited(invited) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("an invitation");
    };
    let first = invited.accept().await.unwrap();
    let second = invited.accept().await.unwrap();
    assert_eq!(first.space.id(), second.space.id());
    assert_eq!(bob.spaces().await.len(), 1);
    assert_eq!(
        bob.engine()
            .outbox(&frasil_events::EventId(*space.id().as_bytes()))
            .await
            .len(),
        1,
        "one successor"
    );
    // A decision after the fact changes nothing.
    invited.decline().await.unwrap();
    assert_eq!(bob.spaces().await.len(), 1);

    // While a claim waits, the engine holds the space and presents it to
    // nobody: what `Device::connect`, the upkeep and `remove_device` go
    // by. Carol, offline, is offered the same invite; the two claims would
    // race if both were signed.
    let carol = device(89, Options::new()).await;
    let Opened::Invited(pending) = SpaceFile::<Notes>::import_bytes(&carol, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("offered");
    };
    let id = frasil_events::EventId(*space.id().as_bytes());
    assert!(carol.engine().spaces().await.contains(&id));
    assert!(!carol.engine().presentable_spaces().await.contains(&id));
    pending.decline().await.unwrap();
    assert!(carol.engine().spaces().await.is_empty());
}

#[cfg(feature = "sqlite")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_claims_held_objects_go_from_the_provider_when_the_device_reopens() {
    let dir = temp_dir("space-file-pending-held");
    let alice = device(90, Options::new()).await;
    let (space, _, _, _) = alices_space(&alice).await;
    // The blob embedded, and an invite as the way in.
    let file = SpaceFile::<Notes>::export(
        &space,
        Export {
            way_in: vec![WayIn::Invite {
                level: Level::Write,
                lifetime: Duration::from_secs(900),
            }],
            ..Export::default()
        },
    )
    .await
    .unwrap();
    assert_eq!(file.manifest().objects.len(), 1);
    let provider = DirProvider::new(dir.join("bob-provider"));
    let store = dir.join("bob");
    let open = |provider: Arc<DirProvider>| {
        Device::open_with(
            frasil::Storage::Directory(store.clone()),
            &[91; 32],
            Options::new()
                .loopback()
                .never_restored()
                .object_provider(provider),
        )
    };
    let bob = open(provider.clone()).await.unwrap();
    let Opened::Invited(invited) = SpaceFile::<Notes>::import_bytes(&bob, file.bytes(), None)
        .await
        .unwrap()
    else {
        panic!("an invitation");
    };
    // The file's object went to the provider while the claim waits.
    assert_eq!(
        std::fs::read_dir(provider.dir.as_path()).unwrap().count(),
        1,
        "held for the claim"
    );
    drop(invited);
    bob.close().await.unwrap();
    drop(bob);

    // Reopened: the claim is forgotten through the provider, which is
    // told to let the file go. (The test provider records the call and
    // keeps the file, so the call is what is checked.)
    assert!(provider.forgotten().is_empty(), "nothing forgotten yet");
    let bob = open(provider.clone()).await.unwrap();
    assert!(bob.engine().spaces().await.is_empty(), "no ghost log");
    // The device's upkeep forgets it once the provider is attached.
    until(|| async { provider.forgotten().len() == 1 }).await;
    assert_eq!(provider.forgotten().len(), 1, "told once");
    bob.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_stages_apart_and_removes_what_a_stopped_writer_left() {
    let dir = temp_dir("space-file-write");
    let path = dir.join("notes.frasil");
    let alice = device(53, Options::new()).await;
    let (space, _, _, _) = alices_space(&alice).await;
    let file = SpaceFile::<Notes>::export(&space, Export::default())
        .await
        .unwrap();

    // What writers that stopped left: the fixed name of old, and a
    // writer's own name, an hour old; and a writer still writing, fresh.
    let old = dir.join("notes.frasil.partial");
    let stopped = dir.join("notes.frasil.1-0.partial");
    let writing = dir.join("notes.frasil.2-0.partial");
    let other = dir.join("other.frasil.partial");
    for aside in [&old, &stopped, &writing, &other] {
        std::fs::write(aside, b"short").unwrap();
    }
    let hour_ago = SystemTime::now() - Duration::from_secs(60 * 60 + 1);
    for aside in [&old, &stopped, &other] {
        std::fs::File::options()
            .write(true)
            .open(aside)
            .unwrap()
            .set_modified(hour_ago)
            .unwrap();
    }

    file.write(&path).await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), file.bytes());
    assert!(!old.exists(), "the old fixed name, stale, is removed");
    assert!(
        !stopped.exists(),
        "a stopped writer's file aside is removed"
    );
    assert!(writing.exists(), "a writer still writing keeps its file");
    assert!(other.exists(), "another path's files are not this writer's");
    let aside: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".partial") && n.starts_with("notes.frasil."))
        .collect();
    assert_eq!(
        aside,
        vec!["notes.frasil.2-0.partial"],
        "nothing of its own left"
    );

    // Two writers of one path at once: each stages apart, both succeed,
    // and the path holds a whole file.
    let a = SpaceFile::<Notes>::from_bytes(file.bytes().to_vec()).unwrap();
    let b = SpaceFile::<Notes>::from_bytes(file.bytes().to_vec()).unwrap();
    let (pa, pb) = (path.clone(), path.clone());
    let (ra, rb) = tokio::join!(
        tokio::spawn(async move { a.write(&pa).await }),
        tokio::spawn(async move { b.write(&pb).await })
    );
    ra.unwrap().unwrap();
    rb.unwrap().unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), file.bytes());
    let _ = std::fs::remove_dir_all(&dir);
}
