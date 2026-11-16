//! Two devices share a note through an always-on peer: one creates a
//! space and admits the other by an invitation and a compared code, then
//! both edit the note at once. The devices bind on loopback alone.
//!
//! Run a peer beside it, on loopback, with a data directory of its own;
//! `frasil-relay` listens on `127.0.0.1:8787` by default:
//!
//! ```text
//! FRASIL_DATA_DIR=$(mktemp -d) cargo run -p frasil-relay
//! cargo run --example shared_note -- http://127.0.0.1:8787
//! ```
//!
//! The peer's URL is the first argument, else `FRASIL_PEER_URL`, else
//! `http://127.0.0.1:8787`.

use frasil::{Device, Document, Level, Options, Storage};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .or_else(|| std::env::var("FRASIL_PEER_URL").ok())
        .unwrap_or_else(|| "http://127.0.0.1:8787".to_owned());
    let note = run(&url).await?;
    println!("Both read: {note}");
    Ok(())
}

/// The whole flow, against the peer at `peer_url`: what both devices read
/// at the end.
pub async fn run(peer_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Each device seals its keys under an unlock key from the keychain.
    let alice = Device::open_with(Storage::Memory, &[1; 32], Options::new().loopback()).await?;
    let bob = Device::open_with(Storage::Memory, &[2; 32], Options::new().loopback()).await?;

    // Alice creates a space, and keeps it at the peer.
    let space = alice.create_space().await?;
    alice.connect(peer_url).await?;

    // Alice invites Bob's device: Bob enters the invitation's text, and
    // both persons confirm that their screens show the same code.
    let invitation = space
        .invite(
            Level::Write,
            "Alice's laptop",
            |code, newcomer| async move {
                println!("Alice sees {code}, for {newcomer}");
                true
            },
        )
        .await?;
    let bobs_space = bob
        .join(invitation.text(), "Bob's phone", |code, host| async move {
            println!("Bob sees {code}, from {host}");
            true
        })
        .await?;
    invitation.admitted().await?;
    bob.connect(peer_url).await?;

    // Alice writes a note; Bob opens it once it has arrived.
    let note = space.create_document()?;
    note.edit(|doc| doc.get_text("body").insert(0, "Hello"))
        .await?;
    let bobs_note = bobs_space
        .document_when_available(note.id(), Duration::from_secs(30))
        .await?;

    // Both edit at once, and each sees both edits.
    note.edit(|doc| doc.get_text("body").insert(5, ", world"))
        .await?;
    bobs_note
        .edit(|doc| doc.get_text("body").insert(0, "Bob: "))
        .await?;
    let read = agreed(&note, &bobs_note).await?;

    alice.close().await?;
    bob.close().await?;
    Ok(read)
}

/// Waits until both copies of the note hold both edits.
async fn agreed(a: &Document, b: &Document) -> frasil::Result<String> {
    loop {
        let (left, right) = (a.text("body").await?, b.text("body").await?);
        if left == right && left.contains("world") && left.contains("Bob") {
            return Ok(left);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
