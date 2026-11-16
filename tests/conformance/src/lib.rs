//! End-to-end scenarios: Frasil's clients against `frasil-relay`.
//!
//! Conformance is defined by `docs/spec/overview.md`, section 7
//! (Conformance).
//!
//! - [`client`]: a device's end of a device-to-peer connection, over the
//!   server binding's WebSocket or the iroh binding, as a test driver.
//! - [`history`]: the histories of `peers.json`, and events a scenario
//!   signs onto them with the vectors' keys.
//!
//! The scenarios are this crate's tests. They run on loopback only, against
//! `frasil_relay::testing`'s peer, and every wait has a deadline.

pub mod client;
pub mod history;

/// An HTTP client for the peer's routes. reqwest takes its TLS provider from
/// the process default, so this installs ring, the only provider linked,
/// first.
pub fn http_client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::new()
}

use frasil_relay::testing::{Options, TestPeer, spawn_with};
use frasil_relay::{Extensions, PeerError, Settings};

/// The extensions on in every test peer: those this crate's features name,
/// so that a scenario of an extension runs against a peer with it on, and
/// every other scenario against the core peer when the features are off.
pub const EXTENSIONS: Extensions = Extensions {
    ephemeral: cfg!(feature = "ephemeral"),
    file_versions: cfg!(feature = "ext-file-versions"),
    invite_links: cfg!(feature = "ext-invite-links"),
    libraries: cfg!(feature = "ext-libraries"),
    deposit_tokens: cfg!(feature = "ext-deposit-tokens"),
};

/// The test peers' settings: a peer that hosts any space a connection
/// creates ([`frasil_relay::Hosting::Open`]), with [`EXTENSIONS`] on, so
/// that a scenario creates its spaces with no ticket unless it asks for
/// one. With `ext-libraries`, such a space is attached to the test peer's
/// open library. An operator's peer is closed by default
/// ([`Settings::default`]): a scenario of that sets its own settings.
pub fn settings() -> Settings {
    Settings {
        extensions: EXTENSIONS,
        ..Settings::open_core()
    }
}

/// A test peer's default options, with [`settings`].
pub fn options() -> Options {
    Options {
        settings: settings(),
        ..Options::default()
    }
}

/// Starts a test peer on loopback with [`options`].
///
/// # Errors
///
/// If a listener does not bind.
pub async fn spawn_loopback() -> Result<TestPeer, PeerError> {
    spawn_with(options()).await
}
