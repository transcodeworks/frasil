//! The always-on peers a device knows for each space: the peer hints of the
//! welcome that admitted it, the peers that granted it the space, and the
//! home peer of the space's library (admission.md, "The welcome";
//! ext-libraries.md, "The home peer"), kept in the space's `peers` table
//! (at-rest.md, "Tables").
//!
//! A device tries them, home peer first, when a peer answers `moved`
//! (peers.md, "Refusal codes"). A peer that answered `moved` stays, last,
//! as a last resort: a space may come back to it. In the welcomes it signs
//! for the space a device names the home peer, then the peers it syncs the
//! space with now.

use crate::at_rest::Batch;
use crate::device::Engine;
use crate::error::Result;
use frasil_events::EventId;
use frasil_store::tables::{MAX_PEER_HINTS, MAX_PEER_URL, PeersRecord};
use frasil_store::{Table, TableValue};
use std::sync::PoisonError;

/// Whether `url` is a peer hint a device keeps: the URL of an origin, such
/// as `https://peer.example`, with no path, query, fragment or
/// credentials; plain `http` only on loopback, for tests (admission.md,
/// "The welcome": a newcomer ignores a hint that is not such a URL).
pub(crate) fn is_peer_url(url: &str) -> bool {
    if url.is_empty() || url.len() > MAX_PEER_URL {
        return false;
    }
    let rest = if let Some(rest) = url.strip_prefix("https://") {
        rest
    } else if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or_default();
        if !matches!(host, "127.0.0.1" | "localhost") && !rest.starts_with("[::1]") {
            return false;
        }
        rest
    } else {
        return false;
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    !authority.is_empty() && !authority.contains(['/', '?', '#', '@', ' '])
}

/// A peer URL as the device compares it: without a trailing slash.
pub(crate) fn same_peer(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// A change to the peers kept for a space.
enum Change<'a> {
    /// Hints learned: a welcome's, or a peer that granted the space.
    Hints(&'a [String]),
    /// The home peer its issuer named.
    #[cfg(feature = "ext-libraries")]
    Home(&'a str),
    /// A peer that answered `moved`.
    Demote(&'a str),
}

/// What a device keeps of a space's peers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KeptPeers {
    /// The home peer of the space's library, as its issuer named it.
    pub home: Option<String>,
    /// The peer hints, in the order the device learned them.
    pub hints: Vec<String>,
}

/// `hints` after `kept`'s, each a peer URL not kept yet, at most 8 in all:
/// a newcomer ignores a hint that is not such a URL (admission.md, "The
/// welcome").
fn merge_hints(kept: &mut Vec<String>, hints: &[String]) {
    for hint in hints {
        if is_peer_url(hint) && !kept.iter().any(|url| same_peer(url, hint)) {
            kept.push(hint.clone());
        }
    }
    kept.truncate(MAX_PEER_HINTS);
}

/// Puts a peer that answered `moved` last among the hints, and no longer
/// as the home peer (peers.md, "Refusal codes").
fn demote(kept: &mut KeptPeers, url: &str) {
    let known = kept.hints.iter().any(|hint| same_peer(hint, url))
        || kept
            .home
            .as_deref()
            .is_some_and(|home| same_peer(home, url));
    if !known {
        return;
    }
    kept.hints.retain(|hint| !same_peer(hint, url));
    if kept
        .home
        .as_deref()
        .is_some_and(|home| same_peer(home, url))
    {
        kept.home = None;
    }
    kept.hints.push(url.trim_end_matches('/').to_owned());
}

impl KeptPeers {
    /// The peers in the order a device names and tries them: the home peer
    /// first, then the hints, each once, at most 8.
    pub fn ordered(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for url in self.home.iter().chain(&self.hints) {
            if !out.iter().any(|kept| same_peer(kept, url)) {
                out.push(url.clone());
            }
        }
        out.truncate(MAX_PEER_HINTS);
        out
    }
}

/// The `peers` record of a space's log.
async fn read_kept(vault: &crate::at_rest::Vault, space: &EventId) -> Result<KeptPeers> {
    Ok(match vault.get(&space.0, Table::Peers, &[]).await? {
        Some(TableValue::Peers(PeersRecord { hints, home })) => KeptPeers { home, hints },
        _ => KeptPeers::default(),
    })
}

impl Engine {
    /// The peers the device keeps for a space: none for a space it holds no
    /// log of.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn kept_peers(&self, space: &EventId) -> Result<KeptPeers> {
        let state = self.lock().await;
        if !state.vault.has_log(&space.0) {
            return Ok(KeptPeers::default());
        }
        read_kept(&state.vault, space).await
    }

    /// Makes a change to the peers kept for a space, and writes them when
    /// they changed. Returns whether they did. One procedure for every
    /// change, boxed, so that its callers share its code.
    fn change_peers<'a>(
        &'a self,
        space: &'a EventId,
        change: Change<'a>,
    ) -> frasil_store::BoxFuture<'a, Result<bool>> {
        Box::pin(self.change_peers_now(space, change))
    }

    async fn change_peers_now(&self, space: &EventId, change: Change<'_>) -> Result<bool> {
        let mut state = self.lock().await;
        if !state.vault.has_log(&space.0) {
            return Ok(false);
        }
        let mut kept = read_kept(&state.vault, space).await?;
        let before = kept.clone();
        match change {
            Change::Hints(hints) => merge_hints(&mut kept.hints, hints),
            #[cfg(feature = "ext-libraries")]
            Change::Home(url) => kept.home = Some(url.to_owned()),
            Change::Demote(url) => demote(&mut kept, url),
        }
        kept.hints.retain(|url| is_peer_url(url));
        kept.hints.truncate(MAX_PEER_HINTS);
        kept.home = kept.home.filter(|url| is_peer_url(url));
        if kept == before {
            return Ok(false);
        }
        let mut batch = Batch::default();
        if kept.home.is_none() && kept.hints.is_empty() {
            state.vault.delete(&mut batch, &space.0, Table::Peers, &[]);
        } else {
            let value = TableValue::Peers(PeersRecord {
                hints: kept.hints,
                home: kept.home,
            });
            state
                .vault
                .put(&mut batch, &space.0, Table::Peers, &[], &value)?;
        }
        state.vault.commit(batch).await?;
        Ok(true)
    }

    /// Keeps peer hints of a space the device did not keep yet, after those
    /// it keeps: a welcome's, or a peer that granted the space. A hint that
    /// is not a peer URL is ignored.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn keep_peer_hints(&self, space: &EventId, hints: &[String]) -> Result<bool> {
        self.change_peers(space, Change::Hints(hints)).await
    }

    /// Keeps the home peer of a space's library, as its issuer returns it
    /// (ext-libraries.md, "The home peer").
    ///
    /// # Errors
    ///
    /// The store's.
    #[cfg(feature = "ext-libraries")]
    pub(crate) async fn keep_home_peer(&self, space: &EventId, url: &str) -> Result<bool> {
        self.change_peers(space, Change::Home(url)).await
    }

    /// Puts a peer that answered `moved` for a space last among its hints,
    /// and no longer as its home peer: it no longer hosts the space
    /// (peers.md, "Refusal codes"), and is tried only after the others.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn demote_peer(&self, space: &EventId, url: &str) -> Result<bool> {
        self.change_peers(space, Change::Demote(url)).await
    }

    /// Whether a party that is not connected now could still send an
    /// object of a space, so that what the connected ones sent settles
    /// nothing for good: a connection of the space is being made; the
    /// device keeps an always-on peer of the space that does not grant it
    /// the space on a connection now; or the space has a member besides
    /// this device, which may connect and hold the object. Only a space
    /// whose one member is this device, with every peer it keeps
    /// connected, has no other party to wait for.
    #[cfg_attr(not(feature = "adapter-blobs"), allow(dead_code))]
    pub(crate) async fn others_may_serve(&self, space: &EventId) -> bool {
        if self.fetches().expecting(space) {
            return true;
        }
        let kept = self
            .kept_peers(space)
            .await
            .map(|kept| kept.ordered())
            .unwrap_or_default();
        let syncing: Vec<String> = self
            .syncing()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(of, _)| of == space)
            .map(|(_, url)| url.clone())
            .collect();
        if kept
            .iter()
            .any(|url| !syncing.iter().any(|with| same_peer(with, url)))
        {
            return true;
        }
        let own = frasil_space::MemberRef::device(self.device_id());
        self.read(space, |replica| {
            replica
                .roster()
                .members_in()
                .any(|(member, _)| *member != own)
        })
        .await
        .unwrap_or(false)
    }

    /// Notes the peers that grant the device each space on an open
    /// connection now, for the welcomes it signs: each space with a peer's
    /// URL.
    pub(crate) fn set_syncing(&self, syncing: Vec<(EventId, String)>) {
        *self
            .syncing()
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = syncing;
    }

    /// The peer hints of a welcome this device signs for a space
    /// (admission.md, "The welcome"): the home peer first where it knows
    /// one, then `also`, then the peers it syncs the space with now, at
    /// most 8.
    pub(crate) fn welcome_hints<'a>(
        &'a self,
        space: &'a EventId,
        also: &'a [String],
    ) -> frasil_store::BoxFuture<'a, Vec<String>> {
        Box::pin(self.welcome_hints_now(space, also))
    }

    async fn welcome_hints_now(&self, space: &EventId, also: &[String]) -> Vec<String> {
        let home = self.kept_peers(space).await.unwrap_or_default().home;
        let syncing: Vec<String> = self
            .syncing()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|(of, _)| of == space)
            .map(|(_, url)| url.clone())
            .collect();
        let mut hints = Vec::new();
        merge_hints(&mut hints, &home.into_iter().collect::<Vec<_>>());
        merge_hints(&mut hints, also);
        merge_hints(&mut hints, &syncing);
        hints
    }
}

#[cfg(test)]
mod tests {
    use super::{KeptPeers, demote, is_peer_url, merge_hints};

    #[test]
    fn peer_urls_are_origins() {
        assert!(is_peer_url("https://peer.example"));
        assert!(is_peer_url("https://peer.example:8443/"));
        assert!(is_peer_url("http://127.0.0.1:4000"));
        assert!(!is_peer_url("http://peer.example"));
        assert!(!is_peer_url("https://peer.example/path"));
        assert!(!is_peer_url("https://user@peer.example"));
        assert!(!is_peer_url("https://peer.example?x"));
        assert!(!is_peer_url("peer.example"));
        assert!(!is_peer_url(&format!("https://{}", "a".repeat(512))));
    }

    #[test]
    fn the_home_peer_comes_first_once() {
        let kept = KeptPeers {
            home: Some("https://home.example".into()),
            hints: vec![
                "https://a.example".into(),
                "https://home.example/".into(),
                "https://b.example".into(),
            ],
        };
        assert_eq!(
            kept.ordered(),
            [
                "https://home.example",
                "https://a.example",
                "https://b.example"
            ]
        );
    }

    /// A welcome's hints that are no peer's origin are ignored, as plain
    /// `http` off loopback is, and at most 8 are kept.
    #[test]
    fn hints_kept_are_origins_and_at_most_eight() {
        let mut kept = Vec::new();
        let offered: Vec<String> = [
            "not a url",
            "http://peer.example",
            "https://peer.example/path",
            "https://a.example",
            "https://a.example/",
        ]
        .into_iter()
        .map(String::from)
        .chain((0..10).map(|n| format!("https://p{n}.example")))
        .collect();
        merge_hints(&mut kept, &offered);
        assert_eq!(kept.len(), 8);
        assert_eq!(kept[0], "https://a.example");
        assert!(kept.iter().all(|url| is_peer_url(url)));
    }

    /// A peer that answered `moved` goes last, and is no home peer, but
    /// stays to be tried again.
    #[test]
    fn a_peer_that_answered_moved_goes_last() {
        let mut kept = KeptPeers {
            home: Some("https://home.example".into()),
            hints: vec!["https://a.example".into(), "https://b.example".into()],
        };
        demote(&mut kept, "https://home.example/");
        demote(&mut kept, "https://a.example");
        demote(&mut kept, "https://unknown.example");
        assert_eq!(kept.home, None);
        assert_eq!(
            kept.ordered(),
            [
                "https://b.example",
                "https://home.example",
                "https://a.example"
            ]
        );
    }
}
