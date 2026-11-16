//! Pausing a space's sync with always-on peers, such as every space of a
//! library its operator suspended: while paused, the device stores nothing
//! at a peer and fetches nothing from one for the space, and the space stays
//! attached, readable and writable here. Resuming offers its heads again and
//! fetches what it lacks, so it catches up with what changed meanwhile.
//!
//! A library exists only at a peer, and the client never learns which one a
//! space is billed to (ext-libraries.md), so the application names the
//! spaces it holds in that library. A pause lasts while the device is open;
//! the application pauses again after [`Device::open`] when it should.
//! Member connections are not paused.

#![cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]

use super::{Device, Space, SpaceId};

impl Space {
    /// Pauses the space's sync with always-on peers: no store and no fetch
    /// until [`Space::resume_sync`]. Its changes stay on this device, and
    /// [`Space::is_durable`] is false while any wait.
    pub fn pause_sync(&self) {
        self.device.engine().links().pause(self.id().event());
    }

    /// Resumes the space's sync with always-on peers: it offers its heads
    /// and fetches what it lacks at each connected peer, and so catches up.
    pub fn resume_sync(&self) {
        let space = self.id().event();
        if !self.device.engine().links().resume(&space) {
            return;
        }
        for peer in self.device.peers_of(&space) {
            peer.handle().resume(space);
        }
    }

    /// Whether the space's sync with always-on peers is paused.
    pub fn is_sync_paused(&self) -> bool {
        self.device.engine().links().is_paused(&self.id().event())
    }
}

impl Device {
    /// Pauses the sync of these spaces with always-on peers at once, such as
    /// every space of one library: [`Space::pause_sync`] for each. A space
    /// this device does not hold yet is paused from the moment it does.
    pub fn pause_sync(&self, spaces: impl IntoIterator<Item = SpaceId>) {
        let mut links = self.engine().links();
        for space in spaces {
            links.pause(space.event());
        }
    }

    /// Resumes the sync of these spaces with always-on peers:
    /// [`Space::resume_sync`] for each.
    pub fn resume_sync(&self, spaces: impl IntoIterator<Item = SpaceId>) {
        let resumed: Vec<_> = {
            let mut links = self.engine().links();
            spaces
                .into_iter()
                .map(SpaceId::event)
                .filter(|space| links.resume(space))
                .collect()
        };
        for space in resumed {
            for peer in self.peers_of(&space) {
                peer.handle().resume(space);
            }
        }
    }
}
