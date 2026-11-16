//! Leaving a space, and forgetting it on this device (at-rest.md,
//! "Forgetting a log, and re-keying").

use super::Space;
use crate::error::{Error, Result};
use frasil_space::{Level, MemberRef};

impl Space {
    /// Forgets the space on this device: its log, streams and keys at rest
    /// go, and [`Device::spaces`](super::Device::spaces) no longer lists it
    /// (at-rest.md, "Forgetting a log, and re-keying"). The roster does not
    /// change: other members still count this device as a member, and
    /// writers still seal for it, until an administrator removes it. Use it
    /// once this device was removed ([`Event::Removed`](super::Event::Removed)),
    /// or to drop a space this device no longer wants to hold. Changes not
    /// yet durable at a peer are lost.
    ///
    /// # Errors
    ///
    /// The store's.
    pub async fn forget(&self) -> Result<()> {
        self.device()
            .engine()
            .forget_space(&self.id().event())
            .await
    }

    /// Leaves the space, then forgets it on this device. An administering
    /// device removes its person, when its person is a member, with every
    /// device on the person's list, then itself; the space rotates its
    /// keys for the person's removal, and another writer heals after its
    /// own (roster.md, "The event alone"). Once a connected peer holds the
    /// removals, the device forgets the space as [`Space::forget`] does. A
    /// device that is no longer a member forgets it as soon as what it
    /// wrote is durable.
    ///
    /// Only an administering device signs roster events. With the
    /// `ext-guests` feature, a member that does not administer sends a
    /// leave request to the administering devices instead, and from then
    /// on writes nothing there (ext-guests.md, "The leave request"); the
    /// space stays on this device until it is removed, or until it
    /// [forgets](Space::forget) it. Without the feature such a member asks
    /// an administrator to remove it.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a member that does not administer, without
    /// the `ext-guests` feature, and for the last administering device, which hands `administer` to another
    /// device first; [`Error::Connection`] when no connected peer holds the
    /// removals within 30 seconds: the space stays on this device, and a
    /// later call finishes leaving; the store's.
    pub async fn leave(&self) -> Result<()> {
        let engine = self.device().engine();
        let space = self.id().event();
        let me = engine.device_id();
        match self.level().await {
            None => {}
            Some(Level::Administer) => {
                let person = engine.person().await;
                let (others, person_in, device_in) = engine
                    .read(&space, |replica| {
                        // Only device members administer: a person's
                        // grant is at most `write`.
                        let others = replica
                            .devices()
                            .iter()
                            .any(|(device, level)| *level == Level::Administer && *device != me);
                        let roster = replica.roster();
                        (
                            others,
                            person.is_some_and(|p| roster.is_in(&MemberRef::person(p))),
                            roster.is_in(&MemberRef::device(me)),
                        )
                    })
                    .await?;
                if !others {
                    return Err(Error::NotAllowed(
                        "the last administering device stays: grant administer to another device first",
                    ));
                }
                if let (Some(person), true) = (person, person_in) {
                    engine.remove(space, MemberRef::person(person)).await?;
                }
                if device_in {
                    engine.remove(space, MemberRef::device(me)).await?;
                }
                self.device().present(space);
            }
            #[cfg(feature = "ext-guests")]
            Some(_) => return self.request_leave().await,
            #[cfg(not(feature = "ext-guests"))]
            Some(_) => {
                return Err(Error::NotAllowed(
                    "only an administering device removes itself: ask an administrator, or forget the space",
                ));
            }
        }
        self.flush().await?;
        self.forget().await
    }
}
