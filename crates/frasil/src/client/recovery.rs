//! Recovery: a recovery sheet or a passkey that brings a person back on a
//! new device after every other device is lost (identity.md, "Recovery").
//!
//! - [`Device::create_recovery_sheet`] adds a recovery key to the device's
//!   person and returns the [`RecoverySheet`] to print, once.
//! - [`Device::add_passkey`] adds a passkey member through the
//!   application's [`Passkey`]: WebAuthn in a browser, a platform API
//!   elsewhere.
//! - [`Device::recover`] and [`Device::recover_with_passkey`] make a new
//!   device of the person from the sheet or the passkey and a peer that
//!   holds the personal space: the device fetches it through the recovery
//!   entry, signs itself in, and reaches every space the personal space
//!   records a recovery entry of.
//!
//! The device's peer connections register each recovery entry at every
//! peer they use. A sheet or a passkey works once a peer holds the
//! personal space with its entry: keep the device connected until the
//! personal space [`is durable`](super::Space::is_durable).

use super::{Device, MemberId, SpaceId};
use crate::error::{Error, Result};
use frasil_identity::passkey::{UserHandle, prf_input};
use frasil_store::BoxFuture;
use frasil_store::store::MaybeSync;
use zeroize::Zeroizing;

/// A recovery sheet (identity.md, "Recovery keys"): the recovery key's
/// secret in its printed form, the person ID and the personal space ID.
/// Print it or write it down once; the device forgets the secret.
///
/// Its [`text`](Self::text) is four lines:
///
/// ```text
/// Frasil recovery sheet
/// Secret: ABCD-EFGH-…-XYZ
/// Person: <64 hexadecimal digits>
/// Personal space: <64 hexadecimal digits>
/// ```
///
/// [`RecoverySheet::read`] takes that text back, with any spacing and
/// case, and ignores other lines.
pub struct RecoverySheet {
    secret: Zeroizing<String>,
    person: MemberId,
    personal_space: SpaceId,
}

impl core::fmt::Debug for RecoverySheet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoverySheet")
            .field("person", &self.person)
            .field("personal_space", &self.personal_space)
            .finish_non_exhaustive()
    }
}

/// The sheet's first line.
const TITLE: &str = "Frasil recovery sheet";

impl RecoverySheet {
    /// The secret in its printed form: 55 characters in groups of four
    /// joined by `-`.
    pub fn secret(&self) -> &str {
        &self.secret
    }

    /// The person.
    pub fn person(&self) -> MemberId {
        self.person
    }

    /// The person's personal space.
    pub fn personal_space(&self) -> SpaceId {
        self.personal_space
    }

    /// The sheet as text, to print or show once.
    pub fn text(&self) -> Zeroizing<String> {
        Zeroizing::new(format!(
            "{TITLE}\nSecret: {}\nPerson: {}\nPersonal space: {}\n",
            self.secret.as_str(),
            self.person,
            self.personal_space
        ))
    }

    /// Reads a sheet's text as [`text`](Self::text) writes it. The secret
    /// is checked as identity.md's "Recovery keys" reads it: spaces and
    /// hyphens removed, lower case mapped to upper case.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for text that lacks a line; `InvalidSheet` for a
    /// secret that does not read, such as one mistyped.
    pub fn read(text: &str) -> Result<Self> {
        let mut secret = None;
        let mut person = None;
        let mut personal_space = None;
        for line in text.lines() {
            let Some((label, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match label.trim().to_ascii_lowercase().as_str() {
                "secret" => secret = Some(Zeroizing::new(value.to_owned())),
                "person" => person = Some(value.parse::<MemberId>()?),
                "personal space" => personal_space = Some(value.parse::<SpaceId>()?),
                _ => {}
            }
        }
        let secret = secret.ok_or(Error::Invalid("a recovery sheet has a secret line"))?;
        frasil_identity::recovery::RecoverySecret::read_sheet(&secret).map_err(Error::class)?;
        Ok(Self {
            secret,
            person: person.ok_or(Error::Invalid("a recovery sheet has a person line"))?,
            personal_space: personal_space
                .ok_or(Error::Invalid("a recovery sheet has a personal space line"))?,
        })
    }
}

/// A future a [`Passkey`] returns.
pub type PasskeyFuture<'a, T> = BoxFuture<'a, Result<T>>;

/// A passkey's PRF output, as the platform returned it: zeroised when
/// dropped, and never shown.
pub struct PrfOutput(Zeroizing<Vec<u8>>);

impl PrfOutput {
    /// The output of these bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for PrfOutput {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl core::fmt::Debug for PrfOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PrfOutput([redacted])")
    }
}

/// One passkey assertion: the credential's user handle and its PRF output.
pub struct PasskeyAssertion {
    /// The credential's user handle, `user.id`.
    pub user_handle: Vec<u8>,
    /// The PRF output for the input asked for; `None` when the passkey gave
    /// none, so that it cannot be used.
    pub prf_output: Option<PrfOutput>,
}

impl core::fmt::Debug for PasskeyAssertion {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasskeyAssertion")
            .field("user_handle", &self.user_handle)
            .finish_non_exhaustive()
    }
}

/// The platform's passkeys, which the application supplies: WebAuthn in a
/// browser, a platform API elsewhere. Frasil never sees the ceremony, so
/// the application keeps identity.md's rules for it ("The passkey
/// ceremony"): user verification required at registration and at every
/// assertion; the PRF extension requested at registration, with the input
/// given as `prf.eval.first` and never a `second`; a discoverable
/// credential (`residentKey: "required"`) whose `user.id` is the handle
/// given; and the output kept on the client, stripped from anything sent
/// to a server.
pub trait Passkey: MaybeSync {
    /// Registers a discoverable passkey whose `user.id` is `user_handle`,
    /// evaluating its PRF at `prf_input`. Returns the output, or `None` when
    /// the platform returns none at registration: the device then asks for
    /// two assertions.
    fn register<'a>(
        &'a self,
        user_handle: &'a [u8; 64],
        prf_input: &'a [u8; 32],
    ) -> PasskeyFuture<'a, Option<PrfOutput>>;

    /// Asks for an assertion with an empty `allowCredentials`, evaluating
    /// the PRF at `prf_input`.
    fn assert<'a>(&'a self, prf_input: &'a [u8; 32]) -> PasskeyFuture<'a, PasskeyAssertion>;
}

/// The output of an assertion, for a passkey of this handle.
fn output_of(assertion: PasskeyAssertion, handle: &[u8; 64]) -> Result<PrfOutput> {
    if assertion.user_handle != handle[..] {
        return Err(Error::Class("WrongPerson"));
    }
    assertion.prf_output.ok_or(Error::NotAllowed(
        "this passkey gives no PRF output, so it cannot be used",
    ))
}

impl Device {
    /// Adds a recovery key to this device's person, and returns its sheet:
    /// show it or print it once, since the device forgets the secret
    /// (identity.md, "Adding list members"). The person's spaces wrap their
    /// keys for the recovery key from now on, and each one this device
    /// writes in gets a recovery entry, so that a device recovered from the
    /// sheet reaches it. The device's peer connections register the
    /// entries.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of no person; the store's.
    pub async fn create_recovery_sheet(&self) -> Result<RecoverySheet> {
        let made = self.engine().add_recovery_key().await?;
        self.present(made.personal_space);
        Ok(RecoverySheet {
            secret: made.printed,
            person: MemberId::from_bytes(made.person),
            personal_space: SpaceId::of(made.personal_space),
        })
    }

    /// Adds a passkey to this device's person, as a passkey member
    /// (identity.md, "Adding list members"): registers it through
    /// `passkey`, then asks for one assertion, and adds it only once both
    /// evaluations derive the same keys. Its spaces then wrap for it as for
    /// a recovery key.
    ///
    /// # Errors
    ///
    /// [`Error::NotAllowed`] for a device of no person, or a passkey that
    /// gives no PRF output; `UnstablePrf` when the two evaluations differ;
    /// `WrongPerson` for an assertion of another passkey; the passkey's.
    pub async fn add_passkey(&self, passkey: &dyn Passkey) -> Result<()> {
        let engine = self.engine();
        let person = engine
            .person()
            .await
            .ok_or(Error::NotAllowed("the device is no person's"))?;
        engine.find_personal_space().await;
        let personal_space = engine.personal_space().await.ok_or(Error::NotAllowed(
            "the device does not know its personal space",
        ))?;
        let handle = UserHandle {
            person_id: person,
            personal_space: personal_space.0,
        }
        .to_bytes();
        let input = prf_input();
        let first = match passkey.register(&handle, &input).await? {
            Some(output) => output,
            None => output_of(passkey.assert(&input).await?, &handle)?,
        };
        let second = output_of(passkey.assert(&input).await?, &handle)?;
        engine
            .add_passkey_member(first.bytes(), second.bytes())
            .await?;
        self.present(personal_space);
        Ok(())
    }
}

#[cfg(any(feature = "server", feature = "iroh", feature = "server-socket"))]
mod recovering {
    use super::{Device, Passkey, RecoverySheet, output_of};
    use crate::advanced::recovery::{RecoveryMember, RecoveryStatus};
    use crate::client::{Options, Peer, Storage};
    use crate::error::{Error, Result};
    use frasil_events::EventId;
    use frasil_identity::passkey::{UserHandle, prf_input};
    use frasil_store::device_keys::SEALED_DEVICE_KEYS_BYTES;
    use std::time::Duration;

    /// How long a recovering device waits for the personal space, and then
    /// for each other space.
    const RECOVERY_DEADLINE: Duration = Duration::from_secs(60);

    /// How often it looks again.
    const TICK: Duration = Duration::from_millis(100);

    impl Device {
        /// Makes a new device of a person from a recovery sheet's text, in
        /// `storage`, with its keys sealed under `unlock_key` as
        /// [`Device::open`] does (identity.md, "Recovery"): opens the
        /// device, then [`Device::recover_from_sheet`]. The directory store
        /// and configured [`Options::keep_keys`] keeper retain the resealed
        /// keys, so reopening preserves the person.
        ///
        /// # Errors
        ///
        /// As [`Device::open`] and [`Device::recover_from_sheet`].
        pub async fn recover(
            storage: Storage,
            unlock_key: &[u8; 32],
            sheet: &str,
            peer_url: &str,
            options: Options,
        ) -> Result<Device> {
            let sheet = RecoverySheet::read(sheet)?;
            open_and_recover(storage, unlock_key, options, |device| async move {
                device.recover_from_sheet(unlock_key, sheet, peer_url).await
            })
            .await
        }

        /// Makes a new device of a person from a passkey, as
        /// [`Device::recover`] does from a sheet: opens the device, then
        /// [`Device::recover_from_passkey`].
        ///
        /// # Errors
        ///
        /// As [`Device::open`] and [`Device::recover_from_passkey`].
        pub async fn recover_with_passkey(
            storage: Storage,
            unlock_key: &[u8; 32],
            passkey: &dyn Passkey,
            peer_url: &str,
            options: Options,
        ) -> Result<Device> {
            open_and_recover(storage, unlock_key, options, |device| async move {
                device
                    .recover_from_passkey(unlock_key, passkey, peer_url)
                    .await
            })
            .await
        }

        /// Makes this device, new and of no person, a device of the person
        /// a recovery sheet names (identity.md, "Recovery"). It connects to
        /// the peer at `peer_url`, which holds the personal space, fetches
        /// the space through the recovery key's entry, and has the recovery
        /// key sign it into the person's list. It then reaches each space
        /// the personal space records a recovery entry of, and writes there
        /// through the person's grants; a space without one reaches it once
        /// a member there hands it the person's new list. Returns the
        /// device's keys sealed again under `unlock_key` to name the person:
        /// the directory store and configured [`Options::keep_keys`] keeper
        /// retain them. Without either, the application keeps the returned
        /// bytes in place of the old keys.
        ///
        /// # Errors
        ///
        /// `InvalidSheet` for a secret that does not read;
        /// `CredentialRefused` when the peer holds no recovery entry of the
        /// sheet's key, so a sheet of another key or person; `NotOnList`
        /// when the person's list does not hold the recovery key;
        /// [`Error::NotAllowed`] for a device that is already a person's;
        /// [`Error::Timeout`]; a failure to retain the resealed keys; as
        /// [`Device::connect`].
        pub async fn recover_from_sheet(
            &self,
            unlock_key: &[u8; 32],
            sheet: RecoverySheet,
            peer_url: &str,
        ) -> Result<[u8; SEALED_DEVICE_KEYS_BYTES]> {
            let member = RecoveryMember::from_sheet(
                sheet.secret(),
                *sheet.person().as_bytes(),
                sheet.personal_space().event(),
            )?;
            self.recover_as(unlock_key, member, peer_url).await
        }

        /// Makes this device a device of the person a passkey serves, as
        /// [`Device::recover_from_sheet`] does from a sheet (identity.md,
        /// "Using a passkey member"): `passkey` asks for an assertion, whose
        /// user handle names the person and the personal space. The device
        /// is rooted in the passkey.
        ///
        /// # Errors
        ///
        /// [`Error::NotAllowed`] for a passkey that gives no PRF output;
        /// `Malformed` for a user handle that is not Frasil's; as
        /// [`Device::recover_from_sheet`].
        pub async fn recover_from_passkey(
            &self,
            unlock_key: &[u8; 32],
            passkey: &dyn Passkey,
            peer_url: &str,
        ) -> Result<[u8; SEALED_DEVICE_KEYS_BYTES]> {
            let input = prf_input();
            let assertion = passkey.assert(&input).await?;
            let handle = UserHandle::parse(&assertion.user_handle)
                .map_err(Error::class)?
                .to_bytes();
            let output = output_of(assertion, &handle)?;
            let member = RecoveryMember::from_passkey(&handle, output.bytes())?;
            self.recover_as(unlock_key, member, peer_url).await
        }

        /// Recovers with a list member: identity.md's "Recovery", steps 1
        /// to 6, then the other spaces.
        async fn recover_as(
            &self,
            unlock_key: &[u8; 32],
            member: RecoveryMember,
            peer_url: &str,
        ) -> Result<[u8; SEALED_DEVICE_KEYS_BYTES]> {
            let engine = self.engine();
            let personal = engine.begin_recovery(member).await?;
            let recovered = async {
                let peer = self.connect(peer_url).await?;
                wait_for_list(self, &peer, personal).await?;
                engine.complete_recovery(unlock_key).await
            }
            .await;
            let recovered = match recovered {
                Ok(recovered) => recovered,
                Err(error) => {
                    engine.end_recovery().await;
                    return Err(error);
                }
            };
            self.present(personal);
            // The other spaces, each through its recovery entry; the device
            // publishes the person's new list there once it writes.
            for space in &recovered.others {
                self.present(*space);
            }
            let mut waited = Duration::ZERO;
            let mut pending: Vec<EventId> = recovered.others.clone();
            while !pending.is_empty() && waited < RECOVERY_DEADLINE {
                let mut left = Vec::new();
                for space in pending {
                    if engine.reaches(&space).await {
                        engine.publish_list(space, &recovered.person).await?;
                    } else {
                        left.push(space);
                    }
                }
                pending = left;
                if !pending.is_empty() {
                    self.sleep(TICK).await;
                    waited += TICK;
                }
            }
            engine.end_recovery().await;
            self.keep_sealed_keys(&recovered.person, &recovered.sealed)
                .await?;
            Ok(recovered.sealed)
        }
    }

    /// Opens a device in `storage` and recovers it; a device that fails
    /// recovery or retaining its resealed keys is closed.
    async fn open_and_recover<'a, F, Fut>(
        storage: Storage,
        unlock_key: &[u8; 32],
        options: Options,
        recover: F,
    ) -> Result<Device>
    where
        F: FnOnce(Device) -> Fut,
        Fut: std::future::Future<Output = Result<[u8; SEALED_DEVICE_KEYS_BYTES]>> + 'a,
    {
        let device = Device::open_with(storage, unlock_key, options).await?;
        if let Err(error) = recover(device.clone()).await {
            let _ = device.close().await;
            return Err(error);
        }
        Ok(device)
    }

    /// Waits until the merged list holds the list member (identity.md,
    /// "Recovery", steps 1 to 4).
    async fn wait_for_list(device: &Device, peer: &Peer, personal: EventId) -> Result<()> {
        let engine = device.engine();
        let mut waited = Duration::ZERO;
        loop {
            if let Some((_, code)) = peer
                .handle()
                .status()
                .refused
                .iter()
                .find(|(space, _)| *space == personal)
            {
                return Err(match code.as_str() {
                    "credential_refused" => Error::Class("CredentialRefused"),
                    "no_library" => Error::Class("NotFound"),
                    _ => Error::Connection(code.clone()),
                });
            }
            if let Some(why) = peer.status().closed {
                return Err(Error::Connection(why));
            }
            // The list member signs only once the device holds all the peer
            // serves: a list event of its own that the device lacked would
            // make it sign a second event at one place of its chain, a fork
            // that voids it (identity.md, "Security considerations",
            // equivocation).
            let status = engine.recovery_status().await;
            let fetched = peer.handle().status().caught_up.contains(&personal);
            if status == RecoveryStatus::Ready && fetched {
                return Ok(());
            }
            if waited >= RECOVERY_DEADLINE {
                return Err(if status == RecoveryStatus::NotListed {
                    Error::Class("NotOnList")
                } else {
                    Error::Timeout
                });
            }
            device.sleep(TICK).await;
            waited += TICK;
        }
    }
}
