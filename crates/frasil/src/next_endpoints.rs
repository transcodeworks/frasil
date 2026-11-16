//! Announced next endpoints (ext-next-endpoints.md), feature
//! `ext-next-endpoints`.
//!
//! A device keeps the seed of its next member endpoint key in the
//! device-wide `next_endpoint` table. Each time the node binds its member
//! endpoint, which is a rotation, it takes that seed, draws and keeps the
//! next, and only then binds ("Rotating"). Member connections tell each
//! member admitted on an attach the next key in a `NextEndpoint`
//! ("Announcing"); the member keeps it in the space's `announced` table,
//! beside the ticket it keeps of the device ("Receiving"), and dials the
//! kept ticket under it when it reconnects ("Reconnecting"). When the
//! membership of a device it has admitted ends, the device replaces its
//! next seed, so the former member never learns the key it takes.

use crate::at_rest::Batch;
use crate::device::Engine;
use crate::error::Result;
use frasil_crypto::device::DeviceId;
use frasil_crypto::primitives::ed25519_public;
use frasil_events::EventId;
use frasil_store::Table;
use frasil_store::tables::{Secret, TableValue};
use zeroize::Zeroizing;

impl Engine {
    /// A rotation (ext-next-endpoints.md, "Rotating"): the seed the member
    /// endpoint binds under, the kept next seed if there is one, else a
    /// fresh one. A fresh next seed is kept first, durably, and its key is
    /// the one announced from now on.
    ///
    /// # Errors
    ///
    /// [`crate::Error::NoRandomness`], or the store's.
    pub(crate) async fn rotate_member_endpoint(&self) -> Result<Zeroizing<[u8; 32]>> {
        let next = self.platform().draw::<32>()?;
        let mut state = self.lock().await;
        let current = match state.vault.get_device(Table::NextEndpoint).await? {
            Some(TableValue::NextEndpoint(seed)) if seed.expose() != &*next => {
                Zeroizing::new(*seed.expose())
            }
            _ => self.platform().draw::<32>()?,
        };
        keep_next(&mut state.vault, &next).await?;
        drop(state);
        self.links().set_next_endpoint(ed25519_public(&next));
        Ok(current)
    }

    /// Withdraws the announced key ("Announcing", withdrawing): a fresh
    /// next seed replaces it, and member connections announce the new key.
    ///
    /// # Errors
    ///
    /// [`crate::Error::NoRandomness`], or the store's.
    pub(crate) async fn withdraw_next_endpoint(&self) -> Result<()> {
        let next = self.platform().draw::<32>()?;
        let mut state = self.lock().await;
        keep_next(&mut state.vault, &next).await?;
        drop(state);
        self.links().set_next_endpoint(ed25519_public(&next));
        Ok(())
    }

    /// The key this device announces as its next, once its member endpoint
    /// has bound.
    pub(crate) fn next_endpoint_key(&self) -> Option<[u8; 32]> {
        self.links().next_endpoint()
    }

    /// Keeps the next key a member announced in a space, beside the ticket
    /// the device keeps of that member ("Receiving", step 5); nothing when
    /// it keeps no ticket of the member there.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn remember_announced(
        &self,
        space: &EventId,
        member: &DeviceId,
        key: [u8; 32],
    ) -> Result<()> {
        let mut state = self.lock().await;
        if !state.vault.has_log(&space.0) {
            return Ok(());
        }
        if state
            .vault
            .get(&space.0, Table::Endpoint, &member.0)
            .await?
            .is_none()
        {
            return Ok(());
        }
        let value = TableValue::Announced(key);
        if state
            .vault
            .get(&space.0, Table::Announced, &member.0)
            .await?
            == Some(value.clone())
        {
            return Ok(());
        }
        let mut batch = Batch::default();
        state
            .vault
            .put(&mut batch, &space.0, Table::Announced, &member.0, &value)?;
        state.vault.commit(batch).await
    }

    /// The next key a member announced in a space, if the device keeps one.
    ///
    /// # Errors
    ///
    /// The store's.
    pub(crate) async fn announced(
        &self,
        space: &EventId,
        member: &DeviceId,
    ) -> Result<Option<[u8; 32]>> {
        let state = self.lock().await;
        if !state.vault.has_log(&space.0) {
            return Ok(None);
        }
        Ok(
            match state
                .vault
                .get(&space.0, Table::Announced, &member.0)
                .await?
            {
                Some(TableValue::Announced(key)) => Some(key),
                _ => None,
            },
        )
    }
}

/// Replaces the `next_endpoint` record with this seed, in a commit of its
/// own.
async fn keep_next(vault: &mut crate::at_rest::Vault, next: &[u8; 32]) -> Result<()> {
    let value = Zeroizing::new(TableValue::NextEndpoint(Secret::new(*next)).encode());
    let (address, record) = vault.seal(None, Table::NextEndpoint, &[], &value)?;
    let mut batch = Batch::default();
    batch.puts.push((address, record));
    vault.commit(batch).await
}
