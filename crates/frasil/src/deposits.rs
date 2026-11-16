//! A device's own records of no log for deposits in device mailboxes
//! (at-rest.md, "Tables"): the deposits a peer has not accepted yet
//! (transport.md, "A sender keeps what was refused"), and, with deposit
//! tokens, each peer's keys and the tokens the device holds
//! (ext-deposit-tokens.md).

use crate::at_rest::Batch;
use crate::device::Engine;
use crate::error::Result;
use frasil_store::{Table, TableValue};

/// A device-wide record to put: its table, its item and its value.
pub(crate) type DevicePut = (Table, Vec<u8>, TableValue);

impl Engine {
    /// Every record of a device-wide table that opens, with its item.
    pub(crate) async fn device_records(&self, table: Table) -> Result<Vec<(Vec<u8>, TableValue)>> {
        let state = self.lock().await;
        state.vault.scan_device(table).await
    }

    /// One record of a device-wide table, by its item.
    #[cfg_attr(not(feature = "ext-deposit-tokens"), allow(dead_code))]
    pub(crate) async fn device_record(
        &self,
        table: Table,
        item: &[u8],
    ) -> Result<Option<TableValue>> {
        let state = self.lock().await;
        state.vault.get_device_item(table, item).await
    }

    /// Deletes and puts device-wide records in one commit: its deletes
    /// first (at-rest.md, "Committing").
    pub(crate) async fn commit_device(
        &self,
        puts: Vec<DevicePut>,
        deletes: Vec<(Table, Vec<u8>)>,
    ) -> Result<()> {
        let mut state = self.lock().await;
        let mut batch = Batch::default();
        for (table, item) in &deletes {
            state.vault.delete_device(&mut batch, *table, item);
        }
        for (table, item, value) in &puts {
            state.vault.put_device(&mut batch, *table, item, value)?;
        }
        state.vault.commit(batch).await
    }
}
