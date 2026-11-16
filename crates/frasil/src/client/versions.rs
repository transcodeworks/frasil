//! Named versions (decision: a client toolkit): a synced tag on a
//! frontier of a document, or on a change of a table, kept in a Records
//! stream of Frasil's own in the space.
//!
//! The versions stream is a Records stream (adapter-records.md) whose
//! opening every member derives from the space's ID, so that no registry
//! names it: `frasil:records` with the salt
//! `SHA-256("frasil:versions" || space ID)[..16]`. It holds one table,
//! `versions`, one row per tag: the stream tagged, the name, the version
//! (a Loro frontier, or a change's ID), the device that tagged, and the
//! time its clock gave, shown and never checked. A tag travels as any
//! change does, and every member reads it; a writer removes one.

use crate::client::streams::{Records, Transaction};
use crate::client::{MemberId, SpaceId, StreamId, UnitId, VersionId};
use crate::error::{Error, Result};
use frasil_base::cbor::Value;
use frasil_crypto::primitives::sha256;
use frasil_units::stream::Opening;
use std::collections::BTreeMap;

/// The table of the versions stream.
const TABLE: &str = "versions";

/// What a version marks.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Marked {
    /// A Loro document at a frontier, as [`Document::at`](crate::Document::at) reads it.
    #[cfg(feature = "adapter-loro")]
    Document(loro::Frontiers),
    /// Records tables after a change, as [`Records::at`](crate::Records::at) replays them.
    Records(UnitId),
}

/// A named version: a tag a member put on a stream's version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// The tag's ID: its row's key.
    pub id: VersionId,
    /// The stream it marks.
    pub stream: StreamId,
    /// Its name: shown, never checked.
    pub name: String,
    /// What it marks.
    pub marked: Marked,
    /// The device that tagged.
    pub author: MemberId,
    /// When, by the tagging device's clock, in seconds since 1970, when
    /// that clock was known: shown, never checked.
    pub time: Option<u64>,
}

/// The opening of a space's versions stream.
pub(crate) fn opening(space: SpaceId) -> Opening {
    let digest = sha256(&[b"frasil:versions", space.as_bytes()]);
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&digest[..16]);
    Opening::with_salt(frasil_adapter_records::TYPE, salt)
}

fn bytes_of(value: &Value) -> Option<&[u8]> {
    value.as_bytes().ok()
}

fn version_of(key: &[u8], row: &BTreeMap<String, Value>) -> Option<Version> {
    let mut id = [0u8; 16];
    if key.len() != 16 {
        return None;
    }
    id.copy_from_slice(key);
    let stream = bytes_of(row.get("stream")?)?;
    let stream = StreamId::from_bytes(stream.try_into().ok()?);
    let name = row.get("name")?.as_text().ok()?.to_string();
    let author = bytes_of(row.get("device")?)?;
    let author = MemberId::from_bytes(author.try_into().ok()?);
    let time = row.get("time").and_then(|t| t.as_unsigned().ok());
    let marked = match row.get("frontier").and_then(bytes_of) {
        #[cfg(feature = "adapter-loro")]
        Some(frontier) => Marked::Document(loro::Frontiers::decode(frontier).ok()?),
        // A document's version, which a build without Loro does not read.
        #[cfg(not(feature = "adapter-loro"))]
        Some(_) => return None,
        None => {
            let change = bytes_of(row.get("change")?)?;
            Marked::Records(UnitId::from_bytes(change.try_into().ok()?))
        }
    };
    Some(Version {
        id: VersionId::from_bytes(id),
        stream,
        name,
        marked,
        author,
        time,
    })
}

impl crate::client::Space {
    /// The space's versions stream: a Records stream of Frasil's own,
    /// which [`Space::streams`](crate::Space::streams) lists as Records
    /// once a tag is written. Applications leave it to Frasil.
    pub fn versions_stream(&self) -> StreamId {
        StreamId::from_bytes(opening(self.id()).stream())
    }

    /// The versions stream as Records, held: a partial replica holds it
    /// as it holds any stream it opens.
    pub(crate) async fn versions_records(&self) -> Result<Records> {
        let opening = opening(self.id());
        self.device
            .engine()
            .hold_stream(self.id().event(), opening.stream())
            .await?;
        Ok(Records {
            space: self.clone(),
            opening,
        })
    }

    /// Every version tagged in the space, oldest first by name then ID.
    ///
    /// # Errors
    ///
    /// [`Error::UnknownSpace`].
    pub async fn versions(&self) -> Result<Vec<Version>> {
        let rows = match self.versions_records().await?.rows(TABLE).await {
            Ok(rows) => rows,
            Err(Error::UnknownStream) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut versions: Vec<Version> = rows
            .iter()
            .filter_map(|(key, row)| version_of(key, row))
            .collect();
        versions.sort_by(|a, b| (&a.name, a.id).cmp(&(&b.name, b.id)));
        Ok(versions)
    }

    /// Removes a tag: a writer's change to the versions stream.
    ///
    /// # Errors
    ///
    /// As [`Records::write`](crate::Records::write).
    pub async fn untag(&self, version: VersionId) -> Result<()> {
        self.versions_records()
            .await?
            .write(|t| {
                t.delete(TABLE, version.as_bytes());
            })
            .await
    }

    /// Tags: a row of the versions table.
    pub(crate) async fn tag(
        &self,
        stream: StreamId,
        name: &str,
        marked: &Marked,
    ) -> Result<Version> {
        if name.is_empty() || name.len() > 256 {
            return Err(Error::Invalid("a version's name is 1 to 256 bytes"));
        }
        let key: [u8; 16] = self.device().engine().nonce()?;
        let author = self.device().id();
        let time = self.device().engine().wall_clock();
        let mut transaction = Transaction::default();
        transaction.insert(TABLE, &key);
        transaction.set(
            TABLE,
            &key,
            "stream",
            Value::from(stream.as_bytes().to_vec()),
        );
        transaction.set(TABLE, &key, "name", Value::from(name));
        transaction.set(
            TABLE,
            &key,
            "device",
            Value::from(author.as_bytes().to_vec()),
        );
        if let Some(time) = time {
            transaction.set(TABLE, &key, "time", Value::from(time));
        }
        match marked {
            #[cfg(feature = "adapter-loro")]
            Marked::Document(frontier) => {
                transaction.set(TABLE, &key, "frontier", Value::from(frontier.encode()));
            }
            Marked::Records(change) => {
                transaction.set(
                    TABLE,
                    &key,
                    "change",
                    Value::from(change.as_bytes().to_vec()),
                );
            }
        }
        self.versions_records()
            .await?
            .write_transaction(transaction)
            .await?;
        Ok(Version {
            id: VersionId::from_bytes(key),
            stream,
            name: name.to_string(),
            marked: marked.clone(),
            author,
            time,
        })
    }
}

#[cfg(feature = "adapter-loro")]
impl crate::client::streams::Document {
    /// Tags the document as it stands at this device, by name: a synced
    /// version every member sees and reads with [`Document::at`](Self::at).
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a name of 0 or over 256 bytes; as
    /// [`Records::write`](crate::Records::write).
    pub async fn tag(&self, name: &str) -> Result<Version> {
        let frontier = match self.read().await {
            Ok(doc) => doc.oplog_frontiers(),
            Err(error) => return Err(error),
        };
        self.space
            .tag(self.id(), name, &Marked::Document(frontier))
            .await
    }

    /// The versions tagged on this document.
    ///
    /// # Errors
    ///
    /// As [`Space::versions`](crate::Space::versions).
    pub async fn versions(&self) -> Result<Vec<Version>> {
        let id = self.id();
        Ok(self
            .space
            .versions()
            .await?
            .into_iter()
            .filter(|version| version.stream == id)
            .collect())
    }
}

impl Records {
    /// Tags the tables as they stand at this device, by name: the latest
    /// change this device holds of them, which
    /// [`Records::at`](Self::at) replays.
    ///
    /// # Errors
    ///
    /// [`Error::Invalid`] for a name of 0 or over 256 bytes, or tables with
    /// no change yet; as [`Records::write`](Self::write).
    pub async fn tag(&self, name: &str) -> Result<Version> {
        let last = self
            .history()
            .await?
            .into_iter()
            .next_back()
            .ok_or(Error::Invalid("the tables have no change to tag"))?;
        self.space
            .tag(self.id(), name, &Marked::Records(last.id))
            .await
    }

    /// The versions tagged on these tables.
    ///
    /// # Errors
    ///
    /// As [`Space::versions`](crate::Space::versions).
    pub async fn versions(&self) -> Result<Vec<Version>> {
        let id = self.id();
        Ok(self
            .space
            .versions()
            .await?
            .into_iter()
            .filter(|version| version.stream == id)
            .collect())
    }
}
