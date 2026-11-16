//! Where a peer keeps object chunks (peers.md, "Objects"): a directory on a
//! local filesystem, an S3-compatible bucket, or memory for tests. Each
//! backend stores opaque pieces by key; the peer's index of what it holds
//! is in its database.

use crate::config::S3Config;
use futures_util::future::BoxFuture;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};

/// A backend failed. The message never holds a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobError(pub String);

impl core::fmt::Display for BlobError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "object storage: {}", self.0)
    }
}

impl std::error::Error for BlobError {}

/// A store of opaque pieces by key. A key is ASCII: lowercase hex and `/`.
pub trait Blobs: Send + Sync {
    /// Stores a piece, durably when the future completes, replacing any
    /// piece under the key.
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Result<(), BlobError>>;

    /// The piece under a key, or `None`.
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BlobError>>;

    /// Deletes the piece under a key; deleting nothing succeeds.
    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BlobError>>;
}

/// Pieces in memory, lost when dropped. For tests.
#[derive(Debug, Default)]
pub struct MemoryBlobs {
    pieces: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryBlobs {
    /// No pieces.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many pieces it holds.
    pub fn len(&self) -> usize {
        self.pieces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Whether it holds no piece.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Blobs for MemoryBlobs {
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Result<(), BlobError>> {
        self.pieces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key.to_owned(), bytes);
        Box::pin(async { Ok(()) })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BlobError>> {
        let piece = self
            .pieces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(key)
            .cloned();
        Box::pin(async move { Ok(piece) })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BlobError>> {
        self.pieces
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(key);
        Box::pin(async { Ok(()) })
    }
}

/// Pieces as files under a directory: each written to a temporary file,
/// synced, then renamed into place.
#[derive(Debug, Clone)]
pub struct FileBlobs {
    root: PathBuf,
}

impl FileBlobs {
    /// Pieces under `root`, which is made if missing.
    ///
    /// # Errors
    ///
    /// If the directory cannot be made.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, BlobError> {
        std::fs::create_dir_all(root.as_ref()).map_err(|e| BlobError(e.to_string()))?;
        Ok(Self {
            root: root.as_ref().to_path_buf(),
        })
    }

    fn path(&self, key: &str) -> Result<PathBuf, BlobError> {
        if key.is_empty()
            || !key
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'/' || b.is_ascii_digit())
            || key.contains("//")
            || key.starts_with('/')
        {
            return Err(BlobError("a key outside the store".into()));
        }
        Ok(self.root.join(key))
    }
}

impl Blobs for FileBlobs {
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Result<(), BlobError>> {
        Box::pin(async move {
            let path = self.path(key)?;
            let error = |e: std::io::Error| BlobError(e.to_string());
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await.map_err(error)?;
            }
            let temporary = path.with_extension("partial");
            {
                use tokio::io::AsyncWriteExt;
                let mut file = tokio::fs::File::create(&temporary).await.map_err(error)?;
                file.write_all(&bytes).await.map_err(error)?;
                file.sync_all().await.map_err(error)?;
            }
            tokio::fs::rename(&temporary, &path).await.map_err(error)
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BlobError>> {
        Box::pin(async move {
            let path = self.path(key)?;
            match tokio::fs::read(&path).await {
                Ok(bytes) => Ok(Some(bytes)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(BlobError(e.to_string())),
            }
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BlobError>> {
        Box::pin(async move {
            let path = self.path(key)?;
            match tokio::fs::remove_file(&path).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(BlobError(e.to_string())),
            }
        })
    }
}

/// Pieces in an S3-compatible bucket (B2 included), under the configured
/// prefix. Pieces are at most 1 MiB, so each is one `PUT`.
pub struct S3Blobs {
    bucket: Box<s3::Bucket>,
    prefix: String,
}

impl core::fmt::Debug for S3Blobs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("S3Blobs")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

impl S3Blobs {
    /// A bucket's client. The endpoint is HTTPS, or HTTP on loopback.
    ///
    /// # Errors
    ///
    /// For an endpoint, bucket or credentials that do not read.
    pub fn open(config: &S3Config) -> Result<Self, BlobError> {
        Ok(Self {
            bucket: s3_client(config)?,
            prefix: config.prefix.clone(),
        })
    }

    fn key(&self, key: &str) -> String {
        format!("{}{key}", self.prefix)
    }
}

/// A client for an S3-compatible bucket. The endpoint is HTTPS, or HTTP on
/// loopback.
///
/// # Errors
///
/// For an endpoint, bucket or credentials that do not read.
pub(crate) fn s3_client(config: &S3Config) -> Result<Box<s3::Bucket>, BlobError> {
    let endpoint = config.endpoint.as_str();
    let loopback = ["http://127.0.0.1", "http://localhost", "http://[::1]"]
        .iter()
        .any(|prefix| {
            endpoint
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with([':', '/']))
        });
    if !(endpoint.starts_with("https://") || loopback) || endpoint.contains(['@', '?', '#']) {
        return Err(BlobError("the S3 endpoint is not HTTPS".into()));
    }
    if config.bucket.is_empty() || config.access_key.is_empty() || config.secret_key.is_empty() {
        return Err(BlobError("an S3 bucket and credentials are needed".into()));
    }
    let credentials = s3::creds::Credentials::new(
        Some(&config.access_key),
        Some(&config.secret_key),
        None,
        None,
        None,
    )
    .map_err(|_| BlobError("the S3 credentials do not read".into()))?;
    let region = s3::Region::Custom {
        region: config.region.clone(),
        endpoint: config.endpoint.clone(),
    };
    let mut bucket = s3::Bucket::new(&config.bucket, region, credentials)
        .map_err(|_| BlobError("the S3 configuration does not read".into()))?;
    if config.path_style {
        bucket = bucket.with_path_style();
    }
    bucket.set_request_timeout(Some(std::time::Duration::from_secs(30)));
    Ok(bucket)
}

fn s3_failed(status: u16) -> BlobError {
    BlobError(format!("S3 answered {status}"))
}

impl Blobs for S3Blobs {
    fn put<'a>(&'a self, key: &'a str, bytes: Vec<u8>) -> BoxFuture<'a, Result<(), BlobError>> {
        Box::pin(async move {
            let response = self
                .bucket
                .put_object(self.key(key), &bytes)
                .await
                .map_err(|_| BlobError("an S3 PUT failed".into()))?;
            match response.status_code() {
                200..=299 => Ok(()),
                status => Err(s3_failed(status)),
            }
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>, BlobError>> {
        Box::pin(async move {
            let response = self
                .bucket
                .get_object(self.key(key))
                .await
                .map_err(|_| BlobError("an S3 GET failed".into()))?;
            match response.status_code() {
                200..=299 => Ok(Some(response.bytes().to_vec())),
                404 => Ok(None),
                status => Err(s3_failed(status)),
            }
        })
    }

    fn delete<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), BlobError>> {
        Box::pin(async move {
            let response = self
                .bucket
                .delete_object(self.key(key))
                .await
                .map_err(|_| BlobError("an S3 DELETE failed".into()))?;
            match response.status_code() {
                200..=299 | 404 => Ok(()),
                status => Err(s3_failed(status)),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn files_round_trip_and_refuse_keys_outside_the_root() {
        let root = std::env::temp_dir().join(format!(
            "frasil-relay-blobs-{}",
            crate::util::hex(&*frasil_crypto::random_bytes::<8>().unwrap())
        ));
        let blobs = FileBlobs::open(&root).unwrap();
        blobs.put("ab/cd/0", b"piece".to_vec()).await.unwrap();
        assert_eq!(
            blobs.get("ab/cd/0").await.unwrap().as_deref(),
            Some(&b"piece"[..])
        );
        blobs.delete("ab/cd/0").await.unwrap();
        assert_eq!(blobs.get("ab/cd/0").await.unwrap(), None);
        blobs.delete("ab/cd/0").await.unwrap();
        assert!(blobs.get("../x").await.is_err());
        assert!(blobs.get("/etc").await.is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn s3_refuses_plain_http_off_loopback() {
        let config = S3Config {
            endpoint: "http://s3.example.org".into(),
            region: "auto".into(),
            bucket: "b".into(),
            access_key: "a".into(),
            secret_key: "s".into(),
            prefix: String::new(),
            path_style: true,
        };
        assert!(S3Blobs::open(&config).is_err());
        let loopback = S3Config {
            endpoint: "http://127.0.0.1:9000".into(),
            ..config
        };
        assert!(S3Blobs::open(&loopback).is_ok());
    }
}
