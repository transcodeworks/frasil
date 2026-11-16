//! Object providers for the tests (at-rest.md, "Held objects"): one over a
//! directory, whose tokens are file names and whose stamp is the content's
//! SHA-256, and one in memory, which the vectors drive.

#![allow(dead_code)]

use frasil::advanced::held::{ObjectProvider, ObjectReader, ObjectStat, ObjectWriter};
use frasil::{Error, Result, SpaceId};
use frasil_crypto::primitives::sha256;
use frasil_store::BoxFuture;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// What a provider was told.
#[derive(Debug, Default)]
pub struct Calls {
    /// The tokens `forget` named, in order.
    pub forgotten: Vec<Vec<u8>>,
    /// How many writers were aborted.
    pub aborted: usize,
    /// How many writers finished.
    pub finished: usize,
    /// How many writers were created.
    pub created: usize,
}

/// The stamp of a plaintext: its SHA-256's first 16 bytes.
pub fn stamp_of(bytes: &[u8]) -> Vec<u8> {
    sha256(&[bytes])[..16].to_vec()
}

// ---------------------------------------------------------------------------
// A directory.

/// A provider over a directory: a token is a file's name in it.
#[derive(Debug)]
pub struct DirProvider {
    pub dir: PathBuf,
    pub calls: Arc<Mutex<Calls>>,
}

impl DirProvider {
    pub fn new(dir: impl Into<PathBuf>) -> Arc<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(Self {
            dir,
            calls: Arc::new(Mutex::new(Calls::default())),
        })
    }

    pub fn path(&self, token: &[u8]) -> PathBuf {
        self.dir.join(String::from_utf8_lossy(token).as_ref())
    }

    /// Writes a file, and returns its token.
    pub fn write(&self, name: &str, bytes: &[u8]) -> Vec<u8> {
        std::fs::write(self.path(name.as_bytes()), bytes).unwrap();
        name.as_bytes().to_vec()
    }

    pub fn read(&self, token: &[u8]) -> Vec<u8> {
        std::fs::read(self.path(token)).unwrap()
    }

    /// How many files the directory holds.
    pub fn files(&self) -> usize {
        std::fs::read_dir(&self.dir).unwrap().count()
    }

    pub fn forgotten(&self) -> Vec<Vec<u8>> {
        self.calls.lock().unwrap().forgotten.clone()
    }
}

struct FileReader(PathBuf);

impl ObjectReader for FileReader {
    fn read_at<'a>(&'a mut self, offset: u64, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let bytes = std::fs::read(&self.0).map_err(|e| Error::Store(e.to_string()))?;
            let start = usize::try_from(offset).unwrap().min(bytes.len());
            let n = (bytes.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&bytes[start..start + n]);
            Ok(n)
        })
    }
}

struct FileWriter {
    dir: PathBuf,
    calls: Arc<Mutex<Calls>>,
    partial: PathBuf,
    name: String,
    bytes: Vec<u8>,
}

impl ObjectWriter for FileWriter {
    fn write<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.bytes.extend_from_slice(bytes);
            std::fs::write(&self.partial, &self.bytes).map_err(|e| Error::Store(e.to_string()))
        })
    }

    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<(Vec<u8>, Vec<u8>)>> {
        Box::pin(async move {
            let final_path = self.dir.join(&self.name);
            std::fs::rename(&self.partial, &final_path).map_err(|e| Error::Store(e.to_string()))?;
            self.calls.lock().unwrap().finished += 1;
            Ok((self.name.into_bytes(), stamp_of(&self.bytes)))
        })
    }

    fn abort(self: Box<Self>) -> BoxFuture<'static, Result<()>> {
        Box::pin(async move {
            let _ = std::fs::remove_file(&self.partial);
            self.calls.lock().unwrap().aborted += 1;
            Ok(())
        })
    }
}

impl ObjectProvider for DirProvider {
    fn stat<'a>(&'a self, token: &'a [u8]) -> BoxFuture<'a, Result<Option<ObjectStat>>> {
        Box::pin(async move {
            Ok(std::fs::read(self.path(token))
                .ok()
                .map(|bytes| ObjectStat {
                    size: bytes.len() as u64,
                    stamp: stamp_of(&bytes),
                }))
        })
    }

    fn open<'a>(&'a self, token: &'a [u8]) -> BoxFuture<'a, Result<Box<dyn ObjectReader>>> {
        Box::pin(async move { Ok(Box::new(FileReader(self.path(token))) as Box<dyn ObjectReader>) })
    }

    fn create<'a>(
        &'a self,
        _space: SpaceId,
        object_id: [u8; 32],
        _size: u64,
        hint: &'a [u8],
    ) -> BoxFuture<'a, Result<Box<dyn ObjectWriter>>> {
        Box::pin(async move {
            // A fresh name per create, so that two writers of one object
            // never share a file.
            let name = if hint.is_empty() {
                let n = self.calls.lock().unwrap().created;
                self.calls.lock().unwrap().created += 1;
                format!(
                    "object-{}-{n}",
                    frasil_testkit::hex::encode(&object_id[..8])
                )
            } else {
                String::from_utf8_lossy(hint).into_owned()
            };
            let partial = self.dir.join(format!("{name}.partial"));
            std::fs::write(&partial, b"").map_err(|e| Error::Store(e.to_string()))?;
            Ok(Box::new(FileWriter {
                dir: self.dir.clone(),
                calls: self.calls.clone(),
                partial,
                name,
                bytes: Vec::new(),
            }) as Box<dyn ObjectWriter>)
        })
    }

    fn forget<'a>(&'a self, token: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.calls.lock().unwrap().forgotten.push(token.to_vec());
            Ok(())
        })
    }
}

/// A fresh directory under the target's temporary directory.
pub fn temp_dir(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------------
// In memory, as the vectors model it.

/// Files by token, each with its stamp.
pub type Files = Arc<Mutex<BTreeMap<Vec<u8>, (Vec<u8>, Vec<u8>)>>>;

/// A file that changes after the first `stat`, as a vector models it: its
/// token, its new bytes and its new stamp.
pub type Later = Mutex<Option<(Vec<u8>, Vec<u8>, Vec<u8>)>>;

/// A provider in memory: files by token, each with its stamp given.
#[derive(Debug, Default)]
pub struct MemoryProvider {
    pub files: Files,
    pub calls: Arc<Mutex<Calls>>,
    /// A file that changes after the first `stat`, as a vector models it.
    pub later: Later,
    pub stats: Mutex<usize>,
}

impl MemoryProvider {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn put(&self, token: &[u8], bytes: &[u8], stamp: &[u8]) {
        self.files
            .lock()
            .unwrap()
            .insert(token.to_vec(), (bytes.to_vec(), stamp.to_vec()));
    }

    pub fn file(&self, token: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        self.files.lock().unwrap().get(token).cloned()
    }
}

struct MemoryReader(Vec<u8>);

impl ObjectReader for MemoryReader {
    fn read_at<'a>(&'a mut self, offset: u64, buf: &'a mut [u8]) -> BoxFuture<'a, Result<usize>> {
        Box::pin(async move {
            let start = usize::try_from(offset).unwrap().min(self.0.len());
            let n = (self.0.len() - start).min(buf.len());
            buf[..n].copy_from_slice(&self.0[start..start + n]);
            Ok(n)
        })
    }
}

struct MemoryWriter {
    files: Files,
    calls: Arc<Mutex<Calls>>,
    token: Vec<u8>,
    bytes: Vec<u8>,
}

impl ObjectWriter for MemoryWriter {
    fn write<'a>(&'a mut self, bytes: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.bytes.extend_from_slice(bytes);
            Ok(())
        })
    }

    fn finish(self: Box<Self>) -> BoxFuture<'static, Result<(Vec<u8>, Vec<u8>)>> {
        Box::pin(async move {
            let stamp = stamp_of(&self.bytes);
            self.files
                .lock()
                .unwrap()
                .insert(self.token.clone(), (self.bytes.clone(), stamp.clone()));
            self.calls.lock().unwrap().finished += 1;
            Ok((self.token, stamp))
        })
    }

    fn abort(self: Box<Self>) -> BoxFuture<'static, Result<()>> {
        Box::pin(async move {
            self.calls.lock().unwrap().aborted += 1;
            Ok(())
        })
    }
}

impl ObjectProvider for MemoryProvider {
    fn stat<'a>(&'a self, token: &'a [u8]) -> BoxFuture<'a, Result<Option<ObjectStat>>> {
        Box::pin(async move {
            let mut stats = self.stats.lock().unwrap();
            *stats += 1;
            if *stats > 1
                && let Some((changed, bytes, stamp)) = self.later.lock().unwrap().clone()
                && changed == token
            {
                self.put(token, &bytes, &stamp);
            }
            Ok(self.file(token).map(|(bytes, stamp)| ObjectStat {
                size: bytes.len() as u64,
                stamp,
            }))
        })
    }

    fn open<'a>(&'a self, token: &'a [u8]) -> BoxFuture<'a, Result<Box<dyn ObjectReader>>> {
        Box::pin(async move {
            let (bytes, _) = self.file(token).ok_or(Error::Class("Changed"))?;
            Ok(Box::new(MemoryReader(bytes)) as Box<dyn ObjectReader>)
        })
    }

    fn create<'a>(
        &'a self,
        _space: SpaceId,
        object_id: [u8; 32],
        _size: u64,
        hint: &'a [u8],
    ) -> BoxFuture<'a, Result<Box<dyn ObjectWriter>>> {
        Box::pin(async move {
            // The vectors' model: the hint, or "object/" and the ID's first
            // eight bytes in hex.
            let token = if hint.is_empty() {
                format!("object/{}", frasil_testkit::hex::encode(&object_id[..8])).into_bytes()
            } else {
                hint.to_vec()
            };
            Ok(Box::new(MemoryWriter {
                files: self.files.clone(),
                calls: self.calls.clone(),
                token,
                bytes: Vec::new(),
            }) as Box<dyn ObjectWriter>)
        })
    }

    fn forget<'a>(&'a self, token: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.calls.lock().unwrap().forgotten.push(token.to_vec());
            Ok(())
        })
    }
}
