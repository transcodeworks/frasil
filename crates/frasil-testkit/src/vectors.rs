//! The specification's vector files, `docs/spec/vectors/*.json`.
//!
//! Each file is one JSON object. Its top-level keys are families, apart from
//! a few metadata keys ([`is_metadata`]). Each document's "Test vectors"
//! section lists its file's families.
//!
//! A file as written keeps each long byte string once, in its `blobs`
//! list; [`expand`] puts them back in place, and every loader here hands
//! out the expanded file. `docs/spec/vectors/README.md` describes the form.

use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use std::path::{Path, PathBuf};

/// The 26 vector files, one per document of the specification, in the order
/// of `docs/spec/vectors/README.md`.
pub const FILES: [&str; 26] = [
    "overview.json",
    "crypto.json",
    "events.json",
    "identity.json",
    "roster.json",
    "keys.json",
    "units.json",
    "transport.json",
    "peers.json",
    "admission.json",
    "at-rest.json",
    "ext-invite-links.json",
    "ext-guests.json",
    "ext-restricted-spaces.json",
    "ext-recovery-agent.json",
    "ext-ephemeral.json",
    "ext-libraries.json",
    "ext-deposit-tokens.json",
    "ext-app-requests.json",
    "ext-drive.json",
    "ext-space-files.json",
    "ext-file-versions.json",
    "ext-next-endpoints.json",
    "adapter-loro.json",
    "adapter-records.json",
    "adapter-blobs.json",
];

/// Top-level keys that describe a file rather than hold a family.
const METADATA: [&str; 5] = [
    "specification",
    "construction",
    "version",
    "protocol",
    "note",
];

/// Whether a file's top-level key is metadata rather than a family:
/// `specification`, `construction`, `version`, `protocol` and `note`, and
/// `units` when it is a string (`overview.json` names its unit of time).
pub fn is_metadata(key: &str, value: &Value) -> bool {
    METADATA.contains(&key) || (key == "units" && value.is_string())
}

/// Why a vector file or family could not be read.
#[derive(Debug)]
pub enum VectorError {
    /// The file could not be read.
    Io {
        /// The file's path.
        path: PathBuf,
        /// The underlying error.
        error: std::io::Error,
    },
    /// The file is not a JSON object.
    Json {
        /// The file's path.
        path: PathBuf,
        /// The underlying error, if the JSON did not parse.
        error: Option<serde_json::Error>,
    },
    /// The file has no family of that name.
    NoFamily {
        /// The file's name.
        file: String,
        /// The family asked for.
        family: String,
    },
    /// A blob reference or the `blobs` list is not as
    /// `docs/spec/vectors/README.md` describes.
    Blobs {
        /// The file's name.
        file: String,
        /// What is wrong.
        error: BlobError,
    },
    /// The family does not have the shape asked for.
    Shape {
        /// The file's name.
        file: String,
        /// The family.
        family: String,
        /// The underlying error.
        error: serde_json::Error,
    },
}

impl std::fmt::Display for VectorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, error } => write!(f, "{}: {error}", path.display()),
            Self::Json {
                path,
                error: Some(error),
            } => write!(f, "{}: {error}", path.display()),
            Self::Json { path, error: None } => {
                write!(f, "{}: not a JSON object", path.display())
            }
            Self::NoFamily { file, family } => write!(f, "{file} has no family `{family}`"),
            Self::Blobs { file, error } => write!(f, "{file}: {error}"),
            Self::Shape {
                file,
                family,
                error,
            } => write!(f, "{file} `{family}`: {error}"),
        }
    }
}

impl std::error::Error for VectorError {}

/// One vector file.
#[derive(Debug, Clone)]
pub struct VectorFile {
    name: String,
    root: Map<String, Value>,
}

impl VectorFile {
    /// Loads a file of [`vectors_dir`](crate::vectors_dir) by its name, such
    /// as `crypto.json`.
    pub fn load(name: &str) -> Result<Self, VectorError> {
        Self::load_from(&crate::vectors_dir(), name)
    }

    /// Loads a file by its name from another directory.
    pub fn load_from(dir: &Path, name: &str) -> Result<Self, VectorError> {
        let path = dir.join(name);
        let text = std::fs::read_to_string(&path).map_err(|error| VectorError::Io {
            path: path.clone(),
            error,
        })?;
        Self::parse(name, &text).map_err(|error| match error {
            VectorError::Json { error, .. } => VectorError::Json { path, error },
            other => other,
        })
    }

    /// Reads a file's text, under the given name.
    pub fn parse(name: &str, text: &str) -> Result<Self, VectorError> {
        let json_error = |error| VectorError::Json {
            path: PathBuf::from(name),
            error,
        };
        let value: Value = serde_json::from_str(text).map_err(|error| json_error(Some(error)))?;
        if !value.is_object() {
            return Err(json_error(None));
        }
        match expand(value) {
            Ok(Value::Object(root)) => Ok(Self {
                name: name.to_owned(),
                root,
            }),
            Ok(_) => Err(json_error(None)),
            Err(error) => Err(VectorError::Blobs {
                file: name.to_owned(),
                error,
            }),
        }
    }

    /// The file's name, such as `crypto.json`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The families, sorted by name, without the file's metadata.
    pub fn families(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.root
            .iter()
            .filter(|(key, value)| !is_metadata(key, value))
            .map(|(key, value)| (key.as_str(), value))
    }

    /// The families' names, sorted.
    pub fn family_names(&self) -> Vec<&str> {
        self.families().map(|(name, _)| name).collect()
    }

    /// Whether the file has a family of this name.
    pub fn has_family(&self, family: &str) -> bool {
        self.root
            .get(family)
            .is_some_and(|value| !is_metadata(family, value))
    }

    /// One family's raw JSON.
    pub fn family(&self, family: &str) -> Result<&Value, VectorError> {
        self.root
            .get(family)
            .filter(|value| !is_metadata(family, value))
            .ok_or_else(|| VectorError::NoFamily {
                file: self.name.clone(),
                family: family.to_owned(),
            })
    }

    /// One family, read into a type of the caller's.
    pub fn family_as<T: DeserializeOwned>(&self, family: &str) -> Result<T, VectorError> {
        T::deserialize(self.family(family)?).map_err(|error| VectorError::Shape {
            file: self.name.clone(),
            family: family.to_owned(),
            error,
        })
    }

    /// One metadata value, such as `specification`.
    pub fn metadata(&self, key: &str) -> Option<&Value> {
        self.root.get(key).filter(|value| is_metadata(key, value))
    }

    /// The whole file, expanded: families and metadata.
    pub fn root(&self) -> &Map<String, Value> {
        &self.root
    }
}

/// The top-level key of a file's long byte strings.
pub const BLOBS: &str = "blobs";

/// Why a file's blobs could not be expanded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobError {
    /// `blobs` is not a list of strings.
    NotAList,
    /// Entry `index` of `blobs` is not base64 with padding.
    NotBase64 {
        /// The entry.
        index: usize,
    },
    /// A reference names an entry `blobs` does not have.
    NoEntry {
        /// The entry named.
        index: u64,
    },
    /// A reference `{"blob": n}` whose `n` is not a whole number.
    BadReference,
}

impl std::fmt::Display for BlobError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAList => write!(f, "`{BLOBS}` is not a list of strings"),
            Self::NotBase64 { index } => write!(f, "`{BLOBS}` entry {index} is not base64"),
            Self::NoEntry { index } => write!(f, "no `{BLOBS}` entry {index}"),
            Self::BadReference => write!(f, "a blob reference without an entry number"),
        }
    }
}

impl std::error::Error for BlobError {}

/// A file as written, expanded into the JSON it stands for
/// (`docs/spec/vectors/README.md`, "Long byte strings"): the top-level
/// `blobs` list, base64 with padding, is taken out, and each object
/// `{"blob": n}` becomes the lowercase hex of entry `n`. A value with no
/// `blobs` is returned as it is, apart from any reference, which then
/// names no entry.
///
/// # Errors
///
/// [`BlobError`] for a `blobs` that is not a list of base64 strings, or a
/// reference that names no entry.
pub fn expand(mut file: Value) -> Result<Value, BlobError> {
    let blobs = match file.as_object_mut().and_then(|root| root.remove(BLOBS)) {
        None => Vec::new(),
        Some(Value::Array(entries)) => entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let text = entry.as_str().ok_or(BlobError::NotAList)?;
                base64_decode(text)
                    .map(crate::hex::encode)
                    .ok_or(BlobError::NotBase64 { index })
            })
            .collect::<Result<_, _>>()?,
        Some(_) => return Err(BlobError::NotAList),
    };
    put_back(&mut file, &blobs)?;
    Ok(file)
}

fn put_back(value: &mut Value, blobs: &[String]) -> Result<(), BlobError> {
    match value {
        Value::Object(map) if map.len() == 1 && map.contains_key("blob") => {
            let index = map["blob"].as_u64().ok_or(BlobError::BadReference)?;
            let entry = usize::try_from(index)
                .ok()
                .and_then(|i| blobs.get(i))
                .ok_or(BlobError::NoEntry { index })?;
            *value = Value::String(entry.clone());
        }
        Value::Object(map) => {
            for item in map.values_mut() {
                put_back(item, blobs)?;
            }
        }
        Value::Array(items) => {
            for item in items {
                put_back(item, blobs)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Base64 with padding (RFC 4648, section 4), strictly: a multiple of four
/// characters, padding only at the end, and no stray bits.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    fn digit(c: u8) -> Option<u32> {
        Some(u32::from(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        }))
    }
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let quads = bytes.chunks_exact(4);
    let last = quads.len().checked_sub(1);
    for (i, quad) in quads.enumerate() {
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && Some(i) != last) {
            return None;
        }
        let mut n = 0u32;
        for &c in &quad[..4 - pad] {
            n = (n << 6) | digit(c)?;
        }
        n <<= 6 * pad;
        let [_, a, b, c] = n.to_be_bytes();
        let kept = 3 - pad;
        if [a, b, c][kept..].iter().any(|&x| x != 0) {
            return None;
        }
        out.extend_from_slice(&[a, b, c][..kept]);
    }
    Some(out)
}

/// Loads every file of [`FILES`].
pub fn load_all() -> Result<Vec<VectorFile>, VectorError> {
    FILES.iter().map(|name| VectorFile::load(name)).collect()
}

/// Loads one family, read into a type of the caller's, and panics with the
/// file and family named if it cannot. For tests.
pub fn family<T: DeserializeOwned>(file: &str, family: &str) -> T {
    VectorFile::load(file)
        .and_then(|vectors| vectors.family_as(family))
        .unwrap_or_else(|error| panic!("{error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{"specification":"x.md","units":"seconds","note":"n",
        "cases":[{"a":"00"}],"history_free":"a301","online":300}"#;

    #[test]
    fn separates_families_from_metadata() {
        let file = VectorFile::parse("x.json", SAMPLE).unwrap();
        assert_eq!(file.family_names(), ["cases", "history_free", "online"]);
        assert_eq!(file.metadata("specification"), Some(&Value::from("x.md")));
        assert!(file.family("specification").is_err());
        assert!(file.family("units").is_err());
        assert!(file.has_family("cases"));
        assert!(!file.has_family("note"));
    }

    #[test]
    fn units_holding_a_family_is_a_family() {
        let file = VectorFile::parse("y.json", r#"{"units":[1,2]}"#).unwrap();
        assert_eq!(file.family_names(), ["units"]);
    }

    #[test]
    fn reads_a_family_into_a_type() {
        #[derive(serde::Deserialize)]
        struct Case {
            #[serde(deserialize_with = "crate::hex::bytes")]
            a: Vec<u8>,
        }
        let file = VectorFile::parse("x.json", SAMPLE).unwrap();
        let cases: Vec<Case> = file.family_as("cases").unwrap();
        assert_eq!(cases[0].a, vec![0]);
        assert!(matches!(
            file.family_as::<Vec<Case>>("online"),
            Err(VectorError::Shape { .. })
        ));
        assert!(matches!(
            file.family_as::<Value>("absent"),
            Err(VectorError::NoFamily { .. })
        ));
    }

    #[test]
    fn expands_blobs_in_place() {
        let text = r#"{"cases":[{"a":{"blob":1},"b":{"blob":0}}],"note":"n",
            "blobs":["AAEC","/w=="]}"#;
        let file = VectorFile::parse("b.json", text).unwrap();
        assert_eq!(file.family_names(), ["cases"]);
        assert_eq!(
            file.family("cases").unwrap(),
            &serde_json::json!([{"a": "ff", "b": "000102"}])
        );
        let plain = serde_json::json!({"cases": [{"blob": "x", "c": 1}]});
        assert_eq!(expand(plain.clone()), Ok(plain));
    }

    #[test]
    fn refuses_bad_blobs() {
        let read = |text: &str| expand(serde_json::from_str(text).unwrap());
        assert_eq!(
            read(r#"{"a":{"blob":2},"blobs":["AA=="]}"#),
            Err(BlobError::NoEntry { index: 2 })
        );
        assert_eq!(
            read(r#"{"a":{"blob":0}}"#),
            Err(BlobError::NoEntry { index: 0 })
        );
        assert_eq!(
            read(r#"{"a":{"blob":"0"},"blobs":[]}"#),
            Err(BlobError::BadReference)
        );
        assert_eq!(read(r#"{"blobs":"AA=="}"#), Err(BlobError::NotAList));
        for bad in ["AA=", "AB==", "A===", "AA==AA==", "AA-A", "AA=A"] {
            let text = format!(r#"{{"blobs":["{bad}"]}}"#);
            assert_eq!(read(&text), Err(BlobError::NotBase64 { index: 0 }), "{bad}");
        }
        assert!(VectorFile::parse("c.json", r#"{"a":{"blob":0}}"#).is_err());
    }

    #[test]
    fn decodes_base64() {
        for (text, bytes) in [
            ("", &b""[..]),
            ("Zg==", b"f"),
            ("Zm8=", b"fo"),
            ("Zm9v", b"foo"),
            ("Zm9vYg==", b"foob"),
            ("Zm9vYmE=", b"fooba"),
            ("Zm9vYmFy", b"foobar"),
            ("+/8=", &[0xfb, 0xff][..]),
        ] {
            assert_eq!(base64_decode(text).as_deref(), Some(bytes), "{text}");
        }
    }

    #[test]
    fn refuses_a_file_that_is_not_an_object() {
        assert!(VectorFile::parse("z.json", "[1]").is_err());
        assert!(VectorFile::parse("z.json", "{").is_err());
    }
}
