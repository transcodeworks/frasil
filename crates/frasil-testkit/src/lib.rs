//! Test support for Frasil's crates, and, with the `devices` feature, for
//! the tests of applications built on the `frasil` crate.
//!
//! - [`vectors`] loads the specification's vector files,
//!   `docs/spec/vectors/*.json`, and gives typed access to their families by
//!   name. `docs/spec/vectors/README.md` describes the files.
//! - [`hex`] reads the lowercase hex the vector files use for byte strings.
//! - [`claims`] checks every crate's `claims.txt`, the list of vector families
//!   the crate proves.
//! - `devices`, with the `devices` feature: devices in memory on loopback,
//!   a space shared between two of them, and waits with a deadline, for an
//!   application's own tests through the `frasil` API.
//!
//! The testkit holds no peer: scenarios that need one run in the
//! `tests/conformance` crate.

pub mod claims;
#[cfg(feature = "devices")]
pub mod devices;
pub mod hex;
pub mod vectors;

use std::path::{Path, PathBuf};

/// The workspace's root directory.
pub fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("frasil-testkit lives two levels below the workspace root")
        .to_path_buf()
}

/// The directory of the specification's vector files.
pub fn vectors_dir() -> PathBuf {
    workspace_root().join("docs/spec/vectors")
}
