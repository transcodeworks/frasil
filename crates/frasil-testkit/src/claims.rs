//! The vector claims check.
//!
//! Each crate lists the vector families it proves in a `claims.txt` beside
//! its `Cargo.toml`, one per line:
//!
//! ```text
//! # comment
//! crypto.json ed25519_keys
//! crypto.json x25519_keys   # a comment may follow a claim
//! [ext-invite-links] ext-invite-links.json drops
//! ```
//!
//! A claim that begins `[feature]` is proved only when the crate is built
//! with that feature. The claiming crate must declare the feature, and this
//! crate must know it ([`FEATURES`]). The check verifies such a claim, and
//! counts its family as claimed, only when this crate is built with the same
//! feature, so `--all-features` verifies every claim; otherwise it reads the
//! claim and leaves its family alone.
//!
//! The check fails when a line is not `[feature] <file.json> <family>` or
//! `<file.json> <family>`, when a feature is unknown or undeclared, when a
//! claimed file or family does not exist, or when a family is claimed
//! twice. With [`REQUIRE_EVERY_FAMILY_CLAIMED`] on, it also fails when a
//! family of any vector file is unclaimed, a family whose only claims are
//! under features this build lacks aside.

use crate::vectors::{self, VectorError, VectorFile};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Whether the check fails on a family that no crate claims: on, so every
/// family of every vector file is proved by some crate.
pub const REQUIRE_EVERY_FAMILY_CLAIMED: bool = true;

/// The features a claim may name, each with whether this build has it.
pub const FEATURES: [(&str, bool); 8] = [
    ("ext-file-versions", cfg!(feature = "ext-file-versions")),
    ("ext-guests", cfg!(feature = "ext-guests")),
    ("ext-invite-links", cfg!(feature = "ext-invite-links")),
    ("ext-libraries", cfg!(feature = "ext-libraries")),
    ("ext-next-endpoints", cfg!(feature = "ext-next-endpoints")),
    ("ext-recovery-agent", cfg!(feature = "ext-recovery-agent")),
    (
        "ext-restricted-spaces",
        cfg!(feature = "ext-restricted-spaces"),
    ),
    ("space-files", cfg!(feature = "space-files")),
];

/// Whether this build has a feature; `None` for a feature it does not know.
pub fn built_with(feature: &str) -> Option<bool> {
    FEATURES
        .iter()
        .find(|(name, _)| *name == feature)
        .map(|&(_, on)| on)
}

/// The directories, under the workspace root, whose subdirectories are
/// workspace members and may hold a `claims.txt`.
const MEMBER_PARENTS: [&str; 3] = ["crates", "apps", "tests"];

/// Where a claim was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// The `claims.txt` it is in.
    pub source: PathBuf,
    /// Its line, from 1.
    pub line: usize,
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.source.display(), self.line)
    }
}

/// One claim: a crate proves this family of this file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// Where the claim was made.
    pub origin: Origin,
    /// The vector file, such as `crypto.json`.
    pub file: String,
    /// The family, such as `ed25519_keys`.
    pub family: String,
    /// The feature the claim is proved under, such as `ext-invite-links`;
    /// `None` for a claim proved in every build.
    pub feature: Option<String>,
}

/// Something the check refuses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// A line that is neither blank, a comment, `<file.json> <family>` nor
    /// `[feature] <file.json> <family>`.
    Malformed {
        /// Where the line is.
        origin: Origin,
        /// The line.
        text: String,
    },
    /// A claim under a feature this crate does not know ([`FEATURES`]).
    UnknownFeature(Claim),
    /// A claim under a feature the claiming crate does not declare.
    UndeclaredFeature(Claim),
    /// A claim of a file that is not one of the vector files.
    UnknownFile(Claim),
    /// A claim of a family that the named file does not hold.
    UnknownFamily(Claim),
    /// A family claimed a second time.
    ClaimedTwice {
        /// The first claim.
        first: Claim,
        /// The later claim.
        second: Claim,
    },
    /// A family that no crate claims, when [`REQUIRE_EVERY_FAMILY_CLAIMED`]
    /// is on.
    Unclaimed {
        /// The vector file.
        file: String,
        /// The family.
        family: String,
    },
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed { origin, text } => {
                write!(
                    f,
                    "{origin}: expected `[feature] <file.json> <family>` or \
                     `<file.json> <family>`, found {text:?}"
                )
            }
            Self::UnknownFeature(claim) => write!(
                f,
                "{}: no feature `{}` is known to the claims check",
                claim.origin,
                claim.feature.as_deref().unwrap_or_default()
            ),
            Self::UndeclaredFeature(claim) => write!(
                f,
                "{}: the crate declares no feature `{}`",
                claim.origin,
                claim.feature.as_deref().unwrap_or_default()
            ),
            Self::UnknownFile(claim) => {
                write!(f, "{}: no vector file `{}`", claim.origin, claim.file)
            }
            Self::UnknownFamily(claim) => write!(
                f,
                "{}: {} has no family `{}`",
                claim.origin, claim.file, claim.family
            ),
            Self::ClaimedTwice { first, second } => write!(
                f,
                "{}: {} `{}` is already claimed at {}",
                second.origin, second.file, second.family, first.origin
            ),
            Self::Unclaimed { file, family } => {
                write!(f, "{file} `{family}` is claimed by no crate")
            }
        }
    }
}

/// Reads one `claims.txt`. Returns its claims, and a problem for each line
/// it cannot read.
pub fn parse(source: &Path, text: &str) -> (Vec<Claim>, Vec<Problem>) {
    let mut claims = Vec::new();
    let mut problems = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let origin = Origin {
            source: source.to_path_buf(),
            line: index + 1,
        };
        let content = raw.split('#').next().unwrap_or_default().trim();
        if content.is_empty() {
            continue;
        }
        let words: Vec<&str> = content.split_whitespace().collect();
        let feature = |word: &str| {
            word.strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
                .filter(|name| {
                    !name.is_empty()
                        && name
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                })
                .map(str::to_owned)
        };
        match words[..] {
            [file, family] if file.ends_with(".json") => claims.push(Claim {
                origin,
                file: file.to_owned(),
                family: family.to_owned(),
                feature: None,
            }),
            [gate, file, family] if file.ends_with(".json") && feature(gate).is_some() => {
                claims.push(Claim {
                    origin,
                    file: file.to_owned(),
                    family: family.to_owned(),
                    feature: feature(gate),
                });
            }
            _ => problems.push(Problem::Malformed {
                origin,
                text: raw.to_owned(),
            }),
        }
    }
    (claims, problems)
}

/// Checks claims against the vector files. `built_with` says whether this
/// build has a feature, `None` for one it does not know: a claim under a
/// feature it lacks is left alone, and its family is not reported unclaimed.
pub fn check(
    claims: &[Claim],
    files: &[VectorFile],
    require_every_family: bool,
    built_with: impl Fn(&str) -> Option<bool>,
) -> Vec<Problem> {
    let mut problems = Vec::new();
    let mut seen: BTreeMap<(&str, &str), &Claim> = BTreeMap::new();
    let mut unverified: Vec<(&str, &str)> = Vec::new();
    for claim in claims {
        if let Some(feature) = &claim.feature {
            match built_with(feature) {
                None => {
                    problems.push(Problem::UnknownFeature(claim.clone()));
                    continue;
                }
                Some(false) => {
                    unverified.push((&claim.file, &claim.family));
                    continue;
                }
                Some(true) => {}
            }
        }
        let Some(file) = files.iter().find(|file| file.name() == claim.file) else {
            problems.push(Problem::UnknownFile(claim.clone()));
            continue;
        };
        if !file.has_family(&claim.family) {
            problems.push(Problem::UnknownFamily(claim.clone()));
            continue;
        }
        match seen.get(&(claim.file.as_str(), claim.family.as_str())) {
            Some(first) => problems.push(Problem::ClaimedTwice {
                first: (*first).clone(),
                second: claim.clone(),
            }),
            None => {
                seen.insert((&claim.file, &claim.family), claim);
            }
        }
    }
    if require_every_family {
        for file in files {
            for family in file.family_names() {
                let key = (file.name(), family);
                if !seen.contains_key(&key) && !unverified.contains(&key) {
                    problems.push(Problem::Unclaimed {
                        file: file.name().to_owned(),
                        family: family.to_owned(),
                    });
                }
            }
        }
    }
    problems
}

/// Every `claims.txt` of the workspace's members, as paths relative to the
/// workspace root, sorted.
pub fn claims_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for parent in MEMBER_PARENTS {
        let Ok(entries) = std::fs::read_dir(root.join(parent)) else {
            continue;
        };
        for entry in entries {
            let relative = Path::new(parent)
                .join(entry?.file_name())
                .join("claims.txt");
            if root.join(&relative).is_file() {
                found.push(relative);
            }
        }
    }
    found.sort();
    Ok(found)
}

/// Reads every crate's `claims.txt` and checks the claims against all 21
/// vector files, with [`REQUIRE_EVERY_FAMILY_CLAIMED`].
pub fn check_workspace() -> Result<Vec<Problem>, VectorError> {
    let root = crate::workspace_root();
    let files = vectors::load_all()?;
    let sources = claims_files(&root).map_err(|error| VectorError::Io {
        path: root.clone(),
        error,
    })?;
    let mut claims = Vec::new();
    let mut problems = Vec::new();
    for source in sources {
        let text =
            std::fs::read_to_string(root.join(&source)).map_err(|error| VectorError::Io {
                path: source.clone(),
                error,
            })?;
        let (mut read, mut refused) = parse(&source, &text);
        problems.append(&mut refused);
        let manifest = source.with_file_name("Cargo.toml");
        let manifest =
            std::fs::read_to_string(root.join(&manifest)).map_err(|error| VectorError::Io {
                path: manifest.clone(),
                error,
            })?;
        for claim in &read {
            if let Some(feature) = &claim.feature
                && built_with(feature).is_some()
                && !declares(&manifest, feature)
            {
                problems.push(Problem::UndeclaredFeature(claim.clone()));
            }
        }
        claims.append(&mut read);
    }
    problems.extend(check(
        &claims,
        &files,
        REQUIRE_EVERY_FAMILY_CLAIMED,
        built_with,
    ));
    Ok(problems)
}

/// Whether a crate's manifest declares a feature: a line `<feature> = ...`
/// in its `[features]` table.
pub fn declares(manifest: &str, feature: &str) -> bool {
    let mut in_features = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_features = line == "[features]";
        } else if in_features
            && line
                .split_once('=')
                .is_some_and(|(name, _)| name.trim() == feature)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files() -> Vec<VectorFile> {
        vec![
            VectorFile::parse("a.json", r#"{"specification":"a.md","one":[],"two":{}}"#).unwrap(),
            VectorFile::parse("b.json", r#"{"three":"00"}"#).unwrap(),
        ]
    }

    fn claims(source: &str, text: &str) -> Vec<Claim> {
        let (claims, problems) = parse(Path::new(source), text);
        assert!(problems.is_empty(), "{problems:?}");
        claims
    }

    #[test]
    fn reads_claims_comments_and_blank_lines() {
        let read = claims(
            "x/claims.txt",
            "# heading\n\na.json one\n  b.json three  # why\n",
        );
        assert_eq!(read.len(), 2);
        assert_eq!(read[0].family, "one");
        assert_eq!(read[1].file, "b.json");
        assert_eq!(read[1].origin.line, 4);
        assert!(check(&read, &files(), false, built_with).is_empty());
    }

    #[test]
    fn an_empty_claims_file_is_valid() {
        assert!(claims("x/claims.txt", "").is_empty());
    }

    #[test]
    fn refuses_malformed_lines() {
        let (_, problems) = parse(Path::new("x"), "a.json\na.json one two\none a.json\n");
        assert_eq!(problems.len(), 3);
        assert!(
            problems
                .iter()
                .all(|p| matches!(p, Problem::Malformed { .. }))
        );
    }

    #[test]
    fn refuses_unknown_files_and_families() {
        let read = claims("x", "c.json one\na.json three\na.json specification\n");
        let problems = check(&read, &files(), false, built_with);
        assert!(matches!(problems[0], Problem::UnknownFile(_)));
        assert!(matches!(problems[1], Problem::UnknownFamily(_)));
        assert!(matches!(problems[2], Problem::UnknownFamily(_)));
        assert_eq!(problems.len(), 3);
    }

    #[test]
    fn refuses_a_family_claimed_twice() {
        let mut read = claims("x", "a.json one\n");
        read.extend(claims("y", "a.json two\na.json one\n"));
        let problems = check(&read, &files(), false, built_with);
        assert_eq!(problems.len(), 1);
        let Problem::ClaimedTwice { first, second } = &problems[0] else {
            panic!("{problems:?}");
        };
        assert_eq!(first.origin.source, Path::new("x"));
        assert_eq!(second.origin.source, Path::new("y"));
        assert_eq!(second.origin.line, 2);
    }

    #[test]
    fn reads_feature_claims() {
        let read = claims("x", "[ext-a] a.json one\n[ext-b] b.json three\n");
        assert_eq!(read[0].feature.as_deref(), Some("ext-a"));
        assert_eq!(read[1].family, "three");
        let (_, problems) = parse(
            Path::new("x"),
            "[] a.json one\n[Ext] a.json one\n[a a.json one\n",
        );
        assert_eq!(problems.len(), 3);
    }

    #[test]
    fn a_feature_claim_is_checked_only_in_a_build_with_its_feature() {
        let read = claims(
            "x",
            "[ext-a] a.json one\n[ext-a] a.json nine\n[ext-c] b.json three\n",
        );
        let only = |on: &'static str| {
            move |feature: &str| match feature {
                "ext-a" | "ext-b" => Some(feature == on),
                _ => None,
            }
        };
        // Without the feature: read and left alone, its families not
        // unclaimed; the unknown feature is refused either way.
        let problems = check(&read, &files(), true, only("ext-b"));
        assert!(matches!(problems[0], Problem::UnknownFeature(_)));
        assert_eq!(
            problems[1..],
            [
                Problem::Unclaimed {
                    file: "a.json".into(),
                    family: "two".into()
                },
                Problem::Unclaimed {
                    file: "b.json".into(),
                    family: "three".into()
                },
            ]
        );
        // With it: verified.
        let problems = check(&read, &files(), false, only("ext-a"));
        assert!(matches!(&problems[0], Problem::UnknownFamily(c) if c.family == "nine"));
        assert!(matches!(problems[1], Problem::UnknownFeature(_)));
        assert_eq!(problems.len(), 2);
    }

    #[test]
    fn a_manifest_declares_its_features() {
        let manifest = "[package]\next-a = 1\n[features]\n# x\next-b = []\next-c=[\"y\"]\n[dependencies]\next-d = 1\n";
        assert!(declares(manifest, "ext-b") && declares(manifest, "ext-c"));
        assert!(!declares(manifest, "ext-a") && !declares(manifest, "ext-d"));
    }

    #[test]
    fn unclaimed_families_fail_only_when_required() {
        let read = claims("x", "a.json one\n");
        assert!(check(&read, &files(), false, built_with).is_empty());
        let problems = check(&read, &files(), true, built_with);
        assert_eq!(
            problems,
            vec![
                Problem::Unclaimed {
                    file: "a.json".into(),
                    family: "two".into()
                },
                Problem::Unclaimed {
                    file: "b.json".into(),
                    family: "three".into()
                },
            ]
        );
    }
}
