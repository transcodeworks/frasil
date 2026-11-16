//! Every crate's `claims.txt` names existing vector families, each once.

use frasil_testkit::claims;

#[test]
fn every_claim_names_one_existing_family() {
    let problems = claims::check_workspace().unwrap_or_else(|error| panic!("{error}"));
    let report: Vec<String> = problems.iter().map(ToString::to_string).collect();
    assert!(problems.is_empty(), "vector claims:\n{}", report.join("\n"));
}

#[test]
fn every_member_has_a_claims_file() {
    let root = frasil_testkit::workspace_root();
    let found = claims::claims_files(&root).unwrap();
    for member in ["crates/frasil-testkit", "apps/relay", "tests/conformance"] {
        let expected = std::path::Path::new(member).join("claims.txt");
        assert!(
            found.contains(&expected),
            "{} is missing",
            expected.display()
        );
    }
}
