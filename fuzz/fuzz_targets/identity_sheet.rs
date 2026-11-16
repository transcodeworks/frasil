//! frasil-identity's recovery sheet reader on arbitrary text (identity.md,
//! "Recovery keys"). It never panics; it refuses only as `InvalidSheet`; and
//! a secret it reads prints as the text it read, separators and case aside.
#![no_main]

use frasil_identity::IdentityClass;
use frasil_identity::recovery::RecoverySecret;
use libfuzzer_sys::fuzz_target;

fn cleaned(text: &str) -> String {
    text.chars()
        .filter(|c| *c != ' ' && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match RecoverySecret::read_sheet(text) {
        Ok(secret) => {
            let printed = secret.printed();
            assert_eq!(cleaned(&printed), cleaned(text));
            let again = RecoverySecret::read_sheet(&printed).expect("a printed sheet reads");
            assert_eq!(again.bytes(), secret.bytes());
        }
        Err(class) => assert_eq!(class, IdentityClass::InvalidSheet),
    }
});
