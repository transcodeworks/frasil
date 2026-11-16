//! frasil-identity's fingerprint parser on arbitrary text (identity.md,
//! "Fingerprints"). It never panics; it refuses only as `InvalidFingerprint`
//! or `FingerprintMistyped`; and a fingerprint it reads parses again from
//! its characters, its display and its QR form.
#![no_main]

use frasil_identity::IdentityClass;
use frasil_identity::fingerprint::Fingerprint;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    match Fingerprint::parse(text) {
        Ok(fp) => {
            assert!(fp.value() < 1 << 120);
            for form in [fp.characters(), fp.display(), fp.qr()] {
                assert_eq!(Fingerprint::parse(&form), Ok(fp));
            }
        }
        Err(class) => assert!(matches!(
            class,
            IdentityClass::InvalidFingerprint | IdentityClass::FingerprintMistyped
        )),
    }
});
