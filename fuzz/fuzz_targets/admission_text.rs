//! frasil-admission's text readers on arbitrary text (admission.md, 2.8 The
//! QR code, 2.9 The setup code). They never panic; each refuses only with
//! `Malformed` or `UnsupportedVersion`; and what either accepts is the one
//! text of what it returns.
#![no_main]

use frasil_admission::AdmissionClass;
use frasil_admission::qr::AdmitQr;
use frasil_admission::setup::SetupCode;
use frasil_base::ErrorClass;
use libfuzzer_sys::fuzz_target;

fn refused(error: AdmissionClass) {
    assert!(
        matches!(
            error,
            AdmissionClass::Shared(ErrorClass::Malformed | ErrorClass::UnsupportedVersion)
        ),
        "{error:?}"
    );
}

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    for candidate in [
        text.to_owned(),
        format!("FRASIL-ADMIT:{text}"),
        format!("FRASIL-SETUP:{text}"),
    ] {
        match AdmitQr::read(&candidate) {
            Ok(qr) => assert_eq!(qr.text(), candidate, "a second text"),
            Err(error) => refused(error),
        }
        match SetupCode::read(&candidate) {
            Ok(code) => assert_eq!(code.text(), candidate, "a second text"),
            Err(error) => refused(error),
        }
    }
});
