//! Signed welcome requests must refuse arbitrary bytes without panicking.
#![no_main]
use frasil_admission::welcome_request::WelcomeRequest;
use frasil_crypto::device::KeyRing;
use libfuzzer_sys::fuzz_target;
fuzz_target!(|data: &[u8]| {
    let _ = WelcomeRequest::read(data);
    let _ = WelcomeRequest::verify(data, &KeyRing::new());
});
