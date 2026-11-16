//! frasil-crypto's signature checks on arbitrary bytes (crypto.md,
//! "Verifying a signature" and "Strict Ed25519 verification"): the scheme
//! code, the kind's policy, the length, both halves of a scheme-2 signature
//! and the ML-DSA-65 signature decoder. They never panic; they refuse only
//! with `verify`'s classes, in its order; and nothing verifies that the
//! fixed signer did not sign.
#![no_main]

use frasil_crypto::ErrorClass;
use frasil_crypto::mldsa65;
use frasil_crypto::schemes::{self, Held, KindPolicy, Scheme, Signed, Signer};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fn signer() -> &'static Signer {
    static SIGNER: OnceLock<Signer> = OnceLock::new();
    SIGNER.get_or_init(|| Signer::from_seeds(&[1; 32], &[2; 32], None))
}

fuzz_target!(|data: &[u8]| {
    let [scheme, kind, flags, rest @ ..] = data else {
        return;
    };
    let (tbs, signature) = rest.split_at(rest.len().min(usize::from(*flags & 0x3f)));
    let signer = signer();
    let held = Held {
        keys: (flags & 0x40 != 0).then_some(signer.keys()),
        sunset: flags & 0x80 != 0,
        covered: kind & 0x80 != 0,
    };
    let Ok(policy) = KindPolicy::for_kind(u64::from(*kind & 0x7f)) else {
        return;
    };
    let signed = Signed {
        scheme: u64::from(*scheme),
        ed: signer.identity_key(),
        kc: signer.kc(),
        tbs,
        signature,
    };
    match schemes::verify(policy, &signed, &held) {
        Ok(()) => {
            // Only the signer's own signature verifies under its keys.
            let scheme = Scheme::from_code(signed.scheme).unwrap();
            assert_eq!(signature, signer.sign(scheme, tbs).as_slice());
        }
        Err(class) => assert!(matches!(
            class,
            ErrorClass::UnsupportedVersion
                | ErrorClass::SchemeNotAllowed
                | ErrorClass::Malformed
                | ErrorClass::BadSignature
                | ErrorClass::NoHybridKey
                | ErrorClass::Uncovered
        )),
    }
    // Steps 1 to 4 alone agree with verify on what they refuse.
    if let Err(class) = schemes::verify_ed25519_steps(policy, &signed) {
        assert_eq!(schemes::verify(policy, &signed, &held), Err(class));
    }
    // The ML-DSA-65 decoder and verifier on the bytes as a signature, and
    // strict Ed25519 on them as one.
    let _ = mldsa65::verify(signer.mldsa_public(), tbs, signature);
    let _ = schemes::ed25519_verify_strict(&signer.identity_key().0, tbs, signature);
    if signature.len() >= 3373 {
        let _ = mldsa65::verify(signer.mldsa_public(), tbs, &signature[64..3373]);
    }
});
