//! frasil-admission's readers of ext-guests.md on arbitrary bytes: a leave
//! request ("The leave request"), its checks before the roster's ("A leave
//! request", steps 1 to 3), and an offer that may carry key 13 ("The guest
//! preset"). They never panic, each refuses only with its procedure's
//! classes, and what a reader accepts is the one encoding of what it
//! returns.
#![no_main]

use frasil_admission::ext_guests::LeaveRequest;
use frasil_admission::{AdmissionClass, JoinerType, Offer};
use frasil_base::ErrorClass;
use frasil_crypto::device::{DeviceKeys, KeyRing};
use frasil_crypto::schemes::Signer;
use frasil_crypto::wrap::xwing_public;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    match LeaveRequest::read(data) {
        Ok(request) => assert_eq!(request.encode(), data, "a second encoding"),
        Err(error) => assert!(
            matches!(
                error,
                AdmissionClass::Shared(ErrorClass::Malformed | ErrorClass::UnsupportedVersion)
            ),
            "{error:?}"
        ),
    }

    let signer = Signer::from_seeds(&[8; 32], &[9; 32], Some(&xwing_public(&[10; 32])));
    let mut keys = KeyRing::new();
    keys.add_device(DeviceKeys {
        ed: *signer.identity_key(),
        keys: signer.keys().clone(),
    });
    if let Err(error) = LeaveRequest::verify(data, &keys) {
        assert!(
            matches!(
                error,
                AdmissionClass::Shared(
                    ErrorClass::Malformed
                        | ErrorClass::UnsupportedVersion
                        | ErrorClass::NoHybridKey
                        | ErrorClass::BadSignature
                )
            ),
            "{error:?}"
        );
    }

    for joiner in [JoinerType::Device, JoinerType::Person] {
        match Offer::read(data, joiner) {
            Ok(offer) => {
                assert!(offer.expires_at.is_none() || offer.session.is_some());
                assert_eq!(Offer::read(&offer.encode(), joiner), Ok(offer));
            }
            Err(error) => assert_eq!(error, AdmissionClass::Shared(ErrorClass::Malformed)),
        }
    }
});
