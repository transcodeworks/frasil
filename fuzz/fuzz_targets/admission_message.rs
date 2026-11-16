//! frasil-admission's message and body readers on arbitrary bytes
//! (admission.md, 2.4 The offer, 2.5 Messages, 2.6 The seal, 2.7 Bodies,
//! 2.10 The welcome, 2.11 The lookup prompt and the Join). They never
//! panic; `read_message` refuses only with its steps' classes; a sealed
//! body opens or fails only as crypto.md's wrap does; and every body that
//! reads is the one encoding of what it returns.
#![no_main]

use frasil_admission::bodies::{
    HelloBody, ListEvents, OfferBody, RequestBody, ResponseBody, RevealBody,
};
use frasil_admission::lookup::{Join, Prompt};
use frasil_admission::message::{MessageType, open_body, read_message};
use frasil_admission::welcome::Welcome;
use frasil_admission::{AdmissionClass, Ctx, JoinerType, Offer};
use frasil_base::ErrorClass;
use libfuzzer_sys::fuzz_target;

const SEED: [u8; 32] = [6; 32];

fn round_trip<T>(data: &[u8], read: Result<T, AdmissionClass>, encode: impl Fn(&T) -> Vec<u8>) {
    match read {
        Ok(value) => assert_eq!(encode(&value), data, "a second encoding"),
        Err(error) => assert!(
            matches!(error, AdmissionClass::Shared(ErrorClass::Malformed)),
            "{error:?}"
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    match read_message(data) {
        Ok(message) => {
            assert!(data.len() <= message.kind.limit());
            assert!(message.kind != MessageType::Cancel || message.body.is_empty());
            if let Err(error) = open_body(message.kind, &message.request, &SEED, message.body) {
                assert!(
                    matches!(
                        error,
                        AdmissionClass::Shared(
                            ErrorClass::Malformed
                                | ErrorClass::UnsupportedVersion
                                | ErrorClass::Decrypt
                        )
                    ),
                    "{error:?}"
                );
            }
        }
        Err(error) => assert!(
            matches!(
                error,
                AdmissionClass::Shared(
                    ErrorClass::Malformed | ErrorClass::UnsupportedVersion | ErrorClass::TooLarge
                )
            ),
            "{error:?}"
        ),
    }
    round_trip(data, RequestBody::read(data), RequestBody::encode);
    round_trip(data, ResponseBody::read(data), ResponseBody::encode);
    round_trip(
        data,
        RevealBody::read(data, Ctx::DeviceList),
        RevealBody::encode,
    );
    round_trip(data, RevealBody::read(data, Ctx::Space), RevealBody::encode);
    round_trip(data, ListEvents::read(data), ListEvents::encode);
    round_trip(data, HelloBody::read(data), HelloBody::encode);
    round_trip(data, OfferBody::read(data), OfferBody::encode);
    round_trip(data, Offer::read(data, JoinerType::Device), Offer::encode);
    round_trip(data, Offer::read(data, JoinerType::Person), Offer::encode);
    round_trip(data, Welcome::read(data), Welcome::encode);
    round_trip(data, Join::read(data), Join::encode);
    match Prompt::read(data) {
        Ok(prompt) => assert_eq!(prompt.encode(), data, "a second encoding"),
        Err(error) => assert!(
            matches!(
                error,
                AdmissionClass::Shared(ErrorClass::Malformed | ErrorClass::UnsupportedVersion)
            ),
            "{error:?}"
        ),
    }
});
