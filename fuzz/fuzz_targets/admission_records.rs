//! frasil-admission's checks of signed records, sealed welcomes, lists and
//! exchange mailboxes on arbitrary bytes (admission.md, 2.10 The welcome,
//! 3.4 A person's new device, 3.5 A person that joins a space, 3.6 Exchange
//! mailboxes, 3.9 Lookups, 3.14 Access requests). They never panic, and
//! each refuses only with its procedure's classes.
#![no_main]

use frasil_admission::AdmissionClass;
use frasil_admission::access::AccessRequest;
use frasil_admission::lookup::answer_prompt;
use frasil_admission::mailbox::ExchangeMailboxes;
use frasil_admission::new_device::{check_list, check_list_result};
use frasil_admission::welcome::Welcome;
use frasil_base::ErrorClass;
use frasil_crypto::device::{DeviceId, DeviceKeys, KeyRing};
use frasil_crypto::schemes::Signer;
use frasil_crypto::wrap::xwing_public;
use frasil_events::EventId;
use libfuzzer_sys::fuzz_target;

const SEED: [u8; 32] = [7; 32];

fuzz_target!(|data: &[u8]| {
    let xwing = xwing_public(&SEED);
    let signer = Signer::from_seeds(&[8; 32], &[9; 32], Some(&xwing));
    let me = *signer.device_id();
    let ed = *signer.identity_key();
    let mut keys = KeyRing::new();
    keys.add_device(DeviceKeys {
        ed,
        keys: signer.keys().clone(),
    });

    if let Err(error) = AccessRequest::verify(data, &keys) {
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
    let shared =
        |device: &DeviceId| (*device == me).then(|| (ed, Box::new(*signer.mldsa_public())));
    if let Err(error) = answer_prompt(data, shared) {
        assert!(
            matches!(
                error,
                AdmissionClass::Shared(
                    ErrorClass::Malformed
                        | ErrorClass::UnsupportedVersion
                        | ErrorClass::NotCommitted
                        | ErrorClass::BadSignature
                )
            ),
            "{error:?}"
        );
    }
    if let Err(error) = Welcome::open(data, &me, &SEED) {
        assert!(
            matches!(
                error,
                AdmissionClass::Shared(
                    ErrorClass::Malformed | ErrorClass::UnsupportedVersion | ErrorClass::Decrypt
                )
            ),
            "{error:?}"
        );
    }
    let _ = check_list_result(data, &[1; 32], &me, &[EventId([2; 32])], &me);
    if let Err(error) = check_list(data, &[1; 32], Some(&[EventId([1; 32])])) {
        assert!(
            matches!(
                error,
                AdmissionClass::BadList
                    | AdmissionClass::ListMismatch
                    | AdmissionClass::Shared(ErrorClass::Malformed)
            ),
            "{error:?}"
        );
    }
    // A peer's exchange mailboxes, fed the input split into messages.
    let mut peer: ExchangeMailboxes<u8> = ExchangeMailboxes::default();
    for (n, chunk) in data.split(|&b| b == 0xff).enumerate() {
        let _ = peer.put(&((n % 3) as u8), chunk, 1_760_000_000 + n as u64);
    }
});
