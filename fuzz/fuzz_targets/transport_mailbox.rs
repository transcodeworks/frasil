//! frasil-transport's mailbox readers on arbitrary bytes (transport.md, 2.7
//! Mailboxes and 3.14 Mailboxes): the item plaintext, `open_item`, and the
//! collection check. They never panic; each refuses only with its steps'
//! classes; a plaintext that reads is the one encoding of what it returns;
//! and nothing passes the collection check that the mailbox's own device
//! did not sign.
#![no_main]

use frasil_base::ErrorClass;
use frasil_crypto::device::{IdentityKey, KeysCommitment, Signatory};
use frasil_crypto::primitives::{ed25519_public, ed25519_sign};
use frasil_transport::TransportClass;
use frasil_transport::mailbox::{
    self, Kind, check_collect, collect_input, item_plaintext, open_item, read_item_plaintext,
};
use libfuzzer_sys::fuzz_target;

const XWING_SEED: [u8; 32] = [3; 32];
const IDENTITY_SEED: [u8; 32] = [4; 32];
const BINDING: [u8; 32] = [5; 32];
const KC: KeysCommitment = KeysCommitment([6; 32]);

fuzz_target!(|data: &[u8]| {
    if let Ok(item) = read_item_plaintext(data) {
        assert_eq!(item_plaintext(&item.content, &item.body), data);
    }
    let me = Signatory {
        ed: IdentityKey(ed25519_public(&IDENTITY_SEED)),
        kc: KC,
    };
    let device = me.device_id();
    // The core content names: access and welcome requests, list events.
    match open_item(data, &device, &XWING_SEED, |name| {
        mailbox::content::CORE.contains(&name)
    }) {
        Ok(item) => assert!(mailbox::content::CORE.contains(&item.content.as_str())),
        Err(error) => assert!(
            matches!(
                error,
                TransportClass::UnknownContent
                    | TransportClass::Shared(
                        ErrorClass::Malformed
                            | ErrorClass::UnsupportedVersion
                            | ErrorClass::Decrypt
                    )
            ),
            "{error:?}"
        ),
    }
    // The collection check: the fuzzer's bytes as the signature, then as
    // the device's `ed || kc`, then as its `kc` beside its own `ed`, with
    // the device's own address, which hashes its device ID.
    let address = mailbox::address(Kind::Device, device.as_bytes());
    let signed = ed25519_sign(&IDENTITY_SEED, &collect_input(&BINDING, &address));
    match check_collect(&address, &me.to_bytes(), data, &BINDING) {
        Ok(checked) => {
            assert_eq!(data, signed.as_slice());
            assert_eq!(checked.address(), &address);
        }
        Err(error) => assert!(
            matches!(
                error,
                TransportClass::Shared(ErrorClass::Malformed | ErrorClass::BadSignature)
            ),
            "{error:?}"
        ),
    }
    if let Err(error) = check_collect(&address, data, &signed, &BINDING) {
        assert!(
            matches!(
                error,
                TransportClass::WrongMailbox
                    | TransportClass::Shared(
                        ErrorClass::Malformed | ErrorClass::InvalidKey | ErrorClass::BadSignature
                    )
            ),
            "{error:?}"
        );
    } else {
        assert_eq!(data, me.to_bytes().as_slice());
    }
    if let Some(kc) = data.get(..32) {
        let mut signer = me.ed.0.to_vec();
        signer.extend_from_slice(kc);
        match check_collect(&address, &signer, &signed, &BINDING) {
            Ok(checked) => {
                assert_eq!(kc, KC.as_bytes());
                assert_eq!(checked.collector(), device);
            }
            Err(error) => assert_eq!(error, TransportClass::WrongMailbox),
        }
    }
});
