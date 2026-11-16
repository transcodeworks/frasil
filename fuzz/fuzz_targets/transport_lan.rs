//! frasil-transport's local-network packet readers on arbitrary bytes
//! (transport.md, 2.9 Local-network packets, and 3.16's member
//! announcements and nearby pairing). They never panic; a member
//! announcement is refused only as `Malformed` or `NotForMe`; one that
//! opens is exactly the announcement of what it gives, under its nonce;
//! and a nearby announcement that reads carries a clean name.
#![no_main]

use frasil_base::ErrorClass;
use frasil_transport::TransportClass;
use frasil_transport::lan::{self, NAME_CHARACTERS, PACKET_BYTES};
use libfuzzer_sys::fuzz_target;

const SECRETS: [[u8; 32]; 2] = [[1; 32], [2; 32]];

fuzz_target!(|data: &[u8]| {
    match lan::open(data, &SECRETS) {
        Ok(found) => {
            // Only a packet sealed under a tried state opens, and only one
            // byte string seals a plaintext the reader accepts.
            let nonce: [u8; 24] = data[1..25].try_into().unwrap();
            let again =
                lan::announce_with(&SECRETS[found.state], &found.endpoint, found.port, &nonce);
            assert_eq!(again.as_slice(), data);
            assert_eq!(data.len(), PACKET_BYTES);
        }
        Err(error) => assert!(
            matches!(
                error,
                TransportClass::NotForMe | TransportClass::Shared(ErrorClass::Malformed)
            ),
            "{error:?}"
        ),
    }
    // The fuzzer's bytes as a plaintext, sealed and opened.
    if data.len() >= 25 + 2 {
        let nonce: [u8; 24] = data[..24].try_into().unwrap();
        let mut plaintext = [0u8; lan::PLAINTEXT_BYTES];
        let take = (data.len() - 24).min(lan::PLAINTEXT_BYTES);
        plaintext[..take].copy_from_slice(&data[24..24 + take]);
        let _ = lan::open(&seal(&SECRETS[1], &nonce, &plaintext), &SECRETS);
    }
    if let Ok(nearby) = lan::read_nearby(data) {
        assert!(nearby.port >= 1);
        assert!(nearby.name.chars().count() <= NAME_CHARACTERS);
        assert_eq!(lan::nearby_name(&nearby.name), nearby.name);
    }
});

/// A member announcement of an arbitrary plaintext.
fn seal(secret: &[u8; 32], nonce: &[u8; 24], plaintext: &[u8]) -> Vec<u8> {
    let sealed = frasil_crypto::primitives::xchacha20poly1305_seal(
        &lan::lan_key(secret),
        nonce,
        frasil_crypto::labels::LAN_ANNOUNCE,
        plaintext,
    );
    [&[lan::MEMBER][..], nonce, &sealed].concat()
}
