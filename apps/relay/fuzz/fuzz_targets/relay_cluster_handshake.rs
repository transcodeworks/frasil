//! frasil-relay's internal links' handshake, on arbitrary bytes (crate
//! `cluster`, module `handshake`): a dialer's first message and its last,
//! as a listener reads them, and a listener's answer, as a dialer reads it.
//! A first message that reads is written again as the same bytes; a MAC
//! checks only when it is the one the cluster key makes over the
//! transcript; and both ends of an exchange over the bytes read derive
//! matching keys. Nothing panics.
#![no_main]

#[allow(dead_code)]
#[path = "../../src/cluster/handshake.rs"]
mod handshake;

use handshake::{DIALER, FINISH, HELLO, Hello, LISTENER, REPLY, REPLY_BODY, Reply};
use libfuzzer_sys::fuzz_target;

/// The cluster key of the target.
const KEY: [u8; 32] = [7; 32];

fuzz_target!(|data: &[u8]| {
    let psk = handshake::psk(&KEY);
    // A dialer's first message, then its MAC, as a listener reads them.
    if let Some(Ok(first)) = data.get(..HELLO).map(<&[u8; HELLO]>::try_from) {
        if let Some(hello) = Hello::decode(first) {
            assert_eq!(&hello.encode(), first, "a first message reads back");
        }
        if let Some(Ok(mac)) = data
            .get(HELLO..HELLO + FINISH)
            .map(<&[u8; FINISH]>::try_from)
        {
            let reply = Reply {
                public: [1; 32],
                nonce: [2; 16],
                node: 3,
            }
            .encode();
            let th = handshake::transcript(first, &reply);
            assert_eq!(
                handshake::verify(&psk, DIALER, &th, mac),
                *mac == handshake::mac(&psk, DIALER, &th),
                "only the key's MAC checks"
            );
        }
    }
    // A listener's answer, as a dialer reads it.
    if let Some(Ok(second)) = data.get(..REPLY).map(<&[u8; REPLY]>::try_from) {
        let (reply, mac) = Reply::decode(second);
        let body = reply.encode();
        assert_eq!(&body[..], &second[..REPLY_BODY], "an answer reads back");
        let hello = Hello {
            public: [4; 32],
            nonce: [5; 16],
            node: 6,
        }
        .encode();
        let th = handshake::transcript(&hello, &body);
        assert_eq!(
            handshake::verify(&psk, LISTENER, &th, &mac),
            mac == handshake::mac(&psk, LISTENER, &th),
            "only the key's MAC checks"
        );
        // The keys of an exchange over the bytes read, as both ends derive
        // them from one shared secret.
        let dialer = handshake::keys(&psk, &reply.public, &th, true);
        let listener = handshake::keys(&psk, &reply.public, &th, false);
        if let (Some(dialer), Some(listener)) = (dialer, listener) {
            assert_eq!(*dialer.send, *listener.receive);
            assert_eq!(*dialer.receive, *listener.send);
        }
    }
});
