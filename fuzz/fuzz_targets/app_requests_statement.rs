//! frasil-app-requests' statement and the shapes of its fields on arbitrary
//! request parts (ext-app-requests.md, "The statement"), and its list
//! delivery reader on arbitrary bytes ("The list delivery"). Neither panics.
//! A statement that is built holds every field at its shape and at most
//! 5,361 bytes; a list delivery that reads is the one encoding of its events.
//!
//! The input is split at `\n` into the audience, the subject, the method,
//! the request target, the body and the heads; the target is split at its
//! first `?`. The whole input is also read as a list delivery.
#![no_main]

use frasil_app_requests::delivery::{encode_delivery, read_delivery};
use frasil_app_requests::statement::{
    LABEL, MAX_STATEMENT_BYTES, Request, audience_ok, heads_ok, method_ok, path_ok, query_ok,
    statement, subject_ok,
};
use frasil_crypto::device::{IdentityKey, KeysCommitment, Signatory};
use frasil_events::EventId;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(events) = read_delivery(data) {
        assert_eq!(
            encode_delivery(&events),
            data,
            "a second list delivery encoding"
        );
    }

    let mut parts = data.splitn(6, |&b| b == b'\n');
    let mut next = || parts.next().unwrap_or_default();
    let (audience, subject, method, target, body, heads) =
        (next(), next(), next(), next(), next(), next());
    let (Ok(audience), Ok(method), Ok(target)) = (
        core::str::from_utf8(audience),
        core::str::from_utf8(method),
        core::str::from_utf8(target),
    ) else {
        return;
    };
    let request = Request::from_target(audience, subject, method, target, body);
    let heads: Vec<EventId> = heads
        .chunks_exact(32)
        .map(|chunk| EventId(chunk.try_into().expect("32 bytes")))
        .collect();
    let signer = Signatory {
        ed: IdentityKey([2; 32]),
        kc: KeysCommitment([5; 32]),
    };
    let built = statement(&request, &[1; 32], &signer, 3, &[4; 16], &heads);
    let shaped = audience_ok(request.audience)
        && subject_ok(request.subject)
        && method_ok(request.method)
        && path_ok(request.path)
        && query_ok(request.query)
        && heads_ok(&heads);
    assert_eq!(built.is_ok(), shaped);
    if let Ok(out) = built {
        assert!(out.starts_with(LABEL));
        assert!(out.len() <= MAX_STATEMENT_BYTES);
    }
});
