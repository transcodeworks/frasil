//! Helpers the tests share.

#![allow(dead_code)]

use frasil_base::errors::Class;
use frasil_base::time::Reading;
use frasil_crypto::primitives::sha256;
use frasil_store::tables::{DroppedOrigin, Head, KeyValue, TableValue};
use serde_json::{Value as Json, json};
use std::future::Future;
use std::task::{Context, Poll, Waker};

/// The vector file.
pub const FILE: &str = "at-rest.json";

/// A family of `at-rest.json`, as JSON.
pub fn family(name: &str) -> Json {
    frasil_testkit::vectors::family(FILE, name)
}

/// The bytes of a hex string.
pub fn unhex(text: &str) -> Vec<u8> {
    frasil_testkit::hex::decode(text).unwrap_or_else(|error| panic!("{text}: {error}"))
}

/// The bytes of a hex string field.
pub fn bytes(value: &Json, key: &str) -> Vec<u8> {
    let text = value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"));
    unhex(text)
}

/// The bytes of a hex string field, as an array.
pub fn array<const N: usize>(value: &Json, key: &str) -> [u8; N] {
    bytes(value, key)
        .try_into()
        .unwrap_or_else(|_| panic!("{key} is not {N} bytes"))
}

/// The bytes of a hex string field that may be `null`.
pub fn optional<const N: usize>(value: &Json, key: &str) -> Option<[u8; N]> {
    (!value[key].is_null()).then(|| array(value, key))
}

/// A string field.
pub fn text<'a>(value: &'a Json, key: &str) -> &'a str {
    value[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string"))
}

/// The class name a result failed with, or `"accepted"` if it passed, as
/// the vectors write it.
pub fn outcome<T, C: Class>(result: Result<T, C>) -> &'static str {
    result.err().map_or("accepted", Class::name)
}

/// The reference's fixed inputs: SHA-256 of a description, so no value is
/// magic.
pub fn example(name: &str) -> [u8; 32] {
    sha256(&[b"frasil spec example/", name.as_bytes()])
}

/// One byte changed, as the reference changes it: the low bit flipped.
pub fn flip(data: &[u8], at: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    out[at] ^= 1;
    out
}

/// Runs a future that is ready when first polled, as every future of the
/// crate's stores is.
pub fn ready<F: Future>(future: F) -> F::Output {
    let mut future = std::pin::pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the future was not ready"),
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> Json {
    Json::String(frasil_testkit::hex::encode(bytes))
}

fn reading(r: &Reading) -> Json {
    let mut out = json!({"1": r.timeline, "2": r.run});
    if let Some(wall) = r.wall {
        out["3"] = json!(wall);
    }
    out
}

fn ids(ids: &[[u8; 32]]) -> Json {
    Json::Array(ids.iter().map(hex).collect())
}

/// The head as the vectors show an opened one.
pub fn head_json(head: &Head) -> Json {
    let tips: Vec<Json> = head
        .tips
        .iter()
        .map(|t| json!([hex(t.log), hex(t.author), t.seq, hex(t.event)]))
        .collect();
    let mut out = json!({"1": hex(head.store_id), "2": head.generation, "3": tips});
    if let Some(restore) = &head.restore {
        out["4"] = json!(restore.found_at);
        out["5"] = ids(&restore.synced);
    }
    if let Some(revision) = head.revision {
        out["6"] = json!(revision);
    }
    out
}

/// An opened value as the vectors show it: bytes in hex, map keys as text,
/// and the reference's names for the values it splits.
pub fn opened_json(value: &TableValue) -> Json {
    match value {
        TableValue::Head(head) => head_json(head),
        TableValue::Log(log) => {
            json!({"kind": log.kind.code(), "log_key": hex(log.log_key.expose())})
        }
        TableValue::Timeline(r) => reading(r),
        TableValue::Epoch(epoch) => json!(epoch),
        TableValue::NextEndpoint(seed) => hex(seed.expose()),
        TableValue::DepositKeys(keys) => {
            let mut out = json!({
                "1": keys.seen.iter().map(|(id, first)| json!([hex(id), first])).collect::<Vec<_>>(),
                "2": keys
                    .latest
                    .iter()
                    .map(|(id, public, role)| json!([hex(id), hex(public), role]))
                    .collect::<Vec<_>>(),
            });
            if keys.inconsistent {
                out["3"] = json!(1);
            }
            if let Some(paused) = &keys.paused {
                out["4"] = reading(paused);
            }
            out
        }
        TableValue::Token(token) => hex(token.expose()),
        TableValue::Deposit(deposit) => {
            let mut out = json!({
                "1": deposit.peer,
                "2": hex(deposit.address),
                "3": hex(&deposit.item),
                "4": reading(&deposit.first),
                "5": deposit.attempts,
                "6": deposit.next,
            });
            if let Some(token) = &deposit.token {
                out["7"] = hex(token.expose());
            }
            out
        }
        TableValue::Announced(key) => hex(key),
        TableValue::Event(event) => {
            let mut out = json!({
                "1": hex(&event.signed),
                "2": event.state.code(),
                "3": event.flags,
            });
            if let Some(class) = &event.class {
                out["4"] = json!(class);
            }
            if let Some(first) = &event.first_sight {
                out["5"] = reading(first);
            }
            if let Some(frozen) = &event.frozen {
                out["6"] = Json::Array(
                    frozen
                        .capabilities
                        .iter()
                        .map(|(name, mode)| json!([name, mode]))
                        .collect(),
                );
                if !frozen.attribution.is_empty() {
                    out["7"] = Json::Array(
                        frozen
                            .attribution
                            .iter()
                            .map(|(kind, id, label)| match label {
                                Some(label) => json!([kind, hex(id), label]),
                                None => json!([kind, hex(id)]),
                            })
                            .collect(),
                    );
                }
                if !frozen.voided_by.is_empty() {
                    out["8"] = ids(&frozen.voided_by);
                }
            }
            out
        }
        TableValue::Object(bytes) | TableValue::Host(bytes) | TableValue::Endpoint(bytes) => {
            hex(bytes)
        }
        TableValue::Held(held) => {
            json!({"1": hex(&held.token), "2": held.size, "3": hex(&held.stamp)})
        }
        TableValue::Peers(peers) => {
            let mut out = json!({});
            if !peers.hints.is_empty() {
                out["1"] = json!(peers.hints);
            }
            if let Some(home) = &peers.home {
                out["2"] = json!(home);
            }
            out
        }
        TableValue::Key(KeyValue::Bundle(bundle)) => {
            let mut out = json!({});
            for (name, slot) in [
                ("content", &bundle.content),
                ("upload", &bundle.upload),
                ("grant", &bundle.grant),
            ] {
                if let Some(secret) = slot {
                    out[name] = hex(secret.expose());
                }
            }
            out
        }
        TableValue::Key(KeyValue::BodyKey(body)) => json!({
            "source": if body.handed_by.is_some() { 2 } else { 1 },
            "body_key": hex(body.key.expose()),
            "handed_by": body.handed_by.map_or(Json::Null, hex),
        }),
        TableValue::Key(KeyValue::RecordKey(record)) => json!({
            "source": if record.handed { 2 } else { 1 },
            "record_key": hex(record.key.expose()),
        }),
        TableValue::Dropped(origin) => match origin {
            DroppedOrigin::Held { kind, height } => match height {
                Some(height) => json!({"1": 1, "2": kind, "3": height}),
                None => json!({"1": 1, "2": kind}),
            },
            DroppedOrigin::Missing => json!({"1": 2}),
        },
        TableValue::Retention(retention) => match retention {
            frasil_store::tables::Retention::Kept => json!({"1": 1}),
            frasil_store::tables::Retention::Cached { read } => json!({"1": 2, "2": read}),
            frasil_store::tables::Retention::Put { keep: false } => json!({"1": 3}),
            frasil_store::tables::Retention::Put { keep: true } => json!({"1": 3, "3": 1}),
        },
        TableValue::Outbox(id) => hex(id),
        TableValue::Ack(heads) => ids(heads),
        TableValue::Listing(listing) => json!({"1": hex(&listing.served), "2": listing.at}),
        TableValue::State(state) => {
            let mut out = json!({});
            if let Some(heads) = &state.base_heads {
                out["1"] = ids(heads);
            }
            if let Some(stubs) = &state.base_stubs {
                out["2"] = Json::Array(stubs.iter().map(hex).collect());
            }
            if let Some(r) = &state.last_sync {
                out["3"] = reading(r);
            }
            if let Some(grants) = &state.left {
                out["4"] = ids(grants);
            }
            if state.personal {
                out["5"] = json!(1);
            }
            if let Some(entry) = &state.claiming {
                out["6"] = hex(entry);
            }
            if let Some(checkpoint) = &state.kept_checkpoint {
                out["7"] = hex(checkpoint);
            }
            if let Some(devices) = &state.erasing {
                out["9"] = Json::Array(
                    devices
                        .iter()
                        .map(|(id, key)| json!([hex(id), hex(key)]))
                        .collect(),
                );
            }
            if let Some(expressed) = &state.expressed_again {
                out["8"] = Json::Array(
                    expressed
                        .0
                        .iter()
                        .map(|(stream, incarnation)| json!([hex(stream), incarnation]))
                        .collect(),
                );
            }
            out
        }
        TableValue::Pseudonym(pseudonym) => {
            let mut out = json!({});
            if let Some(token) = &pseudonym.token {
                out["1"] = hex(token.expose());
            }
            if let Some((ed25519, mldsa)) = &pseudonym.seeds {
                out["2"] = hex(ed25519.expose());
                out["3"] = hex(mldsa.expose());
            }
            out
        }
        TableValue::Invite(record) | TableValue::Claim(record) => json!({
            "space": hex(record.space),
            "invite_entry": hex(record.invite_entry),
            "secret": hex(record.secret.expose()),
        }),
        TableValue::Replay(window) => json!({
            "epoch": window.epoch,
            "counter": window.counter,
            "window": window.window,
        }),
        TableValue::Vouched(person) => json!({ "person": hex(person) }),
    }
}
