"""Announced next endpoints (ext-next-endpoints.md), protocol 1, written from
the specification, independently of any implementation: a rotation that
takes the announced key, the `NextEndpoint` message and its receiver, and
the tickets a device dials when it reconnects. Frames, tickets and
endpoint-key validation are handshakes.py's."""

from __future__ import annotations

import at_rest
import handshakes as hs
from events import cbor, h, is_bytes, uncbor
from formats import example
from primitives import SpecError, ed25519_public, ed25519_valid, point_encode, \
    small_order_points

EXTENSION = "ext-next-endpoints"
NEXT_ENDPOINT = hs.NEXT_ENDPOINT
CAP = hs.TYPE_CAPS[NEXT_ENDPOINT]
assert NEXT_ENDPOINT in hs.IGNORABLE_TYPES


def endpoint_key(seed: bytes) -> bytes:
    """A member endpoint key: the public key of its Ed25519 seed."""
    return ed25519_public(seed)


def rotate(kept: bytes | None, fresh_current: bytes, fresh_next: bytes) -> dict:
    """Section 3.1: the seed the rotation takes, the next seed it keeps
    instead, and the key it announces."""
    current = kept if kept is not None else fresh_current
    assert fresh_next != current
    return {"seed": current, "endpoint_key": endpoint_key(current),
            "next_seed": fresh_next, "next_key": endpoint_key(fresh_next)}


def encode(attach: int, key: bytes) -> bytes:
    return cbor({0: NEXT_ENDPOINT, 1: attach, 2: key})


def read(payload: bytes, connection: str = "member") -> dict:
    """Section 3.3, steps 1 and 2, at a receiver that implements the
    extension."""
    value = hs.read_message(payload, "control", connection, extensions=(EXTENSION,))
    if value is None or value[0] != NEXT_ENDPOINT or connection != "member":
        raise SpecError("Malformed")
    if set(value) != {0, 1, 2} or not hs._uint(value[1]) or not is_bytes(value[2], 32):
        raise SpecError("Malformed")
    if not ed25519_valid(value[2]):
        raise SpecError("InvalidKey")
    return {"attach": value[1], "key": value[2]}


def receive(payload: bytes, admitted: bool, sender_endpoint: bytes) -> dict:
    """Section 3.3: what the receiver does with a message that reads."""
    message = read(payload)
    if not admitted:
        return {"outcome": "dropped", "step": 3}
    if message["key"] == sender_endpoint:
        return {"outcome": "dropped", "step": 4}
    return {"outcome": "kept", "announced": message["key"]}


def dialed(kept_ticket: bytes, announced: bytes | None) -> list[bytes]:
    """Section 3.4: the tickets a device dials for one member, in order:
    the kept ticket, then the announced ticket when the key differs."""
    ticket = hs.read_ticket_cbor(kept_ticket)
    out = [kept_ticket]
    if announced is not None and announced != ticket["endpoint"]:
        out.append(hs.ticket_cbor(ticket["kind"], announced, ticket["relays"],
                                  ticket["addresses"]))
    return out


def _parameters() -> dict:
    return {"type": NEXT_ENDPOINT, "name": hs.TYPE_NAMES[NEXT_ENDPOINT], "cap": CAP,
            "tables": [{"code": t, "name": at_rest.TABLES[t][0],
                        "scope": "device" if at_rest.TABLES[t][1] == at_rest.DEVICE else "log"}
                       for t in (at_rest.T_NEXT_ENDPOINT, at_rest.T_ANNOUNCED)]}


def _rotation() -> dict:
    kept = example("ext-next-endpoints/kept next seed")
    fresh_current = example("ext-next-endpoints/fresh seed")
    fresh_next = example("ext-next-endpoints/fresh next seed")
    taken = rotate(kept, fresh_current, fresh_next)
    first = rotate(None, fresh_current, kept)
    assert taken["endpoint_key"] == first["next_key"]
    return {
        "with_a_kept_seed": {"kept_next_seed": h(kept), "fresh_seed": h(fresh_current),
                             "fresh_next_seed": h(fresh_next),
                             "endpoint_key": h(taken["endpoint_key"]),
                             "announced_key": h(taken["next_key"]),
                             "record_before": h(kept), "record_after": h(fresh_next)},
        "with_none": {"fresh_seed": h(fresh_current), "fresh_next_seed": h(kept),
                      "endpoint_key": h(first["endpoint_key"]),
                      "announced_key": h(first["next_key"]), "record_after": h(kept)},
    }


def _announcement() -> dict:
    key = endpoint_key(example("ext-next-endpoints/fresh next seed"))
    sender = endpoint_key(example("ext-next-endpoints/sender current seed"))
    message = encode(0, key)
    frame = hs.u32be(len(message)) + message
    assert len(message) <= CAP
    core, rest = hs.read_frame(frame, "control", "member")
    assert core is None and rest == b""
    read_back = read(message)
    assert read_back == {"attach": 0, "key": key}
    current = encode(0, sender)
    return {
        "attach": 0, "next_key": h(key), "sender_endpoint_key": h(sender),
        "message": h(message), "frame": h(frame),
        "core_receiver": "dropped",
        "outcomes": [
            {"description": "on an attach both sides admitted", "message": h(message),
             **_hex(receive(message, True, sender))},
            {"description": "on an attach the receiver has not admitted",
             "message": h(message), **_hex(receive(message, False, sender))},
            {"description": "naming the sender's current key", "message": h(current),
             **_hex(receive(current, True, sender))},
        ],
    }


def _hex(outcome: dict) -> dict:
    return {k: h(v) if isinstance(v, bytes) else v for k, v in outcome.items()}


def _refused() -> list:
    key = endpoint_key(example("ext-next-endpoints/fresh next seed"))
    small = point_encode(small_order_points()[1])
    out = []
    for description, payload, connection in (
            ("an extra key, 3", cbor({0: NEXT_ENDPOINT, 1: 0, 2: key, 3: 0}), "member"),
            ("a key of 31 bytes", cbor({0: NEXT_ENDPOINT, 1: 0, 2: key[:31]}), "member"),
            ("an attach that is not unsigned", cbor({0: NEXT_ENDPOINT, 1: b"\x00", 2: key}),
             "member"),
            ("a small-order key", encode(0, small), "member"),
            ("on a device-to-peer connection", encode(0, key), "peer")):
        out.append({"description": description, "connection": connection,
                    "message": h(payload), "error": hs.expect_class(read, payload, connection)})
    return out


def _reconnecting() -> list:
    old = endpoint_key(example("ext-next-endpoints/member old seed"))
    announced = endpoint_key(example("ext-next-endpoints/member next seed"))
    kept = hs.ticket_cbor(1, old, ["https://relay.example.org"],
                          [bytes([192, 168, 1, 20]) + (47_767).to_bytes(2, "big")])
    out = []
    for description, key in (("an announced key", announced),
                             ("an announced key equal to the ticket's", old)):
        tickets = dialed(kept, key)
        out.append({"description": description, "kept_ticket": h(kept),
                    "announced_key": h(key), "dialed": [h(t) for t in tickets]})
    return out


def ext_next_endpoints_vectors() -> dict:
    return {
        "parameters": _parameters(),
        "rotation": _rotation(),
        "announcement": _announcement(),
        "refused": _refused(),
        "reconnecting": _reconnecting(),
    }


def self_test() -> None:
    v = ext_next_endpoints_vectors()
    assert [r["error"] for r in v["refused"]] == [
        "Malformed", "Malformed", "Malformed", "InvalidKey", "Malformed"], v["refused"]
    assert [o["outcome"] for o in v["announcement"]["outcomes"]] == [
        "kept", "dropped", "dropped"]
    assert [len(r["dialed"]) for r in v["reconnecting"]] == [2, 1]
    second = uncbor(bytes.fromhex(v["reconnecting"][0]["dialed"][1]))
    first = uncbor(bytes.fromhex(v["reconnecting"][0]["dialed"][0]))
    assert {k: x for k, x in second.items() if k != 3} == {k: x for k, x in first.items()
                                                          if k != 3}
    assert v == ext_next_endpoints_vectors(), "the vectors are not deterministic"


if __name__ == "__main__":
    self_test()
    print("ext_next_endpoints: self-test passed")
