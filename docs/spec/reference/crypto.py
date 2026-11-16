"""Cryptography (crypto.md): the label registry, sizes, suites and schemes,
the checks of Ed25519, X25519 and X-Wing public keys with Wycheproof, the
test fixtures, the X-Wing wrap, and signature schemes 0 and 2 with anchors
and coverage (history_sigs.py), written from the specification, independently of any
implementation.

The Wycheproof files are fetched once from a pinned commit into `.cache/`
and checked by SHA-256; with no network and no cache, `wycheproof` stops."""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

import history_sigs as hs
import identity
import keygraph
import mldsa
import wraps
import xwing
from formats import example, xwing_valid
from primitives import field
from primitives import (
    BASE, L, P, SpecError, ed25519_checks, ed25519_public, ed25519_valid, point_add,
    point_decode_lenient, point_encode, point_mul, sha256, small_order_points, small_order_u,
    x25519_checks, x25519_function, x25519_shared, x25519_valid,
)

HERE = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# The label registry ("The label registry"), in the document's order.

REGISTRY = [
    ("frasil/hybrid-signature/ed25519/v1", "first bytes of the message the Ed25519 half of a scheme-2 signature signs", "crypto"),
    ("frasil/hybrid-signature/mldsa/v1", "first bytes of the message the ML-DSA-65 half signs", "crypto"),
    ("frasil/device-hybrid-seed/v1", "hash prefix of a test fixture's X-Wing seed", "crypto"),
    ("frasil/device-mldsa-seed/v1", "hash prefix of a test fixture's ML-DSA-65 seed", "crypto"),
    ("frasil/device-keys-commitment/v1", "hash prefix of a keys commitment, `kc`", "crypto"),
    ("frasil/device-id/v1", "hash prefix of a device ID", "crypto"),
    ("frasil/event/v1", "first bytes of what an event signs", "events"),
    ("frasil/event-id/v1", "hash prefix of an event ID", "events"),
    ("frasil/device-list/possession/v3", "first bytes of the possession statement", "identity"),
    ("frasil/device-list/seniority/v1", "hash prefix that orders list members for the seniority pick", "identity"),
    ("frasil/account-link/v1", "first bytes of an account link statement", "identity"),
    ("frasil/account-unlink/v1", "first bytes of an account unlink statement", "identity"),
    ("frasil/key-fingerprint/v1", "first bytes of a fingerprint's digest input", "identity"),
    ("frasil/recovery/v1", "HKDF salt of every recovery-key derivation", "identity"),
    ("frasil/recovery-key/hybrid/v1", "HKDF info of a recovery key's X-Wing seed", "identity"),
    ("frasil/recovery-key/mldsa/v1", "HKDF info of a recovery key's ML-DSA-65 seed", "identity"),
    ("frasil/recovery-key/fetch/v1", "HKDF info of a recovery key's fetch seed", "identity"),
    ("frasil/passkey-prf-input/v2", "the bytes SHA-256 hashes into the passkey PRF input", "identity"),
    ("frasil/passkey-extract/v1", "HKDF salt of the passkey extract", "identity"),
    ("frasil/passkey-member/v1", "first bytes of the HKDF info of a passkey member's Ed25519 seed", "identity"),
    ("frasil/passkey-unlock/v1", "first bytes of the HKDF info of a passkey's unlock key", "identity"),
    ("frasil/passkey/hybrid/v1", "first bytes of the HKDF info of a passkey member's X-Wing seed", "identity"),
    ("frasil/passkey/mldsa/v1", "first bytes of the HKDF info of a passkey member's ML-DSA-65 seed", "identity"),
    ("frasil/passkey/fetch/v1", "first bytes of the HKDF info of a passkey member's fetch seed", "identity"),
    ("frasil/roster/seniority/v1", "hash prefix that orders grants by seniority", "roster"),
    ("frasil/checkpoint-record/v1", "hash prefix of a checkpoint record's digest", "roster"),
    ("frasil/merge-key/v1", "info prefix of a merged content key", "keys"),
    ("frasil/merge-upload/v1", "info prefix of a merged upload seed", "keys"),
    ("frasil/merge-grant/v1", "info prefix of a merged grant seed", "keys"),
    ("frasil/grant-key/v1", "HKDF info of a grant key's X-Wing seed", "keys"),
    ("frasil/grant-commitment/v1", "hash prefix of a grant rotation's commitment", "keys"),
    ("frasil/read-credential/v1", "HKDF info of a read credential's seed", "keys"),
    ("frasil/upload-key/v1", "HKDF info of an upload key's seed", "keys"),
    ("frasil/space-metadata-key/v1", "HKDF info of a state's metadata key", "keys"),
    ("frasil/object-id-key/v1", "HKDF info of a state's object ID key", "keys"),
    ("frasil/object-nonce-key/v1", "HKDF info of a state's object nonce key", "keys"),
    ("frasil/key-link/v1", "info prefix of a link key, and associated-data prefix of a link", "keys"),
    ("frasil/bundle-wrap/v1", "HPKE info prefix of a bundle wrap", "keys"),
    ("frasil/space-wrap/v1", "HPKE info prefix of a space wrap", "keys"),
    ("frasil/removal-wrap/v1", "HPKE info prefix of a removal wrap", "keys"),
    ("frasil/space-event/v1", "info prefix of a body key, and associated-data prefix of a space event's sealed part", "keys"),
    ("frasil/space-event-commitment/v1", "HKDF info of a body key's commitment", "keys"),
    ("frasil/rotation-rank/v1", "hash prefix of a device's rank for a trigger", "keys"),
    ("frasil/name/v1", "associated-data prefix of a sealed name", "keys"),
    ("frasil/unit/v1", "info prefix of a unit's body key, and associated-data prefix of its seal", "units"),
    ("frasil/unit-key/v1", "HKDF info of a state's unit key", "units"),
    ("frasil/unit-commitment/v1", "HKDF info of a unit's body key commitment", "units"),
    ("frasil/object-seal-key/v1", "HKDF info of a state's object seal key", "units"),
    ("frasil/object-chunk/v1", "associated-data prefix of an object's chunk", "units"),
    ("frasil/stream-id/v1", "hash prefix of a stream ID", "units"),
    ("frasil/head-statement/v1", "first bytes of what a head statement signs", "units"),
    ("frasil/space-snapshot/v1", "first bytes of what a space snapshot signs", "units"),
    ("frasil/member-key/v1", "HKDF info of a state's member key", "transport"),
    ("frasil/member-offer/v1", "prefix of an offer tag's HMAC input", "transport"),
    ("frasil/member-transcript/v1", "prefix of an attach's transcript hash", "transport"),
    ("frasil/member-answer/v1", "prefix of an answer's proof", "transport"),
    ("frasil/member-identify/v1", "prefix of what a device signs to bind itself to a connection", "transport"),
    ("frasil/peer-binding/v1", "prefix of the device-to-peer binding hash", "transport"),
    ("frasil/server-channel/v1", "prefix of the server binding's channel value", "transport"),
    ("frasil/lan-key/v1", "HKDF info of a state's local-network announcement key", "transport"),
    ("frasil/lan-announce/v1", "associated data of a member announcement", "transport"),
    ("frasil/mailbox/v1", "prefix of a mailbox address hash", "transport"),
    ("frasil/mailbox-collect/v1", "prefix of what a device signs to collect its own mailbox", "transport"),
    ("frasil/mailbox-item/v1", "HPKE info prefix of a sealed device mailbox item", "transport"),
    ("frasil/p1/member", "ALPN of a member connection", "transport"),
    ("frasil/p1/peer", "ALPN of a device-to-peer connection", "transport"),
    ("frasil/p1/nearby", "ALPN of a nearby pairing connection", "transport"),
    ("frasil/storage-proof/v1", "first bytes of a credential proof's statement", "peers"),
    ("frasil/storage-merge/v1", "first bytes of a merge statement's message", "peers"),
    ("frasil/skeleton-twin/v1", "HKDF info of a twin secret", "peers"),
    ("frasil/skeleton-twin-commitment/v1", "hash prefix of a twin commitment", "peers"),
    ("frasil/skeleton-binding/v1", "HKDF info of a binding key, and associated-data prefix of a binding", "peers"),
    ("frasil/skeleton-device/v1", "first bytes of the statement a device signs over its pseudonym", "peers"),
    ("frasil/skeleton-token/v1", "HPKE info prefix of a slot token's seal", "peers"),
    ("frasil/skeleton-slot/ed25519/v1", "HKDF info of an administrator slot's Ed25519 seed", "peers"),
    ("frasil/skeleton-slot/mldsa/v1", "HKDF info of an administrator slot's ML-DSA-65 seed", "peers"),
    ("frasil/skeleton-enrol/v1", "first bytes of the statement a slot's keys sign to enrol a pseudonym", "peers"),
    ("frasil/skeleton-root/v1", "first bytes of the statement the founder's device signs over its pseudonym", "peers"),
    ("frasil/skeleton/seniority/v1", "hash prefix of an administrator slot's seniority", "peers"),
    ("frasil/admission/commit/v1", "prefix of the joiner's commitment", "admission"),
    ("frasil/admission/code/v1", "prefix of the code hash", "admission"),
    ("frasil/admission/heads/v1", "prefix of a heads hash", "admission"),
    ("frasil/admission/seal/v1", "HPKE info prefix of an exchange message", "admission"),
    ("frasil/admission/setup/v1", "prefix of the setup MAC's input", "admission"),
    ("frasil/admission/setup-tag/v1", "prefix of the setup tag", "admission"),
    ("frasil/admission/prompt/v1", "prefix of what a lookup prompt's signature signs", "admission"),
    ("frasil/welcome/v1", "HPKE info prefix of a sealed welcome", "admission"),
    ("frasil/access-request/v1", "prefix of what an access request's signature signs", "admission"),
    ("frasil/welcome-request/v1", "prefix of what a welcome request's signature signs", "admission"),
    ("frasil/sealed-device-keys/v1", "associated-data prefix of sealed device keys, and HKDF info of a kind 2 sealing key", "at-rest"),
    ("frasil/unlock-key/v1", "HKDF salt of a kind 2 sealing key", "at-rest"),
    ("frasil/at-rest/seal-key/v1", "HKDF info of a seal key", "at-rest"),
    ("frasil/at-rest/tag-key/v1", "HKDF info of a tag key", "at-rest"),
    ("frasil/at-rest/scope/v1", "prefix of a scope tag's HMAC input", "at-rest"),
    ("frasil/at-rest/item/v1", "prefix of an item tag's HMAC input", "at-rest"),
    ("frasil/at-rest/record/v1", "associated-data prefix of a record", "at-rest"),
    ("frasil/at-rest/mark/v1", "associated-data prefix of the continuity mark", "at-rest"),
    ("frasil/at-rest/app-key/v1", "HKDF info prefix of an application key", "at-rest"),
    ("frasil/space-file/key/v1", "HKDF info of a space file's sealing key", "ext-space-files"),
    ("frasil/space-file/way-in/v1", "associated-data prefix of a sealed way in", "ext-space-files"),
    ("frasil/invite/v1", "HKDF salt of every invite-key derivation", "ext-invite-links"),
    ("frasil/invite/hybrid/v1", "HKDF info of an invite key's X-Wing seed", "ext-invite-links"),
    ("frasil/invite/mldsa/v1", "HKDF info of an invite key's ML-DSA-65 seed", "ext-invite-links"),
    ("frasil/invite/locator/v1", "HKDF info of an invite drop's locator", "ext-invite-links"),
    ("frasil/invite/drop/v1", "HKDF info of an invite drop's key, and its associated-data prefix", "ext-invite-links"),
    ("frasil/leave-request/v1", "prefix of what a leave request's signature signs", "ext-guests"),
    ("frasil/restricted-key/v1", "HKDF info prefix of a restricted space's content key", "ext-restricted-spaces"),
    ("frasil/parent-reference/v1", "HKDF info of the key that seals a restricted unit's parent state, and that seal's associated-data prefix", "ext-restricted-spaces"),
    ("frasil/ephemeral-key/v1", "HKDF info of the ephemeral key", "ext-ephemeral"),
    ("frasil/ephemeral/v1", "prefix of what a sender signs, and of the seal's associated data", "ext-ephemeral"),
    ("frasil/ephemeral-slot/v1", "prefix of an ephemeral slot handle's HMAC input", "ext-ephemeral"),
    ("frasil/library-ticket/v1", "first bytes of what a ticket's issuer signs", "ext-libraries"),
    ("frasil/object-access/v1", "HKDF info of an object's access seed", "ext-libraries"),
    ("frasil/object-hold/v1", "first bytes of what a hold's proof signs", "ext-libraries"),
    ("frasil/device-signed-request/v1", "first bytes of a device-signed request's statement", "ext-app-requests"),
    ("frasil/deposit-key/v1", "`DeriveKeyPair` info of a peer's deposit key, and hash prefix of its key ID", "ext-deposit-tokens"),
    ("frasil/deposit-token/v1", "first bytes of a deposit token's VOPRF input", "ext-deposit-tokens"),
    ("frasil/loro-peer/v1", "hash prefix of a writer's Loro peer ID", "adapter-loro"),
]

PURPOSE_STRINGS = [
    ("ed25519", "the whole HKDF info of a recovery key's Ed25519 seed under frasil/recovery/v1, "
                "and of an invite key's under frasil/invite/v1; a length-prefixed field inside "
                "the passkey infos"),
    ("device-keys", "a length-prefixed field inside the passkey unlock key's info"),
    ("x25519", "reserved as a purpose string"),
]

RESERVED = [
    b"frasil/admission/keys/v1", b"frasil/aead/v1", b"frasil/blob-id/v1",
    b"frasil/blob-nonce/v1", b"frasil/blob-part/v1\x00",
    b"frasil/blob/v1/chunk", b"frasil/blob/v1/manifest", b"frasil/comparison-code/commit/v1",
    b"frasil/comparison-code/v1", b"frasil/device-keys/v1", b"frasil/device-list/entry/v1",
    b"frasil/device-list/label/v1",
    b"frasil/device-list/possession/v1", b"frasil/device-list/possession/v2",
    b"frasil/device-list/v1", b"frasil/device-proof/v1",
    b"frasil/invite-pending/v1", b"frasil/invite-wrap-signature/v1", b"frasil/invite-wrap/v1",
    b"frasil/key-chain-signature/v1", b"frasil/key-chain/v1", b"frasil/key-registration/v1",
    b"frasil/lan/v1", b"frasil/member/1", b"frasil/member/v1", b"frasil/metadata-key/v1",
    b"frasil/nearby/1", b"frasil/passkey-prf-input/v1", b"frasil/peer/1", b"frasil/presence/v1",
    b"frasil/proposal/v2", b"frasil/scope-blob-id/v1", b"frasil/scope-blob-nonce/v1",
    b"frasil/scope-key/v1", b"frasil/scope-metadata-key/v1", b"frasil/scope-wrap/v1",
    b"frasil/scoped-aead/v1", b"frasil/sealed-invite/v1", b"frasil/sealed-pending-update/v1",
    b"frasil/snapshot/v1", b"frasil/update/v1", b"frasil/vault-roster/entry/v1",
    b"frasil/vault-roster/label/v1", b"frasil/vault-roster/v1", b"frasil/wrap-signature/v1",
    b"frasil/wrap/v1",
]

OTHER_NAMES = ["capability names that begin frasil.", "ephemeral names and mailbox content "
               "names that begin frasil/", "frasil.p1", "FRASIL-FP1:", "FRASIL-ADMIT:",
               "FRASIL-SETUP:", "setup-<tag>"]


def registry_labels() -> list[bytes]:
    return [label.encode() for label, _, _ in REGISTRY]


def check_registry() -> list:
    """No label, purpose string or reserved string equals another or is a
    prefix of another. Returns the pairs that do (none)."""
    every = registry_labels() + [p.encode() for p, _ in PURPOSE_STRINGS] + RESERVED
    clashes = []
    for i, a in enumerate(every):
        for b in every[i + 1:]:
            if a.startswith(b) or b.startswith(a):
                clashes.append((a, b))
    return clashes


def module_labels_outside_registry() -> list[str]:
    """Labels the reference modules declare that the registry lists
    neither as a label nor as reserved: to report, not to refuse."""
    import importlib

    known = set(registry_labels()) | set(RESERVED)
    out = []
    for name in ("events", "roster", "identity", "spaces", "keygraph", "clocks", "history_sigs",
                 "units", "adapters", "storage", "library", "admission", "guests", "ephemeral",
                 "handshakes", "at_rest"):
        try:
            module = importlib.import_module(name)
        except Exception:  # noqa: BLE001 - another editor's module may be mid-change
            continue
        for label in getattr(module, "NEW_LABELS", []):
            if label not in known:
                out.append(f"{name}: {label.decode(errors='replace')}")
    return sorted(set(out))


# ---------------------------------------------------------------------------
# Key checks ("Ed25519 public keys", "X25519 public keys", "X-Wing and
# ML-DSA-65 public keys"), each step recorded.

ED_ORDER = [("length_ok", True), ("decodes", True), ("canonical", True),
            ("small_order", False), ("torsion_free", True)]
X_ORDER = [("length_ok", True), ("top_bit_clear", True), ("below_p", True), ("prime_order", True)]


def first_failure(checks: dict, order: list) -> str:
    for step, wanted in order:
        if checks[step] is not wanted:
            return step
    return "accept"


def _neutral(point: tuple) -> bool:
    return point[0] % P == 0 and (point[1] - point[2]) % P == 0


def ed_case(name: str, key: bytes) -> dict:
    checks = ed25519_checks(key)
    verdict = first_failure(checks, ED_ORDER)
    assert (verdict == "accept") == ed25519_valid(key)
    return {"name": name, "key": key.hex(), "decodes": checks["decodes"],
            "canonical": checks["canonical"], "small_order": checks["small_order"],
            "torsion_free": checks["torsion_free"],
            "accepted_by_a_lenient_decoder": len(key) == 32 and point_decode_lenient(key) is not None,
            "result": "accept" if verdict == "accept" else "refuse",
            "refused_at": None if verdict == "accept" else verdict}


def x_case(name: str, key: bytes) -> dict:
    checks = x25519_checks(key)
    verdict = first_failure(checks, X_ORDER)
    assert (verdict == "accept") == x25519_valid(key)
    return {"name": name, "key": key.hex(), "top_bit_clear": checks["top_bit_clear"],
            "below_p": checks["below_p"], "on_curve": checks["on_curve"],
            "prime_order": checks["prime_order"],
            "result": "accept" if verdict == "accept" else "refuse",
            "refused_at": None if verdict == "accept" else verdict}


def _u_of(point: tuple) -> int:
    zi = pow(point[2], P - 2, P)
    y = point[1] * zi % P
    return (1 + y) * pow(1 - y, P - 2, P) % P


def fixtures() -> dict:
    """Two devices built by the fixture derivations ("A device's keys"),
    each with its keys commitment and device ID, and a recovery agent's keys
    commitment and device ID, with no X-Wing key."""
    out = {}
    for name in ("laptop", "phone"):
        k = identity.fixture_keys(example(f"crypto/{name}/ed25519"))
        out[name] = {n: k[n].hex() for n in ("identity_seed", "identity", "xwing_seed", "xwing",
                                             "mldsa_seed", "mldsa_public", "kc", "device_id")}
        assert k["kc"] == hs.keys_commitment(k["mldsa_public"], k["xwing"])
    agent = identity.agent_keys(example("crypto/agent/ed25519"))
    assert agent["kc"] == hs.sha256(hs.KEYS_COMMITMENT_LABEL + field(agent["mldsa_public"])
                                    + bytes(4))
    out["recovery_agent"] = {n: agent[n].hex() for n in ("identity_seed", "identity",
                                                         "mldsa_seed", "mldsa_public", "kc",
                                                         "device_id")}
    out["recovery_agent"]["xwing"] = None
    return out


def device_id_vectors() -> dict:
    """`device_ids`: a device's, a recovery agent's and an administrator
    pseudonym's keys commitment and device ID, each hash's input written
    out ("A device's keys")."""
    import storage

    rows = []
    laptop = identity.fixture_keys(example("crypto/laptop/ed25519"))
    agent = identity.agent_keys(example("crypto/agent/ed25519"))
    pseudonym = storage.pseudonym_signer(example("crypto/pseudonym/ed25519"),
                                         example("crypto/pseudonym/mldsa"))
    for name, ed, mldsa_public, xwing_public in [
        ("a device", laptop["identity"], laptop["mldsa_public"], laptop["xwing"]),
        ("a recovery agent: no X-Wing key, so field(xwing) is u32be(0)", agent["identity"],
         agent["mldsa_public"], None),
        ("an administrator pseudonym: no X-Wing key", pseudonym.ed_public,
         pseudonym.mldsa_public, None),
    ]:
        kc_input = hs.KEYS_COMMITMENT_LABEL + field(mldsa_public) + field(xwing_public or b"")
        kc = hs.keys_commitment(mldsa_public, xwing_public)
        id_input = hs.DEVICE_ID_LABEL + ed + kc
        assert hs.sha256(kc_input) == kc and hs.sha256(id_input) == hs.device_id(ed, kc)
        rows.append({"name": name, "ed25519_public": ed.hex(), "mldsa_public": mldsa_public.hex(),
                     "xwing_public": None if xwing_public is None else xwing_public.hex(),
                     "kc_input": kc_input.hex(), "kc": kc.hex(), "device_id_input": id_input.hex(),
                     "device_id": hs.device_id(ed, kc).hex()})
    # One Ed25519 key under two key sets is two devices.
    other = identity.fixture_keys(example("crypto/phone/ed25519"))
    shared = hs.device_id_of(laptop["identity"], other["mldsa_public"], other["xwing"])
    assert shared != laptop["device_id"]
    rows.append({"name": "the laptop's Ed25519 key beside the phone's ML-DSA-65 and X-Wing keys: "
                         "another device ID",
                 "ed25519_public": laptop["identity"].hex(),
                 "mldsa_public": other["mldsa_public"].hex(), "xwing_public": other["xwing"].hex(),
                 "kc": other["kc"].hex(), "device_id": shared.hex()})
    return {"labels": {"kc": hs.KEYS_COMMITMENT_LABEL.decode(),
                       "device_id": hs.DEVICE_ID_LABEL.decode()},
            "cases": rows}


def key_families() -> dict:
    laptop = identity.fixture_keys(example("crypto/laptop/ed25519"))
    person = example("crypto/person-id")
    member = identity.passkey_keys(person, example("crypto/passkey/prf-output"))
    torsion = small_order_points()
    orders: dict = {}
    for q in torsion:
        order = next(n for n in (1, 2, 4, 8) if _neutral(point_mul(n, q)))
        orders.setdefault(order, []).append(q)
    ed = [ed_case("RFC 8032 test 1 public key", bytes.fromhex(
              "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")),
          ed_case("the base point", point_encode(BASE)),
          ed_case("a device's identity key", laptop["identity"]),
          ed_case("a passkey member's identity key", member["identity"])]
    for order in (1, 2, 4, 8):
        for i, q in enumerate(orders[order]):
            ed.append(ed_case(f"small order: order {order}, point {i + 1}", point_encode(q)))
    for y in range(19):
        for sign in (0, 1):
            encoded = ((y + P) | (sign << 255)).to_bytes(32, "little")
            if point_decode_lenient(encoded) is not None:
                ed.append(ed_case(f"non-canonical: y = p + {y}, sign bit {sign}", encoded))
    ed.append(ed_case("x = 0 with the sign bit set: the neutral point",
                      (1 | (1 << 255)).to_bytes(32, "little")))
    ed.append(ed_case("x = 0 with the sign bit set: the point of order 2",
                      ((P - 1) | (1 << 255)).to_bytes(32, "little")))
    for order in (2, 4, 8):
        ed.append(ed_case(f"mixed order: the base point plus a point of order {order}",
                          point_encode(point_add(BASE, orders[order][0]))))
    not_point = next(bytes([i]) + bytes(31) for i in range(2, 256)
                     if point_decode_lenient(bytes([i]) + bytes(31)) is None)
    ed.append(ed_case("not the encoding of a point", not_point))
    ed.append(ed_case("31 bytes", laptop["identity"][:31]))

    rfc_alice = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    rfc_bob = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    laptop_x = laptop["xwing"][1184:]
    x = [x_case("RFC 7748 Alice's public key", rfc_alice),
         x_case("RFC 7748 Bob's public key", rfc_bob),
         x_case("the base point, u = 9", (9).to_bytes(32, "little")),
         x_case("the X25519 part of a device's X-Wing key", laptop_x),
         x_case("the X25519 part of a passkey member's X-Wing key", member["xwing"][1184:])]
    for u in small_order_u():
        label = {0: "0", 1: "1", P - 1: "p - 1"}.get(u, f"{u:x}"[:8] + "...")
        x.append(x_case(f"small order: u = {label}", u.to_bytes(32, "little")))
    x.append(x_case("bit 255 set on a valid key",
                    (int.from_bytes(rfc_alice, "little") | (1 << 255)).to_bytes(32, "little")))
    for k in (0, 1, 9, 18):
        x.append(x_case(f"p or more: u = p + {k}", (P + k).to_bytes(32, "little")))
    twist = next(u for u in range(2, 1000)
                 if pow((u ** 3 + 486662 * u * u + u) % P, (P - 1) // 2, P) == P - 1)
    x.append(x_case(f"a point on the twist, u = {twist}", twist.to_bytes(32, "little")))
    x.append(x_case("mixed order: the base point plus a point of order 8",
                    _u_of(point_add(BASE, orders[8][0])).to_bytes(32, "little")))
    x.append(x_case("31 bytes", laptop_x[:31]))

    private = example("crypto/at-use/x25519")
    at_use = [{"name": "a valid pair", "private": private.hex(), "public": laptop_x.hex(),
               "shared": x25519_shared(private, laptop_x).hex()}]
    for u in (0, 1):
        public = u.to_bytes(32, "little")
        try:
            x25519_shared(private, public)
            raise AssertionError("an all-zero result was accepted")
        except SpecError as error:
            at_use.append({"name": f"an all-zero result, u = {u}", "private": private.hex(),
                           "public": public.hex(), "error": error.error})

    k = laptop["xwing"]
    xw = []
    for name, key in [("a device's X-Wing key", k),
                      ("a first coefficient of q = 3329", bytes([0x01, 0x0D]) + k[2:]),
                      ("a coefficient of 4095", bytes([0xFF, 0xFF, 0xFF]) + k[3:]),
                      ("an X25519 part of zero", k[:1184] + bytes(32)),
                      ("1,215 bytes", k[:-1])]:
        xw.append({"name": name, "key": key.hex(),
                   "result": "accept" if xwing_valid(key) else "refuse"})
    assert [c["result"] for c in xw] == ["accept"] + ["refuse"] * 4
    return {
        "constants": {"p": f"{P:x}", "l": f"{L:x}",
                      "d": f"{(-121665 * pow(121666, P - 2, P)) % P:x}"},
        "ed25519_keys": ed, "x25519_keys": x, "x25519_at_use": at_use, "xwing_keys": xw,
    }


# ---------------------------------------------------------------------------
# Wycheproof, pinned: the C2SP repository, a commit, and each file's SHA-256.

WYCHEPROOF_REPOSITORY = "https://github.com/C2SP/wycheproof"
WYCHEPROOF_COMMIT = "3fa63dd0344abb611f1fb1d77e119938603ea230"
WYCHEPROOF_FILES = {
    "LICENSE": "58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd",
    "testvectors_v1/ed25519_test.json":
        "752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536",
    "testvectors_v1/x25519_test.json":
        "35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d",
}


def wycheproof(path: str) -> bytes:
    cache = HERE / ".cache" / "wycheproof" / WYCHEPROOF_COMMIT / path
    if not cache.exists():
        url = f"https://raw.githubusercontent.com/C2SP/wycheproof/{WYCHEPROOF_COMMIT}/{path}"
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                data = response.read()
        except OSError as error:
            sys.exit(f"could not fetch {url}: {error}")
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_bytes(data)
    data = cache.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != WYCHEPROOF_FILES[path]:
        sys.exit(f"{path}: SHA-256 {digest} is not the pinned {WYCHEPROOF_FILES[path]}")
    return data


def wycheproof_results() -> dict:
    wycheproof("LICENSE")
    ed_file = json.loads(wycheproof("testvectors_v1/ed25519_test.json"))
    x_file = json.loads(wycheproof("testvectors_v1/x25519_test.json"))
    ed_keys = []
    for group in ed_file["testGroups"]:
        key = bytes.fromhex(group["publicKey"]["pk"])
        ed_keys.append({"group": len(ed_keys), "tests": len(group["tests"]),
                        "result": first_failure(ed25519_checks(key), ED_ORDER)})
    x_tests = []
    for group in x_file["testGroups"]:
        for test in group["tests"]:
            public, private = bytes.fromhex(test["public"]), bytes.fromhex(test["private"])
            ours = x25519_function(private, public)
            if ours == bytes(32):
                use = "refused: all-zero shared secret"
            else:
                assert ours.hex() == test["shared"], test["tcId"]
                use = "shared secret matches"
            entry = first_failure(x25519_checks(public), X_ORDER)
            x_tests.append({"tcId": test["tcId"], "flags": ",".join(test["flags"]),
                            "wycheproof_result": test["result"],
                            "at_entry": entry if entry == "accept" else f"refused at {entry}",
                            "at_use": use})
    return {"repository": WYCHEPROOF_REPOSITORY, "commit": WYCHEPROOF_COMMIT,
            "licence": "Apache-2.0 (the LICENSE file at that commit)",
            "files": {path: {"sha256": digest} for path, digest in WYCHEPROOF_FILES.items()},
            "ed25519_public_keys": ed_keys, "x25519_tests": x_tests}


# ---------------------------------------------------------------------------
# The X-Wing wrap, by bundle wraps (keys.md) to four kinds of recipient.


def wrap_families() -> dict:
    prefix = "crypto/wraps"
    space = example(f"{prefix}/space")
    other_space = example(f"{prefix}/other-space")
    key_name = keygraph.encode_set([example(f"{prefix}/rotation")])
    content = example(f"{prefix}/content-key")
    bundle = keygraph.make_bundle(content=content)
    person = example(f"{prefix}/person-id")
    device = identity.fixture_keys(example(f"{prefix}/laptop/ed25519"))
    output = example(f"{prefix}/passkey/prf-output")
    member = identity.passkey_keys(person, output)
    sheet = identity.recovery_keys(example(f"{prefix}/recovery/secret"))
    invite = identity.invite_keys(example(f"{prefix}/invite/secret"))
    recipients = [
        {"name": "a device", "keys": device,
         "derivation": "SHA-256(\"frasil/device-hybrid-seed/v1\" || identity seed), the fixture "
                       "derivation; a device draws its X-Wing seed at random"},
        {"name": "a passkey member", "keys": member, "prf_output": output, "person_id": person,
         "derivation": "HKDF-Expand(prk, \"frasil/passkey/hybrid/v1\" || field(person_id), 32)"},
        {"name": "a recovery key", "keys": sheet, "secret": sheet["secret"],
         "derivation": "HKDF-Expand(HKDF-Extract(\"frasil/recovery/v1\", secret), "
                       "\"frasil/recovery-key/hybrid/v1\", 32)"},
        {"name": "an invite key", "keys": invite, "secret": invite["secret"],
         "derivation": "HKDF-Expand(HKDF-Extract(\"frasil/invite/v1\", secret), "
                       "\"frasil/invite/hybrid/v1\", 32)"},
    ]
    made_wraps = []
    for index, r in enumerate(recipients):
        k = r["keys"]
        assert xwing_valid(k["xwing"])
        eseed = example(f"{prefix}/eseed/{index}") + example(f"{prefix}/eseed/{index}/2")
        made = keygraph.seal_bundle_wrap(space, key_name, b"", k["device_id"], k["xwing"], bundle,
                                         eseed)
        assert keygraph.open_bundle_wrap(made["wrap"], space, key_name, b"", k["device_id"],
                                         k["xwing_seed"]) == {"content": content}
        info = keygraph.bundle_wrap_info(space, key_name, b"", k["device_id"])
        assert wraps.open_wrap(made["wrap"], k["xwing_seed"], info, keygraph.WRAP_BYTES) == bundle
        r["wrap"] = made["wrap"]
        row = {"name": r["name"], "identity": k["identity"].hex(),
               "xwing_seed": k["xwing_seed"].hex(), "xwing": k["xwing"].hex(),
               "mldsa_public": k["mldsa_public"].hex(), "kc": k["kc"].hex(),
               "device_id": k["device_id"].hex(),
               "derivation": r["derivation"]}
        for extra in ("prf_output", "person_id", "secret"):
            if extra in r:
                row[extra] = r[extra].hex()
        row.update({"encapsulation_randomness": eseed.hex(), "info": made["info"].hex(),
                    "enc": made["enc"].hex(), "ciphertext": made["sealed"].hex(),
                    "wrap": made["wrap"].hex(), "wrap_bytes": len(made["wrap"])})
        made_wraps.append(row)
    dev, other = recipients[0], recipients[1]
    blob = dev["wrap"]
    refusals = []
    for name, data, opener, log in [
        ("the X25519 suite, 0x0020", blob[:1] + wraps.u16be(wraps.SUITE_X25519) + blob[3:], dev,
         space),
        ("an unknown suite, 0x0041", blob[:1] + bytes([0x00, 0x41]) + blob[3:], dev, space),
        ("an unknown version, 2", bytes([0x02]) + blob[1:], dev, space),
        ("truncated to two bytes", blob[:2], dev, space),
        ("one byte short of its length", blob[:-1], dev, space),
        ("one byte longer than its length", blob + b"\x00", dev, space),
        ("opened by another recipient", blob, other, space),
        ("opened in another space", blob, dev, other_space),
    ]:
        k = opener["keys"]
        try:
            keygraph.open_bundle_wrap(data, log, key_name, b"", k["device_id"], k["xwing_seed"])
            error = "accepted"
        except SpecError as e:
            error = e.error
        refusals.append({"name": name, "wrap": data.hex(), "opener": opener["name"],
                         "log": log.hex(), "error": error})
    return {
        "wraps": {"space": space.hex(), "key_name": key_name.hex(), "content_key": content.hex(),
                  "bundle": bundle.hex(), "recipients": made_wraps},
        "wrap_refusals": refusals,
    }


def crypto_vectors() -> dict:
    clashes = check_registry()
    assert not clashes, clashes
    sig = hs.signature_vectors()
    keys = key_families()
    wrap = wrap_families()
    return {
        "specification": "crypto.md",
        "labels": {
            "registry": [{"label": label, "hex": label.encode().hex(), "used_as": used,
                          "in": f"{doc}.md"} for label, used, doc in REGISTRY],
            "purpose_strings": [{"string": p, "hex": p.encode().hex(), "use": use}
                                for p, use in PURPOSE_STRINGS],
            "reserved": [{"string": r.decode(), "hex": r.hex()} for r in RESERVED],
            "other_names": OTHER_NAMES,
            "none_equals_or_prefixes_another": not clashes,
        },
        "sizes": {
            "ed25519_seed": 32, "ed25519_public": 32, "ed25519_signature": 64,
            "xwing_seed": 32, "xwing_public": xwing.XWING_PK_SIZE, "xwing_enc": xwing.XWING_CT_SIZE,
            "mldsa65_seed": 32, "mldsa65_public": mldsa.PUBLIC_KEY_BYTES,
            "mldsa65_secret_expanded": mldsa.SECRET_KEY_BYTES,
            "mldsa65_signature": mldsa.SIGNATURE_BYTES,
            "scheme2_signature": hs.HYBRID_SIGNATURE_BYTES,
            "xchacha20poly1305_nonce": 24, "xchacha20poly1305_tag": 16,
        },
        "suites": [
            {"name": "X-Wing (MLKEM768-X25519)", "kem": wraps.SUITE_XWING, "kdf": 1, "aead": 3,
             "state": "the only suite"},
            {"name": "DHKEM(X25519, HKDF-SHA256)", "kem": wraps.SUITE_X25519,
             "state": "refused: UnsupportedVersion"},
        ],
        "wrap_uses": [
            {"use": "bundle wrap", "label": "frasil/bundle-wrap/v1", "length": 1236},
            {"use": "space wrap", "label": "frasil/space-wrap/v1", "length": 1236},
            {"use": "removal wrap", "label": "frasil/removal-wrap/v1", "length": 1236},
            {"use": "slot token", "label": "frasil/skeleton-token/v1", "length": 1171},
            {"use": "exchange message", "label": "frasil/admission/seal/v1",
             "length": "at least 1,139"},
            {"use": "welcome", "label": "frasil/welcome/v1", "length": "at least 1,139"},
            {"use": "device mailbox item", "label": "frasil/mailbox-item/v1",
             "length": "1,139 to 262,144"},
        ],
        "schemes": [
            {"code": 0, "scheme": "Ed25519, verified strictly", "signature_bytes": 64},
            {"code": 1, "scheme": "reserved", "state": "refused: UnsupportedVersion"},
            {"code": 2, "scheme": "Ed25519 and ML-DSA-65, both of which must verify",
             "signature_bytes": hs.HYBRID_SIGNATURE_BYTES},
        ],
        **keys,
        "wycheproof": wycheproof_results(),
        "fixtures": fixtures(),
        "device_ids": device_id_vectors(),
        **wrap,
        "kind_policy": sig["kind_policy"],
        "signers": sig["signers"],
        "signatures": sig["signatures"],
        "signature_refusals": sig["signature_refusals"],
        "coverage": sig["coverage"],
        "mldsa65_known_answers": hs.mldsa65_known_answers(),
    }


def self_test() -> None:
    assert not check_registry()
    assert len(REGISTRY) == len({label for label, _, _ in REGISTRY})
    for label in (identity.RECOVERY_FETCH_LABEL, identity.PASSKEY_FETCH_LABEL,
                  hs.HYBRID_ED25519_LABEL, keygraph.BUNDLE_WRAP_LABEL, wraps.HYBRID_SEED_LABEL,
                  hs.KEYS_COMMITMENT_LABEL, hs.DEVICE_ID_LABEL):
        assert label in registry_labels(), label
    w = wrap_families()
    errors = {r["name"]: r["error"] for r in w["wrap_refusals"]}
    assert errors["the X25519 suite, 0x0020"] == "UnsupportedVersion"
    assert errors["an unknown version, 2"] == "UnsupportedVersion"
    assert errors["truncated to two bytes"] == "Malformed"
    assert errors["one byte longer than its length"] == "Malformed"
    assert errors["opened by another recipient"] == "Decrypt"
    assert errors["opened in another space"] == "Decrypt"
    k = key_families()
    assert [c["result"] for c in k["x25519_keys"][:5]] == ["accept"] * 5


if __name__ == "__main__":
    self_test()
    print(len(json.dumps(crypto_vectors())))
    print("\n".join(module_labels_outside_registry()))
