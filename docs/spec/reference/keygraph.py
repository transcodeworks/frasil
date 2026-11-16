"""The key graph (keys.md), protocol 1, written from the
specification, independently of any implementation.

Part one, the bytes: rotation sets and key names, the derivations (merge
keys, the grant key pair and its commitment, the read credential, the
upload key, the metadata and object keys, restricted spaces), the recipient
bundle, bundle wraps and space wraps under X-Wing (with no recipient in the
clear), links, gap records, and the rotation payload a roster event or key
event carries: its visible part, its sealed part and its notices, with the
checks a verifier runs in their order.

Part two, the graph: the current key of a set of valid events, entitlement
and potential entitlement, the link gate, what a set of devices can derive,
the heal test, the deliveries a view calls for, and stability for restored
members. Validity is an input: roster.md's procedure decides it. The worked
histories use a small stand-in resolution that is enough for them, and the
vectors record the valid sets it gives, so that roster.md's procedure can be
checked against them.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace

import xwing
from formats import ARRAY, BYTES, MAP, TEXT, UNSIGNED, Reader, cbor_bytes, example, head, u64be
import hashlib
import hmac

from primitives import (
    SpecError,
    ed25519_public,
    ed25519_valid,
    sha256,
    field,
    hkdf,
    hkdf_extract,
    x25519_valid,
    xchacha20poly1305_open,
    xchacha20poly1305_seal,
)

# ---------------------------------------------------------------------------
# Constants and labels (keys.md).

VERSION = 0x01
SUITE_XWING = 0x647A
SUITE_X25519 = 0x0020
NO_SALT = bytes(32)
ID_BYTES = 32
MAX_ROTATIONS = 64
COLLAPSE_ABOVE = 8
SELF_REF_BYTES = 1 + 32 + 8
KIND_CONTENT, KIND_GRANT = 0x01, 0x02
KIND_NAMES = {KIND_CONTENT: "content", KIND_GRANT: "grant"}
FLAG_CONTENT, FLAG_UPLOAD, FLAG_GRANT = 0x01, 0x02, 0x04
XWING_PK_BYTES = xwing.XWING_PK_SIZE  # 1216
XWING_ENC_BYTES = xwing.XWING_CT_SIZE  # 1120
TAG_BYTES = 16
NONCE_BYTES = 24
WRAP_HEADER_BYTES = 1 + 2
BUNDLE_BYTES = 97  # every bundle is padded to its full length
WRAP_BYTES = WRAP_HEADER_BYTES + XWING_ENC_BYTES + BUNDLE_BYTES + TAG_BYTES  # 1236
WRAP_SIZES = (WRAP_BYTES,)
MAX_WRAPS_PER_EVENT = 768       # bundle wraps and space wraps together
MAX_DELIVERIES_PER_EVENT = 64

MERGE_KEY_LABEL = b"frasil/merge-key/v1"
MERGE_UPLOAD_LABEL = b"frasil/merge-upload/v1"
MERGE_GRANT_LABEL = b"frasil/merge-grant/v1"
GRANT_KEY_LABEL = b"frasil/grant-key/v1"
GRANT_COMMITMENT_LABEL = b"frasil/grant-commitment/v1"
READ_CREDENTIAL_LABEL = b"frasil/read-credential/v1"
UPLOAD_KEY_LABEL = b"frasil/upload-key/v1"
METADATA_KEY_LABEL = b"frasil/space-metadata-key/v1"
OBJECT_ID_KEY_LABEL = b"frasil/object-id-key/v1"
OBJECT_NONCE_KEY_LABEL = b"frasil/object-nonce-key/v1"
RESTRICTED_KEY_LABEL = b"frasil/restricted-key/v1"
PARENT_REFERENCE_LABEL = b"frasil/parent-reference/v1"
KEY_LINK_LABEL = b"frasil/key-link/v1"
BUNDLE_WRAP_LABEL = b"frasil/bundle-wrap/v1"
SPACE_WRAP_LABEL = b"frasil/space-wrap/v1"
REMOVAL_WRAP_LABEL = b"frasil/removal-wrap/v1"
REMOVAL_FLAG = 0x08  # the first byte of a removal wrap's plaintext
PAYLOAD_SEAL_LABEL = b"frasil/space-event/v1"  # the sealed part of a space event
BODY_COMMITMENT_LABEL = b"frasil/space-event-commitment/v1"  # commits to its body key
ROTATION_RANK_LABEL = b"frasil/rotation-rank/v1"
ROTATION_RANK_CAP = 63  # overview.md: rotation_rank_cap

NEW_LABELS: list[bytes] = [
    MERGE_KEY_LABEL,
    MERGE_UPLOAD_LABEL,
    MERGE_GRANT_LABEL,
    GRANT_KEY_LABEL,
    GRANT_COMMITMENT_LABEL,
    READ_CREDENTIAL_LABEL,
    UPLOAD_KEY_LABEL,
    METADATA_KEY_LABEL,
    OBJECT_ID_KEY_LABEL,
    OBJECT_NONCE_KEY_LABEL,
    RESTRICTED_KEY_LABEL,
    PARENT_REFERENCE_LABEL,
    KEY_LINK_LABEL,
    BUNDLE_WRAP_LABEL,
    SPACE_WRAP_LABEL,
    REMOVAL_WRAP_LABEL,
    PAYLOAD_SEAL_LABEL,
    BODY_COMMITMENT_LABEL,
    ROTATION_RANK_LABEL,
]


def u16be(value: int) -> bytes:
    return value.to_bytes(2, "big")


# ---------------------------------------------------------------------------
# Rotation sets and key names.


def encode_set(ids) -> bytes:
    """A rotation set: u8(n) || id_1 || ... || id_n, 1 <= n <= 64, each id 32
    bytes, strictly ascending bytewise."""
    ids = list(ids)
    if not ids or any(len(i) != ID_BYTES for i in ids):
        raise SpecError("Malformed")
    if len(ids) > MAX_ROTATIONS:
        raise SpecError("TooManyRotations")
    if any(a >= b for a, b in zip(ids, ids[1:])):
        raise SpecError("Malformed")
    return bytes([len(ids)]) + b"".join(ids)


def canonical(ids) -> tuple:
    """The canonical order of a set of rotation ids: ascending bytewise."""
    return tuple(sorted(set(ids)))


def self_ref(author: bytes, seq: int) -> bytes:
    """The name of the carrying event's own rotation: 0x00 || author || u64be(seq)."""
    assert len(author) == 32
    return b"\x00" + author + u64be(seq)


def read_name(data: bytes, allow_self: bool) -> tuple[bytes, bytes]:
    """Order: split one key name off the front of `data`.
    Returns (name, rest)."""
    if len(data) < 1:
        raise SpecError("Malformed")
    n = data[0]
    if n == 0:
        if not allow_self or len(data) < SELF_REF_BYTES:
            raise SpecError("Malformed")
        return data[:SELF_REF_BYTES], data[SELF_REF_BYTES:]
    if n > MAX_ROTATIONS:
        raise SpecError("TooManyRotations")
    size = 1 + ID_BYTES * n
    if len(data) < size:
        raise SpecError("Malformed")
    ids = [data[1 + ID_BYTES * i: 1 + ID_BYTES * (i + 1)] for i in range(n)]
    if any(a >= b for a, b in zip(ids, ids[1:])):
        raise SpecError("Malformed")
    return data[:size], data[size:]


def decode_set(data: bytes) -> tuple:
    """A whole rotation set, never a self reference, nothing after it."""
    name, rest = read_name(data, allow_self=False)
    if rest:
        raise SpecError("Malformed")
    return tuple(name[1 + ID_BYTES * i: 1 + ID_BYTES * (i + 1)] for i in range(name[0]))


def decode_key_reference(data: bytes) -> tuple:
    """A space's unit names one rotation set, nothing after it."""
    return decode_set(data)


def parent_reference_key(own_secret: bytes) -> bytes:
    return hkdf(NO_SALT, own_secret, PARENT_REFERENCE_LABEL)


def seal_restricted_reference(space: bytes, own: tuple, parent: tuple, own_secret: bytes,
                              nonce: bytes) -> bytes:
    """A restricted space's unit names its own state in the
    clear, then its parent's state sealed under a key from its own secret."""
    aad = PARENT_REFERENCE_LABEL + field(space) + encode_set(own)
    sealed = xchacha20poly1305_seal(parent_reference_key(own_secret), nonce, encode_set(parent),
                                    aad)
    return encode_set(own) + nonce + sealed


def read_restricted_reference(data: bytes) -> tuple:
    """The parts a peer sees: the own state, and the sealed parent state.
    ext-restricted-spaces.md, "Reading a restricted key reference", steps 1
    and 2: the rest is 41 + 32b bytes with 1 <= b <= 64."""
    own, rest = read_name(data, allow_self=False)
    if len(rest) < NONCE_BYTES + 1 + ID_BYTES + TAG_BYTES or (
            len(rest) - NONCE_BYTES - TAG_BYTES - 1) % ID_BYTES:
        raise SpecError("Malformed")
    if (len(rest) - NONCE_BYTES - TAG_BYTES - 1) // ID_BYTES > MAX_ROTATIONS:
        raise SpecError("TooManyRotations")
    return decode_set(own), rest[:NONCE_BYTES], rest[NONCE_BYTES:]


def open_restricted_reference(data: bytes, space: bytes, own_secret: bytes) -> tuple:
    own, nonce, sealed = read_restricted_reference(data)
    aad = PARENT_REFERENCE_LABEL + field(space) + encode_set(own)
    parent = xchacha20poly1305_open(parent_reference_key(own_secret), nonce, sealed, aad)
    return own, decode_set(parent)


# ---------------------------------------------------------------------------
# Derivations.


def merge_secret(label: bytes, space: bytes, ids, secrets) -> dict:
    """T_i = HMAC-SHA256(secret_i, info) for each input in the
    set's order, then HKDF-SHA256(salt = none, ikm = t_1 || ... || t_n, info),
    with info = label || field(space) || encode_set(S), for |S| >= 2. Each
    input is a PRF key under HMAC's standard assumption."""
    ids = list(ids)
    assert len(ids) >= 2 and len(ids) == len(secrets) and list(canonical(ids)) == ids
    info = label + field(space) + encode_set(ids)
    ts = [hmac.new(s, info, hashlib.sha256).digest() for s in secrets]
    return {"info": info, "t": ts, "ikm": b"".join(ts),
            "secret": hkdf(NO_SALT, b"".join(ts), info)}


def state_secret(label: bytes, space: bytes, ids, secret_of) -> bytes:
    """The secret of a state: the rotation's own for one rotation, the merge
    of its inputs' otherwise."""
    ids = canonical(ids)
    if len(ids) == 1:
        return secret_of(ids[0])
    return merge_secret(label, space, ids, [secret_of(i) for i in ids])["secret"]


def content_key(space: bytes, ids, key_of) -> bytes:
    return state_secret(MERGE_KEY_LABEL, space, ids, key_of)


def upload_seed(space: bytes, ids, seed_of) -> bytes:
    return state_secret(MERGE_UPLOAD_LABEL, space, ids, seed_of)


def grant_seed(space: bytes, ids, seed_of) -> bytes:
    return state_secret(MERGE_GRANT_LABEL, space, ids, seed_of)


def grant_key_pair(seed: bytes) -> dict:
    """The grant key, an X-Wing key pair. Like every derivation
    from one state's secret, it binds only its label."""
    xwing_seed = hkdf(NO_SALT, seed, GRANT_KEY_LABEL)
    return {"info": GRANT_KEY_LABEL, "xwing_seed": xwing_seed,
            "public": xwing.xwing_public_key(xwing_seed)}


def grant_commitment(public: bytes, brk: bool) -> bytes:
    """SHA-256(label || u8(break) || grant public key), the
    commitment a grant rotation publishes and a notice is checked against."""
    return sha256(GRANT_COMMITMENT_LABEL + bytes([1 if brk else 0]) + public)


def ed25519_pair(label: bytes, secret: bytes) -> dict:
    seed = hkdf(NO_SALT, secret, label)
    return {"info": label, "seed": seed, "public": ed25519_public(seed)}


def read_credential(key: bytes) -> dict:
    """From the content key of the state (in a restricted
    space, from its own content secret)."""
    return ed25519_pair(READ_CREDENTIAL_LABEL, key)


def upload_key(seed: bytes) -> dict:
    """From the upload seed of the state."""
    return ed25519_pair(UPLOAD_KEY_LABEL, seed)


def derived_keys(key: bytes) -> dict:
    """The metadata key and the object keys of a state."""
    out = {}
    for name, label in (("metadata_key", METADATA_KEY_LABEL),
                        ("object_id_key", OBJECT_ID_KEY_LABEL),
                        ("object_nonce_key", OBJECT_NONCE_KEY_LABEL)):
        out[name] = {"info": label, "key": hkdf(NO_SALT, key, label)}
    return out


def restricted_key(space: bytes, parent: bytes, own: bytes, parent_key: bytes) -> dict:
    """A restricted space's content key, from its own secret (the
    salt) and its parent's content key (the input keying material)."""
    info = RESTRICTED_KEY_LABEL + field(space) + field(parent)
    return {"info": info, "prk": hkdf_extract(own, parent_key),
            "key": hkdf(own, parent_key, info)}


# ---------------------------------------------------------------------------
# The recipient bundle.


def make_bundle(content: bytes | None = None, upload: bytes | None = None,
                grant: bytes | None = None) -> bytes:
    """Flags, then three 32-byte slots in a fixed order; a slot
    the flags leave out is zero, so every bundle is 97 bytes."""
    assert content is not None or grant is not None
    assert upload is None or content is not None
    flags = ((FLAG_CONTENT if content is not None else 0)
             | (FLAG_UPLOAD if upload is not None else 0)
             | (FLAG_GRANT if grant is not None else 0))
    return bytes([flags]) + b"".join(x if x is not None else bytes(32)
                                     for x in (content, upload, grant))


def read_bundle(data: bytes) -> dict:
    if len(data) != BUNDLE_BYTES:
        raise SpecError("Malformed")
    flags = data[0]
    if flags & ~0x07 or flags == 0 or (flags & FLAG_UPLOAD and not flags & FLAG_CONTENT):
        raise SpecError("Malformed")
    out = {}
    for i, (flag, name) in enumerate(((FLAG_CONTENT, "content"), (FLAG_UPLOAD, "upload"),
                                      (FLAG_GRANT, "grant"))):
        slot = data[1 + 32 * i: 33 + 32 * i]
        if flags & flag:
            out[name] = slot
        elif any(slot):
            raise SpecError("Malformed")
    return out


def check_bundle(bundle: dict, key_name: bytes, grant_name: bytes) -> dict:
    """The content key exactly when a key name is given; the grant seed only
    when a grant key name is (a recipient that does not propagate gets none)."""
    if ("content" in bundle) != bool(key_name) or ("grant" in bundle and not grant_name):
        raise SpecError("Malformed")
    return bundle


# ---------------------------------------------------------------------------
# Bundle wraps and space wraps. Neither names its
# recipient: a recipient finds its own by trying to open each.


def bundle_wrap_info(log: bytes, key_name: bytes, grant_name: bytes, recipient: bytes) -> bytes:
    return (BUNDLE_WRAP_LABEL + u16be(SUITE_XWING) + field(log) + field(key_name)
            + field(grant_name) + recipient)


def space_wrap_info(log: bytes, key_name: bytes, grant_name: bytes, grantee: bytes,
                    grantee_rotation: bytes) -> bytes:
    return (SPACE_WRAP_LABEL + u16be(SUITE_XWING) + field(log) + field(key_name)
            + field(grant_name) + grantee + grantee_rotation)


def _seal(public: bytes, info: bytes, bundle: bytes, eseed: bytes) -> dict:
    read_bundle(bundle)
    enc, sealed = xwing.hpke_xwing_seal(public, info, b"", bundle, eseed)
    return {"info": info, "enc": enc, "sealed": sealed,
            "wrap": bytes([VERSION]) + u16be(SUITE_XWING) + enc + sealed}


def seal_bundle_wrap(log: bytes, key_name: bytes, grant_name: bytes, recipient: bytes,
                     recipient_hybrid: bytes, bundle: bytes, eseed: bytes) -> dict:
    """A bundle wrap for one device, with X-Wing's 64 bytes of encapsulation
    randomness given."""
    return _seal(recipient_hybrid, bundle_wrap_info(log, key_name, grant_name, recipient),
                 bundle, eseed)


def seal_space_wrap(log: bytes, key_name: bytes, grant_name: bytes, grantee: bytes,
                    grantee_rotation: bytes, grantee_public: bytes, bundle: bytes,
                    eseed: bytes) -> dict:
    assert len(grantee) == ID_BYTES and len(grantee_rotation) == ID_BYTES
    return _seal(grantee_public,
                 space_wrap_info(log, key_name, grant_name, grantee, grantee_rotation),
                 bundle, eseed)


def read_wrap(blob: bytes) -> dict:
    """The layout, with no key. Both kinds of wrap
    share it."""
    if len(blob) < 1:
        raise SpecError("Malformed")
    if blob[0] != VERSION:
        raise SpecError("UnsupportedVersion")
    if len(blob) < 3 or int.from_bytes(blob[1:3], "big") != SUITE_XWING:
        raise SpecError("UnsupportedVersion" if len(blob) >= 3 else "Malformed")
    if len(blob) not in WRAP_SIZES:
        raise SpecError("Malformed")
    return {"enc": blob[3:3 + XWING_ENC_BYTES], "sealed": blob[3 + XWING_ENC_BYTES:]}


def open_bundle_wrap(blob: bytes, log: bytes, key_name: bytes, grant_name: bytes,
                     device: bytes, hybrid_seed: bytes) -> dict:
    """Taker's checks in order. `Decrypt` is also what a
    device gets when it tries a wrap meant for another."""
    parts = read_wrap(blob)
    info = bundle_wrap_info(log, key_name, grant_name, device)
    plain = xwing.hpke_xwing_open(hybrid_seed, parts["enc"], info, b"", parts["sealed"])
    return check_bundle(read_bundle(plain), key_name, grant_name)


def open_space_wrap(blob: bytes, log: bytes, key_name: bytes, grant_name: bytes,
                    grantee: bytes, grantee_rotation: bytes, grant_xwing_seed: bytes) -> dict:
    """Taker's checks in order: the taker is a device of the
    granted space holding the grant key of that rotation."""
    parts = read_wrap(blob)
    info = space_wrap_info(log, key_name, grant_name, grantee, grantee_rotation)
    plain = xwing.hpke_xwing_open(grant_xwing_seed, parts["enc"], info, b"", parts["sealed"])
    return check_bundle(read_bundle(plain), key_name, grant_name)


# Removal wraps: a rotation's body key, for a device its roster changes
# remove, among the bundle wraps of its own delivery.


def removal_wrap_info(log: bytes, key_name: bytes, grant_name: bytes, recipient: bytes) -> bytes:
    return (REMOVAL_WRAP_LABEL + u16be(SUITE_XWING) + field(log) + field(key_name)
            + field(grant_name) + recipient)


def removal_plaintext(body_key: bytes) -> bytes:
    assert len(body_key) == 32
    return bytes([REMOVAL_FLAG]) + body_key + bytes(64)


def seal_removal_wrap(log: bytes, key_name: bytes, grant_name: bytes, recipient: bytes,
                      recipient_hybrid: bytes, body_key: bytes, eseed: bytes) -> dict:
    """A removal wrap for one removed device, with X-Wing's 64 bytes of
    encapsulation randomness given."""
    info = removal_wrap_info(log, key_name, grant_name, recipient)
    plain = removal_plaintext(body_key)
    enc, sealed = xwing.hpke_xwing_seal(recipient_hybrid, info, b"", plain, eseed)
    return {"info": info, "plaintext": plain, "enc": enc, "sealed": sealed,
            "wrap": bytes([VERSION]) + u16be(SUITE_XWING) + enc + sealed}


def open_removal_wrap(blob: bytes, log: bytes, key_name: bytes, grant_name: bytes,
                      device: bytes, hybrid_seed: bytes, commitment: bytes) -> bytes:
    """The opener's checks in order (keys.md, 3.1): open_wrap, the plaintext's
    shape, then the body key against the carrying event's commitment."""
    parts = read_wrap(blob)
    info = removal_wrap_info(log, key_name, grant_name, device)
    plain = xwing.hpke_xwing_open(hybrid_seed, parts["enc"], info, b"", parts["sealed"])
    if len(plain) != BUNDLE_BYTES or plain[0] != REMOVAL_FLAG or any(plain[33:]):
        raise SpecError("Malformed")
    body_key = plain[1:33]
    if body_commitment(body_key) != commitment:
        raise SpecError("KeyMismatch")
    return body_key


def find_removal_wrap(wraps: list, log: bytes, key_name: bytes, grant_name: bytes,
                      device: bytes, hybrid_seed: bytes, commitment: bytes) -> tuple:
    """Trial decryption for a removal wrap: the index of the first that
    opens, and its body key, or (None, None)."""
    for i, blob in enumerate(wraps):
        try:
            return i, open_removal_wrap(blob, log, key_name, grant_name, device,
                                        hybrid_seed, commitment)
        except SpecError:
            continue
    return None, None


def find_own_wrap(wraps: list, log: bytes, key_name: bytes, grant_name: bytes,
                  device: bytes, hybrid_seed: bytes) -> tuple:
    """Trial decryption: the index of the first wrap that opens, and its
    bundle, or (None, None)."""
    for i, blob in enumerate(wraps):
        try:
            return i, open_bundle_wrap(blob, log, key_name, grant_name, device, hybrid_seed)
        except SpecError:
            continue
    return None, None


# ---------------------------------------------------------------------------
# Links and gap records.

LINK_SEALED_BYTES = 32 + TAG_BYTES


def link_info(kind: int, log: bytes, under: bytes, reaches: bytes) -> bytes:
    return KEY_LINK_LABEL + field(log) + bytes([kind]) + under + reaches


def link_aad(kind: int, log: bytes, under: bytes, reaches: bytes) -> bytes:
    return KEY_LINK_LABEL + bytes([VERSION]) + field(log) + bytes([kind]) + under + reaches


def link_key(kind: int, log: bytes, under: bytes, reaches: bytes, under_secret: bytes) -> bytes:
    return hkdf(NO_SALT, under_secret, link_info(kind, log, under, reaches))


def seal_link(kind: int, log: bytes, under: bytes, reaches: bytes, under_secret: bytes,
              reached_secret: bytes, nonce: bytes) -> dict:
    assert len(nonce) == NONCE_BYTES and under != reaches
    read_name(under, allow_self=True)
    decode_set(reaches)
    key = link_key(kind, log, under, reaches, under_secret)
    aad = link_aad(kind, log, under, reaches)
    sealed = xchacha20poly1305_seal(key, nonce, reached_secret, aad)
    return {"info": link_info(kind, log, under, reaches),
            "prk": hkdf_extract(NO_SALT, under_secret), "link_key": key, "aad": aad,
            "link": bytes([VERSION, kind]) + under + reaches + nonce + sealed}


def read_link(link: bytes) -> dict:
    """The layout, with no key."""
    if len(link) < 1:
        raise SpecError("Malformed")
    if link[0] != VERSION:
        raise SpecError("UnsupportedVersion")
    if len(link) < 2 or link[1] not in KIND_NAMES:
        raise SpecError("Malformed")
    under, rest = read_name(link[2:], allow_self=True)
    reaches, rest = read_name(rest, allow_self=False)
    if len(rest) != NONCE_BYTES + LINK_SEALED_BYTES or under == reaches:
        raise SpecError("Malformed")
    return {"kind": link[1], "under": under, "reaches": reaches,
            "nonce": rest[:NONCE_BYTES], "sealed": rest[NONCE_BYTES:]}


def open_link(link: bytes, kind: int, log: bytes, under: bytes, reaches: bytes,
              under_secret: bytes) -> bytes:
    """Order."""
    parts = read_link(link)
    if parts["kind"] != kind or parts["under"] != under or parts["reaches"] != reaches:
        raise SpecError("Malformed")
    key = link_key(kind, log, under, reaches, under_secret)
    return xchacha20poly1305_open(key, parts["nonce"], parts["sealed"],
                                  link_aad(kind, log, under, reaches))


def gap_record(kind: int, state: bytes) -> bytes:
    decode_set(state)
    return bytes([kind]) + state


def read_gap(record: bytes) -> tuple[int, tuple]:
    if len(record) < 1 or record[0] not in KIND_NAMES:
        raise SpecError("Malformed")
    return record[0], decode_set(record[1:])


# ---------------------------------------------------------------------------
# Deterministic CBOR, the subset the rotation payload uses: unsigned
# integers, byte strings, arrays and maps with unsigned keys in ascending
# order (RFC 8949, section 4.2.1).


def c_uint(value: int) -> bytes:
    return head(UNSIGNED, value)


def c_array(items: list[bytes]) -> bytes:
    return head(ARRAY, len(items)) + b"".join(items)


def c_map(pairs: list[tuple[int, bytes]]) -> bytes:
    pairs = sorted(pairs)
    assert len({k for k, _ in pairs}) == len(pairs)
    return head(MAP, len(pairs)) + b"".join(c_uint(k) + v for k, v in pairs)


def _item(reader: Reader, depth: int = 0, text: bool = False):
    if not reader.data or depth > 4:
        raise SpecError("Malformed")
    major = reader.data[0] >> 5
    if major == UNSIGNED:
        return reader.head(UNSIGNED)
    if major == BYTES:
        return reader.bytes()
    if major == TEXT and text:
        try:
            return reader.take(reader.head(TEXT)).decode("utf-8")
        except UnicodeDecodeError as error:
            raise SpecError("Malformed") from error
    if major == ARRAY:
        return [_item(reader, depth + 1, text) for _ in range(reader.head(ARRAY))]
    if major == MAP:
        out, last = {}, -1
        for _ in range(reader.head(MAP)):
            if not reader.data or reader.data[0] >> 5 != UNSIGNED:
                raise SpecError("Malformed")
            key = reader.head(UNSIGNED)
            if key <= last:
                raise SpecError("Malformed")
            last = key
            out[key] = _item(reader, depth + 1, text)
        return out
    raise SpecError("Malformed")


def decode_cbor(data: bytes, text: bool = False):
    """A value of the subset; text strings only where `text` allows them."""
    reader = Reader(data)
    value = _item(reader, 0, text)
    if reader.data:
        raise SpecError("Malformed")
    return value


# ---------------------------------------------------------------------------
# The rotation payload: a visible part a peer reads, and a
# sealed part only members open.

P_VERSION, P_ROTATES, P_GRANT_COMMITMENT = 1, 2, 3
P_DELIVERIES, P_SEALED, P_SEALED_UNDER = 7, 8, 9
P_READ, P_UPLOAD = 11, 12
P_NONCE = 13  # a genesis's 16-byte nonce, visible (roster.md)
P_COMMITMENT = 14  # the body key's commitment, with every sealed part
P_TWIN = 15  # a roster event's skeleton twin, by event ID
P_RESERVED = (4, 5, 6, 10)  # once break, triggers, frontier and notices
P_LAST = P_TWIN
D_KEY, D_GRANT, D_WRAPS, D_SPACE_WRAPS = 1, 2, 3, 4
S_GRANT, S_BREAK, S_LINKS, S_GAPS, S_NOTICES = 1, 2, 3, 4, 5
S_ROSTER = 16  # a space event's roster changes (roster.md)
S_PADDING = 17  # zero bytes that hide the plaintext's length (roster.md)
S_REFS = 18  # the event's refs to other logs, sealed (events.md)
MAX_REFS = 64  # refs in one body (events.md)
N_SPACE, N_ROTATION, N_PUBLIC, N_FROM_NOW_ON = 1, 2, 3, 4


def encode_sealed_inner(p: dict) -> bytes:
    pairs = []
    if p.get("grant_rotation"):
        pairs.append((S_GRANT, c_uint(1)))
    elif p.get("grant_state"):
        pairs.append((S_GRANT, cbor_bytes(p["grant_state"])))
    if p.get("break"):
        pairs.append((S_BREAK, c_uint(1)))
    if p.get("links"):
        pairs.append((S_LINKS, c_array([cbor_bytes(x) for x in p["links"]])))
    if p.get("gaps"):
        pairs.append((S_GAPS, c_array([cbor_bytes(x) for x in p["gaps"]])))
    if p.get("notices"):
        items = []
        for n in p["notices"]:
            np_ = [(N_SPACE, cbor_bytes(n["space"])), (N_ROTATION, cbor_bytes(n["rotation"])),
                   (N_PUBLIC, cbor_bytes(n["public"]))]
            if n.get("from_now_on"):
                np_.append((N_FROM_NOW_ON, c_uint(1)))
            items.append(c_map(np_))
        pairs.append((S_NOTICES, c_array(items)))
    if p.get("roster") is not None:
        pairs.append((S_ROSTER, cbor_bytes(p["roster"])))
    if p.get("padding") is not None:
        pairs.append((S_PADDING, cbor_bytes(p["padding"])))
    if p.get("refs"):
        pairs.append((S_REFS, encode_refs(p["refs"])))
    for key, value in p.get("raw_inner", {}).items():
        pairs.append((key, value))
    return c_map(pairs)


def encode_refs(refs) -> bytes:
    """Sealed key 18: [log ID, event ID] pairs, 1 to 64, strictly ascending
    by the 64 bytes log || id (events.md)."""
    pairs = sorted(set((bytes(a), bytes(b)) for a, b in refs))
    assert 1 <= len(pairs) <= MAX_REFS
    return c_array([c_array([cbor_bytes(a), cbor_bytes(b)]) for a, b in pairs])


def read_refs(value) -> tuple:
    """Sealed key 18, read: a nonempty array (Malformed) of at most 64
    entries (TooLarge, events.md's limits), each a pair of two 32-byte
    strings, strictly ascending by log || id (Malformed)."""
    if not isinstance(value, list) or not value:
        raise SpecError("Malformed")
    if len(value) > MAX_REFS:
        raise SpecError("TooLarge")
    for ref in value:
        if not (isinstance(ref, list) and len(ref) == 2
                and all(isinstance(x, bytes) and len(x) == ID_BYTES for x in ref)):
            raise SpecError("Malformed")
    flat = [a + b for a, b in value]
    if any(x >= y for x, y in zip(flat, flat[1:])):
        raise SpecError("Malformed")
    return tuple((a, b) for a, b in value)


def seal_aad(log: bytes, author: bytes, seq: int) -> bytes:
    return PAYLOAD_SEAL_LABEL + field(log) + author + u64be(seq)


def seal_key(secret: bytes, log: bytes, author: bytes, seq: int) -> bytes:
    """The per-event body key, from the new rotation's content
    key, or, in an event that does not rotate, from the content key of the
    state it names; bound to the event by its log, author and sequence number.
    Revealing it reveals one event's sealed part and nothing of the state."""
    return hkdf(NO_SALT, secret, seal_aad(log, author, seq))


def body_commitment(body_key: bytes) -> bytes:
    """A visible commitment to the body key, so that a holder of
    the key alone (a newcomer, roster.md) knows it holds the one
    key the author sealed under; the AEAD alone does not commit to its key."""
    return hkdf(NO_SALT, body_key, BODY_COMMITMENT_LABEL)


def encode_payload(p: dict, log: bytes = b"", author: bytes = bytes(32), seq: int = 1,
                   seal_secret: bytes | None = None, nonce: bytes | None = None) -> bytes:
    """`p` holds the visible fields: rotates, grant_commitment, read, upload,
    deliveries [{key, grant, wraps, space_wraps}], sealed_under; and the
    sealed fields: grant_rotation, break, links, gaps, notices [{space,
    rotation, public, from_now_on}]. The sealed part is sealed under
    `seal_secret` with `nonce`, bound to the carrying event."""
    pairs = [(P_VERSION, c_uint(p.get("version", VERSION)))]
    if p.get("rotates"):
        pairs.append((P_ROTATES, c_uint(1)))
    if p.get("grant_commitment") is not None:
        pairs.append((P_GRANT_COMMITMENT, cbor_bytes(p["grant_commitment"])))
    if p.get("deliveries"):
        items = []
        for d in p["deliveries"]:
            dp = []
            if d.get("key"):
                dp.append((D_KEY, cbor_bytes(d["key"])))
            if d.get("grant"):
                dp.append((D_GRANT, cbor_bytes(d["grant"])))
            if d.get("wraps"):
                dp.append((D_WRAPS, c_array([cbor_bytes(w) for w in d["wraps"]])))
            if d.get("space_wraps"):
                dp.append((D_SPACE_WRAPS, c_array([cbor_bytes(w) for w in d["space_wraps"]])))
            items.append(c_map(dp))
        pairs.append((P_DELIVERIES, c_array(items)))
    inner_fields = ("grant_rotation", "break", "links", "gaps", "notices", "raw_inner",
                    "padding", "refs")
    if any(p.get(k) for k in inner_fields) or p.get("roster") is not None \
            or p.get("always_seal"):
        inner = encode_sealed_inner(p)
        key = seal_key(seal_secret, log, author, seq)
        sealed = nonce + xchacha20poly1305_seal(key, nonce, inner, seal_aad(log, author, seq))
        pairs.append((P_SEALED, cbor_bytes(sealed)))
        commitment = p.get("commitment", body_commitment(key))
    if p.get("sealed_under"):
        pairs.append((P_SEALED_UNDER, cbor_bytes(p["sealed_under"])))
    if p.get("read") is not None:
        pairs.append((P_READ, cbor_bytes(p["read"])))
    if p.get("upload") is not None:
        pairs.append((P_UPLOAD, cbor_bytes(p["upload"])))
    if p.get("nonce") is not None:
        pairs.append((P_NONCE, cbor_bytes(p["nonce"])))
    if P_SEALED in dict(pairs) and commitment is not False:  # False: refusal vectors only
        pairs.append((P_COMMITMENT, cbor_bytes(commitment)))
    if p.get("twin") is not None:
        pairs.append((P_TWIN, cbor_bytes(p["twin"])))
    for key, value in p.get("raw", {}).items():   # reserved keys, for refusal vectors only
        pairs.append((key, value))
    return c_map(pairs)


def hybrid_public_valid(key: bytes) -> bool:
    return (len(key) == XWING_PK_BYTES and xwing.mlkem768_encapsulation_key_valid(key[:1184])
            and x25519_valid(key[1184:]))


def _bytes_list(value, minimum: int = 1) -> list:
    if not isinstance(value, list) or len(value) < minimum:
        raise SpecError("Malformed")
    if any(not isinstance(x, bytes) for x in value):
        raise SpecError("Malformed")
    return value


def _flag(value) -> bool:
    if value != 1:
        raise SpecError("Malformed")
    return True


def read_payload(data: bytes, author: bytes, seq: int) -> dict:
    """Visible part, in order: what a peer can check too.
    `author` and `seq` are the carrying event's (envelope keys 3 and 4)."""
    value = decode_cbor(data)                                         # 1
    if not isinstance(value, dict) or type(value.get(P_VERSION)) is not int \
            or value[P_VERSION] < 0:
        raise SpecError("Malformed")
    if value[P_VERSION] != VERSION:                                   # 2
        raise SpecError("UnsupportedVersion")
    allowed = (P_VERSION, P_ROTATES, P_GRANT_COMMITMENT, P_DELIVERIES, P_SEALED,
               P_SEALED_UNDER, P_READ, P_UPLOAD, P_NONCE, P_COMMITMENT, P_TWIN)
    if any(k not in allowed for k in value):                          # 3
        raise SpecError("Malformed")
    rotates = P_ROTATES in value and _flag(value[P_ROTATES])          # 4
    rotating_keys = (P_GRANT_COMMITMENT, P_READ, P_UPLOAD)
    if any((k in value) != rotates for k in rotating_keys):
        raise SpecError("Malformed")
    if (P_SEALED_UNDER in value) == rotates:
        raise SpecError("Malformed")
    if P_SEALED not in value or P_COMMITMENT not in value:  # every space event seals
        raise SpecError("Malformed")
    out = {"rotates": rotates, "grant_commitment": None, "read": None, "upload": None,
           "deliveries": [], "sealed": None, "sealed_under": None}
    for k, size in ((P_GRANT_COMMITMENT, 32), (P_READ, 32), (P_UPLOAD, 32),  # 5
                    (P_COMMITMENT, 32), (P_TWIN, 32), (P_NONCE, 16)):
        if k in value and (not isinstance(value[k], bytes) or len(value[k]) != size):
            raise SpecError("Malformed")
    if P_NONCE in value and (not rotates or P_TWIN in value):
        raise SpecError("Malformed")
    for k in (P_READ, P_UPLOAD):
        if k in value and not ed25519_valid(value[k]):
            raise SpecError("InvalidKey")
    for k, name in ((P_READ, "read"), (P_UPLOAD, "upload"),
                    (P_GRANT_COMMITMENT, "grant_commitment"), (P_COMMITMENT, "commitment"),
                    (P_TWIN, "twin"), (P_NONCE, "nonce")):
        if k in value:
            out[name] = value[k]
    own = self_ref(author, seq)

    def name_ok(name) -> bytes:
        if not isinstance(name, bytes):
            raise SpecError("Malformed")
        parsed, rest = read_name(name, allow_self=True)
        if rest or (parsed[0] == 0 and (parsed != own or not rotates)):
            raise SpecError("Malformed")
        return parsed

    if P_DELIVERIES in value:                                         # 6
        deliveries = value[P_DELIVERIES]
        if not isinstance(deliveries, list) or not deliveries:
            raise SpecError("Malformed")
        for d in deliveries:
            if not isinstance(d, dict) or any(k < D_KEY or k > D_SPACE_WRAPS for k in d):
                raise SpecError("Malformed")
            if D_KEY not in d and D_GRANT not in d:
                raise SpecError("Malformed")
            if D_WRAPS not in d and D_SPACE_WRAPS not in d:
                raise SpecError("Malformed")
            entry = {"key": name_ok(d[D_KEY]) if D_KEY in d else None,
                     "grant": name_ok(d[D_GRANT]) if D_GRANT in d else None,
                     "wraps": _bytes_list(d[D_WRAPS]) if D_WRAPS in d else [],
                     "space_wraps": _bytes_list(d[D_SPACE_WRAPS]) if D_SPACE_WRAPS in d else []}
            for w in entry["wraps"] + entry["space_wraps"]:
                read_wrap(w)
            out["deliveries"].append(entry)
        wraps = sum(len(d["wraps"]) + len(d["space_wraps"]) for d in out["deliveries"])
        if len(out["deliveries"]) > MAX_DELIVERIES_PER_EVENT or wraps > MAX_WRAPS_PER_EVENT:
            raise SpecError("Malformed")
        for d in out["deliveries"]:
            # The own delivery names both states by the self reference, so a
            # peer cannot tell a grant rotation by its shape.
            if d["key"] == own and d["grant"] not in (None, own):
                raise SpecError("Malformed")
    sealed = value[P_SEALED]                                          # 7
    if not isinstance(sealed, bytes) or len(sealed) < NONCE_BYTES + TAG_BYTES + 1:
        raise SpecError("Malformed")
    out["sealed"] = sealed
    if P_SEALED_UNDER in value:
        out["sealed_under"] = name_ok(value[P_SEALED_UNDER])
        if out["sealed_under"][0] == 0:
            raise SpecError("Malformed")
    out["_own"] = own
    out["_name_ok"] = name_ok
    return out


def open_sealed(payload: dict, secret: bytes, log: bytes, author: bytes, seq: int) -> dict:
    """Sealed part, in order, by a member that holds the
    secret it is sealed under. Returns the payload with its sealed fields."""
    return open_with_body_key(payload, seal_key(secret, log, author, seq), log, author, seq)


def open_with_body_key(payload: dict, body_key: bytes, log: bytes, author: bytes,
                       seq: int) -> dict:
    """The same, by a holder of the event's body key alone: a newcomer whose
    snapshot carries it (roster.md)."""
    out = dict(payload)
    out.update({"grant_rotation": False, "break": False, "links": [], "gaps": [],
                "notices": [], "roster": None, "refs": ()})
    if payload["sealed"] is None:
        return out
    sealed = payload["sealed"]
    if body_commitment(body_key) != payload["commitment"]:              # 8
        raise SpecError("BadSeal")
    try:
        inner = xchacha20poly1305_open(body_key, sealed[:NONCE_BYTES], sealed[NONCE_BYTES:],
                                       seal_aad(log, author, seq))
    except SpecError as error:
        raise SpecError("BadSeal") from error
    value = decode_cbor(inner)                                        # 9
    if not isinstance(value, dict) or set(value) - {
            S_GRANT, S_BREAK, S_LINKS, S_GAPS, S_NOTICES, S_ROSTER, S_PADDING, S_REFS}:
        raise SpecError("Malformed")
    if S_PADDING in value and (not isinstance(value[S_PADDING], bytes)
                               or any(value[S_PADDING])):
        raise SpecError("Malformed")
    if S_ROSTER in value:
        if not isinstance(value[S_ROSTER], bytes):
            raise SpecError("Malformed")
        out["roster"] = value[S_ROSTER]
    rotates = payload["rotates"]
    if (S_GRANT in value or S_BREAK in value) and not rotates:
        raise SpecError("Malformed")
    # Sealed key 1: 1 for a grant rotation, whose own delivery's grant slot
    # carries its new grant seed; else the key name of the grant state that
    # slot carries.
    out["grant_state"] = None
    if S_GRANT in value:
        if isinstance(value[S_GRANT], bytes):
            decode_set(value[S_GRANT])
            out["grant_state"] = value[S_GRANT]
        else:
            _flag(value[S_GRANT])
    out["grant_rotation"] = S_GRANT in value and value[S_GRANT] == 1
    own_grant = any(d["key"] == payload["_own"] and d["grant"] == payload["_own"]
                    for d in payload["deliveries"])
    if own_grant and S_GRANT not in value:
        raise SpecError("Malformed")
    out["break"] = S_BREAK in value and _flag(value[S_BREAK])
    if S_REFS in value:
        out["refs"] = read_refs(value[S_REFS])
    if S_LINKS in value:                                              # 10
        for link in _bytes_list(value[S_LINKS]):
            payload["_name_ok"](read_link(link)["under"])
            out["links"].append(link)
    if S_GAPS in value:                                               # 11
        for record in _bytes_list(value[S_GAPS]):
            read_gap(record)
            out["gaps"].append(record)
    if S_NOTICES in value:                                            # 12
        notices = value[S_NOTICES]
        if not isinstance(notices, list) or not notices:
            raise SpecError("Malformed")
        for n in notices:
            if not isinstance(n, dict) or set(n) - {N_SPACE, N_ROTATION, N_PUBLIC, N_FROM_NOW_ON}:
                raise SpecError("Malformed")
            if not all(isinstance(n.get(k), bytes) for k in (N_SPACE, N_ROTATION, N_PUBLIC)):
                raise SpecError("Malformed")
            if len(n[N_SPACE]) != ID_BYTES or len(n[N_ROTATION]) != ID_BYTES or \
                    len(n[N_PUBLIC]) != XWING_PK_BYTES:
                raise SpecError("Malformed")
            from_now_on = N_FROM_NOW_ON in n and _flag(n[N_FROM_NOW_ON])
            if from_now_on and not out["break"]:
                raise SpecError("Malformed")
            if not hybrid_public_valid(n[N_PUBLIC]):
                raise SpecError("InvalidKey")
            out["notices"].append({"space": n[N_SPACE], "rotation": n[N_ROTATION],
                                   "public": n[N_PUBLIC], "from_now_on": from_now_on})
    return out


def check_payload_context(p: dict | None, ctx: dict) -> None:
    """Checks that need the carrying event and the roster at
    its place, in order. `ctx` holds: event ("genesis", "roster" or "key");
    refs (its sealed refs name events of other logs); refs_granted (they name
    an event of the log of a space this space grants); notice_covers (the
    payload carries a notice for each such space). Each notice's own checks
    (check_notice) decide no verdict;
    removes, removes_self, removes_propagating, lowers_to_read, lowers_self,
    admits_from_now_on, admits_propagating, author_propagates, restricted;
    sealed_under_stale (a valid rotation in the event's past follows the state
    it is sealed under). `p` is the opened payload, or None when the event
    carries none."""
    event = ctx["event"]
    rotates = p is not None and p["rotates"]
    exempt = ctx.get("removes_self") or ctx.get("lowers_self")
    must_rotate = event == "genesis" or ctx.get("admits_from_now_on") or (
        not exempt and (ctx.get("removes") or ctx.get("lowers_to_read")))
    if must_rotate and not rotates:                                   # 1
        raise SpecError("RotationRequired")
    if p is None:
        return
    if not rotates and ctx.get("sealed_under_stale"):                 # 2
        raise SpecError("StaleSeal")
    response = event == "key" and ctx.get("refs")
    if ctx.get("admits_from_now_on") and not p["break"]:             # 3
        raise SpecError("BreakRequired")
    if p["break"] and not (ctx.get("admits_from_now_on") or response):  # 4
        raise SpecError("UnexpectedBreak")
    grant = p.get("grant_rotation")
    if grant and (ctx.get("restricted") or not ctx.get("author_propagates")):  # 5
        raise SpecError("GrantKeyNotAllowed")
    required = not ctx.get("restricted") and (
        event == "genesis" or ctx.get("removes_propagating")
        or (ctx.get("admits_from_now_on") and ctx.get("admits_propagating"))
        or bool(response and rotates))
    if required and not grant:                                        # 6
        raise SpecError("GrantKeyRequired")
    if event == "roster" and grant and not required:                  # 7
        raise SpecError("UnexpectedGrantKey")
    if event == "key" and ctx.get("refs_granted") \
            and not ctx.get("notice_covers"):                         # 8
        raise SpecError("NoticeRequired")


def check_notice(notice: dict, grantee_rotation: dict | None, author_propagates_there,
                 stale: bool = False) -> None:
    """Each notice, in order: whether it admits its principal at this
    replica, never the verdict of its event. Pending is a notice this replica
    cannot check yet, which admits nothing. `grantee_rotation` is what this
    replica holds of the grantee's rotation the notice names: its visible
    part's `grant_commitment` and whether it is `valid` in the grantee's log
    as held; None when it does not hold it. `stale` says that some valid
    rotation of the grantee that a valid event of this space names in its
    refs is not in that rotation's past. `author_propagates_there` says
    whether the notice's author is a propagating member of the grantee at
    that rotation (None: not known)."""
    if grantee_rotation is None:
        raise SpecError("Pending")
    if not grantee_rotation.get("valid", True):
        raise SpecError("NoticeVoid")
    if grantee_rotation.get("grant_commitment") != grant_commitment(notice["public"],
                                                                    notice["from_now_on"]):
        raise SpecError("NoticeMismatch")
    if stale:
        raise SpecError("NoticeStale")
    if author_propagates_there is None:
        raise SpecError("Pending")
    if not author_propagates_there:
        raise SpecError("NotGranteeMember")


def check_commitment(bundle: dict, payload: dict) -> None:
    """A taker that opens the secrets of one rotation checks
    them against that rotation's commitments. `payload` is the rotation's
    opened payload."""
    if "content" in bundle and read_credential(bundle["content"])["public"] != payload["read"]:
        raise SpecError("KeyMismatch")
    if "upload" in bundle and upload_key(bundle["upload"])["public"] != payload["upload"]:
        raise SpecError("KeyMismatch")
    if "grant" in bundle and grant_commitment(grant_key_pair(bundle["grant"])["public"],
                                              payload.get("break", False)) != \
            payload["grant_commitment"]:
        raise SpecError("KeyMismatch")


def verify_slots(bundle: dict, payload: dict) -> tuple[dict, list]:
    """Keep each secret of a single rotation's bundle that its
    commitment confirms, drop the others. Returns (kept, dropped)."""
    kept, dropped = {}, []
    for slot, ok in (("content", lambda x: read_credential(x)["public"] == payload["read"]),
                     ("upload", lambda x: upload_key(x)["public"] == payload["upload"]),
                     ("grant", lambda x: grant_commitment(grant_key_pair(x)["public"],
                                                          payload.get("break", False))
                      == payload["grant_commitment"])):
        if slot in bundle:
            if ok(bundle[slot]):
                kept[slot] = bundle[slot]
            else:
                dropped.append(slot)
    return kept, dropped


def seal_mismatch(key_source: str) -> str:
    """What a commitment mismatch means depends on where
    the key came from. A key derived from rotation keys that each matched
    their commitments proves the author sealed under something else:
    `BadSeal`. A merged key received whole by wrap is provisional, and a
    mismatch may be the wrapper's junk: the event is held, `Sealed`."""
    return "BadSeal" if key_source == "derived" else "Sealed"


def tries(delivery: dict, rotations_held_in_log, holds, entitled) -> bool:
    """A device tries a delivery's wraps only if every rotation it
    names is an event of the log it holds, and it lacks the named state and is
    entitled to it. `holds` and `entitled` are functions of a key name."""
    names = [n for n in (delivery["key"], delivery["grant"]) if n is not None]
    for n in names:
        if n[0] != 0 and not all(r in rotations_held_in_log for r in decode_set(n)):
            return False
    return any(not holds(n) and entitled(n) for n in names)


def filler_commitment(content_key_: bytes) -> bytes:
    """The commitment a rotation that is not a grant rotation
    publishes in key 3, indistinguishable from a real one to a peer. Derived
    here so the vectors are fixed; a writer draws it at random."""
    return sha256(b"filler" + content_key_)


# ---------------------------------------------------------------------------
# The rank.


def rank_value(space: bytes, trigger: bytes, device: bytes) -> dict:
    """SHA-256("frasil/rotation-rank/v1" || field(space) || field(trigger) ||
    device ID); the value is its first 8 bytes, big-endian."""
    digest = sha256(ROTATION_RANK_LABEL + field(space) + field(trigger) + device)
    return {"digest": digest, "value": int.from_bytes(digest[:8], "big")}


def rank_order(space: bytes, trigger: bytes, devices) -> list:
    """The candidate devices in rank order: by value, then by device ID."""
    return sorted(devices, key=lambda d: (rank_value(space, trigger, d)["value"], d))


def rank_delay(position: int, step: int) -> int:
    """overview.md: min(rank, 63) x rotation_step, in seconds."""
    return min(position, ROTATION_RANK_CAP) * step


# ---------------------------------------------------------------------------
# Part two: the graph.
#
# A history is a set of events with causal parents (events.md). The kinds
# that matter here: "genesis" and the roster events "grant", "remove" and
# "demote" (roster.md), "key" (a key event) and "unit". Members are the
# principals a roster grants; each has devices. A rotation is the genesis,
# a roster event that rotates, or a key event that rotates; a grant rotation
# also carries a fresh grant seed.

READ, WRITE, ADMIN = 1, 2, 3
LEVEL_NAMES = {READ: "read", WRITE: "write", ADMIN: "administer"}
ROSTER_KINDS = frozenset({"grant", "remove", "demote", "succeed"})
# A successor needs no level: its authority is the invite's (roster.md, 5.8).
NEED = {"grant": ADMIN, "remove": ADMIN, "demote": ADMIN, "key": WRITE, "unit": WRITE,
        "succeed": 0, "checkpoint": ADMIN}


def bundle_contents(level: int, propagates: bool, invite: bool = False) -> tuple:
    """The secrets a recipient's bundle carries. An invite key
    gets the upload seed whatever its level, so that its claimant can store
    its successor and its list; and the grant seed unless it carries
    `session`, since it propagates as its claimant will."""
    out = ["content"]
    if level >= WRITE or invite:
        out.append("upload")
    if propagates:
        out.append("grant")
    return tuple(out)


@dataclass(frozen=True)
class Event:
    id: bytes
    label: str
    kind: str
    author: str
    parents: frozenset
    target: str = ""
    level: int = 0
    history: bool = True
    session: bool = False
    rotates: bool = False
    grant: bool = False
    brk: bool = False
    keyref: tuple = ()
    # A notice: (principal, the grantee's rotation, from now on).
    notice: tuple = ()
    # The event's sealed refs (inner key 18), as (space, rotation) pairs of other logs.
    refs: tuple = ()
    # A notice this replica refused (NoticeMismatch, NotGranteeMember): it
    # admits nothing, and the carrying event stands.
    bogus: bool = False
    # A grant of an invite key (roster.md); a "succeed" event is
    # its successor, signed by the invite key, naming the claimant as target.
    invite: bool = False


@dataclass(frozen=True)
class Wrap:
    kind: int
    state: tuple
    device: str


@dataclass(frozen=True)
class Link:
    kind: int
    under: tuple
    reaches: tuple


@dataclass(frozen=True)
class Gap:
    kind: int
    state: tuple


@dataclass
class Member:
    level: int
    history: bool
    session: bool
    grants: tuple


class Graph:
    """The algorithms over one space's history. Every
    function takes the view W (event ids, closed under parents), the valid
    set V within it (roster.md), and the key artifacts the view holds."""

    def __init__(self, space: bytes):
        self.space = space
        self.devices: dict[str, tuple] = {}
        self.dev_member: dict[str, str] = {}
        self.events: dict[bytes, Event] = {}
        self.anc: dict[bytes, frozenset] = {}
        self.height: dict[bytes, int] = {}
        self.genesis: bytes | None = None
        self._memo: dict = {}
        # For space principals: each grantee rotation's past in its own log,
        # itself included.
        self.foreign_past: dict[str, frozenset] = {}
        # The devices each granted space's merged roster holds now, as this
        # replica holds that space's log.
        self.foreign_current: dict[str, set] = {}
        # For a principal whose devices include one admitted at a break of the
        # granted space: this space's responses to those breaks. The
        # principal is entitled only to states that follow them.
        self.principal_floor: dict[str, list] = {}
        # Devices whose person's list revoked them, as this replica holds the
        # list (keys.md, "Healing"): they are no longer inside, and nothing is
        # wrapped for them, but they keep every state they received.
        self.revoked: set = set()
        # keys.md, "Keys after a checkpoint": in the graph of a checkpoint's
        # world, the root's record (world_graph), and the granted spaces the
        # record gives a floor. Empty in any other graph.
        self.records: dict[bytes, dict] = {}
        self.record_floor: set = set()

    def add_member(self, member: str, devices) -> None:
        self.devices[member] = tuple(devices)
        for d in devices:
            self.dev_member.setdefault(d, member)

    def device_level(self, device: str, ros: dict) -> int:
        """A device's level: the highest of the members in `ros` it belongs to."""
        return max((x.level for m, x in ros.items() if device in self.receivers(m)), default=0)

    def receivers(self, member: str) -> tuple:
        """A member's devices that wraps are made for: those its person's
        list has not revoked."""
        return tuple(d for d in self.devices[member] if d not in self.revoked)

    def device_session(self, device: str, ros: dict) -> bool:
        return all(x.session for m, x in ros.items() if device in self.devices[m])

    def add(self, e: Event) -> None:
        anc = set()
        for p in e.parents:
            anc |= self.anc[p]
            anc.add(p)
        self.events[e.id] = e
        self.anc[e.id] = frozenset(anc)
        self.height[e.id] = 1 + max((self.height[p] for p in e.parents), default=-1)
        if e.kind == "genesis":
            self.genesis = e.id
        self._memo.clear()

    # -- order -------------------------------------------------------------
    def le(self, a: bytes, b: bytes) -> bool:
        return a == b or a in self.anc[b]

    def concurrent(self, a: bytes, b: bytes) -> bool:
        return a != b and a not in self.anc[b] and b not in self.anc[a]

    def closure(self, ids) -> frozenset:
        out = set(ids)
        for i in ids:
            out |= self.anc[i]
        return frozenset(out)

    def heads(self, W) -> frozenset:
        covered = set()
        for i in W:
            covered |= self.anc[i]
        return frozenset(i for i in W if i not in covered)

    def member(self, device: str) -> str:
        return self.dev_member[device]

    def is_rotation(self, i: bytes, kind: int = KIND_CONTENT) -> bool:
        e = self.events[i]
        rotation = e.kind in ("genesis", "checkpoint") or (
            e.kind in ROSTER_KINDS | {"key"} and e.rotates)
        return rotation and (kind == KIND_CONTENT or e.grant)

    # -- the roster of a set of valid roster events (roster.md) -------------
    def roster_of(self, P: frozenset) -> dict:
        key = ("roster", P)
        if key in self._memo:
            return self._memo[key]
        grants, removals, demotions = defaultdict(list), defaultdict(list), defaultdict(list)
        retiring = []
        for i in P:
            e = self.events[i]
            if self.admits(e):
                grants[e.notice[0]].append((i, WRITE, not e.notice[2], False))
            if e.refs:
                retiring.append(i)
            if e.kind == "genesis":
                grants[e.target].append((i, ADMIN, True, False))
            elif e.kind == "grant":
                grants[e.target].append((i, e.level, e.history, e.session))
            elif e.kind == "remove":
                removals[e.target].append(i)
            elif e.kind == "demote":
                demotions[e.target].append(i)
            elif e.kind == "checkpoint" and i in self.records:
                # The root of a checkpoint's world stands as its genesis:
                # the record's members granted at it, its principals
                # admitted at it where this replica holds their space's log.
                for m, (level, history, session) in sorted(self.records[i]["members"].items()):
                    if "@" in m and m.split("@", 1)[0] not in self.foreign_current:
                        continue
                    grants[m].append((i, level, history, session))
            elif e.kind == "succeed":
                # The invite key is out, and its claimant holds the invite's
                # grant from the successor on (roster.md).
                invite = self.member(e.author)
                removals[invite].append(i)
                g = max((x for x in P if self.events[x].kind == "grant"
                         and self.events[x].target == invite and self.le(x, i)),
                        key=lambda x: (self.height[x], x))
                ge = self.events[g]
                grants[e.target].append((i, ge.level, ge.history, ge.session))
        # Standing rule: a principal (T, R) is in force only if
        # R has in its past every rotation of T that an event of P names in
        # its sealed refs. A later notice can never bring one out of force back.
        named = defaultdict(set)
        for i in retiring:
            for space, rotation in self.events[i].refs:
                named[space].add(rotation)
        for i in P:
            for space, rotation in self.records.get(i, {}).get("named", ()):
                named[space].add(rotation)
        out = {}
        for m, gs in grants.items():
            if "@" in m:
                space, rotation = m.split("@", 1)
                if not named[space] <= self.foreign_past.get(rotation, frozenset()):
                    continue
            inforce = [g for g in gs if not any(g[0] in self.anc[r] for r in removals[m])]
            if not inforce:
                continue
            level = max(g[1] for g in inforce)
            for d in demotions[m]:
                if any(g[0] in self.anc[d] for g in inforce):
                    level = min(level, self.events[d].level)
            out[m] = Member(level, any(g[2] for g in inforce), all(g[3] for g in inforce),
                            tuple(sorted(g[0] for g in inforce)))
        self._memo[key] = out
        return out

    def admits(self, e: Event) -> bool:
        """keys.md, "Notices and space principals": e's notice admits its
        principal only where this replica holds the granted space's log and
        the notice passes its checks there (NoticeStale aside, which the
        standing rule in roster_of covers)."""
        return bool(e.notice) and not e.bogus \
            and e.notice[0].split("@", 1)[0] in self.foreign_current

    def valid_roster(self, V: frozenset) -> frozenset:
        """The valid events that change membership: the genesis, roster
        events, and key events that carry a notice or put a principal out of force."""
        return frozenset(i for i in V if self.events[i].kind in ("genesis", "checkpoint")
                         or self.events[i].kind in ROSTER_KINDS
                         or self.events[i].notice or self.events[i].refs)

    def members(self, V: frozenset, kind: int = KIND_CONTENT, W: frozenset | None = None) -> dict:
        """The merged roster; for the grant graph, only members
        that propagate. Given the view W, an invite key whose claim was raced
        is left out: it receives nothing more and counts as outside."""
        ros = self.roster_of(self.valid_roster(V))
        if kind == KIND_GRANT:
            ros = {m: x for m, x in ros.items() if not x.session}
        if W is not None:
            raced = self.raced(W, V)
            ros = {m: x for m, x in ros.items() if m not in raced}
        return ros

    def invites(self) -> set:
        return {e.target for e in self.events.values() if e.kind == "grant" and e.invite}

    def raced(self, W: frozenset, V: frozenset) -> set:
        """Invite keys with a successor in the view that is void as
        ClaimRaced (ext-invite-links.md, "Keys"): the stand-in models no
        close, so a void successor that races another, one concurrent with
        it and signed by the same invite key. A successor void for any other
        reason leaves its invite key as it was."""
        out = {self.member(e.author) for i, e in self.events.items()
               if i in W and e.kind == "succeed" and i not in V
               and i in self.forked_successors(W)}
        # In a checkpoint's world, an invite key its record shows raced
        # (ext-invite-links.md, "Across a checkpoint").
        for i, rec in self.records.items():
            if i in V:
                out |= set(rec.get("raced", ()))
        return out

    def forked_successors(self, W: frozenset) -> set:
        """The successors of the view that fork their invite key's chain:
        each concurrent with another successor the same key signed."""
        succ = [i for i in W if self.events[i].kind == "succeed"]
        return {i for i in succ for x in succ
                if x != i and self.events[x].author == self.events[i].author
                and self.concurrent(x, i)}

    def inside_devices(self, V: frozenset, kind: int, W: frozenset | None = None) -> set:
        """The devices of the members; of a space principal
        (T, R), only those this space's effective membership holds, that is,
        those still in T as this replica holds T's log. Any other holder of
        g_R counts as outside. A replica that does not hold T's log counts
        none of them as inside (neither_devices). An invite key in force is
        inside; after a valid successor, a revocation or a raced claim it is
        outside (ext-invite-links.md, "Keys"): its claimant is inside as a
        member of its own."""
        out = set()
        members = self.members(V, kind, W)
        for m in members:
            devices = set(self.receivers(m))
            if "@" in m:
                devices &= self.foreign_current.get(m.split("@", 1)[0], set())
            out |= devices
        return out

    def neither_devices(self, V: frozenset, kind: int, W: frozenset | None = None) -> set:
        """keys.md, "Notices and space principals": the devices of a
        principal whose space's log this replica does not hold, and that are
        not inside otherwise, count as neither inside nor outside."""
        inside = self.inside_devices(V, kind, W)
        return {d for m in self.members(V, kind, W)
                if "@" in m and m.split("@", 1)[0] not in self.foreign_current
                for d in self.devices[m] if d not in inside}

    # -- the current key ------------------------------------
    def current(self, V: frozenset, kind: int = KIND_CONTENT) -> tuple:
        rots = [i for i in V if self.is_rotation(i, kind)]
        return canonical(r for r in rots if not any(r in self.anc[o] for o in rots))

    # -- conflicts, for stability ------------------------------------------
    def attacks(self, x: bytes, e: bytes) -> bool:
        """roster.md's rule, as the stand-in uses it: does roster event x void
        concurrent event e?"""
        xe, ee = self.events[x], self.events[e]
        if xe.kind not in ("remove", "demote") or not self.concurrent(x, e) \
                or ee.kind == "checkpoint":
            return False
        am = self.member(ee.author)
        if ee.kind == "demote" and ee.target == am:
            return False  # a self-demotion is never voided by concurrency
        if xe.kind == "remove" and xe.target == am:
            return True
        if xe.kind == "demote" and xe.target == am and xe.level < NEED.get(ee.kind, WRITE):
            return True
        return ee.kind == "grant" and xe.kind == "remove" and xe.target == ee.target

    # -- entitlement ------------------------------------------
    def place(self, V: frozenset, state: tuple) -> frozenset:
        return frozenset(p for p in self.valid_roster(V) if any(self.le(p, i) for i in state))

    def ent(self, V: frozenset, m: str, state: tuple, kind: int = KIND_CONTENT) -> bool:
        key = ("ent", V, m, state, kind)
        if key in self._memo:
            return self._memo[key]
        if self.records and any(i not in self.events for i in state):
            # keys.md, "Keys after a checkpoint": a state with a rotation
            # before the world's root, which this graph does not hold.
            out = all(self.ent_before(V, m, i, kind) if i not in self.events
                      else self.ent(V, m, (i,), kind) for i in state)
            self._memo[key] = out
            return out
        ros = self.roster_of(self.place(V, state))
        out = m in ros and (kind == KIND_CONTENT or not ros[m].session)
        if not out:
            # Rule 4: a claimant takes its invite key's entitlement.
            for i in V:
                e = self.events[i]
                if e.kind == "succeed" and e.target == m \
                        and self.ent(V, self.member(e.author), state, kind):
                    out = True
                    break
        if not out and len(state) > 1:
            out = all(self.ent(V, m, (i,), kind) for i in state)
        elif not out:
            r = state[0]
            now = self.members(V, kind)
            inforce = now[m].grants if m in now else ()
            for x in self.valid_roster(V):
                e = self.events[x]
                grant = ((e.kind == "grant" and e.target == m and e.history
                          and not (kind == KIND_GRANT and e.session))
                         or (self.admits(e) and e.notice[0] == m and not e.notice[2]))
                if grant and not self.le(x, r) and (r in self.anc[x] or x in inforce):
                    out = True
                    break
        # A principal is entitled only where every one of its
        # devices is, through its own path. A device admitted at a break of
        # the granted space is entitled here only from this space's response
        # to that break.
        floors = self.principal_floor.get(m, ())
        if out and floors:
            out = all(self.le(f, r) for f in floors for r in state)
        self._memo[key] = out
        return out

    def ent_before(self, V: frozenset, m: str, r: bytes, kind: int = KIND_CONTENT) -> bool:
        """keys.md, "Keys after a checkpoint", entitlement to rotation r
        before the root, at a replica that forgot it: a valid "with history"
        grant after the root entitles its member; so does a valid "with
        history" notice, unless the record gives its space a floor. A member
        of the record alone is not entitled here: only a replica that holds
        the past can tell, and only such a replica delivers it."""
        if "@" in m and m.split("@", 1)[0] in self.record_floor:
            return False
        for x in self.valid_roster(V):
            e = self.events[x]
            if x == self.genesis:
                continue
            if (e.kind == "grant" and e.target == m and e.history
                    and not (kind == KIND_GRANT and e.session)):
                return True
            if self.admits(e) and e.notice[0] == m and not e.notice[2]:
                return True
        return False

    def void_removals(self, W: frozenset, V: frozenset, m: str) -> list:
        return sorted(r for r in W if self.events[r].kind == "remove"
                      and self.events[r].target == m and r not in V)

    def voiders(self, V: frozenset, r: bytes) -> list:
        return sorted(x for x in self.valid_roster(V) if x != self.genesis and self.attacks(x, r))

    def stable(self, W: frozenset, V: frozenset, r: bytes) -> bool:
        """Roster.md, defines it: every current
        administrator device has a valid event whose past holds the voided
        removal and every event voiding it (or is one of them)."""
        need = [r] + self.voiders(V, r)
        admins = [d for m, x in sorted(self.members(V).items()) if x.level == ADMIN
                  for d in self.devices[m]]
        for d in admins:
            if not any(self.events[e].author == d and all(self.le(n, e) for n in need)
                       for e in V):
                return False
        return True

    def made_while_out(self, V, m, state, kind, r) -> bool:
        """M is entitled to the state only because the removal
        r is void, and the state was made without knowledge of that: its
        past lacks r or one of the events that void it."""
        if self.ent(V | {r}, m, state, kind):
            return False
        past = self.closure(state)
        return not all(x in past for x in [r] + self.voiders(V, r))

    def restored_pending(self, W, V, m, state, kind, timed_out=False) -> bool:
        """A key made while m was out, before the voiding of m's removal is
        stable."""
        if timed_out:
            return False
        return any(self.made_while_out(V, m, state, kind, r) and not self.stable(W, V, r)
                   for r in self.void_removals(W, V, m))

    def ent_eff(self, W, V, m, state, kind=KIND_CONTENT, timed_out=False) -> bool:
        return (self.ent(V, m, state, kind)
                and not self.restored_pending(W, V, m, state, kind, timed_out))

    def breaks(self, W: frozenset, kind: int) -> dict:
        out = defaultdict(list)
        for i in W:
            e = self.events[i]
            if e.kind == "grant" and not e.history and not (kind == KIND_GRANT and e.session):
                out[e.target].append(i)
            if e.notice and e.notice[2]:
                out[e.notice[0]].append(i)
        for m, floors in self.principal_floor.items():
            out[m].extend(f for f in floors if f in W)
        return out

    def gate(self, W, V, under: tuple, k: tuple, kind=KIND_CONTENT, timed_out=False) -> bool:
        """May a link to k hang under `under`?"""
        if not all(self.ent_eff(W, V, m, k, kind, timed_out) for m in self.members(V, kind)):
            return False
        pts = self.closure(under)
        for m, bs in self.breaks(W, kind).items():
            if not any(b in pts for b in bs):
                continue
            if self.ent(V, m, k, kind) or any(self.le(b, r) for b in bs for r in k):
                continue
            return False
        return True


class Holdings:
    """What each device can derive from the artifacts of one
    kind that a view holds."""

    def __init__(self, g: Graph, W: frozenset, arts, V: frozenset, kind: int):
        self.g = g
        self.wraps = defaultdict(set)
        self.links = defaultdict(set)
        self.gaps = set()
        univ = set()
        for a in arts:
            if a.kind != kind:
                continue
            if isinstance(a, Wrap):
                self.wraps[a.device].add(a.state)
                states = (a.state,)
            elif isinstance(a, Link):
                self.links[a.under].add(a.reaches)
                states = (a.under, a.reaches)
            else:
                self.gaps.add(a.state)
                states = (a.state,)
            univ.update(s for s in states if len(s) > 1)
        if kind == KIND_CONTENT:
            univ.update(g.events[i].keyref for i in W if len(g.events[i].keyref) > 1)
        current = g.current(V, kind)
        if len(current) > 1:
            univ.add(current)
        self.univ = univ
        self.authored = defaultdict(set)
        for i in W:
            if g.is_rotation(i, kind):
                self.authored[g.events[i].author].add((i,))
        self.holders = set(self.wraps) | set(self.authored)
        self._cache = {}

    def reach(self, devices) -> frozenset:
        devices = frozenset(devices)
        if devices in self._cache:
            return self._cache[devices]
        held = set()
        for d in devices:
            held |= self.wraps.get(d, set())
            held |= self.authored.get(d, set())
        todo = list(held)
        while True:
            while todo:
                k = todo.pop()
                for r in self.links.get(k, ()):
                    if r not in held:
                        held.add(r)
                        todo.append(r)
            new = [s for s in self.univ if s not in held and all((i,) in held for i in s)]
            if not new:
                break
            held.update(new)
            todo.extend(new)
        self._cache[devices] = frozenset(held)
        return self._cache[devices]


def heal_due(g: Graph, W, V, arts, kind: int) -> str | None:
    """: "outside" when the devices outside the merged roster
    together derive the current key, "unreachable" when no inside device
    derives it, else None."""
    K = g.current(V, kind)
    if not K:
        return None
    hold = Holdings(g, W, arts, V, kind)
    inside = g.inside_devices(V, kind, W)
    outside = sorted(hold.holders - inside - g.neither_devices(V, kind, W))
    if outside and K in hold.reach(outside):
        return "outside"
    if inside and not any(K in hold.reach({d}) for d in inside):
        return "unreachable"
    return None


def plan(g: Graph, W, V, arts, kind: int, room, timed_out=False) -> dict:
    """The deliveries a view calls for, each with the first room
    device that can make it (a writer that derives what it delivers), or
    None when no device in the room can."""
    hold = Holdings(g, W, arts, V, kind)
    K = g.current(V, kind)
    now = g.members(V, kind, W)
    content_now = g.members(V, KIND_CONTENT, W)
    pubs = [d for d in sorted(room) if g.device_level(d, now) and
            g.device_level(d, content_now) >= WRITE]
    healing = heal_due(g, W, V, arts, kind)
    preach = {p: hold.reach({p}) for p in pubs}
    wraps, links, gaps, waiting = {}, {}, set(), set()
    art_set = set(arts)

    def give(k, d, why):
        if k in hold.reach({d}) or (k, d) in wraps:
            return
        wraps[(k, d)] = (next((p for p in pubs if k in preach[p]), None), why)

    def link_or_wrap(under, k, why):
        if healing:
            return  # No new link under a state the heal test condemns
        if g.gate(W, V, under, k, kind, timed_out):
            if Link(kind, under, k) not in art_set:
                links[(under, k)] = next((p for p in pubs if under in preach[p]
                                          and k in preach[p]), None)
            return
        if Gap(kind, k) not in art_set:
            gaps.add(k)
        for m in sorted(now):
            if g.ent_eff(W, V, m, k, kind, timed_out):
                for d in g.receivers(m):
                    give(k, d, why)

    for m in sorted(now):                                             # 14.1
        for d in g.receivers(m):
            give(K, d, "current")
    keys = {(i,) for i in W if g.is_rotation(i, kind)}                # 14.2
    if kind == KIND_CONTENT:
        # Every state an event is sealed under: a unit's key reference, or
        # a space event's that does not rotate.
        keys |= {g.events[i].keyref for i in W if g.events[i].keyref}
    for m in sorted(now):
        for k in sorted(keys):
            if k == K or not g.ent(V, m, k, kind):
                continue
            pending = g.restored_pending(W, V, m, k, kind, timed_out)
            for d in g.receivers(m):
                if k in hold.reach({d}):
                    continue
                if pending:
                    waiting.add((k, d))
                else:
                    give(k, d, "entitled")
    if len(K) > 1:                                                    # 14.3
        for i in K:
            link_or_wrap(K, (i,), "merge input")
    void = {(i,) for i in W if g.is_rotation(i, kind) and i not in V}  # 14.4
    if kind == KIND_CONTENT:
        void |= {g.events[u].keyref for u in W if g.events[u].kind == "unit"
                 and len(g.events[u].keyref) > 1
                 and any(x not in V for x in g.events[u].keyref)}
    for k in sorted(void - {K}):
        link_or_wrap(K, k, "void")
    for m in sorted(now):                                             # 14.5
        for k in sorted(hold.gaps | gaps):
            if g.ent_eff(W, V, m, k, kind, timed_out):
                for d in g.receivers(m):
                    give(k, d, "gap")
    return {
        "kind": kind,
        "wraps": sorted((k, d, by, why) for (k, d), (by, why) in wraps.items()),
        "links": sorted((u, k, by) for (u, k), by in links.items()),
        "gaps": sorted(gaps),
        "waiting": sorted(waiting),
        "heal": healing,
    }


# ---------------------------------------------------------------------------
# The worked histories: a small world of devices that act on their own views
# and meet in rooms. Validity comes from a stand-in for roster.md's
# procedure (decide roster events in causal order; a
# valid removal or demotion voids its target's concurrent actions and a
# concurrent grant of its target; in a mutual pair the more senior author's
# stands, every administrator here holding the top rank), which settles
# every history here; the vectors record the valid sets it gives.


class World:
    def __init__(self, name: str):
        self.name = name
        self.space = example(f"keygraph/{name}/space")
        self.g = Graph(self.space)
        self.views: dict[str, set] = {}
        self.art_views: dict[str, set] = {}
        self.arts: list = []
        self.art_index: dict = {}
        self.secrets: dict[bytes, dict] = {}
        self._valid: dict = {}
        self.heals = 0
        self.labels: dict[bytes, str] = {}
        self.record: list = []        # every act, for the cross-check with roster.py
        # keys.md, "Keys after a checkpoint": each checkpoint's record, and
        # each artifact's publisher's view when it was first published, which
        # says whether it belongs to a checkpoint's world.
        self.records: dict[bytes, dict] = {}
        self.art_view: dict[int, frozenset] = {}
        self.checks: list = []        # (title, view labels, valid labels) per checkpoint

    # -- setup ---------------------------------------------------------------
    def new_member(self, member: str, devices) -> None:
        self.g.add_member(member, devices)
        for d in devices:
            self.views.setdefault(d, set())
            self.art_views.setdefault(d, set())

    def event_id(self, label: str) -> bytes:
        return example(f"keygraph/{self.name}/{label}")

    def genesis(self, member: str, devices) -> Event:
        self.new_member(member, devices)
        e = Event(self.event_id("genesis"), "genesis", "genesis", devices[0], frozenset(),
                  target=member, level=ADMIN, rotates=True, grant=True)
        self._add(e)
        self.record.append({"label": "genesis", "kind": "genesis", "author": devices[0],
                            "view": frozenset(), "kw": {"target": member}})
        for d in devices:
            self.views[d].add(e.id)
        self._secrets(e)
        for kind in (KIND_CONTENT, KIND_GRANT):
            for d in devices:
                self.publish(devices[0], Wrap(kind, (e.id,), d))
        self.sync(devices)
        return e

    def _add(self, e: Event) -> None:
        assert e.id not in self.g.events, e.label
        self.g.add(e)
        self.labels[e.id] = e.label
        self._valid.clear()

    def _secrets(self, e: Event) -> None:
        base = f"keygraph/{self.name}/{e.label}"
        self.secrets[e.id] = {"content": example(base + "/content"),
                              "upload": example(base + "/upload")}
        if e.grant:
            self.secrets[e.id]["grant"] = example(base + "/grant")

    # -- the stand-in resolution ----------------------------------------------
    def auth(self, e: bytes, P: frozenset) -> bool:
        g = self.g
        ee = g.events[e]
        ros = g.roster_of(P)
        am = g.member(ee.author)
        # A notice decides no verdict: a refused or stale one only admits
        # nothing (roster_of).
        if g.device_level(ee.author, ros) < NEED[ee.kind]:
            return False
        if ee.kind == "succeed":
            # admission.md: the invite in, accepted once, the
            # claimant not in.
            once = not any(g.events[p].kind == "succeed" and g.events[p].author == ee.author
                           for p in P)
            return am in ros and once and ee.target not in ros
        if ee.kind == "grant":
            return ee.target not in ros and ee.target != am
        if ee.kind == "remove":
            return ee.target in ros and ee.target != am
        if ee.kind == "demote":
            return ee.target in ros and ros[ee.target].level > ee.level
        return True

    def resolve(self, W) -> frozenset:
        W = frozenset(W)
        if W in self._valid:
            return self._valid[W]
        g = self.g
        gen = g.genesis
        R = sorted((i for i in W if g.events[i].kind in ROSTER_KINDS),
                   key=lambda i: (g.height[i], i))
        status: dict = {}
        # roster.md: two concurrent successors of one invite are
        # both void; the stand-in models no close.
        for e in R:
            if g.events[e].kind == "succeed" and any(
                    x != e and g.events[x].kind == "succeed"
                    and g.events[x].author == g.events[e].author and g.concurrent(x, e)
                    for x in R):
                status[e] = False

        def past_valid(e):
            return frozenset([gen] + [p for p in R if p in g.anc[e] and status.get(p)])

        def seniority(e):
            """The height of e's author's most senior valid grant at e's
            place, the founder's being the genesis (roster.md, section 3.2);
            every administrator here holds the top rank."""
            a = g.events[e].author
            if a == g.events[gen].author:
                return (0, gen)
            heights = [(g.height[p], p) for p in R if p in g.anc[e] and status.get(p)
                       and g.events[p].kind == "grant" and g.events[p].target == g.member(a)]
            return min(heights, default=(1 << 30, e))

        progress = True
        while progress:
            progress = False
            for e in R:
                if e in status or any(p not in status for p in R if p in g.anc[e]):
                    continue
                if not self.auth(e, past_valid(e)):
                    status[e] = False
                    progress = True
                    continue
                beaten = pending = False
                for x in R:
                    if x == e or not g.attacks(x, e):
                        continue
                    if g.attacks(e, x):
                        # A mutual pair: the more senior author's stands.
                        if any(p not in status for p in R if p in g.anc[x]):
                            pending = True
                            continue
                        if seniority(x) > seniority(e):
                            continue
                    if x not in status:
                        pending = True
                    elif status[x]:
                        beaten = True
                if beaten or not pending:
                    status[e] = not beaten
                    progress = True
        assert len(status) == len(R), "the stand-in cannot settle this history"
        vr = frozenset([gen] + [e for e in R if status[e]])
        valid = set(vr)
        # Key events and units, in causal order: a key event's notices and
        # refs change who is in, so the place of a later event
        # holds the valid key events before it.
        for i in sorted(W, key=lambda x: (g.height[x], x)):
            if g.events[i].kind in ("key", "unit", "checkpoint"):
                P = frozenset(p for p in valid if p in g.anc[i]
                              and (p in vr or g.events[p].notice or g.events[p].refs))
                if self.auth(i, P) and not any(g.attacks(x, i) for x in vr if x != gen):
                    valid.add(i)
        self._valid[W] = frozenset(valid)
        return self._valid[W]

    # -- checkpoints (keys.md, "Keys after a checkpoint") ----------------------
    def make_checkpoint(self, device: str, label: str) -> Event:
        """`device`, an administrator, signs a checkpoint over its view: a
        grant rotation, no break, whose record is the roster of its past
        (roster.md, "The checkpoint record"): each member in, but invite
        keys that count as outside (raced; a claimed one is out), each with
        its level, history and session; the raced invite keys; each space
        principal in force; the granted spaces with a floor (a "from now
        on" notice or a principal's floor in its past); and the rotations
        of granted spaces its refs name. Its own delivery wraps for the
        inside of its past alone (_on_rotation)."""
        g = self.g
        W = frozenset(self.views[device])
        V = self.resolve(W)
        raced = g.raced(W, V)
        members = {m: (x.level, x.history, x.session)
                   for m, x in g.roster_of(g.valid_roster(V)).items()}
        floor = {e.notice[0].split("@", 1)[0] for i in V for e in (g.events[i],)
                 if g.admits(e) and e.notice[2]}
        floor |= {m.split("@", 1)[0] for m, fs in g.principal_floor.items()
                  if m in members and any(f in V for f in fs)}
        named = sorted({ref for i in V for ref in g.events[i].refs})
        e = self.act(device, "checkpoint", label, rotates=True, grant=True)
        self.records[e.id] = {"members": members, "raced": sorted(raced & set(members)),
                              "floor": sorted(floor), "named": named}
        self.cross_check = False  # roster.py's checkpoints.py judges these
        return e

    def world_graph(self, c: bytes) -> Graph:
        """The key graph of checkpoint c's world (roster.md, "The world
        after a checkpoint"; keys.md, "Keys after a checkpoint"): c as its
        root, standing as its genesis with its record, and the events after
        c, each linked to its parents among them only. A replica that forgot
        what came before c holds this and nothing else."""
        g = self.g
        wg = Graph(g.space)
        wg.devices, wg.dev_member = dict(g.devices), dict(g.dev_member)
        wg.foreign_past = dict(g.foreign_past)
        wg.foreign_current = {k: set(v) for k, v in g.foreign_current.items()}
        wg.revoked = set(g.revoked)
        wg.add(replace(g.events[c], parents=frozenset()))
        wg.genesis = c
        for i in sorted((i for i in g.events if c in g.anc[i]), key=lambda i: (g.height[i], i)):
            e = g.events[i]
            wg.add(replace(e, parents=frozenset(p for p in e.parents if p in wg.events)))
        # A principal's floor before c is the record's (keys.md, "Keys after
        # a checkpoint"); floors after c stay.
        wg.principal_floor = {m: [f for f in fs if f in wg.events]
                              for m, fs in g.principal_floor.items()}
        wg.principal_floor = {m: fs for m, fs in wg.principal_floor.items() if fs}
        wg.records = {c: self.records[c]}
        wg.record_floor = set(self.records[c]["floor"])
        return wg

    def world_view(self, device: str, c: bytes) -> tuple:
        """What a replica keeping c in effect holds of `device`'s view: the
        world's graph, its events, its valid set (the full view's, after c,
        with c), and the artifacts of c and the events after it: those
        published by a device whose view held c. Late artifacts and those
        before c count for nothing."""
        W, V, _ = self.view(device)
        assert c in V, "the checkpoint is valid in this view"
        wg = self.world_graph(c)
        Wc = frozenset(i for i in W if i in wg.events)
        # An event after c with a parent, other than its author's previous
        # event, that is neither c nor after c is void (MixedCut): no
        # rotation of the world.
        g = self.g
        mixed = {i for i in Wc if i != c and any(
            p not in wg.events and g.events[p].author != g.events[i].author
            for p in g.events[i].parents)}
        Vc = frozenset(i for i in V if i in wg.events and i not in mixed)
        arts = [self.arts[i] for i in sorted(self.art_views[device]) if c in self.art_view[i]]
        return wg, Wc, Vc, arts

    # -- artifacts and rooms -----------------------------------------------------
    def publish(self, device: str, art) -> bool:
        idx = self.art_index.get(art)
        if idx is None:
            idx = len(self.arts)
            self.arts.append(art)
            self.art_index[art] = idx
            self.art_view[idx] = frozenset(self.views[device])
        if idx in self.art_views[device]:
            return False
        self.art_views[device].add(idx)
        return True

    def sync(self, devices) -> None:
        ev, art = set(), set()
        for d in devices:
            ev |= self.views[d]
            art |= self.art_views[d]
        for d in devices:
            self.views[d] = set(ev)
            self.art_views[d] = set(art)

    def view(self, device: str) -> tuple:
        W = frozenset(self.views[device])
        arts = [self.arts[i] for i in sorted(self.art_views[device])]
        return W, self.resolve(W), arts

    # -- acting -------------------------------------------------------------
    def act(self, device: str, kind: str, label: str, view=None, **kw) -> Event:
        W = frozenset(self.views[device] if view is None else view)
        V0 = self.resolve(W)
        g = self.g
        if kind in ROSTER_KINDS and kind != "succeed":
            kw.setdefault("rotates", True)
        if kind == "unit" or not kw.get("rotates", False):
            # A unit, or a space event that does not rotate: sealed under
            # the author's current content state.
            kw["keyref"] = g.current(V0, KIND_CONTENT)
        if kind == "remove":
            ros = g.members(V0)
            kw.setdefault("grant", kw["target"] not in ros or not ros[kw["target"]].session)
        if kind == "grant" and not kw.get("history", True):
            kw["brk"] = True
            kw.setdefault("grant", not kw.get("session", False))
        e = Event(self.event_id(label), label, kind, device, g.heads(W), **kw)
        self._add(e)
        self.record.append({"label": label, "kind": kind, "author": device,
                            "view": frozenset(self.labels[i] for i in W), "kw": dict(kw)})
        self.views[device].add(e.id)
        if g.is_rotation(e.id):
            self._secrets(e)
            self._on_rotation(device, e, W, V0)
        return e

    def _on_rotation(self, device: str, e: Event, W: frozenset, V0: frozenset) -> None:
        """A rotation wraps its keys for the roster at
        its place, links the previous key where the gate allows, and records
        a gap otherwise."""
        g = self.g
        W2 = W | {e.id}
        V2 = self.resolve(W2)
        for kind in (KIND_CONTENT, KIND_GRANT):
            if kind == KIND_GRANT and not e.grant:
                continue
            now = g.members(V2, kind, W2)
            for m in sorted(now):
                for d in g.receivers(m):
                    self.publish(device, Wrap(kind, (e.id,), d))
            prev = g.current(V0, kind)
            if not prev:
                continue
            arts = self.view(device)[2]
            if e.brk:
                self.publish(device, Gap(kind, prev))
            elif g.gate(W2, V2, (e.id,), prev, kind):
                self.publish(device, Link(kind, (e.id,), prev))
            else:
                self.publish(device, Gap(kind, prev))
                hold = Holdings(g, W2, arts, V2, kind)
                if prev in hold.reach({device}):
                    for m in sorted(now):
                        if g.ent_eff(W2, V2, m, prev, kind):
                            for d in g.receivers(m):
                                if prev not in hold.reach({d}):
                                    self.publish(device, Wrap(kind, prev, d))
            if e.kind == "grant" and e.history:
                arts = self.view(device)[2]
                hold = Holdings(g, W2, arts, V2, kind)
                for k in sorted(hold.gaps):
                    if g.ent_eff(W2, V2, e.target, k, kind) and k in hold.reach({device}):
                        for d in g.receivers(e.target):
                            if k not in hold.reach({d}):
                                self.publish(device, Wrap(kind, k, d))

    def apply(self, p: dict) -> bool:
        changed = False
        kind = p["kind"]
        for k, d, by, _ in p["wraps"]:
            if by is not None:
                changed |= self.publish(by, Wrap(kind, k, d))
        for u, k, by in p["links"]:
            if by is not None:
                changed |= self.publish(by, Link(kind, u, k))
        return changed

    def gaps_by(self, p: dict, room) -> bool:
        changed = False
        for k in p["gaps"]:
            for d in sorted(room):
                changed |= self.publish(d, Gap(p["kind"], k))
                break
        return changed

    def healer(self, room, W, V, arts, grant_due: bool) -> tuple:
        """The first writer of the room that derives the
        current key; for a grant heal, one that propagates."""
        g = self.g
        content = g.members(V)
        writers = [d for d in sorted(room) if g.device_level(d, content) >= WRITE]
        hold = Holdings(g, W, arts, V, KIND_CONTENT)
        K = g.current(V)
        holding = [d for d in writers if K in hold.reach({d})] or writers
        if grant_due:
            prop = [d for d in holding if not g.device_session(d, content)]
            if prop:
                return prop[0], True
        return (holding[0], False) if holding else (None, False)

    def repair(self, room, heal: bool = True, rounds: int = 30, timed_out: bool = False) -> list:
        """Each round heals first, when the heal test fires, so that no link
        hangs under a condemned state, then makes the
        deliveries the view calls for."""
        room = sorted(room)
        self.sync(room)
        healed = []
        for _ in range(rounds):
            changed = False
            W, V, arts = self.view(room[0])
            due_c = heal_due(self.g, W, V, arts, KIND_CONTENT)
            due_g = heal_due(self.g, W, V, arts, KIND_GRANT)
            if heal and (due_c or due_g):
                who, grant = self.healer(room, W, V, arts, bool(due_g))
                if who is not None and (due_c or grant):
                    self.heals += 1
                    healed.append(self.act(who, "key", f"heal-{self.heals}", rotates=True,
                                           grant=grant))
                    self.sync(room)
                    changed = True
            W, V, arts = self.view(room[0])
            for kind in (KIND_CONTENT, KIND_GRANT):
                p = plan(self.g, W, V, arts, kind, room, timed_out)
                changed |= self.apply(p) | self.gaps_by(p, room)
            self.sync(room)
            if not changed:
                break
        return healed

    # -- reading results ------------------------------------------------------
    def key_bytes(self, state: tuple, kind: int = KIND_CONTENT) -> bytes:
        name = {KIND_CONTENT: "content", KIND_GRANT: "grant"}[kind]
        label = MERGE_KEY_LABEL if kind == KIND_CONTENT else MERGE_GRANT_LABEL
        return state_secret(label, self.space, state, lambda i: self.secrets[i][name])

    def reaches(self, device: str, devices, state: tuple, kind: int = KIND_CONTENT) -> bool:
        W, V, arts = self.view(device)
        return state in Holdings(self.g, W, arts, V, kind).reach(devices)


def roster_cross_check(w: World) -> list:
    """Rebuild a worked history with reference/roster.py and events.py, and
    compare roster.py's valid set and maximal rotations with the stand-in's
    at every checkpoint. Members are devices there (administer is per
    device), so a member with several devices is granted and removed as all
    of its devices in one event. Returns one row per checkpoint."""
    import roster as rs
    levels = {READ: rs.READ, WRITE: rs.WRITE, ADMIN: rs.ADMINISTER}
    first = w.record[0]
    r = rs.Roster(first["author"], f"keygraph-cross-check/{w.name}")
    ids = {"genesis": r.genesis}
    for rec in w.record[1:]:
        author, kw = rec["author"], rec["kw"]
        r.hist.view[author] = {ids[label] for label in rec["view"]}
        r.hist.device(author)
        if rec["kind"] in ("grant", "remove", "demote"):
            devices = w.g.devices[kw["target"]]
            changes = []
            for d in devices:
                if rec["kind"] == "grant":
                    session = example(f"keygraph/session/{d}")[:16] if kw.get("session") else None
                    changes.append(r.device_grant(
                        d, levels[kw["level"]],
                        rs.WITH_HISTORY if kw.get("history", True) else rs.FROM_NOW_ON,
                        session=session))
                elif rec["kind"] == "remove":
                    changes.append(rs.Change(rs.REMOVE, (rs.DEVICE, r.hist.device(d))))
                else:
                    changes.append(rs.Change(rs.CHANGE, (rs.DEVICE, r.hist.device(d)),
                                             levels[kw["level"]]))
            ids[rec["label"]] = r.act(author, changes, rec["label"])
        elif rec["kind"] == "key":
            ids[rec["label"]] = r.heal(author, rec["label"])
        else:
            ids[rec["label"]] = r.unit(author, rec["label"])
    rows = []
    for title, view, valid in w.checks:
        sp = r.resolve(view={ids[label] for label in view})
        got = {label for label, i in ids.items() if i in sp.valid() and label in view}
        rotations = sorted(label for label, i in ids.items() if i in sp.rotations())
        ours = next(cp for cp in w.cp_rotations if cp[0] == title)[1]
        by_label = {w.labels[i]: i for i in w.g.events}
        W = frozenset(by_label[label] for label in view)
        V = frozenset(by_label[label] for label in valid)
        stability = []
        for x in sorted(i for i in W if w.g.events[i].kind == "remove" and i not in V):
            mine_voiders = sorted(w.labels[i] for i in w.g.voiders(V, x))
            theirs = sorted(label for label, i in ids.items()
                            if i in sp.voiders(ids[w.labels[x]]))
            ours_stable = w.g.stable(W, V, x)
            their_stable = sp.stable([ids[w.labels[x]]] + sp.voiders(ids[w.labels[x]]))
            stability.append({"removal": w.labels[x], "voiders_agree": mine_voiders == theirs,
                              "stable_agrees": ours_stable == their_stable,
                              "voiders": theirs, "stable": their_stable})
        rows.append({"checkpoint": title, "valid_agrees": got == set(valid),
                     "stability": stability,
                     "only_roster_py": sorted(got - set(valid)),
                     "only_stand_in": sorted(set(valid) - got),
                     "rotations_agree": rotations == ours,
                     "statuses": {label: sp.status[ids[label]][1] for label in sorted(view)
                                  if not sp.status[ids[label]][0]}})
    return rows


# ---------------------------------------------------------------------------
# Sealed names ("Sealed names").

NAME_LABEL = b"frasil/name/v1"
NAME_KINDS = {"space": 1, "document": 2}
MAX_NAME_BYTES = 1022
MAX_NAME_ID_BYTES = 128
NAME_OVERHEAD = 1 + 24 + 16


def name_metadata_key(content_key_: bytes) -> bytes:
    """The metadata key of the state whose content key is given."""
    return derived_keys(content_key_)["metadata_key"]["key"]


def padded_len(length: int) -> int:
    return -(-(length + 2) // 64) * 64


def name_aad(space: bytes, reference: bytes, kind: int, id_: bytes) -> bytes:
    return NAME_LABEL + space + field(reference) + bytes([kind]) + field(id_)


def check_name_kind(space: bytes, kind: int, id_: bytes) -> None:
    """The kind is known and the ID has its kind's shape."""
    if len(space) != 32 or kind not in NAME_KINDS.values():
        raise SpecError("Malformed")
    if kind == NAME_KINDS["space"] and len(id_) != 32:
        raise SpecError("Malformed")
    if kind == NAME_KINDS["document"] and not 1 <= len(id_) <= MAX_NAME_ID_BYTES:
        raise SpecError("Malformed")


def seal_name(key: bytes, space: bytes, reference: bytes, kind: int, id_: bytes, name: bytes,
              nonce: bytes) -> dict:
    """Sealing a name, with the nonce given."""
    check_name_kind(space, kind, id_)
    if not 1 <= len(name) <= MAX_NAME_BYTES:
        raise SpecError("InvalidName")
    padded = len(name).to_bytes(2, "big") + name
    padded += bytes(padded_len(len(name)) - len(padded))
    aad = name_aad(space, reference, kind, id_)
    sealed = b"\x01" + nonce + xchacha20poly1305_seal(key, nonce, padded, aad)
    return {"padded": padded, "aad": aad, "sealed": sealed}


def open_name(key: bytes, space: bytes, reference: bytes, kind: int, id_: bytes,
              sealed: bytes) -> bytes:
    """Opening a sealed name, in order."""
    check_name_kind(space, kind, id_)
    if not sealed:
        raise SpecError("Malformed")
    if sealed[0] != 1:
        raise SpecError("UnsupportedVersion")
    body = len(sealed) - NAME_OVERHEAD
    if body <= 0 or body % 64 or body > padded_len(MAX_NAME_BYTES):
        raise SpecError("Malformed")
    plain = xchacha20poly1305_open(key, sealed[1:25], sealed[25:],
                                   name_aad(space, reference, kind, id_))
    length = int.from_bytes(plain[:2], "big")
    if (not 1 <= length <= MAX_NAME_BYTES or len(plain) != padded_len(length)
            or any(plain[2 + length:])):
        raise SpecError("Malformed")
    try:
        plain[2:2 + length].decode("utf-8")
    except UnicodeDecodeError as error:
        raise SpecError("Malformed") from error
    return plain[2:2 + length]


def name_record(space: bytes, reference: bytes, sealed: bytes) -> bytes:
    """A record names its space and the state it is sealed under."""
    assert len(space) == 32
    return b"\x01" + space + field(reference) + sealed


def read_name_record(record: bytes, restricted: bool) -> tuple[bytes, bytes, bytes]:
    """Reading a record, steps 1, 2 and 4: (space, reference, sealed name). A
    restricted space's reference is ext-restricted-spaces.md's form."""
    if not record:
        raise SpecError("Malformed")
    if record[0] != 1:
        raise SpecError("UnsupportedVersion")
    if len(record) < 1 + 32 + 4:
        raise SpecError("Malformed")
    space = record[1:33]
    length = int.from_bytes(record[33:37], "big")
    rest = record[37:]
    if length == 0 or len(rest) < length:
        raise SpecError("Malformed")
    reference = rest[:length]
    if restricted:
        read_restricted_reference(reference)
    else:
        decode_set(reference)
    return space, reference, rest[length:]


def open_name_record(record: bytes, space: bytes, restricted: bool, key_for, kind: int,
                     id_: bytes) -> bytes:
    """Reading a record in a space, in order: `key_for(reference)` is the
    content key of the state the reference names, or raises MissingState.
    The space is checked before the reference is read."""
    if not record:
        raise SpecError("Malformed")
    if record[0] != 1:
        raise SpecError("UnsupportedVersion")
    if len(record) < 1 + 32 + 4:
        raise SpecError("Malformed")
    if record[1:33] != space:
        raise SpecError("Decrypt")
    _, reference, sealed = read_name_record(record, restricted)
    check_name_kind(space, kind, id_)
    return open_name(name_metadata_key(key_for(reference)), space, reference, kind, id_, sealed)


_NP = "sealed-names"


def _name_states() -> dict:
    space = example(f"{_NP}/space")
    ra, rb = sorted([example(f"{_NP}/rotation/A"), example(f"{_NP}/rotation/B")])
    secrets = {ra: example(f"{_NP}/rotation/A/content"), rb: example(f"{_NP}/rotation/B/content")}
    states = {"A": (ra,), "A+B": (ra, rb)}
    content = {label: content_key(space, ids, secrets.__getitem__)
               for label, ids in states.items()}
    references = {label: encode_set(ids) for label, ids in states.items()}
    assert content["A"] == secrets[ra]
    return {"space": space, "ra": ra, "rb": rb, "secrets": secrets, "content": content,
            "references": references}


def sealed_names_family() -> dict:
    st = _name_states()
    space, content, references = st["space"], st["content"], st["references"]

    def space_key_for(reference: bytes) -> bytes:
        for label, ref in references.items():
            if ref == reference:
                return content[label]
        raise SpecError("MissingState")

    states = [
        {"state": "A", "rotations": [st["ra"].hex()], "content_key": content["A"].hex(),
         "key_reference": references["A"].hex(),
         "metadata_key": name_metadata_key(content["A"]).hex()},
        {"state": "A+B", "rotations": [st["ra"].hex(), st["rb"].hex()],
         "content_key_inputs": [st["secrets"][st["ra"]].hex(), st["secrets"][st["rb"]].hex()],
         "content_key": content["A+B"].hex(), "key_reference": references["A+B"].hex(),
         "metadata_key": name_metadata_key(content["A+B"]).hex()},
    ]
    restricted = example(f"{_NP}/restricted")
    granted = example(f"{_NP}/granted-space")
    stream = example(f"{_NP}/stream")[:16]
    cases, sealed_by = [], {}
    for label, where, kind, id_, name in [
        ("the space's own name", "A+B", "space", space, "Spring tour".encode()),
        ("a restricted space's name, kept in its parent", "A+B", "space", restricted,
         "Salaries".encode()),
        ("a granted space's name, kept in the granting space", "A", "space", granted,
         "Lighting team".encode()),
        ("a document's name, by its stream ID, 62 bytes: the longest in one bucket", "A+B",
         "document", stream, b"x" * 62),
        ("a document's name, 63 bytes: two buckets", "A+B", "document", stream, b"x" * 63),
        ("a document's name, not ASCII", "A+B", "document", b"notes", "Régie générale".encode()),
        ("the longest name", "A+B", "document", b"notes", b"y" * MAX_NAME_BYTES),
    ]:
        reference = references[where]
        key = name_metadata_key(content[where])
        code = NAME_KINDS[kind]
        nonce = example(f"{_NP}/nonce/{len(cases)}")[:24]
        sealed = seal_name(key, space, reference, code, id_, name, nonce)
        assert open_name(key, space, reference, code, id_, sealed["sealed"]) == name
        record = name_record(space, reference, sealed["sealed"])
        assert open_name_record(record, space, False, space_key_for, code, id_) == name
        sealed_by[label] = (reference, sealed["sealed"], record)
        cases.append({"name": label, "space": space.hex(), "state": where, "kind": kind,
                      "kind_code": code, "id": id_.hex(), "name_bytes": name.hex(),
                      "nonce": nonce.hex(), "padded": sealed["padded"].hex(),
                      "aad": sealed["aad"].hex(), "sealed": sealed["sealed"].hex(),
                      "record": record.hex()})
    ref_ab, doc_sealed, doc_record = sealed_by[
        "a document's name, by its stream ID, 62 bytes: the longest in one bucket"]
    _, own_sealed, _ = sealed_by["the space's own name"]
    key_ab = name_metadata_key(content["A+B"])
    doc = NAME_KINDS["document"]

    def flip(b, i):
        return b[:i] + bytes([b[i] ^ 1]) + b[i + 1:]

    def forged(padded: bytes, label: str) -> bytes:
        nonce = example(f"{_NP}/nonce/{label}")[:24]
        return b"\x01" + nonce + xchacha20poly1305_seal(key_ab, nonce, padded,
                                                        name_aad(space, ref_ab, doc, stream))

    refusals = []

    def refuse_open(label, kind, id_, sealed, key=key_ab, reference=ref_ab, in_space=space):
        refusals.append({
            "name": label, "operation": "open", "space": in_space.hex(), "kind": kind,
            "id": id_.hex(), "key_reference": reference.hex(), "metadata_key": key.hex(),
            "sealed": sealed.hex(),
            "error": expect_error(open_name, key, in_space, reference, NAME_KINDS.get(kind, 5),
                                  id_, sealed)})

    refuse_open("a document's name opened as the space's name", "space", space, doc_sealed)
    refuse_open("the space's name opened as a document named by the same 32 bytes",
                "document", space, own_sealed)
    refuse_open("a document's name opened for another document", "document", b"notes",
                doc_sealed)
    refuse_open("a name opened under another state's key and reference", "document", stream,
                doc_sealed, key=name_metadata_key(content["A"]), reference=references["A"])
    refuse_open("a name opened with its key but another reference", "document", stream,
                doc_sealed, reference=references["A"])
    refuse_open("a name opened as another space's", "document", stream, doc_sealed,
                in_space=granted)
    refuse_open("a space name whose ID is not 32 bytes", "space", space[:31], own_sealed)
    refuse_open("a document ID of 129 bytes", "document", b"d" * 129, doc_sealed)
    refuse_open("an unknown kind 5", "kind 5", stream, doc_sealed)
    refuse_open("a changed ciphertext byte", "document", stream,
                flip(doc_sealed, len(doc_sealed) - 20))
    refuse_open("an unknown version", "document", stream, b"\x02" + doc_sealed[1:])
    refuse_open("one byte short", "document", stream, doc_sealed[:-1])
    refuse_open("padded to one bucket more than the name needs", "document", stream,
                forged((6).to_bytes(2, "big") + b"Budget" + bytes(128 - 8), "overpadded"))
    refuse_open("a byte after the name that is not zero", "document", stream,
                forged((6).to_bytes(2, "big") + b"Budget" + b"\x01" + bytes(64 - 9), "nonzero"))
    refuse_open("a name that is not UTF-8", "document", stream,
                forged((2).to_bytes(2, "big") + b"\xff\xfe" + bytes(60), "utf8"))

    def refuse_seal(label, kind, id_, name):
        refusals.append({
            "name": label, "operation": "seal", "space": space.hex(), "kind": kind,
            "id": id_.hex(), "name_bytes": name.hex(),
            "error": expect_error(seal_name, key_ab, space, ref_ab, NAME_KINDS.get(kind, 5), id_,
                                  name, bytes(24))})

    refuse_seal("an empty name", "document", stream, b"")
    refuse_seal("a name of 1,023 bytes", "document", stream, b"z" * 1023)
    refuse_seal("an empty document ID", "document", b"", b"Budget")
    refuse_seal("an unknown kind 5", "kind 5", b"example-subject", b"Lighting designer")

    records = []

    def refuse_record(label, record):
        records.append({
            "name": label, "space": space.hex(), "kind": "document", "id": stream.hex(),
            "record": record.hex(),
            "error": expect_error(open_name_record, record, space, False, space_key_for, doc,
                                  stream)})

    refuse_record("a record of another space", name_record(granted, ref_ab, doc_sealed))
    refuse_record("a record naming a state the reader does not hold", name_record(
        space, encode_set([example(f"{_NP}/rotation/unknown")]), doc_sealed))
    refuse_record("a record of an unknown version", b"\x02" + doc_record[1:])
    refuse_record("a record whose reference is not a rotation set",
                  name_record(space, b"\x02" + st["ra"] + st["rb"][:31], doc_sealed))
    refuse_record("a record whose reference names 65 rotations",
                  name_record(space, bytes([65]) + bytes(32 * 65), doc_sealed))
    refuse_record("a record whose reference length runs past its end",
                  b"\x01" + space + (4096).to_bytes(4, "big") + ref_ab)
    refuse_record("36 bytes", doc_record[:36])
    return {"labels": {NAME_LABEL.decode(): NAME_LABEL.hex(),
                       METADATA_KEY_LABEL.decode(): METADATA_KEY_LABEL.hex()},
            "kinds": NAME_KINDS, "space": space.hex(),
            "note": ("Each name is sealed under the metadata key of the state its record "
                     "names: A, or the merge A+B. A refusal's metadata_key is the key it is "
                     "opened with."),
            "states": states, "sealed": cases, "refusals": refusals,
            "record_refusals": records}


def restricted_names_family() -> dict:
    """ext-restricted-spaces.json's restricted_names: a restricted space F
    under the space above, whose names seal under F's own state, with its
    key reference sealing the parent's state."""
    st = _name_states()
    space, content, references = st["space"], st["content"], st["references"]
    ra, rb = st["ra"], st["rb"]
    restricted = example(f"{_NP}/restricted")
    rf = example(f"{_NP}/restricted/rotation/F")
    f_secret = example(f"{_NP}/restricted/rotation/F/content")
    k_f = restricted_key(restricted, space, f_secret, content["A+B"])
    f_reference = seal_restricted_reference(restricted, (rf,), (ra, rb), f_secret,
                                            example(f"{_NP}/restricted/nonce")[:24])
    assert open_restricted_reference(f_reference, restricted, f_secret) == ((rf,), (ra, rb))

    def restricted_key_for(reference: bytes) -> bytes:
        own, parent = open_restricted_reference(reference, restricted, f_secret)
        if own != (rf,) or parent != (ra, rb):
            raise SpecError("MissingState")
        return k_f["key"]

    stream = example(f"{_NP}/stream")[:16]
    name = "Budget".encode()
    doc = NAME_KINDS["document"]
    key = name_metadata_key(k_f["key"])
    nonce = example(f"{_NP}/nonce/7")[:24]
    sealed = seal_name(key, restricted, f_reference, doc, stream, name, nonce)
    record = name_record(restricted, f_reference, sealed["sealed"])
    assert open_name_record(record, restricted, True, restricted_key_for, doc, stream) == name
    bad = name_record(restricted, references["A"], sealed["sealed"])
    return {
        "space": restricted.hex(), "parent": space.hex(),
        "state": {"rotations": [rf.hex()], "own_secret": f_secret.hex(), "parent_state": "A+B",
                  "parent_content_key": content["A+B"].hex(), "content_key": k_f["key"].hex(),
                  "key_reference": f_reference.hex(), "metadata_key": key.hex()},
        "sealed": {"name": "a document's name in the restricted space", "kind": "document",
                   "id": stream.hex(), "name_bytes": name.hex(), "nonce": nonce.hex(),
                   "padded": sealed["padded"].hex(), "aad": sealed["aad"].hex(),
                   "sealed": sealed["sealed"].hex(), "record": record.hex()},
        "refusals": [{"name": "a record of a restricted space whose reference is a plain set",
                      "record": bad.hex(),
                      "error": expect_error(open_name_record, bad, restricted, True,
                                            restricted_key_for, doc, stream)}],
    }


# ---------------------------------------------------------------------------
# The vectors of keys.md.


def h(value: bytes) -> str:
    return value.hex()


def expect_error(function, *args) -> str:
    try:
        function(*args)
    except SpecError as error:
        return error.error
    raise AssertionError(f"{function.__name__} accepted")


def device_keys(name: str) -> dict:
    """A device by crypto.md's fixture derivations, named by its device ID."""
    import history_sigs as hs
    signer = hs.fixture_signer(example(f"keygraph/device/{name}/ed25519"), name)
    return {"name": name, "identity_seed": signer.ed_seed, "identity": signer.ed_public,
            "hybrid_seed": signer.xwing_seed, "hybrid": signer.xwing_public,
            "mldsa": signer.mldsa_public, "kc": signer.kc, "device_id": signer.device_id}


def device_json(d: dict) -> dict:
    return {"name": d["name"], "identity_seed": h(d["identity_seed"]),
            "identity": h(d["identity"]), "hybrid_seed": h(d["hybrid_seed"]),
            "hybrid": h(d["hybrid"]), "kc": h(d["kc"]), "device_id": h(d["device_id"])}


def eseed(label: str) -> bytes:
    return example(label + "/1") + example(label + "/2")


SPACE = example("keygraph/space")
ROT = {name: example(f"keygraph/rotation/{name}") for name in ("A", "B", "C")}
SECRETS = {name: {"content": example(f"keygraph/rotation/{name}/content"),
                  "upload": example(f"keygraph/rotation/{name}/upload"),
                  "grant": example(f"keygraph/rotation/{name}/grant")} for name in ROT}
BY_ID = {i: n for n, i in ROT.items()}


def _secret_of(kind: str):
    return lambda i: SECRETS[BY_ID[i]][kind]


def rotation_set_vectors() -> dict:
    one = canonical([ROT["A"]])
    three = canonical(ROT.values())
    author = device_keys("laptop")["device_id"]
    good = [
        {"name": "one rotation", "ids": [h(i) for i in one], "encoding": h(encode_set(one))},
        {"name": "three rotations, ascending bytewise", "ids": [h(i) for i in three],
         "encoding": h(encode_set(three))},
    ]
    own = {"name": "the carrying event's own rotation", "author": h(author), "seq": 7,
           "encoding": h(self_ref(author, 7))}
    many = [example(f"keygraph/many/{i}") for i in range(65)]
    enc = encode_set(three)
    negative = []
    for name, data, allow_self in [
        ("empty", b"", False),
        ("n = 0 where a self reference is not allowed", self_ref(author, 7), False),
        ("a self reference one byte short", self_ref(author, 7)[:-1], True),
        ("65 rotations", bytes([65]) + b"".join(sorted(many)), False),
        ("one id short", enc[:-1], False),
        ("not ascending", bytes([2]) + three[1] + three[0], False),
        ("a repeated id", bytes([2]) + three[0] + three[0], False),
        ("a byte after the set", enc + b"\x00", False),
    ]:
        def run(data=data, allow_self=allow_self):
            if allow_self:
                name_, rest = read_name(data, True)
                if rest:
                    raise SpecError("Malformed")
                return name_
            return decode_set(data)
        negative.append({"name": name, "encoding": h(data), "self_allowed": allow_self,
                         "error": expect_error(run)})
    collapse = [{"size": n, "collapse_due": n > COLLAPSE_ABOVE,
                 "unit_may_name_it": n <= MAX_ROTATIONS} for n in (1, 8, 9, 64, 65)]
    return {"sets": good, "self_reference": own, "negative": negative, "collapse": collapse}


def derivation_vectors() -> dict:
    out = []
    for names in (("A",), ("A", "B"), ("A", "B", "C")):
        ids = canonical(ROT[n] for n in names)
        item = {"state": [BY_ID[i] for i in ids], "ids": [h(i) for i in ids]}
        for kind, label in (("content", MERGE_KEY_LABEL), ("upload", MERGE_UPLOAD_LABEL),
                            ("grant", MERGE_GRANT_LABEL)):
            if len(ids) > 1:
                m = merge_secret(label, SPACE, ids, [_secret_of(kind)(i) for i in ids])
                item[kind] = {"info": h(m["info"]), "t": [h(t) for t in m["t"]],
                              "ikm": h(m["ikm"]), "secret": h(m["secret"])}
            else:
                item[kind] = {"secret": h(_secret_of(kind)(ids[0]))}
        k = bytes.fromhex(item["content"]["secret"])
        w = bytes.fromhex(item["upload"]["secret"])
        g = bytes.fromhex(item["grant"]["secret"])
        gk = grant_key_pair(g)
        item["grant_key"] = {"info": h(gk["info"]), "xwing_seed": h(gk["xwing_seed"]),
                             "public": h(gk["public"]),
                             "commitment": h(grant_commitment(gk["public"], False)),
                             "commitment_at_a_break": h(grant_commitment(gk["public"], True))}
        rc, uk = read_credential(k), upload_key(w)
        item["read_credential"] = {"info": h(rc["info"]), "seed": h(rc["seed"]),
                                   "public": h(rc["public"])}
        item["upload_key"] = {"info": h(uk["info"]), "seed": h(uk["seed"]),
                              "public": h(uk["public"])}
        for name, d in derived_keys(k).items():
            item[name] = {"info": h(d["info"]), "key": h(d["key"])}
        # The body key of a space event sealed under this state: laptop's
        # event at seq 5 in SPACE, with its commitment.
        author = example("keygraph/device/laptop/ed25519")[:32]
        bk = seal_key(k, SPACE, author, 5)
        item["body_key"] = {"author": h(author), "seq": 5,
                            "info": h(seal_aad(SPACE, author, 5)), "key": h(bk),
                            "commitment": h(body_commitment(bk))}
        out.append(item)
    other = example("keygraph/other-space")
    ab = canonical([ROT["A"], ROT["B"]])
    assert content_key(other, ab, _secret_of("content")) != bytes.fromhex(out[1]["content"]["secret"])
    return {"space": h(SPACE),
            "rotations": [{"name": n, "id": h(ROT[n]),
                           **{k: h(v) for k, v in SECRETS[n].items()}} for n in sorted(ROT)],
            "states": out,
            "other_space": h(other),
            "other_space_content_key_of_A_B": h(content_key(other, ab, _secret_of("content")))}


def restricted_vectors() -> dict:
    parent = example("keygraph/restricted/parent")
    space = example("keygraph/restricted/space")
    p_rot = {n: example(f"keygraph/restricted/parent/{n}") for n in ("P1", "P2")}
    f_rot = {n: example(f"keygraph/restricted/own/{n}") for n in ("F1", "F2")}
    sec = {n: {"content": example(f"keygraph/restricted/{n}/content"),
               "upload": example(f"keygraph/restricted/{n}/upload")}
           for n in list(p_rot) + list(f_rot)}
    names = {**{i: n for n, i in p_rot.items()}, **{i: n for n, i in f_rot.items()}}

    def of(kind):
        return lambda i: sec[names[i]][kind]

    out = []
    for own_names, parent_names in ((("F1",), ("P1",)), (("F1",), ("P1", "P2")),
                                    (("F1", "F2"), ("P1", "P2"))):
        s_f = canonical(f_rot[n] for n in own_names)
        s_p = canonical(p_rot[n] for n in parent_names)
        f = content_key(space, s_f, of("content"))
        fw = upload_seed(space, s_f, of("upload"))
        k_p = content_key(parent, s_p, of("content"))
        rk = restricted_key(space, parent, f, k_p)
        nonce = example(f"keygraph/restricted/reference/{len(out)}")[:NONCE_BYTES]
        ref = seal_restricted_reference(space, s_f, s_p, f, nonce)
        assert open_restricted_reference(ref, space, f) == (s_f, s_p)
        out.append({
            "own_state": [names[i] for i in s_f], "parent_state": [names[i] for i in s_p],
            "own_secret": h(f), "own_upload_seed": h(fw), "parent_key": h(k_p),
            "info": h(rk["info"]), "prk": h(rk["prk"]), "key": h(rk["key"]),
            "read_credential": h(read_credential(f)["public"]),
            "upload_key": h(upload_key(fw)["public"]),
            "parent_reference_key": h(parent_reference_key(f)),
            "reference_nonce": h(nonce), "key_reference": h(ref),
        })
    ref = bytes.fromhex(out[2]["key_reference"])
    negative = [
        {"name": "the parent's state opened with another own secret",
         "reference": h(ref), "own_secret": h(sec["F1"]["content"]),
         "error": expect_error(open_restricted_reference, ref, space, sec["F1"]["content"])},
        {"name": "one byte short", "reference": h(ref[:-1]),
         "error": expect_error(read_restricted_reference, ref[:-1])},
        {"name": "no sealed parent state", "reference": h(ref[:65]),
         "error": expect_error(read_restricted_reference, ref[:65])},
    ]
    # A space event of F, sealed under F's own secret: its rotation F2, a
    # key event by a member of F, at seq 4.
    author = device_keys("laptop")
    f2 = sec["F2"]
    payload = encode_payload({
        "rotates": True, "grant_commitment": filler_commitment(f2["content"]),
        "read": read_credential(f2["content"])["public"],
        "upload": upload_key(f2["upload"])["public"],
        "links": [seal_link(KIND_CONTENT, space, self_ref(author["device_id"], 4),
                            encode_set([f_rot["F1"]]), f2["content"], sec["F1"]["content"],
                            example("keygraph/restricted/event/link")[:NONCE_BYTES])["link"]]},
        space, author["device_id"], 4, f2["content"],
        example("keygraph/restricted/event/seal")[:NONCE_BYTES])
    visible = read_payload(payload, author["device_id"], 4)
    body_key_ = seal_key(f2["content"], space, author["device_id"], 4)
    opened = open_with_body_key(visible, body_key_, space, author["device_id"], 4)
    assert len(opened["links"]) == 1 and not opened["grant_rotation"]
    event = {"name": "F's rotation F2, sealed under F's own secret f_R",
             "author": h(author["device_id"]), "seq": 4, "secret": h(f2["content"]),
             "body_key": h(body_key_), "commitment": h(body_commitment(body_key_)),
             "payload": h(payload)}
    return {"space": h(space), "parent": h(parent),
            "rotations": [{"name": n, "id": h(i), "content": h(sec[n]["content"]),
                           "upload": h(sec[n]["upload"])}
                          for n, i in sorted({**p_rot, **f_rot}.items())],
            "keys": out, "negative": negative, "space_event": event}


def bundle_vectors() -> dict:
    k, w, g = SECRETS["A"]["content"], SECRETS["A"]["upload"], SECRETS["A"]["grant"]
    good = [{"name": name, "bundle": h(make_bundle(**parts))} for name, parts in [
        ("content only (a reader that does not propagate)", {"content": k}),
        ("content and upload (a guest that writes)", {"content": k, "upload": w}),
        ("content and grant (a reader that propagates)", {"content": k, "grant": g}),
        ("content, upload and grant (a writer that propagates)",
         {"content": k, "upload": w, "grant": g}),
        ("grant only (a gap in the grant graph)", {"grant": g}),
    ]]
    negative = [{"name": name, "bundle": h(data), "error": expect_error(read_bundle, data)}
                for name, data in [
                    ("empty", b""),
                    ("no flag", b"\x00" + k + bytes(64)),
                    ("an unknown flag", b"\x09" + k + bytes(64)),
                    ("upload without content", b"\x02" + bytes(32) + w + bytes(32)),
                    ("one byte short", make_bundle(content=k, upload=w)[:-1]),
                    ("a byte too many", make_bundle(content=k) + b"\x00"),
                    ("an absent slot that is not zero", b"\x01" + k + w + bytes(32)),
                ]]
    who = [{"recipient": name, "level": LEVEL_NAMES[level], "propagates": prop,
            "invite": invite, "bundle": list(bundle_contents(level, prop, invite))}
           for name, level, prop, invite in [
               ("a writer that propagates", WRITE, True, False),
               ("a reader that propagates", READ, True, False),
               ("a guest that writes", WRITE, False, False),
               ("an invite key at read, without session", READ, True, True),
               ("an invite key at write, without session", WRITE, True, True),
               ("a guest invite at read", READ, False, True),
           ]]
    return {"good": good, "negative": negative, "who_gets_what": who}


def wrap_vectors() -> dict:
    laptop, reader, guest, other = (device_keys(n) for n in ("laptop", "reader", "guest", "other"))
    a = encode_set(canonical([ROT["A"]]))
    ab = encode_set(canonical([ROT["A"], ROT["B"]]))
    own = self_ref(laptop["device_id"], 3)
    k_ab = content_key(SPACE, canonical([ROT["A"], ROT["B"]]), _secret_of("content"))
    w_ab = upload_seed(SPACE, canonical([ROT["A"], ROT["B"]]), _secret_of("upload"))
    g_ab = grant_seed(SPACE, canonical([ROT["A"], ROT["B"]]), _secret_of("grant"))
    cases, made = [], {}
    for name, recipient, key_name, grant_name, parts in [
        ("the merged state {A, B} for a writer that propagates", laptop, ab, ab,
         {"content": k_ab, "upload": w_ab, "grant": g_ab}),
        ("the merged state {A, B} for a reader that propagates", reader, ab, ab,
         {"content": k_ab, "grant": g_ab}),
        ("the same delivery for a guest that writes: no grant seed", guest, ab, ab,
         {"content": k_ab, "upload": w_ab}),
        ("the carrying event's own rotation, named by its author and sequence", reader, own, own,
         {"content": SECRETS["C"]["content"], "grant": SECRETS["C"]["grant"]}),
        ("a gap key: the content of {A} alone", reader, a, b"",
         {"content": SECRETS["A"]["content"]}),
    ]:
        label = f"keygraph/wrap/{len(cases)}"
        bundle = make_bundle(**parts)
        sealed = seal_bundle_wrap(SPACE, key_name, grant_name, recipient["device_id"],
                                  recipient["hybrid"], bundle, eseed(label))
        opened = open_bundle_wrap(sealed["wrap"], SPACE, key_name, grant_name,
                                  recipient["device_id"], recipient["hybrid_seed"])
        assert make_bundle(**opened) == bundle
        made[len(cases)] = (sealed["wrap"], key_name, grant_name, recipient)
        cases.append({"name": name, "recipient": recipient["name"], "key_name": h(key_name),
                      "grant_name": h(grant_name), "bundle": h(bundle), "info": h(sealed["info"]),
                      "encapsulation_randomness": h(eseed(label)), "enc": h(sealed["enc"]),
                      "sealed": h(sealed["sealed"]), "wrap": h(sealed["wrap"])})
    # Trial decryption: the guest finds its own wrap among the delivery's three.
    delivery = [made[i][0] for i in (0, 1, 2)]
    index, _ = find_own_wrap(delivery, SPACE, ab, ab, guest["device_id"], guest["hybrid_seed"])
    assert index == 2
    blob, key_name, grant_name, recipient = made[0]

    def with_byte(data, index, value):
        return data[:index] + bytes([value]) + data[index + 1:]

    inconsistent = seal_bundle_wrap(SPACE, ab, b"", laptop["device_id"], laptop["hybrid"],
                                    make_bundle(content=k_ab, grant=g_ab),
                                    eseed("keygraph/wrap/bad"))["wrap"]
    negative = []
    for name, data, args, who in [
        ("empty", b"", (key_name, grant_name), laptop),
        ("version 2", with_byte(blob, 0, 2), (key_name, grant_name), laptop),
        ("the X25519 suite, which protocol 1 does not use",
         blob[:1] + u16be(SUITE_X25519) + blob[3:], (key_name, grant_name), laptop),
        ("one byte short", blob[:-1], (key_name, grant_name), laptop),
        ("tried by another device", blob, (key_name, grant_name), other),
        ("opened as another state", blob, (a, grant_name), laptop),
        ("opened without its grant state", blob, (key_name, b""), laptop),
        ("a changed ciphertext byte", with_byte(blob, len(blob) - 20, blob[-20] ^ 1),
         (key_name, grant_name), laptop),
        ("a grant seed in a delivery that names no grant state", inconsistent, (ab, b""), laptop),
    ]:
        def run(data=data, args=args, who=who):
            return open_bundle_wrap(data, SPACE, args[0], args[1], who["device_id"],
                                    who["hybrid_seed"])
        negative.append({"name": name, "wrap": h(data), "opener": who["name"],
                         "key_name": h(args[0]), "grant_name": h(args[1]),
                         "error": expect_error(run)})
    return {"log": h(SPACE), "devices": [device_json(d) for d in (laptop, reader, guest, other)],
            "wraps": cases, "trial_decryption": {"delivery": [h(x) for x in delivery],
                                                 "opener": "guest", "found_at": index},
            "negative": negative}


def removal_wrap_vectors() -> dict:
    laptop, reader, other = (device_keys(n) for n in ("laptop", "reader", "other"))
    own = self_ref(laptop["device_id"], 7)
    k_r = example("keygraph/removal/content")
    key = seal_key(k_r, SPACE, laptop["device_id"], 7)
    commitment = body_commitment(key)
    label = "keygraph/removal-wrap/0"
    sealed = seal_removal_wrap(SPACE, own, own, reader["device_id"], reader["hybrid"], key,
                               eseed(label))
    assert open_removal_wrap(sealed["wrap"], SPACE, own, own, reader["device_id"],
                             reader["hybrid_seed"], commitment) == key
    # The own delivery: the remaining member's bundle wrap, then the
    # removed device's removal wrap.
    bundle = make_bundle(content=k_r, upload=example("keygraph/removal/upload"))
    kept = seal_bundle_wrap(SPACE, own, own, laptop["device_id"], laptop["hybrid"], bundle,
                            eseed("keygraph/removal-wrap/kept"))["wrap"]
    delivery = [kept, sealed["wrap"]]
    removed_at, found = find_removal_wrap(delivery, SPACE, own, own, reader["device_id"],
                                          reader["hybrid_seed"], commitment)
    assert (removed_at, found) == (1, key)
    kept_at, _ = find_own_wrap(delivery, SPACE, own, own, laptop["device_id"],
                               laptop["hybrid_seed"])
    assert kept_at == 0
    assert find_own_wrap(delivery, SPACE, own, own, reader["device_id"],
                         reader["hybrid_seed"]) == (None, None)

    def shaped(plain: bytes, name: str) -> bytes:
        info = removal_wrap_info(SPACE, own, own, reader["device_id"])
        enc, ct = xwing.hpke_xwing_seal(reader["hybrid"], info, b"", plain,
                                        eseed(f"keygraph/removal-wrap/{name}"))
        return bytes([VERSION]) + u16be(SUITE_XWING) + enc + ct

    wrong_flag = shaped(b"\x01" + key + bytes(64), "flag")
    tail = shaped(bytes([REMOVAL_FLAG]) + key + b"\x01" + bytes(63), "tail")
    other_key = shaped(removal_plaintext(example("keygraph/removal/other-key")), "other-key")
    negative = []
    for name, data, who, as_bundle in [
        ("tried by another device", sealed["wrap"], other, False),
        ("tried by the remaining member", sealed["wrap"], laptop, False),
        ("opened as a bundle wrap", sealed["wrap"], reader, True),
        ("a bundle wrap opened as a removal wrap", kept, laptop, False),
        ("a first byte other than 0x08", wrong_flag, reader, False),
        ("a tail that is not zero", tail, reader, False),
        ("a body key that does not match the commitment", other_key, reader, False),
    ]:
        def run(data=data, who=who, as_bundle=as_bundle):
            if as_bundle:
                return open_bundle_wrap(data, SPACE, own, own, who["device_id"],
                                        who["hybrid_seed"])
            return open_removal_wrap(data, SPACE, own, own, who["device_id"],
                                     who["hybrid_seed"], commitment)
        negative.append({"name": name, "wrap": h(data), "opener": who["name"],
                         "as": "bundle wrap" if as_bundle else "removal wrap",
                         "error": expect_error(run)})
    return {"log": h(SPACE), "devices": [device_json(d) for d in (laptop, reader, other)],
            "author": "laptop", "seq": 7, "key_name": h(own), "grant_name": h(own),
            "rotation_content_key": h(k_r), "body_key": h(key), "commitment": h(commitment),
            "removal_wrap": {"recipient": "reader", "info": h(sealed["info"]),
                             "plaintext": h(sealed["plaintext"]),
                             "encapsulation_randomness": h(eseed(label)),
                             "enc": h(sealed["enc"]), "sealed": h(sealed["sealed"]),
                             "wrap": h(sealed["wrap"])},
            "trial_decryption": {"delivery": [h(x) for x in delivery],
                                 "removed": {"opener": "reader", "found_at": removed_at},
                                 "remaining": {"opener": "laptop", "found_at": kept_at}},
            "refusals": negative}


def space_wrap_vectors() -> dict:
    grantee = example("keygraph/grantee-space")
    t_rot = example("keygraph/grantee-space/rotation/T1")
    t_seed = example("keygraph/grantee-space/T1/grant")
    t_key = grant_key_pair(t_seed)
    s = canonical([ROT["A"], ROT["B"]])
    name = encode_set(s)
    k = content_key(SPACE, s, _secret_of("content"))
    w = upload_seed(SPACE, s, _secret_of("upload"))
    g = grant_seed(SPACE, s, _secret_of("grant"))
    cases, made = [], []
    for title, parts in [("a grant at write: content, upload and grant",
                          {"content": k, "upload": w, "grant": g}),
                         ("a grant at read: content and grant", {"content": k, "grant": g})]:
        label = f"keygraph/space-wrap/{len(cases)}"
        sealed = seal_space_wrap(SPACE, name, name, grantee, t_rot, t_key["public"],
                                 make_bundle(**parts), eseed(label))
        opened = open_space_wrap(sealed["wrap"], SPACE, name, name, grantee, t_rot,
                                 t_key["xwing_seed"])
        assert make_bundle(**opened) == make_bundle(**parts)
        made.append(sealed["wrap"])
        cases.append({"name": title, "bundle": h(make_bundle(**parts)), "info": h(sealed["info"]),
                      "encapsulation_randomness": h(eseed(label)), "enc": h(sealed["enc"]),
                      "sealed": h(sealed["sealed"]), "wrap": h(sealed["wrap"])})
    blob = made[0]
    other_seed = grant_key_pair(example("keygraph/grantee-space/T2/grant"))["xwing_seed"]
    negative = []
    for title, data, args in [
        ("version 2", b"\x02" + blob[1:], (grantee, t_rot, t_key["xwing_seed"])),
        ("one byte short", blob[:-1], (grantee, t_rot, t_key["xwing_seed"])),
        ("tried as another space's", blob, (example("keygraph/third-space"), t_rot,
                                            t_key["xwing_seed"])),
        ("tried at another grantee rotation", blob, (grantee, example("x"), t_key["xwing_seed"])),
        ("tried with another grant key", blob, (grantee, t_rot, other_seed)),
    ]:
        def run(data=data, args=args):
            return open_space_wrap(data, SPACE, name, name, *args)
        negative.append({"name": title, "wrap": h(data), "grantee": h(args[0]),
                         "grantee_rotation": h(args[1]), "grant_xwing_seed": h(args[2]),
                         "error": expect_error(run)})
    return {"log": h(SPACE), "key_name": h(name), "grantee": h(grantee),
            "grantee_rotation": h(t_rot), "grantee_grant_seed": h(t_seed),
            "grantee_grant_key": {"info": h(t_key["info"]), "xwing_seed": h(t_key["xwing_seed"]),
                                  "public": h(t_key["public"])},
            "wraps": cases, "negative": negative}


def link_vectors() -> dict:
    author = device_keys("laptop")["device_id"]
    own = self_ref(author, 3)
    a, b = encode_set([ROT["A"]]), encode_set([ROT["B"]])
    ab = encode_set(canonical([ROT["A"], ROT["B"]]))
    k_ab = content_key(SPACE, canonical([ROT["A"], ROT["B"]]), _secret_of("content"))
    g_ab = grant_seed(SPACE, canonical([ROT["A"], ROT["B"]]), _secret_of("grant"))
    cases = []
    for title, kind, under, reaches, under_secret, reached in [
        ("a rotation's own key reaching the state before it, {A, B}", KIND_CONTENT, own, ab,
         SECRETS["C"]["content"], k_ab),
        ("the merge key {A, B} reaching its input {A}", KIND_CONTENT, ab, a, k_ab,
         SECRETS["A"]["content"]),
        ("the merged grant seed {A, B} reaching the grant seed of {B}", KIND_GRANT, ab, b, g_ab,
         SECRETS["B"]["grant"]),
    ]:
        nonce = example(f"keygraph/link/{len(cases)}")[:NONCE_BYTES]
        made = seal_link(kind, SPACE, under, reaches, under_secret, reached, nonce)
        assert open_link(made["link"], kind, SPACE, under, reaches, under_secret) == reached
        cases.append({"name": title, "kind": KIND_NAMES[kind], "under": h(under),
                      "reaches": h(reaches), "under_secret": h(under_secret),
                      "reached_secret": h(reached), "info": h(made["info"]),
                      "prk": h(made["prk"]), "link_key": h(made["link_key"]),
                      "aad": h(made["aad"]), "nonce": h(nonce), "link": h(made["link"])})
    link = bytes.fromhex(cases[1]["link"])

    def with_byte(data, index, value):
        return data[:index] + bytes([value]) + data[index + 1:]

    negative = []
    for title, data, kind, under, reaches, secret in [
        ("empty", b"", KIND_CONTENT, ab, a, k_ab),
        ("version 2", with_byte(link, 0, 2), KIND_CONTENT, ab, a, k_ab),
        ("an unknown kind", with_byte(link, 1, 3), KIND_CONTENT, ab, a, k_ab),
        ("one byte short", link[:-1], KIND_CONTENT, ab, a, k_ab),
        ("reaching a self reference", bytes([1, 1]) + ab + own + bytes(72),
         KIND_CONTENT, ab, own, k_ab),
        ("opened as a grant link", link, KIND_GRANT, ab, a, k_ab),
        ("opened as reaching {B}", link, KIND_CONTENT, ab, b, k_ab),
        ("opened with the key it reaches", link, KIND_CONTENT, ab, a, SECRETS["A"]["content"]),
        ("a changed tag byte", with_byte(link, len(link) - 1, link[-1] ^ 1), KIND_CONTENT, ab, a,
         k_ab),
    ]:
        def run(data=data, kind=kind, under=under, reaches=reaches, secret=secret):
            return open_link(data, kind, SPACE, under, reaches, secret)
        negative.append({"name": title, "link": h(data), "kind": kind, "under": h(under),
                         "reaches": h(reaches), "under_secret": h(secret),
                         "error": expect_error(run)})
    gaps = [{"name": "a content gap at {A, B}", "record": h(gap_record(KIND_CONTENT, ab))},
            {"name": "a grant gap at {A}", "record": h(gap_record(KIND_GRANT, a))}]
    gap_negative = [{"name": t, "record": h(d), "error": expect_error(read_gap, d)} for t, d in [
        ("kind 0", b"\x00" + ab), ("a self reference", bytes([1]) + own), ("empty", b"")]]
    return {"log": h(SPACE), "links": cases, "negative": negative, "gaps": gaps,
            "gap_negative": gap_negative}


def envelope(kind: int, author: str, seq: int, body: bytes) -> dict:
    """The payload's carrying event, built by events.py (events.md, section
    4): in the space SPACE, after a fixed previous event of its author. The
    log is for encoding only; it is not resolved. Its refs, if any, are
    already in the body, sealed at inner key 18."""
    import events
    signer = events.signer_for(example(f"keygraph/device/{author}/ed25519"), author)
    prev = example(f"keygraph/payload/prev/{author}/{seq - 1}")
    fields = events.event_fields(kind, signer, seq, body, log=SPACE, prev=prev,
                                 parents=[prev])
    signed = events.sign_fields(fields, signer)
    event = events.decode_event(signed)
    events.verify_hybrid(event, [signer.keys])
    assert event.author == device_keys(author)["device_id"]
    assert event.body == body
    return {"kind": kind, "author_mldsa": h(signer.mldsa_public), "signed": h(signed),
            "event_id": h(event.id)}


def payload_vectors() -> dict:
    import roster as rs
    laptop, reader, guest = (device_keys(n) for n in ("laptop", "reader", "guest"))
    new = {"content": example("keygraph/payload/new/content"),
           "upload": example("keygraph/payload/new/upload"),
           "grant": example("keygraph/payload/new/grant")}
    new_grant = grant_key_pair(new["grant"])["public"]
    commits = {"read": read_credential(new["content"])["public"],
               "upload": upload_key(new["upload"])["public"]}
    prev = canonical([ROT["A"], ROT["B"]])
    prev_name = encode_set(prev)
    k_prev = content_key(SPACE, prev, _secret_of("content"))
    g_prev = grant_seed(SPACE, prev, _secret_of("grant"))
    both = {"content": new["content"], "upload": new["upload"], "grant": new["grant"]}
    team = example("keygraph/payload/team-space")
    team_rot = {"removal": example("keygraph/payload/team-removal"),
                "break": example("keygraph/payload/team-break")}
    team_key = grant_key_pair(example("keygraph/payload/team/grant"))
    # The visible parts of the team's rotations, as a replica holding the
    # team's log reads them: their grant commitments bind the break flag.
    team_rotations = {team_rot["removal"]: {"grant_commitment": grant_commitment(
                          team_key["public"], False)},
                      team_rot["break"]: {"grant_commitment": grant_commitment(
                          team_key["public"], True)}}
    cases = []

    def own_delivery(own, recipients, grant=True, space_wraps=()):
        wraps = []
        for i, (d, parts) in enumerate(recipients):
            wraps.append(seal_bundle_wrap(SPACE, own, own if grant else b"", d["device_id"],
                                          d["hybrid"], make_bundle(**parts),
                                          eseed(f"keygraph/payload/{len(cases)}/{i}"))["wrap"])
        return {"key": own, "grant": own if grant else None, "wraps": wraps,
                "space_wraps": list(space_wraps)}

    def links_back(own, grant=True):
        out = [seal_link(KIND_CONTENT, SPACE, own, prev_name, new["content"], k_prev,
                         example(f"keygraph/payload/{len(cases)}/link")[:NONCE_BYTES])["link"]]
        if grant:
            out.append(seal_link(KIND_GRANT, SPACE, own, prev_name, new["grant"], g_prev,
                                 example(f"keygraph/payload/{len(cases)}/grant-link")
                                 [:NONCE_BYTES])["link"])
        return out

    def add(title, author, seq, p, ctx, kind, changes=None, refs=(), seal_secret=None):
        """Every case is a space event (events.md, kind 2): its body is the
        payload, and a roster event's changes travel in the sealed part."""
        rotating = p.get("rotates")
        secret = new["content"] if rotating else seal_secret
        if kind == "roster":
            p = {**p, "roster": rs.update_roster(changes)}
        if refs:
            p = {**p, "refs": refs}
        data = encode_payload({**p, "always_seal": True}, SPACE, author["device_id"], seq, secret,
                              example(f"keygraph/payload/{len(cases)}/seal")[:NONCE_BYTES])
        visible = read_payload(data, author["device_id"], seq)
        opened = open_sealed(visible, secret, SPACE, author["device_id"], seq)
        notices = opened["notices"]
        covers = None
        assert opened["refs"] == tuple(sorted(set(refs)))
        if ctx.get("refs_granted"):
            covers = any(n["rotation"] in [r for _, r in opened["refs"]] for n in notices)
        check_payload_context(opened, {**ctx, "refs": bool(opened["refs"]),
                                       "notice_covers": covers})
        for n in notices:
            check_notice(n, team_rotations.get(n["rotation"]), True)
        body = data
        event = envelope(2, author["name"], seq, body)
        cases.append({"name": title, "author": h(author["device_id"]), "seq": seq,
                      "context": ctx, "refs": [[h(a), h(b)] for a, b in refs],
                      "seal_secret": h(secret) if secret else None,
                      "payload": h(data), "body": h(body), "event": event,
                      "summary": {"rotates": opened["rotates"],
                                  "grant_rotation": opened["grant_rotation"],
                                  "break": opened["break"],
                                  "deliveries": len(opened["deliveries"]),
                                  "wraps": sum(len(d["wraps"]) for d in opened["deliveries"]),
                                  "space_wraps": sum(len(d["space_wraps"])
                                                     for d in opened["deliveries"]),
                                  "links": len(opened["links"]), "gaps": len(opened["gaps"]),
                                  "notices": len(notices)}})
        return opened

    def team_space_wrap(own, tag, brk=False):
        return seal_space_wrap(SPACE, own, own, team, team_rot["break" if brk else "removal"],
                               team_key["public"], make_bundle(**both),
                               eseed(f"keygraph/payload/space/{tag}"))["wrap"]

    own5 = self_ref(laptop["device_id"], 5)
    grant5 = {"rotates": True, "grant_commitment": grant_commitment(new_grant, False), **commits}
    removal = add(
        "a removal of a member that propagates: a roster event whose slot holds a grant rotation",
        laptop, 5,
        {**grant5, "grant_rotation": True,
         "deliveries": [own_delivery(own5, [(laptop, both),
                                            (reader, {"content": new["content"],
                                                      "grant": new["grant"]})])],
         "links": links_back(own5)},
        {"event": "roster", "removes": True, "removes_propagating": True,
         "author_propagates": True}, "roster",
        [rs.Change(rs.REMOVE, (rs.DEVICE, device_keys("old-device")["device_id"]))])
    own6 = self_ref(laptop["device_id"], 6)
    trigger = (team, team_rot["removal"])
    add("a response to a removal in a granted space: its sealed refs name it, the payload "
        "rotates and carries a notice for the team's new grant rotation", laptop, 6,
        {**grant5, "grant_rotation": True,
         "deliveries": [own_delivery(own6, [(laptop, both)],
                                     space_wraps=[team_space_wrap(own6, 6)])],
         "links": links_back(own6),
         "notices": [{"space": team, "rotation": team_rot["removal"],
                      "public": team_key["public"]}]},
        {"event": "key", "author_propagates": True, "refs_granted": True}, "key", refs=[trigger])
    own7 = self_ref(laptop["device_id"], 7)
    add("a cascaded break for the team's from-now-on admission: notice from now on, gaps, no "
        "link back", laptop, 7,
        {"rotates": True, "grant_commitment": grant_commitment(new_grant, True), **commits,
         "grant_rotation": True, "break": True,
         "deliveries": [own_delivery(own7, [(laptop, both)],
                                     space_wraps=[team_space_wrap(own7, 7, brk=True)])],
         "gaps": [gap_record(KIND_CONTENT, prev_name), gap_record(KIND_GRANT, prev_name)],
         "notices": [{"space": team, "rotation": team_rot["break"],
                      "public": team_key["public"], "from_now_on": True}]},
        {"event": "key", "author_propagates": True, "refs_granted": True}, "key",
        refs=[(team, team_rot["break"])])
    add("a response that loses nothing: delivery only, a notice and a space wrap of the current "
        "state", laptop, 8,
        {"deliveries": [{"key": prev_name, "grant": prev_name,
                         "space_wraps": [seal_space_wrap(
                             SPACE, prev_name, prev_name, team, team_rot["removal"],
                             team_key["public"], make_bundle(content=k_prev, grant=g_prev),
                             eseed("keygraph/payload/loses-nothing"))["wrap"]]}],
         "notices": [{"space": team, "rotation": team_rot["removal"],
                      "public": team_key["public"]}],
         "sealed_under": prev_name},
        {"event": "key", "author_propagates": True, "refs_granted": True}, "key",
        refs=[trigger], seal_secret=k_prev)
    guest_own = self_ref(guest["device_id"], 2)
    add("a guest's heal: content and upload only, its commitment a filler; its own delivery "
        "names both states by its self reference, and sealed key 1 names the grant state",
        guest, 2,
        {"rotates": True, "grant_commitment": filler_commitment(new["content"]), **commits,
         "grant_state": prev_name,
         "deliveries": [own_delivery(guest_own, [(guest, {"content": new["content"],
                                                          "upload": new["upload"]})])],
         "links": links_back(guest_own, grant=False)},
        {"event": "key", "author_propagates": False}, "key")
    add("a delivery only: the merged state for a member that lacks it, a link and a gap",
        laptop, 9,
        {"deliveries": [{"key": prev_name, "grant": prev_name, "wraps": [seal_bundle_wrap(
            SPACE, prev_name, prev_name, reader["device_id"], reader["hybrid"],
            make_bundle(content=k_prev, grant=g_prev),
            eseed("keygraph/payload/delivery"))["wrap"]]}],
         "links": [seal_link(KIND_CONTENT, SPACE, prev_name, encode_set([ROT["A"]]), k_prev,
                             SECRETS["A"]["content"],
                             example("keygraph/payload/delivery-link")[:NONCE_BYTES])["link"]],
         "gaps": [gap_record(KIND_CONTENT, encode_set([ROT["B"]]))],
         "sealed_under": prev_name},
        {"event": "key", "author_propagates": True}, "key", seal_secret=k_prev)
    self_removal = {"name": "a self-removal: it does not rotate, and is sealed under the "
                            "current state, which it names",
                    "context": {"event": "roster", "removes": True, "removes_self": True,
                                "removes_propagating": False, "author_propagates": True}}
    check_payload_context(None, self_removal["context"])
    body = encode_payload(
        {"sealed_under": prev_name,
         "roster": rs.update_roster([rs.Change(rs.REMOVE, (rs.DEVICE, laptop["device_id"]))])},
        SPACE, laptop["device_id"], 10, k_prev,
        example("keygraph/payload/self-removal/seal")[:NONCE_BYTES])
    assert open_sealed(read_payload(body, laptop["device_id"], 10), k_prev, SPACE,
                       laptop["device_id"], 10)["roster"] is not None
    self_removal["body"] = h(body)
    self_removal["event"] = envelope(2, "laptop", 10, body)

    nonce = example("keygraph/payload/negative/seal")[:NONCE_BYTES]

    def enc(p, secret=None):
        return encode_payload(p, SPACE, laptop["device_id"], 5, secret or new["content"], nonce)

    gap_only = {"gaps": [gap_record(KIND_CONTENT, prev_name)], "sealed_under": prev_name}
    raw = []
    for title, data in [
        ("not a map", c_array([])),
        ("version 2", c_map([(1, c_uint(2)), (7, c_array([]))])),
        ("an unknown key 16", c_map([(1, c_uint(1)), (2, c_uint(1)), (16, c_uint(1))])),
        ("a twin of 31 bytes", enc({**grant5, "always_seal": True, "twin": bytes(31)})),
        ("a twin beside a genesis's nonce",
         enc({**grant5, "always_seal": True, "nonce": bytes(16), "twin": bytes(32)})),
        ("a sealed part without its commitment",
         enc({**grant5, "always_seal": True, "commitment": False})),
        ("a commitment of 31 bytes", enc({**grant5, "always_seal": True, "commitment": bytes(31)})),
        ("a nonce in a payload that does not rotate", enc({**gap_only, "nonce": bytes(16)},
                                                          k_prev)),
        ("reserved key 4", enc({**grant5, "raw": {4: c_uint(1)}})),
        ("reserved key 5",
         enc({**grant5, "raw": {5: c_array([cbor_bytes(trigger[0] + trigger[1])])}})),
        ("reserved key 6",
         enc({**grant5, "raw": {6: cbor_bytes(b"frontier")}})),
        ("reserved key 10",
         enc({**grant5, "raw": {10: c_array([])}})),
        ("a rotation without its upload key", enc({**grant5, "upload": None})),
        ("a rotation without its grant commitment", enc({**grant5, "grant_commitment": None})),
        ("a grant commitment of 31 bytes",
         enc({**grant5, "always_seal": True, "grant_commitment": bytes(31)})),
        ("a read credential that is not a valid Ed25519 key",
         enc({**grant5, "always_seal": True, "read": bytes(32)})),
        ("a commitment without rotating", enc({**gap_only, "read": commits["read"]}, k_prev)),
        ("map keys out of order", bytes.fromhex("a2") + c_uint(2) + c_uint(1) + c_uint(1) + c_uint(1)),
        ("nothing at all, without rotating", c_map([(1, c_uint(1))])),
        ("a sealed part without the state it is sealed under",
         enc({"gaps": [gap_record(KIND_CONTENT, prev_name)]}, k_prev)),
        ("a rotation naming a state it is sealed under", enc({**grant5, "sealed_under": prev_name,
                                                              "links": links_back(own5)})),
        ("a delivery with no wraps",
         enc({"always_seal": True, "sealed_under": prev_name,
              "deliveries": [{"key": prev_name}]}, k_prev)),
        ("a self reference with another sequence",
         enc({**grant5, "always_seal": True,
              "deliveries": [own_delivery(own5, [(laptop, both)])
                             | {"key": self_ref(laptop["device_id"], 6)}]})),
        ("a self reference in a payload that does not rotate",
         enc({"always_seal": True, "sealed_under": prev_name,
              "deliveries": [own_delivery(own5, [(laptop, both)])]}, k_prev)),
    ]:
        raw.append({"name": title, "payload": h(data), "author": h(laptop["device_id"]), "seq": 5,
                    "error": expect_error(read_payload, data, laptop["device_id"], 5)})
    sealed_negative = []
    for title, p, secret, opener in [
        ("opened under another key", {**grant5, "links": links_back(own5)}, new["content"], k_prev),
        ("a from-now-on notice without a break",
         {**grant5, "notices": [{"space": team, "rotation": team_rot["break"],
                                 "public": team_key["public"], "from_now_on": True}]},
         new["content"], new["content"]),
        ("a break in a payload that does not rotate",
         {**gap_only, "break": True}, k_prev, k_prev),
        ("a notice whose key is not an X-Wing key",
         {**grant5, "notices": [{"space": team, "rotation": team_rot["removal"],
                                 "public": team_key["public"][:1184] + bytes(32)}]},
         new["content"], new["content"]),
        ("an unknown sealed key 6", {**grant5, "raw_inner": {6: c_uint(1)}},
         new["content"], new["content"]),
        ("a commitment to another key", {**grant5, "always_seal": True,
                                         "commitment": body_commitment(bytes(32))},
         new["content"], new["content"]),
        ("a sealed part damaged in transit", {**grant5, "always_seal": True, "tamper": True},
         new["content"], new["content"]),
        ("padding that is not zero", {**grant5, "padding": b"\x00\x01"},
         new["content"], new["content"]),
        ("refs that are an empty list", {**grant5, "raw_inner": {S_REFS: c_array([])}},
         new["content"], new["content"]),
        ("refs out of order",
         {**grant5, "raw_inner": {S_REFS: c_array([
             c_array([cbor_bytes(team), cbor_bytes(team_rot["removal"])]),
             c_array([cbor_bytes(team), cbor_bytes(team_rot["break"])])][::(
                 1 if team_rot["removal"] > team_rot["break"] else -1)])}},
         new["content"], new["content"]),
        ("a ref repeated",
         {**grant5, "raw_inner": {S_REFS: c_array([
             c_array([cbor_bytes(team), cbor_bytes(team_rot["break"])])] * 2)}},
         new["content"], new["content"]),
        ("a ref whose event ID is 31 bytes",
         {**grant5, "raw_inner": {S_REFS: c_array([
             c_array([cbor_bytes(team), cbor_bytes(team_rot["break"][:31])])])}},
         new["content"], new["content"]),
        ("65 refs",
         {**grant5, "raw_inner": {S_REFS: c_array([
             c_array([cbor_bytes(team), cbor_bytes(bytes([i]) + bytes(31))])
             for i in range(65)])}},
         new["content"], new["content"]),
    ]:
        data = enc({k: v for k, v in p.items() if k != "tamper"}, secret)
        if p.get("tamper"):
            sealed = decode_cbor(data)[P_SEALED]
            data = data.replace(sealed, sealed[:-1] + bytes([sealed[-1] ^ 1]))
        visible = read_payload(data, laptop["device_id"], 5)
        sealed_negative.append({"name": title, "payload": h(data), "author": h(laptop["device_id"]),
                                "seq": 5, "opened_with": h(opener),
                                "error": expect_error(open_sealed, visible, opener, SPACE,
                                                      laptop["device_id"], 5)})
    contextual = []
    for title, p, ctx in [
        ("a removal that does not rotate", None,
         {"event": "roster", "removes": True, "removes_propagating": True, "author_propagates": True}),
        ("a removal whose slot only delivers", {"rotates": False, "break": False},
         {"event": "roster", "removes": True, "removes_propagating": True, "author_propagates": True}),
        ("a demotion to read that does not rotate", None,
         {"event": "roster", "lowers_to_read": True, "author_propagates": True}),
        ("a from-now-on admission without a break", {"rotates": True, "break": False,
                                                     "grant_rotation": True},
         {"event": "roster", "admits_from_now_on": True, "admits_propagating": True,
          "author_propagates": True}),
        ("a break in a key event that responds to nothing",
         {"rotates": True, "break": True, "grant_rotation": True},
         {"event": "key", "author_propagates": True}),
        ("a break in a with-history admission",
         {"rotates": True, "break": True, "grant_rotation": True},
         {"event": "roster", "author_propagates": True}),
        ("a grant rotation by a guest", {"rotates": True, "break": False, "grant_rotation": True},
         {"event": "key", "author_propagates": False}),
        ("a grant rotation in a restricted space",
         {"rotates": True, "break": False, "grant_rotation": True},
         {"event": "key", "author_propagates": True, "restricted": True}),
        ("a removal of a member that propagates, without a grant rotation",
         {"rotates": True, "break": False, "grant_rotation": False},
         {"event": "roster", "removes": True, "removes_propagating": True,
          "author_propagates": True}),
        ("a from-now-on admission of a person, without a grant rotation",
         {"rotates": True, "break": True, "grant_rotation": False},
         {"event": "roster", "admits_from_now_on": True, "admits_propagating": True,
          "author_propagates": True}),
        ("a response that rotates, without a grant rotation",
         {"rotates": True, "break": False, "grant_rotation": False},
         {"event": "key", "author_propagates": True, "refs": True}),
        ("a genesis without a grant rotation",
         {"rotates": True, "break": False, "grant_rotation": False},
         {"event": "genesis", "author_propagates": True}),
        ("a guest's removal with a grant rotation",
         {"rotates": True, "break": False, "grant_rotation": True},
         {"event": "roster", "removes": True, "removes_propagating": False,
          "author_propagates": True}),
        ("a response to a granted space's change, with no notice for it",
         {"rotates": True, "break": False, "grant_rotation": True},
         {"event": "key", "author_propagates": True, "refs": True, "refs_granted": True,
          "notice_covers": False}),
        ("a delivery sealed under a state a valid rotation in its past follows",
         {"rotates": False, "break": False, "grant_rotation": False},
         {"event": "key", "author_propagates": True, "sealed_under_stale": True}),
    ]:
        contextual.append({"name": title, "opened": p, "context": ctx,
                           "error": expect_error(check_payload_context, p, ctx)})
    good_delivery_only = {"name": "a delivery-only response with a notice is accepted",
                          "opened": {"rotates": False, "break": False, "grant_rotation": False},
                          "context": {"event": "key", "author_propagates": True, "refs": True,
                                      "refs_granted": True, "notice_covers": True}}
    check_payload_context(good_delivery_only["opened"], good_delivery_only["context"])
    good_delivery_only["result"] = "accepted"
    # Step 8 is a key event's: a roster event that changes a granted space
    # and carries its heads needs no notice.
    roster_citing = {"name": "a roster event whose refs name a granted space's log, with no "
                             "notice, is accepted",
                     "opened": {"rotates": False, "break": False, "grant_rotation": False},
                     "context": {"event": "roster", "author_propagates": True, "refs": True,
                                 "refs_granted": True, "notice_covers": False}}
    check_payload_context(roster_citing["opened"], roster_citing["context"])
    roster_citing["result"] = "accepted"
    honest = {"space": team, "rotation": team_rot["removal"], "public": team_key["public"],
              "from_now_on": False}
    fake_key = grant_key_pair(example("keygraph/payload/attacker/grant"))["public"]
    notices = [{"name": "an honest notice", "notice": {k: h(v) if isinstance(v, bytes) else v
                                                      for k, v in honest.items()},
                "grantee_commitment": h(team_rotations[team_rot["removal"]]["grant_commitment"]),
                "grantee_valid": True, "author_propagates_there": True, "result": "accepted"}]
    check_notice(honest, team_rotations[team_rot["removal"]], True)
    stale = {"name": "a re-notice of a principal out of force: T0 noticed after a response "
                      "named T1",
             "notice": {k: h(v) if isinstance(v, bytes) else v for k, v in honest.items()},
             "grantee_commitment": h(team_rotations[team_rot["removal"]]["grant_commitment"]),
             "grantee_valid": True, "stale": True, "author_propagates_there": True,
             "result": expect_error(check_notice, honest, team_rotations[team_rot["removal"]],
                                    True, True)}
    for title, n, rot, member in [
        ("a key the grantee's rotation did not commit to", {**honest, "public": fake_key},
         team_rotations[team_rot["removal"]], True),
        ("a break rotation noticed as with history", {**honest, "rotation": team_rot["break"]},
         team_rotations[team_rot["break"]], True),
        ("a with-history rotation noticed as from now on", {**honest, "from_now_on": True},
         team_rotations[team_rot["removal"]], True),
        ("an author that is not a propagating member of the grantee (a guest of this space)",
         honest, team_rotations[team_rot["removal"]], False),
        ("a replica that does not hold the grantee's rotation", honest, None, True),
        ("a rotation that is void in the grantee's log as held", honest,
         {**team_rotations[team_rot["removal"]], "valid": False}, True),
        ("a replica that cannot yet tell whether the author belongs to the grantee", honest,
         team_rotations[team_rot["removal"]], None),
    ]:
        notices.append({"name": title,
                        "notice": {k: h(v) if isinstance(v, bytes) else v for k, v in n.items()},
                        "grantee_commitment": h(rot["grant_commitment"]) if rot else None,
                        "grantee_valid": rot.get("valid", True) if rot else None,
                        "author_propagates_there": member,
                        "result": expect_error(check_notice, n, rot, member)})
    notices.append(stale)
    opened = open_bundle_wrap(removal["deliveries"][0]["wraps"][0], SPACE, own5, own5,
                              laptop["device_id"], laptop["hybrid_seed"])
    check_commitment(opened, removal)
    commitments = []
    for title, parts in [
        ("the removal's own wrap for the laptop: every slot verifies", opened),
        ("a content key the rotation did not commit to", {**opened, "content": k_prev}),
        ("an upload seed the rotation did not commit to", {**opened, "upload": k_prev}),
        ("a grant seed the rotation did not commit to", {**opened, "grant": k_prev}),
    ]:
        kept, dropped = verify_slots(parts, removal)
        commitments.append({"name": title, "bundle": h(make_bundle(**parts)),
                            "kept": sorted(kept), "dropped": dropped})
    provisional = [
        {"key_source": "derived", "meaning": "derived from rotation keys that each matched "
                                             "their commitments", "on_mismatch": seal_mismatch("derived")},
        {"key_source": "wrapped", "meaning": "a merged state's key received whole by wrap: "
                                             "provisional", "on_mismatch": seal_mismatch("wrapped")},
    ]
    in_log = {ROT["A"], ROT["B"]}
    held = {encode_set([ROT["A"]])}
    trials = []
    for title, d, entitled in [
        ("a state this device lacks and is entitled to: tried",
         {"key": prev_name, "grant": None}, True),
        ("a state this device already holds: skipped",
         {"key": encode_set([ROT["A"]]), "grant": None}, True),
        ("a state naming a rotation that is no event of the log: skipped",
         {"key": encode_set([example("keygraph/no-such-rotation")]), "grant": None}, True),
        ("a state this device is not entitled to: skipped",
         {"key": prev_name, "grant": None}, False),
    ]:
        trials.append({"name": title, "key_name": h(d["key"]), "entitled": entitled,
                       "tried": tries(d, in_log, held.__contains__, lambda n, e=entitled: e)})
    dummy = bytes([VERSION]) + u16be(SUITE_XWING) + bytes(WRAP_BYTES - 3)
    caps = [
        {"name": "765 bundle wraps and 3 space wraps in one event: at the cap",
         "wraps": 765, "space_wraps": 3, "result": "accepted"},
        {"name": "769 wraps in one event", "wraps": 769, "space_wraps": 0,
         "result": expect_error(read_payload, encode_payload(
             {"deliveries": [{"key": prev_name, "wraps": [dummy] * 769}],
              "sealed_under": prev_name, "always_seal": True}, SPACE, laptop["device_id"], 5,
             k_prev, nonce), laptop["device_id"], 5)},
        {"name": "65 deliveries in one event", "deliveries": 65,
         "result": expect_error(read_payload, encode_payload(
             {"deliveries": [{"key": prev_name, "wraps": [dummy]}] * 65,
              "sealed_under": prev_name, "always_seal": True}, SPACE, laptop["device_id"], 5,
             k_prev, nonce), laptop["device_id"], 5)},
    ]
    read_payload(encode_payload({"deliveries": [{"key": prev_name, "wraps": [dummy] * 765,
                                                 "space_wraps": [dummy] * 3}],
                                 "sealed_under": prev_name, "always_seal": True}, SPACE,
                                laptop["device_id"], 5, k_prev, nonce), laptop["device_id"], 5)
    return {"log": h(SPACE), "devices": [device_json(d) for d in (laptop, reader, guest)],
            "new_rotation_secrets": {k: h(x) for k, x in new.items()},
            "commitments_of_new_rotation": {**{k: h(x) for k, x in commits.items()},
                                            "grant": h(grant_commitment(new_grant, False))},
            "team": {"space": h(team), "grant_public": h(team_key["public"]),
                     "rotations": {name: {"id": h(i), "grant_commitment": h(
                         team_rotations[i]["grant_commitment"])}
                         for name, i in team_rot.items()}},
            "payloads": cases, "self_removal": self_removal, "negative": raw,
            "sealed_negative": sealed_negative, "context_negative": contextual,
            "context_accepted": [good_delivery_only, roster_citing], "notices": notices,
            "commitment_checks": commitments, "provisional_keys": provisional,
            "trial_decryption": {"rotations_in_log": sorted(h(r) for r in in_log),
                                 "held": sorted(h(x) for x in held), "cases": trials},
            "caps": {"max_wraps_per_event": MAX_WRAPS_PER_EVENT,
                     "max_deliveries_per_event": MAX_DELIVERIES_PER_EVENT,
                     "dummy_wrap_layout": "0x01, 0x647a, then 1233 zero bytes",
                     "cases": caps}}


def rank_vectors() -> dict:
    space = example("keygraph/rank/space")
    trigger = example("keygraph/rank/trigger")
    devices = [device_keys(f"writer-{i}")["device_id"] for i in range(5)]
    order = rank_order(space, trigger, devices)
    rows = []
    for position, d in enumerate(order):
        r = rank_value(space, trigger, d)
        rows.append({"position": position, "device_id": h(d), "digest": h(r["digest"]),
                     "value": r["value"], "delay_seconds_at_step_2": rank_delay(position, 2)})
    caps = [{"position": p, "step": s, "delay_seconds": rank_delay(p, s)}
            for p, s in ((0, 2), (1, 2), (63, 2), (64, 2), (200, 10))]
    return {"space": h(space), "trigger": h(trigger), "ranks": rows, "delays": caps}


WORLDS: list = []


def _setup(name: str, members) -> tuple:
    w = World(name)
    first = members[0][0]
    w.genesis(first, [first + "1"])
    devices = [first + "1"]
    for member, level in members[1:]:
        w.new_member(member, [member + "1"])
        devices.append(member + "1")
        w.sync(devices)
        w.act(first + "1", "grant", f"grant-{member}", target=member, level=level, history=True)
        w.sync(devices)
    w.repair(devices)
    return w, devices


def _labels(w: World, state) -> list:
    return [w.labels[i] for i in state]


def _name(w: World, state) -> str:
    """A state in the histories: its rotations' labels in canonical order,
    joined by "+"."""
    return "+".join(w.labels[i] for i in state)


def _art(w: World, a) -> str:
    kind = KIND_NAMES[a.kind]
    if isinstance(a, Wrap):
        return f"wrap {kind} {_name(w, a.state)} to {a.device}"
    if isinstance(a, Link):
        return f"link {kind} {_name(w, a.under)} > {_name(w, a.reaches)}"
    return f"gap {kind} {_name(w, a.state)}"


def _plan_json(w: World, p: dict) -> dict:
    return {"wraps": [f"{_name(w, k)} to {d} by {by or 'nobody in the room'} ({why})"
                      for k, d, by, why in p["wraps"]],
            "links": [f"{_name(w, u)} > {_name(w, k)} by {by or 'nobody in the room'}"
                      for u, k, by in p["links"]],
            "gaps": [_name(w, k) for k in p["gaps"]],
            "waiting": [f"{_name(w, k)} to {d}" for k, d in p["waiting"]],
            "heal": p["heal"]}


def checkpoint(w: World, title: str, device: str, room, queries=(), timed_out=False) -> dict:
    """The state of one device's view: an implementation given the view's
    events, its valid set and its artifacts must compute everything else."""
    W, V, arts = w.view(device)
    g = w.g
    order = sorted(W, key=lambda i: (g.height[i], w.labels[i]))
    K, G = g.current(V), g.current(V, KIND_GRANT)
    out = {
        "name": title, "view_of": device, "room": sorted(room),
        "events": [w.labels[i] for i in order],
        "valid": sorted(w.labels[i] for i in V),
        "artifacts": sorted(_art(w, a) for a in arts),
        "roster": {m: {"level": LEVEL_NAMES[x.level], "session": x.session}
                   for m, x in sorted(g.members(V).items())},
        "current": {"content": _name(w, K), "content_key": h(w.key_bytes(K)),
                    "grant": _name(w, G), "grant_seed": h(w.key_bytes(G, KIND_GRANT))},
        "plan": {KIND_NAMES[kind]: _plan_json(w, plan(g, W, V, arts, kind, room, timed_out))
                 for kind in (KIND_CONTENT, KIND_GRANT)},
        "entitlement": {},
        "reaches": [],
    }
    # Inputs the view needs besides its events: whether gap_key_timeout has
    # passed, each granted space's current devices as this replica holds its
    # log, and each principal's floors (keys.md, "Notices and space
    # principals" and "Entitlement and the link gate").
    if timed_out:
        out["timed_out"] = True
    if g.foreign_current:
        out["foreign_current"] = {t: sorted(ds) for t, ds in sorted(g.foreign_current.items())}
    if g.revoked:
        out["revoked"] = sorted(g.revoked)
    if g.principal_floor:
        out["principal_floor"] = {m: sorted(w.labels[f] for f in fs)
                                  for m, fs in sorted(g.principal_floor.items())}
    states = sorted({(i,) for i in W if g.is_rotation(i)} | {K})
    for m in sorted(g.members(V)):
        for kind in (KIND_CONTENT, KIND_GRANT):
            for state in states:
                if kind == KIND_GRANT and state != G and not (
                        len(state) == 1 and g.is_rotation(state[0], KIND_GRANT)):
                    continue
                if not g.ent(V, m, state, kind):
                    continue
                row = out["entitlement"].setdefault(m, {"content": [], "grant": [],
                                                        "pending_stability": []})
                if g.restored_pending(W, V, m, state, kind, timed_out):
                    row["pending_stability"].append(f"{KIND_NAMES[kind]} {_name(w, state)}")
                else:
                    row[KIND_NAMES[kind]].append(_name(w, state))
    w.checks.append((title, frozenset(w.labels[i] for i in W), frozenset(w.labels[i] for i in V)))
    if not hasattr(w, "cp_rotations"):
        w.cp_rotations = []
    w.cp_rotations.append((title, sorted(w.labels[i] for i in K)))
    for devices, state, kind, expected in queries:
        result = state in Holdings(g, W, arts, V, kind).reach(devices)
        assert result == expected, (w.name, title, devices, _labels(w, state), kind)
        out["reaches"].append({"devices": sorted(devices), "kind": KIND_NAMES[kind],
                               "state": _name(w, state), "result": result})
    return out


def _history(w: World, title: str, note: str, checkpoints: list) -> dict:
    g = w.g
    order = sorted(g.events, key=lambda i: (g.height[i], w.labels[i]))
    events = []
    for i in order:
        e = g.events[i]
        item = {"label": e.label, "id": h(i), "kind": e.kind, "author": e.author,
                "parents": sorted(w.labels[p] for p in e.parents)}
        if e.kind in ("genesis",) or e.kind in ROSTER_KINDS:
            item["target"] = e.target
        if e.kind in ("grant", "demote", "genesis"):
            item["level"] = LEVEL_NAMES[e.level]
        if e.kind == "grant":
            item["history"] = "with history" if e.history else "from now on"
            item["session"] = e.session
        if g.is_rotation(i):
            item["rotates"] = True
            item["grant_rotation"] = e.grant
            item["break"] = e.brk
            item["secrets"] = {k: h(v) for k, v in w.secrets[i].items()}
        if e.keyref:
            item["key_reference"] = _name(w, e.keyref)
        if e.notice:
            item["notice"] = {"principal": e.notice[0], "grantee_rotation": e.notice[1],
                              "from_now_on": e.notice[2]}
        if e.refs:
            item["refs"] = [f"{s}@{r}" for s, r in e.refs]
        if e.bogus:
            item["refused_notice"] = True
        if i in w.records:
            rec = w.records[i]
            item["record"] = {
                "members": {m: {"level": LEVEL_NAMES[lv], "history": hi, "session": se}
                            for m, (lv, hi, se) in sorted(rec["members"].items())},
                "raced": rec["raced"], "floor": rec["floor"],
                "named": [f"{s_}@{r_}" for s_, r_ in rec["named"]]}
        events.append(item)
    WORLDS.append(w)
    out_extra = {}
    if g.foreign_past:
        out_extra["grantee_rotations"] = {r: sorted(p) for r, p in sorted(g.foreign_past.items())}
    return {"name": title, "note": note, "space": h(w.space), **out_extra,
            "members": {m: list(ds) for m, ds in sorted(g.devices.items())},
            "events": events, "checkpoints": checkpoints}


def history_example_1() -> dict:
    w, devs = _setup("example-1", [("P", ADMIN), ("Q", ADMIN), ("M", WRITE), ("N", WRITE)])
    a = w.act("P1", "remove", "A", target="M")
    w.sync(["P1", "N1"])
    b = w.act("Q1", "remove", "B", target="N")
    w.sync(["Q1", "M1"])
    w.sync(devs)
    S = canonical([a.id, b.id])
    cps = [checkpoint(w, "the rooms reconcile", "P1", devs, [
        ({"P1"}, S, KIND_CONTENT, True), ({"Q1"}, S, KIND_CONTENT, True),
        ({"M1"}, S, KIND_CONTENT, False), ({"N1"}, S, KIND_CONTENT, False),
        ({"M1", "N1"}, S, KIND_CONTENT, True), ({"M1", "N1"}, S, KIND_GRANT, True)])]
    healed = w.repair(devs)
    W, V, _ = w.view("P1")
    K = w.g.current(V)
    cps.append(checkpoint(w, "after the first informed writer heals", "P1", devs, [
        ({"M1", "N1"}, K, KIND_CONTENT, False), ({"P1"}, K, KIND_CONTENT, True),
        ({"Q1"}, K, KIND_CONTENT, True), ({"M1", "N1"}, w.g.current(V, KIND_GRANT), KIND_GRANT, False)]))
    assert [e.label for e in healed] == ["heal-1"]
    return _history(w, "a cross-removal",
                    "P removes M in room A while Q removes N in room B. S = {A, B}; M and N "
                    "together derive k_S, so the heal test fires for the content key and the "
                    "grant key; P heals with a grant rotation.", cps)


def history_example_2() -> dict:
    w, devs = _setup("example-2", [("P", ADMIN), ("Q", ADMIN), ("M", ADMIN), ("N", WRITE)])
    a = w.act("P1", "remove", "A", target="M")
    b = w.act("M1", "remove", "B", target="N")
    w.sync(["M1", "Q1"])
    uq = w.act("Q1", "unit", "uq")
    un = w.act("N1", "unit", "un")
    w.sync(["M1", "Q1", "N1"])
    cps = [checkpoint(w, "room B meets room C: N's unit is refused past B", "Q1", ["M1", "Q1", "N1"])]
    W, V, _ = w.view("Q1")
    assert un.id not in V
    w.sync(devs)
    W, V, _ = w.view("P1")
    assert b.id not in V and un.id in V and w.g.current(V) == (a.id,)
    w.repair(devs)
    cps.append(checkpoint(w, "everyone meets: B is void, N is back; k_B waits for stability",
                          "P1", devs, [
                              ({"P1"}, uq.keyref, KIND_CONTENT, True),
                              ({"Q1"}, uq.keyref, KIND_CONTENT, True),
                              ({"N1"}, uq.keyref, KIND_CONTENT, False),
                              ({"M1"}, (a.id,), KIND_CONTENT, False)]))
    for d in ("P1", "Q1"):
        w.act(d, "unit", f"after-merge-{d}")
    w.sync(devs)
    w.repair(devs)
    W, V, _ = w.view("P1")
    assert w.g.stable(W, V, b.id)
    cps.append(checkpoint(w, "P and Q sign past the merge: the voiding of B is stable", "P1", devs, [
        ({"N1"}, uq.keyref, KIND_CONTENT, True), ({"M1"}, w.g.current(V), KIND_CONTENT, False)]))
    return _history(w, "a void rotation",
                    "M's removal voids M's concurrent rotation B. Q's unit under k_B stays "
                    "readable to P and Q; N, whose removal B was, receives k_B once the "
                    "voiding is stable.", cps)


def history_example_3() -> dict:
    w, devs = _setup("example-3", [("P", ADMIN), ("Q", ADMIN), ("M", WRITE)])
    w.new_member("G", ["G1"])
    before = w.g.current(w.resolve(w.views["P1"]))
    g_ = w.act("P1", "grant", "G-from-now-on", target="G", level=WRITE, history=False, session=True)
    w.sync(["P1", "G1"])
    x = w.act("Q1", "key", "X", rotates=True)
    w.sync(["Q1", "M1"])
    ux = w.act("M1", "unit", "ux")
    devs = devs + ["G1"]
    w.sync(devs)
    w.repair(devs)
    W, V, _ = w.view("P1")
    S = canonical([g_.id, x.id])
    assert w.g.current(V) == S
    cps = [checkpoint(w, "after the merge and its deliveries", "P1", devs, [
        ({"G1"}, S, KIND_CONTENT, True), ({"G1"}, (x.id,), KIND_CONTENT, False),
        ({"G1"}, ux.keyref, KIND_CONTENT, False), ({"G1"}, before, KIND_CONTENT, False),
        ({"Q1"}, (g_.id,), KIND_CONTENT, True),
        ({"G1"}, w.g.current(V, KIND_GRANT), KIND_GRANT, False)])]
    r = w.act("P1", "remove", "G-removed", target="G")
    assert not r.grant
    w.sync(devs)
    w.repair(devs)
    W, V, _ = w.view("P1")
    cps.append(checkpoint(w, "G leaves: a content rotation only", "P1", devs, [
        ({"G1"}, (r.id,), KIND_CONTENT, False), ({"G1"}, w.g.current(V), KIND_CONTENT, False)]))
    return _history(w, "a guest from now on",
                    "P admits guest G from now on (a break) while Q rotates on another branch. "
                    "G receives k_S, never k_X: no link from k_S reaches it, because G counts "
                    "as a potential holder. G holds no grant key. G's removal rotates the "
                    "content key only.", cps)


def history_example_4() -> dict:
    w, devs = _setup("example-4", [("P", ADMIN), ("Q", ADMIN), ("M", ADMIN), ("N", WRITE),
                                   ("Z", WRITE)])
    a = w.act("P1", "remove", "A", target="Z")
    un = w.act("N1", "unit", "un")
    w.sync(["P1", "N1"])
    b = w.act("M1", "remove", "B", target="N")
    w.sync(["M1", "Z1"])
    c = w.act("Q1", "remove", "C", target="M")
    ab = ["P1", "N1", "M1", "Z1"]
    w.sync(ab)
    cps = [checkpoint(w, "rooms A and B reconcile first", "P1", ab, [
        ({"N1", "Z1"}, canonical([a.id, b.id]), KIND_CONTENT, True)])]
    w.repair(ab, heal=False)
    hh = w.act("P1", "key", "H", rotates=True, grant=True)
    w.act("P1", "unit", "uab")
    w.sync(ab)
    w.sync(devs)
    W, V, _ = w.view("P1")
    S = canonical([hh.id, c.id])
    assert w.g.current(V) == S and b.id not in V and un.id in V
    cps.append(checkpoint(w, "room C arrives: B is void, S = {H, C}", "P1", devs, [
        ({"M1"}, S, KIND_CONTENT, False), ({"M1", "Z1"}, S, KIND_CONTENT, True),
        ({"M1"}, canonical([a.id, b.id]), KIND_CONTENT, True)]))
    w.repair(devs)
    W, V, _ = w.view("P1")
    K = w.g.current(V)
    cps.append(checkpoint(w, "a writer heals again; N works at once, k_H waits", "P1", devs, [
        ({"M1", "Z1"}, K, KIND_CONTENT, False), ({"N1"}, K, KIND_CONTENT, True),
        ({"N1"}, (c.id,), KIND_CONTENT, True), ({"N1"}, (hh.id,), KIND_CONTENT, False),
        ({"N1"}, (b.id,), KIND_CONTENT, False)]))
    cps.append(checkpoint(w, "the same view after the timeout T", "P1", devs, [], timed_out=True))
    for d in ("P1", "Q1"):
        w.act(d, "unit", f"after-merge-{d}")
    w.sync(devs)
    w.repair(devs)
    W, V, _ = w.view("P1")
    assert w.g.stable(W, V, b.id)
    cps.append(checkpoint(w, "every administrator signs past the merge: k_H reaches N", "P1",
                          devs, [({"N1"}, (hh.id,), KIND_CONTENT, True),
                                 ({"N1"}, (b.id,), KIND_CONTENT, True)]))
    return _history(w, "a void input, learned late",
                    "Rooms A and B heal with H; room C voids B. M (removed by C) holds k_H and "
                    "Z (removed by A) holds k_C, so the heal test fires again. N, restored, "
                    "receives k_H and k_B only once the voiding of B is stable.", cps)


def history_example_5() -> dict:
    w, devs = _setup("example-5", [("P", ADMIN), ("Q", ADMIN), ("M", WRITE), ("R", ADMIN)])
    w.new_member("H", ["H1"])
    r = w.act("Q1", "remove", "Q-removes-P", target="P")
    work = w.act("Q1", "grant", "Q-grants-H", target="H", level=WRITE)
    w.sync(["Q1", "P1"])
    backdated = frozenset(x for x in w.views["P1"] if not w.g.le(r.id, x))
    b = w.act("P1", "remove", "P-removes-Q-backdated", view=backdated, target="Q")
    w.sync(devs)
    W, V, _ = w.view("M1")
    assert r.id not in V and b.id in V and work.id not in V
    S = canonical([b.id])
    cps = [checkpoint(w, "P, the more senior, stands; Q's removal of P and its later grant "
                         "are void", "M1", devs, [
        ({"Q1"}, S, KIND_CONTENT, False), ({"P1"}, S, KIND_CONTENT, True)])]
    w.repair(devs)
    W, V, _ = w.view("M1")
    cps.append(checkpoint(w, "a writer heals", "M1", devs, [
        ({"Q1"}, w.g.current(V), KIND_CONTENT, False),
        ({"P1"}, w.g.current(V), KIND_CONTENT, True)]))
    w.act("R1", "grant", "R-regrants-Q", target="Q", level=ADMIN, history=True)
    w.sync(devs)
    w.repair(devs)
    W, V, _ = w.view("M1")
    cps.append(checkpoint(w, "the space recovery member re-grants Q with history", "M1", devs, [
        ({"Q1"}, w.g.current(V), KIND_CONTENT, True), ({"Q1"}, (b.id,), KIND_CONTENT, True),
        ({"P1"}, w.g.current(V), KIND_CONTENT, True)]))
    return _history(w, "the backdated duel",
                    "Q removes P; P writes a removal of Q whose parents leave its own removal "
                    "out. P and Q hold the same rank and P is the more senior, so P's removal "
                    "stands and Q's removal of P and Q's concurrent grant of H are void. The "
                    "space recovery member R re-grants Q, who receives the current key and its "
                    "gap keys.", cps)


def history_counterexamples() -> list:
    out = []
    w, devs = _setup("c1", [("P", ADMIN), ("M", ADMIN), ("Q", ADMIN), ("N", WRITE)])
    w.act("P1", "remove", "P-removes-N", target="N")
    w.act("P1", "key", "P-heals", rotates=True, grant=True)
    w.sync(["P1", "Q1"])
    w.act("M1", "remove", "M-removes-Q", target="Q")
    w.sync(["M1", "N1"])
    w.sync(devs)
    W, V, _ = w.view("P1")
    S = w.g.current(V)
    cps = [checkpoint(w, "S = {heal, M's removal}: one removal in S", "P1", devs,
                      [({"N1", "Q1"}, S, KIND_CONTENT, True)])]
    w.repair(devs)
    W, V, _ = w.view("P1")
    cps.append(checkpoint(w, "healed", "P1", devs, [({"N1", "Q1"}, w.g.current(V), KIND_CONTENT, False)]))
    out.append(_history(w, "a removal outside the merged state",
                        "The heal test counts every holder outside the roster, not removals in S.", cps))

    w, devs = _setup("c2", [("P", ADMIN), ("R", ADMIN), ("Q", ADMIN), ("X", WRITE)])
    w.act("P1", "remove", "P-removes-X", target="X")
    w.sync(["P1", "Q1"])
    w.act("Q1", "grant", "Q-regrants-X", target="X", level=WRITE, history=True)
    w.sync(["P1", "Q1", "X1"])
    w.act("P1", "key", "P-heals", rotates=True, grant=True)
    w.sync(["P1", "Q1", "X1"])
    w.act("R1", "remove", "R-removes-Q", target="Q")
    w.sync(devs)
    W, V, _ = w.view("P1")
    cps = [checkpoint(w, "Q's re-grant of X is void; X alone derives the current key", "P1", devs,
                      [({"X1"}, w.g.current(V), KIND_CONTENT, True)])]
    w.repair(devs)
    W, V, _ = w.view("P1")
    cps.append(checkpoint(w, "healed", "P1", devs, [({"X1"}, w.g.current(V), KIND_CONTENT, False)]))
    out.append(_history(w, "one removed member alone derives the current key",
                        "A single outsider holding every input is enough for the heal test.", cps))

    w = World("c3")
    w.genesis("P", ["P1"])
    devs = ["P1"]
    for member, level, ds in (("Q", ADMIN, ["Q1", "Q2"]), ("R", ADMIN, ["R1"]),
                              ("X", WRITE, ["X1"]), ("Y", WRITE, ["Y1"]), ("Z", WRITE, ["Z1"])):
        w.new_member(member, ds)
        devs += ds
        w.sync(devs)
        w.act("P1", "grant", f"grant-{member}", target=member, level=level)
        w.sync(devs)
    w.repair(devs)
    w.act("P1", "remove", "P-removes-X", target="X")
    w.act("Q1", "remove", "Q-removes-Y", target="Y")
    w.sync(["Q1", "Q2"])
    w.act("R1", "remove", "R-removes-Z", target="Z")
    w.sync(["P1", "Q1"])
    w.repair(["P1", "Q1"])
    w.sync(["Q2", "R1"])
    w.repair(["Q2", "R1"])
    w.sync(devs)
    W, V, _ = w.view("P1")
    S = w.g.current(V)
    assert len(S) == 2 and all(w.g.events[i].kind == "key" for i in S)
    cps = [checkpoint(w, "two concurrent heals meet", "P1", devs,
                      [({"X1", "Z1"}, S, KIND_CONTENT, True)])]
    w.repair(devs)
    W, V, _ = w.view("P1")
    cps.append(checkpoint(w, "a second heal; none needs a third", "P1", devs,
                          [({"X1", "Z1"}, w.g.current(V), KIND_CONTENT, False)]))
    out.append(_history(w, "concurrent heals need a second heal",
                        "Each healer wrapped for someone the other excluded.", cps))

    w, devs = _setup("c4", [("P", ADMIN), ("R", ADMIN), ("Q", ADMIN), ("W", WRITE)])
    w.new_member("G", ["G1"])
    w.act("P1", "grant", "P-admits-G-from-now-on", target="G", level=WRITE, history=False)
    w.sync(["P1", "W1", "G1"])
    w.act("W1", "key", "W-rotates", rotates=True)
    w.sync(["P1", "W1", "G1"])
    q = w.act("Q1", "remove", "Q-removes-P", target="P")
    uq = w.act("Q1", "unit", "uq")
    w.act("R1", "remove", "R-removes-Q", target="Q")
    room = ["P1", "W1", "G1", "Q1"]
    w.sync(room)
    w.repair(room)
    cps = [checkpoint(w, "rooms 1 and 2 meet: G's grant is void for now", "P1", room)]
    w.act("W1", "unit", "uw")
    w.sync(room)
    devs = devs + ["G1"]
    w.sync(devs)
    w.repair(devs)
    W, V, _ = w.view("P1")
    assert "G" in w.g.members(V) and q.id not in V
    cps.append(checkpoint(w, "room 3 arrives: G is back and must not reach k_q", "P1", devs,
                          [({"G1"}, uq.keyref, KIND_CONTENT, False)]))
    out.append(_history(w, "a stale link across a break",
                        "Links are gated on potential entitlement: the grantee of every break in "
                        "the hanging key's past counts, valid or void.", cps))

    w, devs = _setup("c7", [("P", ADMIN), ("Q", ADMIN)])
    w.new_member("G", ["G1"])
    w.new_member("K", ["K1"])
    w.act("P1", "grant", "P-admits-G-from-now-on", target="G", level=READ, history=False)
    w.sync(["P1", "G1"])
    w.act("Q1", "key", "Q-rotates", rotates=True)
    ux = w.act("Q1", "unit", "ux")
    devs = devs + ["G1"]
    w.sync(devs)
    w.repair(devs)
    w.act("P1", "grant", "P-grants-K-with-history", target="K", level=WRITE, history=True)
    devs = devs + ["K1"]
    w.sync(devs)
    w.repair(devs)
    cps = [checkpoint(w, "K, granted with history, reaches the other branch's unit", "P1", devs,
                      [({"K1"}, ux.keyref, KIND_CONTENT, True), ({"G1"}, ux.keyref, KIND_CONTENT, False)])]
    out.append(_history(w, "with history across a break's merge",
                        "A with-history grant receives every gap key it is entitled to.", cps))

    w, devs = _setup("c8", [("P", ADMIN), ("R", ADMIN), ("Q", ADMIN), ("W", WRITE), ("V", WRITE)])
    w.new_member("G", ["G1"])
    w.act("P1", "grant", "P-admits-G-from-now-on", target="G", level=READ, history=False)
    w.sync(["P1", "W1", "G1"])
    w.act("W1", "key", "W-rotates", rotates=True)
    w.sync(["P1", "W1", "G1"])
    w.act("Q1", "remove", "Q-removes-P", target="P")
    w.sync(["Q1", "V1"])
    w.act("V1", "key", "V-rotates", rotates=True)
    w.sync(["Q1", "V1"])
    w.act("R1", "remove", "R-removes-Q", target="Q")
    room = ["P1", "W1", "G1", "Q1", "V1"]
    w.sync(room)
    w.repair(room)
    u = w.act("W1", "unit", "u")
    devs = devs + ["G1"]
    w.sync(devs)
    w.repair(devs)
    cps = [checkpoint(w, "G's grant valid again: it receives the old merge key", "P1", devs,
                      [({"G1"}, u.keyref, KIND_CONTENT, True)])]
    out.append(_history(w, "a grant valid again misses an old merged key",
                        "Wraps follow the merged roster for every key a member is entitled to.",
                        cps))
    return out


def history_guest_heal() -> dict:
    w, devs = _setup("guest-heal", [("P", ADMIN), ("Q", ADMIN), ("M", WRITE), ("N", WRITE)])
    w.new_member("G", ["G1"])
    w.act("P1", "grant", "P-admits-guest", target="G", level=WRITE, history=False, session=True)
    devs = devs + ["G1"]
    w.sync(devs)
    w.repair(devs)
    w.act("P1", "remove", "P-removes-M", target="M")
    w.sync(["P1", "N1", "G1"])
    w.act("Q1", "remove", "Q-removes-N", target="N")
    w.sync(["Q1", "M1"])
    w.sync(["Q1", "G1"])
    W, V, _ = w.view("G1")
    cps = [checkpoint(w, "only the guest has met both rooms", "G1", ["G1"])]
    w.repair(["G1"])
    W, V, _ = w.view("G1")
    G = w.g.current(V, KIND_GRANT)
    cps.append(checkpoint(w, "the guest heals the content key; the grant heal waits", "G1", ["G1"], [
        ({"M1", "N1"}, w.g.current(V), KIND_CONTENT, False),
        ({"M1", "N1"}, G, KIND_GRANT, True)]))
    w.sync(["G1", "P1"])
    w.repair(["G1", "P1"])
    W, V, _ = w.view("P1")
    cps.append(checkpoint(w, "P meets the guest and heals the grant key", "P1", ["G1", "P1"], [
        ({"M1", "N1"}, w.g.current(V, KIND_GRANT), KIND_GRANT, False),
        ({"G1"}, w.g.current(V, KIND_GRANT), KIND_GRANT, False)]))
    return _history(w, "a guest heals; the grant key waits for a member that propagates",
                    "A guest may heal the content key but never draws a grant "
                    "seed, so the grant key's heal waits for a writer that propagates.", cps)


def history_break_merge_superseded() -> dict:
    """keys.md, "Deliveries", items 1 and 2: P admits N "from now on" (the
    break B) while Q rotates X on another branch. M meets both and, under
    the merged state B+X, signs a key event that does not rotate. P rotates
    Y after B before it sees X, and then Z after both, so B+X is never
    current at P and no rotation links back to it. N holds B's key and not
    X's, and is entitled to B+X, whose place holds N's admission: item 2
    delivers it, and M's event opens at N."""
    w, devs = _setup("break-merge-superseded", [("P", ADMIN), ("Q", ADMIN), ("M", WRITE)])
    w.new_member("N", ["N1"])
    b = w.act("P1", "grant", "P-admits-N-from-now-on", target="N", level=WRITE, history=False)
    w.sync(["P1", "M1", "N1"])
    x = w.act("Q1", "key", "X", rotates=True)
    w.sync(["Q1", "M1"])
    merged = canonical([b.id, x.id])
    e = w.act("M1", "key", "M-signs-under-the-merge", rotates=False)
    assert e.keyref == merged
    w.act("P1", "key", "Y", rotates=True)
    devs = devs + ["N1"]
    w.sync(devs)
    z = w.act("P1", "key", "Z", rotates=True)
    w.sync(devs)
    W, V, _ = w.view("P1")
    assert w.g.current(V) == (z.id,)
    assert w.g.ent(V, "N", merged), "rule 1: the merged state's place holds N's admission"
    cps = [checkpoint(w, "the merge is superseded before any writer delivers it", "P1", devs, [
        ({"N1"}, merged, KIND_CONTENT, False), ({"N1"}, (z.id,), KIND_CONTENT, True),
        ({"M1"}, merged, KIND_CONTENT, True)])]
    w.repair(devs)
    W, V, _ = w.view("P1")
    cps.append(checkpoint(w, "a writer delivers the merged state N is entitled to", "P1", devs, [
        ({"N1"}, merged, KIND_CONTENT, True), ({"N1"}, (x.id,), KIND_CONTENT, False)]))
    return _history(w, "a break's merge superseded before its delivery",
                    "A member admitted from now on holds its break's key and not that of a "
                    "rotation concurrent with it. An event sealed under the merged state "
                    "opens at the member only once it receives that state; once the state "
                    "is no longer current, item 2 delivers it, since the member is entitled "
                    "to it.", cps)


def history_invite() -> dict:
    """roster.md, in the key graph: P invites by link "from now
    on" (a break when the invite is made); the invite key I1 is a wrap
    recipient inside the merged roster. Its claim hands the invite's
    entitlement to the claimant C and puts I1 outside, holding the current
    key, so a writer heals: C receives the heal and I1 does not."""
    w, devs = _setup("invite", [("P", ADMIN), ("M", WRITE)])
    w.cross_check = False  # roster.py's own vectors test the successor
    w.new_member("I", ["I1"])
    w.new_member("C", ["C1"])
    inv = w.act("P1", "grant", "P-invites-by-link", target="I", level=WRITE, history=False,
                invite=True)
    w.sync(devs + ["I1"])
    w.repair(devs + ["I1"])
    W, V, arts = w.view("P1")
    assert heal_due(w.g, W, V, arts, KIND_CONTENT) is None
    cps = [checkpoint(w, "the invite key is inside; nothing heals", "P1", devs + ["I1"], [
        ({"I1"}, (inv.id,), KIND_CONTENT, True)])]
    w.act("I1", "succeed", "C-claims", target="C")
    w.sync(devs + ["I1", "C1"])
    W, V, arts = w.view("P1")
    assert heal_due(w.g, W, V, arts, KIND_CONTENT) == "outside"
    assert heal_due(w.g, W, V, arts, KIND_GRANT) == "outside"
    assert w.g.ent(V, "C", (inv.id,)), "rule 4: the claimant takes the invite's entitlement"
    cps.append(checkpoint(w, "a claim puts the invite key outside, holding the current key",
                          "P1", devs + ["I1", "C1"], [({"I1"}, (inv.id,), KIND_CONTENT, True)]))
    healed = w.repair(devs + ["I1", "C1"])
    assert healed, "a claim calls for a heal"
    W, V, arts = w.view("P1")
    assert heal_due(w.g, W, V, arts, KIND_CONTENT) is None
    assert heal_due(w.g, W, V, arts, KIND_GRANT) is None
    cps.append(checkpoint(w, "a writer heals: C receives the heal, the invite key does not",
                          "P1", devs + ["I1", "C1"], [
                              ({"C1"}, (inv.id,), KIND_CONTENT, True),
                              ({"C1"}, w.g.current(V), KIND_CONTENT, True),
                              ({"I1"}, w.g.current(V), KIND_CONTENT, False),
                              ({"I1"}, w.g.current(V, KIND_GRANT), KIND_GRANT, False)]))
    return _history(w, "an invite key, its claim, and the heal test",
                    "ext-invite-links.md, \"Keys\"; keys.md, \"The current state and the "
                    "inside\" and \"Healing\": an invite key in force is inside; once its "
                    "claim puts it out it counts as outside, holding the state the invite "
                    "delivered, so a writer heals. The claimant is wrapped for as a member "
                    "of its own.", cps)


def history_invite_raced() -> dict:
    w, devs = _setup("invite-raced", [("P", ADMIN), ("M", WRITE)])
    w.cross_check = False
    w.new_member("I", ["I1"])
    w.new_member("C", ["C1"])
    w.new_member("D", ["D1"])
    w.act("P1", "grant", "P-invites-by-link", target="I", level=WRITE, history=True,
          invite=True)
    w.sync(devs + ["I1"])
    w.repair(devs + ["I1"])
    before = set(w.views["I1"])
    w.act("I1", "succeed", "C-claims", target="C")
    w.act("I1", "succeed", "D-claims-concurrently", target="D", view=before)
    w.sync(devs + ["I1"])
    W, V, arts = w.view("P1")
    assert not any(w.g.events[i].kind == "succeed" for i in V)
    assert heal_due(w.g, W, V, arts, KIND_CONTENT) == "outside"
    cps = [checkpoint(w, "a raced claim: both void, and the invite key counts as outside",
                      "P1", devs)]
    w.repair(devs)
    W, V, arts = w.view("P1")
    assert heal_due(w.g, W, V, arts, KIND_CONTENT) is None
    cps.append(checkpoint(w, "a writer heals", "P1", devs,
                          [({"I1"}, w.g.current(V), KIND_CONTENT, False)]))
    return _history(w, "a raced claim counts the invite key as outside",
                    "keys.md, \"Healing\": after a raced claim the invite key's holdings "
                    "count as outside, so the heal test rotates the space.", cps)


def history_space_principals() -> dict:
    """P grants the team T. T's grant rotations are given as data (T0; T1, T
    removes b; T2, T removes c, who is also in P directly; T3, T admits f from
    now on; T4, T heals its grant key), each with the devices that hold its
    grant seed, and T's current devices as this replica holds T's log.
    Notices admit T's principals in P; the rotations responses name in their
    refs put them out of force, as a standing rule."""
    w = World("space-principals")
    w.g.foreign_past = {"T0": frozenset({"T0"}), "T1": frozenset({"T0", "T1"}),
                        "T2": frozenset({"T0", "T1", "T2"}),
                        "T3": frozenset({"T0", "T1", "T2", "T3"}),
                        "T4": frozenset({"T0", "T1", "T2", "T3", "T4"}),
                        "FAKE": frozenset({"FAKE"})}
    w.g.foreign_current = {"T": {"a1", "b1", "c1"}}
    w.genesis("P", ["P1"])
    devs = ["P1"]
    for member, ds in (("X", ["X1"]), ("C", ["c1"])):
        w.new_member(member, ds)
        devs += ds
        w.sync(devs)
        w.act("P1", "grant", f"grant-{member}", target=member, level=WRITE, history=True)
        w.sync(devs)
    w.new_member("T@T0", ["a1", "b1", "c1"])
    devs += ["a1", "b1"]
    w.act("P1", "grant", "P-grants-T", target="T@T0", level=WRITE, history=True)
    w.sync(devs)
    w.repair(devs)
    w.act("X1", "key", "X-rotates", rotates=True)
    w.sync(devs)
    w.repair(devs)
    cps = [checkpoint(w, "P grants T: T's principal at T0 holds P's keys", "P1", devs, [
        ({"a1"}, w.g.current(w.resolve(w.views["P1"])), KIND_CONTENT, True),
        ({"b1"}, w.g.current(w.resolve(w.views["P1"])), KIND_CONTENT, True)])]
    # T removes b (T1). a1 responds: a grant rotation, refs T1, a notice for T1.
    w.g.foreign_current["T"] = {"a1", "c1"}
    w.new_member("T@T1", ["a1", "c1"])
    w.act("a1", "key", "a-responds-to-T1", rotates=True, grant=True,
          notice=("T@T1", "T1", False), refs=(("T", "T1"),))
    w.sync(devs)
    w.repair(devs)
    W, V, _ = w.view("P1")
    K = w.g.current(V)
    assert "T@T0" not in w.g.members(V) and "T@T1" in w.g.members(V)
    cps.append(checkpoint(w, "T removes b; the response puts T@T0 out of force and admits T@T1", "P1",
                          devs, [({"b1"}, K, KIND_CONTENT, False), ({"a1"}, K, KIND_CONTENT, True),
                                 ({"c1"}, K, KIND_CONTENT, True)]))
    # T removes c (T2); c is still a direct member of P, so P loses nothing.
    w.g.foreign_current["T"] = {"a1"}
    w.new_member("T@T2", ["a1"])
    w.act("a1", "key", "a-responds-to-T2", rotates=False,
          notice=("T@T2", "T2", False), refs=(("T", "T2"),))
    w.sync(devs)
    w.repair(devs)
    W, V, arts = w.view("P1")
    assert w.g.current(V) == K and heal_due(w.g, W, V, arts, KIND_CONTENT) is None
    cps.append(checkpoint(w, "T removes c, who is also in P: a response that loses nothing",
                          "P1", devs, [({"c1"}, K, KIND_CONTENT, True)]))
    # A principal out of force cannot come back. c, still a writer of P and a
    # member of T at T0, re-notices T0: it admits nothing (NoticeStale), since
    # responses in P named T1 and T2. Nor does an event that both names T2 in
    # its sealed refs and notices T0. Both events stand: a notice decides no
    # verdict.
    renotice = w.act("c1", "key", "c-re-notices-T0", rotates=False,
                     notice=("T@T0", "T0", False))
    both = w.act("a1", "key", "a-puts-out-of-force-and-re-admits", rotates=False,
                 notice=("T@T0", "T0", False), refs=(("T", "T2"),))
    w.sync(devs)
    w.act("P1", "key", "P-rotates-after-re-notices", rotates=True)
    w.sync(devs)
    w.repair(devs)
    W, V, arts = w.view("P1")
    assert renotice.id in V and both.id in V and "T@T0" not in w.g.members(V)
    K = w.g.current(V)
    cps.append(checkpoint(w, "a re-notice of T0, and an event that puts it out of force and re-admits it: "
                             "both stand, and admit nothing (NoticeStale)", "P1", devs,
                          [({"b1"}, K, KIND_CONTENT, False), ({"a1"}, K, KIND_CONTENT, True)]))
    # Two refused notices, in events that stand: one planted by X, who is no
    # member of T, naming a rotation T never made (NotGranteeMember); one by
    # a, noticing T3, a break, as with history (NoticeMismatch).
    w.new_member("T@FAKE", ["evil1"])
    w.new_member("T@T3", ["a1", "f1"])
    plant = w.act("X1", "key", "X-plants-a-notice", rotates=False,
                  notice=("T@FAKE", "FAKE", False), bogus=True)
    mislabel = w.act("a1", "key", "a-notices-T3-without-its-break", rotates=False,
                     notice=("T@T3", "T3", False), bogus=True)
    w.sync(devs)
    w.act("P1", "key", "P-rotates", rotates=True)
    w.sync(devs)
    w.repair(devs)
    W, V, _ = w.view("P1")
    K = w.g.current(V)
    assert plant.id in V and mislabel.id in V
    assert "T@FAKE" not in w.g.members(V) and "T@T3" not in w.g.members(V)
    cps.append(checkpoint(w, "two refused notices: their events stand, and nobody seals to them",
                          "P1", devs, [
        ({"evil1"}, K, KIND_CONTENT, False), ({"f1"}, K, KIND_CONTENT, False)]))
    # T admits f from now on (T3, a break). a responds with a cascaded break.
    before = K
    w.g.foreign_current["T"] = {"a1", "f1"}
    devs.append("f1")
    w.act("a1", "key", "a-breaks-for-T3", rotates=True, grant=True, brk=True,
          notice=("T@T3", "T3", True), refs=(("T", "T3"),))
    w.sync(devs)
    w.repair(devs)
    W, V, _ = w.view("P1")
    K = w.g.current(V)
    cps.append(checkpoint(w, "T admits f from now on: P breaks, f reaches nothing before it",
                          "P1", devs, [({"f1"}, K, KIND_CONTENT, True),
                                       ({"f1"}, before, KIND_CONTENT, False),
                                       ({"a1"}, before, KIND_CONTENT, True)]))
    # T heals its grant key (T4, no break). a responds with a rotation and a
    # notice "with history". f, admitted to T at T3's break, is entitled in P
    # only from P's response to that break: the principal's entitlement is
    # the intersection over its devices.
    break_response = w.g.events[w.event_id("a-breaks-for-T3")].id
    w.new_member("T@T4", ["a1", "f1"])
    w.g.principal_floor["T@T4"] = [break_response]
    w.act("a1", "key", "a-responds-to-T4", rotates=True, grant=True,
          notice=("T@T4", "T4", False), refs=(("T", "T4"),))
    w.sync(devs)
    w.repair(devs)
    W, V, _ = w.view("P1")
    K = w.g.current(V)
    cps.append(checkpoint(w, "a notice with history after the break: f still reaches nothing "
                             "before the break", "P1", devs,
                          [({"f1"}, K, KIND_CONTENT, True),
                           ({"f1"}, (break_response,), KIND_CONTENT, True),
                           ({"f1"}, before, KIND_CONTENT, False),
                           ({"a1"}, before, KIND_CONTENT, True)]))
    h_ = _history(w, "space principals: a grant, notices, a principal out of force, cascades, a "
                     "break and refused notices",
                  "Members named T@R are the principal of space T at its grant rotation R, "
                  "whose devices are those holding R's grant seed. A notice admits one; the "
                  "rotation an event's sealed refs name puts out of force every principal of T whose "
                  "rotation does not include it. Space wraps appear as wraps to the principal's devices. "
                  "Refused notices stand for check_notice's NotGranteeMember, NoticeMismatch "
                  "and NoticeStale; they admit nothing, and their events stand. A principal's "
                  "inside devices are those still in T; T@T4's entitlement starts at P's "
                  "response to T3, where f joined.", cps)
    w.cross_check = False
    return h_


def history_revoked_device() -> dict:
    """keys.md, "Healing": a device keeps every state it received, whatever
    its person's list says later. Q's list revokes Q2, which holds the
    current keys: Q2 is outside, so both heal tests fire, and a writer heals
    with a grant rotation that wraps nothing for Q2."""
    w = World("revoked-device")
    w.genesis("P", ["P1"])
    devs = ["P1", "Q1", "Q2"]
    w.new_member("Q", ["Q1", "Q2"])
    w.sync(devs)
    w.act("P1", "grant", "grant-Q", target="Q", level=WRITE, history=True)
    w.sync(devs)
    w.repair(devs)
    W, V, arts = w.view("P1")
    K, G = w.g.current(V), w.g.current(V, KIND_GRANT)
    assert heal_due(w.g, W, V, arts, KIND_CONTENT) is None
    cps = [checkpoint(w, "Q's two devices hold the current keys", "P1", devs, [
        ({"Q2"}, K, KIND_CONTENT, True), ({"Q2"}, G, KIND_GRANT, True)])]
    w.g.revoked.add("Q2")
    w._valid.clear()
    room = ["P1", "Q1"]
    W, V, arts = w.view("P1")
    assert heal_due(w.g, W, V, arts, KIND_CONTENT) == "outside"
    assert heal_due(w.g, W, V, arts, KIND_GRANT) == "outside"
    cps.append(checkpoint(w, "Q's list revokes Q2, which still holds the current keys: "
                             "both heal tests fire", "P1", room, [
        ({"Q2"}, K, KIND_CONTENT, True), ({"Q2"}, G, KIND_GRANT, True)]))
    healed = w.repair(room)
    assert [e.label for e in healed] == ["heal-1"] and healed[0].grant
    W, V, arts = w.view("P1")
    assert heal_due(w.g, W, V, arts, KIND_CONTENT) is None
    assert heal_due(w.g, W, V, arts, KIND_GRANT) is None
    K, G = w.g.current(V), w.g.current(V, KIND_GRANT)
    cps.append(checkpoint(w, "a writer heals, and wraps nothing for Q2", "P1", room, [
        ({"Q2"}, K, KIND_CONTENT, False), ({"Q2"}, G, KIND_GRANT, False),
        ({"Q1"}, K, KIND_CONTENT, True)]))
    return _history(w, "a revoked device keeps what it received",
                    "Q's list revokes Q2 after Q2 received the current keys. A holder is "
                    "any device a wrap was made for, whatever the list says now, so Q2 "
                    "counts as outside and a writer heals. The checkpoint's input "
                    "`revoked` names the devices the list has revoked.", cps)


def world_checkpoint(w: World, title: str, c: bytes, device: str, room, queries=(),
                     before=()) -> dict:
    """keys.md, "Keys after a checkpoint": one device's view as a replica
    that keeps checkpoint c in effect holds it. `before` asks entitlement
    to states before c: (member, state, kind, expected)."""
    wg, W, V, arts = w.world_view(device, c)
    order = sorted(W, key=lambda i: (wg.height[i], w.labels[i]))
    K, G = wg.current(V), wg.current(V, KIND_GRANT)
    out = {
        "name": title, "view_of": device, "world_of": w.labels[c], "room": sorted(room),
        "events": [w.labels[i] for i in order],
        "valid": sorted(w.labels[i] for i in V),
        "artifacts": sorted(_art(w, a) for a in arts),
        "roster": {m: {"level": LEVEL_NAMES[x.level], "session": x.session}
                   for m, x in sorted(wg.members(V).items())},
        "inside": {KIND_NAMES[k]: sorted(wg.inside_devices(V, k, W))
                   for k in (KIND_CONTENT, KIND_GRANT)},
        "current": {"content": _name(w, K), "grant": _name(w, G)},
        "heal": {KIND_NAMES[k]: heal_due(wg, W, V, arts, k) for k in (KIND_CONTENT, KIND_GRANT)},
        "plan": {KIND_NAMES[kind]: _plan_json(w, plan(wg, W, V, arts, kind, room))
                 for kind in (KIND_CONTENT, KIND_GRANT)},
        "entitlement_before": [],
        "reaches": [],
    }
    if wg.foreign_current:
        out["foreign_current"] = {t: sorted(ds) for t, ds in sorted(wg.foreign_current.items())}
    for m, state, kind, expected in before:
        got = wg.ent(V, m, state, kind)
        assert got == expected, (w.name, title, m, _labels(w, state), kind, got)
        out["entitlement_before"].append({"member": m, "kind": KIND_NAMES[kind],
                                          "state": _name(w, state), "entitled": got})
    for devices, state, kind, expected in queries:
        result = state in Holdings(wg, W, arts, V, kind).reach(devices)
        assert result == expected, (w.name, title, devices, _labels(w, state), kind)
        out["reaches"].append({"devices": sorted(devices), "kind": KIND_NAMES[kind],
                               "state": _name(w, state), "result": result})
    return out


def _world_heal(w: World, c: bytes, device: str) -> tuple:
    wg, W, V, arts = w.world_view(device, c)
    return heal_due(wg, W, V, arts, KIND_CONTENT), heal_due(wg, W, V, arts, KIND_GRANT)


def checkpoint_heal() -> dict:
    """A cross-removal after the checkpoint: P removes M while Q removes N.
    In the world, M and N together derive the merged state, so the heal
    test fires, and a writer heals."""
    w, devs = _setup("cp-heal", [("P", ADMIN), ("Q", ADMIN), ("M", WRITE), ("N", WRITE)])
    w.act("P1", "key", "K0", rotates=True)
    w.sync(devs)
    w.repair(devs)
    c = w.make_checkpoint("P1", "C")
    w.sync(devs)
    w.repair(devs)
    assert _world_heal(w, c.id, "P1") == (None, None)
    w.act("P1", "remove", "A", target="M")
    w.sync(["P1", "N1"])
    w.act("Q1", "remove", "B", target="N")
    w.sync(["Q1", "M1"])
    w.sync(devs)
    assert _world_heal(w, c.id, "P1") == ("outside", "outside")
    cps = [world_checkpoint(w, "two removals after the checkpoint: M and N derive the merged "
                               "state, so the heal test fires", c.id, "P1", devs)]
    healed = w.repair(devs)
    assert [e.label for e in healed] == ["heal-1"]
    assert _world_heal(w, c.id, "P1") == (None, None)
    wg, W, V, _ = w.world_view("P1", c.id)
    cps.append(world_checkpoint(w, "a writer heals in the world", c.id, "P1", devs, [
        ({"M1", "N1"}, wg.current(V), KIND_CONTENT, False),
        ({"Q1"}, wg.current(V), KIND_CONTENT, True)]))
    return _history(w, "a heal after a checkpoint",
                    "keys.md, \"Keys after a checkpoint\": the world's current state, inside "
                    "and heal test read the checkpoint C and the events after it alone.", cps)


def checkpoint_entitlement() -> dict:
    """After the checkpoint, P grants N "with history" and F "from now on".
    A replica that forgot entitles N to every state before the checkpoint,
    F to none, and M, a member of the record, to none: only a replica that
    holds the past delivers M's."""
    w, devs = _setup("cp-entitlement", [("P", ADMIN), ("M", WRITE)])
    k0 = w.act("P1", "key", "K0", rotates=True)
    w.sync(devs)
    w.repair(devs)
    c = w.make_checkpoint("P1", "C")
    w.sync(devs)
    w.repair(devs)
    w.new_member("N", ["N1"])
    w.new_member("F", ["F1"])
    devs = devs + ["N1", "F1"]
    w.sync(devs)
    w.act("P1", "grant", "grant-N-with-history", target="N", level=WRITE, history=True)
    w.act("P1", "grant", "grant-F-from-now-on", target="F", level=WRITE, history=False)
    w.sync(devs)
    w.repair(devs)
    gen = (w.g.genesis,)
    cps = [world_checkpoint(w, "a with-history grant after the checkpoint reaches states "
                               "before it; a from-now-on one does not", c.id, "P1", devs, [
        ({"F1"}, (k0.id,), KIND_CONTENT, False)], before=[
        ("N", (k0.id,), KIND_CONTENT, True), ("N", gen, KIND_CONTENT, True),
        ("N", gen, KIND_GRANT, True), ("F", (k0.id,), KIND_CONTENT, False),
        ("F", gen, KIND_CONTENT, False), ("M", (k0.id,), KIND_CONTENT, False)])]
    return _history(w, "entitlement to states before a checkpoint",
                    "keys.md, \"Keys after a checkpoint\": a \"with history\" grant after the "
                    "checkpoint entitles its member to every state before it; a member of "
                    "the record is entitled to those its past entitled it to, which a "
                    "replica that forgot cannot tell, so it delivers none of them.", cps)


def checkpoint_raced_invite(dishonest: bool) -> dict:
    """I's claims race before the checkpoint, so I counts as outside. The
    checkpoint's record shows I raced, and its own delivery wraps nothing
    for I: no heal is due in the world. A checkpoint that wrapped for I
    anyway leaves an outside holder of the world's state: the heal test
    fires."""
    name = "cp-raced-invite" + ("-wrapped" if dishonest else "")
    w, devs = _setup(name, [("P", ADMIN), ("M", WRITE)])
    w.new_member("I", ["I1"])
    w.new_member("C", ["C1"])
    w.new_member("D", ["D1"])
    w.act("P1", "grant", "P-invites-by-link", target="I", level=WRITE, history=True,
          invite=True)
    w.sync(devs + ["I1"])
    w.repair(devs + ["I1"])
    before = set(w.views["I1"])
    w.act("I1", "succeed", "C-claims", target="C")
    w.act("I1", "succeed", "D-claims-concurrently", target="D", view=before)
    w.sync(devs + ["I1"])
    c = w.make_checkpoint("P1", "C")
    assert w.records[c.id]["raced"] == ["I"]
    if dishonest:
        for kind in (KIND_CONTENT, KIND_GRANT):
            w.publish("P1", Wrap(kind, (c.id,), "I1"))
    w.sync(devs + ["I1"])
    wg, W, V, arts = w.world_view("P1", c.id)
    assert "I1" not in wg.inside_devices(V, KIND_CONTENT, W)
    expected = ("outside", "outside") if dishonest else (None, None)
    assert _world_heal(w, c.id, "P1") == expected, (name, _world_heal(w, c.id, "P1"))
    title = ("a checkpoint that wrapped for the raced invite key: the heal test fires"
             if dishonest else "the record shows the invite key raced; the checkpoint wraps "
             "nothing for it, and no heal is due")
    cps = [world_checkpoint(w, title, c.id, "P1", devs, [
        ({"I1"}, (c.id,), KIND_CONTENT, dishonest)])]
    return _history(w, "a raced invite key across a checkpoint" + (
        ", wrapped for" if dishonest else ""),
                    "ext-invite-links.md, \"Across a checkpoint\"; keys.md, \"Keys after a "
                    "checkpoint\": a raced invite key counts as outside in the world; the "
                    "checkpoint wraps only for the inside of its past, so it already heals "
                    "what the key held.", cps)


def checkpoint_granted_space(floor: bool) -> dict:
    """P grants team T. With `floor`, T admits f from now on (T1, a break)
    and a responds with a "from now on" notice before the checkpoint; the
    record gives T a floor. Right after the checkpoint the record's
    principal is inside and no heal is due. After it, T heals its grant key
    (T2) and a responds with a "with history" notice: with the floor, that
    principal is entitled to no state before the checkpoint; without it, it
    is, as a "with history" grant would be."""
    name = "cp-granted" + ("-floor" if floor else "")
    w = World(name)
    w.g.foreign_past = {"T0": frozenset({"T0"}), "T1": frozenset({"T0", "T1"}),
                        "T2": frozenset({"T0", "T1", "T2"})}
    w.g.foreign_current = {"T": {"a1", "f1"} if floor else {"a1"}}
    w.genesis("P", ["P1"])
    devs = ["P1", "a1"]
    w.new_member("T@T0", ["a1"])
    w.sync(devs)
    w.act("P1", "grant", "P-grants-T", target="T@T0", level=WRITE, history=True)
    w.sync(devs)
    w.repair(devs)
    if floor:
        w.new_member("T@T1", ["a1", "f1"])
        devs.append("f1")
        w.act("a1", "key", "a-breaks-for-T1", rotates=True, grant=True, brk=True,
              notice=("T@T1", "T1", True), refs=(("T", "T1"),))
        w.sync(devs)
        w.repair(devs)
    k0 = w.act("P1", "key", "K0", rotates=True)
    w.sync(devs)
    w.repair(devs)
    c = w.make_checkpoint("P1", "C")
    w.sync(devs)
    w.repair(devs)
    assert w.records[c.id]["floor"] == (["T"] if floor else [])
    principal = "T@T1" if floor else "T@T0"
    wg, W, V, arts = w.world_view("P1", c.id)
    assert principal in wg.members(V) and "a1" in wg.inside_devices(V, KIND_CONTENT, W)
    assert _world_heal(w, c.id, "P1") == (None, None)
    cps = [world_checkpoint(w, "right after the checkpoint the record's principal is inside",
                            c.id, "P1", devs, [({"a1"}, (c.id,), KIND_CONTENT, True)])]
    w.new_member("T@T2", ["a1", "f1"] if floor else ["a1"])
    if floor:
        w.g.principal_floor["T@T2"] = [w.event_id("a-breaks-for-T1")]
    w.act("a1", "key", "a-responds-to-T2", rotates=True, grant=True,
          notice=("T@T2", "T2", False), refs=(("T", "T2"),))
    w.sync(devs)
    w.repair(devs)
    cps.append(world_checkpoint(
        w, "a with-history notice after the checkpoint" + (
            ": the floor keeps every state before it from the principal" if floor
            else ": with no floor, the principal reaches states before it"),
        c.id, "P1", devs, before=[("T@T2", (k0.id,), KIND_CONTENT, not floor),
                                  ("T@T2", (w.g.genesis,), KIND_CONTENT, not floor)]))
    h_ = _history(w, "a granted space across a checkpoint" + (", with a floor" if floor else ""),
                  "roster.md, \"Other logs and extensions\"; keys.md, \"Keys after a "
                  "checkpoint\": the record keeps T's principal, which the world admits at "
                  "its root, and T's floor, which keeps a later principal from every state "
                  "before the checkpoint.", cps)
    w.cross_check = False
    return h_


def checkpoint_late_rotation() -> dict:
    """P removes M, then checkpoints. Q, which saw neither, rotates
    concurrently (L) and wraps L for M. L is late: in the world it is no
    rotation, and its wraps count for nothing."""
    w, devs = _setup("cp-late", [("P", ADMIN), ("Q", ADMIN), ("M", WRITE)])
    old = set(w.views["Q1"])
    w.act("P1", "remove", "R", target="M")
    w.sync(["P1"])
    c = w.make_checkpoint("P1", "C")
    late = w.act("Q1", "key", "L", rotates=True, view=old)
    w.sync(devs)
    wg, W, V, arts = w.world_view("P1", c.id)
    assert late.id not in W and wg.current(V) == (c.id,)
    assert Wrap(KIND_CONTENT, (late.id,), "M1") in w.arts
    assert not any(isinstance(a, Wrap) and a.device == "M1" for a in arts)
    assert "M1" not in Holdings(wg, W, arts, V, KIND_CONTENT).holders
    assert _world_heal(w, c.id, "P1") == (None, None)
    cps = [world_checkpoint(w, "a late rotation wrapped for M: no rotation of the world, and "
                               "its wraps count for nothing", c.id, "P1", devs, [
        ({"M1"}, (c.id,), KIND_CONTENT, False)])]
    return _history(w, "a late rotation across a checkpoint",
                    "keys.md, \"Keys after a checkpoint\": holdings in the world come from "
                    "the artifacts of the checkpoint and the events after it alone.", cps)


def checkpoint_mixed_rotation() -> dict:
    """Q, offline, rotates late (L) and wraps L for M, whom P removed before
    checkpointing. P then takes Q's view and rotates (X), citing both C and
    L: X is after C with a parent, not its prev, neither C nor after it, so
    it is void (MixedCut), no rotation of the world, and the world's
    current state stays C. A later rotation after C that cites X counts,
    and M reaches neither. (Q's own next event may cite L as its prev.)"""
    w, devs = _setup("cp-mixed", [("P", ADMIN), ("Q", ADMIN), ("M", WRITE)])
    old = set(w.views["Q1"])
    w.act("P1", "remove", "R", target="M")
    w.sync(["P1"])
    c = w.make_checkpoint("P1", "C")
    late = w.act("Q1", "key", "L", rotates=True, view=old)
    w.sync(["P1", "Q1"])
    mixed = w.act("P1", "key", "X", rotates=True)
    assert late.id in mixed.parents and c.id in w.g.anc[mixed.id]
    w.sync(devs)
    wg, W, V, arts = w.world_view("P1", c.id)
    assert mixed.id in W and mixed.id not in V and wg.current(V) == (c.id,)
    cps = [world_checkpoint(w, "a rotation that cites the checkpoint and a late rotation is "
                               "void (MixedCut): the world's current state stays C", c.id,
                            "P1", devs, [({"M1"}, (c.id,), KIND_CONTENT, False)])]
    after = w.act("P1", "key", "K", rotates=True)
    w.sync(devs)
    w.repair(devs)
    wg, W, V, arts = w.world_view("P1", c.id)
    assert after.id in V and wg.current(V) == (after.id,)
    cps.append(world_checkpoint(w, "a later rotation after the checkpoint counts; M reaches "
                                   "none of the world's states", c.id, "P1",
                                devs, [({"M1"}, (after.id,), KIND_CONTENT, False),
                                       ({"Q1"}, (after.id,), KIND_CONTENT, True)]))
    return _history(w, "a mixed rotation across a checkpoint",
                    "roster.md, \"What follows a checkpoint\" and \"The world after a "
                    "checkpoint\"; keys.md, \"Keys after a checkpoint\": a rotation after "
                    "the checkpoint that also cites a late one is void (MixedCut), so it is "
                    "no rotation of the world.", cps)


def checkpoint_worlds_family() -> list:
    """keys.json's checkpoint_worlds."""
    return [checkpoint_heal(), checkpoint_entitlement(), checkpoint_raced_invite(False),
            checkpoint_raced_invite(True), checkpoint_granted_space(True),
            checkpoint_granted_space(False), checkpoint_late_rotation(),
            checkpoint_mixed_rotation()]


KEYS_LABELS = [MERGE_KEY_LABEL, MERGE_UPLOAD_LABEL, MERGE_GRANT_LABEL, GRANT_KEY_LABEL,
               GRANT_COMMITMENT_LABEL, READ_CREDENTIAL_LABEL, UPLOAD_KEY_LABEL,
               METADATA_KEY_LABEL, OBJECT_ID_KEY_LABEL, OBJECT_NONCE_KEY_LABEL, KEY_LINK_LABEL,
               BUNDLE_WRAP_LABEL, SPACE_WRAP_LABEL, REMOVAL_WRAP_LABEL, PAYLOAD_SEAL_LABEL,
               BODY_COMMITMENT_LABEL,
               ROTATION_RANK_LABEL, NAME_LABEL]


def _histories() -> list:
    return [history_example_1(), history_example_2(), history_example_3(),
            history_example_4(), history_example_5(), *history_counterexamples(),
            history_guest_heal(), history_space_principals(), history_revoked_device(),
            history_break_merge_superseded()]


def keys_vectors() -> dict:
    """keys.json."""
    import clocks
    import roster as rs
    import spaces

    bundles = bundle_vectors()
    who = [r for r in bundles["who_gets_what"] if not r["invite"]]
    for r in who:
        del r["invite"]
    rotation_sets = rotation_set_vectors()
    rotation_sets["refusals"] = rotation_sets.pop("negative")
    bundle_wraps = wrap_vectors()
    bundle_wraps["refusals"] = bundle_wraps.pop("negative")
    space_wraps = space_wrap_vectors()
    space_wraps["refusals"] = space_wraps.pop("negative")
    links = link_vectors()
    links["refusals"] = links.pop("negative")
    links["gap_refusals"] = links.pop("gap_negative")
    p = payload_vectors()
    se = rs.space_event_vectors()
    decisions = clocks.decision_tables()
    return {
        "specification": "keys.md",
        "labels": {label.decode(): label.hex() for label in KEYS_LABELS},
        "parameters": {
            "max_rotations": MAX_ROTATIONS, "collapse_above": COLLAPSE_ABOVE,
            "max_deliveries_per_event": MAX_DELIVERIES_PER_EVENT,
            "max_wraps_per_event": MAX_WRAPS_PER_EVENT, "max_refs_per_event": MAX_REFS,
            "max_name_bytes": MAX_NAME_BYTES, "max_document_id_bytes": MAX_NAME_ID_BYTES,
            "max_breaks_per_space": 256, "cascade_warning": 1024,
            "suite": SUITE_XWING, "self_reference_bytes": SELF_REF_BYTES,
            "bundle_bytes": BUNDLE_BYTES, "grant_public_key_bytes": XWING_PK_BYTES,
            "wrap_bytes": WRAP_BYTES, "rotation_rank_cap": ROTATION_RANK_CAP,
            "link_bytes_between_single_rotations": 2 + 33 + 33 + NONCE_BYTES + LINK_SEALED_BYTES,
        },
        "rotation_sets": rotation_sets,
        "derivations": derivation_vectors(),
        "bundles": {"shapes": bundles["good"], "refusals": bundles["negative"],
                    "who_gets_what": who},
        "bundle_wraps": bundle_wraps,
        "space_wraps": space_wraps,
        "removal_wraps": removal_wrap_vectors(),
        "links": links,
        "space_event_bodies": {
            "shapes": {"history": se["history"], "events": se["shapes"],
                       "body_key": se["body_key"], "genesis_body_key": se["genesis_body_key"]},
            "log": p["log"], "devices": p["devices"],
            "new_rotation_secrets": p["new_rotation_secrets"],
            "commitments_of_new_rotation": p["commitments_of_new_rotation"],
            "team": p["team"], "bodies": p["payloads"], "self_removal": p["self_removal"],
        },
        "visible_refusals": p["negative"],
        "sealed_refusals": p["sealed_negative"],
        "context_refusals": {"refused": p["context_negative"],
                             "accepted": p["context_accepted"]},
        "notices": p["notices"],
        "taking_keys": {"commitment_checks": p["commitment_checks"],
                        "provisional_keys": p["provisional_keys"],
                        "trial_decryption": p["trial_decryption"], "caps": p["caps"]},
        "ranks": {**rank_vectors(), "cascade_candidates": spaces.rank_vectors()},
        "rotation_delay": decisions["rotation_delay"],
        "cascades": spaces.cascade_vectors(core=True),
        "gap_keys": decisions["gap_keys"],
        "histories": _histories(),
        "checkpoint_worlds": checkpoint_worlds_family(),
        "sealed_names": sealed_names_family(),
    }


def restricted_families() -> dict:
    """ext-restricted-spaces.json's restricted_keys, reference_refusals,
    restricted_space_event and restricted_names."""
    r = restricted_vectors()
    return {"restricted_keys": {"space": r["space"], "parent": r["parent"],
                                "rotations": r["rotations"], "keys": r["keys"]},
            "reference_refusals": r["negative"],
            "restricted_space_event": r["space_event"],
            "restricted_names": restricted_names_family()}


def invite_keys_family() -> dict:
    """ext-invite-links.json's keys: who receives what, for invite keys; a
    claim that hands its entitlement, after which the invite key is outside
    and a writer heals; a raced claim after which the invite key is outside
    and a writer heals."""
    who = [r for r in bundle_vectors()["who_gets_what"] if r["invite"]]
    return {"who_gets_what": who, "histories": [history_invite(), history_invite_raced()]}


def self_test() -> None:
    for new in NEW_LABELS:
        for other in NEW_LABELS:
            if other is not new:
                assert not other.startswith(new), (new, other)
    a, b = ROT["A"], ROT["B"]
    assert decode_set(encode_set(canonical([b, a]))) == canonical([a, b])
    assert expect_error(encode_set, sorted([a, b], reverse=True)) == "Malformed"
    k = content_key(SPACE, (a, b), _secret_of("content"))
    assert k == content_key(SPACE, (b, a), _secret_of("content"))
    assert k != SECRETS["A"]["content"]
    WORLDS.clear()
    first = keys_vectors()
    invites = invite_keys_family()
    worlds = list(WORLDS)
    WORLDS.clear()
    assert first == keys_vectors(), "the vectors are not deterministic"
    WORLDS.clear()
    # Every history's valid sets, maximal rotations, voiding events and
    # stability agree with reference/roster.py, rebuilt as real events.
    checked = 0
    for w in worlds:
        if not getattr(w, "cross_check", True):
            continue  # roster.py does not read notices
        for row in roster_cross_check(w):
            assert row["valid_agrees"] and row["rotations_agree"], (w.name, row)
            assert all(s["voiders_agree"] and s["stable_agrees"] for s in row["stability"]), \
                (w.name, row)
            checked += 1
    assert checked == sum(len(x["checkpoints"]) for x in first["histories"]
                          if "grantee_rotations" not in x)
    assert len(first["histories"]) == 15
    who = {r["recipient"]: r["bundle"] for r in invites["who_gets_what"]}
    assert who["an invite key at read, without session"] == ["content", "upload", "grant"]
    assert who["a guest invite at read"] == ["content", "upload"]
    sealed = {c["name"]: c["error"] for c in first["sealed_refusals"]}
    assert sealed["a commitment to another key"] == "BadSeal", sealed
    assert sealed["a sealed part damaged in transit"] == "BadSeal", sealed
    names = first["sealed_names"]
    assert len(names["sealed"]) == 7 and len(names["record_refusals"]) == 7
    restricted = restricted_families()
    assert restricted["restricted_names"]["refusals"][0]["error"] == "Malformed"
    # keys.md, "Keys after a checkpoint": each case asserts as it builds;
    # here, the verdicts the vectors show.
    worlds = {x["name"]: x["checkpoints"] for x in first["checkpoint_worlds"]}
    assert len(worlds) == 8
    mixed = worlds["a mixed rotation across a checkpoint"]
    assert mixed[0]["current"]["content"] == "C" and "X" not in mixed[0]["valid"]
    heal = worlds["a heal after a checkpoint"]
    assert heal[0]["heal"] == {"content": "outside", "grant": "outside"}
    assert heal[1]["heal"] == {"content": None, "grant": None}
    assert worlds["a raced invite key across a checkpoint"][0]["heal"]["content"] is None
    assert worlds["a raced invite key across a checkpoint, wrapped for"][0]["heal"]["content"] \
        == "outside"
    assert not any(e["entitled"] for e in worlds[
        "a granted space across a checkpoint, with a floor"][1]["entitlement_before"])
    assert all(e["entitled"] for e in worlds[
        "a granted space across a checkpoint"][1]["entitlement_before"])
    assert worlds["a late rotation across a checkpoint"][0]["current"]["content"] == "C"


if __name__ == "__main__":
    self_test()
    print("ok")
