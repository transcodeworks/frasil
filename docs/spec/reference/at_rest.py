"""What a device keeps at rest (at-rest.md), written from the specification,
independently of any implementation: the sealed device keys and their seal under an
unlock key; the store secret's keys; blinded addresses; the sealed record
and every table's value; the mark and the continuity decision it feeds;
application keys; and held objects, which the application keeps as
plaintext and the device seals again when it serves."""

from __future__ import annotations

import hashlib
import hmac
import json

import events as ev
import history_sigs as hs
import identity
import keygraph as kg
import mldsa
import units
import xwing
from events import cbor, h, is_bytes, is_uint, uncbor
from formats import REVISION, device, example, u32be, u64be
from primitives import (
    SpecError,
    ed25519_public,
    field,
    hkdf,
    sha256,
    xchacha20poly1305_open,
    xchacha20poly1305_seal,
)

# ---------------------------------------------------------------------------
# Labels.

SEAL_KEY_LABEL = b"frasil/at-rest/seal-key/v1"
TAG_KEY_LABEL = b"frasil/at-rest/tag-key/v1"
SCOPE_LABEL = b"frasil/at-rest/scope/v1"
ITEM_LABEL = b"frasil/at-rest/item/v1"
RECORD_LABEL = b"frasil/at-rest/record/v1"
MARK_LABEL = b"frasil/at-rest/mark/v1"
APP_KEY_LABEL = b"frasil/at-rest/app-key/v1"
NEW_LABELS = [SEAL_KEY_LABEL, TAG_KEY_LABEL, SCOPE_LABEL, ITEM_LABEL, RECORD_LABEL, MARK_LABEL,
              APP_KEY_LABEL]

# The sealed device keys' labels (at-rest.md, "Sealed device keys").
SEALED_DEVICE_KEYS = b"frasil/sealed-device-keys/v1"
UNLOCK_KEY_SALT = b"frasil/unlock-key/v1"

NONE = bytes(32)
VERSION = 1

# ---------------------------------------------------------------------------
# Sealed device keys (at-rest.md, "Sealed device keys").

KIND_PASSKEY_UNLOCK = 1
KIND_UNLOCK_KEY = 2
LAYOUT_VERSION = 1
ZERO_PERSON = bytes(32)
HEADER_BYTES = 1 + 1 + 32 + 32
SEEDS = ("identity_seed", "xwing_seed", "mldsa_seed", "store_secret")
PLAINTEXT_BYTES = 1 + 32 * len(SEEDS)                                  # 129
SEALED_DEVICE_KEYS_BYTES = HEADER_BYTES + 24 + PLAINTEXT_BYTES + 16    # 235


def passkey_unlock_key(person_id: bytes, prf_output: bytes) -> bytes:
    """The unlock key a passkey derives for a person (identity.md, the
    passkey member's derivations)."""
    return identity.passkey_keys(person_id, prf_output)["unlock_key"]


def fixture_keys(name: str) -> dict:
    """A vector device's four secrets: crypto.md's fixture seeds from the
    device's identity seed, and a store secret. A real device draws all four
    from its random source."""
    seeds = identity.fixture_keys(device(name).seed)
    return {"identity_seed": seeds["identity_seed"], "xwing_seed": seeds["xwing_seed"],
            "mldsa_seed": seeds["mldsa_seed"],
            "store_secret": example(f"at-rest/{name}/store-secret")}


def public_keys(keys: dict) -> dict:
    """The three public keys the seeds give, their kc and device ID
    (crypto.md, "A device's keys"): what open_device_keys's step 10
    derives."""
    ed = ed25519_public(keys["identity_seed"])
    mldsa_public = mldsa.mldsa_keygen(keys["mldsa_seed"])[0]
    xwing_public = xwing.xwing_public_key(keys["xwing_seed"])
    kc = hs.keys_commitment(mldsa_public, xwing_public)
    return {"identity": ed, "mldsa": mldsa_public, "xwing": xwing_public, "kc": kc,
            "device_id": hs.device_id(ed, kc)}


def keys_device_id(keys: dict) -> bytes:
    return public_keys(keys)["device_id"]


def device_keys_plaintext(keys: dict) -> bytes:
    return bytes([LAYOUT_VERSION]) + b"".join(keys[n] for n in SEEDS)


def parse_device_keys(plaintext: bytes) -> dict:
    if not plaintext:
        raise SpecError("Malformed")
    if plaintext[0] != LAYOUT_VERSION:
        raise SpecError("UnsupportedVersion")
    if len(plaintext) != PLAINTEXT_BYTES:
        raise SpecError("Malformed")
    return {n: plaintext[1 + 32 * i: 33 + 32 * i] for i, n in enumerate(SEEDS)}


def device_sealing_key(kind: int, key: bytes) -> bytes:
    """Kind 1: the passkey's unlock key as it is. Kind 2: a key derived from
    the application's, never the application's key itself."""
    if len(key) != 32:
        raise SpecError("Malformed")
    return key if kind == KIND_PASSKEY_UNLOCK else hkdf(UNLOCK_KEY_SALT, key, SEALED_DEVICE_KEYS)


def device_keys_header(kind: int, device_id: bytes, person_id: bytes) -> bytes:
    return bytes([VERSION, kind]) + device_id + person_id


def seal_device_keys(kind: int, key: bytes, person_id: bytes, keys: dict, nonce: bytes) -> dict:
    if kind not in (KIND_PASSKEY_UNLOCK, KIND_UNLOCK_KEY) or len(person_id) != 32:
        raise SpecError("Malformed")
    if kind == KIND_PASSKEY_UNLOCK and person_id == ZERO_PERSON:
        raise SpecError("Malformed")
    header = device_keys_header(kind, keys_device_id(keys), person_id)
    aad = SEALED_DEVICE_KEYS + header
    plaintext = device_keys_plaintext(keys)
    sk = device_sealing_key(kind, key)
    return {"header": header, "aad": aad, "plaintext": plaintext, "sealing_key": sk,
            "nonce": nonce,
            "blob": header + nonce + xchacha20poly1305_seal(sk, nonce, plaintext, aad)}


def read_device_keys_header(blob: bytes) -> dict:
    """at-rest.md, open_device_keys steps 1 to 3: what anyone reads without
    a key."""
    if len(blob) < 2:
        raise SpecError("Malformed")
    if blob[0] != VERSION:
        raise SpecError("UnsupportedVersion")
    if blob[1] not in (KIND_PASSKEY_UNLOCK, KIND_UNLOCK_KEY) or len(blob) != SEALED_DEVICE_KEYS_BYTES:
        raise SpecError("Malformed")
    person = blob[34:66]
    if blob[1] == KIND_PASSKEY_UNLOCK and person == ZERO_PERSON:
        raise SpecError("Malformed")
    return {"kind": blob[1], "device_id": blob[2:34], "person_id": person}


def open_device_keys(blob: bytes, kind: int, key: bytes, expected_person: bytes | None,
                     expected_device: bytes | None = None) -> dict:
    """at-rest.md, open_device_keys, in order. `expected_person` None skips
    step 5 only so that the vectors can show the AEAD refusing a changed
    header; a client always names it."""
    header = read_device_keys_header(blob)
    if header["kind"] != kind:
        raise SpecError("WrongKeyKind")
    if expected_person is not None and header["person_id"] != expected_person:
        raise SpecError("WrongPerson")
    if expected_device is not None and header["device_id"] != expected_device:
        raise SpecError("WrongDevice")
    plaintext = xchacha20poly1305_open(device_sealing_key(kind, key),
                                       blob[HEADER_BYTES:HEADER_BYTES + 24],
                                       blob[HEADER_BYTES + 24:],
                                       SEALED_DEVICE_KEYS + blob[:HEADER_BYTES])
    keys = parse_device_keys(plaintext)
    # Step 10: the device ID of the three seeds' public keys.
    if keys_device_id(keys) != header["device_id"]:
        raise SpecError("Malformed")
    return keys


# ---------------------------------------------------------------------------
# The store's keys and addresses (at-rest.md, "Keys, addresses and records").

DEVICE, LOG = "device", "log"
DEVICE_SCOPE = bytes(16)
TAG_BYTES = 16
ADDRESS_BYTES = TAG_BYTES + 1 + TAG_BYTES
RECORD_OVERHEAD = 1 + 24 + 16
MIN_RECORD = RECORD_OVERHEAD + 4                                       # 45
SEALED_CHUNK_MIN = 24 + 16

T_HEAD, T_LOG, T_TIMELINE, T_EPOCH, T_NEXT_ENDPOINT = 0x00, 0x01, 0x02, 0x03, 0x04
T_DEPOSIT_KEYS, T_TOKEN, T_DEPOSIT = 0x05, 0x06, 0x07
T_EVENT, T_OBJECT, T_KEY, T_OUTBOX = 0x10, 0x11, 0x12, 0x13
T_ACK, T_LISTING, T_STATE, T_PSEUDONYM = 0x14, 0x15, 0x16, 0x17
T_INVITE, T_CLAIM, T_REPLAY, T_VOUCHED, T_ENDPOINT, T_HOST = 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x20
T_HELD, T_PEERS, T_ANNOUNCED = 0x1D, 0x1E, 0x1F
T_DROPPED = 0x21
TABLES = {
    T_HEAD: ("head", DEVICE), T_LOG: ("log", DEVICE), T_TIMELINE: ("timeline", DEVICE),
    T_EPOCH: ("epoch", DEVICE), T_NEXT_ENDPOINT: ("next_endpoint", DEVICE),
    T_DEPOSIT_KEYS: ("deposit_keys", DEVICE), T_TOKEN: ("token", DEVICE),
    T_DEPOSIT: ("deposit", DEVICE),
    T_EVENT: ("event", LOG), T_OBJECT: ("object", LOG), T_KEY: ("key", LOG),
    T_OUTBOX: ("outbox", LOG), T_ACK: ("ack", LOG), T_LISTING: ("listing", LOG),
    T_STATE: ("state", LOG), T_PSEUDONYM: ("pseudonym", LOG), T_INVITE: ("invite", LOG),
    T_CLAIM: ("claim", LOG), T_REPLAY: ("replay", LOG), T_VOUCHED: ("vouched", LOG),
    T_ENDPOINT: ("endpoint", LOG), T_HELD: ("held", LOG), T_PEERS: ("peers", LOG),
    T_ANNOUNCED: ("announced", LOG),
    T_HOST: ("host", LOG), T_DROPPED: ("dropped", LOG),
}
LOG_SPACE, LOG_LIST = 1, 2
K_ROTATION, K_STATE, K_BODY, K_GAP, K_RECORD = 1, 2, 3, 4, 5
# dropped: an event the device held and dropped, or a parent a peer answered
# Missing for (roster.md, "Forgetting, and starting from a checkpoint").
D_HELD, D_MISSING = 1, 2
BODY_DERIVED, BODY_HANDED = 1, 2
S_VALID, S_REFUSED, S_PENDING, S_HELD, S_AWAITING_KEY, S_ALONE = 1, 2, 3, 4, 5, 6
F_VERIFIED, F_PROVISIONAL = 0x01, 0x02
MAX_TIPS = 65536
MAX_ACK_HEADS = 256
MAX_BASE_HEADS = 256
# ext-guests.md: a leave request names 1 to 64 grants, which `state` key 4 keeps.
MAX_LEFT_GRANTS = 64
MAX_HOST_ITEM = 256
# transport.md, "Tickets": a ticket is at most 1,024 bytes of CBOR.
MAX_ENDPOINT_VALUE = 1024
# ext-deposit-tokens.md: the issuing keys a device keeps per peer, the newest;
# a token's length and version; a key list's entries and roles.
MAX_SEEN_KEYS = 64
TOKEN_BYTES = 129
# transport.md, "Mailboxes": the largest mailbox item.
MAX_MAILBOX_ITEM = 262_144
MAX_CHUNK = 1024 * 1024
MAX_CLASS = 64
MAX_SLOT_INDEX = 64
MAX_OBJECT_SIZE = 2 ** 40
# at-rest.md, "Held objects": a held record's token and stamp.
MAX_HELD_TOKEN = 1024
# admission.md, "The welcome": 0 to 8 peer hints of 1 to 512 bytes; a `peers` record keeps
# 1 to 8, and a home peer of the same length.
MAX_PEER_HINTS = 8
MAX_PEER_URL = 512
MAX_HELD_STAMP = 64


def hmac256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def seal_key(scope_key: bytes) -> bytes:
    return hkdf(NONE, scope_key, SEAL_KEY_LABEL)


def tag_key(scope_key: bytes) -> bytes:
    return hkdf(NONE, scope_key, TAG_KEY_LABEL)


def app_key(scope_key: bytes, purpose: bytes) -> bytes:
    """at-rest.md, "Application keys": a key for the application's own data,
    under the store secret or a log key."""
    return hkdf(NONE, scope_key, APP_KEY_LABEL + field(purpose))


def scope_tag(store_secret: bytes, log_id: bytes | None) -> bytes:
    if log_id is None:
        return DEVICE_SCOPE
    if len(log_id) != 32:
        raise SpecError("Malformed")
    return hmac256(tag_key(store_secret), SCOPE_LABEL + log_id)[:TAG_BYTES]


def item_tag(scope_key: bytes, table: int, item: bytes) -> bytes:
    return hmac256(tag_key(scope_key), ITEM_LABEL + bytes([table]) + field(item))[:TAG_BYTES]


def address(store_secret: bytes, scope_key: bytes, table: int, item: bytes,
            log_id: bytes | None) -> bytes:
    return scope_tag(store_secret, log_id) + bytes([table]) + item_tag(scope_key, table, item)


def record_aad(addr: bytes) -> bytes:
    return RECORD_LABEL + bytes([VERSION]) + addr


def seal_record(scope_key: bytes, addr: bytes, item: bytes, value: bytes, nonce: bytes) -> dict:
    plaintext = field(item) + value
    aad = record_aad(addr)
    return {"plaintext": plaintext, "aad": aad, "nonce": nonce,
            "record": bytes([VERSION]) + nonce + xchacha20poly1305_seal(
                seal_key(scope_key), nonce, plaintext, aad)}


# ---------------------------------------------------------------------------
# Items and values, table by table (at-rest.md, "Tables" and "The head,
# events and keys").


def _set_ok(data: bytes, minimum: int) -> bool:
    try:
        n = data[0]
        ids = [data[1 + 32 * i: 33 + 32 * i] for i in range(n)]
        return len(data) == 1 + 32 * n and n >= minimum and kg.encode_set(ids) == data
    except (IndexError, SpecError):
        return False


def slot_reference_ok(item: bytes) -> bool:
    """peers.md's slot reference, [c, index, maker]: a 32-byte twin
    commitment, an index below 64 and the 32-byte event ID of the event that
    made the administrator slot, in deterministic CBOR."""
    try:
        ref = uncbor(item)
    except SpecError:
        return False
    return (isinstance(ref, list) and len(ref) == 3 and is_bytes(ref[0], 32)
            and is_uint(ref[1]) and ref[1] < MAX_SLOT_INDEX and is_bytes(ref[2], 32))


def slot_reference(commitment: bytes, index: int, maker: bytes) -> bytes:
    return cbor([commitment, index, maker])


def item_ok(table: int, item: bytes) -> bool:
    if table in (T_HEAD, T_TIMELINE, T_EPOCH, T_NEXT_ENDPOINT, T_STATE, T_PEERS):
        return item == b""
    if table in (T_LOG, T_EVENT, T_ACK, T_LISTING, T_REPLAY, T_INVITE, T_CLAIM, T_VOUCHED,
                 T_ENDPOINT, T_HELD, T_ANNOUNCED, T_DEPOSIT_KEYS, T_DROPPED):
        return len(item) == 32
    if table == T_TOKEN:
        return len(item) == 64
    if table == T_DEPOSIT:
        return len(item) == 16
    if table == T_OBJECT:
        return len(item) == 36
    if table == T_OUTBOX:
        return len(item) == 40 and int.from_bytes(item[32:], "big") >= 1
    if table == T_PSEUDONYM:
        return slot_reference_ok(item)
    if table == T_HOST:
        return 1 <= len(item) <= MAX_HOST_ITEM
    if table == T_KEY:
        if not item:
            return False
        kind, rest = item[0], item[1:]
        if kind in (K_ROTATION, K_BODY, K_RECORD):
            return len(rest) == 32
        if kind == K_STATE:
            return _set_ok(rest, 2)
        if kind == K_GAP:
            return len(rest) >= 1 and rest[0] in (1, 2) and _set_ok(rest[1:], 1)
    return False


def _map(value: bytes, allowed: set, required: set) -> dict:
    m = uncbor(value)
    if not isinstance(m, dict) or not set(m) <= allowed or not required <= set(m):
        raise SpecError("Malformed")
    return m


def _check_reading(r) -> dict:
    if (not isinstance(r, dict) or not set(r) <= {1, 2, 3} or not {1, 2} <= set(r)
            or not all(is_uint(x) for x in r.values())):
        raise SpecError("Malformed")
    return r


def _erasing(value) -> bool:
    """The `state` record's key 9, alone, in the residue of the device's
    own erasure (peers.md, "A device's own erasure"): 1 to 64 pairs
    [device ID (32), X-Wing key (1,216)], strictly ascending by device ID."""
    return isinstance(value, list) and 1 <= len(value) <= 64 and all(
        isinstance(a, list) and len(a) == 2 and is_bytes(a[0], 32) and is_bytes(a[1], 1216)
        for a in value) and all(a[0] < b[0] for a, b in zip(value, value[1:]))


def _attribution(value) -> bool:
    """The `event` record's key 7 (roster.md, section 3.11): 1 to 64
    entries [type, ID] or [type, ID, label], the label 1 to 64 bytes of
    UTF-8, strictly ascending by type then ID."""
    if not (isinstance(value, list) and 1 <= len(value) <= 64):
        return False
    for a in value:
        if not (isinstance(a, list) and len(a) in (2, 3) and is_uint(a[0]) and a[0] <= 3
                and is_bytes(a[1], 32)):
            return False
        if len(a) == 3 and not (isinstance(a[2], str) and 1 <= len(a[2].encode()) <= 64):
            return False
    return all((a[0], a[1]) < (b[0], b[1]) for a, b in zip(value, value[1:]))


def _expressed_again(pairs) -> bool:
    """The `state` record's key 8: 1 or more [stream (16 bytes), incarnation
    from 1], strictly ascending by stream then incarnation."""
    return (isinstance(pairs, list) and len(pairs) >= 1
            and all(isinstance(p, list) and len(p) == 2 and is_bytes(p[0], 16)
                    and is_uint(p[1]) and p[1] >= 1 for p in pairs)
            and all((a[0], a[1]) < (b[0], b[1]) for a, b in zip(pairs, pairs[1:])))


def _ascending(ids, length: int = 32) -> bool:
    return (isinstance(ids, list) and all(is_bytes(i, length) for i in ids)
            and all(a < b for a, b in zip(ids, ids[1:])))


def read_value(table: int, item: bytes, value: bytes, log_id: bytes | None):
    """Each table's value, which must parse exactly."""
    if table == T_HEAD:
        m = _map(value, {1, 2, 3, 4, 5, 6}, {1, 2, 3})
        if 6 in m and not is_uint(m[6]):
            raise SpecError("Malformed")
        tips = m[3]
        if not (is_bytes(m[1], 16) and is_uint(m[2]) and m[2] >= 1 and isinstance(tips, list)
                and len(tips) <= MAX_TIPS):
            raise SpecError("Malformed")
        for t in tips:
            if not (isinstance(t, list) and len(t) == 4 and is_bytes(t[0], 32)
                    and is_bytes(t[1], 32) and is_uint(t[2]) and t[2] >= 1
                    and is_bytes(t[3], 32)):
                raise SpecError("Malformed")
        if any(a[0] + a[1] >= b[0] + b[1] for a, b in zip(tips, tips[1:])):
            raise SpecError("Malformed")
        if (4 in m) != (5 in m) or (4 in m and not (is_uint(m[4]) and 1 <= m[4] <= m[2]
                                                     and _ascending(m[5]))):
            raise SpecError("Malformed")
        return m
    if table == T_LOG:
        if len(value) != 33 or value[0] not in (LOG_SPACE, LOG_LIST):
            raise SpecError("Malformed")
        return {"kind": value[0], "log_key": value[1:]}
    if table == T_TIMELINE:
        return _check_reading(uncbor(value))
    if table == T_EPOCH:
        if len(value) != 8:
            raise SpecError("Malformed")
        return int.from_bytes(value, "big")
    if table in (T_NEXT_ENDPOINT, T_ANNOUNCED):
        if len(value) != 32:
            raise SpecError("Malformed")
        return value
    if table == T_EVENT:
        m = _map(value, {1, 2, 3, 4, 5, 6, 7, 8}, {1, 2, 3})
        if not (is_bytes(m[1]) and is_uint(m[2]) and S_VALID <= m[2] <= S_ALONE
                and is_uint(m[3]) and m[3] <= F_VERIFIED | F_PROVISIONAL):
            raise SpecError("Malformed")
        # Key 6: a kept unit of a forgotten past, its author's capabilities
        # at its place, frozen with state 1 or 2 (units.md, "The past of a
        # kept checkpoint").
        if 6 in m:
            caps = m[6]
            if m[2] not in (S_VALID, S_REFUSED) or not isinstance(caps, list) \
                    or len(caps) > 64 or not all(
                        isinstance(c, list) and len(c) == 2 and isinstance(c[0], str)
                        and 1 <= len(c[0].encode()) <= 64 and c[1] in (0, 1) for c in caps) \
                    or any((a[0].encode(), a[1]) >= (b[0].encode(), b[1])
                           for a, b in zip(caps, caps[1:])):
                raise SpecError("Malformed")
        # Key 7, its attribution, for a unit the write rule admits, whatever
        # its content became (state 1 or 2); key 8, the events that void a
        # unit the write rule voids, with state 2; each only beside key 6,
        # and never both.
        if 7 in m and not (6 in m and 8 not in m and _attribution(m[7])):
            raise SpecError("Malformed")
        if 8 in m and not (6 in m and m[2] == S_REFUSED and isinstance(m[8], list)
                           and 1 <= len(m[8]) <= 64 and all(is_bytes(x, 32) for x in m[8])
                           and all(a < b for a, b in zip(m[8], m[8][1:]))):
            raise SpecError("Malformed")
        if (4 in m) != (m[2] == S_REFUSED) or (
                4 in m and not (isinstance(m[4], str) and 1 <= len(m[4].encode()) <= MAX_CLASS)):
            raise SpecError("Malformed")
        if 5 in m:
            _check_reading(m[5])
        outer = uncbor(m[1])
        if not (isinstance(outer, list) and len(outer) == 2 and is_bytes(outer[0])
                and is_bytes(outer[1])):
            raise SpecError("Malformed")
        fields = uncbor(outer[0])
        own = ev.event_id(outer[0])
        if not isinstance(fields, dict) or own != item or fields.get(2, own) != log_id:
            raise SpecError("Malformed")
        return m
    if table == T_OBJECT:
        part = int.from_bytes(item[32:], "big")
        if part == 0:
            hd = _map(value, {1, 2, 3, 4}, {1, 2, 3, 4})
            if hd[1] != 1 or hd[2] != item[:32] or not is_bytes(hd[3]) \
                    or not (is_uint(hd[4]) and hd[4] <= MAX_OBJECT_SIZE):
                raise SpecError("Malformed")
        elif not SEALED_CHUNK_MIN <= len(value) <= MAX_CHUNK:
            raise SpecError("Malformed")
        return value
    if table == T_DROPPED:
        # Key 3, the height of a dropped parent of an event the log keeps of
        # its kept checkpoint's past, only with origin 1 (events.md,
        # "Placement and order").
        m = _map(value, {1, 2, 3}, {1})
        if m[1] not in (D_HELD, D_MISSING) or (2 in m) != (m[1] == D_HELD) \
                or (2 in m and not (is_uint(m[2]) and m[2] <= 255)) \
                or (3 in m and (m[1] != D_HELD or not is_uint(m[3]) or m[3] < 1)):
            raise SpecError("Malformed")
        return m
    if table == T_KEY:
        if item[0] == K_RECORD:
            # A checkpoint's record object key: derived from rotation secrets
            # this device holds (1), or handed by a space snapshot (2).
            if len(value) != 33 or value[0] not in (BODY_DERIVED, BODY_HANDED):
                raise SpecError("Malformed")
            return {"source": value[0], "record_key": value[1:]}
        if item[0] == K_BODY:
            if not value or value[0] not in (BODY_DERIVED, BODY_HANDED) \
                    or len(value) != (33 if value[0] == BODY_DERIVED else 65):
                raise SpecError("Malformed")
            return {"source": value[0], "body_key": value[1:33], "handed_by": value[33:] or None}
        return kg.read_bundle(value)
    if table == T_OUTBOX:
        if len(value) != 32:
            raise SpecError("Malformed")
        return value
    if table == T_ACK:
        heads = uncbor(value)
        if not (_ascending(heads) and 1 <= len(heads) <= MAX_ACK_HEADS):
            raise SpecError("Malformed")
        return heads
    if table == T_LISTING:
        m = _map(value, {1, 2}, {1, 2})
        if not (is_bytes(m[1]) and is_uint(m[2])):
            raise SpecError("Malformed")
        return m
    if table == T_STATE:
        m = _map(value, {1, 2, 3, 4, 5, 6, 7, 8, 9}, set())
        if not m or (9 in m and (len(m) != 1 or not _erasing(m[9]))) or (1 in m and not (_ascending(m[1]) and 1 <= len(m[1]) <= MAX_BASE_HEADS)) \
                or (2 in m and not (isinstance(m[2], list) and all(is_bytes(x) for x in m[2]))) \
                or (4 in m and not (_ascending(m[4]) and 1 <= len(m[4]) <= MAX_LEFT_GRANTS)) \
                or (5 in m and m[5] != 1) \
                or (6 in m and not (is_bytes(m[6]) and len(m[6]) == 32)) \
                or (7 in m and not (is_bytes(m[7]) and len(m[7]) == 32)) \
                or (8 in m and not _expressed_again(m[8])):
            raise SpecError("Malformed")
        if 3 in m:
            _check_reading(m[3])
        return m
    if table == T_PSEUDONYM:
        m = _map(value, {1, 2, 3}, set())
        if not m or (2 in m) != (3 in m) or not all(is_bytes(x, 32) for x in m.values()):
            raise SpecError("Malformed")
        return m
    if table in (T_INVITE, T_CLAIM):
        if len(value) != 96 or value[:32] != log_id or value[32:64] != item:
            raise SpecError("Malformed")
        return {"space": value[:32], "invite_entry": value[32:64], "secret": value[64:]}
    if table == T_REPLAY:
        if len(value) != 24:
            raise SpecError("Malformed")
        return {"epoch": int.from_bytes(value[:8], "big"),
                "counter": int.from_bytes(value[8:16], "big"),
                "window": int.from_bytes(value[16:], "big")}
    if table == T_VOUCHED:
        if len(value) != 32:
            raise SpecError("Malformed")
        return {"person": value}
    if table == T_ENDPOINT:
        if not 1 <= len(value) <= MAX_ENDPOINT_VALUE:
            raise SpecError("Malformed")
        return value
    if table == T_HELD:
        m = _map(value, {1, 2, 3}, {1, 2, 3})
        if not (is_bytes(m[1]) and 1 <= len(m[1]) <= MAX_HELD_TOKEN
                and is_uint(m[2]) and m[2] <= MAX_OBJECT_SIZE
                and is_bytes(m[3]) and 1 <= len(m[3]) <= MAX_HELD_STAMP):
            raise SpecError("Malformed")
        return m
    if table == T_PEERS:
        m = _map(value, {1, 2}, set())
        if not m:
            raise SpecError("Malformed")
        def url(u) -> bool:
            return isinstance(u, str) and 1 <= len(u.encode()) <= MAX_PEER_URL
        if 1 in m and not (isinstance(m[1], list) and 1 <= len(m[1]) <= MAX_PEER_HINTS
                           and all(url(u) for u in m[1])):
            raise SpecError("Malformed")
        if 2 in m and not url(m[2]):
            raise SpecError("Malformed")
        return m
    if table == T_HOST:
        return value
    if table == T_DEPOSIT_KEYS:
        m = _map(value, {1, 2, 3, 4}, {1, 2})
        seen, latest = m[1], m[2]
        if not (isinstance(seen, list) and 1 <= len(seen) <= MAX_SEEN_KEYS
                and all(isinstance(e, list) and len(e) == 2 and is_bytes(e[0], 32)
                        and is_uint(e[1]) for e in seen)):
            raise SpecError("Malformed")
        if not (isinstance(latest, list) and 1 <= len(latest) <= 2
                and all(isinstance(e, list) and len(e) == 3 and is_bytes(e[0], 32)
                        and is_bytes(e[1], 32) and e[2] in (1, 2) for e in latest)
                and sum(1 for e in latest if e[2] == 1) == 1
                and len({bytes(e[0]) for e in latest}) == len(latest)):
            raise SpecError("Malformed")
        if 3 in m and m[3] != 1:
            raise SpecError("Malformed")
        if 4 in m:
            _check_reading(m[4])
        return m
    if table == T_TOKEN:
        if len(value) != TOKEN_BYTES or value[0] != 1 or value[33:65] != item[32:]:
            raise SpecError("Malformed")
        return value
    if table == T_DEPOSIT:
        m = _map(value, {1, 2, 3, 4, 5, 6, 7}, {1, 2, 3, 4, 5, 6})
        if not (isinstance(m[1], str) and 1 <= len(m[1].encode()) <= MAX_PEER_URL
                and is_bytes(m[2], 32)
                and is_bytes(m[3]) and 1 <= len(m[3]) <= MAX_MAILBOX_ITEM
                and is_uint(m[5]) and is_uint(m[6])
                and (7 not in m or is_bytes(m[7], TOKEN_BYTES))):
            raise SpecError("Malformed")
        _check_reading(m[4])
        return m
    raise SpecError("Malformed")


def held_value(token: bytes, size: int, stamp: bytes) -> bytes:
    """A `held` record's value (at-rest.md, "Tables")."""
    return cbor({1: token, 2: size, 3: stamp})


# ---------------------------------------------------------------------------
# Held objects (at-rest.md, "Held objects"): the object provider, a put in
# two passes, a serve that seals the chunks again, a receive that writes
# through the provider, and the records each commits.


class Provider:
    """A model of the application's object provider: files by token, each
    with a stamp, and the tokens it was told to forget. `create` names a
    received plaintext by the hint, or by the object ID, and stamps it with
    the first 16 bytes of its SHA-256."""

    def __init__(self):
        self.files: dict[bytes, tuple[bytes, bytes]] = {}
        self.forgotten: list[bytes] = []

    def put(self, token: bytes, data: bytes, stamp: bytes) -> None:
        self.files[token] = (data, stamp)

    def stat(self, token: bytes):
        file = self.files.get(token)
        return None if file is None else (len(file[0]), file[1])

    def read(self, token: bytes, offset: int, length: int) -> bytes:
        """`open(token)`, then one read at an offset."""
        return self.files[token][0][offset:offset + length]

    def create(self, space: bytes, oid: bytes, size: int, hint: bytes) -> "Writer":
        return Writer(self, hint or b"object/" + oid[:8].hex().encode())

    def forget(self, token: bytes) -> None:
        self.forgotten.append(token)


class Writer:
    """A provider's writer: takes the plaintext in order, then finishes
    with a token and a stamp, or aborts."""

    def __init__(self, provider: Provider, token: bytes):
        self.provider, self.token, self.data, self.done = provider, token, b"", None

    def write(self, data: bytes) -> None:
        self.data += data

    def finish(self) -> tuple[bytes, bytes]:
        stamp = sha256(self.data)[:16]
        self.provider.put(self.token, self.data, stamp)
        self.done = "finished"
        return self.token, stamp

    def abort(self) -> None:
        self.done = "aborted"


def seal_chunk(space: bytes, keys: dict, okey: bytes, oid: bytes, size: int, index: int,
               plain: bytes) -> dict:
    """`chunk_i` from `plain_i` alone (units.md, "Objects")."""
    aad = units.chunk_aad(space, oid, size, index)
    nonce = hmac256(keys["nonce_key"], aad + plain)[:units.NONCE_BYTES]
    return {"index": index, "aad": aad, "nonce": nonce,
            "sealed": nonce + xchacha20poly1305_seal(okey, nonce, plain, aad)}


def _plain_length(size: int, chunk: int, index: int) -> int:
    return min(chunk, size - index * chunk) if size else 0


def held_records(oid: bytes, header: bytes, token: bytes, size: int, stamp: bytes) -> list:
    """The two records a held object has: its part 0, and its `held`
    record."""
    return [(T_OBJECT, oid + u32be(0), header), (T_HELD, oid, held_value(token, size, stamp))]


def put_held(space: bytes, content_key: bytes, key_ref: bytes, provider: Provider,
             token: bytes, chunk: int = units.CHUNK_BYTES) -> dict:
    """at-rest.md, "Held objects", putting, in order: two passes over the
    plaintext, then one commit."""
    # 1. The size and the stamp.
    stat = provider.stat(token)
    if stat is None:
        raise SpecError("Changed")
    size, stamp = stat
    keys = units.object_keys(content_key)
    # 2. Pass one: the object ID over the whole plaintext.
    plaintext = provider.read(token, 0, size)
    if len(plaintext) != size:
        raise SpecError("Changed")
    oid = hmac256(keys["id_key"], plaintext)
    okey = units.object_key(content_key, oid)
    # 3. Pass two: each chunk sealed and hashed into the digest.
    header = units.object_header(oid, key_ref, size)
    digest = hashlib.sha256(u32be(len(header)) + header)
    chunks = []
    for i in range(units.chunk_count(size, chunk)):
        plain = provider.read(token, i * chunk, _plain_length(size, chunk, i))
        if len(plain) != _plain_length(size, chunk, i):
            raise SpecError("Changed")
        sealed = seal_chunk(space, keys, okey, oid, size, i, plain)
        digest.update(sealed["sealed"])
        chunks.append(sealed)
    locator = oid + digest.digest()
    # 4. The stamp again.
    if provider.stat(token) != (size, stamp):
        raise SpecError("Changed")
    # 5. One commit.
    return {"id": oid, "header": header, "chunks": chunks, "locator": locator,
            "records": held_records(oid, header, token, size, stamp)}


def serve_held(space: bytes, content_key: bytes, record: dict, locator: bytes,
               provider: Provider, first: int, count: int,
               chunk: int = units.CHUNK_BYTES) -> dict:
    """at-rest.md, "Held objects", serving, in order: the chunks `first` to
    `first + count - 1` sealed again from the plaintext, or "not held"."""
    oid, token, size, stamp = record["id"], record["token"], record["size"], record["stamp"]
    # 1. The size and the stamp are the record's.
    if provider.stat(token) != (size, stamp):
        return {"outcome": "not held", "step": 1}
    keys = units.object_keys(content_key)
    okey = units.object_key(content_key, oid)
    n = units.chunk_count(size, chunk)
    last = min(first + count, n)
    whole = first == 0 and last == n
    chunks, plaintext = [], hashlib.sha256()
    read_id = hmac.new(keys["id_key"], b"", hashlib.sha256)
    header = units.object_header(oid, record["key_ref"], size)
    digest = hashlib.sha256(u32be(len(header)) + header)
    # 2. Each chunk asked for.
    for i in range(first, last):
        plain = provider.read(token, i * chunk, _plain_length(size, chunk, i))
        if len(plain) != _plain_length(size, chunk, i):
            return {"outcome": "not held", "step": 2}
        sealed = seal_chunk(space, keys, okey, oid, size, i, plain)
        read_id.update(plain)
        digest.update(sealed["sealed"])
        chunks.append(sealed)
    # 3. A serve from chunk 0 to the end checks the ID and the digest.
    if whole and (read_id.digest() != oid or digest.digest() != locator[32:]):
        return {"outcome": "not held", "step": 3}
    return {"outcome": "held", "chunks": chunks}


def receive_held(space: bytes, content_key: bytes | None, okey: bytes | None, locator: bytes,
                 header: bytes, chunks: list, provider: Provider, hint: bytes = b"",
                 chunk: int = units.CHUNK_BYTES) -> dict:
    """at-rest.md, "Held objects", receiving, in order: the chunks, in
    order, written through the provider as they open, then the checks of
    the whole, then one commit. With `k(S)` the object ID is checked; with
    the object key alone, only the digest."""
    oid = locator[:32]
    hd = uncbor(header)
    size = hd[4]
    if content_key is not None:
        okey = units.object_key(content_key, oid)
    # 1. A writer, once the header is held.
    writer = provider.create(space, oid, size, hint)
    digest = hashlib.sha256(u32be(len(header)) + header)
    written = hmac.new(units.object_keys(content_key)["id_key"], b"", hashlib.sha256) \
        if content_key is not None else None
    try:
        # 2. Each chunk, in order, opened and written through.
        for i, sealed in enumerate(chunks):
            try:
                plain = xchacha20poly1305_open(okey, sealed[:units.NONCE_BYTES],
                                               sealed[units.NONCE_BYTES:],
                                               units.chunk_aad(space, oid, size, i))
            except Exception:
                raise SpecError("Decrypt")
            writer.write(plain)
            digest.update(sealed)
            if written is not None:
                written.update(plain)
        # 3. The whole: the digest, and with k(S) the object ID.
        if digest.digest() != locator[32:]:
            raise SpecError("ObjectMismatch")
        if written is not None and written.digest() != oid:
            raise SpecError("ObjectMismatch")
    except SpecError:
        writer.abort()
        raise
    # 4. The token and the stamp, and one commit.
    token, stamp = writer.finish()
    return {"token": token, "stamp": stamp, "plaintext": writer.data,
            "records": held_records(oid, header, token, size, stamp)}


def open_record(store_secret: bytes, log_key: bytes | None, addr: bytes, record: bytes,
                log_id: bytes | None) -> dict:
    """at-rest.md, "Opening a record", in order. `log_id` and `log_key` are
    the caller's: None for a device-wide table."""
    if len(addr) != ADDRESS_BYTES or addr[TAG_BYTES] not in TABLES:
        raise SpecError("Malformed")
    table = addr[TAG_BYTES]
    scope = TABLES[table][1]
    if (scope == DEVICE) != (log_id is None) or addr[:TAG_BYTES] != scope_tag(store_secret,
                                                                             log_id):
        raise SpecError("Malformed")
    if not record:
        raise SpecError("Malformed")
    if record[0] != VERSION:
        raise SpecError("UnsupportedVersion")
    if len(record) < MIN_RECORD:
        raise SpecError("Malformed")
    scope_key = store_secret if scope == DEVICE else log_key
    plaintext = xchacha20poly1305_open(seal_key(scope_key), record[1:25], record[25:],
                                       record_aad(addr))
    n = int.from_bytes(plaintext[:4], "big")
    item = plaintext[4:4 + n]
    if len(plaintext) < 4 or len(item) != n or not item_ok(table, item) \
            or item_tag(scope_key, table, item) != addr[TAG_BYTES + 1:]:
        raise SpecError("Malformed")
    return {"table": TABLES[table][0], "item": item,
            "value": read_value(table, item, plaintext[4 + n:], log_id)}


# ---------------------------------------------------------------------------
# The mark and continuity (at-rest.md, "The mark" and "Continuity").

MARK_BYTES = 1 + 24 + 16 + 8 + 16                                      # 65
MODE_DEVICE_BOUND, MODE_NEVER_RESTORED, MODE_NONE = "device-bound", "never-restored", "none"


def mark_aad(device_id: bytes) -> bytes:
    return MARK_LABEL + bytes([VERSION]) + device_id


def seal_mark(store_secret: bytes, device_id: bytes, store_id: bytes, generation: int,
              nonce: bytes) -> bytes:
    return bytes([VERSION]) + nonce + xchacha20poly1305_seal(
        seal_key(store_secret), nonce, store_id + generation.to_bytes(8, "big"),
        mark_aad(device_id))


def open_mark(store_secret: bytes, device_id: bytes, mark: bytes) -> tuple[bytes, int]:
    if not mark:
        raise SpecError("Malformed")
    if mark[0] != VERSION:
        raise SpecError("UnsupportedVersion")
    if len(mark) != MARK_BYTES:
        raise SpecError("Malformed")
    plain = xchacha20poly1305_open(seal_key(store_secret), mark[1:25], mark[25:],
                                   mark_aad(device_id))
    return plain[:16], int.from_bytes(plain[16:], "big")


def continuity(mode: str, head: dict | None, mark: bytes | None, store_secret: bytes,
               device_id: bytes) -> str:
    """at-rest.md, continuity, in order: Current or Restored."""
    if head is None:
        return "Restored"
    if mode == MODE_NEVER_RESTORED:
        return "Current"
    if mode != MODE_DEVICE_BOUND or mark is None:
        return "Restored"
    try:
        store_id, generation = open_mark(store_secret, device_id, mark)
    except SpecError:
        return "Restored"
    return "Current" if (store_id, generation) == (head[1], head[2]) else "Restored"


def may_sign(head: dict, log_id: bytes) -> bool:
    """at-rest.md, "After a restore": only in a log synced since."""
    return 4 not in head or log_id in head[5]


def head_value(store_id: bytes, generation: int, tips, restored: int | None = None,
               confirmed=()) -> bytes:
    m = {1: store_id, 2: generation,
         3: [list(t) for t in sorted(tips, key=lambda t: t[0] + t[1])], 6: REVISION}
    if restored is not None:
        m[4], m[5] = restored, sorted(confirmed)
    return cbor(m)


def check_head_revision(head: dict) -> str:
    """at-rest.md, "Continuity": before `continuity`, a head without key 6
    or of another revision refuses the store."""
    return "Opens" if head.get(6) == REVISION else "RevisionMismatch"


# ---------------------------------------------------------------------------
# Vectors.


def _expect(function, *args, **kwargs) -> str:
    try:
        function(*args, **kwargs)
    except SpecError as error:
        return str(error)
    return "accepted"


def _flip(data: bytes, i: int) -> bytes:
    return data[:i] + bytes([data[i] ^ 1]) + data[i + 1:]


PRF_OUTPUT_LABEL = "identity/passkey-1/prf-output"


def _persons() -> dict:
    """identity.json's two persons: the first events of their lists."""
    alice = identity.Person("laptop", prefix="identity/alice")
    bob = identity.Person("laptop", prefix="identity/bob")
    return {"alice": alice.id, "bob": bob.id}


def _keys_json(keys: dict) -> dict:
    return {n: h(keys[n]) for n in SEEDS}


def _sealed_device_keys(persons: dict) -> tuple[list, list]:
    """The families `sealed_device_keys` and `sealed_device_keys_refusals`."""
    alice, bob = persons["alice"], persons["bob"]
    browser, desktop, sensor = (fixture_keys(n) for n in ("browser", "desktop", "sensor"))
    output = example(PRF_OUTPUT_LABEL)
    unlock = passkey_unlock_key(alice, output)
    unlock_bob = passkey_unlock_key(bob, output)
    external = example("unlock-key")
    by_passkey = seal_device_keys(KIND_PASSKEY_UNLOCK, unlock, alice, browser,
                                  example("at-rest/nonce/device-keys/1")[:24])
    by_key = seal_device_keys(KIND_UNLOCK_KEY, external, alice, desktop,
                              example("at-rest/nonce/device-keys/2")[:24])
    member = seal_device_keys(KIND_UNLOCK_KEY, external, ZERO_PERSON, sensor,
                              example("at-rest/nonce/device-keys/3")[:24])
    cases = []
    for name, sealed, keys, kind, key, person, extra in [
        ("a browser, kind 1, under its passkey's unlock key", by_passkey, browser,
         KIND_PASSKEY_UNLOCK, unlock, alice,
         {"prf_output": h(output),
          "note": "the unlock key of identity.json's first passkey: alice's person ID and "
                  "that passkey's PRF output"}),
        ("a desktop, kind 2, under an unlock key from the platform's keychain", by_key, desktop,
         KIND_UNLOCK_KEY, external, alice,
         {"note": "32 bytes from another source; the sealing key is derived from them"}),
        ("a device member, kind 2, with a zero person ID", member, sensor, KIND_UNLOCK_KEY,
         external, ZERO_PERSON, {"note": "the person ID field is 32 zero bytes"}),
    ]:
        opened = open_device_keys(sealed["blob"], kind, key, person, keys_device_id(keys))
        assert opened == keys
        pub = public_keys(keys)
        cases.append({
            "name": name, **extra, "key_kind": kind, "key": h(key),
            "sealing_key": h(sealed["sealing_key"]), "person_id": h(person),
            "identity": h(pub["identity"]), "kc": h(pub["kc"]), "device_id": h(pub["device_id"]),
            "keys": _keys_json(keys), "plaintext": h(sealed["plaintext"]),
            "header": h(sealed["header"]), "aad": h(sealed["aad"]),
            "nonce": h(sealed["nonce"]), "sealed": h(sealed["blob"]),
        })

    def refuse(name, blob, kind, key, reason, person=alice, dev=None):
        return {"name": name, "sealed": h(blob), "key_kind": kind, "key": h(key),
                "expected_person": None if person is None else h(person),
                "expected_device": None if dev is None else h(dev),
                "error": _expect(open_device_keys, blob, kind, key, person, dev),
                "reason": reason}

    blob = by_key["blob"]
    header = by_key["header"]
    key2 = device_sealing_key(KIND_UNLOCK_KEY, external)
    n4 = example("at-rest/nonce/device-keys/4")[:24]
    n5 = example("at-rest/nonce/device-keys/5")[:24]
    forged = header + n4 + xchacha20poly1305_seal(key2, n4, device_keys_plaintext(browser),
                                                  SEALED_DEVICE_KEYS + header)
    # The desktop's identity seed beside another device's ML-DSA-65 seed:
    # the Ed25519 key is the desktop's, the device ID another.
    n6 = example("at-rest/nonce/device-keys/6")[:24]
    mixed = header + n6 + xchacha20poly1305_seal(
        key2, n6, device_keys_plaintext({**desktop, "mldsa_seed": browser["mldsa_seed"]}),
        SEALED_DEVICE_KEYS + header)
    later = header + n5 + xchacha20poly1305_seal(
        key2, n5, b"\x02" + device_keys_plaintext(desktop)[1:], SEALED_DEVICE_KEYS + header)
    direct = header + n5 + xchacha20poly1305_seal(external, n5, by_key["plaintext"],
                                                  SEALED_DEVICE_KEYS + header)
    pk_zero = by_passkey["blob"][:34] + ZERO_PERSON + by_passkey["blob"][66:]
    refusals = [
        refuse("another unlock key", blob, KIND_UNLOCK_KEY, example("other-unlock-key"),
               "the AEAD fails"),
        refuse("sealed directly under a kind 2 key, not the key derived from it", direct,
               KIND_UNLOCK_KEY, external, "a kind 2 unlock key is never used as it is"),
        refuse("the unlock key the same passkey derives for another person", by_passkey["blob"],
               KIND_PASSKEY_UNLOCK, unlock_bob, "the unlock key binds the person ID"),
        refuse("a changed ciphertext byte", _flip(blob, len(blob) - 20), KIND_UNLOCK_KEY,
               external, "the AEAD fails"),
        refuse("a changed device ID in the header", _flip(blob, 5), KIND_UNLOCK_KEY, external,
               "the header is associated data"),
        refuse("a changed person ID in the header, not checked by the caller", _flip(blob, 40),
               KIND_UNLOCK_KEY, external, "only the AEAD catches it: the header is associated "
               "data", person=None),
        refuse("another person than the one expected", blob, KIND_UNLOCK_KEY, external,
               "the caller named another person", person=bob),
        refuse("a device member's keys opened as a person's", member["blob"], KIND_UNLOCK_KEY,
               external, "the person ID is zero; the caller named alice"),
        refuse("another device than the one expected", blob, KIND_UNLOCK_KEY, external,
               "the caller named another device",
               dev=keys_device_id(browser)),
        refuse("kind 1 keys opened as kind 2", by_passkey["blob"], KIND_UNLOCK_KEY, external,
               "the key kind differs"),
        refuse("the kind byte changed", bytes([1, 1]) + blob[2:], KIND_PASSKEY_UNLOCK, external,
               "the header is associated data"),
        refuse("kind 1 with a zero person ID", pk_zero, KIND_PASSKEY_UNLOCK, unlock,
               "a passkey belongs to a person", person=ZERO_PERSON),
        refuse("an unknown version", bytes([2]) + blob[1:], KIND_UNLOCK_KEY, external,
               "a reader never guesses at a version it does not know"),
        refuse("an unknown key kind", bytes([1, 9]) + blob[2:], KIND_UNLOCK_KEY, external,
               "kinds 1 and 2 only"),
        refuse("one byte short", blob[:-1], KIND_UNLOCK_KEY, external,
               f"sealed device keys are exactly {SEALED_DEVICE_KEYS_BYTES} bytes"),
        refuse("one byte long", blob + b"\x00", KIND_UNLOCK_KEY, external,
               f"sealed device keys are exactly {SEALED_DEVICE_KEYS_BYTES} bytes"),
        refuse("keys that do not match the device ID", forged, KIND_UNLOCK_KEY, external,
               "the three seeds must give the header's device ID"),
        refuse("the device's identity seed with another ML-DSA-65 seed", mixed,
               KIND_UNLOCK_KEY, external,
               "the Ed25519 key matches, but the keys' kc and so the device ID do not"),
        refuse("an unknown layout of the keys inside", later, KIND_UNLOCK_KEY, external,
               "the plaintext's layout version is 1"),
    ]
    return cases, refusals


class _Store:
    """One device's store in the vectors: the store secret, its log keys, and
    the fixed nonces the vectors use."""

    def __init__(self, name: str, store_secret: bytes):
        self.name, self.s = name, store_secret
        self.log_keys: dict[bytes, bytes] = {}

    def key_for(self, log_id):
        return self.s if log_id is None else self.log_keys[log_id]

    def seal(self, table: int, item: bytes, value: bytes, log_id=None, label: str = "") -> dict:
        k = self.key_for(log_id)
        addr = address(self.s, k, table, item, log_id)
        nonce = example(f"at-rest/{self.name}/nonce/{label or TABLES[table][0]}")[:24]
        return {"address": addr, **seal_record(k, addr, item, value, nonce)}

    def open(self, addr: bytes, record: bytes, log_id=None) -> dict:
        return open_record(self.s, None if log_id is None else self.log_keys.get(log_id), addr,
                           record, log_id)


def _make_reading(t: int, run: int, w: int | None = None) -> dict:
    r = {1: t, 2: run}
    if w is not None:
        r[3] = w
    return r


def _plain(value):
    """A decoded value as the JSON shows it: bytes in hex, keys as text."""
    if isinstance(value, bytes):
        return h(value)
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_plain(v) for v in value]
    return value


def at_rest_vectors(persons: dict | None = None) -> dict:
    """at-rest.json: the families of at-rest.md, "Test vectors"."""
    persons = persons or _persons()
    alice = persons["alice"]
    keys = fixture_keys("browser")
    s = keys["store_secret"]
    signer = ev.signer_for(keys["identity_seed"], "browser")
    device_id = signer.device_id
    assert device_id == keys_device_id(keys)
    store = _Store("browser", s)
    store_id = example("at-rest/browser/store-id")[:16]

    space = example("at-rest/space")                      # a space's ID: its genesis's ID
    store.log_keys[space] = example("at-rest/browser/log-key/space")
    store.log_keys[alice] = example("at-rest/browser/log-key/alice")
    L = store.log_keys[space]

    derivations = {
        "store_secret": h(s),
        "seal_key(store secret)": h(seal_key(s)),
        "tag_key(store secret)": h(tag_key(s)),
        "space": h(space),
        "log_key(space)": h(L),
        "seal_key(log key)": h(seal_key(L)),
        "tag_key(log key)": h(tag_key(L)),
        "scope_tag(space)": h(scope_tag(s, space)),
        "scope_tag(alice's list)": h(scope_tag(s, alice)),
        "app_key(log key, \"com.example.index\")": h(app_key(L, b"com.example.index")),
        "app_key(store secret, \"com.example.settings\")": h(app_key(s, b"com.example.settings")),
    }

    sealed_cases, sealed_refusals = _sealed_device_keys(persons)

    # A unit the browser signs in the space at seq 1, and an object.
    content_key = example("at-rest/space/content-key")
    rotation = example("at-rest/space/rotation")
    key_ref = kg.encode_set([rotation])
    stream = example("at-rest/stream")[:16]
    obj = units.seal_object(space, content_key, key_ref, b"an attachment at rest", chunk=16)
    inner = units.encode_inner(units.TYPE_RECORDS, b"a record")
    unit = units.make_unit(signer, space, 1, None, [space], stream, key_ref, content_key, inner,
                           example("at-rest/unit-nonce")[:24])
    unit_id = unit["id"]
    reading = _make_reading(86400, 3, 1792800000)
    unit_value = cbor({1: unit["signed"], 2: S_VALID, 3: F_VERIFIED, 5: reading})

    rows = []

    def add(name: str, table: int, item: bytes, value: bytes, log_id=None, label: str = "",
            note: str = "") -> dict:
        sealed = store.seal(table, item, value, log_id, label)
        opened = store.open(sealed["address"], sealed["record"], log_id)
        rows.append({
            "name": name, "table": table, "table_name": TABLES[table][0],
            "log": None if log_id is None else h(log_id),
            "item": h(item), "value": h(value), "opened": _plain(opened["value"]),
            "address": h(sealed["address"]), "plaintext": h(sealed["plaintext"]),
            "aad": h(sealed["aad"]), "nonce": h(sealed["nonce"]),
            "record": h(sealed["record"]), **({"note": note} if note else {}),
        })
        return sealed

    tips = [(space, device_id, 1, unit_id)]
    head = add("the head: generation 2, one tip", T_HEAD, b"", head_value(store_id, 2, tips))
    add("the space's log key", T_LOG, space, bytes([LOG_SPACE]) + L, label="log/space")
    add("alice's list's log key", T_LOG, alice, bytes([LOG_LIST]) + store.log_keys[alice],
        label="log/alice")
    add("the timeline's last reading", T_TIMELINE, b"", cbor(reading))
    add("the ephemeral epoch", T_EPOCH, b"", (7).to_bytes(8, "big"),
        note="ext-ephemeral.md's epoch")
    add("the seed of the announced next member endpoint key", T_NEXT_ENDPOINT, b"",
        example("at-rest/next-endpoint"), note="ext-next-endpoints.md's next seed")
    deposit_peer = example("at-rest/deposit-peer")
    first_key, second_key = example("at-rest/deposit-key/1"), example("at-rest/deposit-key/2")
    add("a peer's deposit keys: two issuing keys seen, the latest list, a pause",
        T_DEPOSIT_KEYS, deposit_peer,
        cbor({1: [[first_key, 86400], [second_key, 691200]],
              2: [[second_key, example("at-rest/deposit-public/2"), 1],
                  [first_key, example("at-rest/deposit-public/1"), 2]],
              4: reading}),
        note="ext-deposit-tokens.md, 3.2 and 3.11: the item is the peer's ID")
    token_nonce = example("at-rest/token-nonce")
    add("an unspent deposit token", T_TOKEN, deposit_peer + token_nonce,
        bytes([1]) + second_key + token_nonce + example("at-rest/token-mac") * 2,
        note="ext-deposit-tokens.md, 3.5: the item is the peer's ID and the token's nonce")
    add("a deposit refused busy, kept to deposit again, paid with a token", T_DEPOSIT,
        example("at-rest/deposit-id")[:16],
        cbor({1: "https://peer.example", 2: example("at-rest/deposit-address"),
              3: b"a sealed welcome", 4: reading, 5: 1, 6: 86460,
              7: bytes([1]) + second_key + token_nonce + example("at-rest/token-mac") * 2}),
        note="transport.md, \"A sender keeps what was refused\"")
    unit_rec = add("the browser's unit: valid, signature verified", T_EVENT, unit_id,
                   unit_value, space)
    add("the object's header", T_OBJECT, obj["id"] + (0).to_bytes(4, "big"), obj["header"],
        space, label="object/0")
    add("the object's first chunk", T_OBJECT, obj["id"] + (1).to_bytes(4, "big"),
        obj["chunks"][0]["sealed"], space, label="object/1")
    add("a rotation's secrets: content key and upload seed", T_KEY,
        bytes([K_ROTATION]) + rotation,
        kg.make_bundle(content_key, example("at-rest/space/upload-seed")), space,
        label="key/rotation")
    merged = sorted([rotation, example("at-rest/space/rotation-2")])
    add("a merged state's key received whole: provisional", T_KEY,
        bytes([K_STATE]) + kg.encode_set(merged),
        kg.make_bundle(example("at-rest/space/merged-key")), space, label="key/state")
    add("a body key handed in a unit", T_KEY, bytes([K_BODY]) + example("at-rest/space/event"),
        bytes([BODY_HANDED]) + example("at-rest/space/body-key") + unit_id, space,
        label="key/body")
    add("a gap key", T_KEY, bytes([K_GAP, 1]) + kg.encode_set([example("at-rest/space/gap")]),
        kg.make_bundle(example("at-rest/space/gap-key")), space, label="key/gap")
    add("the unit in the outbox, not yet durable", T_OUTBOX,
        device_id + (1).to_bytes(8, "big"), unit_id, space)
    peer = example("at-rest/peer")
    add("a peer's acknowledged heads", T_ACK, peer, cbor([unit_id]), space)
    add("a peer's listing, cached", T_LISTING, peer,
        cbor({1: b"the listing as the peer served it", 2: 86400}), space)
    add("the log's state: the last completed sync", T_STATE, b"", cbor({3: reading}), space)
    add("the log's state: a leave request sent, with the grants it named", T_STATE, b"",
        cbor({3: reading, 4: [example("at-rest/space/event")]}), space, label="state/left",
        note="ext-guests.md: Left outlasts a restart")
    add("the log's state: the person's personal space", T_STATE, b"", cbor({5: 1}), space,
        label="state/personal", note="identity.md: the personal space, known after a restart")
    add("the log's state: a claim begun, not signed", T_STATE, b"",
        cbor({6: example("at-rest/space/invite-entry")}), space, label="state/claiming",
        note="ext-invite-links.md: a log that names a claim with no claim record is forgotten "
             "at load")
    attribution = [[0, device_id, "Carol's laptop"], [1, example("at-rest/frozen/person"),
                                                       "Carol"]]
    add("a unit of a forgotten past, its verdict and its author's capabilities frozen",
        T_EVENT, unit_id, cbor({1: unit["signed"], 2: S_VALID, 3: F_VERIFIED,
                                6: [["comment", 0], ["comment", 1], ["suggest", 1]],
                                7: attribution}), space,
        label="event/frozen",
        note="units.md, \"The past of a kept checkpoint\": the capabilities its author held "
             "at its place, which its adapter reads, never those of a later place; its "
             "attribution there, the device and the person it wrote through with their labels "
             "at that place, which its history shows, never the current labels")
    add("a unit of a forgotten past whose content its adapter refused, still attributed",
        T_EVENT, unit_id, cbor({1: unit["signed"], 2: S_REFUSED, 3: F_VERIFIED,
                                4: "LoroOverlap", 6: [],
                                7: [[1, example("at-rest/frozen/person")]]}), space,
        label="event/frozen-refused",
        note="roster.md, section 3.11: a unit the write rule admits is attributed whatever its "
             "adapter made of its content; here a member with no label at its place")
    add("a unit of a forgotten past that the write rule voids, with what voids it",
        T_EVENT, unit_id, cbor({1: unit["signed"], 2: S_REFUSED, 3: F_VERIFIED,
                                4: "NotAWriter", 6: [],
                                8: [example("at-rest/frozen/voider")]}), space,
        label="event/frozen-void",
        note="roster.md, section 3.14: attributed to no member; the events that void it, "
             "which are some, so its author re-submits it once it writes again")
    add("an event kept alone, never judged", T_EVENT, unit_id,
        cbor({1: unit["signed"], 2: S_ALONE, 3: F_VERIFIED}), space, label="event/alone",
        note="state 6: an event a log that forgot keeps without judging it, such as a "
             "list's first event or an add its kept record names (identity.md)")
    kept = example("at-rest/space/kept-checkpoint")
    s1, s2 = example("at-rest/stream/one")[:16], example("at-rest/stream/two")[:16]
    s1, s2 = min(s1, s2), max(s1, s2)
    add("the log's state: the incarnations this device expressed again", T_STATE, b"",
        cbor({3: reading, 8: [[s1, 3], [s1, 7], [s2, 2]]}), space, label="state/expressed",
        note="units.md, \"Re-submission\": each a Loro incarnation of this device's own whose "
             "refused units it does not re-submit, having written their text again")
    admins = sorted([[example(f"at-rest/erasing/{n}/device"),
                      xwing.xwing_public_key(example(f"at-rest/erasing/{n}/xwing"))]
                     for n in ("one", "two")])
    add("the log's state in the residue of the device's own erasure", T_STATE, b"",
        cbor({9: admins}), space, label="state/erasing",
        note="peers.md, \"A device's own erasure\": the administering devices of its view at "
             "the drop, to which it sends a welcome request when a peer answers that the "
             "erasure is late")
    add("the log's state: the kept checkpoint of a log that forgot", T_STATE, b"",
        cbor({3: reading, 7: kept}), space, label="state/kept",
        note="roster.md, section 3.15.6: the event ID of the kept checkpoint")
    add("a dropped space event, held and forgotten", T_DROPPED,
        example("at-rest/space/dropped"), cbor({1: D_HELD, 2: 1}), space,
        label="dropped/held",
        note="roster.md, section 3.15.6: the ID of an event it dropped, and its kind")
    add("a dropped space event that a kept event cites, with its height", T_DROPPED,
        example("at-rest/space/dropped-parent"), cbor({1: D_HELD, 2: 1, 3: 41}), space,
        label="dropped/height",
        note="events.md, \"Placement and order\": the height of a dropped parent of an event "
             "the log keeps of its kept checkpoint's past, so that the kept event is placed at "
             "the height it was judged at; author and seq are not kept")
    add("a parent a peer answered Missing for, at a newcomer", T_DROPPED,
        example("at-rest/space/missing"), cbor({1: D_MISSING}), space, label="dropped/missing",
        note="roster.md, \"Starting from a checkpoint\": counted as dropped")
    add("a checkpoint's record object key, handed by a snapshot", T_KEY,
        bytes([K_RECORD]) + kept, bytes([BODY_HANDED]) + example("at-rest/space/record-key"),
        space, label="key/record",
        note="units.md, \"The space snapshot\": the key a newcomer reads the record with")
    add("an administrator pseudonym, enrolled", T_PSEUDONYM,
        slot_reference(example("at-rest/slot-c"), 0, example("at-rest/slot-maker")),
        cbor({2: example("at-rest/pseudonym/ed25519"), 3: example("at-rest/pseudonym/mldsa")}),
        space, note="the item is peers.md's slot reference [c, index, maker]")
    entry = example("at-rest/invite-entry")
    secret = example("at-rest/invite-secret")
    add("an invite this device made", T_INVITE, entry, space + entry + secret, space,
        note="ext-invite-links.md: space ID || invite entry || secret")
    claim = add("a link this device claimed", T_CLAIM, entry, space + entry + secret, space,
                note="kept until a peer or member holds the successor")
    add("a sender's replay window", T_REPLAY, example("at-rest/sender"),
        (5).to_bytes(8, "big") + (40).to_bytes(8, "big") + (0xFF).to_bytes(8, "big"), space,
        note="ext-ephemeral.md's replay window")
    add("a list member this device vouches for in the space", T_VOUCHED,
        example("at-rest/vouched"), example("at-rest/vouched/person"), space,
        note="ext-recovery-agent.md: the item is the list member's device ID, "
             "the value its person ID")
    add("where this device last reached a member", T_ENDPOINT, example("at-rest/sender"),
        cbor({1: 1, 2: 1, 3: device("at-rest/endpoint").identity,
              5: [bytes([127, 0, 0, 1]) + (47768).to_bytes(2, "big")]}), space,
        note="transport.md, \"Reconnecting\": the item is the member's device ID, "
             "the value a member ticket's CBOR, which the device reads when it dials")
    add("the next key a member announced", T_ANNOUNCED, example("at-rest/sender"),
        ed25519_public(example("at-rest/announced")), space,
        note="ext-next-endpoints.md: the item is the member's device ID, the value the "
             "next member endpoint key it announced")
    add("the space's peers and its home peer", T_PEERS, b"",
        cbor({1: ["https://peer.example", "https://other.example"],
              2: "https://home.example"}), space,
        note="admission.md, \"The welcome\": the hints a welcome named or a peer granted; "
             "ext-libraries.md: the home peer the issuer returned")
    add("a hosted space's record", T_HOST, b"peer/entries", b"the peer role's own bytes",
        space)

    # Refusals (at-rest.md, "Opening a record").
    addr_u, rec_u = unit_rec["address"], unit_rec["record"]
    addr_h = head["address"]
    other_log = example("at-rest/other-space")
    bad_value = store.seal(T_EVENT, unit_id, b"\x00", space, "bad-value")
    lying = seal_record(L, addr_u, example("at-rest/other-event"), unit_value,
                        example("at-rest/browser/nonce/lying")[:24])
    wrong_space = seal_record(L, claim["address"], entry, other_log + entry + secret,
                              example("at-rest/browser/nonce/wrong-space")[:24])
    head_under_log = seal_record(L, addr_h, b"", head_value(store_id, 2, tips),
                                 example("at-rest/browser/nonce/head-under-log")[:24])
    record_refusals = []

    def refuse(name, addr, record, log_id, reason, log_key=None):
        k = store.log_keys.get(log_id) if log_key is None and log_id is not None else log_key
        record_refusals.append({"name": name, "address": h(addr), "record": h(record),
                                "log": None if log_id is None else h(log_id),
                                "log_key": None if k is None else h(k),
                                "error": _expect(open_record, s, k, addr, record, log_id),
                                "reason": reason})

    refuse("moved to another event's address",
           address(s, L, T_EVENT, example("at-rest/other-event"), space), rec_u, space,
           "the address is associated data")
    refuse("opened under another log's key", addr_u, rec_u, space,
           "each log's records are sealed under its own key",
           log_key=example("at-rest/other-log-key"))
    refuse("a log's record opened under another log's scope", addr_u, rec_u, other_log,
           "the scope tag names the log")
    refuse("a log's table under the device-wide scope", DEVICE_SCOPE + addr_u[16:], rec_u, None,
           "event records belong to a log")
    refuse("an unknown table", addr_u[:16] + b"\x7f" + addr_u[17:], rec_u, space,
           "only the tables of at-rest.md")
    refuse("a changed ciphertext byte", addr_u, _flip(rec_u, len(rec_u) - 3), space,
           "the AEAD fails")
    refuse("an unknown version", addr_u, b"\x02" + rec_u[1:], space,
           "a reader never guesses at a version it does not know")
    refuse("shorter than any record", addr_u, rec_u[:MIN_RECORD - 1], space,
           "41 bytes of overhead and a 4-byte item length")
    refuse("an item that is not the address's", addr_u, lying["record"], space,
           "the item's tag must equal the address's")
    refuse("an event record whose value does not parse", bad_value["address"],
           bad_value["record"], space, "each table's value parses exactly")
    for name, table, value, label, reason in (
            ("a state with no incarnation expressed again", T_STATE, cbor({8: []}),
             "expressed-empty", "key 8 is absent when there are none"),
            ("a state whose incarnations expressed again are out of order", T_STATE,
             cbor({8: [[bytes(15) + b"\x02", 1], [bytes(15) + b"\x01", 1]]}),
             "expressed-unordered", "key 8 is strictly ascending by stream then incarnation"),
            ("a frozen unit with both an attribution and voiding events", T_EVENT,
             cbor({1: unit["signed"], 2: S_REFUSED, 3: F_VERIFIED, 4: "NotAWriter", 6: [],
                   7: [[1, example("at-rest/frozen/person")]],
                   8: [example("at-rest/frozen/voider")]}),
             "attribution-and-voiders", "key 7 is for a unit the write rule admits, key 8 for "
             "one it voids"),
            ("a frozen attribution out of order", T_EVENT,
             cbor({1: unit["signed"], 2: S_VALID, 3: F_VERIFIED, 6: [],
                   7: [[1, example("at-rest/frozen/person")], [0, device_id]]}),
             "attribution-unordered", "key 7 is strictly ascending by type then ID"),
            ("a frozen attribution with an empty label", T_EVENT,
             cbor({1: unit["signed"], 2: S_VALID, 3: F_VERIFIED, 6: [],
                   7: [[0, device_id, ""]]}),
             "attribution-empty-label", "a label is 1 to 64 bytes of UTF-8"),
            ("an erasing state beside another key", T_STATE,
             cbor({3: {1: 1, 2: 1}, 9: admins}), "erasing-not-alone",
             "key 9 is a residue's, alone"),
            ("a dropped record of origin 2 with a height", T_DROPPED,
             cbor({1: D_MISSING, 3: 41}), "missing-height",
             "key 3 is a dropped parent's height, from 1, and only with origin 1"),
            ("a dropped record with height 0", T_DROPPED, cbor({1: D_HELD, 2: 1, 3: 0}),
             "height-0", "key 3 is a dropped parent's height, from 1, and only with origin 1")):
        item = b"" if table == T_STATE else unit_id if table == T_EVENT \
            else example(f"at-rest/space/dropped/{label}")
        bad = store.seal(table, item, value, space, f"refused/{label}")
        refuse(name, bad["address"], bad["record"], space, reason)
    refuse("a claim naming another space", claim["address"], wrong_space["record"], space,
           "the value's space ID is the log's")
    refuse("a device-wide record sealed under a log key", addr_h, head_under_log["record"],
           None, "device-wide records are sealed under the store secret's key")

    # The mark, and continuity.
    def mark(gen, sid=store_id, label=""):
        return seal_mark(s, device_id, sid, gen, example(f"at-rest/mark/{label or gen}")[:24])

    head2 = uncbor(head_value(store_id, 2, tips))
    m2, m3 = mark(2), mark(3)
    decisions = []
    for name, mode, hd, mk, note in [
        ("the head and the mark agree", MODE_DEVICE_BOUND, head2, m2, ""),
        ("a store restored from a backup at generation 2; the mark is at 3", MODE_DEVICE_BOUND,
         head2, m3, "the device signed after the backup"),
        ("a crash between writing the mark and committing", MODE_DEVICE_BOUND, head2, m3,
         "counted as a restore; it costs one sync"),
        ("the mark is another store's", MODE_DEVICE_BOUND, head2,
         mark(2, example("at-rest/other-store")[:16], "other"), ""),
        ("no mark in the device-bound slot", MODE_DEVICE_BOUND, head2, None, ""),
        ("a changed mark", MODE_DEVICE_BOUND, head2, _flip(m2, 30), "it does not open"),
        ("the store has no head", MODE_DEVICE_BOUND, None, m2,
         "the device keys exist, so the store was lost"),
        ("mode none", MODE_NONE, head2, None, "every start counts as a restore"),
        ("mode never-restored", MODE_NEVER_RESTORED, head2, None,
         "the application states that its store is never restored from a backup"),
    ]:
        decisions.append({"name": name, "mode": mode,
                          "head_generation": None if hd is None else hd[2],
                          "head_store_id": None if hd is None else h(hd[1]),
                          "mark": None if mk is None else h(mk),
                          "outcome": continuity(mode, hd, mk, s, device_id),
                          **({"note": note} if note else {})})

    # After a restore found with the head at 2 and the mark at 3: g = 4. The
    # head records it, and the device signs only in logs it has synced since.
    after_bytes = head_value(store_id, 4, tips, restored=4, confirmed=[space])
    restored_head = uncbor(after_bytes)
    after = {
        "head": h(after_bytes),
        "mark": h(mark(4)),
        "may_sign": {"the space, synced since": may_sign(restored_head, space),
                     "alice's list, not yet synced": may_sign(restored_head, alice)},
    }
    # A space the device originates after the restore: it writes its own
    # genesis and adds that log to key 5 in the genesis commit, so it may sign
    # there at once; a genesis learned from another party is not added and
    # still waits for a sync (section 3.6, step 2).
    originated = example("at-rest/originated-space")
    learned = example("at-rest/learned-space")
    originated_bytes = head_value(store_id, 4, tips, restored=4, confirmed=[space, originated])
    originated_head = uncbor(originated_bytes)
    after["originated"] = {
        "head": h(originated_bytes),
        "originated_log": h(originated),
        "learned_log": h(learned),
        "may_sign": {"an originated genesis, added in its commit":
                     may_sign(originated_head, originated),
                     "a learned genesis, not added": may_sign(originated_head, learned)},
    }
    revisions = []
    for name, change in [("this revision", lambda m: None),
                         ("no revision", lambda m: m.pop(6)),
                         ("another revision", lambda m: m.__setitem__(6, REVISION + 1))]:
        value = uncbor(head_value(store_id, 2, tips))
        change(value)
        revisions.append({"name": name, "head": h(cbor(value)),
                          "outcome": check_head_revision(value)})
    mark_cases = {
        "store_id": h(store_id), "generation": 2, "device_id": h(device_id),
        "plaintext": h(store_id + (2).to_bytes(8, "big")),
        "aad": h(mark_aad(device_id)), "nonce": h(m2[1:25]), "mark": h(m2),
        "refusals": [
            {"name": name, "device_id": h(dev), "mark": h(mk),
             "error": _expect(open_mark, s, dev, mk)}
            for name, dev, mk in [
                ("an unknown version", device_id, b"\x02" + m2[1:]),
                ("one byte short", device_id, m2[:-1]),
                ("another device's", example("at-rest/other-device"), m2),
                ("a changed byte", device_id, _flip(m2, 40)),
            ]],
    }

    held = _held_vectors(store, space)

    # From a passkey to a record: what the unlock key unlocks.
    output = example(PRF_OUTPUT_LABEL)
    unlock = passkey_unlock_key(alice, output)
    sealed_keys = seal_device_keys(KIND_PASSKEY_UNLOCK, unlock, alice, keys,
                                   example("at-rest/nonce/device-keys/1")[:24])
    opened = open_device_keys(sealed_keys["blob"], KIND_PASSKEY_UNLOCK, unlock, alice, device_id)
    chain = {
        "person_id": h(alice), "prf_output": h(output), "unlock_key": h(unlock),
        "sealed_device_keys": h(sealed_keys["blob"]),
        "store_secret": h(opened["store_secret"]),
        "head_address": h(addr_h), "head_record": h(head["record"]),
        "head_opened": _plain(open_record(opened["store_secret"], None, addr_h, head["record"],
                                          None)["value"]),
    }
    return {
        "construction": "at-rest",
        "version": 1,
        "specification": "at-rest.md",
        "device": {"name": "browser", "keys": _keys_json(keys),
                   **{k: h(v) for k, v in public_keys(keys).items()}},
        "derivations": derivations,
        "sealed_device_keys": sealed_cases,
        "sealed_device_keys_refusals": sealed_refusals,
        "records": rows,
        "record_refusals": record_refusals,
        "mark": mark_cases,
        "continuity": decisions,
        "after_restore": after,
        "head_revisions": revisions,
        "passkey_to_record": chain,
        "held": held,
    }


def _held_vectors(store: "_Store", space: bytes) -> dict:
    """The family `held`: the record, puts from units.json's object
    plaintexts, chunk 1 sealed alone, serves and receives."""
    s = store.s
    L = store.log_keys[space]
    # units.json's objects: its space, state and key reference, so that a
    # held put yields the same bytes.
    S = [units.ROT["A"]]
    key_ref = kg.encode_set(S)
    k = units.state_key(S)
    uspace = units.SPACE
    small = b"an attachment of one chunk"
    big = bytes(range(150))
    plaintexts = [("one chunk", small, units.CHUNK_BYTES, b"attachments/small.bin"),
                  ("three chunks, the chunk size lowered to 64", big, 64, b"attachments/big.bin"),
                  ("empty", b"", units.CHUNK_BYTES, b"attachments/empty.bin")]

    def chunks_json(chunks):
        return [{"index": c["index"], "aad": h(c["aad"]), "nonce": h(c["nonce"]),
                 "sealed": h(c["sealed"])} for c in chunks]

    def records_json(records):
        return [{"table": t, "table_name": TABLES[t][0], "item": h(i), "value": h(v)}
                for t, i, v in records]

    provider = Provider()
    puts, put = [], {}
    for name, plaintext, chunk, token in plaintexts:
        stamp = example(f"at-rest/held/stamp/{token.decode()}")[:16]
        provider.put(token, plaintext, stamp)
        put[name] = put_held(uspace, k, key_ref, provider, token, chunk)
        expected = units.seal_object(uspace, k, key_ref, plaintext, chunk)
        assert put[name]["id"] == expected["id"] and put[name]["header"] == expected["header"]
        assert [c["sealed"] for c in put[name]["chunks"]] == \
            [c["sealed"] for c in expected["chunks"]]
        assert put[name]["locator"] == expected["locator"]
        puts.append({"name": name, "chunk_bytes": chunk, "token": h(token), "stamp": h(stamp),
                     "size": len(plaintext), "plaintext": h(plaintext),
                     "pass_one": {"id": h(put[name]["id"])},
                     "pass_two": {"header": h(put[name]["header"]),
                                  "chunks": chunks_json(put[name]["chunks"]),
                                  "locator": h(put[name]["locator"])},
                     "commit": records_json(put[name]["records"]),
                     "equals": f"units.json objects, case \"{name}\""})
    three = put["three chunks, the chunk size lowered to 64"]
    token, stamp = b"attachments/big.bin", example("at-rest/held/stamp/attachments/big.bin")[:16]

    # Two puts refused as Changed: the file changed between the passes, and
    # the file gone.
    class Changing(Provider):
        """A provider whose file changes after the first stat."""
        def __init__(self, base: Provider, token: bytes, later: tuple):
            super().__init__()
            self.files = dict(base.files)
            self.token, self.later, self.stats = token, later, 0

        def stat(self, token):
            self.stats += 1
            if token == self.token and self.stats > 1:
                self.files[token] = self.later
            return super().stat(token)

    changed = Changing(provider, token, (big + b"!", example("at-rest/held/stamp/changed")[:16]))
    gone = Provider()
    put_refusals = [
        {"name": "the file changed between the passes", "token": h(token),
         "error": _expect(put_held, uspace, k, key_ref, changed, token, 64),
         "reason": "the stamp after pass two is not the one before pass one"},
        {"name": "the file gone", "token": h(token),
         "error": _expect(put_held, uspace, k, key_ref, gone, token, 64),
         "reason": "stat gives none"},
    ]
    assert [r["error"] for r in put_refusals] == ["Changed", "Changed"]

    # The held record of the three-chunk object, sealed and opened.
    rows = []
    for t, item, value in three["records"]:
        label = "held/object/0" if t == T_OBJECT else "held"
        sealed = store.seal(t, item, value, space, label)
        opened = store.open(sealed["address"], sealed["record"], space)
        rows.append({"name": ("the held object's header" if t == T_OBJECT
                              else "the held record: token, size and stamp"),
                     "table": t, "table_name": TABLES[t][0], "log": h(space),
                     "item": h(item), "value": h(value), "opened": _plain(opened["value"]),
                     "address": h(sealed["address"]), "plaintext": h(sealed["plaintext"]),
                     "aad": h(sealed["aad"]), "nonce": h(sealed["nonce"]),
                     "record": h(sealed["record"])})
    oid = three["id"]
    refusals = []
    for name, value, reason in [
        ("a 1,025-byte token", held_value(bytes(1025), 150, stamp), "a token is 1 to 1,024 bytes"),
        ("an empty token", held_value(b"", 150, stamp), "a token is 1 to 1,024 bytes"),
        ("a 65-byte stamp", held_value(token, 150, bytes(65)), "a stamp is 1 to 64 bytes"),
        ("an empty stamp", held_value(token, 150, b""), "a stamp is 1 to 64 bytes"),
        ("a size over 2^40", held_value(token, MAX_OBJECT_SIZE + 1, stamp),
         "the size is 0 to 2^40"),
        ("no stamp", cbor({1: token, 2: 150}), "keys 1 to 3 are required"),
        ("an unknown key", cbor({1: token, 2: 150, 3: stamp, 4: 1}), "keys 1 to 3 only"),
    ]:
        sealed = store.seal(T_HELD, oid, value, space, "held/" + name)
        refusals.append({"name": name, "address": h(sealed["address"]),
                         "record": h(sealed["record"]), "log": h(space), "log_key": h(L),
                         "error": _expect(open_record, s, L, sealed["address"], sealed["record"],
                                          space),
                         "reason": reason})
    assert all(r["error"] == "Malformed" for r in refusals)

    # Chunk 1 of the three-chunk object, sealed alone.
    keys = units.object_keys(k)
    okey = units.object_key(k, oid)
    plain_1 = big[64:128]
    alone = seal_chunk(uspace, keys, okey, oid, 150, 1, plain_1)
    assert alone["sealed"] == three["chunks"][1]["sealed"]
    reseal = {"chunk_bytes": 64, "id": h(oid), "size": 150, "index": 1, "plain": h(plain_1),
              "keys": {n: h(v) for n, v in keys.items()}, "object_key": h(okey),
              "aad": h(alone["aad"]), "nonce": h(alone["nonce"]), "sealed": h(alone["sealed"]),
              "equals": "units.json objects, case \"three chunks, the chunk size lowered to "
                        "64\", chunk 1"}

    # Serves.
    record = {"id": oid, "token": token, "size": 150, "stamp": stamp, "key_ref": key_ref}
    locator = three["locator"]
    serves = []

    def serve(name, files, first, count, note=""):
        p = Provider()
        p.files = files
        got = serve_held(uspace, k, record, locator, p, first, count, 64)
        current = p.stat(token)
        file = None if current is None else {"size": current[0], "stamp": h(current[1]),
                                             "plaintext": h(p.files[token][0])}
        serves.append({"name": name, "first": first, "count": count, "provider": file,
                       "outcome": got["outcome"],
                       **({"chunks": chunks_json(got["chunks"])} if "chunks" in got else {}),
                       **({"step": got["step"]} if "step" in got else {}),
                       **({"note": note} if note else {})})
        return got

    same = {token: (big, stamp)}
    whole = serve("served whole", same, 0, 3, "the ID and the digest are checked in the pass")
    assert [c["sealed"] for c in whole["chunks"]] == [c["sealed"] for c in three["chunks"]]
    one = serve("chunk 1 alone", same, 1, 1)
    assert one["chunks"][0]["sealed"] == three["chunks"][1]["sealed"]
    serve("a changed stamp", {token: (big, example("at-rest/held/stamp/changed")[:16])}, 0, 3,
          "the file was written again")
    serve("a changed size", {token: (big + b"!", stamp)}, 0, 3,
          "stat finds another size under the same stamp")
    flipped = _flip(big, 100)
    serve("a changed byte under an unchanged stamp, served whole", {token: (flipped, stamp)}, 0, 3,
          "only the object ID computed in the pass finds it")
    serve("a changed byte under an unchanged stamp, chunk 1 alone", {token: (flipped, stamp)},
          1, 1, "a partial serve cannot check the ID: the chunk seals, and the receiver's "
                "digest or ID check refuses the object")
    assert [x["outcome"] for x in serves] == ["held", "held", "not held", "not held",
                                               "not held", "held"]

    # Receives.
    header = three["header"]
    sealed_chunks = [c["sealed"] for c in three["chunks"]]
    receives = []

    def receive(name, content_key, object_key, want, chunks, hint=b"", note=""):
        p = Provider()
        try:
            got = receive_held(uspace, content_key, object_key, want, header, chunks, p, hint, 64)
            outcome = {"outcome": "accepted", "token": h(got["token"]), "stamp": h(got["stamp"]),
                       "plaintext": h(got["plaintext"]), "commit": records_json(got["records"])}
        except SpecError as error:
            outcome = {"outcome": "refused", "error": str(error),
                       "writer": "aborted", "commit": []}
        receives.append({"name": name, "with": "k(S)" if content_key is not None else "object key",
                         "locator": h(want), "header": h(header), "hint": h(hint),
                         "chunks": [h(c) for c in chunks], **outcome,
                         **({"note": note} if note else {})})
        return outcome

    got = receive("with k(S), checked by the object ID", k, None, locator, sealed_chunks,
                  b"downloads/big.bin")
    assert got["plaintext"] == h(big)
    got = receive("with the object key alone, checked by the digest", None, okey, locator,
                  sealed_chunks)
    assert got["plaintext"] == h(big)
    got = receive("a changed byte in chunk 1", k, None, locator,
                  [sealed_chunks[0], _flip(sealed_chunks[1], 30), sealed_chunks[2]],
                  note="refused at its chunk, before the digest")
    assert got["error"] == "Decrypt"
    other = oid + sha256(b"another object")
    got = receive("a locator of another digest, with the object key alone", None, okey, other,
                  sealed_chunks, note="every chunk opens; the whole is not what the locator names")
    assert got["error"] == "ObjectMismatch"
    # A writer with k(S) that sealed another plaintext under this object's
    # ID: the chunks open and the digest is the locator's, so only the ID
    # check of a reader with k(S) refuses it.
    lie = big[::-1]
    lied = [seal_chunk(uspace, keys, okey, oid, 150, i, lie[i * 64:(i + 1) * 64])["sealed"]
            for i in range(3)]
    lied_locator = oid + sha256(u32be(len(header)) + header + b"".join(lied))
    got = receive("another plaintext sealed under this ID, with k(S)", k, None, lied_locator, lied,
                  note="a writer that held k(S) lied: the ID over the plaintext is not the "
                       "header's")
    assert got["error"] == "ObjectMismatch"
    got = receive("another plaintext sealed under this ID, with the object key alone", None,
                  okey, lied_locator, lied,
                  note="the object key alone checks only the digest, which the writer chose")
    assert got["plaintext"] == h(lie)

    return {"fixtures": {"space": h(uspace), "content_key": h(k), "key_reference": h(key_ref),
                         "note": "units.json's space and its state [A], so that a held put "
                                 "gives that file's object bytes"},
            "records": rows, "record_refusals": refusals, "puts": puts,
            "put_refusals": put_refusals, "reseal": reseal, "serves": serves,
            "receives": receives}


def self_test() -> None:
    for a in NEW_LABELS:
        for b in NEW_LABELS + [SEALED_DEVICE_KEYS, UNLOCK_KEY_SALT]:
            assert a is b or (not a.startswith(b) and not b.startswith(a)), (a, b)
    assert (PLAINTEXT_BYTES, SEALED_DEVICE_KEYS_BYTES, MIN_RECORD, MARK_BYTES) == (
        129, 235, 45, 65)
    persons = _persons()
    a = at_rest_vectors(persons)
    assert all(len(bytes.fromhex(c["sealed"])) == SEALED_DEVICE_KEYS_BYTES
               and len(bytes.fromhex(c["plaintext"])) == PLAINTEXT_BYTES
               for c in a["sealed_device_keys"])
    errors = {c["name"]: c["error"] for c in a["sealed_device_keys_refusals"]}
    assert errors == {
        "another unlock key": "Decrypt",
        "sealed directly under a kind 2 key, not the key derived from it": "Decrypt",
        "the unlock key the same passkey derives for another person": "Decrypt",
        "a changed ciphertext byte": "Decrypt",
        "a changed device ID in the header": "Decrypt",
        "a changed person ID in the header, not checked by the caller": "Decrypt",
        "another person than the one expected": "WrongPerson",
        "a device member's keys opened as a person's": "WrongPerson",
        "another device than the one expected": "WrongDevice",
        "kind 1 keys opened as kind 2": "WrongKeyKind",
        "the kind byte changed": "Decrypt",
        "kind 1 with a zero person ID": "Malformed",
        "an unknown version": "UnsupportedVersion",
        "an unknown key kind": "Malformed",
        "one byte short": "Malformed",
        "one byte long": "Malformed",
        "keys that do not match the device ID": "Malformed",
        "the device's identity seed with another ML-DSA-65 seed": "Malformed",
        "an unknown layout of the keys inside": "UnsupportedVersion",
    }, errors
    assert {r["table"] for r in a["records"]} == set(TABLES) - {T_HELD}
    assert {r["table"] for r in a["held"]["records"]} == {T_OBJECT, T_HELD}
    assert len(a["held"]["record_refusals"]) == 7
    assert [p["pass_two"]["locator"] for p in a["held"]["puts"]] == [
        h(units.seal_object(units.SPACE, units.state_key([units.ROT["A"]]),
                            kg.encode_set([units.ROT["A"]]), p, c)["locator"])
        for p, c in ((b"an attachment of one chunk", units.CHUNK_BYTES),
                     (bytes(range(150)), 64), (b"", units.CHUNK_BYTES))]
    assert {r["item"][:2] for r in a["records"] if r["table"] == T_KEY} == {
        "01", "02", "03", "04", "05"}
    errors = {c["name"]: c["error"] for c in a["record_refusals"]}
    assert errors == {
        "moved to another event's address": "Decrypt",
        "opened under another log's key": "Decrypt",
        "a log's record opened under another log's scope": "Malformed",
        "a log's table under the device-wide scope": "Malformed",
        "an unknown table": "Malformed",
        "a changed ciphertext byte": "Decrypt",
        "an unknown version": "UnsupportedVersion",
        "shorter than any record": "Malformed",
        "an item that is not the address's": "Malformed",
        "an event record whose value does not parse": "Malformed",
        "a state with no incarnation expressed again": "Malformed",
        "a state whose incarnations expressed again are out of order": "Malformed",
        "a frozen unit with both an attribution and voiding events": "Malformed",
        "a frozen attribution out of order": "Malformed",
        "a frozen attribution with an empty label": "Malformed",
        "an erasing state beside another key": "Malformed",
        "a dropped record of origin 2 with a height": "Malformed",
        "a dropped record with height 0": "Malformed",
        "a claim naming another space": "Malformed",
        "a device-wide record sealed under a log key": "Decrypt",
    }, errors
    outcomes = [d["outcome"] for d in a["continuity"]]
    assert outcomes == ["Current", "Restored", "Restored", "Restored", "Restored", "Restored",
                        "Restored", "Restored", "Current"], outcomes
    assert a["after_restore"]["may_sign"] == {"the space, synced since": True,
                                              "alice's list, not yet synced": False}
    assert a["after_restore"]["originated"]["may_sign"] == {
        "an originated genesis, added in its commit": True,
        "a learned genesis, not added": False}
    mark_errors = {c["name"]: c["error"] for c in a["mark"]["refusals"]}
    assert mark_errors == {"an unknown version": "UnsupportedVersion",
                           "one byte short": "Malformed",
                           "another device's": "Decrypt",
                           "a changed byte": "Decrypt"}, mark_errors
    assert a["passkey_to_record"]["head_opened"]["2"] == 2
    assert len(bytes.fromhex(a["mark"]["mark"])) == MARK_BYTES
    assert app_key(NONE, b"x") != app_key(NONE, b"y")
    # An empty object's one chunk is 40 bytes, and a part of that size parses.
    assert read_value(T_OBJECT, bytes(32) + (1).to_bytes(4, "big"), bytes(SEALED_CHUNK_MIN),
                      None) == bytes(SEALED_CHUNK_MIN)
    assert not item_ok(T_PSEUDONYM, slot_reference(bytes(32), MAX_SLOT_INDEX, bytes(32)))
    assert item_ok(T_PSEUDONYM, slot_reference(bytes(32), MAX_SLOT_INDEX - 1, bytes(32)))
    assert not item_ok(T_PSEUDONYM, cbor([bytes(32), 0]))
    assert json.dumps(a, sort_keys=True) == json.dumps(at_rest_vectors(persons), sort_keys=True)


if __name__ == "__main__":
    self_test()
    print("at_rest self-test passed")
