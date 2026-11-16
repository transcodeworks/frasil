"""Units, objects, compaction and baseline sync (units.md), protocol 1,
written from the specification, independently of any implementation.

The bytes: a unit's visible body, its seal and its sealed part, built into
an event of kind 4 with events.py; stream IDs and their openings; objects
(keys, ID, header, chunks with synthetic nonces); stubs; the snapshot
unit's compaction declaration, with covers and boundary stubs computed from
a log; placement against stubs; the stream snapshot and the space snapshot;
Frasil's own units (list copies, body keys, recovery entries,
the system stream's snapshot state); a read-only person's list events;
head statements; and the baseline sync messages. Each reader runs the
checks of the specification in their order and raises the error class it
names.
"""

from __future__ import annotations

import hashlib
import hmac

import events
import history_sigs as hs
import keygraph
from events import KIND_SPACE, KIND_UNIT, cbor, is_bytes, is_uint, uncbor
from formats import example
from primitives import (
    SpecError,
    ed25519_public,
    ed25519_sign,
    ed25519_valid,
    ed25519_verify_strict,
    field,
    hkdf,
    sha256,
    xchacha20poly1305_open,
    xchacha20poly1305_seal,
)

# ---------------------------------------------------------------------------
# Labels and limits (units.md, "Limits").

UNIT_AAD_LABEL = b"frasil/unit/v1"
UNIT_KEY_LABEL = b"frasil/unit-key/v1"
UNIT_COMMITMENT_LABEL = b"frasil/unit-commitment/v1"
OBJECT_SEAL_KEY_LABEL = b"frasil/object-seal-key/v1"
OBJECT_CHUNK_LABEL = b"frasil/object-chunk/v1"
STREAM_ID_LABEL = b"frasil/stream-id/v1"
HEAD_STATEMENT_LABEL = b"frasil/head-statement/v1"
SPACE_SNAPSHOT_LABEL = b"frasil/space-snapshot/v1"
NEW_LABELS = [UNIT_AAD_LABEL, UNIT_KEY_LABEL, UNIT_COMMITMENT_LABEL, OBJECT_SEAL_KEY_LABEL,
              OBJECT_CHUNK_LABEL, STREAM_ID_LABEL, HEAD_STATEMENT_LABEL, SPACE_SNAPSHOT_LABEL]

VERSION = 1
NO_SALT = bytes(32)
STREAM_BYTES = 16
ID_BYTES = 32
NONCE_BYTES = 24
COMMITMENT_BYTES = 32
TAG_BYTES = 16
MAX_UNIT_BYTES = 1024 * 1024
MAX_OBJECTS = 4096
MAX_COVERS = 4096
MAX_STUBS = 8192
MAX_EXCLUDED = 4096
MAX_REFS = 64
MAX_TYPE_BYTES = 64
MAX_LIST_EVENTS = 16
MAX_BODY_KEYS = 1024
CHUNK_BYTES = 1024 * 1024 - 40  # a sealed chunk is exactly 1,048,576 bytes
SEALED_CHUNK_BYTES = 1024 * 1024
MAX_OBJECT_BYTES = 1 << 40
MAX_HEADS = 256
MAX_STATEMENT_STREAMS = 64
MAX_IDS = 4096
MAX_CHUNKS_WANTED = 64
MAX_MESSAGE_BYTES = 1024 * 1024 + 4096
MAX_STATEMENT_BYTES = 65536
MAX_PROOFS = 256
# max_streams_per_space: set by the operator within these bounds (peers.md).
MAX_STREAMS_PER_SPACE = {"min": 1, "max": 1 << 20, "default": 65536}

# The visible body and the sealed part.
B_VERSION, B_STREAM, B_KEY, B_STREAM_PREV, B_OBJECTS, B_COMPACTS, B_SEALED = range(1, 8)
C_OBJECT, C_COVERS, C_STUBS = 1, 2, 3
I_TYPE, I_CONTENT, I_RESUBMITS, I_COPIED_FROM, I_EXCLUDED = 1, 2, 3, 4, 5
I_STREAM_OPENING = 6
I_PADDING, I_REFS = 17, 18
LOCATOR_BYTES = 64
B_SUPERSEDES = 8  # ext-file-versions.md gives it meaning; units.md fixes its form
MAX_SUPERSESSIONS = 4096
STUB_KINDS = (KIND_UNIT,) + tuple(range(64, 128))

# Adapter types (units.md, "Adapter types"), in that table's order.
TYPE_LIST = "frasil:list"
TYPE_BODY_KEYS = "frasil:body-keys"
TYPE_RECOVERY_ENTRY = "frasil:recovery-entry"
TYPE_SYSTEM = "frasil:system"
TYPE_MOVE = "frasil:move"
TYPE_LORO = "frasil:loro"
TYPE_RECORDS = "frasil:records"
TYPE_BLOBS = "frasil:blobs"
FRASIL_TYPES = (TYPE_LIST, TYPE_BODY_KEYS, TYPE_RECOVERY_ENTRY, TYPE_SYSTEM,
                TYPE_MOVE, TYPE_LORO, TYPE_RECORDS, TYPE_BLOBS)
SYSTEM_TYPES = (TYPE_LIST, TYPE_BODY_KEYS, TYPE_RECOVERY_ENTRY, TYPE_SYSTEM)

# A read-only person's list events (units.md, "Frasil's own units").
LIST_EVENTS_CONTENT_NAME = "frasil/list-events"


def u64be(value: int) -> bytes:
    return value.to_bytes(8, "big")


def u32be(value: int) -> bytes:
    return value.to_bytes(4, "big")


def h(value: bytes) -> str:
    return value.hex()


def expect_error(function, *args, **kwargs) -> str:
    try:
        function(*args, **kwargs)
    except SpecError as error:
        return error.error
    raise AssertionError(f"{function.__name__} accepted what it must refuse")


def ascending(items) -> bool:
    return all(a < b for a, b in zip(items, items[1:]))


def valid_type(value) -> bool:
    if not isinstance(value, str):
        return False
    raw = value.encode()
    return 1 <= len(raw) <= MAX_TYPE_BYTES and all(0x21 <= c <= 0x7E for c in raw)


def valid_stream(value) -> bool:
    return is_bytes(value, STREAM_BYTES) and value != bytes(STREAM_BYTES)


def read_key_reference(data: bytes) -> None:
    """keys.md, "Reading a unit's key reference", step 1: one rotation set.
    A restricted space's unit carries its own set followed by its sealed
    parent set, the form ext-restricted-spaces.md defines."""
    name, rest = keygraph.read_name(data, allow_self=False)
    if rest:
        keygraph.read_restricted_reference(data)


def read_refs(value) -> list:
    """units.md, "The sealed part", key 18: 1 to 64 [log ID, event ID]
    pairs, strictly ascending by their 64 bytes. An empty array is
    Malformed; more than 64 refs is TooLarge (events.md's limits)."""
    if not isinstance(value, list) or not value:
        raise SpecError("Malformed")
    if len(value) > MAX_REFS:
        raise SpecError("TooLarge")
    flat = []
    for pair in value:
        if not (isinstance(pair, list) and len(pair) == 2 and is_bytes(pair[0], 32)
                and is_bytes(pair[1], 32)):
            raise SpecError("Malformed")
        flat.append(pair[0] + pair[1])
    if not ascending(flat):
        raise SpecError("Malformed")
    return value


# ---------------------------------------------------------------------------
# The seal (units.md, "The seal").


def unit_key(content_key: bytes) -> bytes:
    return hkdf(NO_SALT, content_key, UNIT_KEY_LABEL)


def unit_aad(log: bytes, author: bytes, seq: int, stream: bytes, key_ref: bytes) -> bytes:
    return (UNIT_AAD_LABEL + field(log) + author + u64be(seq) + stream + field(key_ref))


def body_key(content_key: bytes, aad: bytes) -> bytes:
    """A unit's body key: it opens that one unit's sealed part."""
    return hkdf(NO_SALT, unit_key(content_key), aad)


def commitment(key: bytes) -> bytes:
    return hkdf(NO_SALT, key, UNIT_COMMITMENT_LABEL)


def seal(content_key: bytes, nonce: bytes, inner: bytes, aad: bytes) -> bytes:
    assert len(nonce) == NONCE_BYTES
    key = body_key(content_key, aad)
    return nonce + commitment(key) + xchacha20poly1305_seal(key, nonce, inner, aad)


def open_sealed(key: bytes, sealed: bytes, aad: bytes) -> bytes:
    """Opens a seal under a body key that matches its commitment; raises
    otherwise."""
    if sealed[NONCE_BYTES:NONCE_BYTES + COMMITMENT_BYTES] != commitment(key):
        raise ValueError("the body key misses the commitment")
    return xchacha20poly1305_open(key, sealed[:NONCE_BYTES],
                                  sealed[NONCE_BYTES + COMMITMENT_BYTES:], aad)


# ---------------------------------------------------------------------------
# The sealed part (units.md, "The sealed part").


def encode_inner(type_: str, content: bytes, *, resubmits: bytes | None = None,
                 copied_from=None, excluded=None, padding: int = 0, refs=None,
                 opening=None) -> bytes:
    value = {I_TYPE: type_, I_CONTENT: content}
    if opening is not None:
        value[I_STREAM_OPENING] = [opening[0], opening[1]]
    if resubmits is not None:
        value[I_RESUBMITS] = resubmits
    if copied_from is not None:
        value[I_COPIED_FROM] = list(copied_from)
    if excluded:
        value[I_EXCLUDED] = sorted(excluded)
    if padding:
        value[I_PADDING] = bytes(padding)
    if refs:
        value[I_REFS] = [list(r) for r in sorted(refs, key=lambda r: r[0] + r[1])]
    return cbor(value)


def read_inner(data: bytes, snapshot_unit: bool) -> dict:
    """units.md, "A unit, at a member", step 15."""
    value = uncbor(data)
    if not isinstance(value, dict):
        raise SpecError("Malformed")
    if any(k not in (I_TYPE, I_CONTENT, I_RESUBMITS, I_COPIED_FROM, I_EXCLUDED, I_STREAM_OPENING,
                     I_PADDING,
                     I_REFS) for k in value):
        raise SpecError("Malformed")
    if I_TYPE not in value or I_CONTENT not in value:
        raise SpecError("Malformed")
    if not valid_type(value[I_TYPE]) or not is_bytes(value[I_CONTENT]):
        raise SpecError("Malformed")
    if I_RESUBMITS in value and not is_bytes(value[I_RESUBMITS], 32):
        raise SpecError("Malformed")
    if I_COPIED_FROM in value:
        c = value[I_COPIED_FROM]
        if not (isinstance(c, list) and len(c) == 2 and is_bytes(c[0], 32) and is_bytes(c[1], 32)):
            raise SpecError("Malformed")
    if I_RESUBMITS in value and I_COPIED_FROM in value:
        raise SpecError("Malformed")
    if I_EXCLUDED in value:
        e = value[I_EXCLUDED]
        if not snapshot_unit or not isinstance(e, list) or not 1 <= len(e) <= MAX_EXCLUDED \
                or not all(is_bytes(i, 32) for i in e) or not ascending(e):
            raise SpecError("Malformed")
    if I_STREAM_OPENING in value:
        o = value[I_STREAM_OPENING]
        if not (isinstance(o, list) and len(o) == 2 and valid_type(o[0]) and is_bytes(o[1], 16)):
            raise SpecError("Malformed")
    if I_PADDING in value and (not is_bytes(value[I_PADDING]) or any(value[I_PADDING])):
        raise SpecError("Malformed")
    if I_REFS in value:
        read_refs(value[I_REFS])
    return value


# ---------------------------------------------------------------------------
# The visible body, and the checks at a peer (units.md, "A unit, at a peer").


def encode_compacts(object_id: bytes, covers, stubs) -> dict:
    return {C_OBJECT: object_id,
            C_COVERS: [list(c) for c in sorted(covers)],
            C_STUBS: [list(s) for s in sorted(stubs)]}


def encode_body(stream: bytes, key_ref: bytes, sealed: bytes, *, stream_prev: bytes | None = None,
                objects=None, compacts: dict | None = None, supersedes=None) -> bytes:
    value = {B_VERSION: VERSION, B_STREAM: stream, B_KEY: key_ref, B_SEALED: sealed}
    if stream_prev is not None:
        value[B_STREAM_PREV] = stream_prev
    if objects:
        value[B_OBJECTS] = sorted(objects)
    if compacts is not None:
        value[B_COMPACTS] = compacts
    if supersedes:
        value[B_SUPERSEDES] = [list(s) for s in sorted(supersedes, key=lambda s: b"".join(s))]
    return cbor(value)


def read_supersessions(value, objects, snapshot_unit: bool) -> list:
    """units.md, "A unit, at a peer", step 11: 1 to 4,096 supersessions of
    three elements in a log unit and two in a snapshot unit, each successor
    in `objects`, and in a snapshot unit each predecessor too, strictly
    ascending by their bytes."""
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_SUPERSESSIONS:
        raise SpecError("Malformed")
    n = 2 if snapshot_unit else 3
    for s in value:
        if not (isinstance(s, list) and len(s) == n and is_bytes(s[0], LOCATOR_BYTES)
                and is_bytes(s[-1], LOCATOR_BYTES)
                and (snapshot_unit or is_bytes(s[1], ID_BYTES))):
            raise SpecError("Malformed")
        if s[0] not in objects or (snapshot_unit and s[-1] not in objects):
            raise SpecError("Malformed")
    if not ascending([b"".join(s) for s in value]):
        raise SpecError("Malformed")
    return [tuple(s) for s in value]


def read_stub(value) -> tuple:
    """units.md, "Stubs": [id, author, seq, height, kind], and a unit's stream
    as a sixth element in a space snapshot. Kind 4 or 64 to
    127; a space event, an anchor or a storage event is never stubbed."""
    if not (isinstance(value, list) and len(value) in (5, 6, 7) and is_bytes(value[0], 32)
            and is_bytes(value[1], 32) and is_uint(value[2]) and value[2] >= 1
            and is_uint(value[3]) and value[3] >= 1 and is_uint(value[4])):
        raise SpecError("Malformed")
    if value[4] not in STUB_KINDS:
        raise SpecError("Malformed")
    # The event's cuts, when it declares any, as the last element
    # (events.md, "Cuts"): an array where the stream is bytes.
    rest = list(value[5:])
    if rest and isinstance(rest[-1], list):
        cuts = rest.pop()
        if not (1 <= len(cuts) <= 4 and all(is_bytes(c, 32) for c in cuts)
                and ascending(cuts)):
            raise SpecError("Malformed")
    if len(rest) > 1 or (rest and (value[4] != KIND_UNIT or not valid_stream(rest[0]))):
        raise SpecError("Malformed")
    return tuple(value)


def read_stubs(value, limit: int = MAX_STUBS) -> list:
    if not isinstance(value, list) or len(value) > limit:
        raise SpecError("Malformed")
    stubs = [read_stub(s) for s in value]
    if not ascending([s[0] for s in stubs]):
        raise SpecError("Malformed")
    return stubs


def read_compaction_stubs(value) -> list:
    """A snapshot unit's stubs (units.md, "Stubs"): kind 4, five elements,
    or six when the stubbed unit declares cuts, the sixth its cuts."""
    stubs = read_stubs(value)
    for x in stubs:
        if x[4] != KIND_UNIT or not (len(x) == 5 or (len(x) == 6 and isinstance(x[5], list))):
            raise SpecError("Malformed")
    return stubs


def stub_mismatch(stub, event, height: int) -> str | None:
    """units.md, "Placing against stubs": a replica that holds both an
    event and a stub of it compares author, seq, height, kind and cuts (the
    stub's last element, when it is an array; none otherwise). BadStub on a
    mismatch, reported against the stub's signer."""
    cuts = tuple(stub[-1]) if isinstance(stub[-1], list) else ()
    if (stub[0], stub[1], stub[2], stub[3], stub[4], cuts) != (
            event.id, event.author, event.seq, height, event.kind, tuple(event.cuts)):
        return "BadStub"
    return None


def read_covers(value) -> list:
    if not isinstance(value, list) or len(value) > MAX_COVERS:
        raise SpecError("Malformed")
    for pair in value:
        if not (isinstance(pair, list) and len(pair) == 2 and is_bytes(pair[0], 32)
                and is_bytes(pair[1], 32)):
            raise SpecError("Malformed")
    if not ascending([p[0] for p in value]):
        raise SpecError("Malformed")
    return [tuple(p) for p in value]


def read_body(data: bytes) -> dict:
    """units.md, "A unit, at a peer", steps 4 to 11: what a peer reads,
    never a sealed byte."""
    try:
        value = uncbor(data)
    except SpecError:
        raise SpecError("Malformed")
    if not isinstance(value, dict) or not is_uint(value.get(B_VERSION)):
        raise SpecError("Malformed")
    if value[B_VERSION] != VERSION:
        raise SpecError("UnsupportedVersion")
    if any(k not in range(B_VERSION, B_SUPERSEDES + 1) for k in value):
        raise SpecError("Malformed")
    if any(k not in value for k in (B_STREAM, B_KEY, B_SEALED)):
        raise SpecError("Malformed")
    if not valid_stream(value[B_STREAM]):
        raise SpecError("Malformed")
    if not is_bytes(value[B_KEY]):
        raise SpecError("Malformed")
    read_key_reference(value[B_KEY])
    if B_STREAM_PREV in value and not is_bytes(value[B_STREAM_PREV], 32):
        raise SpecError("Malformed")
    objects = value.get(B_OBJECTS)
    if objects is not None and not (isinstance(objects, list) and 1 <= len(objects) <= MAX_OBJECTS
                                    and all(is_bytes(o, LOCATOR_BYTES) for o in objects)
                                    and ascending(objects)):
        raise SpecError("Malformed")
    if (not is_bytes(value[B_SEALED])
            or len(value[B_SEALED]) < NONCE_BYTES + COMMITMENT_BYTES + TAG_BYTES):
        raise SpecError("Malformed")
    if B_COMPACTS in value:
        c = value[B_COMPACTS]
        if not isinstance(c, dict) or sorted(c) != [C_OBJECT, C_COVERS, C_STUBS]:
            raise SpecError("Malformed")
        if not is_bytes(c[C_OBJECT], LOCATOR_BYTES) or not objects or c[C_OBJECT] not in objects:
            raise SpecError("Malformed")
        read_covers(c[C_COVERS])
        read_compaction_stubs(c[C_STUBS])
    if B_SUPERSEDES in value:
        read_supersessions(value[B_SUPERSEDES], objects or [], B_COMPACTS in value)
    return value


def peer_check(signed: bytes) -> tuple:
    """units.md, "A unit, at a peer", steps 1, 2 and 4 to 11 (placement,
    step 3, is the log's)."""
    event = events.decode_event(signed)
    if event.kind != KIND_UNIT:
        raise SpecError("Malformed")
    if len(signed) > MAX_UNIT_BYTES:
        raise SpecError("TooLarge")
    return event, read_body(event.body)


# ---------------------------------------------------------------------------
# Building and opening units.


def make_unit(signer, log: bytes, seq: int, prev: bytes | None, parents, stream: bytes,
              key_ref: bytes, content_key: bytes, inner: bytes, nonce: bytes, *,
              stream_prev: bytes | None = None, objects=None, compacts: dict | None = None,
              scheme: int | None = None, supersedes=None) -> dict:
    aad = unit_aad(log, signer.device_id, seq, stream, key_ref)
    sealed = seal(content_key, nonce, inner, aad)
    body = encode_body(stream, key_ref, sealed, stream_prev=stream_prev, objects=objects,
                       compacts=compacts, supersedes=supersedes)
    fields = events.event_fields(KIND_UNIT, signer, seq, body, log=log, prev=prev,
                                 parents=parents, scheme=scheme)
    signed = events.sign_fields(fields, signer)
    return {"aad": aad, "sealed": sealed, "body": body, "signed": signed,
            "id": events.event_id(cbor(fields)), "event_bytes": cbor(fields)}


def open_unit(signed: bytes, content_key: bytes, system: bytes | None = None, *,
              handed: bytes | None = None) -> dict:
    """units.md, "A unit, at a member", steps 14 and 15 (the key reference
    and the write rule are the caller's): open the seal under the body key
    derived from the named state's key, or under a body key handed over
    when `content_key` is None. A handed key that misses the commitment, or
    under which the seal fails, holds the unit."""
    event, body = peer_check(signed)
    aad = unit_aad(event.log, event.author, event.seq, body[B_STREAM], body[B_KEY])
    sealed = body[B_SEALED]
    key = body_key(content_key, aad) if content_key is not None else handed
    try:
        inner = open_sealed(key, sealed, aad)
    except Exception:
        raise SpecError("BadSeal" if content_key is not None else "Sealed")
    value = read_inner(inner, B_COMPACTS in body)
    if system is not None and (I_STREAM_OPENING in value) == (body[B_STREAM] == system):
        raise SpecError("Malformed")  # key 6 exactly outside the system stream
    return value


def stream_id(type_: str, salt: bytes) -> bytes:
    """units.md, "Streams": a document stream's ID commits to its adapter
    type through its opening [type, salt]."""
    raw = type_.encode()
    return sha256(STREAM_ID_LABEL + bytes([len(raw)]) + raw + salt)[:STREAM_BYTES]


def check_stream(stream: bytes, inner: dict) -> str:
    """units.md, "A unit, at a member", the stream check: SHA-256 of the
    opening gives the visible stream, and the type is the opening's type or
    frasil:move. Each unit is judged alone, whatever order it came in."""
    type_, salt = inner[I_STREAM_OPENING]
    if stream_id(type_, salt) != stream:
        return "StreamMismatch"
    if inner[I_TYPE] not in (type_, TYPE_MOVE):
        return "WrongAdapter"
    return "accepted"


def content_check(stream: bytes, system: bytes, inner: dict, adapters=FRASIL_TYPES) -> str:
    """units.md, "A unit, at a member", step 17, before the adapter's own
    checks: WrongStream first, then the stream check, then UnknownAdapter
    for a type this replica has no adapter for (its content is ignored)."""
    in_system = stream == system
    if (inner[I_TYPE] in SYSTEM_TYPES) != in_system:
        return "WrongStream"
    if not in_system:
        verdict = check_stream(stream, inner)
        if verdict != "accepted":
            return verdict
    if inner[I_TYPE] not in adapters:
        return "UnknownAdapter"
    return "accepted"


# Frasil's own units (units.md, "Frasil's own units").

def list_copy_content(signed_list_events) -> bytes:
    assert 1 <= len(signed_list_events) <= MAX_LIST_EVENTS
    return cbor(list(signed_list_events))


def read_list_copy(content: bytes) -> list:
    value = uncbor(content)
    if not (isinstance(value, list) and 1 <= len(value) <= MAX_LIST_EVENTS
            and all(is_bytes(v) for v in value)):
        raise SpecError("Malformed")
    out = []
    for signed in value:
        try:
            event = events.decode_event(signed)
        except SpecError:
            continue  # dropped from the copy; the unit stays valid
        if event.kind == events.KIND_DEVICE_LIST:
            out.append(event.id)
    return out


def body_keys_content(pairs) -> bytes:
    pairs = sorted(pairs)
    assert 1 <= len(pairs) <= MAX_BODY_KEYS
    return cbor([list(p) for p in pairs])


def read_body_keys(content: bytes) -> list:
    value = uncbor(content)
    if not (isinstance(value, list) and 1 <= len(value) <= MAX_BODY_KEYS):
        raise SpecError("Malformed")
    for pair in value:
        if not (isinstance(pair, list) and len(pair) == 2 and is_bytes(pair[0], 32)
                and is_bytes(pair[1], 32)):
            raise SpecError("Malformed")
    if not ascending([p[0] for p in value]):
        raise SpecError("Malformed")
    return value


def recovery_entry_content(space: bytes, key: bytes, member: bytes | None = None,
                           seed: bytes | None = None) -> bytes:
    """A frasil:recovery-entry unit's content: one recovery entry, the map of
    identity.md's "Fetch keys and recovery entries"."""
    import identity
    return identity.recovery_entry(space, key, member=member, seed=seed)


def read_recovery_entry_content(content: bytes, personal_space: bytes,
                                active_members=None) -> dict:
    """units.md, "Frasil's own units", recovery entries: the entry is read
    by identity.md's checks. One that fails, or whose list member is not
    active, is ignored; the unit stays valid either way."""
    import identity
    try:
        entry = identity.read_recovery_entry(content, personal_space)
    except SpecError as error:
        return {"outcome": "ignored", "class": error.error}
    if active_members is not None and "member" in entry \
            and entry["member"] not in active_members:
        return {"outcome": "ignored", "reason": "its list member is not active"}
    return {"outcome": "read", "entry": entry}


def system_snapshot_state(list_events, body_keys, entries=(), forgotten=None) -> bytes:
    """units.md, "Frasil's own units": a frasil:system unit's snapshot state.
    Key 1, the cover's list events, ascending by event ID, each once; key 2,
    its body keys; key 3 is reserved and absent; key 4, optional, its
    recovery entries, each once, ascending by encoding; key 5, optional,
    for each person whose list key 1 carries from a list checkpoint on,
    `[person ID, the IDs of the list events its writer forgot]`, both
    ascending (identity.md, "List checkpoints")."""
    by_id = {events.decode_event(e).id: e for e in list_events}
    value = {1: [by_id[i] for i in sorted(by_id)],
             2: [list(p) for p in sorted(body_keys)]}
    if entries:
        value[4] = sorted(set(entries))
    if forgotten:
        value[5] = [[person, sorted(set(ids))] for person, ids in sorted(forgotten.items())
                    if ids]
    return cbor(value)


def read_system_state(state: bytes) -> dict:
    """The snapshot state's shape, as a reader checks it: keys 1 and 2, key
    3 absent, keys 4 and 5 optional, key 5's pairs and IDs strictly
    ascending (Malformed)."""
    value = uncbor(state)
    if not (isinstance(value, dict) and 1 in value and 2 in value
            and set(value) <= {1, 2, 4, 5}):
        raise SpecError("Malformed")
    pairs = value.get(5, [])
    if 5 in value and not (isinstance(pairs, list) and pairs):
        raise SpecError("Malformed")
    persons = []
    for pair in pairs:
        if not (isinstance(pair, list) and len(pair) == 2 and is_bytes(pair[0], ID_BYTES)
                and isinstance(pair[1], list) and pair[1]
                and all(is_bytes(x, ID_BYTES) for x in pair[1])
                and all(a < b for a, b in zip(pair[1], pair[1][1:]))):
            raise SpecError("Malformed")
        persons.append(pair[0])
    if any(a >= b for a, b in zip(persons, persons[1:])):
        raise SpecError("Malformed")
    return value


# A read-only person's list events (units.md, "Frasil's own units"): the
# frasil/list-events body and the ListEvents sync message carry the same
# events.

LE_SPACE, LE_EVENTS = 1, 2


def list_events_body(space: bytes, signed_list_events) -> bytes:
    assert 1 <= len(signed_list_events) <= MAX_LIST_EVENTS
    return cbor({LE_SPACE: space, LE_EVENTS: list(signed_list_events)})


def read_list_events_body(data: bytes) -> tuple:
    """The device-mailbox body {1: space ID, 2: 1 to 16 signed device-list
    events, each a byte string}."""
    value = uncbor(data)
    if not (isinstance(value, dict) and sorted(value) == [LE_SPACE, LE_EVENTS]
            and is_bytes(value[LE_SPACE], ID_BYTES)):
        raise SpecError("Malformed")
    listed = value[LE_EVENTS]
    if not (isinstance(listed, list) and 1 <= len(listed) <= MAX_LIST_EVENTS
            and all(is_bytes(e) for e in listed)):
        raise SpecError("Malformed")
    return value[LE_SPACE], listed


def person_of(event) -> bytes:
    """identity.md: the person ID is the list's first event's ID, and every
    later list event carries it as its log."""
    return event.id if event.log is None else event.log


def forward_list_events(signed_list_events, persons, held=()) -> list:
    """What a writer does with list events handed to it: each is checked as
    a list event of a person the space's roster names, now or before; one
    that fails is dropped, and nothing else. One its view lacks is
    forwarded in a frasil:list unit."""
    import identity
    out = []
    for signed in signed_list_events:
        try:
            event = events.decode_event(signed)
            if event.kind == events.KIND_DEVICE_LIST:
                identity.check_body(event)
        except SpecError as error:
            out.append({"decision": "dropped", "class": error.error})
            continue
        if event.kind != events.KIND_DEVICE_LIST:
            out.append({"id": event.id, "decision": "dropped",
                        "reason": "not a device-list event"})
        elif person_of(event) not in persons:
            out.append({"id": event.id, "decision": "dropped",
                        "reason": "of a person the space's roster never named"})
        elif event.id in held:
            out.append({"id": event.id, "decision": "already in the system stream"})
        else:
            out.append({"id": event.id, "decision": "forwarded in a frasil:list unit"})
    return out


# ---------------------------------------------------------------------------
# Objects (units.md, "Objects" and "Reading an object").


def object_keys(content_key: bytes) -> dict:
    derived = keygraph.derived_keys(content_key)
    return {"id_key": derived["object_id_key"]["key"],
            "nonce_key": derived["object_nonce_key"]["key"],
            "seal_key": hkdf(NO_SALT, content_key, OBJECT_SEAL_KEY_LABEL)}


def object_id(content_key: bytes, plaintext: bytes) -> bytes:
    return hmac.new(object_keys(content_key)["id_key"], plaintext, hashlib.sha256).digest()


def object_key(content_key: bytes, oid: bytes) -> bytes:
    """units.md, "Objects": `object key = HMAC(object_seal_key(S), object
    ID)`, which opens that object alone."""
    return hmac.new(object_keys(content_key)["seal_key"], oid, hashlib.sha256).digest()


def chunk_count(size: int, chunk: int) -> int:
    return max(1, -(-size // chunk))


def chunk_aad(space: bytes, oid: bytes, size: int, index: int) -> bytes:
    return OBJECT_CHUNK_LABEL + field(space) + oid + u64be(size) + u64be(index)


def object_header(oid: bytes, key_ref: bytes, size: int) -> bytes:
    return cbor({1: VERSION, 2: oid, 3: key_ref, 4: size})


def seal_object(space: bytes, content_key: bytes, key_ref: bytes, plaintext: bytes,
                chunk: int = CHUNK_BYTES) -> dict:
    keys = object_keys(content_key)
    oid = hmac.new(keys["id_key"], plaintext, hashlib.sha256).digest()
    okey = hmac.new(keys["seal_key"], oid, hashlib.sha256).digest()
    size = len(plaintext)
    header = object_header(oid, key_ref, size)
    chunks = []
    for i in range(chunk_count(size, chunk)):
        plain = plaintext[i * chunk:(i + 1) * chunk]
        aad = chunk_aad(space, oid, size, i)
        nonce = hmac.new(keys["nonce_key"], aad + plain, hashlib.sha256).digest()[:NONCE_BYTES]
        sealed = nonce + xchacha20poly1305_seal(okey, nonce, plain, aad)
        chunks.append({"index": i, "aad": aad, "nonce": nonce, "sealed": sealed})
    data = u32be(len(header)) + header + b"".join(c["sealed"] for c in chunks)
    digest = sha256(data)
    return {"id": oid, "digest": digest, "locator": oid + digest, "header": header,
            "chunks": chunks, "bytes": data, "keys": keys, "object_key": okey}


def read_object_by_chunks(data: bytes, space: bytes, content_key: bytes | None, want: bytes,
                          **kw) -> bytes:
    """units.md, "Reading an object", by a reader that reads the object as
    its chunks arrive: steps 1 to 7 first, step 0 on the whole last, and the
    verdict still the first step, in order, that fails. A fault at steps 1
    to 7 stands only once step 0 has passed."""
    fault = None
    try:
        plain = read_object(data, space, content_key, want, step0=False, **kw)
    except SpecError as error:
        fault = error
    if sha256(data) != want[32:]:
        raise SpecError("ObjectMismatch")
    if fault is not None:
        raise fault
    return plain


def read_object(data: bytes, space: bytes, content_key: bytes | None, want: bytes,
                chunk: int = CHUNK_BYTES, okey: bytes | None = None,
                record: bool = False, self_ref: bytes | None = None,
                peer: bool = False, step0: bool = True) -> bytes:
    """units.md, "Reading an object", in order; `want` is the locator,
    ID || digest. A reader with the object key `okey` and not `k(S)` skips
    step 7. Header key 3 is a key reference, or a self reference: a peer
    (`peer`, steps 0 to 4 only) accepts either; a member accepts a self
    reference only in a checkpoint's record (`record`), and there only the
    checkpoint's own, `self_ref` (else BadCheckpoint)."""
    if step0 and sha256(data) != want[32:]:
        raise SpecError("ObjectMismatch")
    if len(data) < 4 or 4 + int.from_bytes(data[:4], "big") > len(data):
        raise SpecError("Malformed")
    n = int.from_bytes(data[:4], "big")
    header = uncbor(data[4:4 + n])
    if not isinstance(header, dict) or not is_uint(header.get(1)):
        raise SpecError("Malformed")
    if header[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if sorted(header) != [1, 2, 3, 4] or not is_bytes(header[2], 32) or not is_bytes(header[3]) \
            or not is_uint(header[4]):
        raise SpecError("Malformed")
    self_named = header[3][:1] == b"\x00"
    if self_named and (record or peer):
        # A checkpoint's record names the checkpoint by its self reference
        # (roster.md, "The checkpoint record"): it is sealed under that
        # checkpoint's own state, whose ID does not exist when it is sealed.
        name, rest = keygraph.read_name(header[3], allow_self=True)
        if rest:
            raise SpecError("Malformed")
    elif record:
        raise SpecError("Malformed")  # a record names its checkpoint, never a state
    else:
        read_key_reference(header[3])  # a self reference here is Malformed
    if header[4] > MAX_OBJECT_BYTES:
        raise SpecError("TooLarge")
    oid, size = header[2], header[4]
    if oid != want[:32]:
        raise SpecError("ObjectMismatch")
    count = chunk_count(size, chunk)
    lengths = [min(chunk, size - i * chunk) for i in range(count)] if size else [0]
    rest = data[4 + n:]
    if len(rest) != sum(NONCE_BYTES + x + TAG_BYTES for x in lengths):
        raise SpecError("Malformed")
    if peer:
        return b""  # a peer runs steps 0 to 4 and opens nothing
    if record and self_ref is not None and header[3] != self_ref:
        # The locator binds the header: an object naming another event is
        # the checkpoint author's own fault (roster.md, "The record object").
        raise SpecError("BadCheckpoint")
    if content_key is None and okey is None:
        raise SpecError("Sealed")
    if content_key is not None:
        okey = object_key(content_key, oid)
    plain, at = [], 0
    for i, length in enumerate(lengths):
        part = rest[at:at + NONCE_BYTES + length + TAG_BYTES]
        at += len(part)
        try:
            plain.append(xchacha20poly1305_open(okey, part[:NONCE_BYTES],
                                                part[NONCE_BYTES:], chunk_aad(space, oid, size, i)))
        except Exception:
            raise SpecError("Decrypt")
    plaintext = b"".join(plain)
    if content_key is not None and \
            hmac.new(object_keys(content_key)["id_key"], plaintext, hashlib.sha256).digest() != oid:
        raise SpecError("ObjectMismatch")
    return plaintext


# ---------------------------------------------------------------------------
# Compaction (units.md, "Compacting"): covers and boundary stubs from a log.


class Replica:
    """A full replica's log with each unit's visible body, for compaction."""

    def __init__(self, genesis_signed: bytes):
        g = events.decode_event(genesis_signed)
        self.log = events.Log(g)
        self.bodies: dict[bytes, dict] = {}

    def add(self, signed: bytes) -> bytes:
        event = events.decode_event(signed)
        if event.kind == KIND_UNIT:
            self.bodies[event.id] = read_body(event.body)
        assert self.log.add(event) == "placed"
        return event.id

    def ev(self, i: bytes) -> events.Event:
        return self.log.events[i]

    def stream_of(self, i: bytes) -> bytes | None:
        body = self.bodies.get(i)
        return body[B_STREAM] if body else None

    def past(self, i: bytes) -> frozenset:
        return self.log.anc[i]

    def covers(self, parents, stream: bytes) -> list:
        """Each writer's stream frontier in the past the parents fix."""
        past = set()
        for p in parents:
            past |= self.log.anc[p] | {p}
        best: dict[bytes, tuple] = {}
        for i in past:
            if self.stream_of(i) == stream:
                e = self.ev(i)
                if e.author not in best or e.seq > best[e.author][0]:
                    best[e.author] = (e.seq, i)
        return sorted((a, v[1]) for a, v in best.items())

    def cover_set(self, covers, stream: bytes) -> set:
        """Each [w, c] names c and w's units of the stream below it."""
        out = set()
        for writer, last in covers:
            limit = self.ev(last).seq
            for i, e in self.log.events.items():
                if e.author == writer and e.seq <= limit and self.stream_of(i) == stream:
                    out.add(i)
        return out

    def stub(self, i: bytes) -> tuple:
        e = self.ev(i)
        return (i, e.author, e.seq, self.log.height[i], e.kind)

    def boundary_stubs(self, cover: set, outside_extra=()) -> list:
        """Every unit of the cover that an event outside the cover
        names as a parent (the snapshot unit's own parents included)."""
        out = set()
        for i, e in self.log.events.items():
            if i in cover:
                continue
            out |= {p for p in e.parents if p in cover}
        for parents in outside_extra:
            out |= {p for p in parents if p in cover}
        return sorted(self.stub(i) for i in out)


def place_against_stubs(events_signed, stubs, genesis_signed: bytes) -> dict:
    """units.md, "Placing against stubs": place events whose parents are
    placed or stubbed, taking a
    stubbed parent's height from its stub. Returns heights and the pending."""
    g = events.decode_event(genesis_signed)
    height = {g.id: 0}
    stub_of = {s[0]: s for s in stubs}
    for s in stubs:
        height[s[0]] = s[3]
    todo = [events.decode_event(s) for s in events_signed]
    progress = True
    while progress:
        progress = False
        for e in list(todo):
            if all(p in height for p in e.parents):
                height[e.id] = 1 + max(height[p] for p in e.parents)
                todo.remove(e)
                progress = True
    return {"heights": height, "pending": sorted(e.id for e in todo), "stubbed": stub_of}


# ---------------------------------------------------------------------------
# The stream snapshot and the space snapshot (units.md, "Snapshot units and
# stream snapshots", "The space snapshot").


def stream_snapshot(type_: str, stream: bytes, state: bytes, *, history_free: bool = False,
                    moved: bytes | None = None) -> bytes:
    value = {1: VERSION, 2: type_, 3: stream, 5: state}
    if history_free:
        value[4] = 1
    if moved is not None:
        value[6] = moved
    return cbor(value)


def read_stream_snapshot(data: bytes, stream: bytes, type_: str) -> dict:
    value = uncbor(data)
    if not isinstance(value, dict) or not is_uint(value.get(1)):
        raise SpecError("Malformed")
    if value[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if any(k not in (1, 2, 3, 4, 5, 6) for k in value) or any(k not in value for k in (2, 3, 5)):
        raise SpecError("Malformed")
    if value[2] != type_ or value[3] != stream or not is_bytes(value[5]):
        raise SpecError("Malformed")
    if 4 in value and value[4] != 1:
        raise SpecError("Malformed")
    if 6 in value and not is_bytes(value[6]):
        raise SpecError("Malformed")
    return value


def stream_entry(stream: bytes, opening, oid: bytes, key_ref: bytes, covers, excluded=(),
                 supersedes=()) -> dict:
    """Key 2 is the stream's opening [type, salt] (units.md, "Streams"); key
    7, when there are any, the history-free state's supersessions
    (ext-file-versions.md, "The supersession set")."""
    entry = {1: stream, 2: [opening[0], opening[1]], 3: oid, 4: key_ref,
             5: [list(c) for c in sorted(covers)], 6: sorted(excluded)}
    if supersedes:
        entry[7] = [list(s) for s in sorted(supersedes, key=lambda s: b"".join(s))]
    return entry


def space_snapshot_map(space: bytes, sender: bytes, base, stubs, body_keys, lists, logs,
                       streams, system: bytes, proofs=()) -> bytes:
    value = {1: VERSION, 2: space, 3: sender, 4: sorted(base),
             5: [list(s) for s in sorted(stubs)],
             6: [list(p) for p in sorted(body_keys)],
             7: sorted(lists, key=lambda s: events.decode_event(s).id),
             8: sorted(logs, key=lambda m: m[1]),
             9: sorted(streams, key=lambda m: m[1])}
    if proofs:
        value[10] = list(proofs)
    value[11] = system
    return cbor(value)


def read_proofs(value) -> list:
    """Key 10, and a log entry's key 5: 1 to 256 equivocation proofs, each
    the byte string of events.md's array (checked by verify_proof once its
    events are placed)."""
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_PROOFS:
        raise SpecError("Malformed")
    for proof in value:
        if not is_bytes(proof):
            raise SpecError("Malformed")
        inner = uncbor(proof)
        if not (isinstance(inner, list) and len(inner) == 3 and is_uint(inner[0])
                and is_bytes(inner[1]) and is_bytes(inner[2])):
            raise SpecError("Malformed")
    return value


def read_snapshot_stubs(value) -> list:
    """A space snapshot's stubs, and a log entry's: six elements, the sixth
    the unit's stream, or seven when the unit declares cuts, the seventh its
    cuts; at most 8,192 (units.md, "Limits")."""
    stubs = read_stubs(value)
    for x in stubs:
        if not (len(x) in (6, 7) and valid_stream(x[5])
                and (len(x) == 6 or isinstance(x[6], list))):
            raise SpecError("Malformed")
    return stubs


def read_body_key_pairs(value) -> list:
    """[event ID, body key] pairs, bytes(32) each, ascending by event ID."""
    if not isinstance(value, list) or not all(
            isinstance(p, list) and len(p) == 2 and is_bytes(p[0], 32) and is_bytes(p[1], 32)
            for p in value):
        raise SpecError("Malformed")
    if not ascending([p[0] for p in value]):
        raise SpecError("Malformed")
    return value


def read_log_entry(entry) -> dict:
    """A log entry: key 1, a space ID of the grant path; key 2, its signed
    events; key 3, its stubs; key 4, its body keys; key 5, optional, its
    equivocation proofs."""
    if not (isinstance(entry, dict) and all(k in range(1, 6) for k in entry)
            and all(k in entry for k in (1, 2, 3, 4)) and is_bytes(entry[1], ID_BYTES)):
        raise SpecError("Malformed")
    if not (isinstance(entry[2], list) and all(is_bytes(e) for e in entry[2])):
        raise SpecError("Malformed")
    read_snapshot_stubs(entry[3])
    read_body_key_pairs(entry[4])
    if 5 in entry:
        read_proofs(entry[5])
    return entry


def read_stream_entry(entry) -> dict:
    """A stream entry: keys 1 to 6, each with its type, and key 7 when
    present; key 2, the opening, hashes to key 1."""
    if not (isinstance(entry, dict)
            and sorted(entry) in ([1, 2, 3, 4, 5, 6], [1, 2, 3, 4, 5, 6, 7])):
        raise SpecError("Malformed")
    o = entry[2]
    if not (valid_stream(entry[1]) and isinstance(o, list) and len(o) == 2
            and valid_type(o[0]) and is_bytes(o[1], 16)
            and is_bytes(entry[3], LOCATOR_BYTES) and is_bytes(entry[4])):
        raise SpecError("Malformed")
    if stream_id(o[0], o[1]) != entry[1]:
        raise SpecError("Malformed")
    read_key_reference(entry[4])
    read_covers(entry[5])
    excluded = entry[6]
    if not (isinstance(excluded, list) and len(excluded) <= MAX_EXCLUDED
            and all(is_bytes(i, ID_BYTES) for i in excluded) and ascending(excluded)):
        raise SpecError("Malformed")
    if 7 in entry:
        supersedes = entry[7]
        if not (isinstance(supersedes, list) and 1 <= len(supersedes) <= MAX_SUPERSESSIONS
                and all(isinstance(s, list) and len(s) == 2 and is_bytes(s[0], LOCATOR_BYTES)
                        and is_bytes(s[1], LOCATOR_BYTES) for s in supersedes)
                and ascending([b"".join(s) for s in supersedes])):
            raise SpecError("Malformed")
    return entry


MAX_PLACED = 4_096  # key 15's IDs


def sign_space_snapshot(signer, snapshot: bytes) -> bytes:
    signature = hs.sign(signer, events.SCHEME_HYBRID, SPACE_SNAPSHOT_LABEL + snapshot)
    return cbor([snapshot, signature])


def read_space_snapshot(data: bytes, space: bytes, keys=()) -> dict:
    """units.md, "The space snapshot", using it, steps 1 to 3. `sender` is
    its `ed || kc`; `keys` are the (ML-DSA-65 key, X-Wing key or None) pairs
    the newcomer holds from any source: until one hashes to the sender's
    kc, the snapshot is provisional."""
    outer = uncbor(data)
    if not (isinstance(outer, list) and len(outer) == 2 and is_bytes(outer[0])
            and is_bytes(outer[1], hs.HYBRID_SIGNATURE_BYTES)):
        raise SpecError("Malformed")
    snapshot, signature = outer
    value = uncbor(snapshot)
    if not isinstance(value, dict) or not is_uint(value.get(1)):
        raise SpecError("Malformed")
    if value[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if any(k not in range(1, 16) for k in value) \
            or any(k not in value for k in list(range(1, 10)) + [11]):
        raise SpecError("Malformed")
    # Keys 12 to 14: the checkpoint in effect at the base, its record's
    # object key and the checkpoints its cuts reach (roster.md).
    if (13 in value or 14 in value) and 12 not in value:
        raise SpecError("Malformed")
    if 12 in value and (not is_bytes(value[12], 32) or not is_bytes(value.get(13), 32)):
        raise SpecError("Malformed")
    if 14 in value:
        # The checkpoints key 12's cuts reach: signed space events, strictly
        # ascending by event ID.
        if not (isinstance(value[14], list) and all(is_bytes(e) for e in value[14])):
            raise SpecError("Malformed")
        try:
            chain = [events.decode_event(e) for e in value[14]]
        except SpecError:
            raise SpecError("Malformed")
        if any(e.kind != KIND_SPACE for e in chain) or not ascending([e.id for e in chain]):
            raise SpecError("Malformed")
    if not valid_stream(value[11]):
        raise SpecError("Malformed")
    if 10 in value:
        read_proofs(value[10])
    if not is_bytes(value[2], 32) or not is_bytes(value[3], 64):
        raise SpecError("Malformed")
    base = value[4]
    if not (isinstance(base, list) and 1 <= len(base) <= MAX_HEADS
            and all(is_bytes(b, 32) for b in base) and ascending(base)):
        raise SpecError("Malformed")
    read_snapshot_stubs(value[5])
    read_body_key_pairs(value[6])
    if not isinstance(value[7], list) or not all(is_bytes(e) for e in value[7]):
        raise SpecError("Malformed")
    try:
        list_ids = [events.decode_event(e).id for e in value[7]]
    except SpecError:
        raise SpecError("Malformed")
    if not ascending(list_ids):
        raise SpecError("Malformed")
    # Key 15: the list events whose own copy is in the past of the base,
    # each one of key 7 (roster.md, "A list at an event's place").
    if 15 in value:
        placed = value[15]
        if not (isinstance(placed, list) and 1 <= len(placed) <= MAX_PLACED
                and all(is_bytes(i, 32) for i in placed) and ascending(placed)
                and set(placed) <= set(list_ids)):
            raise SpecError("Malformed")
    if not isinstance(value[8], list) or not isinstance(value[9], list):
        raise SpecError("Malformed")
    for entry in value[8]:
        read_log_entry(entry)
    for entry in value[9]:
        read_stream_entry(entry)
    if not ascending([e[1] for e in value[8]]) or not ascending([e[1] for e in value[9]]):
        raise SpecError("Malformed")
    if value[2] != space:
        raise SpecError("WrongSpace")
    tbs = SPACE_SNAPSHOT_LABEL + snapshot
    ed, kc, _ = hs.split_signer(value[3])
    if not hs.verify_ed25519_half(ed, tbs, signature):
        raise SpecError("BadSignature")
    held = hs.keys_for(kc, keys or ())
    if held is None:
        return {"value": value, "provisional": True}
    if not hs.verify_mldsa_half(ed, held[0], tbs, signature):
        raise SpecError("BadSignature")
    return {"value": value, "provisional": False}


# ---------------------------------------------------------------------------
# Head statements (units.md, "Head statements").


def head_statement(space: bytes, device: bytes, heads, streams=None) -> bytes:
    value = {1: VERSION, 2: space, 3: device, 4: sorted(heads)}
    if streams:
        value[5] = [[s, [list(p) for p in sorted(pairs)]] for s, pairs in sorted(streams)]
    return cbor(value)


def sign_statement(seed: bytes, statement: bytes) -> bytes:
    """Scheme 0, by the Ed25519 seed of the statement's `device`'s ed."""
    return cbor([statement, ed25519_sign(seed, HEAD_STATEMENT_LABEL + statement)])


def read_statement(signed: bytes, space: bytes, members) -> dict:
    """units.md, "Heads, acknowledgements and durability": once the bytes
    decode, in order: the signature under `device`'s ed, the space, a valid
    ed, and the device ID of `device`'s ed and kc a member of the merged
    roster. A statement that fails is ignored."""
    if len(signed) > MAX_STATEMENT_BYTES:
        raise SpecError("TooLarge")
    outer = uncbor(signed)
    if not (isinstance(outer, list) and len(outer) == 2 and is_bytes(outer[0])
            and is_bytes(outer[1], 64)):
        raise SpecError("Malformed")
    value = uncbor(outer[0])
    if not isinstance(value, dict) or not is_uint(value.get(1)):
        raise SpecError("Malformed")
    if value[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if any(k not in (1, 2, 3, 4, 5) for k in value) or any(k not in value for k in (2, 3, 4)):
        raise SpecError("Malformed")
    heads = value[4]
    if not (is_bytes(value[2], 32) and is_bytes(value[3], 64) and isinstance(heads, list)
            and 1 <= len(heads) <= MAX_HEADS and all(is_bytes(x, 32) for x in heads)
            and ascending(heads)):
        raise SpecError("Malformed")
    if 5 in value:
        streams = value[5]
        if not (isinstance(streams, list) and 1 <= len(streams) <= MAX_STATEMENT_STREAMS):
            raise SpecError("Malformed")
        for entry in streams:
            if not (isinstance(entry, list) and len(entry) == 2 and valid_stream(entry[0])):
                raise SpecError("Malformed")
            read_covers(entry[1])
            if not entry[1]:
                raise SpecError("Malformed")
        if not ascending([e[0] for e in streams]):
            raise SpecError("Malformed")
    ed, _, device = hs.split_signer(value[3])
    if not ed25519_verify_strict(ed, HEAD_STATEMENT_LABEL + outer[0], outer[1]):
        raise SpecError("BadSignature")
    if value[2] != space:
        raise SpecError("WrongSpace")
    if not ed25519_valid(ed):
        raise SpecError("InvalidKey")
    if device not in members:
        raise SpecError("NotAMember")
    return value


# ---------------------------------------------------------------------------
# Sync messages (units.md, "Sync messages").

M_HEADS, M_WANT, M_EVENTS, M_MISSING, M_ACK, M_STREAM_HEADS, M_STREAM_WANT = range(1, 8)
M_OBJECT_WANT, M_OBJECT_CHUNKS, M_OBJECT_HAVE, M_PATH_WANT, M_PATH = range(8, 13)
M_SUBSCRIBE, M_STATEMENT, M_SNAPSHOT_WANT, M_SNAPSHOT_OFFER, M_LIST_EVENTS = range(13, 18)
MESSAGE_NAMES = {
    M_HEADS: "Heads", M_WANT: "Want", M_EVENTS: "Events", M_MISSING: "Missing", M_ACK: "Ack",
    M_STREAM_HEADS: "StreamHeads", M_STREAM_WANT: "StreamWant", M_OBJECT_WANT: "ObjectWant",
    M_OBJECT_CHUNKS: "ObjectChunks", M_OBJECT_HAVE: "ObjectHave", M_PATH_WANT: "PathWant",
    M_PATH: "Path", M_SUBSCRIBE: "Subscribe", M_STATEMENT: "Statement",
    M_SNAPSHOT_WANT: "SnapshotWant", M_SNAPSHOT_OFFER: "SnapshotOffer",
    M_LIST_EVENTS: "ListEvents",
}
# Types that travel on member connections only (transport.md routes them).
MEMBER_ONLY = (M_STATEMENT, M_SNAPSHOT_WANT, M_SNAPSHOT_OFFER, M_LIST_EVENTS)
FIRST_IGNORABLE = 64


def message(type_: int, space: bytes, **fields) -> bytes:
    value = {0: type_, 1: space}
    for key, item in fields.items():
        value[int(key[1:])] = item
    return cbor(value)


def _ids(value, lo: int, hi: int, size: int = 32) -> None:
    if not (isinstance(value, list) and lo <= len(value) <= hi
            and all(is_bytes(x, size) for x in value) and ascending(value)):
        raise SpecError("Malformed")


def _triples(value, hi: int) -> None:
    if not isinstance(value, list) or len(value) > hi:
        raise SpecError("Malformed")
    keys = []
    for t in value:
        if not (isinstance(t, list) and len(t) == 3 and is_bytes(t[0], 32)):
            raise SpecError("Malformed")
        keys.append(t)
    return keys


def read_message(data: bytes) -> dict:
    """units.md, "Sync messages" and "Sync": the shape of each type. An
    unknown type from 18 to 63 is UnknownMessage; from 64 it is ignored."""
    if len(data) > MAX_MESSAGE_BYTES:
        raise SpecError("TooLarge")
    value = uncbor(data)
    if not isinstance(value, dict) or not is_uint(value.get(0)) or not is_bytes(value.get(1), 32):
        raise SpecError("Malformed")
    t = value[0]
    if t >= FIRST_IGNORABLE:
        return {"type": t, "ignored": True}
    if t not in MESSAGE_NAMES:
        raise SpecError("UnknownMessage")
    allowed = {M_HEADS: (2, 3, 4), M_WANT: (2, 3, 4, 5), M_EVENTS: (2,), M_MISSING: (2, 3),
               M_ACK: (2,), M_STREAM_HEADS: (2, 3, 4), M_STREAM_WANT: (2, 3, 4),
               M_OBJECT_WANT: (2, 3, 4), M_OBJECT_CHUNKS: (2, 3, 4, 5), M_OBJECT_HAVE: (2, 3),
               M_PATH_WANT: (2, 3), M_PATH: (2, 3, 4), M_SUBSCRIBE: (2,), M_STATEMENT: (2,),
               M_SNAPSHOT_WANT: (2,), M_SNAPSHOT_OFFER: (2,), M_LIST_EVENTS: (2,)}[t]
    if any(k not in (0, 1) + allowed for k in value):
        raise SpecError("Malformed")
    required = {M_HEADS: (2,), M_EVENTS: (2,), M_ACK: (2,), M_STREAM_HEADS: (2, 4),
                M_STREAM_WANT: (2, 3), M_OBJECT_WANT: (2, 3, 4), M_OBJECT_CHUNKS: (2, 4, 5),
                M_OBJECT_HAVE: (2,), M_PATH_WANT: (2, 3), M_PATH: (2, 3, 4), M_STATEMENT: (2,),
                M_SNAPSHOT_WANT: (2,), M_SNAPSHOT_OFFER: (2,), M_LIST_EVENTS: (2,)}.get(t, ())
    if any(k not in value for k in required):
        raise SpecError("Malformed")
    if t == M_HEADS:
        _ids(value[2], 0, MAX_IDS)
        if 4 in value:
            _ids(value[4], 1, MAX_IDS, STREAM_BYTES)
        if 3 in value:
            v = _triples(value[3], MAX_IDS)
            if not all(is_uint(x[1]) and x[1] >= 1 and is_bytes(x[2], 32) for x in v) \
                    or not ascending([x[0] + x[2] for x in v]):
                raise SpecError("Malformed")
    elif t == M_WANT:
        if 2 not in value and 3 not in value:
            raise SpecError("Malformed")
        if 2 in value:
            _ids(value[2], 1, MAX_IDS)
        if 3 in value:
            r = _triples(value[3], MAX_IDS)
            if not r or not all(is_uint(x[1]) and is_uint(x[2]) and 1 <= x[1] <= x[2] for x in r) \
                    or not ascending([x[0] for x in r]):
                raise SpecError("Malformed")
        if 4 in value and not (isinstance(value[4], list) and value[4] and ascending(value[4])
                               and all(is_uint(k) and 1 <= k <= 127 for k in value[4])):
            raise SpecError("Malformed")
        if 5 in value:
            _ids(value[5], 1, MAX_IDS, STREAM_BYTES)
    elif t in (M_EVENTS,):
        if not (isinstance(value[2], list) and 1 <= len(value[2]) <= MAX_IDS
                and all(is_bytes(e) for e in value[2])):
            raise SpecError("Malformed")
    elif t == M_MISSING:
        if 2 in value:
            _ids(value[2], 1, MAX_IDS)
        if 3 in value:
            pairs = value[3]
            if not (isinstance(pairs, list) and 1 <= len(pairs) <= MAX_IDS and all(
                    isinstance(p, list) and len(p) == 2 and is_bytes(p[0], 32)
                    and is_bytes(p[1], 32) for p in pairs) and ascending([p[0] for p in pairs])):
                raise SpecError("Malformed")
    elif t == M_ACK:
        _ids(value[2], 1, MAX_IDS)
    elif t == M_STREAM_HEADS:
        if not valid_stream(value[2]) or (3 in value and not is_bytes(value[3], 32)):
            raise SpecError("Malformed")
        v = _triples(value[4], MAX_COVERS)
        if not all(is_bytes(x[1], 32) and is_uint(x[2]) and x[2] >= 1 for x in v) \
                or not ascending([x[0] for x in v]):
            raise SpecError("Malformed")
    elif t == M_STREAM_WANT:
        if not valid_stream(value[2]):
            raise SpecError("Malformed")
        read_covers(value[3])
        if 4 in value and value[4] != 1:
            raise SpecError("Malformed")
    elif t == M_OBJECT_WANT:
        if not (is_bytes(value[2], LOCATOR_BYTES) and is_uint(value[3]) and is_uint(value[4])
                and 1 <= value[4] <= MAX_CHUNKS_WANTED):
            raise SpecError("Malformed")
    elif t == M_OBJECT_CHUNKS:
        if not (is_bytes(value[2], LOCATOR_BYTES) and is_uint(value[4]) and is_bytes(value[5])
                and NONCE_BYTES + TAG_BYTES <= len(value[5]) <= CHUNK_BYTES + NONCE_BYTES + TAG_BYTES):
            raise SpecError("Malformed")
        if 3 in value and not is_bytes(value[3]):
            raise SpecError("Malformed")
    elif t == M_OBJECT_HAVE:
        _ids(value[2], 1, MAX_IDS, LOCATOR_BYTES)
        if 3 in value and not (isinstance(value[3], list) and len(value[3]) == len(value[2])
                               and all(is_uint(c) for c in value[3])):
            raise SpecError("Malformed")
    elif t == M_PATH_WANT:
        if not (is_bytes(value[2], 32) and is_bytes(value[3], 32)):
            raise SpecError("Malformed")
    elif t == M_PATH:
        if not (is_bytes(value[2], 32) and is_bytes(value[3], 32) and isinstance(value[4], list)
                and len(value[4]) <= MAX_IDS and all(is_bytes(e) for e in value[4])):
            raise SpecError("Malformed")
    elif t == M_SUBSCRIBE:
        if 2 in value:
            _ids(value[2], 1, MAX_IDS, STREAM_BYTES)
    elif t == M_STATEMENT:
        if not (isinstance(value[2], list) and 1 <= len(value[2]) <= 64
                and all(is_bytes(s) for s in value[2])):
            raise SpecError("Malformed")
    elif t == M_SNAPSHOT_WANT:
        _ids(value[2], 1, MAX_IDS, STREAM_BYTES)
    elif t == M_SNAPSHOT_OFFER:
        if not is_bytes(value[2]):
            raise SpecError("Malformed")
    elif t == M_LIST_EVENTS:
        if not (isinstance(value[2], list) and 1 <= len(value[2]) <= MAX_LIST_EVENTS
                and all(is_bytes(e) for e in value[2])):
            raise SpecError("Malformed")
    return {"type": t, "name": MESSAGE_NAMES[t], "value": value}


def check_path(path_signed, start: bytes, target: bytes) -> bool:
    """`Path`: the first event a parent of `start`'s event, each next a
    parent of the one before, the last with `target` among its parents."""
    chain = [events.decode_event(s) for s in path_signed]
    if not chain:
        return False
    if chain[0].id not in start.parents:
        return False
    for a, b in zip(chain, chain[1:]):
        if b.id not in a.parents:
            return False
    return target in chain[-1].parents


# ---------------------------------------------------------------------------
# Decisions: stub confirmation, statement outcomes, settling.


def confirm_stub(held_in_full: bool, sources) -> str:
    """units.md, "Placing against stubs": a stub a space event rests on
    counts once the event is held in full, or two different signers sign
    the same stub. Each signer is the writer of a source the replica has
    judged ("Where stubs come from"): a valid unit, or a space snapshot's
    base."""
    if held_in_full:
        return "placed: held in full"
    stubs = {stub for _, stub in sources}
    if len(stubs) > 1:
        return "pending: stubs disagree"
    if len({signer_ for signer_, _ in sources}) >= 2:
        return "placed: two signers agree"
    return "pending: one signer"


WITHHOLDING_GRACE = 300


def statement_outcome(peer_serves: bool, author_supplies: bool, peer_acknowledged: bool,
                      first_missing, last_missing, withholding_grace: int) -> str:
    """units.md, "Heads, acknowledgements and durability": whom a missing
    head is reported against. `first_missing` and `last_missing` are the
    readings of the peer's first and latest `Missing` for the head, on the
    receiver's monotonic clock, or None when it answered none."""
    if peer_serves:
        return "consistent"
    if not author_supplies:
        return "BadStatement, against the statement's author"
    if peer_acknowledged:
        return "Withheld, against the peer"
    if first_missing is not None and last_missing - first_missing >= withholding_grace:
        return "Withheld, against the peer"
    return "not reported"


def settled(stable: bool, first_sight: int, now: int, gap_key_timeout: int) -> str:
    """units.md, "Checking, using and settling a snapshot": stable, or at
    least gap_key_timeout since first sight, on the lower estimate."""
    if stable:
        return "Settled"
    if now - first_sight >= gap_key_timeout:
        return "Settled"
    return "Unsettled"


# ---------------------------------------------------------------------------
# The vectors (units.md, "Test vectors").

SPACE = example("units/space")
SALT = {n: sha256(b"units/salt/" + n.encode())[:16] for n in ("X", "Y", "L", "B", "Z")}
STREAM_X = stream_id(TYPE_RECORDS, SALT["X"])
STREAM_Y = stream_id(TYPE_RECORDS, SALT["Y"])
STREAM_L = stream_id(TYPE_LORO, SALT["L"])
STREAM_B = stream_id(TYPE_BLOBS, SALT["B"])
OPEN = {STREAM_X: (TYPE_RECORDS, SALT["X"]), STREAM_Y: (TYPE_RECORDS, SALT["Y"]),
        STREAM_L: (TYPE_LORO, SALT["L"]), STREAM_B: (TYPE_BLOBS, SALT["B"])}
SYSTEM = sha256(b"units/system-stream (stands for 16 random bytes)")[:16]
ROT = {n: example(f"units/rotation/{n}") for n in ("A", "B")}
ROT_KEY = {ROT[n]: example(f"units/rotation/{n}/content") for n in ROT}
GAP_KEY_TIMEOUT = 604800


def signer(name: str):
    return events.signer_for(example(f"units/device/{name}"), name)


def state_key(ids, space: bytes = SPACE, keys=None) -> bytes:
    keys = ROT_KEY if keys is None else keys
    return keygraph.content_key(space, keygraph.canonical(ids), keys.__getitem__)


def nonce(label: str) -> bytes:
    return sha256(b"units/nonce/" + label.encode())[:NONCE_BYTES]


def genesis():
    a = signer("A")
    fields = events.event_fields(KIND_SPACE, a, 1, b"opaque genesis body for units.md")
    return events.sign_fields(fields, a)


def move_record() -> bytes:
    """A move record (ext-restricted-spaces.md, "The move record"): version,
    the space and stream the document moved to, and a cached name."""
    return cbor({1: 1, 2: example("units/carve-out"), 3: sha256(b"units/stream/N")[:16],
                 4: "Budget"})


def unit_case(name: str, built: dict, inner: bytes, key_ref: bytes, k: bytes) -> dict:
    key = body_key(k, built["aad"])
    return {"name": name, "state_key": h(k), "unit_key": h(unit_key(k)),
            "body_key": h(key), "commitment": h(commitment(key)),
            "key_reference": h(key_ref), "inner": h(inner), "aad": h(built["aad"]),
            "nonce": h(built["sealed"][:NONCE_BYTES]), "sealed": h(built["sealed"]),
            "body": h(built["body"]), "event": h(built["event_bytes"]),
            "signed": h(built["signed"]), "id": h(built["id"])}


def parameters() -> dict:
    """units.md, "Limits", the frasil: types and the system stream's types."""
    return {"max_unit_bytes": MAX_UNIT_BYTES, "max_locators": MAX_OBJECTS,
            "max_covers": MAX_COVERS, "max_stubs": MAX_STUBS, "max_excluded": MAX_EXCLUDED,
            "adapter_type_bytes": [1, MAX_TYPE_BYTES], "adapter_type_octets": [0x21, 0x7E],
            "list_events_per_copy": [1, MAX_LIST_EVENTS],
            "body_keys_per_unit": [1, MAX_BODY_KEYS],
            "max_object_bytes": MAX_OBJECT_BYTES, "chunk_bytes": CHUNK_BYTES,
            "sealed_chunk_bytes": SEALED_CHUNK_BYTES,
            "heads_per_statement": [1, MAX_HEADS], "max_statement_bytes": MAX_STATEMENT_BYTES,
            "max_message_items": MAX_IDS, "max_message_bytes": MAX_MESSAGE_BYTES,
            "max_streams_per_space": dict(MAX_STREAMS_PER_SPACE),
            "frasil_types": list(FRASIL_TYPES), "system_types": list(SYSTEM_TYPES)}


def unit_vectors(gid: bytes, key_ref: bytes, k: bytes, person) -> tuple[list, dict]:
    """Nine units, from the content key to the event ID."""
    import identity
    a, b, c = signer("A"), signer("B"), signer("C")
    L, B, Y = OPEN[STREAM_L], OPEN[STREAM_B], OPEN[STREAM_Y]
    list_event = person.log.events[person.id].signed
    cases, built, systems = [], {}, {}

    def add(key, name, u, inner, ref, key_, system=SYSTEM, **extra):
        built[key] = u
        systems[name] = (system, key_)
        cases.append(unit_case(name, u, inner, ref, key_) | extra)

    inner = encode_inner(TYPE_LORO, b"loro content stand-in", opening=L)
    u1 = make_unit(a, gid, 2, gid, [gid], STREAM_L, key_ref, k, inner, nonce("u1"))
    add("plain", "a plain unit", u1, inner, key_ref, k)

    o1 = sha256(b"units/object/1") + sha256(b"units/object/1/digest")
    o2 = sha256(b"units/object/2") + sha256(b"units/object/2/digest")
    inner = encode_inner(TYPE_BLOBS, b"blobs content stand-in", opening=B)
    u2 = make_unit(b, gid, 1, None, [u1["id"]], STREAM_B, key_ref, k, inner, nonce("u2"),
                   objects=[o1, o2])
    add("objects", "a unit naming two objects", u2, inner, key_ref, k,
        locators=[h(o1), h(o2)])

    inner = encode_inner(TYPE_LIST, list_copy_content([list_event]))
    u3 = make_unit(a, gid, 3, u1["id"], [u1["id"], u2["id"]], SYSTEM, key_ref, k, inner,
                   nonce("u3"))
    add("list_copy", "a list copy carrying a device-list genesis", u3, inner, key_ref, k,
        list_event_id=h(person.id))

    pairs = [(sha256(b"units/space-event/1"), sha256(b"units/body-key/1")),
             (sha256(b"units/space-event/2"), sha256(b"units/body-key/2"))]
    inner = encode_inner(TYPE_BODY_KEYS, body_keys_content(pairs))
    u4 = make_unit(a, gid, 4, u3["id"], [u3["id"]], SYSTEM, key_ref, k, inner, nonce("u4"),
                   stream_prev=u3["id"])
    add("body_keys", "a body-keys unit", u4, inner, key_ref, k)

    inner = encode_inner(TYPE_MOVE, move_record(), padding=3, opening=L)
    u5 = make_unit(b, gid, 2, u2["id"], [u2["id"], u4["id"]], STREAM_L, key_ref, k, inner,
                   nonce("u5"))
    add("move", "a move unit with padding", u5, inner, key_ref, k)

    person_log, person_head = example("units/person-log"), example("units/person-head")
    inner = encode_inner(TYPE_LORO, b"same content again", resubmits=u1["id"], opening=L,
                         refs=[(person_log, person_head)])
    u6 = make_unit(c, gid, 1, None, [u5["id"]], STREAM_L, key_ref, k, inner, nonce("u6"))
    add("resubmission", "a re-submission with refs", u6, inner, key_ref, k)

    S2 = [ROT["A"], ROT["B"]]
    ref2 = keygraph.encode_set(keygraph.canonical(S2))
    k2 = state_key(S2, gid)  # a merge binds the space of the units' log (keys.md)
    inner = encode_inner(TYPE_RECORDS, b"records content stand-in", opening=Y)
    u7 = make_unit(a, gid, 5, u4["id"], [u4["id"], u6["id"]], STREAM_Y, ref2, k2, inner,
                   nonce("u7"))
    add("merged_state", "a unit under a merged state", u7, inner, ref2, k2)

    restricted = example("units/restricted-space")
    own = [example("units/restricted/rotation")]
    own_secret = example("units/restricted/secret")
    kr = keygraph.restricted_key(restricted, SPACE, own_secret, k)["key"]
    rref = keygraph.seal_restricted_reference(restricted, tuple(own), (ROT["A"],), own_secret,
                                              nonce("parent-ref"))
    rgen = example("units/restricted/genesis")
    inner = encode_inner(TYPE_LORO, b"private folder content", opening=L)
    u8 = make_unit(a, restricted, 2, rgen, [rgen], STREAM_L, rref, kr, inner, nonce("u8"))
    add("restricted", "a unit of a restricted space", u8, inner, rref, kr,
        restricted_space=h(restricted), own_secret=h(own_secret))

    # A recovery entry of the personal space, written by the person's first
    # device in that space's system stream: the recovery key's fetch key.
    personal = identity.personal_space_fixture(person.id)
    personal_system = sha256(b"units/personal/system-stream (stands for 16 random bytes)")[:16]
    prot = example("units/personal/rotation")
    pkeys = {prot: example("units/personal/rotation/content")}
    pref = keygraph.encode_set([prot])
    pk = state_key([prot], personal, pkeys)
    rk = identity.recovery_keys(example("units/recovery/secret"))
    entry = recovery_entry_content(personal, rk["fetch_key"], member=rk["device_id"])
    read = read_recovery_entry_content(entry, personal, active_members={rk["device_id"]})
    assert read["outcome"] == "read", read
    pgen = example("units/personal/genesis")
    inner = encode_inner(TYPE_RECOVERY_ENTRY, entry)
    u10 = make_unit(person.hist.signer("Q"), personal, 2, pgen, [pgen],
                    personal_system, pref, pk, inner, nonce("u10"))
    add("recovery_entry", "a recovery-entry unit of a personal space", u10, inner, pref, pk,
        system=personal_system, personal_space=h(personal),
        personal_system_stream=h(personal_system), entry=h(entry),
        recovery_key={"device_id": h(rk["device_id"]), "fetch_key": h(rk["fetch_key"])})

    for case in cases:
        system, key_ = systems[case["name"]]
        signed = bytes.fromhex(case["signed"])
        opened = open_unit(signed, key_, system)
        stream = read_body(events.decode_event(signed).body)[B_STREAM]
        case["content_check"] = content_check(stream, system, opened)
        assert case["content_check"] == "accepted", case["name"]
    assert len(cases) == 9
    return cases, built


def list_events_vectors(person) -> dict:
    """A read-only person's list events: the frasil/list-events body and its
    ListEvents message, and a body with an event the writer drops."""
    import identity
    stranger = identity.Person("R", prefix="units/person")
    named = person.log.events[person.id].signed
    unnamed = stranger.log.events[stranger.id].signed
    persons = {person.id}
    body = list_events_body(SPACE, [named])
    assert read_list_events_body(body) == (SPACE, [named])
    msg = message(M_LIST_EVENTS, SPACE, k2=[named])
    assert read_message(msg)["name"] == "ListEvents"
    kept = forward_list_events([named], persons)
    mixed = list_events_body(SPACE, [named, unnamed])
    _, listed = read_list_events_body(mixed)
    decisions = forward_list_events(listed, persons)
    assert [d["decision"] for d in decisions] == ["forwarded in a frasil:list unit", "dropped"]

    def show(rows):
        return [{k_: (h(v) if isinstance(v, bytes) else v) for k_, v in r.items()} for r in rows]

    return {"content_name": LIST_EVENTS_CONTENT_NAME, "space": h(SPACE),
            "roster_persons": [h(person.id)],
            "body": {"events": [h(named)], "bytes": h(body), "decisions": show(kept)},
            "message": {"type": M_LIST_EVENTS, "name": "ListEvents", "bytes": h(msg)},
            "dropped": {"case": "a body with an event of a person the space's roster never "
                                "named: the writer drops that event and forwards the other",
                        "events": [h(named), h(unnamed)], "unnamed_person": h(stranger.id),
                        "bytes": h(mixed), "decisions": show(decisions)}}


def unit_refusal_vectors(gid: bytes, key_ref: bytes, k: bytes, good_body: bytes,
                         list_event: bytes) -> list:
    """Units refused by units.md's "A unit, at a peer" and "A unit, at a
    member", each with its class."""
    a, b = signer("A"), signer("B")
    L = OPEN[STREAM_L]
    o1 = sha256(b"units/object/1") + sha256(b"units/object/1/digest")
    o2 = sha256(b"units/object/2") + sha256(b"units/object/2/digest")
    out = []

    def bad(name, signed, cls, key=k):
        def run():
            peer_check(signed)
            open_unit(signed, key, SYSTEM)
        got = expect_error(run)
        assert got == cls, (name, got, cls)
        out.append({"name": name, "signed": h(signed), "class": cls})

    def with_body(name, body_value, cls, *, raw=None, key=k):
        body = raw if raw is not None else cbor(body_value)
        fields = events.event_fields(KIND_UNIT, a, 2, body, log=gid, prev=gid,
                                     parents=[gid])
        bad(name, events.sign_fields(fields, a), cls, key)

    good = uncbor(good_body)
    with_body("version 2", good | {1: 2}, "UnsupportedVersion")
    with_body("no stream", {k_: v for k_, v in good.items() if k_ != 2}, "Malformed")
    with_body("a stream of all zeros", good | {2: bytes(16)}, "Malformed")
    with_body("a stream of 15 bytes", good | {2: bytes(range(1, 16))}, "Malformed")
    with_body("an unknown key 9", good | {9: b""}, "Malformed")
    with_body("a key reference of 65 rotations", good | {3: bytes([65]) + bytes(32 * 65)},
              "TooManyRotations")
    high, low = max(ROT.values()), min(ROT.values())
    with_body("a key reference not ascending", good | {3: bytes([2]) + high + low}, "Malformed")
    with_body("objects not ascending", good | {5: [max(o1, o2), min(o1, o2)]}, "Malformed")
    with_body("an object named by a 32-byte ID, not a locator", good | {5: [o1[:32]]},
              "Malformed")
    with_body("a seal of 71 bytes", good | {7: bytes(71)}, "Malformed")
    with_body("compacts whose object is not in objects",
              good | {6: encode_compacts(o1, [], [])}, "Malformed")
    with_body("covers not ascending", good | {5: [o1], 6: {1: o1, 2: sorted(
        [[b.device_id, gid], [a.device_id, gid]], reverse=True), 3: []}}, "Malformed")
    with_body("a stub with seq 0", good | {5: [o1], 6: {1: o1, 2: [], 3: [
        [gid, a.device_id, 0, 1, KIND_UNIT]]}}, "Malformed")
    for kind in (2, 5, 6):
        with_body(f"a stub of kind {kind}", good | {5: [o1], 6: {1: o1, 2: [], 3: [
            [gid, a.device_id, 1, 1, kind]]}}, "Malformed")
    with_body("a body that is not CBOR", None, "Malformed", raw=b"\xff")
    with_body("a seal opened under another state's key", good, "BadSeal",
              key=state_key([ROT["B"]]))
    sealed = good[7]
    other = sealed[:NONCE_BYTES] + bytes(COMMITMENT_BYTES) + sealed[NONCE_BYTES + COMMITMENT_BYTES:]
    with_body("a commitment that is not the body key's", good | {7: other}, "BadSeal")
    big_inner = encode_inner(TYPE_LORO, bytes(MAX_UNIT_BYTES), opening=L)
    big = make_unit(a, gid, 2, gid, [gid], STREAM_L, key_ref, k, big_inner, nonce("big"))
    assert expect_error(peer_check, big["signed"]) == "TooLarge"
    out.append({"name": "a unit over 1,048,576 bytes", "signed_length": len(big["signed"]),
                "class": "TooLarge"})
    op = [TYPE_LORO, L[1]]
    for name, inner_bad in (
            ("an empty type", cbor({1: "", 2: b"", 6: op})),
            ("a type with a space", cbor({1: "my type", 2: b"", 6: op})),
            ("no content", cbor({1: TYPE_LORO, 6: op})),
            ("resubmits and copied_from together", cbor({1: TYPE_LORO, 2: b"", 3: gid,
                                                         4: [SPACE, gid], 6: op})),
            ("excluded in a log unit", cbor({1: TYPE_LORO, 2: b"", 5: [gid], 6: op})),
            ("padding that is not zero", cbor({1: TYPE_LORO, 2: b"", 6: op, 17: b"\x01"})),
            ("refs out of order", cbor({1: TYPE_LORO, 2: b"", 6: op, 18: sorted(
                [[SPACE, gid], [gid, SPACE]], reverse=True)})),
            ("a document unit with no opening", cbor({1: TYPE_LORO, 2: b""})),
            ("an opening with a salt of 15 bytes",
             cbor({1: TYPE_LORO, 2: b"", 6: [TYPE_LORO, L[1][:15]]}))):
        uu = make_unit(a, gid, 2, gid, [gid], STREAM_L, key_ref, k, inner_bad, nonce(name))
        bad(name, uu["signed"], "Malformed")
    sys_with_opening = make_unit(a, gid, 2, gid, [gid], SYSTEM, key_ref, k,
                                 encode_inner(TYPE_LIST, list_copy_content([list_event]),
                                              opening=L), nonce("sys-opening"))
    bad("a system unit with an opening", sys_with_opening["signed"], "Malformed")
    assert len(out) == 30
    return out


def handed_body_key_vectors(plain: dict, k: bytes) -> dict:
    """units.md, "A unit, at a member", steps 13 and 14, and "Frasil's own
    units", body keys: a member that does not hold k(S) opens a unit under
    its handed body key, and holds it under a key that misses the
    commitment."""
    key = body_key(k, plain["aad"])
    opened = open_unit(plain["signed"], None, SYSTEM, handed=key)
    wrong = hkdf(NO_SALT, key, b"units/a wrong body key")
    got = expect_error(open_unit, plain["signed"], None, SYSTEM, handed=wrong)
    assert got == "Sealed", got
    return {"signed": h(plain["signed"]), "body_key": h(key),
            "opened": {"type": opened[I_TYPE], "content": h(opened[I_CONTENT])},
            "wrong_key": h(wrong), "wrong_key_class": got}


def stream_type_vectors(gid: bytes, key_ref: bytes, k: bytes) -> dict:
    """units.md, "A unit, at a member", the stream check: an honest Records
    stream, and a writer that backdates a unit of another type into it. Each
    unit is judged alone, so the verdicts hold in either canonical order."""
    d = signer("D")
    X = OPEN[STREAM_X]
    own = (TYPE_LORO, SALT["Z"])
    rows = []
    for name, inner, opening in (
            ("an honest unit", encode_inner(TYPE_RECORDS, b"honest changeset", opening=X), X),
            ("a backdated Loro unit with its own opening",
             encode_inner(TYPE_LORO, b"loro", opening=own), own),
            ("a Loro unit under the stream's true opening",
             encode_inner(TYPE_LORO, b"loro", opening=X), X),
            ("a move unit under the stream's opening",
             encode_inner(TYPE_MOVE, move_record(), opening=X), X)):
        u = make_unit(d, gid, 1, None, [gid], STREAM_X, key_ref, k, inner, nonce("st/" + name))
        opened = open_unit(u["signed"], k, SYSTEM)
        rows.append({"case": name, "stream": h(STREAM_X), "type": opened[I_TYPE],
                     "opening": {"type": opening[0], "salt": h(opening[1]),
                                 "hashes_to": h(stream_id(*opening))},
                     "signed": h(u["signed"]), "verdict": check_stream(STREAM_X, opened)})
    assert [r["verdict"] for r in rows] == ["accepted", "StreamMismatch", "WrongAdapter",
                                            "accepted"]
    return {"label": h(STREAM_ID_LABEL),
            "streams": [{"type": t, "salt": h(sa), "stream": h(sid)}
                        for sid, (t, sa) in sorted(OPEN.items(), key=lambda x: x[1])],
            "cases": rows}


def object_vectors(k: bytes, key_ref: bytes) -> tuple[dict, list]:
    small = b"an attachment of one chunk"
    one = seal_object(SPACE, k, key_ref, small)
    assert read_object(one["bytes"], SPACE, k, one["locator"]) == small
    big = bytes(range(150))
    three = seal_object(SPACE, k, key_ref, big, chunk=64)
    assert read_object(three["bytes"], SPACE, k, three["locator"], chunk=64) == big
    empty = seal_object(SPACE, k, key_ref, b"")
    assert read_object(empty["bytes"], SPACE, k, empty["locator"]) == b""
    # Two writers that upload one plaintext under one state compute one locator.
    again = seal_object(SPACE, k, key_ref, small)
    assert again["locator"] == one["locator"]
    # The object key alone opens the object, and opens no other.
    assert read_object(three["bytes"], SPACE, None, three["locator"], chunk=64,
                       okey=three["object_key"]) == big
    assert expect_error(read_object, three["bytes"], SPACE, None, three["locator"], 64,
                        one["object_key"]) == "Decrypt"

    def show(name, o, plaintext, chunk):
        return {"name": name, "chunk_bytes": chunk, "plaintext": h(plaintext),
                "keys": {n: h(v) for n, v in o["keys"].items()}, "id": h(o["id"]),
                "object_key": h(o["object_key"]),
                "digest": h(o["digest"]), "locator": h(o["locator"]),
                "header": h(o["header"]),
                "chunks": [{"index": c["index"], "aad": h(c["aad"]), "nonce": h(c["nonce"]),
                            "sealed": h(c["sealed"])} for c in o["chunks"]],
                "bytes": h(o["bytes"])}

    refusals = []

    def refuse(name, data, cls, want=None, key=k, chunk=64):
        # The locator a unit would name for these bytes, unless the case gives one.
        want = want if want is not None else three["id"] + sha256(data)
        got = expect_error(read_object, data, SPACE, key, want, chunk)
        assert got == cls, (name, got, cls)
        refusals.append({"name": name, "chunk_bytes": chunk, "locator": h(want),
                         "bytes": h(data), "class": cls})

    d = three["bytes"]
    hl = int.from_bytes(d[:4], "big")
    head, chunks = d[:4 + hl], d[4 + hl:]
    first, second, third = chunks[:104], chunks[104:208], chunks[208:]
    refuse("another object's ID under these bytes' digest", d, "ObjectMismatch",
           want=one["id"] + sha256(d))
    junk = u32be(len(three["header"])) + three["header"] + bytes(len(chunks))
    refuse("junk uploaded under the object's ID: another digest", junk, "ObjectMismatch",
           want=three["locator"])
    refuse("the last chunk dropped", head + first + second, "Malformed")
    refuse("two chunks swapped", head + second + first + third, "Decrypt")
    refuse("a byte changed in a chunk",
           head + first[:-1] + bytes([first[-1] ^ 1]) + second + third, "Decrypt")
    hdr = uncbor(three["header"])
    h2 = cbor(hdr | {1: 2})
    refuse("header version 2", u32be(len(h2)) + h2 + chunks, "UnsupportedVersion")
    h3 = cbor(hdr | {4: 151})
    refuse("a size one larger", u32be(len(h3)) + h3 + chunks, "Malformed")
    refuse("a state this reader lacks", d, "Sealed", key=None)
    refuse("a header length past the end", u32be(10 ** 6) + d[4:], "Malformed")
    assert len(refusals) == 9
    return ({"chunk_bytes": CHUNK_BYTES,
             "cases": [show("one chunk", one, small, CHUNK_BYTES),
                       show("three chunks, the chunk size lowered to 64", three, big, 64),
                       show("empty", empty, b"", CHUNK_BYTES)]},
            refusals)


def compaction_vectors(k: bytes, key_ref: bytes) -> dict:
    """units.md, "Compacting" and "Placing against stubs": three writers in
    two streams, a snapshot unit by C in X, its covers and boundary stubs,
    and placement against them."""
    g = genesis()
    gid = events.decode_event(g).id
    a, b, c = signer("A"), signer("B"), signer("C")
    rep = Replica(g)
    names = {gid: "g"}

    def put(name, s, seq, prev, parents, stream, stream_prev=None, **kw):
        inner = encode_inner(TYPE_RECORDS, name.encode(), opening=OPEN[stream])
        u = make_unit(s, gid, seq, prev, parents, stream, key_ref, k, inner, nonce("c/" + name),
                      stream_prev=stream_prev, **kw)
        rep.add(u["signed"])
        names[u["id"]] = name
        return u

    a1 = put("a1", a, 2, gid, [gid], STREAM_X)
    b1 = put("b1", b, 1, None, [a1["id"]], STREAM_X)
    c1 = put("c1", c, 1, None, [a1["id"]], STREAM_Y)
    a2 = put("a2", a, 3, a1["id"], [a1["id"], b1["id"], c1["id"]], STREAM_Y)
    b2 = put("b2", b, 2, b1["id"], [a2["id"], b1["id"]], STREAM_X, stream_prev=b1["id"])
    b3 = put("b3", b, 3, b2["id"], [b2["id"]], STREAM_Y)  # concurrent with the snapshot
    # The snapshot unit s by C in X, citing b2 and its own c1.
    parents = [b2["id"], c1["id"]]
    covers = rep.covers(parents, STREAM_X)
    cover = rep.cover_set(covers, STREAM_X)
    stubs = rep.boundary_stubs(cover, outside_extra=[parents])
    snapshot_plain = stream_snapshot(TYPE_RECORDS, STREAM_X, b"records state stand-in")
    obj = seal_object(SPACE, k, key_ref, snapshot_plain)
    compacts = encode_compacts(obj["locator"], covers, stubs)
    s_inner = encode_inner(TYPE_RECORDS, b"", excluded=[b1["id"]], opening=OPEN[STREAM_X])
    s = make_unit(c, gid, 2, c1["id"], parents, STREAM_X, key_ref, k, s_inner, nonce("c/s"),
                  objects=[obj["locator"]], compacts=compacts)
    rep.add(s["signed"])
    names[s["id"]] = "s"
    # A later unit by A in X, after s.
    a3 = put("a3", a, 4, a2["id"], [a2["id"], s["id"], b3["id"]], STREAM_X, stream_prev=a1["id"])
    # A newcomer holds g, s, the Y units, a3, and only s's stubs for the cover.
    newcomer = [s["signed"], c1["signed"], a2["signed"], b3["signed"], a3["signed"]]
    placed = place_against_stubs(newcomer, stubs, g)
    assert not placed["pending"], [names.get(i) for i in placed["pending"]]
    for i, height in placed["heights"].items():
        assert rep.log.height[i] == height, names.get(i)
    # Without the stubs, the newcomer cannot place them.
    unplaced = place_against_stubs(newcomer, [], g)
    assert unplaced["pending"]
    order = rep.log.canonical()
    return {
        "events": [{"name": names[i], "id": h(i),
                    "signed": h(rep.ev(i).signed), "height": rep.log.height[i],
                    "stream": h(rep.stream_of(i)) if rep.stream_of(i) else None}
                   for i in order],
        "snapshot_unit": {"name": "s", "parents": [names[p] for p in sorted(parents)],
                          "covers": [{"writer": h(w), "unit": names[u]} for w, u in covers],
                          "cover": sorted(names[i] for i in cover),
                          "stubs": [{"event": names[st[0]], "stub": [h(st[0]), h(st[1]), st[2],
                                                                     st[3], st[4]]}
                                    for st in stubs],
                          "excluded": ["b1"],
                          "excluded_note": "as if the compactor had refused b1: the format only",
                          "object": h(obj["locator"]),
                          "compacts": h(cbor(compacts)), "signed": h(s["signed"])},
        "newcomer": {"holds": ["g", "s", "c1", "a2", "b3", "a3"],
                     "pending_without_stubs": sorted(names[i] for i in unplaced["pending"]),
                     "heights_with_stubs": {names[i]: v for i, v in placed["heights"].items()
                                            if i in names},
                     "agrees_with_full_replica": True},
        "canonical_order": [names[i] for i in order],
    }


def snapshot_vectors(k: bytes, key_ref: bytes, list_event: bytes):
    plain = stream_snapshot(TYPE_RECORDS, STREAM_X, b"records state", history_free=True)
    read_stream_snapshot(plain, STREAM_X, TYPE_RECORDS)
    obj = seal_object(SPACE, k, key_ref, plain)
    stream_refusals = []
    for name, value, cls in (
            ("version 2", uncbor(plain) | {1: 2}, "UnsupportedVersion"),
            ("another stream", uncbor(plain) | {3: STREAM_Y}, "Malformed"),
            ("another type", uncbor(plain) | {2: TYPE_LORO}, "Malformed"),
            ("history_free 2", uncbor(plain) | {4: 2}, "Malformed")):
        got = expect_error(read_stream_snapshot, cbor(value), STREAM_X, TYPE_RECORDS)
        assert got == cls
        stream_refusals.append({"name": name, "plaintext": h(cbor(value)), "class": cls})
    stream = {"type": TYPE_RECORDS, "stream": h(STREAM_X), "plaintext": h(plain),
              "object_id": h(obj["id"]), "locator": h(obj["locator"]), "object": h(obj["bytes"]),
              "refusals": stream_refusals}

    sender = signer("A")
    base = sorted([sha256(b"units/base/1"), sha256(b"units/base/2")])
    stubs = sorted([(sha256(b"units/base/stub/0"), signer("C").device_id, 3, 9, KIND_UNIT,
                     STREAM_X),
                    (sha256(b"units/base/stub/1"), signer("B").device_id, 7, 12, KIND_UNIT,
                     STREAM_Y)])
    body_keys = [(sha256(b"units/space-event/1"), sha256(b"units/body-key/1"))]
    logs = [{1: example("units/team"), 2: [], 3: [], 4: []}]
    entry = stream_entry(STREAM_X, OPEN[STREAM_X], obj["locator"], key_ref,
                         [(signer("B").device_id, sha256(b"units/base/1"))])
    # A fork shown only in units: C signs two units at sequence number 1.
    c = signer("C")
    gid = sha256(b"units/base/genesis")
    fork = [make_unit(c, SPACE, 1, None, [gid], STREAM_Y, key_ref, k,
                      encode_inner(TYPE_RECORDS, label.encode(), opening=OPEN[STREAM_Y]),
                      nonce("fork/" + label))
            for label in ("one", "two")]
    first, second = sorted(fork, key=lambda f: f["id"])
    proof = events.make_proof(events.PROOF_DUPLICATE, first["signed"], second["signed"])
    shown = events.verify_proof(proof)
    snap = space_snapshot_map(SPACE, sender.signer_bytes, base, stubs, body_keys, [list_event], logs,
                              [entry], system=SYSTEM, proofs=[proof])
    signed = sign_space_snapshot(sender, snap)
    ok = read_space_snapshot(signed, SPACE, [sender.keys])
    assert not ok["provisional"]
    assert read_space_snapshot(signed, SPACE, [])["provisional"]
    assert read_space_snapshot(signed, SPACE, [c.keys])["provisional"]
    refusals = []
    for name, data, cls in (
            ("another space", signed, "WrongSpace"),
            ("a signature changed", cbor([snap, bytes([uncbor(signed)[1][0] ^ 1])
                                          + uncbor(signed)[1][1:]]), "BadSignature"),
            ("version 2", sign_space_snapshot(sender, cbor(uncbor(snap) | {1: 2})),
             "UnsupportedVersion"),
            ("an empty base", sign_space_snapshot(sender, cbor(uncbor(snap) | {4: []})),
             "Malformed"),
            ("a stream entry whose opening gives another stream",
             sign_space_snapshot(sender, cbor(uncbor(snap) | {9: [entry | {2: list(OPEN[STREAM_Y])}]})),
             "Malformed")):
        space = example("units/other-space") if name == "another space" else SPACE
        got = expect_error(read_space_snapshot, data, space, [sender.keys])
        assert got == cls, (name, got)
        refusals.append({"name": name, "space": h(space), "signed": h(data), "class": cls})
    space_snap = {"space": h(SPACE), "sender": h(sender.signer_bytes),
                  "sender_device_id": h(sender.device_id),
                  "sender_mldsa": h(sender.mldsa_public), "sender_xwing": h(sender.xwing_public), "system_stream": h(SYSTEM),
                  "list_event": h(list_event),
                  "proof": {"bytes": h(proof), "author": h(c.device_id),
                            "events": [h(first["id"]), h(second["id"])],
                            "verify_proof": {k_: (h(v) if isinstance(v, bytes) else v)
                                             for k_, v in sorted(shown.items())}},
                  "snapshot": h(snap), "tbs_prefix": h(SPACE_SNAPSHOT_LABEL),
                  "signed": h(signed),
                  "outcomes": [{"keys_held": "the sender's, which hash to its kc",
                                "outcome": "accepted"},
                               {"keys_held": "none", "outcome": "provisional"},
                               {"keys_held": "another device's, which hash to another kc",
                                "outcome": "provisional"}],
                  "refusals": refusals}
    return stream, space_snap


def _signed(kind: int, signer_, seq: int, body: bytes, parents, cuts=(), prev=None) -> bytes:
    fields = events.event_fields(kind, signer_, seq, body, log=SPACE, prev=prev,
                                 parents=parents, cuts=cuts)
    return events.sign_fields(fields, signer_)


def checkpoint_format_vectors(k: bytes, key_ref: bytes, list_event: bytes) -> dict:
    """units.json's `record_objects`, `stubs_with_cuts` and
    `snapshot_checkpoint` families: a checkpoint's record object, whose
    header names the checkpoint by its self reference; stubs that carry
    cuts; and a space snapshot that names a checkpoint (keys 12 to 14)."""
    a = signer("A")
    # -- the record object: sealed under the checkpoint's own content key,
    # its header the self reference of the checkpoint A signs at seq 5.
    own = sha256(b"units/checkpoint/content-key")
    ref = keygraph.self_ref(a.device_id, 5)
    plain = b"a checkpoint record, as roster.md encodes it"
    obj = seal_object(SPACE, own, ref, plain)
    assert read_object(obj["bytes"], SPACE, own, obj["locator"], record=True,
                       self_ref=ref) == plain
    assert read_object(obj["bytes"], SPACE, None, obj["locator"], record=True, self_ref=ref,
                       okey=obj["object_key"]) == plain
    assert read_object(obj["bytes"], SPACE, None, obj["locator"], peer=True) == b""
    ordinary = seal_object(SPACE, k, key_ref, plain)
    bad_ref = seal_object(SPACE, own, ref[:-1], plain, chunk=CHUNK_BYTES)
    obj_refusals = []
    for name, data, want, kw, cls in (
            ("the self reference of another seq: the checkpoint at seq 6", obj["bytes"],
             obj["locator"], {"record": True, "self_ref": keygraph.self_ref(a.device_id, 6)},
             "BadCheckpoint"),
            ("the self reference of another author", obj["bytes"], obj["locator"],
             {"record": True, "self_ref": keygraph.self_ref(signer("B").device_id, 5)},
             "BadCheckpoint"),
            ("a record object read as any other object", obj["bytes"], obj["locator"], {},
             "Malformed"),
            ("an object under a key reference read as a record", ordinary["bytes"],
             ordinary["locator"], {"record": True, "self_ref": ref}, "Malformed"),
            ("a self reference of 40 bytes, at a peer", bad_ref["bytes"], bad_ref["locator"],
             {"peer": True}, "Malformed")):
        key = None if kw.get("peer") else (k if data is ordinary["bytes"] else own)
        got = expect_error(read_object, data, SPACE, key, want, **kw)
        assert got == cls, (name, got)
        obj_refusals.append({"name": name, "object": h(data), "locator": h(want),
                             "reader": "peer" if kw.get("peer") else
                             ("record" if kw.get("record") else "member"),
                             "self_ref": h(kw["self_ref"]) if "self_ref" in kw else None,
                             "class": cls})
    records = {"space": h(SPACE), "author": h(a.device_id), "seq": 5, "self_ref": h(ref),
               "content_key": h(own), "plaintext": h(plain), "header": h(obj["header"]),
               "object_key": h(obj["object_key"]), "locator": h(obj["locator"]),
               "object": h(obj["bytes"]),
               "accepted": ["a member reading the record with the checkpoint's content key",
                            "a newcomer with the record's object key alone",
                            "a peer, steps 0 to 4"],
               "refusals": obj_refusals}

    # -- stubs with cuts.
    c1, c2 = sorted([sha256(b"units/cut/1"), sha256(b"units/cut/2")])
    b = signer("B")
    gid = sha256(b"units/base/genesis")
    prev = sha256(b"units/stubbed/prev")
    unit = _signed(KIND_UNIT, b, 4, b"a unit body", [gid, prev], cuts=[c1], prev=prev)
    ue = events.decode_event(unit)
    five = [ue.id, b.device_id, 4, 7, KIND_UNIT]
    stub_cases = []
    for name, container, stub, cls in (
            ("a snapshot unit's stub without cuts", "snapshot unit", five[:], None),
            ("a snapshot unit's stub with cuts", "snapshot unit", five + [[c1]], None),
            ("a snapshot unit's stub with two cuts", "snapshot unit", five + [[c1, c2]], None),
            ("a snapshot unit's stub whose sixth element is a stream", "snapshot unit",
             five + [STREAM_X], "Malformed"),
            ("a snapshot unit's stub with five cuts", "snapshot unit",
             five + [sorted(sha256(bytes([i])) for i in range(5))], "Malformed"),
            ("a snapshot unit's stub with cuts out of order", "snapshot unit",
             five + [[c2, c1]], "Malformed"),
            ("a snapshot unit's stub with an empty cuts array", "snapshot unit", five + [[]],
             "Malformed"),
            ("a space snapshot's stub without cuts", "space snapshot", five + [STREAM_X], None),
            ("a space snapshot's stub with cuts", "space snapshot", five + [STREAM_X, [c1]],
             None),
            ("a space snapshot's stub with cuts and no stream", "space snapshot",
             five + [[c1]], "Malformed"),
            ("a space snapshot's stub whose seventh element is bytes", "space snapshot",
             five + [STREAM_X, c1], "Malformed")):
        reader = read_compaction_stubs if container == "snapshot unit" else read_snapshot_stubs
        got = expect_error(reader, [stub]) if cls else (reader([stub]) and None)
        assert got == cls, (name, got)
        stub_cases.append({"name": name, "container": container, "stub": h(cbor(stub)),
                           "class": cls or "accepted"})
    compares = []
    for name, stub, height in (
            ("the unit's own stub, with its cut", five + [STREAM_X, [c1]], 7),
            ("a stub without the unit's cut", five + [STREAM_X], 7),
            ("a stub with another cut", five + [STREAM_X, [c2]], 7),
            ("a stub with another height", five + [STREAM_X, [c1]], 8),
            ("a snapshot unit's stub, five elements and its cut", five + [[c1]], 7)):
        got = stub_mismatch(stub, ue, height)
        compares.append({"name": name, "stub": h(cbor(stub)), "height": height,
                         "verdict": got or "match"})
    assert [c["verdict"] for c in compares] == ["match", "BadStub", "BadStub", "BadStub",
                                                 "match"]
    stubs = {"unit": h(unit), "unit_id": h(ue.id), "cuts": [h(c1)], "reading": stub_cases,
             "comparing": compares}

    # -- a space snapshot that names a checkpoint: key 12, the checkpoint in
    # effect at the base; key 13, its record's object key; key 14, the
    # checkpoints its cuts reach, as signed space events.
    p = signer("C")
    first = _signed(KIND_SPACE, p, 1, b"an earlier checkpoint", [gid])
    e1 = events.decode_event(first)
    second = _signed(KIND_SPACE, p, 2, b"another earlier checkpoint", [e1.id], cuts=[e1.id],
                     prev=e1.id)
    e2 = events.decode_event(second)
    checkpoint = sha256(b"units/checkpoint/id")
    chain = sorted([first, second], key=lambda x: events.decode_event(x).id)
    base = [sha256(b"units/base/1")]
    unit_stub = (ue.id, b.device_id, 4, 7, KIND_UNIT, STREAM_X, [c1])
    snap = uncbor(space_snapshot_map(SPACE, a.signer_bytes, base, [unit_stub], [], [list_event],
                                     [], [], system=SYSTEM))
    full = snap | {12: checkpoint, 13: obj["object_key"], 14: chain,
                   15: [events.decode_event(list_event).id]}
    signed = sign_space_snapshot(a, cbor(full))
    got = read_space_snapshot(signed, SPACE, [a.keys])
    assert not got["provisional"] and got["value"][12] == checkpoint
    snap_refusals = []
    for name, value in (
            ("key 13 without key 12", snap | {13: obj["object_key"]}),
            ("key 14 without key 12", snap | {14: []}),
            ("key 12 without key 13", snap | {12: checkpoint}),
            ("key 14 out of order", full | {14: list(reversed(chain))}),
            ("key 14 holding a unit", full | {14: [unit]}),
            ("key 14 holding bytes that are no event", full | {14: [b"no event"]}),
            ("key 15 empty", full | {15: []}),
            ("key 15 naming an event key 7 does not carry", full | {15: [bytes(32)]})):
        data = sign_space_snapshot(a, cbor(value))
        cls = expect_error(read_space_snapshot, data, SPACE, [a.keys])
        assert cls == "Malformed", (name, cls)
        snap_refusals.append({"name": name, "signed": h(data), "class": cls})
    snapshot = {"space": h(SPACE), "sender": h(a.signer_bytes), "checkpoint": h(checkpoint),
                "record_key": h(obj["object_key"]),
                "cut_chain": [h(events.decode_event(x).id) for x in chain],
                "placed": [h(events.decode_event(list_event).id)],
                "signed": h(signed), "outcome": "accepted", "refusals": snap_refusals}
    assert e2.cuts == (e1.id,) or list(e2.cuts) == [e1.id]
    return {"record_objects": records, "stubs_with_cuts": stubs, "snapshot_checkpoint": snapshot}


def statement_vectors(gid: bytes, uid: bytes) -> dict:
    b = signer("B")
    seed, device, member = b.ed_seed, b.signer_bytes, b.device_id
    st = head_statement(SPACE, device, [uid], streams=[(STREAM_X, [(member, uid)])])
    signed = sign_statement(seed, st)
    assert read_statement(signed, SPACE, {member})[3] == device
    # B's Ed25519 key under another kc: another device, though B's key signs.
    other_kc = hs.keys_commitment(signer("C").mldsa_public, signer("C").xwing_public)
    refusals = []
    for name, data, members, cls in (
            ("a device that is not a member", signed, set(), "NotAMember"),
            ("another space", sign_statement(seed, head_statement(example("units/other-space"),
                                                                  device, [uid])), {member},
             "WrongSpace"),
            ("no heads", sign_statement(seed, cbor({1: 1, 2: SPACE, 3: device, 4: []})),
             {member}, "Malformed"),
            ("the signature of another statement", cbor([head_statement(SPACE, device, [gid]),
                                                         uncbor(signed)[1]]), {member},
             "BadSignature"),
            ("B's Ed25519 key under another kc: another device ID, not a member",
             sign_statement(seed, head_statement(SPACE, b.ed_public + other_kc, [uid])),
             {member}, "NotAMember")):
        got = expect_error(read_statement, data, SPACE, members)
        assert got == cls, (name, got)
        refusals.append({"name": name, "signed": h(data), "class": cls})
    return {"space": h(SPACE), "seed": h(seed), "device": h(device), "device_id": h(member),
            "statement": h(st), "tbs_prefix": h(HEAD_STATEMENT_LABEL), "signed": h(signed),
            "refusals": refusals}


def sent_after_heads(kind: int, stream: bytes | None, streams: list | None,
                     system: bytes) -> bool:
    """units.md, "Sync", the exchange, step 1: whether an event the other side
    lacks is sent in answer to its `Heads`. With key 4, a partial replica's
    `Heads`, only its frame and the streams key 4 names."""
    if streams is None or kind != KIND_UNIT:
        return True
    return stream == system or stream in streams


def message_vectors(gid: bytes, u1: dict, u2: dict, k: bytes, key_ref: bytes,
                    statement: bytes, snapshot: bytes, list_event: bytes) -> dict:
    a = signer("A").device_id
    oid = sha256(b"units/object/1") + sha256(b"units/object/1/digest")
    obj = seal_object(SPACE, k, key_ref, b"an attachment of one chunk")
    samples = [
        message(M_HEADS, SPACE, k2=sorted([u1["id"], u2["id"]]),
                k3=[[a, 2, u1["id"]]]),
        message(M_WANT, SPACE, k3=[[a, 1, 2]], k4=[2, 4]),
        message(M_EVENTS, SPACE, k2=[u1["signed"]]),
        message(M_MISSING, SPACE, k3=[[u1["id"], u2["id"]]]),
        message(M_ACK, SPACE, k2=[u2["id"]]),
        message(M_STREAM_HEADS, SPACE, k2=STREAM_X, k4=[[a, u1["id"], 2]]),
        message(M_STREAM_WANT, SPACE, k2=STREAM_X, k3=[], k4=1),
        message(M_OBJECT_WANT, SPACE, k2=oid, k3=0, k4=4),
        message(M_OBJECT_CHUNKS, SPACE, k2=obj["locator"], k3=obj["header"], k4=0,
                k5=obj["chunks"][0]["sealed"]),
        message(M_OBJECT_HAVE, SPACE, k2=[oid], k3=[3]),
        message(M_PATH_WANT, SPACE, k2=u2["id"], k3=gid),
        message(M_PATH, SPACE, k2=u2["id"], k3=gid, k4=[u1["signed"]]),
        message(M_SUBSCRIBE, SPACE, k2=[STREAM_X]),
        message(M_STATEMENT, SPACE, k2=[statement]),
        message(M_SNAPSHOT_WANT, SPACE, k2=[STREAM_X]),
        message(M_SNAPSHOT_OFFER, SPACE, k2=snapshot),
        message(M_LIST_EVENTS, SPACE, k2=[list_event]),
    ]
    cases = []
    for data in samples:
        r = read_message(data)
        cases.append({"name": r["name"], "type": r["type"],
                      "member_connections_only": r["type"] in MEMBER_ONLY, "bytes": h(data)})
    assert [c_["type"] for c_ in cases] == list(range(1, 18))
    assert check_path([u1["signed"]], events.decode_event(u2["signed"]), gid)
    refusals = []
    for name, data, cls in (
            ("type 18", message(18, SPACE), "UnknownMessage"),
            ("no space", cbor({0: 1, 2: []}), "Malformed"),
            ("a Want with neither IDs nor ranges", message(M_WANT, SPACE, k4=[4]), "Malformed"),
            ("Heads not ascending", message(M_HEADS, SPACE, k2=sorted([u1["id"], u2["id"]],
                                                                       reverse=True)),
             "Malformed"),
            ("an ObjectWant of 65 chunks", message(M_OBJECT_WANT, SPACE, k2=oid, k3=0, k4=65),
             "Malformed"),
            ("an unknown key", message(M_ACK, SPACE, k2=[u2["id"]], k9=1), "Malformed"),
            ("a range from 3 to 2", message(M_WANT, SPACE, k3=[[a, 3, 2]]), "Malformed")):
        got = expect_error(read_message, data)
        assert got == cls, (name, got)
        refusals.append({"name": name, "bytes": h(data), "class": cls})
    partial = message(M_HEADS, SPACE, k2=[u2["id"]], k4=[STREAM_X])
    assert read_message(partial)["type"] == M_HEADS
    sends = [{"event": name, "sent": sent_after_heads(kind, stream, [STREAM_X], SYSTEM)}
             for name, kind, stream in (
                 ("a space event", KIND_SPACE, None),
                 ("an anchor", events.KIND_ANCHOR, None),
                 ("a unit of the system stream", KIND_UNIT, SYSTEM),
                 ("a unit of a stream key 4 names", KIND_UNIT, STREAM_X),
                 ("a unit of another stream", KIND_UNIT, STREAM_Y))]
    assert [s["sent"] for s in sends] == [True, True, True, True, False]
    ignored = message(64, SPACE, k2=b"a later hint")
    assert read_message(ignored)["ignored"]
    return {"cases": cases,
            "partial_heads": {"bytes": h(partial), "streams": [h(STREAM_X)],
                              "system_stream": h(SYSTEM), "sends": sends},
            "ignorable": {"bytes": h(ignored), "type": 64, "outcome": "ignored"},
            "refusals": refusals,
            "path": {"from": h(u2["id"]), "to": h(gid), "events": [h(u1["id"])],
                     "signed": [h(u1["signed"])], "checks": True}}


def partial_decision(r_in_past_proven: bool, u_before_r_proven: bool) -> str:
    """units.md, "Partial replicas": a partial replica's verdict on a unit u
    whose writer's removal r it holds. It never applies a unit whose order
    against r it has not proven."""
    if r_in_past_proven:
        return "NotAWriter"
    if u_before_r_proven:
        return "valid"
    return "Pending: order not proven"


def partial_vectors() -> list:
    rows = []
    for name, in_past, before, full in (
            ("u before r, a Path from r down to u fetched", False, True, "valid"),
            ("u before r, no Path yet", False, False, "valid"),
            ("u after r, r among u's parents", True, False, "NotAWriter"),
            ("u concurrent with r", False, False, "RefusedByRemoval")):
        rows.append({"case": name, "r_in_u_past_proven": in_past,
                     "u_before_r_proven": before,
                     "partial_replica": partial_decision(in_past, before),
                     "full_replica": full})
    return rows


def stub_confirmation_vectors() -> list:
    st = (sha256(b"units/stub/id"), signer("B").device_id, 3, 7, KIND_UNIT)
    lied = st[:3] + (900,) + st[4:]
    rows = []
    for name, full, sources in (
            ("one space snapshot", False, [("sender", st)]),
            ("a space snapshot and a snapshot unit by another writer", False,
             [("sender", st), ("compactor", st)]),
            ("the same signer twice", False, [("sender", st), ("sender", st)]),
            ("two signers, one height lied", False, [("sender", st), ("compactor", lied)]),
            ("the parent fetched in full", True, [("sender", lied)])):
        rows.append({"case": name, "held_in_full": full,
                     "sources": [[sg, [h(x) if isinstance(x, bytes) else x for x in stub]]
                                 for sg, stub in sources],
                     "decision": confirm_stub(full, sources)})
    return rows


def supersession_vectors(gid: bytes, key_ref: bytes, k: bytes) -> dict:
    """units.md, "The visible body", key 8, and step 11 of "A unit, at a
    peer": a log unit and a snapshot unit with supersessions, and seven
    refusals of the form."""
    a = signer("A")
    X = OPEN[STREAM_X]

    def loc(name):
        return sha256(b"units/version/" + name.encode()) + \
            sha256(b"units/version/" + name.encode() + b"/digest")

    def listing(name):
        return sha256(b"units/listing/" + name.encode())

    p1, p2, s1, s2 = loc("p1"), loc("p2"), loc("s1"), loc("s2")
    l1, l2 = listing("l1"), listing("l2")
    log_sup = [(s1, l1, p1), (s2, l2, p2)]
    log = make_unit(a, gid, 2, gid, [gid], STREAM_X, key_ref, k,
                    encode_inner(TYPE_RECORDS, b"two versions", opening=X), nonce("sup/log"),
                    objects=[s1, s2], supersedes=log_sup)
    peer_check(log["signed"])
    # A seed snapshot unit whose own listings replace one another: q replaces
    # p, and r replaces q.
    p, q, r = loc("p"), loc("q"), loc("r")
    snap_plain = stream_snapshot(TYPE_RECORDS, STREAM_X, b"records state stand-in")
    obj = seal_object(SPACE, k, key_ref, snap_plain)
    compacts = encode_compacts(obj["locator"], [], [])
    snap_sup = [(q, p), (r, q)]
    snap = make_unit(a, gid, 3, log["id"], [log["id"]], STREAM_X, key_ref, k,
                     encode_inner(TYPE_RECORDS, b"", opening=X), nonce("sup/snap"),
                     objects=[p, q, r, obj["locator"]], compacts=compacts, supersedes=snap_sup)
    peer_check(snap["signed"])

    def shown(u, sup):
        return {"body": h(u["body"]), "signed": h(u["signed"]), "id": h(u["id"]),
                "objects": [h(o) for o in sorted(uncbor(u["body"])[B_OBJECTS])],
                "supersedes": [[h(x) for x in s] for s in
                               sorted(sup, key=lambda s: b"".join(s))]}

    refusals = []
    good_log, good_snap = uncbor(log["body"]), uncbor(snap["body"])
    too_many = [[loc(f"m{i}"), listing(f"m{i}"), p1] for i in range(MAX_SUPERSESSIONS + 1)]
    too_many_objects = sorted({s[0] for s in too_many})
    for name, base, patch in (
            ("a successor not in objects", good_log, {8: [[p, l1, p1]]}),
            ("a two-element supersession in a log unit", good_log, {8: [[s1, p1]]}),
            ("a three-element supersession in a snapshot unit", good_snap,
             {8: [[q, l1, p]]}),
            ("a listing of 31 bytes", good_log, {8: [[s1, l1[:31], p1]]}),
            ("a snapshot's predecessor not in objects", good_snap, {8: [[q, p1]]}),
            ("supersessions out of order", good_log,
             {8: [list(s) for s in sorted(log_sup, key=lambda s: b"".join(s), reverse=True)]}),
            ("4,097 supersessions", good_log,
             {5: too_many_objects, 8: sorted(too_many, key=lambda s: b"".join(s))})):
        body = cbor(base | patch)
        fields = events.event_fields(KIND_UNIT, a, 2, body, log=gid, prev=gid,
                                     parents=[gid])
        signed = events.sign_fields(fields, a)
        got = expect_error(peer_check, signed)
        assert got == "Malformed", (name, got)
        refusals.append({"name": name, "signed": h(signed), "class": "Malformed"})
    return {"log_unit": shown(log, log_sup), "snapshot_unit": shown(snap, snap_sup),
            "refusals": refusals}


def units_vectors() -> dict:
    """units.json: every family units.md's "Test vectors" lists."""
    from identity import Person
    g = genesis()
    gid = events.decode_event(g).id
    a, b, c = signer("A"), signer("B"), signer("C")
    S = [ROT["A"]]
    key_ref = keygraph.encode_set(S)
    k = state_key(S)
    person = Person("Q", prefix="units/person")
    list_event = person.log.events[person.id].signed
    out = {"specification": "units.md",
           "fixtures": {"space": h(SPACE), "genesis": {"signed": h(g), "id": h(gid)},
                        "devices": {n: h(s.device_id) for n, s in (("A", a), ("B", b), ("C", c))},
                        "rotations": {n: h(i) for n, i in ROT.items()},
                        "person": {"id": h(person.id), "first_event": h(list_event)}},
           "parameters": parameters()}
    cases, built = unit_vectors(gid, key_ref, k, person)
    out["units"] = cases
    out["list_events"] = list_events_vectors(person)
    out["unit_refusals"] = unit_refusal_vectors(gid, key_ref, k, built["plain"]["body"],
                                                list_event)
    out["handed_body_keys"] = handed_body_key_vectors(built["plain"], k)
    out["supersessions"] = supersession_vectors(gid, key_ref, k)
    out["stream_types"] = stream_type_vectors(gid, key_ref, k)
    out["system_stream"] = {"stream": h(SYSTEM),
                            "note": "16 random bytes, not all zero, drawn by the founder and "
                                    "sealed in the genesis's roster part and in every space "
                                    "snapshot"}
    out["objects"], out["object_refusals"] = object_vectors(k, key_ref)
    out["compaction"] = compaction_vectors(k, key_ref)
    out["stream_snapshot"], out["space_snapshot"] = snapshot_vectors(k, key_ref, list_event)
    out.update(checkpoint_format_vectors(k, key_ref, list_event))
    out["head_statements"] = statement_vectors(gid, built["plain"]["id"])
    g = WITHHOLDING_GRACE
    out["statement_outcomes"] = [
        {"peer_serves": p_, "author_supplies": a_, "peer_acknowledged": k_,
         "first_missing": f_, "last_missing": l_, "withholding_grace": g,
         "outcome": statement_outcome(p_, a_, k_, f_, l_, g)}
        for p_, a_, k_, f_, l_ in (
            (True, True, False, None, None),
            (False, True, False, 100, 100),
            (False, True, False, 100, 100 + g - 1),
            (False, True, False, 100, 100 + g),
            (False, True, True, 100, 100),
            (False, False, False, 100, 100 + g),
            (False, False, True, 100, 100))]
    out["stub_confirmation"] = stub_confirmation_vectors()
    out["messages"] = message_vectors(gid, built["plain"], built["objects"], k, key_ref,
                                      bytes.fromhex(out["head_statements"]["signed"]),
                                      bytes.fromhex(out["space_snapshot"]["signed"]),
                                      list_event)
    t = GAP_KEY_TIMEOUT
    out["settled"] = [
        {"stable": s, "first_sight": f, "now": n, "gap_key_timeout": t,
         "outcome": settled(s, f, n, t)}
        for s, f, n in ((True, 0, 10), (False, 0, t - 1), (False, 0, t), (False, 100, t + 101))]
    out["partial_replica"] = partial_vectors()
    return out


def self_test() -> None:
    assert len(set(NEW_LABELS)) == len(NEW_LABELS)
    for i, x in enumerate(NEW_LABELS):
        for j, y in enumerate(NEW_LABELS):
            assert i == j or not x.startswith(y)
    k = state_key([ROT["A"]])
    o = seal_object(SPACE, k, keygraph.encode_set([ROT["A"]]), b"x" * 130, chunk=64)
    assert read_object(o["bytes"], SPACE, k, o["locator"], chunk=64) == b"x" * 130
    assert stream_id(TYPE_LORO, SALT["L"]) == STREAM_L
    # The stream check and WrongStream, each unit alone.
    loro = {I_TYPE: TYPE_LORO, I_CONTENT: b"", I_STREAM_OPENING: list(OPEN[STREAM_L])}
    assert content_check(STREAM_L, SYSTEM, loro) == "accepted"
    assert content_check(STREAM_X, SYSTEM, loro) == "StreamMismatch"
    assert content_check(SYSTEM, SYSTEM, {I_TYPE: TYPE_LORO, I_CONTENT: b""}) == "WrongStream"
    assert content_check(STREAM_L, SYSTEM, loro | {I_TYPE: TYPE_LIST}) == "WrongStream"
    assert content_check(STREAM_L, SYSTEM, loro | {I_TYPE: TYPE_RECORDS}) == "WrongAdapter"
    other = {I_TYPE: "com.example.timesheet", I_CONTENT: b"",
             I_STREAM_OPENING: ["com.example.timesheet", SALT["Z"]]}
    assert content_check(stream_id("com.example.timesheet", SALT["Z"]), SYSTEM,
                         other) == "UnknownAdapter"
    # A frasil:system snapshot state with key 4, each entry once.
    entry = cbor({0: 1, 1: SPACE, 2: bytes(32), 3: bytes(32)})
    state = uncbor(system_snapshot_state([], [], [entry, entry]))
    assert sorted(state) == [1, 2, 4] and state[4] == [entry]
    assert sorted(uncbor(system_snapshot_state([], []))) == [1, 2]
    # Key 5: the forgotten IDs of a list carried from a list checkpoint on.
    gone = {bytes([2]) * 32: [bytes([9]) * 32, bytes([3]) * 32]}
    state = read_system_state(system_snapshot_state([], [], forgotten=gone))
    assert state[5] == [[bytes([2]) * 32, [bytes([3]) * 32, bytes([9]) * 32]]]
    assert expect_error(read_system_state, cbor({1: [], 2: [], 5: [[bytes(32), []]]})) == \
        "Malformed"
    assert expect_error(read_system_state, cbor({1: [], 2: [], 3: 0})) == "Malformed"
    # frasil:stubs is no system type: a unit of it in the system stream is
    # refused as content, as any other type there.
    assert content_check(SYSTEM, SYSTEM, {I_TYPE: "frasil:stubs", I_CONTENT: b""}) == \
        "WrongStream"
    assert expect_error(read_message, message(M_LIST_EVENTS, SPACE, k2=[b"e"] * 17)) == \
        "Malformed"
    assert expect_error(read_list_events_body, cbor({1: SPACE, 2: []})) == "Malformed"
    units_vectors()
