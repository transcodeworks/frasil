"""Always-on peers (peers.md), written from the specification, independently of any
implementation: the credential proofs a device presents over transport.md's
`presented`, the peer's table of entries (learnt from rotations and merge
statements, retired by an administrators' credentials request, by a fork
and under the cap), its table of recovery entries, the storage event (kind
6) and its types, the store right, the administrator skeleton (the root,
twins and the roster events that name them, slot tokens, enrolments and
their sealed device bindings, disowns), the peer's resolution of the
skeleton with roster.md's procedure, stability at the peer, the decisions on
erasure, credentials requests, release and collection, and the checks a
replica runs on twins.

Histories are built with roster.py's builder, whose rotations are made here
to commit to an upload key derived from an upload seed, as keys.md,
"Derivations", derives it, so that proofs and merge statements can be
signed."""

from __future__ import annotations

import events
import handshakes
import history_sigs as hs
import identity
import keygraph as kg
import roster
import units
import wraps
from clocks import DAY, HOUR, elapsed_lower
from events import KIND_STORAGE, KIND_SPACE, KIND_UNIT, cbor, decide, h, is_bytes, is_uint, uncbor
from formats import example, hybrid_key_valid
from primitives import (
    SpecError, ed25519_public, ed25519_sign_deterministic, ed25519_valid, ed25519_verify_strict,
    field, hkdf, sha256, xchacha20poly1305_open, xchacha20poly1305_seal,
)

PROOF_LABEL = b"frasil/storage-proof/v1"
MERGE_LABEL = b"frasil/storage-merge/v1"
TWIN_LABEL = b"frasil/skeleton-twin/v1"
TWIN_COMMITMENT_LABEL = b"frasil/skeleton-twin-commitment/v1"
BINDING_LABEL = b"frasil/skeleton-binding/v1"
DEVICE_LABEL = b"frasil/skeleton-device/v1"
TOKEN_LABEL = b"frasil/skeleton-token/v1"
SLOT_ED_LABEL = b"frasil/skeleton-slot/ed25519/v1"
SLOT_MLDSA_LABEL = b"frasil/skeleton-slot/mldsa/v1"
ENROL_LABEL = b"frasil/skeleton-enrol/v1"
ROOT_LABEL = b"frasil/skeleton-root/v1"
SENIORITY_LABEL = b"frasil/skeleton/seniority/v1"
NEW_LABELS = [PROOF_LABEL, MERGE_LABEL, TWIN_LABEL, TWIN_COMMITMENT_LABEL,
              BINDING_LABEL, DEVICE_LABEL, TOKEN_LABEL, SLOT_ED_LABEL, SLOT_MLDSA_LABEL,
              ENROL_LABEL, ROOT_LABEL, SENIORITY_LABEL]

NO_SALT = bytes(32)
VERSION = 1
ROOT, CHANGE, ENROL, DISOWN, ACK, ERASE, CREDENTIALS, RELEASE, RESTORE = 0, 1, 2, 3, 4, 5, 6, 16, 17
CUT = 7  # peers.md, "Skeleton cuts"
TYPE_NAMES = {ROOT: "root", CHANGE: "change", ENROL: "enrol", DISOWN: "disown", ACK: "ack",
              ERASE: "erase", CREDENTIALS: "credentials", CUT: "cut", RELEASE: "release",
              RESTORE: "restore"}
SKELETON_TYPES = (ROOT, CHANGE, ENROL, DISOWN, ACK, ERASE, CREDENTIALS, CUT)
REQUEST_TYPES = (ACK, ERASE, CREDENTIALS)
WRITER_TYPES = (RELEASE, RESTORE)
CONTESTED_TYPES = (CHANGE, DISOWN, ENROL)

MAX_STORAGE_EVENT = 262144
MAX_GRANTS = 64
MAX_LIVE_NAMED = 64
MAX_KEEP = 64            # fetch keys in one credentials request's keep list
MAX_RECOVERY_ENTRIES = 64  # live recovery entries per space
CREDENTIAL_CAP = 256
CREDENTIAL_CAP_RANGE = (16, 4096)
MERGE_PER_STATE = 4  # live merge entries of one state
PENDING_CAP = 4096
MAX_SKELETON_PLACE = 4096
MAX_PLANTED = 256  # grants of changes that repeat a commitment, in a change's past and its own
MAX_MERGE = 64
SIG2 = hs.HYBRID_SIGNATURE_BYTES  # 3,373
MLDSA_BYTES = hs.MLDSA_PUBLIC_KEY_BYTES  # 1,952
TOKEN_WRAP_BYTES = wraps.HEADER_BYTES + wraps.ENC_BYTES + 32 + wraps.TAG_BYTES  # 1,171
BINDING_NONCE = 24
BINDING_BYTES = BINDING_NONCE + SIG2 + 32 + 16  # 3,445
STREAM_BYTES = 16
SCHEME_BYTE = bytes([events.SCHEME_HYBRID])
# transport.md, "Presenting credentials": the credentials and the purposes.
READ_CREDENTIAL, UPLOAD_KEY, PSEUDONYM, FETCH_KEY = 1, 2, 3, 4
SPACE_TRAFFIC, ADMINISTRATION = 1, 2

# peers.md, "Refusal codes": each code and its status.
CODES = {"quota_exceeded": 507, "no_library": 507, "library_closed": 507, "stream_limit": 507,
         "released": 410, "erased": 410, "recovery_entries_full": 507,
         "credential_refused": 403, "not_authorized": 403, "conflict": 409,
         "object_mismatch": 422, "rate_limited": 429, "too_large": 413,
         "moved": 421, "extension_required": 422}

# What a peer refuses for the event itself ("What a peer checks before it
# stores a skeleton event"), as opposed to its verdict in the peer's own
# resolution, which replicas do not read.
REFUSED_AT_STORE = ("Malformed", "UnsupportedVersion", "InvalidKey", "TooLarge",
                    "NotCommitted", "BadSignature", "NotAuthorized", "UnknownAdministratorSlot",
                    "DuplicateRoot", "PlantedSlotsFull")
P_TWIN = kg.P_TWIN  # keys.md, "The space event's body": visible key 15, the twin

# The body's keys.
B_VERSION, B_TYPE = 1, 2
R_TWIN, R_MLDSA, R_DUEL, R_FOUNDER_MLDSA, R_FOUNDER_SIG, R_FOUNDER_XWING = 3, 4, 5, 6, 7, 8
C_TWIN, C_GRANTS, C_LOWER, C_SALT = 3, 4, 5, 6
G_SLOT_ED, G_SLOT_MLDSA_HASH, G_TOKEN, G_RANK = 1, 2, 3, 4
MAX_RANK = 255  # an administrator slot's rank, its grant's (roster.md, section 2.3)
E_SLOT, E_MLDSA, E_SLOT_MLDSA, E_AUTHORIZATION, E_BINDING = 3, 4, 5, 6, 7
D_SLOT = 3
X_SPACE = 3
X_RESERVED = (4, 5)  # an erase body's keys reserved for naming parts of a space
L_LIVE, L_RECOVERY = 3, 4
W_STREAM, W_SNAPSHOT = 3, 5
K_TWIN, K_SALT, K_RECORD, K_EPOCH, K_SLOTS, K_STANDING = 3, 4, 5, 6, 7, 8  # a cut's keys
MAX_CUT_SLOTS = 512
MAX_STANDING = 1024  # peers.md, "Storage events": the administrators and heard members
RESERVED_CUT_KEY = 9  # peers.md, "Reserved cut keys": keys from 9 of a cut's body

# ---------------------------------------------------------------------------
# peers.md, "The credential proof", over transport.md's `presented`.


def proof_message(binding: bytes, space: bytes, credential: int, public: bytes) -> bytes:
    return PROOF_LABEL + handshakes.presented(binding, space, credential, public)


def make_proof(seed: bytes, binding: bytes, space: bytes, credential: int,
               public: bytes) -> dict:
    message = proof_message(binding, space, credential, public)
    return {"presented": handshakes.presented(binding, space, credential, public),
            "proof": ed25519_sign_deterministic(seed, message)}


# ---------------------------------------------------------------------------
# peers.md, "The merge statement".


def merge_message(space: bytes, state: bytes, read: bytes, upload: bytes) -> bytes:
    return MERGE_LABEL + field(space) + field(state) + read + upload


def encode_merge(space: bytes, state: bytes, read: bytes, upload: bytes, signatures) -> bytes:
    return cbor({1: VERSION, 2: space, 3: state, 4: read, 5: upload, 6: list(signatures)})


def read_merge(data: bytes) -> dict:
    value = uncbor(data)
    if not isinstance(value, dict) or set(value) != {1, 2, 3, 4, 5, 6}:
        raise SpecError("Malformed")
    if value[1] != VERSION:
        raise SpecError("UnsupportedVersion" if is_uint(value[1]) else "Malformed")
    if not (is_bytes(value[2], 32) and is_bytes(value[3]) and is_bytes(value[4], 32)
            and is_bytes(value[5], 32) and isinstance(value[6], list)):
        raise SpecError("Malformed")
    state = kg.decode_set(value[3])
    if not 2 <= len(state) <= MAX_MERGE or len(value[6]) != len(state) \
            or not all(is_bytes(s, 64) for s in value[6]):
        raise SpecError("Malformed")
    if not ed25519_valid(value[4]) or not ed25519_valid(value[5]):
        raise SpecError("InvalidKey")
    return {"space": value[2], "state": state, "name": value[3], "read": value[4],
            "upload": value[5], "signatures": value[6]}


# ---------------------------------------------------------------------------
# peers.md, "Skeleton derivations": the twin commitment, the root statement,
# the slot token, enrolment and the device binding.


def twin_secret(body_key: bytes) -> bytes:
    return hkdf(NO_SALT, body_key, TWIN_LABEL)


def twin_commitment(author: bytes, seq: int, secret: bytes, salt: bytes = b"") -> bytes:
    """From R's self reference (keys.md, "Reading key names, bundles, wraps
    and links"), its twin secret and the twin's salt, never from R's event
    ID, so that the twin can be signed before R. The root carries no salt:
    for c(genesis) it is empty."""
    assert len(salt) in (0, 32)
    return sha256(TWIN_COMMITMENT_LABEL + kg.self_ref(author, seq) + secret + salt)


def binding_key(secret: bytes) -> bytes:
    return hkdf(NO_SALT, secret, BINDING_LABEL)


def slot_signer(token: bytes) -> hs.Signer:
    """An administrator slot's keys, which sign no event: named by the slot's
    Ed25519 key and the SHA-256 of its ML-DSA-65 key."""
    return hs.Signer("slot", hkdf(NO_SALT, token, SLOT_ED_LABEL),
                     hkdf(NO_SALT, token, SLOT_MLDSA_LABEL))


def pseudonym_signer(ed_seed: bytes, mldsa_seed: bytes, name: str = "pseudonym") -> hs.Signer:
    """An administrator pseudonym: an Ed25519 seed and an ML-DSA-65 seed, and
    no X-Wing key, so its kc hashes an empty X-Wing key and its device ID
    follows (peers.md, "Skeleton derivations")."""
    return hs.Signer(name, ed_seed, mldsa_seed)


def token_info(space: bytes, c: bytes, index: int, grantee: bytes) -> bytes:
    """The slot token's wrap info (crypto.md, "The X-Wing wrap"): the label,
    the suite, then the space, the administrator slot and the grantee's
    device ID."""
    return wraps.wrap_info(TOKEN_LABEL, field(space) + field(c) + bytes([index]) + grantee)


def grant_map(space: bytes, c: bytes, index: int, grantee: bytes, grantee_xwing: bytes,
              token: bytes, eseed: bytes, rank: int = MAX_RANK) -> dict:
    """`eseed` is X-Wing's 64 bytes of encapsulation randomness."""
    slot = slot_signer(token)
    sealed = wraps.seal_wrap(grantee_xwing, token_info(space, c, index, grantee), token, eseed)
    assert len(sealed["wrap"]) == TOKEN_WRAP_BYTES
    return {G_SLOT_ED: slot.ed_public, G_SLOT_MLDSA_HASH: sha256(slot.mldsa_public),
            G_TOKEN: sealed["wrap"], G_RANK: rank}


def open_token(wrap: bytes, space: bytes, c: bytes, index: int, grantee: bytes,
               xwing_seed: bytes, grant: dict) -> bytes:
    """peers.md, "The skeleton", granting an administrator slot: the
    grantee's own check (BadToken). The wrap opens by crypto.md's "Opening a
    wrap", at the fixed length 1,171."""
    try:
        token = wraps.open_wrap(wrap, xwing_seed, token_info(space, c, index, grantee),
                                TOKEN_WRAP_BYTES)
    except Exception as error:
        raise SpecError("BadToken") from error
    slot = slot_signer(token)
    if slot.ed_public != grant[G_SLOT_ED] or sha256(slot.mldsa_public) != grant[G_SLOT_MLDSA_HASH]:
        raise SpecError("BadToken")
    return token


def root_statement(space: bytes, pid: bytes) -> bytes:
    """`pid` is the pseudonym P0's device ID, which commits to both its keys."""
    return ROOT_LABEL + field(space) + field(pid) + field(SCHEME_BYTE)


def _slot_part(space: bytes, c: bytes, index: int) -> bytes:
    return field(space) + field(c) + bytes([index])


def enrol_statement(space: bytes, c: bytes, index: int, pid: bytes) -> bytes:
    return ENROL_LABEL + _slot_part(space, c, index) + field(pid) + field(SCHEME_BYTE)


def device_statement(space: bytes, c: bytes, index: int, pid: bytes) -> bytes:
    return DEVICE_LABEL + _slot_part(space, c, index) + field(pid) + field(SCHEME_BYTE)


def binding_aad(space: bytes, c: bytes, index: int, pid: bytes) -> bytes:
    return BINDING_LABEL + _slot_part(space, c, index) + pid


def seal_binding(secret: bytes, space: bytes, c: bytes, index: int, pseudonym: hs.Signer,
                 device: hs.Signer, nonce: bytes) -> bytes:
    """The device signature over the pseudonym's device ID, and the device's
    own device ID, sealed."""
    signature = hs.sign(device, events.SCHEME_HYBRID,
                        device_statement(space, c, index, pseudonym.device_id))
    return nonce + xchacha20poly1305_seal(binding_key(secret), nonce,
                                          signature + device.device_id,
                                          binding_aad(space, c, index, pseudonym.device_id))


def open_binding(binding: bytes, secret: bytes, space: bytes, c: bytes, index: int,
                 pid: bytes) -> tuple[bytes, bytes]:
    """peers.md, "What replicas check", enrolments: the device signature and
    the device's device ID. A binding that does not open makes the enrolment
    foreign."""
    if len(binding) != BINDING_BYTES:
        raise SpecError("Malformed")
    try:
        plain = xchacha20poly1305_open(binding_key(secret), binding[:BINDING_NONCE],
                                       binding[BINDING_NONCE:], binding_aad(space, c, index, pid))
    except Exception as error:
        raise SpecError("Decrypt") from error
    return plain[:SIG2], plain[SIG2:]


def hybrid_ok(ed: bytes, mldsa: bytes, message: bytes, signature: bytes) -> bool:
    return (hs.verify_ed25519_half(ed, message, signature)
            and hs.verify_mldsa_half(ed, mldsa, message, signature))


# ---------------------------------------------------------------------------
# peers.md, "Storage events": the body.


def encode_body(kind: int, fields: dict) -> bytes:
    out = {B_VERSION: VERSION, B_TYPE: kind}
    out.update({k: v for k, v in fields.items() if v is not None})
    return cbor(out)


def slot_ref(c: bytes, index: int, maker: bytes) -> list:
    """peers.md, "Storage events": [c, index, maker], maker the event ID of
    the root or change that made the administrator slot."""
    return [c, index, maker]


def root_body(twin: bytes, mldsa: bytes, founder_mldsa: bytes, founder_signature: bytes,
              founder_xwing: bytes, duel: int = 0) -> bytes:
    return encode_body(ROOT, {R_TWIN: twin, R_MLDSA: mldsa, R_DUEL: duel,
                              R_FOUNDER_MLDSA: founder_mldsa, R_FOUNDER_SIG: founder_signature,
                              R_FOUNDER_XWING: founder_xwing})


def change_body(twin: bytes, salt: bytes, grants=None, lower=None) -> bytes:
    return encode_body(CHANGE, {C_TWIN: twin, C_GRANTS: grants,
                                C_LOWER: None if lower is None else slot_ref(*lower),
                                C_SALT: salt})


def enrol_body(slot: tuple, mldsa: bytes, slot_mldsa: bytes, authorization: bytes,
               binding: bytes) -> bytes:
    return encode_body(ENROL, {E_SLOT: slot_ref(*slot), E_MLDSA: mldsa, E_SLOT_MLDSA: slot_mldsa,
                               E_AUTHORIZATION: authorization, E_BINDING: binding})


def disown_body(slot: tuple) -> bytes:
    return encode_body(DISOWN, {D_SLOT: slot_ref(*slot)})


def ack_body() -> bytes:
    return encode_body(ACK, {})


def erase_body() -> bytes:
    """peers.md, "Erasure": an erasure names the whole space, and nothing
    narrower."""
    return encode_body(ERASE, {X_SPACE: 1})


def credentials_body(live=None, recovery=None) -> bytes:
    """`live` names entries, as (encode_set(state), read) pairs; `recovery`
    is the keep list of fetch keys. A request carries at least one."""
    return encode_body(CREDENTIALS, {
        L_LIVE: None if live is None else [[s, r] for s, r in sorted(live,
                                                                    key=lambda x: x[0] + x[1])],
        L_RECOVERY: None if recovery is None else sorted(recovery)})


def cut_body(twin: bytes, salt: bytes, record: bytes, epoch: int, slots,
             standing=()) -> bytes:
    """peers.md, "Skeleton cuts": `slots` and `standing` as read_body gives
    them."""
    entries = [[slot_ref(*s["slot"]), s["slot_ed"] or b"", s["slot_mldsa_hash"] or b"",
                [s["seniority"][0], s["seniority"][1], s["seniority"][3]], s["pseudonym"] or b"",
                s.get("rank", MAX_RANK)]
               for s in sorted(slots, key=lambda s: cbor(slot_ref(*s["slot"])))]
    stand = [[slot_ref(*x["slot"]), x["order"], x["dormant"], x.get("pseudonym") or b""]
             for x in sorted(standing, key=lambda x: cbor(slot_ref(*x["slot"])))]
    return encode_body(CUT, {K_TWIN: twin, K_SALT: salt, K_RECORD: record, K_EPOCH: epoch,
                             K_SLOTS: entries, K_STANDING: stand})


def release_body(stream: bytes) -> bytes:
    return encode_body(RELEASE, {W_STREAM: stream})


def restore_body(stream: bytes | None = None, snapshot: bytes | None = None) -> bytes:
    assert (stream is None) != (snapshot is None)
    return encode_body(RESTORE, {W_STREAM: stream, W_SNAPSHOT: snapshot})


ALLOWED = {
    ROOT: ({R_TWIN, R_MLDSA, R_DUEL, R_FOUNDER_MLDSA, R_FOUNDER_SIG, R_FOUNDER_XWING}, set()),
    CHANGE: ({C_TWIN, C_SALT}, {C_GRANTS, C_LOWER}),
    ENROL: ({E_SLOT, E_MLDSA, E_SLOT_MLDSA, E_AUTHORIZATION, E_BINDING}, set()),
    DISOWN: ({D_SLOT}, set()),
    ACK: (set(), set()),
    ERASE: ({X_SPACE}, set()),
    CREDENTIALS: (set(), {L_LIVE, L_RECOVERY}),
    CUT: ({K_TWIN, K_SALT, K_RECORD, K_EPOCH, K_SLOTS, K_STANDING}, set()),
    RELEASE: ({W_STREAM}, set()),
    RESTORE: (set(), {W_STREAM, W_SNAPSHOT}),
}


def _read_slot(value) -> tuple:
    """A slot reference: exactly [c, index, maker]."""
    if not (isinstance(value, list) and len(value) == 3 and is_bytes(value[0], 32)
            and is_uint(value[1]) and value[1] < MAX_GRANTS and is_bytes(value[2], 32)):
        raise SpecError("Malformed")
    return (value[0], value[1], value[2])


def _ids(value, length: int, most: int) -> list:
    if not (isinstance(value, list) and 1 <= len(value) <= most
            and all(is_bytes(v, length) for v in value)):
        raise SpecError("Malformed")
    if any(a >= b for a, b in zip(value, value[1:])):
        raise SpecError("Malformed")
    if length == STREAM_BYTES and any(v == bytes(STREAM_BYTES) for v in value):
        raise SpecError("Malformed")
    return list(value)


def read_body(data: bytes) -> dict:
    """peers.md, "Storage events", reading a body, in order."""
    value = uncbor(data)
    if not isinstance(value, dict) or not is_uint(value.get(B_VERSION)):
        raise SpecError("Malformed")
    if value[B_VERSION] != VERSION:
        raise SpecError("UnsupportedVersion")
    kind = value.get(B_TYPE)
    if not is_uint(kind) or kind not in ALLOWED:
        raise SpecError("Malformed")
    required, optional = ALLOWED[kind]
    # A cut's keys from 9 are a later document's: held, nothing more read
    # (peers.md, "Reserved cut keys").
    if kind == CUT and any(is_uint(k) and k >= RESERVED_CUT_KEY for k in value):
        raise SpecError("ExtensionRequired")
    keys = set(value) - {B_VERSION, B_TYPE}
    if not required <= keys or not keys <= required | optional:
        raise SpecError("Malformed")
    out = {"type": kind}
    if kind == ROOT:
        if not (is_bytes(value[R_TWIN], 32) and is_bytes(value[R_MLDSA], MLDSA_BYTES)
                and value[R_DUEL] == 0 and is_bytes(value[R_FOUNDER_MLDSA], MLDSA_BYTES)
                and is_bytes(value[R_FOUNDER_SIG], SIG2)
                and is_bytes(value[R_FOUNDER_XWING], wraps.xwing.XWING_PK_SIZE)):
            raise SpecError("Malformed")
        # The whole body's structure first, then its keys.
        if not hybrid_key_valid(value[R_FOUNDER_XWING]):
            raise SpecError("InvalidKey")
        out.update(twin=value[R_TWIN], mldsa=value[R_MLDSA], duel=value[R_DUEL],
                   founder_mldsa=value[R_FOUNDER_MLDSA], founder_signature=value[R_FOUNDER_SIG],
                   founder_xwing=value[R_FOUNDER_XWING])
    elif kind == CHANGE:
        if not is_bytes(value[C_TWIN], 32) or not is_bytes(value[C_SALT], 32) \
                or (C_GRANTS in value) == (C_LOWER in value):
            raise SpecError("Malformed")
        out["twin"], out["salt"] = value[C_TWIN], value[C_SALT]
        if C_GRANTS in value:
            grants = value[C_GRANTS]
            if not isinstance(grants, list) or not 1 <= len(grants) <= MAX_GRANTS:
                raise SpecError("Malformed")
            for g in grants:
                if not (isinstance(g, dict)
                        and set(g) == {G_SLOT_ED, G_SLOT_MLDSA_HASH, G_TOKEN, G_RANK}
                        and is_bytes(g[G_SLOT_ED], 32) and is_bytes(g[G_SLOT_MLDSA_HASH], 32)
                        and is_bytes(g[G_TOKEN], TOKEN_WRAP_BYTES)
                        and is_uint(g[G_RANK]) and g[G_RANK] <= MAX_RANK):
                    raise SpecError("Malformed")
            # Every grant's structure before any key: the keys come last.
            if not all(ed25519_valid(g[G_SLOT_ED]) for g in grants):
                raise SpecError("InvalidKey")
            out["grants"] = grants
        else:
            out["lower"] = _read_slot(value[C_LOWER])
    elif kind == ENROL:
        if not (is_bytes(value[E_MLDSA], MLDSA_BYTES) and is_bytes(value[E_SLOT_MLDSA], MLDSA_BYTES)
                and is_bytes(value[E_AUTHORIZATION], SIG2)
                and is_bytes(value[E_BINDING], BINDING_BYTES)):
            raise SpecError("Malformed")
        out.update(slot=_read_slot(value[E_SLOT]), mldsa=value[E_MLDSA],
                   slot_mldsa=value[E_SLOT_MLDSA], authorization=value[E_AUTHORIZATION],
                   binding=value[E_BINDING])
    elif kind == DISOWN:
        out["slot"] = _read_slot(value[D_SLOT])
    elif kind == CUT:
        if not (is_bytes(value[K_TWIN], 32) and is_bytes(value[K_SALT], 32)
                and is_bytes(value[K_RECORD], 64) and is_uint(value[K_EPOCH])
                and value[K_EPOCH] >= 1 and isinstance(value[K_SLOTS], list)
                and len(value[K_SLOTS]) <= MAX_CUT_SLOTS):
            raise SpecError("Malformed")
        slots = []
        for entry in value[K_SLOTS]:
            if not (isinstance(entry, list) and len(entry) == 6
                    and is_uint(entry[5]) and entry[5] <= MAX_RANK
                    and (entry[1] == b"" or is_bytes(entry[1], 32))
                    and (entry[2] == b"" or is_bytes(entry[2], 32))
                    and (entry[1] == b"") == (entry[2] == b"")
                    and isinstance(entry[3], list) and len(entry[3]) == 3
                    and is_uint(entry[3][0]) and is_uint(entry[3][1])
                    and is_bytes(entry[3][2], 32)
                    and (entry[4] == b"" or is_bytes(entry[4], 32))):
                raise SpecError("Malformed")
            slots.append({"slot": _read_slot(entry[0]), "slot_ed": entry[1] or None,
                          "slot_mldsa_hash": entry[2] or None,
                          "seniority": (entry[3][0], entry[3][1], None, entry[3][2]),
                          "pseudonym": entry[4] or None, "rank": entry[5]})
        refs = [cbor(e[0]) for e in value[K_SLOTS]]
        if any(a >= b for a, b in zip(refs, refs[1:])):
            raise SpecError("Malformed")
        # The standing entries: [slot reference, order, dormant, pseudonym],
        # the last the root or enrolment of a slot that is out, else empty.
        stand = value[K_STANDING]
        if not (isinstance(stand, list) and 1 <= len(stand) <= MAX_STANDING):
            raise SpecError("Malformed")
        standing = []
        for entry in stand:
            if not (isinstance(entry, list) and len(entry) == 4 and is_uint(entry[1])
                    and entry[1] >= 1 and is_uint(entry[2])
                    and (entry[3] == b"" or is_bytes(entry[3], 32))):
                raise SpecError("Malformed")
            standing.append({"slot": _read_slot(entry[0]), "order": entry[1],
                             "dormant": entry[2], "pseudonym": entry[3] or None})
        srefs = [cbor(e[0]) for e in stand]
        if any(a >= b for a, b in zip(srefs, srefs[1:])):
            raise SpecError("Malformed")
        # The whole body's structure first, then its keys: a slot's slot_ed.
        if not all(s["slot_ed"] is None or ed25519_valid(s["slot_ed"]) for s in slots):
            raise SpecError("InvalidKey")
        out.update(twin=value[K_TWIN], salt=value[K_SALT], record=value[K_RECORD],
                   epoch=value[K_EPOCH], slots=slots, standing=standing)
    elif kind == ERASE:
        # Key 3 alone: keys 4 and 5 are reserved, and fail the allowed keys
        # above.
        if not is_uint(value[X_SPACE]) or value[X_SPACE] != 1:
            raise SpecError("Malformed")
        out["space"] = True
    elif kind == CREDENTIALS:
        if not keys:
            raise SpecError("Malformed")  # key 3, key 4, or both
        names, keep = None, None
        if L_LIVE in value:
            live = value[L_LIVE]
            if not isinstance(live, list) or not 1 <= len(live) <= MAX_LIVE_NAMED:
                raise SpecError("Malformed")
            names = []
            for item in live:
                if not (isinstance(item, list) and len(item) == 2 and is_bytes(item[0])
                        and is_bytes(item[1], 32)):
                    raise SpecError("Malformed")
                kg.decode_set(item[0])
                names.append((item[0], item[1]))
            if any(a[0] + a[1] >= b[0] + b[1] for a, b in zip(names, names[1:])):
                raise SpecError("Malformed")
        if L_RECOVERY in value:
            keep = value[L_RECOVERY]
            if not (isinstance(keep, list) and len(keep) <= MAX_KEEP
                    and all(is_bytes(k, 32) for k in keep)) \
                    or any(a >= b for a, b in zip(keep, keep[1:])):
                raise SpecError("Malformed")
            keep = list(keep)
        if any(not ed25519_valid(k) for k in [n[1] for n in names or ()] + (keep or [])):
            raise SpecError("InvalidKey")
        out["live"], out["recovery"] = names, keep
    elif kind in WRITER_TYPES:
        if len(keys) != 1:
            raise SpecError("Malformed")  # a release names a stream; a restore one thing
        if W_STREAM in value:
            out["stream"] = _ids([value[W_STREAM]], STREAM_BYTES, 1)[0]
        elif not is_bytes(value[W_SNAPSHOT], 32):
            raise SpecError("Malformed")
        else:
            out["snapshot"] = value[W_SNAPSHOT]
    return out


def storage_event_size(event: events.Event) -> None:
    if len(event.signed) > MAX_STORAGE_EVENT:
        raise SpecError("TooLarge")


# ---------------------------------------------------------------------------
# peers.md, "What a peer checks before it stores a skeleton event" and "The
# skeleton's resolution": the skeleton at a peer.


def named_twins(log: events.Log, view) -> dict:
    """Twin event ID -> the space event that names it in visible key 15
    (keys.md, "The space event's body"), the first in canonical order."""
    out = {}
    for i in log.canonical(view):
        e = log.events[i]
        if e.kind != KIND_SPACE:
            continue
        try:
            value = kg.decode_cbor(e.body)
        except SpecError:
            continue
        twin = value.get(P_TWIN) if isinstance(value, dict) else None
        if isinstance(twin, bytes) and len(twin) == 32 and twin not in out:
            out[twin] = i
    return out


class Skeleton:
    """The storage events of one log a peer holds in `view`, checked by
    peers.md's "What a peer checks before it stores a skeleton event" and
    resolved by "The skeleton's resolution". Reads no sealed part; fork
    evidence counts only events whose signatures verified."""

    def __init__(self, log: events.Log, view=None, base=None, presets=None):
        """With `base`, the log is a skeleton cut's world (skeleton_cuts.py):
        its root is the cut, whose slots stand in from the start, each
        enrolled to the pseudonym its entry carries. `presets` are verdicts
        decided before the procedure: later cuts, judged on their own past."""
        self.log = log
        self.view = set(log.events if view is None else view)
        self.space = log.id
        self.base = base
        self.epoch = base["epoch"] if base is not None else 0
        self.status: dict[bytes, tuple] = dict(presets or {})
        self.body: dict[bytes, dict] = {}
        order = log.canonical(self.view)
        storage = [i for i in order if log.events[i].kind == KIND_STORAGE]
        for i in storage:
            try:
                storage_event_size(log.events[i])
                self.body[i] = read_body(log.events[i].body)
            except SpecError as error:
                self.status[i] = (False, error.error, None)
        self.skeleton = [i for i in storage if i in self.body
                         and self.body[i]["type"] in SKELETON_TYPES]
        self.requests_ = [i for i in storage if i in self.body
                          and self.body[i]["type"] in WRITER_TYPES]
        self.names = named_twins(log, self.view)
        # An administrator slot is (c, index, the event that made it), as a
        # slot reference names it (peers.md, "Storage events").
        self.key_of: dict[bytes, bytes] = {}   # pseudonym's device ID -> its ML-DSA-65 key
        self.ed_of: dict[bytes, bytes] = {}    # pseudonym's device ID -> its Ed25519 key
        self.slot_of: dict[bytes, tuple] = {}  # pseudonym -> the administrator slot it enrols
        self.slots: dict[tuple, dict] = {}     # administrator slot -> {creator, slot_ed,
        #                                        slot_mldsa_hash}
        self.makers: list[bytes] = []          # the root and applied changes, canonical order
        self.enrols: dict[bytes, tuple] = {}   # enrolment -> the administrator slot it enrols
        self.targets: dict[bytes, list] = {}   # lower or disown -> the slot it lowers
        self.checked: list[bytes] = []         # changes step 6 passes, pending ones included
        self.repeats: set[bytes] = set()       # those that repeat a commitment
        self.root = None
        self.base_slots: dict[tuple, dict] = {}
        # pseudonym -> the event ID of the root or enrolment that enrolled it
        self.enrolled_by: dict[bytes, bytes] = {}
        if base is not None:
            self._install_base()
        self._store_checks()
        verified = {i for i in self.view if self.log.events[i].kind != KIND_STORAGE
                    or (i in self.body and self.status.get(i, (True, None))[1]
                        not in REFUSED_AT_STORE)}
        self.forks = log.fork_points(self.view, lambda i: i in verified)
        self._resolve()

    def _install_base(self) -> None:
        """peers.md, "Skeleton cuts": the cut stands as the root."""
        cut = self.log.genesis
        self.root = cut
        self.status[cut] = (True, "root", None)
        for s in self.base["slots"]:
            self.base_slots[s["slot"]] = s
            self.slots[s["slot"]] = {"creator": s["slot"][2], "slot_ed": s["slot_ed"],
                                     "slot_mldsa_hash": s["slot_mldsa_hash"],
                                     "rank": s["rank"]}
            if s["pseudonym"] is not None:
                # The entry names the root or enrolment by its ID; every
                # holder keeps that event (peers.md, "Truncation").
                pe = self.base["enrolments"][s["pseudonym"]]
                mldsa = read_body(pe.body)["mldsa"]
                self.key_of[pe.author] = mldsa
                self.ed_of[pe.author] = pe.ed
                self.slot_of[pe.author] = s["slot"]
                self.enrolled_by[pe.author] = s["pseudonym"]

    # -- the peer's checks, in canonical order: the event that makes an
    # administrator slot, and an author's enrolment, come before the events
    # that rely on them.
    def _store_checks(self) -> None:
        genesis = self.log.events[self.log.genesis]
        for i in self.skeleton:
            b, e = self.body[i], self.log.events[i]
            kind = b["type"]
            if self.base is not None and i == self.log.genesis:
                continue
            if kind == CUT:
                continue  # judged on its own past (skeleton_cuts.py)
            if kind == ROOT:
                if self.root is not None:
                    self.status[i] = (False, "DuplicateRoot", None)
                    continue
                statement = root_statement(self.space, e.author)
                if e.seq != 1 or e.parents != (self.log.genesis,):
                    self.status[i] = (False, "Malformed", None)
                elif hs.keys_commitment(b["mldsa"], None) != e.kc \
                        or hs.keys_commitment(b["founder_mldsa"], b["founder_xwing"]) \
                        != genesis.kc:
                    self.status[i] = (False, "NotCommitted", None)
                elif not hs.verify_mldsa_half(e.ed, b["mldsa"],
                                              events.signing_input(e.event_bytes), e.signature) \
                        or not hybrid_ok(genesis.ed, b["founder_mldsa"], statement,
                                         b["founder_signature"]):
                    self.status[i] = (False, "BadSignature", None)
                else:
                    self.root = i
                    slot = (b["twin"], 0, i)
                    self.slots[slot] = {"creator": i, "slot_ed": None, "slot_mldsa_hash": None,
                                        "rank": MAX_RANK}  # the founder's
                    self.makers.append(i)
                    self.key_of[e.author] = b["mldsa"]
                    self.ed_of[e.author] = e.ed
                    self.slot_of[e.author] = slot
                    self.enrolled_by[e.author] = i
                continue
            if kind == ENROL:
                c, index, _ = b["slot"]
                slot = self.named_slot(b["slot"], i)
                # The root's administrator slot is enrolled from the start: an
                # enrolment names one an applied change made.
                if slot is None or self.slots[slot]["slot_ed"] is None:
                    self.status[i] = (False, "UnknownAdministratorSlot", None)
                    continue
                statement = enrol_statement(self.space, c, index, e.author)
                if e.seq != 1 or e.author in self.key_of \
                        or sha256(b["slot_mldsa"]) != self.slots[slot]["slot_mldsa_hash"] \
                        or not hybrid_ok(self.slots[slot]["slot_ed"], b["slot_mldsa"], statement,
                                         b["authorization"]):
                    self.status[i] = (False, "BadSignature", None)
                    continue
                # Its mldsa, beside an empty X-Wing key, hashes to its kc.
                if hs.keys_commitment(b["mldsa"], None) != e.kc:
                    self.status[i] = (False, "NotCommitted", None)
                    continue
                if not hs.verify_mldsa_half(e.ed, b["mldsa"], events.signing_input(e.event_bytes),
                                            e.signature):
                    self.status[i] = (False, "BadSignature", None)
                    continue
                self.key_of[e.author] = b["mldsa"]
                self.ed_of[e.author] = e.ed
                self.slot_of[e.author] = slot
                self.enrols[i] = slot
                self.enrolled_by[e.author] = i
                continue
            # Step 4 first: the signature under an enrolled pseudonym's key.
            key = self.key_of.get(e.author)
            if key is None:
                self.status[i] = (False, "NotAuthorized", None)
                continue
            if not hs.verify_mldsa_half(e.ed, key, events.signing_input(e.event_bytes),
                                        e.signature):
                self.status[i] = (False, "BadSignature", None)
                continue
            target = b.get("lower") if kind == CHANGE else (b["slot"] if kind == DISOWN else None)
            if target is not None:
                lowered = self.named_slot(target, i)
                if lowered is None:
                    self.status[i] = (False, "UnknownAdministratorSlot", None)
                    continue
                self.targets[i] = [lowered]
            if kind == CHANGE:
                # Step 6: the planted administrator slots the peer recognises,
                # grants of changes that repeat a commitment, in its past and
                # its own, number at most 256.
                past = [j for j in self.checked if self.log.le(j, i)]
                repeats = (self.root is not None and self.log.le(self.root, i)
                           and self.body[self.root]["twin"] == b["twin"]) \
                    or any(self.body[j]["twin"] == b["twin"] for j in past)
                grants = len(b.get("grants", []))
                if repeats and grants:
                    count = grants + sum(len(self.body[j].get("grants", []))
                                         for j in past if j in self.repeats)
                    if count > MAX_PLANTED:
                        self.status[i] = (False, "PlantedSlotsFull", None)
                        continue
                self.checked.append(i)
                if repeats:
                    self.repeats.add(i)
                # Applied only once a stored space event names it in visible key 15.
                if i not in self.names:
                    self.status[i] = (False, "Unnamed", None)
                    continue
                # A change that repeats a commitment makes administrator slots
                # of its own.
                self.makers.append(i)
                for index, g in enumerate(b.get("grants", [])):
                    self.slots[(b["twin"], index, i)] = {"creator": i, "slot_ed": g[G_SLOT_ED],
                                                         "slot_mldsa_hash": g[G_SLOT_MLDSA_HASH],
                                                         "rank": g[G_RANK]}

    def named_slot(self, ref: tuple, i: bytes):
        """peers.md, "Storage events": the administrator slot a slot reference
        in event `i` names, made at its index by its maker, the root or an
        applied change in i's past whose twin is its commitment; else None."""
        c, index, maker = ref
        slot = (c, index, maker)
        if slot in self.base_slots:
            return slot  # a slot of the cut, by its reference as written there
        if slot in self.slots and maker != i and maker in self.log.events \
                and self.log.le(maker, i):
            return slot
        return None

    # -- peers.md, "The skeleton's resolution"
    def lowered(self, i: bytes) -> list[tuple]:
        """The administrator slot a lower or disown lowers, the one its slot
        reference names, as a list of one."""
        return self.targets.get(i, [])

    def author_slot(self, i: bytes):
        if self.body[i]["type"] == ENROL:
            return self.enrols.get(i)
        return self.slot_of.get(self.log.events[i].author)

    def self_lowering(self, i: bytes) -> bool:
        """A lower or disown whose slot reference names its author's own
        administrator slot."""
        return self.lowered(i) == [self.slot_of.get(self.log.events[i].author)]

    def state(self, place) -> dict:
        """The administrator slots at a place: the root's, and those valid
        changes make; in unless a valid lower or disown names them; enrolled
        by a valid enrolment."""
        st = {}
        if self.base is not None:
            for s, entry in self.base_slots.items():
                pe = self.base["enrolments"][entry["pseudonym"]] if entry["pseudonym"] else None
                st[s] = {"in": True, "enrolled": pe.author if pe else None}
        elif self.root is not None:
            st[self.slot_of[self.log.events[self.root].author]] = {
                "in": True, "enrolled": self.log.events[self.root].author}
        place = [i for i in self.log.canonical(place) if i in self.body]
        for i in place:
            b = self.body[i]
            if b["type"] == CHANGE:
                for index in range(len(b.get("grants", []))):
                    st[(b["twin"], index, i)] = {"in": True, "enrolled": None}
        for i in place:
            if self.body[i]["type"] == ENROL and self.enrols.get(i) in st:
                st[self.enrols[i]]["enrolled"] = self.log.events[i].author
        for i in place:
            for ls in self.lowered(i):
                if ls in st:
                    st[ls]["in"] = False
        return st

    def attacks(self, x: bytes, e: bytes) -> bool:
        if not self.log.concurrent(x, e) or self.self_lowering(e):
            return False
        return self.author_slot(e) in self.lowered(x)

    def mutual(self, x: bytes, e: bytes) -> bool:
        return (self.attacks(x, e) and self.attacks(e, x)
                and self.log.events[x].author != self.log.events[e].author)

    def rank(self, slot) -> int:
        return self.slots.get(slot, {}).get("rank", 0) if slot is not None else 0

    def key(self, slot) -> tuple:
        """The order of authority: the higher rank, then the more senior."""
        return (-self.rank(slot), self.seniority(slot))

    def loses(self, x: bytes, e: bytes) -> bool:
        """In a mutual pair only the outranking author's lowering counts
        (roster.md, section 3.5.2): x's attack on e is dropped when x's
        author's slot does not outrank e's."""
        return self.mutual(x, e) and not (self.key(self.author_slot(x))
                                          < self.key(self.author_slot(e)))

    def spares_enrolment(self, x: bytes, e: bytes, contested) -> bool:
        """Neither side of a mutual pair undoes its partner's authority
        (roster.md, section 3.5.2): x's attack on the enrolment e does not
        count when e's author signed an event that is x's mutual partner."""
        if self.body[e]["type"] != ENROL:
            return False
        author = self.log.events[e].author
        return any(self.log.events[y].author == author and e in self.log.anc[y]
                   and self.mutual(y, x) for y in contested)

    def seniority(self, slot: tuple) -> tuple:
        """The epoch, the height of the event that made it, a hash, that
        event's ID; a slot of the cut keeps the seniority its entry gives."""
        creator = slot[2]
        digest = sha256(SENIORITY_LABEL + self.space + slot[0] + bytes([slot[1]]))
        if slot in self.base_slots:
            e, height, _, maker = self.base_slots[slot]["seniority"]
            return (e, height, digest, maker)
        return (self.epoch, self.log.height[creator], digest, creator)

    def _resolve(self) -> None:
        contested = [i for i in self.skeleton if i not in self.status
                     and self.body[i]["type"] in CONTESTED_TYPES]
        for i in contested:
            e = self.log.events[i]
            if e.author in self.forks and e.seq >= self.forks[e.author] \
                    and not self.self_lowering(i):
                self.status[i] = (False, "Forked", None)
        # Two concurrent enrolments of one administrator slot are both void.
        enrols = [i for i in contested if self.body[i]["type"] == ENROL and i not in self.status]
        for i in enrols:
            if any(j != i and self.enrols[j] == self.enrols[i]
                   and self.log.concurrent(i, j) for j in enrols):
                self.status[i] = (False, "ConcurrentEnrolment", None)
        contested = [i for i in contested if i not in self.status]
        cset = set(contested)
        cpast = {e: frozenset(p for p in self.log.anc[e] if p in cset) for e in contested}

        def place(e, status):
            return frozenset(p for p in cpast[e] if status[p][0])

        def auth(e, status):
            pl = place(e, status)
            if len(pl) + 1 > MAX_SKELETON_PLACE:
                return (False, "Full")
            st = self.state(pl)
            b = self.body[e]
            author = self.log.events[e].author
            if b["type"] == ENROL:
                s = st.get(self.enrols[e])
                if s is None or not s["in"]:
                    return (False, "NotAMember")
                if s["enrolled"] is not None:
                    return (False, "AlreadyEnrolled")
                return (True, None)
            mine = st.get(self.slot_of.get(author))
            if mine is None or not mine["in"] or mine["enrolled"] != author:
                return (False, "NotAnAdministrator")
            targets = self.lowered(e)
            if targets and not any(t in st and st[t]["in"] for t in targets):
                return (False, "NotAMember")
            # Ranks: no slot lowers a slot of a higher rank.
            if any(self.rank(t) > self.rank(self.slot_of.get(author)) for t in targets):
                return (False, "HigherRank")
            return (True, None)

        def pick(e, status):
            return (*self.key(self.author_slot(e)), self.log.height[e], e)

        decided = decide(contested, lambda e: cpast[e],
                         lambda e: [x for x in contested if self.attacks(x, e)],
                         auth, lambda x, e, status: self.loses(x, e)
                         or self.spares_enrolment(x, e, contested), pick)
        for e, v in decided.items():
            if not v[0] and v[1] == "attacked":
                v = (False, "RemovedConcurrently", v[2])
            self.status[e] = v
        if self.root is not None:
            self.status[self.root] = (True, "root", None)
        self.valid_contested = frozenset(i for i in contested if self.status[i][0])
        self.merged = self.state(self.valid_contested)
        # Requests: valid at the peer.
        for i in self.skeleton:
            if i in self.status or self.body[i]["type"] not in REQUEST_TYPES:
                continue
            self.status[i] = self._request(i)

    def _request(self, i: bytes) -> tuple:
        e = self.log.events[i]
        if e.author in self.forks and e.seq >= self.forks[e.author]:
            return (False, "Forked", None)
        slot = self.slot_of.get(e.author)
        st = self.state(frozenset(p for p in self.log.anc[i] if p in self.valid_contested))
        s = st.get(slot)
        if s is None or not s["in"] or s["enrolled"] != e.author:
            return (False, "NotAnAdministrator", None)
        for x in self.log.canonical(self.valid_contested):
            if slot in self.lowered(x) and self.log.concurrent(x, i):
                return (False, "RemovedConcurrently", x)
        return (True, "rules", None)

    # -- peers.md, "Stability at the peer"
    def administrators(self) -> list[tuple]:
        return sorted(s for s, v in self.merged.items() if v["in"])

    def acknowledging(self, slot: tuple) -> list[bytes]:
        out = [slot[2]] if slot[2] in self.log.events else []
        key = self.merged.get(slot, {}).get("enrolled")
        if key is not None and key not in self.forks:
            out += [i for i in self.skeleton if self.log.events[i].author == key]
        return out

    def _acknowledged(self, target: bytes, slots) -> bool:
        for slot in slots:
            key = self.merged.get(slot, {}).get("enrolled")
            if key is not None and key in self.forks:
                continue
            if not any(self.log.le(target, a) for a in self.acknowledging(slot)):
                return False
        return True

    def lowerings(self) -> list[bytes]:
        """Valid lowerings of another pseudonym's administrator slot, disowns
        and named lowers alike: they count for stability only once settled.
        Only self-lowerings take an administrator slot out at once."""
        return [x for x in self.log.canonical(self.valid_contested)
                if self.lowered(x) and not self.self_lowering(x)]

    def settled(self, x: bytes, clock=None) -> bool:
        """A lowering of another administrator slot counts for stability once
        it is settled: stable itself over the skeleton before it, the lowered
        administrator slot included, or held for T since its first sight.
        `clock` is (first_sights, now, T) as clocks.py's readings."""
        before = self.state(frozenset(p for p in self.log.anc[x] if p in self.valid_contested))
        if self._acknowledged(x, sorted(s for s, v in before.items() if v["in"])):
            return True
        if clock is not None:
            sights, now, timeout = clock
            return x in sights and elapsed_lower(sights[x], now) >= timeout
        return False

    def stability_set(self, clock=None) -> list[tuple]:
        slots = set(self.administrators())
        for x in self.lowerings():
            if not self.settled(x, clock):
                slots.update(self.lowered(x))
        return sorted(slots)

    def stable(self, target: bytes, clock=None) -> bool:
        return self._acknowledged(target, self.stability_set(clock))

    def valid(self, i: bytes) -> bool:
        return self.status.get(i, (False,))[0]


# ---------------------------------------------------------------------------
# peers.md, "Entries", "Learning a rotation's credentials", "Merge
# statements", "Retirement and the cap", "Presenting a credential" and
# "Recovery entries": the peer's entries and recovery entries.


class Credentials:
    """A peer's entries and recovery entries for one space, changed in the
    order the peer meets each operation. `log` is the space's log as the peer
    holds it; an entry's rotations are events of it. `sight` counts the
    peer's first sights, of entries and recovery entries alike."""

    def __init__(self, log: events.Log, cap: int = CREDENTIAL_CAP):
        self.log = log
        self.cap = cap
        self.entries: list[dict] = []
        self.recovery: list[dict] = []
        self.sight = 0
        self.reports: list[str] = []
        self.erased = False

    def name(self, e: dict) -> tuple:
        return (kg.encode_set(e["state"]), e["read"])

    def find(self, state: bytes, read: bytes):
        for e in self.entries:
            if self.name(e) == (state, read):
                return e
        return None

    def live(self) -> list[dict]:
        return [e for e in self.entries if e["status"] == "live"]

    def _maximal(self, rid: bytes) -> bool:
        rots = [e["state"][0] for e in self.entries if e["source"] != "merge"]
        return not any(rid in self.log.anc[o] for o in rots)

    def _add(self, entry: dict) -> None:
        self.sight += 1
        entry["seen"] = self.sight
        entry.setdefault("proved", False)
        if entry["status"] == "live" and entry["source"] == "merge":
            same = [e for e in self.live() if e["source"] == "merge"
                    and e["state"] == entry["state"]]
            if len(same) >= MERGE_PER_STATE:
                self._retire(self._oldest(same))
        if entry["status"] == "live" and len(self.live()) >= self.cap:
            merges = [e for e in self.live() if e["source"] == "merge" and not e["proved"]]
            superseded = [e for e in self.live() if e["source"] != "merge"
                          and not self._maximal(e["state"][0])]
            if merges or superseded:
                self._retire(min(merges or superseded, key=lambda e: e["seen"]))
            else:
                entry["status"] = "retired"
                self.reports.append("KeyStateFull")
        self.entries.append(entry)

    @staticmethod
    def _oldest(entries: list) -> dict:
        """The oldest entry never proved by a successful present, else the oldest."""
        unproved = [e for e in entries if not e["proved"]]
        return min(unproved or entries, key=lambda e: e["seen"])

    def _retire(self, entry: dict) -> None:
        entry["status"] = "retired"
        if entry["source"] != "merge":
            for m in self.entries:
                if m["source"] == "merge" and entry["state"][0] in m["state"]:
                    m["status"] = "retired"

    def add_rotation(self, rid: bytes, source: str = "rotation", live: bool = True) -> None:
        """peers.md, "Learning a rotation's credentials": a stored space event
        that rotates."""
        visible = roster.read_visible(self.log.events[rid])
        if not visible["rotates"]:
            return
        author = self.log.events[rid].author
        forks = self.log.fork_points()
        forked = author in forks and self.log.events[rid].seq >= forks[author]
        self._add({"state": (rid,), "read": visible["read"], "upload": visible["upload"],
                   "status": "live" if live and not forked else "retired", "source": source})

    def merge(self, statement: bytes, space: bytes) -> str:
        """peers.md, "Merge statements", in order."""
        try:
            m = read_merge(statement)
        except SpecError as error:
            return error.error
        if m["space"] != space:
            return "Malformed"
        inputs = []
        for rid in m["state"]:
            e = next((x for x in self.entries if x["state"] == (rid,)), None)
            if e is None or e["status"] != "live":
                return "UnknownState"
            inputs.append(e)
        if any(a != b and a in self.log.anc[b] for a in m["state"] for b in m["state"]):
            return "UnknownState"
        message = merge_message(space, m["name"], m["read"], m["upload"])
        if not all(ed25519_verify_strict(e["upload"], message, s)
                   for e, s in zip(inputs, m["signatures"])):
            return "BadSignature"
        self._add({"state": tuple(m["state"]), "read": m["read"], "upload": m["upload"],
                   "status": "live", "source": "merge"})
        return "accepted"

    def execute(self, request: bytes, live, keep=None, seen=None) -> None:
        """peers.md, "Credentials requests", carried out. With `live` (key 3),
        named entries become live and others whose rotations are all in the
        request's past retire; without it, no entry changes. With `keep` (key
        4), named recovery entries become live and every other one the peer
        added before `seen`, its first sight of the request, retires; without
        it, no recovery entry changes."""
        if live is not None:
            names = set(live)
            for e in self.entries:
                if self.name(e) in names:
                    e["status"] = "live"
            for e in self.entries:
                if self.name(e) not in names and e["status"] == "live" \
                        and all(r in self.log.anc[request] for r in e["state"]):
                    self._retire(e)
        if keep is not None:
            kept = set(keep)
            for e in self.recovery:
                if e["key"] in kept:
                    e["status"] = "live"
                elif seen is None or e["seen"] < seen:
                    e["status"] = "retired"

    def first_sight(self) -> int:
        """The peer's first sight of an event, in the order of its sights."""
        self.sight += 1
        return self.sight

    def register(self, key: bytes, rights) -> str:
        """peers.md, "Presenting a credential", registering a recovery entry,
        on a connection that holds `rights` in the space."""
        if "store" not in rights:
            return "CredentialRefused"
        if not ed25519_valid(key):
            return "InvalidKey"
        if any(e["key"] == key for e in self.recovery):
            return "accepted"  # live or retired, nothing changes
        if len([e for e in self.recovery if e["status"] == "live"]) >= MAX_RECOVERY_ENTRIES:
            return "RecoveryEntriesFull"
        self.recovery.append({"key": key, "status": "live", "seen": self.first_sight()})
        return "accepted"

    def fork(self) -> None:
        """peers.md, "Learning a rotation's credentials", a fork: entries of
        rotations by an author at or after its fork point retire."""
        forks = self.log.fork_points()
        for e in self.entries:
            if e["source"] == "merge":
                continue
            ev = self.log.events[e["state"][0]]
            if ev.author in forks and ev.seq >= forks[ev.author]:
                self._retire(e)

    def check_present(self, credential: int, space: bytes, public: bytes, proof: bytes,
                      conn: dict, skeleton: "Skeleton | None" = None) -> str:
        """peers.md, "Presenting a credential", in order. `conn` holds the
        connection's `binding` and `purpose`, and `importing` while it is the
        import in progress; `skeleton` is the peer's skeleton of the space.
        Returns the rights granted, or the class or code refused."""
        allowed = (READ_CREDENTIAL, UPLOAD_KEY, FETCH_KEY) if conn["purpose"] == SPACE_TRAFFIC \
            else (PSEUDONYM,)
        if credential not in (READ_CREDENTIAL, UPLOAD_KEY, PSEUDONYM, FETCH_KEY):
            return "Malformed"
        if credential not in allowed:
            return "purpose_violation"
        if self.erased:
            return "erased"
        # Among the entries with the presented key: a live one first; then,
        # for an upload key on the importing connection, a retired import
        # entry; then the first added.
        def matching(entries: list, field: str) -> "dict | None":
            found = [e for e in entries if e[field] == public]
            live = next((e for e in found if e["status"] == "live"), None)
            if live is not None:
                return live
            if credential == UPLOAD_KEY and conn.get("importing"):
                imported = next((e for e in found if e["source"] == "import"), None)
                if imported is not None:
                    return imported
            return found[0] if found else None

        entry = None
        if credential == READ_CREDENTIAL:
            entry = matching(self.entries, "read")
        elif credential == UPLOAD_KEY:
            entry = matching(self.entries, "upload")
        elif credential == FETCH_KEY:
            entry = matching(self.recovery, "key")
        if credential != PSEUDONYM and entry is None:
            return "UnknownCredential"
        if credential == PSEUDONYM and (skeleton is None or public not in skeleton.key_of):
            return "UnknownCredential"
        # Credential 3 names the pseudonym's device ID; its proof verifies
        # under the Ed25519 key its root or enrolment carries.
        key = skeleton.ed_of[public] if credential == PSEUDONYM else public
        if not ed25519_verify_strict(key, proof_message(conn["binding"], space, credential,
                                                        public), proof):
            return "BadProof"
        if credential == UPLOAD_KEY and entry["status"] != "live":
            if not (conn.get("importing") and entry["source"] == "import"):
                return "RetiredCredential"
            entry["status"] = "live"  # peers.md, "Hosting a space": the importer proves it
        if credential == FETCH_KEY:
            return "catch-up" if entry["status"] == "live" else "RetiredCredential"
        if entry is not None:
            entry["proved"] = True
        if credential == READ_CREDENTIAL:
            return "fetch, live" if entry["status"] == "live" else "catch-up"
        if credential == UPLOAD_KEY:
            return "store, release"
        return "erase"

    def describe_recovery(self) -> list[dict]:
        return [{"key": h(e["key"]), "status": e["status"]} for e in self.recovery]

    def describe(self, names) -> list[dict]:
        return [{"state": [names(r) for r in e["state"]], "read": h(e["read"]),
                 "upload": h(e["upload"]), "status": e["status"], "source": e["source"],
                 "proved": e.get("proved", False)}
                for e in self.entries]


# ---------------------------------------------------------------------------
# peers.md, "Storing an event", step 2: the store right.


def may_store(log: events.Log, i: bytes, conn: dict) -> str:
    """Whether the connection may store event `i` of the space. `conn` holds
    `rights`, the rights its presents for the space were granted; `create`
    while it creates the space and has stored nothing of it; `importing`
    while it is the import in progress; and `pseudonym`, the administrator
    pseudonym its administration present proved. A refusal answers the code
    not_authorized."""
    if "store" in conn["rights"] or conn.get("importing"):
        return "accepted"
    if conn.get("create"):
        return "accepted" if i == log.genesis else "NotAuthorized"
    e = log.events[i]
    if "erase" in conn["rights"] and e.kind == KIND_STORAGE and e.author == conn.get("pseudonym"):
        try:
            if read_body(e.body)["type"] in SKELETON_TYPES:
                return "accepted"
        except SpecError as error:
            return error.error
    return "NotAuthorized"


# ---------------------------------------------------------------------------
# peers.md, "Erasure", "Credentials requests", "Release and restore" and
# "Collection": the peer's decisions.


def erasure_decision(valid: bool, stable: bool, accepted: dict, now: dict, timeout: int) -> str:
    """peers.md, "Erasure"; a credentials request is carried out by the same
    rule."""
    if not valid:
        return "Void"
    if stable or elapsed_lower(accepted, now) >= timeout:
        return "Execute"
    return "Wait"


def release_decision(released: bool, stable: bool, released_at: dict, now: dict,
                     retention: int, timeout: int) -> str:
    """peers.md, "Release and restore"."""
    if not released:
        return "Keep"
    waited = elapsed_lower(released_at, now)
    if waited >= retention and (stable or waited >= timeout):
        return "Reclaim"
    return "Keep"


def collect_decision(cancelled: bool, stable: bool, seen: dict, now: dict, timeout: int) -> str:
    """peers.md, "Collection"."""
    if cancelled:
        return "Keep"
    if stable or elapsed_lower(seen, now) >= timeout:
        return "Collect"
    return "Keep"


def released(log: events.Log, requests: dict, stream: bytes) -> bool:
    """peers.md, "Release and restore": some release names the stream, and every maximal release
    or restore naming it is a release. `requests` maps event IDs to read
    bodies of writer requests."""
    ids = [i for i, b in requests.items() if b.get("stream") == stream]
    if not any(requests[i]["type"] == RELEASE for i in ids):
        return False
    maximal = [i for i in ids if not any(i in log.anc[j] for j in ids)]
    return all(requests[i]["type"] == RELEASE for i in maximal)


# ---------------------------------------------------------------------------
# peers.md, "What replicas check".


def body_key_of(r, i: bytes) -> bytes:
    """The space event's body key (keys.md, "The space event's body"), for a
    replica that holds every rotation key."""
    e = r.log.events[i]
    visible = roster.read_visible(e)
    if visible["rotates"]:
        secret = r.krot[i]
    else:
        secret = kg.content_key(r.log.id, kg.decode_set(visible["sealed_under"]),
                                r.krot.__getitem__)
    return roster.body_key(e, visible, secret)


def twin_of(r, i: bytes) -> dict:
    """R's twin secret, the salt of the twin R names (none for the genesis,
    whose twin is the root) and c(R)."""
    e = r.log.events[i]
    secret = twin_secret(body_key_of(r, i))
    salt = b"" if i == r.genesis else read_body(r.log.events[r.twin_names[i]].body)["salt"]
    return {"secret": secret, "salt": salt, "c": twin_commitment(e.author, e.seq, secret, salt)}


def administer_changes(sp, i: bytes, place) -> dict:
    """peers.md, "The skeleton", a change: the devices a roster event grants
    administer and the device it lowers from administer, at `place` (a set of
    valid roster events and the genesis); with `place` None, from its changes
    alone."""
    if i == sp.log.genesis:
        return {"grants": [sp.log.events[i].author], "lowers": [], "ranks": [MAX_RANK]}
    st = sp.state(place) if place is not None else {}
    grants, lowers, ranks = [], [], []
    for c in sp.changes(i):
        if c.member is None or c.member[0] != roster.DEVICE:
            continue
        prior = st.get(c.member)
        was = prior is not None and prior.present and prior.level == roster.ADMINISTER
        if c.op == roster.GRANT and c.level == roster.ADMINISTER:
            grants.append(c.member[1])
            ranks.append(c.rank)
        elif c.op == roster.CHANGE and c.level == roster.ADMINISTER and not was:
            grants.append(c.member[1])
            ranks.append(c.rank)
        elif c.op in (roster.REMOVE, roster.CHANGE) and was and (
                c.op == roster.REMOVE or c.level is not None and c.level < roster.ADMINISTER):
            lowers.append(c.member[1])
    return {"grants": grants, "lowers": lowers, "ranks": ranks}


class TwinView(roster.StorageView):
    """peers.md, "What replicas check", as the StorageView roster.py's
    resolution reads (roster.md, "The twin" and "Anchors and storage
    events"): which twin a roster event has, whether it passes, and which
    device each pseudonym's binding names. Candidates are only changes signed
    by the pseudonym enrolled, not foreignly, for the roster event's own
    author, so a change another member signs with the same commitment is
    ignored."""

    def __init__(self, log: events.Log, view):
        self.log = log
        self.view = set(view)
        self.sk = Skeleton(log, self.view)
        self.named_by = {R: t for t, R in self.sk.names.items()}
        self.space = None
        self.admin: dict[bytes, dict] = {}    # roster event -> its changes, at its place
        self.reasons: dict[bytes, str] = {}
        self._c: dict[bytes, tuple] = {}
        self._devices: dict[bytes, object] = {}

    # -- the twin commitment of every roster event this replica opened, under
    # the salt of the twin it names; empty for the genesis, whose twin is the
    # root. None when R names no change.
    def c_of(self, R: bytes) -> tuple:
        if R not in self._c:
            e = self.log.events[R]
            secret = twin_secret(self.space.decoded[R].body_key)
            if R == self.log.genesis:
                salt = b""
            else:
                t = self.named_by.get(R)
                b = self.sk.body.get(t) if t is not None else None
                salt = b["salt"] if b is not None and b["type"] == CHANGE else None
            c = None if salt is None else twin_commitment(e.author, e.seq, secret, salt)
            self._c[R] = (secret, c)
        return self._c[R]

    def roster_of_maker(self, maker: bytes):
        """The roster event the replica opened that names `maker` in visible
        key 15; the genesis for the root."""
        if maker == self.sk.root:
            return self.log.genesis
        R = self.sk.names.get(maker)
        if R is None or R not in self.space.decoded or not self.space.is_roster(R):
            return None
        return R

    def changes_of(self, R: bytes) -> dict:
        if R not in self.admin:
            self.admin[R] = administer_changes(self.space, R, None)
        return self.admin[R]

    def slot_device(self, slot: tuple):
        """peers.md, "What replicas check": the device an administrator slot
        [c, index, maker] was made for: the founder for the root's; the device
        granted administer at index by the roster event naming maker, when c
        is that event's commitment under maker's salt; else none."""
        c, index, maker = slot
        R = self.roster_of_maker(maker)
        if R is None or self.c_of(R)[1] != c:
            return None
        grants = self.changes_of(R)["grants"]
        return grants[index] if index < len(grants) else None

    def slot_entry(self, space, device: bytes):
        """roster.md, "The checkpoint record", member key 13: the
        administrator slot in at the merged skeleton of this view that was
        made for `device`, as [c, index, maker, pseudonym], the pseudonym the
        enrolled one's device ID or empty bytes when none is enrolled; None
        when the skeleton holds no slot for it. Of two such slots, the most
        senior."""
        self.space = space
        found = sorted((self.sk.seniority(s), s) for s, v in self.sk.merged.items()
                       if v["in"] and self.slot_device(s) == device)
        if not found:
            return None
        slot = found[0][1]
        return (slot[0], slot[1], slot[2], self.sk.merged[slot]["enrolled"] or b"")

    # -- enrolments' bindings
    def binding_secret(self, e, slot: tuple):
        """peers.md, section 2.5, the secret an enrolment's binding is sealed
        under: twin_secret(R) of the roster event whose twin made its slot;
        or, when the enrolment's cuts name a checkpoint whose skeleton cut
        lists the slot, that checkpoint's (the smallest ID of several). Read
        from the enrolment's own envelope, so that every replica opens it
        alike, whichever checkpoints are in effect at it."""
        listing = []
        for x in e.cuts:
            if x not in self.log.events:
                continue
            cut = roster.read_visible(self.log.events[x]).get("twin")
            if cut is None or cut not in self.log.events:
                continue
            try:
                body = read_body(self.log.events[cut].body)
            except SpecError:
                continue
            if body["type"] == CUT and any(s_["slot"] == slot for s_ in body["slots"]):
                listing.append(x)
        if listing:
            x = min(listing)
            decoded = getattr(self.space, "decoded", {}).get(x) if self.space else None
            return None if decoded is None else twin_secret(decoded.body_key)
        R = self.roster_of_maker(slot[2])
        return None if R is None else self.c_of(R)[0]

    def device_of(self, pseudonym: bytes):
        if pseudonym not in self._devices:
            self._devices[pseudonym] = self._binding(pseudonym)
        d = self._devices[pseudonym]
        return d if isinstance(d, bytes) else None

    def _binding(self, pseudonym: bytes):
        sk = self.sk
        if sk.root is not None and self.log.events[sk.root].author == pseudonym:
            return self.log.events[self.log.genesis].author
        for i in sk.skeleton:
            b, e = sk.body[i], self.log.events[i]
            if b["type"] != ENROL or e.author != pseudonym or \
                    sk.status.get(i, (True, ""))[1] in ("UnknownAdministratorSlot",
                                                        "BadSignature"):
                continue
            c, index, maker = b["slot"]
            device = self.slot_device(b["slot"])
            secret = self.binding_secret(e, b["slot"])
            if secret is None or device is None:
                return "foreign"
            try:
                signature, named = open_binding(b["binding"], secret, self.log.id, c,
                                                index, pseudonym)
            except SpecError:
                return "foreign"
            statement = device_statement(self.log.id, c, index, pseudonym)
            keys = self.space.device_keys(named)
            if named == device and keys is not None and hybrid_ok(keys[0], keys[1], statement,
                                                                  signature):
                return device
            return "foreign"
        return None

    # -- the checks on a twin
    def twin_of_event(self, R: bytes):
        """The twin R names in visible key 15; the root for the genesis."""
        if R == self.log.genesis:
            return self.sk.root
        return self.named_by.get(R)

    def pseudonym_keys(self, space, pseudonym: bytes) -> list:
        """roster.md, "Anchors and storage events": the key a root or
        enrolment that the peer's checks accept carries for the pseudonym,
        by its device ID: whether the skeleton vouches for it."""
        key = self.sk.key_of.get(pseudonym)
        return [key] if key is not None else []

    def twin(self, space, event: bytes, twin_id, place) -> str | None:
        self.space = space
        if event == self.log.genesis:
            return self._root(space)
        if event not in space.decoded or not space.is_roster(event):
            return None
        ch = administer_changes(space, event, place)
        self.admin[event] = ch
        if not ch["grants"] and not ch["lowers"]:
            self.reasons.pop(event, None)
            return None
        verdict = self._check(event, ch, twin_id)
        self.reasons[event] = verdict or "valid"
        return None if verdict is None else verdict.split(":")[0]

    def _root(self, space) -> str | None:
        """peers.md, "What replicas check", step 3: the root, one that
        section 3.11 does not refuse, names c(genesis) and the genesis's duel
        policy. A held root that section 3.11 refuses, its founder keys not
        the genesis's say, is BadTwin."""
        if self.sk.root is None:
            refused = [i for i in self.sk.skeleton if self.sk.body[i]["type"] == ROOT
                       and self.sk.status.get(i, (True, None))[1] in REFUSED_AT_STORE]
            if refused:
                self.reasons[self.log.genesis] = "BadTwin: root"
                return "BadTwin"
            self.reasons[self.log.genesis] = "NoTwin"
            return "NoTwin"
        t = self.sk.body[self.sk.root]
        d = space.decoded[self.log.genesis]
        if t["duel"] != d.duel or t["twin"] != self.c_of(self.log.genesis)[1]:
            self.reasons[self.log.genesis] = "BadTwin: root"
            return "BadTwin"
        self.reasons[self.log.genesis] = "valid"
        return None

    def _check(self, R: bytes, ch: dict, s) -> str | None:
        if s is None:
            return "BadTwin: names no twin"
        if s not in self.view:
            return "NoTwin"
        b, e = self.sk.body.get(s), self.log.events[s]
        if b is None or b["type"] != CHANGE \
                or self.sk.status.get(s, (True, None))[1] in REFUSED_AT_STORE:
            return "BadTwin: not a change"
        if b["twin"] != self.c_of(R)[1]:
            return "BadTwin: commitment"
        slot = self.sk.slot_of.get(e.author)
        if slot is None or self.slot_device(slot) != self.log.events[R].author \
                or self.device_of(e.author) is None:
            return "BadTwin: author"
        if e.author in self.sk.forks and e.seq >= self.sk.forks[e.author]:
            return "BadTwin: forked"
        if ch["lowers"]:
            if b.get("lower") is None or self.slot_device(b["lower"]) != ch["lowers"][0]:
                return "BadTwin: grants"
        elif len(b.get("grants", [])) != len(ch["grants"]):
            return "BadTwin: grants"
        elif [g[G_RANK] for g in b["grants"]] != list(ch.get("ranks", [])):
            return "BadTwin: ranks"  # each slot carries its grant's rank
        skeleton = set(self.sk.skeleton)
        # Beside skeleton events a twin cites only checkpoints, so that it
        # follows what its roster event follows: its cuts are R's (peers.md,
        # "Skeleton cuts"), or the peer, which reads it in another world,
        # would apply what replicas hold valid, or the reverse.
        checkpoints = {x for x in self.view if x in self.space.decoded
                       and self.space.decoded[x].part is not None}
        if s not in self.log.events[R].parents or not set(e.parents) <= skeleton | checkpoints \
                or any(x != s and x not in self.log.anc[s]
                       for x in skeleton & self.log.anc[R]) \
                or tuple(e.cuts) != tuple(self.log.events[R].cuts):
            return "BadTwin: parents"
        for R2, ch2 in self.admin.items():
            if R2 in (R, self.log.genesis) or not (ch2["grants"] or ch2["lowers"]):
                continue
            s2 = self.named_by.get(R2)
            if s2 is not None and (R2 in self.log.anc[R]) != (s2 in self.log.anc[R]):
                return "BadTwin: cite-together"
        return None


class ReplicaTwinView(TwinView):
    """The twin view of a replica that reads the skeleton as a peer resolves
    it (roster.md, "Other logs and extensions"): `sk` is the peer's skeleton
    over what the replica holds, rooted at a cut when one is in effect, and
    `mapping` maps each slot of that cut to the device and pseudonym its
    checkpoint's record names for it. A slot of the cut that no entry names
    maps to no device, as a foreign enrolment's."""

    def __init__(self, log: events.Log, view, sk: "Skeleton", mapping=None):
        self.log = log
        self.view = set(view)
        self.sk = sk
        self.named_by = {R: t for t, R in sk.names.items()}
        self.space = None
        self.admin = {}
        self.reasons = {}
        self._c = {}
        self._devices = {}
        self.mapping = mapping

    def _cut_slot(self, slot) -> bool:
        return self.mapping is not None and slot in self.sk.base_slots

    def roster_of_maker(self, maker: bytes):
        if self.mapping is not None and maker == self.sk.root:
            return None  # the cut makes no slot of a roster event
        return super().roster_of_maker(maker)

    def slot_device(self, slot: tuple):
        if self._cut_slot(slot):
            entry = self.mapping.get(slot)
            return None if entry is None else entry[0]
        return super().slot_device(slot)

    def _binding(self, pseudonym: bytes):
        slot = self.sk.slot_of.get(pseudonym)
        if self._cut_slot(slot) and self.sk.enrolled_by.get(pseudonym) is not None \
                and pseudonym not in {self.log.events[i].author for i in self.sk.enrols}:
            entry = self.mapping.get(slot)
            return entry[0] if entry is not None and entry[1] == pseudonym else "foreign"
        return super()._binding(pseudonym)

    def twin(self, space, event: bytes, twin_id, place) -> str | None:
        self.space = space
        if space.base is not None and event == space.log.genesis:
            return None  # a checkpoint's twin is its own validity's step
        return super().twin(space, event, twin_id, place)


class Replica:
    """A replica's view: roster.py's resolution with this specification's
    TwinView as its StorageView, and peers.md's checks on bindings, disowns
    and twins on top."""

    def __init__(self, r, view=None):
        self.r = r
        self.log = r.log
        self.view = set(self.log.events if view is None else view)
        self.tv = TwinView(self.log, self.view)
        self.sp = r.resolve(self.view, storage=self.tv)
        self.sk = self.tv.sk
        self.verdicts = {}
        for R in self.log.canonical(self.view):
            status = self.sp.status.get(R, (True, None, None))
            if R not in self.tv.reasons and not status[0] and status[1] in (
                    "TwinRequired", "UnexpectedTwin"):
                self.verdicts[R] = (status[1], None, None)
        for R, reason in self.tv.reasons.items():
            status = self.sp.status.get(R, (True, None, None))
            verdict = status[1] if not status[0] and status[1] in ("NoTwin", "BadTwin") \
                else ("valid" if reason == "valid" else reason.split(":")[0])
            self.verdicts[R] = (verdict, None, reason.split(": ")[1] if ": " in reason else None)
        self.device_of = {}
        for i in self.sk.skeleton:
            p = self.log.events[i].author
            if p not in self.device_of:
                self.device_of[p] = self.tv.device_of(p) or "foreign"

    def planted(self) -> list[tuple]:
        """Planted administrator slots: made by an applied change that is not
        the valid twin of the roster event naming it, such as one a key event
        names."""
        out = []
        for j in self.sk.makers:
            R = self.sk.names.get(j)
            if j != self.sk.root and (R is None or self.verdicts.get(R, ("",))[0] != "valid"):
                c = self.sk.body[j]["twin"]
                out += [(c, k, j) for k in range(len(self.sk.body[j].get("grants", [])))]
        return out

    def justified(self, disown: bytes) -> bool:
        """peers.md, "The skeleton", a disown: whether a replica deems it
        justified."""
        slot = self.sk.body[disown]["slot"]
        if slot in self.planted():
            return True
        R = self.tv.roster_of_maker(slot[2])
        if R is None or self.verdicts.get(R, ("NoTwin",))[0] != "valid":
            return True
        if any(self.device_of.get(p) == "foreign" for p, s in self.sk.slot_of.items()
               if s == slot):
            return True
        device = self.tv.slot_device(slot)
        st = self.sp.state(self.sp.place(disown, self.sp.valid_roster))
        m = st.get((roster.DEVICE, device))
        return not (m is not None and m.present and m.level == roster.ADMINISTER)


# ---------------------------------------------------------------------------
# Example histories.


class StorageRoster(roster.Roster):
    """roster.py's builder, with each rotation committing to the upload key of
    an upload seed of its own, as keys.md, "Derivations", derives it. The
    names in PSEUDONYMS are administrator pseudonyms, with no X-Wing key."""

    PSEUDONYMS = {"P0", "A0", "A1", "A2", "A3", "B0", "B1", "B2", "C1", "C2", "X"}

    def __init__(self, founder: str = "P", prefix: str = "storage"):
        self.wrot: dict[bytes, bytes] = {}
        self._last_w = None
        self.twin_names: dict[bytes, bytes] = {}  # roster event -> the twin it names
        self._next_twin = None
        self.admin_slot: dict[str, tuple] = {}    # device name -> its slot reference
        super().__init__(founder, prefix, keyless=self.PSEUDONYMS)
        self.wrot[self.genesis] = self._last_w

    def _space(self, by, label, roster_part, rotates, genesis_nonce=None, refs=()):
        lbl = f"{self.prefix}/{label}"
        if not rotates:
            return super()._space(by, label, roster_part, rotates, genesis_nonce, refs)
        seal_nonce = example(f"{lbl}/seal-nonce")[:kg.NONCE_BYTES]
        secret = example(f"{lbl}/content-key")
        w = example(f"{lbl}/upload-seed")
        payload = {"rotates": True, "grant_commitment": example(f"{lbl}/grant-commitment"),
                   "read": kg.read_credential(secret)["public"],
                   "upload": kg.upload_key(w)["public"]}
        if self._next_twin is not None:
            payload["twin"], self._next_twin = self._next_twin, None
        self._last_w = w
        return roster.space_body(payload, secret, seal_nonce, roster_part, genesis_nonce,
                                 refs), secret

    def space_event(self, by, label, roster_part, rotates, refs=(), **kw):
        i = super().space_event(by, label, roster_part, rotates, refs=refs, **kw)
        if rotates:
            self.wrot[i] = self._last_w
        return i

    def read_seed(self, rid: bytes) -> bytes:
        return kg.read_credential(self.krot[rid])["seed"]

    def upload_seed(self, rid: bytes) -> bytes:
        return kg.upload_key(self.wrot[rid])["seed"]

    # -- the skeleton
    def skeleton_closure(self, view) -> set:
        """The closure of the skeleton events of `view`: a twin's view, so that
        its parents are the skeleton heads its author holds."""
        out = set()
        for x in view:
            if self.log.events[x].kind == KIND_STORAGE and \
                    read_body(self.log.events[x].body)["type"] in SKELETON_TYPES:
                out |= self.log.anc[x] | {x}
        return out

    def followed_closure(self, by: str, parents=None) -> set:
        """peers.md, "Skeleton cuts": a twin follows the checkpoints its roster
        event will follow, so it cites them beside the skeleton events; the
        closure of those checkpoints, for the twin's view. Empty in a log
        with no checkpoint."""
        if self.hist.cuts_for is None:
            return set()
        if parents is None:
            author = self.hist.device(by)
            w = self.hist.view[by]
            mine = [i for i in w if self.log.events[i].author == author]
            last = max(mine, key=lambda i: (self.log.events[i].seq, i), default=None)
            parents = self.hist.parents_for(by, w, last)
        out = set()
        for c in self.hist.cuts_for(parents):
            out |= self.log.anc[c] | {c}
        return out

    def root(self, pseudonym: str, founder: str = "P", label: str | None = None, *,
             founder_keys: tuple | None = None, **kw) -> bytes:
        """`founder_keys` replaces the founder's ML-DSA-65 and X-Wing keys the
        root carries."""
        g = self.genesis
        t = twin_of(self, g)
        p = self.hist.without_xwing(pseudonym)
        statement = root_statement(self.id, p.device_id)
        f = self.hist.signer(founder)
        mldsa_, xwing_ = founder_keys or (f.mldsa_public, f.xwing_public)
        body = root_body(t["c"], p.mldsa_public, mldsa_,
                         hs.sign(f, events.SCHEME_HYBRID, statement), xwing_, **kw)
        root = self.hist.act(pseudonym, KIND_STORAGE, body, label or f"{pseudonym}: root",
                             view={g})
        self.admin_slot[founder] = (t["c"], 0, root)
        return root

    def predict(self, by: str, label: str) -> dict:
        """The twin commitment of the rotating roster event `by` will sign
        next, from its body key and the salt its twin draws, before the event
        exists."""
        author = self.hist.device(by)
        mine = [self.log.events[i].seq for i in self.hist.view[by]
                if self.log.events[i].author == author]
        seq = 1 + max(mine, default=0)
        body_key = kg.seal_key(example(f"{self.prefix}/{label}/content-key"), self.id, author, seq)
        secret = twin_secret(body_key)
        salt = example(f"{self.prefix}/{label}/salt")
        return {"seq": seq, "body_key": body_key, "secret": secret, "salt": salt,
                "c": twin_commitment(author, seq, secret, salt)}

    def named(self, by: str, pseudonym: str, label: str, changes, *, grants=None, lower=None,
              twin_label=None, twin_view=None, twin_extra=(), cite=True, name=True,
              author=None, commitment=None, view=None) -> tuple[bytes, bytes]:
        """The twin first, signed by `author` (normally
        `by`'s pseudonym), then the roster event, which names the twin in its
        visible key 15 and cites it."""
        if view is not None:
            self.hist.view[by] = set(view)
        p = self.predict(by, label)
        c = p["c"] if commitment is None else commitment
        maps = None
        if grants is not None:
            def rank_of(g):
                ch = next((x for x in changes if x.member == (roster.DEVICE,
                                                              self.hist.device(g))), None)
                return MAX_RANK if ch is None or ch.rank is None else ch.rank
            maps = [grant_map(self.id, c, index, self.hist.device(g), self.hist.xwing(g),
                              self.token(None, index, c),
                              example(f"{label}/eseed/{index}/a")
                              + example(f"{label}/eseed/{index}/b"), rank_of(g))
                    for index, g in enumerate(grants)]
        tview = self.skeleton_closure(self.hist.view[by]) if twin_view is None else twin_view
        if twin_view is None:
            tview |= self.followed_closure(by)
        self.hist.without_xwing(author or pseudonym)
        s = self.hist.act(author or pseudonym, KIND_STORAGE,
                          change_body(c, p["salt"], maps, lower),
                          twin_label or f"{author or pseudonym}: twin of {label}",
                          view=tview, extra_parents=twin_extra)
        self._next_twin = (s if name is True else name) if name else None
        R = self.act(by, changes, label, extra_parents=[s] if cite else [])
        assert self.log.events[R].seq == p["seq"] and self._next_twin is None
        if name:
            self.twin_names[R] = s if name is True else name
        for index, g in enumerate(grants or ()):
            self.admin_slot[g] = (c, index, s)
        return R, s

    def grant_admin(self, by: str, pseudonym: str, who, label: str, rank=None,
                    **kw) -> tuple:
        who = [who] if isinstance(who, str) else list(who)
        changes = [self.device_grant(w, roster.ADMINISTER, roster.WITH_HISTORY, roster.VIA_CODE,
                                     rank=rank)
                   for w in who]
        kw.setdefault("grants", who)
        return self.named(by, pseudonym, label, changes, **kw)

    def remove_admin(self, by: str, pseudonym: str, who: str, label: str, **kw) -> tuple:
        kw.setdefault("lower", self.admin_slot[who])
        return self.named(by, pseudonym, label, [roster.Change(roster.REMOVE, self.member(who))],
                          **kw)

    def token(self, R, index: int, c: bytes) -> bytes:
        return example(f"{self.prefix}/token/{c.hex()}/{index}")

    def enrol(self, pseudonym: str, device: str, R: bytes, index: int, label: str, *,
              view=None, binding_device: str | None = None, under: bytes | None = None) -> bytes:
        """The binding is sealed as peers.md, section 2.5, says: under
        twin_secret(R), or, when the enrolment's cuts name a checkpoint whose
        skeleton cut lists the slot, under that checkpoint's (the smallest ID
        of several). `under` forces another event's, for a refusal."""
        t = twin_of(self, R)
        token = self.token(R, index, t["c"])
        slot = slot_signer(token)
        p = self.hist.without_xwing(pseudonym)
        authorization = hs.sign(slot, events.SCHEME_HYBRID,
                                enrol_statement(self.id, t["c"], index, p.device_id))
        w = set(self.hist.view[device] if view is None else view)
        mine = [i for i in w if self.log.events[i].author == p.device_id]
        parents = None
        if under is None and not mine and self.hist.cuts_for is not None:
            parents = self.hist.parents_for(pseudonym, w)
            ref = (t["c"], index, self.twin_names[R])
            listing = []
            for x in self.hist.cuts_for(parents):
                cut = self.twin_names.get(x)
                if cut is not None and any(
                        s_["slot"] == ref for s_ in read_body(self.log.events[cut].body)["slots"]):
                    listing.append(x)
            under = min(listing) if listing else None
        secret = t["secret"] if under is None else twin_of(self, under)["secret"]
        binding = seal_binding(secret, self.id, t["c"], index, p,
                               self.hist.signer(binding_device or device),
                               example(f"{label}/binding-nonce")[:BINDING_NONCE])
        body = enrol_body((t["c"], index, self.twin_names[R]), p.mldsa_public, slot.mldsa_public,
                          authorization, binding)
        return self.hist.act(pseudonym, KIND_STORAGE, body, label, view=w, parents=parents)

    def request(self, name: str, body: bytes, label: str, **kw) -> bytes:
        return self.hist.act(name, KIND_STORAGE, body, label, **kw)

    def skeleton(self, view=None) -> "Skeleton":
        return Skeleton(self.log, view)


def stream(name: str) -> bytes:
    return example(f"storage/stream/{name}")[:STREAM_BYTES]


def object_id(name: str) -> bytes:
    return example(f"storage/object/{name}")


CHANNEL = example("storage/channel-binding")


def unit_body(r, by: str, stream_: bytes, label: str):
    """A unit body of `stream_`, sealed under the state `by` holds: one that
    passes units.md's checks at a peer, so the history can be stored there."""
    (state,) = r.current_state(by)
    key_ref = kg.encode_set((state,))
    nonce = example(f"{r.prefix}/{label}/nonce")[:units.NONCE_BYTES]
    inner = units.encode_inner(units.TYPE_RECORDS, label.encode())

    def body(log: bytes, author: bytes, seq: int) -> bytes:
        aad = units.unit_aad(log, author, seq, stream_, key_ref)
        return units.encode_body(stream_, key_ref, units.seal(r.krot[state], nonce, inner, aad))
    return body


def reading(t: int) -> dict:
    return {"timeline": t, "wall": None, "run": 1}


def main_history() -> dict:
    """One space: P founds it, grants A administer and W write; A enrols; W
    stores, rotates and releases; P removes A while A's pseudonym erases
    the space concurrently; P's pseudonym acknowledges; W restores; P's
    pseudonym asks for credentials and erases the space; P grants B
    administer, and B never enrols; P's pseudonym erases the space again."""
    r = StorageRoster("P", "storage")
    g = r.genesis
    root = r.root("P0")
    r.sync("P", "P0")
    ra, sa = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A", "A1")
    ea = r.enrol("A1", "A", ra, 0, "A1: enrols")
    r.sync("P", "P0", "A", "A1")
    rw = r.grant("P", "W", roster.WRITE, label="P grants W write")
    r.sync("P", "P0", "A", "A1", "W")
    u1 = r.unit("W", "W writes to the notes stream",
                body=unit_body(r, "W", stream("notes"), "W writes to the notes stream"))
    rel = r.request("W", release_body(stream("notes")), "W releases the notes stream")
    hw = r.heal("W", "W rotates")
    r.sync("P", "P0", "A", "A1", "W")
    before_removal = set(r.hist.view["A1"])
    rm, srm = r.remove_admin("P", "P0", "A", "P removes A")
    e1 = r.request("A1", erase_body(), "A1 erases the space", view=before_removal)
    r.sync("P", "P0", "A", "A1", "W")
    ack = r.request("P0", ack_body(), "P0 acknowledges")
    r.sync("P", "P0", "A", "A1", "W")
    rs = r.request("W", restore_body(stream("notes")), "W restores the notes stream")
    r.sync("P", "P0", "A", "A1", "W")
    current = [x for x in r.current_state("P")]
    live = [(kg.encode_set((x,)), roster.read_visible(r.log.events[x])["read"]) for x in current]
    cr = r.request("P0", credentials_body(live), "P0 asks for the current credentials")
    e2 = r.request("P0", erase_body(), "P0 erases the space")
    r.sync("P", "P0", "A", "A1", "W")
    rb, sb = r.grant_admin("P", "P0", "B", "P grants B administer")
    r.sync("P", "P0")
    e3 = r.request("P0", erase_body(), "P0 erases the space again")
    return {"r": r, "ids": {"genesis": g, "root": root, "grant_a": ra, "twin_a": sa,
                            "enrol_a": ea, "grant_w": rw, "unit": u1, "release": rel,
                            "w_rotates": hw, "remove_a": rm, "twin_remove_a": srm,
                            "erase_a1": e1, "ack": ack, "restore": rs, "erase_p0": e2,
                            "credentials": cr, "grant_b": rb, "twin_b": sb, "erase_unstable": e3},
            "live": live}


def _skeleton_summary(r, sk: Skeleton) -> dict:
    out = {}
    for i in r.log.canonical(sk.view):
        if i in sk.status and r.log.events[i].kind == KIND_STORAGE:
            v = sk.status[i]
            out[r.name(i)] = "valid" if v[0] else v[1] + (f" by {r.name(v[2])}" if v[2] else "")
    return {"events": out, "administrators": _slots(r, sk.administrators())}


def _slots(r, slots) -> list:
    """Administrator slots as the vectors write them: [c, index, the name of
    the event that made it]."""
    return [[h(c), k, r.name(m)] for c, k, m in slots]


def _decisions() -> dict:
    T, retention = 7 * DAY, 30 * DAY
    a = reading(1000)
    rows = []
    for valid, stable, t in ((False, True, 0), (True, True, 0), (True, False, T - 1),
                             (True, False, T), (True, False, HOUR)):
        rows.append({"valid": valid, "stable": stable, "elapsed": t, "timeout": T,
                     "outcome": erasure_decision(valid, stable, a, reading(1000 + t), T)})
    rows.append({"valid": True, "stable": False, "elapsed": HOUR, "timeout": HOUR,
                 "outcome": erasure_decision(True, False, a, reading(1000 + HOUR), HOUR)})
    creds = []
    for valid, stable, t in ((False, False, T), (True, True, 0), (True, False, T - 1),
                             (True, False, T)):
        creds.append({"valid": valid, "stable": stable, "elapsed": t, "timeout": T,
                      "outcome": erasure_decision(valid, stable, a, reading(1000 + t), T)})
    rel = []
    for released_, stable, t in ((False, True, retention), (True, True, retention - 1),
                                 (True, True, retention), (True, False, retention),
                                 (True, False, T)):
        rel.append({"released": released_, "stable": stable, "elapsed": t,
                    "retention": retention, "timeout": T,
                    "outcome": release_decision(released_, stable, a, reading(1000 + t),
                                                retention, T)})
    rel.append({"released": True, "stable": False, "elapsed": 0, "retention": 0,
                "timeout": T, "outcome": release_decision(True, False, a, a, 0, T)})
    rel.append({"released": True, "stable": True, "elapsed": 0, "retention": 0,
                "timeout": T, "outcome": release_decision(True, True, a, a, 0, T)})
    col = []
    for cancelled, stable, t in ((True, True, T), (False, True, 0), (False, False, T - 1),
                                 (False, False, T)):
        col.append({"cancelled": cancelled, "stable": stable, "elapsed": t, "timeout": T,
                    "outcome": collect_decision(cancelled, stable, a, reading(1000 + t), T)})
    return {"erasure": rows, "credentials_request": creds, "release": rel, "collection": col}


NONCE_PEER = example("storage/nonce-peer")
NONCE_CLIENT = example("storage/nonce-client")


def _code(verdict: str) -> str | None:
    """The refusal code a peer answers for a verdict ("Refusal codes")."""
    if verdict in ("UnknownCredential", "BadProof", "RetiredCredential", "CredentialRefused"):
        return "credential_refused"
    if verdict == "NotAuthorized":
        return "not_authorized"
    if verdict == "RecoveryEntriesFull":
        return "recovery_entries_full"
    if verdict in CODES or verdict == "purpose_violation":
        return verdict
    return None


def _with_code(case: dict) -> dict:
    code = _code(case["verdict"])
    if code is not None:
        case["code"] = code
    return case


def _bindings_of_connections() -> tuple[bytes, bytes]:
    return (handshakes.peer_binding(CHANNEL, NONCE_PEER, NONCE_CLIENT, SPACE_TRAFFIC),
            handshakes.peer_binding(CHANNEL, NONCE_PEER, NONCE_CLIENT, ADMINISTRATION))


def _proofs(r, ids: dict, sk: "Skeleton", pseudonym: str) -> dict:
    space = r.id
    live_rid, retired_rid = ids["w_rotates"], r.genesis
    cred = Credentials(r.log)
    cred.add_rotation(retired_rid)
    cred.add_rotation(live_rid)
    for e in cred.entries:
        if e["state"] == (retired_rid,):
            e["status"] = "retired"
    traffic, admin = _bindings_of_connections()
    out = {"channel": h(CHANNEL), "nonce_peer": h(NONCE_PEER), "nonce_client": h(NONCE_CLIENT),
           "binding_space_traffic": h(traffic), "binding_administration": h(admin), "cases": []}

    def vis(rid):
        return roster.read_visible(r.log.events[rid])

    def case(label, credential, seed, public, *, binding=traffic, purpose=SPACE_TRAFFIC,
             proof_space=space, proof_credential=None):
        p = make_proof(seed, binding, proof_space, proof_credential or credential, public)
        conn = {"binding": traffic if purpose == SPACE_TRAFFIC else admin, "purpose": purpose}
        out["cases"].append(_with_code({
            "name": label, "credential": credential,
            "purpose": "space traffic" if purpose == SPACE_TRAFFIC else "administration",
            "public": h(public), "presented": h(p["presented"]), "proof": h(p["proof"]),
            "verdict": cred.check_present(credential, space, public, p["proof"], conn, sk)}))

    case("a read credential of a live entry", READ_CREDENTIAL, r.read_seed(live_rid),
         vis(live_rid)["read"])
    case("an upload key of a live entry", UPLOAD_KEY, r.upload_seed(live_rid),
         vis(live_rid)["upload"])
    case("a read credential of a retired entry", READ_CREDENTIAL, r.read_seed(retired_rid),
         vis(retired_rid)["read"])
    case("an upload key of a retired entry", UPLOAD_KEY, r.upload_seed(retired_rid),
         vis(retired_rid)["upload"])
    p = r.hist.signer(pseudonym)
    case("an administrator pseudonym, on an administration connection", PSEUDONYM, p.ed_seed,
         p.device_id, binding=admin, purpose=ADMINISTRATION)
    case("an administrator pseudonym, on a space-traffic connection", PSEUDONYM, p.ed_seed,
         p.device_id)
    stranger = example("storage/stranger")
    case("a key the peer does not hold", READ_CREDENTIAL, stranger, ed25519_public(stranger))
    case("a proof over another connection's binding", READ_CREDENTIAL, r.read_seed(live_rid),
         vis(live_rid)["read"], binding=example("storage/another-binding"))
    case("a proof over another space", READ_CREDENTIAL, r.read_seed(live_rid),
         vis(live_rid)["read"], proof_space=example("storage/another-space"))
    case("a proof made for another credential", READ_CREDENTIAL, r.read_seed(live_rid),
         vis(live_rid)["read"], proof_credential=UPLOAD_KEY)
    out["stores"] = _stores(r, ids, p.device_id)
    return out


def _stores(r, ids: dict, pseudonym: bytes) -> list[dict]:
    """peers.md, "Storing an event", step 2, for the rights a connection's
    presents were granted."""
    out = []

    def case(label, i, rights=(), **conn):
        out.append(_with_code({"name": label, "event": r.name(i), "rights": sorted(rights),
                               "verdict": may_store(r.log, i, {"rights": set(rights), **conn})}))

    case("a unit, under the store right", ids["unit"], ("store", "release"))
    case("a unit, on a connection granted fetch and live only", ids["unit"], ("fetch", "live"))
    case("a unit, on a connection granted catch-up only", ids["unit"], ("catch-up",))
    case("the pseudonym's own acknowledgement, on its administration connection", ids["ack"],
         ("erase",), pseudonym=pseudonym)
    case("another pseudonym's enrolment, on an administration connection", ids["enrol_a"],
         ("erase",), pseudonym=pseudonym)
    case("a create whose first stored event is the genesis", ids["genesis"], create=True)
    case("a create whose first stored event is not the genesis", ids["root"], create=True)
    return out


def _merge_cases(r, a: bytes, b: bytes) -> dict:
    space = r.id
    state = kg.encode_set(kg.canonical((a, b)))
    ids = kg.decode_set(state)
    k = kg.content_key(space, ids, r.krot.__getitem__)
    w = kg.upload_seed(space, ids, r.wrot.__getitem__)
    read, upload = kg.read_credential(k)["public"], kg.upload_key(w)["public"]
    message = merge_message(space, state, read, upload)
    sigs = [ed25519_sign_deterministic(r.upload_seed(x), message) for x in ids]

    def fresh():
        cred = Credentials(r.log)
        for x in r.log.canonical():
            if r.log.events[x].kind == KIND_SPACE and roster.read_visible(r.log.events[x])["rotates"]:
                cred.add_rotation(x)
        return cred

    good = encode_merge(space, state, read, upload, sigs)
    cases = [{"name": "accepted", "statement": h(good), "verdict": fresh().merge(good, space)}]
    missing = encode_merge(space, state, read, upload, sigs[:1])
    cases.append({"name": "a signature missing", "statement": h(missing),
                  "verdict": fresh().merge(missing, space)})
    wrong = encode_merge(space, state, read, upload, [sigs[0], sigs[0]])
    cases.append({"name": "a signature by the wrong upload key", "statement": h(wrong),
                  "verdict": fresh().merge(wrong, space)})
    absent = kg.encode_set(kg.canonical((a, example("storage/absent"))))
    unknown = encode_merge(space, absent, read, upload, sigs)
    cases.append({"name": "a rotation the peer does not hold", "statement": h(unknown),
                  "verdict": fresh().merge(unknown, space)})
    g = r.genesis
    chain = kg.encode_set(kg.canonical((g, a)))
    chained = encode_merge(space, chain, read, upload,
                           [ed25519_sign_deterministic(r.upload_seed(x),
                                                       merge_message(space, chain, read, upload))
                            for x in kg.decode_set(chain)])
    cases.append({"name": "not a state: one rotation in the past of the other",
                  "statement": h(chained), "verdict": fresh().merge(chained, space)})
    return {"prefix": r.prefix, "events": r.hist.describe(),
            "state": [r.name(x) for x in ids], "content_key": h(k), "upload_seed": h(w),
            "read": h(read), "upload": h(upload), "message": h(message), "cases": cases}


def _credentials_steps() -> dict:
    """The entries after each step, at a peer."""
    r = StorageRoster("P", "storage/credentials")
    r.root("P0")
    r.sync("P", "P0")
    r.grant("P", "W", roster.WRITE, label="P grants W write")
    r.grant("P", "V", roster.WRITE, label="P grants V write")
    r.sync("P", "P0", "W", "V")
    hp = r.heal("P", "P rotates")
    r.sync("P", "P0", "W", "V")
    before = set(r.hist.view["W"])
    rm = r.remove("P", "W", "P removes W")
    x = r.heal("W", "W rotates, racing its removal", view=before)
    r.sync("P", "P0", "V")
    steps = []
    cred = Credentials(r.log)
    names = r.name

    def snap(label, extra=None):
        out = {"step": label, "entries": cred.describe(names)}
        if extra:
            out.update(extra)
        steps.append(out)

    cred.add_rotation(r.genesis)
    snap("the space is created: the genesis's entry")
    cred.add_rotation(r.hist.by_name("P grants W write"))
    cred.add_rotation(r.hist.by_name("P grants V write"))
    cred.add_rotation(hp)
    snap("three rotations stored")
    cred.add_rotation(x)
    snap("W's rotation, stored before its removal reached the peer: live too")
    cred.add_rotation(rm)
    snap("P's removal of W: live")
    # A merge statement over the removal and W's racing rotation, signed by both.
    space = r.id
    state = kg.encode_set(kg.canonical((rm, x)))
    ids = kg.decode_set(state)
    k = kg.content_key(space, ids, r.krot.__getitem__)
    w = kg.upload_seed(space, ids, r.wrot.__getitem__)
    read, upload = kg.read_credential(k)["public"], kg.upload_key(w)["public"]
    msg = merge_message(space, state, read, upload)
    verdict = cred.merge(encode_merge(space, state, read, upload,
                                      [ed25519_sign_deterministic(r.upload_seed(i), msg)
                                       for i in ids]), space)
    snap("a merge statement over the removal and W's rotation", {"verdict": verdict})
    live = [(kg.encode_set((rm,)), roster.read_visible(r.log.events[rm])["read"])]
    req = r.request("P0", credentials_body(live), "P0 asks to keep the removal's entry live",
                    view=r.hist.view["P"])
    cred.execute(req, live)
    snap("the credentials request carried out: W's racing rotation was not in its past",
         {"request": h(r.log.events[req].signed)})
    r.sync("P", "P0", "V", "W")
    hv = r.heal("V", "V rotates, citing W's rotation")
    cred.add_rotation(hv)
    live2 = [(kg.encode_set((hv,)), roster.read_visible(r.log.events[hv])["read"])]
    req2 = r.request("P0", credentials_body(live2), "P0 asks to keep V's rotation live")
    cred.execute(req2, live2)
    snap("a second request, after V's rotation that cites W's: W has no live entry left",
         {"request": h(r.log.events[req2].signed)})
    # The cap, lowered to 2 for the vector.
    small = Credentials(r.log, cap=2)
    for i in (r.genesis, hp, x):
        small.add_rotation(i)
    cap = {"cap": 2, "entries": small.describe(names), "reports": small.reports}
    full = Credentials(r.log, cap=1)
    for i in (x, rm):
        full.add_rotation(i)
    cap["every_entry_maximal"] = {"cap": 1, "entries": full.describe(names),
                                  "reports": full.reports}
    # A fork: W signs two events at one sequence number.
    wseq = r.log.events[x].seq
    fork = r.hist.act("W", KIND_UNIT, b"W forks its chain", "W forks", view=before,
                      seq=wseq, prev=r.log.events[x].prev)
    forked = Credentials(r.log)
    for i in (r.genesis, hp, x, rm):
        forked.add_rotation(i)
    forked.fork()
    return {"steps": steps, "cap": cap,
            "fork": {"event": h(r.log.events[fork].signed), "entries": forked.describe(names)},
            "events": r.hist.describe()}


def _recovery_entries() -> dict:
    """peers.md, "Presenting a credential", recovery entries: registering,
    re-adding, a present of a fetch key, retirement by a keep list, and the
    cap of 64 live recovery entries. The fetch key is a recovery key's
    (identity.md, "Fetch keys and recovery entries"); the junk keys are a
    writer's."""
    r = StorageRoster("P", "storage/recovery")
    r.root("P0")
    r.sync("P", "P0")
    r.grant("P", "W", roster.WRITE, label="P grants W write")
    r.sync("P", "P0", "W")
    space = r.id
    rk = identity.recovery_keys(example("storage/recovery/sheet-secret"))
    fetch, fetch_seed = rk["fetch_key"], rk["fetch_seed"]

    def junk_seed(n):
        return example(f"storage/recovery/junk/{n}")

    def junk(n):
        return ed25519_public(junk_seed(n))

    store = ("store", "release")
    cred = Credentials(r.log)
    steps = []

    def step(label, key, verdict, **extra):
        steps.append(_with_code({"step": label, "key": h(key), "verdict": verdict, **extra,
                                 "entries": cred.describe_recovery()}))

    step("a writer registers the recovery key's fetch key", fetch, cred.register(fetch, store))
    step("the same key again: accepted, nothing changes", fetch, cred.register(fetch, store))
    invalid = bytes([1]) + bytes(31)  # the identity point: small order
    step("a key that is not a valid Ed25519 key", invalid, cred.register(invalid, store))
    step("on a connection granted fetch and live only", junk(0),
         cred.register(junk(0), ("fetch", "live")))
    step("a writer registers a junk key", junk(1), cred.register(junk(1), store))
    keep = [fetch]
    req = r.request("P0", credentials_body(recovery=keep),
                    "P0 asks to keep only the recovery key's fetch key")
    seen = cred.first_sight()
    request = {"event": h(r.log.events[req].signed), "body": h(r.log.events[req].body),
               "keep": [h(k) for k in keep]}
    step("a writer registers a second junk key, after the peer's first sight of the request",
         junk(2), cred.register(junk(2), store))
    cred.execute(req, None, keep=keep, seen=seen)
    steps.append({"step": "the request carried out: the first junk key retires, the second, "
                          "added after its first sight, stays live",
                  "entries": cred.describe_recovery()})
    traffic, admin = _bindings_of_connections()
    presents = []

    def present(label, seed, public, purpose=SPACE_TRAFFIC):
        binding = traffic if purpose == SPACE_TRAFFIC else admin
        p = make_proof(seed, binding, space, FETCH_KEY, public)
        presents.append(_with_code({
            "name": label, "credential": FETCH_KEY,
            "purpose": "space traffic" if purpose == SPACE_TRAFFIC else "administration",
            "public": h(public), "presented": h(p["presented"]), "proof": h(p["proof"]),
            "verdict": cred.check_present(FETCH_KEY, space, public, p["proof"],
                                          {"binding": binding, "purpose": purpose})}))

    present("the recovery key's fetch key, live", fetch_seed, fetch)
    present("the first junk key, retired", junk_seed(1), junk(1))
    present("the recovery key's fetch key, on an administration connection", fetch_seed, fetch,
            ADMINISTRATION)
    present("a fetch key the space does not hold", junk_seed(99), junk(99))
    step("the retired junk key registered again: accepted, it stays retired", junk(1),
         cred.register(junk(1), store))
    bulk = [cred.register(junk(n), store) for n in range(3, 65)]
    assert set(bulk) == {"accepted"}
    steps.append({"step": "62 more junk keys registered: 64 live recovery entries",
                  "keys": [h(junk(n)) for n in range(3, 65)], "verdict": "accepted",
                  "live": len([e for e in cred.recovery if e["status"] == "live"]),
                  "entries": cred.describe_recovery()})
    step("a 65th live recovery entry", junk(65), cred.register(junk(65), store))
    step("the recovery key's fetch key again, at the cap: accepted, nothing changes", fetch,
         cred.register(fetch, store))
    # The credentials request's body with a keep list.
    entry = (kg.encode_set((r.genesis,)), roster.read_visible(r.log.events[r.genesis])["read"])
    keys = sorted(junk(n) for n in range(65))
    bodies = [
        ("a keep list alone", credentials_body(recovery=[fetch])),
        ("entries and a keep list", credentials_body([entry], [fetch])),
        ("an empty keep list", credentials_body(recovery=[])),
        ("neither entries nor a keep list", cbor({B_VERSION: VERSION, B_TYPE: CREDENTIALS})),
        ("a keep list out of order", cbor({B_VERSION: VERSION, B_TYPE: CREDENTIALS,
                                           L_RECOVERY: [keys[1], keys[0]]})),
        ("a keep list of 65 keys", credentials_body(recovery=keys)),
        ("a keep list naming an invalid key", credentials_body(recovery=[invalid])),
    ]
    return {"space": h(space), "fetch_seed": h(fetch_seed), "fetch_key": h(fetch),
            "steps": steps, "presents": presents, "request": request,
            "bodies": [{"name": n, "body": h(b), "verdict": _expect(read_body, b)}
                       for n, b in bodies]}


def _admins(prefix: str, *names: str) -> StorageRoster:
    """P founds a space and grants each of `names` administer; each enrols."""
    r = StorageRoster("P", prefix)
    r.root("P0")
    r.sync("P", "P0")
    for n in names:
        R, _ = r.grant_admin("P", "P0", n, f"P grants {n} administer")
        r.sync("P", "P0", *names, *[f"{x}1" for x in names])
        r.enrol(f"{n}1", n, R, 0, f"{n}1: enrols")
        r.sync("P", "P0", *names, *[f"{x}1" for x in names])
    return r


def _resolution_cases() -> dict:
    out = {}
    # A mutual lowering: P and A lower each other's administrator slots concurrently.
    r = _admins("storage/duel", "A")
    base = set(r.hist.view["P"])
    r.remove_admin("P", "P0", "A", "P removes A", view=base)
    r.hist.view["A1"] = set(base)
    r.remove_admin("A", "A1", "P", "A removes P", view=base)
    r.request("P0", erase_body(), "P0 erases the space, before seeing A's removal",
              view=r.hist.view["P0"])
    r.request("A1", erase_body(), "A1 erases the space, before seeing P's removal",
              view=r.hist.view["A1"])
    out["mutual_lowering"] = {"events": r.hist.describe(),
                              "peer": _skeleton_summary(r, r.skeleton())}
    # A mutual lowering whose one side is backdated before its partner's
    # enrolment: the enrolment stands, and the more senior lowering stands,
    # as the roster's does (equal ranks).
    r = StorageRoster("P", "storage/late-enrolment")
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A", "A1")
    base = set(r.hist.view["P"])
    r.enrol("A1", "A", ra, 0, "A1: enrols")
    r.sync("A", "A1")
    r.remove_admin("A", "A1", "P", "A removes P")
    r.remove_admin("P", "P0", "A", "P removes A, backdated before A1's enrolment", view=base)
    r.sync(*r.everyone())
    sk = r.skeleton()
    late = _skeleton_summary(r, sk)
    # Equal ranks: the root's slot, the more senior, stands.
    assert len(late["administrators"]) == 1 and late["events"]["A1: enrols"] == "valid" \
        and any(v.startswith("RemovedConcurrently") for v in late["events"].values()), late
    out["late_enrolment"] = {"events": r.hist.describe(), "peer": late}
    # Two concurrent enrolments of one administrator slot: the granter's and the grantee's.
    r = StorageRoster("P", "storage/enrolments")
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A", "A1", "X")
    base = set(r.hist.view["P"])
    r.enrol("A1", "A", ra, 0, "A1: enrols", view=base)
    r.enrol("X", "P", ra, 0, "X: the granter enrols its own pseudonym", view=base)
    rep = Replica(r)
    out["concurrent_enrolments"] = {"events": r.hist.describe(),
                                    "peer": _skeleton_summary(r, rep.sk),
                                    "bindings": _bindings(r, rep)}
    # Ranks: a slot of rank 10 lowers one of rank 20: HigherRank at the peer,
    # as the roster event is at replicas.
    r = StorageRoster("P", "storage/ranks")
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer at rank 10", rank=10)
    r.sync("P", "P0", "A")
    r.enrol("A1", "A", ra, 0, "A1: enrols")
    r.sync("P", "P0", "A", "A1")
    rb, _ = r.grant_admin("P", "P0", "B", "P grants B administer at rank 20", rank=20)
    r.sync("P", "P0", "A", "A1", "B")
    r.enrol("B1", "B", rb, 0, "B1: enrols")
    r.sync("P", "P0", "A", "A1", "B", "B1")
    r.remove_admin("A", "A1", "B", "A, rank 10, removes B, rank 20")
    r.sync(*r.everyone())
    ranks = _skeleton_summary(r, r.skeleton())
    assert any(v == "HigherRank" for v in ranks["events"].values()), ranks
    assert len(ranks["administrators"]) == 3, ranks
    out["ranks"] = {"events": r.hist.describe(), "peer": ranks}
    out["disown_attack"] = _disown_attack()
    out["lowers_named_by_key_events"] = _key_event_lower_attack()
    out["removal_cost"] = _removal_cost()
    out["repeated_commitment"] = _repeated_commitment()
    out["grant_map_copy"] = _grant_map_copy()
    out["lower_of_a_copy"] = _lower_of_a_copy()
    out["unknown_makers"] = _unknown_makers()
    out["planted_limit"] = _planted_limit()
    return out


def _bindings(r, rep) -> dict:
    return {r.hist.key_name(p): (r.hist.key_name(d) if d != "foreign" else d)
            for p, d in sorted(rep.device_of.items())}


def _disown_attack() -> dict:
    """peers.md, "Stability at the peer": A disowns P's and B's
    administrator slots, then erases. Its own acknowledgement is the only one
    left in the merged skeleton, but the disowns count for stability only
    once they are settled, or after T. Then P lowers A concurrently with the
    erasure, which voids it."""
    r = _admins("storage/disown-attack", "A", "B")
    d1 = r.request("A1", disown_body(r.admin_slot["P"]), "A1 disowns P's administrator slot")
    d2 = r.request("A1", disown_body(r.admin_slot["B"]), "A1 disowns B's administrator slot")
    erase = r.request("A1", erase_body(), "A1 erases the space")
    sk = r.skeleton()
    T = 7 * DAY
    sights = {d1: reading(100), d2: reading(100)}
    within, after = reading(100 + T - 1), reading(100 + T)
    out = {"events": None, "peer_before_response": _skeleton_summary(r, sk),
           "merged_administrators": _slots(r, sk.administrators()),
           "stability_set": _slots(r, sk.stability_set()),
           "erase_stable_without_the_rule": sk._acknowledged(erase, sk.administrators()),
           "erase_stable": sk.stable(erase),
           "erase_stable_within_T": sk.stable(erase, (sights, within, T)),
           "erase_stable_after_T": sk.stable(erase, (sights, after, T))}
    base = {i for i in r.log.events if not r.log.le(d1, i)}
    r.remove_admin("P", "P0", "A", "P removes A, concurrently with A1's disowns", view=base)
    sk2 = r.skeleton()
    out["events"] = r.hist.describe()
    out["peer_after_response"] = _skeleton_summary(r, sk2)
    return out


def _key_event_lower_attack() -> dict:
    """peers.md, "The skeleton's resolution", where the peer and the roster
    differ: A names, from key events of its own, changes lowering P's and
    B's administrator slots, then erases. A peer cannot tell a key event from
    a roster event and applies the lowers; they still keep P and B in the
    stability set until settled, or T."""
    r = _admins("storage/key-event-attack", "A", "B")
    lowers = []
    for n in ("P", "B"):
        view = r.skeleton_closure(r.hist.view["A"])
        x = r.request("A1", change_body(example(f"storage/key-event-attack/{n}"),
                                        example(f"storage/key-event-attack/{n}/salt"),
                                        lower=r.admin_slot[n]),
                      f"A1: a change lowering {n}'s administrator slot", view=view)
        r.sync("A", "A1")
        r._next_twin = x
        r.heal("A", f"A's key event naming the change lowering {n}", extra_parents=[x])
        r.sync("A", "A1")
        lowers.append(x)
    erase = r.request("A1", erase_body(), "A1 erases the space",
                      view=r.hist.view["A"])
    sk = r.skeleton()
    T = 7 * DAY
    sights = {x: reading(100) for x in lowers}
    return {"events": r.hist.describe(), "peer": _skeleton_summary(r, sk),
            "lowers_applied": all(sk.valid(x) for x in lowers),
            "erase_stable_without_the_rule": sk._acknowledged(erase, sk.administrators()),
            "erase_stable": sk.stable(erase),
            "erase_stable_within_T": sk.stable(erase, (sights, reading(100 + T - 1), T)),
            "erase_stable_after_T": sk.stable(erase, (sights, reading(100 + T), T))}


def _removal_cost() -> dict:
    """peers.md, "Stability at the peer", the cost: P removes A through a
    genuine roster event; P's later erasure waits until A acknowledges the
    removal, or T."""
    r = _admins("storage/removal-cost", "A")
    _, lower = r.remove_admin("P", "P0", "A", "P removes A")
    r.sync("P", "P0")
    erase = r.request("P0", erase_body(), "P0 erases the space")
    sk = r.skeleton()
    T = 7 * DAY
    sights = {lower: reading(100)}
    before = sk.stable(erase)
    r.sync("P", "P0", "A", "A1")
    r.request("A1", ack_body(), "A1 acknowledges its removal")
    return {"events": r.hist.describe(), "erase_stable": before,
            "erase_stable_within_T": sk.stable(erase, (sights, reading(100 + T - 1), T)),
            "erase_stable_after_T": sk.stable(erase, (sights, reading(100 + T), T)),
            "erase_stable_once_A_acknowledges": r.skeleton().stable(erase)}


def _repeated_commitment() -> dict:
    """peers.md, "What a peer checks before it stores a skeleton event", a
    repeated commitment: concurrently with P's grant of B, A1 signs a change
    with B's commitment and salt; after the root, one with the root's. A's
    key events name both, and A enrols a pseudonym of its own under each
    copy's keys, each naming its copy. B1 then enrols with both B's twin and
    the copy in its past, naming B's twin. A1 erases the space and A's
    pseudonyms acknowledge it. Each copy makes an administrator slot of its
    own, so the erasure waits for P0 and B1. Last, P0 disowns the copy of
    B's administrator slot, which lowers the copy alone: B's stays in."""
    prefix = "storage/repeated-commitment"
    r = _admins(prefix, "A")
    rb, sb = r.grant_admin("P", "P0", "B", "P grants B administer")
    r.sync("P", "P0", "B")
    copies = {}
    for name, R in (("B's grant", rb), ("the root", r.genesis)):
        t = twin_of(r, R)
        token = example(f"{prefix}/copy of {name}/token")
        grant = grant_map(r.id, t["c"], 0, r.hist.device("A"), r.hist.xwing("A"), token,
                          example(f"{prefix}/copy of {name}/a")
                          + example(f"{prefix}/copy of {name}/b"))
        salt = t["salt"] or example(f"{prefix}/copy of {name}/salt")
        x = r.request("A1", change_body(t["c"], salt, [grant]),
                      f"A1: a change with the commitment of {name}",
                      view=r.skeleton_closure(r.hist.view["A1"]))
        r.sync("A", "A1")
        r._next_twin = x
        r.heal("A", f"A's key event naming the change with the commitment of {name}",
               extra_parents=[x])
        r.sync("A", "A1")
        copies[name] = (R, t["c"], token, x)
    everyone = ("P", "P0", "A", "A1", "A2", "A3", "B", "B1")
    r.sync(*everyone)
    for pseudonym, name in (("A2", "the root"), ("A3", "B's grant")):
        R, c, token, x = copies[name]
        slot = slot_signer(token)
        p = r.hist.signer(pseudonym)
        label = f"{pseudonym}: enrols under the keys of the change with the commitment of {name}"
        authorization = hs.sign(slot, events.SCHEME_HYBRID,
                                enrol_statement(r.id, c, 0, p.device_id))
        binding = seal_binding(twin_of(r, R)["secret"], r.id, c, 0, p, r.hist.signer("A"),
                               example(f"{label}/binding-nonce")[:BINDING_NONCE])
        r.hist.act(pseudonym, KIND_STORAGE,
                   enrol_body((c, 0, x), p.mldsa_public, slot.mldsa_public, authorization,
                              binding),
                   label, view=r.hist.view["A"])
        r.sync(*everyone)
    r.enrol("B1", "B", rb, 0, "B1: enrols")
    r.sync(*everyone)
    erase = r.request("A1", erase_body(), "A1 erases the space")
    r.sync(*everyone)
    for pseudonym in ("A2", "A3"):
        r.request(pseudonym, ack_body(), f"{pseudonym} acknowledges the erasure")
        r.sync(*everyone)
    sk = r.skeleton()
    out = {"peer_before_acknowledgements": _skeleton_summary(r, sk),
           "stability_set": _slots(r, sk.stability_set()),
           "erase_valid": sk.valid(erase), "erase_stable": sk.stable(erase)}
    r.request("P0", ack_body(), "P0 acknowledges the erasure")
    r.sync(*everyone)
    out["erase_stable_once_P0_acknowledges"] = r.skeleton().stable(erase)
    r.request("B1", ack_body(), "B1 acknowledges the erasure")
    r.sync(*everyone)
    out["erase_stable_once_B1_acknowledges"] = r.skeleton().stable(erase)
    _, c_b, _, copy_b = copies["B's grant"]
    disown = r.request("P0", disown_body((c_b, 0, copy_b)),
                       "P0 disowns the copy of B's administrator slot")
    sk = r.skeleton()
    out["disown_lowers"] = _slots(r, sk.lowered(disown))
    out["peer"] = _skeleton_summary(r, sk)
    out["events"] = r.hist.describe()
    assert r.admin_slot["B"] == (c_b, 0, sb) and r.admin_slot["B"] in sk.administrators()
    assert sk.valid(disown) and sk.lowered(disown) == [(c_b, 0, copy_b)]
    return out


def _grant_map_copy() -> dict:
    """peers.md, "What a peer checks before it stores a skeleton event", a
    repeated commitment: after P's grant of B, A1 copies B's twin, its
    commitment, salt and grant map whole, into a change A's key event names.
    B1 enrols with the copy in its past and names B's twin: it enrols B's
    administrator slot, which two administrator slots' keys could verify.
    The copy's administrator slot stays unenrolled; a disown of it is
    justified and lowers it alone."""
    prefix = "storage/grant-map-copy"
    r = _admins(prefix, "A")
    rb, sb = r.grant_admin("P", "P0", "B", "P grants B administer")
    r.sync("P", "P0", "A", "A1")
    twin = read_body(r.log.events[sb].body)
    copy = r.request("A1", change_body(twin["twin"], twin["salt"], twin["grants"]),
                     "A1: a copy of B's twin, its grant map whole",
                     view=r.skeleton_closure(r.hist.view["A1"]))
    r.sync("A", "A1")
    r._next_twin = copy
    r.heal("A", "A's key event naming the copy of B's twin", extra_parents=[copy])
    everyone = ("P", "P0", "A", "A1", "B", "B1")
    r.sync(*everyone)
    enrol = r.enrol("B1", "B", rb, 0, "B1: enrols, the copy in its past")
    r.sync(*everyone)
    disown = r.request("P0", disown_body((twin["twin"], 0, copy)),
                       "P0 disowns the copy's administrator slot")
    rep = Replica(r)
    sk = rep.sk
    assert r.log.le(copy, enrol) and sk.valid(enrol) and sk.slot_of[r.hist.device("B1")] \
        == (twin["twin"], 0, sb)
    assert twin["grants"] == read_body(r.log.events[copy].body)["grants"]
    assert rep.justified(disown) and sk.lowered(disown) == [(twin["twin"], 0, copy)]
    return {"events": r.hist.describe(), "peer": _skeleton_summary(r, sk),
            "copy_repeats": copy in sk.repeats,
            "enrolled": _slots(r, [sk.slot_of[r.hist.device("B1")]]),
            "planted": _slots(r, rep.planted()),
            "justified": {r.name(disown): rep.justified(disown)},
            "disown_lowers": _slots(r, sk.lowered(disown)),
            "bindings": _bindings(r, rep)}


def _lower_of_a_copy() -> dict:
    """peers.md, "The skeleton's resolution": after the root, A1 copies the
    root's commitment in a change with one grant, named by A's key event.
    P0 lowers the copy in a change P's key event names. The lower names the
    copy, so the founder's administrator slot stays in and enrolled to P0."""
    prefix = "storage/lower-of-a-copy"
    r = _admins(prefix, "A")
    c = twin_of(r, r.genesis)["c"]
    grant = grant_map(r.id, c, 0, r.hist.device("A"), r.hist.xwing("A"),
                      example(f"{prefix}/copy/token"),
                      example(f"{prefix}/copy/a") + example(f"{prefix}/copy/b"))
    copy = r.request("A1", change_body(c, example(f"{prefix}/copy/salt"), [grant]),
                     "A1: a change with the commitment of the root",
                     view=r.skeleton_closure(r.hist.view["A1"]))
    r.sync("A", "A1")
    r._next_twin = copy
    r.heal("A", "A's key event naming the copy of the root's commitment", extra_parents=[copy])
    r.sync("P", "P0", "A", "A1")
    sk = r.skeleton()
    before = _slots(r, sk.administrators())
    lower = r.request("P0", change_body(example(f"{prefix}/lower"),
                                        example(f"{prefix}/lower/salt"), lower=(c, 0, copy)),
                      "P0: a change lowering the copy",
                      view=r.skeleton_closure(r.hist.view["P0"]))
    r.sync("P", "P0")
    r._next_twin = lower
    r.heal("P", "P's key event naming the change lowering the copy", extra_parents=[lower])
    sk = r.skeleton()
    founder = r.admin_slot["P"]
    assert sk.valid(lower) and sk.lowered(lower) == [(c, 0, copy)]
    assert sk.merged[founder] == {"in": True, "enrolled": r.hist.device("P0")}
    return {"events": r.hist.describe(), "administrators_before": before,
            "peer": _skeleton_summary(r, sk), "lowers": _slots(r, sk.lowered(lower)),
            "founder": _slots(r, [founder])}


def _unknown_makers() -> dict:
    """peers.md, "What a peer checks before it stores a skeleton event", step
    5: a disown and a lower naming a maker that did not make the
    administrator slot, by another commitment, at an index it has no grant
    at, and outside their past, are UnknownAdministratorSlot; a disown whose
    slot reference has two elements is Malformed."""
    prefix = "storage/unknown-makers"
    r = _admins(prefix, "A")
    c_a, _, s_a = r.admin_slot["A"]
    c_p, _, root = r.admin_slot["P"]
    rb, sb = r.grant_admin("P", "P0", "B", "P grants B administer")
    r.sync("P", "P0")
    c_b = r.admin_slot["B"][0]
    cases = {}
    cases["P0 disowns [c(A's grant), 0, B's twin]"] = r.request(
        "P0", disown_body((c_a, 0, sb)), "P0 disowns [c(A's grant), 0, B's twin]")
    cases["P0 disowns [c(genesis), 1, the root]"] = r.request(
        "P0", disown_body((c_p, 1, root)), "P0 disowns [c(genesis), 1, the root]")
    cases["A1 disowns [c(B's grant), 0, B's twin], outside its past"] = r.request(
        "A1", disown_body((c_b, 0, sb)), "A1 disowns [c(B's grant), 0, B's twin], outside its past")
    lower = r.request("P0", change_body(example(f"{prefix}/lower"),
                                        example(f"{prefix}/lower/salt"), lower=(c_a, 1, s_a)),
                      "P0: a change lowering [c(A's grant), 1, A's twin]",
                      view=r.skeleton_closure(r.hist.view["P0"]))
    old = encode_body(DISOWN, {D_SLOT: [c_a, 0]})
    r.request("P0", old, "P0 disowns [c(A's grant), 0]: two elements")
    sk = r.skeleton()
    for i in list(cases.values()) + [lower]:
        assert sk.status[i][1] == "UnknownAdministratorSlot", (r.name(i), sk.status[i])
    return {"events": r.hist.describe(), "peer": _skeleton_summary(r, sk)}


def _planted_limit() -> dict:
    """peers.md, "Limits" and "What a peer checks before it stores a skeleton
    event", step 6: A1 copies the commitment of its own grant in changes one
    after another, each with 64 grants and named by A's key event: the
    fourth takes the planted administrator slots the peer recognises to 256
    and applies. A fifth copy that lowers, making no administrator slot,
    still applies. P then grants B administer, the copies in its past: its
    twin repeats nothing, applies and passes at replicas, and B1 enrols.
    Last, a sixth copy with one grant would take the count to 257 and is
    refused (PlantedSlotsFull)."""
    prefix = "storage/planted-limit"
    r = _admins(prefix, "A")
    c, _, s_a = r.admin_slot["A"]
    salt = read_body(r.log.events[s_a].body)["salt"]

    def copy(n: int, grants: int, label: str) -> bytes:
        maps = [{G_SLOT_ED: ed25519_public(example(f"{prefix}/{n}/{k}/ed25519")),
                 G_SLOT_MLDSA_HASH: example(f"{prefix}/{n}/{k}/mldsa"),
                 G_TOKEN: bytes([0x01]) + example(f"{prefix}/{n}/{k}/token") * 36
                 + bytes(TOKEN_WRAP_BYTES - 1 - 32 * 36), G_RANK: MAX_RANK}
                for k in range(grants)]
        body = change_body(c, salt, maps) if grants else \
            change_body(c, salt, lower=(c, 0, copies[0]))
        return r.request("A1", body, label, view=r.skeleton_closure(r.hist.view["A1"]))

    copies = []
    for n in range(5):
        label = f"A1: copy {n + 1} of A's commitment, " + (
            "64 grants" if n < 4 else "lowering the first copy's administrator slot 0")
        x = copy(n, 64 if n < 4 else 0, label)
        r.sync("A", "A1")
        r._next_twin = x
        r.heal("A", f"A's key event naming copy {n + 1}", extra_parents=[x])
        r.sync("A", "A1")
        copies.append(x)
    r.sync("P", "P0", "A", "A1")
    rb, sb = r.grant_admin("P", "P0", "B", "P grants B administer, the copies in its past")
    r.sync("P", "P0", "A", "A1", "B", "B1")
    enrol = r.enrol("B1", "B", rb, 0, "B1: enrols")
    r.sync("P", "P0", "A", "A1", "B", "B1")
    over = copy(5, 1, "A1: copy 6 of A's commitment, one grant")
    rep = Replica(r)
    sk = rep.sk
    assert all(sk.valid(x) for x in copies) and sk.valid(sb) and sk.valid(enrol)
    assert sk.status[over][1] == "PlantedSlotsFull"
    assert all(x in sk.repeats for x in copies) and sb not in sk.repeats
    assert sum(len(sk.body[x].get("grants", [])) for x in copies) == MAX_PLANTED
    assert rep.verdicts[rb][0] == "valid"
    return {"events": r.hist.describe(), "limit": MAX_PLANTED, "peer": _skeleton_summary(r, sk),
            "repeats": [r.name(x) for x in r.log.canonical() if x in sk.repeats],
            "replica": {r.name(rb): rep.verdicts[rb][0]}}


def _twin_checks() -> dict:
    out = {}

    def variant(label, **kw):
        rr = _admins("storage/replica", "A")
        y, s = rr.grant_admin("P", "P0", "B", "P grants B administer", twin_label=label, **kw)
        rep = Replica(rr)
        v = rep.verdicts[y]
        return {"prefix": rr.prefix, "events": rr.hist.describe(),
                "roster_event": h(rr.log.events[y].signed), "twin": h(rr.log.events[s].signed),
                "verdict": v[0], "reason": v[2], "peer": _skeleton_summary(rr, rep.sk)}

    out["passes"] = variant("P0: twin of P grants B")
    out["wrong_grants"] = variant("P0: twin granting two administrator slots",
                                  grants=["B", "A"])
    out["another_administrators_pseudonym"] = variant("A1: twin of P's grant", author="A1")
    # A root whose founder keys are another device's: they do not hash to the
    # genesis's kc. The peer refuses it (NotCommitted); a replica holding it
    # finds the genesis's twin BadTwin, and the space unusable.
    rr = StorageRoster("P", "storage/replica-root-keys")
    other = rr.hist.signer("H")
    root = rr.root("P0", founder_keys=(other.mldsa_public, other.xwing_public))
    try:
        Replica(rr)
        replica = "valid"
    except SpecError as error:
        replica = error.error
    out["root_founder_keys_not_committed"] = {
        "prefix": rr.prefix, "events": rr.hist.describe(), "root": h(rr.log.events[root].signed),
        "founder_keys_named": {"mldsa": h(other.mldsa_public), "xwing": h(other.xwing_public)},
        "peer": rr.skeleton().status[root][1], "replica": replica}
    # A twin that cites an event that is not a skeleton event.
    rr = _admins("storage/replica-parents", "A")
    u = rr.unit("P", "P writes a unit")
    rr.sync("P", "P0")
    y, s = rr.grant_admin("P", "P0", "B", "P grants B administer",
                          twin_label="P0: twin citing a unit", twin_extra=[u])
    rep = Replica(rr)
    out["parent_not_a_skeleton_event"] = {"prefix": rr.prefix, "events": rr.hist.describe(),
                                          "twin": h(rr.log.events[s].signed),
                                          "verdict": rep.verdicts[y][0],
                                          "reason": rep.verdicts[y][2]}
    # The roster event names a twin it does not cite: pending while the replica
    # lacks it, void once it arrives. A roster event that cites its twin is
    # never pending, since a replica places an event only with its parents.
    rr = _admins("storage/replica-missing", "A")
    y, s = rr.grant_admin("P", "P0", "B", "P grants B administer", cite=False)
    view = {i for i in rr.log.events if i != s}
    rep = Replica(rr, view)
    full = Replica(rr)
    out["twin_not_cited"] = {"prefix": rr.prefix, "events": rr.hist.describe(),
                             "holds": [rr.name(i) for i in rr.log.canonical(view)],
                             "verdict": rep.verdicts[y][0], "roster_event": rep.sp.status[y][1],
                             "with_the_twin": full.verdicts[y][0],
                             "reason_with_the_twin": full.verdicts[y][2]}
    # The roster event names no twin.
    rr = _admins("storage/replica-unnamed", "A")
    y, s = rr.grant_admin("P", "P0", "B", "P grants B administer", name=False)
    rep = Replica(rr)
    out["names_no_twin"] = {"prefix": rr.prefix, "events": rr.hist.describe(),
                            "verdict": rep.verdicts[y][0], "reason": rep.verdicts[y][2],
                            "peer": _skeleton_summary(rr, rep.sk)}
    # A junk change with the roster event's commitment and salt, by another
    # administrator's pseudonym, after the twin: no event names it, so the
    # peer never applies it and replicas never read it.
    rr = _admins("storage/replica-junk", "A")
    y, s = rr.grant_admin("P", "P0", "B", "P grants B administer")
    rr.sync("P", "P0", "A", "A1")
    t = twin_of(rr, y)
    junk = rr.request("A1", change_body(t["c"], t["salt"], lower=rr.admin_slot["P"]),
                      "A1: a junk change with the commitment of P's twin",
                      view=rr.skeleton_closure(rr.hist.view["A1"]))
    rep = Replica(rr)
    out["unnamed_change_with_its_commitment"] = {"prefix": rr.prefix,
                                                 "events": rr.hist.describe(),
                                                 "junk": h(rr.log.events[junk].signed),
                                                 "verdict": rep.verdicts[y][0],
                                                 "peer": _skeleton_summary(rr, rep.sk)}
    # A twin by a pseudonym that forked at it.
    rr = _admins("storage/replica-forked")
    view = rr.skeleton_closure(rr.hist.view["P"])
    y, s = rr.grant_admin("P", "P0", "A", "P grants A administer")
    rr.hist.act("P0", KIND_STORAGE, ack_body(), "P0: an ack at the twin's sequence number",
                view=view)
    rep = Replica(rr)
    out["forked_pseudonym"] = {"prefix": rr.prefix, "events": rr.hist.describe(),
                               "verdict": rep.verdicts[y][0], "reason": rep.verdicts[y][2],
                               "peer": _skeleton_summary(rr, rep.sk)}
    # A foreign enrolment, and a planted administrator slot (a change a key
    # event names), each disowned.
    rr = StorageRoster("P", "storage/replica-foreign")
    rr.root("P0")
    rr.sync("P", "P0")
    x, _ = rr.grant_admin("P", "P0", "A", "P grants A administer")
    rr.sync("P", "P0", "X")
    rr.enrol("X", "P", x, 0, "X: P enrols its own pseudonym into A's administrator slot",
             view=rr.hist.view["P"])
    rr.sync("P", "P0", "X")
    planted_c = example("storage/planted")
    planted = rr.request("P0", change_body(planted_c, example("storage/planted-salt"), [grant_map(
        rr.id, planted_c, 0, rr.hist.device("Q"), rr.hist.xwing("Q"),
        example("storage/planted-token"), example("storage/planted/a")
        + example("storage/planted/b"))]), "P0: a planted grant with no roster twin",
        view=rr.skeleton_closure(rr.hist.view["P0"]))
    rr.sync("P", "P0")
    rr._next_twin = planted
    rr.heal("P", "P's key event naming the planted grant", extra_parents=[planted])
    rr.sync("P", "P0")
    d1 = rr.request("P0", disown_body(rr.admin_slot["A"]), "P0 disowns A's administrator slot")
    d2 = rr.request("P0", disown_body((planted_c, 0, planted)),
                    "P0 disowns the planted administrator slot")
    rep = Replica(rr)
    out["foreign_enrolment_and_planted_administrator_slot"] = {
        "prefix": rr.prefix, "events": rr.hist.describe(), "bindings": _bindings(rr, rep),
        "planted": _slots(rr, rep.planted()),
        "justified": {rr.name(d1): rep.justified(d1), rr.name(d2): rep.justified(d2)},
        "peer": _skeleton_summary(rr, rep.sk)}
    return out


def _parameters() -> dict:
    return {"max_storage_event": MAX_STORAGE_EVENT, "max_grants": MAX_GRANTS,
            "max_live_named": MAX_LIVE_NAMED, "max_keep": MAX_KEEP,
            "max_recovery_entries": MAX_RECOVERY_ENTRIES, "merge_rotations": [2, MAX_MERGE],
            "max_skeleton_place": MAX_SKELETON_PLACE, "max_planted": MAX_PLANTED,
            "max_cut_slots": MAX_CUT_SLOTS, "max_standing": MAX_STANDING,
            "reserved_cut_key": RESERVED_CUT_KEY,
            "credential_cap": CREDENTIAL_CAP,
            "credential_cap_range": list(CREDENTIAL_CAP_RANGE),
            "merge_per_state": MERGE_PER_STATE, "pending_cap": PENDING_CAP,
            "max_file_versions": {"default": 100, "range": [1, 1024]},
            "sealed_token_bytes": TOKEN_WRAP_BYTES, "binding_bytes": BINDING_BYTES,
            "types": {str(k): v for k, v in sorted(TYPE_NAMES.items())},
            "largest_events": _largest_events(),
            "codes": dict(sorted(CODES.items())),
            "note": "keys derive from fixed seeds, as roster.py's do; each rotation commits "
                    "to the upload key of an upload seed of its own; pseudonyms are example "
                    "devices named for their administrator slot"}


def peers_vectors() -> dict:
    hist = main_history()
    r, ids = hist["r"], hist["ids"]
    sk = r.skeleton()
    rep = Replica(r)
    twins = {}
    for key in ("genesis", "grant_a", "remove_a", "grant_b"):
        R = ids[key]
        t = twin_of(r, R)
        twins[r.name(R)] = {"body_key": h(body_key_of(r, R)), "twin_secret": h(t["secret"]),
                            "salt": h(t["salt"]), "c": h(t["c"]),
                            "binding_key": h(binding_key(t["secret"])),
                            "replica": rep.verdicts[R][0]}
    # The grantee opens its token.
    ta = sk.body[ids["twin_a"]]["grants"][0]
    c_a = twin_of(r, ids["grant_a"])["c"]
    token = open_token(ta[G_TOKEN], r.id, c_a, 0, r.hist.device("A"),
                       r.hist.signer("A").xwing_seed, ta)
    slot = slot_signer(token)
    requests = {i: sk.body[i] for i in sk.requests_}
    # Stability: A's removal keeps A's administrator slot in the stability set
    # until A acknowledges it or T passes; B's, granted later, never enrols.
    T = 7 * DAY
    sights = {ids["twin_remove_a"]: reading(100)}
    stab = {}
    for key in ("erase_a1", "erase_p0", "credentials", "erase_unstable"):
        i = ids[key]
        stab[r.name(i)] = {"valid": sk.valid(i), "stable": sk.stable(i),
                           "stable_within_T": sk.stable(i, (sights, reading(100 + T - 1), T)),
                           "stable_after_T": sk.stable(i, (sights, reading(100 + T), T))}
    view_before_b = {i for i in r.log.events if not r.log.le(ids["grant_b"], i)}
    return {
        "specification": "peers.md",
        "parameters": _parameters(),
        "proofs": _proofs(r, ids, sk, "P0"),
        "merge_statement": _merge_cases(*_merge_space()),
        "skeleton": {
            "events": r.hist.describe(),
            "twins": twins,
            "names": {r.name(R): r.name(S) for R, S in sorted(r.twin_names.items())},
            "token": {"twin": r.name(ids["twin_a"]), "token": h(token),
                      "info": h(token_info(r.id, c_a, 0, r.hist.device("A"))),
                      "sealed_token": h(ta[G_TOKEN]),
                      "slot_ed_seed": h(hkdf(NO_SALT, token, SLOT_ED_LABEL)),
                      "slot_mldsa_seed": h(hkdf(NO_SALT, token, SLOT_MLDSA_LABEL)),
                      "slot_ed": h(slot.ed_public),
                      "slot_mldsa_hash": h(sha256(slot.mldsa_public))},
            "bindings": _bindings(r, rep),
            "peer": _skeleton_summary(r, sk),
            "released_before_restore": {"notes": released(
                r.log, {i: b for i, b in requests.items() if i != ids["restore"]},
                stream("notes"))},
            "released_after_restore": {"notes": released(r.log, requests, stream("notes"))},
        },
        "twin_checks": _twin_checks(),
        "skeleton_cuts": __import__("skeleton_cuts").skeleton_cut_vectors(),
        "resolution": _resolution_cases(),
        "stability": {"timeout": T, "first_sight_of_the_removal": 100,
                      "requests": stab,
                      "before_b": {r.name(ids["erase_p0"]): r.skeleton(
                          view_before_b).stable(ids["erase_p0"])},
                      "note": "A never acknowledges its removal, so P0's requests after it "
                              "wait for T; B's administrator slot, granted later, is never "
                              "enrolled and acknowledges only through the event that made "
                              "it, so the request after it is not stable even after T"},
        "credentials": _credentials_steps(),
        "merge_cap": _merge_cap(),
        "decisions": _decisions(),
        "recovery_entries": _recovery_entries(),
        "erase_bodies": _erase_bodies(),
    }


def _erase_bodies() -> list:
    """peers.md, "Storage events": an erase body names the whole space, and
    keys 4 and 5 are reserved, so a body that names streams or objects, with
    or without key 3, is Malformed."""
    s1, s2 = stream("notes"), stream("photos")
    o1 = object_id("draft")

    def body(fields: dict) -> bytes:
        return cbor({B_VERSION: VERSION, B_TYPE: ERASE, **fields})

    bodies = [
        ("the whole space", erase_body()),
        ("a stream", body({4: [s1]})),
        ("two streams", body({4: sorted([s1, s2])})),
        ("an object", body({5: [o1]})),
        ("a stream and an object", body({4: [s1], 5: [o1]})),
        ("the space and a stream", body({X_SPACE: 1, 4: [s1]})),
        ("the space and an object", body({X_SPACE: 1, 5: [o1]})),
        ("nothing", body({})),
        ("the space as 2", body({X_SPACE: 2})),
    ]
    return [{"name": n, "body": h(b), "verdict": _expect(read_body, b)} for n, b in bodies]


def _largest_events() -> dict:
    """peers.md, "Limits": the largest body of each type the limits allow,
    with a scheme-2 signature and a full envelope, under the 262,144-byte
    limit."""
    sig, envelope = SIG2, 64 + 32 * 3 + 256 * 35  # ed, kc, ids and 256 parents, generously
    wide = kg.encode_set(tuple(bytes([i]) * 32 for i in range(1, 65)))
    sizes = {
        "root": len(root_body(bytes(32), bytes(MLDSA_BYTES), bytes(MLDSA_BYTES), bytes(SIG2),
                              bytes(wraps.xwing.XWING_PK_SIZE))),
        "change, 64 grants": len(change_body(bytes(32), bytes(32), [{G_SLOT_ED: bytes(32),
                                                          G_SLOT_MLDSA_HASH: bytes(32),
                                                          G_TOKEN: bytes(TOKEN_WRAP_BYTES),
                                                          G_RANK: MAX_RANK}] * 64)),
        "enrol": len(enrol_body((bytes(32), 63, bytes(32)), bytes(MLDSA_BYTES), bytes(MLDSA_BYTES),
                                bytes(SIG2), bytes(BINDING_BYTES))),
        "disown": len(disown_body((bytes(32), 63, bytes(32)))),
        "ack": len(ack_body()),
        "erase": len(erase_body()),
        "credentials, 64 states of 64 rotations and 64 fetch keys": len(credentials_body(
            [(wide, i.to_bytes(32, "big")) for i in range(64)],
            [(i + 64).to_bytes(32, "big") for i in range(64)])),
        "release": len(release_body(bytes(STREAM_BYTES))),
        "restore": len(restore_body(snapshot=bytes(32))),
    }
    return {k: v + sig + envelope for k, v in sizes.items()}


def _merge_cap() -> dict:
    """peers.md, "Retirement and the cap": a writer floods junk merge
    statements for one state. Live merge entries of a state are capped at 4,
    the oldest never proved going first, so the honest entry, proved by a
    present, stays live; under the space's cap, unproved merge entries go
    before any rotation's entry."""
    r, a, b = _merge_space()
    space = r.id
    state = kg.encode_set(kg.canonical((a, b)))
    ids = kg.decode_set(state)
    k = kg.content_key(space, ids, r.krot.__getitem__)
    w = kg.upload_seed(space, ids, r.wrot.__getitem__)

    def statement(read, upload):
        msg = merge_message(space, state, read, upload)
        return encode_merge(space, state, read, upload,
                            [ed25519_sign_deterministic(r.upload_seed(x), msg) for x in ids])

    def fresh(cap=CREDENTIAL_CAP):
        cred = Credentials(r.log, cap)
        for x in r.log.canonical():
            if r.log.events[x].kind == KIND_SPACE and roster.read_visible(r.log.events[x])["rotates"]:
                cred.add_rotation(x)
        return cred

    honest_read = kg.read_credential(k)["public"]
    honest = statement(honest_read, kg.upload_key(w)["public"])
    junk = [statement(ed25519_public(example(f"storage/junk/{n}/read")),
                      ed25519_public(example(f"storage/junk/{n}/upload"))) for n in range(5)]
    binding = _bindings_of_connections()[0]
    cred = fresh()
    cred.merge(honest, space)
    proof = make_proof(kg.read_credential(k)["seed"], binding, space, READ_CREDENTIAL,
                       honest_read)
    proved = cred.check_present(READ_CREDENTIAL, space, honest_read, proof["proof"],
                                {"binding": binding, "purpose": SPACE_TRAFFIC})
    verdicts = [cred.merge(j, space) for j in junk]
    small = fresh(cap=len(fresh().live()) + 1)
    small.merge(junk[0], space)
    small_verdict = small.merge(honest, space)
    return {"statements": {"honest": h(honest), "junk": [h(j) for j in junk]},
            "per_state": {"present": proved, "junk_verdicts": verdicts,
                          "entries": cred.describe(r.name)},
            "space_cap": {"cap": small.cap, "honest": small_verdict,
                          "entries": small.describe(r.name), "reports": small.reports}}


def _merge_space():
    r = StorageRoster("P", "storage/merge")
    r.root("P0")
    r.sync("P", "P0")
    r.grant("P", "W", roster.WRITE, label="P grants W write")
    r.sync("P", "P0", "W")
    base = set(r.hist.view["P"])
    a = r.heal("P", "P rotates", view=base)
    b = r.heal("W", "W rotates", view=base)
    return r, a, b


def _expect(function, *args) -> str:
    try:
        function(*args)
    except SpecError as error:
        return error.error
    return "accepted"


def self_test() -> None:
    for new in NEW_LABELS:
        for other in NEW_LABELS:
            if other is not new:
                assert not other.startswith(new), (new, other)
    hist = main_history()
    r, ids = hist["r"], hist["ids"]
    sk = r.skeleton()
    assert sk.root == ids["root"]
    assert sk.valid(ids["twin_a"]) and sk.valid(ids["enrol_a"])
    assert sk.status[ids["erase_a1"]][1] == "RemovedConcurrently"
    # P removed A, which never acknowledges its removal: P's later erasure waits for T.
    assert sk.valid(ids["erase_p0"]) and not sk.stable(ids["erase_p0"])
    assert sk.valid(ids["erase_unstable"]) and not sk.stable(ids["erase_unstable"])
    rep = Replica(r)
    for key in ("genesis", "grant_a", "remove_a", "grant_b"):
        assert rep.verdicts[ids[key]][0] == "valid", (key, rep.verdicts[ids[key]])
    assert rep.device_of[r.hist.device("A1")] == r.hist.device("A")
    requests = {i: sk.body[i] for i in sk.requests_}
    assert not released(r.log, requests, stream("notes"))
    # The history's unit passes units.md's checks at a peer.
    assert units.peer_check(r.log.events[ids["unit"]].signed)[1][units.B_STREAM] == stream("notes")
    # A token that does not open for another grantee is BadToken.
    ta = sk.body[ids["twin_a"]]["grants"][0]
    c_a = twin_of(r, ids["grant_a"])["c"]
    assert _expect(open_token, ta[G_TOKEN], r.id, c_a, 0, r.hist.device("B"),
                   r.hist.signer("A").xwing_seed, ta) == "BadToken"
    assert _expect(open_token, ta[G_TOKEN][:-1], r.id, c_a, 0, r.hist.device("A"),
                   r.hist.signer("A").xwing_seed, ta) == "BadToken"
    v = peers_vectors()
    assert set(v) == {"specification", "parameters", "proofs", "merge_statement", "skeleton",
                      "twin_checks", "resolution", "stability", "credentials", "merge_cap",
                      "decisions", "recovery_entries", "erase_bodies", "skeleton_cuts"}
    tc = v["twin_checks"]
    assert tc["root_founder_keys_not_committed"]["peer"] == "NotCommitted"
    assert tc["root_founder_keys_not_committed"]["replica"] == "BadTwin"
    assert tc["twin_not_cited"]["verdict"] == "NoTwin"
    assert (tc["twin_not_cited"]["with_the_twin"], tc["twin_not_cited"]["reason_with_the_twin"]) \
        == ("BadTwin", "parents")
    assert tc["passes"]["verdict"] == "valid"
    for bad, why in (("wrong_grants", "grants"), ("parent_not_a_skeleton_event", "parents"),
                     ("another_administrators_pseudonym", "author"),
                     ("names_no_twin", "names no twin"), ("forked_pseudonym", "forked")):
        expect = ("TwinRequired", None) if bad == "names_no_twin" else ("BadTwin", why)
        assert (tc[bad]["verdict"], tc[bad]["reason"]) == expect, (bad, tc[bad])
    junk = tc["unnamed_change_with_its_commitment"]
    assert junk["verdict"] == "valid"
    assert "Unnamed" in junk["peer"]["events"].values()
    res = v["resolution"]
    attack = res["disown_attack"]
    assert attack["erase_stable_without_the_rule"] and not attack["erase_stable"]
    assert not attack["erase_stable_within_T"] and attack["erase_stable_after_T"]
    assert attack["peer_after_response"]["events"]["A1 erases the space"].startswith(
        "RemovedConcurrently")
    ke = res["lowers_named_by_key_events"]
    assert ke["lowers_applied"] and ke["erase_stable_without_the_rule"]
    assert not ke["erase_stable"] and not ke["erase_stable_within_T"]
    assert ke["erase_stable_after_T"]
    rc = res["repeated_commitment"]
    assert [m for _, _, m in rc["disown_lowers"]] == [
        "A1: a change with the commitment of B's grant"]
    assert "P0: twin of P grants B administer" in [m for _, _, m in rc["peer"]["administrators"]]
    assert not rc["erase_stable"] and not rc["erase_stable_once_P0_acknowledges"]
    assert rc["erase_stable_once_B1_acknowledges"]
    gm = res["grant_map_copy"]
    assert gm["copy_repeats"] and gm["peer"]["events"]["B1: enrols, the copy in its past"] \
        == "valid" and all(gm["justified"].values())
    assert gm["enrolled"][0][2] == "P0: twin of P grants B administer"
    lc = res["lower_of_a_copy"]
    assert lc["founder"][0] in lc["peer"]["administrators"]
    assert lc["lowers"][0][2] == "A1: a change with the commitment of the root"
    um = res["unknown_makers"]["peer"]["events"]
    assert um["P0 disowns [c(A's grant), 0]: two elements"] == "Malformed"
    assert sum(v == "UnknownAdministratorSlot" for v in um.values()) == 4
    pl = res["planted_limit"]
    assert pl["peer"]["events"]["A1: copy 6 of A's commitment, one grant"] == "PlantedSlotsFull"
    assert pl["peer"]["events"]["A1: copy 4 of A's commitment, 64 grants"] == "valid"
    assert pl["peer"]["events"]["B1: enrols"] == "valid"
    assert set(pl["replica"].values()) == {"valid"} and len(pl["repeats"]) == 5
    cost = res["removal_cost"]
    assert not cost["erase_stable"] and not cost["erase_stable_within_T"]
    assert cost["erase_stable_after_T"] and cost["erase_stable_once_A_acknowledges"]
    cap = v["merge_cap"]
    assert any(e["proved"] and e["status"] == "live" for e in cap["per_state"]["entries"])
    assert cap["space_cap"]["reports"] == []
    for size in _largest_events().values():
        assert size <= MAX_STORAGE_EVENT, size
    assert set(_largest_events()) >= {"root", "ack", "disown", "release", "restore", "enrol"}
    fp = tc["foreign_enrolment_and_planted_administrator_slot"]
    assert all(fp["justified"].values()) and fp["planted"]
    assert [c["verdict"] for c in v["merge_statement"]["cases"]] == [
        "accepted", "Malformed", "BadSignature", "UnknownState", "UnknownState"]
    assert [c["verdict"] for c in v["proofs"]["cases"]] == [
        "fetch, live", "store, release", "catch-up", "RetiredCredential", "erase",
        "purpose_violation", "UnknownCredential", "BadProof", "BadProof", "BadProof"]
    assert [c["verdict"] for c in v["proofs"]["stores"]] == [
        "accepted", "NotAuthorized", "NotAuthorized", "accepted", "NotAuthorized", "accepted",
        "NotAuthorized"]
    assert all(c["code"] == "not_authorized" for c in v["proofs"]["stores"]
               if c["verdict"] == "NotAuthorized")
    assert v["credentials"]["cap"]["every_entry_maximal"]["reports"] == ["KeyStateFull"]
    mutual = res["mutual_lowering"]["peer"]
    # Equal ranks: P's slot, the root's and the more senior, stands.
    assert len(mutual["administrators"]) == 1 and mutual["events"][
        "P0 erases the space, before seeing A's removal"] == "valid" and mutual["events"][
        "A1 erases the space, before seeing P's removal"].startswith("RemovedConcurrently"), \
        mutual
    assert set(res["concurrent_enrolments"]["peer"]["events"].values()) >= {
        "ConcurrentEnrolment"}
    st = v["stability"]["requests"]
    assert st["P0 erases the space"]["stable_after_T"]
    assert not st["P0 erases the space"]["stable_within_T"]
    assert not st["P0 erases the space again"]["stable_after_T"]
    eb = v["erase_bodies"]
    assert [b["verdict"] for b in eb] == ["accepted"] + ["Malformed"] * (len(eb) - 1)
    re_ = v["recovery_entries"]
    assert [s["verdict"] for s in re_["steps"] if "verdict" in s] == [
        "accepted", "accepted", "InvalidKey", "CredentialRefused", "accepted", "accepted",
        "accepted", "accepted", "RecoveryEntriesFull", "accepted"]
    assert [p["verdict"] for p in re_["presents"]] == [
        "catch-up", "RetiredCredential", "purpose_violation", "UnknownCredential"]
    assert [b["verdict"] for b in re_["bodies"]] == [
        "accepted", "accepted", "accepted", "Malformed", "Malformed", "Malformed", "InvalidKey"]
    assert re_["steps"][-2]["code"] == "recovery_entries_full"
    assert v == peers_vectors(), "the vectors are not deterministic"


if __name__ == "__main__":
    import json
    self_test()
    print(json.dumps(peers_vectors(), indent=1)[:2000])
