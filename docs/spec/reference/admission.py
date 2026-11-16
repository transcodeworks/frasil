"""Admission (admission.md), written from the specification, independently of any
implementation: the mutual admission code, its transcript and messages, the
seal of its messages, exchange mailboxes at a peer, the setup code, the
welcome, lookup prompts and Joins, access requests, and the body keys a
newcomer needs and their top-up.

It also builds what ext-invite-links.md defines on top of admission (the
invite key, the link, the drop, the invite grant and the successor), for
that extension's vectors only; admission.json carries none of it. roster.py
reads member type 3, op 4 and change keys 13 and 14; this module uses its
`Space` directly (`AdmissionSpace` names it). Events are built with
events.py's and roster.py's functions."""

from __future__ import annotations

import base64
import hmac
from dataclasses import dataclass

import events
import history_sigs as hs
import identity
import keygraph as kg
import roster
import wraps
import xwing
from events import KIND_SPACE, cbor, h, is_bytes, is_uint, uncbor
from formats import example, hybrid_key_valid, identifier_ok
from primitives import (
    SpecError, ed25519_valid, field, hkdf, sha256, xchacha20poly1305_open,
    xchacha20poly1305_seal,
)

# ---------------------------------------------------------------------------
# Labels (crypto.md, "The label registry").

COMMIT_LABEL = b"frasil/admission/commit/v1"
CODE_LABEL = b"frasil/admission/code/v1"
HEADS_LABEL = b"frasil/admission/heads/v1"
SEAL_LABEL = b"frasil/admission/seal/v1"
SETUP_MAC_LABEL = b"frasil/admission/setup/v1"
SETUP_TAG_LABEL = b"frasil/admission/setup-tag/v1"
INVITE_LOCATOR_LABEL = b"frasil/invite/locator/v1"
INVITE_DROP_LABEL = b"frasil/invite/drop/v1"
WELCOME_LABEL = b"frasil/welcome/v1"
ACCESS_REQUEST_LABEL = b"frasil/access-request/v1"
WELCOME_REQUEST_LABEL = b"frasil/welcome-request/v1"
PROMPT_LABEL = b"frasil/admission/prompt/v1"
NEW_LABELS = [COMMIT_LABEL, CODE_LABEL, HEADS_LABEL, SEAL_LABEL, SETUP_MAC_LABEL,
              SETUP_TAG_LABEL, INVITE_LOCATOR_LABEL, INVITE_DROP_LABEL, WELCOME_LABEL,
              ACCESS_REQUEST_LABEL, WELCOME_REQUEST_LABEL, PROMPT_LABEL]
ADMISSION_LABELS = [COMMIT_LABEL, CODE_LABEL, HEADS_LABEL, SEAL_LABEL,
                    SETUP_MAC_LABEL, SETUP_TAG_LABEL, PROMPT_LABEL, WELCOME_LABEL,
                    ACCESS_REQUEST_LABEL, WELCOME_REQUEST_LABEL]

# Labels this module derives with from other documents: the invite key's
# (ext-invite-links.md, "The secret, its keys and the link") and the mailbox
# address (transport.md, "Mailboxes").
INVITE_SALT = identity.INVITE_SALT
INVITE_HYBRID_INFO = identity.INVITE_HYBRID_LABEL
MAILBOX_LABEL = b"frasil/mailbox/v1"
MAILBOX_EXCHANGE, MAILBOX_PERSON, MAILBOX_DEVICE, MAILBOX_DROP = 1, 2, 3, 4

# ---------------------------------------------------------------------------
# Constants.

VERSION = 1
CTX_LIST, CTX_SPACE = 0x01, 0x02
JOINER_DEVICE, JOINER_PERSON = 0, 1
LIFETIME = 900          # overview.md, admission_code_lifetime
SKEW = 60               # overview.md, admission_code_skew
MAILBOX_GRACE = 60      # overview.md, exchange_mailbox_lifetime: expires_at + 60
MAX_DISPLAY = 256
MAX_HEADS = 256
MAX_HINTS = 8
MAX_LOCATION = 512
REQUEST_BYTES = 16
NONCE_BYTES = 32
SETUP_SECRET_BYTES = 16
SETUP_TAG_BYTES = 8
SETUP_CODE_BYTES = 1 + 32 + SETUP_SECRET_BYTES
SETUP_PREFIX = "FRASIL-SETUP:"
ADMIT_PREFIX = "FRASIL-ADMIT:"

# Exchange messages (admission.md, "Messages").
M_REQUEST, M_RESPONSE, M_REVEAL, M_LIST, M_RESULT, M_CANCEL, M_JOIN = 1, 2, 3, 4, 5, 6, 7
M_HELLO, M_OFFER, M_WELCOME = 8, 9, 10
M_NAMES = {M_REQUEST: "Request", M_RESPONSE: "Response", M_REVEAL: "Reveal", M_LIST: "List",
           M_RESULT: "Result", M_CANCEL: "Cancel", M_JOIN: "Join", M_HELLO: "Hello",
           M_OFFER: "Offer", M_WELCOME: "Welcome"}
MAX_MESSAGE = 262_144
MAX_REQUEST_MESSAGE = 4_096

# Exchange mailboxes at a peer (admission.md, "Exchange mailboxes").
MAILBOX_NEW_PER_MINUTE = 10
MAILBOX_MAX_PER_SOURCE = 128
MAILBOX_MAX_TOTAL = 65_536
MAILBOX_MAX_BYTES = 256 * 1024 * 1024

# A peer's refusals on the wire (admission.md, "Error classes").
REASONS = {"Malformed": ("malformed", 400), "MailboxInUse": ("mailbox_in_use", 409),
           "UnknownMailbox": ("unknown_mailbox", 404), "Expired": ("expired", 410),
           "Cancelled": ("cancelled", 410), "Duplicate": ("duplicate", 409),
           "OutOfOrder": ("out_of_order", 409), "RateLimited": ("rate_limited", 429),
           "MailboxFull": ("mailbox_full", 503)}

# The invite in the roster (ext-invite-links.md, "The invite grant and the
# successor").
INVITE = roster.INVITE          # member type 3: the invite key
SUCCEED = roster.SUCCEED        # op 4: the successor
C_EXPIRES = roster.C_EXPIRES    # change key 13: expires_at (an invite; a session's grant)
C_CLAIMS = roster.C_CLAIMS      # change key 14: what the successor may grant
MAX_U64 = (1 << 64) - 1
LINK_VERSION = 1
LINK_BYTES = 1 + 32 + 32 + 32
DROP_MAX_BYTES = 65_536
DROP_MIN_BYTES = 24 + 16

# Offer keys mirror the roster's change keys (admission.md, "The offer").
O_LEVEL, O_CAPS, O_LABEL, O_HISTORY, O_SESSION, O_REPLACES, O_EXPIRES = 2, 3, 4, 5, 7, 8, 13


def u8(n: int) -> bytes:
    return bytes([n])


def u16be(n: int) -> bytes:
    return n.to_bytes(2, "big")


def u64be(n: int) -> bytes:
    return n.to_bytes(8, "big")


def eseed(label: str) -> bytes:
    """64 bytes of X-Wing encapsulation randomness, fixed for the vectors."""
    return example(label + "/1") + example(label + "/2")


def _text_ok(value, maximum: int = 64) -> bool:
    return (isinstance(value, str) and 1 <= len(value.encode()) <= maximum
            and identifier_ok(value))


def _display_ok(value) -> bool:
    return isinstance(value, str) and len(value.encode()) <= MAX_DISPLAY


def _map(data: bytes, keys: set, required: set) -> dict:
    try:
        value = uncbor(data)
    except SpecError:
        raise SpecError("Malformed")
    if not isinstance(value, dict) or cbor(value) != data:
        raise SpecError("Malformed")
    if set(value) - keys or not required <= set(value):
        raise SpecError("Malformed")
    return value


def check_expiry(expires_at: int, now_wall: int | None, lifetime: int = LIFETIME,
                 skew: int = SKEW) -> None:
    """overview.md, check_expiry, in order. A receiver whose wall clock is
    not known refuses."""
    if now_wall is None:
        raise SpecError("Expired")
    if expires_at > now_wall + lifetime + skew:
        raise SpecError("Malformed")
    if now_wall > expires_at:
        raise SpecError("Expired")


# ---------------------------------------------------------------------------
# The transcript (admission.md, "The transcript and the code").


def heads_hash(log: bytes, heads) -> bytes:
    """The hash of a log's heads as one side holds them, sorted."""
    heads = sorted(set(heads))
    if not 1 <= len(heads) <= MAX_HEADS or any(len(x) != 32 for x in heads):
        raise SpecError("Malformed")
    return sha256(HEADS_LABEL + field(log) + u16be(len(heads)) + b"".join(heads))


def j_fields(ctx: int, request: bytes, expires_at: int, eph_j: bytes, joiner_type: int,
             joiner: bytes, display: bytes) -> bytes:
    """J_fields."""
    assert len(request) == REQUEST_BYTES and len(eph_j) == xwing.XWING_PK_SIZE
    assert len(joiner) == (32 if joiner_type == JOINER_DEVICE else 64)
    return (u8(ctx) + request + u64be(expires_at) + field(eph_j) + u8(joiner_type) + joiner
            + field(display))


def i_fields(ctx: int, log: bytes, target_heads: bytes, approver: bytes, eph_i: bytes,
             offer: bytes, display: bytes) -> bytes:
    """I_fields."""
    assert len(log) == 32 and len(target_heads) == 32 and len(approver) == 32
    return (u8(ctx) + log + target_heads + approver + field(eph_i) + field(offer)
            + field(display))


def commitment(jf: bytes, nonce_j: bytes) -> bytes:
    return sha256(COMMIT_LABEL + field(jf) + nonce_j)


def code_hash(jf: bytes, if_: bytes, channel: bytes, nonce_j: bytes, nonce_i: bytes) -> bytes:
    return sha256(CODE_LABEL + field(jf) + field(if_) + field(channel) + nonce_j + nonce_i)


def code(digest: bytes) -> str:
    """64 bits of the code hash modulo 10^6, as six digits."""
    return f"{int.from_bytes(digest[:8], 'big') % 1_000_000:06d}"


def grouped(digits: str) -> str:
    return digits[:3] + " " + digits[3:]


# ---------------------------------------------------------------------------
# The offer (admission.md, "The offer").


def encode_offer(level: int, history: int, *, caps=None, label: str | None = None,
                 session: bytes | None = None, expires_at: int | None = None,
                 replaces: bytes | None = None) -> bytes:
    out = {O_LEVEL: level, O_HISTORY: history}
    if caps:
        out[O_CAPS] = [[n, m] for n, m in sorted(caps, key=lambda c: c[0].encode())]
    if label is not None:
        out[O_LABEL] = label
    if session is not None:
        out[O_SESSION] = session
    if expires_at is not None:
        out[O_EXPIRES] = expires_at
    if replaces is not None:
        out[O_REPLACES] = replaces
    return cbor(out)


def read_offer(data: bytes, ctx: int, joiner_type: int, *, guests: bool = False) -> dict:
    """admission.md, "The offer": Malformed unless the offer has this shape.
    A core joiner refuses key 13, a session's expiry, as Malformed
    (admission.md, "Invite links and guests"); `guests` reads it as
    ext-guests.md does, only beside `session`."""
    if ctx == CTX_LIST:
        if data != b"":
            raise SpecError("Malformed")
        return {}
    allowed = {O_LEVEL, O_CAPS, O_LABEL, O_HISTORY, O_SESSION, O_REPLACES}
    if guests:
        allowed.add(O_EXPIRES)
    value = _map(data, allowed, {O_LEVEL, O_HISTORY})
    if value[O_LEVEL] not in roster.LEVEL_NAMES or value[O_HISTORY] not in (0, 1):
        raise SpecError("Malformed")
    if O_SESSION in value and (joiner_type != JOINER_DEVICE or not is_bytes(value[O_SESSION], 16)):
        raise SpecError("Malformed")
    if O_EXPIRES in value and (O_SESSION not in value or not is_uint(value[O_EXPIRES])
                               or value[O_EXPIRES] > MAX_U64):
        raise SpecError("Malformed")
    if O_REPLACES in value and (joiner_type != JOINER_PERSON
                                or not is_bytes(value[O_REPLACES], 32)):
        raise SpecError("Malformed")
    if value[O_LEVEL] == roster.ADMINISTER and (joiner_type != JOINER_DEVICE
                                                or O_SESSION in value):
        raise SpecError("Malformed")
    if O_LABEL in value and not _text_ok(value[O_LABEL]):
        raise SpecError("Malformed")
    caps = value.get(O_CAPS)
    if caps is not None:
        if not isinstance(caps, list) or not 1 <= len(caps) <= roster.MAX_CAPS:
            raise SpecError("Malformed")
        names = []
        for c in caps:
            if not (isinstance(c, list) and len(c) == 2 and _text_ok(c[0]) and c[1] in (0, 1)):
                raise SpecError("Malformed")
            names.append(c[0].encode())
        if any(a >= b for a, b in zip(names, names[1:])):
            raise SpecError("Malformed")
    return value


# ---------------------------------------------------------------------------
# Exchange messages and their seal (admission.md, "Messages" and "The seal").


def envelope(mtype: int, request: bytes, body: bytes) -> bytes:
    return u8(VERSION) + u8(mtype) + request + body


def read_envelope(data: bytes) -> dict:
    """admission.md, "Messages": reading a message, in order, as a peer and
    both sides read one."""
    if len(data) < 1:
        raise SpecError("Malformed")
    if data[0] != VERSION:
        raise SpecError("UnsupportedVersion")
    if len(data) < 2 + REQUEST_BYTES or data[1] not in M_NAMES:
        raise SpecError("Malformed")
    limit = MAX_REQUEST_MESSAGE if data[1] in (M_REQUEST, M_CANCEL) else MAX_MESSAGE
    if len(data) > limit:
        raise SpecError("TooLarge")
    if data[1] == M_CANCEL and len(data) != 2 + REQUEST_BYTES:
        raise SpecError("Malformed")
    return {"type": data[1], "request": data[2:2 + REQUEST_BYTES], "body": data[2 + REQUEST_BYTES:]}


def seal_info(request: bytes, mtype: int) -> bytes:
    """crypto.md's wrap info for an exchange message: the label, the suite,
    then the request and the message type."""
    return wraps.wrap_info(SEAL_LABEL, request + u8(mtype))


def seal_body(mtype: int, request: bytes, recipient_eph: bytes, plaintext: bytes,
              enc_seed: bytes) -> bytes:
    """admission.md, "The seal": crypto.md's wrap to the recipient's X-Wing
    key, `0x01 || u16be(0x647a) || enc || ciphertext`."""
    return wraps.seal_wrap(recipient_eph, seal_info(request, mtype), plaintext, enc_seed)["wrap"]


def open_body(mtype: int, request: bytes, eph_seed: bytes, body: bytes) -> bytes:
    """crypto.md, "Opening a wrap", with step 5 requiring at least 1,139
    bytes."""
    return wraps.open_wrap(body, eph_seed, seal_info(request, mtype))


@dataclass
class DeviceKeys:
    """A joining device's three key pairs, from fixed seeds in the vectors,
    and the device ID they give (crypto.md, "A device's keys")."""
    name: str
    signer: hs.Signer

    @property
    def identity(self) -> bytes:
        """The Ed25519 key, the Reveal's and the Hello's `identity`."""
        return self.signer.ed_public

    @property
    def hybrid_seed(self) -> bytes:
        return self.signer.xwing_seed

    @property
    def hybrid(self) -> bytes:
        return self.signer.xwing_public

    xwing_seed = hybrid_seed
    xwing = hybrid

    @property
    def device_id(self) -> bytes:
        return self.signer.device_id

    def digest(self, ctx: int | None = None) -> bytes:
        """The joiner of a device: its device ID."""
        return self.device_id


def device_keys(name: str) -> DeviceKeys:
    seed = example(f"admission/{name}/ed25519")
    signer = hs.Signer(name, seed, hs.device_mldsa_seed_fixture(seed),
                       example(f"admission/{name}/xwing"))
    events.KNOWN_SIGNERS[signer.device_id] = signer
    return DeviceKeys(name, signer)


def roster_device_keys(r: roster.Roster, name: str) -> DeviceKeys:
    """A device of a roster.py history: its Ed25519 seed and the fixture
    ML-DSA-65 and X-Wing keys."""
    return DeviceKeys(name, r.hist.signer(name))


def possession_for(keys: DeviceKeys, ctx: int, person_id: bytes | None = None,
                   approver: bytes | None = None) -> bytes | None:
    """A Reveal's `possession`, for ctx 0x01 only: the possession statement
    over the person ID the Response named, with its approver as adder
    (identity.md). A device joining a space signs no statement over its
    keys: its device ID, in the committed J_fields, is what the grant names."""
    if ctx == CTX_SPACE:
        return None
    st = identity.possession_statement(person_id, approver, identity.DEVICE, keys.identity,
                                       keys.signer.mldsa_public, keys.hybrid)
    return identity.prove(keys.signer, st)


# Message bodies (admission.md, "Bodies").

R_NONCE, R_TYPE, R_IDENTITY, R_MLDSA, R_XWING, R_POSSESSION, R_DISPLAY = range(1, 8)
R_PERSON, R_HEADS = 8, 9


def request_body(ctx: int, expires_at: int, commit: bytes, eph_j: bytes) -> bytes:
    return cbor({1: ctx, 2: expires_at, 3: commit, 4: eph_j})


def read_request(body: bytes) -> dict:
    v = _map(body, {1, 2, 3, 4}, {1, 2, 3, 4})
    if v[1] not in (CTX_LIST, CTX_SPACE) or not is_uint(v[2]) or v[2] > MAX_U64 \
            or not is_bytes(v[3], 32) or not is_bytes(v[4], xwing.XWING_PK_SIZE):
        raise SpecError("Malformed")
    return {"ctx": v[1], "expires_at": v[2], "commitment": v[3], "eph": v[4]}


def response_plain(nonce_i: bytes, log: bytes, heads, approver: bytes, eph_i: bytes,
                   offer: bytes, display: str) -> bytes:
    return cbor({1: nonce_i, 2: log, 3: sorted(set(heads)), 4: approver, 5: eph_i, 6: offer,
                 7: display})


def _heads_ok(value) -> bool:
    return (isinstance(value, list) and 1 <= len(value) <= MAX_HEADS
            and all(is_bytes(x, 32) for x in value)
            and all(a < b for a, b in zip(value, value[1:])))


def read_response(plain: bytes) -> dict:
    v = _map(plain, set(range(1, 8)), set(range(1, 8)))
    if not (is_bytes(v[1], NONCE_BYTES) and is_bytes(v[2], 32) and _heads_ok(v[3])
            and is_bytes(v[4], 32) and is_bytes(v[5], xwing.XWING_PK_SIZE) and is_bytes(v[6])
            and _display_ok(v[7])):
        raise SpecError("Malformed")
    return {"nonce": v[1], "log": v[2], "heads": v[3], "approver": v[4], "eph": v[5],
            "offer": v[6], "display": v[7]}


def reveal_plain_device(nonce_j: bytes, keys: DeviceKeys, ctx: int, possession: bytes | None,
                        display: str) -> bytes:
    """A device's Reveal: its three public keys, and for ctx 0x01 its
    possession proof."""
    out = {R_NONCE: nonce_j, R_TYPE: JOINER_DEVICE, R_IDENTITY: keys.identity,
           R_MLDSA: keys.signer.mldsa_public, R_XWING: keys.hybrid, R_DISPLAY: display}
    if ctx == CTX_LIST:
        out[R_POSSESSION] = possession
    return cbor(out)


def reveal_plain_person(nonce_j: bytes, person_id: bytes, heads, display: str) -> bytes:
    return cbor({R_NONCE: nonce_j, R_TYPE: JOINER_PERSON, R_DISPLAY: display,
                 R_PERSON: person_id, R_HEADS: sorted(set(heads))})


def read_reveal(plain: bytes, ctx: int) -> dict:
    v = _map(plain, set(range(1, 10)), {R_NONCE, R_TYPE, R_DISPLAY})
    if v[R_TYPE] == JOINER_DEVICE:
        need = set(range(1, 8)) - ({R_POSSESSION} if ctx == CTX_SPACE else set())
        if set(v) != need or not (
                is_bytes(v[R_NONCE], NONCE_BYTES) and is_bytes(v[R_IDENTITY], 32)
                and is_bytes(v[R_MLDSA], hs.MLDSA_PUBLIC_KEY_BYTES)
                and is_bytes(v[R_XWING], xwing.XWING_PK_SIZE)
                and _display_ok(v[R_DISPLAY])
                and (ctx != CTX_LIST
                     or is_bytes(v[R_POSSESSION], hs.HYBRID_SIGNATURE_BYTES))):
            raise SpecError("Malformed")
        return {"nonce": v[R_NONCE], "type": JOINER_DEVICE, "identity": v[R_IDENTITY],
                "mldsa": v[R_MLDSA], "xwing": v[R_XWING], "possession": v.get(R_POSSESSION),
                "display": v[R_DISPLAY]}
    if v[R_TYPE] != JOINER_PERSON or ctx != CTX_SPACE \
            or set(v) != {R_NONCE, R_TYPE, R_DISPLAY, R_PERSON, R_HEADS} or not (
            is_bytes(v[R_NONCE], NONCE_BYTES) and is_bytes(v[R_PERSON], 32)
            and _heads_ok(v[R_HEADS]) and _display_ok(v[R_DISPLAY])):
        raise SpecError("Malformed")
    return {"nonce": v[R_NONCE], "type": JOINER_PERSON, "person": v[R_PERSON],
            "heads": v[R_HEADS], "display": v[R_DISPLAY]}


def joiner_part(reveal: dict, ctx: int | None = None) -> tuple[int, bytes]:
    if reveal["type"] == JOINER_DEVICE:
        return JOINER_DEVICE, hs.device_id_of(reveal["identity"], reveal["mldsa"], reveal["xwing"])
    return JOINER_PERSON, reveal["person"] + heads_hash(reveal["person"], reveal["heads"])


# ---------------------------------------------------------------------------
# The joiner and the approver (admission.md, "The joiner" and "The approver").


class Approver:
    """admission.md, "The approver": an administering device of the space
    (ctx 0x02), or a list member of the person (ctx 0x01). `guests` lets it
    offer ext-guests.md's key 13."""

    def __init__(self, approver: bytes, ctx: int, log: bytes, heads, offer: bytes,
                 display: str, eph_seed: bytes, nonce_i: bytes, channel: bytes = b"", *,
                 guests: bool = False):
        self.approver, self.ctx, self.log, self.heads = approver, ctx, log, sorted(set(heads))
        self.offer, self.display, self.channel = offer, display, channel
        self.eph_seed, self.eph = eph_seed, xwing.xwing_public_key(eph_seed)
        self.nonce_i = nonce_i
        self.guests = guests
        self.answered: dict = {}
        self.ended: set = set()

    def i_fields(self) -> bytes:
        return i_fields(self.ctx, self.log, heads_hash(self.log, self.heads), self.approver,
                        self.eph, self.offer, self.display.encode())

    def on_request(self, message: bytes, now: int | None, enc_seed: bytes) -> bytes:
        """Steps 1 to 6, in order."""
        env = read_envelope(message)
        if env["type"] != M_REQUEST:
            raise SpecError("Malformed")
        req = read_request(env["body"])
        check_expiry(req["expires_at"], now)
        if env["request"] in self.answered:
            raise SpecError("Replayed")
        if req["ctx"] != self.ctx:
            raise SpecError("Malformed")
        if not hybrid_key_valid(req["eph"]):
            raise SpecError("InvalidKey")
        self.answered[env["request"]] = req
        plain = response_plain(self.nonce_i, self.log, self.heads, self.approver, self.eph,
                               self.offer, self.display)
        return envelope(M_RESPONSE, env["request"],
                        seal_body(M_RESPONSE, env["request"], req["eph"], plain, enc_seed))

    def on_reveal(self, message: bytes, now: int | None) -> dict | None:
        """Steps 7 to 12, in order; the code for step 13. One Reveal per
        request: after it, or after any failure, the request has ended, and
        a later Reveal is ignored (None)."""
        env = read_envelope(message)
        req = self.answered.get(env["request"])
        if env["type"] != M_REVEAL or req is None:
            raise SpecError("Malformed")
        if env["request"] in self.ended:
            return None
        self.ended.add(env["request"])
        if now is None or now > req["expires_at"]:
            raise SpecError("Expired")
        reveal = read_reveal(open_body(M_REVEAL, env["request"], self.eph_seed, env["body"]),
                             self.ctx)
        jtype, joiner = joiner_part(reveal)
        jf = j_fields(self.ctx, env["request"], req["expires_at"], req["eph"], jtype, joiner,
                      reveal["display"].encode())
        if commitment(jf, reveal["nonce"]) != req["commitment"]:
            raise SpecError("CommitmentMismatch")
        read_offer(self.offer, self.ctx, jtype, guests=self.guests)
        if jtype == JOINER_DEVICE:
            if not ed25519_valid(reveal["identity"]) or not hybrid_key_valid(reveal["xwing"]) \
                    or not hs.mldsa_key_valid(reveal["mldsa"]):
                raise SpecError("InvalidKey")
            # Step 12: for ctx 0x01 only, the possession proof.
            if self.ctx == CTX_LIST:
                st = identity.possession_statement(self.log, self.approver, identity.DEVICE,
                                                   reveal["identity"],
                                                   reveal["mldsa"], reveal["xwing"])
                if not identity.proof_ok(reveal["identity"], reveal["mldsa"], st,
                                         reveal["possession"]):
                    raise SpecError("BadPossession")
        digest = code_hash(jf, self.i_fields(), self.channel, reveal["nonce"], self.nonce_i)
        return {"reveal": reveal, "j_fields": jf, "code_hash": digest, "code": code(digest)}

    def welcome(self, request: bytes, plain: bytes, enc_seed: bytes) -> bytes:
        """admission.md, "A person's new device", over a direct connection: a
        Welcome after the Result, its welcome sealed to eph_J."""
        req = self.answered[request]
        return envelope(M_WELCOME, request,
                        seal_body(M_WELCOME, request, req["eph"], plain, enc_seed))


class Joiner:
    """admission.md, "The joiner": a person's new device, a device member or
    a guest, or a device of the person that joins. `guests` reads offers as
    ext-guests.md does."""

    def __init__(self, ctx: int, request: bytes, expires_at: int, eph_seed: bytes,
                 nonce_j: bytes, display: str, keys: DeviceKeys | None = None,
                 person: bytes | None = None, person_heads=None, channel: bytes = b"", *,
                 guests: bool = False, expected_person: bytes | None = None):
        self.ctx, self.request, self.expires_at = ctx, request, expires_at
        self.eph_seed, self.eph = eph_seed, xwing.xwing_public_key(eph_seed)
        self.nonce_j, self.display, self.keys = nonce_j, display, keys
        self.person, self.person_heads = person, sorted(set(person_heads or []))
        self.channel = channel
        self.guests = guests
        self.expected_person = expected_person
        self.response: dict | None = None

    def joiner(self) -> tuple[int, bytes]:
        if self.person is not None:
            return JOINER_PERSON, self.person + heads_hash(self.person, self.person_heads)
        return JOINER_DEVICE, self.keys.digest()

    def j_fields(self) -> bytes:
        jtype, joiner = self.joiner()
        return j_fields(self.ctx, self.request, self.expires_at, self.eph, jtype, joiner,
                        self.display.encode())

    def start(self) -> bytes:
        if len(self.display.encode()) > MAX_DISPLAY:
            raise SpecError("Malformed")
        body = request_body(self.ctx, self.expires_at,
                            commitment(self.j_fields(), self.nonce_j), self.eph)
        return envelope(M_REQUEST, self.request, body)

    def on_response(self, message: bytes, now: int, enc_seed: bytes) -> dict | None:
        """Steps 4 to 6: ignores (None) a Response past expiry, after the
        first accepted, that does not open and read, whose X-Wing key fails
        crypto.md's check, or whose offer does not suit this joiner; refuses
        (WrongPerson) a ctx 0x01 Response for another person than the one
        it expects, before it signs anything over log; reveals once."""
        try:
            env = read_envelope(message)
        except SpecError:
            return None
        if env["type"] != M_RESPONSE or env["request"] != self.request:
            return None
        if now > self.expires_at or self.response is not None:
            return None
        try:
            resp = read_response(open_body(M_RESPONSE, self.request, self.eph_seed,
                                           env["body"]))
            if not hybrid_key_valid(resp["eph"]):
                return None
            read_offer(resp["offer"], self.ctx, self.joiner()[0], guests=self.guests)
        except SpecError:
            return None
        if self.ctx == CTX_LIST and self.expected_person is not None \
                and resp["log"] != self.expected_person:
            raise SpecError("WrongPerson")
        self.response = resp
        if self.person is not None:
            plain = reveal_plain_person(self.nonce_j, self.person, self.person_heads,
                                        self.display)
        else:
            proof = possession_for(self.keys, self.ctx, resp["log"], resp["approver"])
            plain = reveal_plain_device(self.nonce_j, self.keys, self.ctx, proof, self.display)
        if_ = i_fields(self.ctx, resp["log"], heads_hash(resp["log"], resp["heads"]),
                       resp["approver"], resp["eph"], resp["offer"], resp["display"].encode())
        digest = code_hash(self.j_fields(), if_, self.channel, self.nonce_j, resp["nonce"])
        reveal = envelope(M_REVEAL, self.request,
                          seal_body(M_REVEAL, self.request, resp["eph"], plain, enc_seed))
        return {"reveal": reveal, "i_fields": if_, "code_hash": digest, "code": code(digest)}

    def on_welcome(self, message: bytes) -> dict:
        """admission.md, "A person's new device", over a direct connection,
        steps 1 and 2 of a Welcome's checks, once the Result was accepted."""
        env = read_envelope(message)
        if env["type"] != M_WELCOME or env["request"] != self.request or self.response is None:
            raise SpecError("Malformed")
        w = read_welcome(open_body(M_WELCOME, self.request, self.eph_seed, env["body"]))
        if w["approver"] != self.response["approver"]:
            raise SpecError("WrongApprover")
        return w


def check_grant(event: events.Event, decoded: roster.Decoded, log: events.Log, response: dict,
                joiner: Joiner, *, via: int = roster.VIA_CODE) -> None:
    """admission.md, "Accepting a grant", steps 1 to 6, in order: the joiner
    accepts only the grant the code authenticated. Its own resolution of the
    space (step 7) comes on top."""
    if event.author != response["approver"]:
        raise SpecError("WrongApprover")
    if event.log != response["log"]:
        raise SpecError("WrongSpace")
    past = log.anc[event.id]
    if not all(x in past for x in response["heads"]):
        raise SpecError("NotFollowing")
    jtype, _ = joiner.joiner()
    member = (roster.PERSON, joiner.person) if jtype == JOINER_PERSON \
        else (roster.DEVICE, joiner.keys.device_id)
    grants = [c for c in (decoded.changes or ()) if c.member == member and c.op == roster.GRANT]
    if len(grants) != 1:
        raise SpecError("WrongMember")
    c = grants[0]
    offer = uncbor(response["offer"])
    caps = tuple((n, m) for n, m in offer.get(O_CAPS, [])) or None
    want = (offer[O_LEVEL], caps, offer.get(O_LABEL), offer[O_HISTORY], offer.get(O_SESSION),
            offer.get(O_REPLACES), offer.get(O_EXPIRES), via)
    got = (c.level, c.caps, c.label, c.history, c.session, c.replaces,
           getattr(c, "expires_at", None), c.via)
    if want != got:
        raise SpecError("OfferMismatch")
    if c.replaces is not None and not any(o.op == roster.REMOVE
                                          and o.member == (roster.PERSON, c.replaces)
                                          for o in decoded.changes):
        raise SpecError("OfferMismatch")
    if offer[O_HISTORY] == roster.FROM_NOW_ON and not (decoded.rotates
                                                       and decoded.payload.get("break")):
        raise SpecError("OfferMismatch")


def list_result(signed_events) -> bytes:
    """The List, and the Result of ctx 0x01: every event of the person's
    list the sender holds, in a Result the new add included."""
    return cbor({1: VERSION, 2: list(signed_events)})


def check_list_result(plain: bytes, response: dict, joiner: Joiner) -> bytes:
    """admission.md, "A person's new device", at the new device, in order;
    returns the add's event ID."""
    v = _map(plain, {1, 2}, {1, 2})
    if v[1] != VERSION or not isinstance(v[2], list) or not v[2] \
            or not all(is_bytes(x) for x in v[2]):
        raise SpecError("Malformed")
    try:
        evs = [events.decode_event(x) for x in v[2]]
    except SpecError:
        raise SpecError("Malformed")
    first = [e for e in evs if e.genesis]
    if len(first) != 1 or first[0].kind != events.KIND_DEVICE_LIST \
            or first[0].id != response["log"]:
        raise SpecError("WrongPerson")
    log = events.Log(first[0])
    pending = [e for e in evs if not e.genesis]
    while pending:
        placed = [e for e in pending if all(p in log.events for p in e.parents)]
        if not placed:
            raise SpecError("Malformed")
        for e in placed:
            if e.log != log.id or log.add(e) != "placed":
                raise SpecError("Malformed")
        pending = [e for e in pending if e not in placed]
    keys = joiner.keys

    def names_j(e) -> bool:
        """An add whose key 3 is J's device ID. Its body's own checks
        (identity.md, NotCommitted among them) are step 7's."""
        try:
            value = uncbor(e.body)
        except SpecError:
            return False
        return (isinstance(value, dict) and value.get(identity.B_ACTION) == identity.ADD
                and value.get(identity.B_DEVICE) == keys.device_id)
    adds = [e for e in evs if not e.genesis and names_j(e)]
    if len(adds) != 1:
        raise SpecError("WrongMember")
    add = adds[0]
    if add.author != response["approver"]:
        raise SpecError("WrongApprover")
    if not all(x in log.anc[add.id] for x in response["heads"]):
        raise SpecError("NotFollowing")
    lst = identity.DeviceList(log)
    if not lst.status.get(add.id, (False,))[0]:
        raise SpecError("NotInList")
    return add.id


# ---------------------------------------------------------------------------
# Exchange mailboxes (admission.md, "Exchange mailboxes"): what a peer
# checks. Clients rely on none of it.


class Peer:
    """A peer's exchange mailboxes, by request ID, in memory only."""

    def __init__(self):
        self.mailboxes: dict = {}
        self.opened: dict = {}  # source -> times of the exchange mailboxes it opened
        self.bytes = 0

    def _sweep(self, now: int) -> None:
        """Drops each exchange mailbox after exchange_mailbox_lifetime."""
        for rid in [r for r, s in self.mailboxes.items() if now > s["drop_at"]]:
            self.bytes -= sum(len(m) for m in self.mailboxes[rid]["messages"].values())
            del self.mailboxes[rid]

    def put(self, source: str, message: bytes, now: int) -> str:
        """Steps 1 to 12, in order: "stored" or the class of the refusal."""
        self._sweep(now)
        try:
            env = read_envelope(message)
        except SpecError as error:
            return error.error
        rid, mtype = env["request"], env["type"]
        if mtype == M_REQUEST:
            if rid in self.mailboxes:
                return "MailboxInUse"
            try:
                req = read_request(env["body"])
                check_expiry(req["expires_at"], now)
            except SpecError as error:
                return error.error
            recent = [t for t in self.opened.get(source, []) if now - t < 60]
            mine = [s for s in self.mailboxes.values() if s["source"] == source]
            if len(recent) >= MAILBOX_NEW_PER_MINUTE or len(mine) >= MAILBOX_MAX_PER_SOURCE:
                return "RateLimited"
            if len(self.mailboxes) >= MAILBOX_MAX_TOTAL \
                    or self.bytes + len(message) > MAILBOX_MAX_BYTES:
                return "MailboxFull"
            self.opened[source] = recent + [now]
            self.mailboxes[rid] = {"source": source, "expires_at": req["expires_at"],
                                   "drop_at": req["expires_at"] + MAILBOX_GRACE,
                                   "messages": {M_REQUEST: message}, "cancelled": False}
            self.bytes += len(message)
            return "stored"
        if not M_RESPONSE <= mtype <= M_CANCEL:
            return "Malformed"  # a Join goes to a device's mailbox; Hello and Offer stay nearby
        box = self.mailboxes.get(rid)
        if box is None:
            return "UnknownMailbox"
        if now > box["expires_at"]:
            return "Expired"
        if box["cancelled"]:
            return "Cancelled"
        if mtype == M_CANCEL:
            box["cancelled"] = True
            return "stored"
        if mtype in box["messages"]:
            return "Duplicate"
        needs = {M_RESPONSE: M_REQUEST, M_REVEAL: M_RESPONSE, M_LIST: M_REVEAL,
                 M_RESULT: M_REVEAL}
        if needs[mtype] not in box["messages"]:
            return "OutOfOrder"
        if self.bytes + len(message) > MAILBOX_MAX_BYTES:
            return "MailboxFull"
        box["messages"][mtype] = message
        self.bytes += len(message)
        return "stored"


def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode().rstrip("=")


def _unb32(body: str) -> bytes:
    if not body or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" for ch in body):
        raise SpecError("Malformed")
    try:
        raw = base64.b32decode(body + "=" * (-len(body) % 8))
    except Exception:
        raise SpecError("Malformed")
    if _b32(raw) != body:
        raise SpecError("Malformed")
    return raw


def admit_qr(ctx: int, request: bytes, commit: bytes, location: str) -> str:
    """admission.md, "The QR code": where the joiner's exchange mailbox is."""
    return ADMIT_PREFIX + _b32(cbor({1: VERSION, 2: ctx, 3: request, 4: commit, 5: location}))


def read_admit_qr(text: str) -> dict:
    """admission.md, "The QR code": reading, in order."""
    if not text.startswith(ADMIT_PREFIX):
        raise SpecError("Malformed")
    v = _map(_unb32(text[len(ADMIT_PREFIX):]), {1, 2, 3, 4, 5}, {1, 2, 3, 4, 5})
    if v[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if v[2] not in (CTX_LIST, CTX_SPACE) or not is_bytes(v[3], REQUEST_BYTES) \
            or not is_bytes(v[4], 32) or not _text_ok(v[5], MAX_LOCATION):
        raise SpecError("Malformed")
    return {"ctx": v[2], "request": v[3], "commitment": v[4], "location": v[5]}


# ---------------------------------------------------------------------------
# The setup code (admission.md, "The setup code" and "Setup").


def setup_code(digest: bytes, secret: bytes) -> bytes:
    assert len(digest) == 32 and len(secret) == SETUP_SECRET_BYTES
    return u8(VERSION) + digest + secret


def setup_text(code_bytes: bytes) -> str:
    return SETUP_PREFIX + _b32(code_bytes)


def read_setup_text(text: str) -> dict:
    """admission.md, "The setup code": reading the text, in order."""
    if not text.startswith(SETUP_PREFIX):
        raise SpecError("Malformed")
    raw = _unb32(text[len(SETUP_PREFIX):])
    if raw[0] != VERSION:
        raise SpecError("UnsupportedVersion")
    if len(raw) != SETUP_CODE_BYTES:
        raise SpecError("Malformed")
    return {"digest": raw[1:33], "secret": raw[33:]}


def setup_tag(secret: bytes) -> bytes:
    return sha256(SETUP_TAG_LABEL + secret)[:SETUP_TAG_BYTES]


def setup_name(secret: bytes) -> str:
    """The name a device in setup mode announces nearby."""
    return "setup-" + setup_tag(secret).hex()


def setup_mac(secret: bytes, jf: bytes, if_: bytes, channel: bytes) -> bytes:
    return hmac.new(secret, SETUP_MAC_LABEL + field(jf) + field(if_) + field(channel),
                    "sha256").digest()


def hello(request: bytes, keys: DeviceKeys, eph_j: bytes, display: str) -> bytes:
    """The device's first message on the nearby connection, in the clear
    inside the connection."""
    body = cbor({1: eph_j, 2: keys.identity, 3: keys.signer.mldsa_public, 4: keys.hybrid,
                 5: display})
    return envelope(M_HELLO, request, body)


def read_hello(message: bytes) -> dict:
    env = read_envelope(message)
    if env["type"] != M_HELLO:
        raise SpecError("Malformed")
    v = _map(env["body"], set(range(1, 6)), set(range(1, 6)))
    if not (is_bytes(v[1], xwing.XWING_PK_SIZE) and is_bytes(v[2], 32)
            and is_bytes(v[3], hs.MLDSA_PUBLIC_KEY_BYTES) and is_bytes(v[4], xwing.XWING_PK_SIZE)
            and _display_ok(v[5])):
        raise SpecError("Malformed")
    return {"request": env["request"], "eph": v[1], "identity": v[2], "mldsa": v[3],
            "xwing": v[4], "display": v[5]}


def setup_offer(request: bytes, eph_j: bytes, log: bytes, heads, approver: bytes, eph_i: bytes,
                offer: bytes, display: str, mac: bytes, enc_seed: bytes) -> bytes:
    plain = cbor({1: log, 2: sorted(set(heads)), 3: approver, 4: eph_i, 5: offer, 6: display,
                  7: mac})
    return envelope(M_OFFER, request, seal_body(M_OFFER, request, eph_j, plain, enc_seed))


def read_setup_offer(message: bytes, eph_seed: bytes) -> dict:
    env = read_envelope(message)
    if env["type"] != M_OFFER:
        raise SpecError("Malformed")
    v = _map(open_body(M_OFFER, env["request"], eph_seed, env["body"]), set(range(1, 8)),
             set(range(1, 8)))
    if not (is_bytes(v[1], 32) and _heads_ok(v[2]) and is_bytes(v[3], 32)
            and is_bytes(v[4], xwing.XWING_PK_SIZE) and is_bytes(v[5]) and _display_ok(v[6])
            and is_bytes(v[7], 32)):
        raise SpecError("Malformed")
    return {"request": env["request"], "log": v[1], "heads": v[2], "approver": v[3],
            "eph": v[4], "offer": v[5], "display": v[6], "mac": v[7]}


class HeadlessDevice:
    """admission.md, "Setup", at the device: it binds to the first Offer
    whose MAC verifies and refuses every other until it is reset."""

    def __init__(self, keys: DeviceKeys, secret: bytes, request: bytes, eph_seed: bytes,
                 display: str):
        self.keys, self.secret, self.request = keys, secret, request
        self.eph_seed, self.eph = eph_seed, xwing.xwing_public_key(eph_seed)
        self.display = display
        self.bound: dict | None = None

    def j_fields(self) -> bytes:
        return j_fields(CTX_SPACE, self.request, 0, self.eph, JOINER_DEVICE,
                        self.keys.digest(), self.display.encode())

    def on_offer_message(self, message: bytes, channel: bytes) -> str:
        """Steps 1 to 5, in order: "bound" or the class of the refusal."""
        if self.bound is not None:
            return "Provisioned"
        try:
            o = read_setup_offer(message, self.eph_seed)
            if o["request"] != self.request:
                return "Malformed"
            read_offer(o["offer"], CTX_SPACE, JOINER_DEVICE)
        except SpecError as error:
            return error.error
        if_ = i_fields(CTX_SPACE, o["log"], heads_hash(o["log"], o["heads"]), o["approver"],
                       o["eph"], o["offer"], o["display"].encode())
        return self.on_offer(if_, o["mac"], channel)

    def on_offer(self, if_: bytes, mac: bytes, channel: bytes) -> str:
        if self.bound is not None:
            return "Provisioned"
        if not hmac.compare_digest(mac, setup_mac(self.secret, self.j_fields(), if_, channel)):
            return "BadMac"
        self.bound = {"i_fields": if_}
        return "bound"


def admin_check_setup(scanned: dict, hello: dict) -> str:
    """admission.md, "Setup", at the administrator, steps 2 and 3: the device
    ID of the Hello's keys is the scanned one, and the keys pass crypto.md's
    checks."""
    if hs.device_id_of(hello["identity"], hello["mldsa"], hello["xwing"]) != scanned["digest"]:
        return "SetupMismatch"
    if not ed25519_valid(hello["identity"]) or not hybrid_key_valid(hello["xwing"]) \
            or not hs.mldsa_key_valid(hello["mldsa"]):
        return "InvalidKey"
    return "accepted"


# ---------------------------------------------------------------------------
# Invite links and drops (ext-invite-links.md, "The secret, its keys and the
# link" and "The drop and its messages"). Not in admission.json.


def invite_keys(secret: bytes) -> dict:
    """The invite key K's Ed25519, X-Wing and ML-DSA-65 keys (identity.py's
    derivation), with a signer for K."""
    d = identity.invite_keys(secret)
    signer = identity.signer_of(d, "invite")
    assert signer.ed_public == d["identity"] and signer.device_id == d["device_id"]
    events.KNOWN_SIGNERS[signer.device_id] = signer
    return {"ed_seed": d["identity_seed"], "identity": d["identity"],
            "hybrid_seed": d["xwing_seed"], "hybrid": d["xwing"], "signer": signer,
            "mldsa_seed": d["mldsa_seed"], "mldsa": signer.mldsa_public,
            "kc": d["kc"], "device_id": d["device_id"]}


def link_fragment_raw(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def link_fragment(secret: bytes, entry: bytes, space: bytes) -> str:
    assert len(secret) == 32 and len(entry) == 32 and len(space) == 32
    return link_fragment_raw(u8(LINK_VERSION) + secret + entry + space)


def read_link_fragment(text: str) -> dict:
    """Reading a fragment, in order."""
    alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    if not text or any(ch not in alphabet for ch in text):
        raise SpecError("Malformed")
    try:
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception:
        raise SpecError("Malformed")
    if not raw or link_fragment_raw(raw) != text:
        raise SpecError("Malformed")
    if raw[0] != LINK_VERSION:
        raise SpecError("UnsupportedVersion")
    if len(raw) != LINK_BYTES:
        raise SpecError("Malformed")
    return {"secret": raw[1:33], "entry": raw[33:65], "space": raw[65:97]}


def drop_locator(secret: bytes) -> bytes:
    return hkdf(INVITE_SALT, secret, INVITE_LOCATOR_LABEL)


def drop_key(secret: bytes) -> bytes:
    return hkdf(INVITE_SALT, secret, INVITE_DROP_LABEL)


def drop_plain(key_name: bytes, grant_name: bytes, wrap: bytes, peers=(),
               snapshot=None) -> bytes:
    """Key 6, the locator of the snapshot for K, when the invite publishes
    one."""
    m = {1: VERSION, 2: key_name, 3: grant_name, 4: wrap, 5: list(peers)}
    if snapshot is not None:
        m[6] = snapshot
    return cbor(m)


def seal_drop(secret: bytes, plain: bytes, nonce: bytes) -> bytes:
    return nonce + xchacha20poly1305_seal(drop_key(secret), nonce, plain,
                                          INVITE_DROP_LABEL + drop_locator(secret))


def open_drop(secret: bytes, sealed: bytes) -> dict:
    """Opening a drop, in order."""
    if not DROP_MIN_BYTES <= len(sealed) <= DROP_MAX_BYTES:
        raise SpecError("Malformed")
    plain = xchacha20poly1305_open(drop_key(secret), sealed[:24], sealed[24:],
                                   INVITE_DROP_LABEL + drop_locator(secret))
    v = _map(plain, {1, 2, 3, 4, 5, 6}, {1, 2, 3, 4, 5})
    if v[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if not is_bytes(v[2]) or not v[2] or not is_bytes(v[3]) \
            or not is_bytes(v[4], kg.WRAP_BYTES) or not isinstance(v[5], list) \
            or len(v[5]) > MAX_HINTS or not all(_text_ok(p, MAX_LOCATION) for p in v[5]) \
            or (6 in v and not is_bytes(v[6], 64)):
        raise SpecError("Malformed")
    return {"key": v[2], "grant": v[3], "wrap": v[4], "peers": v[5], "snapshot": v.get(6)}


# ---------------------------------------------------------------------------
# The invite grant and its successor (ext-invite-links.md, "The invite grant
# and the successor"). roster.py reads member type 3, op 4 and change keys 13
# and 14 and resolves them; this module uses it directly.


AdmissionChange = roster.Change


class RawChange:
    """A change given as its map, for roster.update_roster and Roster.act."""

    def __init__(self, value: dict):
        self.value = value

    @property
    def op(self) -> int:
        return self.value[roster.C_OP]

    @property
    def member(self):
        m = self.value.get(roster.C_MEMBER)
        return (m[0], m[1]) if m else None

    def encode(self) -> dict:
        return dict(self.value)


def invite_grant(keys: dict, level: int, history: int, expires_at: int, claims: int, *,
                 caps=None, label: str | None = None, session: bytes | None = None) -> RawChange:
    """An op-0 change granting member type 3, the invite key."""
    out = {0: roster.GRANT, 1: [INVITE, keys["device_id"]], 2: level, 5: history,
           6: roster.VIA_LINK, 9: keys["hybrid"], 10: keys["mldsa"], 12: keys["identity"],
           C_EXPIRES: expires_at, C_CLAIMS: claims}
    if caps:
        out[3] = [[n, m] for n, m in caps]
    if label is not None:
        out[4] = label
    if session is not None:
        out[7] = session
    return RawChange(out)


def successor(member: tuple, keys: DeviceKeys | None = None) -> RawChange:
    """Op 4, granting the claimant."""
    out = {0: SUCCEED, 1: [member[0], member[1]]}
    if member[0] == roster.DEVICE:
        out.update({9: keys.hybrid, 10: keys.signer.mldsa_public, 12: keys.identity})
    return RawChange(out)


def revoke_invite(key: bytes) -> RawChange:
    return RawChange({0: roster.REMOVE, 1: [INVITE, key]})


def guest_grant(keys: DeviceKeys, level: int, session: bytes, *, expires_at: int | None = None,
                caps=None, label: str | None = None, via: int = roster.VIA_CODE,
                history: int = roster.FROM_NOW_ON) -> RawChange:
    """A device grant with `session`, and with change key 13 when the session
    has an expiry (ext-guests.md)."""
    base = roster.Change(roster.GRANT, (roster.DEVICE, keys.device_id), level,
                         tuple(caps) if caps else None, label, history, via, session, None,
                         keys.hybrid, keys.signer.mldsa_public, None, keys.identity).encode()
    if expires_at is not None:
        base[C_EXPIRES] = expires_at
    return RawChange(base)


decode_change = roster.decode_change
AdmissionSpace = roster.Space


def check_claimable(sp: AdmissionSpace, entry: bytes, invite_key: bytes) -> str:
    """ext-invite-links.md, "Claiming", steps 6, 7 and 9: the resolved roster
    holds the entry the link names as valid, granting exactly the key the
    link's secret derives, and whether the invite is still open."""
    if entry not in sp.view or not sp.is_roster(entry):
        return "NotInRoster"
    v = sp.status.get(entry)
    if v is None or not v[0]:
        return "NotInRoster"
    if [c.member for c in sp.changes(entry)
            if c.op == roster.GRANT and c.member[0] == INVITE] != [(INVITE, invite_key)]:
        return "WrongInvite"
    st = sp.roster.get((INVITE, invite_key))
    if st is None:
        return "NotInRoster"
    if st.present:
        return "InviteRaced" if invite_key in sp.forks else "Open"
    if any(sp.is_successor(r) for r in st.removed_by):
        return "InviteUsed"
    return "InviteRevoked"


# ---------------------------------------------------------------------------
# Admission events with deliveries, built on roster.py's Roster.


def admission_event(r: roster.Roster, by: str, changes, label: str, *, rotates: bool = True,
                    brk: bool = False, recipients=(), refs=(), view=None,
                    extra_parents=()) -> bytes:
    """A roster event whose own delivery wraps for `recipients`, each
    (device ID, X-Wing key, writes, propagates). A rotation seals under its own
    key; an event that does not rotate seals under its author's current state
    and delivers that state. Like roster.md's vectors, these payloads carry no
    links or gap records. Whether a rotation is a grant rotation, and a break,
    is roster.py's reading of keys.md's flags (`Roster.flags`): a guest's
    admission is a break but no grant rotation, and its delivery then names
    no grant state."""
    lbl = f"{r.prefix}/{label}"
    seal_nonce = example(f"{lbl}/seal-nonce")[:kg.NONCE_BYTES]
    roster_bytes = roster.update_roster(list(changes))
    state = None
    me = (roster.DEVICE, r.hist.device(by))
    flags = r.flags(list(changes), me, view if view is not None else r.hist.view[by])
    assert flags["break"] == brk, (label, flags)
    granting = flags["grant_rotation"]
    if rotates:
        secret = example(f"{lbl}/content-key")
        upload_seed = example(f"{lbl}/upload-seed")
        grant_seed = example(f"{lbl}/grant-seed")
        gk = kg.grant_key_pair(grant_seed)
        payload = {"rotates": True, "grant_commitment": kg.grant_commitment(gk["public"], brk),
                   "read": kg.read_credential(secret)["public"],
                   "upload": kg.upload_key(upload_seed)["public"],
                   "grant_rotation": granting, "break": brk}
    else:
        saved = r.hist.view[by]
        if view is not None:
            r.hist.view[by] = set(view)
        state = r.current_state(by)
        r.hist.view[by] = saved
        secret = kg.content_key(r.log.id, state, r.krot.__getitem__)
        upload_seed = grant_seed = None
        payload = {"sealed_under": kg.encode_set(state)}

    def build(log, author, seq):
        p = dict(payload)
        if recipients:
            name = kg.self_ref(author, seq) if rotates else kg.encode_set(state)
            gname = name if rotates and granting else b""
            wraps = []
            for k, (ident, hybrid, writes, propagates) in enumerate(recipients):
                bundle = kg.make_bundle(secret, upload_seed if writes else None,
                                        grant_seed if propagates and gname else None)
                wraps.append(kg.seal_bundle_wrap(log, name, gname, ident, hybrid, bundle,
                                                 eseed(f"{lbl}/wrap/{k}"))["wrap"])
            p["deliveries"] = [{"key": name, "grant": gname or None, "wraps": wraps}]
        return roster.space_body(p, secret, seal_nonce, roster_bytes, refs=refs)(log, author, seq)

    i = r.hist.act(by, KIND_SPACE, build, label, view=view, extra_parents=extra_parents)
    if rotates:
        r.krot[i] = secret
    return i


def own_bundle(event: events.Event, device: bytes, hybrid_seed: bytes) -> dict:
    """A newcomer finds its own wrap among the event's deliveries."""
    p = kg.read_payload(event.body, event.author, event.seq)
    for d in p["deliveries"]:
        i, bundle = kg.find_own_wrap(d["wraps"], event.log, d["key"], d["grant"] or b"",
                                     device, hybrid_seed)
        if bundle is not None:
            return {"delivery": d, "index": i, "bundle": bundle, "wrap": d["wraps"][i]}
    raise SpecError("NoWrap")


# ---------------------------------------------------------------------------
# The welcome, the prompt and the Join (admission.md, "The welcome" and "The
# lookup prompt and the Join").


def welcome_plain(space: bytes, event_id: bytes, key_name: bytes, grant_name: bytes,
                  wrap: bytes, approver: bytes, peers=(), snapshot=None) -> bytes:
    """Key 9, the newcomer's snapshot locator, only for an admission from
    now on."""
    m = {1: VERSION, 2: space, 3: event_id, 4: key_name, 5: grant_name, 6: wrap,
         7: approver, 8: list(peers)}
    if snapshot is not None:
        m[9] = snapshot
    return cbor(m)


def read_welcome(plain: bytes) -> dict:
    v = _map(plain, set(range(1, 10)), set(range(1, 9)))
    if v[1] != VERSION or not is_bytes(v[2], 32) or not is_bytes(v[3], 32) \
            or not is_bytes(v[4]) or not 1 <= len(v[4]) or not is_bytes(v[5]) \
            or not is_bytes(v[6], kg.WRAP_BYTES) or not is_bytes(v[7], 32) \
            or not isinstance(v[8], list) or len(v[8]) > MAX_HINTS \
            or not all(_text_ok(p, MAX_LOCATION) for p in v[8]) \
            or (9 in v and not is_bytes(v[9], 64)):
        raise SpecError("Malformed")
    return {"space": v[2], "event": v[3], "key": v[4], "grant": v[5], "wrap": v[6],
            "approver": v[7], "peers": v[8], "snapshot": v.get(9)}


def welcome_info(recipient: bytes) -> bytes:
    """crypto.md's wrap info for a sealed welcome: the label, the suite, then
    the recipient's device ID."""
    return wraps.wrap_info(WELCOME_LABEL, recipient)


def seal_welcome(recipient: bytes, recipient_hybrid: bytes, plain: bytes,
                 enc_seed: bytes) -> bytes:
    return wraps.seal_wrap(recipient_hybrid, welcome_info(recipient), plain, enc_seed)["wrap"]


def open_welcome(blob: bytes, device: bytes, hybrid_seed: bytes) -> dict:
    """crypto.md, "Opening a wrap", with step 5 requiring at least 1,139
    bytes and the info naming the device's own device ID; then the map
    reads."""
    return read_welcome(wraps.open_wrap(blob, hybrid_seed, welcome_info(device)))


def prompt(reference: bytes, approver: bytes, approver_hybrid: bytes, display: str,
           peers=()) -> bytes:
    """What an administrator leaves in a person's mailbox after a lookup.
    Nothing in it is secret or trusted."""
    return cbor({1: VERSION, 2: reference, 3: approver, 4: approver_hybrid, 5: display,
                 6: list(peers)})


def signed_prompt(record: bytes, signer: hs.Signer) -> bytes:
    """The approver's device signs its prompt under scheme 2."""
    return sign_record(PROMPT_LABEL, record, signer)


def answer_prompt(signed: bytes, shared) -> str:
    """admission.md, "Lookups", step 2, at the person's device, in order.
    `shared(device ID)` gives the (Ed25519 key, ML-DSA-65 key) this device
    holds for the approver's device, from a space it holds that grants both
    the approver's device ID and this person, or from any other source;
    None when no such space grants the approver's device ID. With the
    prompt's X-Wing key they must give that device ID (crypto.md, "A
    device's keys")."""
    outer = _map(signed, {1, 2}, {1, 2})
    if not is_bytes(outer[1]) or not is_bytes(outer[2], hs.HYBRID_SIGNATURE_BYTES):
        raise SpecError("Malformed")
    v = _map(outer[1], set(range(1, 7)), set(range(1, 7)))
    if v[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if not (is_bytes(v[2], REQUEST_BYTES) and is_bytes(v[3], 32)
            and is_bytes(v[4], xwing.XWING_PK_SIZE) and _display_ok(v[5])
            and isinstance(v[6], list) and len(v[6]) <= MAX_HINTS
            and all(_text_ok(x, MAX_LOCATION) for x in v[6])):
        raise SpecError("Malformed")
    known = shared(v[3])
    if known is None:
        return "code exchange"
    ed, mldsa = known
    if hs.device_id_of(ed, mldsa, v[4]) != v[3]:
        raise SpecError("NotCommitted")
    if not identity.proof_ok(ed, mldsa, PROMPT_LABEL + field(outer[1]), outer[2]):
        raise SpecError("BadSignature")
    return "Join"


def join_plain(reference: bytes, person_id: bytes, list_events, display: str) -> bytes:
    return cbor({1: reference, 2: person_id, 3: list(list_events), 4: display})


def mailbox_address(kind: int, name: bytes) -> bytes:
    """transport.md, "Mailboxes": a mailbox's address."""
    return sha256(MAILBOX_LABEL + u8(kind) + field(name))


# ---------------------------------------------------------------------------
# Access requests (admission.md, "The access request" and "Access requests").


def access_request(target: bytes, carrier: bytes, member: tuple, device: bytes, level: int,
                   request_id: bytes, note: str | None = None) -> bytes:
    out = {1: VERSION, 2: target, 3: carrier, 4: [member[0], member[1]], 5: device, 6: level,
           8: request_id}
    if note is not None:
        out[7] = note
    return cbor(out)


def sign_record(label: bytes, record: bytes, signer: hs.Signer) -> bytes:
    return cbor({1: record, 2: hs.sign(signer, events.SCHEME_HYBRID, label + field(record))})


def verify_access_request(signed: bytes, keys_of) -> dict:
    """The administering device's checks, in order. `keys_of(device)` gives
    the (Ed25519, ML-DSA-65, X-Wing) key sets the device holds from the
    carrier space's records or any other source; only one can hash to the
    requesting device's device ID (crypto.md, "A device's keys")."""
    outer = _map(signed, {1, 2}, {1, 2})
    if not is_bytes(outer[1]) or not is_bytes(outer[2], hs.HYBRID_SIGNATURE_BYTES):
        raise SpecError("Malformed")
    v = _map(outer[1], set(range(1, 9)), {1, 2, 3, 4, 5, 6, 8})
    if v[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if not (is_bytes(v[2], 32) and is_bytes(v[3], 32) and v[2] != v[3]
            and isinstance(v[4], list) and len(v[4]) == 2
            and v[4][0] in (roster.DEVICE, roster.PERSON) and is_bytes(v[4][1], 32)
            and is_bytes(v[5], 32) and v[6] in (roster.READ, roster.WRITE)
            and is_bytes(v[8], 16) and (7 not in v or _display_ok(v[7]))):
        raise SpecError("Malformed")
    held = next((k for k in keys_of(v[5]) if hs.device_id_of(*k) == v[5]), None)
    if held is None:
        raise SpecError("NoHybridKey")
    if not identity.proof_ok(held[0], held[1], ACCESS_REQUEST_LABEL + field(outer[1]),
                             outer[2]):
        raise SpecError("BadSignature")
    return {"target": v[2], "carrier": v[3], "member": tuple(v[4]), "device": v[5],
            "level": v[6], "request": v[8], "note": v.get(7)}


# ---------------------------------------------------------------------------
# Welcome requests (admission.md, "The access request" and "Welcome requests").
WELCOME_REASON_ERASURE_LATE = 1


def welcome_request(space: bytes, device: bytes, request_id: bytes,
                    reason: int = WELCOME_REASON_ERASURE_LATE) -> bytes:
    return cbor({1: VERSION, 2: space, 3: device, 4: request_id, 5: reason})


def verify_welcome_request(signed: bytes, keys_of, is_member) -> dict:
    """The administering device's checks, in order: both maps read; the
    version; the fields' types, lengths and reason; keys it holds that hash
    to the requesting device's ID; the signature; and the device is a member
    at its merged roster, else the request is ignored (`is_member(device)`).
    A request it answers gets a welcome with a space snapshot, once per
    request ID."""
    outer = _map(signed, {1, 2}, {1, 2})
    if not is_bytes(outer[1]) or not is_bytes(outer[2], hs.HYBRID_SIGNATURE_BYTES):
        raise SpecError("Malformed")
    v = _map(outer[1], set(range(1, 6)), set(range(1, 6)))
    if v[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if not (is_bytes(v[2], 32) and is_bytes(v[3], 32) and is_bytes(v[4], 16)
            and v[5] == WELCOME_REASON_ERASURE_LATE):
        raise SpecError("Malformed")
    held = next((k for k in keys_of(v[3]) if hs.device_id_of(*k) == v[3]), None)
    if held is None:
        raise SpecError("NoHybridKey")
    if not identity.proof_ok(held[0], held[1], WELCOME_REQUEST_LABEL + field(outer[1]),
                             outer[2]):
        raise SpecError("BadSignature")
    out = {"space": v[2], "device": v[3], "request": v[4], "reason": v[5]}
    out["answer"] = "welcome" if is_member(v[3]) else "ignored"
    return out


# ---------------------------------------------------------------------------
# Vectors (admission.md, "Test vectors").


def _err(function, *args, **kw) -> str:
    try:
        function(*args, **kw)
    except SpecError as error:
        return error.error
    return "accepted"


TYPE_NAMES = {roster.DEVICE: "device", roster.PERSON: "person", roster.SPACE: "space",
              INVITE: "invite"}


def summary(r: roster.Roster, sp: AdmissionSpace, names: dict | None = None) -> dict:
    names = names or {}

    def mname(m):
        return names.get(m[1], r.member_name(m))

    def show(i):
        v = sp.status[i]
        if v[0]:
            return "valid" + (f" ({v[1]})" if v[1] in ("agreed", "seniority") else "")
        return v[1] + (f" by {r.name(v[2])}" if v[2] else "")

    out_roster = {}
    for m, s in sorted(sp.roster.items(), key=lambda kv: (kv[0][0], mname(kv[0]))):
        if not s.present:
            out_roster[mname(m)] = "out"
            continue
        e = {"type": TYPE_NAMES[m[0]], "level": roster.LEVEL_NAMES[s.level],
             "history": "with history" if s.history else "from now on",
             "via": roster.VIA_NAMES[s.via]}
        if s.session:
            e["session"] = s.session.hex()
        if s.label:
            e["label"] = s.label
        if s.caps:
            e["capabilities"] = sorted([n, "narrows" if md else "extends"] for n, md in s.caps)
        out_roster[mname(m)] = e
    return {"events": {r.name(i): show(i) for i in r.log.canonical(sp.view) if i != r.genesis},
            "roster": out_roster}


def _keys_json(keys: DeviceKeys) -> dict:
    return {"identity_seed": h(keys.signer.ed_seed), "identity": h(keys.identity),
            "mldsa_seed": h(keys.signer.mldsa_seed), "xwing_seed": h(keys.hybrid_seed),
            "kc": h(keys.signer.kc), "device_id": h(keys.device_id)}


def _parameters() -> dict:
    return {
        "ctx": {"device list": CTX_LIST, "space": CTX_SPACE},
        "joiner_type": {"device": JOINER_DEVICE, "person": JOINER_PERSON},
        "message_types": {v: k for k, v in M_NAMES.items()},
        "admission_code_lifetime": LIFETIME, "admission_code_skew": SKEW,
        "exchange_mailbox_lifetime": "expires_at + 60",
        "sizes": {"request": REQUEST_BYTES, "nonce": NONCE_BYTES, "commitment": 32,
                  "ephemeral_key": xwing.XWING_PK_SIZE, "display": [0, MAX_DISPLAY],
                  "heads": [1, MAX_HEADS], "possession": hs.HYBRID_SIGNATURE_BYTES,
                  "sealed_body_minimum": wraps.MIN_BYTES,
                  "request_and_cancel_messages": MAX_REQUEST_MESSAGE,
                  "other_messages": MAX_MESSAGE, "qr_location": [1, MAX_LOCATION],
                  "peer_hints": [0, MAX_HINTS], "setup_code": SETUP_CODE_BYTES,
                  "setup_secret": SETUP_SECRET_BYTES, "setup_tag": SETUP_TAG_BYTES,
                  "bundle_wrap": kg.WRAP_BYTES},
        "exchange_mailbox_limits": {
            "new_per_source_per_minute": MAILBOX_NEW_PER_MINUTE,
            "open_per_source": MAILBOX_MAX_PER_SOURCE, "per_peer": MAILBOX_MAX_TOTAL,
            "bytes_per_peer": MAILBOX_MAX_BYTES},
    }


T_REQUEST, T_RESPONSE, T_REVEAL = 1_760_000_100, 1_760_000_110, 1_760_000_120
T_EXPIRES = 1_760_000_900


def _exchange(desc, k, ctx, jkeys, pid, pheads, akey, log, heads, offer, dj, di, ch) -> dict:
    joiner = Joiner(ctx, example(f"admission/t{k}/request")[:16], T_EXPIRES,
                    example(f"admission/t{k}/eph-j"), example(f"admission/t{k}/nonce-j"), dj,
                    keys=jkeys, person=pid, person_heads=pheads, channel=ch)
    appr = Approver(akey, ctx, log, heads, offer, di, example(f"admission/t{k}/eph-i"),
                    example(f"admission/t{k}/nonce-i"), channel=ch)
    req = joiner.start()
    resp = appr.on_request(req, T_REQUEST, eseed(f"admission/t{k}/enc-response"))
    jr = joiner.on_response(resp, T_RESPONSE, eseed(f"admission/t{k}/enc-reveal"))
    ar = appr.on_reveal(jr["reveal"], T_REVEAL)
    assert ar["code"] == jr["code"] and ar["j_fields"] == joiner.j_fields()
    jtype, jpart = joiner.joiner()
    item = {"description": desc, "ctx": ctx, "request": h(joiner.request),
            "expires_at": joiner.expires_at, "eph_j_seed": h(joiner.eph_seed),
            "eph_j": h(joiner.eph), "nonce_j": h(joiner.nonce_j),
            "eph_i_seed": h(appr.eph_seed), "eph_i": h(appr.eph), "nonce_i": h(appr.nonce_i),
            "joiner_type": jtype, "joiner": h(jpart), "display_j": dj, "approver": h(akey),
            "log": h(log), "heads": [h(x) for x in sorted(heads)],
            "heads_hash": h(heads_hash(log, heads)), "offer": h(offer), "display_i": di,
            "channel": h(ch), "j_fields": h(joiner.j_fields()), "i_fields": h(jr["i_fields"]),
            "commitment": h(commitment(joiner.j_fields(), joiner.nonce_j)),
            "code_hash": h(ar["code_hash"]), "code": ar["code"], "grouped": grouped(ar["code"]),
            "seal_info": {"response": h(seal_info(joiner.request, M_RESPONSE)),
                          "reveal": h(seal_info(joiner.request, M_REVEAL))},
            "messages": {"request": h(req), "response": h(resp), "reveal": h(jr["reveal"])}}
    if jkeys is not None:
        item["joiner_keys"] = _keys_json(jkeys)
    if pheads:
        item["person_heads"] = [h(x) for x in sorted(pheads)]
    return item


def _transcript_vectors() -> dict:
    new = device_keys("new-laptop")
    phone = device_keys("phone")
    guest = device_keys("guest-laptop")
    host = device_keys("host-desktop")
    ada = example("admission/person/ada")
    ada_heads = [example("admission/person/ada/head-1"), example("admission/person/ada/head-2")]
    space = example("admission/space/show")
    space_heads = [example("admission/space/show/head")]
    channel = example("admission/channel/exporter")
    session = example("admission/session")[:16]
    guest_offer = encode_offer(roster.WRITE, roster.FROM_NOW_ON, caps=[("drive", 0)],
                               label="Operator", session=session)
    out = [
        _exchange("a person's new device (ctx 0x01) through an exchange mailbox", 0, CTX_LIST,
                  new, None, None, phone.device_id, ada, ada_heads, b"", "Ada's new laptop",
                  "Ada's phone", b""),
        _exchange("a guest nearby (ctx 0x02, a device), with a channel", 1, CTX_SPACE, guest,
                  None, None, host.device_id, space, space_heads, guest_offer, "Guest laptop",
                  "Venue host", channel),
        _exchange("a person joining a space (ctx 0x02, a person) through an exchange mailbox",
                  2, CTX_SPACE, None, example("admission/person/bob"),
                  [example("admission/person/bob/head")], host.device_id, space, space_heads,
                  encode_offer(roster.WRITE, roster.WITH_HISTORY), "Bob", "Alice", b""),
        _exchange("a replacement: a new person replacing another (ctx 0x02, a person)", 3,
                  CTX_SPACE, None, example("admission/person/bob-2"),
                  [example("admission/person/bob-2/head")], host.device_id, space, space_heads,
                  encode_offer(roster.WRITE, roster.WITH_HISTORY,
                               replaces=example("admission/person/bob")),
                  "Bob (new phone)", "Alice", b""),
    ]
    leading = None
    eph_j = xwing.xwing_public_key(example("admission/t1/eph-j"))
    eph_i = xwing.xwing_public_key(example("admission/t1/eph-i"))
    if_ = i_fields(CTX_SPACE, space, heads_hash(space, space_heads), host.device_id, eph_i,
                   guest_offer, b"Venue host")
    for n in range(1000):
        rid = example(f"admission/leading/{n}")[:16]
        jf = j_fields(CTX_SPACE, rid, T_EXPIRES, eph_j, JOINER_DEVICE, guest.digest(),
                      b"Guest laptop")
        digest = code_hash(jf, if_, channel, example("admission/t1/nonce-j"),
                           example("admission/t1/nonce-i"))
        if code(digest).startswith("0"):
            leading = {"counter": n, "request": h(rid), "j_fields": h(jf), "i_fields": h(if_),
                       "channel": h(channel), "nonce_j": h(example("admission/t1/nonce-j")),
                       "nonce_i": h(example("admission/t1/nonce-i")),
                       "code_hash": h(digest), "code": code(digest),
                       "grouped": grouped(code(digest))}
            break
    # The nearby exchange's fields with an empty channel: the code differs.
    relayed = code_hash(bytes.fromhex(out[1]["j_fields"]), bytes.fromhex(out[1]["i_fields"]),
                        b"", bytes.fromhex(out[1]["nonce_j"]), bytes.fromhex(out[1]["nonce_i"]))
    qr_codes = []
    for x in (out[0], out[2]):
        text = admit_qr(x["ctx"], bytes.fromhex(x["request"]), bytes.fromhex(x["commitment"]),
                        "https://peer.example")
        assert read_admit_qr(text)["commitment"] == bytes.fromhex(x["commitment"])
        qr_codes.append({"ctx": x["ctx"], "request": x["request"],
                         "commitment": x["commitment"], "location": "https://peer.example",
                         "text": text})
    qr = qr_codes[1]["text"]
    return {"exchanges": out, "leading_zero": leading,
            "channel_matters": {"with the channel": out[1]["code"],
                                "the same fields with an empty channel": code(relayed)},
            "qr_codes": qr_codes,
            "qr_refusals": {"lower case": _err(read_admit_qr, qr.lower()),
                            "no prefix": _err(read_admit_qr, qr[len(ADMIT_PREFIX):]),
                            "version 2": _err(read_admit_qr, ADMIT_PREFIX + _b32(cbor(
                                {1: 2, 2: 2, 3: bytes(16), 4: bytes(32), 5: "x"})))}}


def _new_device_vectors() -> dict:
    """admission.md, "A person's new device": the exchange, the add the
    approver signs, and the new device's checks of the Result."""
    ada = identity.Person("phone", "admission/ada")
    ada.add("phone", "tablet", identity.DEVICE)
    new = DeviceKeys("new-laptop", ada.hist.signer("new-laptop"))
    phone = ada.hist.device("phone")
    heads = ada.log.heads(ada.hist.view["phone"])
    joiner = Joiner(CTX_LIST, example("admission/ada/request")[:16], T_EXPIRES,
                    example("admission/ada/eph-j"), example("admission/ada/nonce-j"),
                    "Ada's new laptop", keys=new)
    appr = Approver(phone, CTX_LIST, ada.id, heads, b"", "Ada's phone",
                    example("admission/ada/eph-i"), example("admission/ada/nonce-i"))
    req = joiner.start()
    resp = appr.on_request(req, T_REQUEST, eseed("admission/ada/enc-1"))
    jr = joiner.on_response(resp, T_RESPONSE, eseed("admission/ada/enc-2"))
    ar = appr.on_reveal(jr["reveal"], T_REVEAL)
    assert ar["code"] == jr["code"]
    assert ar["reveal"]["possession"] == possession_for(new, CTX_LIST, ada.id, phone)
    add = ada.add("phone", "new-laptop", identity.DEVICE, "phone adds the new laptop")
    plain = list_result([ada.log.events[i].signed for i in ada.log.canonical()])
    result = envelope(M_RESULT, joiner.request, seal_body(M_RESULT, joiner.request, joiner.eph,
                                                          plain, eseed("admission/ada/enc-3")))
    got = open_body(M_RESULT, joiner.request, joiner.eph_seed, read_envelope(result)["body"])
    resp_v = joiner.response
    checks = {"the Result": "accepted" if check_list_result(got, resp_v, joiner) == add
              else "refused"}
    for desc, change in (("another approver", {"approver": ada.hist.device("tablet")}),
                         ("another person", {"log": example("admission/ada/other")}),
                         ("a head the add does not follow",
                          {"heads": sorted(resp_v["heads"] + [example("admission/ada/x")])})):
        checks[desc] = _err(check_list_result, got, {**resp_v, **change}, joiner)
    without = list_result([ada.log.events[i].signed for i in ada.log.canonical() if i != add])
    checks["a list without the add"] = _err(check_list_result, without, resp_v, joiner)
    # The joiner that expects a person (section 3.1, step 5): it reveals
    # for its person's Response, and refuses another person's before it
    # signs anything over its log.
    expected = {}
    for desc, person in (("the expected person", ada.id),
                         ("another person than the expected one",
                          example("admission/ada/other"))):
        expecting = Joiner(CTX_LIST, joiner.request, T_EXPIRES, joiner.eph_seed, joiner.nonce_j,
                           "Ada's new laptop", keys=new, expected_person=person)
        try:
            revealed = expecting.on_response(resp, T_RESPONSE, eseed("admission/ada/enc-2"))
            expected[desc] = "accepted" if revealed["reveal"] == jr["reveal"] else "refused"
        except SpecError as e:
            assert expecting.response is None
            expected[desc] = e.error
    direct = _new_device_direct(new, phone, ada.id, heads, plain, joiner.eph, ar["code"])
    return {"person": h(ada.id), "heads": [h(x) for x in sorted(heads)],
            "new_device": _keys_json(new), "code": ar["code"],
            "request": h(req), "response": h(resp), "reveal": h(jr["reveal"]),
            "possession_statement": h(identity.possession_statement(
                ada.id, phone, identity.DEVICE, new.identity, new.signer.mldsa_public,
                new.hybrid)),
            "possession": h(ar["reveal"]["possession"]),
            "add": h(ada.log.events[add].signed),
            "result_plaintext": h(plain), "result": h(result), "checks": checks,
            "expected_person": {"other_person": h(example("admission/ada/other")),
                                "checks": expected},
            "direct": direct}


def _new_device_direct(new: DeviceKeys, phone: bytes, person: bytes, heads, plain: bytes,
                       other_eph: bytes, mailbox_code: str) -> dict:
    """admission.md, "A person's new device", "Over a direct connection":
    the same exchange with the connection's channel, the Result, and a
    Welcome after it, with the new device's checks of the Welcome."""
    tag = "admission/ada/direct"
    channel = example(f"{tag}/exporter")
    joiner = Joiner(CTX_LIST, example(f"{tag}/request")[:16], T_EXPIRES,
                    example(f"{tag}/eph-j"), example(f"{tag}/nonce-j"), "Carol",
                    keys=new, channel=channel)
    appr = Approver(phone, CTX_LIST, person, heads, b"", "Desktop",
                    example(f"{tag}/eph-i"), example(f"{tag}/nonce-i"), channel=channel)
    req = joiner.start()
    resp = appr.on_request(req, T_REQUEST, eseed(f"{tag}/enc-1"))
    jr = joiner.on_response(resp, T_RESPONSE, eseed(f"{tag}/enc-2"))
    ar = appr.on_reveal(jr["reveal"], T_REVEAL)
    assert ar["code"] == jr["code"] and ar["code"] != mailbox_code
    result = envelope(M_RESULT, joiner.request, seal_body(M_RESULT, joiner.request, joiner.eph,
                                                          plain, eseed(f"{tag}/enc-3")))
    got = open_body(M_RESULT, joiner.request, joiner.eph_seed, read_envelope(result)["body"])
    checks = {"the Result": "accepted" if check_list_result(got, joiner.response, joiner)
              else "refused"}
    wrap = b"".join(example(f"{tag}/wrap/{i}") for i in range(kg.WRAP_BYTES // 32 + 1))
    welcome = welcome_plain(example(f"{tag}/space"), example(f"{tag}/delivery"),
                            example(f"{tag}/key-name"), b"", wrap[:kg.WRAP_BYTES], phone)
    message = appr.welcome(joiner.request, welcome, eseed(f"{tag}/enc-4"))
    checks["the Welcome"] = "accepted" if joiner.on_welcome(message)["approver"] == phone \
        else "refused"
    other = welcome_plain(example(f"{tag}/space"), example(f"{tag}/delivery"),
                          example(f"{tag}/key-name"), b"", wrap[:kg.WRAP_BYTES],
                          example(f"{tag}/another-approver"))
    checks["a Welcome naming another approver"] = _err(
        joiner.on_welcome, appr.welcome(joiner.request, other, eseed(f"{tag}/enc-5")))
    checks["a Welcome sealed to another exchange's key"] = _err(
        joiner.on_welcome, envelope(M_WELCOME, joiner.request,
                                    seal_body(M_WELCOME, joiner.request, other_eph, welcome,
                                              eseed(f"{tag}/enc-6"))))
    return {"channel": h(channel), "request": h(req), "response": h(resp),
            "reveal": h(jr["reveal"]), "code": ar["code"], "result": h(result),
            "welcome": h(welcome), "welcome_seal_info": h(seal_info(joiner.request, M_WELCOME)),
            "welcome_message": h(message), "checks": checks}


def _negative_vectors() -> dict:
    """admission.md, "The joiner", "The approver" and "The offer": the
    approver's refusals, what the joiner ignores, and refused offers."""
    guest = device_keys("guest-laptop")
    host = device_keys("host-desktop")
    space = example("admission/space/show")
    heads = [example("admission/space/show/head")]
    offer = encode_offer(roster.WRITE, roster.FROM_NOW_ON, session=bytes(16))

    def pair(tag, expires=T_EXPIRES, display="Guest laptop", keys=guest, a_offer=offer):
        j = Joiner(CTX_SPACE, example(f"admission/n/{tag}/request")[:16], expires,
                   example(f"admission/n/{tag}/eph-j"), example(f"admission/n/{tag}/nonce-j"),
                   display, keys=keys)
        a = Approver(host.device_id, CTX_SPACE, space, heads, a_offer, "Host",
                     example(f"admission/n/{tag}/eph-i"), example(f"admission/n/{tag}/nonce-i"))
        return j, a

    def result(function, *args):
        try:
            out = function(*args)
        except SpecError as error:
            return error.error
        return "ignored" if out is None else "accepted"

    appr = {}
    j, a = pair("expired")
    appr["a Request past its expiry"] = result(a.on_request, j.start(), T_EXPIRES + 1,
                                               eseed("n/e"))
    j, a = pair("lifetime", expires=T_REQUEST + 961)
    appr["a Request living 961 seconds"] = result(a.on_request, j.start(), T_REQUEST,
                                                  eseed("n/l"))
    j, a = pair("replay")
    a.on_request(j.start(), T_REQUEST, eseed("n/r1"))
    appr["a Request answered before"] = result(a.on_request, j.start(), T_REQUEST,
                                               eseed("n/r2"))
    j, a = pair("ctx")
    req = j.start()
    bad = envelope(M_REQUEST, j.request, request_body(CTX_LIST, j.expires_at, bytes(32), j.eph))
    appr["a Request for a device list, sent to a space's approver"] = result(
        a.on_request, bad, T_REQUEST, eseed("n/c"))
    appr["an envelope of version 2"] = result(a.on_request, b"\x02" + req[1:], T_REQUEST,
                                              eseed("n/v"))
    appr["an envelope of type 11, unknown"] = result(a.on_request, req[:1] + b"\x0b" + req[2:],
                                                     T_REQUEST, eseed("n/u"))
    appr["a Request message over 4,096 bytes"] = result(
        a.on_request, envelope(M_REQUEST, j.request, bytes(MAX_REQUEST_MESSAGE)), T_REQUEST,
        eseed("n/b"))
    appr["a Cancel with a body"] = result(a.on_request, envelope(M_CANCEL, j.request, b"x"),
                                          T_REQUEST, eseed("n/x"))
    # A relay that relabels the joiner after the commitment.
    j, a = pair("swap")
    resp = a.on_request(j.start(), T_REQUEST, eseed("n/s1"))
    jr = j.on_response(resp, T_RESPONSE, eseed("n/s2"))
    j2 = Joiner(CTX_SPACE, j.request, j.expires_at, j.eph_seed, j.nonce_j, "Attacker", keys=guest)
    forged = j2.on_response(resp, T_RESPONSE, eseed("n/s3"))
    appr["a Reveal with another display"] = result(a.on_reveal, forged["reveal"], T_REVEAL)
    appr["a second Reveal"] = result(a.on_reveal, jr["reveal"], T_REVEAL)
    # A relay that substitutes its own keys: its Reveal opens another commitment.
    j, a = pair("keys")
    resp = a.on_request(j.start(), T_REQUEST, eseed("n/k1"))
    j3 = Joiner(CTX_SPACE, j.request, j.expires_at, j.eph_seed, j.nonce_j, j.display,
                keys=device_keys("attacker"))
    appr["a Reveal of other keys"] = result(
        a.on_reveal, j3.on_response(resp, T_RESPONSE, eseed("n/k2"))["reveal"], T_REVEAL)
    j, a = pair("late")
    resp = a.on_request(j.start(), T_REQUEST, eseed("n/t1"))
    jr = j.on_response(resp, T_RESPONSE, eseed("n/t2"))
    appr["a Reveal past the expiry"] = result(a.on_reveal, jr["reveal"], T_EXPIRES + 1)

    joiner = {}
    j, a = pair("twice")
    resp = a.on_request(j.start(), T_REQUEST, eseed("n/w1"))
    j.on_response(resp, T_RESPONSE, eseed("n/w2"))
    joiner["a second Response"] = result(j.on_response, resp, T_RESPONSE + 1, eseed("n/w3"))
    j, a = pair("jlate")
    resp = a.on_request(j.start(), T_REQUEST, eseed("n/x1"))
    joiner["a Response past the expiry"] = result(j.on_response, resp, T_EXPIRES + 1,
                                                  eseed("n/x2"))
    j, a = pair("other-key")
    req = j.start()
    a.on_request(req, T_REQUEST, eseed("n/o1"))
    other = response_plain(a.nonce_i, space, heads, host.device_id, a.eph, offer, "Host")
    wrong = envelope(M_RESPONSE, j.request, seal_body(
        M_RESPONSE, j.request, xwing.xwing_public_key(example("admission/n/other-key/other")),
        other, eseed("n/o2")))
    joiner["a Response sealed to another key"] = result(j.on_response, wrong, T_RESPONSE,
                                                        eseed("n/o3"))
    j, a = pair("unsuited", a_offer=encode_offer(roster.ADMINISTER, roster.FROM_NOW_ON,
                                                 session=bytes(16)))
    resp = a.on_request(j.start(), T_REQUEST, eseed("n/a1"))
    joiner["a Response whose offer does not suit the joiner"] = result(
        j.on_response, resp, T_RESPONSE, eseed("n/a2"))

    offers = {
        "administer with a session": _err(
            read_offer, encode_offer(roster.ADMINISTER, 0, session=bytes(16)), CTX_SPACE,
            JOINER_DEVICE),
        "administer to a person": _err(
            read_offer, encode_offer(roster.ADMINISTER, 1), CTX_SPACE, JOINER_PERSON),
        "a session to a person": _err(
            read_offer, encode_offer(roster.WRITE, 0, session=bytes(16)), CTX_SPACE,
            JOINER_PERSON),
        "key 13, expires_at, at a core joiner": _err(
            read_offer, encode_offer(roster.WRITE, 0, session=bytes(16), expires_at=5),
            CTX_SPACE, JOINER_DEVICE),
        "key 9": _err(read_offer, cbor({2: 1, 5: 0, 9: 1}), CTX_SPACE, JOINER_DEVICE),
        "replaces, to a device": _err(
            read_offer, encode_offer(roster.WRITE, 1, replaces=bytes(32)), CTX_SPACE,
            JOINER_DEVICE),
        "an offer in ctx 0x01": _err(read_offer, cbor({2: 1, 5: 0}), CTX_LIST, JOINER_DEVICE),
    }
    return {"approver": appr, "joiner_ignores": joiner, "refused_offers": offers}


def _step(who: str, what: str, res: str) -> dict:
    out = {"who": who, "what": what, "result": res}
    if res in REASONS:
        out["reason"], out["status"] = REASONS[res]
    return out


def _exchange_mailbox_vectors() -> dict:
    """admission.md, "Exchange mailboxes": what a peer stores and refuses."""
    peer = Peer()
    guest = device_keys("guest-laptop")
    host = device_keys("host-desktop")
    space = example("admission/space/show")
    heads = [example("admission/space/show/head")]
    offer = encode_offer(roster.WRITE, roster.FROM_NOW_ON, session=bytes(16))
    j = Joiner(CTX_SPACE, example("admission/mailbox/request")[:16], T_EXPIRES,
               example("admission/mailbox/eph-j"), example("admission/mailbox/nonce-j"), "Guest",
               keys=guest)
    a = Approver(host.device_id, CTX_SPACE, space, heads, offer, "Host",
                 example("admission/mailbox/eph-i"), example("admission/mailbox/nonce-i"))
    steps = []
    req = j.start()
    steps.append(_step("joiner", "the Request", peer.put("joiner", req, T_REQUEST)))
    steps.append(_step("joiner", "the same Request again", peer.put("joiner", req,
                                                                   T_REQUEST + 1)))
    resp = a.on_request(req, T_REQUEST + 2, eseed("admission/mailbox/enc-response"))
    steps.append(_step("relay", "a Reveal before any Response", peer.put(
        "relay", envelope(M_REVEAL, j.request, b"x" * 1200), T_REQUEST + 3)))
    steps.append(_step("approver", "the Response", peer.put("approver", resp, T_REQUEST + 4)))
    steps.append(_step("relay", "a second Response", peer.put("relay", resp, T_REQUEST + 5)))
    jr = j.on_response(resp, T_REQUEST + 6, eseed("admission/mailbox/enc-reveal"))
    steps.append(_step("joiner", "the Reveal", peer.put("joiner", jr["reveal"], T_REQUEST + 7)))
    steps.append(_step("approver", "a Result after the expiry", peer.put(
        "approver", envelope(M_RESULT, j.request, b"r" * 1200), T_EXPIRES + 1)))
    steps.append(_step("anyone", "a Response for no exchange mailbox", peer.put(
        "anyone", envelope(M_RESPONSE, bytes(16), b"x"), T_REQUEST + 8)))
    steps.append(_step("anyone", "a Join", peer.put(
        "anyone", envelope(M_JOIN, bytes(16), b"x"), T_REQUEST + 8)))
    rate = []
    for n in range(MAILBOX_NEW_PER_MINUTE + 1):
        rj = Joiner(CTX_SPACE, example(f"admission/mailbox/rate/{n}")[:16], 1_760_001_900,
                    example("admission/mailbox/eph-j"), example("admission/mailbox/nonce-j"),
                    "G", keys=guest)
        rate.append(peer.put("busy", rj.start(), 1_760_001_100 + n))
    long_j = Joiner(CTX_SPACE, example("admission/mailbox/long")[:16], 1_760_002_000 + 961,
                    example("admission/mailbox/eph-j"), example("admission/mailbox/nonce-j"),
                    "G", keys=guest)
    return {
        "address": {"request": h(j.request), "kind": MAILBOX_EXCHANGE,
                    "address": h(mailbox_address(MAILBOX_EXCHANGE, j.request))},
        "steps": steps,
        "eleven_requests_in_a_minute": rate,
        "a Request living 961 seconds": _step("other", "a Request living 961 seconds",
                                              peer.put("other", long_j.start(), 1_760_002_000)),
    }


def _setup_vectors() -> dict:
    dev = device_keys("rack-executor")
    secret = example("admission/setup/secret")[:SETUP_SECRET_BYTES]
    raw = setup_code(dev.digest(), secret)
    text = setup_text(raw)
    scanned = read_setup_text(text)
    device = HeadlessDevice(dev, secret, example("admission/setup/request")[:16],
                            example("admission/setup/eph-j"), "Rack 3 executor")
    host = device_keys("host-desktop")
    other = device_keys("not-the-rack")
    space = example("admission/space/show")
    heads = [example("admission/space/show/head")]
    offer = encode_offer(roster.WRITE, roster.FROM_NOW_ON, caps=[("execute", 0)],
                         label="Rack executor")
    eph_i_seed = example("admission/setup/eph-i")
    eph_i = xwing.xwing_public_key(eph_i_seed)
    channel = example("admission/setup/exporter")
    hello_msg = hello(device.request, dev, device.eph, device.display)
    got = read_hello(hello_msg)
    jf = j_fields(CTX_SPACE, got["request"], 0, got["eph"], JOINER_DEVICE,
                  hs.device_id_of(got["identity"], got["mldsa"], got["xwing"]),
                  got["display"].encode())
    assert jf == device.j_fields()
    if_ = i_fields(CTX_SPACE, space, heads_hash(space, heads), host.device_id, eph_i, offer,
                   b"Stage manager")
    mac = setup_mac(secret, jf, if_, channel)
    offer_msg = setup_offer(device.request, device.eph, space, heads, host.device_id, eph_i, offer,
                            "Stage manager", mac, eseed("admission/setup/enc-offer"))
    bad_msg = setup_offer(device.request, device.eph, space, heads, host.device_id, eph_i, offer,
                          "Stage manager", bytes([mac[0] ^ 1]) + mac[1:],
                          eseed("admission/setup/enc-bad"))
    if2 = i_fields(CTX_SPACE, space, heads_hash(space, heads), other.device_id, eph_i, offer,
                   b"Someone else")
    second_msg = setup_offer(device.request, device.eph, space, heads, other.device_id, eph_i,
                             offer, "Someone else", setup_mac(secret, jf, if2, channel),
                             eseed("admission/setup/enc-second"))
    wrong = {"identity": other.identity, "mldsa": other.signer.mldsa_public,
             "xwing": other.hybrid}
    outcomes = {"the administrator, the device's own keys": admin_check_setup(scanned, got),
                "the administrator, another device's keys": admin_check_setup(scanned, wrong)}
    outcomes["the device, a MAC that does not verify"] = device.on_offer_message(bad_msg, channel)
    outcomes["the device, an Offer on another connection"] = device.on_offer_message(
        offer_msg, example("admission/setup/other-exporter"))
    outcomes["the device, the first MAC that verifies"] = device.on_offer_message(offer_msg,
                                                                                  channel)
    outcomes["the device, a second Offer with a valid MAC"] = device.on_offer_message(
        second_msg, channel)
    return {
        "device": _keys_json(dev),
        "secret": h(secret), "code": h(raw), "text": text, "tag": h(setup_tag(secret)),
        "announced_name": setup_name(secret),
        "request": h(device.request), "eph_j_seed": h(device.eph_seed),
        "eph_i_seed": h(eph_i_seed), "hello": h(hello_msg), "j_fields": h(jf),
        "i_fields": h(if_), "channel": h(channel), "mac": h(mac),
        "seal_info": h(seal_info(device.request, M_OFFER)), "offer_message": h(offer_msg),
        "outcomes": outcomes,
        "text_refusals": {
            "no prefix": _err(read_setup_text, text[len(SETUP_PREFIX):]),
            "lower case": _err(read_setup_text, SETUP_PREFIX + text[len(SETUP_PREFIX):].lower()),
            "version 2": _err(read_setup_text, setup_text(b"\x02" + raw[1:])),
            "one byte short": _err(read_setup_text, setup_text(raw[:-1])),
        },
        "a peer refusing a Hello": _step("anyone", "a Hello", Peer().put("x", hello_msg, 0)),
    }


def _welcome_vectors() -> dict:
    """admission.md, "The welcome" and "Accepting a grant": a guest's
    admitting event with its own wrap, the Result and the sealed welcome that
    carry a copy, and the joiner's checks of the grant."""
    r = roster.Roster("H", "admission/welcome")
    guest = roster_device_keys(r, "G")
    session = example("admission/welcome/session")[:16]
    offer = encode_offer(roster.WRITE, roster.FROM_NOW_ON, caps=[("drive", 0)], label="Operator",
                         session=session)
    heads = r.log.heads(r.hist.view["H"])
    channel = example("admission/welcome/exporter")
    joiner = Joiner(CTX_SPACE, example("admission/welcome/request")[:16], T_EXPIRES,
                    example("admission/welcome/eph-j"), example("admission/welcome/nonce-j"),
                    "Guest laptop", keys=guest, channel=channel)
    host = r.hist.device("H")
    appr = Approver(host, CTX_SPACE, r.id, heads, offer, "Venue host",
                    example("admission/welcome/eph-i"), example("admission/welcome/nonce-i"),
                    channel=channel)
    resp = appr.on_request(joiner.start(), T_REQUEST, eseed("admission/welcome/enc-1"))
    jr = joiner.on_response(resp, T_RESPONSE, eseed("admission/welcome/enc-2"))
    ar = appr.on_reveal(jr["reveal"], T_REVEAL)
    g = admission_event(r, "H", [guest_grant(guest, roster.WRITE, session, caps=[("drive", 0)],
                                             label="Operator")],
                        "H admits the guest", brk=True,
                        recipients=[(host, r.hist.xwing("H"), True, True),
                                    (guest.device_id, guest.hybrid, True, False)])
    ev = r.log.events[g]
    own = own_bundle(ev, guest.device_id, guest.hybrid_seed)
    plain = welcome_plain(r.id, g, own["delivery"]["key"], own["delivery"]["grant"] or b"",
                          own["wrap"], host, ["iroh:host-member-endpoint"])
    result = envelope(M_RESULT, joiner.request, seal_body(M_RESULT, joiner.request, joiner.eph,
                                                          plain, eseed("admission/welcome/enc-3")))
    sealed = seal_welcome(guest.device_id, guest.hybrid, plain, eseed("admission/welcome/enc-4"))
    opened = open_welcome(sealed, guest.device_id, guest.hybrid_seed)
    assert opened["wrap"] == own["wrap"]
    assert read_welcome(open_body(M_RESULT, joiner.request, joiner.eph_seed,
                                  read_envelope(result)["body"]))["wrap"] == own["wrap"]
    decoded = roster.decode_body(ev, roster.body_key(ev, roster.read_visible(ev),
                                                     own["bundle"]["content"]))
    resp_v = joiner.response
    checks = {"the grant": _err(check_grant, ev, decoded, r.log, resp_v, joiner)}
    for desc, change in (("another approver", {"approver": r.hist.device("G")}),
                         ("another space", {"log": example("admission/welcome/other-space")}),
                         ("a head the grant does not follow",
                          {"heads": sorted(resp_v["heads"] + [example("admission/welcome/x")])}),
                         ("another offer", {"offer": encode_offer(roster.READ, 0,
                                                                  session=session)})):
        checks[desc] = _err(check_grant, ev, decoded, r.log, {**resp_v, **change}, joiner)
    checks["the same grant, expected by lookup"] = _err(check_grant, ev, decoded, r.log, resp_v,
                                                        joiner, via=roster.VIA_LOOKUP)
    refusals = {
        "another device opens it": _err(open_welcome, sealed, r.hist.device("H"),
                                        example("roster/H/xwing")),
        "version 2": _err(open_welcome, b"\x02" + sealed[1:], guest.device_id, guest.hybrid_seed),
        "suite 0x0020": _err(open_welcome, sealed[:1] + u16be(wraps.SUITE_X25519) + sealed[3:],
                             guest.device_id, guest.hybrid_seed),
        "1,138 bytes": _err(open_welcome, sealed[:wraps.MIN_BYTES - 1], guest.device_id,
                            guest.hybrid_seed),
    }
    sp = AdmissionSpace(r.log, None, keys=r.keyring())
    return {
        "code": ar["code"], "grant_event": h(ev.signed), "grant_id": h(g),
        "guest": {"identity_seed": h(guest.signer.ed_seed), "xwing_seed": h(guest.hybrid_seed)},
        "own_wrap_index": own["index"], "bundle_holds": sorted(own["bundle"]),
        "welcome": h(plain), "result_message": h(result),
        "welcome_info": h(welcome_info(guest.device_id)), "sealed_welcome": h(sealed),
        "joiner_checks": checks, "refused_welcomes": refusals,
        "roster": summary(r, sp)["roster"],
    }


def _top_up_vectors() -> dict:
    """admission.md, "The newcomer's snapshot" and "Top-ups": the body keys
    a newcomer's snapshot carries, and the top-up of a space event
    concurrent with the admission."""
    r = roster.Roster("A", "admission/records")
    r.hist.view["A"] = set(r.log.events)
    r.grant("A", "W", roster.WRITE, roster.WITH_HISTORY, label="A grants W write")
    r.sync("A", "W")
    vw = set(r.hist.view["W"])
    n = roster_device_keys(r, "N")
    adm = admission_event(r, "A", [guest_grant(n, roster.WRITE,
                                               example("admission/records/session")[:16])],
                          "A admits N from now on", brk=True,
                          recipients=[(n.device_id, n.hybrid, True, False)])
    r.hist.view["W"] = vw
    x = r.space_event("W", "W delivers, concurrent with the admission", None, False)
    # A rotation concurrent with the break is not the break and does not
    # follow it, so its state is from before the break: what is sealed
    # under it is in the top-up set.
    heal = r.heal("W", "W rotates, concurrent with the admission")
    y = r.space_event("W", "W delivers under its concurrent rotation", None, False)
    full = AdmissionSpace(r.log, None, keys=r.keyring())
    pre = AdmissionSpace(r.log, r.log.anc[adm] | {adm}, keys=r.keyring())
    snap = pre.snapshot_keys([adm])
    before = AdmissionSpace(r.log, None, keys=roster.Keyring({adm: r.krot[adm]}, dict(snap)))
    extra = {i: k for i, k in full.snapshot_keys([adm]).items() if i not in snap}
    after = AdmissionSpace(r.log, None, keys=roster.Keyring({adm: r.krot[adm]},
                                                             {**snap, **extra}))
    writers = sorted([r.hist.device("A"), r.hist.device("W")])
    order = kg.rank_order(r.id, x, writers)
    assert heal not in r.log.anc[adm] and adm not in r.log.anc[heal]
    assert set(extra) == {x, heal, y}, sorted(r.name(i) for i in extra)
    return {
        "snapshot_body_keys": {r.name(i): h(k) for i, k in sorted(
            snap.items(), key=lambda kv: r.log.order_key(kv[0]))},
        "concurrent_event": r.name(x),
        "before_the_top_up": summary(r, before)["events"],
        "top_up_body_keys": {r.name(i): h(k) for i, k in sorted(extra.items())},
        "top_up_rank": [r.hist.key_name(d) for d in order],
        "after_the_top_up": summary(r, after)["events"],
    }


def _lookup_vectors() -> dict:
    admin = device_keys("alice-desktop")
    reference = example("admission/lookup/reference")[:16]
    p = prompt(reference, admin.device_id, admin.hybrid, "Alice", ["https://peer.example"])
    sp_ = signed_prompt(p, admin.signer)
    known = {admin.device_id: (admin.identity, admin.signer.mldsa_public)}
    other = device_keys("mallory-desktop")
    forged = cbor({1: p, 2: uncbor(signed_prompt(p, other.signer))[2]})
    swapped = signed_prompt(prompt(reference, admin.device_id, other.hybrid, "Alice"),
                            admin.signer)
    answers = {"a co-member's device": answer_prompt(sp_, known.get),
               "a device no shared space names": answer_prompt(sp_, lambda d: None),
               "signed by another key": _err(answer_prompt, forged, known.get),
               "naming another X-Wing key": _err(answer_prompt, swapped, known.get)}
    plain = join_plain(reference, example("admission/person/bob"),
                       [b"(the person's signed list events)"], "Bob")
    sealed = seal_body(M_JOIN, reference, admin.hybrid, plain, eseed("admission/lookup/enc"))
    assert open_body(M_JOIN, reference, admin.hybrid_seed, sealed) == plain
    return {"prompt": h(p), "signed_prompt": h(sp_), "answers": answers,
            "join_plain": h(plain), "seal_info": h(seal_info(reference, M_JOIN)),
            "join": h(envelope(M_JOIN, reference, sealed)),
            "approver_xwing_seed": h(admin.hybrid_seed)}


def _access_request_vectors() -> dict:
    dev = device_keys("requester-phone")
    target = example("admission/access/target")
    carrier = example("admission/access/carrier")
    person = example("admission/person/dana")
    rec = access_request(target, carrier, (roster.PERSON, person), dev.device_id, roster.WRITE,
                         example("admission/access/request")[:16], "For the budget review")
    signed = sign_record(ACCESS_REQUEST_LABEL, rec, dev.signer)
    triple = (dev.identity, dev.signer.mldsa_public, dev.hybrid)

    def keys(device):
        return [triple]
    tampered = cbor({1: rec[:-1] + bytes([rec[-1] ^ 1]), 2: uncbor(signed)[2]})
    return {
        "record": h(rec), "signed": h(signed),
        "device": {"identity_seed": h(dev.signer.ed_seed), "mldsa_seed": h(dev.signer.mldsa_seed),
                   "xwing_seed": h(dev.hybrid_seed), "device_id": h(dev.device_id)},
        "checks": {
            "the request": "accepted" if verify_access_request(signed, keys) else "refused",
            "no keys held that hash to the device ID": _err(verify_access_request, signed,
                                                            lambda d: []),
            "a changed request ID": _err(verify_access_request, tampered, keys),
            "the target is the carrier": _err(verify_access_request, sign_record(
                ACCESS_REQUEST_LABEL, access_request(carrier, carrier, (roster.PERSON, person),
                                                     dev.device_id, roster.WRITE, bytes(16)),
                dev.signer), keys),
            "administer asked for": _err(verify_access_request, sign_record(
                ACCESS_REQUEST_LABEL, access_request(target, carrier, (roster.PERSON, person),
                                                     dev.device_id, roster.ADMINISTER,
                                                     bytes(16)),
                dev.signer), keys),
        },
    }


def _welcome_request_vectors() -> dict:
    dev = device_keys("erasing-laptop")
    space = example("admission/welcome-request/space")
    rec = welcome_request(space, dev.device_id, example("admission/welcome-request/id")[:16])
    signed = sign_record(WELCOME_REQUEST_LABEL, rec, dev.signer)
    triple = (dev.identity, dev.signer.mldsa_public, dev.hybrid)

    def keys(device):
        return [triple]

    def member(device):
        return True
    tampered = cbor({1: rec[:-1] + bytes([rec[-1] ^ 1]), 2: uncbor(signed)[2]})
    other_id = welcome_request(space, dev.device_id, bytes(16))
    return {
        "record": h(rec), "signed": h(signed),
        "device": {"identity_seed": h(dev.signer.ed_seed), "mldsa_seed": h(dev.signer.mldsa_seed),
                   "xwing_seed": h(dev.hybrid_seed), "device_id": h(dev.device_id)},
        "checks": {
            "the request, from a member": verify_welcome_request(signed, keys, member)["answer"],
            "the request, from a device that is no member": verify_welcome_request(
                signed, keys, lambda d: False)["answer"],
            "no keys held that hash to the device ID": _err(verify_welcome_request, signed,
                                                            lambda d: [], member),
            "a changed reason": _err(verify_welcome_request, tampered, keys, member),
            "signed over another request": _err(verify_welcome_request, cbor(
                {1: other_id, 2: uncbor(signed)[2]}), keys, member),
            "version 2": _err(verify_welcome_request, sign_record(
                WELCOME_REQUEST_LABEL, cbor({**uncbor(rec), 1: 2}), dev.signer), keys, member),
            "a reason it does not know": _err(verify_welcome_request, sign_record(
                WELCOME_REQUEST_LABEL, welcome_request(space, dev.device_id, bytes(16), 2),
                dev.signer), keys, member),
        },
    }


def admission_vectors() -> dict:
    """admission.json."""
    return {
        "specification": "admission.md",
        "parameters": _parameters(),
        "transcript": _transcript_vectors(),
        "new_device": _new_device_vectors(),
        "negative": _negative_vectors(),
        "exchange_mailbox": _exchange_mailbox_vectors(),
        "setup": _setup_vectors(),
        "welcome": _welcome_vectors(),
        "top_up": _top_up_vectors(),
        "lookup": _lookup_vectors(),
        "access_request": _access_request_vectors(),
        "welcome_request": _welcome_request_vectors(),
    }


# ---------------------------------------------------------------------------
# Extension vectors built here, for ext-invite-links.json and ext-guests.json.
# Each function returns one family of that document's "Test vectors".

INVITE_EXPIRES = 1_760_604_800


def _invite_participant(r: roster.Roster, name: str, keys: dict, view) -> None:
    """The claimant signs as the invite key: a participant of the history whose
    keys the link's secret derives."""
    r.hist.keys[name] = keys["ed_seed"]
    r.hist.signers[name] = keys["signer"]
    r.hist.view[name] = set(view)


def _invite_base(keys: dict):
    r = roster.Roster("A", "admission/invites")
    r.hist.view["A"] = set(r.log.events)
    r.grant("A", "B", roster.ADMINISTER, roster.WITH_HISTORY, label="A grants B administer")
    r.sync("A", "B")
    e = admission_event(r, "A", [invite_grant(keys, roster.WRITE, roster.FROM_NOW_ON,
                                              INVITE_EXPIRES, roster.PERSON, label="Invited")],
                        "A invites by link", brk=True,
                        recipients=[(keys["device_id"], keys["hybrid"], True, True)])
    r.sync("A", "B")
    _invite_participant(r, "invite", keys, r.hist.view["A"])
    return r, e


def _invite_secret() -> bytes:
    return example("admission/invite/secret")


def _invite_drop(secret: bytes, keys: dict, r: roster.Roster, e: bytes) -> dict:
    own = own_bundle(r.log.events[e], keys["device_id"], keys["hybrid_seed"])
    plain = drop_plain(own["delivery"]["key"], own["delivery"]["grant"] or b"", own["wrap"],
                       ["https://peer.example"])
    nonce = example("admission/invite/drop-nonce")[:24]
    return {"own": own, "plain": plain, "nonce": nonce, "drop": seal_drop(secret, plain, nonce)}


def ext_invite_links_derivations() -> dict:
    """ext-invite-links.json, `derivations`: a secret, every key, the
    locator, the drop key, the drop's address and the fragment."""
    secret = _invite_secret()
    keys = invite_keys(secret)
    r, e = _invite_base(keys)
    fragment = link_fragment(secret, e, r.id)
    assert len(fragment) == 130 and read_link_fragment(fragment)["entry"] == e
    return {"secret": h(secret),
            "keys": {"identity_seed": h(keys["ed_seed"]), "identity": h(keys["identity"]),
                     "xwing_seed": h(keys["hybrid_seed"]), "xwing": h(keys["hybrid"]),
                     "mldsa_seed": h(keys["mldsa_seed"]),
                     "mldsa_public_sha256": h(sha256(keys["mldsa"])), "kc": h(keys["kc"]),
                     "device_id": h(keys["device_id"])},
            "locator": h(drop_locator(secret)), "drop_key": h(drop_key(secret)),
            "drop_address": h(mailbox_address(MAILBOX_DROP, drop_locator(secret))),
            "invite_entry": h(e), "space": h(r.id), "fragment": fragment,
            "fragment_bytes": LINK_BYTES, "fragment_characters": len(fragment)}


def ext_invite_links_links() -> dict:
    """ext-invite-links.json, `links`: refused fragments."""
    secret = _invite_secret()
    entry, space = example("admission/invite/entry"), example("admission/invite/space")
    good = link_fragment(secret, entry, space)
    return {
        "a fragment of version 2": _err(read_link_fragment,
                                        link_fragment_raw(b"\x02" + secret + entry + space)),
        "a fragment with padding": _err(read_link_fragment, good + "="),
        "a fragment one byte short": _err(read_link_fragment,
                                          link_fragment_raw(b"\x01" + secret + entry + space[:-1])),
        "a fragment in standard base64": _err(read_link_fragment,
                                              good.replace("-", "+").replace("_", "/") + "+"),
        "an empty fragment": _err(read_link_fragment, ""),
    }


def ext_invite_links_drops() -> dict:
    """ext-invite-links.json, `drops`, the part built here: a drop sealed and
    opened, and refused drops. A MailboxPut of kind 4 and the peer's drop
    store are transport's."""
    secret = _invite_secret()
    keys = invite_keys(secret)
    r, e = _invite_base(keys)
    d = _invite_drop(secret, keys, r, e)
    got = open_drop(secret, d["drop"])
    assert got["wrap"] == d["own"]["wrap"]
    v2 = seal_drop(secret, cbor({1: 2, 2: b"k", 3: b"", 4: d["own"]["wrap"], 5: []}), d["nonce"])
    return {
        "secret": h(secret), "locator": h(drop_locator(secret)), "drop_key": h(drop_key(secret)),
        "associated_data": h(INVITE_DROP_LABEL + drop_locator(secret)),
        "plaintext": h(d["plain"]), "nonce": h(d["nonce"]), "drop": h(d["drop"]),
        "opened": {"key_name": h(got["key"]), "grant_key_name": h(got["grant"]),
                   "wrap": h(got["wrap"]), "peer_hints": got["peers"]},
        "drop_bytes": [DROP_MIN_BYTES, DROP_MAX_BYTES],
        "refused_drops": {
            "opened with another secret": _err(open_drop, example("admission/invite/other"),
                                               d["drop"]),
            "39 bytes": _err(open_drop, secret, d["drop"][:DROP_MIN_BYTES - 1]),
            "65,537 bytes": _err(open_drop, secret, d["drop"] + bytes(DROP_MAX_BYTES
                                                                      - len(d["drop"]) + 1)),
            "a damaged tag": _err(open_drop, secret, d["drop"][:-1]
                                  + bytes([d["drop"][-1] ^ 1])),
            "version 2": _err(open_drop, secret, v2),
        },
    }


def _invite_histories(keys: dict) -> tuple[dict, dict]:
    bob = example("admission/person/bob")
    carol = example("admission/person/carol")
    names = {keys["device_id"]: "invite", bob: "Bob", carol: "Carol"}

    def claim(r, who, label, rotates=False, extra=()):
        return r.space_event("invite", label,
                             roster.update_roster([successor((roster.PERSON, who)), *extra]),
                             rotates)

    def resolve(r, view=None):
        return AdmissionSpace(r.log, view, keys=r.keyring())

    cases = {}
    r, e = _invite_base(keys)
    s1 = claim(r, bob, "Bob claims")
    sp = resolve(r)
    cases["one claim"] = summary(r, sp, names)
    cases["one claim"]["claimable"] = check_claimable(sp, e, keys["device_id"])
    encodings = {"invite_event": h(r.log.events[e].signed), "invite_event_id": h(e),
                 "successor_event": h(r.log.events[s1].signed), "successor_id": h(s1),
                 "space": h(r.id)}

    r, e = _invite_base(keys)
    v0 = set(r.hist.view["invite"])
    claim(r, bob, "Bob claims")
    r.hist.view["invite"] = set(v0)
    claim(r, carol, "Carol claims")
    sp = resolve(r)
    cases["two concurrent claims"] = summary(r, sp, names)
    cases["two concurrent claims"]["claimable"] = check_claimable(sp, e, keys["device_id"])

    r, e = _invite_base(keys)
    claim(r, bob, "Bob claims")
    claim(r, carol, "Carol claims after")
    cases["a claim after a claim"] = summary(r, resolve(r), names)

    r, e = _invite_base(keys)
    v0 = set(r.hist.view["invite"])
    claim(r, bob, "Bob claims")
    r.hist.view["invite"] = set(v0)
    claim(r, carol, "Carol claims")
    r.hist.view["invite"] = set(r.log.events)
    claim(r, example("admission/person/dan"), "Dan claims after the race")
    names[example("admission/person/dan")] = "Dan"
    cases["a claim after a race"] = summary(r, resolve(r), names)

    r, e = _invite_base(keys)
    va = set(r.hist.view["A"])
    r.act("A", [revoke_invite(keys["device_id"])], "A revokes the invite at its expiry")
    r.hist.view["invite"] = va
    claim(r, bob, "Bob claims")
    cases["a claim concurrent with the revocation"] = summary(r, resolve(r), names)

    r, e = _invite_base(keys)
    r.act("A", [revoke_invite(keys["device_id"])], "A revokes the invite")
    r.sync("A", "invite")
    claim(r, bob, "Bob claims")
    sp = resolve(r)
    cases["a claim after the revocation"] = summary(r, sp, names)
    cases["a claim after the revocation"]["claimable"] = check_claimable(sp, e, keys["device_id"])

    r, e = _invite_base(keys)
    claim(r, bob, "Bob claims")
    r.sync("A", "invite")
    r.act("A", [revoke_invite(keys["device_id"])], "A closes the invite",
          rotation=False)  # a close takes nothing from anyone
    cases["a claim and its close"] = summary(r, resolve(r), names)

    r, e = _invite_base(keys)
    v0 = set(r.hist.view["invite"])
    claim(r, bob, "Bob claims")
    r.sync("A", "invite")
    r.act("A", [revoke_invite(keys["device_id"])], "A closes the invite",
          rotation=False)  # a close takes nothing from anyone
    r.hist.view["invite"] = set(v0)
    claim(r, carol, "Carol claims, backdated after the close")
    cases["a late claim after a close"] = summary(r, resolve(r), names)

    r, e = _invite_base(keys)
    r.act("A", [roster.Change(roster.GRANT, (roster.PERSON, bob), roster.READ, None, None,
                              roster.WITH_HISTORY, roster.VIA_CODE)], "A grants Bob read")
    r.sync("A", "invite")
    claim(r, bob, "Bob claims")
    cases["a claimant already in"] = summary(r, resolve(r), names)

    r, e = _invite_base(keys)
    dev = roster_device_keys(r, "D")
    r.space_event("invite", "a device claims",
                  roster.update_roster([successor((roster.DEVICE, dev.device_id), dev)]), False)
    cases["a claimant of the wrong type"] = summary(r, resolve(r), names)

    r, e = _invite_base(keys)
    r.space_event("B", "B signs a successor",
                  roster.update_roster([successor((roster.PERSON, bob))]), False)
    cases["op 4 by an administrator"] = summary(r, resolve(r), names)

    r, e = _invite_base(keys)
    claim(r, bob, "Bob claims")
    r.sync("A", "invite")
    admission_event(r, "A", [invite_grant(keys, roster.READ, roster.FROM_NOW_ON, 1_760_700_000,
                                          roster.PERSON)], "A grants the used invite again",
                    brk=True)
    cases["a used invite granted again"] = summary(r, resolve(r), names)

    r, e = _invite_base(keys)
    claim(r, bob, "a rotating claim", rotates=True)
    cases["a successor that rotates"] = summary(r, resolve(r), names)

    r, e = _invite_base(keys)
    claim(r, bob, "a claim with two changes",
          extra=[roster.Change(roster.REMOVE, (roster.DEVICE, r.hist.device("B")))])
    cases["a successor with two changes"] = summary(r, resolve(r), names)
    return cases, encodings


def ext_invite_links_histories() -> dict:
    """ext-invite-links.json, `histories`, the cases built here, with each
    event's status and the roster."""
    return _invite_histories(invite_keys(_invite_secret()))[0]


def ext_invite_links_encodings() -> dict:
    """ext-invite-links.json, `encodings`: an invite grant and a successor,
    byte for byte."""
    keys = invite_keys(_invite_secret())
    out = {"member_type_invite": INVITE, "op_succeed": SUCCEED,
           "change_keys": {"expires_at": C_EXPIRES, "claims": C_CLAIMS}}
    out.update(_invite_histories(keys)[1])
    return out


def ext_invite_links_refused_changes() -> dict:
    """ext-invite-links.json, `refused_changes`: grants and successors
    refused by shape."""
    keys = invite_keys(_invite_secret())
    bob = example("admission/person/bob")
    neg = {}
    base_map = invite_grant(keys, roster.WRITE, roster.FROM_NOW_ON, 1, roster.PERSON).value
    for desc, change in (
        ("an invite at administer", {2: roster.ADMINISTER}),
        ("an invite with no expires_at", {C_EXPIRES: None}),
        ("an invite with no claims", {C_CLAIMS: None}),
        ("an invite with via code", {6: roster.VIA_CODE}),
        ("an invite with a session that a person claims", {7: bytes(16)}),
        ("an invite that a space claims", {C_CLAIMS: roster.SPACE}),
        ("an invite that replaces", {8: bytes(32)}),
        ("an invite whose keys do not give K: another device's Ed25519 key",
         {12: device_keys("x").identity}),
    ):
        m = dict(base_map)
        for k, v in change.items():
            if v is None:
                m.pop(k)
            else:
                m[k] = v
        neg[desc] = _err(decode_change, m, bytes(32))
    neg["op 5"] = _err(decode_change, {0: 5, 1: [roster.PERSON, bob]}, bytes(32))
    neg["a change of an invite"] = _err(decode_change, {0: roster.CHANGE,
                                                        1: [INVITE, keys["device_id"]],
                                                        2: roster.READ}, bytes(32))
    neg["a successor naming a level"] = _err(decode_change, {0: SUCCEED, 1: [roster.PERSON, bob],
                                                             2: roster.READ}, bytes(32))
    neg["a successor granting a space"] = _err(decode_change,
                                               {0: SUCCEED, 1: [roster.SPACE, bob]}, bytes(32))
    g = guest_grant(device_keys("g"), roster.WRITE, bytes(16), expires_at=5).value
    del g[7]
    neg["expires_at on a device grant without session"] = _err(decode_change, g, bytes(32))
    neg["claims on a device grant"] = _err(decode_change, {**guest_grant(
        device_keys("g"), roster.WRITE, bytes(16)).value, C_CLAIMS: 0}, bytes(32))
    return neg


def ext_invite_links_claims() -> dict:
    """ext-invite-links.json, `claims`: the claimant's walk ("Claiming"),
    from fragment to roster, with and without the snapshot's body keys."""
    secret = _invite_secret()
    keys = invite_keys(secret)
    r, e = _invite_base(keys)
    names = {keys["device_id"]: "invite"}
    fragment = link_fragment(secret, e, r.id)
    d = _invite_drop(secret, keys, r, e)
    link = read_link_fragment(fragment)
    assert link["entry"] == e and link["space"] == r.id and link["secret"] == secret
    drop = open_drop(link["secret"], d["drop"])
    index, bundle = kg.find_own_wrap([drop["wrap"]], link["space"], drop["key"], drop["grant"],
                                     keys["device_id"], keys["hybrid_seed"])
    assert index == 0
    ev = r.log.events[link["entry"]]
    own = own_bundle(ev, keys["device_id"], keys["hybrid_seed"])
    assert own["wrap"] == drop["wrap"]
    full = AdmissionSpace(r.log, None, keys=r.keyring())
    body_keys = full.snapshot_keys([e])
    without = None
    try:
        AdmissionSpace(r.log, None, keys=roster.Keyring({e: bundle["content"]}))
    except SpecError as error:
        without = error.error
    newcomer = AdmissionSpace(r.log, None,
                              keys=roster.Keyring({e: bundle["content"]}, dict(body_keys)))
    return {
        "fragment": fragment, "drop": h(d["drop"]),
        "drop_wrap_opens": "accepted", "own_wrap_index": own["index"],
        "bundle_holds": sorted(bundle), "content_key": h(bundle["content"]),
        "read_credential": h(kg.read_credential(bundle["content"])["public"]),
        "invite_entry": h(e), "with_no_body_keys": without,
        "body_keys": {r.name(i): h(k) for i, k in sorted(body_keys.items(),
                                                         key=lambda kv: r.log.order_key(kv[0]))},
        "with_the_body_keys": summary(r, newcomer, names),
        "claimable": check_claimable(newcomer, e, keys["device_id"]),
    }


def ext_guests_offer_expiry() -> dict:
    """For ext-guests.json: offer key 13, a session's expiry, read by a
    joiner that implements ext-guests.md and by a core joiner (admission.md,
    "Invite links and guests")."""
    with_expiry = encode_offer(roster.WRITE, roster.FROM_NOW_ON, session=bytes(16),
                               expires_at=1_760_100_000)
    return {
        "offer": h(with_expiry),
        "an ext-guests joiner, key 13 with a session": _err(
            read_offer, with_expiry, CTX_SPACE, JOINER_DEVICE, guests=True),
        "an ext-guests joiner, key 13 without a session": _err(
            read_offer, cbor({2: 1, 5: 0, 13: 5}), CTX_SPACE, JOINER_DEVICE, guests=True),
        "a core joiner, key 13 with a session": _err(
            read_offer, with_expiry, CTX_SPACE, JOINER_DEVICE),
    }


def self_test() -> None:
    for a in NEW_LABELS:
        for b in NEW_LABELS:
            assert a is b or not a.startswith(b), (a, b)
    v = admission_vectors()
    assert list(v) == ["specification", "parameters", "transcript", "new_device", "negative",
                       "exchange_mailbox", "setup", "welcome", "top_up", "lookup",
                       "access_request", "welcome_request"], list(v)
    t = v["transcript"]
    assert len(t["exchanges"]) == 4 and all(len(x["code"]) == 6 for x in t["exchanges"])
    assert t["leading_zero"]["code"].startswith("0")
    assert t["qr_refusals"] == {"lower case": "Malformed", "no prefix": "Malformed",
                                "version 2": "UnsupportedVersion"}
    cm = t["channel_matters"]
    assert cm["with the channel"] != cm["the same fields with an empty channel"]
    nd = v["new_device"]["checks"]
    assert nd == {"the Result": "accepted", "another approver": "WrongApprover",
                  "another person": "WrongPerson", "a head the add does not follow":
                  "NotFollowing", "a list without the add": "WrongMember"}, nd
    ep = v["new_device"]["expected_person"]["checks"]
    assert ep == {"the expected person": "accepted",
                  "another person than the expected one": "WrongPerson"}, ep
    nd = v["new_device"]["direct"]["checks"]
    assert nd == {"the Result": "accepted", "the Welcome": "accepted",
                  "a Welcome naming another approver": "WrongApprover",
                  "a Welcome sealed to another exchange's key": "Decrypt"}, nd
    n = v["negative"]
    assert n["approver"] == {
        "a Request past its expiry": "Expired",
        "a Request living 961 seconds": "Malformed",
        "a Request answered before": "Replayed",
        "a Request for a device list, sent to a space's approver": "Malformed",
        "an envelope of version 2": "UnsupportedVersion",
        "an envelope of type 11, unknown": "Malformed",
        "a Request message over 4,096 bytes": "TooLarge",
        "a Cancel with a body": "Malformed",
        "a Reveal with another display": "CommitmentMismatch",
        "a second Reveal": "ignored",
        "a Reveal of other keys": "CommitmentMismatch",
        "a Reveal past the expiry": "Expired"}, n["approver"]
    assert set(n["joiner_ignores"].values()) == {"ignored"}, n["joiner_ignores"]
    assert len(n["refused_offers"]) == 7
    assert set(n["refused_offers"].values()) == {"Malformed"}, n["refused_offers"]
    m = v["exchange_mailbox"]
    assert [x["result"] for x in m["steps"]] == [
        "stored", "MailboxInUse", "OutOfOrder", "stored", "Duplicate", "stored", "Expired",
        "UnknownMailbox", "Malformed"], m["steps"]
    assert m["eleven_requests_in_a_minute"] == ["stored"] * 10 + ["RateLimited"]
    assert m["a Request living 961 seconds"]["result"] == "Malformed"
    s = v["setup"]
    assert s["outcomes"] == {"the administrator, the device's own keys": "accepted",
                             "the administrator, another device's keys": "SetupMismatch",
                             "the device, a MAC that does not verify": "BadMac",
                             "the device, an Offer on another connection": "BadMac",
                             "the device, the first MAC that verifies": "bound",
                             "the device, a second Offer with a valid MAC": "Provisioned"}, s
    assert s["a peer refusing a Hello"]["result"] == "Malformed"
    assert all(x != "accepted" for x in s["text_refusals"].values())
    assert len(s["announced_name"]) == 22
    w = v["welcome"]
    assert w["joiner_checks"] == {
        "the grant": "accepted", "another approver": "WrongApprover",
        "another space": "WrongSpace", "a head the grant does not follow": "NotFollowing",
        "another offer": "OfferMismatch",
        "the same grant, expected by lookup": "OfferMismatch"}, w["joiner_checks"]
    assert w["refused_welcomes"] == {"another device opens it": "Decrypt",
                                     "version 2": "UnsupportedVersion",
                                     "suite 0x0020": "UnsupportedVersion",
                                     "1,138 bytes": "Malformed"}, w["refused_welcomes"]
    rec = v["top_up"]
    assert rec["before_the_top_up"][rec["concurrent_event"]] == "Sealed"
    assert all(x == "valid" for x in rec["after_the_top_up"].values())
    assert v["lookup"]["answers"] == {"a co-member's device": "Join",
                                      "a device no shared space names": "code exchange",
                                      "signed by another key": "BadSignature",
                                      "naming another X-Wing key": "NotCommitted"}
    a = v["access_request"]["checks"]
    assert a == {"the request": "accepted", "no keys held that hash to the device ID": "NoHybridKey",
                 "a changed request ID": "BadSignature",
                 "the target is the carrier": "Malformed",
                 "administer asked for": "Malformed"}, a
    w = v["welcome_request"]["checks"]
    assert w == {"the request, from a member": "welcome",
                 "the request, from a device that is no member": "ignored",
                 "no keys held that hash to the device ID": "NoHybridKey",
                 "a changed reason": "Malformed",
                 "signed over another request": "BadSignature",
                 "version 2": "UnsupportedVersion",
                 "a reason it does not know": "Malformed"}, w
    _ext_self_test()


def _ext_self_test() -> None:
    d = ext_invite_links_derivations()
    assert d["fragment_characters"] == 130 and d["fragment_bytes"] == 97
    assert all(x != "accepted" for x in ext_invite_links_links().values())
    dr = ext_invite_links_drops()["refused_drops"]
    assert dr == {"opened with another secret": "Decrypt", "39 bytes": "Malformed",
                  "65,537 bytes": "Malformed", "a damaged tag": "Decrypt",
                  "version 2": "UnsupportedVersion"}, dr
    inv = ext_invite_links_histories()
    one = inv["one claim"]
    assert one["events"]["Bob claims"] == "valid" and one["roster"]["invite"] == "out"
    assert one["roster"]["Bob"]["via"] == "link" and one["claimable"] == "InviteUsed"
    assert inv["two concurrent claims"]["events"]["Bob claims"] == "ClaimRaced"
    assert inv["two concurrent claims"]["events"]["Carol claims"] == "ClaimRaced"
    assert inv["two concurrent claims"]["claimable"] == "InviteRaced"
    assert inv["a claim after a claim"]["events"]["Carol claims after"] == "InviteUsed"
    assert inv["a claim concurrent with the revocation"]["events"]["Bob claims"].startswith(
        "RemovedConcurrently")
    assert inv["a claim after the revocation"]["events"]["Bob claims"] == "NotAnInvite"
    assert inv["a claim after the revocation"]["claimable"] == "InviteRevoked"
    closed = inv["a claim and its close"]["events"]
    assert closed["Bob claims"] == "valid" and closed["A closes the invite"] == "valid", closed
    late = inv["a late claim after a close"]["events"]
    assert late["Bob claims"] == "valid" and late["A closes the invite"] == "valid", late
    assert not late["Carol claims, backdated after the close"].startswith("valid"), late
    assert inv["a claimant already in"]["events"]["Bob claims"] == "AlreadyMember"
    assert inv["a claimant of the wrong type"]["events"]["a device claims"] == "ClaimMismatch"
    assert inv["op 4 by an administrator"]["events"]["B signs a successor"] == "NotAnInvite"
    assert inv["a used invite granted again"]["events"]["A grants the used invite again"] \
        == "InviteUsed"
    assert inv["a successor that rotates"]["events"]["a rotating claim"] == "Malformed"
    assert inv["a successor with two changes"]["events"]["a claim with two changes"] \
        == "Malformed"
    cl = ext_invite_links_claims()
    assert cl["with_no_body_keys"] == "Sealed" and cl["claimable"] == "Open"
    assert all(x == "valid" for x in cl["with_the_body_keys"]["events"].values())
    ref = ext_invite_links_refused_changes()
    assert ref["an invite at administer"] == "AdministerNotDevice"
    k = "an invite whose keys do not give K: another device's Ed25519 key"
    assert ref[k] == "NotCommitted"
    assert all(x == "Malformed" for n, x in ref.items()
               if n not in ("an invite at administer", k))
    assert ext_invite_links_encodings()["member_type_invite"] == 3
    g = ext_guests_offer_expiry()
    assert g["an ext-guests joiner, key 13 with a session"] == "accepted"
    assert g["an ext-guests joiner, key 13 without a session"] == "Malformed"
    assert g["a core joiner, key 13 with a session"] == "Malformed"


if __name__ == "__main__":
    self_test()
    print("admission: self-test passed")
