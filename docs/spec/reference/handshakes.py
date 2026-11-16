"""Transport (transport.md), protocol 1, written from the
specification, independently of any implementation.

The member handshake proves, under a state both sides hold, that each side
holds a state of a space, without showing a non-member which space; it then
binds each side's device ID to the transport's channel. The
device-to-peer handshake gives an always-on peer a binding value for the
credential proofs of peers.md, and never a device identity. Around them:
frames and their caps, local-network announcements that only members can
open, nearby announcements, tickets, mailbox addresses and sealed device
mailbox items.

Channel values come out of a TLS handshake, so the vectors take them as
inputs. The module keeps its file name; its vector function is
`transport_vectors()`, for transport.json. `ext_invite_links_drops()` and
`ext_libraries_library_attach()` give the material that ext-invite-links.md
and ext-libraries.md place in their own files.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import unicodedata

import events
import history_sigs as hs
import identity
import keygraph
import wraps
import xwing
from events import cbor, is_bytes, is_uint, uncbor
from formats import REVISION, example
from primitives import (
    SpecError,
    ed25519_public,
    ed25519_sign_deterministic,
    ed25519_valid,
    ed25519_verify_strict,
    field,
    hkdf,
    point_encode,
    sha256,
    small_order_points,
    xchacha20poly1305_open,
    xchacha20poly1305_seal,
)

# ---------------------------------------------------------------------------
# Labels and names (transport.md, "Labels and names"; crypto.md's registry).

MEMBER_KEY_LABEL = b"frasil/member-key/v1"
OFFER_LABEL = b"frasil/member-offer/v1"
TRANSCRIPT_LABEL = b"frasil/member-transcript/v1"
ANSWER_LABEL = b"frasil/member-answer/v1"
IDENTIFY_LABEL = b"frasil/member-identify/v1"
PEER_BINDING_LABEL = b"frasil/peer-binding/v1"
SERVER_CHANNEL_LABEL = b"frasil/server-channel/v1"
LAN_KEY_LABEL = b"frasil/lan-key/v1"
LAN_ANNOUNCE_LABEL = b"frasil/lan-announce/v1"
MAILBOX_LABEL = b"frasil/mailbox/v1"
MAILBOX_COLLECT_LABEL = b"frasil/mailbox-collect/v1"
MAILBOX_ITEM_LABEL = b"frasil/mailbox-item/v1"
ALPN_MEMBER = b"frasil/p1/member"
ALPN_PEER = b"frasil/p1/peer"
ALPN_NEARBY = b"frasil/p1/nearby"
WEBSOCKET_SUBPROTOCOL = "frasil.p1"
EXPORTER_LABEL = b"EXPORTER-Channel-Binding"  # RFC 9266; not a Frasil label

NEW_LABELS: list[bytes] = [
    MEMBER_KEY_LABEL, OFFER_LABEL, TRANSCRIPT_LABEL, ANSWER_LABEL, IDENTIFY_LABEL,
    PEER_BINDING_LABEL, SERVER_CHANNEL_LABEL, LAN_KEY_LABEL, LAN_ANNOUNCE_LABEL, MAILBOX_LABEL,
    MAILBOX_COLLECT_LABEL, MAILBOX_ITEM_LABEL,
    ALPN_MEMBER, ALPN_PEER, ALPN_NEARBY,
]

# ext-guests.md's label, listed by guests.py; used here only to sign the
# leave request that a sealed `frasil/leave-request` item carries.
LEAVE_REQUEST_LABEL = b"frasil/leave-request/v1"

PROTOCOL = 1
OFFER_TAGS = 16
NONCE_BYTES = 32
TAG_BYTES = 32
ROLE_INITIATOR = 0x01  # the byte that marks an initiator's tag
ROLE_DIALER, ROLE_LISTENER = 0x01, 0x02
MAX_ATTACHES = 1024
CANDIDATES_PER_SPACE = 256
CANDIDATE_BUDGET = 8192
EXTRA_OFFERS = 3
MAX_OFFERS = 1 + EXTRA_OFFERS
OLDER_STATES_OPENING = 3  # a listener tries its current state and up to 3 before it
HANDSHAKE_DEADLINE = 10
PROBATION_SECONDS, PROBATION_EVENTS = 30, 4096
PAIRING_DEADLINE = 90

# Message types (transport.md, "Message types").
OFFER, ANSWER, REFUSE, IDENTIFY, ADMIT, DETACH, OPEN, ADDRESSES = 1, 2, 3, 4, 5, 6, 7, 8
PEER_HELLO, HELLO, PRESENT, GRANTED, REFUSED = 16, 17, 18, 19, 20
LIBRARY_ATTACH, ACCEPTED, MERGE = 21, 22, 23
MAILBOX_PUT, MAILBOX_GET, MAILBOX_ITEMS, AWAITING, MAILBOX_DELETE = 24, 25, 26, 27, 28
REGISTER_RECOVERY_ENTRY, EVENT_REFUSED, HOLD_OBJECT = 29, 30, 31
TOKEN_KEYS_GET, TOKEN_KEYS, TOKEN_REQUEST, TOKEN_ISSUE = 40, 41, 42, 43  # ext-deposit-tokens.md's
SYNC, ADAPTER_SYNC = 32, 34
EPHEMERAL, GONE = 48, 49
PAIRING = 64
NEXT_ENDPOINT = 96  # ext-next-endpoints.md's, in the ignorable range
ERASURE_LATE = 97  # peers.md, "A device's own erasure": core, in the ignorable range
TYPE_NAMES = {OFFER: "Offer", ANSWER: "Answer", REFUSE: "Refuse", IDENTIFY: "Identify",
              ADMIT: "Admit", DETACH: "Detach", OPEN: "Open", ADDRESSES: "Addresses",
              PEER_HELLO: "PeerHello",
              HELLO: "Hello", PRESENT: "Present", GRANTED: "Granted", REFUSED: "Refused",
              LIBRARY_ATTACH: "LibraryAttach", ACCEPTED: "Accepted", MERGE: "Merge",
              MAILBOX_PUT: "MailboxPut", MAILBOX_GET: "MailboxGet",
              MAILBOX_ITEMS: "MailboxItems", AWAITING: "Awaiting",
              MAILBOX_DELETE: "MailboxDelete", REGISTER_RECOVERY_ENTRY: "RegisterRecoveryEntry",
              EVENT_REFUSED: "EventRefused", HOLD_OBJECT: "HoldObject",
              TOKEN_KEYS_GET: "TokenKeysGet", TOKEN_KEYS: "TokenKeys",
              TOKEN_REQUEST: "TokenRequest", TOKEN_ISSUE: "TokenIssue",
              SYNC: "Sync", ADAPTER_SYNC: "AdapterSync", EPHEMERAL: "Ephemeral", GONE: "Gone",
              PAIRING: "Pairing", NEXT_ENDPOINT: "NextEndpoint", ERASURE_LATE: "ErasureLate"}
# Types 21, 28, 31, 40 to 43 and 96 are their extensions'. A receiver that
# does not implement the extension treats them as unknown.
DEPOSIT_TOKEN_TYPES = (TOKEN_KEYS_GET, TOKEN_KEYS, TOKEN_REQUEST, TOKEN_ISSUE)
EXTENSION_TYPES = {LIBRARY_ATTACH: "ext-libraries", MAILBOX_DELETE: "ext-invite-links",
                   HOLD_OBJECT: "ext-libraries", NEXT_ENDPOINT: "ext-next-endpoints",
                   **{t: "ext-deposit-tokens" for t in DEPOSIT_TOKEN_TYPES}}
IGNORABLE_TYPES = range(96, 128)

UNITS_MESSAGE_BYTES = 1_052_672  # units.md, "Sync messages"
SYNC_CAP = UNITS_MESSAGE_BYTES + 4_096
MAILBOX_ITEM_BYTES = 262_144
MAILBOX_CAP = MAILBOX_ITEM_BYTES + 4_096
EPHEMERAL_CAP = 25_088
OBJECT_CHUNK_BYTES = 1_048_576
TYPE_CAPS = {**{t: 4_096 for t in (OFFER, ANSWER, REFUSE, IDENTIFY, ADMIT, DETACH, OPEN,
                                   NEXT_ENDPOINT)},
             **{t: 16_384 for t in (ADDRESSES, PEER_HELLO, HELLO, PRESENT, GRANTED, REFUSED,
                                    LIBRARY_ATTACH, ACCEPTED, MERGE, MAILBOX_DELETE,
                                    REGISTER_RECOVERY_ENTRY, EVENT_REFUSED, HOLD_OBJECT,
                                    *DEPOSIT_TOKEN_TYPES)},
             **{t: MAILBOX_CAP for t in (MAILBOX_PUT, MAILBOX_GET, MAILBOX_ITEMS, AWAITING,
                                         ERASURE_LATE)},
             SYNC: SYNC_CAP, ADAPTER_SYNC: SYNC_CAP,
             EPHEMERAL: EPHEMERAL_CAP, GONE: EPHEMERAL_CAP, PAIRING: MAILBOX_CAP}
STREAM_CAPS = {"control": MAILBOX_CAP, "sync": SYNC_CAP, "object": SYNC_CAP,
               "ephemeral": EPHEMERAL_CAP, "nearby": MAILBOX_CAP}
STREAM_TYPES = {
    "control": {OFFER, ANSWER, REFUSE, IDENTIFY, ADMIT, DETACH, ADDRESSES, PEER_HELLO, HELLO,
                PRESENT, GRANTED, REFUSED, LIBRARY_ATTACH, ACCEPTED, MERGE, MAILBOX_PUT,
                MAILBOX_GET, MAILBOX_ITEMS, AWAITING, MAILBOX_DELETE, REGISTER_RECOVERY_ENTRY,
                EVENT_REFUSED, HOLD_OBJECT, GONE, NEXT_ENDPOINT, ERASURE_LATE,
                *DEPOSIT_TOKEN_TYPES},
    "sync": {OPEN, SYNC, ADAPTER_SYNC},
    "object": {OPEN, SYNC},
    "ephemeral": {OPEN, EPHEMERAL},
    "nearby": {PAIRING},
}
STREAM_KIND_CODES = {"sync": 1, "object": 2, "ephemeral": 3}
MAX_AWAITING = 7_829  # the most event IDs an `Awaiting` within its cap holds
# Member addresses (transport.md, "The iroh binding", member addresses).
MAX_ADDRESS_ENTRIES = 64
LEARNED_TICKETS, LEARNED_SECONDS = 128, 10  # as local-network candidates
CROSS_DIAL_WAIT_SECONDS = 1  # the greater endpoint key's wait

# Codes (transport.md, "Codes"): QUIC and WebSocket closes, Refuse, Detach.
CLOSE_CODES = {0: "done", 1: "malformed", 2: "too_large", 3: "unsupported_version",
               4: "no_common_state", 5: "bad_proof", 6: "bad_signature",
               7: "membership_ended", 8: "unknown_member", 9: "timeout", 10: "attach_limit",
               11: "busy", 12: "purpose_violation", 13: "credential_refused",
               14: "invalid_key", 15: "forked", 16: "revision_mismatch",
               17: "reconnect"}


def class_of(code_name: str) -> str:
    """A code's error class: its name in UpperCamelCase."""
    return "".join(part.capitalize() for part in code_name.split("_"))


PURPOSE_SPACE, PURPOSE_ADMINISTRATION = 1, 2
CREDENTIAL_READ, CREDENTIAL_UPLOAD, CREDENTIAL_ADMINISTRATOR, CREDENTIAL_FETCH = 1, 2, 3, 4
MAILBOX_EXCHANGE, MAILBOX_PERSON, MAILBOX_DEVICE, MAILBOX_DROP = 1, 2, 3, 4
MAILBOX_KIND_NAMES = {1: "exchange mailbox", 2: "person mailbox", 3: "device mailbox"}
RIGHTS = {1: "fetch", 2: "live", 3: "store", 4: "release", 5: "erase", 6: "catch-up"}
SERVICES = {1: "relay", 2: "store", 3: "mailbox", 4: "account", 5: "library", 6: "deposit"}

# The reason codes transport.md raises, with their HTTP statuses
# (transport.md, "Codes"). peers.md, admission.md and the extensions give
# their own codes' statuses.
REASONS = [
    ("malformed", 400), ("revision_mismatch", 400), ("unauthenticated", 401),
    ("credential_refused", 403), ("purpose_violation", 403), ("not_found", 404),
    ("too_large", 413), ("invalid_key", 422), ("bad_signature", 422), ("rate_limited", 429),
    ("busy", 503),
]

LAN_VERSION_MEMBER, LAN_VERSION_NEARBY = 0x01, 0x02
LAN_PLAINTEXT_BYTES = 96
LAN_PACKET_BYTES = 1 + 24 + LAN_PLAINTEXT_BYTES + 16
LAN_GROUPS = ("239.255.77.67", "ff02::7767")
LAN_PORT = 47_767
NEARBY_NAME_CHARACTERS = 48
NEARBY_FALLBACK = "Nearby device"
BIDI_CONTROLS = {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
TICKET_MAX_BYTES = 1024
TICKET_PREFIX = "frasil:"

DEVICE_MAILBOX_ITEMS = 64
DEVICE_MAILBOX_BYTES = 4 * 1024 * 1024
CONTENT_NAME_BYTES = 64
CONTENT_ACCESS_REQUEST = "frasil/access-request"
CONTENT_LEAVE_REQUEST = "frasil/leave-request"  # ext-guests.md
CONTENT_LIST_EVENTS = "frasil/list-events"
CONTENT_WELCOME_REQUEST = "frasil/welcome-request"
CORE_CONTENT = frozenset({CONTENT_ACCESS_REQUEST, CONTENT_LIST_EVENTS, CONTENT_WELCOME_REQUEST})


def h(value: bytes) -> str:
    return value.hex()


def u32be(value: int) -> bytes:
    return value.to_bytes(4, "big")


def _uint(value) -> bool:
    return is_uint(value) and value >= 0


def hmac256(key: bytes, message: bytes) -> bytes:
    return hmac.new(key, message, hashlib.sha256).digest()


def expect_class(function, *args, **kwargs) -> str:
    try:
        function(*args, **kwargs)
    except SpecError as error:
        return error.error
    raise AssertionError(f"{function.__name__} accepted")


# ---------------------------------------------------------------------------
# Framing (transport.md, "Frames and stream classes" and "Reading a frame").


def frame(message: dict) -> bytes:
    payload = cbor(message)
    return u32be(len(payload)) + payload


def read_frame(data: bytes, stream: str, connection: str = "peer",
               extensions=()) -> tuple[dict | None, bytes]:
    """read_frame, in order, on the front of a stream's bytes. Returns the
    message, or None for an ignorable type the receiver drops, and what
    follows. The prefix is checked before anything is allocated."""
    if len(data) < 4:
        raise SpecError("Incomplete")
    length = int.from_bytes(data[:4], "big")
    if length > STREAM_CAPS[stream]:
        raise SpecError("TooLarge")
    if len(data) < 4 + length:
        raise SpecError("Incomplete")
    message = read_message(data[4:4 + length], stream, connection, extensions)
    return message, data[4 + length:]


def read_message(payload: bytes, stream: str, connection: str = "peer",
                 extensions=()) -> dict | None:
    """read_frame, steps 2 to 6, on one message. `connection` is "member" or
    "peer"; `extensions` names the extensions the receiver implements."""
    value = uncbor(payload)
    if not isinstance(value, dict) or not value or not _uint(value.get(0)):
        raise SpecError("Malformed")
    kind = value[0]
    known = kind in TYPE_CAPS and (kind not in EXTENSION_TYPES
                                   or EXTENSION_TYPES[kind] in extensions)
    if not known:
        if kind in IGNORABLE_TYPES:
            return None
        raise SpecError("UnknownMessage")
    if kind not in STREAM_TYPES[stream]:
        raise SpecError("Malformed")
    if len(payload) > TYPE_CAPS[kind]:
        raise SpecError("TooLarge")
    if connection == "member" and (kind == GONE or (kind == EPHEMERAL and 3 in value)):
        raise SpecError("Malformed")
    if connection != "member" and kind == ADDRESSES:
        raise SpecError("Malformed")
    if kind == ERASURE_LATE and (connection != "peer" or not _erasure_late_ok(value)):
        raise SpecError("Malformed")
    return value


def _erasure_late_ok(value: dict) -> bool:
    """transport.md, ErasureLate: exactly keys 0 to 5; the space and the
    erasure's ID, 32 bytes each; the cut's signed envelope, bytes; the
    checkpoint's ID, 32 bytes; the standing, 0, 1 or 2. What the cut says is
    the residue's to check (peers.md, "What the residue checks")."""
    return (set(value) == {0, 1, 2, 3, 4, 5}
            and all(isinstance(value[k], bytes) for k in (1, 2, 3, 4))
            and len(value[1]) == 32 and len(value[2]) == 32 and len(value[4]) == 32
            and _uint(value[5]) and value[5] <= 2)


# ---------------------------------------------------------------------------
# The member handshake (transport.md, "Member handshake values" and "The
# member handshake").


def member_key(state_secret: bytes) -> bytes:
    """hk(S) = HKDF(none, k(S), "frasil/member-key/v1").
    ext-restricted-spaces.md says which secret replaces k(S) in a restricted
    space."""
    return hkdf(keygraph.NO_SALT, state_secret, MEMBER_KEY_LABEL)


def offer_tag(hk: bytes, channel: bytes, attach: int, nonce: bytes) -> bytes:
    return hmac256(hk, OFFER_LABEL + field(channel) + bytes([ROLE_INITIATOR]) + u32be(attach)
                   + nonce)


def offered_states(current: tuple, held: set, history: list) -> list:
    """The initiator's choice: its current state; then, for a state that
    holds several rotations, each of them alone that it holds, in canonical
    order, at most 7; then the states it held as current before, most
    recent first; at most 16 in all."""
    out = [current]
    if len(current) > 1:
        out += [(r,) for r in current if (r,) in held][:7]
    for state in history:
        if state not in out:
            out.append(state)
    return out[:OFFER_TAGS]


def encode_offer(attach: int, nonce: bytes, tags: list, revision: int = REVISION) -> bytes:
    return cbor({0: OFFER, 1: attach, 2: nonce, 3: tags, 4: revision})


def read_offer(payload: bytes, initiator: int = ROLE_DIALER, previous_offers: int = 0) -> dict:
    """On Offer, steps 1 to 5. `initiator` is the initiator's role on the
    connection (the dialer numbers its attaches 0, 2, 4, the listener 1, 3,
    5); `previous_offers` counts the offers this attach has had."""
    value = read_message(payload, "control", "member")
    if (value is None or value[0] != OFFER or set(value) != {0, 1, 2, 3, 4}
            or not _uint(value[4])):
        raise SpecError("Malformed")
    if value[4] != REVISION:
        raise SpecError("RevisionMismatch")
    attach, nonce, tags = value[1], value[2], value[3]
    if not _uint(attach):
        raise SpecError("Malformed")
    if attach >= MAX_ATTACHES:
        raise SpecError("AttachLimit")
    parity = 0 if initiator == ROLE_DIALER else 1
    if (attach % 2 != parity or not is_bytes(nonce, NONCE_BYTES)
            or not isinstance(tags, list) or len(tags) != OFFER_TAGS
            or not all(is_bytes(t, TAG_BYTES) for t in tags)):
        raise SpecError("Malformed")
    if previous_offers >= MAX_OFFERS:
        raise SpecError("Malformed")
    return {"attach": attach, "nonce": nonce, "tags": tags}


def respond(offer_payload: bytes, channel: bytes, candidates: list,
            initiator: int = ROLE_DIALER, previous_offers: int = 0) -> dict:
    """On Offer, at the responder. candidates: (space, state, secret) in the
    responder's order. It computes at most 8,192 tags per offer. The match
    is the candidate whose tag equals the offer's tag of the smallest index;
    among equal tags, the first in the responder's order. Out of budget
    without a match, it answers Busy, not NoCommonState."""
    offer = read_offer(offer_payload, initiator, previous_offers)
    expected = {}
    for space, state, secret in candidates[:CANDIDATE_BUDGET]:
        tag = offer_tag(member_key(secret), channel, offer["attach"], offer["nonce"])
        expected.setdefault(tag, (space, state, secret))
    for index, tag in enumerate(offer["tags"]):
        if tag in expected:
            space, state, secret = expected[tag]
            return {"index": index, "space": space, "state": state, "secret": secret}
    raise SpecError("Busy" if len(candidates) > CANDIDATE_BUDGET else "NoCommonState")


def encode_answer_core(attach: int, nonce: bytes, index: int) -> bytes:
    return cbor({0: ANSWER, 1: attach, 2: nonce, 3: index})


def encode_answer(attach: int, nonce: bytes, index: int, proof: bytes) -> bytes:
    return cbor({0: ANSWER, 1: attach, 2: nonce, 3: index, 4: proof})


def transcript(channel: bytes, endpoint_i: bytes, endpoint_r: bytes, offer: bytes,
               answer_core: bytes) -> bytes:
    return sha256(TRANSCRIPT_LABEL + field(channel) + field(endpoint_i) + field(endpoint_r)
                  + field(offer) + field(answer_core))


def answer_proof(hk: bytes, th: bytes) -> bytes:
    return hmac256(hk, ANSWER_LABEL + th)


def verify_answer(answer_payload: bytes, ctx: dict) -> dict:
    """On Answer or Refuse, at the initiator, steps 1 to 4. ctx: attach,
    channel, endpoint_i, endpoint_r, offer (bytes), offered (a (state,
    secret) per tag index, None for a filler). A Refuse raises its code's
    class."""
    value = read_message(answer_payload, "control", "member")
    if value is not None and value[0] == REFUSE:
        # A reconnect on a member connection is taken as done (transport.md,
        # "Reconnecting elsewhere").
        name = CLOSE_CODES.get(value.get(2), "malformed")
        raise SpecError(class_of("done" if name == "reconnect" else name))
    if value is None or value[0] != ANSWER or set(value) != {0, 1, 2, 3, 4}:
        raise SpecError("Malformed")
    attach, nonce, index, proof = value[1], value[2], value[3], value[4]
    if (attach != ctx["attach"] or not is_bytes(nonce, NONCE_BYTES) or not _uint(index)
            or index >= OFFER_TAGS or not is_bytes(proof, 32)):
        raise SpecError("Malformed")
    offered = ctx["offered"][index]
    if offered is None:
        raise SpecError("BadProof")  # a filler names no state
    state, secret = offered
    th = transcript(ctx["channel"], ctx["endpoint_i"], ctx["endpoint_r"], ctx["offer"],
                    encode_answer_core(attach, nonce, index))
    if not hmac.compare_digest(answer_proof(member_key(secret), th), proof):
        raise SpecError("BadProof")
    return {"state": state, "transcript": th}


def identify_input(th0: bytes, role: int, signer: bytes) -> bytes:
    """`signer` is the device's `ed || kc` (crypto.md, "A device's keys"):
    the signature covers both, so it binds the device ID they give."""
    assert len(signer) == 64
    return IDENTIFY_LABEL + th0 + bytes([role]) + signer


def encode_identify(signer: bytes, signature: bytes) -> bytes:
    return cbor({0: IDENTIFY, 1: signer, 2: signature})


def verify_identify(payload: bytes, th0: bytes, role: int) -> bytes:
    """On Identify, steps 6 to 9: role is the sender's role on the
    connection. Returns the device ID of the sender's ed and kc, for the
    roster check."""
    value = read_message(payload, "control", "member")
    if value is None or value[0] != IDENTIFY or set(value) != {0, 1, 2}:
        raise SpecError("Malformed")
    signer, signature = value[1], value[2]
    if not is_bytes(signer, 64) or not is_bytes(signature, 64):
        raise SpecError("Malformed")
    ed, _, device_id = hs.split_signer(signer)
    if not ed25519_valid(ed):
        raise SpecError("InvalidKey")
    if not ed25519_verify_strict(ed, identify_input(th0, role, signer), signature):
        raise SpecError("BadSignature")
    return device_id


# ---------------------------------------------------------------------------
# The device-to-peer handshake and credentials (transport.md, "The
# device-to-peer handshake" and "Presenting credentials").


def server_channel(origin: str) -> bytes:
    """The server binding's channel: the origin the client connected to,
    as RFC 6454 serialises it, hashed under a label."""
    return sha256(SERVER_CHANNEL_LABEL + field(origin.encode("ascii")))


def peer_binding(channel: bytes, nonce_peer: bytes, nonce_client: bytes, purpose: int) -> bytes:
    return sha256(PEER_BINDING_LABEL + field(channel) + nonce_peer + nonce_client
                  + bytes([purpose]))


def presented(binding: bytes, space: bytes, credential: int, public: bytes) -> bytes:
    """What peers.md's credential proof covers after its own label."""
    return field(binding) + field(space) + bytes([credential]) + field(public)


def encode_peer_hello(nonce: bytes, services: list, limits: dict,
                      revision: int = REVISION) -> bytes:
    return cbor({0: PEER_HELLO, 1: PROTOCOL, 2: nonce, 3: services, 4: limits, 5: revision})


def encode_hello(nonce: bytes, purpose: int, revision: int = REVISION) -> bytes:
    return cbor({0: HELLO, 1: PROTOCOL, 2: nonce, 3: purpose, 4: revision})


def read_hello(payload: bytes, kind: int) -> dict:
    """A `Hello` at the peer (steps 2 to 5), or a `PeerHello` at the
    device: its keys, protocol and revision."""
    value = read_message(payload, "control")
    keys = {HELLO: {0, 1, 2, 3, 4}, PEER_HELLO: {0, 1, 2, 3, 4, 5}}[kind]
    revision_key = 4 if kind == HELLO else 5
    if value is None or value[0] != kind or set(value) != keys or not _uint(value[1]):
        raise SpecError("Malformed")
    if value[1] != PROTOCOL:
        raise SpecError("UnsupportedVersion")
    if not _uint(value[revision_key]):
        raise SpecError("Malformed")
    if value[revision_key] != REVISION:
        raise SpecError("RevisionMismatch")
    if not is_bytes(value[2], NONCE_BYTES):
        raise SpecError("Malformed")
    if kind == HELLO and value[3] not in (PURPOSE_SPACE, PURPOSE_ADMINISTRATION):
        raise SpecError("Malformed")
    return value


def encode_present(request: int, space: bytes, credential: int, public: bytes,
                   proof: bytes) -> bytes:
    return cbor({0: PRESENT, 1: request, 2: space, 3: credential, 4: public, 5: proof})


def encode_register_recovery_entry(request: int, space: bytes, fetch_key: bytes) -> bytes:
    return cbor({0: REGISTER_RECOVERY_ENTRY, 1: request, 2: space, 3: fetch_key})


def object_locator(object_id: bytes, stored: bytes) -> bytes:
    """units.md: the object ID, then SHA-256 of the stored object."""
    assert len(object_id) == 32
    return object_id + sha256(stored)


def chunk_path(space: bytes, locator: bytes, index: int) -> str:
    """An object chunk's route on the server binding."""
    if len(space) != 32 or len(locator) != 64 or index < 0:
        raise SpecError("Malformed")
    return f"/frasil/p1/spaces/{space.hex()}/objects/{locator.hex()}/chunks/{index}"


def peer_session_check(purpose: int, presents: list, bearer: bool, sends=()) -> str:
    """What a connection of each purpose may carry. `sends` names the
    device's other requests: "library_attach" (type 21), "merge",
    "register_recovery_entry" and "mailbox"."""
    if purpose == PURPOSE_ADMINISTRATION:
        if bearer or sends:
            return "purpose_violation"
        if len(presents) != 1 or presents[0]["credential"] != CREDENTIAL_ADMINISTRATOR:
            return "purpose_violation"
        return "ok"
    if any(p["credential"] == CREDENTIAL_ADMINISTRATOR for p in presents):
        return "purpose_violation"
    return "ok"


# ---------------------------------------------------------------------------
# Local-network packets, nearby announcements and tickets (transport.md,
# "Local-network packets", "The iroh binding" and "Tickets").


def lan_key(state_secret: bytes) -> bytes:
    return hkdf(keygraph.NO_SALT, state_secret, LAN_KEY_LABEL)


def lan_plaintext(endpoint: bytes, port: int) -> bytes:
    core = cbor({1: endpoint, 2: port})
    body = len(core).to_bytes(2, "big") + core
    return body + bytes(LAN_PLAINTEXT_BYTES - len(body))


def lan_announce(state_secret: bytes, endpoint: bytes, port: int, nonce: bytes) -> bytes:
    sealed = xchacha20poly1305_seal(lan_key(state_secret), nonce, lan_plaintext(endpoint, port),
                                    LAN_ANNOUNCE_LABEL)
    return bytes([LAN_VERSION_MEMBER]) + nonce + sealed


def lan_open(packet: bytes, state_secrets: list) -> dict:
    """A listener, for each packet, in order. `state_secrets`: for a space
    it has open, its current state's k(S) and up to 3 before it."""
    if len(packet) != LAN_PACKET_BYTES or packet[0] != LAN_VERSION_MEMBER:
        raise SpecError("Malformed")
    nonce, sealed = packet[1:25], packet[25:]
    for index, secret in enumerate(state_secrets[:1 + OLDER_STATES_OPENING]):
        try:
            plaintext = xchacha20poly1305_open(lan_key(secret), nonce, sealed, LAN_ANNOUNCE_LABEL)
        except SpecError:
            continue
        length = int.from_bytes(plaintext[:2], "big")
        if length < 1 or 2 + length > len(plaintext) or any(plaintext[2 + length:]):
            raise SpecError("Malformed")
        value = uncbor(plaintext[2:2 + length])
        if (not isinstance(value, dict) or set(value) != {1, 2} or not is_bytes(value[1], 32)
                or not _uint(value[2]) or not 1 <= value[2] <= 65535):
            raise SpecError("Malformed")
        return {"state": index, "endpoint": value[1], "port": value[2]}
    raise SpecError("NotForMe")


def nearby_name(text: str) -> str:
    kept = "".join(c for c in text if unicodedata.category(c) != "Cc"
                   and ord(c) not in BIDI_CONTROLS).strip()
    kept = kept[:NEARBY_NAME_CHARACTERS].strip()
    return kept or NEARBY_FALLBACK


def nearby_announce(endpoint: bytes, port: int, name: str) -> bytes:
    return bytes([LAN_VERSION_NEARBY]) + cbor({1: endpoint, 2: port, 3: nearby_name(name)})


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def encode_ticket(kind: int, endpoint: bytes, relays: list, addresses: list) -> str:
    body = {1: 1, 2: kind, 3: endpoint}
    if relays:
        body[4] = relays
    if addresses:
        body[5] = addresses
    raw = cbor(body)
    if len(raw) > TICKET_MAX_BYTES:
        raise SpecError("TooLarge")
    return TICKET_PREFIX + _b64(raw)


def read_ticket(text: str) -> dict:
    """A ticket's reader: Malformed for another prefix, padding, an encoding
    that is not canonical, an unknown key, a relay array that is empty, too
    long or not all https; InvalidKey for an endpoint key crypto.md
    refuses."""
    if not text.startswith(TICKET_PREFIX):
        raise SpecError("Malformed")
    encoded = text[len(TICKET_PREFIX):]
    if "=" in encoded or len(encoded) > 4 * TICKET_MAX_BYTES // 3 + 4:
        raise SpecError("Malformed")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except ValueError as error:
        raise SpecError("Malformed") from error
    if _b64(raw) != encoded or len(raw) > TICKET_MAX_BYTES:
        raise SpecError("Malformed")
    value = uncbor(raw)
    if not isinstance(value, dict) or value.get(1) != 1 or not set(value) <= {1, 2, 3, 4, 5}:
        raise SpecError("Malformed")
    if value.get(2) not in (1, 2, 3) or not is_bytes(value.get(3), 32):
        raise SpecError("Malformed")
    if 4 in value:
        relays = value[4]
        if (not isinstance(relays, list) or not 1 <= len(relays) <= 4
                or not all(isinstance(r, str) and r.startswith("https://") for r in relays)):
            raise SpecError("Malformed")
    if 5 in value:
        addresses = value[5]
        if (not isinstance(addresses, list) or not 1 <= len(addresses) <= 16
                or not all(is_bytes(a) and len(a) in (6, 18) for a in addresses)):
            raise SpecError("Malformed")
    if not ed25519_valid(value[3]):
        raise SpecError("InvalidKey")
    return {"kind": value[2], "endpoint": value[3], "relays": value.get(4, []),
            "addresses": value.get(5, [])}


def read_ticket_cbor(raw: bytes) -> dict:
    """A ticket's CBOR, by the checks of read_ticket that follow the
    base64url decoding."""
    if not is_bytes(raw) or len(raw) > TICKET_MAX_BYTES:
        raise SpecError("Malformed")
    return read_ticket(TICKET_PREFIX + _b64(raw))


def ticket_cbor(kind: int, endpoint: bytes, relays: list, addresses: list) -> bytes:
    text = encode_ticket(kind, endpoint, relays, addresses)[len(TICKET_PREFIX):]
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---------------------------------------------------------------------------
# Member addresses (transport.md, "The iroh binding", member addresses).


def encode_addresses(attach: int, entries: list) -> bytes:
    return cbor({0: ADDRESSES, 1: attach, 2: [[key, ticket] for key, ticket in entries]})


def read_addresses(payload: bytes, connection: str = "member") -> dict:
    """Steps 1 and 2 at the receiver: the message, and each ticket."""
    value = read_message(payload, "control", connection)
    if value is None or value[0] != ADDRESSES or set(value) != {0, 1, 2}:
        raise SpecError("Malformed")
    if not _uint(value[1]) or not isinstance(value[2], list):
        raise SpecError("Malformed")
    entries = value[2]
    if len(entries) > MAX_ADDRESS_ENTRIES:
        raise SpecError("Malformed")
    seen = set()
    for entry in entries:
        if (not isinstance(entry, list) or len(entry) != 2 or not is_bytes(entry[0], 32)
                or not is_bytes(entry[1]) or entry[0] in seen):
            raise SpecError("Malformed")
        seen.add(entry[0])
    out = []
    for key, raw in entries:
        ticket = read_ticket_cbor(raw)
        if ticket["kind"] != 1:
            raise SpecError("Malformed")
        out.append((key, ticket))
    return {"attach": value[1], "entries": out}


def address_outcome(member: bytes, ticket: dict, receiver: dict) -> dict:
    """Steps 4 to 7 for one entry. `receiver` holds its device ID, the
    sender's, its own member endpoint key, the device IDs that reach the
    space in its view, and those it holds an admitted attach of the space
    with. The tickets it keeps play no part: a learned ticket is never
    written to the endpoint table."""
    if (member in (receiver["device"], receiver["sender"])
            or member not in receiver["view"]):
        return {"outcome": "skipped", "step": 4}
    if ticket["endpoint"] == receiver["endpoint"]:
        return {"outcome": "skipped", "step": 5}
    if member in receiver["attached"]:
        return {"outcome": "skipped", "step": 6}
    return {"outcome": "dialed"}


def receive_addresses(payload: bytes, receiver: dict, admitted: bool) -> list | None:
    """The receiver's procedure: None when step 3 drops the message."""
    read = read_addresses(payload)
    if not admitted:
        return None
    return [address_outcome(key, ticket, receiver) for key, ticket in read["entries"]]


# The local-network ranges ("Sending to a guest").
LOCAL_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8",
    "fc00::/7", "fe80::/10", "::1/128")]


def is_local_network(address: bytes) -> bool:
    """A ticket's direct address, IP then port: whether its IP is in a
    local-network range of its own version. An IPv4-mapped IPv6 address is
    an IPv6 address, in none of them."""
    ip = ipaddress.ip_address(address[:-2])
    return any(ip in network for network in LOCAL_NETWORKS if network.version == ip.version)


def guest_entries(entries: list) -> list:
    """What a sender lists to a guest from the entries it lists to a full
    member: each ticket with only its local-network addresses and no relay,
    and no entry left with no address."""
    out = []
    for key, raw in entries:
        ticket = read_ticket_cbor(raw)
        local = [a for a in ticket["addresses"] if is_local_network(a)]
        if local:
            out.append((key, ticket_cbor(ticket["kind"], ticket["endpoint"], [], local)))
    return out


# ---------------------------------------------------------------------------
# Mailboxes (transport.md, "Mailboxes", both sections).


def mailbox_address(kind: int, name: bytes) -> bytes:
    return sha256(MAILBOX_LABEL + bytes([kind]) + field(name))


def item_info(recipient: bytes) -> bytes:
    """info = "frasil/mailbox-item/v1" || u16be(0x647a) || the recipient's
    device ID."""
    assert len(recipient) == 32
    return wraps.wrap_info(MAILBOX_ITEM_LABEL, recipient)


def item_plaintext(content: str, body: bytes) -> bytes:
    return cbor({1: content, 2: body})


def seal_item(content: str, body: bytes, recipient: bytes, recipient_xwing: bytes,
              eseed: bytes) -> dict:
    """The item seal: crypto.md's X-Wing wrap, for a device mailbox item
    whose own document defines no seal. One recipient per item."""
    return wraps.seal_wrap(recipient_xwing, item_info(recipient),
                           item_plaintext(content, body), eseed)


def open_item(item: bytes, recipient: bytes, xwing_seed: bytes,
              implemented=CORE_CONTENT) -> dict:
    """Opening an item, in order; `recipient` is the device's own device ID
    and `implemented` the content names it implements. Step 4, the
    body's own checks, is the content name's document's."""
    plaintext = wraps.open_wrap(item, xwing_seed, item_info(recipient),
                                (wraps.MIN_BYTES, MAILBOX_ITEM_BYTES))
    value = uncbor(plaintext)
    if (not isinstance(value, dict) or set(value) != {1, 2} or not isinstance(value[1], str)
            or not 1 <= len(value[1].encode()) <= CONTENT_NAME_BYTES
            or not is_bytes(value[2])):
        raise SpecError("Malformed")
    if value[1] not in implemented:
        raise SpecError("UnknownContent")
    return {"content": value[1], "body": value[2]}


def read_mailbox_put(payload: bytes, extensions=()) -> dict:
    """A MailboxPut's shape at a peer: kinds 1 to 3 have exactly keys 0 to 3
    and 6; kind 4 is ext-invite-links.md's, and a peer that does not
    implement it refuses it as Malformed; so is key 7, a deposit token of
    kind 3, ext-deposit-tokens.md's, which reads it in its own order."""
    v = read_message(payload, "control", "peer", extensions)
    if v is None or v[0] != MAILBOX_PUT or not _uint(v.get(6)):
        raise SpecError("Malformed")
    if v[6] == MAILBOX_DROP and "ext-invite-links" in extensions:
        return v
    if v[6] == MAILBOX_DEVICE and 7 in v and "ext-deposit-tokens" in extensions:
        return v
    if (v[6] not in (MAILBOX_EXCHANGE, MAILBOX_PERSON, MAILBOX_DEVICE)
            or set(v) != {0, 1, 2, 3, 6} or not is_bytes(v[2], 32) or not is_bytes(v[3])):
        raise SpecError("Malformed")
    if len(v[3]) > MAILBOX_ITEM_BYTES:
        raise SpecError("TooLarge")
    return v


class DeviceMailbox:
    """A device mailbox at a peer: at most 64 items and 4 MiB; a deposit
    past either evicts the oldest items first."""

    def __init__(self):
        self.items: list = []

    def put(self, item_id: bytes, item: bytes) -> list:
        """Deposit, then evict the oldest items past the cap. Returns the
        IDs evicted."""
        if len(item) > MAILBOX_ITEM_BYTES:
            raise SpecError("TooLarge")
        self.items.append((item_id, item))
        evicted = []
        while (len(self.items) > DEVICE_MAILBOX_ITEMS
               or sum(len(i) for _, i in self.items) > DEVICE_MAILBOX_BYTES):
            evicted.append(self.items.pop(0)[0])
        return evicted


class PeerMailboxes:
    """A peer's device mailboxes under its caps (transport.md, "Mailboxes",
    "The peer's caps"): each mailbox's own cap, and what all of them hold
    together. Items are (ID, bytes), IDs in deposit order. A deposit past
    its mailbox's cap evicts that mailbox's oldest items; one past the
    peer's cap then evicts, oldest first, items of mailboxes that are not
    claimed, unless its own is not claimed, and is refused Busy if room is
    still lacking. A refused deposit changes nothing."""

    def __init__(self, cap_items: int, cap_bytes: int):
        self.cap = (cap_items, cap_bytes)
        self.boxes: dict[bytes, dict] = {}
        self.next_id = 1

    def box(self, address: bytes, claimed: bool = False) -> dict:
        return self.boxes.setdefault(address, {"claimed": claimed, "items": []})

    def describe(self) -> list:
        return [{"address": h(a), "claimed": b["claimed"],
                 "items": [[i, n] for i, n in b["items"]]}
                for a, b in sorted(self.boxes.items())]

    def deposit(self, address: bytes, size: int) -> dict:
        if size > MAILBOX_ITEM_BYTES:
            return {"verdict": "TooLarge", "evicted": []}
        own = self.boxes.get(address, {"claimed": False, "items": []})
        mine = list(own["items"])
        evicted = []
        while mine and (len(mine) + 1 > DEVICE_MAILBOX_ITEMS
                        or sum(n for _, n in mine) + size > DEVICE_MAILBOX_BYTES):
            evicted.append(mine.pop(0)[0])
        others = [(i, n, a) for a, b in self.boxes.items() if a != address
                  for i, n in b["items"]]
        count = len(mine) + len(others) + 1
        total = sum(n for _, n in mine) + sum(n for _, n, _ in others) + size
        if count > self.cap[0] or total > self.cap[1]:
            if not own["claimed"]:
                return {"verdict": "Busy", "evicted": []}
            gone = set()
            for i, n, a in sorted(others):
                if count <= self.cap[0] and total <= self.cap[1]:
                    break
                if not self.boxes[a]["claimed"]:
                    gone.add(i)
                    evicted.append(i)
                    count, total = count - 1, total - n
            if count > self.cap[0] or total > self.cap[1]:
                return {"verdict": "Busy", "evicted": []}
            for b in self.boxes.values():
                b["items"] = [(i, n) for i, n in b["items"] if i not in gone]
        item_id = self.next_id
        self.next_id += 1
        self.box(address)["items"] = mine + [(item_id, size)]
        return {"verdict": "accepted", "id": item_id, "evicted": sorted(evicted)}


def mailbox_claimed(collections: list, now: int, retention: int) -> bool:
    """transport.md, "Claimed device mailboxes": claimed from a collection
    that passes its checks until `mailbox_retention` passes on the peer's
    timeline with no further collection. Readings are the peer's timeline."""
    seen = [c for c in collections if c <= now]
    return bool(seen) and now - max(seen) < retention


def item_kept(deposited: int, collections: list, now: int, retention: int,
              uncollected: int) -> bool:
    """Whether a device-mailbox item is still kept at `now`: one received
    while its mailbox was not claimed goes `uncollected_retention` after its
    deposit, unless the mailbox is claimed by then; otherwise it is kept for
    `mailbox_retention` from its deposit."""
    claimed_by_then = mailbox_claimed(collections, deposited, retention) or any(
        deposited <= c < deposited + uncollected for c in collections)
    return now - deposited < (retention if claimed_by_then else uncollected)


def collect_input(binding: bytes, address: bytes) -> bytes:
    """What a device signs, with its Ed25519 identity key, to collect its
    own mailbox."""
    return MAILBOX_COLLECT_LABEL + binding + address


def encode_mailbox_get(request: int, address: bytes, signer: bytes,
                       signature: bytes) -> bytes:
    """Key 4 is the device's `ed || kc`."""
    return cbor({0: MAILBOX_GET, 1: request, 2: address, 4: signer, 5: signature,
                 6: MAILBOX_DEVICE})


def check_collect(address: bytes, signer: bytes, signature: bytes, binding: bytes) -> None:
    """Collecting a device mailbox: the peer's checks, in order. The address
    hashes the device ID of `signer`'s ed and kc."""
    if not is_bytes(address, 32) or not is_bytes(signer, 64) or not is_bytes(signature, 64):
        raise SpecError("Malformed")
    ed, _, device_id = hs.split_signer(signer)
    if not ed25519_valid(ed):
        raise SpecError("InvalidKey")
    if mailbox_address(MAILBOX_DEVICE, device_id) != address:
        raise SpecError("WrongMailbox")
    if not ed25519_verify_strict(ed, collect_input(binding, address), signature):
        raise SpecError("BadSignature")


# ---------------------------------------------------------------------------
# Vectors: fixtures.

ROT = {n: example(f"transport/rotation {n}") for n in "ABCD"}
ROTATION_KEY = {n: example(f"transport/rotation key {n}") for n in "ABCD"}
SPACE = example("transport/space")
OTHER_SPACE = example("transport/other space")
OTHER_SECRET = example("transport/other space content key")
CHANNEL = example("transport/exporter, connection 1")
CHANNEL_2 = example("transport/exporter, connection 2")
DEVICES = {n: example(f"transport/device {n}") for n in ("dialer", "listener", "mallory")}
ENDPOINTS = {n: example(f"transport/endpoint {n}") for n in ("dialer", "listener")}
NONCE_PEER = example("transport/peer nonce")
NONCE_CLIENT = example("transport/client nonce")
XWING_SEEDS = {n: example(f"transport/{n} x-wing seed") for n in ("listener", "dialer")}
PEER_LIMITS = {1: SYNC_CAP, 2: 65_536, 3: MAILBOX_ITEM_BYTES, 4: OBJECT_CHUNK_BYTES}


def signer(name: str) -> hs.Signer:
    """A device's keys: its identity seed, the fixture ML-DSA-65 seed, and
    its X-Wing seed, the fixture derivation where XWING_SEEDS names none."""
    seed = DEVICES[name]
    return hs.Signer(name, seed, hs.device_mldsa_seed_fixture(seed),
                     XWING_SEEDS.get(name) or hs.device_hybrid_seed_fixture(seed))


def device(name: str) -> bytes:
    """The device's device ID."""
    return signer(name).device_id


def ed_kc(name: str) -> bytes:
    """The device's `ed || kc`, as Identify and MailboxGet carry it."""
    return signer(name).signer_bytes


def endpoint(name: str) -> bytes:
    return ed25519_public(ENDPOINTS[name])


def _state(*names: str) -> tuple:
    return keygraph.canonical(ROT[n] for n in names)


def _secret(state: tuple) -> bytes:
    by_id = {ROT[n]: ROTATION_KEY[n] for n in "ABCD"}
    return keygraph.content_key(SPACE, state, lambda r: by_id[r])


def _label(state: tuple) -> str:
    names = {ROT[n]: n for n in "ABCD"}
    return "{" + ",".join(sorted(names[r] for r in state)) + "}"


def _filler(name: str, index: int) -> bytes:
    return example(f"transport/filler {name} {index}")


def _make_offer(states: list, attach: int, nonce: bytes, channel: bytes, filler: str):
    tags, offered = [], []
    for state in states:
        tags.append(offer_tag(member_key(_secret(state)), channel, attach, nonce))
        offered.append((state, _secret(state)))
    for i in range(len(tags), OFFER_TAGS):
        tags.append(_filler(filler, i))
        offered.append(None)
    return encode_offer(attach, nonce, tags), tags, offered


def _candidates(states: list, other: bool = True) -> list:
    out = [(SPACE, s, _secret(s)) for s in states]
    if other:
        out = [(OTHER_SPACE, (example("transport/other rotation"),), OTHER_SECRET)] + out
    return out


def _xwing(name: str) -> bytes:
    return signer(name).xwing_public


def _eseed(name: str) -> bytes:
    return example(f"transport/{name}, encapsulation 1") + example(
        f"transport/{name}, encapsulation 2")


# ---------------------------------------------------------------------------
# Vectors: families.


def member_handshake_vectors() -> dict:
    """One whole handshake: the dialer's current state merges C and D; the
    listener has not seen D and holds {C} and earlier."""
    nonce_d = example("transport/nonce dialer")
    nonce_l = example("transport/nonce listener")
    e_d, e_l = endpoint("dialer"), endpoint("listener")
    held_d = {_state("C"), _state("D"), _state("C", "D")}
    states = offered_states(_state("C", "D"), held_d, [_state("C"), _state("B"), _state("A")])
    offer, tags, offered = _make_offer(states, 0, nonce_d, CHANNEL, "dialer")
    match = respond(offer, CHANNEL, _candidates([_state("C"), _state("B"), _state("A")]))
    core = encode_answer_core(0, nonce_l, match["index"])
    th = transcript(CHANNEL, e_d, e_l, offer, core)
    proof = answer_proof(member_key(match["secret"]), th)
    answer = encode_answer(0, nonce_l, match["index"], proof)
    got = verify_answer(answer, {"attach": 0, "channel": CHANNEL, "endpoint_i": e_d,
                                 "endpoint_r": e_l, "offer": offer, "offered": offered})
    assert got["state"] == match["state"] == _state("C")
    identify_ = {}
    for name, role in (("dialer", ROLE_DIALER), ("listener", ROLE_LISTENER)):
        signed = identify_input(th, role, ed_kc(name))
        signature = ed25519_sign_deterministic(DEVICES[name], signed)
        message = encode_identify(ed_kc(name), signature)
        assert verify_identify(message, th, role) == device(name)
        identify_[name] = {"role": role, "ed_kc": h(ed_kc(name)), "device_id": h(device(name)),
                           "signed": h(signed), "signature": h(signature), "message": h(message),
                           "frame": h(u32be(len(message)) + message)}
    second_nonce = example("transport/nonce dialer, attach 2")
    other_offer, other_tags, _ = _make_offer([_state("C")], 2, second_nonce, CHANNEL, "attach 2")
    assert respond(other_offer, CHANNEL, _candidates([_state("C")]))["state"] == _state("C")
    all_states = (_state("A"), _state("B"), _state("C"), _state("D"), _state("C", "D"))
    return {
        "channel": h(CHANNEL),
        "endpoint_keys": {"dialer": {"seed": h(ENDPOINTS["dialer"]), "public": h(e_d)},
                          "listener": {"seed": h(ENDPOINTS["listener"]), "public": h(e_l)}},
        "devices": {n: {"seed": h(DEVICES[n]), "ed25519": h(signer(n).ed_public),
                        "mldsa": h(signer(n).mldsa_public), "xwing": h(signer(n).xwing_public),
                        "kc": h(signer(n).kc), "device_id": h(device(n))} for n in DEVICES},
        "space": h(SPACE),
        "rotations": {n: h(ROT[n]) for n in "ABCD"},
        "rotation_keys": {n: h(ROTATION_KEY[n]) for n in "ABCD"},
        "content_keys": {_label(s): h(_secret(s)) for s in all_states},
        "member_keys": {_label(s): h(member_key(_secret(s))) for s in all_states},
        "offer": {"attach": 0, "nonce": h(nonce_d),
                  "offered_states": [_label(s) for s in states],
                  "tags": [h(t) for t in tags], "message": h(offer),
                  "frame": h(u32be(len(offer)) + offer)},
        "listener_candidates": [_label(s) for s in (_state("C"), _state("B"), _state("A"))],
        "match": {"index": match["index"], "state": _label(match["state"])},
        "answer": {"nonce": h(nonce_l), "core": h(core), "transcript": h(th),
                   "proof": h(proof), "message": h(answer),
                   "frame": h(u32be(len(answer)) + answer)},
        "identify": identify_,
        "admit": h(frame({0: ADMIT, 1: 0})),
        "second_attach_offer": {"attach": 2, "nonce": h(second_nonce),
                                "offered_states": ["{C}"], "tags": [h(t) for t in other_tags],
                                "message": h(other_offer)},
        "other_space": {"space": h(OTHER_SPACE), "content_key": h(OTHER_SECRET)},
        "channel_2": h(CHANNEL_2),
    }


def state_choice_vectors() -> list:
    """What each side offers and holds, and the match or refusal."""
    rows = [
        ("equal states", _state("C"), {_state("C")}, [_state("B")],
         [_state("C"), _state("B")]),
        ("an initiator ahead: the responder has not seen D", _state("D"),
         {_state("D")}, [_state("C"), _state("B")], [_state("C"), _state("B"), _state("A")]),
        ("an initiator behind: it missed C and D", _state("B"), {_state("B")}, [_state("A")],
         [_state("D"), _state("C"), _state("B"), _state("A")]),
        ("a merged state: the responder holds one of its rotations alone", _state("C", "D"),
         {_state("C"), _state("D")}, [_state("C")], [_state("C"), _state("B")]),
        ("a member admitted from now on at D, and a member that has seen D",
         _state("D"), {_state("D")}, [], [_state("D"), _state("C")]),
        ("no common state: a member admitted from now on at D meets one that stopped at B",
         _state("D"), {_state("D")}, [], [_state("B"), _state("A")]),
    ]
    out = []
    for i, (description, current, held, history, responder) in enumerate(rows):
        states = offered_states(current, held, history)
        nonce = example(f"transport/state choice {i}")
        offer, tags, _ = _make_offer(states, 0, nonce, CHANNEL, f"state choice {i}")
        try:
            match = respond(offer, CHANNEL, _candidates(responder))
            result = {"match": {"index": match["index"], "state": _label(match["state"])}}
        except SpecError as error:
            result = {"refused": error.error}
        out.append({"description": description, "initiator_current": _label(current),
                    "offered_states": [_label(s) for s in states],
                    "responder_holds": [_label(s) for s in responder],
                    "nonce": h(nonce), "tags": [h(t) for t in tags], **result})
    return out


def member_refusals_vectors() -> list:
    v_nonce_d = example("transport/nonce dialer")
    v_nonce_l = example("transport/nonce listener")
    e_d, e_l = endpoint("dialer"), endpoint("listener")
    states = [_state("C", "D"), _state("C"), _state("D"), _state("B"), _state("A")]
    offer, tags, offered = _make_offer(states, 0, v_nonce_d, CHANNEL, "dialer")
    cands = _candidates([_state("C"), _state("B"), _state("A")])
    ctx = {"attach": 0, "channel": CHANNEL, "endpoint_i": e_d, "endpoint_r": e_l,
           "offer": offer, "offered": offered}
    out = []

    def add(description: str, step: str, expected: str, message: bytes, function):
        got = expect_class(function, message)
        assert got == expected, (description, got, expected)
        out.append({"description": description, "at": step, "message": h(message),
                    "error": expected})

    def at_responder(channel=CHANNEL, candidates=cands):
        return lambda m: respond(m, channel, candidates)

    add("an offer of 15 tags", "offer", "Malformed",
        encode_offer(0, v_nonce_d, tags[:15]), at_responder())
    add("an offer of 17 tags", "offer", "Malformed",
        encode_offer(0, v_nonce_d, tags + [tags[0]]), at_responder())
    add("an offer with a 31-byte nonce", "offer", "Malformed",
        encode_offer(0, v_nonce_d[:31], tags), at_responder())
    add("an offer with an extra key", "offer", "Malformed",
        cbor({0: OFFER, 1: 0, 2: v_nonce_d, 3: tags, 4: REVISION, 5: 1}), at_responder())
    add("an offer without its revision", "offer", "Malformed",
        cbor({0: OFFER, 1: 0, 2: v_nonce_d, 3: tags}), at_responder())
    add("an offer of another revision", "offer", "RevisionMismatch",
        encode_offer(0, v_nonce_d, tags, REVISION + 1), at_responder())
    add("an offer replayed on another connection", "offer", "NoCommonState", offer,
        at_responder(channel=CHANNEL_2))
    add("an offer moved to another attach", "offer", "NoCommonState",
        encode_offer(2, v_nonce_d, tags), at_responder())
    add("an offer given another nonce", "offer", "NoCommonState",
        encode_offer(0, example("transport/another nonce"), tags), at_responder())
    add("an offer from a non-member: sixteen random tags", "offer", "NoCommonState",
        encode_offer(0, v_nonce_d, [_filler("stranger", i) for i in range(16)]), at_responder())
    match = respond(offer, CHANNEL, cands)
    secret = match["secret"]

    def answer_with(index=match["index"], attach=0, nonce=v_nonce_l, key=secret,
                    endpoints=(e_d, e_l), channel=CHANNEL):
        core = encode_answer_core(attach, nonce, index)
        th = transcript(channel, endpoints[0], endpoints[1], offer, core)
        return encode_answer(attach, nonce, index, answer_proof(member_key(key), th))

    def at_initiator(m):
        return verify_answer(m, ctx)

    add("an answer whose proof binds the endpoint keys swapped", "answer", "BadProof",
        answer_with(endpoints=(e_l, e_d)), at_initiator)
    add("an answer whose proof binds another connection's channel", "answer", "BadProof",
        answer_with(channel=CHANNEL_2), at_initiator)
    add("an answer proved under another state than the one its index names", "answer",
        "BadProof", answer_with(key=_secret(_state("B"))), at_initiator)
    add("an answer whose index names a filler", "answer", "BadProof",
        answer_with(index=OFFER_TAGS - 1), at_initiator)
    add("an answer with index 16", "answer", "Malformed", answer_with(index=16), at_initiator)
    add("an answer for another attach", "answer", "Malformed", answer_with(attach=2),
        at_initiator)
    add("the initiator's own offer reflected as an answer", "answer", "Malformed", offer,
        at_initiator)
    add("a refusal: no common state", "answer", "NoCommonState",
        cbor({0: REFUSE, 1: 0, 2: 4}), at_initiator)
    add("a refusal: another revision", "answer", "RevisionMismatch",
        cbor({0: REFUSE, 1: 0, 2: 16}), at_initiator)
    core = encode_answer_core(0, v_nonce_l, match["index"])
    th = transcript(CHANNEL, e_d, e_l, offer, core)
    th_other = transcript(CHANNEL_2, e_d, e_l, offer, core)

    def identify_with(name="dialer", role=ROLE_DIALER, transcript_=th, claimed=None,
                      signed_kc=None):
        """`claimed` is the `ed || kc` the message carries; `signed_kc`
        another kc than the one it carries, over which the device signs."""
        key = claimed or ed_kc(name)
        over = key[:32] + signed_kc if signed_kc else key
        signature = ed25519_sign_deterministic(DEVICES[name], identify_input(transcript_, role,
                                                                             over))
        return encode_identify(key, signature)

    def at_listener(m):
        return verify_identify(m, th, ROLE_DIALER)

    add("an identify signed over another connection's transcript", "identify", "BadSignature",
        identify_with(transcript_=th_other), at_listener)
    add("the listener's own identify reflected to it", "identify", "BadSignature",
        identify_with(name="listener", role=ROLE_LISTENER), at_listener)
    add("an identify naming a key that did not sign it", "identify", "BadSignature",
        identify_with(name="mallory", claimed=ed_kc("dialer")), at_listener)
    small = point_encode(small_order_points()[1])
    add("an identify naming a small-order key", "identify", "InvalidKey",
        encode_identify(small + signer("dialer").kc, bytes(64)), at_listener)
    add("an identify whose kc is not the one signed", "identify", "BadSignature",
        identify_with(signed_kc=signer("mallory").kc), at_listener)
    add("an identify with a 63-byte signature", "identify", "Malformed",
        encode_identify(ed_kc("dialer"), bytes(63)), at_listener)
    return out


def roster_check(standing: dict) -> tuple:
    """transport.md, "The roster check": the outcome for the device's
    standing in the verifier's own current view."""
    kind = standing["standing"]
    if kind == "reaches":
        return ("Admit", None)
    if kind == "forked":
        return ("Detach", "forked")
    if kind == "ended":
        return ("Detach", "membership_ended")
    assert kind in ("named nowhere", "only through a log not held")
    return ("probation", None)


def probation_outcome(start: dict, steps: list) -> tuple:
    """Probation from its start: at each step, `seconds` since it began,
    the `events` received from the device by then, and the device's
    standing; it ends at the first of the device in or out, or probation
    spent (30 seconds or 4,096 events), unknown_member."""
    assert roster_check(start)[0] == "probation"
    for step in steps:
        outcome = roster_check(step)
        if outcome[0] != "probation":
            return ("probation, then " + outcome[0], outcome[1])
        if step["seconds"] >= PROBATION_SECONDS or step["events"] >= PROBATION_EVENTS:
            return ("probation, then Detach", "unknown_member")
    return ("probation", None)


def roster_check_vectors() -> list:
    """transport.md, "The roster check": the other device in the verifier's
    own current view, its standing there, and the outcome for the attach."""
    reaches = {"standing": "reaches", "path": "device grant"}
    nowhere = {"standing": "named nowhere"}
    unheld = {"standing": "only through a log not held"}
    removed = {"standing": "ended", "ended": "removed"}
    rows = [
        ("reaches the space through a device grant", reaches),
        ("reaches the space through a device grant with session set: a guest",
         {"standing": "reaches", "path": "guest"}),
        ("reaches the space through a person grant whose list, as held, vouches for the device",
         {"standing": "reaches", "path": "person grant"}),
        ("reaches the space through a granted space",
         {"standing": "reaches", "path": "granted space"}),
        ("has a fork point in the space's log", {"standing": "forked"}),
        ("was named and is removed", removed),
        ("was named and is revoked from its list", {"standing": "ended", "ended": "revoked"}),
        ("was named and is gone from a granted space",
         {"standing": "ended", "ended": "gone from a granted space"}),
        ("is named nowhere: its grant is in an event the verifier lacks, which probation "
         "brings", {**nowhere, "probation": [{**nowhere, "seconds": 5, "events": 10},
                                             {**reaches, "seconds": 6, "events": 10}]}),
        ("is named nowhere, and probation is spent without its grant",
         {**nowhere, "probation": [{**nowhere, "seconds": 29, "events": 0},
                                   {**nowhere, "seconds": 30, "events": 0}]}),
        ("reaches the space only through a log the verifier does not hold, and probation is "
         "spent", {**unheld, "probation": [{**unheld, "seconds": 1, "events": PROBATION_EVENTS - 1},
                                           {**unheld, "seconds": 1, "events": PROBATION_EVENTS}]}),
        ("was removed by an event the verifier has not received", reaches),
        ("was admitted, and a later view removes it: the re-check",
         {**reaches, "recheck": removed}),
        ("the verifier learns that it was removed itself: every attach of that space",
         {**reaches, "verifier_removed": True}),
    ]
    out = []
    for description, standing in rows:
        if standing.get("verifier_removed"):
            outcome = ("Detach", "membership_ended")
        elif "recheck" in standing:
            assert roster_check(standing)[0] == "Admit"
            outcome = roster_check(standing["recheck"])
        elif "probation" in standing:
            outcome = probation_outcome(standing, standing["probation"])
        else:
            outcome = roster_check(standing)
        out.append({"device_in_view": description, "input": standing, "outcome": outcome[0],
                    **({"code": outcome[1]} if outcome[1] else {})})
    return out


def device_to_peer_vectors() -> dict:
    origin = "https://peer.example.org"
    bindings = {}
    for binding_name, channel in (("iroh", CHANNEL), ("server", server_channel(origin))):
        entry = {"channel": h(channel)}
        if binding_name == "server":
            entry["origin"] = origin
        for purpose in (PURPOSE_SPACE, PURPOSE_ADMINISTRATION):
            entry[f"purpose_{purpose}"] = h(peer_binding(channel, NONCE_PEER, NONCE_CLIENT,
                                                         purpose))
        bindings[binding_name] = entry
    binding = peer_binding(CHANNEL, NONCE_PEER, NONCE_CLIENT, PURPOSE_SPACE)
    read = keygraph.read_credential(_secret(_state("C")))
    upload = keygraph.upload_key(example("transport/upload seed C"))
    recovery = identity.recovery_keys(example("transport/recovery secret"))
    presentations = []
    for request, (name, credential, public) in enumerate((
            ("a read credential of {C}", CREDENTIAL_READ, read["public"]),
            ("an upload key of {C}", CREDENTIAL_UPLOAD, upload["public"]),
            ("a fetch key of a recovery key", CREDENTIAL_FETCH, recovery["fetch_key"])),
            start=1):
        presentations.append({"description": name, "request": request,
                              "credential": credential, "public": h(public),
                              "presented": h(presented(binding, SPACE, credential, public)),
                              "present_without_proof": h(
                                  cbor({0: PRESENT, 1: request, 2: SPACE, 3: credential,
                                        4: public}))})
    register = encode_register_recovery_entry(4, SPACE, recovery["fetch_key"])
    hello = encode_hello(NONCE_CLIENT, PURPOSE_SPACE)
    peer_hello = encode_peer_hello(NONCE_PEER, [1, 2, 3], PEER_LIMITS)
    sessions = []
    for description, purpose, presents, bearer, *rest in (
            ("space traffic: read credentials, an upload key and a fetch key for two spaces",
             PURPOSE_SPACE, [{"credential": 1}, {"credential": 2}, {"credential": 4}], False),
            ("space traffic carrying an account's bearer token", PURPOSE_SPACE,
             [{"credential": 1}], True),
            ("space traffic presenting an administrator pseudonym", PURPOSE_SPACE,
             [{"credential": 1}, {"credential": 3}], False),
            ("administration: one pseudonym for one space", PURPOSE_ADMINISTRATION,
             [{"credential": 3}], False),
            ("administration with a bearer token", PURPOSE_ADMINISTRATION,
             [{"credential": 3}], True),
            ("administration for two spaces", PURPOSE_ADMINISTRATION,
             [{"credential": 3}, {"credential": 3}], False),
            ("administration presenting a read credential", PURPOSE_ADMINISTRATION,
             [{"credential": 1}], False),
            ("space traffic: a type 21 request, a Merge, a RegisterRecoveryEntry and a "
             "MailboxPut", PURPOSE_SPACE, [{"credential": 2}], False,
             ("library_attach", "merge", "register_recovery_entry", "mailbox")),
            ("administration carrying a RegisterRecoveryEntry", PURPOSE_ADMINISTRATION,
             [{"credential": 3}], False, ("register_recovery_entry",)),
            ("administration carrying a MailboxPut", PURPOSE_ADMINISTRATION,
             [{"credential": 3}], False, ("mailbox",))):
        sends = rest[0] if rest else ()
        sessions.append({"description": description, "purpose": purpose,
                         "credentials": [p["credential"] for p in presents], "bearer": bearer,
                         "sends": list(sends),
                         "outcome": peer_session_check(purpose, presents, bearer, sends)})
    awaiting_ids = sorted([example("transport/an erase request"),
                           example("transport/a snapshot unit")])
    awaiting = cbor({0: AWAITING, 1: SPACE, 2: awaiting_ids})
    hellos = []
    for description, payload, kind in (
            ("a Hello of this protocol and revision", hello, HELLO),
            ("a Hello of another protocol",
             cbor({0: HELLO, 1: 2, 2: NONCE_CLIENT, 3: PURPOSE_SPACE, 4: REVISION}), HELLO),
            ("a Hello of another revision",
             encode_hello(NONCE_CLIENT, PURPOSE_SPACE, REVISION + 1), HELLO),
            ("a Hello without its revision",
             cbor({0: HELLO, 1: PROTOCOL, 2: NONCE_CLIENT, 3: PURPOSE_SPACE}), HELLO),
            ("a PeerHello of another revision",
             encode_peer_hello(NONCE_PEER, [1], {1: SYNC_CAP}, REVISION + 1), PEER_HELLO),
            ("a PeerHello of another protocol",
             cbor({0: PEER_HELLO, 1: 2, 2: NONCE_PEER, 3: [1], 4: {}, 5: REVISION}),
             PEER_HELLO)):
        try:
            read_hello(payload, kind)
            result = "accepted"
        except SpecError as error:
            result = error.error
        hellos.append({"description": description, "message": h(payload), "result": result})
    stored = example("transport/a stored object's bytes, opaque here") * 4
    locator = object_locator(example("transport/an object ID"), stored)
    return {
        "nonce_peer": h(NONCE_PEER), "nonce_client": h(NONCE_CLIENT), "space": h(SPACE),
        "bindings": bindings,
        "peer_hello": h(peer_hello), "hello": h(hello),
        "presentations": presentations,
        "credential_seeds": {"read_credential_state": "{C}",
                             "upload_seed": h(example("transport/upload seed C")),
                             "recovery_secret": h(example("transport/recovery secret"))},
        "grants": [{"credential": 1, "entry": "live", "rights": [1, 2]},
                   {"credential": 1, "entry": "retired", "rights": [6]},
                   {"credential": 2, "entry": "live", "rights": [3, 4]},
                   {"credential": 3, "entry": "", "rights": [5]},
                   {"credential": 4, "entry": "live", "rights": [6]}],
        "rights": {str(code): name for code, name in RIGHTS.items()},
        "register_recovery_entry": {"request": 4, "space": h(SPACE),
                                    "fetch_key": h(recovery["fetch_key"]),
                                    "message": h(register),
                                    "frame": h(u32be(len(register)) + register)},
        "awaiting": h(awaiting),
        "awaiting_ids": [h(x) for x in awaiting_ids],
        "sessions": sessions,
        "hellos": hellos,
        "object_route": {"object_id": h(locator[:32]), "stored_object": h(stored),
                         "digest": h(locator[32:]), "locator": h(locator),
                         "chunk_path": chunk_path(SPACE, locator, 3)},
    }


def _reader_list_events() -> tuple[bytes, list]:
    """A read-only person's device-list events: its list's genesis and the
    add of a second device."""
    person = identity.Person("reader phone", prefix="transport/reader")
    added = person.add("reader phone", "reader laptop", identity.DEVICE)
    return person.id, [person.log.events[person.genesis].signed,
                       person.log.events[added].signed]


def framing_vectors() -> dict:
    _, list_events = _reader_list_events()
    list_events_message = cbor({0: 17, 1: SPACE, 2: list_events[1:]})  # units.md's ListEvents
    examples = []
    for description, message, connection in (
            ("an Admit", {0: ADMIT, 1: 0}, "member"),
            ("a Detach: membership ended", {0: DETACH, 1: 3, 2: 7}, "member"),
            ("a sync stream's Open", {0: OPEN, 1: STREAM_KIND_CODES["sync"], 2: 0}, "member"),
            ("an Ephemeral on a member connection, attach 0",
             {0: EPHEMERAL, 1: 0, 2: bytes.fromhex("a50101")}, "member"),
            ("an Ephemeral relayed by a peer, with its origin",
             {0: EPHEMERAL, 1: SPACE, 2: bytes.fromhex("a50101"),
              3: bytes.fromhex("0102030405060708")}, "peer"),
            ("a Sync for a space, on a device-to-peer connection",
             {0: SYNC, 1: SPACE, 2: bytes.fromhex("a10101")}, "peer"),
            ("a Sync carrying units.md's ListEvents, on a member connection, attach 0",
             {0: SYNC, 1: 0, 2: list_events_message}, "member"),
            ("an ErasureLate from a peer, on an administration connection",
             {0: ERASURE_LATE, 1: SPACE, 2: example("transport/erasure"),
              3: b"the cut's signed envelope", 4: example("transport/erasure-checkpoint"), 5: 0},
             "peer")):
        stream = {EPHEMERAL: "ephemeral", ADMIT: "control", DETACH: "control",
                  ERASURE_LATE: "control"}.get(
            message[0], "sync")
        data = frame(message)
        got, rest = read_frame(data, stream, connection)
        assert got == message and rest == b""
        examples.append({"description": description, "stream": stream,
                         "connection": connection, "frame": h(data)})
    caps = []
    for stream, cap in STREAM_CAPS.items():
        for length in (cap, cap + 1):
            prefix = u32be(length)
            result = expect_class(read_frame, prefix, stream)
            caps.append({"stream": stream, "prefix": h(prefix), "length": length,
                         "result": "TooLarge" if result == "TooLarge" else "read on"})
    refused = []
    for description, stream, connection, payload, error in (
            ("an unknown message type, 90", "control", "peer", cbor({0: 90}),
             "UnknownMessage"),
            ("a LibraryAttach at a receiver that does not implement ext-libraries",
             "control", "peer", cbor({0: LIBRARY_ATTACH, 1: 1, 2: SPACE, 3: 1, 4: b""}),
             "UnknownMessage"),
            ("a message with no type", "control", "peer", cbor({1: 1}), "Malformed"),
            ("a Sync on the control stream", "control", "peer", cbor({0: SYNC, 1: 0, 2: b""}),
             "Malformed"),
            ("an Offer on the ephemeral stream", "ephemeral", "member", cbor({0: OFFER}),
             "Malformed"),
            ("an Identify over its 4,096-byte cap", "control", "member",
             cbor({0: IDENTIFY, 1: bytes(32), 2: bytes(4_060)}), "TooLarge"),
            ("a payload that is not deterministic CBOR", "control", "peer",
             bytes.fromhex("a2010000"), "Malformed"),
            ("a Gone on a member connection", "control", "member",
             cbor({0: GONE, 1: 0, 2: bytes(8)}), "Malformed"),
            ("an Ephemeral with an origin on a member connection", "ephemeral", "member",
             cbor({0: EPHEMERAL, 1: 0, 2: bytes.fromhex("a50101"), 3: bytes(8)}), "Malformed"),
            ("an ErasureLate with a standing of 3", "control", "peer",
             cbor({0: ERASURE_LATE, 1: SPACE, 2: bytes(32), 3: b"c", 4: bytes(32), 5: 3}),
             "Malformed"),
            ("an ErasureLate with a key it does not list", "control", "peer",
             cbor({0: ERASURE_LATE, 1: SPACE, 2: bytes(32), 3: b"c", 4: bytes(32), 5: 0, 6: 1}),
             "Malformed"),
            ("an ErasureLate on a member connection", "control", "member",
             cbor({0: ERASURE_LATE, 1: SPACE, 2: bytes(32), 3: b"c", 4: bytes(32), 5: 0}),
             "Malformed")):
        data = u32be(len(payload)) + payload
        got = expect_class(read_frame, data, stream, connection)
        assert got == error, (description, got)
        refused.append({"description": description, "stream": stream,
                        "connection": connection, "frame": h(data), "error": error})
    dropped_payload = cbor({0: 100, 1: b"an ignorable message"})
    dropped_frame = u32be(len(dropped_payload)) + dropped_payload
    assert read_frame(dropped_frame, "control")[0] is None
    return {"examples": examples, "caps": caps, "refused": refused,
            "dropped": [{"description": "an unknown type in 96 to 127, 100: dropped",
                         "stream": "control", "connection": "peer", "frame": h(dropped_frame),
                         "result": "dropped"}]}


def local_network_vectors() -> dict:
    secret_c, secret_d = _secret(_state("C")), _secret(_state("D"))
    nonce = example("transport/lan nonce")[:24]
    packet = lan_announce(secret_c, endpoint("listener"), 47_767, nonce)
    opened = lan_open(packet, [secret_d, secret_c])
    assert opened["endpoint"] == endpoint("listener") and opened["state"] == 1
    nonce_2 = example("transport/lan nonce 2")[:24]
    second = lan_announce(secret_c, endpoint("listener"), 47_767, nonce_2)
    name_in = "Sam's‮ laptop\x07 at the venue, stage left"
    nearby_endpoint = example("transport/nearby endpoint")
    nearby = nearby_announce(nearby_endpoint, 52_001, name_in)
    return {
        "lan_key": {"state": "{C}", "content_key": h(secret_c), "key": h(lan_key(secret_c))},
        "plaintext": h(lan_plaintext(endpoint("listener"), 47_767)),
        "nonce": h(nonce),
        "packet": h(packet),
        "packet_bytes": len(packet),
        "listener_tries": ["{D}", "{C}"],
        "opened_with": "{C}",
        "opened": {"endpoint_key": h(opened["endpoint"]), "port": opened["port"]},
        "second_packet": {"nonce": h(nonce_2), "packet": h(second)},
        "non_member_content_key": h(OTHER_SECRET),
        "non_member": expect_class(lan_open, packet, [OTHER_SECRET]),
        "older_state_only": expect_class(lan_open, packet, [_secret(_state("B"))]),
        "nearby_name_in": name_in,
        "nearby_name_out": nearby_name(name_in),
        "nearby_name_empty": {"in": "‮\x07 ", "out": nearby_name("‮\x07 ")},
        "nearby_endpoint": h(nearby_endpoint),
        "nearby_port": 52_001,
        "nearby_packet": h(nearby),
    }


def tickets_vectors() -> dict:
    ticket = encode_ticket(1, endpoint("listener"), ["https://relay.example.org"],
                           [bytes([192, 168, 1, 20]) + (47_767).to_bytes(2, "big")])
    read = read_ticket(ticket)
    assert read["endpoint"] == endpoint("listener")
    small = point_encode(small_order_points()[1])
    e = endpoint("listener")
    encoded = ticket[len(TICKET_PREFIX):]
    refused = {
        "padding characters": ticket + "==",
        "an unknown key, 6": TICKET_PREFIX + _b64(cbor({1: 1, 2: 1, 3: e, 6: bytes(32)})),
        "an empty relay array": TICKET_PREFIX + _b64(cbor({1: 1, 2: 1, 3: e, 4: []})),
        "a relay over plain HTTP": TICKET_PREFIX + _b64(
            cbor({1: 1, 2: 1, 3: e, 4: ["http://relay.example.org"]})),
        "a small-order endpoint key": TICKET_PREFIX + _b64(cbor({1: 1, 2: 1, 3: small})),
    }
    return {"ticket": ticket,
            "cbor": h(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))),
            "kind": 1, "endpoint_key": h(e), "relays": read["relays"],
            "addresses": [h(a) for a in read["addresses"]],
            "refused": [{"description": k, "ticket": v, "error": expect_class(read_ticket, v)}
                        for k, v in refused.items()]}


def _member(name: str) -> bytes:
    """A member's device ID, by the fixture derivations."""
    return hs.fixture_signer(example(f"transport/addresses, {name} identity")).device_id


def _member_endpoint(name: str) -> bytes:
    return ed25519_public(example(f"transport/addresses, {name} endpoint"))


def member_addresses_vectors() -> dict:
    """The `Addresses` a sender lists for a receiver on attach 0, what the
    receiver does with each entry, and messages it refuses."""
    # "echo" lists, under another device ID, the receiver's own endpoint.
    names = ["receiver", "sender", "removed", "venue", "booth", "desk", "echo"]
    ids = {n: _member(n) for n in names}
    endpoints = {n: _member_endpoint(n) for n in names}
    port = 47_000
    def ticket_of(name: str, endpoint_key: bytes | None = None, kind: int = 1,
                  relays: tuple = ()) -> bytes:
        return ticket_cbor(kind, endpoint_key or endpoints[name], list(relays),
                           [bytes([127, 0, 0, 1]) + (port + names.index(name)).to_bytes(2, "big")])
    entries = [
        (ids["venue"], ticket_of("venue")),
        (ids["booth"], ticket_of("booth")),
        (ids["desk"], ticket_of("desk", relays=("https://relay.example.org",))),
        (ids["receiver"], ticket_of("receiver")),
        (ids["sender"], ticket_of("sender")),
        (ids["removed"], ticket_of("removed")),
        (ids["echo"], ticket_of("echo", endpoints["receiver"])),
    ]
    receiver = {"device": ids["receiver"], "sender": ids["sender"],
                "endpoint": endpoints["receiver"],
                "view": {ids[n] for n in names if n != "removed"},
                "attached": {ids["desk"]}}
    # The receiver keeps a ticket of the booth, under an endpoint key the
    # booth has since rotated away from; it keeps it unchanged.
    kept = {ids["booth"]: ticket_of("booth", _member_endpoint("booth, rotated"))}
    message = encode_addresses(0, entries)
    outcomes = receive_addresses(message, receiver, admitted=True)
    assert [(o["outcome"], o.get("step")) for o in outcomes] == [
        ("dialed", None), ("dialed", None), ("skipped", 6), ("skipped", 4), ("skipped", 4),
        ("skipped", 4), ("skipped", 5)]
    learned = [(key, raw) for (key, raw), o in zip(entries, outcomes) if o["outcome"] == "dialed"]
    assert receive_addresses(message, receiver, admitted=False) is None
    assert len(message) <= TYPE_CAPS[ADDRESSES]
    read = read_addresses(message)
    small = point_encode(small_order_points()[1])
    venue = (ids["venue"], ticket_of("venue"))
    many = [(_member(f"many {i}"), ticket_of("venue")) for i in range(MAX_ADDRESS_ENTRIES + 1)]
    refused = []
    for description, payload, connection in (
            ("a device ID twice", encode_addresses(0, [venue, venue]), "member"),
            ("65 entries", encode_addresses(0, many), "member"),
            ("a ticket of kind peer",
             encode_addresses(0, [(ids["venue"], ticket_of("venue", kind=2))]), "member"),
            ("an entry of three items",
             cbor({0: ADDRESSES, 1: 0, 2: [[ids["venue"], ticket_of("venue"), b""]]}),
             "member"),
            ("an extra key, 3", cbor({0: ADDRESSES, 1: 0, 2: [list(venue)], 3: 0}), "member"),
            ("a small-order endpoint key",
             encode_addresses(0, [(ids["venue"], cbor({1: 1, 2: 1, 3: small}))]), "member"),
            ("on a device-to-peer connection", encode_addresses(0, [venue]), "peer")):
        refused.append({"description": description, "connection": connection,
                        "message": h(payload), "error": expect_class(read_addresses, payload,
                                                                     connection)})
    return {
        "limits": {"max_entries": MAX_ADDRESS_ENTRIES, "learned_tickets": LEARNED_TICKETS,
                   "learned_seconds": LEARNED_SECONDS,
                   "cross_dial_wait_seconds": CROSS_DIAL_WAIT_SECONDS},
        "receiver": {"device_id": h(ids["receiver"]), "endpoint_key": h(endpoints["receiver"]),
                     "view": [h(ids[n]) for n in names if n != "removed"],
                     "kept": [{"device_id": h(k), "ticket": h(v)} for k, v in kept.items()],
                     "attached": [h(ids["desk"])]},
        "sender": {"device_id": h(ids["sender"])},
        "attach": 0,
        "message": h(message),
        "frame": h(u32be(len(message)) + message),
        "entries": [{"device_id": h(key), "ticket": h(raw),
                     "ticket_text": TICKET_PREFIX + _b64(raw),
                     "endpoint_key": h(ticket["endpoint"]), **outcome}
                    for (key, raw), (_, ticket), outcome in zip(entries, read["entries"],
                                                                outcomes)],
        "learned": [{"device_id": h(key), "ticket": h(raw)} for key, raw in learned],
        "kept_after": [{"device_id": h(k), "ticket": h(v)} for k, v in kept.items()],
        "not_admitted": "dropped",
        "sending": sending_to_guest_vectors(),
        "refused": refused,
    }


def _address(text: str, port: int) -> bytes:
    return ipaddress.ip_address(text).packed + port.to_bytes(2, "big")


def sending_to_guest_vectors() -> dict:
    """What a sender lists on attach 0 to a full member and to a guest, and
    addresses classified at and around each local-network range's bounds."""
    relay = "https://relay.example.org"
    tickets = [
        # Every address local: listed whole to a guest.
        ("crew", [], [_address("10.0.0.5", 47_010), _address("172.16.0.1", 47_010),
                    _address("169.254.10.10", 47_010),
                    _address("127.0.0.1", 47_010)]),
        # A public address and a relay beside a private one: narrowed.
        ("venue", [relay], [_address("203.0.113.7", 47_011),
                            _address("192.168.1.20", 47_011)]),
        # IPv6: a documentation address, a unique local one, link-local
        # and loopback: narrowed.
        ("booth", [], [_address("2001:db8::3", 47_012), _address("fd12:3456::3", 47_012),
                       _address("fe80::3", 47_012), _address("::1", 47_012)]),
        # Public addresses and a relay only: left out.
        ("desk", [relay], [_address("198.51.100.9", 47_013),
                           _address("::ffff:192.168.1.9", 47_013)]),
        # A relay alone: left out.
        ("lighting", [relay], []),
    ]
    entries = [(_member(name), ticket_cbor(1, _member_endpoint(name), relays, addresses))
               for name, relays, addresses in tickets]
    to_guest = guest_entries(entries)
    assert [key for key, _ in to_guest] == [_member(n) for n in ("crew", "venue", "booth")]
    assert to_guest[0] == entries[0]
    assert all(read_ticket_cbor(raw)["relays"] == [] for _, raw in to_guest)
    classified = [
        ("10.0.0.0", True), ("10.255.255.255", True), ("9.255.255.255", False),
        ("11.0.0.0", False), ("172.15.255.255", False), ("172.16.0.0", True),
        ("172.31.255.255", True), ("172.32.0.0", False), ("192.168.0.0", True),
        ("192.168.255.255", True), ("192.167.255.255", False), ("192.169.0.0", False),
        ("169.254.0.0", True), ("169.254.255.255", True), ("169.253.255.255", False),
        ("169.255.0.0", False), ("127.0.0.0", True), ("127.255.255.255", True),
        ("128.0.0.0", False), ("100.64.0.1", False), ("0.0.0.0", False),
        ("255.255.255.255", False), ("224.0.0.1", False), ("203.0.113.7", False),
        ("::1", True), ("::", False), ("::2", False), ("fc00::", True),
        ("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", True), ("fbff:ffff::", False),
        ("fe00::", False), ("fe80::", True), ("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", True),
        ("fe7f:ffff::", False), ("fec0::", False), ("ff02::1", False), ("2001:db8::3", False),
        ("::ffff:192.168.1.9", False), ("::ffff:127.0.0.1", False), ("::127.0.0.1", False),
    ]
    for text, local in classified:
        assert is_local_network(_address(text, 1)) is local, text
    return {
        "members": [{"device_id": h(key), "ticket": h(raw)} for key, raw in entries],
        "to_member": h(encode_addresses(0, entries)),
        "to_guest": h(encode_addresses(0, to_guest)),
        "guest_entries": [{"device_id": h(key), "ticket": h(raw)} for key, raw in to_guest],
        "addresses": [{"text": text, "address": h(_address(text, 47_000)), "local_network": local}
                      for text, local in classified],
    }


def _leave_request(space: bytes) -> bytes:
    """A guest's signed leave request (ext-guests.md, "The leave request"),
    the body of a `frasil/leave-request` item."""
    guest = hs.device_signer("transport/guest")
    record = cbor({1: 1, 2: space, 3: [0, guest.device_id],
                   4: [example("transport/the guest's grant")],
                   5: example("transport/leave request ID")[:16], 6: guest.device_id})
    return cbor({1: record, 2: hs.sign(guest, events.SCHEME_HYBRID,
                                       LEAVE_REQUEST_LABEL + field(record))})


def peer_caps_vectors() -> dict:
    """The peer's caps over its device mailboxes, and which items it keeps:
    a claimed mailbox's deposit evicts items of mailboxes nobody claimed,
    never a claimed one's; an unclaimed mailbox's deposit evicts nothing
    elsewhere."""
    a, b, c = (example(f"transport/caps mailbox {n}") for n in "abc")
    steps = []
    peer = PeerMailboxes(4, 1_000_000)
    peer.box(a, claimed=True)
    peer.box(b)
    before = peer.describe()
    for name, address in (("into unclaimed B", b), ("into claimed A", a), ("into unclaimed B", b),
                          ("into claimed A: the peer's four items", a),
                          ("into C, unclaimed, past the cap: nothing evicted elsewhere", c),
                          ("into claimed A, past the cap: B's oldest goes", a),
                          ("into claimed A, past the cap: B's last goes", a),
                          ("into claimed A, past the cap, with only claimed items left", a)):
        result = peer.deposit(address, 2_000)
        steps.append({"step": name, "address": h(address), "bytes": 2_000, **result,
                      "after": peer.describe()})
    by_bytes = PeerMailboxes(10, 5_000)
    by_bytes.box(a, claimed=True)
    by_bytes.box(b)
    by_bytes.deposit(b, 3_000)
    bytes_before = by_bytes.describe()
    bytes_step = {"address": h(a), "bytes": 3_000, **by_bytes.deposit(a, 3_000),
                  "after": by_bytes.describe()}
    day, hour = 86_400, 3_600
    retention, uncollected = 7 * day, 72 * hour
    kept = []
    for name, deposited, collections, now in (
            ("never collected, a second before uncollected_retention", 0, [], uncollected - 1),
            ("never collected, at uncollected_retention", 0, [], uncollected),
            ("collected after the deposit, before uncollected_retention", 0, [10 * hour],
             uncollected),
            ("the same, a second before mailbox_retention", 0, [10 * hour], retention - 1),
            ("the same, at mailbox_retention", 0, [10 * hour], retention),
            ("deposited while the mailbox was claimed", 100 * hour, [10 * hour],
             100 * hour + uncollected + 1),
            ("collected only after uncollected_retention", 0, [80 * hour], 80 * hour)):
        kept.append({"case": name, "deposited": deposited, "collections": collections,
                     "now": now, "kept": item_kept(deposited, collections, now, retention,
                                                   uncollected)})
    claimed = [{"collections": cs, "now": now, "claimed": mailbox_claimed(cs, now, retention)}
               for cs, now in (([], 0), ([0], 0), ([0], retention - 1), ([0], retention),
                               ([0, 3 * day], retention))]
    return {"cap": {"items": 4, "bytes": 1_000_000}, "before": before, "steps": steps,
            "by_bytes": {"cap": {"items": 10, "bytes": 5_000}, "before": bytes_before,
                         "step": bytes_step},
            "mailbox_retention": retention, "uncollected_retention": uncollected,
            "claimed": claimed, "kept": kept}


def mailboxes_vectors() -> dict:
    request_id = example("transport/request ID")[:16]
    person_id = example("transport/person ID")
    me, mine = device("listener"), ed_kc("listener")
    address = mailbox_address(MAILBOX_DEVICE, me)
    binding = peer_binding(CHANNEL, NONCE_PEER, NONCE_CLIENT, PURPOSE_SPACE)
    signed = collect_input(binding, address)
    signature = ed25519_sign_deterministic(DEVICES["listener"], signed)
    check_collect(address, mine, signature, binding)
    other_binding = peer_binding(CHANNEL_2, NONCE_PEER, NONCE_CLIENT, PURPOSE_SPACE)
    get = encode_mailbox_get(1, address, mine, signature)
    # The listener's Ed25519 key under another kc: another device ID, whose
    # mailbox this is not.
    other_kc = signer("listener").ed_public + signer("dialer").kc

    # Eviction, by count and by bytes.
    by_count, evicted_count = DeviceMailbox(), []
    for i in range(DEVICE_MAILBOX_ITEMS + 2):
        gone = by_count.put(i.to_bytes(16, "big"), bytes(wraps.MIN_BYTES))
        if gone:
            evicted_count.append({"deposit": i, "evicted": [int.from_bytes(g, "big")
                                                            for g in gone]})
    by_bytes, evicted_bytes = DeviceMailbox(), []
    for i in range(DEVICE_MAILBOX_BYTES // MAILBOX_ITEM_BYTES + 1):
        gone = by_bytes.put(i.to_bytes(16, "big"), bytes(MAILBOX_ITEM_BYTES))
        if gone:
            evicted_bytes.append({"deposit": i, "evicted": [int.from_bytes(g, "big")
                                                            for g in gone]})

    # Sealed items.
    recipient_xwing = _xwing("listener")
    leave = _leave_request(SPACE)
    reader_person, list_events = _reader_list_events()
    list_body = cbor({1: SPACE, 2: list_events})
    items = []
    sealed = {}
    for content, body, note in (
            (CONTENT_LEAVE_REQUEST, leave,
             "a guest's signed leave request (ext-guests.md), to an administering device"),
            (CONTENT_LIST_EVENTS, list_body,
             "a read-only person's device-list events with the space to forward them into "
             "(units.md), to a writer device")):
        s = seal_item(content, body, me, recipient_xwing, _eseed(content))
        got = open_item(s["wrap"], me, XWING_SEEDS["listener"],
                        CORE_CONTENT | {CONTENT_LEAVE_REQUEST})
        assert got == {"content": content, "body": body}
        sealed[content] = s["wrap"]
        items.append({"content": content, "description": note,
                      "plaintext": h(item_plaintext(content, body)), "info": h(s["info"]),
                      "eseed": h(_eseed(content)), "enc": h(s["enc"]),
                      "item": h(s["wrap"]), "item_bytes": len(s["wrap"])})
    items[1]["reader_person_id"] = h(reader_person)
    unknown = seal_item("com.example.note", b"an application's note", me, recipient_xwing,
                        _eseed("com.example.note"))["wrap"]
    to_other = seal_item(CONTENT_LEAVE_REQUEST, leave, device("dialer"), _xwing("dialer"),
                         _eseed("to another recipient"))["wrap"]
    leave_item = sealed[CONTENT_LEAVE_REQUEST]
    every = CORE_CONTENT | {CONTENT_LEAVE_REQUEST}
    refused_items = []
    for description, item, error in (
            ("the leave request sealed under another recipient's key, the dialer's", to_other,
             "Decrypt"),
            ("the leave-request item with an unknown suite, 0x0020",
             leave_item[:1] + (0x0020).to_bytes(2, "big") + leave_item[3:],
             "UnsupportedVersion"),
            ("the leave-request item truncated to 1,138 bytes", leave_item[:wraps.MIN_BYTES - 1],
             "Malformed"),
            ("an item with an unknown content name, com.example.note", unknown,
             "UnknownContent")):
        got = expect_class(open_item, item, me, XWING_SEEDS["listener"], every)
        assert got == error, (description, got)
        refused_items.append({"description": description, "item": h(item), "error": error})
    return {
        "addresses": [{"kind": 1, "mailbox": MAILBOX_KIND_NAMES[1], "name": h(request_id),
                       "address": h(mailbox_address(MAILBOX_EXCHANGE, request_id))},
                      {"kind": 2, "mailbox": MAILBOX_KIND_NAMES[2], "name": h(person_id),
                       "address": h(mailbox_address(MAILBOX_PERSON, person_id))},
                      {"kind": 3, "mailbox": MAILBOX_KIND_NAMES[3], "name": h(me),
                       "address": h(address)}],
        "collection": {"ed_kc": h(mine), "device_id": h(me), "address": h(address),
                       "binding": h(binding), "signed": h(signed), "signature": h(signature),
                       "mailbox_get": h(get)},
        "collection_refusals": [
            {"description": "a signature over another connection's binding",
             "error": expect_class(check_collect, address, mine, signature, other_binding)},
            {"description": "another device's mailbox",
             "error": expect_class(check_collect, mailbox_address(MAILBOX_DEVICE,
                                                                  device("dialer")),
                                   mine, signature, binding)},
            {"description": "signed by another device",
             "error": expect_class(check_collect, address, mine, ed25519_sign_deterministic(
                 DEVICES["dialer"], signed), binding)},
            {"description": "the device's Ed25519 key under another kc",
             "ed_kc": h(other_kc),
             "error": expect_class(check_collect, address, other_kc, signature, binding)},
        ],
        "eviction": {"items": DEVICE_MAILBOX_ITEMS, "bytes": DEVICE_MAILBOX_BYTES,
                     "by_count": {"item_bytes": wraps.MIN_BYTES, "deposits":
                                  DEVICE_MAILBOX_ITEMS + 2, "evictions": evicted_count},
                     "by_bytes": {"item_bytes": MAILBOX_ITEM_BYTES, "deposits":
                                  DEVICE_MAILBOX_BYTES // MAILBOX_ITEM_BYTES + 1,
                                  "evictions": evicted_bytes}},
        "recipient": {"device_id": h(me), "x_wing_seed": h(XWING_SEEDS["listener"]),
                      "x_wing_key": h(recipient_xwing),
                      "implements": sorted(CORE_CONTENT | {CONTENT_LEAVE_REQUEST})},
        "items": items,
        "item_refusals": refused_items,
        "peer_caps": peer_caps_vectors(),
        "token_put": {
            "description": "a MailboxPut of kind 3 with key 7, a deposit token "
                           "(ext-deposit-tokens.md), at a peer that does not implement it",
            "message": h(_token_put()), "error": expect_class(read_mailbox_put, _token_put())},
    }


def _token_put() -> bytes:
    return cbor({0: MAILBOX_PUT, 1: 1, 2: mailbox_address(MAILBOX_DEVICE, device("listener")),
                 3: bytes(wraps.MIN_BYTES), 6: MAILBOX_DEVICE, 7: bytes([1]) + bytes(128)})


def transport_vectors() -> dict:
    message_types = [{"type": t, "name": TYPE_NAMES[t], "cap": TYPE_CAPS[t],
                      "classes": [s for s in STREAM_TYPES if t in STREAM_TYPES[s]],
                      **({"extension": EXTENSION_TYPES[t] + ".md"} if t in EXTENSION_TYPES
                         else {})}
                     for t in sorted(TYPE_CAPS)]
    return {
        "construction": "transport",
        "version": 1,
        "protocol": PROTOCOL,
        "specification": "transport.md",
        "labels": {label.decode(): label.hex() for label in NEW_LABELS},
        "parameters": {
            "revision": REVISION,
            "offer_tags": OFFER_TAGS, "extra_offers": EXTRA_OFFERS,
            "candidates_per_space": CANDIDATES_PER_SPACE,
            "candidate_budget": CANDIDATE_BUDGET, "max_attaches": MAX_ATTACHES,
            "handshake_deadline_seconds": HANDSHAKE_DEADLINE,
            "probation": {"seconds": PROBATION_SECONDS, "events": PROBATION_EVENTS},
            "pairing_deadline_seconds": PAIRING_DEADLINE,
            "exporter_label": EXPORTER_LABEL.decode(), "exporter_bytes": 32,
            "websocket_subprotocol": WEBSOCKET_SUBPROTOCOL,
            "stream_caps": STREAM_CAPS,
            "message_types": message_types,
            "ignorable_types": [IGNORABLE_TYPES.start, IGNORABLE_TYPES.stop - 1],
            "codes": {str(code): name for code, name in CLOSE_CODES.items()},
            "reasons": {code: status for code, status in REASONS},
            "services": {str(code): name for code, name in SERVICES.items()},
            "peer_limits": {"max_frame_bytes": PEER_LIMITS[1],
                            "max_streams_per_space": PEER_LIMITS[2],
                            "max_mailbox_item_bytes": PEER_LIMITS[3],
                            "max_chunk_bytes": PEER_LIMITS[4]},
            "lan_groups": list(LAN_GROUPS), "lan_port": LAN_PORT,
            "lan_packet_bytes": LAN_PACKET_BYTES,
            "nearby_name_characters": NEARBY_NAME_CHARACTERS,
            "ticket_max_bytes": TICKET_MAX_BYTES,
            "mailbox_item_bytes": MAILBOX_ITEM_BYTES, "mailbox_item_min_bytes": wraps.MIN_BYTES,
            "content_name_bytes": CONTENT_NAME_BYTES,
            "device_mailbox_items": DEVICE_MAILBOX_ITEMS,
            "device_mailbox_bytes": DEVICE_MAILBOX_BYTES,
        },
        "member_handshake": member_handshake_vectors(),
        "state_choice": state_choice_vectors(),
        "member_refusals": member_refusals_vectors(),
        "roster_check": roster_check_vectors(),
        "device_to_peer": device_to_peer_vectors(),
        "framing": framing_vectors(),
        "local_network": local_network_vectors(),
        "tickets": tickets_vectors(),
        "member_addresses": member_addresses_vectors(),
        "mailboxes": mailboxes_vectors(),
    }


# ---------------------------------------------------------------------------
# Extension material: ext-invite-links.md's drops and ext-libraries.md's
# LibraryAttach. Reference C assembles their files from these.

DROP_MAX_BYTES = 65_536
DROP_LIFETIME_MAX = 604_800


def encode_drop_put(request: int, address: bytes, drop: bytes, space: bytes,
                    lifetime: int) -> bytes:
    """MailboxPut, kind 4 (ext-invite-links.md, "The drop and its
    messages")."""
    return cbor({0: MAILBOX_PUT, 1: request, 2: address, 3: drop, 4: space, 5: lifetime,
                 6: MAILBOX_DROP})


def encode_drop_delete(request: int, address: bytes, space: bytes) -> bytes:
    return cbor({0: MAILBOX_DELETE, 1: request, 2: address, 3: space, 6: MAILBOX_DROP})


class DropStore:
    """A peer's invite drops (ext-invite-links.md, "Making an invite and
    keeping drops"): by address, with the upload entry each was placed
    under."""

    def __init__(self):
        self.drops: dict = {}

    def put(self, message: bytes, store_entry: bytes | None, quota: int = 1 << 40) -> str:
        """On MailboxPut of kind 4, in order. `store_entry` is the upload
        entry whose store right the connection holds for key 4's space, or
        None; `quota` is the bytes the space may still use."""
        v = uncbor(message)
        if (not isinstance(v, dict) or v.get(0) != MAILBOX_PUT or v.get(6) != MAILBOX_DROP
                or set(v) != {0, 1, 2, 3, 4, 5, 6} or not is_bytes(v[3])):
            raise SpecError("Malformed")
        if (not is_bytes(v[2], 32) or not is_bytes(v[4], 32) or not _uint(v[5])
                or not 1 <= v[5] <= DROP_LIFETIME_MAX):
            raise SpecError("Malformed")
        if len(v[3]) > DROP_MAX_BYTES:
            raise SpecError("TooLarge")
        if store_entry is None:
            return "credential_refused"
        if v[2] in self.drops:
            return "conflict"
        if len(v[3]) > quota:
            return "quota_exceeded"
        self.drops[v[2]] = {"space": v[4], "entry": store_entry, "drop": v[3]}
        return "stored"

    def delete(self, message: bytes, entry: bytes | None) -> str:
        """On MailboxDelete: only on a connection that proved the entry the
        drop was placed under."""
        v = uncbor(message)
        drop = self.drops.get(v[2])
        if drop is None:
            return "not_found"
        if entry is None or drop["space"] != v[3] or drop["entry"] != entry:
            return "credential_refused"
        del self.drops[v[2]]
        return "deleted"


def ext_invite_links_drops(locator: bytes | None = None, drop: bytes | None = None,
                           space: bytes | None = None) -> dict:
    """ext-invite-links.json's `drops` family, the parts at a peer: a
    MailboxPut of kind 4 and refused ones, a MailboxDelete, and a peer's
    drop store. The drop is opaque here; Reference C may pass the invite's
    real locator and sealed drop from its derivations."""
    locator = locator or example("transport/an invite locator")
    space = space or SPACE
    drop = drop or (example("transport/drop nonce")[:24] + bytes(120))
    address = mailbox_address(MAILBOX_DROP, locator)
    lifetime = 86_400
    put = encode_drop_put(2, address, drop, space, lifetime)
    entry_a, entry_b = example("transport/upload entry A"), example("transport/upload entry B")
    refused = []
    for description, message, entry, quota, expected in (
            ("a 31-byte address", encode_drop_put(2, address[:31], drop, space, lifetime),
             entry_a, 1 << 40, "Malformed"),
            ("a lifetime of 0", encode_drop_put(2, address, drop, space, 0), entry_a,
             1 << 40, "Malformed"),
            ("a lifetime of 604,801 seconds",
             encode_drop_put(2, address, drop, space, DROP_LIFETIME_MAX + 1), entry_a, 1 << 40,
             "Malformed"),
            ("a drop of 65,537 bytes",
             encode_drop_put(2, address, bytes(DROP_MAX_BYTES + 1), space, lifetime), entry_a,
             1 << 40, "TooLarge"),
            ("a connection without the store right for the space", put, None, 1 << 40,
             "credential_refused"),
            ("a space over its quota", put, entry_a, len(drop) - 1, "quota_exceeded")):
        try:
            got = DropStore().put(message, entry, quota)
        except SpecError as error:
            got = error.error
        assert got == expected, (description, got)
        row = {"description": description, "error": got}
        if len(message) < 4096:
            row["message"] = h(message)
        else:
            row["message_sha256"] = h(sha256(message))
        refused.append(row)
    store = DropStore()
    delete = encode_drop_delete(3, address, space)
    steps = [
        ("a drop placed under upload entry A", store.put(put, entry_a)),
        ("a second drop at the same address, under entry B",
         store.put(encode_drop_put(2, address, drop + b"x", space, lifetime), entry_b)),
        ("a MailboxDelete under entry B", store.delete(delete, entry_b)),
        ("a MailboxDelete with no upload entry", store.delete(delete, None)),
        ("the placer's MailboxDelete, under entry A", store.delete(delete, entry_a)),
        ("a MailboxDelete of an address that holds no drop", store.delete(delete, entry_a)),
        ("a drop at the address again, now free, under entry B", store.put(put, entry_b)),
    ]
    return {
        "locator": h(locator), "address": h(address), "space": h(space), "drop": h(drop),
        "lifetime": lifetime,
        "mailbox_put": h(put), "mailbox_delete": h(delete),
        "mailbox_put_refusals": refused,
        "core_peer": {"description": "the MailboxPut of kind 4 at a peer that does not "
                                     "implement ext-invite-links",
                      "error": expect_class(read_mailbox_put, put)},
        "drop_store": [{"step": s, "result": r} for s, r in steps],
    }


def ext_libraries_library_attach(signed_tickets: dict | None = None) -> list:
    """ext-libraries.json's `library_attach` family: a LibraryAttach for
    each purpose, as it travels. `signed_tickets` maps purpose (1 create, 2
    import, 3 move) to a signed ticket; by default library.py signs them."""
    if signed_tickets is None:
        import library  # imported here: library.py imports this module
        signed_tickets = {}
        for purpose in (1, 2, 3):
            ticket = library.encode_ticket("project:7c1f9e2a0b4d4e8f",
                                           example(f"transport/library ticket {purpose}")[:16],
                                           purpose, library.NOW + 3600,
                                           ed25519_public(library.ISSUER_SEED))
            signed_tickets[purpose] = library.sign_ticket(library.ISSUER_SEED, ticket)
    out = []
    for request, (purpose, name) in enumerate(((1, "create"), (2, "import"), (3, "move")),
                                              start=1):
        signed = signed_tickets[purpose]
        message = cbor({0: LIBRARY_ATTACH, 1: request, 2: SPACE, 3: purpose, 4: signed})
        got = read_message(message, "control", "peer", ("ext-libraries",))
        assert got is not None and set(got) == {0, 1, 2, 3, 4}
        out.append({"purpose": purpose, "name": name, "request": request, "space": h(SPACE),
                    "signed": h(signed), "message": h(message),
                    "frame": h(u32be(len(message)) + message)})
    return out


# ---------------------------------------------------------------------------


def drops_core_ok() -> bool:
    put = bytes.fromhex(ext_invite_links_drops()["mailbox_put"])
    return (expect_class(read_mailbox_put, put) == "Malformed"
            and read_mailbox_put(put, ("ext-invite-links",))[6] == MAILBOX_DROP)


def self_test() -> None:
    for new in NEW_LABELS:
        for other in NEW_LABELS:
            if other is not new:
                assert not other.startswith(new), (new, other)
    # The largest `Awaiting` fits its cap, and one more ID does not.
    for count, fits in ((MAX_AWAITING, True), (MAX_AWAITING + 1, False)):
        largest = cbor({0: AWAITING, 1: bytes(32), 2: [bytes(32)] * count})
        assert (len(largest) <= TYPE_CAPS[AWAITING]) == fits, (count, len(largest))
    v = transport_vectors()
    assert list(v)[4:] == ["labels", "parameters", "member_handshake", "state_choice",
                           "member_refusals", "roster_check", "device_to_peer", "framing",
                           "local_network", "tickets", "member_addresses", "mailboxes"]
    assert [c["error"] for c in v["member_addresses"]["refused"]] == [
        "Malformed", "Malformed", "Malformed", "Malformed", "Malformed", "InvalidKey",
        "Malformed"]
    sets = {row["description"]: row for row in v["state_choice"]}
    assert len(sets) == 6
    assert sets["equal states"]["match"]["index"] == 0
    assert sets["an initiator ahead: the responder has not seen D"]["match"]["state"] == "{C}"
    assert sets["an initiator behind: it missed C and D"]["match"]["state"] == "{B}"
    assert sets["a merged state: the responder holds one of its rotations alone"][
        "match"]["index"] == 1
    assert v["state_choice"][-1]["refused"] == "NoCommonState"
    assert v["member_handshake"]["match"]["state"] == "{C}"
    assert len(v["member_refusals"]) == 25
    assert peer_binding(CHANNEL, bytes(32), bytes(32), 1) != peer_binding(CHANNEL_2, bytes(32),
                                                                          bytes(32), 1)
    lan = v["local_network"]
    assert lan["packet"] != lan["second_packet"]["packet"]
    assert lan["non_member"] == lan["older_state_only"] == "NotForMe"
    assert lan["nearby_name_out"] == "Sam's laptop at the venue, stage left"
    assert lan["nearby_name_empty"]["out"] == NEARBY_FALLBACK
    assert [c["error"] for c in v["tickets"]["refused"]] == [
        "Malformed", "Malformed", "Malformed", "Malformed", "InvalidKey"]
    framing = v["framing"]
    assert [c["result"] for c in framing["caps"]] == ["read on", "TooLarge"] * len(STREAM_CAPS)
    assert framing["refused"][0]["error"] == "UnknownMessage"
    assert framing["dropped"][0]["result"] == "dropped"
    peer = v["device_to_peer"]
    assert len(peer["object_route"]["chunk_path"].split("/")[6]) == 128
    assert [p["credential"] for p in peer["presentations"]] == [1, 2, 4]
    assert [x["result"] for x in peer["hellos"]] == [
        "accepted", "UnsupportedVersion", "RevisionMismatch", "Malformed", "RevisionMismatch",
        "UnsupportedVersion"]
    outcomes = [x["outcome"] for x in peer["sessions"]]
    assert outcomes == ["ok", "ok", "purpose_violation", "ok", "purpose_violation",
                        "purpose_violation", "purpose_violation", "ok", "purpose_violation",
                        "purpose_violation"], outcomes
    box = v["mailboxes"]
    assert [a["kind"] for a in box["addresses"]] == [1, 2, 3]
    assert box["eviction"]["by_count"]["evictions"] == [{"deposit": 64, "evicted": [0]},
                                                        {"deposit": 65, "evicted": [1]}]
    assert box["eviction"]["by_bytes"]["evictions"] == [{"deposit": 16, "evicted": [0]}]
    assert [c["error"] for c in box["collection_refusals"]] == ["BadSignature",
                                                                "WrongMailbox",
                                                                "BadSignature",
                                                                "WrongMailbox"]
    assert [i["content"] for i in box["items"]] == [CONTENT_LEAVE_REQUEST, CONTENT_LIST_EVENTS]
    caps = box["peer_caps"]
    assert [x["verdict"] for x in caps["steps"]] == ["accepted"] * 4 + [
        "Busy", "accepted", "accepted", "Busy"], caps["steps"]
    assert [x["evicted"] for x in caps["steps"]][5:7] == [[1], [3]]
    assert caps["by_bytes"]["step"]["evicted"] == [1]
    assert [k["kept"] for k in caps["kept"]] == [True, False, True, True, False, True, False]
    assert [c["claimed"] for c in caps["claimed"]] == [False, True, True, False, True]
    assert box["token_put"]["error"] == "Malformed"
    assert read_mailbox_put(_token_put(), ("ext-deposit-tokens",))[7][0] == 1
    assert drops_core_ok(), "kind 4 at a core peer"
    assert [c["error"] for c in box["item_refusals"]] == [
        "Decrypt", "UnsupportedVersion", "Malformed", "UnknownContent"]
    # A core device drops a leave request.
    leave = bytes.fromhex(box["items"][0]["item"])
    assert expect_class(open_item, leave, device("listener"), XWING_SEEDS["listener"]) == \
        "UnknownContent"
    # read_offer: the attach limit, parity and the fourth offer.
    tags = [bytes(32)] * OFFER_TAGS
    assert expect_class(read_offer, encode_offer(1024, bytes(32), tags)) == "AttachLimit"
    assert expect_class(read_offer, encode_offer(1, bytes(32), tags)) == "Malformed"
    assert read_offer(encode_offer(1, bytes(32), tags), ROLE_LISTENER)["attach"] == 1
    assert expect_class(read_offer, encode_offer(0, bytes(32), tags), ROLE_DIALER,
                        MAX_OFFERS) == "Malformed"
    # Out of budget without a match: Busy.
    many = [(SPACE, (bytes([i % 256, i // 256]) * 16,), bytes(32))
            for i in range(CANDIDATE_BUDGET + 1)]
    assert expect_class(respond, encode_offer(0, bytes(32), tags), CHANNEL, many) == "Busy"
    drops = ext_invite_links_drops()
    assert [s["result"] for s in drops["drop_store"]] == [
        "stored", "conflict", "credential_refused", "credential_refused", "deleted",
        "not_found", "stored"]
    assert [r["error"] for r in drops["mailbox_put_refusals"]] == [
        "Malformed", "Malformed", "Malformed", "TooLarge", "credential_refused",
        "quota_exceeded"]
    attach = ext_libraries_library_attach({1: b"t1", 2: b"t2", 3: b"t3"})
    assert [a["purpose"] for a in attach] == [1, 2, 3]


if __name__ == "__main__":
    self_test()
    print("handshakes: self-test passed")
