"""Device-signed requests (ext-app-requests.md), protocol 1, written from
the specification, independently of any implementation.

It holds the statement ("The statement") with the shapes of its fields, the
six header values ("Headers") and how they are read, the list delivery ("The
list delivery", "List deliveries"), and the verifier's checks ("Verifying"),
steps 3 to 12 in their order, over protocol 1's device lists: the person ID,
list events and their merge (identity.md, `reference/identity.py`). Ed25519
signing and strict verification are in `primitives.py`; events and logs in
`events.py`.
"""

from __future__ import annotations

import hashlib
import unicodedata

import events
import history_sigs as hs
import identity
from events import KIND_DEVICE_LIST, Log, cbor, decode_event, uncbor
from formats import example
from primitives import (
    IDENTITY,
    L,
    P,
    SpecError,
    ed25519_public,
    ed25519_scalar,
    ed25519_sign_deterministic,
    ed25519_valid,
    ed25519_verify_lenient,
    ed25519_verify_strict,
    field,
    point_decode,
    point_encode,
    sha256,
)

LABEL = b"frasil/device-signed-request/v1"
NEW_LABELS: list[bytes] = []  # LABEL is listed by generate.py.
VERSION = 0x01
# The scheme byte follows the version byte, in the statement and in
# X-Frasil-Signature. A signed request is verified once, within seconds, so
# it is scheme 0, Ed25519 (crypto.md); every other value is refused.
SCHEME = 0x00
REQUEST_SCHEMES = (SCHEME,)
LIFETIME_SECONDS = 60
CLOCK_SKEW_SECONDS = 60
NONCE_BYTES = 16
ID_BYTES = 32
MAX_HEADS = 16
MIN_AUDIENCE_BYTES = 8
MAX_AUDIENCE_BYTES = 256
MAX_SUBJECT_BYTES = 256
MAX_METHOD_BYTES = 16
MAX_PATH_BYTES = 2048
MAX_QUERY_BYTES = 2048
U64_MAX = 2**64 - 1
LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "[::1]")
DEFAULT_PORTS = {"https": 443, "http": 80}
# "The list delivery": its map and its route.
DELIVERY_VERSION = 1
DELIVERY_METHOD = "PUT"
DELIVERY_PATH = "/frasil/p1/device-list"
MAX_DELIVERY_EVENTS = identity.MAX_LIST_EVENTS
# "Who signs": a verifier that implements ext-recovery-agent.md lets a
# member rooted in an agent sign once agent_waiting_period's default has
# passed since its own first sight of the add.
AGENT_WAIT_SECONDS = identity.AGENT_WAIT_SECONDS

# The signer's `ed || kc` (crypto.md, "A device's keys"), 128 hex digits.
DEVICE = "X-Frasil-Device"
PERSON_ID = "X-Frasil-Person-Id"
EXPIRES = "X-Frasil-Expires"
NONCE = "X-Frasil-Nonce"
LIST_HEADS = "X-Frasil-List-Heads"
SIGNATURE = "X-Frasil-Signature"
HEADS_MAX_BYTES = MAX_HEADS * 64 + MAX_HEADS - 1
# "Headers", in its order: the header, the most bytes its value has, and
# whether it is required.
HEADERS = [
    (DEVICE, 128, True),
    (PERSON_ID, 64, True),
    (EXPIRES, 20, True),
    (NONCE, 32, True),
    (LIST_HEADS, HEADS_MAX_BYTES, False),
    (SIGNATURE, 132, True),
]

SIGNER_KINDS = (identity.DEVICE, identity.PASSKEY)
SUBJECT = "example-subject"
OTHER_SUBJECT = "example-subject-2"
SIGNED_AT = 1790000000
PREFIX = "device-signed-request"

# "Error classes and codes": the status and code a verifier answers for each
# refusal. check_expiry's Expired and Malformed are signature_expired; every
# other Malformed is signature_invalid.
CODES = {
    "Unsigned": (401, "signature_required"),
    "Malformed": (401, "signature_invalid"),
    "UnsupportedVersion": (401, "signature_invalid"),
    "InvalidKey": (401, "signature_invalid"),
    "BadSignature": (401, "signature_invalid"),
    "Replayed": (401, "signature_invalid"),
    "WrongPerson": (403, "device_not_listed"),
    "NotASigner": (403, "device_not_listed"),
    "ListNeeded": (403, "device_list_needed"),
    "BadListDelivery": (400, "malformed"),
}
EXPIRY_CODE = (401, "signature_expired")


class Refused(SpecError):
    """A refusal with the status and code the verifier answers."""

    def __init__(self, error: str, code: tuple | None = None):
        super().__init__(error)
        self.status, self.code = code or CODES[error]


def check_expiry(expires_at: int, now: int | None, lifetime: int, skew: int) -> None:
    """overview.md's check_expiry, in order; now + lifetime + skew saturates
    at 2^64 - 1."""
    if now is None:
        raise Refused("Expired", EXPIRY_CODE)
    if expires_at > min(now + lifetime + skew, U64_MAX):
        raise Refused("Malformed", EXPIRY_CODE)
    if now > expires_at:
        raise Refused("Expired", EXPIRY_CODE)


def h(value: bytes) -> str:
    return value.hex()


# ---------------------------------------------------------------------------
# "The statement": the shapes.


def audience_ok(audience: str) -> bool:
    """The canonical origin of "The statement"."""
    if not MIN_AUDIENCE_BYTES <= len(audience.encode("utf-8")) <= MAX_AUDIENCE_BYTES:
        return False
    for scheme in ("https", "http"):
        if audience.startswith(scheme + "://"):
            rest = audience[len(scheme) + 3:]
            break
    else:
        return False
    if rest.startswith("["):
        close = rest.find("]")
        if close < 0:
            return False
        host, after = rest[: close + 1], rest[close + 1:]
        inner = host[1:-1]
        if not inner or any(c not in "0123456789abcdef:." for c in inner):
            return False
    else:
        colon = rest.find(":")
        host, after = (rest, "") if colon < 0 else (rest[:colon], rest[colon:])
        labels = host.split(".")
        if any(
            not label or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label)
            for label in labels
        ):
            return False
    if after:
        port = after[1:]
        if not after.startswith(":") or not 1 <= len(port) <= 5:
            return False
        if any(c not in "0123456789" for c in port) or port[0] == "0":
            return False
        if not 1 <= int(port) <= 65535 or int(port) == DEFAULT_PORTS[scheme]:
            return False
    return scheme == "https" or host in LOOPBACK_HOSTS


def subject_ok(subject: bytes) -> bool:
    """The token's subject: 1 to 256 bytes of UTF-8, no control character
    (category Cc), not only white space."""
    if not 1 <= len(subject) <= MAX_SUBJECT_BYTES:
        return False
    try:
        text = subject.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return not text.isspace() and not any(unicodedata.category(c) == "Cc" for c in text)


def visible_ascii(text: str) -> bool:
    return all(0x21 <= ord(c) <= 0x7E for c in text)


def method_ok(method: str) -> bool:
    return 1 <= len(method) <= MAX_METHOD_BYTES and all("A" <= c <= "Z" for c in method)


def path_ok(path: str) -> bool:
    return (
        1 <= len(path.encode("utf-8")) <= MAX_PATH_BYTES
        and path.startswith("/")
        and visible_ascii(path)
        and "?" not in path
        and "#" not in path
    )


def query_ok(query: str) -> bool:
    return (
        len(query.encode("utf-8")) <= MAX_QUERY_BYTES
        and visible_ascii(query)
        and "#" not in query
    )


def heads_ok(heads: list[bytes]) -> bool:
    """0 to 16 event IDs, strictly ascending."""
    return (
        len(heads) <= MAX_HEADS
        and all(len(i) == ID_BYTES for i in heads)
        and all(a < b for a, b in zip(heads, heads[1:]))
    )


def statement_parts(request: dict, person_id: bytes, signer: bytes, expires_at: int,
                    nonce: bytes, heads: list[bytes],
                    scheme: int = SCHEME) -> list[tuple[str, bytes]]:
    """"The statement", field by field. `signer` is the signer's `ed || kc`,
    64 bytes. Refuses (Malformed) any value outside its shape, as a signer
    and step 5 of the verifier do."""
    if not audience_ok(request["audience"]) or not subject_ok(request["subject"]):
        raise SpecError("Malformed")
    if not method_ok(request["method"]) or not path_ok(request["path"]):
        raise SpecError("Malformed")
    if not query_ok(request["query"]):
        raise SpecError("Malformed")
    if len(person_id) != ID_BYTES or len(signer) != 64 or len(nonce) != NONCE_BYTES:
        raise SpecError("Malformed")
    if not 0 <= expires_at <= U64_MAX or not heads_ok(heads):
        raise SpecError("Malformed")
    return [
        ("label", LABEL),
        ("version", bytes([VERSION])),
        ("scheme", bytes([scheme])),
        ("audience", field(request["audience"].encode())),
        ("subject", field(request["subject"])),
        ("person_id", field(person_id)),
        ("signer", field(signer)),
        ("method", field(request["method"].encode())),
        ("path", field(request["path"].encode())),
        ("query", field(request["query"].encode())),
        ("body_hash", field(sha256(request["body"]))),
        ("expires_at", expires_at.to_bytes(8, "big")),
        ("nonce", field(nonce)),
        ("heads", field(b"".join(heads))),
    ]


def statement(request: dict, person_id: bytes, signer: bytes, expires_at: int,
              nonce: bytes, heads: list[bytes], scheme: int = SCHEME) -> bytes:
    return b"".join(part for _, part in statement_parts(request, person_id, signer,
                                                        expires_at, nonce, heads, scheme))


# ---------------------------------------------------------------------------
# "Headers": the header values.


def write_headers(signer: bytes, person_id: bytes, expires_at: int, nonce: bytes,
                  heads: list[bytes], signature: bytes, version: int = VERSION,
                  scheme: int = SCHEME) -> dict:
    return {
        DEVICE: h(signer),
        PERSON_ID: h(person_id),
        EXPIRES: str(expires_at),
        NONCE: h(nonce),
        LIST_HEADS: ",".join(h(i) for i in heads) if heads else None,
        SIGNATURE: h(bytes([version, scheme]) + signature),
    }


def lower_hex(text: str, length: int) -> bool:
    return len(text) == length and all(c in "0123456789abcdef" for c in text)


def decimal(text: str, digits: int) -> int | None:
    """1 to `digits` decimal digits, with no leading zero unless the value
    is 0; None otherwise."""
    if not 1 <= len(text) <= digits or any(c not in "0123456789" for c in text):
        return None
    if len(text) > 1 and text[0] == "0":
        return None
    return int(text)


def read_heads(value: str) -> list[bytes] | None:
    """1 to 16 IDs of 64 lowercase hex digits, separated by single commas,
    strictly ascending; None otherwise."""
    parts = value.split(",")
    if not 1 <= len(parts) <= MAX_HEADS or not all(lower_hex(p, 64) for p in parts):
        return None
    heads = [bytes.fromhex(p) for p in parts]
    return heads if heads_ok(heads) else None


def read_headers(values: dict) -> dict:
    """"Verifying", step 3: Unsigned when none is present; then, in the
    order of "Headers", a value longer than its limit or not of its shape, a
    required one absent, or one repeated, is Malformed; then the version
    byte and the scheme byte, each UnsupportedVersion when it is not version
    1's. A repeated header is given as a list of its values."""
    if all(values.get(name) is None for name, _, _ in HEADERS):
        raise Refused("Unsigned")
    for name, limit, required in HEADERS:
        value = values.get(name)
        if value is None:
            if required:
                raise Refused("Malformed")
            continue
        if isinstance(value, list):
            raise Refused("Malformed")
        if len(value.encode("utf-8")) > limit:
            raise Refused("Malformed")
        if name in (DEVICE, PERSON_ID, NONCE, SIGNATURE):
            if not lower_hex(value, limit):
                raise Refused("Malformed")
        elif name == EXPIRES:
            expires = decimal(value, 20)
            if expires is None or expires > U64_MAX:
                raise Refused("Malformed")
        elif read_heads(value) is None:
            raise Refused("Malformed")
    raw_heads = values.get(LIST_HEADS)
    signature = bytes.fromhex(values[SIGNATURE])
    if signature[0] != VERSION or signature[1] not in REQUEST_SCHEMES:
        raise Refused("UnsupportedVersion")
    return {
        "scheme": signature[1],
        "signer": bytes.fromhex(values[DEVICE]),
        "person_id": bytes.fromhex(values[PERSON_ID]),
        "expires_at": int(values[EXPIRES]),
        "nonce": bytes.fromhex(values[NONCE]),
        "heads": [] if raw_heads is None else read_heads(raw_heads),
        "signature": signature[2:],
    }


# ---------------------------------------------------------------------------
# The verifier's state, and list deliveries ("List deliveries").


class State:
    """What a verifier keeps, durably: per subject, the recorded person; per
    person, the list events it placed (they only grow), which are its pin of
    the person; per list event, when it first saw it. A stateful verifier
    also keeps (identity, nonce) until expires_at + signed_request_skew; a
    stateless one has no nonce store."""

    def __init__(self, recorded: dict | None = None, nonce_store: bool = False):
        self.recorded: dict[bytes, bytes] = dict(recorded or {})
        self.logs: dict[bytes, Log] = {}
        self.first_seen: dict[bytes, int] = {}
        self.nonces: dict[tuple, int] | None = {} if nonce_store else None

    def place(self, person_id: bytes, signed_events: list[bytes], now: int) -> int:
        """Placing a list delivery's events: each in the person's log, after
        its parents; one whose parents are missing waits. Nothing is placed
        when any event does not decode as a list event of this person, or when
        the person's first event is neither held nor delivered. Returns how
        many events are placed that were not."""
        decoded = []
        for signed in signed_events:
            try:
                event = decode_event(signed)
            except SpecError as error:
                raise Refused("BadListDelivery") from error
            if event.kind != KIND_DEVICE_LIST or event.log_id != person_id:
                raise Refused("BadListDelivery")
            decoded.append(event)
        log = self.logs.get(person_id)
        before = 0 if log is None else len(log.events)
        if log is None:
            genesis = next((e for e in decoded if e.genesis), None)
            if genesis is None:
                return 0
            log = Log(genesis)
            try:
                identity.DeviceList(log)
            except SpecError as error:
                raise Refused("BadListDelivery") from error
        for event in decoded:
            log.add(event)
        self.logs[person_id] = log
        for i in log.canonical():
            self.first_seen.setdefault(i, now)
        return len(log.events) - before

    def held(self, person_id: bytes) -> Log | None:
        return self.logs.get(person_id)


def delivery(signed_events: list[bytes]) -> bytes:
    """"The list delivery": a deterministic CBOR map {1: 1, 2: [signed list
    events]}."""
    return cbor({1: DELIVERY_VERSION, 2: list(signed_events)})


def read_delivery(body: bytes) -> list[bytes]:
    try:
        value = uncbor(body)
    except SpecError as error:
        raise Refused("BadListDelivery") from error
    if not isinstance(value, dict) or set(value) != {1, 2} or value[1] != DELIVERY_VERSION:
        raise Refused("BadListDelivery")
    items = value[2]
    if not isinstance(items, list) or not 1 <= len(items) <= MAX_DELIVERY_EVENTS \
            or not all(isinstance(i, bytes) for i in items):
        raise Refused("BadListDelivery")
    return items


def is_delivery(request: dict) -> bool:
    return request["method"] == DELIVERY_METHOD and request["path"] == DELIVERY_PATH


# ---------------------------------------------------------------------------
# "Verifying", steps 3 to 12.


def signer_standing(lst: identity.DeviceList, device: bytes, first_seen: dict,
                    now: int, wait: int = AGENT_WAIT_SECONDS) -> str | None:
    """"Who signs": the signer's kind if the merged list holds its device ID
    as an active device or passkey member that has not forked and is not
    waiting; None otherwise."""
    member = lst.active_members().get(device)
    if member is None or member.kind not in SIGNER_KINDS:
        return None
    if member.rooted == identity.AGENT_ROOTED:
        seen = first_seen.get(member.adds[0])
        if seen is None or now - seen < wait:
            return None
    return identity.KIND_NAMES[member.kind]


def verify(values: dict, request: dict, state: State, now: int) -> dict:
    """Steps 3 to 12 on `state`, which a nonce, a list delivery and a first
    record change. Steps 1 and 2, the body and the token, are the caller's:
    `request["subject"]` is the token's sub."""
    read = read_headers(values)                                       # step 3
    signer, person_id = read["signer"], read["person_id"]
    ed, _, device = hs.split_signer(signer)
    if not ed25519_valid(ed):                                         # step 4
        raise Refused("InvalidKey")
    try:
        signed = statement(request, person_id, signer, read["expires_at"],
                           read["nonce"], read["heads"], read["scheme"])  # step 5
    except SpecError as error:
        raise Refused(error.error) from error
    if not ed25519_verify_strict(ed, signed, read["signature"]):      # step 6
        raise Refused("BadSignature")
    check_expiry(read["expires_at"], now, LIFETIME_SECONDS, CLOCK_SKEW_SECONDS)  # step 7
    if state.nonces is not None:                                      # step 8
        key = (device, read["nonce"])
        if key in state.nonces and now <= state.nonces[key]:
            raise Refused("Replayed")
        state.nonces[key] = read["expires_at"] + CLOCK_SKEW_SECONDS
    recorded = state.recorded.get(request["subject"])                 # step 9
    if recorded is not None and recorded != person_id:
        raise Refused("WrongPerson")
    if is_delivery(request):                                          # step 10
        state.place(person_id, read_delivery(request["body"]), now)
    log = state.held(person_id)                                       # step 11
    lacking = log is None or any(i not in log.events for i in read["heads"])
    lst = identity.DeviceList(log) if log is not None else None
    kind = None if lst is None else signer_standing(lst, device, state.first_seen, now)
    if kind is None:
        raise Refused("ListNeeded" if lacking else "NotASigner")
    newly_recorded = recorded is None                                 # step 12
    state.recorded[request["subject"]] = person_id
    return {
        "device": h(device),
        "person_id": h(person_id),
        "kind": kind,
        "expires_at": read["expires_at"],
        "list_needed": lacking,
        "recorded_person": newly_recorded,
    }


# ---------------------------------------------------------------------------
# The vectors: ext-app-requests.json.


def request_json(request: dict) -> dict:
    return {
        "audience": request["audience"],
        "subject_hex": h(request["subject"]),
        "method": request["method"],
        "path": request["path"],
        "query": request["query"],
        "body_hex": h(request["body"]),
    }


class Lists:
    """The two persons of the vectors and the views a verifier holds."""

    def __init__(self):
        p = identity.Person("laptop", prefix=f"{PREFIX}/person")
        D, PK, R, A = identity.DEVICE, identity.PASSKEY, identity.RECOVERY, identity.AGENT
        p.add("laptop", "phone", D)
        p.add("laptop", "passkey", PK)
        p.hist.sync("laptop", "passkey")
        p.add("passkey", "browser", D, "passkey adds browser (rooted in the passkey)")
        p.hist.sync("laptop", "passkey")
        p.add("laptop", "recovery", R)
        p.add("laptop", "agent", A)
        p.hist.sync("laptop", "agent")
        p.add("agent", "helped", D, "agent adds helped (rooted in the agent)")
        p.hist.sync("laptop", "agent", "phone", "passkey")
        before = set(p.log.events)
        p.revoke("laptop", "passkey")
        tablet_add = p.add("phone", "tablet", D, "phone adds tablet, concurrently")
        self.tablet_add = tablet_add
        self.person = p
        p.hist.seed("nobody")
        other = identity.Person("stranger", prefix=f"{PREFIX}/other")
        self.other = other
        full = set(p.log.events)
        self.views = {
            "before revocation": before,
            "without tablet": full - {tablet_add},
            "full": full,
        }
        lst = identity.DeviceList(p.log)
        assert all(v[0] for v in lst.status.values())
        assert len(p.log.heads()) == 2

    def signed(self, view: str) -> list[bytes]:
        log = self.person.log
        return [log.events[i].signed for i in log.canonical(self.views[view])]

    def heads(self, view: str) -> list[bytes]:
        return self.person.log.heads(self.views[view])

    def state(self, view: str | None, record: bool = True, first_seen_at: int = SIGNED_AT,
              other: bool = False, nonce_store: bool = False) -> State:
        s = State({SUBJECT.encode(): self.person.id} if record else None, nonce_store)
        if view is not None:
            s.place(self.person.id, self.signed(view), first_seen_at)
        if other:
            o = self.other.log
            s.place(self.other.id, [o.events[i].signed for i in o.canonical()], first_seen_at)
        return s

    def seed(self, name: str) -> bytes:
        if name == "stranger":
            return self.other.hist.seed(name)
        return self.person.hist.seed(name)

    def signer(self, name: str):
        """The key holder `name`, whose `ed || kc` a request carries."""
        if name == "stranger":
            return self.other.hist.signer(name)
        return self.person.hist.signer(name)

    def json(self) -> dict:
        p = self.person

        def events_of(person) -> list[dict]:
            return [{"name": person.hist.name(i), "id": h(i),
                     "author": person.hist.author_name(i),
                     "signed": h(person.log.events[i].signed)}
                    for i in person.log.canonical()]

        return {
            "note": (
                "A verifier's state names a view of example-subject's person: the "
                "verifier has placed exactly those events, from list deliveries. Every "
                "list is identity.md's, built by reference/identity.py; each event is "
                "given signed."
            ),
            "person_id": h(p.id),
            "events": events_of(p),
            "views": {name: {"events": [p.hist.name(i) for i in p.log.canonical(view)],
                             "heads": [h(i) for i in p.log.heads(view)]}
                      for name, view in self.views.items()},
            "other_person": {"person_id": h(self.other.id), "events": events_of(self.other)},
            "keys": {
                name: {"identity": h(self.signer(name).ed_public),
                       "kc": h(self.signer(name).kc),
                       "device_id": h(self.signer(name).device_id),
                       "signing_seed": h(self.seed(name))}
                for name in ("laptop", "phone", "passkey", "browser", "recovery", "agent",
                             "helped", "tablet", "nobody", "stranger")
            },
        }


def state_json(view: str | None, record: bool, first_seen_at: int = SIGNED_AT,
               other: bool = False, nonce_store: bool = False) -> dict:
    return {"recorded_person": SUBJECT if record else None, "view": view,
            "first_seen_at": first_seen_at if view else None, "other_person": other,
            "nonce_store": nonce_store}


def refusal_json(refusal: Refused) -> dict:
    return {"class": refusal.error, "status": refusal.status, "code": refusal.code}


def ext_app_requests_vectors() -> dict:
    lists = Lists()
    person = lists.person.id
    expires_at = SIGNED_AT + LIFETIME_SECONDS
    window = [expires_at - LIFETIME_SECONDS - CLOCK_SKEW_SECONDS, SIGNED_AT, expires_at]
    long_ago = SIGNED_AT - AGENT_WAIT_SECONDS - CLOCK_SKEW_SECONDS - 1

    def sign(signer: str, request: dict, nonce_name: str, heads: list[bytes],
             person_id: bytes = person, expires: int = expires_at):
        seed = lists.seed(signer)
        nonce = example(f"{PREFIX}/{nonce_name}")[:NONCE_BYTES]
        signed = statement(request, person_id, lists.signer(signer).signer_bytes, expires, nonce,
                           heads)
        return signed, nonce, ed25519_sign_deterministic(seed, signed)

    phone = lists.signer("phone").device_id
    put_path = f"/v1/devices/{h(phone)}/name"
    host_256 = "a" * (MAX_AUDIENCE_BYTES - len("https://") - len(".com")) + ".com"
    subject_256 = ("s" * MAX_SUBJECT_BYTES).encode()
    sixteen = sorted(lists.heads("full")
                     + [example(f"{PREFIX}/unheld-head/{n}") for n in range(MAX_HEADS - 2)])
    api = "https://api.example.com"
    cases = [
        ("a GET with no body and two heads", "laptop", {
            "audience": api, "subject": SUBJECT.encode(),
            "method": "GET", "path": "/v1/projects", "query": "", "body": b"",
        }, ("full", True, SIGNED_AT), lists.heads("full"),
         "the signer's heads are the verifier's: two branches"),
        ("a PUT with a JSON body and no heads", "phone", {
            "audience": api, "subject": SUBJECT.encode(),
            "method": "PUT", "path": put_path, "query": "", "body": b'{"name":"Phone"}',
        }, ("full", True, SIGNED_AT), [], "no heads are sent"),
        ("a path with a query, to a loopback audience with a port", "tablet", {
            "audience": "http://localhost:8787", "subject": SUBJECT.encode(),
            "method": "GET", "path": "/v1/projects", "query": "limit=10&after=a%2Fb",
            "body": b"",
        }, ("full", True, SIGNED_AT), [lists.tablet_add],
         "the signer, on the phone's branch, has not seen the revocation; its head is held"),
        ("a passkey member, against the list before its revocation", "passkey", {
            "audience": api, "subject": SUBJECT.encode(),
            "method": "DELETE", "path": "/v1/invites/3f2a", "query": "", "body": b"",
        }, ("before revocation", True, SIGNED_AT), lists.heads("before revocation"),
         "the verifier holds the list before the event that revokes the passkey member"),
        ("every field at its limit, signed by a device a passkey member added", "browser", {
            "audience": "https://" + host_256, "subject": subject_256,
            "method": "A" * MAX_METHOD_BYTES, "path": "/" + "p" * (MAX_PATH_BYTES - 1),
            "query": "q" * MAX_QUERY_BYTES, "body": bytes(range(256)) * 4,
        }, ("full", False, SIGNED_AT), sixteen,
         "sixteen heads, fourteen of which the verifier lacks: accepted, list needed; the "
         "256-byte subject has no recorded person, so the verifier records one; the browser "
         "is rooted in the passkey and active"),
        ("a device the recovery agent added, after the waiting period", "helped", {
            "audience": api, "subject": SUBJECT.encode(),
            "method": "GET", "path": "/v1/projects", "query": "", "body": b"",
        }, ("full", True, long_ago), lists.heads("full"),
         "the verifier first saw its add more than 72 hours before the earliest instant"),
        ("a first request that is a list delivery", "laptop", {
            "audience": api, "subject": SUBJECT.encode(),
            "method": DELIVERY_METHOD, "path": DELIVERY_PATH, "query": "",
            "body": delivery(lists.signed("full")),
        }, (None, False, SIGNED_AT), lists.heads("full"),
         "the verifier holds nothing and has recorded no person; it places the delivered "
         "events, accepts, and records the person for example-subject"),
    ]
    vectors = []
    signed_cases = {}
    for name, signer, request, (view, record, seen_at), heads, note in cases:
        nonce_name = f"{len(vectors) + 1}/nonce"
        signed, nonce, signature = sign(signer, request, nonce_name, heads)
        signer_bytes = lists.signer(signer).signer_bytes
        values = write_headers(signer_bytes, person, expires_at, nonce, heads, signature)
        parts = statement_parts(request, person, signer_bytes, expires_at, nonce, heads)
        results = [verify(values, request, lists.state(view, record, seen_at), now)
                   for now in window]
        assert all(result == results[0] for result in results), name
        for now in (window[0] - 1, expires_at + 1):
            try:
                verify(values, request, lists.state(view, record, seen_at), now)
                raise AssertionError(f"{name} accepted outside its window")
            except Refused as refusal:
                assert refusal.code == "signature_expired"
        signed_cases[name] = (signer, request, values, signed, signature, heads)
        vectors.append({
            "name": name,
            "note": note,
            "signer": signer,
            "request": request_json(request),
            "signer_ed_kc": h(signer_bytes),
            "device_id": h(lists.signer(signer).device_id),
            "person_id": h(person),
            "body_sha256": h(sha256(request["body"])),
            "signed_at": SIGNED_AT,
            "expires_at": expires_at,
            "nonce": h(nonce),
            "heads": [h(i) for i in heads],
            "statement_fields": {part: h(value) for part, value in parts},
            "statement": h(signed),
            "signature": h(signature),
            "headers": values,
            "state": state_json(view, record, seen_at),
            "accepted_at": window,
            "verified": results[0],
        })
    lengths = [len(v["statement"]) // 2 for v in vectors]

    laptop_case = signed_cases[cases[0][0]]
    _, laptop_request, laptop_values, laptop_statement, laptop_signature, laptop_heads = \
        laptop_case
    laptop = lists.signer("laptop").signer_bytes
    refusals = []

    def attempt(name: str, reason: str, error: str, values: dict | None = None,
                request: dict | None = None, state: tuple = ("full", True, SIGNED_AT),
                now: int = SIGNED_AT, other: bool = False, code: str | None = None):
        values = dict(laptop_values if values is None else values)
        request = dict(laptop_request if request is None else request)
        view, record, seen_at = state
        try:
            verify(values, request, lists.state(view, record, seen_at, other), now)
        except Refused as refusal:
            assert refusal.error == error, (name, refusal.error)
            assert code is None or refusal.code == code, (name, refusal.code)
            refusals.append({
                "name": name,
                "reason": reason,
                "headers": values,
                "request": request_json(request),
                "state": state_json(view, record, seen_at, other),
                "now": now,
                **refusal_json(refusal),
            })
            return
        raise AssertionError(f"refusal {name!r} was accepted")

    def changed(base: dict, **changes) -> dict:
        out = dict(base)
        for key, value in changes.items():
            out[{"device": DEVICE, "person_id": PERSON_ID, "expires": EXPIRES,
                 "nonce": NONCE, "heads": LIST_HEADS, "signature": SIGNATURE}[key]] = value
        return out

    def signed_by(signer: str, request: dict, heads: list[bytes], person_id: bytes = person,
                  nonce_name: str | None = None) -> dict:
        _, nonce, signature = sign(signer, request, nonce_name or f"signer/{signer}", heads,
                                   person_id)
        return write_headers(lists.signer(signer).signer_bytes, person_id, expires_at, nonce,
                             heads, signature)

    # The verifier takes the audience, the subject, the method, the path,
    # the query and the body from itself, the token and the request.
    attempt("another audience", "the verifier's own audience is in the statement",
            "BadSignature", request={**laptop_request, "audience": "https://api.example.org"})
    attempt("another subject", "the token's subject is in the statement", "BadSignature",
            request={**laptop_request, "subject": OTHER_SUBJECT.encode()})
    attempt("another person ID in the header",
            "the person ID is in the statement; the header cannot be swapped", "BadSignature",
            values=changed(laptop_values, person_id=h(lists.other.id)))
    put = signed_cases[cases[1][0]]
    put_request, put_values = put[1], put[2]
    flipped_body = bytes([put_request["body"][0] ^ 1]) + put_request["body"][1:]
    attempt("the body changed by one byte", "the body's hash is in the statement",
            "BadSignature", values=put_values, request={**put_request, "body": flipped_body})
    attempt("the method changed", "the method is in the statement", "BadSignature",
            request={**laptop_request, "method": "DELETE"})
    query_case = signed_cases[cases[2][0]]
    query_request, query_values = query_case[1], query_case[2]
    attempt("the query moved into the path, its ? percent-encoded",
            "path and query are two fields; a path with a raw ? is Malformed instead",
            "BadSignature", values=query_values,
            request={**query_request, "path": query_request["path"] + "%3F"
                     + query_request["query"], "query": ""})
    phone_seed = lists.seed("phone")
    attempt("signed by another key than the device ID names",
            "the signature is verified under the key the header names", "BadSignature",
            values=changed(laptop_values, signature=h(bytes([VERSION, SCHEME])
                                                      + ed25519_sign_deterministic(
                                                          phone_seed, laptop_statement))))

    # Time, after the signature: check_expiry.
    attempt("expired", "now is after expires_at", "Expired", now=expires_at + 1,
            code="signature_expired")
    attempt("121 seconds ahead",
            "expires_at is more than signed_request_lifetime plus signed_request_skew after "
            "now", "Malformed", now=expires_at - LIFETIME_SECONDS - CLOCK_SKEW_SECONDS - 1,
            code="signature_expired")

    # The person and the list: after the signature and the time.
    passkey_case = signed_cases[cases[3][0]]
    attempt("a revoked signer", "the verifier holds the event that revokes the passkey member",
            "NotASigner", values=passkey_case[2], request=passkey_case[1])
    full_heads = lists.heads("full")
    for name, signer, reason in [
        ("a key on no list", "nobody",
         "the key was never added, and the signer's heads are all held"),
        ("a recovery key", "recovery", "a recovery key never signs a request"),
        ("the recovery agent", "agent", "a recovery agent never signs a request"),
    ]:
        attempt(name, reason, "NotASigner", values=signed_by(signer, laptop_request, full_heads))
    attempt("a device the recovery agent added, within the waiting period",
            "the verifier first saw its add at the signing instant; it waits 72 hours",
            "NotASigner", values=signed_by("helped", laptop_request, full_heads),
            state=("full", True, SIGNED_AT))
    other_heads = lists.other.log.heads()
    attempt("a device of another person once the subject's person is recorded",
            "example-subject's recorded person is the first person; a device of another "
            "person holds nothing for this subject, even with that person's list held",
            "WrongPerson",
            values=signed_by("stranger", laptop_request, other_heads, lists.other.id),
            other=True)
    attempt("no list and no record", "the verifier has never been given this person's list",
            "ListNeeded", state=(None, False, SIGNED_AT))
    tablet_request = {**laptop_request, "path": "/v1/projects/7"}
    tablet_values = signed_by("tablet", tablet_request, [lists.tablet_add],
                              nonce_name="signer/tablet/branch")
    attempt("a device added on a branch the verifier lacks",
            "the verifier holds the list without the phone's add of the tablet, which the "
            "signer's head names", "ListNeeded", values=tablet_values, request=tablet_request,
            state=("without tablet", True, SIGNED_AT))
    for name, body, reason in [
        ("a list delivery that does not read", b"\xa1\x01\x01",
         "a list delivery is the map {1: 1, 2: [signed list events]}"),
        ("a list delivery holding another person's event",
         delivery(lists.signed("full")[:3] + [lists.other.log.events[lists.other.id].signed]),
         "every event of a list delivery is of the person the header names"),
    ]:
        request = {**laptop_request, "method": DELIVERY_METHOD, "path": DELIVERY_PATH,
                   "body": body}
        attempt(name, reason, "BadListDelivery", request=request,
                values=signed_by("laptop", request, [], nonce_name=f"delivery/{name}"),
                state=(None, False, SIGNED_AT))

    # Strict verification (crypto.md).
    seed = lists.seed("laptop")
    s = laptop_signature
    s_plus_l = s[:32] + (int.from_bytes(s[32:], "little") + L).to_bytes(32, "little")
    k = int.from_bytes(hashlib.sha512(point_encode(IDENTITY) + laptop[:32]
                                      + laptop_statement).digest(), "little") % L
    small_r = point_encode(IDENTITY) + ((k * ed25519_scalar(seed)) % L).to_bytes(32, "little")
    non_canonical_r = (1 + P).to_bytes(32, "little") + small_r[32:]
    for name, signature, reason in [
        ("an unreduced S (S + l)", s_plus_l, "strict verification refuses S >= l"),
        ("an R of small order, made by the key's holder", small_r,
         "strict verification refuses an R of small order"),
        ("a non-canonical R", non_canonical_r,
         "strict verification refuses an R that is not canonically encoded"),
    ]:
        attempt(name, reason, "BadSignature",
                values=changed(laptop_values, signature=h(bytes([VERSION, SCHEME]) + signature)))

    # Key validation, before the signature.
    neutral = point_encode(IDENTITY)
    any_statement = neutral + bytes(32)
    attempt("a key of small order, with a signature that fits every statement",
            "ed25519_valid runs before the signature is checked", "InvalidKey",
            values=changed(laptop_values, device=h(neutral + laptop[32:]),
                           signature=h(bytes([VERSION, SCHEME]) + any_statement)))
    not_a_point = next(bytes([i]) + bytes(31) for i in range(2, 256)
                       if point_decode(bytes([i]) + bytes(31)) is None)
    attempt("a key that is no point", "ed25519_valid (crypto.md)",
            "InvalidKey", values=changed(laptop_values, device=h(not_a_point + laptop[32:])))

    # The version byte, after every shape; then the scheme byte.
    for version in (0x02, 0x00):
        attempt(f"version byte 0x{version:02x}", "version 1 is the only layout",
                "UnsupportedVersion",
                values=changed(laptop_values,
                               signature=h(bytes([version, SCHEME]) + laptop_signature)))
    for scheme in (0x01, 0x02):
        attempt(f"scheme byte 0x{scheme:02x}",
                "Ed25519 (0x00) is the only scheme a signed request uses; a verifier refuses "
                "another rather than guess what the signature's bytes mean",
                "UnsupportedVersion",
                values=changed(laptop_values,
                               signature=h(bytes([VERSION, scheme]) + laptop_signature)))

    # Each header malformed, and the request's parts outside their shapes.
    device_text, person_text = laptop_values[DEVICE], laptop_values[PERSON_ID]
    expires, nonce_text = laptop_values[EXPIRES], laptop_values[NONCE]
    heads_text, signature_text = laptop_values[LIST_HEADS], laptop_values[SIGNATURE]
    first, second = heads_text.split(",")
    seventeen = ",".join(h(i) for i in sorted(
        sixteen + [example(f"{PREFIX}/unheld-head/{MAX_HEADS}")]))
    for name, values in [
        ("a device header of 127 hex digits",
         changed(laptop_values, device=device_text[:127])),
        ("a device header of 129 hex digits",
         changed(laptop_values, device=device_text + "0")),
        ("a device header in upper case", changed(laptop_values, device=device_text.upper())),
        ("a device header of 64 hex digits: an Ed25519 key alone",
         changed(laptop_values, device=device_text[:64])),
        ("a person ID of 63 hex digits", changed(laptop_values, person_id=person_text[:63])),
        ("a person ID in upper case", changed(laptop_values, person_id=person_text.upper())),
        ("an empty expiry", changed(laptop_values, expires="")),
        ("an expiry with a leading zero", changed(laptop_values, expires="0" + expires)),
        ("an expiry with a sign", changed(laptop_values, expires="+" + expires)),
        ("an expiry with a space", changed(laptop_values, expires=" " + expires)),
        ("an expiry of 2^64", changed(laptop_values, expires=str(2**64))),
        ("an expiry of 21 digits", changed(laptop_values, expires="1" * 21)),
        ("a nonce of 30 hex digits", changed(laptop_values, nonce=nonce_text[:30])),
        ("a nonce of 34 hex digits", changed(laptop_values, nonce=nonce_text + "00")),
        ("a nonce in upper case", changed(laptop_values, nonce=nonce_text.upper())),
        ("heads in descending order", changed(laptop_values, heads=second + "," + first)),
        ("a head repeated", changed(laptop_values, heads=first + "," + first)),
        ("seventeen heads", changed(laptop_values, heads=seventeen)),
        ("an empty heads value", changed(laptop_values, heads="")),
        ("heads with a trailing comma", changed(laptop_values, heads=heads_text + ",")),
        ("heads separated by a comma and a space",
         changed(laptop_values, heads=first + ", " + second)),
        ("a head in upper case", changed(laptop_values, heads=first.upper() + "," + second)),
        ("a head of 63 hex digits", changed(laptop_values, heads=first[:63])),
        ("a signature without its version byte",
         changed(laptop_values, signature=signature_text[2:])),
        ("a signature without its version and scheme bytes",
         changed(laptop_values, signature=signature_text[4:])),
        ("a signature of 134 hex digits", changed(laptop_values, signature=signature_text + "00")),
        ("a signature in upper case", changed(laptop_values, signature=signature_text.upper())),
        ("the signature header absent", changed(laptop_values, signature=None)),
        ("the device header absent", changed(laptop_values, device=None)),
        ("the person ID header absent", changed(laptop_values, person_id=None)),
        ("only the heads present", {DEVICE: None, PERSON_ID: None, EXPIRES: None,
                                    NONCE: None, LIST_HEADS: heads_text, SIGNATURE: None}),
        ("the nonce header repeated, with one value twice",
         changed(laptop_values, nonce=[nonce_text, nonce_text])),
    ]:
        attempt(name, "\"Headers\": every value has one shape, and a header appears once; "
                "a list gives a header's values in the order they arrived", "Malformed",
                values=values, code="signature_invalid")
    for name, change in [
        ("a method in lower case", {"method": "get"}),
        ("a method of 17 letters", {"method": "A" * (MAX_METHOD_BYTES + 1)}),
        ("a path that does not begin with /", {"path": "v1/projects"}),
        ("a path with a space", {"path": "/v1/my projects"}),
        ("a path with a raw ?", {"path": "/v1/projects?limit=10"}),
        ("a path of 2049 bytes", {"path": "/" + "p" * MAX_PATH_BYTES}),
        ("a query with a #", {"query": "a#b"}),
        ("a query of 2049 bytes", {"query": "q" * (MAX_QUERY_BYTES + 1)}),
        ("an audience in upper case", {"audience": "https://API.example.com"}),
        ("an audience with a trailing slash", {"audience": "https://api.example.com/"}),
        ("an audience with the default port", {"audience": "https://api.example.com:443"}),
        ("an audience over http to a host that is not loopback",
         {"audience": "http://api.example.com"}),
        ("a blank subject", {"subject": b"   "}),
        ("a subject of 257 bytes", {"subject": b"s" * (MAX_SUBJECT_BYTES + 1)}),
    ]:
        attempt(name, "\"The statement\": the verifier's and the request's parts have one "
                "shape", "Malformed", request={**laptop_request, **change},
                code="signature_invalid")

    # A replayed nonce at a stateful verifier.
    stateful = lists.state("full", True, SIGNED_AT, nonce_store=True)
    first_result = verify(laptop_values, laptop_request, stateful, SIGNED_AT)
    try:
        verify(laptop_values, laptop_request, stateful, SIGNED_AT + 1)
        raise AssertionError("a replayed nonce was accepted")
    except Refused as refusal:
        assert refusal.error == "Replayed"
        replay = refusal
    refusals.append({
        "name": "a replayed nonce at a stateful verifier",
        "reason": "the verifier keeps (device, nonce) until expires_at + "
                  "signed_request_skew; the same request again, a second later, is refused",
        "headers": laptop_values,
        "request": request_json(laptop_request),
        "state": state_json("full", True, nonce_store=True),
        "first": {"now": SIGNED_AT, "verified": first_result},
        "now": SIGNED_AT + 1,
        **refusal_json(replay),
    })
    attempt("no header at all", "the request is not signed", "Unsigned",
            values={DEVICE: None, PERSON_ID: None, EXPIRES: None, NONCE: None,
                    LIST_HEADS: None, SIGNATURE: None}, code="signature_required")

    # List deliveries: a refusal, the list delivery that answers it, and the retry.
    state = lists.state("without tablet", True, SIGNED_AT)
    try:
        verify(tablet_values, tablet_request, state, SIGNED_AT)
        raise AssertionError("the tablet was accepted before the list delivery")
    except Refused as refusal:
        assert refusal.error == "ListNeeded"
        needed = refusal
    missing = [lists.person.log.events[lists.tablet_add].signed]
    delivery_request = {"audience": api, "subject": SUBJECT.encode(),
                        "method": DELIVERY_METHOD, "path": DELIVERY_PATH, "query": "",
                        "body": delivery(missing)}
    delivery_values = signed_by("tablet", delivery_request, [lists.tablet_add],
                                nonce_name="delivery/tablet")
    delivered = verify(delivery_values, delivery_request, state, SIGNED_AT)
    retry_values = signed_by("tablet", tablet_request, [lists.tablet_add],
                             nonce_name="signer/tablet/retry")
    retried = verify(retry_values, tablet_request, state, SIGNED_AT)
    assert not delivered["list_needed"] and not retried["list_needed"]
    assert len(state.held(person).events) == len(lists.views["full"])
    list_deliveries = [{
        "name": "a device on a branch the verifier lacks delivers its list and retries",
        "state": state_json("without tablet", True),
        "first": {"headers": tablet_values, "request": request_json(tablet_request),
                  **refusal_json(needed), "response_header": {"X-Frasil-List-Needed": "1"}},
        "list_delivery": {"headers": delivery_values,
                          "request": request_json(delivery_request),
                          "events": [h(i) for i in [lists.tablet_add]], "verified": delivered,
                          "status": 204},
        "retry": {"note": "a new request, with its own nonce",
                  "headers": retry_values, "request": request_json(tablet_request),
                  "verified": retried},
        "held_afterwards": "full",
        "now": SIGNED_AT,
    }]

    # A head the verifier lacks, the signer held: accepted, list needed.
    unheld = sorted(full_heads + [example(f"{PREFIX}/unheld-head/0")])
    values = signed_by("laptop", laptop_request, unheld, nonce_name="head/unheld")
    result = verify(values, laptop_request, lists.state("full"), SIGNED_AT)
    assert result["list_needed"] is True
    heads = [{
        "name": "a head the verifier does not hold",
        "reason": "the signer is active in the verifier's list, so the request is accepted; "
                  "the response carries X-Frasil-List-Needed: 1 and the client delivers",
        "headers": values,
        "request": request_json(laptop_request),
        "state": state_json("full", True),
        "now": SIGNED_AT,
        "verified": result,
        "response_header": {"X-Frasil-List-Needed": "1"},
    }]

    lenient = {
        "small_order_r": ed25519_verify_lenient(laptop[:32], laptop_statement, small_r),
        "non_canonical_r": ed25519_verify_lenient(laptop[:32], laptop_statement, non_canonical_r),
        "small_order_key": ed25519_verify_lenient(neutral, laptop_statement, any_statement),
    }
    assert lenient["small_order_r"] and lenient["small_order_key"]

    return {
        "parameters": {
            "label": LABEL.decode(),
            "version_byte": VERSION,
            "scheme_byte": SCHEME,
            "signed_request_lifetime": LIFETIME_SECONDS,
            "signed_request_skew": CLOCK_SKEW_SECONDS,
            "nonce_bytes": NONCE_BYTES,
            "max_heads": MAX_HEADS,
            "min_audience_bytes": MIN_AUDIENCE_BYTES,
            "max_audience_bytes": MAX_AUDIENCE_BYTES,
            "max_subject_bytes": MAX_SUBJECT_BYTES,
            "max_method_bytes": MAX_METHOD_BYTES,
            "max_path_bytes": MAX_PATH_BYTES,
            "max_query_bytes": MAX_QUERY_BYTES,
            "agent_waiting_period": AGENT_WAIT_SECONDS,
            "list_delivery": {"version": DELIVERY_VERSION, "method": DELIVERY_METHOD,
                              "path": DELIVERY_PATH, "content_type": "application/cbor",
                              "max_events": MAX_DELIVERY_EVENTS},
            "headers": [{"name": name, "max_bytes": limit, "required": required}
                        for name, limit, required in HEADERS],
            "codes": {cls: {"status": st, "code": code} for cls, (st, code) in CODES.items()},
            "check_expiry_code": {"status": EXPIRY_CODE[0], "code": EXPIRY_CODE[1]},
            "statement_bytes_in_vectors": {"least": min(lengths), "most": max(lengths)},
        },
        "lists": lists.json(),
        "requests": vectors,
        "request_refusals": refusals,
        "list_deliveries": list_deliveries,
        "heads": heads,
        "lenient_verifier_would_accept": lenient,
    }


def self_test() -> None:
    """A round trip, a refusal per list outcome, and the shapes."""
    p = identity.Person("first", prefix=f"{PREFIX}/self-test")
    p.add("first", "second", identity.DEVICE)
    log = p.log
    request = {"audience": "https://api.example.com", "subject": b"s", "method": "GET",
               "path": "/", "query": "", "body": b""}
    seed = p.hist.seed("second")
    nonce = bytes(NONCE_BYTES)
    heads = log.heads()
    signer = p.hist.signer("second").signer_bytes
    signed = statement(request, p.id, signer, 100, nonce, heads)
    values = write_headers(signer, p.id, 100, nonce, heads,
                           ed25519_sign_deterministic(seed, signed))
    empty = State()
    try:
        verify(values, request, empty, 50)
        raise AssertionError("accepted without a list")
    except Refused as refusal:
        assert refusal.error == "ListNeeded"
    held = State()
    held.place(p.id, [log.events[i].signed for i in log.canonical()], 0)
    assert verify(values, request, held, 50)["recorded_person"] is True
    assert verify(values, request, held, 50)["recorded_person"] is False
    assert held.recorded[b"s"] == p.id
    for now, error in ((101, "Expired"), (-21, "Malformed"), (None, "Expired")):
        try:
            verify(values, request, held, now)
            raise AssertionError("accepted outside the window")
        except Refused as refusal:
            assert refusal.error == error and refusal.code == "signature_expired"
    check_expiry(U64_MAX, U64_MAX - 1, LIFETIME_SECONDS, CLOCK_SKEW_SECONDS)
    assert read_heads(",".join(h(i) for i in heads)) == heads
    assert read_heads(h(heads[0]).upper()) is None
    min_len = len(statement({**request, "audience": "https://a.example"}, p.id,
                            signer, 0, nonce, []))
    assert min_len == 236 + len("https://a.example") - MIN_AUDIENCE_BYTES + len("GET") - 1
    longest = {"audience": "https://" + "a" * (MAX_AUDIENCE_BYTES - 12) + ".com",
               "subject": b"s" * MAX_SUBJECT_BYTES, "method": "A" * MAX_METHOD_BYTES,
               "path": "/" + "p" * (MAX_PATH_BYTES - 1), "query": "q" * MAX_QUERY_BYTES,
               "body": b""}
    assert len(statement(longest, p.id, signer, 0, nonce,
                         [bytes([i]) * 32 for i in range(MAX_HEADS)])) == 5361
    assert read_delivery(delivery([b"x"])) == [b"x"]
