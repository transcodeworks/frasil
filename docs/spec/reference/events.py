"""The signed event envelope and per-device chains (events.md),
written from the specification, independently of any implementation: deterministic CBOR,
the envelope and its checks in their order, the event ID, the author as the
device ID of the envelope's `ed` and `kc`, a log's causal order, heads and
canonical order, chain evidence and equivocation proofs keyed by device ID,
and the decision procedure that roster.md and identity.md share."""

from __future__ import annotations

import itertools
import json
import math
import struct

import history_sigs as hs
import mldsa
from formats import example
from primitives import (
    SpecError,
    ed25519_public,
    ed25519_sign,
    ed25519_sign_deterministic,
    ed25519_valid,
    ed25519_verify_strict,
    sha256,
)
from primitives import ed25519_sign_with_nonce

EVENT_SIGNATURE_LABEL = b"frasil/event/v1"
EVENT_ID_LABEL = b"frasil/event-id/v1"
NEW_LABELS = [EVENT_SIGNATURE_LABEL, EVENT_ID_LABEL]

ENVELOPE_VERSION = 1
SCHEME_ED25519 = 0
SCHEME_HYBRID = 2  # crypto.md: Ed25519 and ML-DSA-65, both required
SIGNATURE_BYTES = {SCHEME_ED25519: 64, SCHEME_HYBRID: hs.HYBRID_SIGNATURE_BYTES}
MLDSA_PUBLIC_BYTES = hs.MLDSA_PUBLIC_KEY_BYTES

KIND_DEVICE_LIST = 1
KIND_SPACE = 2  # a space event: roster changes and rotations alike
KIND_ROSTER = KIND_SPACE  # the same kind, by the name of the genesis it starts
RESERVED_KINDS = (3,)  # kind 3 is reserved: refused before any signature is checked
WITHDRAWN_KINDS = RESERVED_KINDS
KIND_UNIT = 4
KIND_ANCHOR = 5
KIND_STORAGE = 6  # peers.md: the administrator skeleton and writers' requests
KIND_SKELETON = KIND_STORAGE  # the name peers.md's skeleton events first had
KIND_ACK = 64  # an ignorable kind; none is defined
KIND_NAMES = {
    KIND_DEVICE_LIST: "device-list event",
    KIND_SPACE: "space event",
    KIND_UNIT: "unit",
    KIND_ANCHOR: "anchor",
    KIND_STORAGE: "storage event",
    KIND_ACK: "ignorable kind 64",
}
# crypto.md: authority events carry scheme 2 only.
AUTHORITY_KINDS = (KIND_DEVICE_LIST, KIND_SPACE, KIND_ANCHOR, KIND_STORAGE)
MUST_UNDERSTAND = range(1, 64)
IGNORABLE = range(64, 128)
GENESIS_KINDS = (KIND_DEVICE_LIST, KIND_SPACE)


def allowed_schemes(kind: int) -> tuple:
    """Before the classical sunset (crypto.md)."""
    return (SCHEME_HYBRID,) if kind in AUTHORITY_KINDS else (SCHEME_ED25519, SCHEME_HYBRID)


def signing_scheme(kind: int) -> int:
    return SCHEME_HYBRID if kind in AUTHORITY_KINDS else SCHEME_ED25519


MAX_SIGNED_EVENT_BYTES = 16 * 1024 * 1024
MAX_PARENTS = 256
MAX_REFS = 64  # refs travel inside a body now; the bound is the same
KIND_LIMITS = {  # kind: (largest signed event in bytes, most parents)
    KIND_DEVICE_LIST: (16384, 16),
    KIND_SPACE: (1024 * 1024, MAX_PARENTS),
    KIND_UNIT: (1024 * 1024, MAX_PARENTS),
    KIND_ANCHOR: (16384, MAX_PARENTS),
    KIND_STORAGE: (262144, MAX_PARENTS),  # peers.md
    KIND_ACK: (16384, MAX_PARENTS),
}

# The keys of the envelope map (events.md). Key 3 is the author's Ed25519
# key and key 10 its keys commitment; the author is their device ID.
F_VERSION, F_KIND, F_LOG, F_ED, F_SEQ, F_PREV, F_PARENTS, F_CUTS, F_BODY, F_SCHEME, F_KC = \
    range(11)
# Envelope key 7 is `cuts`: the checkpoints the event follows (events.md,
# "Cuts"; roster.md, "Checkpoints"), 1 to MAX_CUTS event IDs, strictly
# ascending, absent when its past holds no checkpoint. Refs name other logs'
# events and travel inside each kind's sealed body, never here.
F_REFS = F_CUTS  # the key's name before it held cuts
MAX_CUTS = 4

# ---------------------------------------------------------------------------
# Deterministic CBOR (RFC 8949 section 4.2.1): unsigned integers, byte and
# text strings, arrays, and maps whose keys are unsigned integers in
# ascending order. Nothing else is used.

UNSIGNED, BYTES, TEXT, ARRAY, MAP = 0, 2, 3, 4, 5

# The deepest nesting a decoder accepts (overview.md): the top-level item is
# at depth 0, and an item inside an array or map, key or value, is one deeper.
MAX_DEPTH = 16


def _head(major: int, value: int) -> bytes:
    top = major << 5
    if value < 24:
        return bytes([top | value])
    for size, code in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if value < 256 ** size:
            return bytes([top | code]) + value.to_bytes(size, "big")
    raise ValueError("integer too large")


NEGATIVE = 1
# adapter-records.md's records subset: false, true and a binary64 float.
FALSE, TRUE, FLOAT64 = 0xF4, 0xF5, 0xFB


def cbor(value, records: bool = False) -> bytes:
    """The one deterministic encoding; in the records subset of
    adapter-records.md also negative integers, booleans and binary64 floats
    other than NaN, a float always in 8 bytes."""
    if isinstance(value, bool):
        if not records:
            raise TypeError("booleans are not used")
        return bytes([TRUE if value else FALSE])
    if isinstance(value, int):
        if value < 0:
            if not records:
                raise TypeError("negative integers are not used")
            return _head(NEGATIVE, -1 - value)
        return _head(UNSIGNED, value)
    if isinstance(value, float):
        if not records or math.isnan(value):
            raise TypeError("floats are not used")
        return bytes([FLOAT64]) + struct.pack(">d", value)
    if isinstance(value, (bytes, bytearray)):
        return _head(BYTES, len(value)) + bytes(value)
    if isinstance(value, str):
        raw = value.encode()
        return _head(TEXT, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return _head(ARRAY, len(value)) + b"".join(cbor(v, records) for v in value)
    if isinstance(value, dict):
        keys = sorted(value)
        return _head(MAP, len(keys)) + b"".join(
            cbor(k) + cbor(value[k], records) for k in keys)
    raise TypeError(type(value))


class _Decoder:
    def __init__(self, data: bytes, records: bool = False):
        self.data, self.at, self.records = data, 0, records

    def take(self, n: int) -> bytes:
        if self.at + n > len(self.data):
            raise SpecError("Malformed")
        out = self.data[self.at:self.at + n]
        self.at += n
        return out

    def item(self, depth: int = 0):
        if depth > MAX_DEPTH:
            raise SpecError("Malformed")
        initial = self.take(1)[0]
        major, low = initial >> 5, initial & 31
        if major == 7 and self.records:
            if initial in (FALSE, TRUE):
                return initial == TRUE
            if initial == FLOAT64:
                value = struct.unpack(">d", self.take(8))[0]
                if math.isnan(value):
                    raise SpecError("Malformed")
                return value
            raise SpecError("Malformed")  # other simple values, shorter floats
        if low < 24:
            value = low
        elif low in (24, 25, 26, 27):
            size = {24: 1, 25: 2, 26: 4, 27: 8}[low]
            value = int.from_bytes(self.take(size), "big")
            if value < (24 if size == 1 else 256 ** (size // 2)):
                raise SpecError("Malformed")  # not the shortest head
        else:
            raise SpecError("Malformed")  # indefinite lengths, reserved codes
        if major == UNSIGNED:
            return value
        if major == NEGATIVE and self.records:
            return -1 - value
        if major == BYTES:
            return self.take(value)
        if major == TEXT:
            try:
                return self.take(value).decode("utf-8")
            except UnicodeDecodeError as error:
                raise SpecError("Malformed") from error
        if major == ARRAY:
            return [self.item(depth + 1) for _ in range(value)]
        if major == MAP:
            out, last = {}, -1
            for _ in range(value):
                key = self.item(depth + 1)
                if not is_uint(key) or key <= last:
                    raise SpecError("Malformed")  # keys unsigned, ascending, distinct
                last = key
                out[key] = self.item(depth + 1)
            return out
        raise SpecError("Malformed")  # negative integers, tags, floats, simple values


def uncbor(data: bytes, records: bool = False):
    """Decode exactly one deterministic CBOR item, or Malformed; in the
    records subset when `records` says so."""
    decoder = _Decoder(data, records)
    value = decoder.item()
    if decoder.at != len(data) or cbor(value, records) != data:
        raise SpecError("Malformed")
    return value


def nesting(value) -> int:
    """How many levels an item nests: 0 for a scalar or an empty array or
    map, else one more than its deepest item, map keys included."""
    if isinstance(value, list):
        return 1 + max(map(nesting, value)) if value else 0
    if isinstance(value, dict):
        return 1 + max(max(nesting(k), nesting(v)) for k, v in value.items()) if value else 0
    return 0


def is_bytes(value, length: int | None = None) -> bool:
    return isinstance(value, bytes) and (length is None or len(value) == length)


def is_uint(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


# ---------------------------------------------------------------------------
# The envelope (events.md).


class Event:
    """A decoded event whose signature verified."""

    def __init__(self, fields: dict, signed: bytes, signature: bytes):
        self.fields = fields
        self.version = fields[F_VERSION]
        self.kind = fields[F_KIND]
        self.log = fields.get(F_LOG)  # None for a genesis event
        self.ed = fields[F_ED]
        self.kc = fields[F_KC]
        # events.md: the author is the device ID of keys 3 and 10.
        self.author = hs.device_id(self.ed, self.kc)
        self.seq = fields[F_SEQ]
        self.prev = fields.get(F_PREV)
        self.parents = tuple(fields[F_PARENTS])
        self.cuts = tuple(fields.get(F_CUTS, ()))
        self.body = fields[F_BODY]
        self.scheme = fields.get(F_SCHEME, SCHEME_ED25519)
        self.signed = signed
        self.signature = signature
        self.event_bytes = cbor(fields)
        self.id = event_id(self.event_bytes)
        # Scheme 0 is verified at decoding; scheme 2 once keys that hash to
        # the event's kc are held.
        self.verified = self.scheme == SCHEME_ED25519

    @property
    def genesis(self) -> bool:
        return self.log is None

    @property
    def log_id(self) -> bytes:
        """The log the event belongs to: its `log`, or its own ID for a genesis."""
        return self.id if self.log is None else self.log


def event_fields(kind: int, signer, seq: int, body: bytes, *, log: bytes | None = None,
                 prev: bytes | None = None, parents=(), refs=(), scheme: int | None = None,
                 cuts=()) -> dict:
    """The envelope's fields, `ed` and `kc` the signer's. `refs` is accepted
    and ignored only so that callers written before refs moved into bodies
    keep running; refs belong in the body now."""
    fields = {F_VERSION: ENVELOPE_VERSION, F_KIND: kind, F_ED: signer.ed_public, F_SEQ: seq,
              F_PARENTS: sorted(set(parents)), F_BODY: body, F_KC: signer.kc}
    scheme = signing_scheme(kind) if scheme is None else scheme
    if scheme != SCHEME_ED25519:
        fields[F_SCHEME] = scheme
    if log is not None:
        fields[F_LOG] = log
    if prev is not None:
        fields[F_PREV] = prev
    if cuts:
        fields[F_CUTS] = sorted(set(cuts))
    return fields


def signing_input(event_bytes: bytes) -> bytes:
    return EVENT_SIGNATURE_LABEL + event_bytes


def assemble(event_bytes: bytes, signature: bytes) -> bytes:
    return cbor([event_bytes, signature])


def signer_for(seed: bytes, name: str = "") -> hs.Signer:
    """A device that signs both schemes: the Ed25519 seed, and the fixture
    ML-DSA-65 and X-Wing seeds crypto.md derives from it."""
    return hs.fixture_signer(seed, name)


def sign_fields(fields: dict, signer: hs.Signer) -> bytes:
    """Tbs is the label and the event's bytes, with the scheme
    inside them; scheme 0 is deterministic Ed25519 over tbs, scheme 2 is
    crypto.md's signature over tbs."""
    assert signer.ed_public == fields[F_ED] and signer.kc == fields[F_KC]
    event_bytes = cbor(fields)
    scheme = fields.get(F_SCHEME, SCHEME_ED25519)
    return assemble(event_bytes, hs.sign(signer, scheme, signing_input(event_bytes)))


def verify_hybrid(event: "Event", keys) -> None:
    """events.md, "The ML-DSA-65 half": `keys` are the (ML-DSA-65 key,
    X-Wing key or None) pairs the replica holds from any source. Step 1
    takes the one that hashes to the event's kc (else NoHybridKey, pending);
    step 2 verifies the half under it (else BadSignature, final)."""
    if event.scheme != SCHEME_HYBRID or event.verified:
        return
    held = hs.keys_for(event.kc, keys or ())
    if held is None:
        raise SpecError("NoHybridKey")
    if not hs.verify_mldsa_half(event.ed, held[0], signing_input(event.event_bytes),
                                event.signature):
        raise SpecError("BadSignature")
    event.verified = True


def event_id(event_bytes: bytes) -> bytes:
    """SHA-256, under the event ID label, of the event's map
    bytes, without the signature: a copy signed again is the same event."""
    return sha256(EVENT_ID_LABEL + event_bytes)


def decode_event(signed: bytes) -> Event:
    """The checks that need only the event, in their order."""
    if len(signed) > MAX_SIGNED_EVENT_BYTES:
        raise SpecError("TooLarge")
    outer = uncbor(signed)
    if not (isinstance(outer, list) and len(outer) == 2 and is_bytes(outer[0])
            and is_bytes(outer[1])):
        raise SpecError("Malformed")
    event_bytes, signature = outer
    fields = uncbor(event_bytes)
    if not isinstance(fields, dict) or not is_uint(fields.get(F_VERSION)):
        raise SpecError("Malformed")
    if fields[F_VERSION] != ENVELOPE_VERSION:
        raise SpecError("UnsupportedVersion")
    if any(key > F_KC for key in fields):
        raise SpecError("Malformed")
    if any(key not in fields for key in (F_KIND, F_ED, F_SEQ, F_PARENTS, F_BODY, F_KC)):
        raise SpecError("Malformed")
    scheme = fields.get(F_SCHEME, SCHEME_ED25519)
    if F_SCHEME in fields and (not is_uint(scheme) or scheme == SCHEME_ED25519):
        raise SpecError("Malformed")
    kind, seq = fields[F_KIND], fields[F_SEQ]
    if not is_uint(kind) or not (kind in MUST_UNDERSTAND or kind in IGNORABLE) \
            or kind in WITHDRAWN_KINDS:
        raise SpecError("Malformed")
    if scheme not in SIGNATURE_BYTES:
        raise SpecError("UnsupportedVersion")
    if scheme not in allowed_schemes(kind):
        raise SpecError("SchemeNotAllowed")
    if len(signature) != SIGNATURE_BYTES[scheme]:
        raise SpecError("Malformed")
    if not is_uint(seq) or seq < 1:
        raise SpecError("Malformed")
    if not is_bytes(fields[F_ED], 32) or not is_bytes(fields[F_KC], 32) \
            or not is_bytes(fields[F_BODY]):
        raise SpecError("Malformed")
    for key in (F_LOG, F_PREV):
        if key in fields and not is_bytes(fields[key], 32):
            raise SpecError("Malformed")
    parents = fields[F_PARENTS]
    if not isinstance(parents, list) or not all(is_bytes(p, 32) for p in parents):
        raise SpecError("Malformed")
    if any(a >= b for a, b in zip(parents, parents[1:])):
        raise SpecError("Malformed")  # strictly ascending: sorted, no duplicate
    if F_CUTS in fields:
        cuts = fields[F_CUTS]
        if not (isinstance(cuts, list) and 1 <= len(cuts) <= MAX_CUTS
                and all(is_bytes(c, 32) for c in cuts)
                and all(a < b for a, b in zip(cuts, cuts[1:]))):
            raise SpecError("Malformed")  # 1 to 4 IDs, strictly ascending
    if F_LOG not in fields:
        if seq != 1 or parents or kind not in GENESIS_KINDS or F_CUTS in fields:
            raise SpecError("Malformed")
    elif not parents:
        raise SpecError("Malformed")
    if (F_PREV in fields) != (seq > 1):
        raise SpecError("Malformed")
    if F_PREV in fields and fields[F_PREV] not in parents:
        raise SpecError("Malformed")
    if kind == KIND_ANCHOR and (fields[F_BODY] or F_LOG not in fields):
        raise SpecError("Malformed")
    if kind in MUST_UNDERSTAND and kind not in KIND_NAMES:
        raise SpecError("UnknownKind")
    most_bytes, most_parents = KIND_LIMITS.get(kind, (MAX_SIGNED_EVENT_BYTES, MAX_PARENTS))
    if len(signed) > most_bytes or len(parents) > most_parents:
        raise SpecError("TooLarge")
    if not ed25519_valid(fields[F_ED]):
        raise SpecError("InvalidKey")
    if scheme == SCHEME_ED25519 and not ed25519_verify_strict(
            fields[F_ED], signing_input(event_bytes), signature):
        raise SpecError("BadSignature")
    # Scheme 2: its Ed25519 half needs no other key (crypto.md), so a
    # stranger's event fails here, before any lookup. No value of kc fails
    # here; whether it commits to keys the author holds is the ML-DSA-65
    # half's question.
    if scheme == SCHEME_HYBRID and not hs.verify_ed25519_half(
            fields[F_ED], signing_input(event_bytes), signature):
        raise SpecError("BadSignature")
    return Event(fields, signed, signature)


# ---------------------------------------------------------------------------
# A log: placement, causal order, heads, canonical order and chains.


class Log:
    """The events of one log a replica has placed. An event is placed only once
    every parent is placed; until then it is pending."""

    def __init__(self, genesis: Event):
        assert genesis.genesis
        self.id = genesis.id
        self.genesis = genesis.id
        self.events: dict[bytes, Event] = {}
        self.anc: dict[bytes, frozenset] = {}
        self.height: dict[bytes, int] = {}
        self.pending: dict[bytes, Event] = {}
        self._place(genesis)

    def _place(self, event: Event) -> None:
        anc = set()
        for p in event.parents:
            anc |= self.anc[p]
            anc.add(p)
        self.anc[event.id] = frozenset(anc)
        self.height[event.id] = 1 + max((self.height[p] for p in event.parents), default=-1)
        self.events[event.id] = event

    def add(self, event: Event) -> str:
        """: "placed" or "pending"; WrongLog if it is another log's."""
        if event.id in self.events:
            return "placed"
        if event.genesis or event.log != self.id:
            raise SpecError("WrongLog")
        if not all(p in self.events for p in event.parents):
            self.pending[event.id] = event
            return "pending"
        self._place(event)
        self.pending.pop(event.id, None)
        progressed = True
        while progressed:
            progressed = False
            for pid, pend in list(self.pending.items()):
                if all(p in self.events for p in pend.parents):
                    self._place(pend)
                    del self.pending[pid]
                    progressed = True
        return "placed"

    # Causal order.
    def le(self, a: bytes, b: bytes) -> bool:
        return a == b or a in self.anc[b]

    def concurrent(self, a: bytes, b: bytes) -> bool:
        return a != b and a not in self.anc[b] and b not in self.anc[a]

    def heads(self, view=None) -> list[bytes]:
        ids = set(self.events if view is None else view)
        covered = set()
        for i in ids:
            covered |= self.anc[i]
        return sorted(i for i in ids if i not in covered)

    def order_key(self, i: bytes) -> tuple:
        return (self.height[i], i)

    def canonical(self, view=None) -> list[bytes]:
        """By height, then by event ID as bytes."""
        return sorted(self.events if view is None else view, key=self.order_key)

    def closed(self, view) -> bool:
        view = set(view)
        return all(self.anc[i] <= view for i in view)

    # Chains.
    def chain_evidence(self, view=None, accepted=None) -> list[dict]:
        """Every duplicate and every skip among the events of `view` that the
        replica accepted in full: for a unit, its seal opened."""
        ids = [i for i in self.canonical(view) if accepted is None or accepted(i)]
        out = []
        slots: dict[tuple, list] = {}
        for i in ids:
            e = self.events[i]
            slots.setdefault((e.author, e.seq), []).append(i)
        for (author, seq), slot in sorted(slots.items()):
            for a, b in itertools.combinations(sorted(slot), 2):
                out.append({"type": "duplicate", "author": author, "seq": seq, "first": a,
                            "second": b, "fork_seq": seq})
        for i in ids:
            e = self.events[i]
            if e.prev is None:
                continue
            p = self.events[e.prev]
            if accepted is not None and not accepted(e.prev):
                continue
            if p.author != e.author or p.seq != e.seq - 1:
                fork = min(e.seq, p.seq + 1) if p.author == e.author else e.seq
                out.append({"type": "skip", "author": e.author, "seq": e.seq, "first": i,
                            "second": e.prev, "fork_seq": fork})
        return out

    def fork_points(self, view=None, accepted=None) -> dict[bytes, int]:
        out: dict[bytes, int] = {}
        for ev in self.chain_evidence(view, accepted):
            out[ev["author"]] = min(out.get(ev["author"], ev["fork_seq"]), ev["fork_seq"])
        return out

    def stable(self, target: bytes, view, holders) -> bool:
        """roster.md and identity.md: every holder has a valid
        event in `view` whose past holds `target` (or is `target`)."""
        for author, valid in holders:
            if not any(self.events[i].author == author and self.le(target, i) for i in valid):
                return False
        return True


# ---------------------------------------------------------------------------
# Equivocation proofs.

PROOF_DUPLICATE, PROOF_SKIP = 1, 2


def make_proof(kind: int, first: bytes, second: bytes) -> bytes:
    return cbor([kind, first, second])


def verify_proof(proof: bytes, keys=()) -> dict:
    """The author, the log and the fork point a proof shows; or Malformed,
    the envelope's errors, NoHybridKey, or NotEquivocation. `keys` are the
    (ML-DSA-65 key, X-Wing key or None) pairs the verifier holds from any
    source. A proof is evidence only once the replica accepts both events in
    full; two events of one Ed25519 key under two kc are two authors."""
    value = uncbor(proof)
    if not (isinstance(value, list) and len(value) == 3 and is_uint(value[0])
            and is_bytes(value[1]) and is_bytes(value[2])):
        raise SpecError("Malformed")
    kind, first_bytes, second_bytes = value
    if kind not in (PROOF_DUPLICATE, PROOF_SKIP):
        raise SpecError("Malformed")
    first, second = decode_event(first_bytes), decode_event(second_bytes)
    for e in (first, second):
        verify_hybrid(e, keys)
    if kind == PROOF_DUPLICATE:
        if not first.id < second.id:
            raise SpecError("Malformed")  # smaller ID first: one pair, one proof
        if (first.author, first.log_id, first.seq) != (second.author, second.log_id, second.seq):
            raise SpecError("NotEquivocation")
        fork = first.seq
    else:
        if first.prev is None or first.prev != second.id or first.log_id != second.log_id:
            raise SpecError("NotEquivocation")
        if second.author == first.author and second.seq == first.seq - 1:
            raise SpecError("NotEquivocation")
        fork = min(first.seq, second.seq + 1) if second.author == first.author else first.seq
    return {"author": first.author, "log": first.log_id, "fork_seq": fork}


# ---------------------------------------------------------------------------
# The decision procedure (roster.md; identity.md).

AGREED_LIMIT = 16


def decide(order, past, attackers, auth, dropped, pick_key, limit=AGREED_LIMIT):
    """Decide each contested event valid or void.

    order: the contested events, in canonical order.
    past(e): the contested events in e's past.
    attackers(e): the contested events that attack e.
    auth(e, status): (True, None), or (False, reason); every event of past(e)
        is decided in `status`.
    dropped(x, e, status): True if x's attack on e does not count (a mutual
        pair that both stand, or that e wins), False if it counts, None if not
        yet known.
    pick_key(e, status): the seniority order, the smallest first.

    Returns {event: (valid, how, by)}. For a valid event `how` is "rules",
    "agreed" or "seniority"; for a void one it is the reason, and `by` names
    the attacker when there is one. An event the agreement step voids stays
    void, with its reason under the first assignment the step allowed."""
    status: dict = {}
    pasts = {e: past(e) for e in order}
    att = {e: attackers(e) for e in order}

    def ready(e):
        return all(p in status for p in pasts[e])

    def evaluate(e, assign):
        ok, reason = auth(e, assign)
        if not ok:
            return (False, reason, None)
        pend = False
        for x in att[e]:
            if x in assign and not assign[x][0]:
                continue
            d = dropped(x, e, assign)
            if d is True:
                continue
            if x in assign and d is False:
                return (False, "attacked", x)
            pend = True
        return None if pend else (True, "rules", None)

    while len(status) < len(order):
        progress = True
        while progress:
            progress = False
            for e in order:
                if e in status or not ready(e):
                    continue
                verdict = evaluate(e, status)
                if verdict is not None:
                    status[e] = verdict
                    progress = True
        undecided = [e for e in order if e not in status]
        if not undecided:
            break
        if len(undecided) <= limit:
            allowed = []
            for bits in itertools.product((False, True), repeat=len(undecided)):
                trial = dict(status)
                for e, b in zip(undecided, bits):
                    trial[e] = (b, "trial", None)
                if all(_matches(e, trial, auth, att, dropped) for e in undecided):
                    allowed.append(dict(zip(undecided, bits)))
            agreed = {}
            if allowed:
                agreed = {e: allowed[0][e] for e in undecided
                          if all(a[e] == allowed[0][e] for a in allowed)}
            if agreed:
                first = dict(status)
                for e in undecided:
                    first[e] = (allowed[0][e], "trial", None)
                for e, v in agreed.items():
                    status[e] = (True, "agreed", None) if v else \
                        _void_reason(e, first, auth, att, dropped)
                continue
        candidates = [e for e in undecided if ready(e)]
        assert candidates, "a minimal undecided event always has a decided past"
        pick = min(candidates, key=lambda e: pick_key(e, status))
        assert auth(pick, status)[0]
        status[pick] = (True, "seniority", None)
    return status


def _void_reason(e, trial, auth, att, dropped) -> tuple:
    """Why `e` is void under an allowed assignment: its authority's class,
    else its first valid attacker that counts. One of them exists, since the
    assignment is allowed and voids `e`."""
    ok, reason = auth(e, trial)
    if not ok:
        return (False, reason, None)
    by = next(x for x in att[e] if trial[x][0] and dropped(x, e, trial) is not True)
    return (False, "attacked", by)


def _matches(e, trial, auth, att, dropped) -> bool:
    ok, _ = auth(e, trial)
    beaten = any(trial[x][0] and dropped(x, e, trial) is not True for x in att[e])
    return trial[e][0] == (ok and not beaten)


# ---------------------------------------------------------------------------
# A builder for example histories: devices with views, as rooms that sync.


# Every example key holder a History made, by device ID: the vectors'
# builders use it to find a device's keys and to sign its own statements.
KNOWN_SIGNERS: dict = {}


class History:
    """Each device holds a view (a set of placed events, closed under parents).
    `act` signs an event onto the device's view, following the device's own
    chain unless told otherwise; `sync` merges views, as a room does."""

    def __init__(self, prefix: str = "events"):
        self.prefix = prefix
        self.log: Log | None = None
        self.names: dict[bytes, str] = {}
        self.view: dict[str, set] = {}
        self.keys: dict[str, bytes] = {}
        self.signers: dict[str, hs.Signer] = {}
        # Names of key holders with no X-Wing key: administrator pseudonyms,
        # recovery agents (crypto.md, "A device's keys").
        self.keyless: set = set()
        # Events a replica holds but may not cite: pending, or
        # held as NoHybridKey. Neither they nor what follows them are heads.
        self.uncitable: set = set()
        # roster.md, "Checkpoints": `fence(name, view)` gives the events a
        # device that follows a checkpoint does not cite, those concurrent
        # with it; `cuts_for(parents)` the cuts an event with those parents
        # declares (events.md, "Cuts"). None in a log with no checkpoint.
        self.fence = None
        self.cuts_for = None
        # identity.md, "List checkpoints": a list event declares the list
        # checkpoints it follows in its body; `body_hook(body, parents)` adds
        # them once the parents are known.
        self.body_hook = None

    def seed(self, name: str) -> bytes:
        if name not in self.keys:
            self.keys[name] = example(f"{self.prefix}/{name}/ed25519")
            self.view.setdefault(name, set())
        return self.keys[name]

    def device(self, name: str) -> bytes:
        """The device's device ID (crypto.md, "A device's keys")."""
        return self.signer(name).device_id

    def ed(self, name: str) -> bytes:
        """The device's Ed25519 identity key."""
        return self.signer(name).ed_public

    def signer(self, name: str) -> hs.Signer:
        seed = self.seed(name)
        if name not in self.signers or self.signers[name].ed_seed != seed:
            self.signers[name] = (hs.Signer(name, seed, hs.device_mldsa_seed_fixture(seed))
                                  if name in self.keyless else signer_for(seed, name))
        KNOWN_SIGNERS.setdefault(self.signers[name].device_id, self.signers[name])
        return self.signers[name]

    def without_xwing(self, name: str) -> hs.Signer:
        """Make `name` a key holder with no X-Wing key, as an administrator
        pseudonym is (peers.md): its kc hashes an empty X-Wing key."""
        seed = self.seed(name)
        self.keyless.add(name)
        current = self.signers.get(name)
        if current is None or current.ed_seed != seed or current.xwing_public is not None:
            assert not any(e.ed == ed25519_public(seed) for e in
                           (self.log.events.values() if self.log else ())), name
            self.signers[name] = hs.Signer(name, seed, hs.device_mldsa_seed_fixture(seed))
        KNOWN_SIGNERS.setdefault(self.signers[name].device_id, self.signers[name])
        return self.signers[name]

    def mldsa(self, name: str) -> bytes:
        return self.signer(name).mldsa_public

    def xwing(self, name: str) -> bytes | None:
        return self.signer(name).xwing_public

    def held_keys(self, name: str) -> tuple:
        """(ML-DSA-65 key, X-Wing key or None): the keys its kc commits to."""
        return self.signer(name).keys

    def _decode(self, signed: bytes, name: str, unchecked: bool = False) -> Event:
        event = decode_event(signed)
        if not unchecked:
            verify_hybrid(event, [self.held_keys(name)])
        return event

    def genesis(self, name: str, kind: int, body, label: str = "genesis") -> bytes:
        if callable(body):
            body = body(None, self.device(name), 1)
        fields = event_fields(kind, self.signer(name), 1, body)
        event = self._decode(sign_fields(fields, self.signer(name)), name)
        self.log = Log(event)
        self.names[event.id] = label
        self.view[name].add(event.id)
        return event.id

    def act(self, name: str, kind: int, body: bytes, label: str, *, view=None, seq=None,
            prev=None, extra_parents=(), scheme=None, unchecked: bool = False,
            parents=None, fence: bool = True) -> bytes:
        """`unchecked` places an event whose ML-DSA-65 half does not verify
        under the keys its kc commits to: a forgery the vectors build."""
        author = self.device(name)
        w = set(self.view[name] if view is None else view)
        assert self.log.closed(w)
        if seq is None:
            mine = [i for i in w if self.log.events[i].author == author]
            last = max(mine, key=lambda i: (self.log.events[i].seq, i), default=None)
            seq = 1 if last is None else self.log.events[last].seq + 1
            prev = last
        if parents is None:
            parents = self.parents_for(name, w, prev, fence)
        parents = set(parents) | set(extra_parents)
        if prev is not None:
            parents.add(prev)
        if callable(body):  # a body sealed to its own event (roster.md)
            body = body(self.log.id, author, seq)
        if self.body_hook is not None:
            body = self.body_hook(body, parents)
        cuts = self.cuts_for(parents) if self.cuts_for is not None else ()
        fields = event_fields(kind, self.signer(name), seq, body, log=self.log.id, prev=prev,
                              parents=parents, scheme=scheme, cuts=cuts)
        event = self._decode(sign_fields(fields, self.signer(name)), name, unchecked)
        assert self.log.add(event) == "placed"
        self.names[event.id] = label
        self.view[name] |= self.log.anc[event.id] | {event.id}
        return event.id

    def parents_for(self, name: str, w, prev=None, fence: bool = True) -> set:
        """The heads a device cites: its view's heads but what it may not
        cite, and, when it follows a checkpoint, but the events concurrent
        with it (roster.md, "Checkpoints")."""
        w = set(w)
        blocked = {i for i in w if self.uncitable & (self.log.anc[i] | {i})}
        if fence and self.fence is not None:
            blocked |= self.fence(name, w)
        parents = set(self.log.heads(w - blocked))
        if prev is not None:
            parents.add(prev)
        return parents

    def sync(self, *names: str) -> None:
        union = set()
        for n in names:
            union |= self.view.setdefault(n, set())
        for n in names:
            self.view[n] = set(union)

    def all(self) -> set:
        return set(self.log.events)

    def by_name(self, label: str) -> bytes:
        return next(i for i, n in self.names.items() if n == label)

    def name(self, i: bytes) -> str:
        return self.names.get(i, i.hex()[:16])

    def key_name(self, key: bytes) -> str:
        """The name of the device whose device ID is `key`."""
        for n in self.keys:
            if self.device(n) == key:
                return n
        return key.hex()[:16]

    def author_name(self, i: bytes) -> str:
        return self.key_name(self.log.events[i].author)

    def describe(self, view=None) -> list[dict]:
        out = []
        for i in self.log.canonical(view):
            e = self.log.events[i]
            out.append({
                "name": self.name(i), "id": i.hex(), "kind": e.kind,
                "author": self.author_name(i), "seq": e.seq,
                "prev": self.name(e.prev) if e.prev else None,
                "parents": [self.name(p) for p in e.parents],
                "signed": e.signed.hex(),
            })
        return out


# ---------------------------------------------------------------------------
# Vectors.


def h(value: bytes) -> str:
    return value.hex()


def expect_error(function, *args) -> str:
    try:
        function(*args)
    except SpecError as error:
        return error.error
    return "accepted"


def proof_changed(proof: bytes) -> bytes:
    kind, first, second = uncbor(proof)
    return cbor([kind, first, second[:-1] + bytes([second[-1] ^ 1])])


def events_vectors() -> dict:
    hist = History()
    g = hist.genesis("founder", KIND_SPACE, b"genesis body (opaque to events.md)")
    a = hist.act("founder", KIND_UNIT, b"unit a", "a")
    hist.sync("founder", "writer")
    w1 = hist.act("writer", KIND_UNIT, b"unit w1", "w1")
    b = hist.act("founder", KIND_UNIT, b"unit b", "b")
    hist.sync("founder", "writer")
    m = hist.act("founder", KIND_SPACE, b"space event (opaque to events.md)", "m")
    ack = hist.act("writer", KIND_ACK, b"an event of an ignorable kind", "ignorable")
    anchor = hist.act("writer", KIND_ANCHOR, b"", "anchor")
    log = hist.log

    def enc(i: bytes, name: str) -> dict:
        e = log.events[i]
        event_bytes = uncbor(e.signed)[0]
        signer = hist.signer(hist.author_name(i))
        out = {
            "name": name, "kind": e.kind, "ed": h(e.ed), "kc": h(e.kc), "author": h(e.author),
            "log": h(e.log) if e.log else None, "seq": e.seq,
            "prev": h(e.prev) if e.prev else None, "parents": [h(p) for p in e.parents],
            "body": h(e.body),
            "scheme": e.scheme, "event": h(event_bytes),
            "signing_input": h(signing_input(event_bytes)),
            "signature": h(e.signature), "signed": h(e.signed), "id": h(e.id),
        }
        if e.scheme == SCHEME_HYBRID:
            key = signer.mldsa_public
            out["mldsa_public"] = h(key)
            out["xwing_public"] = h(signer.xwing_public)
            out["ed25519_message"] = h(hs.hybrid_ed25519_message(e.ed,
                                                                 signing_input(event_bytes)))
            out["mldsa_message"] = h(hs.hybrid_mldsa_message(e.ed, key,
                                                             signing_input(event_bytes)))
        return out

    encodings = [
        enc(g, "a genesis space event, scheme 2: no log, no prev, no parents; its ID names "
               "the log"),
        enc(a, "a unit, scheme 0: the founder's second event, seq 2, prev and only parent the "
               "genesis"),
        enc(w1, "another device's first event in the log: seq 1, no prev"),
        enc(b, "the founder's third event"),
        enc(m, "a space event, scheme 2, with two parents; any refs it has travel sealed in its "
               "body"),
        enc(ack, "an event of kind 64, which a replica keeps and chains and gives no effect"),
        enc(anchor, "an anchor: scheme 2, an empty body, the author's heads as parents"),
    ]

    seed = hist.seed("founder")
    base = uncbor(uncbor(log.events[a].signed)[0])
    good = log.events[a].signed
    event_bytes, signature = uncbor(good)

    def resigned(name: str, change) -> dict:
        fields = change(dict(base))
        data = cbor(fields)
        signed = assemble(data, ed25519_sign(seed, signing_input(data)))
        return {"name": name, "signed": h(signed), "error": expect_error(decode_event, signed)}

    def raw(name: str, signed: bytes) -> dict:
        return {"name": name, "signed": h(signed), "error": expect_error(decode_event, signed)}

    big_s = (int.from_bytes(signature[32:], "little")
             + 2**252 + 27742317777372353535851937790883648493).to_bytes(32, "little")
    small_order = dict(base)
    small_order[F_ED] = bytes(32)
    gbase = uncbor(uncbor(log.events[m].signed)[0])
    founder = hist.signer("founder")

    def hybrid_variant(name: str, change) -> dict:
        fields = change(dict(gbase))
        data = cbor(fields)
        sc = fields.get(F_SCHEME, SCHEME_ED25519)
        signed = assemble(data, hs.sign(founder, sc, signing_input(data)))

        def check():
            verify_hybrid(decode_event(signed), [founder.keys])
        return {"name": name, "signed": h(signed), "error": expect_error(check)}

    msig = log.events[m].signature
    mbytes = uncbor(log.events[m].signed)[0]

    def hybrid_raw(name, signature, keys=(founder.keys,)):
        signed = assemble(mbytes, signature)

        def check():
            verify_hybrid(decode_event(signed), keys)
        return {"name": name, "signed": h(signed), "error": expect_error(check)}

    # The writer's ML-DSA-65 key makes the half of an event that names the
    # founder's ed and kc: the replica holds both devices' keys, takes the
    # founder's by kc, and the half does not verify under it.
    writer = hist.signer("writer")
    m_ml = hs.hybrid_mldsa_message(founder.ed_public, writer.mldsa_public, signing_input(mbytes))
    by_writer = msig[:64] + mldsa.sign_internal(writer._mldsa_secret, writer.mldsa_public,
                                                mldsa.message_prime(m_ml))

    negative = [
        raw("a trailing byte", good + b"\x00"),
        raw("a non-shortest head on the outer array", b"\x98\x02" + good[1:]),
        raw("the outer array holds three items", cbor([event_bytes, signature, b""])),
        resigned("version 2", lambda f: {**f, F_VERSION: 2}),
        resigned("an unknown field key 11", lambda f: {**f, 11: 0}),
        resigned("scheme 0 written out", lambda f: {**f, F_SCHEME: 0}),
        resigned("scheme 1, reserved", lambda f: {**f, F_SCHEME: 1}),
        resigned("scheme 3, unknown", lambda f: {**f, F_SCHEME: 3}),
        raw("a signature of 63 bytes", assemble(event_bytes, signature[:63])),
        resigned("kind 0", lambda f: {**f, F_KIND: 0}),
        resigned("kind 128", lambda f: {**f, F_KIND: 128}),
        resigned("kind 3, reserved", lambda f: {**f, F_KIND: 3}),
        resigned("seq 0", lambda f: {**f, F_SEQ: 0}),
        resigned("a log of 31 bytes", lambda f: {**f, F_LOG: f[F_LOG][:31]}),
        resigned("parents out of order",
                 lambda f: {**f, F_PARENTS: [b"\xff" * 32, g]}),
        resigned("a parent twice", lambda f: {**f, F_PARENTS: [g, g]}),
        resigned("envelope key 7, cuts that are not event IDs",
                 lambda f: {**f, F_CUTS: [[example("events/other-log"),
                                           example("events/other-event")]]}),
        resigned("no kc, key 10", lambda f: {k: v for k, v in f.items() if k != F_KC}),
        resigned("a kc of 31 bytes", lambda f: {**f, F_KC: f[F_KC][:31]}),
        resigned("no parents outside a genesis", lambda f: {**f, F_PARENTS: []}),
        resigned("a unit with no log: only rosters and device lists start a log",
                 lambda f: {k: v for k, v in f.items() if k not in (F_LOG, F_PREV)}
                 | {F_SEQ: 1, F_PARENTS: []}),
        resigned("seq 2 without prev", lambda f: {k: v for k, v in f.items() if k != F_PREV}),
        resigned("prev not among the parents", lambda f: {**f, F_PREV: example("events/x")}),
        resigned("kind 7: must be understood, and unknown", lambda f: {**f, F_KIND: 7}),
        raw("an ed of small order (signature left zero)",
            assemble(cbor(small_order), bytes(64))),
        raw("the body changed after signing",
            assemble(cbor({**base, F_BODY: b"changed"}), signature)),
        raw("the kc changed after signing",
            assemble(cbor({**base, F_KC: hist.signer("writer").kc}), signature)),
        raw("the signature's S not reduced", assemble(event_bytes, signature[:32] + big_s)),
        hybrid_variant("a space event under scheme 0",
                       lambda f: {k: v for k, v in f.items() if k != F_SCHEME}),
        hybrid_variant("an anchor with a body", lambda f: {**f, F_KIND: KIND_ANCHOR}),
        hybrid_raw("a scheme-2 signature of 64 bytes", msig[:64]),
        hybrid_raw("a scheme-2 event whose author's keys are not held: only another device's "
                   "hash to another kc", msig, (writer.keys,)),
        hybrid_raw("the Ed25519 half changed", bytes([msig[0] ^ 1]) + msig[1:]),
        hybrid_raw("the ML-DSA-65 half changed", msig[:-1] + bytes([msig[-1] ^ 1])),
        hybrid_raw("the ML-DSA-65 half made by another device's key, under this device's ed "
                   "and kc", by_writer, (founder.keys, writer.keys)),
    ]

    order = log.canonical()
    causal = {
        "ids": {hist.name(i): h(i) for i in order},
        "heights": {hist.name(i): log.height[i] for i in order},
        "heads": [hist.name(i) for i in log.heads()],
        "canonical_order": [hist.name(i) for i in order],
        "pairs": [
            {"first": hist.name(x), "second": hist.name(y),
             "relation": "before" if log.le(x, y) else ("after" if log.le(y, x) else "concurrent")}
            for x, y in itertools.combinations(order, 2)
        ],
    }

    chain_cases = []

    def chain_case(name, build):
        ch = History("events/chains")
        ch.genesis("p", KIND_SPACE, b"genesis")
        ch.sync("p", "x")
        build(ch)

        # An event whose signature verified is evidence, whether
        # or not this replica can open it.
        forks = ch.log.fork_points()
        chain_cases.append({
            "name": name,
            "identity_seeds": {n: h(seed) for n, seed in sorted(ch.keys.items())},
            "devices": {n: {"mldsa_seed": h(ch.signer(n).mldsa_seed),
                            "xwing_seed": h(ch.signer(n).xwing_seed), "kc": h(ch.signer(n).kc),
                            "device_id": h(ch.device(n))} for n in sorted(ch.keys)},
            "events": ch.describe(),
            "evidence": [{"type": x["type"], "author": ch.key_name(x["author"]),
                          "first": ch.name(x["first"]), "second": ch.name(x["second"]),
                          "fork_seq": x["fork_seq"]}
                         for x in ch.log.chain_evidence()],
            "fork_points": {ch.key_name(k): s for k, s in forks.items()},
            "void_from_fork": sorted(ch.name(i) for i, e in ch.log.events.items()
                                     if e.author in forks and e.seq >= forks[e.author]),
        })

    def honest(ch):
        ch.act("x", KIND_UNIT, b"x1", "x1")
        ch.act("x", KIND_UNIT, b"x2", "x2")

    def restore(ch, resync):
        ch.act("x", KIND_UNIT, b"x1", "x1")
        backup = set(ch.view["x"])
        ch.act("x", KIND_UNIT, b"x2", "x2")
        ch.sync("p", "x")
        ch.view["x"] = backup  # restored from a backup
        if resync:
            ch.sync("p", "x")  # it fetches its latest sequence before it writes
            ch.act("x", KIND_UNIT, b"x3", "x3")
        else:
            ch.act("x", KIND_UNIT, b"x2 again", "x2'")

    def skip_forward(ch):
        x1 = ch.act("x", KIND_UNIT, b"x1", "x1")
        ch.act("x", KIND_UNIT, b"x3", "x3", seq=3, prev=x1)

    def skip_backward(ch):
        ch.act("x", KIND_UNIT, b"x1", "x1")
        x2 = ch.act("x", KIND_UNIT, b"x2", "x2")
        ch.act("x", KIND_UNIT, b"x3", "x3")
        ch.act("x", KIND_UNIT, b"x2 again", "x2' citing x2", seq=2, prev=x2)

    def skip_other(ch):
        p2 = ch.act("p", KIND_UNIT, b"p2", "p2")
        ch.sync("p", "x")
        ch.act("x", KIND_UNIT, b"x2", "x2 citing p2", seq=2, prev=p2)

    def resend(ch):
        x1 = ch.act("x", KIND_UNIT, b"x1", "x1")
        e = ch.log.events[x1]
        assert sign_fields(uncbor(uncbor(e.signed)[0]), ch.signer("x")) == e.signed

    chain_case("an honest chain", honest)
    chain_case("a restore that writes before it syncs: two events at seq 2",
               lambda ch: restore(ch, False))
    chain_case("a restore that fetches its latest sequence first", lambda ch: restore(ch, True))
    chain_case("seq 3 whose prev is seq 1", skip_forward)
    chain_case("seq 2 whose prev is seq 2", skip_backward)
    chain_case("a prev that is another device's event", skip_other)
    chain_case("one body signed twice by a deterministic signer is one event", resend)

    def forged(ch):
        ch.act("x", KIND_UNIT, b"x1", "x1")
        before = set(ch.view["x"])
        ch.act("x", KIND_UNIT, b"x2", "x2")
        # A second unit at seq 2 whose seal this replica cannot open: its
        # signature verifies, so it is evidence.
        ch.act("x", KIND_UNIT, b"sealed under no key this replica holds", "x2 unopened",
               view=before)

    chain_case("a second unit at seq 2 this replica cannot open is still evidence", forged)

    def resigned_copy(ch):
        x1 = ch.act("x", KIND_UNIT, b"x1", "x1")
        e = ch.log.events[x1]
        # The same map signed with another valid Ed25519 nonce: a second
        # signature, the same event ID, the same event.
        other = assemble(e.event_bytes, ed25519_sign_with_nonce(
            ch.seed("x"), signing_input(e.event_bytes), 12345))
        copy = decode_event(other)
        assert copy.id == x1 and copy.signed != e.signed
        assert ch.log.add(copy) == "placed"

    chain_case("the same event signed again with another nonce is the same event",
               resigned_copy)

    def shared_ed(ch):
        # Another holder signs with x's Ed25519 seed beside an ML-DSA-65 key
        # and an X-Wing key of its own: its kc is another, so it is another
        # author, and its event at x's seq 2 is no evidence against x.
        ch.act("x", KIND_UNIT, b"x1", "x1")
        ch.act("x", KIND_UNIT, b"x2", "x2")
        ch.keys["x-other-kc"] = ch.seed("x")
        ch.view["x-other-kc"] = set(ch.view["x"])
        ch.signers["x-other-kc"] = hs.Signer(
            "x-other-kc", ch.seed("x"), example("events/chains/x-other-kc/mldsa"),
            example("events/chains/x-other-kc/xwing"))
        ch.act("x-other-kc", KIND_UNIT, b"one Ed25519 key, another kc", "x' at seq 1")
        ch.act("x-other-kc", KIND_UNIT, b"one Ed25519 key, another kc, again", "x' at seq 2")
        assert ch.log.events[ch.by_name("x' at seq 2")].ed == ch.ed("x")
        assert ch.device("x-other-kc") != ch.device("x")

    chain_case("two events at seq 2 that carry one Ed25519 key under two kc: two authors, "
               "no fork", shared_ed)

    ch = History("events/proofs")
    ch.genesis("p", KIND_SPACE, b"genesis")
    ch.sync("p", "x")
    x1 = ch.act("x", KIND_UNIT, b"x1", "x1")
    backup = set(ch.view["x"])
    x2 = ch.act("x", KIND_UNIT, b"x2", "x2")
    ch.view["x"] = backup
    x2b = ch.act("x", KIND_UNIT, b"x2 again", "x2'")
    x4 = ch.act("x", KIND_UNIT, b"x4", "x4", seq=4, prev=x2b)
    ev = ch.log.events
    lo, hi = sorted((x2, x2b))
    dup = make_proof(PROOF_DUPLICATE, ev[lo].signed, ev[hi].signed)
    proofs = []
    for name, proof in [
        ("two events of x at seq 2", dup),
        ("x4 names x2' (seq 2) as its previous event", make_proof(PROOF_SKIP, ev[x4].signed,
                                                                  ev[x2b].signed)),
        ("x2 names x1: an honest link, not a proof", make_proof(PROOF_SKIP, ev[x2].signed,
                                                                ev[x1].signed)),
        ("a duplicate with the larger ID first", make_proof(PROOF_DUPLICATE, ev[hi].signed,
                                                            ev[lo].signed)),
        ("two events at different sequence numbers as a duplicate",
         make_proof(PROOF_DUPLICATE, *sorted((ev[x1].signed, ev[x2].signed),
                                             key=lambda s: event_id(uncbor(s)[0])))),
        ("a proof whose second event is changed", proof_changed(dup)),
        ("proof type 3", cbor([3, ev[lo].signed, ev[hi].signed])),
    ]:
        try:
            result = verify_proof(proof)
            outcome = {"author": h(result["author"]), "log": h(result["log"]),
                       "fork_seq": result["fork_seq"]}
        except SpecError as error:
            outcome = {"error": error.error}
        proofs.append({"name": name,
                       "identity_seeds": {n: h(seed) for n, seed in sorted(ch.keys.items())},
                       "proof": h(proof), **outcome})

    return {
        "specification": "events.md",
        "parameters": {
            "envelope_version": ENVELOPE_VERSION,
            "kinds": {name: kind for kind, name in KIND_NAMES.items()},
            "must_understand": [1, 63], "ignorable": [64, 127],
            "max_signed_event_bytes": MAX_SIGNED_EVENT_BYTES, "max_parents": MAX_PARENTS,
            "max_refs": MAX_REFS,
            "kind_limits": {KIND_NAMES[k]: {"bytes": v[0], "parents": v[1]}
                            for k, v in KIND_LIMITS.items()},
            "signature_bytes": {"0": 64, "2": hs.HYBRID_SIGNATURE_BYTES},
            "identity_seeds": {n: h(s) for n, s in sorted(hist.keys.items())},
            "devices": {n: {"kc": h(hist.signer(n).kc), "device_id": h(hist.device(n))}
                        for n in sorted(hist.keys)},
            "note": ("Each device's identity seed is SHA-256 of a description; its ML-DSA-65 "
                     "and X-Wing seeds are crypto.md's fixture derivations from it."),
        },
        "encodings": encodings,
        "refusals": negative,
        "causal_order": causal,
        "chains": chain_cases,
        "equivocation_proofs": proofs,
    }


def self_test() -> None:
    for value in (0, 23, 24, 255, 256, 65535, 65536, 2**32, b"", b"x" * 300, "é", [1, [2]],
                  {0: 1, 5: b"a"}):
        assert uncbor(cbor(value)) == value
    for bad in (b"\x18\x01", b"\x19\x00\x10", b"\xa2\x01\x00\x00\x00", b"\x9f\xff", b"\x20",
                b"\x00\x00", b"\xf5", b"\xc0\x00"):
        assert expect_error(uncbor, bad) == "Malformed", bad
    assert ed25519_sign(example("t"), b"m") == ed25519_sign_deterministic(example("t"), b"m")
    vectors = events_vectors()
    errors = {c["name"]: c["error"] for c in vectors["refusals"]}
    assert len(vectors["refusals"]) == 35 and len(vectors["encodings"]) == 7
    assert len(vectors["chains"]) == 10 and len(vectors["equivocation_proofs"]) == 7
    expected = {
        "a trailing byte": "Malformed",
        "version 2": "UnsupportedVersion",
        "scheme 0 written out": "Malformed",
        "scheme 1, reserved": "UnsupportedVersion",
        "scheme 3, unknown": "UnsupportedVersion",
        "a space event under scheme 0": "SchemeNotAllowed",
        "kind 3, reserved": "Malformed",
        "an anchor with a body": "Malformed",
        "a scheme-2 signature of 64 bytes": "Malformed",
        "a scheme-2 event whose author's keys are not held: only another device's hash to "
        "another kc": "NoHybridKey",
        "the Ed25519 half changed": "BadSignature",
        "the ML-DSA-65 half changed": "BadSignature",
        "the ML-DSA-65 half made by another device's key, under this device's ed and kc":
            "BadSignature",
        "the kc changed after signing": "BadSignature",
        "a signature of 63 bytes": "Malformed",
        "kind 7: must be understood, and unknown": "UnknownKind",
        "an ed of small order (signature left zero)": "InvalidKey",
        "the body changed after signing": "BadSignature",
        "the signature's S not reduced": "BadSignature",
    }
    for name, error in expected.items():
        assert errors[name] == error, (name, errors[name])
    assert all(e not in ("accepted",) for e in errors.values()), errors
    assert all(e == "Malformed" for n, e in errors.items() if n not in expected), errors
    chains = {c["name"]: c["fork_points"] for c in vectors["chains"]}
    assert chains["an honest chain"] == {}
    assert chains["a restore that writes before it syncs: two events at seq 2"] == {"x": 2}
    assert chains["a restore that fetches its latest sequence first"] == {}
    assert chains["seq 3 whose prev is seq 1"] == {"x": 2}
    assert chains["seq 2 whose prev is seq 2"] == {"x": 2}
    assert chains["a prev that is another device's event"] == {"x": 2}
    assert chains["a second unit at seq 2 this replica cannot open is still evidence"] == {"x": 2}
    assert chains["the same event signed again with another nonce is the same event"] == {}
    assert chains["two events at seq 2 that carry one Ed25519 key under two kc: two authors, "
                  "no fork"] == {}
    proofs = {p["name"]: p for p in vectors["equivocation_proofs"]}
    assert proofs["two events of x at seq 2"]["fork_seq"] == 2
    assert proofs["x4 names x2' (seq 2) as its previous event"]["fork_seq"] == 3
    assert proofs["x2 names x1: an honest link, not a proof"]["error"] == "NotEquivocation"
    assert proofs["a duplicate with the larger ID first"]["error"] == "Malformed"
    assert proofs["two events at different sequence numbers as a duplicate"]["error"] == "NotEquivocation"
    assert proofs["a proof whose second event is changed"]["error"] == "BadSignature"
    assert proofs["proof type 3"]["error"] == "Malformed"
    relations = {p["relation"] for p in vectors["causal_order"]["pairs"]}
    assert relations == {"before", "concurrent"}
    assert vectors["causal_order"]["heads"] == sorted(["m", "anchor"], key=lambda n: bytes.fromhex(
        vectors["causal_order"]["ids"][n]))


if __name__ == "__main__":
    self_test()
    print(len(json.dumps(events_vectors())))
