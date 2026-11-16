"""The ephemeral channel (ext-ephemeral.md), protocol 1, written from the
specification, independently of any implementation.

Live traffic travels apart from units: an ephemeral message is
fire-and-forget, broadcast or targeted; an ephemeral slot is latest-wins per
sender, name and stream, and is sent again to late joiners. Each frame is
signed by its sender's device and sealed under a key derived from the
sender's current content state (keys.md). A relay sees an outer frame: the
space, the key reference, a handle, the size and the timing.

This module holds the encodings, the receiver's checks in their order, the
epoch and the replay window, the relay's table, and the vectors of
ext-ephemeral.json. Validity of the space's events is an input: the
membership verdict a receiver reaches from its own view is given to the
checks as a table.
"""

from __future__ import annotations

import hashlib
import hmac

import history_sigs as hs
import keygraph
from events import cbor, is_bytes, is_uint, uncbor
from formats import example, identifier_ok
from primitives import (
    SpecError,
    ed25519_public,
    ed25519_sign_deterministic,
    ed25519_valid,
    ed25519_verify_strict,
    field,
    hkdf,
    point_encode,
    small_order_points,
    xchacha20poly1305_open,
    xchacha20poly1305_seal,
)

# ---------------------------------------------------------------------------
# Labels and limits ("Labels and limits").

EPHEMERAL_KEY_LABEL = b"frasil/ephemeral-key/v1"
EPHEMERAL_LABEL = b"frasil/ephemeral/v1"
SLOT_LABEL = b"frasil/ephemeral-slot/v1"
NEW_LABELS: list[bytes] = [EPHEMERAL_KEY_LABEL, EPHEMERAL_LABEL, SLOT_LABEL]

VERSION = 1
KIND_MESSAGE, KIND_SLOT = 1, 2
KIND_NAMES = {KIND_MESSAGE: "ephemeral message", KIND_SLOT: "ephemeral slot"}

MAX_OUTER_BYTES = 24_576
PAD_BLOCK = 256
MAX_PLAINTEXT_BYTES = 18_432
MAX_DATA_BYTES = 16_384  # any signed record of at most 16,384 bytes
MAX_NAME_BYTES = 64
MAX_ADAPTER_BYTES = 64
MAX_TARGETS = 16
NONCE_BYTES = 24
TAG_BYTES = 16
HANDLE_BYTES = 16
STREAM_BYTES = 16
FRESH_NONCE_BYTES = 16
SIGNATURE_BYTES = 64
REPLAY_WINDOW = 64
RECENT_NONCES = 4
MAX_SLOTS_PER_SENDER = 32
RECEIVER_SLOTS_PER_SENDER = 32  # held at a receiver per space and sender, cleared ones included
RECEIVER_SLOTS_PER_SPACE = 2_048  # held at a receiver per space, cleared ones included
RELAY_SLOTS_PER_CONNECTION = 64
SEND_QUEUE = 64
RELAY_WINDOW = 64  # a relaying member's relay window per space and sender
MAX_LIST_EVENTS = 16
ORIGIN_BYTES = 8
U64_MAX = 2**64 - 1
EPOCH_RESTORE_STEP = 2**32
# The two timers (overview.md, "Every timer"), in seconds, monotonic.
EPHEMERAL_SEND_DEADLINE = 2
EPHEMERAL_KEY_WAIT = 5

RESERVED_PREFIX = "frasil/"
# "Frasil's names": each reserved name's kind, whether it is targeted
# (True: required; False: none; a slot has none), and its data's rule.
RESERVED_NAMES = {
    "frasil/nonce": KIND_SLOT,              # the sender's receiver nonce, 16 bytes
    "frasil/endpoint": KIND_SLOT,           # a member ticket (transport.md, tickets)
    "frasil/heads": KIND_SLOT,              # the sender's signed head statement (units.md)
    "frasil/leave": KIND_MESSAGE,           # empty; clears every ephemeral slot of the sender
    "frasil/access-request": KIND_MESSAGE,  # a signed access request (admission.md)
    "frasil/leave-request": KIND_MESSAGE,   # a signed leave request (ext-guests.md)
    "frasil/list-events": KIND_MESSAGE,     # {1: space ID, 2: 1 to 16 signed list events}
}
TARGETED_NAMES = {"frasil/access-request", "frasil/leave-request", "frasil/list-events"}
EXTENSION_NAMES = {"frasil/leave-request": "ext-guests"}

# Inner keys ("The inner map").
(I_VERSION, I_KIND, I_SENDER, I_EPOCH, I_COUNTER, I_NAME, I_STREAM, I_TARGETS, I_FRESH,
 I_ADAPTER, I_DATA) = range(1, 12)
# Outer keys ("The outer frame").
O_VERSION, O_KIND, O_SPACE, O_REFERENCE, O_HANDLE, O_SEALED = range(1, 7)


def h(value: bytes) -> str:
    return value.hex()


def u16be(value: int) -> bytes:
    return value.to_bytes(2, "big")


# ---------------------------------------------------------------------------
# Keys ("The ephemeral key", "The ephemeral slot handle").


def ephemeral_key(content_key: bytes) -> bytes:
    """HKDF(salt = none, ikm = k(S), info = "frasil/ephemeral-key/v1"); for a
    restricted space, ikm is its content key k_F (ext-restricted-spaces.md)."""
    return hkdf(keygraph.NO_SALT, content_key, EPHEMERAL_KEY_LABEL)


def slot_handle(ek: bytes, sender: bytes, name: str, stream: bytes | None) -> bytes:
    message = SLOT_LABEL + sender + field(name.encode()) + field(stream or b"")
    return hmac.new(ek, message, hashlib.sha256).digest()[:HANDLE_BYTES]


# ---------------------------------------------------------------------------
# The inner map ("The inner map").


def name_ok(name) -> bool:
    if not isinstance(name, str):
        return False
    raw = name.encode()
    return 1 <= len(raw) <= MAX_NAME_BYTES and identifier_ok(name)


def adapter_ok(adapter) -> bool:
    """An adapter type (units.md): 1 to 64 bytes, each 0x21 to 0x7e."""
    return (isinstance(adapter, str) and 1 <= len(adapter.encode()) <= MAX_ADAPTER_BYTES
            and all(0x21 <= ord(c) <= 0x7E for c in adapter))


def encode_inner(m: dict) -> bytes:
    """Build the inner map from named fields. Validation is read_inner's."""
    out = {I_VERSION: m.get("version", VERSION), I_KIND: m["kind"], I_SENDER: m["sender"],
           I_EPOCH: m["epoch"], I_COUNTER: m["counter"], I_NAME: m["name"],
           I_DATA: m.get("data", b"")}
    if m.get("stream") is not None:
        out[I_STREAM] = m["stream"]
    if m.get("targets") is not None:
        out[I_TARGETS] = list(m["targets"])
    if m.get("fresh") is not None:
        out[I_FRESH] = [list(p) for p in m["fresh"]]
    if m.get("adapter") is not None:
        out[I_ADAPTER] = m["adapter"]
    return cbor(out)


def read_inner(data: bytes) -> dict:
    """"Receiving", step 7: the inner map's rules (the comparison with the
    outer kind is the caller's)."""
    value = uncbor(data)
    if not isinstance(value, dict) or not is_uint(value.get(I_VERSION)):
        raise SpecError("Malformed")
    if value[I_VERSION] != VERSION:
        raise SpecError("UnsupportedVersion")
    if not set(value) <= set(range(1, 12)):
        raise SpecError("Malformed")
    for key in (I_KIND, I_SENDER, I_EPOCH, I_COUNTER, I_NAME, I_DATA):
        if key not in value:
            raise SpecError("Malformed")
    kind = value[I_KIND]
    if kind not in (KIND_MESSAGE, KIND_SLOT):
        raise SpecError("Malformed")
    if not is_bytes(value[I_SENDER], 64):
        raise SpecError("Malformed")
    for key in (I_EPOCH, I_COUNTER):
        if not is_uint(value[key]) or not 1 <= value[key] <= U64_MAX:
            raise SpecError("Malformed")
    if not name_ok(value[I_NAME]):
        raise SpecError("Malformed")
    data = value[I_DATA]
    if not is_bytes(data) or len(data) > MAX_DATA_BYTES:
        raise SpecError("Malformed")
    stream = value.get(I_STREAM)
    if stream is not None and (not is_bytes(stream, STREAM_BYTES) or stream == bytes(STREAM_BYTES)):
        raise SpecError("Malformed")
    adapter = value.get(I_ADAPTER)
    if adapter is not None and not adapter_ok(adapter):
        raise SpecError("Malformed")
    targets = value.get(I_TARGETS)
    fresh = value.get(I_FRESH)
    if kind == KIND_SLOT and (targets is not None or fresh is not None):
        raise SpecError("Malformed")  # targets are for ephemeral messages only
    if targets is not None:
        if (not isinstance(targets, list) or not 1 <= len(targets) <= MAX_TARGETS
                or not all(is_bytes(t, 32) for t in targets)
                or any(a >= b for a, b in zip(targets, targets[1:]))):
            raise SpecError("Malformed")
    if fresh is not None:
        if targets is None or not isinstance(fresh, list) or not 1 <= len(fresh) <= MAX_TARGETS:
            raise SpecError("Malformed")
        devices = []
        for pair in fresh:
            if (not isinstance(pair, list) or len(pair) != 2 or not is_bytes(pair[0], 32)
                    or not is_bytes(pair[1], FRESH_NONCE_BYTES)):
                raise SpecError("Malformed")
            devices.append(pair[0])
        if any(a >= b for a, b in zip(devices, devices[1:])) or not set(devices) <= set(targets):
            raise SpecError("Malformed")
    name = value[I_NAME]
    return {"version": value[I_VERSION], "kind": kind, "sender": value[I_SENDER],
            "epoch": value[I_EPOCH], "counter": value[I_COUNTER], "name": name,
            "stream": stream, "targets": targets,
            "fresh": None if fresh is None else [tuple(p) for p in fresh],
            "adapter": adapter, "data": data}


# ---------------------------------------------------------------------------
# Signing, padding and sealing ("The signature and the seal", "The outer
# frame").


def signing_input(space: bytes, reference: bytes, handle: bytes | None, inner: bytes) -> bytes:
    return EPHEMERAL_LABEL + field(space) + field(reference) + field(handle or b"") + inner


def seal_aad(space: bytes, reference: bytes, kind: int, handle: bytes | None) -> bytes:
    return EPHEMERAL_LABEL + field(space) + field(reference) + bytes([kind]) + field(handle or b"")


def pad(core: bytes) -> bytes:
    body = u16be(len(core)) + core
    return body + bytes(-len(body) % PAD_BLOCK)


def unpad(plaintext: bytes) -> bytes:
    if len(plaintext) % PAD_BLOCK or not PAD_BLOCK <= len(plaintext) <= MAX_PLAINTEXT_BYTES:
        raise SpecError("Malformed")
    length = int.from_bytes(plaintext[:2], "big")
    if length < 1 or 2 + length > len(plaintext):
        raise SpecError("Malformed")
    if any(plaintext[2 + length:]) or len(plaintext) - 2 - length >= PAD_BLOCK:
        raise SpecError("Malformed")  # zeros only, and fewer than one block of them
    return plaintext[2:2 + length]


def encode_outer(kind: int, space: bytes, reference: bytes, handle: bytes | None,
                 sealed: bytes, version: int = VERSION) -> bytes:
    out = {O_VERSION: version, O_KIND: kind, O_SPACE: space, O_REFERENCE: reference,
           O_SEALED: sealed}
    if handle is not None:
        out[O_HANDLE] = handle
    return cbor(out)


def build(m: dict, space: bytes, reference: bytes, content_key: bytes, seed: bytes,
          nonce: bytes) -> dict:
    """A sender's whole construction, with every intermediate value."""
    ek = ephemeral_key(content_key)
    inner = encode_inner(m)
    handle = (slot_handle(ek, m["sender"], m["name"], m.get("stream"))
              if m["kind"] == KIND_SLOT else None)
    tbs = signing_input(space, reference, handle, inner)
    signature = ed25519_sign_deterministic(seed, tbs)
    core = cbor([inner, signature])
    plaintext = pad(core)
    aad = seal_aad(space, reference, m["kind"], handle)
    sealed = nonce + xchacha20poly1305_seal(ek, nonce, plaintext, aad)
    outer = encode_outer(m["kind"], space, reference, handle, sealed)
    return {"ephemeral_key": ek, "inner": inner, "handle": handle, "signing_input": tbs,
            "signature": signature, "core": core, "plaintext": plaintext, "aad": aad,
            "nonce": nonce, "sealed": sealed, "outer": outer}


def reseal(plaintext: bytes, kind: int, space: bytes, reference: bytes, ek: bytes,
           handle: bytes | None, nonce: bytes) -> bytes:
    """Seal a given plaintext as an honest sender would (for refused frames)."""
    aad = seal_aad(space, reference, kind, handle)
    return encode_outer(kind, space, reference, handle,
                        nonce + xchacha20poly1305_seal(ek, nonce, plaintext, aad))


# ---------------------------------------------------------------------------
# Epoch, counter and replay ("Epoch, counter and replay").


class Sender:
    """A device's epoch, per device in at-rest.md's epoch table, and its
    counters, per space. `start` begins a run: it reads e and commits e + 1.
    `restore` begins a run after a restore or with no epoch record: the
    stored epoch (0 if none) plus 2^32 plus a random number below 2^32."""

    def __init__(self, stored: int | None = None):
        self.stored = stored
        self.epoch: int | None = None
        self.counters: dict[bytes, int] = {}

    def start(self) -> int:
        assert self.stored is not None, "with no epoch record, a device restores"
        self.epoch = self.stored + 1
        self.stored = self.epoch
        self.counters = {}
        return self.epoch

    def restore(self, random32: int) -> int:
        assert 0 <= random32 < EPOCH_RESTORE_STEP
        self.epoch = (self.stored or 0) + EPOCH_RESTORE_STEP + random32
        self.stored = self.epoch
        self.counters = {}
        return self.epoch

    def send(self, space: bytes) -> tuple[int, int]:
        """The (epoch, counter) of the next ephemeral message or ephemeral
        slot value in `space`: counter 1 at the start of each epoch."""
        assert self.epoch is not None
        self.counters[space] = self.counters.get(space, 0) + 1
        return self.epoch, self.counters[space]


def _slot_order(key: tuple) -> tuple:
    """Of equal marks, the lowest name by its bytes, then stream, absent
    first ("Epoch, counter and replay", bounds)."""
    return (key[2].encode(), key[3] is not None, key[3] or b"")


class ReplayState:
    """Per space and sender: the ephemeral message window, the highest
    epoch accepted, and the floor; per (sender, name, stream): the held
    ephemeral slot value's (epoch, counter). In memory; a receiver may keep
    the window in the replay table. At most 32 ephemeral slots per space and
    sender and 2,048 per space are held, cleared ones included; a forgotten
    one raises its sender's floor, below which a value for an ephemeral slot
    not held is Replayed."""

    def __init__(self):
        self.window: dict = {}  # (space, sender) -> (epoch, max counter, frozenset seen)
        self.slots: dict = {}   # (space, sender, name, stream) -> (epoch, counter, data)
        self.floors: dict = {}  # (space, sender) -> (epoch, counter), the highest forgotten
        self.epochs: dict = {}  # (space, sender) -> the highest epoch accepted

    def floor(self, space: bytes, sender: bytes) -> tuple:
        return self.floors.get((space, sender), (0, 0))

    def held_by(self, space: bytes, sender: bytes) -> list:
        return [k for k in self.slots if k[0] == space and k[1] == sender]

    def held_in(self, space: bytes) -> list:
        return [k for k in self.slots if k[0] == space]

    def _raise_floor(self, space: bytes, sender: bytes, mark: tuple) -> None:
        self.floors[(space, sender)] = max(self.floor(space, sender), mark)

    def _forget(self, key: tuple) -> None:
        held = self.slots.pop(key)
        self._raise_floor(key[0], key[1], held[:2])

    def _victim(self, keys: list) -> tuple:
        """Of one sender's: the cleared one with the lowest (epoch, counter),
        or, with none cleared, the one with the lowest."""
        cleared = [k for k in keys if not self.slots[k][2]]
        return min(cleared or keys, key=lambda k: (self.slots[k][:2], _slot_order(k)))

    def _accepted_epoch(self, space: bytes, sender: bytes, epoch: int) -> None:
        """A frame of either kind accepted under `epoch`: under a higher one
        than any before, the sender's ephemeral slots of lower epochs are
        forgotten and its floor raised to at least (epoch, 0)."""
        if epoch <= self.epochs.get((space, sender), 0):
            return
        self.epochs[(space, sender)] = epoch
        for key in self.held_by(space, sender):
            if self.slots[key][0] < epoch:
                del self.slots[key]
        self._raise_floor(space, sender, (epoch, 0))

    def message_ok(self, space: bytes, sender: bytes, epoch: int, counter: int) -> bool:
        held = self.window.get((space, sender))
        if held is None or epoch > held[0]:
            return True
        if epoch < held[0]:
            return False
        _, top, seen = held
        if counter > top:
            return True
        return top - counter < REPLAY_WINDOW and counter not in seen

    def accept_message(self, space: bytes, sender: bytes, epoch: int, counter: int) -> None:
        self._accepted_epoch(space, sender, epoch)
        held = self.window.get((space, sender))
        if held is None or epoch > held[0]:
            self.window[(space, sender)] = (epoch, counter, frozenset({counter}))
            return
        _, top, seen = held
        top = max(top, counter)
        seen = frozenset(c for c in seen | {counter} if top - c < REPLAY_WINDOW)
        self.window[(space, sender)] = (epoch, top, seen)

    def slot_ok(self, key: tuple, epoch: int, counter: int) -> bool:
        held = self.slots.get(key)
        if held is not None:
            return (epoch, counter) > held[:2]
        return (epoch, counter) > self.floor(key[0], key[1])

    def accept_slot(self, key: tuple, epoch: int, counter: int, data: bytes) -> None:
        # A cleared slot keeps its mark, so an older value cannot return; a
        # forgotten one raises the floor, for the same reason.
        space, sender = key[0], key[1]
        self._accepted_epoch(space, sender, epoch)
        if key not in self.slots:
            mine = self.held_by(space, sender)
            if len(mine) >= RECEIVER_SLOTS_PER_SENDER:
                self._forget(self._victim(mine))
            in_space = self.held_in(space)
            if len(in_space) >= RECEIVER_SLOTS_PER_SPACE:
                counts: dict = {}
                for k in in_space:
                    counts[k[1]] = counts.get(k[1], 0) + 1
                most = max(counts.values())
                who = min(s for s, c in counts.items() if c == most)
                self._forget(self._victim([k for k in in_space if k[1] == who]))
        self.slots[key] = (epoch, counter, data)

    def drop_sender(self, space: bytes, sender: bytes) -> None:
        """"Membership against the current view": every ephemeral slot of a
        sender whose membership ended is forgotten, its floor raised."""
        for key in self.held_by(space, sender):
            self._forget(key)

    def drop_space(self, space: bytes) -> None:
        """A space the receiver no longer follows: all of it is forgotten."""
        for table in (self.window, self.floors, self.epochs):
            for key in [k for k in table if k[0] == space]:
                del table[key]
        for key in self.held_in(space):
            del self.slots[key]

    def clear_sender(self, space: bytes, sender: bytes, epoch: int, counter: int) -> None:
        """A frasil/leave: each held ephemeral slot of its sender is cleared
        as if with the leave's (epoch, counter)."""
        for key in [k for k in self.slots if k[0] == space and k[1] == sender]:
            if self.slot_ok(key, epoch, counter):
                self.accept_slot(key, epoch, counter, b"")


# ---------------------------------------------------------------------------
# The reserved names ("Frasil's names").


def check_reserved(m: dict, space: bytes, implements=None) -> None:
    """"Receiving", step 11: a frasil/ name is one this receiver implements
    (else UnknownName), with its kind, targets, stream, adapter and data as
    the table says (else Malformed). What a record does is its own
    document's; the frame's verdict is decided here."""
    name = m["name"]
    if not name.startswith(RESERVED_PREFIX):
        return
    if name not in RESERVED_NAMES:
        raise SpecError("UnknownName")
    extension = EXTENSION_NAMES.get(name)
    if extension is not None and implements is not None and extension not in implements:
        raise SpecError("UnknownName")
    if m["kind"] != RESERVED_NAMES[name] or m["stream"] is not None             or m["adapter"] is not None:
        raise SpecError("Malformed")
    if (m["targets"] is not None) != (name in TARGETED_NAMES):
        raise SpecError("Malformed")
    data = m["data"]
    if name == "frasil/nonce" and len(data) != FRESH_NONCE_BYTES:
        raise SpecError("Malformed")
    if name == "frasil/leave" and data:
        raise SpecError("Malformed")
    if name == "frasil/list-events":
        try:
            body = uncbor(data)
        except SpecError:
            raise SpecError("Malformed") from None
        if (not isinstance(body, dict) or set(body) != {1, 2} or body[1] != space
                or not isinstance(body[2], list) or not 1 <= len(body[2]) <= MAX_LIST_EVENTS
                or not all(is_bytes(e) for e in body[2])):
            raise SpecError("Malformed")


# ---------------------------------------------------------------------------
# The receiver's checks, in order ("Receiving").


# The step of "Receiving" the last call of `receive` or `read_outer` was
# at, so that a refusal's vector can be checked against its step.
STEP = [0]


def read_outer(outer: bytes, scope: bytes | None) -> tuple:
    """"Receiving", steps 1 and 2, which a relay runs too: the size, then
    the outer map, whose space is the scope's."""
    # 1. Size.
    STEP[0] = 1
    if len(outer) > MAX_OUTER_BYTES:
        raise SpecError("TooLarge")
    # 2. The outer map.
    STEP[0] = 2
    value = uncbor(outer)
    if not isinstance(value, dict) or not is_uint(value.get(O_VERSION)):
        raise SpecError("Malformed")
    if value[O_VERSION] != VERSION:
        raise SpecError("UnsupportedVersion")
    if (not set(value) <= set(range(1, 7))
            or not {O_KIND, O_SPACE, O_REFERENCE, O_SEALED} <= set(value)):
        raise SpecError("Malformed")
    kind, space = value[O_KIND], value[O_SPACE]
    reference, sealed, handle = value[O_REFERENCE], value[O_SEALED], value.get(O_HANDLE)
    if kind not in (KIND_MESSAGE, KIND_SLOT) or not is_bytes(space, 32) or not is_bytes(reference):
        raise SpecError("Malformed")
    if scope is not None and space != scope:
        raise SpecError("Malformed")
    if (kind == KIND_SLOT) != (handle is not None) or (
            handle is not None and not is_bytes(handle, HANDLE_BYTES)):
        raise SpecError("Malformed")
    if not is_bytes(sealed) or len(sealed) < NONCE_BYTES + PAD_BLOCK + TAG_BYTES:
        raise SpecError("Malformed")
    return kind, space, reference, handle, sealed


def receive(outer: bytes, ctx: dict) -> dict:
    """ctx: own (its device ID); scope: the space the Ephemeral message was
    sent for; spaces: {space: {"restricted": bool, "keys": {reference
    bytes: content key}, "known": set of rotation ids}}, the spaces it
    follows; membership: {sender device ID: verdict}; nonces: recent receiver nonces;
    fresh_only: names that require a fresh entry; adapters: {type: check};
    grants: {sender: effective grant}; implements: the extensions it
    implements; replay: ReplayState. Returns the accepted frame's inner
    fields, or raises the class."""
    kind, space, m, device = judge(outer, ctx)
    # 13. Targets.
    STEP[0] = 13
    if m["targets"] is not None and ctx["own"] not in m["targets"]:
        raise SpecError("NotTargeted")
    # 14. Freshness.
    STEP[0] = 14
    mine = [n for d, n in (m["fresh"] or []) if d == ctx["own"]]
    if mine and mine[0] not in ctx.get("nonces", []):
        raise SpecError("Stale")
    if not mine and m["name"] in ctx.get("fresh_only", ()):
        raise SpecError("Stale")
    # 15. Replay, and the floor.
    STEP[0] = 15
    replay: ReplayState = ctx["replay"]
    slot_key = (space, device, m["name"], m["stream"])
    if kind == KIND_MESSAGE:
        if not replay.message_ok(space, device, m["epoch"], m["counter"]):
            raise SpecError("Replayed")
    elif not replay.slot_ok(slot_key, m["epoch"], m["counter"]):
        raise SpecError("Replayed")
    # 16. The adapter's capability checks (units.md's check interface).
    STEP[0] = 16
    if m["adapter"] is not None:
        check = ctx.get("adapters", {}).get(m["adapter"])
        if check is None:
            raise SpecError("UnknownAdapter")
        if not check(m, ctx.get("grants", {}).get(device, {})):
            raise SpecError("CapabilityRefused")
    # 17. Accepted.
    STEP[0] = 17
    if kind == KIND_MESSAGE:
        replay.accept_message(space, device, m["epoch"], m["counter"])
        if m["name"] == "frasil/leave":
            replay.clear_sender(space, device, m["epoch"], m["counter"])
    else:
        replay.accept_slot(slot_key, m["epoch"], m["counter"], m["data"])
    return m


def judge(outer: bytes, ctx: dict) -> tuple:
    """"Receiving", steps 1 to 12, which a relaying member runs on each
    frame before its relay window: (kind, space, the inner fields, the
    sender's device ID), or raises the class."""
    kind, space, reference, handle, sealed = read_outer(outer, ctx.get("scope"))
    # 3. A space this receiver follows.
    STEP[0] = 3
    info = ctx["spaces"].get(space)
    if info is None:
        raise SpecError("NotFollowing")
    # 4. The key reference reads (Malformed or TooManyRotations), and the
    STEP[0] = 4
    # receiver holds every rotation it names and k(S).
    if info.get("restricted"):
        own, _, _ = keygraph.read_restricted_reference(reference)
        rotations = set(own)
    else:
        rotations = set(keygraph.decode_set(reference))
    if not rotations <= info["known"] or reference not in info["keys"]:
        raise SpecError("Sealed")
    ek = ephemeral_key(info["keys"][reference])
    # 5. Open.
    STEP[0] = 5
    plaintext = xchacha20poly1305_open(ek, sealed[:NONCE_BYTES], sealed[NONCE_BYTES:],
                                       seal_aad(space, reference, kind, handle))
    # 6. Padding and the core.
    STEP[0] = 6
    core = uncbor(unpad(plaintext))
    if (not isinstance(core, list) or len(core) != 2 or not is_bytes(core[0])
            or not is_bytes(core[1], SIGNATURE_BYTES)):
        raise SpecError("Malformed")
    inner_bytes, signature = core
    # 7. The inner map.
    STEP[0] = 7
    m = read_inner(inner_bytes)
    if m["kind"] != kind:
        raise SpecError("Malformed")
    # 8. The slot handle.
    STEP[0] = 8
    if kind == KIND_SLOT and handle != slot_handle(ek, m["sender"], m["name"], m["stream"]):
        raise SpecError("WrongHandle")
    # 9. The sender's ed and the signature under it.
    STEP[0] = 9
    ed, _, device = hs.split_signer(m["sender"])
    if not ed25519_valid(ed):
        raise SpecError("InvalidKey")
    if not ed25519_verify_strict(ed, signing_input(space, reference, handle, inner_bytes),
                                 signature):
        raise SpecError("BadSignature")
    # 10. Its own frames, echoed back: the sender's device ID is its own.
    STEP[0] = 10
    if device == ctx["own"]:
        raise SpecError("Own")
    # 11. Reserved names.
    STEP[0] = 11
    check_reserved(m, space, ctx.get("implements"))
    # 12. Membership, against the receiver's current view.
    STEP[0] = 12
    verdict = ctx["membership"].get(device, "NotAMember")
    if verdict != "in":
        # "Membership against the current view": the end shows; the
        # sender's ephemeral slots are forgotten.
        if verdict in ("MembershipEnded", "Forked", "NotAMember"):
            ctx["replay"].drop_sender(space, device)
        raise SpecError(verdict)
    return kind, space, m, device


def expect_class(function, *args) -> str:
    try:
        function(*args)
    except SpecError as error:
        return error.error
    raise AssertionError("accepted")


# ---------------------------------------------------------------------------
# Relaying ("Relaying").


class Relay:
    """An always-on peer's view of one space's channel: it holds no keys and
    checks only steps 1 and 2 of "Receiving". It draws an origin per
    connection and space; keeps, per connection and handle, the latest
    ephemeral slot frame that connection sent, at most 64; sends them, with
    their origins, to a connection that joins; forwards each frame with its
    sender's origin; and on a close or a lost live right drops that
    connection's frames and sends Gone with its origin. Ephemeral messages
    are forwarded once and never held."""

    def __init__(self, space: bytes):
        self.space = space
        self.joined: list = []
        self.origins: dict = {}
        self.held: dict = {}  # connection -> {handle: outer}, in arrival order

    def origin(self, connection: str) -> bytes:
        """8 random bytes per connection and space, never derived from the
        connection's credentials; here drawn from a fixed input."""
        if connection not in self.origins:
            self.origins[connection] = example(
                f"ephemeral/origin {h(self.space)} {connection}")[:ORIGIN_BYTES]
        return self.origins[connection]

    def join(self, connection: str) -> list:
        if connection in self.joined:
            return []
        self.joined.append(connection)
        self.origin(connection)
        out = []
        for sender, slots in self.held.items():
            if sender != connection:
                out += [{"to": connection, "origin": h(self.origins[sender]),
                         "frame": "ephemeral slot", "handle": h(hd)} for hd in slots]
        return out

    def frame(self, connection: str, outer: bytes) -> list:
        _, _, _, handle, _ = read_outer(outer, self.space)
        out = self.join(connection)  # the first Ephemeral joins, as a Subscribe does
        if handle is not None:
            slots = self.held.setdefault(connection, {})
            slots.pop(handle, None)
            slots[handle] = outer
            while len(slots) > RELAY_SLOTS_PER_CONNECTION:
                slots.pop(next(iter(slots)))
        kind = KIND_NAMES[KIND_SLOT if handle is not None else KIND_MESSAGE]
        extra = {"handle": h(handle)} if handle is not None else {}
        return out + [{"to": c, "origin": h(self.origins[connection]), "frame": kind, **extra}
                      for c in self.joined if c != connection]

    def leave(self, connection: str) -> list:
        """A close, or a lost live right."""
        self.held.pop(connection, None)
        if connection in self.joined:
            self.joined.remove(connection)
        return [{"to": c, "gone": h(self.origins[connection])} for c in self.joined]


class MemberRelay:
    """A member that relays frames between other members ("Relaying", a
    member). It forwards a frame only if steps 1 to 12 of "Receiving" pass
    and its relay window, per space and sender over both kinds, accepts the
    frame's (epoch, counter), which it then records; on its member
    connections only, never on the one the frame came on, never to a peer,
    with no origin. Its own verdict, by "Receiving" with its own replay
    state, is apart and decides nothing about forwarding."""

    def __init__(self, ctx: dict, links: list, window: bool = True):
        self.ctx = ctx          # its receiver context, as for `receive`
        self.links = links      # the members at the other end of its member connections
        self.window = window    # False only to show the loop without one
        self.forwarded = ReplayState()  # its relay windows, by message_ok and accept_message

    def forward(self, outer: bytes, came_from: str) -> list:
        """The members it forwards the frame to, or raises the class."""
        _, space, m, device = judge(outer, self.ctx)
        if self.window:
            if not self.forwarded.message_ok(space, device, m["epoch"], m["counter"]):
                raise SpecError("Replayed")
            self.forwarded.accept_message(space, device, m["epoch"], m["counter"])
        return [link for link in self.links if link != came_from]

    def verdict(self, outer: bytes) -> str:
        try:
            receive(outer, self.ctx)
            return "accepted"
        except SpecError as error:
            return error.error


def ring(members: dict, sender: str, first: str, outer: bytes, limit: int = 1_000) -> list:
    """Delivers a frame through relaying members, first in, first out: the
    sender gives it to `first`, and each member forwards what it may. Ends
    when nothing is left to deliver, or after `limit` deliveries."""
    queue = [(first, sender)]
    out = []
    while queue and len(out) < limit:
        to, came_from = queue.pop(0)
        member = members[to]
        verdict = member.verdict(outer)
        try:
            onward = member.forward(outer, came_from)
            out.append({"to": to, "from": came_from, "forwarded_to": onward,
                        "own_verdict": verdict})
            # Only relaying members pass it on; the sender, at the end of a
            # member connection, receives it as its own.
            queue += [(link, to) for link in onward if link in members]
        except SpecError as error:
            out.append({"to": to, "from": came_from, "refused": error.error,
                        "own_verdict": verdict})
    return out


# ---------------------------------------------------------------------------
# Vectors.

SPACE = example("ephemeral/space")
RESTRICTED = example("ephemeral/restricted space")
ROT = {n: example(f"ephemeral/rotation {n}") for n in "ABC"}
SECRET = {n: example(f"ephemeral/content key {n}") for n in "ABC"}
DEVICE_NAMES = ("alice", "bob", "carol", "dave", "erin", "mallory")
SEEDS = {n: example(f"ephemeral/device {n}") for n in DEVICE_NAMES}
# Each device's keys by crypto.md's fixture derivations: KEYS, its `ed || kc`
# as an inner map's `sender` carries it; IDS, its device ID.
SIGNERS = {n: hs.fixture_signer(s, n) for n, s in SEEDS.items()}
KEYS = {n: k.signer_bytes for n, k in SIGNERS.items()}
IDS = {n: k.device_id for n, k in SIGNERS.items()}
STREAM = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
CUES = "com.example.cues"


def nonce(name: str) -> bytes:
    return example(f"ephemeral/nonce {name}")[:NONCE_BYTES]


def receiver_nonce(name: str) -> bytes:
    return example(f"ephemeral/receiver nonce {name}")[:FRESH_NONCE_BYTES]


def _states() -> dict:
    ab = keygraph.canonical([ROT["A"], ROT["B"]])
    by_id = {ROT["A"]: SECRET["A"], ROT["B"]: SECRET["B"]}
    k_ab = keygraph.content_key(SPACE, ab, lambda r: by_id[r])
    f_c = SECRET["C"]
    k_f = keygraph.restricted_key(RESTRICTED, SPACE, f_c, k_ab)["key"]
    ref_f = keygraph.seal_restricted_reference(RESTRICTED, (ROT["C"],), ab, f_c,
                                               nonce("parent reference"))
    return {"ab": ab, "ref_ab": keygraph.encode_set(ab), "k_ab": k_ab,
            "ref_a": keygraph.encode_set([ROT["A"]]), "k_a": SECRET["A"],
            "ref_b": keygraph.encode_set([ROT["B"]]), "k_b": SECRET["B"],
            "ref_f": ref_f, "k_f": k_f, "f_c": f_c}


def _message(name: str, kind: int, sender: str, epoch: int, counter: int, **extra) -> dict:
    m = {"kind": kind, "sender": KEYS[sender], "epoch": epoch, "counter": counter, "name": name}
    m.update(extra)
    return m


def _cues_check(m: dict, grant: dict) -> bool:
    return "drive" in grant.get("capabilities", ())


def _context(st: dict, replay: ReplayState | None = None, **over) -> dict:
    ctx = {
        "own": IDS["bob"],
        "scope": SPACE,
        "spaces": {
            SPACE: {"restricted": False, "known": {ROT["A"], ROT["B"]},
                    "keys": {st["ref_ab"]: st["k_ab"], st["ref_a"]: st["k_a"]}},
            RESTRICTED: {"restricted": True, "known": {ROT["C"]}, "keys": {st["ref_f"]: st["k_f"]}},
        },
        "membership": {IDS["alice"]: "in", IDS["carol"]: "in", IDS["erin"]: "in",
                       IDS["dave"]: "MembershipEnded", IDS["mallory"]: "NotAMember"},
        "grants": {IDS["alice"]: {"level": "write", "capabilities": ["drive"]},
                   IDS["erin"]: {"level": "write", "capabilities": []}},
        "nonces": [receiver_nonce("bob 2"), receiver_nonce("bob 1")],
        "fresh_only": ["com.example.go"],
        "adapters": {"frasil:loro": lambda m, g: True, CUES: _cues_check},
        "implements": ["ext-guests"],
        "replay": replay if replay is not None else ReplayState(),
    }
    ctx.update(over)
    return ctx


def _fields_json(m: dict) -> dict:
    out = {}
    for k, v in m.items():
        if k == "targets" and v is not None:
            out[k] = [h(x) for x in v]
        elif k == "fresh" and v is not None:
            out[k] = [[h(d), h(n)] for d, n in v]
        elif k == "kind":
            out[k] = KIND_NAMES[v]
        elif isinstance(v, bytes):
            out[k] = h(v)
        else:
            out[k] = v
    return out


def _case(description: str, built: dict, m: dict, space: bytes, reference: bytes) -> dict:
    out = {"description": description, "space": h(space), "key_reference": h(reference),
           "fields": _fields_json(m),
           "ephemeral_key": h(built["ephemeral_key"]), "inner": h(built["inner"]),
           "tbs": h(built["signing_input"]), "signature": h(built["signature"]),
           "core": h(built["core"]), "plaintext": h(built["plaintext"]),
           "aad": h(built["aad"]), "nonce": h(built["nonce"]), "outer": h(built["outer"]),
           "outer_bytes": len(built["outer"])}
    if built["handle"] is not None:
        out["handle"] = h(built["handle"])
    return out


# Stands in for one signed device-list event (identity.md): the channel
# carries its bytes opaquely, and the writer checks them.
LIST_EVENT = bytes.fromhex("82") + b"\x59\x27\x10" + bytes(10_000) + b"\x58\x40" + bytes(64)
LIST_EVENTS_BODY = cbor({1: SPACE, 2: [LIST_EVENT]})
ENDPOINT_TICKET = bytes.fromhex("a4010102015820") + bytes(32) + bytes.fromhex("0380")


def _encoding_specs(st: dict) -> list:
    return [
        ("a broadcast cursor in one document", SPACE, st["ref_ab"], st["k_ab"], "alice",
         _message("com.example.cursor", KIND_MESSAGE, "alice", 3, 41, stream=STREAM,
                  adapter="frasil:loro", data=bytes.fromhex("a2016a706172616772617068021903e8"))),
        ("a targeted command with fresh entries, to two devices", SPACE, st["ref_ab"],
         st["k_ab"], "alice",
         _message("com.example.go", KIND_MESSAGE, "alice", 3, 42, adapter=CUES,
                  targets=sorted([IDS["bob"], IDS["carol"]]),
                  fresh=sorted([(IDS["bob"], receiver_nonce("bob 2")),
                                (IDS["carol"], receiver_nonce("carol 1"))]),
                  data=b"cue 12")),
        ("a presence ephemeral slot in one document", SPACE, st["ref_ab"], st["k_ab"], "alice",
         _message("com.example.presence", KIND_SLOT, "alice", 3, 43, stream=STREAM,
                  data="Alice, paragraph 4".encode())),
        ("the same ephemeral slot cleared: empty data", SPACE, st["ref_ab"], st["k_ab"], "alice",
         _message("com.example.presence", KIND_SLOT, "alice", 3, 44, stream=STREAM, data=b"")),
        ("frasil/endpoint: the sender's member ticket", SPACE,
         st["ref_ab"], st["k_ab"], "alice",
         _message("frasil/endpoint", KIND_SLOT, "alice", 3, 45, data=ENDPOINT_TICKET)),
        ("a restricted space's ephemeral message: its own state and its sealed parent state",
         RESTRICTED, st["ref_f"], st["k_f"], "alice",
         _message("com.example.cursor", KIND_MESSAGE, "alice", 3, 1, data=b"\x01")),
        ("an ephemeral message under an older state the receiver holds", SPACE, st["ref_a"],
         st["k_a"], "erin",
         _message("com.example.cursor", KIND_MESSAGE, "erin", 1, 7, data=b"\x02")),
        ("a reader's frasil/list-events, targeted at a writer", SPACE,
         st["ref_ab"], st["k_ab"], "carol",
         _message("frasil/list-events", KIND_MESSAGE, "carol", 2, 9, targets=[IDS["bob"]],
                  data=LIST_EVENTS_BODY)),
    ]


def encoding_vectors(st: dict) -> tuple[list, dict]:
    cases, outers = [], {}
    for i, (description, space, reference, key, sender, m) in enumerate(_encoding_specs(st)):
        built = build(m, space, reference, key, SEEDS[sender], nonce(f"case {i}"))
        cases.append(_case(description, built, m, space, reference))
        outers[i] = (built, m, space, reference, key)
    return cases, outers


def _bad_plaintext(st: dict, mutate) -> bytes:
    m = _message("com.example.cursor", KIND_MESSAGE, "alice", 3, 50, data=b"x")
    built = build(m, SPACE, st["ref_ab"], st["k_ab"], SEEDS["alice"], nonce("bad"))
    return reseal(mutate(built), KIND_MESSAGE, SPACE, st["ref_ab"], built["ephemeral_key"], None,
                  nonce("bad"))


def _signed_core(st: dict, inner: bytes, kind: int = KIND_MESSAGE, handle=None,
                 seed: bytes | None = None) -> bytes:
    """Sign and seal an inner map, as a sender would, whatever it holds."""
    ek = ephemeral_key(st["k_ab"])
    tbs = signing_input(SPACE, st["ref_ab"], handle, inner)
    core = cbor([inner, ed25519_sign_deterministic(seed or SEEDS["alice"], tbs)])
    return reseal(pad(core), kind, SPACE, st["ref_ab"], ek, handle, nonce("crafted"))


def frame_refusal_vectors(st: dict, outers: dict) -> list:
    base = outers[0][0]["outer"]
    value = uncbor(base)
    good = read_inner(outers[0][0]["inner"])
    out = []

    def add(step: int, description: str, outer: bytes, expected: str,
            ctx_over: dict | None = None, note: str | None = None):
        got = expect_class(receive, outer, _context(st, **(ctx_over or {})))
        assert (STEP[0], got) == (step, expected), (description, STEP[0], got, step, expected)
        case = {"step": step, "description": description, "outer": h(outer), "class": expected}
        if note:
            case["context"] = note
        out.append(case)

    def inner_with(**changes) -> bytes:
        m = {k: v for k, v in good.items() if v is not None}
        m.update(changes)
        return encode_inner({k: v for k, v in m.items() if v is not None})

    other_space = example("ephemeral/other space")
    add(1, "over 24,576 bytes",
        cbor({**value, O_SEALED: value[O_SEALED] + bytes(MAX_OUTER_BYTES)}), "TooLarge")
    add(2, "an outer map that is not deterministic CBOR (keys out of order)",
        bytes([0xa5]) + cbor(2) + cbor(1) + cbor(1) + cbor(1) + cbor(3) + cbor(SPACE)
        + cbor(4) + cbor(value[O_REFERENCE]) + cbor(6) + cbor(value[O_SEALED]), "Malformed")
    add(2, "outer version 2", cbor({**value, O_VERSION: 2}), "UnsupportedVersion")
    add(2, "an ephemeral message carrying a handle", cbor({**value, O_HANDLE: bytes(16)}),
        "Malformed")
    slot = uncbor(outers[2][0]["outer"])
    add(2, "an ephemeral slot without its handle",
        cbor({k: v for k, v in slot.items() if k != O_HANDLE}), "Malformed")
    add(2, "a space other than the one the Ephemeral message was sent for",
        cbor({**value, O_SPACE: RESTRICTED}), "Malformed",
        note="the receiver follows both spaces; the message's scope is the first")
    add(3, "a space the receiver does not follow",
        cbor({**value, O_SPACE: other_space}), "NotFollowing", {"scope": other_space},
        "the Ephemeral message was sent for that space")
    add(4, "a key reference that does not read", cbor({**value, O_REFERENCE: b"\x02" + ROT["A"]}),
        "Malformed")
    add(4, "a key reference naming 65 rotations",
        cbor({**value, O_REFERENCE: bytes([65]) + b"".join(
            example(f"ephemeral/rotation {i:02d}") for i in range(65))}), "TooManyRotations")
    add(4, "a key reference naming a rotation the receiver does not hold",
        cbor({**value, O_REFERENCE: keygraph.encode_set([example("ephemeral/rotation Z")])}),
        "Sealed")
    add(5, "the key reference moved to another state the receiver holds",
        cbor({**value, O_REFERENCE: st["ref_a"]}), "Decrypt")
    add(5, "the outer kind changed to an ephemeral slot, with a handle",
        cbor({**value, O_KIND: KIND_SLOT, O_HANDLE: bytes(16)}), "Decrypt")
    add(5, "a sealed byte changed",
        cbor({**value, O_SEALED: value[O_SEALED][:-1] + bytes([value[O_SEALED][-1] ^ 1])}),
        "Decrypt")
    add(6, "padding that is not zero",
        _bad_plaintext(st, lambda b: b["plaintext"][:-1] + b"\x01"), "Malformed")
    add(6, "a plaintext that is not a multiple of 256 bytes",
        _bad_plaintext(st, lambda b: b["plaintext"] + bytes(1)), "Malformed")
    add(6, "a whole block of padding too many",
        _bad_plaintext(st, lambda b: b["plaintext"] + bytes(PAD_BLOCK)), "Malformed")
    add(7, "inner kind 2 inside an ephemeral message frame",
        _signed_core(st, inner_with(kind=KIND_SLOT, stream=None, adapter=None)), "Malformed")
    add(7, "inner version 2", _signed_core(st, inner_with(version=2)), "UnsupportedVersion")
    add(7, "targets not in ascending order",
        _signed_core(st, inner_with(targets=sorted([IDS["bob"], IDS["carol"]], reverse=True))),
        "Malformed")
    add(7, "a fresh entry for a device that is not a target",
        _signed_core(st, inner_with(targets=[IDS["bob"]],
                                    fresh=[(IDS["carol"], receiver_nonce("carol 1"))])),
        "Malformed")
    add(7, "an empty name", _signed_core(st, inner_with(name="")), "Malformed")
    add(7, "a name with a control character",
        _signed_core(st, inner_with(name="com.example.\x07")), "Malformed")
    add(7, "data over 16,384 bytes", _signed_core(st, inner_with(data=bytes(MAX_DATA_BYTES + 1))),
        "Malformed")
    add(7, "counter 0", _signed_core(st, inner_with(counter=0)), "Malformed")
    add(7, "the all-zero stream", _signed_core(st, inner_with(stream=bytes(16))), "Malformed")
    add(7, "an adapter with a space", _signed_core(st, inner_with(adapter="frasil: loro")),
        "Malformed")
    slot_inner = encode_inner({"kind": KIND_SLOT, "sender": KEYS["alice"], "epoch": 3,
                               "counter": 60, "name": "com.example.presence", "stream": STREAM,
                               "data": b"x"})
    add(8, "an ephemeral slot whose handle is not its own",
        _signed_core(st, slot_inner, KIND_SLOT, handle=bytes(16)), "WrongHandle")
    small = point_encode(small_order_points()[1])
    add(9, "a small-order sender", _signed_core(st, inner_with(sender=small + SIGNERS["alice"].kc)),
        "InvalidKey")
    add(9, "signed by another device than the sender it names",
        _signed_core(st, inner_with(), seed=SEEDS["mallory"]), "BadSignature")
    add(10, "the receiver's own ephemeral message, echoed back",
        _signed_core(st, inner_with(sender=KEYS["bob"]), seed=SEEDS["bob"]), "Own")
    add(11, "an unknown frasil/ name", _signed_core(st, inner_with(name="frasil/unknown")),
        "UnknownName")
    add(11, "frasil/leave-request at a receiver without ext-guests",
        _signed_core(st, inner_with(name="frasil/leave-request", stream=None, adapter=None,
                                    targets=[IDS["bob"]])), "UnknownName",
        {"implements": []}, "the receiver does not implement ext-guests")
    add(11, "a reserved name of the wrong kind: frasil/nonce as an ephemeral message",
        _signed_core(st, inner_with(name="frasil/nonce", stream=None, adapter=None,
                                    data=receiver_nonce("alice 1"))), "Malformed")
    add(11, "a reserved name broadcast where it must be targeted: frasil/access-request",
        _signed_core(st, inner_with(name="frasil/access-request", stream=None, adapter=None)),
        "Malformed")
    add(11, "a reserved name with a stream: frasil/leave",
        _signed_core(st, inner_with(name="frasil/leave", adapter=None, data=b"")), "Malformed")
    add(11, "frasil/list-events naming another space",
        _signed_core(st, inner_with(name="frasil/list-events", stream=None, adapter=None,
                                    targets=[IDS["bob"]],
                                    data=cbor({1: other_space, 2: [LIST_EVENT]}))),
        "Malformed")
    add(12, "a sender whose membership ended in the receiver's view",
        _signed_core(st, inner_with(sender=KEYS["dave"]), seed=SEEDS["dave"]), "MembershipEnded")
    add(12, "a sender no record names",
        _signed_core(st, inner_with(sender=KEYS["mallory"]), seed=SEEDS["mallory"]),
        "NotAMember")
    add(12, "alice's Ed25519 key under another kc: another device, which no record names",
        _signed_core(st, inner_with(sender=SIGNERS["alice"].ed_public + SIGNERS["mallory"].kc)),
        "NotAMember")
    add(12, "a forked sender", _signed_core(st, inner_with()), "Forked",
        {"membership": {IDS["alice"]: "Forked"}}, "the receiver holds a fork of alice's chain")
    add(12, "a sender reached only through a list the receiver does not hold",
        _signed_core(st, inner_with()), "Unjudgeable",
        {"membership": {IDS["alice"]: "Unjudgeable"}}, "alice writes through a person grant")
    add(13, "targeted at another device", _signed_core(st, inner_with(targets=[IDS["carol"]])),
        "NotTargeted")
    add(14, "a fresh entry with a nonce the receiver no longer holds",
        _signed_core(st, inner_with(targets=[IDS["bob"]],
                                    fresh=[(IDS["bob"], receiver_nonce("bob 0"))])), "Stale")
    add(14, "a fresh-only name without a fresh entry",
        _signed_core(st, inner_with(name="com.example.go", targets=[IDS["bob"]])), "Stale")
    replayed = ReplayState()
    receive(base, _context(st, replayed))
    add(15, "the same ephemeral message a second time", base, "Replayed",
        {"replay": replayed}, "the receiver accepted it once")
    add(16, "an adapter the receiver does not have",
        _signed_core(st, inner_with(adapter="com.example.sheets")), "UnknownAdapter")
    add(16, "a command from a writer without the drive capability",
        _signed_core(st, inner_with(sender=KEYS["erin"], name="com.example.go", adapter=CUES,
                                    stream=None, targets=[IDS["bob"]],
                                    fresh=[(IDS["bob"], receiver_nonce("bob 1"))]),
                     seed=SEEDS["erin"]), "CapabilityRefused")
    return out


def accepted_in_order_vectors(outers: dict, st: dict) -> list:
    """The eight frames bob accepts, in order, with one replay state."""
    replay = ReplayState()
    out = []
    for i in sorted(outers):
        built, _, space = outers[i][0], outers[i][1], outers[i][2]
        try:
            got = receive(built["outer"], _context(st, replay, scope=space))
            result = {"accepted": True, "name": got["name"], "kind": KIND_NAMES[got["kind"]]}
        except SpecError as error:
            result = {"accepted": False, "class": error.error}
        out.append({"frame": i, "scope": h(space), **result})
    return out


def restart_vectors(st: dict) -> list:
    """"Freshness across restarts": a receiver's nonces are drawn per run
    and never kept at rest; its replay window may be. Bob accepts a command
    in one run, restarts, and a relay replays it."""
    def go(counter: int, nonce_name: str, i: int) -> bytes:
        m = _message("com.example.go", KIND_MESSAGE, "alice", 3, counter, adapter=CUES,
                     targets=[IDS["bob"]], fresh=[(IDS["bob"], receiver_nonce(nonce_name))],
                     data=b"cue 12")
        return build(m, SPACE, st["ref_ab"], st["k_ab"], SEEDS["alice"],
                     nonce(f"restart {i}"))["outer"]

    def cursor(counter: int, i: int) -> bytes:
        m = _message("com.example.cursor", KIND_MESSAGE, "alice", 3, counter, data=b"\x03")
        return build(m, SPACE, st["ref_ab"], st["k_ab"], SEEDS["alice"],
                     nonce(f"restart cursor {i}"))["outer"]

    first, second = [receiver_nonce("bob run 1")], [receiver_nonce("bob run 2")]
    go_1, go_old_nonce, go_2, cur = go(60, "bob run 1", 1), go(61, "bob run 1", 2), \
        go(62, "bob run 2", 3), cursor(63, 4)
    out = []
    for persisted in (False, True):
        replay = ReplayState()
        steps = []

        def run(label: str, outer: bytes, nonces: list) -> None:
            try:
                receive(outer, _context(st, replay, nonces=nonces))
                outcome = "accepted"
            except SpecError as error:
                outcome = error.error
            steps.append({"step": label, "outer": h(outer), "outcome": outcome})

        run("run 1: a command carrying run 1's nonce", go_1, first)
        run("run 1: a cursor", cur, first)
        if not persisted:
            replay = ReplayState()  # the window was in memory only
        run("run 2: the same command, replayed by a relay", go_1, second)
        run("run 2: a new command that still carries run 1's nonce", go_old_nonce, second)
        run("run 2: the cursor, replayed", cur, second)
        run("run 2: a command carrying run 2's nonce", go_2, second)
        out.append({"window_kept_at_rest": persisted,
                    "nonces": {"run 1": h(first[0]), "run 2": h(second[0])}, "steps": steps})
    return out


def replay_window_vectors() -> dict:
    space, sender = SPACE, IDS["alice"]
    state = ReplayState()
    messages = []
    for epoch, counter in [(1, 1), (1, 3), (1, 2), (1, 2), (1, 70), (1, 6), (1, 7), (1, 7),
                           (2, 1), (1, 100), (2, 1), (2, 65), (2, 1)]:
        ok = state.message_ok(space, sender, epoch, counter)
        if ok:
            state.accept_message(space, sender, epoch, counter)
        messages.append({"epoch": epoch, "counter": counter,
                         "outcome": "accepted" if ok else "Replayed"})
    slots = []
    state = ReplayState()
    key = (space, sender, "com.example.presence", STREAM)
    for epoch, counter, data in [(1, 5, b"v1"), (1, 4, b"v0"), (1, 9, b"v2"), (1, 9, b"v2"),
                                 (2, 1, b""), (1, 12, b"v3"), (2, 2, b"v4")]:
        ok = state.slot_ok(key, epoch, counter)
        if ok:
            state.accept_slot(key, epoch, counter, data)
        held = state.slots.get(key)
        slots.append({"epoch": epoch, "counter": counter, "data": h(data),
                      "outcome": "accepted" if ok else "Replayed",
                      "held": None if held is None or not held[2] else h(held[2])})
    return {"window": REPLAY_WINDOW, "ephemeral_messages": messages, "ephemeral_slots": slots,
            "bounds": bounds_vectors()}


BOUNDS_DATA = b"v"


def bound_sender(i: int) -> bytes:
    """A sender of the bounds vectors: 32 bytes of i, ordered by i."""
    return bytes([i]) * 32


def _offer(state: ReplayState, label: str, sender: bytes, kind: int, epoch: int, counter: int,
           name: str | None = None, data: bytes = BOUNDS_DATA) -> dict:
    """One frame offered to the replay state, accepted if it passes."""
    before = set(state.slots)
    if kind == KIND_MESSAGE:
        ok = state.message_ok(SPACE, sender, epoch, counter)
        if ok:
            state.accept_message(SPACE, sender, epoch, counter)
    else:
        key = (SPACE, sender, name, None)
        ok = state.slot_ok(key, epoch, counter)
        if ok:
            state.accept_slot(key, epoch, counter, data)
    gone = sorted((k[1], k[2]) for k in before - set(state.slots))
    step = {"step": label, "sender": h(sender), "kind": KIND_NAMES[kind], "epoch": epoch,
            "counter": counter, "outcome": "accepted" if ok else "Replayed",
            "held_by_sender": len(state.held_by(SPACE, sender)),
            "held_in_space": len(state.held_in(SPACE)),
            "floor": list(state.floor(SPACE, sender)),
            "forgotten": [[h(s), n] for s, n in gone]}
    if kind == KIND_SLOT:
        step.update({"name": name, "data": h(data)})
    return step


def bounds_vectors() -> dict:
    """"Epoch, counter and replay", bounds, floor and forgetting: one
    sender's ephemeral slots past 32, then a space's past 2,048. Every
    ephemeral slot here has no stream, and data "v" unless cleared."""
    alice = IDS["alice"]
    state = ReplayState()
    one = []
    for j in range(32):
        one.append(_offer(state, f"s{j:02d}: held", alice, KIND_SLOT, 1, j + 1, f"s{j:02d}"))
    one += [
        _offer(state, "a 33rd: the lowest, s00, is forgotten, and the floor is its mark",
               alice, KIND_SLOT, 1, 33, "s32"),
        _offer(state, "s05 cleared", alice, KIND_SLOT, 1, 34, "s05", b""),
        _offer(state, "a 34th: the cleared s05 is forgotten first", alice, KIND_SLOT, 1, 35, "s33"),
        _offer(state, "s00's old value again: below the floor", alice, KIND_SLOT, 1, 1, "s00"),
        _offer(state, "an s05 value older than its clear: below the floor", alice, KIND_SLOT,
               1, 30, "s05"),
        _offer(state, "a new s05 value above the floor: s01, the lowest, is forgotten", alice,
               KIND_SLOT, 1, 36, "s05"),
        _offer(state, "a new run, epoch 2: every slot of epoch 1 is forgotten, the floor is "
               "(2, 0)", alice, KIND_SLOT, 2, 1, "s40"),
        _offer(state, "an epoch 1 value: below the floor", alice, KIND_SLOT, 1, 40, "s01"),
        _offer(state, "an ephemeral message of epoch 3 forgets the slots of epoch 2", alice,
               KIND_MESSAGE, 3, 1),
        _offer(state, "s40 of epoch 2 again: below the floor", alice, KIND_SLOT, 2, 5, "s40"),
    ]
    state = ReplayState()
    senders, names = 64, 32
    for i in range(1, senders + 1):
        for j in range(names):
            key = (SPACE, bound_sender(i), f"n{j:02d}", None)
            assert state.slot_ok(key, 1, j + 1)
            state.accept_slot(key, 1, j + 1, BOUNDS_DATA)
    assert len(state.held_in(SPACE)) == RECEIVER_SLOTS_PER_SPACE
    space = [
        _offer(state, "a 65th sender: the space is full, so sender 1, the lowest of those that "
               "hold the most, forgets its lowest", bound_sender(65), KIND_SLOT, 1, 1, "n00"),
        _offer(state, "sender 1's forgotten value again: below its floor", bound_sender(1),
               KIND_SLOT, 1, 1, "n00"),
        _offer(state, "sender 2's 33rd: it forgets its own lowest", bound_sender(2), KIND_SLOT,
               1, 33, "n32"),
        _offer(state, "sender 1, below 32 but in a full space: sender 2 holds the most of the "
               "lowest ID and forgets its lowest", bound_sender(1), KIND_SLOT, 1, 33, "n32"),
    ]
    return {"slots_per_sender": RECEIVER_SLOTS_PER_SENDER,
            "slots_per_space": RECEIVER_SLOTS_PER_SPACE,
            "data": h(BOUNDS_DATA),
            "one_sender": {"space": h(SPACE), "sender": h(alice), "steps": one},
            "full_space": {"space": h(SPACE),
                           "fill": {"senders": senders, "names": names,
                                    "rule": "sender i is 32 bytes of i, for i from 1; it holds "
                                            "names n00, n01, ... at (1, j + 1) for name j"},
                           "steps": space}}


def epoch_vectors() -> dict:
    """"Epoch, counter and replay": one device's epoch across starts and
    restores, and its counters in two spaces."""
    other = example("ephemeral/second space")
    device = Sender(stored=None)
    steps = []

    def note(step: str, epoch: int, sends=()):
        steps.append({"step": step, "epoch": epoch, "stored_after": device.stored,
                      "sends": [{"space": h(sp), "epoch": e, "counter": c}
                                for sp, (e, c) in sends]})

    r1 = int.from_bytes(example("ephemeral/epoch random 1")[:4], "big")
    e = device.restore(r1)
    note("first start, with no epoch record: 0 + 2^32 + a random number below 2^32", e,
         [(SPACE, device.send(SPACE)), (SPACE, device.send(SPACE)),
          (other, device.send(other))])
    e = device.start()
    note("a restart: read e, commit e + 1; counters start at 1 in each space", e,
         [(other, device.send(other)), (SPACE, device.send(SPACE))])
    e = device.start()
    note("another restart", e, [(SPACE, device.send(SPACE))])
    backup = e - 1
    restored = Sender(stored=backup)
    r2 = int.from_bytes(example("ephemeral/epoch random 2")[:4], "big")
    e2 = restored.restore(r2)
    device = restored
    note("a restore from a backup taken before the last restart: the stored epoch plus 2^32 "
         "plus a random number below 2^32", e2, [(SPACE, device.send(SPACE))])
    assert e2 > e
    e3 = device.start()
    note("a restart after the restore", e3, [(SPACE, device.send(SPACE))])
    return {"restore_step": EPOCH_RESTORE_STEP, "randoms": [r1, r2],
            "backup_stored_epoch": backup, "steps": steps}


def membership_vectors() -> list:
    """"Membership against the current view" as a table."""
    rows = [
        ("a device grant in force, at read", "in"),
        ("a guest: a device grant with a session, in force", "in"),
        ("a person grant, and the person's list as held has a valid add of the device", "in"),
        ("a space grant, and the granted space's merged roster as held has the device "
         "reach it, propagating", "in"),
        ("demoted to read: still in; capability checks decide the rest", "in"),
        ("a waiting list member, through its person's grant", "in"),
        ("a removal the receiver has not received", "in"),
        ("a restricted space reached, and its parent reached too", "in"),
        ("removed by a valid roster event of the merged roster", "MembershipEnded"),
        ("a removal concurrent with the device's last unit: the merged roster has it out",
         "MembershipEnded"),
        ("a person grant whose list, as held, revokes the device; no response in this "
         "space yet", "MembershipEnded"),
        ("a space grant whose granted space, as held, no longer has the device reach it",
         "MembershipEnded"),
        ("a restricted space whose parent the device no longer reaches", "MembershipEnded"),
        ("the receiver holds evidence of a fork of the device's chain in this log", "Forked"),
        ("never named by any roster event or list the receiver holds", "NotAMember"),
        ("only a person grant whose list the receiver does not hold", "Unjudgeable"),
    ]
    return [{"view": v, "verdict": r} for v, r in rows]


def relay_vectors(outers: dict, st: dict) -> dict:
    relay = Relay(SPACE)
    slot_v1 = outers[2][0]["outer"]
    message = outers[0][0]["outer"]
    cleared = outers[3][0]["outer"]
    endpoint = outers[4][0]["outer"]
    steps = [
        ("c1 (alice) sends Subscribe and joins", relay.join("c1")),
        ("c2 (bob) sends Subscribe and joins", relay.join("c2")),
        ("c1 sends an ephemeral slot", relay.frame("c1", slot_v1)),
        ("c1 sends an ephemeral message", relay.frame("c1", message)),
        ("c1 sends the ephemeral slot again, cleared: it replaces the held frame",
         relay.frame("c1", cleared)),
        ("c2 sends an ephemeral slot", relay.frame("c2", endpoint)),
        ("c3 (carol) joins late: held ephemeral slots are sent, with their origins; "
         "ephemeral messages are not", relay.join("c3")),
        ("c2 loses its live right: its frames are dropped, and Gone names its origin",
         relay.leave("c2")),
        ("c1 closes: its frames are dropped, and Gone names its origin", relay.leave("c1")),
        ("c4 joins: nothing is held", relay.join("c4")),
    ]
    return {"space": h(SPACE),
            "origins": {c: h(o) for c, o in sorted(relay.origins.items())},
            "steps": [{"step": s, "sent": sent} for s, sent in steps],
            "member_ring": member_ring_vectors(outers, st)}


# Three relaying members in a ring, and alice, who reaches only bob.
RING_LINKS = {"bob": ["alice", "carol", "erin"], "carol": ["bob", "erin"],
              "erin": ["carol", "bob"]}


def _ring_members(st: dict, window: bool = True) -> dict:
    nonces = {"bob": [receiver_nonce("bob 2")], "carol": [receiver_nonce("carol 1")],
              "erin": [receiver_nonce("erin 1")]}
    return {name: MemberRelay(_context(st, ReplayState(), own=IDS[name], nonces=nonces[name]),
                              links, window)
            for name, links in RING_LINKS.items()}


def member_ring_vectors(outers: dict, st: dict) -> dict:
    """"Relaying", a member: alice sends frame 1, a command targeted at bob
    and carol, to bob alone; bob, carol and erin relay among themselves in a
    ring. Each forwards it once, erin though it is not a target, and each
    refuses it, as Replayed, the second time it arrives."""
    outer = outers[1][0]["outer"]
    deliveries = ring(_ring_members(st), "alice", "bob", outer)
    return {"frame": 1, "sender": "alice", "first": "bob",
            "links": RING_LINKS, "deliveries": deliveries}


def ext_ephemeral_vectors() -> dict:
    st = _states()
    cases, outers = encoding_vectors(st)
    return {
        "parameters": {"max_outer_bytes": MAX_OUTER_BYTES, "pad_block": PAD_BLOCK,
                       "max_plaintext_bytes": MAX_PLAINTEXT_BYTES,
                       "max_data_bytes": MAX_DATA_BYTES, "max_name_bytes": MAX_NAME_BYTES,
                       "max_adapter_bytes": MAX_ADAPTER_BYTES,
                       "max_targets": MAX_TARGETS, "max_fresh_entries": MAX_TARGETS,
                       "handle_bytes": HANDLE_BYTES, "min_sealed_bytes":
                           NONCE_BYTES + PAD_BLOCK + TAG_BYTES,
                       "replay_window": REPLAY_WINDOW, "receiver_nonces": RECENT_NONCES,
                       "live_slots_per_sender": MAX_SLOTS_PER_SENDER,
                       "receiver_slots_per_sender": RECEIVER_SLOTS_PER_SENDER,
                       "receiver_slots_per_space": RECEIVER_SLOTS_PER_SPACE,
                       "relay_slots_per_connection": RELAY_SLOTS_PER_CONNECTION,
                       "send_queue": SEND_QUEUE, "origin_bytes": ORIGIN_BYTES,
                       "relay_window": RELAY_WINDOW,
                       "ephemeral_send_deadline": EPHEMERAL_SEND_DEADLINE,
                       "ephemeral_key_wait": EPHEMERAL_KEY_WAIT,
                       "frasil_names": {k: {"kind": KIND_NAMES[v],
                                            "targets": ("required" if k in TARGETED_NAMES
                                                        else "none")}
                                        for k, v in sorted(RESERVED_NAMES.items())}},
        "fixtures": {
            "devices": {n: {"seed": h(SEEDS[n]), "identity": h(SIGNERS[n].ed_public),
                            "kc": h(SIGNERS[n].kc), "device_id": h(IDS[n])}
                        for n in DEVICE_NAMES},
            "space": {"space": h(SPACE), "rotations": {n: h(ROT[n]) for n in "AB"},
                      "content_keys": {n: h(SECRET[n]) for n in "AB"},
                      "states": {
                          "A": {"reference": h(st["ref_a"]), "ephemeral_key":
                                h(ephemeral_key(st["k_a"]))},
                          "B": {"reference": h(st["ref_b"]), "ephemeral_key":
                                h(ephemeral_key(st["k_b"]))},
                          "merged": {"reference": h(st["ref_ab"]), "content_key": h(st["k_ab"]),
                                     "ephemeral_key": h(ephemeral_key(st["k_ab"]))}}},
            "restricted": {"space": h(RESTRICTED), "parent": h(SPACE), "rotation": h(ROT["C"]),
                           "own_secret": h(st["f_c"]), "parent_state": h(st["ref_ab"]),
                           "content_key": h(st["k_f"]), "key_reference": h(st["ref_f"]),
                           "ephemeral_key": h(ephemeral_key(st["k_f"]))},
            "receiver": {"device": "bob",
                         "receiver_nonces": [h(receiver_nonce("bob 2")),
                                             h(receiver_nonce("bob 1"))],
                         "fresh_only_names": ["com.example.go"],
                         "adapters": {"frasil:loro": "accepts every frame",
                                      CUES: "accepts a sender whose capabilities in the "
                                            "receiver's view carry `drive`"},
                         "implements": ["ext-guests"],
                         "membership": {"alice": "in, with `drive`", "carol": "in",
                                        "erin": "in, without `drive`",
                                        "dave": "MembershipEnded", "mallory": "NotAMember"}}},
        "frames": cases,
        "accepted_in_order": accepted_in_order_vectors(outers, st),
        "frame_refusals": frame_refusal_vectors(st, outers),
        "replay_window": replay_window_vectors(),
        "receiver_restart": restart_vectors(st),
        "epochs": epoch_vectors(),
        "membership": membership_vectors(),
        "relay": relay_vectors(outers, st),
    }


def self_test() -> None:
    for new in NEW_LABELS:
        for other in NEW_LABELS:
            if other is not new:
                assert not other.startswith(new), (new, other)
    st = _states()
    _, outers = encoding_vectors(st)
    for built, m, _space, _reference, _key in outers.values():
        assert len(built["outer"]) <= MAX_OUTER_BYTES
        assert len(built["plaintext"]) % PAD_BLOCK == 0
        got = read_inner(built["inner"])
        assert got["name"] == m["name"] and got["data"] == m.get("data", b"")
    v = ext_ephemeral_vectors()
    assert all(a["accepted"] for a in v["accepted_in_order"]), v["accepted_in_order"]
    outcomes = [m["outcome"] for m in v["replay_window"]["ephemeral_messages"]]
    assert outcomes == ["accepted", "accepted", "accepted", "Replayed", "accepted", "Replayed",
                        "accepted", "Replayed", "accepted", "Replayed", "Replayed", "accepted",
                        "Replayed"], outcomes
    slot_outcomes = [s["outcome"] for s in v["replay_window"]["ephemeral_slots"]]
    assert slot_outcomes == ["accepted", "Replayed", "accepted", "Replayed", "accepted",
                             "Replayed", "accepted"], slot_outcomes
    # A frasil/leave clears each held ephemeral slot of its sender as if with
    # its (epoch, counter); a newer value stays, and an older one cannot return.
    r = ReplayState()
    older, newer, other = (SPACE, IDS["alice"], "a", None), (SPACE, IDS["alice"], "b", None), \
        (SPACE, IDS["bob"], "a", None)
    r.accept_slot(older, 3, 5, b"x")
    r.accept_slot(newer, 3, 9, b"y")
    r.accept_slot(other, 3, 2, b"z")
    r.clear_sender(SPACE, IDS["alice"], 3, 7)
    assert r.slots[older] == (3, 7, b"") and r.slots[newer] == (3, 9, b"y")
    assert r.slots[other] == (3, 2, b"z") and not r.slot_ok(older, 3, 6)
    # The relay never sees a sender, a name or a target.
    assert all("sender" not in step and "name" not in step
               for s in v["relay"]["steps"] for step in s["sent"])
    # A ring of relaying members: each forwards the frame once, the
    # non-target erin too, and refuses it the second time; without the
    # relay window the frame would go round without end.
    ring_v = v["relay"]["member_ring"]["deliveries"]
    assert [(d["to"], d.get("forwarded_to"), d.get("refused"), d["own_verdict"])
            for d in ring_v] == [
        ("bob", ["carol", "erin"], None, "accepted"),
        ("carol", ["erin"], None, "accepted"),
        ("erin", ["carol"], None, "NotTargeted"),
        ("erin", None, "Replayed", "NotTargeted"),
        ("carol", None, "Replayed", "Replayed"),
    ], ring_v
    assert RELAY_WINDOW == REPLAY_WINDOW
    endless = ring(_ring_members(st, window=False), "alice", "bob", outers[1][0]["outer"],
                   limit=100)
    assert len(endless) == 100 and all("forwarded_to" in d for d in endless)
    # The bounds: one sender never holds more than 32, nor a space 2,048.
    b = v["replay_window"]["bounds"]
    assert all(s["held_by_sender"] <= RECEIVER_SLOTS_PER_SENDER for s in b["one_sender"]["steps"])
    assert [s["outcome"] for s in b["one_sender"]["steps"][32:]] == [
        "accepted", "accepted", "accepted", "Replayed", "Replayed", "accepted", "accepted",
        "Replayed", "accepted", "Replayed"]
    assert [s["outcome"] for s in b["full_space"]["steps"]] == [
        "accepted", "Replayed", "accepted", "accepted"]
    assert all(s["held_in_space"] == RECEIVER_SLOTS_PER_SPACE for s in b["full_space"]["steps"])
    # A member whose membership ended loses its ephemeral slots at the
    # receiver, and a value below the floor stays out.
    r = ReplayState()
    r.accept_slot((SPACE, IDS["dave"], "a", None), 1, 4, b"x")
    r.drop_sender(SPACE, IDS["dave"])
    assert not r.slots and r.floor(SPACE, IDS["dave"]) == (1, 4)
    assert not r.slot_ok((SPACE, IDS["dave"], "a", None), 1, 3)
    assert ephemeral_key(st["k_ab"]) != ephemeral_key(st["k_a"])
    steps = {r["step"] for r in v["frame_refusals"]}
    assert steps == set(range(1, 17)), steps
    for scenario in v["receiver_restart"]:
        got = [s["outcome"] for s in scenario["steps"]]
        cursor = "Replayed" if scenario["window_kept_at_rest"] else "accepted"
        assert got == ["accepted", "accepted", "Stale", "Stale", cursor, "accepted"], got
    # The largest key reference still fits: 64 + 64 rotations in a restricted space.
    largest = 1 + 32 * 64 + NONCE_BYTES + 1 + 32 * 64 + TAG_BYTES
    assert largest + MAX_PLAINTEXT_BYTES + NONCE_BYTES + TAG_BYTES + 64 <= MAX_OUTER_BYTES
    # The largest inner map fits the padded plaintext: every field at its
    # limit, a 64-byte sender, 16 targets with 16 fresh entries, and 16,384
    # bytes of data.
    biggest = encode_inner({"kind": KIND_MESSAGE, "sender": bytes(64), "epoch": U64_MAX,
                            "counter": U64_MAX, "name": "n" * 64, "stream": bytes([1]) * 16,
                            "targets": [bytes([i]) * 32 for i in range(1, 17)],
                            "fresh": [(bytes([i]) * 32, bytes(16)) for i in range(1, 17)],
                            "adapter": "a" * 64, "data": bytes(MAX_DATA_BYTES)})
    assert read_inner(biggest)["sender"] == bytes(64)
    padded = pad(cbor([biggest, bytes(SIGNATURE_BYTES)]))
    assert len(padded) <= MAX_PLAINTEXT_BYTES, len(padded)


if __name__ == "__main__":
    self_test()
    print("ephemeral: self-test passed")
