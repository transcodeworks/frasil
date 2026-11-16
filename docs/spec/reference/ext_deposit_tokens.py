"""Deposit tokens (ext-deposit-tokens.md), protocol 1, written from the
specification, independently of any implementation: deposit keys and key
IDs, the deposit grant (a library ticket of purpose 4 with key 7, read by
library.py's ticket code), tokens, the four messages and MailboxPut with key
7; a device's checks of a key list and its consistency rule, a request and
its finishing; a peer's checks of a request, issuance with the allowance
window and each space's share, redemption with the spent set, the two
budgets over device mailboxes, and key rotation, each as a pure state
transition over explicit state. The VOPRF is voprf.py's."""

from __future__ import annotations

import math

import clocks
import library
import voprf as v
from events import cbor, h, is_bytes, is_uint, uncbor
from formats import example
from handshakes import (DEVICE_MAILBOX_BYTES, DEVICE_MAILBOX_ITEMS, MAILBOX_DEVICE,
                        MAILBOX_ITEM_BYTES, MAILBOX_PUT, TOKEN_ISSUE, TOKEN_KEYS, TOKEN_KEYS_GET,
                        TOKEN_REQUEST, mailbox_address)
from history_sigs import device_signer
from primitives import SpecError, ed25519_public, sha256

KEY_LABEL = b"frasil/deposit-key/v1"
TOKEN_LABEL = b"frasil/deposit-token/v1"
NEW_LABELS = [KEY_LABEL, TOKEN_LABEL]

DEPOSIT_SERVICE = 6
TOKEN_VERSION = 0x01
KEY_ID_BYTES = NONCE_BYTES = 32
INPUT_BYTES = len(TOKEN_LABEL) + KEY_ID_BYTES + NONCE_BYTES          # 87
TOKEN_BYTES = 1 + KEY_ID_BYTES + NONCE_BYTES + v.OUTPUT_BYTES          # 129
MAX_BATCH = 256
MAX_GRANT_BYTES = library.MAX_TICKET_BYTES
MESSAGE_CAP = 16_384
ISSUING, ACCEPTING = 1, 2
ROLE_NAMES = {ISSUING: "issuing", ACCEPTING: "accepting only"}

HOUR, DAY = 3_600, 86_400
TOKEN_PERIOD, TOKEN_PERIOD_RANGE = 7 * DAY, (DAY, 30 * DAY)
ALLOWANCE_WINDOW = DAY
DEPOSIT_ALLOWANCE, DEPOSIT_ALLOWANCE_RANGE = 64, (0, 65_536)
SPACE_SHARE = 16
CONSISTENCY_WINDOW = DAY  # three issuing keys first seen within it are KeyInconsistent
LOW_MARK, BATCH = 4, 16   # section 3.12's defaults

# Every class this document raises, with its refusal code and HTTP status
# (section 2.8, and the documents it takes classes from). BadProof and
# KeyInconsistent are a device's own verdicts; KeyInconsistent has no code.
CODES = {
    "Malformed": ("malformed", 400),
    "UnsupportedVersion": ("unsupported_version", 400),
    "TooLarge": ("too_large", 413),
    "InvalidKey": ("invalid_key", 422),
    "TicketRefused": ("ticket_refused", 403),
    "TicketExpired": ("ticket_expired", 403),
    "TicketUsed": ("ticket_used", 409),
    "NoLibrary": ("no_library", 507),
    "LibraryClosed": ("library_closed", 507),
    "CredentialRefused": ("credential_refused", 403),
    "PurposeViolation": ("purpose_violation", 403),
    "Busy": ("busy", 503),
    "BadProof": ("bad_proof", None),
    "TokenRefused": ("token_refused", 403),
    "TokenExpired": ("token_expired", 403),
    "TokenSpent": ("token_spent", 409),
    "AllowanceExhausted": ("allowance_exhausted", 429),
    "KeyInconsistent": (None, None),
}


def verdict(cls: str, **extra) -> dict:
    if cls == "accepted":
        return {"verdict": cls, **extra}
    code, status = CODES[cls]
    out = {"verdict": cls}
    if code is not None:
        out["code"] = code
    if status is not None:
        out["status"] = status
    return {**out, **extra}


# ---------------------------------------------------------------------------
# 2.2 Deposit keys, 2.4 Tokens.


class DepositKey:
    """A peer's deposit key from its seed: `(skS, pkS) = DeriveKeyPair(seed,
    "frasil/deposit-key/v1")`, its public key and key ID."""

    def __init__(self, seed: bytes):
        self.seed = seed
        self.sk, self.pk = v.derive_key_pair(seed, KEY_LABEL)
        self.public = v.serialize_element(self.pk)
        self.id = key_id(self.public)


def key_id(public: bytes) -> bytes:
    return sha256(KEY_LABEL + public)


def token_input(kid: bytes, nonce: bytes) -> bytes:
    return TOKEN_LABEL + kid + nonce


def encode_token(kid: bytes, nonce: bytes, authenticator: bytes) -> bytes:
    return bytes([TOKEN_VERSION]) + kid + nonce + authenticator


# ---------------------------------------------------------------------------
# 2.5 Messages.


def token_keys_get(request: int) -> bytes:
    return cbor({0: TOKEN_KEYS_GET, 1: request})


def token_keys(request: int, keys: list) -> bytes:
    """`keys` is a list of (key, role)."""
    return cbor({0: TOKEN_KEYS, 1: request, 2: [[k.id, k.public, role] for k, role in keys]})


def token_request(request: int, kid: bytes, blinded: list, *, grant: bytes | None = None,
                  space: bytes | None = None) -> bytes:
    m = {0: TOKEN_REQUEST, 1: request, 3: kid, 4: list(blinded)}
    if grant is not None:
        m[2] = grant
    if space is not None:
        m[5] = space
    return cbor(m)


def token_issue(request: int, evaluated: list, proof: bytes) -> bytes:
    return cbor({0: TOKEN_ISSUE, 1: request, 2: list(evaluated), 3: proof})


def token_put(request: int, address: bytes, item: bytes, token: bytes) -> bytes:
    return cbor({0: MAILBOX_PUT, 1: request, 2: address, 3: item, 6: MAILBOX_DEVICE, 7: token})


def token_header(token: bytes) -> str:
    """The server binding's `Authorization` value."""
    return "Frasil-Token " + token.hex()


def discovery_keys(keys: list) -> list:
    """Discovery's `deposit_keys` member."""
    return [{"id": h(k.id), "key": h(k.public), "issuing": role == ISSUING} for k, role in keys]


def _decode(message: bytes) -> dict:
    try:
        m = uncbor(message)
    except SpecError as error:
        raise SpecError("Malformed") from error
    if not isinstance(m, dict):
        raise SpecError("Malformed")
    return m


# ---------------------------------------------------------------------------
# 3.2 Learning a peer's keys.


def check_key_list(entries) -> list:
    """Section 3.2, steps 1 to 3, in order. Returns [(key ID, public key,
    role)]."""
    if not (isinstance(entries, list) and 1 <= len(entries) <= 2):
        raise SpecError("Malformed")
    for e in entries:
        if not (isinstance(e, list) and len(e) == 3 and is_bytes(e[0], 32) and is_bytes(e[1], 32)
                and is_uint(e[2]) and e[2] in (ISSUING, ACCEPTING)):
            raise SpecError("Malformed")
    if sum(e[2] == ISSUING for e in entries) != 1 or len({e[0] for e in entries}) != len(entries):
        raise SpecError("Malformed")
    for e in entries:
        try:
            v.deserialize_element(e[1])
        except SpecError as error:
            raise SpecError("InvalidKey") from error
    for e in entries:
        if key_id(e[1]) != e[0]:
            raise SpecError("Malformed")
    return [tuple(e) for e in entries]


def read_token_keys(message: bytes, request: int) -> list:
    """A `TokenKeys` answering `TokenKeysGet` number `request`: exactly its
    keys, then section 3.2's checks of its list."""
    m = _decode(message)
    if not (set(m) == {0, 1, 2} and m[0] == TOKEN_KEYS and is_uint(m[1]) and m[1] == request):
        raise SpecError("Malformed")
    return check_key_list(m[2])


def read_discovery_keys(member) -> list:
    """Discovery's `deposit_keys`, as entries for section 3.2's checks."""
    if not isinstance(member, list):
        raise SpecError("Malformed")
    entries = []
    for e in member:
        if not (isinstance(e, dict) and set(e) == {"id", "key", "issuing"}
                and isinstance(e["issuing"], bool)):
            raise SpecError("Malformed")
        parts = []
        for name in ("id", "key"):
            text = e[name]
            if not (isinstance(text, str) and len(text) == 64
                    and all(c in "0123456789abcdef" for c in text)):
                raise SpecError("Malformed")
            parts.append(bytes.fromhex(text))
        entries.append([*parts, ISSUING if e["issuing"] else ACCEPTING])
    return check_key_list(entries)


class KeyHistory:
    """What a device keeps per peer (section 3.2): the issuing keys it has
    seen, in order, each with its first sight on the device's timeline. A
    list whose issuing key the device saw replaced, or that would make three
    issuing keys first seen within 24 hours, is KeyInconsistent, and the
    device then stops drawing and spending that peer's tokens."""

    def __init__(self):
        self.seen: list[tuple[bytes, int]] = []
        self.stopped = False
        self.latest: list = []

    def observe(self, entries: list, reading: int) -> str:
        if self.stopped:
            return "KeyInconsistent"
        issuing = next(e[0] for e in entries if e[2] == ISSUING)
        known = [k for k, _ in self.seen]
        if known and issuing == known[-1]:
            pass
        elif issuing in known:
            self.stopped = True
        elif len(self.seen) >= 2 and reading - self.seen[-2][1] < CONSISTENCY_WINDOW:
            self.stopped = True
        else:
            self.seen.append((issuing, reading))
        if self.stopped:
            self.latest = []
            return "KeyInconsistent"
        self.latest = [e[0] for e in entries]
        return "accepted"


# ---------------------------------------------------------------------------
# 3.3 Requesting tokens, 3.5 Finishing issuance: the device.


def blind_batch(kid: bytes, nonces: list, blinds: list) -> dict:
    """Section 3.3, step 2, with each nonce and blind given."""
    inputs = [token_input(kid, n) for n in nonces]
    blinded = [v.blind(i, b) for i, b in zip(inputs, blinds)]
    return {"inputs": inputs, "blinds": blinds, "nonces": nonces, "blinded": blinded,
            "blinded_bytes": [v.serialize_element(e) for e in blinded]}


def finish_issuance(message: bytes, request: int, public: bytes, kid: bytes,
                    batch: dict) -> list:
    """Section 3.5, in order; then each token. Raises the class."""
    n = len(batch["blinded"])
    m = _decode(message)
    if not (set(m) == {0, 1, 2, 3} and m[0] == TOKEN_ISSUE and is_uint(m[1]) and m[1] == request
            and isinstance(m[2], list) and 1 <= len(m[2]) <= n
            and all(is_bytes(e, 32) for e in m[2]) and is_bytes(m[3], 64)):
        raise SpecError("Malformed")
    evaluated = [v.deserialize_element(e) for e in m[2]]
    count = len(evaluated)
    pk = v.deserialize_element(public)
    if not v.verify_proof(v.G, pk, batch["blinded"][:count], evaluated, m[3]):
        raise SpecError("BadProof")
    return [encode_token(kid, nonce, v.finalize(i, b, e)) for nonce, i, b, e in
            zip(batch["nonces"], batch["inputs"], batch["blinds"], evaluated)]


# ---------------------------------------------------------------------------
# 3.9 Spent tokens and key rotation: the keys' shard.


class KeyShard:
    """The peer's deposit keys, one shard (section 3.10), and its spent
    tokens. `keys` lists the live keys, the issuing key first. A key issues
    while the upper estimate since its start is less than token_period, is
    accepting only while it is less than twice that, then retires. When a
    key stops issuing the next begins at once, and the key before it
    retires if it has not, so at most two keys live. An unbounded estimate
    retires both and begins a new key."""

    def __init__(self, period: int = TOKEN_PERIOD):
        self.period = period
        self.keys: list[dict] = []
        self.spent: dict[tuple[bytes, bytes], tuple[bytes, int]] = {}

    def begin(self, seed: bytes, reading: dict) -> None:
        self.keys.insert(0, {"key": DepositKey(seed), "began": reading})
        for old in self.keys[2:]:
            self._retire(old)

    def _retire(self, entry: dict) -> None:
        self.keys.remove(entry)
        kid = entry["key"].id
        self.spent = {k: r for k, r in self.spent.items() if k[0] != kid}

    def issuing(self) -> DepositKey:
        return self.keys[0]["key"]

    def live(self, kid: bytes) -> DepositKey | None:
        return next((e["key"] for e in self.keys if e["key"].id == kid), None)

    def roles(self) -> list:
        return [(e["key"], ISSUING if i == 0 else ACCEPTING) for i, e in enumerate(self.keys)]

    def advance(self, now: dict, next_seed: bytes) -> None:
        """The rotation at reading `now`, beginning a key from `next_seed`
        when one is due."""
        first = clocks.elapsed_upper(self.keys[0]["began"], now)
        if first == math.inf:
            for entry in list(self.keys):
                self._retire(entry)
            self.begin(next_seed, now)
            return
        for entry in list(self.keys[1:]):
            if clocks.elapsed_upper(entry["began"], now) >= 2 * self.period:
                self._retire(entry)
        if first >= self.period:
            if first >= 2 * self.period:
                self._retire(self.keys[0])
            self.begin(next_seed, now)

    def describe(self) -> dict:
        return {"keys": [{"key_id": h(e["key"].id), "role": ROLE_NAMES[r],
                          "began": e["began"]} for e, (_, r) in zip(self.keys, self.roles())],
                "spent": sorted([h(kid), h(nonce)] for kid, nonce in self.spent)}


# ---------------------------------------------------------------------------
# 3.8 The token budget: device mailboxes under two budgets.


class Mailboxes:
    """A peer's device mailboxes with the anonymous budget and the token
    budget (section 3.8). Items are (ID, bytes, paid), IDs in deposit order.
    A refused deposit changes nothing."""

    def __init__(self, anonymous: tuple, tokens: tuple):
        self.caps = {False: anonymous, True: tokens}  # (items, bytes)
        self.boxes: dict[bytes, dict] = {}
        self.next_id = 1

    def box(self, address: bytes, claimed: bool = False) -> dict:
        return self.boxes.setdefault(address, {"claimed": claimed, "items": []})

    def fill(self, address: bytes, items: list) -> None:
        for size, paid in items:
            self.box(address)["items"].append((self.next_id, size, paid))
            self.next_id += 1

    def describe(self) -> list:
        return [{"address": h(a), "claimed": b["claimed"],
                 "items": [[i, n, "token" if p else "anonymous"] for i, n, p in b["items"]]}
                for a, b in sorted(self.boxes.items())]

    def plan(self, address: bytes, size: int, paid: bool):
        """The evictions a deposit makes, or None where it is refused Busy."""
        own = self.box(address) if address in self.boxes else {"claimed": False, "items": []}
        mine = list(own["items"])
        evicted = []
        # Within one mailbox: a token deposit evicts anonymous items first,
        # then token items; an anonymous one, anonymous items only.
        while (len(mine) + 1 > DEVICE_MAILBOX_ITEMS
               or sum(n for _, n, _ in mine) + size > DEVICE_MAILBOX_BYTES):
            anonymous = [x for x in mine if not x[2]]
            victims = anonymous or ([x for x in mine if x[2]] if paid else [])
            if not victims:
                return None
            mine.remove(victims[0])
            evicted.append(victims[0][0])
        # Across the peer: each budget counts its own kind.
        cap_items, cap_bytes = self.caps[paid]
        others = sorted((i, n, a) for a, b in self.boxes.items() if a != address
                        for i, n, p in b["items"] if p == paid)
        count = sum(1 for x in mine if x[2] == paid) + len(others) + 1
        total = sum(n for _, n, p in mine if p == paid) + sum(n for _, n, _ in others) + size
        if count > cap_items or total > cap_bytes:
            if not own["claimed"]:
                return None
            for i, n, a in others:
                if count <= cap_items and total <= cap_bytes:
                    break
                if not self.boxes[a]["claimed"]:
                    evicted.append(i)
                    count, total = count - 1, total - n
            if count > cap_items or total > cap_bytes:
                return None
        return evicted

    def deposit(self, address: bytes, size: int, paid: bool) -> dict:
        evicted = self.plan(address, size, paid)
        if evicted is None:
            return verdict("Busy", evicted=[])
        gone = set(evicted)
        for b in self.boxes.values():
            b["items"] = [x for x in b["items"] if x[0] not in gone]
        item_id = self.next_id
        self.next_id += 1
        self.box(address)["items"].append((item_id, size, paid))
        return verdict("accepted", id=item_id, evicted=sorted(evicted))


# ---------------------------------------------------------------------------
# 3.4 Issuing, 3.7 Redeeming: the peer.


def library_settings(**given) -> dict:
    return {"state": "open", "open_until": None, "deposit_allowance": DEPOSIT_ALLOWANCE,
            "space_share": SPACE_SHARE, "window_start": None, "tokens_drawn": 0,
            "shares": {}, **given}


def current_window(lib: dict, reading: int) -> tuple:
    """The window as section 3.4's first point would open it at `reading`,
    on the lower estimate of the library's timeline: (start, drawn,
    shares)."""
    start = lib["window_start"]
    if start is None or reading - start >= ALLOWANCE_WINDOW:
        return reading, 0, {}
    return start, lib["tokens_drawn"], lib["shares"]


class DepositPeer:
    """What a peer keeps for this document (section 2.7): its keys and
    spent tokens, each library's window and draws, the spaces' libraries,
    the ticket IDs used, and its device mailboxes."""

    def __init__(self, issuers, keys: KeyShard, libraries: dict, spaces: dict,
                 mailboxes: Mailboxes | None = None):
        self.issuers = set(issuers)
        self.keys = keys
        self.libraries = {name: library_settings(**s) for name, s in libraries.items()}
        self.spaces = dict(spaces)
        self.used: set = set()
        self.mailboxes = mailboxes

    def check_request(self, message: bytes, *, store, now_wall, reading: int) -> dict:
        """Section 3.4's checks, in order."""
        m = _decode(message)
        grant_draw = 2 in m
        if not (m.get(0) == TOKEN_REQUEST and {0, 1, 3, 4} <= set(m)
                and set(m) - {0, 1, 3, 4} in ({2}, {5})):
            raise SpecError("Malformed")
        if not (is_uint(m[1]) and is_bytes(m[3], 32) and isinstance(m[4], list)
                and 1 <= len(m[4]) <= MAX_BATCH and all(is_bytes(e, 32) for e in m[4])):
            raise SpecError("Malformed")
        if grant_draw and not (is_bytes(m[2]) and len(m[2]) <= MAX_GRANT_BYTES):
            raise SpecError("Malformed")
        if not grant_draw and not is_bytes(m[5], 32):
            raise SpecError("Malformed")
        blinded = [v.deserialize_element(e) for e in m[4]]
        if grant_draw:
            ticket = library.check_ticket(
                m[2], issuers=self.issuers, now_wall=now_wall, used=self.used,
                purpose=library.DEPOSIT,
                libraries={n: {"state": lib["state"], "open_until": lib["open_until"]}
                           for n, lib in self.libraries.items()},
                deposit_tokens=True)
            if len(blinded) > ticket["tokens"]:
                raise SpecError("TicketRefused")
            name = ticket["library"]
            self.libraries.setdefault(name, library_settings())
        else:
            ticket = None
            if m[5] not in store:
                raise SpecError("CredentialRefused")
            name = self.spaces.get(m[5])
            if name is None:
                raise SpecError("NoLibrary")
            if library.library_state(self.libraries[name], now_wall) != "open":
                raise SpecError("LibraryClosed")
        if m[3] != self.keys.issuing().id:
            raise SpecError("TokenExpired")
        lib = self.libraries[name]
        start, drawn, shares = current_window(lib, reading)
        if drawn >= lib["deposit_allowance"]:
            raise SpecError("AllowanceExhausted")
        if not grant_draw and shares.get(m[5], 0) >= lib["space_share"]:
            raise SpecError("AllowanceExhausted")
        left = lib["deposit_allowance"] - drawn
        if not grant_draw:
            left = min(left, lib["space_share"] - shares.get(m[5], 0))
        return {"request": m[1], "blinded": blinded, "ticket": ticket, "library": name,
                "space": None if grant_draw else m[5], "window": (start, drawn, shares),
                "count": min(len(blinded), left)}

    def issue(self, message: bytes, *, store=(), now_wall=None, reading: int,
              proof_scalar: int) -> dict:
        """Section 3.4: the checks, then the one step that issues."""
        try:
            c = self.check_request(message, store=set(store), now_wall=now_wall, reading=reading)
        except SpecError as error:
            return verdict(error.error)
        key = self.keys.issuing()
        count = c["count"]
        evaluated = [v.blind_evaluate(key.sk, e) for e in c["blinded"][:count]]
        proof = v.generate_proof(key.sk, v.G, key.pk, c["blinded"][:count], evaluated,
                                 proof_scalar)
        lib = self.libraries[c["library"]]
        start, drawn, shares = c["window"]
        shares = dict(shares)
        if c["space"] is not None:
            shares[c["space"]] = shares.get(c["space"], 0) + count
        lib.update(window_start=start, tokens_drawn=drawn + count, shares=shares)
        if c["ticket"] is not None:
            self.used.add(c["ticket"]["id"])
        answer = token_issue(c["request"], [v.serialize_element(e) for e in evaluated], proof)
        return verdict("accepted", count=count, proof_scalar=h(v.serialize_scalar(proof_scalar)),
                       token_issue=h(answer))

    def describe(self) -> dict:
        return {"libraries": {name: {"state": lib["state"],
                                     "deposit_allowance": lib["deposit_allowance"],
                                     "space_share": lib["space_share"],
                                     "window_start": lib["window_start"],
                                     "tokens_drawn": lib["tokens_drawn"],
                                     "shares": {h(s): n for s, n in sorted(lib["shares"].items())}}
                              for name, lib in sorted(self.libraries.items())},
                "spaces": {h(s): name for s, name in sorted(self.spaces.items())},
                "grants_used": sorted(h(i) for i in self.used)}

    def ledger(self, name: str) -> dict:
        """What the library's ledger adds (section 2.7): no per-space row."""
        lib = self.libraries[name]
        return {"library": name, "tokens_drawn": lib["tokens_drawn"],
                "deposit_allowance": lib["deposit_allowance"]}

    def check_deposit(self, *, message: bytes | None = None, post: dict | None = None) -> dict:
        """Section 3.7, steps 1 to 5. `message` is a MailboxPut of kind 3
        with key 7; `post` is the server binding's {address, item,
        authorization}."""
        if message is not None:
            m = _decode_put(message)
            if not (set(m) == {0, 1, 2, 3, 6, 7} and m[0] == MAILBOX_PUT and m[6] == MAILBOX_DEVICE
                    and is_uint(m[1]) and is_bytes(m[2], 32) and is_bytes(m[3])
                    and is_bytes(m[7], TOKEN_BYTES)):
                raise SpecError("Malformed")
            address, item, token, request = m[2], m[3], m[7], m[1]
        else:
            header = post["authorization"]
            hexits = header[len("Frasil-Token "):]
            if not (header.startswith("Frasil-Token ") and len(hexits) == 2 * TOKEN_BYTES
                    and all(ch in "0123456789abcdef" for ch in hexits)):
                raise SpecError("Malformed")
            address, item, token, request = post["address"], post["item"], bytes.fromhex(
                hexits), None
        if token[0] != TOKEN_VERSION:
            raise SpecError("UnsupportedVersion")
        if len(item) > MAILBOX_ITEM_BYTES:
            raise SpecError("TooLarge")
        kid, nonce, authenticator = token[1:33], token[33:65], token[65:]
        key = self.keys.live(kid)
        if key is None:
            raise SpecError("TokenExpired")
        if v.evaluate(key.sk, token_input(kid, nonce)) != authenticator:  # constant time in code
            raise SpecError("TokenRefused")
        return {"address": address, "item": item, "kid": kid, "nonce": nonce,
                "request": request}

    def redeem(self, **form) -> dict:
        """Section 3.7, in order, then the step that keeps the item and
        records the token spent."""
        try:
            c = self.check_deposit(**form)
        except SpecError as error:
            return verdict(error.error)
        digest = sha256(c["address"] + c["item"])
        record = self.keys.spent.get((c["kid"], c["nonce"]))
        if record is not None:
            if record[0] != digest:
                return verdict("TokenSpent")
            return verdict("accepted", id=record[1], repeated=True)
        planned = self.mailboxes.plan(c["address"], len(c["item"]), True)
        if planned is None:
            return verdict("Busy")
        kept = self.mailboxes.deposit(c["address"], len(c["item"]), True)
        self.keys.spent[(c["kid"], c["nonce"])] = (digest, kept["id"])
        return verdict("accepted", id=kept["id"], evicted=kept["evicted"], repeated=False)


def _decode_put(message: bytes) -> dict:
    try:
        m = uncbor(message)
    except SpecError as error:
        raise SpecError("Malformed") from error
    if not isinstance(m, dict):
        raise SpecError("Malformed")
    return m


# ---------------------------------------------------------------------------
# Vectors: ext-deposit-tokens.json.

NOW = library.NOW
LIBRARY = "project:7c1f9e2a0b4d4e8f"
OTHER_LIBRARY = "personal:0d5b2c"
ISSUER_SEED = library.ISSUER_SEED
SEEDS = {n: example(f"deposit-tokens/key seed {n}") for n in range(1, 7)}
SPACES = {n: example(f"deposit-tokens/space {n}") for n in "abcd"}
# A device mailbox is named by its device's device ID (transport.md, 2.7
# Mailboxes); a token binds the address and knows nothing of the device.
RECIPIENT = device_signer("deposit-tokens/recipient").device_id
OTHER_RECIPIENT = device_signer("deposit-tokens/another recipient").device_id
ADDRESS = mailbox_address(MAILBOX_DEVICE, RECIPIENT)
OTHER_ADDRESS = mailbox_address(MAILBOX_DEVICE, OTHER_RECIPIENT)
WALL0 = NOW


def reading(day: float, wall: int | None = 0, run: int = 1) -> dict:
    t = int(day * DAY)
    return {"timeline": t, "wall": None if wall is None else WALL0 + t + wall, "run": run}


def nonce(name: str) -> bytes:
    return example(f"deposit-tokens/nonce {name}")


def blind_scalar(name: str) -> int:
    return v.scalar_from_bytes(example(f"deposit-tokens/blind {name}"))


def proof_scalar(name: str) -> int:
    return v.scalar_from_bytes(example(f"deposit-tokens/proof scalar {name}"))


def item(name: str, size: int = 512) -> bytes:
    data = b""
    counter = 0
    while len(data) < size:
        data += example(f"deposit-tokens/item {name} {counter}")
        counter += 1
    return data[:size]


def grant(*, name: str = "a", tokens: int | None = 16, purpose: int = library.DEPOSIT,
          library_id: str = LIBRARY, not_after: int = NOW + 3600,
          seed: bytes = ISSUER_SEED) -> dict:
    gid = example(f"deposit-tokens/grant {name}")[:16]
    ticket = library.encode_ticket(library_id, gid, purpose, not_after, ed25519_public(seed),
                                   tokens=tokens)
    signed = library.sign_ticket(seed, ticket)
    return {"id": gid, "ticket": ticket, "signed": signed}


def shard(*, issuing: int = 2, accepting: int | None = 1) -> KeyShard:
    s = KeyShard()
    if accepting is not None:
        s.begin(SEEDS[accepting], reading(0))
    s.begin(SEEDS[issuing], reading(7 if accepting is not None else 0))
    return s


def _setup(peer: DepositPeer, *, store=(), now_wall=NOW, read: int = 0) -> dict:
    return {"issuers": sorted(h(i) for i in peer.issuers),
            "keys": [{"seed": h(k.seed), "key_id": h(k.id), "role": ROLE_NAMES[r]}
                     for k, r in peer.keys.roles()],
            "now_wall": now_wall, "reading": read, "store": sorted(h(s) for s in store),
            **peer.describe()}


def _peer(**libraries) -> DepositPeer:
    libs = {LIBRARY: {}, OTHER_LIBRARY: {"state": "suspended"}}
    libs.update(libraries)
    return DepositPeer({ed25519_public(ISSUER_SEED)}, shard(), libs,
                       {SPACES["a"]: LIBRARY, SPACES["b"]: LIBRARY, SPACES["d"]: OTHER_LIBRARY})


def _batch(kid: bytes, names: list) -> dict:
    return blind_batch(kid, [nonce(n) for n in names], [blind_scalar(n) for n in names])


def parameters() -> dict:
    return {
        "suite": "ristretto255-SHA512", "mode": v.MODE_VOPRF, "context": h(v.CONTEXT),
        "labels": {label.decode(): h(label) for label in NEW_LABELS},
        "element_bytes": v.ELEMENT_BYTES, "scalar_bytes": v.SCALAR_BYTES,
        "output_bytes": v.OUTPUT_BYTES, "proof_bytes": 2 * v.SCALAR_BYTES,
        "key_id_bytes": KEY_ID_BYTES, "nonce_bytes": NONCE_BYTES, "input_bytes": INPUT_BYTES,
        "token_bytes": TOKEN_BYTES, "token_version": TOKEN_VERSION,
        "grant_tokens": [1, library.MAX_GRANT_TOKENS], "max_batch": MAX_BATCH,
        "max_grant_bytes": MAX_GRANT_BYTES, "message_cap": MESSAGE_CAP,
        "message_types": {"TokenKeysGet": TOKEN_KEYS_GET, "TokenKeys": TOKEN_KEYS,
                          "TokenRequest": TOKEN_REQUEST, "TokenIssue": TOKEN_ISSUE},
        "service": DEPOSIT_SERVICE, "mailbox_put_key": 7, "ticket_purpose": library.DEPOSIT,
        "ticket_key": 7, "roles": {str(r): name for r, name in ROLE_NAMES.items()},
        "token_period": {"default": TOKEN_PERIOD, "range": list(TOKEN_PERIOD_RANGE)},
        "allowance_window": ALLOWANCE_WINDOW,
        "deposit_allowance": {"default": DEPOSIT_ALLOWANCE,
                              "range": list(DEPOSIT_ALLOWANCE_RANGE)},
        "space_share": {"default": SPACE_SHARE, "range": [0, "deposit_allowance"]},
        "consistency_window": CONSISTENCY_WINDOW,
        "draw_defaults": {"low_mark": LOW_MARK, "batch": BATCH},
        "classes": {c: {"code": code, "status": status} for c, (code, status) in CODES.items()},
    }


def voprf_vectors() -> dict:
    k = v.kats()["voprf"]
    sk, pk = v.derive_key_pair(bytes.fromhex(k["seed"]), bytes.fromhex(k["key_info"]))
    return {"source": "RFC 9497, Appendix A.1.2", "seed": k["seed"], "key_info": k["key_info"],
            "skSm": h(v.serialize_scalar(sk)), "pkSm": h(v.serialize_element(pk)),
            "vectors": [v.rfc9497_case(vector, sk, pk) for vector in k["vectors"]]}


def keys_vectors() -> dict:
    k1, k2 = DepositKey(SEEDS[1]), DepositKey(SEEDS[2])
    listed = [(k2, ISSUING), (k1, ACCEPTING)]
    message = token_keys(1, listed)
    assert [e[0] for e in read_token_keys(message, 1)] == [k2.id, k1.id]
    assert read_discovery_keys(discovery_keys(listed))
    good = [[k2.id, k2.public, ISSUING], [k1.id, k1.public, ACCEPTING]]
    k3 = DepositKey(SEEDS[3])
    noncanonical = (v.P + 2).to_bytes(32, "little")
    refused = []
    for name, entries in (
            ("three entries", good + [[k3.id, k3.public, ACCEPTING]]),
            ("two issuing", [good[0], [k1.id, k1.public, ISSUING]]),
            ("none issuing", [[k2.id, k2.public, ACCEPTING], good[1]]),
            ("one key listed twice", [good[0], [k2.id, k2.public, ACCEPTING]]),
            ("a role of 3", [good[0], [k1.id, k1.public, 3]]),
            ("no entry", []),
            ("a key ID that is not its key's hash", [[k1.id, k2.public, ISSUING]]),
            ("the identity element", [[key_id(bytes(32)), bytes(32), ISSUING]]),
            ("an encoding that is not canonical",
             [[key_id(noncanonical), noncanonical, ISSUING]])):
        msg = cbor({0: TOKEN_KEYS, 1: 1, 2: entries})
        try:
            read_token_keys(msg, 1)
            result = "accepted"
        except SpecError as error:
            result = error.error
        refused.append({"name": name, "token_keys": h(msg), **verdict(result)})
    extra = cbor({0: TOKEN_KEYS, 1: 1, 2: good, 3: 0})
    other = cbor({0: TOKEN_KEYS, 1: 2, 2: good})
    for name, msg in (("an extra key", extra), ("another request", other)):
        try:
            read_token_keys(msg, 1)
            result = "accepted"
        except SpecError as error:
            result = error.error
        refused.append({"name": name, "token_keys": h(msg), **verdict(result)})
    return {
        "keys": [{"seed": h(k.seed), "secret": h(v.serialize_scalar(k.sk)),
                  "public": h(k.public), "key_id": h(k.id)} for k in (k1, k2, k3)],
        "token_keys_get": h(token_keys_get(1)),
        "token_keys": h(message),
        "discovery": {"deposit_keys": discovery_keys(listed)},
        "refused": refused,
    }


def grants_vectors() -> dict:
    g = grant()
    issuer = ed25519_public(ISSUER_SEED)
    k2 = DepositKey(SEEDS[2])
    refused = []

    def run(name, signed, *, n=3, used=()):
        peer = _peer()
        peer.used.update(used)
        message = token_request(1, k2.id, _batch(k2.id, [f"g{i}" for i in range(1, n + 1)])[
            "blinded_bytes"], grant=signed)
        setup = _setup(peer)
        result = peer.issue(message, now_wall=NOW, reading=0, proof_scalar=proof_scalar("g"))
        refused.append({"name": name, "setup": setup, "signed": h(signed),
                        "token_request": h(message), **result,
                        "after": peer.describe()})

    run("a grant that names 2 tokens, with 3 blinded elements", grant(name="two", tokens=2)[
        "signed"])
    run("purpose 4 without key 7", grant(name="no-key-7", tokens=None)["signed"])
    run("key 7 on purpose 1", grant(name="key-7", purpose=library.CREATE)["signed"])
    run("0 tokens", grant(name="zero", tokens=0)["signed"])
    run("257 tokens", grant(name="many", tokens=257)["signed"])
    run("a grant ID already used", g["signed"], used=[g["id"]])
    run("an attaching ticket, purpose 1", grant(name="attach", purpose=library.CREATE,
                                                tokens=None)["signed"])
    run("an untrusted issuer", grant(name="stranger", seed=example("deposit-tokens/stranger"))[
        "signed"])
    run("past not_after", grant(name="old", not_after=NOW - 1)["signed"])
    run("a suspended library", grant(name="suspended", library_id=OTHER_LIBRARY)["signed"])
    # A grant shown to LibraryAttach is refused at check_ticket's step 6.
    try:
        library.check_ticket(g["signed"], issuers={issuer}, now_wall=NOW, used=set(),
                             purpose=library.CREATE, libraries={}, deposit_tokens=True)
        attach = "accepted"
    except SpecError as error:
        attach = error.error
    return {"grant": {"library": LIBRARY, "id": h(g["id"]), "tokens": 16, "not_after": NOW + 3600,
                      "issuer": h(issuer), "ticket": h(g["ticket"]),
                      "signed_message": h(library.TICKET_LABEL + g["ticket"]),
                      "signature": h(uncbor(g["signed"])[1]), "signed": h(g["signed"])},
            "refused": refused,
            "as_attach": {"purpose": "create", "signed": h(g["signed"]), **verdict(attach)}}


def issuance_vectors() -> dict:
    k1, k2 = DepositKey(SEEDS[1]), DepositKey(SEEDS[2])
    g = grant()
    batch = _batch(k2.id, ["1", "2", "3"])
    request = token_request(1, k2.id, batch["blinded_bytes"], grant=g["signed"])
    peer = _peer()
    setup = _setup(peer)
    r = proof_scalar("1")
    result = peer.issue(request, now_wall=NOW, reading=0, proof_scalar=r)
    answer = bytes.fromhex(result["token_issue"])
    tokens = finish_issuance(answer, 1, k2.public, k2.id, batch)
    for t in tokens:
        assert v.evaluate(k2.sk, token_input(t[1:33], t[33:65])) == t[65:]
    issued = uncbor(answer)
    batch_out = {
        "setup": setup, "key_id": h(k2.id), "public": h(k2.public),
        "nonces": [h(x) for x in batch["nonces"]],
        "inputs": [h(x) for x in batch["inputs"]],
        "blinds": [h(v.serialize_scalar(b)) for b in batch["blinds"]],
        "blinded": [h(x) for x in batch["blinded_bytes"]],
        "token_request": h(request),
        "evaluated": [h(x) for x in issued[2]], "proof": h(issued[3]), **result,
        "tokens": [h(t) for t in tokens],
        "after": peer.describe(), "ledger": peer.ledger(LIBRARY)}

    def case(name, message, *, libs=None, read=0, scalar="x"):
        p = _peer(**(libs or {}))
        s = _setup(p, read=read)
        out = p.issue(message, now_wall=NOW, reading=read, proof_scalar=proof_scalar(scalar))
        return {"name": name, "setup": s, "token_request": h(message), **out,
                "after": p.describe()}

    cut = _batch(k2.id, ["c1", "c2", "c3"])
    near = {LIBRARY: {"window_start": 0, "tokens_drawn": DEPOSIT_ALLOWANCE - 2}}
    cases = [case("a batch of three cut to the two the allowance has left",
                  token_request(2, k2.id, cut["blinded_bytes"], grant=grant(name="cut")["signed"]),
                  libs=near, read=HOUR, scalar="cut")]
    full = {LIBRARY: {"window_start": 0, "tokens_drawn": DEPOSIT_ALLOWANCE}}
    cases.append(case("a library whose window has passed draws afresh",
                      token_request(3, k2.id, cut["blinded_bytes"],
                                    grant=grant(name="afresh")["signed"]),
                      libs=full, read=ALLOWANCE_WINDOW, scalar="afresh"))
    refused = []
    for name, message, libs, read in (
            ("under the accepting-only key",
             token_request(4, k1.id, _batch(k1.id, ["r1"])["blinded_bytes"],
                           grant=grant(name="old-key")["signed"]), None, 0),
            ("under a key the peer does not know",
             token_request(5, key_id(bytes(32)), batch["blinded_bytes"],
                           grant=grant(name="unknown-key")["signed"]), None, 0),
            ("an element that is not canonical",
             token_request(6, k2.id, [batch["blinded_bytes"][0], (v.P + 2).to_bytes(32, "little")],
                           grant=grant(name="noncanonical")["signed"]), None, 0),
            ("the identity element",
             token_request(7, k2.id, [bytes(32)], grant=grant(name="identity")["signed"]), None,
             0),
            ("a library that has drawn its whole allowance in its window",
             token_request(8, k2.id, batch["blinded_bytes"], grant=grant(name="full")["signed"]),
             full, ALLOWANCE_WINDOW - 1),
            ("no element", token_request(9, k2.id, [], grant=grant(name="none")["signed"]), None,
             0),
            ("257 elements",
             token_request(10, k2.id, batch["blinded_bytes"] * 85 + batch["blinded_bytes"][:2],
                           grant=grant(name="257")["signed"]), None, 0),
            ("a key ID of 31 bytes",
             token_request(11, k2.id[:31], batch["blinded_bytes"],
                           grant=grant(name="short")["signed"]), None, 0)):
        refused.append(case(name, message, libs=libs, read=read))
    return {"batch": batch_out, "cases": cases, "refused": refused}


def space_draws_vectors() -> dict:
    k2 = DepositKey(SEEDS[2])
    peer = _peer()
    a, b, c, d = (SPACES[n] for n in "abcd")
    steps = []

    def step(name, message, *, store, read):
        setup = _setup(peer, store=store, read=read)
        out = peer.issue(message, store=store, now_wall=NOW, reading=read,
                         proof_scalar=proof_scalar(name))
        steps.append({"name": name, "setup": setup, "token_request": h(message), **out,
                      "after": peer.describe(), "ledger": peer.ledger(LIBRARY)})

    def blinded(prefix, n):
        return _batch(k2.id, [f"{prefix}{i}" for i in range(n)])["blinded_bytes"]

    step("space A draws 10 under its store right", token_request(1, k2.id, blinded("a", 10),
                                                                 space=a), store=[a], read=0)
    step("space A draws 10 more, cut to the 6 its share has left",
         token_request(2, k2.id, blinded("a", 10), space=a), store=[a], read=60)
    step("space A, its share drawn", token_request(3, k2.id, blinded("a", 1), space=a),
         store=[a], read=120)
    step("space B, of the same library, draws its own share",
         token_request(4, k2.id, blinded("b", 16), space=b), store=[b], read=180)
    step("a grant draw beside them counts against the library alone",
         token_request(5, k2.id, blinded("g", 16), grant=grant(name="beside")["signed"]),
         store=[], read=240)
    step("space B, its share drawn", token_request(6, k2.id, blinded("b", 1), space=b),
         store=[b], read=300)
    step("a day later, space A's share begins afresh",
         token_request(7, k2.id, blinded("a", 2), space=a), store=[a], read=ALLOWANCE_WINDOW)
    refused = []
    for name, message, store in (
            ("both keys 2 and 5", cbor({0: TOKEN_REQUEST, 1: 8, 2: grant(name="both")["signed"],
                                         3: k2.id, 4: blinded("x", 1), 5: a}), [a]),
            ("neither key 2 nor key 5", cbor({0: TOKEN_REQUEST, 1: 9, 3: k2.id,
                                               4: blinded("x", 1)}), [a]),
            ("a connection with fetch and catch-up only",
             token_request(10, k2.id, blinded("x", 1), space=a), []),
            ("a connection whose upload key is retired",
             token_request(11, k2.id, blinded("x", 1), space=b), []),
            ("a space attached to no library", token_request(12, k2.id, blinded("x", 1), space=c),
             [c]),
            ("a space of a suspended library",
             token_request(13, k2.id, blinded("x", 1), space=d), [d]),
            ("a space ID of 31 bytes", token_request(14, k2.id, blinded("x", 1), space=a[:31]),
             [a])):
        p = _peer()
        setup = _setup(p, store=store)
        out = p.issue(message, store=store, now_wall=NOW, reading=0,
                      proof_scalar=proof_scalar("x"))
        refused.append({"name": name, "setup": setup, "token_request": h(message), **out})
    return {"steps": steps, "refused": refused,
            "rights": {"a connection with fetch and catch-up only": ["fetch", "catch-up"],
                       "a connection whose upload key is retired": []}}


def finishing_vectors() -> dict:
    k2, k3 = DepositKey(SEEDS[2]), DepositKey(SEEDS[3])
    batch = _batch(k2.id, ["1", "2", "3"])
    r = proof_scalar("finishing")
    evaluated = [v.blind_evaluate(k2.sk, e) for e in batch["blinded"]]
    ser = [v.serialize_element(e) for e in evaluated]
    good = token_issue(1, ser, v.generate_proof(k2.sk, v.G, k2.pk, batch["blinded"], evaluated, r))
    other = _batch(k2.id, ["o1", "o2", "o3"])
    other_eval = [v.blind_evaluate(k2.sk, e) for e in other["blinded"]]
    over_other = token_issue(1, ser, v.generate_proof(k2.sk, v.G, k2.pk, other["blinded"],
                                                      other_eval, r))
    k3_eval = [v.blind_evaluate(k3.sk, e) for e in batch["blinded"]]
    under_k3 = token_issue(1, [v.serialize_element(e) for e in k3_eval],
                           v.generate_proof(k3.sk, v.G, k3.pk, batch["blinded"], k3_eval, r))
    mixed_eval = [evaluated[0], k3_eval[1], evaluated[2]]
    mixed = token_issue(1, [v.serialize_element(e) for e in mixed_eval],
                        v.generate_proof(k2.sk, v.G, k2.pk, batch["blinded"], mixed_eval, r))
    two_eval = evaluated[:2]
    cut = token_issue(1, ser[:2], v.generate_proof(k2.sk, v.G, k2.pk, batch["blinded"][:2],
                                                   two_eval, r))
    four = token_issue(1, ser + ser[:1], uncbor(good)[3])
    big_scalar = uncbor(good)[3][:32] + v.L.to_bytes(32, "little")
    cases = []
    for name, message in (("a good TokenIssue", good),
                          ("two of three, the batch cut", cut),
                          ("a proof over other elements", over_other),
                          ("evaluated and proved under another key", under_k3),
                          ("one element evaluated under a second key", mixed),
                          ("more elements than were sent", four),
                          ("another request", token_issue(2, ser, uncbor(good)[3])),
                          ("an evaluated element that is not canonical",
                           token_issue(1, [ser[0], (v.P + 2).to_bytes(32, "little"), ser[2]],
                                       uncbor(good)[3])),
                          ("a proof scalar not below the group's order",
                           token_issue(1, ser, big_scalar)),
                          ("a proof of 63 bytes", token_issue(1, ser, uncbor(good)[3][:63]))):
        try:
            tokens = finish_issuance(message, 1, k2.public, k2.id, batch)
            out = verdict("accepted", tokens=[h(t) for t in tokens])
        except SpecError as error:
            out = verdict(error.error)
        cases.append({"name": name, "token_issue": h(message), **out})
    return {"key_id": h(k2.id), "public": h(k2.public), "request": 1,
            "nonces": [h(x) for x in batch["nonces"]],
            "blinds": [h(v.serialize_scalar(b)) for b in batch["blinds"]],
            "blinded": [h(x) for x in batch["blinded_bytes"]], "cases": cases}


def _tokens(key: DepositKey, names: list) -> list:
    out = []
    for n in names:
        nn = nonce(n)
        out.append(encode_token(key.id, nn, v.evaluate(key.sk, token_input(key.id, nn))))
    return out


def redemption_vectors() -> dict:
    k1, k2, k6 = DepositKey(SEEDS[1]), DepositKey(SEEDS[2]), DepositKey(SEEDS[6])
    t = _tokens(k2, ["r1", "r2", "r3", "r4", "r5", "r6", "r7"])
    old = _tokens(k1, ["r-old"])[0]
    retired = _tokens(k6, ["r-retired"])[0]
    peer = _peer()
    peer.mailboxes = Mailboxes((64, 1 << 22), (3, 1 << 20))
    peer.mailboxes.box(ADDRESS, claimed=True)
    peer.mailboxes.box(OTHER_ADDRESS, claimed=True)
    steps = []

    def state():
        return {"keys": [{"seed": h(k.seed), "key_id": h(k.id), "role": ROLE_NAMES[r]}
                         for k, r in peer.keys.roles()],
                "spent": [{"key_id": h(kid), "nonce": h(n), "deposit": h(rec[0]), "id": rec[1]}
                          for (kid, n), rec in sorted(peer.keys.spent.items())],
                "mailboxes": peer.mailboxes.describe()}

    def ws(name, put):
        before = state()
        out = peer.redeem(message=put)
        steps.append({"name": name, "route": "websocket", "before": before,
                      "mailbox_put": h(put), **out, "after": state()})

    def post(name, address, body, header, *, zero_item: int | None = None):
        before = state()
        out = peer.redeem(post={"address": address, "item": body, "authorization": header})
        row = {"name": name, "route": "post", "before": before, "address": h(address),
               "authorization": header, **out, "after": state()}
        if zero_item is None:
            row["item"] = h(body)
        else:
            row["zero_item_bytes"] = zero_item
        steps.append(row)

    i1, i2 = item("1"), item("2")
    ws("a good token", token_put(1, ADDRESS, i1, t[0]))
    ws("the same deposit repeated", token_put(2, ADDRESS, i1, t[0]))
    ws("the token on another item", token_put(3, ADDRESS, i2, t[0]))
    post("a good token on the POST route", ADDRESS, i2, token_header(t[1]))
    post("the POST repeated, its answer lost", ADDRESS, i2, token_header(t[1]))
    ws("a token of the accepting-only key", token_put(4, OTHER_ADDRESS, item("3"), old))
    changed = t[2][:-1] + bytes([t[2][-1] ^ 1])
    ws("a changed authenticator", token_put(5, ADDRESS, item("4"), changed))
    ws("a token of a retired key", token_put(6, ADDRESS, item("4"), retired))
    ws("a token of version 2", token_put(7, ADDRESS, item("4"), bytes([2]) + t[2][1:]))
    post("an item of 262,145 bytes", ADDRESS, bytes(MAILBOX_ITEM_BYTES + 1), token_header(t[2]),
         zero_item=MAILBOX_ITEM_BYTES + 1)
    ws("a full token budget", token_put(8, ADDRESS, item("5"), t[3]))
    post("a header in uppercase hex", ADDRESS, item("5"),
         "Frasil-Token " + t[3].hex().upper())
    post("a header of 128 bytes", ADDRESS, item("5"), "Frasil-Token " + t[3][:128].hex())
    ws("a token of 128 bytes", cbor({0: MAILBOX_PUT, 1: 9, 2: ADDRESS, 3: item("5"),
                                     6: MAILBOX_DEVICE, 7: t[3][:128]}))
    ws("an extra key", cbor({0: MAILBOX_PUT, 1: 10, 2: ADDRESS, 3: item("5"),
                             6: MAILBOX_DEVICE, 7: t[3], 8: 0}))
    return {"budgets": {"anonymous": {"items": 64, "bytes": 1 << 22},
                        "tokens": {"items": 3, "bytes": 1 << 20}},
            "addresses": {"recipient": {"device_id": h(RECIPIENT), "address": h(ADDRESS)},
                          "another recipient": {"device_id": h(OTHER_RECIPIENT),
                                                "address": h(OTHER_ADDRESS)}},
            "steps": steps}


def budgets_vectors() -> list:
    out = []
    big = MAILBOX_ITEM_BYTES

    def scenario(name, caps, boxes, deposits):
        mb = Mailboxes(*caps)
        for address, claimed, items in boxes:
            mb.box(address, claimed=claimed)
            mb.fill(address, items)
        before = mb.describe()
        steps = []
        for address, size, paid in deposits:
            result = mb.deposit(address, size, paid)
            steps.append({"address": h(address), "bytes": size,
                          "kind": "token" if paid else "anonymous", **result,
                          "after": mb.describe()})
        out.append({"name": name, "budgets": {"anonymous": {"items": caps[0][0],
                                                            "bytes": caps[0][1]},
                                              "tokens": {"items": caps[1][0],
                                                         "bytes": caps[1][1]}},
                    "before": before, "deposits": steps})

    roomy = ((1_000, 1 << 30), (1_000, 1 << 30))
    full_box = [(big, False)] * 2 + [(big, True)] * 14
    scenario("a mailbox at its cap: token deposits evict anonymous items, then token items",
             roomy, [(ADDRESS, True, full_box)],
             [(ADDRESS, big, True), (ADDRESS, big, True), (ADDRESS, big, True)])
    scenario("an anonymous deposit into a mailbox full of token items is refused", roomy,
             [(ADDRESS, True, [(big, True)] * 16)], [(ADDRESS, big, False)])
    scenario("anonymous deposits at the cap evict the mailbox's oldest anonymous item, never "
             "a token item", roomy,
             [(ADDRESS, True, [(big, True)] * 7 + [(big, False)] + [(big, True)] * 8)],
             [(ADDRESS, big, False), (ADDRESS, big, False)])
    u, c1, c2, u2 = (example(f"deposit-tokens/budget mailbox {n}") for n in
                     ("unclaimed", "claimed 1", "claimed 2", "unclaimed 2"))
    scenario("a full token budget evicts token items of an unclaimed mailbox for a claimed one",
             ((2, 1 << 30), (4, 1 << 30)),
             [(u, False, [(600, True), (600, False), (600, True)]),
              (c1, True, [(600, True), (600, True)]), (c2, True, []), (u2, False, [])],
             [(c2, 600, True), (u2, 600, True), (c2, 600, True), (c2, 600, True),
              (c2, 600, False), (u2, 600, True)])
    return out


def rotation_vectors() -> dict:
    s = KeyShard()
    s.begin(SEEDS[1], reading(0))
    steps = [{"step": "the first key begins", "now": reading(0), "spend": [], **s.describe()}]
    k1 = s.keys[0]["key"]
    s.spent[(k1.id, nonce("rot-1"))] = (bytes(32), 1)

    def step(name, now, seed, spend=()):
        for key_index, n in spend:
            s.spent[(s.keys[key_index]["key"].id, nonce(n))] = (bytes(32), len(s.spent) + 1)
        before = s.describe()
        s.advance(now, SEEDS[seed])
        steps.append({"step": name, "now": now, "next_seed": h(SEEDS[seed]), "before": before,
                      **s.describe()})

    step("a day in: nothing changes", reading(1), 2)
    step("token_period from the first key's start: it stops issuing, the second begins",
         reading(7), 2)
    step("between", reading(10), 3, spend=[(0, "rot-2"), (1, "rot-3")])
    step("two periods from the first key's start: it retires with its records, the third "
         "begins", reading(14), 3)
    step("the wall clock ran ahead by 7 days while the timeline did not: the upper estimate "
         "stops the third key", reading(15, wall=7 * DAY), 4, spend=[(0, "rot-4")])
    step("after a restart with no wall clock: both keys retire, a new one begins",
         reading(16, wall=None, run=2), 5)
    step("the same run, a period later", reading(23, wall=None, run=2), 6)
    return {"token_period": TOKEN_PERIOD, "seeds": {str(n): h(seed) for n, seed in SEEDS.items()},
            "steps": steps}


def key_consistency_vectors() -> list:
    k = {n: DepositKey(SEEDS[n]) for n in (1, 2, 3, 4)}
    out = []

    def sequence(name, lists):
        history = KeyHistory()
        steps = []
        for entries_spec, at in lists:
            entries = [[k[n].id, k[n].public, role] for n, role in entries_spec]
            result = history.observe(check_key_list(entries), at)
            steps.append({"keys": [{"key_id": h(k[n].id), "role": ROLE_NAMES[role]}
                                   for n, role in entries_spec],
                          "reading": at, **verdict(result),
                          "issuing_seen": [{"key_id": h(i), "first_seen": t}
                                           for i, t in history.seen],
                          "keeps_tokens_of": [h(i) for i in history.latest]})
        out.append({"name": name, "steps": steps})

    sequence("a rotation each period", [
        ([(1, ISSUING)], 0), ([(2, ISSUING), (1, ACCEPTING)], 7 * DAY),
        ([(2, ISSUING), (1, ACCEPTING)], 8 * DAY), ([(3, ISSUING), (2, ACCEPTING)], 14 * DAY),
        ([(3, ISSUING)], 15 * DAY)])
    sequence("a replaced key returns", [
        ([(1, ISSUING)], 0), ([(2, ISSUING), (1, ACCEPTING)], 7 * DAY),
        ([(1, ISSUING), (2, ACCEPTING)], 7 * DAY + HOUR), ([(2, ISSUING)], 8 * DAY)])
    sequence("three issuing keys within 24 hours", [
        ([(1, ISSUING)], 0), ([(2, ISSUING), (1, ACCEPTING)], HOUR),
        ([(3, ISSUING), (2, ACCEPTING)], 2 * HOUR)])
    sequence("three issuing keys, the first seen 24 hours before the third", [
        ([(1, ISSUING)], 0), ([(2, ISSUING), (1, ACCEPTING)], HOUR),
        ([(3, ISSUING), (2, ACCEPTING)], DAY), ([(4, ISSUING), (3, ACCEPTING)], DAY + HOUR)])
    return out


def ext_deposit_tokens_vectors() -> dict:
    return {
        "specification": "ext-deposit-tokens.md",
        "parameters": parameters(),
        "voprf": voprf_vectors(),
        "keys": keys_vectors(),
        "grants": grants_vectors(),
        "issuance": issuance_vectors(),
        "space_draws": space_draws_vectors(),
        "finishing": finishing_vectors(),
        "redemption": redemption_vectors(),
        "budgets": budgets_vectors(),
        "rotation": rotation_vectors(),
        "key_consistency": key_consistency_vectors(),
    }


def self_test() -> None:
    v.self_test()
    assert len(TOKEN_LABEL) + 64 == INPUT_BYTES == 87 and TOKEN_BYTES == 129
    out = ext_deposit_tokens_vectors()
    keys = out["keys"]
    assert [r["verdict"] for r in keys["refused"]] == [
        "Malformed", "Malformed", "Malformed", "Malformed", "Malformed", "Malformed",
        "Malformed", "InvalidKey", "InvalidKey", "Malformed", "Malformed"], keys["refused"]
    grants = out["grants"]
    assert [r["verdict"] for r in grants["refused"]] == [
        "TicketRefused", "Malformed", "Malformed", "Malformed", "Malformed", "TicketUsed",
        "TicketRefused", "TicketRefused", "TicketExpired", "LibraryClosed"], grants["refused"]
    assert all(r["after"]["grants_used"] == r["setup"]["grants_used"] for r in grants["refused"])
    assert grants["as_attach"]["verdict"] == "TicketRefused"
    iss = out["issuance"]
    assert iss["batch"]["count"] == 3 and len(iss["batch"]["tokens"]) == 3
    assert iss["batch"]["after"]["libraries"][LIBRARY]["tokens_drawn"] == 3
    assert [c["count"] for c in iss["cases"]] == [2, 3]
    assert [c["verdict"] for c in iss["refused"]] == [
        "TokenExpired", "TokenExpired", "Malformed", "Malformed", "AllowanceExhausted",
        "Malformed", "Malformed", "Malformed"], iss["refused"]
    sd = out["space_draws"]
    assert [s.get("count", s["verdict"]) for s in sd["steps"]] == [
        10, 6, "AllowanceExhausted", 16, 16, "AllowanceExhausted", 2], sd["steps"]
    assert [s["ledger"]["tokens_drawn"] for s in sd["steps"]] == [10, 16, 16, 32, 48, 48, 2]
    assert [r["verdict"] for r in sd["refused"]] == [
        "Malformed", "Malformed", "CredentialRefused", "CredentialRefused", "NoLibrary",
        "LibraryClosed", "Malformed"], sd["refused"]
    fin = out["finishing"]
    assert [c["verdict"] for c in fin["cases"]] == [
        "accepted", "accepted", "BadProof", "BadProof", "BadProof", "Malformed", "Malformed",
        "Malformed", "BadProof", "Malformed"], fin["cases"]
    # Tokens do not depend on the proof: the same nonces, blinds and key.
    assert fin["cases"][0]["tokens"] == iss["batch"]["tokens"]
    red = out["redemption"]["steps"]
    assert [(s["verdict"], s.get("id")) for s in red] == [
        ("accepted", 1), ("accepted", 1), ("TokenSpent", None), ("accepted", 2),
        ("accepted", 2), ("accepted", 3), ("TokenRefused", None), ("TokenExpired", None),
        ("UnsupportedVersion", None), ("TooLarge", None), ("Busy", None), ("Malformed", None),
        ("Malformed", None), ("Malformed", None), ("Malformed", None)], red
    bud = out["budgets"]
    assert [d["evicted"] for d in bud[0]["deposits"]] == [[1], [2], [3]]
    assert [d["verdict"] for d in bud[1]["deposits"]] == ["Busy"]
    assert [d["evicted"] for d in bud[2]["deposits"]] == [[8], [17]]
    assert [(d["verdict"], d["evicted"]) for d in bud[3]["deposits"]] == [
        ("accepted", [1]), ("Busy", []), ("accepted", [3]), ("Busy", []), ("accepted", []),
        ("Busy", [])], bud[3]["deposits"]
    rot = out["rotation"]["steps"]
    assert [len(s["keys"]) for s in rot] == [1, 1, 2, 2, 2, 2, 1, 2], rot
    assert rot[4]["spent"] == [r for r in rot[4]["before"]["spent"]
                               if r[0] != rot[4]["before"]["keys"][1]["key_id"]]
    kc = out["key_consistency"]
    assert [[s["verdict"] for s in q["steps"]] for q in kc] == [
        ["accepted"] * 5, ["accepted", "accepted", "KeyInconsistent", "KeyInconsistent"],
        ["accepted", "accepted", "KeyInconsistent"], ["accepted"] * 4], kc
    assert out == ext_deposit_tokens_vectors(), "the vectors are not deterministic"


if __name__ == "__main__":
    import json
    self_test()
    print(json.dumps(ext_deposit_tokens_vectors(), indent=1)[:2000])
