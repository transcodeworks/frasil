"""Libraries (ext-libraries.md), protocol 1, written from the specification,
independently of any implementation: the signed library ticket and a peer's checks of it
in their order, LibraryAttach, attaching a space by create, import and
move, and the ledger the issuer reads. An import's credentials use
storage.py's entries: every imported rotation's entry starts retired, and
only the importer's proofs make entries live (peers.md, import). Holds: an
object's access key, HoldObject and its checks, which objects a peer keeps
for holds, and the ledger that counts a held object once."""

from __future__ import annotations

import handshakes
import keygraph as kg
import roster
import storage
from events import KIND_SPACE, cbor, h, is_bytes, is_uint, uncbor
from formats import example, identifier_ok
from primitives import SpecError, ed25519_public, ed25519_sign_deterministic, ed25519_valid, \
    ed25519_verify_strict, field, hkdf

TICKET_LABEL = b"frasil/library-ticket/v1"
ACCESS_LABEL = b"frasil/object-access/v1"
HOLD_LABEL = b"frasil/object-hold/v1"
NEW_LABELS = [TICKET_LABEL, ACCESS_LABEL, HOLD_LABEL]
LIBRARY_ATTACH = 21  # transport.md reserves the message type for this extension
HOLD_OBJECT = 31  # and this one
LIBRARY_SERVICE = 5
NO_SALT = bytes(32)
ORPHAN_GRACE = 24 * 3600  # overview.md's default

VERSION = 1
CREATE, IMPORT, MOVE = 1, 2, 3
PURPOSES = {CREATE: "create", IMPORT: "import", MOVE: "move"}
# ext-deposit-tokens.md's deposit grant: purpose 4, with key 7, tokens. A
# peer that does not implement that extension refuses both in step 1.
DEPOSIT = 4
PURPOSE_NAMES = {**PURPOSES, DEPOSIT: "deposit"}
MAX_GRANT_TOKENS = 256
MAX_TICKET_BYTES = 512
MAX_LIBRARY_ID_BYTES = 128
TICKET_LIFETIME = 24 * 3600
TICKET_SKEW = 60
MAX_ISSUERS = 16
DAY = 24 * 3600
T_DEFAULT, T_RANGE = 7 * DAY, (3600, 90 * DAY)
DETACHED_GRACE, DETACHED_GRACE_RANGE = 30 * DAY, (DAY, 365 * DAY)

# "Error classes": each class, its refusal code and its status.
CODES = {
    "Malformed": ("malformed", 400),
    "NotAuthorized": ("not_authorized", 403),
    "TicketRefused": ("ticket_refused", 403),
    "TicketExpired": ("ticket_expired", 403),
    "TicketUsed": ("ticket_used", 409),
    "SpaceExists": ("space_exists", 409),
    "QuotaExceeded": ("quota_exceeded", 507),
    "NoLibrary": ("no_library", 507),
    "LibraryClosed": ("library_closed", 507),
    "Erased": ("erased", 410),
    "HoldRefused": ("hold_refused", 403),
    "UnknownObject": ("unknown_object", 404),
    "OtherLibrary": ("other_library", 409),
}


def check_expiry(expires_at: int, now_wall: int | None, lifetime: int, skew: int) -> None:
    """overview.md's check_expiry, in order: an unknown wall clock is Expired;
    an instant beyond now + lifetime + skew is Malformed; one in the past is
    Expired. No grace follows expires_at."""
    if now_wall is None:
        raise SpecError("Expired")
    if expires_at > now_wall + lifetime + skew:
        raise SpecError("Malformed")
    if now_wall > expires_at:
        raise SpecError("Expired")


def library_id_ok(value) -> bool:
    return (isinstance(value, str) and 1 <= len(value.encode()) <= MAX_LIBRARY_ID_BYTES
            and identifier_ok(value))


def encode_ticket(library: str, ticket_id: bytes, purpose: int, not_after: int,
                  issuer: bytes, tokens: int | None = None) -> bytes:
    """The ticket's map; key 7, tokens, where given (a deposit grant)."""
    fields = {1: VERSION, 2: library, 3: ticket_id, 4: purpose, 5: not_after, 6: issuer}
    if tokens is not None:
        fields[7] = tokens
    return cbor(fields)


def sign_ticket(seed: bytes, ticket: bytes) -> bytes:
    """"The library ticket": `[ticket's bytes, signature]`."""
    return cbor([ticket, ed25519_sign_deterministic(seed, TICKET_LABEL + ticket)])


def read_ticket(signed: bytes, deposit_tokens: bool = False) -> dict:
    """"Checking a ticket", step 1: keys 1 to 6, and 7 exactly for purpose
    4, which only a peer that implements ext-deposit-tokens.md reads."""
    if len(signed) > MAX_TICKET_BYTES:
        raise SpecError("Malformed")
    try:
        outer = uncbor(signed)
        if not (isinstance(outer, list) and len(outer) == 2 and is_bytes(outer[0])
                and is_bytes(outer[1], 64)):
            raise SpecError("Malformed")
        t = uncbor(outer[0])
    except SpecError as error:
        raise SpecError("Malformed") from error
    if not isinstance(t, dict):
        raise SpecError("Malformed")
    grant = deposit_tokens and t.get(4) == DEPOSIT
    if set(t) != set(range(1, 8 if grant else 7)) or t[1] != VERSION:
        raise SpecError("Malformed")
    if not (library_id_ok(t[2]) and is_bytes(t[3], 16) and (t[4] in PURPOSES or grant)
            and is_uint(t[5]) and is_bytes(t[6], 32)):
        raise SpecError("Malformed")
    if grant and not (is_uint(t[7]) and 1 <= t[7] <= MAX_GRANT_TOKENS):
        raise SpecError("Malformed")
    return {"bytes": outer[0], "signature": outer[1], "library": t[2], "id": t[3],
            "purpose": t[4], "not_after": t[5], "issuer": t[6], "tokens": t.get(7)}


def check_ticket(signed: bytes, *, issuers, now_wall: int | None, used, purpose: int,
                 libraries: dict, deposit_tokens: bool = False) -> dict:
    """"Checking a ticket", in order. Raises SpecError with the class.
    `deposit_tokens` says whether the peer implements ext-deposit-tokens.md."""
    t = read_ticket(signed, deposit_tokens)
    if t["issuer"] not in issuers or not ed25519_valid(t["issuer"]):
        raise SpecError("TicketRefused")
    if not ed25519_verify_strict(t["issuer"], TICKET_LABEL + t["bytes"], t["signature"]):
        raise SpecError("TicketRefused")
    try:
        check_expiry(t["not_after"], now_wall, TICKET_LIFETIME, TICKET_SKEW)
    except SpecError as error:
        raise SpecError("TicketExpired") from error
    if t["id"] in used:
        raise SpecError("TicketUsed")
    if t["purpose"] != purpose:
        raise SpecError("TicketRefused")
    if library_state(libraries.get(t["library"], {}), now_wall) != "open":
        raise SpecError("LibraryClosed")
    return t


def library_state(settings: dict, now_wall: int | None) -> str:
    """"Settings": suspended by its state setting, or once open_until is set
    and the wall clock is at or past it, or not known."""
    if settings.get("state", "open") != "open":
        return "suspended"
    until = settings.get("open_until")
    if until is not None and (now_wall is None or now_wall >= until):
        return "suspended"
    return "open"


def library_attach(request: int, space: bytes, purpose: int, signed: bytes) -> bytes:
    """"LibraryAttach": exactly these keys, on a space-traffic connection's
    control stream."""
    return cbor({0: LIBRARY_ATTACH, 1: request, 2: space, 3: purpose, 4: signed})


class LibraryPeer:
    """A peer's libraries, attachments and ledgers ("Settings", "What a peer
    keeps", "Attaching")."""

    def __init__(self, issuers, libraries: dict):
        self.issuers = set(issuers)
        assert len(self.issuers) <= MAX_ISSUERS
        self.libraries = {name: {"quota": None, "state": "open", "erasure_timeout": T_DEFAULT,
                                 **settings} for name, settings in libraries.items()}
        self.spaces: dict[bytes, dict] = {}
        self.used: dict[bytes, int] = {}
        self.erased: set = set()
        self.deleted: set = set()
        self.handed_over: set = set()

    def usage(self, library: str) -> int:
        """used_bytes: its spaces' usage (peers.md, "Quotas and rates"), with
        their invite drops."""
        return sum(s["used"] + s.get("drop_bytes", 0) for s in self.spaces.values()
                   if s["library"] == library)

    def headroom(self, library: str):
        quota = self.libraries[library]["quota"]
        return None if quota is None else quota - self.usage(library)

    def space_usage(self, space: bytes) -> int:
        s = self.spaces[space]
        return s["used"] + s.get("drop_bytes", 0)

    def attach(self, purpose: int, space: bytes, signed: bytes, now_wall: int | None, at: int,
               *, store_right: bool = False, first_is_genesis: bool = True,
               used_bytes: int = 0) -> str:
        """"Attaching", in order, for each purpose. Returns "attached" or the
        class."""
        try:
            if purpose in (CREATE, IMPORT):
                if space in self.spaces:
                    return "SpaceExists"
            elif not store_right:
                return "NotAuthorized"
            t = check_ticket(signed, issuers=self.issuers, now_wall=now_wall, used=self.used,
                             purpose=purpose, libraries=self.libraries)
        except SpecError as error:
            return error.error
        if purpose == CREATE and not first_is_genesis:
            # The attachment lapses with the connection; the ticket is spent.
            self.used[t["id"]] = t["not_after"]
            return "NotAuthorized"
        # The attach is accepted; the genesis that follows is refused Erased
        # for a space erased, deleted or handed over here (an import: only
        # erased), so only a holder of the genesis learns of it. The ticket is
        # spent.
        gone = self.erased | self.deleted | self.handed_over if purpose == CREATE else self.erased
        if purpose != MOVE and space in gone:
            self.used[t["id"]] = t["not_after"]
            return "Erased"
        if t["library"] not in self.libraries:
            self.libraries[t["library"]] = {"quota": None, "state": "open",
                                            "erasure_timeout": T_DEFAULT}
        if purpose == MOVE:
            room = self.headroom(t["library"])
            if room is not None and room < self.space_usage(space):
                return "QuotaExceeded"
            self.spaces[space].update(library=t["library"], ticket=t["id"], at=at)
        else:
            self.spaces[space] = {"library": t["library"], "ticket": t["id"], "at": at,
                                  "used": used_bytes, "released": 0, "covered": 0,
                                  "streams": 0}
        self.used[t["id"]] = t["not_after"]
        return "attached"

    def ledger(self, library: str) -> dict:
        """A library's ledger, as the issuer reads it."""
        lib = self.libraries[library]
        spaces = sorted((k, v) for k, v in self.spaces.items() if v["library"] == library)
        used = sum(v["used"] + v.get("drop_bytes", 0) for _, v in spaces)
        return {"library": library, "used_bytes": used,
                "released_bytes": sum(v["released"] for _, v in spaces),
                "covered_bytes": sum(v["covered"] for _, v in spaces),
                "erasing_bytes": sum(v.get("erasing", 0) for _, v in spaces),
                "drops": sum(v.get("drops", 0) for _, v in spaces),
                "drop_bytes": sum(v.get("drop_bytes", 0) for _, v in spaces),
                "held_bytes": sum(v.get("held", 0) for _, v in spaces),
                "quota_bytes": lib["quota"],
                "headroom_bytes": None if lib["quota"] is None else lib["quota"] - used,
                "erasure_timeout": lib["erasure_timeout"], "state": lib["state"],
                "spaces": [{"space": h(k), "used_bytes": v["used"] + v.get("drop_bytes", 0),
                            "drops": v.get("drops", 0), "drop_bytes": v.get("drop_bytes", 0),
                            "released_bytes": v["released"], "covered_bytes": v["covered"],
                            "held_bytes": v.get("held", 0), "holds": v.get("holds", 0),
                            "streams": v["streams"], "last_store_day": v.get("day")}
                           for k, v in spaces]}


# ---------------------------------------------------------------------------
# Holds ("Object keys and access keys", "HoldObject", "Registering a hold",
# "Keeping a held object").


def access_seed(object_key: bytes) -> bytes:
    """`access_seed = HKDF(none, object key, "frasil/object-access/v1")`."""
    return hkdf(NO_SALT, object_key, ACCESS_LABEL)


def access_key(object_key: bytes) -> bytes:
    return ed25519_public(access_seed(object_key))


def held(binding: bytes, space: bytes, source: bytes, locator: bytes, access: bytes) -> bytes:
    return field(binding) + field(space) + field(source) + field(locator) + field(access)


def hold_proof(object_key: bytes, binding: bytes, space: bytes, source: bytes,
               locator: bytes) -> bytes:
    access = access_key(object_key)
    return ed25519_sign_deterministic(access_seed(object_key),
                                      HOLD_LABEL + held(binding, space, source, locator, access))


def hold_object(request: int, space: bytes, source: bytes, locator: bytes, access: bytes,
                proof: bytes) -> bytes:
    return cbor({0: HOLD_OBJECT, 1: request, 2: space, 3: source, 4: locator, 5: access,
                 6: proof})


def read_hold_object(message: bytes) -> dict:
    """"Registering a hold", step 1."""
    m = uncbor(message)
    if not (isinstance(m, dict) and set(m) == set(range(7)) and m[0] == HOLD_OBJECT
            and is_uint(m[1]) and is_bytes(m[2], 32) and is_bytes(m[3], 32)
            and is_bytes(m[4], 64) and is_bytes(m[5], 32) and is_bytes(m[6], 64)
            and m[2] != m[3]):
        raise SpecError("Malformed")
    return {"request": m[1], "space": m[2], "source": m[3], "locator": m[4], "access": m[5],
            "proof": m[6]}


class HoldPeer:
    """What a peer keeps of objects, units and holds for this document's
    procedures: each space's library, the objects each space stores whole,
    the locators each stored unit lists, the holds, and the erased spaces."""

    def __init__(self, libraries: dict):
        self.library = dict(libraries)          # space -> library
        self.objects: dict = {}                  # (space, locator) -> bytes
        self.units: dict = {}                    # space -> {unit name: set of locators}
        self.holds: dict = {}                    # (space, locator) -> hold
        self.erased: set = set()                 # spaces erased

    def check(self, message: bytes, *, binding: bytes, store: set, fetch: set) -> dict:
        """"Registering a hold", in order. `store` and `fetch` are the spaces
        the connection holds those rights for."""
        m = read_hold_object(message)
        if m["space"] not in store:
            raise SpecError("NotAuthorized")
        if not ed25519_valid(m["access"]) or not ed25519_verify_strict(
                m["access"], HOLD_LABEL + held(binding, m["space"], m["source"], m["locator"],
                                               m["access"]), m["proof"]):
            raise SpecError("HoldRefused")
        if m["source"] not in fetch and not any(
                locator == m["locator"] and hold["access"] == m["access"]
                for (_, locator), hold in self.holds.items()):
            raise SpecError("HoldRefused")
        key = (m["source"], m["locator"])
        if key not in self.objects or m["source"] in self.erased:
            raise SpecError("UnknownObject")
        if self.library.get(m["space"]) is None \
                or self.library.get(m["space"]) != self.library.get(m["source"]):
            raise SpecError("OtherLibrary")
        return m

    def register(self, message: bytes, now: int, **rights) -> str:
        try:
            m = self.check(message, **rights)
        except SpecError as error:
            return error.error
        self.holds.setdefault((m["space"], m["locator"]),
                              {"source": m["source"], "access": m["access"], "at": now})
        return "accepted"

    def lists(self, space: bytes, locator: bytes) -> bool:
        return any(locator in listed for listed in self.units.get(space, {}).values())

    def live(self, space: bytes, locator: bytes, now: int) -> bool:
        """A hold is live while its space stores a unit that lists the
        locator, or, until one does, for orphan_grace from its
        registration."""
        hold = self.holds[(space, locator)]
        return self.lists(space, locator) or now - hold["at"] < ORPHAN_GRACE

    def sweep(self, now: int) -> None:
        """Ends the holds that are not live, then collects every object no
        unit of its space lists and no live hold names; the objects of an
        erased space go whatever holds them, and so do the holds an erased
        space registered."""
        for key in [k for k in self.holds if k[0] in self.erased or not self.live(*k, now)]:
            del self.holds[key]
        for (space, locator) in list(self.objects):
            held_by = [k for k, hold in self.holds.items()
                       if k[1] == locator and hold["source"] == space]
            if space in self.erased or not (self.lists(space, locator) or held_by):
                del self.objects[(space, locator)]

    def ledger_bytes(self, space: bytes) -> dict:
        """A space's object bytes as the ledger counts them: each object once,
        in its source's usage; held_bytes those only holds keep."""
        used = sum(n for (s, _), n in self.objects.items() if s == space)
        held_only = sum(n for (s, loc), n in self.objects.items()
                        if s == space and not self.lists(s, loc))
        holds = sum(1 for (s, _) in self.holds if s == space)
        return {"used_bytes": used, "held_bytes": held_only, "holds": holds}


# ---------------------------------------------------------------------------
# Vectors: ext-libraries.json.

ISSUER_SEED = example("library/issuer")
OTHER_SEED = example("library/another-issuer")
NOW = 1_792_000_000  # the reference instant: a wall-clock instant, in seconds since 1970
SPACE_A = example("library/space-a")
SPACE_B = example("library/space-b")


def _ticket(purpose: int, *, library: str = "project:7c1f9e2a0b4d4e8f", name: str = "a",
            not_after: int = NOW + 3600, seed: bytes = ISSUER_SEED) -> dict:
    ticket = encode_ticket(library, example(f"library/ticket/{name}")[:16], purpose, not_after,
                           ed25519_public(seed))
    signed = sign_ticket(seed, ticket)
    return {"purpose": PURPOSES[purpose], "library": library, "not_after": not_after,
            "ticket": h(ticket), "signed_message": h(TICKET_LABEL + ticket),
            "signature": h(uncbor(signed)[1]), "signed": h(signed), "_signed": signed}


def _strip(t: dict) -> dict:
    return {k: v for k, v in t.items() if not k.startswith("_")}


def _verdict(cls: str) -> dict:
    if cls in ("accepted", "attached"):
        return {"verdict": cls}
    code, status = CODES[cls]
    return {"verdict": cls, "code": code, "status": status}


def _checks() -> list:
    issuers = {ed25519_public(ISSUER_SEED)}
    libraries = {"project:7c1f9e2a0b4d4e8f": {"state": "open"},
                 "personal:0d5b2c": {"state": "suspended"}}
    good = _ticket(CREATE)
    out = []

    def run(label, signed, *, now=NOW, used=(), purpose=CREATE):
        try:
            check_ticket(signed, issuers=issuers, now_wall=now, used=set(used), purpose=purpose,
                         libraries=libraries)
            verdict = "accepted"
        except SpecError as error:
            verdict = error.error
        out.append({"name": label, "signed": h(signed), "now": now,
                    "purpose": PURPOSES[purpose], "used": [h(u) for u in used],
                    "issuers": sorted(h(i) for i in issuers),
                    "libraries": {n: lib["state"] for n, lib in sorted(libraries.items())},
                    **_verdict(verdict)})

    run("a good ticket", good["_signed"])
    run("not a ticket", cbor([b"x", bytes(64)]))
    run("an untrusted issuer", _ticket(CREATE, seed=OTHER_SEED)["_signed"])
    raw = uncbor(good["_signed"])
    run("a changed signature", cbor([raw[0], raw[1][:-1] + bytes([raw[1][-1] ^ 1])]))
    run("past not_after, by one second", _ticket(CREATE, not_after=NOW - 1,
                                                 name="old")["_signed"])
    run("not_after beyond ticket_lifetime and ticket_skew",
        _ticket(CREATE, not_after=NOW + TICKET_LIFETIME + TICKET_SKEW + 1,
                name="long")["_signed"])
    run("a used ticket ID", good["_signed"], used=[example("library/ticket/a")[:16]])
    run("another purpose", good["_signed"], purpose=MOVE)
    run("a suspended library", _ticket(CREATE, library="personal:0d5b2c",
                                       name="suspended")["_signed"])
    run("a peer whose wall clock is not known", good["_signed"], now=None)
    run("a library ID holding a control character",
        sign_ticket(ISSUER_SEED, encode_ticket("project:\u0007", bytes(16), CREATE, NOW,
                                               ed25519_public(ISSUER_SEED))))
    # ext-deposit-tokens.md's grant, at a peer that does not implement it:
    # purpose 4 and key 7 are refused in step 1.
    issuer = ed25519_public(ISSUER_SEED)
    run("a deposit grant, purpose 4 with key 7, at a peer without deposit tokens",
        sign_ticket(ISSUER_SEED, encode_ticket("project:7c1f9e2a0b4d4e8f",
                                               example("library/ticket/grant")[:16], DEPOSIT,
                                               NOW + 3600, issuer, tokens=16)))
    run("key 7 on purpose 1",
        sign_ticket(ISSUER_SEED, encode_ticket("project:7c1f9e2a0b4d4e8f",
                                               example("library/ticket/key-7")[:16], CREATE,
                                               NOW + 3600, issuer, tokens=16)))
    return out


def _library_attach() -> list:
    """`library_attach`: transport's LibraryAttach for each purpose, as it
    travels, carrying the tickets of `tickets`."""
    return handshakes.ext_libraries_library_attach(
        {p: _ticket(p, name=f"purpose-{p}")["_signed"] for p in (CREATE, IMPORT, MOVE)})


def _import_case() -> dict:
    """Import: every imported rotation starts retired, and only the
    importer's proofs make entries live, so a removed writer's racing
    rotation stays retired."""
    r = storage.StorageRoster("P", "library/import")
    r.root("P0")
    r.sync("P", "P0")
    r.grant("P", "W", roster.WRITE, label="P grants W write")
    r.sync("P", "P0", "W")
    before = set(r.hist.view["W"])
    rm = r.remove("P", "W", "P removes W")
    r.heal("W", "W rotates, racing its removal", view=before)
    cred = storage.Credentials(r.log)
    for i in r.log.canonical():
        e = r.log.events[i]
        if e.kind == KIND_SPACE and roster.read_visible(e)["rotates"]:
            cred.add_rotation(i, source="import", live=False)
    binding = handshakes.peer_binding(example("library/channel"), example("library/nonce-p"),
                                      example("library/nonce-c"), storage.SPACE_TRAFFIC)
    upload = roster.read_visible(r.log.events[rm])["upload"]
    p = storage.make_proof(r.upload_seed(rm), binding, r.id, storage.UPLOAD_KEY, upload)
    verdict = cred.check_present(storage.UPLOAD_KEY, r.id, upload, p["proof"],
                                 {"binding": binding, "purpose": storage.SPACE_TRAFFIC,
                                  "importing": True})
    return {"events": r.hist.describe(), "proof": {"presented": h(p["presented"]),
                                                   "proof": h(p["proof"]), "verdict": verdict},
            "entries": cred.describe(r.name)}


def _attach_cases() -> dict:
    issuers = {ed25519_public(ISSUER_SEED)}
    peer = LibraryPeer(issuers, {"project:7c1f9e2a0b4d4e8f": {"quota": 1000},
                                 "personal:9a4e01": {"quota": 100}})
    steps = []

    def step(label, purpose, space, ticket, verdict, **given):
        steps.append({"step": label, "purpose": PURPOSES[purpose], "space": h(space),
                      "ticket": ticket["signed"], "now": NOW, **given, **_verdict(verdict),
                      "recorded": {h(k): {"library": v["library"], "ticket_id": h(v["ticket"]),
                                          "at": v["at"]}
                                   for k, v in sorted(peer.spaces.items())},
                      "tickets_used": sorted(h(u) for u in peer.used)})

    t1 = _ticket(CREATE, name="create-a")
    step("create space A", CREATE, SPACE_A, t1,
         peer.attach(CREATE, SPACE_A, t1["_signed"], NOW, 10, used_bytes=400),
         reading=10, used_bytes=400)
    t1b = _ticket(CREATE, name="create-a2")
    step("create space A again: a space that exists", CREATE, SPACE_A, t1b,
         peer.attach(CREATE, SPACE_A, t1b["_signed"], NOW, 11), reading=11)
    t0 = _ticket(CREATE, name="create-b0")
    step("create space B, whose first stored event is not its genesis", CREATE, SPACE_B, t0,
         peer.attach(CREATE, SPACE_B, t0["_signed"], NOW, 12, first_is_genesis=False),
         reading=12, first_stored_is_genesis=False)
    t2 = _ticket(IMPORT, name="import-b")
    step("import space B", IMPORT, SPACE_B, t2,
         peer.attach(IMPORT, SPACE_B, t2["_signed"], NOW, 13, used_bytes=300),
         reading=13, used_bytes=300)
    t3 = _ticket(MOVE, library="personal:9a4e01", name="move-a")
    step("move space A, with the store right, to a library without headroom", MOVE, SPACE_A,
         t3, peer.attach(MOVE, SPACE_A, t3["_signed"], NOW, 14, store_right=True),
         reading=14, store_right=True)
    t4 = _ticket(MOVE, library="personal:9a4e01", name="move-a2")
    step("move space A without the store right", MOVE, SPACE_A, t4,
         peer.attach(MOVE, SPACE_A, t4["_signed"], NOW, 15), reading=15, store_right=False)
    peer.libraries["personal:9a4e01"]["quota"] = 500
    step("move space A once the library's quota is 500", MOVE, SPACE_A, t4,
         peer.attach(MOVE, SPACE_A, t4["_signed"], NOW, 16, store_right=True),
         reading=16, store_right=True)
    # A release in space B, a snapshot that covers units there, an invite drop.
    peer.spaces[SPACE_B].update(released=50, covered=20, streams=3, day="2026-10-19",
                                drops=1, drop_bytes=1200)
    peer.spaces[SPACE_A].update(streams=1, day="2026-10-18")
    ledgers = [peer.ledger("project:7c1f9e2a0b4d4e8f"), peer.ledger("personal:9a4e01")]
    return {"steps": steps, "ledgers": ledgers,
            "after": "space B released 50 bytes, a snapshot covered 20 bytes, and one invite "
                     "drop of 1,200 bytes was kept; space A has one stream"}


HOLD_SOURCE = example("library/hold/source")
HOLD_SPACE = example("library/hold/space")
HOLD_THIRD = example("library/hold/third")
HOLD_ELSEWHERE = example("library/hold/elsewhere")
HOLD_BINDING = handshakes.peer_binding(example("library/hold/channel"),
                                       example("library/hold/nonce-p"),
                                       example("library/hold/nonce-c"), storage.SPACE_TRAFFIC)


def _held_object() -> dict:
    """An object sealed in HOLD_SOURCE under one state (units.md)."""
    import units
    content_key = example("library/hold/content-key")
    key_ref = bytes([1]) + example("library/hold/rotation")
    obj = units.seal_object(HOLD_SOURCE, content_key, key_ref, b"a show's opening video")
    return {"content_key": content_key, "key_reference": key_ref, **obj}


def _access_keys(obj: dict) -> dict:
    okey = obj["object_key"]
    return {"source": h(HOLD_SOURCE), "content_key": h(obj["content_key"]),
            "key_reference": h(obj["key_reference"]), "object_id": h(obj["id"]),
            "locator": h(obj["locator"]), "object_key": h(okey),
            "access_seed": h(access_seed(okey)), "access_key": h(access_key(okey))}


def _hold_message(obj: dict, space: bytes = HOLD_SPACE, request: int = 1,
                  okey: bytes | None = None) -> bytes:
    okey = okey if okey is not None else obj["object_key"]
    proof = hold_proof(okey, HOLD_BINDING, space, HOLD_SOURCE, obj["locator"])
    return hold_object(request, space, HOLD_SOURCE, obj["locator"], access_key(okey), proof)


def _hold_vectors(obj: dict) -> dict:
    okey = obj["object_key"]
    message = _hold_message(obj)
    m = uncbor(message)
    return {"binding": h(HOLD_BINDING), "space": h(HOLD_SPACE), "source": h(HOLD_SOURCE),
            "locator": h(obj["locator"]), "access": h(access_key(okey)),
            "held": h(held(HOLD_BINDING, HOLD_SPACE, HOLD_SOURCE, obj["locator"],
                           access_key(okey))),
            "signed": h(HOLD_LABEL + held(HOLD_BINDING, HOLD_SPACE, HOLD_SOURCE, obj["locator"],
                                          access_key(okey))),
            "proof": h(m[6]), "message": h(message)}


def _hold_checks(obj: dict) -> list:
    library = "project:7c1f9e2a0b4d4e8f"
    peer = HoldPeer({HOLD_SOURCE: library, HOLD_SPACE: library, HOLD_THIRD: library,
                     HOLD_ELSEWHERE: "personal:9a4e01"})
    peer.objects[(HOLD_SOURCE, obj["locator"])] = len(obj["bytes"])
    out = []

    def listed():
        return sorted([h(s), h(loc), h(hold["access"])] for (s, loc), hold in peer.holds.items())

    def run(name, message, *, store, fetch, now=NOW):
        before = listed()
        verdict = peer.register(message, now, binding=HOLD_BINDING, store=set(store),
                                fetch=set(fetch))
        out.append({"name": name, "message": h(message), "binding": h(HOLD_BINDING),
                    "store_right": sorted(h(x) for x in store),
                    "fetch_right": sorted(h(x) for x in fetch),
                    "libraries": {h(k): v for k, v in sorted(peer.library.items())},
                    "objects": sorted([h(s), h(loc)] for s, loc in peer.objects),
                    "holds_before": before, **_verdict(verdict), "holds_after": listed()})

    good = _hold_message(obj)
    run("without the store right for the holding space", good, store=[], fetch=[HOLD_SOURCE])
    raw = uncbor(good)
    changed = cbor(raw | {6: raw[6][:-1] + bytes([raw[6][-1] ^ 1])})
    run("a changed proof", changed, store=[HOLD_SPACE], fetch=[HOLD_SOURCE])
    run("an access key nothing vouches for: no fetch right for the source, and no hold",
        good, store=[HOLD_SPACE], fetch=[])
    run("a hold under the source's fetch right", good, store=[HOLD_SPACE], fetch=[HOLD_SOURCE])
    run("the same hold again", good, store=[HOLD_SPACE], fetch=[HOLD_SOURCE])
    run("a reference of a reference: another space, under the access key a hold carries",
        _hold_message(obj, space=HOLD_THIRD, request=2), store=[HOLD_THIRD], fetch=[])
    other = dict(obj, locator=obj["id"] + bytes(32))
    run("an object the source does not hold", _hold_message(other, request=3),
        store=[HOLD_SPACE], fetch=[HOLD_SOURCE])
    run("a source billed to another library",
        _hold_message(obj, space=HOLD_ELSEWHERE, request=4), store=[HOLD_ELSEWHERE],
        fetch=[HOLD_SOURCE])
    return out


def _held_objects(obj: dict) -> dict:
    """The source drops its entry: the hold keeps the object until the
    holding space's last unit that lists it goes. An erasure of the source
    space removes the object whatever holds it."""
    library = "project:7c1f9e2a0b4d4e8f"
    peer = HoldPeer({HOLD_SOURCE: library, HOLD_SPACE: library})
    loc = obj["locator"]
    size = len(obj["bytes"])
    peer.objects[(HOLD_SOURCE, loc)] = size
    peer.units[HOLD_SOURCE] = {"a1": {loc}}
    assert peer.register(_hold_message(obj), NOW, binding=HOLD_BINDING, store={HOLD_SPACE},
                         fetch={HOLD_SOURCE}) == "accepted"
    peer.units[HOLD_SPACE] = {"b1": {loc}}
    steps = []

    def step(name, now):
        peer.sweep(now)
        steps.append({"step": name, "now": now,
                      "units": {h(s): {u: [h(x) for x in sorted(v)] for u, v in sorted(us.items())}
                                for s, us in sorted(peer.units.items())},
                      "holds": sorted([h(s), h(l)] for s, l in peer.holds),
                      "kept": sorted([h(s), h(l)] for s, l in peer.objects),
                      "ledger": {"source": peer.ledger_bytes(HOLD_SOURCE),
                                 "holding": peer.ledger_bytes(HOLD_SPACE)}})

    step("the source and the holding space both list the object", NOW)
    del peer.units[HOLD_SOURCE]["a1"]
    step("the source's unit that listed it is collected: the hold keeps it", NOW + 10)
    step("past orphan_grace from the hold's registration, while the holding unit is stored",
         NOW + ORPHAN_GRACE + 10)
    del peer.units[HOLD_SPACE]["b1"]
    step("the holding space's last unit that listed it is collected: the hold ends, and the "
         "object is collected", NOW + ORPHAN_GRACE + 20)
    assert not peer.objects and not peer.holds
    # An erasure of the source space removes the object whatever holds it.
    peer.objects[(HOLD_SOURCE, loc)] = size
    peer.units[HOLD_SOURCE] = {"a2": {loc}}
    peer.units[HOLD_SPACE] = {"b2": {loc}}
    peer.holds[(HOLD_SPACE, loc)] = {"source": HOLD_SOURCE, "access": access_key(
        obj["object_key"]), "at": NOW}
    step("the object listed again and held again", NOW + ORPHAN_GRACE + 30)
    peer.erased.add(HOLD_SOURCE)
    del peer.units[HOLD_SOURCE]
    step("an erasure of the source space executes", NOW + ORPHAN_GRACE + 40)
    assert not peer.objects
    return {"source": h(HOLD_SOURCE), "space": h(HOLD_SPACE), "locator": h(loc),
            "object_bytes": size, "orphan_grace": ORPHAN_GRACE, "steps": steps}


def ext_libraries_vectors() -> dict:
    attach = _attach_cases()
    obj = _held_object()
    return {
        "parameters": {"max_ticket_bytes": MAX_TICKET_BYTES,
                       "max_library_id_bytes": MAX_LIBRARY_ID_BYTES,
                       "max_issuers": MAX_ISSUERS, "library_service": LIBRARY_SERVICE,
                       "library_attach_type": LIBRARY_ATTACH,
                       "hold_object_type": HOLD_OBJECT, "orphan_grace": ORPHAN_GRACE,
                       "ticket_lifetime": TICKET_LIFETIME, "ticket_skew": TICKET_SKEW,
                       "erasure_timeout": {"default": T_DEFAULT, "range": list(T_RANGE)},
                       "detached_grace": {"default": DETACHED_GRACE,
                                          "range": list(DETACHED_GRACE_RANGE)},
                       "now": NOW, "issuer_seed": h(ISSUER_SEED),
                       "issuer": h(ed25519_public(ISSUER_SEED)),
                       "classes": {c: {"code": code, "status": status}
                                   for c, (code, status) in CODES.items()}},
        "tickets": [_strip(_ticket(p, name=f"purpose-{p}")) for p in (CREATE, IMPORT, MOVE)],
        "library_attach": _library_attach(),
        "ticket_checks": _checks(),
        "attachments": attach["steps"],
        "import": _import_case(),
        "ledgers": {"libraries": attach["ledgers"], "after": attach["after"]},
        "access_keys": _access_keys(obj),
        "hold_object": _hold_vectors(obj),
        "holds": _hold_checks(obj),
        "held_objects": _held_objects(obj),
    }


def self_test() -> None:
    for new in NEW_LABELS:
        for other in storage.NEW_LABELS:
            assert not other.startswith(new) and not new.startswith(other)
    v = ext_libraries_vectors()
    verdicts = [c["verdict"] for c in v["ticket_checks"]]
    assert verdicts == ["accepted", "Malformed", "TicketRefused", "TicketRefused",
                        "TicketExpired", "TicketExpired", "TicketUsed", "TicketRefused",
                        "LibraryClosed", "TicketExpired", "Malformed", "Malformed",
                        "Malformed"], verdicts
    steps = [s["verdict"] for s in v["attachments"]]
    assert steps == ["attached", "SpaceExists", "NotAuthorized", "attached", "QuotaExceeded",
                     "NotAuthorized", "attached"], steps
    imp = v["import"]
    assert imp["proof"]["verdict"] == "store, release"
    live = [e["state"] for e in imp["entries"] if e["status"] == "live"]
    assert live == [["P removes W"]], live
    # Erased: a create of a deleted space, while an import of it is allowed.
    peer = LibraryPeer({ed25519_public(ISSUER_SEED)}, {})
    peer.deleted.add(SPACE_A)
    assert peer.attach(CREATE, SPACE_A, _ticket(CREATE, name="x")["_signed"], NOW, 1) == "Erased"
    assert peer.attach(IMPORT, SPACE_A, _ticket(IMPORT, name="y")["_signed"], NOW, 1) \
        == "attached"
    # The ticket is checked first, so a stranger learns nothing of a space
    # erased, deleted or handed over here; a genesis holder's create spends
    # the ticket and is refused Erased.
    peer = LibraryPeer({ed25519_public(ISSUER_SEED)}, {})
    peer.handed_over.add(SPACE_B)
    stranger = LibraryPeer(set(), {})
    stranger.handed_over.add(SPACE_B)
    assert stranger.attach(CREATE, SPACE_B, _ticket(CREATE, name="z")["_signed"], NOW, 1) \
        == "TicketRefused"
    z = _ticket(CREATE, name="z2")
    assert peer.attach(CREATE, SPACE_B, z["_signed"], NOW, 1) == "Erased"
    assert peer.attach(CREATE, SPACE_B, z["_signed"], NOW, 1) == "TicketUsed"
    check_expiry(NOW + TICKET_LIFETIME + TICKET_SKEW, NOW, TICKET_LIFETIME, TICKET_SKEW)
    holds = [c["verdict"] for c in v["holds"]]
    assert holds == ["NotAuthorized", "HoldRefused", "HoldRefused", "accepted", "accepted",
                     "accepted", "UnknownObject", "OtherLibrary"], holds
    kept = [len(s["kept"]) for s in v["held_objects"]["steps"]]
    assert kept == [1, 1, 1, 0, 1, 0], kept
    ledger = v["held_objects"]["steps"][1]["ledger"]
    assert ledger["source"]["held_bytes"] == ledger["source"]["used_bytes"] > 0
    assert ledger["holding"]["used_bytes"] == 0 and ledger["holding"]["holds"] == 1
    assert v == ext_libraries_vectors(), "the vectors are not deterministic"


if __name__ == "__main__":
    import json
    self_test()
    print(json.dumps(ext_libraries_vectors(), indent=1)[:3000])
