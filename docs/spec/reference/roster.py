"""The branching roster (roster.md), written from the specification,
independently of any implementation: the space event's sealed body and its per-event body
key, the roster part of a genesis and an update, the member state and its
meet, the space policy's merge, authority at an event's place, the attack
relation, the resolution procedure, the write rule for units and key events
across logs, derived frontiers and their encoding, stability, the events that
void each void event, duel cascades, re-submission, and what a newcomer's
snapshot carries to open the space events it cannot; the invite key and its
successor (admission.md), and storage events as far as this
specification reads them (their authors' keys, the twin step through a
`StorageView` that peers.md's reference supplies). A space event's body is keys.md's rotation
payload, read and opened by keygraph.py; the vectors' payloads carry no
deliveries, and keys.md's own vectors test whole ones."""

from __future__ import annotations

import copy
import itertools
import json
from dataclasses import dataclass, field as dc_field

import events
import history_sigs as hs
import identity
import keygraph as kg
import spaces
import xwing
from events import (
    KIND_ANCHOR, KIND_SPACE, KIND_STORAGE, KIND_UNIT, History, Log, cbor, decide, h, is_bytes,
    is_uint, uncbor,
)
from formats import example, hybrid_key_valid, identifier_ok
from primitives import (
    SpecError, ed25519_public, ed25519_valid, field, sha256, xchacha20poly1305_open,
    xchacha20poly1305_seal,
)

KIND_ROSTER = KIND_SPACE  # the space event: roster events and key events share kind 2

SENIORITY_LABEL = b"frasil/roster/seniority/v1"
RECORD_LABEL = b"frasil/checkpoint-record/v1"
NEW_LABELS = [SENIORITY_LABEL, RECORD_LABEL]

GENESIS, UPDATE, CHECKPOINT = 0, 1, 2  # roster part types; from 3: reserved, held
GRANT, CHANGE, REMOVE, POLICY, SUCCEED = 0, 1, 2, 3, 4  # 5 to 7: unassigned, Malformed
DEVICE, PERSON, SPACE, INVITE = 0, 1, 2, 3  # 3: an invite key (admission.md)
READ, WRITE, ADMINISTER = 0, 1, 2
FROM_NOW_ON, WITH_HISTORY = 0, 1
VIA_CODE, VIA_LINK, VIA_LOOKUP, VIA_NONE = 0, 1, 2, 3
EXTENDS, NARROWS = 0, 1
OP_NAMES = {GRANT: "grant", CHANGE: "change", REMOVE: "remove", POLICY: "policy",
            SUCCEED: "succeed"}
TYPE_NAMES = {DEVICE: "device", PERSON: "person", SPACE: "space", INVITE: "invite"}
LEVEL_NAMES = {READ: "read", WRITE: "write", ADMINISTER: "administer"}
VIA_NAMES = {VIA_CODE: "code", VIA_LINK: "link", VIA_LOOKUP: "lookup", VIA_NONE: "none"}

G_TYPE, G_FOUNDER, G_DUEL, G_POLICY, G_DESCRIPTOR, G_SYSTEM_STREAM = range(6)
SYSTEM_STREAM_BYTES = 16  # a stream ID (roster.md), random and sealed
U_TYPE, U_CHANGES = range(2)
# A checkpoint's roster part (roster.md, "Checkpoints"): its type, its epoch,
# the record's digest and size, and the locator of the object that holds it.
K_TYPE, K_EPOCH, K_DIGEST, K_SIZE, K_LOCATOR = range(5)
MAX_RECORD_BYTES = 256 * 1024 * 1024
# The record (roster.md, "The checkpoint record") and a member entry in it.
R_VERSION, R_EPOCH, R_PREVIOUS, R_MEMBERS, R_POLICY, R_TIPS, R_FORKS = range(1, 8)
R_HEARD = 8  # the heard members (roster.md, "Votes and effect")
(M_MEMBER, M_LEVEL, M_CAPS, M_LABEL, M_HISTORY, M_VIA, M_SESSION, M_REPLACES, M_SENIORITY,
 M_ED25519, M_MLDSA, M_XWING, M_SLOT, M_EXPIRES, M_CLAIMS, M_INVITE, M_CLAIMANT, M_NOTICES,
 M_FLOOR, M_NAMED, M_RANK) = range(1, 22)
# An invite key's status in a record (ext-invite-links.md, "Across a checkpoint").
INVITE_OPEN, INVITE_CLAIMED, INVITE_RACED, INVITE_USED = range(4)
DORMANT = "frasil.dormant"  # an administrator a checkpoint does not wait for
# Change key 12 is a device grant's Ed25519 key (roster.md, "A device's keys").
(C_OP, C_MEMBER, C_LEVEL, C_CAPS, C_LABEL, C_HISTORY, C_VIA, C_SESSION, C_REPLACES,
 C_HYBRID, C_MLDSA, C_POLICY, C_ED25519, C_EXPIRES, C_CLAIMS, C_RANK) = range(16)
# An administrator's rank (section 2.3): 0 to 255, the larger outranks; the
# founder holds the top rank.
MAX_RANK = 255
# duel_policy 0: ranks decide, and between equals the more senior's lowering
# stands (section 3.5.2).
DUEL_RANKS = 0
DUEL_BOTH_STAND = DUEL_RANKS  # the name the builders use
MAX_U64 = 2 ** 64 - 1
CAPABILITY_RESERVED_PREFIX = "frasil."  # Names only Frasil's specifications define

MAX_CHANGES = 256
MAX_DEVICE_GRANTS = 64  # about 3.2 KB each: 64 fit a 1 MiB space event with room for wraps
S_REFS = 18  # inner key of a space event's sealed part: its refs
MAX_CAPS = 32
MAX_NAME_BYTES = 64
MAX_ROSTER_EVENTS = 4096
NONCE_BYTES = 16
SESSION_BYTES = 16
MLDSA_BYTES = events.MLDSA_PUBLIC_BYTES
HYBRID_BYTES = xwing.XWING_PK_SIZE

# How concurrent policies merge, field by field: the stricter.
POLICY_MERGE = {
    "agent_waiting_period": max,
    "gap_key_timeout": max,
    "bounded_window": "min-on",
    "online_freshness": "min-on",
    "forbid_agents": any,
}

# ---------------------------------------------------------------------------
# Bodies.


@dataclass(frozen=True)
class Change:
    op: int
    member: tuple | None = None  # (type, id); none for a policy change
    level: int | None = None
    caps: tuple | None = None  # ((name, mode), ...) by name
    label: str | None = None
    history: int | None = None
    via: int | None = None
    session: bytes | None = None
    replaces: bytes | None = None
    hybrid: bytes | None = None
    mldsa: bytes | None = None
    policy: bytes | None = None
    ed25519: bytes | None = None  # change key 12: a device grant's Ed25519 key
    expires_at: int | None = None  # change key 13: an invite grant; a guest's grant
    claims: int | None = None  # change key 14: an invite grant, DEVICE or PERSON
    rank: int | None = None  # change key 15: an administrator's rank

    def encode(self) -> dict:
        out = {C_OP: self.op}
        if self.member is not None:
            out[C_MEMBER] = [self.member[0], self.member[1]]
        ed = self.ed25519
        if ed is None and self.op in (GRANT, SUCCEED) and self.member \
                and self.member[0] in (DEVICE, INVITE) and self.mldsa is not None:
            # The vectors' builders take the Ed25519 key of the example key
            # holder whose device ID the member names (events.KNOWN_SIGNERS).
            signer = events.KNOWN_SIGNERS.get(self.member[1])
            if signer is not None:
                ed = signer.ed_public
        for key, value in ((C_LEVEL, self.level), (C_LABEL, self.label),
                           (C_HISTORY, self.history), (C_VIA, self.via),
                           (C_SESSION, self.session), (C_REPLACES, self.replaces),
                           (C_HYBRID, self.hybrid), (C_MLDSA, self.mldsa),
                           (C_POLICY, self.policy), (C_ED25519, ed),
                           (C_EXPIRES, self.expires_at), (C_CLAIMS, self.claims),
                           # The builders' administer grants take the top
                           # rank unless they name one.
                           (C_RANK, self.rank if self.rank is not None or self.level
                            != ADMINISTER or self.member is None or self.member[0] != DEVICE
                            else MAX_RANK)):
            if value is not None:
                out[key] = value
        if self.caps is not None:
            out[C_CAPS] = [[n, m] for n, m in self.caps]
        return out


def member_id(ed: bytes, mldsa_public: bytes, hybrid: bytes) -> bytes:
    """roster.md, "A device's keys": the member ID a device grant's keys 12,
    10 and 9 give, the device ID of the three keys (crypto.md)."""
    return hs.device_id_of(ed, mldsa_public, hybrid)


def genesis_roster(founder: Change, *, policy: bytes | None = None,
                   descriptor: bytes | None = None, duel: int = DUEL_BOTH_STAND,
                   system_stream: bytes | None = None) -> bytes:
    """A genesis's roster part, sealed in its body. A client
    draws the system stream ID at random; the vectors' builders derive it
    from the founder's key when none is given."""
    if system_stream is None:
        system_stream = sha256(b"frasil spec example/system-stream" + founder.member[1])[
            :SYSTEM_STREAM_BYTES]
    return cbor({G_TYPE: GENESIS, G_FOUNDER: founder.encode(), G_DUEL: duel,
                 G_POLICY: policy if policy is not None else spaces.encode_policy({}),
                 G_DESCRIPTOR: descriptor if descriptor is not None
                 else spaces.encode_descriptor(spaces.KIND_SPACE),
                 G_SYSTEM_STREAM: system_stream})


def update_roster(changes: list[Change]) -> bytes:
    """An update's roster part, sealed in its body."""
    return cbor({U_TYPE: UPDATE, U_CHANGES: [c if isinstance(c, dict) else c.encode()
                                             for c in changes]})


def checkpoint_roster(record: bytes, locator: bytes) -> bytes:
    """A checkpoint's roster part (roster.md, "Checkpoints"): the record
    travels as an object, which `locator` names."""
    return cbor({K_TYPE: CHECKPOINT, K_EPOCH: uncbor(record)[R_EPOCH],
                 K_DIGEST: sha256(RECORD_LABEL + record), K_SIZE: len(record),
                 K_LOCATOR: locator})


def read_record_object(data: bytes, space: bytes, secret: bytes | None, part: dict,
                       object_key: bytes | None = None,
                       self_ref: bytes | None = None, chunk: int | None = None,
                       by_chunks: bool = False) -> tuple[dict, bytes]:
    """A checkpoint's record, from the object its roster part names, under
    the checkpoint's own content key (or the record's object key handed to a
    newcomer): units.md's object checks, then the record's size and digest.
    An object that opens but does not match the digest, or whose header's
    self reference is not `self_ref`, the checkpoint's own
    0x00 || author || u64be(seq), is BadCheckpoint: the locator binds that
    object."""
    import units  # noqa: the object reader
    reader = units.read_object_by_chunks if by_chunks else units.read_object
    kw = {} if chunk is None else {"chunk": chunk}
    plain = reader(data, space, secret, part["locator"], okey=object_key,
                   record=True, self_ref=self_ref, **kw)
    if len(plain) != part["size"] or sha256(RECORD_LABEL + plain) != part["digest"]:
        raise SpecError("BadCheckpoint")
    record = read_record(plain)
    if record["epoch"] != part["epoch"]:
        raise SpecError("BadCheckpoint")
    return record, plain


def encode_record(record: dict) -> bytes:
    """roster.md, "The checkpoint record": `record` as read_record gives it."""
    members = []
    for m in record["members"]:
        entry = {M_MEMBER: [m["member"][0], m["member"][1]]}
        if m.get("invite") != INVITE_CLAIMED:
            entry.update({M_LEVEL: m["level"], M_HISTORY: m["history"], M_VIA: m["via"],
                          M_SENIORITY: [m["seniority"][0], m["seniority"][1],
                                        m["seniority"][3]]})
        if m.get("caps"):
            entry[M_CAPS] = [[n, mode] for n, mode in sorted(m["caps"], key=lambda c: c[0].encode())]
        for key, name in ((M_LABEL, "label"), (M_SESSION, "session"),
                          (M_REPLACES, "replaces"), (M_ED25519, "ed25519"),
                          (M_MLDSA, "mldsa"), (M_XWING, "xwing"), (M_EXPIRES, "expires_at"),
                          (M_CLAIMS, "claims"), (M_INVITE, "invite")):
            if m.get(name) is not None:
                entry[key] = m[name]
        if m.get("slot") is not None:
            entry[M_SLOT] = list(m["slot"])
        if m.get("claimant") is not None:
            entry[M_CLAIMANT] = [m["claimant"][0], m["claimant"][1]]
        if m.get("notices"):
            entry[M_NOTICES] = [list(n) for n in sorted(m["notices"], key=lambda n: cbor(list(n)))]
        if m.get("floor"):
            entry[M_FLOOR] = 1
        if m.get("named"):
            entry[M_NAMED] = sorted(m["named"])
        if m.get("rank") is not None:
            entry[M_RANK] = m["rank"]
        members.append(entry)
    members.sort(key=lambda e: cbor(e[M_MEMBER]))
    out = {R_VERSION: 1, R_EPOCH: record["epoch"], R_MEMBERS: members,
           R_POLICY: spaces.encode_policy(record["policy"]),
           R_TIPS: [[a, s, i] for a, (s, i) in sorted(record["tips"].items())],
           R_FORKS: [[a, s] for a, s in sorted(record["forks"].items())]}
    if record.get("previous") is not None:
        out[R_PREVIOUS] = record["previous"]
    if record.get("heard"):
        out[R_HEARD] = [[d, [sen[0], sen[1], sen[3]], rank, *keys]
                        for d, (sen, rank, keys) in sorted(record["heard"].items())]
    return cbor(out)


def _record_member(entry) -> dict:
    """One member entry, in the order of roster.md, "The checkpoint record":
    its keys and their types (Malformed), then its keys' validity
    (InvalidKey) and their hash (NotCommitted) are left to read_record."""
    if not isinstance(entry, dict) or M_MEMBER not in entry:
        raise SpecError("Malformed")
    member = entry[M_MEMBER]
    if not (isinstance(member, list) and len(member) == 2 and is_uint(member[0])
            and member[0] in (DEVICE, PERSON, SPACE, INVITE) and is_bytes(member[1], 32)):
        raise SpecError("Malformed")
    mtype = member[0]
    keyed = mtype in (DEVICE, INVITE)
    claimed = mtype == INVITE and entry.get(M_INVITE) == INVITE_CLAIMED
    state = {M_LEVEL, M_CAPS, M_LABEL, M_HISTORY, M_VIA, M_SESSION, M_SENIORITY}
    allowed = {M_MEMBER}
    if claimed:
        allowed |= {M_ED25519, M_MLDSA, M_XWING, M_INVITE, M_CLAIMANT}
        required = set(allowed)
    else:
        allowed |= state
        required = {M_MEMBER, M_LEVEL, M_HISTORY, M_VIA, M_SENIORITY}
        if mtype == DEVICE:
            allowed |= {M_ED25519, M_MLDSA, M_XWING, M_SLOT, M_EXPIRES, M_RANK}
            required |= {M_ED25519, M_MLDSA, M_XWING}
        elif mtype == INVITE:
            allowed |= {M_ED25519, M_MLDSA, M_XWING, M_EXPIRES, M_CLAIMS, M_INVITE}
            required |= {M_ED25519, M_MLDSA, M_XWING, M_EXPIRES, M_CLAIMS, M_INVITE}
        elif mtype == PERSON:
            allowed |= {M_REPLACES}
            allowed -= {M_SESSION}
        else:
            allowed |= {M_NOTICES, M_FLOOR, M_NAMED}
            allowed -= {M_SESSION}
    if not set(entry) <= allowed or not required <= set(entry):
        raise SpecError("Malformed")
    out = {"member": (mtype, member[1]), "level": None, "caps": frozenset(), "label": None,
           "history": None, "via": None, "session": None, "replaces": None,
           "seniority": None, "ed25519": None, "mldsa": None, "xwing": None, "slot": None,
           "expires_at": None, "claims": None, "invite": None, "claimant": None,
           "notices": (), "floor": False, "named": (), "rank": None}
    if keyed:
        for key, name, length in ((M_ED25519, "ed25519", 32), (M_MLDSA, "mldsa", MLDSA_BYTES),
                                  (M_XWING, "xwing", HYBRID_BYTES)):
            if not is_bytes(entry[key], length):
                raise SpecError("Malformed")
            out[name] = entry[key]
    if mtype == INVITE:
        if not is_uint(entry[M_INVITE]) or entry[M_INVITE] > INVITE_USED:
            raise SpecError("Malformed")
        out["invite"] = entry[M_INVITE]
    if claimed:
        claimant = entry[M_CLAIMANT]
        if not (isinstance(claimant, list) and len(claimant) == 2
                and claimant[0] in (DEVICE, PERSON) and is_bytes(claimant[1], 32)):
            raise SpecError("Malformed")
        out["claimant"] = (claimant[0], claimant[1])
        return out
    sen = entry[M_SENIORITY]
    if not (isinstance(sen, list) and len(sen) == 3 and is_uint(sen[0]) and is_uint(sen[1])
            and is_bytes(sen[2], 32)):
        raise SpecError("Malformed")
    out["seniority"] = (sen[0], sen[1], None, sen[2])
    level, history, via = entry[M_LEVEL], entry[M_HISTORY], entry[M_VIA]
    if not (is_uint(level) and level in LEVEL_NAMES and is_uint(history)
            and history in (FROM_NOW_ON, WITH_HISTORY) and is_uint(via) and via in VIA_NAMES):
        raise SpecError("Malformed")
    if level == ADMINISTER and (mtype != DEVICE or M_SESSION in entry):
        raise SpecError("Malformed")
    # An administrator's rank, exactly with administer (section 2.8).
    if (M_RANK in entry) != (level == ADMINISTER) or (
            M_RANK in entry and not (is_uint(entry[M_RANK]) and entry[M_RANK] <= MAX_RANK)):
        raise SpecError("Malformed")
    out["rank"] = entry.get(M_RANK)
    if mtype == INVITE and via != VIA_LINK:
        raise SpecError("Malformed")
    out.update(level=level, history=history, via=via)
    caps = entry.get(M_CAPS)
    if caps is not None:
        if not (isinstance(caps, list) and 1 <= len(caps) <= MAX_CAPS and all(
                isinstance(c, list) and len(c) == 2 and _name_ok(c[0]) and c[1] in (EXTENDS, NARROWS)
                for c in caps)):
            raise SpecError("Malformed")
        names = [c[0].encode() for c in caps]
        if any(a >= b for a, b in zip(names, names[1:])):
            raise SpecError("Malformed")
        out["caps"] = frozenset((c[0], c[1]) for c in caps)
    if M_LABEL in entry:
        if not _name_ok(entry[M_LABEL]):
            raise SpecError("Malformed")
        out["label"] = entry[M_LABEL]
    for key, name, length in ((M_SESSION, "session", SESSION_BYTES), (M_REPLACES, "replaces", 32)):
        if key in entry:
            if not is_bytes(entry[key], length):
                raise SpecError("Malformed")
            out[name] = entry[key]
    if M_EXPIRES in entry:
        if not is_uint(entry[M_EXPIRES]) or entry[M_EXPIRES] > MAX_U64 \
                or (mtype == DEVICE and M_SESSION not in entry):
            raise SpecError("Malformed")
        out["expires_at"] = entry[M_EXPIRES]
    if M_CLAIMS in entry:
        if entry[M_CLAIMS] not in (DEVICE, PERSON) or (M_SESSION in entry
                                                       and entry[M_CLAIMS] != DEVICE):
            raise SpecError("Malformed")
        out["claims"] = entry[M_CLAIMS]
    if M_SLOT in entry:
        slot = entry[M_SLOT]
        if not (level == ADMINISTER and isinstance(slot, list) and len(slot) == 4
                and is_bytes(slot[0], 32) and is_uint(slot[1]) and is_bytes(slot[2], 32)
                and isinstance(slot[3], bytes) and len(slot[3]) in (0, 32)):
            raise SpecError("Malformed")  # [c, index, maker, pseudonym or empty]
        out["slot"] = tuple(slot)
    if M_NOTICES in entry:
        ns = entry[M_NOTICES]
        if not (isinstance(ns, list) and ns and all(
                isinstance(n, list) and len(n) == 4 and is_bytes(n[0], 32)
                and is_bytes(n[1], HYBRID_BYTES) and n[2] in (0, 1) and is_bytes(n[3], 32)
                for n in ns)):
            raise SpecError("Malformed")
        enc = [cbor(n) for n in ns]
        if any(a >= b for a, b in zip(enc, enc[1:])):
            raise SpecError("Malformed")
        out["notices"] = tuple(tuple(n) for n in ns)
    if M_FLOOR in entry:
        if entry[M_FLOOR] != 1:
            raise SpecError("Malformed")
        out["floor"] = True
    if M_NAMED in entry:
        named = entry[M_NAMED]
        if not (isinstance(named, list) and named
                and all(is_bytes(x, 32) for x in named)
                and all(a < b for a, b in zip(named, named[1:]))):
            raise SpecError("Malformed")
        out["named"] = tuple(named)
    return out


# roster.md, "The checkpoint record", step 3: reserved for later documents.
RESERVED_RECORD_KEY, RESERVED_MEMBER_KEY, RESERVED_MEMBER_TYPE = 9, 22, 4


def read_record(data: bytes) -> dict:
    """Reads a checkpoint record, in order (roster.md, "The checkpoint
    record"): deterministic CBOR, a map with an unsigned key 1 (Malformed);
    version 1 (UnsupportedVersion); exactly its keys with their types and
    orders, each member entry with the keys its type allows (Malformed);
    each device's and invite key's Ed25519 and X-Wing keys valid
    (InvalidKey); and giving its member ID (NotCommitted)."""
    value = uncbor(data)
    if not isinstance(value, dict) or not is_uint(value.get(R_VERSION)):
        raise SpecError("Malformed")
    if value[R_VERSION] != 1:
        raise SpecError("UnsupportedVersion")
    # Step 3: a record key from 9, a member-entry key from 22 or a member
    # type from 4 is a later document's, which this implementation does not
    # define: the checkpoint is held, with every event after it.
    if any(is_uint(k) and k >= RESERVED_RECORD_KEY for k in value) or (
            isinstance(value.get(R_MEMBERS), list) and any(
                isinstance(m, dict) and (
                    any(is_uint(k) and k >= RESERVED_MEMBER_KEY for k in m)
                    or (isinstance(m.get(M_MEMBER), list) and m[M_MEMBER]
                        and is_uint(m[M_MEMBER][0])
                        and m[M_MEMBER][0] >= RESERVED_MEMBER_TYPE))
                for m in value[R_MEMBERS])):
        raise SpecError("ExtensionRequired")
    required = {R_VERSION, R_EPOCH, R_MEMBERS, R_POLICY, R_TIPS, R_FORKS}
    if not required <= set(value) <= required | {R_PREVIOUS, R_HEARD}:
        raise SpecError("Malformed")
    heard = {}
    if R_HEARD in value:
        rows = value[R_HEARD]
        if not (isinstance(rows, list) and rows):
            raise SpecError("Malformed")
        for row in rows:
            if not (isinstance(row, list) and len(row) == 6 and is_bytes(row[0], 32)
                    and isinstance(row[1], list) and len(row[1]) == 3
                    and is_uint(row[1][0]) and is_uint(row[1][1]) and is_bytes(row[1][2], 32)
                    and is_uint(row[2]) and row[2] <= MAX_RANK
                    and is_bytes(row[3], 32) and is_bytes(row[4], MLDSA_BYTES)
                    and is_bytes(row[5], HYBRID_BYTES)):
                raise SpecError("Malformed")
            # Its keys are checked with the members' (below): every
            # structure first, then every key, then every commitment.
            heard[row[0]] = ((row[1][0], row[1][1], None, row[1][2]), row[2],
                             (row[3], row[4], row[5]))
        if any(a[0] >= b[0] for a, b in zip(rows, rows[1:])):
            raise SpecError("Malformed")
    epoch = value[R_EPOCH]
    if not is_uint(epoch) or epoch < 1 or (R_PREVIOUS in value) != (epoch > 1):
        raise SpecError("Malformed")
    if R_PREVIOUS in value and not is_bytes(value[R_PREVIOUS], 32):
        raise SpecError("Malformed")
    if not isinstance(value[R_MEMBERS], list) or not is_bytes(value[R_POLICY]):
        raise SpecError("Malformed")
    members = [_record_member(entry) for entry in value[R_MEMBERS]]
    seen = [cbor([m["member"][0], m["member"][1]]) for m in members]
    if any(a >= b for a, b in zip(seen, seen[1:])):
        raise SpecError("Malformed")
    tips, forks = {}, {}
    for table, out, width in ((value[R_TIPS], tips, 3), (value[R_FORKS], forks, 2)):
        if not isinstance(table, list):
            raise SpecError("Malformed")
        for row in table:
            if not (isinstance(row, list) and len(row) == width and is_bytes(row[0], 32)
                    and is_uint(row[1]) and row[1] >= 1 and (width == 2 or is_bytes(row[2], 32))):
                raise SpecError("Malformed")
            out[row[0]] = row[1] if width == 2 else (row[1], row[2])
        if any(a[0] >= b[0] for a, b in zip(table, table[1:])):
            raise SpecError("Malformed")
    policy = spaces.read_policy(value[R_POLICY])
    for m in members:
        if m["ed25519"] is not None and (not ed25519_valid(m["ed25519"])
                                         or not hybrid_key_valid(m["xwing"])):
            raise SpecError("InvalidKey")
    for _, _, (ed, _, xw) in heard.values():
        if not ed25519_valid(ed) or not hybrid_key_valid(xw):
            raise SpecError("InvalidKey")
    for m in members:
        if m["ed25519"] is not None and hs.device_id_of(m["ed25519"], m["mldsa"],
                                                        m["xwing"]) != m["member"][1]:
            raise SpecError("NotCommitted")
    for d, (_, _, (ed, ml, xw)) in heard.items():
        if hs.device_id_of(ed, ml, xw) != d:
            raise SpecError("NotCommitted")
    return {"epoch": epoch, "previous": value.get(R_PREVIOUS), "members": members,
            "policy": policy, "tips": tips, "forks": forks, "heard": heard}


def encode_refs(refs) -> bytes:
    """Refs, as the envelope once carried them: [log ID, event ID]
    pairs, 1 to 64, strictly ascending, as one CBOR array."""
    pairs = sorted(set((bytes(a), bytes(b)) for a, b in refs))
    assert 1 <= len(pairs) <= events.MAX_REFS
    return cbor([[a, b] for a, b in pairs])


def read_refs(value) -> tuple:
    """A nonempty array (Malformed) of at most 64 refs (TooLarge, events.md's
    limits), each a pair of two 32-byte strings, strictly ascending
    (Malformed)."""
    if not isinstance(value, list) or not value:
        raise SpecError("Malformed")
    if len(value) > events.MAX_REFS:
        raise SpecError("TooLarge")
    for ref in value:
        if not (isinstance(ref, list) and len(ref) == 2 and is_bytes(ref[0], 32)
                and is_bytes(ref[1], 32)):
            raise SpecError("Malformed")
    flat = [a + b for a, b in value]
    if any(x >= y for x, y in zip(flat, flat[1:])):
        raise SpecError("Malformed")
    return tuple((a, b) for a, b in value)


_BUILD_FLAGS: dict | None = None  # set by Roster while it builds a space event


def space_body(payload: dict, secret: bytes, seal_nonce: bytes, roster: bytes | None = None,
               genesis_nonce: bytes | None = None, refs=()):
    """A space event's body, sealed to its own event. Returns a
    function of (log, author, seq), which History.act calls once it knows
    them; inside a genesis the log is the genesis's nonce. Refs travel in the
    sealed part, at inner key 18. A rotation built inside Roster takes the
    grant-rotation and break flags keys.md asks of it,
    unless the payload sets them, so that subclasses' payloads carry them too."""
    flags = {k: v for k, v in (_BUILD_FLAGS or {}).items()
             if k == "twin" or payload.get("rotates")}

    def build(log, author, seq):
        p = {**flags, **payload, "always_seal": True}
        if roster is not None:
            p["roster"] = roster
        if refs:
            p["raw_inner"] = {**p.get("raw_inner", {}), S_REFS: encode_refs(refs)}
        if genesis_nonce is not None:
            p["nonce"] = genesis_nonce
        return kg.encode_payload(p, genesis_nonce if log is None else log, author, seq, secret,
                                 seal_nonce)
    return build


def _name_ok(value) -> bool:
    return (isinstance(value, str) and 1 <= len(value.encode()) <= MAX_NAME_BYTES
            and identifier_ok(value))


def decode_change(value, space_id: bytes | None) -> Change:
    """One change; Malformed, InvalidKey, AdministerNotDevice or
    NotCommitted. Member type 3, op 4 and change keys 13 and 14 are the
    invite's and the guest's; every other change is read by `_decode_base`."""
    if not isinstance(value, dict) or C_OP not in value:
        raise SpecError("Malformed")
    op, member = value[C_OP], value.get(C_MEMBER)
    mtype = member[0] if isinstance(member, list) and len(member) == 2 else None
    if op in (5, 6, 7):
        raise SpecError("Malformed")
    if op == SUCCEED:
        # The claimant, a person, or a device with its keys.
        if mtype not in (DEVICE, PERSON) or not is_bytes(member[1], 32):
            raise SpecError("Malformed")
        if mtype == PERSON:
            if set(value) != {C_OP, C_MEMBER}:
                raise SpecError("Malformed")
            return Change(SUCCEED, (PERSON, member[1]))
        if set(value) != {C_OP, C_MEMBER, C_HYBRID, C_MLDSA, C_ED25519}:
            raise SpecError("Malformed")
        probe = _decode_base({C_OP: GRANT, C_MEMBER: member, C_LEVEL: READ,
                              C_HISTORY: FROM_NOW_ON, C_VIA: VIA_LINK, C_HYBRID: value[C_HYBRID],
                              C_MLDSA: value[C_MLDSA], C_ED25519: value[C_ED25519]},
                             space_id)
        return Change(SUCCEED, probe.member, hybrid=probe.hybrid, mldsa=probe.mldsa,
                      ed25519=probe.ed25519)
    if mtype == INVITE:
        # An invite key is granted (op 0) and removed (op 2), never changed.
        if not is_bytes(member[1], 32):
            raise SpecError("Malformed")
        if op == REMOVE:
            if set(value) != {C_OP, C_MEMBER}:
                raise SpecError("Malformed")
            return Change(REMOVE, (INVITE, member[1]))
        if op != GRANT:
            raise SpecError("Malformed")
        allowed = {C_OP, C_MEMBER, C_LEVEL, C_CAPS, C_LABEL, C_HISTORY, C_VIA, C_SESSION,
                   C_HYBRID, C_MLDSA, C_ED25519, C_EXPIRES, C_CLAIMS}
        required = {C_LEVEL, C_HISTORY, C_VIA, C_HYBRID, C_MLDSA, C_ED25519, C_EXPIRES,
                    C_CLAIMS}
        if set(value) - allowed or not required <= set(value):
            raise SpecError("Malformed")
        if value[C_VIA] != VIA_LINK or not is_uint(value[C_EXPIRES]) \
                or value[C_EXPIRES] > MAX_U64 or value[C_CLAIMS] not in (DEVICE, PERSON):
            raise SpecError("Malformed")
        if C_SESSION in value and value[C_CLAIMS] != DEVICE:
            raise SpecError("Malformed")  # a guest invite is claimed by a device
        if value[C_LEVEL] == ADMINISTER:
            raise SpecError("AdministerNotDevice")
        probe = dict(value)
        del probe[C_EXPIRES], probe[C_CLAIMS]
        probe[C_MEMBER] = [DEVICE, member[1]]  # its keys, as a device grant's
        c = _decode_base(probe, space_id)
        return Change(GRANT, (INVITE, member[1]), c.level, c.caps, c.label, c.history, c.via,
                      c.session, None, c.hybrid, c.mldsa, None, c.ed25519,
                      value[C_EXPIRES], value[C_CLAIMS])
    if C_CLAIMS in value:
        raise SpecError("Malformed")
    if C_EXPIRES in value:
        # A guest session's expiry (ext-guests.md): only on a device grant with `session`.
        if op != GRANT or mtype != DEVICE or C_SESSION not in value \
                or not is_uint(value[C_EXPIRES]) or value[C_EXPIRES] > MAX_U64:
            raise SpecError("Malformed")
        probe = dict(value)
        del probe[C_EXPIRES]
        c = _decode_base(probe, space_id)
        return Change(c.op, c.member, c.level, c.caps, c.label, c.history, c.via, c.session,
                      c.replaces, c.hybrid, c.mldsa, c.policy, c.ed25519, value[C_EXPIRES])
    return _decode_base(value, space_id)


def _decode_base(value, space_id: bytes | None) -> Change:
    """For ops 0 to 3 and member types 0 to 2, without keys 13
    and 14."""
    if not isinstance(value, dict) or C_OP not in value:
        raise SpecError("Malformed")
    op = value[C_OP]
    if op not in (GRANT, CHANGE, REMOVE, POLICY) or set(value) - set(range(13)) - {C_RANK}:
        raise SpecError("Malformed")
    if op == POLICY:
        if set(value) != {C_OP, C_POLICY} or not is_bytes(value[C_POLICY]):
            raise SpecError("Malformed")
        spaces.read_policy(value[C_POLICY])
        return Change(POLICY, policy=value[C_POLICY])
    member = value.get(C_MEMBER)
    if not (isinstance(member, list) and len(member) == 2 and member[0] in (DEVICE, PERSON, SPACE)
            and is_bytes(member[1], 32)):
        raise SpecError("Malformed")
    mtype, mid = member
    allowed = {GRANT: {C_OP, C_MEMBER, C_LEVEL, C_CAPS, C_LABEL, C_HISTORY, C_VIA, C_RANK},
               CHANGE: {C_OP, C_MEMBER, C_LEVEL, C_CAPS, C_LABEL, C_RANK},
               REMOVE: {C_OP, C_MEMBER}}[op]
    if op == GRANT and mtype == DEVICE:
        allowed |= {C_SESSION, C_HYBRID, C_MLDSA, C_ED25519}
    if op == GRANT and mtype == PERSON:
        allowed |= {C_REPLACES}
    if set(value) - allowed:
        raise SpecError("Malformed")
    if op == GRANT and not {C_LEVEL, C_HISTORY, C_VIA} <= set(value):
        raise SpecError("Malformed")
    if op == GRANT and mtype == DEVICE and not {C_HYBRID, C_MLDSA, C_ED25519} <= set(value):
        raise SpecError("Malformed")
    if op == CHANGE and not ({C_LEVEL, C_CAPS, C_LABEL, C_RANK} & set(value)):
        raise SpecError("Malformed")
    level = value.get(C_LEVEL)
    if level is not None and level not in LEVEL_NAMES:
        raise SpecError("Malformed")
    # A rank comes exactly with administer: required on a grant or change
    # that sets administer, absent otherwise (section 2.3).
    rank = value.get(C_RANK)
    if rank is not None and not (is_uint(rank) and rank <= MAX_RANK):
        raise SpecError("Malformed")
    if (rank is not None and level != ADMINISTER) or (
            level == ADMINISTER and mtype == DEVICE and C_SESSION not in value and rank is None):
        raise SpecError("Malformed")
    caps = value.get(C_CAPS)
    if caps is not None:
        if not isinstance(caps, list) or not 1 <= len(caps) <= MAX_CAPS:
            raise SpecError("Malformed")
        for cap in caps:
            if not (isinstance(cap, list) and len(cap) == 2 and _name_ok(cap[0])
                    and cap[1] in (EXTENDS, NARROWS)):
                raise SpecError("Malformed")
        names = [c[0].encode() for c in caps]
        if any(a >= b for a, b in zip(names, names[1:])):
            raise SpecError("Malformed")
        caps = tuple((c[0], c[1]) for c in caps)
    if C_LABEL in value and not _name_ok(value[C_LABEL]):
        raise SpecError("Malformed")
    if C_HISTORY in value and value[C_HISTORY] not in (FROM_NOW_ON, WITH_HISTORY):
        raise SpecError("Malformed")
    if C_VIA in value and value[C_VIA] not in VIA_NAMES:
        raise SpecError("Malformed")
    for key, length in ((C_SESSION, SESSION_BYTES), (C_REPLACES, 32), (C_HYBRID, HYBRID_BYTES),
                        (C_MLDSA, MLDSA_BYTES), (C_ED25519, 32)):
        if key in value and not is_bytes(value[key], length):
            raise SpecError("Malformed")
    if mtype == SPACE and space_id is not None and mid == space_id:
        raise SpecError("Malformed")
    if level == ADMINISTER and (mtype != DEVICE or C_SESSION in value):
        raise SpecError("AdministerNotDevice")
    if op == GRANT and mtype == DEVICE and (not ed25519_valid(value[C_ED25519])
                                            or not hybrid_key_valid(value[C_HYBRID])):
        raise SpecError("InvalidKey")
    # Step 9: the keys give the member ID (section 2.4).
    if op == GRANT and mtype == DEVICE and member_id(
            value[C_ED25519], value[C_MLDSA], value[C_HYBRID]) != mid:
        raise SpecError("NotCommitted")
    return Change(op, (mtype, mid), level, caps, value.get(C_LABEL), value.get(C_HISTORY),
                  value.get(C_VIA), value.get(C_SESSION), value.get(C_REPLACES),
                  value.get(C_HYBRID), value.get(C_MLDSA), None, value.get(C_ED25519),
                  rank=rank)


@dataclass
class Decoded:
    genesis: bool
    changes: tuple | None  # None: no roster part, a key event
    rotates: bool
    payload: dict = dc_field(default_factory=dict)
    duel: int = DUEL_BOTH_STAND
    policy: dict | None = None
    descriptor: dict | None = None
    body_key: bytes = b""
    refs: tuple = ()
    system_stream: bytes | None = None
    checkpoint: dict | None = None  # a checkpoint's record, read (roster.md)
    record_bytes: bytes | None = None
    part: dict | None = None  # a checkpoint's roster part: epoch, digest, size, locator


@dataclass
class Keyring:
    """What a replica holds to open space events: the content key of each
    rotation it holds (by the rotation's event ID), and body keys handed to it
    for single events, each event's as one key or as a list of
    the keys different senders handed."""
    rotations: dict = dc_field(default_factory=dict)
    bodies: dict = dc_field(default_factory=dict)
    states: dict = dc_field(default_factory=dict)  # a merged state's key received whole

    def handed(self, i: bytes) -> list:
        keys = self.bodies.get(i)
        if keys is None:
            return []
        return sorted(set([keys] if isinstance(keys, bytes) else keys))


def open_space_body(visible: dict, key: bytes, log: bytes, author: bytes, seq: int) -> dict:
    """The sealed part, with its refs (inner key 18).
    keys.md owns the inner map; until keygraph.py reads key 18 itself,
    this takes the refs out and hands the rest to keygraph.py, sealed again
    under the same key and nonce, so that its checks run unchanged."""
    if hasattr(kg, "S_REFS"):  # keygraph.py reads key 18 itself: nothing to take out
        out = kg.open_with_body_key(visible, key, log, author, seq)
        out["refs"] = tuple(tuple(r) for r in out.get("refs") or ())
        return out
    if kg.body_commitment(key) != visible["commitment"]:
        raise SpecError("KeyMismatch")
    sealed, aad = visible["sealed"], kg.seal_aad(log, author, seq)
    nonce = sealed[:kg.NONCE_BYTES]
    value = kg.decode_cbor(xchacha20poly1305_open(key, nonce, sealed[kg.NONCE_BYTES:], aad))
    if not isinstance(value, dict) or S_REFS not in value:
        out = kg.open_with_body_key(visible, key, log, author, seq)
        out["refs"] = ()
        return out
    refs = read_refs(value.pop(S_REFS))
    rest = nonce + xchacha20poly1305_seal(key, nonce, cbor(value), aad)
    out = kg.open_with_body_key({**visible, "sealed": rest}, key, log, author, seq)
    out["refs"] = refs
    return out


def read_visible(event: events.Event) -> dict:
    """The visible part, which any peer can check."""
    p = kg.read_payload(event.body, event.author, event.seq)
    if p["sealed"] is None:
        raise SpecError("Malformed")  # every space event seals its contents
    if event.genesis != (p.get("nonce") is not None):
        raise SpecError("Malformed")
    if event.genesis and not p["rotates"]:
        raise SpecError("Malformed")
    return p


def event_log(event: events.Event, visible: dict) -> bytes:
    """What binds a space event's sealed part: the space ID, or inside a
    genesis the genesis's nonce (keys.md)."""
    return visible["nonce"] if event.genesis else event.log


def body_key(event: events.Event, visible: dict, secret: bytes) -> bytes:
    """The per-event body key."""
    return kg.seal_key(secret, event_log(event, visible), event.author, event.seq)


_DECODED: dict = {}


def decode_body(event: events.Event, key: bytes) -> Decoded:
    """The event's body key."""
    hit = _DECODED.get((event.id, key))
    if isinstance(hit, SpecError):
        raise SpecError(hit.error)
    if hit is not None:
        return hit
    try:
        out = _decode_body(event, key)
    except SpecError as error:
        _DECODED[(event.id, key)] = error
        raise
    _DECODED[(event.id, key)] = out
    return out


def _peeks_as_device_grant(value) -> bool:
    """A change, before it is read, that grants a device: op 0 and a member
    [0, ...]."""
    if not isinstance(value, dict):
        return False
    member = value.get(C_MEMBER)
    return (is_uint(value.get(C_OP)) and value[C_OP] == GRANT and isinstance(member, list)
            and len(member) == 2 and is_uint(member[0]) and member[0] == DEVICE)


def _decode_body(event: events.Event, key: bytes) -> Decoded:
    visible = read_visible(event)
    try:
        opened_ = open_space_body(visible, key, event_log(event, visible), event.author,
                                  event.seq)
    except SpecError as error:
        raise SpecError("BadSeal" if error.error in ("Decrypt", "KeyMismatch") else error.error)
    if opened_["roster"] is None:
        if event.genesis or visible.get("twin") is not None:
            raise SpecError("Malformed")  # a key event names no twin
        return Decoded(False, None, visible["rotates"], opened_, body_key=key,
                       refs=opened_["refs"])
    value = uncbor(opened_["roster"])
    if isinstance(value, dict) and is_uint(value.get(0)) and value[0] > CHECKPOINT \
            and not event.genesis:
        # A roster part type a later document defines: held, with every
        # event outside its past (roster.md, "Rules this replica lacks").
        raise SpecError("ExtensionRequired")
    if not isinstance(value, dict) or value.get(0) not in (GENESIS, UPDATE, CHECKPOINT):
        raise SpecError("Malformed")
    if event.genesis != (value[0] == GENESIS):
        raise SpecError("Malformed")
    if value[0] == CHECKPOINT:
        if set(value) != {K_TYPE, K_EPOCH, K_DIGEST, K_SIZE, K_LOCATOR} \
                or not is_uint(value[K_EPOCH]) or value[K_EPOCH] < 1 \
                or not is_bytes(value[K_DIGEST], 32) or not is_uint(value[K_SIZE]) \
                or not is_bytes(value[K_LOCATOR], 64):
            raise SpecError("Malformed")
        if value[K_SIZE] > MAX_RECORD_BYTES:
            raise SpecError("TooLarge")
        if not visible["rotates"] or opened_["refs"]:
            raise SpecError("Malformed")  # it rotates and cites no other log
        return Decoded(False, (), True, opened_, body_key=key, refs=(),
                       part={"epoch": value[K_EPOCH], "digest": value[K_DIGEST],
                             "size": value[K_SIZE], "locator": value[K_LOCATOR]})
    if value[0] == GENESIS:
        if set(value) != set(range(6)):
            raise SpecError("Malformed")
        if not (is_uint(value[G_DUEL]) and is_bytes(value[G_POLICY])
                and is_bytes(value[G_DESCRIPTOR])
                and is_bytes(value[G_SYSTEM_STREAM], SYSTEM_STREAM_BYTES)
                and any(value[G_SYSTEM_STREAM])):
            raise SpecError("Malformed")
        founder = decode_change(value[G_FOUNDER], None)
        if (founder.op != GRANT or founder.member != (DEVICE, event.author)
                or founder.level != ADMINISTER or founder.history != WITH_HISTORY
                or founder.via != VIA_NONE or founder.session is not None
                or founder.caps is not None or founder.label is not None
                or founder.rank != MAX_RANK):
            raise SpecError("Malformed")  # no session, capabilities or label; the top rank
        if value[G_DUEL] != DUEL_BOTH_STAND:
            raise SpecError("UnknownPolicy")
        policy = spaces.read_policy(value[G_POLICY])
        descriptor = spaces.read_descriptor(value[G_DESCRIPTOR])
        if opened_["refs"]:
            raise SpecError("Malformed")  # a genesis cites nothing
        return Decoded(True, (founder,), True, opened_, value[G_DUEL], policy, descriptor, key,
                       system_stream=value[G_SYSTEM_STREAM])
    if set(value) != {U_TYPE, U_CHANGES}:
        raise SpecError("Malformed")
    if not isinstance(value[U_CHANGES], list) or not 1 <= len(value[U_CHANGES]) <= MAX_CHANGES:
        raise SpecError("Malformed")
    # Step 8 counts the device grants before any change is read.
    if sum(_peeks_as_device_grant(c) for c in value[U_CHANGES]) > MAX_DEVICE_GRANTS:
        raise SpecError("Malformed")
    changes = tuple(decode_change(c, event.log) for c in value[U_CHANGES])
    members = [c.member for c in changes if c.member is not None]
    if len(set(members)) != len(members) or sum(c.op == POLICY for c in changes) > 1:
        raise SpecError("Malformed")
    for c in changes:
        if c.replaces is not None and not any(
                o.op == REMOVE and o.member == (PERSON, c.replaces) for o in changes):
            raise SpecError("Malformed")
    if any(c.op == REMOVE and c.member == (DEVICE, event.author) for c in changes) \
            and visible["rotates"]:
        raise SpecError("SelfRotation")
    if any(c.op == SUCCEED for c in changes) and (len(changes) != 1 or visible["rotates"]):
        raise SpecError("Malformed")  # A successor's one change; it never rotates
    return Decoded(False, changes, visible["rotates"], opened_, body_key=key,
                   refs=opened_["refs"])


STORAGE_SKELETON_TYPES = (0, 1, 2, 3, 4, 5, 6, 7)  # peers.md: by a pseudonym; 7 a cut
STORAGE_RECORD_TYPES = (0, 2)  # the root and an enrolment introduce a pseudonym
STORAGE_WRITER_TYPES = (16, 17)  # release and restore: writer requests, by a device


def storage_record(event: events.Event) -> dict:
    """A storage event (kind 6), as far as this specification reads it
    (and 9.5): its type, and for a root or an enrolment the ML-DSA-65 key it
    carries for its own author, the pseudonym, and for a root the founder's
    ML-DSA-65 and X-Wing keys (peers.md). peers.md checks the rest."""
    value = uncbor(event.body)
    if not isinstance(value, dict) or not is_uint(value.get(1)) or not is_uint(value.get(2)):
        raise SpecError("Malformed")
    if value[1] != 1:
        raise SpecError("UnsupportedVersion")
    kind = value[2]
    if kind not in STORAGE_SKELETON_TYPES + STORAGE_WRITER_TYPES:
        raise SpecError("Malformed")
    mldsa = value.get(4) if kind in STORAGE_RECORD_TYPES else None
    if kind in STORAGE_RECORD_TYPES and not is_bytes(mldsa, MLDSA_BYTES):
        raise SpecError("Malformed")
    founder = None
    if kind == 0 and is_bytes(value.get(6), MLDSA_BYTES) and is_bytes(value.get(8), HYBRID_BYTES):
        founder = (value[6], value[8])  # a root's founder_mldsa and founder_xwing
    return {"type": kind, "mldsa": mldsa, "founder": founder}


class StorageView:
    """What peers.md tells this specification about one space's storage
    events. With
    Space(..., storage=None) a replica models no skeleton: the twin check
    is taken as passing, no record names a pseudonym, and skeleton
    events count for no device. peers.md's reference implements this."""

    def twin(self, space: "Space", event: bytes, twin_id: bytes | None,
             place: frozenset) -> str | None:
        """The twin `event` names by its visible key 15 (None for
        the genesis, whose root peers.md finds): None when it is held and
        passes peers.md; "NoTwin" (pending) when it is not
        held; "BadTwin" when it fails. Called only for an event that changes
        who administers at its place, and the genesis."""
        return None

    def pseudonym_keys(self, space: "Space", pseudonym: bytes) -> list:
        """The ML-DSA-65 keys that records of this log carry for
        `pseudonym`, a device ID, that the skeleton vouches for: a root that
        passes peers.md, or an enrolment that verifies against a slot made by
        a held root or change (peers.md)."""
        return []

    def device_of(self, pseudonym: bytes) -> bytes | None:
        """The device a pseudonym's binding names, the founder's for the
        root's; None for a pseudonym enrolled foreignly or not at all."""
        return None

    def slot_entry(self, space: "Space", device: bytes) -> tuple | None:
        """A checkpoint record's `slot` for administrator `device`
        (roster.md, "The checkpoint record"): [c, index, maker, pseudonym
        device ID or empty bytes] of the most senior slot that is in and
        was made for it, or None when the skeleton holds none."""
        return None


# ---------------------------------------------------------------------------
# Member state.


@dataclass(frozen=True)
class State:
    present: bool
    level: int | None = None
    caps: frozenset = frozenset()
    label: str | None = None
    history: int | None = None
    via: int | None = None
    session: bytes | None = None
    replaces: bytes | None = None
    grants: frozenset = frozenset()
    seniority: tuple | None = None
    hybrid: bytes | None = None
    source: tuple = ()
    removed_by: tuple = ()
    expires_at: int | None = None  # a guest's, with session; an invite key's
    rank: int | None = None  # an administrator's (section 2.3)


def meet(states: list[State]) -> State:
    """The most restrictive of concurrent states."""
    if len(states) == 1:
        return states[0]
    ordered = sorted(states, key=lambda s: s.source)
    first, senior = ordered[0], min(states, key=lambda s: s.seniority)
    extends = [frozenset(c for c in s.caps if c[1] == EXTENDS) for s in states]
    narrows = frozenset().union(*(frozenset(c for c in s.caps if c[1] == NARROWS)
                                  for s in states))
    session = next((s.session for s in ordered if s.session is not None), None)
    expires = next((s.expires_at for s in ordered if s.session is not None), None)
    return State(
        True,
        level=min(s.level for s in states),
        caps=frozenset.intersection(*extends) | narrows,
        label=first.label,
        history=WITH_HISTORY if all(s.history == WITH_HISTORY for s in states) else FROM_NOW_ON,
        via=first.via, session=session, replaces=first.replaces,
        grants=frozenset().union(*(s.grants for s in states)),
        seniority=senior.seniority, hybrid=senior.hybrid, source=first.source,
        expires_at=expires,
        # The lowest rank of the concurrent states, as for levels.
        rank=min((s.rank for s in states if s.rank is not None), default=None)
        if min(s.level for s in states) == ADMINISTER else None,
    )


def merge_policies(policies: list[dict]) -> dict:
    out = {}
    for name, rule in POLICY_MERGE.items():
        values = [p[name] for p in policies]
        if rule == "min-on":
            on = [v for v in values if v is not None]
            out[name] = min(on) if on else None
        else:
            out[name] = rule(values)
    return out


UNIT_REFS_PREFIX = b"unit with refs:"  # a stand-in for units.md's sealed refs
# A stand-in for a unit's key reference (units.md, "The unit header"): the
# state it is sealed under, which a replica reads before any key.
UNIT_SEAL_PREFIX = b"unit sealed under:"


def unit_sealed_body(state, label: str) -> bytes:
    return UNIT_SEAL_PREFIX + cbor([kg.encode_set(sorted(state)), label])


def unit_key_reference(event: events.Event) -> list | None:
    """The rotations a unit's key reference names, in this module's
    stand-in; None for a unit that carries none."""
    if event.kind != KIND_UNIT or not event.body.startswith(UNIT_SEAL_PREFIX):
        return None
    return list(kg.decode_set(uncbor(event.body[len(UNIT_SEAL_PREFIX):])[0]))


def opened(event: events.Event) -> bool:
    """Stands in for units.md: a unit is accepted only if its seal opens. The
    vectors mark a unit that does not open by its body's first bytes."""
    return not (event.kind == KIND_UNIT and event.body.startswith(b"sealed under no key"))


# roster.md, section 3.11, "A list at an event's place": the copies of
# list events, `frasil:list` units of the system stream. By person ID, each
# copy as (the space's log, the copy's event ID, the list event's ID, the
# device the list event adds or revokes, if it does, and "add" or
# "revoke"). A person with no copy here
# is read as held: histories that do not model copies give every list event
# a place before every space event.
LIST_COPIES: dict[bytes, list] = {}


def record_copy(log, copy: bytes, person: bytes, carried) -> None:
    """Record that space event `copy` of `log` carries list events
    `carried`, each (list event ID, device or None, "add", "revoke" or
    None)."""
    for lid, dev, op in carried:
        LIST_COPIES.setdefault(person, []).append((log, copy, lid, dev, op))


class Space:
    """One space's log resolved in a view. `lists` maps
    person IDs to resolved device lists, `spaces` space IDs to resolved
    spaces: the other logs this view's checks across logs may need."""

    def __init__(self, log: Log, view=None, lists=None, spaces_=None, keys=None, storage=None,
                 extra_keys=(), presets=None, base=None):
        """`extra_keys` are key pairs this replica holds from any other
        source: an admission exchange, a cache. `presets` are verdicts
        decided before the procedure: checkpoints, judged on their own past,
        and events whose cuts do not match (roster.md, "Checkpoints"). With
        `base`, the log is the world of a checkpoint (checkpoints.py): its
        root is the checkpoint, whose record stands where a genesis's
        founder does."""
        self.log = log
        self.base = base
        self.epoch = base["record"]["epoch"] if base is not None else 0
        self._presets = dict(presets or {})
        self.extra_keys = list(extra_keys)
        self.view = set(log.events if view is None else view)
        assert log.closed(self.view)
        self.lists = lists or {}
        self.spaces = spaces_ or {}
        self.keys = keys or Keyring()
        self.storage: StorageView | None = storage
        self.decoded: dict[bytes, Decoded] = {}
        self.status: dict[bytes, tuple] = {}
        self._cache: dict = {}
        self._unwaiting: set | None = None  # unwaiting_writers, found once
        self.alive_paths: dict[bytes, tuple] = {}  # a valid write's paths at step 2
        self.provisional: set = set()  # opened with a handed key
        self._logs = self._other_logs()
        self._open()
        if base is not None:
            self._install_base()
        self._check_signatures()
        for i, verdict in self._presets.items():
            if i in self.view and i != log.genesis and i not in self.status:
                self.status[i] = verdict
        if log.genesis in self.status:
            raise SpecError(self.status[log.genesis][1])
        self.genesis_body = self.decoded[log.genesis]
        # In a checkpoint's world the descriptor stays the genesis's
        # (roster.md, "The world after a checkpoint").
        self.space_descriptor = base["descriptor"] if base is not None \
            else self.genesis_body.descriptor
        self._forced_race: set = set()
        # The genesis: keys.md's .
        kg.check_payload_context(self.genesis_body.payload, {
            "event": "genesis", "author_propagates": True,
            "restricted": (self.space_descriptor or {}).get("kind")
            == spaces.KIND_RESTRICTED})
        if self.storage is not None:
            # A genesis waits for its root (NoTwin), and a
            # space whose root fails is unusable (BadTwin).
            verdict = self.storage.twin(self, log.genesis, None, frozenset())
            if verdict:
                raise SpecError(verdict)
        # events.md: an event whose signature verified is fork
        # evidence, whether or not this replica can open it.
        self.forks = log.fork_points(self.view, lambda i: i in self._signed)
        if base is not None:
            # roster.md, "The world after a checkpoint": an author the record
            # shows forked stays forked, and an event at or below its tip
            # repeats a sequence number the record already holds.
            for author, seq in base["record"]["forks"].items():
                self.forks[author] = min(self.forks.get(author, seq), seq)
            for i in self.view:
                e = self.ev(i)
                tip = base["record"]["tips"].get(e.author)
                if i != log.genesis and tip is not None and e.seq <= tip[0]:
                    self.forks[e.author] = min(self.forks.get(e.author, e.seq), e.seq)
        self._hold_sealed()
        self._resolve_roster()
        self._judge_writes()

    # -- helpers
    def ev(self, i: bytes) -> events.Event:
        return self.log.events[i]

    def changes(self, i: bytes) -> tuple:
        return self.decoded[i].changes or ()

    def is_roster(self, i: bytes) -> bool:
        """A space event whose sealed part holds roster changes."""
        return i in self.decoded and self.decoded[i].changes is not None

    def is_key(self, i: bytes) -> bool:
        """A space event that changes no membership: a key event."""
        return i in self.decoded and self.decoded[i].changes is None

    def is_successor(self, i: bytes) -> bool:
        """A roster event whose one change is op 4, signed by an
        invite key."""
        return i in self.decoded and any(c.op == SUCCEED for c in self.changes(i))

    def claimant(self, i: bytes) -> tuple:
        return next(c.member for c in self.changes(i) if c.op == SUCCEED)

    def author_member(self, i: bytes) -> tuple:
        """The member whose authority an event uses: its author's device, or,
        for a successor, the invite key."""
        return (INVITE if self.is_successor(i) else DEVICE, self.ev(i).author)

    def accepted(self, i: bytes) -> bool:
        return i in self._signed and opened(self.ev(i))

    def refs(self, i: bytes) -> tuple:
        """The refs an event carries in its body. Units carry theirs inside their seal (units.md); this
        module stands in for it with a unit body that starts with
        UNIT_REFS_PREFIX and holds the refs' encoding."""
        if i in self.decoded:
            return self.decoded[i].refs
        e = self.ev(i)
        if e.kind == KIND_UNIT and e.body.startswith(UNIT_REFS_PREFIX):
            return read_refs(uncbor(e.body[len(UNIT_REFS_PREFIX):]))
        return ()

    def _other_logs(self) -> dict:
        """Every other log this replica reads for this space, by log ID, with
        the events it holds of it: the lists and granted spaces it was given,
        and theirs in turn."""
        out: dict = {}

        def walk(lists, spaces_):
            for pid, lst in lists.items():
                # A list held from its checkpoint on: a ref to an event before
                # the checkpoint counts as resolved, whether the replica kept
                # that event or forgot it (section 3.15.8).
                out.setdefault(pid, (lst.log, set(lst.view)
                                     | set(getattr(lst, "before_checkpoint", ()))))
            for sid, sp in spaces_.items():
                if sid not in out:
                    out[sid] = (sp.log, sp.view)
                    walk(sp.lists, sp.spaces)
        walk(self.lists, self.spaces)
        return out

    def resolves(self, ref: tuple) -> bool:
        """This replica holds the event a ref names."""
        held = self._logs.get(ref[0])
        return held is not None and ref[1] in held[1]

    def covers(self, ref: tuple, log_id: bytes, end: bytes) -> bool:
        """A ref names `end`, or a held event of its log that has
        `end` in its past: the referrer knew of `end`."""
        if ref[0] != log_id:
            return False
        if ref[1] == end:
            return True
        held = self._logs.get(log_id)
        return held is not None and ref[1] in held[1] and end in held[0].anc[ref[1]]

    def secret_for(self, i: bytes, visible: dict) -> bytes | None:
        """The new rotation's content key, or the content key of
        the state a non-rotating event names, if this replica holds it. A
        rotation key whose read credential does not match the event's visible
        `read` is not that rotation's key, and counts as not held: the
        replica treats the event as one it cannot open, never as BadSeal."""
        if visible["rotates"]:
            secret = self.keys.rotations.get(i)
            if secret is not None and kg.read_credential(secret)["public"] != visible["read"]:
                return None  # not this rotation's key (keys.md)
            return secret
        state = kg.decode_set(visible["sealed_under"])
        if not all(r in self.keys.rotations for r in state):
            return None
        return kg.content_key(self.log.id, state, self.keys.rotations.__getitem__)

    def provisional_secret(self, visible: dict) -> bytes | None:
        """A merged state's content key received whole by wrap,
        which this replica could not check against single rotations'
        commitments (keys.md)."""
        if visible["rotates"]:
            return None
        return self.keys.states.get(visible["sealed_under"])

    def _open(self) -> None:
        """Each space event's visible part, then its
        sealed part with the body key this replica can derive or was given."""
        self._sealed: set = set()
        self._bad_seal: set = set()
        self._extension: set = set()
        self._void_body: dict[bytes, str] = {}
        self.visible: dict[bytes, dict] = {}
        for i in self.log.canonical(self.view):
            e = self.ev(i)
            if e.kind == KIND_UNIT and self.base is not None:
                # units.md, section 3.2, step 12: in a checkpoint's world a
                # unit sealed under a rotation that is neither the
                # checkpoint nor after it in its past is StaleSeal, read
                # before any key (roster.md, "The world after a checkpoint").
                state = unit_key_reference(e)
                if state is not None and not all(
                        r == self.log.genesis or r in self.log.anc[i] for r in state):
                    self.status[i] = (False, "StaleSeal", None)
                continue
            if e.kind != KIND_SPACE:
                continue
            try:
                visible = read_visible(e)
                self.visible[i] = visible
                if not visible["rotates"]:
                    state = kg.decode_set(visible["sealed_under"])
                    if not all(r in self.log.anc[i] for r in state):
                        # In a checkpoint's world the log holds only the
                        # root and what follows it: a state outside it is
                        # StaleSeal, read from the visible part alone
                        # (roster.md, "The world after a checkpoint").
                        raise SpecError("StaleSeal" if self.base is not None else "Malformed")
            except SpecError as error:
                self.status[i] = (False, error.error, None)  # steps 2 and 3: no evidence
                continue
            secret = self.secret_for(i, visible)
            whole = None if secret is not None else self.provisional_secret(visible)
            if secret is not None:
                key = body_key(e, visible, secret)
                if kg.body_commitment(key) != visible["commitment"]:
                    self._bad_seal.add(i)  # step 4: sealed under another key
                    continue
            elif whole is not None:
                # Step 4 under a provisional key: a mismatch may be the
                # wrapper's junk, so the event is held, never BadSeal.
                key = body_key(e, visible, whole)
                if kg.body_commitment(key) != visible["commitment"]:
                    self._sealed.add(i)
                    continue
                self.provisional.add(i)
            else:
                # Step 4, a handed key. Two senders that hand
                # different keys for one event cannot both be honest: hold it.
                handed = self.keys.handed(i)
                key = handed[0] if len(handed) == 1 else None
                if key is None or kg.body_commitment(key) != visible["commitment"]:
                    self._sealed.add(i)  # step 4: held until its key arrives
                    continue
                self.provisional.add(i)
            try:
                self.decoded[i] = decode_body(e, key)
            except SpecError as error:
                # Steps 4 to 10: the signature is still checked, for evidence.
                if error.error == "ExtensionRequired":
                    self._extension.add(i)
                elif error.error == "BadSeal":
                    self._bad_seal.add(i)
                else:
                    self._void_body[i] = error.error
        # A replica that cannot open the genesis has no space.
        if self.log.genesis in self._sealed:
            raise SpecError("Sealed")
        if self.log.genesis in self._bad_seal:
            raise SpecError("BadSeal")

    def _hold_sealed(self) -> None:
        """A space event this replica cannot open is held as
        Sealed, and everything after it as Pending: never applied, never cited.
        : so is a unit or key event whose refs name an event this
        replica does not hold; a roster event is not, and
        its refs count only once they resolve."""
        self._unresolved = {i for i in self.view
                            if ((i in self.decoded and self.is_key(i))
                                or self.ev(i).kind == KIND_UNIT)
                            and not all(self.resolves(r) for r in self.refs(i))}
        held = self._sealed | self._bad_seal | self._unresolved | self._unopened
        # roster.md, "The space descriptor": a descriptor of a kind or with a
        # key that a later document defines holds every event after the
        # genesis, which this replica has read.
        if (self.space_descriptor or {}).get("reserved"):
            for i in self.view - {self.log.genesis}:
                if i not in self.status:
                    self.status[i] = (False, "ExtensionRequired", None)
                held.add(i)
        # roster.md, "Rules this replica lacks": a roster part of a type a
        # later document defines, by an author with standing, is held with
        # every event outside its past: this replica's view stops there.
        frozen = set()
        for x in sorted(self._extension, key=self.log.order_key):
            if x in self.status:
                continue
            if not self.standing(x):
                self.status[x] = (False, "NotAnAdministrator", None)
                continue
            self.status[x] = (False, "ExtensionRequired", None)
            held.add(x)
            frozen |= {i for i in self.view if i != x and i not in self.log.anc[x]}
        for i in sorted(frozen, key=self.log.order_key):
            if i not in self.status:
                self.status[i] = (False, "ExtensionRequired", None)
        held |= frozen
        self._unaccepted = set(held)
        for i in self.log.canonical(self.view):
            if self.log.anc[i] & held:
                self._unaccepted.add(i)
            if i in self._bad_seal and i not in self.status:
                self.status[i] = (False, "BadSeal", None)
            elif i in self._sealed and i not in self.status:
                self.status[i] = (False, "Sealed", None)
            elif i in self._unresolved and i not in self.status:
                self.status[i] = (False, "Pending", None)
            elif i not in self.status and self.log.anc[i] & held:
                self.status[i] = (False, "Pending", None)

    def sealed_under(self, i: bytes) -> tuple:
        """The rotations whose keys open space event i: itself if it rotates,
        else the state it names."""
        v = self.visible[i]
        return (i,) if v["rotates"] else kg.decode_set(v["sealed_under"])

    def snapshot_keys(self, held) -> dict:
        """What a snapshot carries for a newcomer that will hold
        the rotation keys `held`: the body key of every space event this
        replica opened that the newcomer could not open itself."""
        return {i: d.body_key for i, d in sorted(self.decoded.items())
                if not set(self.sealed_under(i)) <= set(held)}

    def carried_keys(self) -> list[tuple]:
        """The (ML-DSA-65 key, X-Wing key or None) pairs this log's records
        carry, opened, valid or void: each grant of a device or an invite key
        and each successor of a device (keys 10 and 9), and each root or
        enrolment's pseudonym key, with no X-Wing key, beside the founder's
        keys a root carries (peers.md). A verifier takes them by their hash
        (crypto.md, "Keys by their hash"), so the source vouches for nothing."""
        out = []
        for i in self.log.canonical(self.view):
            found = []
            if i in self.decoded and self.decoded[i].changes is not None:
                found = [(c.mldsa, c.hybrid) for c in self.decoded[i].changes
                         if c.op in (GRANT, SUCCEED) and c.mldsa is not None]
            elif self.ev(i).kind == KIND_STORAGE:
                try:
                    record = storage_record(self.ev(i))
                except SpecError:
                    record = {"mldsa": None}
                if record["mldsa"] is not None:
                    found = [(record["mldsa"], None)]
                if record.get("founder") is not None:
                    found.append(record["founder"])
            out += [k for k in found if k not in out]
        return out

    def held_keys(self) -> list[tuple]:
        """Every key pair this replica holds for this space's authors: this
        log's records, then the held lists of persons and the held granted
        spaces, each by ID, then any it was given (`extra_keys`). Only the
        pair that hashes to an author's kc is ever tried."""
        out = list(self.carried_keys())
        for pid in sorted(self.lists):
            out += [k for k in self.lists[pid].named_keys() if k not in out]
        for sid in sorted(self.spaces):
            out += [k for k in self.spaces[sid].held_keys() if k not in out]
        out += [k for k in self.extra_keys if k not in out]
        return out

    def key_sets(self) -> list[tuple]:
        """(Ed25519 key, ML-DSA-65 key, X-Wing key or None) triples this
        replica holds with an Ed25519 key: each grant of a device or invite
        key in this log, each add of a held list, each held granted space's."""
        out = []
        for i in self.log.canonical(self.view):
            if i in self.decoded and self.decoded[i].changes is not None:
                out += [(c.ed25519, c.mldsa, c.hybrid) for c in self.decoded[i].changes
                        if c.op in (GRANT, SUCCEED) and c.ed25519 is not None
                        and (c.ed25519, c.mldsa, c.hybrid) not in out]
        for pid in sorted(self.lists):
            lst = self.lists[pid]
            for i in lst.log.canonical(lst.view):
                b = lst.bodies.get(i)
                if b and b.action == identity.ADD and (b.identity, b.mldsa, b.xwing) not in out:
                    out.append((b.identity, b.mldsa, b.xwing))
        for sid in sorted(self.spaces):
            out += [k for k in self.spaces[sid].key_sets() if k not in out]
        return out

    def device_keys(self, device: bytes) -> tuple | None:
        """crypto.md, "Keys by their hash": the Ed25519, ML-DSA-65 and X-Wing
        keys of a holder known only by its device ID, from any source, which
        hash to that device ID; None while none held do."""
        return next((k for k in self.key_sets() if hs.device_id_of(*k) == device), None)

    def pseudonym_keys(self, pseudonym: bytes) -> list[bytes]:
        """Whether the skeleton vouches for `pseudonym`: the ML-DSA-65 key a
        root or an enrolment by it names, counted only when the root passes
        peers.md's checks, or the enrolment verifies against a slot a held
        root or change made. A self-signed enrolment of a stranger names
        nothing, so its events are dropped. Those checks are peers.md's,
        through the StorageView; a replica that models no skeleton counts
        none. It decides whether a skeleton event is kept, never whether its
        signature verifies (section 3.4.2)."""
        if self.storage is None:
            return []
        return list(self.storage.pseudonym_keys(self, pseudonym))

    def named(self, author: bytes) -> bool:
        """Some record names `author` (section 3.12.2): a grant of its device
        ID, or of it as an invite key, in this log; an add of it in a list
        the space reads; a grant of it in a granted space; or a skeleton
        record of its pseudonym that the skeleton vouches for."""
        for i in self.log.canonical(self.view):
            if self.is_roster(i) and any(c.op in (GRANT, SUCCEED) and c.member in (
                    (DEVICE, author), (INVITE, author)) for c in self.changes(i)):
                return True
        for lst in self.lists.values():
            if any(b.action == identity.ADD and b.device == author for b in lst.bodies.values()):
                return True
        if any(sp.named(author) for sp in self.spaces.values()):
            return True
        return bool(self.pseudonym_keys(author))

    def _check_signatures(self) -> None:
        """Every event's signature under the keys that hash to its kc,
        wherever this replica holds them (section 3.4.2); events this replica
        cannot open are checked too, for the evidence their signatures give
        (events.md)."""
        self._signed: set = set()
        progress = True
        while progress:
            progress = False
            held = self.held_keys()
            for i in self.log.canonical(self.view):
                if i in self._signed or i in self.status:
                    continue
                e = self.ev(i)
                if e.scheme == events.SCHEME_ED25519:
                    self._signed.add(i)
                    progress = True
                    continue
                if e.kind == KIND_STORAGE:
                    try:
                        storage_record(e)
                    except SpecError as error:
                        self.status[i] = (False, error.error, None)
                        progress = True
                        continue
                verdict = identity.signature_ok(e, held)
                if verdict == "NoHybridKey":
                    continue
                if verdict is True:
                    self._signed.add(i)
                else:
                    self.status[i] = (False, verdict, None)
                progress = True
        held = self._sealed | self._bad_seal
        # Steps 5 to 10 come before the signature's step 11: a body void
        # alone keeps its class whatever its signature. A held body's
        # signature still counts: BadSignature is final.
        for i, error in self._void_body.items():
            if i not in self.status or self.status[i][1] == "BadSignature":
                self.status[i] = (False, error, None)
        # A unit whose seal does not open is held (units.md): Sealed, with
        # every event after it; its signature still counts as evidence.
        self._unopened = {i for i in self._signed if not opened(self.ev(i))}
        for i in self.view:
            if i not in self._signed and i not in self.status and i not in held:
                self.status[i] = (False, "NoHybridKey", None)
            elif i in self._unopened:
                self.status[i] = (False, "Sealed", None)

    def seniority_key(self, g: bytes, member_id: bytes) -> tuple:
        """Height, then a hash of the space ID and the grantee's
        key, which the granter does not choose, then the grant's ID. After a
        checkpoint, the epoch comes first, and heights count from the
        checkpoint (roster.md, "The world after a checkpoint")."""
        return (self.epoch, self.log.height[g], sha256(SENIORITY_LABEL + self.log.id + member_id),
                g)

    def _install_base(self) -> None:
        """The root of a checkpoint's world stands as a genesis (roster.md,
        "The world after a checkpoint"): the record's members as its grants,
        the record's policy as its policy. An invite key the record shows
        claimed is out, as if the root were its successor; the root counts
        as a successor of every key whose status is not open. The root
        carries each granted space's recorded notices, by their recorded
        authors, and names the recorded `named` IDs in its refs."""
        root = self.log.genesis
        record = self.base["record"]
        d = self.decoded.get(root)
        if d is None or d.part is None:
            raise SpecError("Sealed")
        grants, states = [], {}
        self._root_used: set = set()
        self._root_notices: list = []
        refs = []
        for m in record["members"]:
            member = m["member"]
            if member[0] == INVITE and m["invite"] != INVITE_OPEN:
                self._root_used.add(member[1])
            if m.get("invite") == INVITE_CLAIMED:
                grants.append(Change(GRANT, member, READ, None, None, FROM_NOW_ON, VIA_LINK,
                                     None, None, m["xwing"], m["mldsa"], None, m["ed25519"]))
                states[member] = State(False, removed_by=(root,))
                continue
            caps = tuple(sorted(m["caps"])) or None
            grants.append(Change(GRANT, member, m["level"], caps, m["label"], m["history"],
                                 m["via"], m["session"], m["replaces"], m["xwing"], m["mldsa"],
                                 None, m["ed25519"], m["expires_at"], m["claims"]))
            epoch, height, _, grant = m["seniority"]
            states[member] = State(
                True, level=m["level"], caps=frozenset(m["caps"]), label=m["label"],
                history=m["history"], via=m["via"], session=m["session"],
                replaces=m["replaces"], grants=frozenset([root]),
                seniority=(epoch, height,
                           sha256(SENIORITY_LABEL + self.log.id + member[1]), grant),
                hybrid=m["xwing"], source=self.log.order_key(root),
                expires_at=m["expires_at"], rank=m.get("rank"))
            if member[0] == SPACE:
                for rotation, public, brk, author in m["notices"]:
                    self._root_notices.append(({"space": member[1], "rotation": rotation,
                                                "public": public, "from_now_on": bool(brk)},
                                               author))
                refs += [(member[1], x) for x in m["named"]]
        self._base_states = states
        self.decoded[root] = Decoded(True, tuple(grants), True, d.payload, DUEL_BOTH_STAND,
                                     record["policy"], self.base["descriptor"], d.body_key,
                                     refs=tuple(sorted(refs)),
                                     system_stream=self.base["system_stream"],
                                     checkpoint=record, part=d.part)

    def root_successor(self, key: bytes) -> bool:
        """In a checkpoint's world, the root counts as a successor of every
        invite key whose recorded status is not open (ext-invite-links.md,
        "Across a checkpoint")."""
        return self.base is not None and key in getattr(self, "_root_used", ())

    def place(self, i: bytes, valid) -> frozenset:
        return frozenset([self.log.genesis] + [p for p in self.log.anc[i] if p in valid])

    def _valid_place(self, i: bytes, status) -> frozenset:
        return frozenset([self.log.genesis] + [p for p in self.log.anc[i]
                                                if p in status and status[p][0]
                                                and self.is_roster(p)])

    # -- the roster at a set of valid roster events
    def state(self, valid: frozenset) -> dict:
        hit = self._cache.get(valid)
        if hit is not None:
            return hit
        by_member: dict = {}
        for eid in valid:
            for c in self.changes(eid):
                if c.member is not None:
                    by_member.setdefault(c.member, []).append((eid, c))
        out = {}
        for m, items in by_member.items():
            ids = [e for e, _ in items]
            maximal = [(e, c) for e, c in items
                       if not any(e != e2 and e in self.log.anc[e2] for e2 in ids)]
            removals = [e for e, c in maximal if c.op == REMOVE]
            if removals:
                out[m] = State(False, removed_by=tuple(sorted(removals,
                                                               key=self.log.order_key)))
                continue
            states = [s for s in (self._item_state(e, c, valid) for e, c in maximal) if s]
            if states:
                out[m] = meet(states)
        # An invite key is out at any place that holds a
        # valid successor it signed, as if that successor removed it.
        for e in sorted(valid, key=self.log.order_key):
            key = (INVITE, self.ev(e).author)
            if self.is_successor(e) and (key not in out or out[key].present):
                out[key] = State(False, removed_by=(e,))
        self._cache[valid] = out
        return out

    def _item_state(self, e: bytes, c: Change, valid) -> State | None:
        if self.base is not None and e == self.log.genesis:
            return self._base_states.get(c.member)
        if c.op == SUCCEED:
            # The claimant takes the invite's state at the
            # successor's place, by link, with the successor as its grant.
            inv = self.state(self.place(e, valid)).get((INVITE, self.ev(e).author))
            if inv is None or not inv.present:
                return None
            return State(True, level=inv.level, caps=inv.caps, label=inv.label,
                         history=inv.history, via=VIA_LINK, session=inv.session,
                         grants=frozenset([e]), seniority=self.seniority_key(e, c.member[1]),
                         hybrid=c.hybrid if c.member[0] == DEVICE else None,
                         source=self.log.order_key(e),
                         expires_at=inv.expires_at if inv.session is not None else None)
        if c.op == GRANT:
            return State(True, level=c.level, caps=frozenset(c.caps or ()), label=c.label,
                         history=c.history, via=c.via, session=c.session, replaces=c.replaces,
                         grants=frozenset([e]), seniority=self.seniority_key(e, c.member[1]),
                         hybrid=c.hybrid, source=self.log.order_key(e),
                         expires_at=c.expires_at, rank=c.rank)
        prior = self.state(self.place(e, valid)).get(c.member)
        if prior is None or not prior.present:
            return None
        level = prior.level if c.level is None else c.level
        return State(True, level=level,
                     caps=prior.caps if c.caps is None else frozenset(c.caps),
                     label=prior.label if c.label is None else c.label,
                     history=prior.history, via=prior.via, session=prior.session,
                     replaces=prior.replaces, grants=prior.grants, seniority=prior.seniority,
                     hybrid=prior.hybrid, source=self.log.order_key(e),
                     expires_at=prior.expires_at,
                     rank=None if level != ADMINISTER else (
                         prior.rank if prior.level == ADMINISTER else c.rank))

    def policy(self, valid: frozenset) -> dict:
        """."""
        items = [(e, c) for e in valid for c in self.changes(e) if c.op == POLICY]
        items.append((self.log.genesis, None))
        ids = [e for e, _ in items]
        maximal = [(e, c) for e, c in items
                   if not any(e != e2 and e in self.log.anc[e2] for e2 in ids)]
        return merge_policies([self.genesis_body.policy if c is None
                               else spaces.read_policy(c.policy) for _, c in maximal])

    # -- the rules
    def self_lowering(self, e: bytes) -> bool:
        me = (DEVICE, self.ev(e).author)
        return all(c.member == me and (c.op == REMOVE or (
            c.op == CHANGE and c.level is not None and c.level < ADMINISTER
            and c.caps is None and c.label is None)) for c in self.changes(e))

    def auth(self, e: bytes, status) -> tuple:
        """The checks at the event's place, in their order, with
        the twin of step 7 last."""
        if self.storage is not None and any(
                self._held_for_twin(p, status) for p in self.log.anc[e] if p in status):
            return (False, "Pending")  # Held, as if not received
        verdict = (self._successor_auth(e, status) if self.is_successor(e)
                   else self._auth(e, status))
        if verdict[0] and self.storage is not None:
            twin = self._twin(e, self._valid_place(e, status))
            if twin:
                return (False, twin)
        return verdict

    def administer_changes(self, e: bytes, S: dict) -> dict:
        """ (peers.md): the devices e grants or
        raises to administer, and those it lowers from it, at a place whose
        roster is S."""
        if e == self.log.genesis:
            return {"grants": [self.ev(e).author], "lowers": []}
        grants, lowers = [], []
        for c in self.changes(e):
            if c.member is None or c.member[0] != DEVICE:
                continue
            prior = S.get(c.member)
            was = prior is not None and prior.present and prior.level == ADMINISTER
            if c.op == GRANT and c.level == ADMINISTER:
                grants.append(c.member[1])
            elif c.op == CHANGE and c.level == ADMINISTER and not was:
                grants.append(c.member[1])
            elif was and (c.op == REMOVE or (c.op == CHANGE and c.level is not None
                                             and c.level < ADMINISTER)):
                lowers.append(c.member[1])
        return {"grants": grants, "lowers": lowers}

    def _twin(self, e: bytes, place: frozenset) -> str | None:
        """Visible key 15 names the twin exactly when e
        changes who administers at its place; that twin is held and passes
        peers.md."""
        named = self.visible[e].get("twin")
        ch = self.administer_changes(e, self.state(place))
        if not (ch["grants"] or ch["lowers"]):
            return "UnexpectedTwin" if named is not None else None
        if named is None:
            return "TwinRequired"
        return self.storage.twin(self, e, named, place)

    def _context(self, e: bytes, S: dict) -> dict:
        """keys.md's context for the checks against the event and its place,
        derived from e's changes and the roster S at its place."""
        me = self.author_member(e)
        mine = S.get(me)
        ctx = {"event": "roster",
               "author_propagates": mine is not None and mine.present and mine.session is None,
               "restricted": (self.space_descriptor or {}).get("kind")
               == spaces.KIND_RESTRICTED}
        lowering = self.self_lowering(e)
        for c in self.changes(e):
            cur = S.get(c.member) if c.member is not None else None
            held = cur is not None and cur.present
            if c.op == REMOVE and held:  # a close removes no one who holds anything new
                ctx["removes"] = True
                if c.member == me:
                    ctx["removes_self"] = True
                elif cur.session is None and not lowering:
                    ctx["removes_propagating"] = True
            elif c.op == CHANGE and held and c.level is not None and c.level < cur.level:
                if c.member == me:
                    ctx["lowers_self"] = True
                if c.level == READ:
                    ctx["lowers_to_read"] = True
            elif c.op == GRANT and c.history == FROM_NOW_ON:
                ctx["admits_from_now_on"] = True
                if c.session is None:
                    ctx["admits_propagating"] = True
        return ctx

    def _payload_checks(self, e: bytes, S: dict, place) -> tuple:
        """keys.md's checks against the event and its place, in their order:
        RotationRequired before StaleSeal. The rotations a roster event's
        place counts are the genesis and the roster events valid there.
        Step 8 is a key event's; a notice's own checks decide no verdict."""
        ctx = self._context(e, S)
        ctx["sealed_under_stale"] = self._stale(e, place)
        try:
            self._check_with_notices(e, S, ctx, place)
        except SpecError as error:
            return (False, error.error)
        return (True, None)

    # -- notices (keys.md, "Checks against the event and its place", step 8)
    def is_rotation(self, i: bytes) -> bool:
        """This replica holds `i`, a space event of this log whose visible
        part rotates."""
        if i not in self.view or self.ev(i).kind != KIND_SPACE:
            return False
        try:
            return bool(read_visible(self.ev(i))["rotates"])
        except SpecError:
            return False

    def _check_with_notices(self, e: bytes, S: dict, ctx: dict, valid=frozenset()) -> None:
        """keys.md's checks against the event and its place, steps 1 to 8.
        Step 8 reads only the event and the roster at its place: a key event
        whose sealed refs name an event of the log of a space S grants
        carries a notice for that space (NoticeRequired). Every replica
        decides it alike, whichever granted spaces' logs it holds; a
        notice's own checks (notice_outcome) decide no verdict."""
        notices = self.decoded[e].payload.get("notices") or []
        granted = {m[1] for m, st in S.items() if m[0] == SPACE and st.present}
        cited = {log_id for log_id, _ in self.refs(e) if log_id in granted}
        if cited:
            ctx["refs_granted"] = True
            ctx["notice_covers"] = cited <= {n["space"] for n in notices}
        kg.check_payload_context(self.decoded[e].payload, ctx)

    def notice_outcome(self, e: bytes, n: dict, author: bytes | None = None) -> str | None:
        """keys.md, "Notices and space principals": whether notice n of
        event e admits its principal at this replica: None when it does,
        else its class, Pending while this replica does not hold the
        granted space's log or cannot tell. Staleness is left to
        principals(), whose standing rule covers it."""
        sp = self.spaces.get(n["space"])
        if sp is None:
            return "Pending"
        R = n["rotation"]
        grantee = None
        if R in sp.view and sp.ev(R).kind == KIND_SPACE:
            grantee = {"valid": bool(sp.status.get(R, (False,))[0]),
                       "grant_commitment": read_visible(sp.ev(R))["grant_commitment"]}
        propagates = None
        if R in sp.view:
            place = sp._valid_place(R, sp.status)
            if sp.status.get(R, (False,))[0] and sp.is_roster(R):
                place = place | {R}
            who = self.ev(e).author if author is None else author
            propagates = sp.effective(place).get(who, (0, None))[1] is not None
        try:
            kg.check_notice(n, grantee, propagates)
        except SpecError as error:
            return error.error
        return None

    def principals(self) -> list:
        """keys.md's space principals in force at this view, as (space ID,
        rotation) pairs: each notice of a valid event that admits its
        principal here, while the roster grants its space and its rotation
        has in its past, or is, every valid rotation of that space that a
        valid event names in its sealed refs."""
        valid = self.valid()
        granted = {m[1] for m, st in self.roster.items() if m[0] == SPACE and st.present}
        out = set()
        for e, n, author in self.carried_notices(valid):
            if n["space"] not in granted or self.notice_outcome(e, n, author) is not None:
                continue
            sp = self.spaces[n["space"]]
            named = {r for i in valid for log_id, r in self.refs(i)
                     if log_id == n["space"] and r in sp.view
                     and sp.status.get(r, (False,))[0] and sp.is_rotation(r)}
            if all(sp.log.le(x, n["rotation"]) for x in named):
                out.add((n["space"], n["rotation"]))
        return sorted(out)

    def carried_notices(self, valid=None) -> list:
        """(event, notice, author) for every notice a valid event carries;
        in a checkpoint's world the root carries the record's notices, each
        by the author the record names (roster.md, "The world after a
        checkpoint")."""
        valid = self.valid() if valid is None else valid
        out = []
        for e in self.log.canonical(valid):
            if e not in self.decoded:
                continue
            for n in self.decoded[e].payload.get("notices") or []:
                out.append((e, n, self.ev(e).author))
        if self.base is not None:
            out += [(self.log.genesis, n, a) for n, a in getattr(self, "_root_notices", ())]
        return out

    def _held_for_twin(self, p: bytes, status) -> bool:
        """P, a roster event in the past, waits for its
        twin. Under a trial assignment this is computed
        at p's place under that assignment."""
        v = status.get(p)
        if v is None or v[0] or not self.is_roster(p):
            return False
        if v[1] == "NoTwin":
            return True
        if v[1] != "trial":
            return False
        core = (self._successor_auth(p, status) if self.is_successor(p)
                else self._auth(p, status))
        return core[0] and self._twin(p, self._valid_place(p, status)) == "NoTwin"

    def _invite_named(self, key: bytes, place) -> bool:
        """An invite key is granted once; InviteUsed if an
        event of the place names it or it signed a successor there."""
        return any(any(x.member == (INVITE, key) for x in self.changes(p))
                   or (self.is_successor(p) and self.ev(p).author == key)
                   for p in place if p in self.decoded)

    def _invite_grant(self, grants, key: bytes) -> Change | None:
        for g in sorted(grants, key=self.log.order_key):
            for c in self.changes(g):
                if c.op == GRANT and c.member == (INVITE, key):
                    return c
        return None

    def _successor_auth(self, e: bytes, status) -> tuple:
        """ext-invite-links.md, "Invites in the roster": a successor's
        authority, in order. A successor of the same key in its past voids
        it, whether that successor is valid or void."""
        place = self._valid_place(e, status)
        S = self.state(place)
        author = self.ev(e).author
        if self.root_successor(author) or any(
                self.is_successor(p) and self.ev(p).author == author for p in self.log.anc[e]):
            return (False, "InviteUsed")
        inv = S.get((INVITE, author))
        if inv is None or not inv.present:
            return (False, "NotAnInvite")
        c = self._invite_grant(inv.grants, author)
        member = self.claimant(e)
        if c is None or member[0] != c.claims:
            return (False, "ClaimMismatch")
        cur = S.get(member)
        if cur is not None and cur.present:
            return (False, "AlreadyMember")
        if len(place) + 1 > MAX_ROSTER_EVENTS:
            return (False, "Full")
        if self._stale(e, place):
            return (False, "StaleSeal")
        if self._forced_race and e in self._forced_race:
            return (False, "ClaimRaced")  # An unclosed race voids it
        return self._payload_checks(e, S, place)

    def _auth(self, e: bytes, status) -> tuple:
        place = self._valid_place(e, status)
        S = self.state(place)
        me = (DEVICE, self.ev(e).author)
        a = S.get(me)
        if a is None or not a.present or a.level != ADMINISTER:
            return (False, "NotAnAdministrator")
        mine = a.rank if a.rank is not None else MAX_RANK
        for c in self.changes(e):
            if c.op == POLICY:
                continue
            cur = S.get(c.member)
            present = cur is not None and cur.present
            if c.op == GRANT:
                if c.member == me:
                    return (False, "SelfGrant")
                if c.member[0] == INVITE and self._invite_named(c.member[1], place):
                    return (False, "InviteUsed")
                if present:
                    return (False, "AlreadyMember")
                if c.rank is not None and c.rank > mine:
                    return (False, "HigherRank")  # a rank above its author's
            else:
                closes = (c.op == REMOVE and c.member[0] == INVITE and cur is not None
                          and cur.removed_by
                          and all(self.is_successor(r) or (
                              r == self.log.genesis and self.root_successor(c.member[1]))
                              for r in cur.removed_by))
                if not present and not closes:
                    return (False, "NoSuchMember")  # a close is valid
                if c.op == CHANGE and c.member == me and not (
                        c.level is not None and c.level < cur.level and c.caps is None
                        and c.label is None):
                    return (False, "SelfChange")
                # A change carries no session: whether it raises a guest is
                # the roster's at its place.
                if c.op == CHANGE and c.level == ADMINISTER and cur.session is not None:
                    return (False, "AdministerNotDevice")
                # Ranks (section 3.6): nobody changes or removes an
                # administrator of a higher rank than its own, or sets a rank
                # above its own; a rank is set when a device becomes an
                # administrator, never changed in place.
                if present and cur.level == ADMINISTER and cur.rank is not None \
                        and cur.rank > mine and c.member != me:
                    return (False, "HigherRank")
                if c.op == CHANGE and c.rank is not None and c.rank > mine:
                    return (False, "HigherRank")
                if c.op == CHANGE and c.level == ADMINISTER and present \
                        and cur.level == ADMINISTER and c.rank != cur.rank:
                    return (False, "RankInPlace")
        if len(self.changes(e)) > 1:
            for c in self.changes(e):
                cur = S.get(c.member) if c.member else None
                if cur is None:
                    continue
                lowers = c.op == REMOVE or (c.op == CHANGE and c.level is not None
                                            and c.level < cur.level)
                if lowers and c.member[0] == DEVICE and cur.level == ADMINISTER:
                    return (False, "AdminAlone")
        # At most 4,096 valid roster events in the
        # event's valid past, itself included; void events count for nothing.
        if len(place) + 1 > MAX_ROSTER_EVENTS:
            return (False, "Full")
        # 5: keys.md's checks against the event and its place, in their
        # order: RotationRequired, then StaleSeal (sealed under the author's
        # current content state, as far as the roster at its place shows).
        return self._payload_checks(e, S, place)

    def _stale(self, e: bytes, valid) -> bool:
        """StaleSeal: e does not rotate, and a valid rotation in its past
        follows a rotation of the state it is sealed under."""
        if self.decoded[e].rotates:
            return False
        S = self.sealed_under(e)
        return any(r in self.decoded and self.decoded[r].rotates and r not in S
                   and r in self.log.anc[e] and any(x in self.log.anc[r] for x in S)
                   for r in valid)

    def attacks(self, x: bytes, e: bytes) -> str | None:
        """A successor's author taken as its invite key.
        Attack (d) never holds between two successors (ext-invite-links.md)."""
        if not self.log.concurrent(x, e) or self.self_lowering(e):
            return None
        me = self.author_member(e)
        for c in self.changes(x):
            if c.member == me and c.op == REMOVE:
                return "RemovedConcurrently"
            if c.member == me and c.op == CHANGE and c.level is not None and c.level < ADMINISTER:
                return "DemotedConcurrently"
        removed = {c.member for c in self.changes(x) if c.op == REMOVE}
        if any(c.op in (GRANT, CHANGE, SUCCEED) and c.member in removed
               for c in self.changes(e)):
            return "TargetRemovedConcurrently"
        return None

    def standing_candidates(self, e: bytes) -> list:
        """The opened roster events of the view, valid or void, that name e's
        author at administer; for a successor, those that grant its invite
        key (ext-invite-links.md)."""
        author = self.ev(e).author
        if self.is_successor(e):
            return [p for p in self.decoded if p in self.view
                    and any(c.op == GRANT and c.member == (INVITE, author)
                            for c in self.changes(p))]
        me = (DEVICE, author)
        return [p for p in self.decoded if p in self.view
                and any(c.member == me and c.op in (GRANT, CHANGE) and c.level == ADMINISTER
                        for c in self.changes(p))]

    def standing(self, e: bytes) -> bool:
        """Section 3.7, "Standing": the genesis or a roster event in e's past,
        opened through step 10 whether valid or void, names e's author's
        device member at administer. For a successor, a grant of its invite
        key in its past (ext-invite-links.md)."""
        return any(p in self.log.anc[e] for p in self.standing_candidates(e))

    def _unstanding_class(self, e: bytes) -> str:
        """The class of an event whose author has no standing: section 3.6's
        step 1, or for a successor ext-invite-links.md's steps 1 and 2."""
        if not self.is_successor(e):
            return "NotAnAdministrator"
        author = self.ev(e).author
        if self.root_successor(author) or any(
                self.is_successor(p) and self.ev(p).author == author for p in self.log.anc[e]):
            return "InviteUsed"
        return "NotAnInvite"

    def lower_each_other(self, x: bytes, e: bytes) -> bool:
        """Each attacks the other through (a) or (b), and their authors differ."""
        lower = ("RemovedConcurrently", "DemotedConcurrently")
        return (self.ev(x).author != self.ev(e).author and self.attacks(x, e) in lower
                and self.attacks(e, x) in lower)

    def mutual(self, x: bytes, e: bytes) -> bool:
        """A mutual pair: two events that lower each other with one change each."""
        return (self.lower_each_other(x, e) and len(self.changes(x)) == 1
                and len(self.changes(e)) == 1)

    def support(self, x: bytes) -> set:
        """The contested events in x's past that grant or change its author's
        member (a successor grants its claimant), with the support of each."""
        out, todo = set(), [x]
        while todo:
            s = todo.pop()
            m = self.author_member(s)
            for p in self.contested:
                if p not in out and p in self.log.anc[s] and any(
                        c.op in (GRANT, CHANGE, SUCCEED) and c.member == m
                        for c in self.changes(p)):
                    out.add(p)
                    todo.append(p)
        return out

    def _shields(self) -> set:
        """(e, g) for each attack of e on g that no duel lets count: g is in
        the support of an event x that lowers each other with e, and x's
        author did not sign g."""
        out = set()
        for x in self.contested:
            partners = [e for e in self.contested if self.lower_each_other(x, e)]
            if not partners:
                continue
            author = self.ev(x).author
            for g in self.support(x):
                if self.ev(g).author != author:
                    out |= {(e, g) for e in partners}
        return out

    def counts(self, x: bytes, e: bytes) -> bool:
        """Whether x's attack on e counts (section 3.5.2): not when they lower
        each other and e has one change; not through (a), (b) or (c) when e
        is in the support of an event that lowers each other with x, and
        that event's author did not sign e."""
        if self.lower_each_other(x, e) and len(self.changes(e)) == 1:
            return False
        return not (self.attacks(x, e) in ("RemovedConcurrently", "DemotedConcurrently",
                                           "TargetRemovedConcurrently")
                    and (x, e) in self._shielded)

    def outranks_at(self, x: bytes, e: bytes, status) -> bool | None:
        """Whether x's author outranks e's author, each at its own event's
        place: the higher rank, then the more senior (section 3.5.2). None
        while either place is undecided."""
        if not all(p in status for p in (self._cpast[x] | self._cpast[e])):
            return None
        a = self.state(self._valid_place(x, status)).get(self.author_member(x))
        b = self.state(self._valid_place(e, status)).get(self.author_member(e))
        if a is None or b is None:
            return None
        return ((-(a.rank or 0), a.seniority) < (-(b.rank or 0), b.seniority))

    def dropped(self, x: bytes, e: bytes, status):
        """decide()'s rule: x's attack on e does not count. In a mutual pair
        (section 3.5.2, duel_policy 0) only the outranking author's lowering
        counts: between equal ranks, the more senior's."""
        if self.mutual(x, e):
            win = self.outranks_at(x, e, status)
            return None if win is None else not win
        return not self.counts(x, e)

    def pick_key(self, e: bytes, status) -> tuple:
        """Step 4: the highest rank first, then the most senior."""
        S = self.state(self._valid_place(e, status))
        st = S[self.author_member(e)]
        return (-(st.rank or 0), st.seniority, self.log.height[e], e)

    def _resolve_roster(self) -> None:
        log = self.log
        roster_events = [i for i in log.canonical(self.view)
                         if self.is_roster(i) and i != log.genesis
                         and i not in self.status]
        successors = [i for i in roster_events if self.is_successor(i)]
        for i in roster_events:
            author = self.ev(i).author
            # A successor takes 's race rule
            # in place of its invite key's chain penalty.
            if author in self.forks and self.ev(i).seq >= self.forks[author] \
                    and not self.self_lowering(i) and i not in successors:
                self.status[i] = (False, "Forked", None)

        # Standing: an author no event in its event's past
        # names at administer (or, for a successor, no grant of its invite
        # key) is void before the procedure, and is not contested.
        unstanding = {}
        for i in roster_events:
            if i not in self.status and _STANDING and not self.standing(i):
                unstanding[i] = self._unstanding_class(i)
        contested = [i for i in roster_events if i not in self.status and i not in unstanding]
        cset = set(contested)
        self.contested = contested
        self._shielded = self._shields()
        cpast = {e: frozenset(p for p in log.anc[e] if p in cset) for e in contested}
        self._cpast = cpast
        racing = {i: [j for j in successors if j != i and self.ev(j).author == self.ev(i).author
                      and log.concurrent(i, j)] for i in successors if i in cset}
        racing = {i: js for i, js in racing.items() if js}
        # A racing successor is void unless each successor it
        # races is concurrent with a valid close. Closes never depend on the
        # successors, so forcing more successors void only grows the set,
        # and the loop ends.
        self._forced_race: set = set()
        while True:
            self._cache.clear()
            decided = decide(
                contested,
                lambda e: cpast[e],
                lambda e: [x for x in contested if self.attacks(x, e)],
                self.auth,
                self.dropped,
                self.pick_key,
            )
            closes = {k: [x for x in contested if decided[x][0] and any(
                c.op == REMOVE and c.member == (INVITE, k) for c in self.changes(x))]
                for k in {self.ev(i).author for i in racing}}
            more = {i for i, js in racing.items() if decided[i][0] and not all(
                any(log.concurrent(j, x) for x in closes[self.ev(i).author]) for j in js)}
            if not more - self._forced_race:
                break
            self._forced_race |= more
        for e, v in decided.items():
            if not v[0] and v[1] == "attacked":
                v = (False, self.attacks(v[2], e), v[2])
            self.status[e] = v
        for e, cls in unstanding.items():
            # Section 3.6, step 0, before step 1: Pending behind a roster
            # event that waits for its twin.
            if self.storage is not None and any(
                    self._held_for_twin(p, self.status) for p in log.anc[e] if p in self.status):
                cls = "Pending"
            self.status[e] = (False, cls, None)
        self.unstanding = frozenset(unstanding)
        self.status[log.genesis] = (True, "genesis", None)
        self.valid_roster = frozenset(i for i in self.status
                                      if self.status[i][0] and self.is_roster(i))
        self.roster = self.state(self.valid_roster)
        self.space_policy = self.policy(self.valid_roster)

    # -- paths and the write rule
    def placed_adds(self, person: bytes, e: bytes, op: str = "add") -> set | None:
        """roster.md, section 3.11, "A list at an event's place": the
        devices an add of which is at e's place: carried by a copy of the
        add itself, or of a list checkpoint whose record names it, that is
        e or in e's past, or, in a checkpoint's world, in the checkpoint's
        past (a replica that forgot keeps those copies whole). A copy of a
        later list event places nothing in its past, so no list history is
        read. None for a person with no copy recorded: read as held."""
        copies = LIST_COPIES.get(person)
        if not copies:
            return None
        k = ("placed", person, e, op)
        if k not in self._cache:
            past = self.log.anc[e] | {e}
            root = self.base["id"] if self.base is not None else None
            out = set()
            for log, copy, _, dev, what in copies:
                if dev is None or what != op:
                    continue
                if copy in past or (root is not None and log.events.get(root) is not None
                                    and (copy == root or copy in log.anc[root])):
                    out.add(dev)
            self._cache[k] = out
        return self._cache[k]

    def paths(self, device: bytes, S: dict, minimum: int = WRITE,
              at: bytes | None = None) -> tuple[list, bool]:
        """Every member through which `device` holds `minimum` in S, and
        whether a path could not be judged for lack of another log. With
        `at`, a person's list is read as it stands at that event's place."""
        out, unknown = [], False
        for m, st in sorted(S.items()):
            if not st.present or st.level < minimum:
                continue
            if m == (DEVICE, device):
                out.append(m)
            elif m[0] == PERSON:
                lst = self.lists.get(m[1])
                if lst is None:
                    unknown = True
                elif device in lst.writers():
                    placed = self.placed_adds(m[1], at) if at is not None else None
                    if placed is None or device in placed:
                        out.append(m)
            elif m[0] == SPACE:
                sp = self.spaces.get(m[1])
                if sp is None:
                    unknown = True
                elif device in sp.propagating_writers():
                    out.append(m)
        return out, unknown

    def effective(self, valid: frozenset, depth: int = 0, seen=(),
                  unwaiting: bool = False) -> dict:
        """roster.md, 3.3, over the roster of `valid`: every device that
        reaches this space, as (its highest level over every path, its
        highest over the paths that propagate, or None when none does). The
        two are kept apart: a space grant caps at write and passes on only
        the second, so a device's strongest path, a guest's say, never
        hides a weaker one that propagates. With `unwaiting`, over the
        paths that are not waiting (section 3.10, step 3) only."""
        out: dict = {}

        def offer(d, level, propagates):
            lv, prop = out.get(d, (level, None))
            if propagates:
                prop = level if prop is None else max(prop, level)
            out[d] = (max(lv, level), prop)

        for m, st in sorted(self.state(valid).items()):
            if not st.present:
                continue
            if m[0] == DEVICE:
                offer(m[1], st.level, st.session is None)
            elif m[0] == PERSON and m[1] in self.lists:
                lst = self.lists[m[1]]
                for d, mem in lst.active_members().items():
                    if mem.kind in (identity.DEVICE, identity.PASSKEY) \
                            and not (unwaiting and lst.waiting(d)):
                        offer(d, st.level, True)
            elif m[0] == SPACE and m[1] in self.spaces and m[1] not in seen \
                    and depth < spaces.MAX_GRANT_DEPTH - 1:
                inner = self.spaces[m[1]]
                kept = inner.unwaiting_writers() if unwaiting else None
                for d, (_, prop) in inner.effective(inner.valid_roster, depth + 1,
                                                    seen + (self.log.id,)).items():
                    if prop is not None and (kept is None or d in kept):
                        offer(d, min(st.level, prop, WRITE), True)
        return out

    def _propagating_at(self, valid: frozenset, unwaiting: bool = False) -> set:
        return {d for d, (_, prop) in self.effective(valid, unwaiting=unwaiting).items()
                if prop is not None and prop >= WRITE}

    def unwaiting_writers(self) -> set:
        """The propagating writers (below) that reach this space at write
        through some path that is not waiting (section 3.10, step 3): a
        device grant, a person whose list does not hold the device as
        rooted in an agent and unconfirmed, or a space among whose own such
        writers it is. Over the same places as propagating_writers."""
        if self._unwaiting is None:
            out = self._propagating_at(self.valid_roster, True)
            for x in self.valid_roster:
                out |= self._propagating_at(self.place(x, self.valid_roster) | {x}, True)
            self._unwaiting = out
        return self._unwaiting

    def propagating_writers(self) -> set:
        """The devices that reach this space at write and propagate
        (roster.md, 6.1), at its merged roster or at the place of any valid
        roster event: a device that reached it earlier keeps its path until a
        response to the end of it. A granting space whose grant
        carried this log's heads answers every end in their past with the
        grant itself, so a device gone before the grant writes nothing."""
        out = self._propagating_at(self.valid_roster)
        for x in self.valid_roster:
            out |= self._propagating_at(self.place(x, self.valid_roster) | {x})
        return out

    def ends(self, device: bytes) -> list[tuple]:
        """The events that end `device`'s path into a space that
        grants this one: a valid event of this log after which it no longer
        propagates here at write, and the ends of the paths it had through a
        person or a space this one grants."""
        out = []
        for x in self.log.canonical(self.valid_roster):
            before = self.place(x, self.valid_roster)
            if device in self._propagating_at(before) \
                    and device not in self._propagating_at(before | {x}):
                out.append((self.log.id, x))
        for m, st in sorted(self.roster.items()):
            if m[0] == PERSON and m[1] in self.lists:
                out += [(m[1], r) for r in self.lists[m[1]].ends(device)]
            elif m[0] == SPACE and m[1] in self.spaces:
                out += self.spaces[m[1]].ends(device)
        return out

    def lowered(self, x: bytes) -> set:
        return {c.member for c in self.changes(x) if c.member and (c.op == REMOVE or (
            c.op == CHANGE and c.level is not None and c.level < WRITE))}

    def responses(self, log_id: bytes, end: bytes, ended: bytes) -> list[bytes]:
        """Valid events of this space whose refs name `end`, or an
        event of its log that has `end` in its past, by a device other than
        the one the end concerns: a valid roster event (a grant that carries
        the heads its author held is one), or a key event already decided
        valid (: earlier in canonical order)."""
        out = []
        for i in self.log.canonical(self.view):
            e = self.ev(i)
            if e.author == ended or not any(self.covers(r, log_id, end) for r in self.refs(i)):
                continue
            if self.is_roster(i) and self.status.get(i, (False,))[0]:
                out.append(i)
            elif self.is_key(i) and i in self._valid_keys:
                out.append(i)
        return out

    def _forked(self, i: bytes) -> bool:
        a = self.ev(i).author
        return a in self.forks and self.ev(i).seq >= self.forks[a]

    def _judge_writes(self) -> None:
        """Key events once, in canonical order, each counting as
        responses only the roster events and the key events already decided
        valid before it (a least fixed point: nothing is revisited); then
        units, anchors and ignorable kinds, against every valid response."""
        self._valid_keys: set = set()
        order = self.log.canonical(self.view)
        # What follows a roster event that waits for its
        # twin is held with it, as if not received.
        twinless = {i for i, v in self.status.items() if not v[0] and v[1] == "NoTwin"}
        if twinless:
            for i in order:
                if i not in self.status and self.log.anc[i] & twinless:
                    self.status[i] = (False, "Pending", None)
        for i in order:
            if self.is_key(i) and i not in self.status:
                self.status[i] = self._write_or_drop(i)
                if self.status[i][0]:
                    self._valid_keys.add(i)
        for i in order:
            e = self.ev(i)
            if i in self.status or self.is_roster(i):
                continue
            if e.kind == KIND_ANCHOR:
                S = self.state(self.place(i, self.valid_roster))
                p, unknown = self.paths(e.author, S, READ)
                self.status[i] = ((True, "kept", None) if p else
                                  (False, "Pending" if unknown else "NotAMember", None))
            elif e.kind == KIND_UNIT:
                self.status[i] = self._write_or_drop(i)
            elif e.kind == KIND_STORAGE:
                # Peers.md judges storage events. A writer
                # request (types 16, 17) is judged by the write rule, as a
                # unit; a skeleton event is kept when the skeleton vouches
                # for its pseudonym (section 3.12.1), else dropped.
                if storage_record(e)["type"] in STORAGE_WRITER_TYPES:
                    self.status[i] = self._write_or_drop(i)
                elif self.pseudonym_keys(e.author):
                    self.status[i] = (True, "kept", None)
                else:
                    self.status[i] = (False, "Dropped", None)
            elif self.named(e.author):
                self.status[i] = (True, "kept", None)  # an ignorable kind
            else:
                self.status[i] = (False, "Dropped", None)
        # A unit, an anchor, a storage event or an ignorable kind whose
        # author no record names is dropped, not held, and fetched again when
        # a record arrives. A writer's event stays pending while a person's
        # list or a granted space's roster that could name it is missing.
        unknown = any(st.present and ((m[0] == PERSON and m[1] not in self.lists)
                                      or (m[0] == SPACE and m[1] not in self.spaces))
                      for m, st in self.roster.items())
        for i in order:
            e = self.ev(i)
            if self.status.get(i, (True, None))[1] != "NoHybridKey":
                continue
            skeleton = e.kind == KIND_STORAGE and \
                storage_record(e)["type"] in STORAGE_SKELETON_TYPES
            if skeleton or (not unknown and (e.kind in (KIND_UNIT, KIND_STORAGE, KIND_ANCHOR)
                                             or e.kind >= 64)):
                self.status[i] = (False, "Dropped", None)

    def _write_or_drop(self, i: bytes) -> tuple:
        """A write that no path admits, from an author no record
        names, is dropped, not kept, so that strangers cannot make replicas
        store their events."""
        verdict = self.write_rule(i)
        if verdict[1] == "NotAWriter" and not self.named(self.ev(i).author):
            return (False, "Dropped", None)
        return verdict

    def write_rule(self, u: bytes) -> tuple:
        """Its order."""
        if self._forked(u):
            return (False, "Forked", None)
        author = self.ev(u).author
        S = self.state(self.place(u, self.valid_roster))
        paths, unknown = self.paths(author, S, at=u)
        if not paths:
            return (False, "Pending" if unknown else "NotAWriter", None)
        found = tuple(paths)
        if self.is_key(u) and all(self._waiting(m, author) for m in paths):
            return (False, "WaitingDevice", None)
        lowering = [x for x in self.log.canonical(self.valid_roster)
                    if x != self.log.genesis and self.log.concurrent(x, u) and self.lowered(x)]
        remaining = [m for m in paths if not any(m in self.lowered(x) for x in lowering)]
        if not remaining:
            by = next(x for x in lowering if any(m in self.lowered(x) for m in paths))
            return (False, "Pending" if unknown else "RefusedByRemoval", by)
        ended_by, alive = None, []
        for m in remaining:
            if m[0] == PERSON:
                ends = [(m[1], x) for x in self.lists[m[1]].ends(author)]
            elif m[0] == SPACE:
                ends = self.spaces[m[1]].ends(author)
            else:
                ends = []
            hit = next((k for log_id, x in ends for k in self.responses(log_id, x, author)
                        if not self.log.le(u, k)), None)
            if hit:
                ended_by = ended_by or hit
            else:
                alive.append(m)
        if not alive:
            return (False, "Pending" if unknown else "RefusedAfterResponse", ended_by)
        if self.is_key(u):
            verdict = self._key_checks(u, S, alive)  # 6
            if verdict is not None:
                return (False, verdict, None)
        self.alive_paths[u] = (found, S)
        return (True, "rules", None)

    def attribution(self, u: bytes) -> list | None:
        """Section 3.11, attribution: for a unit valid by the write rule, the
        paths step 2 finds at its place, each person's list read there, each
        [type, ID] or [type, ID, label] with its label at the unit's place,
        by type then ID, at most 64; None for a unit the write rule voids,
        which is attributed to no member."""
        if self.ev(u).kind != KIND_UNIT or not self.status.get(u, (False,))[0] \
                or u not in self.alive_paths:
            return None
        alive, S = self.alive_paths[u]
        # A person whose revocation of the device is at the unit's place
        # held it no longer there; it is left out, unless that would leave
        # no path, the unit then standing on paths every one of which a
        # revocation has reached.
        author = self.ev(u).author
        kept = [m for m in alive if not (m[0] == PERSON and author in (
            self.placed_adds(m[1], u, "revoke") or ()))]
        out = []
        for m in sorted(kept or alive)[:64]:
            label = S[m].label
            out.append([m[0], m[1]] + ([label] if label is not None else []))
        return out

    def _waiting(self, m: tuple, device: bytes) -> bool:
        """Section 3.10, step 3: a path is waiting when it is a person grant
        whose list holds the device as rooted in an agent and not confirmed,
        or a space through which it reaches this one only by waiting
        paths."""
        if m[0] == PERSON:
            return self.lists[m[1]].waiting(device)
        if m[0] == SPACE:
            return device not in self.spaces[m[1]].unwaiting_writers()
        return False

    def _key_checks(self, u: bytes, S: dict, paths: list) -> str | None:
        """The write rule's step 6: keys.md's checks against a key event and
        its place, in their order. Its author propagates when a path left
        after step 5 is a person, a space, or its own device member without
        `session`; it responds when it carries sealed refs. The rotations
        counted are the genesis, the valid roster events and the key events
        decided valid before it. Step 8 reads the spaces granted at its
        place; a notice's own checks decide no verdict."""
        ctx = {"event": "key",
               "author_propagates": any(m[0] != DEVICE or S[m].session is None
                                        for m in paths),
               "refs": bool(self.refs(u)),
               "restricted": (self.space_descriptor or {}).get("kind")
               == spaces.KIND_RESTRICTED,
               "sealed_under_stale": self._stale(u, self.valid_roster | self._valid_keys)}
        try:
            self._check_with_notices(u, S, ctx, self.valid_roster | self._valid_keys)
        except SpecError as error:
            return error.error
        return None

    # -- results
    def valid(self) -> frozenset:
        return frozenset(i for i, v in self.status.items() if v[0])

    def rotations(self) -> list[bytes]:
        """The maximal valid rotations (keys.md, 4.1): the
        genesis, and roster events and key events whose payload rotates."""
        rot = [i for i in self.valid() if i in self.decoded and self.decoded[i].rotates]
        return sorted((r for r in rot if not any(r in self.log.anc[o] for o in rot)),
                      key=self.log.order_key)

    def administrators(self) -> list[bytes]:
        return sorted(m[1] for m, s in self.roster.items()
                      if s.present and m[0] == DEVICE and s.level == ADMINISTER
                      and m[1] not in self.forks)

    def device_of(self, i: bytes) -> bytes | None:
        """The device an event counts for: its author, or for a
        skeleton event the device its pseudonym's binding names."""
        e = self.ev(i)
        if e.kind == KIND_STORAGE and storage_record(e)["type"] in STORAGE_SKELETON_TYPES:
            return self.storage.device_of(e.author) if self.storage is not None else None
        return e.author

    def stable(self, target) -> bool:
        """Every current administrator has a valid event whose
        past holds every event of `target`."""
        targets = [target] if isinstance(target, bytes) else list(target)
        mine = [i for i in self.valid() if self.ev(i).kind < 64]
        return all(any(self.device_of(i) == a and all(self.log.le(t, i) for t in targets)
                       for i in mine) for a in self.administrators())

    def may_drop(self, u: bytes, first_seen: int, now: int) -> bool:
        """A refused unit's content may be dropped once the event
        that refused it is stable, or once this replica has held the refusal
        for the space's gap_key_timeout."""
        v = self.status[u]
        if v[0] or v[2] is None:
            return False
        return self.stable(v[2]) or now - first_seen >= self.space_policy["gap_key_timeout"]

    def voiders(self, e: bytes, seen=None) -> list[bytes]:
        """The events that void e."""
        seen = set() if seen is None else seen
        if e in seen or self.status.get(e, (True,))[0]:
            return []
        seen.add(e)
        valid, how, by = self.status[e]
        if how == "Forked":
            author = self.ev(e).author
            ev = self.log.chain_evidence(self.view, self.accepted)
            return sorted({i for x in ev if x["author"] == author
                           for i in (x["first"], x["second"])}, key=self.log.order_key)
        if how == "ClaimRaced":
            author = self.ev(e).author
            return sorted((j for j in self.view if j != e and j in self.decoded
                           and self.is_successor(j) and self.ev(j).author == author
                           and self.log.concurrent(e, j)), key=self.log.order_key)
        if by is not None and self.is_roster(e):
            return sorted({x for x in self.contested if self.status[x][0]
                           and self.attacks(x, e) and self.dropped(x, e, self.status) is False},
                          key=self.log.order_key)
        if by is not None:
            return [by]
        if how in ("NotAnAdministrator", "AlreadyMember", "NoSuchMember", "NotAMember",
                   "NotAWriter"):
            author = self.ev(e).author
            who = {(DEVICE, author)} | {c.member for c in self.decoded.get(
                e, Decoded(False, (), None)).changes if c.member}
            # A unit or key event: also a person whose list holds its author,
            # whose grant it could have written through.
            if not self.is_roster(e):
                who |= {(PERSON, p) for p, lst in self.lists.items()
                        if author in lst.writers()
                        and (self.placed_adds(p, e) is None
                             or author in self.placed_adds(p, e))}
            out = set()
            for p in self.log.anc[e]:
                if self.is_roster(p) and not self.status[p][0] \
                        and p in self.decoded and any(c.member in who
                                                      for c in self.changes(p)):
                    out |= set(self.voiders(p, seen))
            return sorted(out, key=self.log.order_key)
        return []

    def frontier(self, x: bytes) -> dict:
        """For each device that held write through a member x
        lowers, its latest accepted event in x's past."""
        devices = set()
        for m in self.lowered(x):
            if m[0] == DEVICE:
                devices.add(m[1])
            elif m[0] == PERSON and m[1] in self.lists:
                devices |= set(self.lists[m[1]].writers())
            elif m[0] == SPACE and m[1] in self.spaces:
                devices |= self.spaces[m[1]].propagating_writers()
        return self.heads_of(devices, self.log.anc[x])

    def heads_of(self, devices, past) -> dict:
        out = {}
        for d in devices:
            mine = [i for i in past if self.ev(i).author == d and self.accepted(i)]
            if mine:
                out[d] = max(mine, key=lambda i: (self.ev(i).seq, i))
        return out

    def duels(self) -> list[tuple]:
        """Section 3.14, duels: each mutual pair one side of which stands,
        the outranking author's, so that a client shows what it voided."""
        c = self.contested
        return [(a, b) for n, a in enumerate(c) for b in c[n + 1:] if self.mutual(a, b)
                and (self.status[a][0] or self.status[b][0])]

    def voided_by(self, x: bytes) -> list[bytes]:
        """What x voids, against the view without x and what
        follows it."""
        without = {i for i in self.view if not self.log.le(x, i)}
        other = Space(self.log, without, self.lists, self.spaces, self.keys, self.storage)
        return [i for i in self.log.canonical(without)
                if other.status.get(i, (False,))[0] and not self.status[i][0]]

    def _through_voided_grant(self, u: bytes) -> bool:
        """roster.md, section 3.14, re-submission: a unit refused as
        NotAWriter is re-submitted exactly when events void it, so that a
        grant it could have written through, of its device or of a person
        whose list holds it, was voided in its past; a replica that forgot
        reads those events from the unit's frozen key 8."""
        return bool(self.voiders(u))

    def resubmissions(self) -> dict:
        """Each device's refused units, once it writes again:
        those refused by a removal or a response, and those refused as
        NotAWriter because the grant they wrote through was voided."""
        out = {}
        for i in self.log.canonical(self.view):
            v = self.status.get(i)
            if self.ev(i).kind != KIND_UNIT or v[0]:
                continue
            if v[1] not in ("RefusedByRemoval", "RefusedAfterResponse") and not (
                    v[1] == "NotAWriter" and self._through_voided_grant(i)):
                continue
            author = self.ev(i).author
            if self.paths(author, self.roster)[0] and author not in self.forks:
                out.setdefault(author, []).append(i)
        return out


# ---------------------------------------------------------------------------
# Example histories.

def rotation_payload(secret: bytes, label: str) -> dict:
    """A rotation's visible fields in the shape of keys.md:
    a grant commitment and the public halves of its read credential (from the
    rotation's content key) and upload key. keys.md's own vectors test
    whole payloads with deliveries; these carry none."""
    return {"rotates": True, "grant_commitment": example(f"{label}/grant-commitment"),
            "read": kg.read_credential(secret)["public"],
            "upload": ed25519_public(example(f"{label}/upload"))}


class Roster:
    """A space's history being built in the vectors."""

    def __init__(self, founder: str = "P", prefix: str = "roster", *, policy=None,
                 descriptor=None, duel: int = DUEL_BOTH_STAND, keys=None,
                 grant_keys: bool = False, keyless=()):
        self.hist = History(prefix)
        self.hist.keyless |= set(keyless)
        if keys:
            self.hist.keys.update(keys)
        self.prefix = prefix
        self.persons: dict[bytes, str] = {}
        self.spaces: dict[bytes, str] = {}
        self.krot: dict[bytes, bytes] = {}  # each rotation's content key, by its event ID
        # With grant_keys, each rotation commits to a real grant key, derived
        # from '<prefix>/<label>/grant-seed', so that a notice can name it
        # (keys.md, "Notices and space principals"); each one's public key,
        # by its event ID.
        self.grant_keys = grant_keys
        self.grant_public: dict[bytes, bytes] = {}
        self._public: bytes | None = None
        restricted = descriptor is not None and \
            spaces.read_descriptor(descriptor)["kind"] == spaces.KIND_RESTRICTED
        self.restricted = restricted
        founder_change = self.device_grant(founder, ADMINISTER, WITH_HISTORY, VIA_NONE)
        roster = genesis_roster(founder_change, policy=policy, descriptor=descriptor, duel=duel,
                                system_stream=example(f"{prefix}/system-stream")[:16])
        global _BUILD_FLAGS
        _BUILD_FLAGS = {"grant_rotation": not restricted}
        try:
            body, secret = self._space(founder, "genesis", roster, True,
                                       example(f"{prefix}/nonce")[:NONCE_BYTES])
        finally:
            _BUILD_FLAGS = None
        self.genesis = self.hist.genesis(founder, KIND_SPACE, body,
                                         f"{founder} creates the space")
        self.krot[self.genesis] = secret
        if self._public is not None:
            self.grant_public[self.genesis] = self._public

    def current_state(self, by: str) -> list[bytes]:
        """The rotations `by` holds at the top of its view: the state a space
        event that does not rotate is sealed under (keys.md)."""
        view = self.hist.view[by]
        if self.hist.fence is not None:
            # A device that follows a checkpoint seals under the state of
            # the events it may cite (roster.md, "Clients").
            view = view - self.hist.fence(by, view)
        rots = [i for i in view if i in self.krot]
        return sorted(i for i in rots if not any(i in self.log.anc[j] for j in rots if j != i))

    def _space(self, by: str, label: str, roster: bytes | None, rotates: bool,
               genesis_nonce: bytes | None = None, refs=(), notices=()):
        """A space event's body, sealed under its body key, its
        refs and notices inside."""
        lbl = f"{self.prefix}/{label}"
        seal_nonce = example(f"{lbl}/seal-nonce")[:kg.NONCE_BYTES]
        self._public = None
        if rotates:
            secret = example(f"{lbl}/content-key")
            payload = rotation_payload(secret, lbl)
            if self.grant_keys:
                self._public = kg.grant_key_pair(example(f"{lbl}/grant-seed"))["public"]
                payload["grant_commitment"] = kg.grant_commitment(
                    self._public, bool((_BUILD_FLAGS or {}).get("break")))
        else:
            state = self.current_state(by)
            secret = kg.content_key(self.log.id, state, self.krot.__getitem__)
            payload = {"sealed_under": kg.encode_set(state)}
        if notices:
            payload["notices"] = list(notices)
        return space_body(payload, secret, seal_nonce, roster, genesis_nonce, refs), secret

    def space_event(self, by: str, label: str, roster: bytes | None, rotates: bool,
                    refs=(), flags=None, twin=None, notices=(), **kw) -> bytes:
        """`twin` is the skeleton twin's event ID, visible key 15 (section
        8.4), for an event that changes who administers. `notices` are
        keys.md's notices, each {space, rotation, public, from_now_on}."""
        global _BUILD_FLAGS
        _BUILD_FLAGS = {**(flags or {}), **({"twin": twin} if twin is not None else {})}
        try:
            extra = {"notices": notices} if notices else {}
            body, secret = self._space(by, label, roster, rotates, refs=refs, **extra)
        finally:
            _BUILD_FLAGS = None
        i = self.hist.act(by, KIND_SPACE, body, label, **kw)
        if rotates:
            self.krot[i] = secret
            if self._public is not None:
                self.grant_public[i] = self._public
        return i

    def notice(self, rotation: bytes, from_now_on: bool = False) -> dict:
        """keys.md's notice of one of this space's rotations, for a space
        that grants this one."""
        return {"space": self.id, "rotation": rotation, "public": self.grant_public[rotation],
                "from_now_on": from_now_on}

    @property
    def log(self) -> Log:
        return self.hist.log

    @property
    def id(self) -> bytes:
        return self.log.id

    def all(self) -> set:
        return self.hist.all()

    def member(self, name: str) -> tuple:
        for pid, n in self.persons.items():
            if n == name:
                return (PERSON, pid)
        for sid, n in self.spaces.items():
            if n == name:
                return (SPACE, sid)
        return (DEVICE, self.hist.device(name))

    def device_grant(self, name: str, level: int, history: int = WITH_HISTORY,
                     via: int = VIA_CODE, **kw) -> Change:
        return Change(GRANT, (DEVICE, self.hist.device(name)), level, kw.get("caps"),
                      kw.get("label"), history, via, kw.get("session"), None,
                      self.hist.xwing(name), self.hist.mldsa(name), None,
                      self.hist.ed(name), rank=kw.get("rank"))

    def act(self, by: str, changes: list[Change], label: str, *, rotation=True, refs=(),
            twin=None, **kw) -> bytes:
        """A roster event. `refs` are the heads of the other logs its changes
        name, as its author holds them."""
        me = (DEVICE, self.hist.device(by))
        removes_self = any(c.op == REMOVE and c.member == me for c in changes)
        return self.space_event(by, label, update_roster(changes),
                                rotation and not removes_self, refs=refs,
                                flags=self.flags(changes, me, kw.get("view", self.hist.view[by])),
                                twin=twin, **kw)

    def flags(self, changes, me, view=None) -> dict:
        """keys.md: a break for an admission "from now on",
        and a grant rotation for one that propagates or for a removal of a
        member that propagates at the author's view, which the builder
        resolves. A removal of a member already out, such as an invite's
        close (roster.md), removes no one."""
        coded = [c.encode() for c in changes]
        admits = [c for c in coded if c.get(C_OP) == GRANT and c.get(C_HISTORY) == FROM_NOW_ON]
        removed = [tuple(c[C_MEMBER]) for c in coded
                   if c.get(C_OP) == REMOVE and tuple(c[C_MEMBER]) != me]
        removes = False
        if removed:
            roster = self.resolve(set(view if view is not None else self.log.events)).roster
            removes = any(m in roster and roster[m].present and roster[m].session is None
                          for m in removed)
        grant = not self.restricted and (removes or any(c.get(C_SESSION) is None
                                                        for c in admits))
        return {"grant_rotation": grant, "break": bool(admits)}

    def grant(self, by: str, who: str, level: int, history: int = WITH_HISTORY, *,
              label: str | None = None, via: int = VIA_CODE, caps=None, session=None,
              tag=None, rank=None, **kw) -> bytes:
        m = self.member(who)
        if m[0] == DEVICE:
            c = self.device_grant(who, level, history, via, caps=caps, label=tag,
                                  session=session, rank=rank)
        else:
            c = Change(GRANT, m, level, caps, tag, history, via)
        what = {FROM_NOW_ON: " from now on", WITH_HISTORY: ""}[history]
        return self.act(by, [c], label or f"{by} grants {who} {LEVEL_NAMES[level]}{what}", **kw)

    def remove(self, by: str, who: str, label: str | None = None, **kw) -> bytes:
        return self.act(by, [Change(REMOVE, self.member(who))], label or f"{by} removes {who}",
                        **kw)

    def change(self, by: str, who: str, level: int | None = None, label: str | None = None,
               caps=None, tag=None, rank=None, **kw) -> bytes:
        c = Change(CHANGE, self.member(who), level, caps, tag, rank=rank)
        what = f"changes {who} to {LEVEL_NAMES[level]}" if level is not None else f"changes {who}"
        return self.act(by, [c], label or f"{by} {what}", **kw)

    def set_policy(self, by: str, values: dict, label: str, **kw) -> bytes:
        return self.act(by, [Change(POLICY, policy=spaces.encode_policy(values))], label,
                        rotation=False, **kw)

    def heal(self, by: str, label: str | None = None, refs=(), **kw) -> bytes:
        """A key event that rotates. One that responds, carrying refs, is a
        grant rotation (keys.md, "Checks against the event and its place",
        step 6): the device whose path ended may hold the grant seed."""
        if refs and "flags" not in kw:
            kw["flags"] = {"grant_rotation": not self.restricted}
        return self.space_event(by, label or f"{by} heals", None, True, refs=refs, **kw)

    @staticmethod
    def heads_ref(log_id: bytes, log: Log, view=None) -> list:
        """Refs naming the heads of another log a granter holds."""
        return [(log_id, x) for x in log.heads(view)]

    def deliver(self, by: str, label: str, **kw) -> bytes:
        return self.space_event(by, label, None, False, **kw)

    def unit(self, by: str, label: str | None = None, body: bytes | None = None, refs=(),
             **kw) -> bytes:
        label = label or f"{by} writes a unit"
        if refs:
            body = UNIT_REFS_PREFIX + encode_refs(refs)
        elif body is None and getattr(self, "unit_seals", False):
            # Sealed under the state of what it may cite (roster.md,
            # "Clients"): its key reference names that state.
            body = unit_sealed_body(self.current_state(by), label)
        return self.hist.act(by, KIND_UNIT, body or f"unit: {label}".encode(), label, **kw)

    def copy_list(self, by: str, person, carried, label: str | None = None, **kw) -> bytes:
        """identity.md, "Sealed list copies": a `frasil:list` unit by `by`
        that carries list events of `person` (an identity.Person), each
        (list event ID, the name of the device it adds or revokes, or None,
        and "add", "revoke" or None)."""
        u = self.unit(by, label or f"{by} copies {person.hist.name(carried[0][0])}", **kw)
        record_copy(self.log, u, person.id,
                    [(lid, None if dev is None else person.hist.device(dev), op)
                     for lid, dev, op in carried])
        return u

    def anchor(self, by: str, label: str | None = None, **kw) -> bytes:
        return self.hist.act(by, KIND_ANCHOR, b"", label or f"{by} anchors", **kw)

    def sync(self, *names: str) -> None:
        self.hist.sync(*names)

    def everyone(self) -> list[str]:
        return list(self.hist.view)

    def keyring(self) -> Keyring:
        """Every rotation's content key: a replica that holds them all."""
        return Keyring(dict(self.krot))

    def resolve(self, view=None, lists=None, spaces_=None, keys=None, storage=None) -> Space:
        return Space(self.log, view, lists, spaces_, keys or self.keyring(), storage)

    def name(self, i: bytes) -> str:
        return self.hist.name(i)

    def member_name(self, m: tuple) -> str:
        if m[0] == PERSON:
            return self.persons.get(m[1], m[1].hex()[:12])
        if m[0] == SPACE:
            return self.spaces.get(m[1], m[1].hex()[:12])
        return self.hist.key_name(m[1])

    def summary(self, sp: Space, extra: bool = True) -> dict:
        def show(i):
            v = sp.status[i]
            if v[0]:
                return "valid" + (f" ({v[1]})" if v[1] in ("agreed", "seniority", "kept") else "")
            return v[1] + (f" by {self.name(v[2])}" if v[2] else "")

        roster = {}
        for m, s in sorted(sp.roster.items(), key=lambda kv: self.member_name(kv[0])):
            if not s.present:
                roster[self.member_name(m)] = "removed"
                continue
            entry = {"type": TYPE_NAMES[m[0]], "level": LEVEL_NAMES[s.level],
                     "history": "with history" if s.history else "from now on",
                     "seniority": h(s.seniority[2])}
            if s.rank is not None:
                entry["rank"] = s.rank
            if s.caps:
                entry["capabilities"] = sorted([n, "narrows" if md else "extends"]
                                               for n, md in s.caps)
            if s.label:
                entry["label"] = s.label
            if s.session:
                entry["session"] = s.session.hex()
            if s.replaces:
                entry["replaces"] = self.persons.get(s.replaces, s.replaces.hex())
            roster[self.member_name(m)] = entry
        out = {
            "events": {self.name(i): show(i) for i in self.log.canonical(sp.view)
                       if i != self.genesis},
            "roster": roster,
            "rotations_maximal": [self.name(i) for i in sp.rotations()],
        }
        voids = {self.name(i): [self.name(x) for x in sp.voiders(i)]
                 for i in self.log.canonical(sp.view) if not sp.status[i][0] and sp.voiders(i)}
        if voids:
            out["voided_by"] = voids
        if extra:
            if sp.forks:
                out["forked"] = {self.hist.key_name(k): s for k, s in sp.forks.items()}
            fr = {}
            for x in self.log.canonical(sp.valid_roster):
                if x != self.genesis and sp.lowered(x):
                    f = sp.frontier(x)
                    fr[self.name(x)] = {"heads": {self.hist.key_name(d): self.name(i)
                                                  for d, i in sorted(f.items())}}
            if fr:
                out["frontiers"] = fr
            duels = sp.duels()
            if duels:
                out["duels"] = [{"pair": [self.name(a), self.name(b)],
                                 "voided_by": {self.name(s): [self.name(i)
                                                              for i in sp.voided_by(s)]
                                               for s in (a, b)}} for a, b in duels]
            res = sp.resubmissions()
            if res:
                out["resubmit"] = {self.hist.key_name(d): [self.name(i) for i in ids]
                                   for d, ids in res.items()}
        return out


def setup(members, prefix: str) -> Roster:
    """The founder, then each member granted by the founder with history."""
    r = Roster(members[0][0], prefix)
    names = [members[0][0]]
    for name, level in members[1:]:
        r.hist.view[members[0][0]] = set(r.log.events)
        r.grant(members[0][0], name, level)
        names.append(name)
    for n in names:
        r.hist.device(n)
    r.sync(*names)
    return r


def partial_replica(r: "Roster", frame: set) -> dict:
    """units.md, "Partial replicas": a replica that holds a space's frame,
    here its space events, and witnesses each parent of a frame event
    outside it, fetching no other unit.

    "Heights": it knows a height when it holds the event's whole past; a
    height resting on a witness whose parents it does not all hold is a
    lower bound, one more than the greatest among the parents it holds, or
    1. It resolves the roster only when every two contested roster events
    are proven ordered or of known heights both; until then every event of
    its view but the genesis is pending, and it fetches, by ID, the parents
    it does not hold beneath them, until it knows the heights."""
    log = r.log
    full = r.resolve(r.all())
    # A roster event without standing whose author an event names at
    # administer counts here too: its standing rests on an order.
    contested = list(full.contested) + [e for e in r.log.canonical(full.unstanding)
                                        if full.standing_candidates(e)]

    def measure(held):
        height, known, past = {}, {}, {}
        for i in sorted(held, key=log.order_key):
            ps = [p for p in log.events[i].parents if p in held]
            height[i] = 0 if i == log.genesis else 1 + max((height[p] for p in ps), default=0)
            known[i] = i == log.genesis or (len(ps) == len(log.events[i].parents)
                                          and all(known[p] for p in ps))
            past[i] = frozenset().union(*(past[p] | {p} for p in ps))
        return height, known, past

    def unordered(known, past):
        out = set()
        for a, b in itertools.combinations(contested, 2):
            if a not in past[b] and b not in past[a] and not (known[a] and known[b]):
                out |= {a, b}
        return out

    def wanted(held, known, starts):
        out, seen, stack = set(), set(), list(starts)
        while stack:
            i = stack.pop()
            if i in seen or known[i]:
                continue
            seen.add(i)
            for p in log.events[i].parents:
                (stack.append(p) if p in held else out.add(p))
        return out

    witnessed = {p for i in frame for p in log.events[i].parents if p not in frame}
    held = set(frame) | witnessed
    height, known, past = measure(held)
    first = unordered(known, past)
    assert first, "the case needs a pair the replica cannot order"
    first_height, first_known = dict(height), dict(known)
    names = lambda ids: [r.name(i) for i in log.canonical(ids)]
    # A replica that took the lower bounds as heights.
    bounded = copy.copy(log)
    bounded.height = {**log.height, **height}
    lower = r.summary(Space(bounded, r.all(), None, None, r.keyring(), None), extra=False)
    fetches = []
    pending = first
    while pending:
        round_ = wanted(held, known, pending)
        assert round_, "a peer serves each parent by ID"
        fetches.append(names(round_))
        held |= round_
        height, known, past = measure(held)
        pending = unordered(known, past)
    shown = r.summary(full, extra=False)["events"]
    after = {r.name(i): shown[r.name(i)] for i in log.canonical(frame) if i != log.genesis}
    return {
        "holds": names(frame),
        "witnessed": names(witnessed),
        "heights": {r.name(i): {"height": log.height[i], "lower_bound": first_height[i],
                                "known": first_known[i]}
                    for i in log.canonical(set(frame) | witnessed)},
        "unordered": names(first),
        "with_lower_bounds": {k: v for k, v in lower["events"].items() if k in after},
        "events": {k: "Pending" for k in after},
        "fetches": fetches,
        "after_fetching": after,
    }


_FAILS = None  # a list while collecting failures instead of raising


def _fail(s):
    if _FAILS is not None:
        _FAILS.append(s)
        return
    raise AssertionError(json.dumps(s, indent=1)[:3000])


def _invite_grant(r: "Roster", name: str, history: int = FROM_NOW_ON, level: int = WRITE,
                  claims: int = PERSON) -> Change:
    """admission.md: the grant of an invite key, here a
    participant's own key so that the vectors can sign as it."""
    inv = r.hist.signer(name)
    return Change(GRANT, (INVITE, inv.device_id), level, None, "invited", history, VIA_LINK,
                  None, None, inv.xwing_public, inv.mldsa_public, None, inv.ed_public,
                  1_760_604_800, claims)


# Section 3.7's standing screen; the self-test turns it off to show what it
# changes.
_STANDING = True

# A reader's roster events after a contest: enough of them to bring the
# undecided events past the agreement step's limit, were they contested.
JUNK_AFTER_CONTEST = events.AGREED_LIMIT - 4


def _contest_with_junk(prefix: str) -> tuple:
    """A cycle through authority that the agreement step settles (as
    procedure_tables' "an event the agreement step voids stays void after the
    pick"), then a reader's chain of roster events after all of it. Returns
    the history, the contest's events by role, the reader's events, and the
    views: the contest alone, with as many reader's events as bring the
    undecided events to the limit, and with one more.

    e1, P raises B and E to administer. e0, concurrent with it, C removes B
    and changes D. e2, B after e1 and concurrent with e0, removes D. e3, E
    after all three, changes D. Seniority: P, C, B, E."""
    r = setup([("P", ADMINISTER), ("C", ADMINISTER), ("B", WRITE), ("E", WRITE),
               ("D", WRITE), ("M", READ)], prefix)
    e1 = r.act("P", [Change(CHANGE, r.member("B"), ADMINISTER),
                     Change(CHANGE, r.member("E"), ADMINISTER)], "P raises B and E (e1)")
    e0 = r.act("C", [Change(REMOVE, r.member("B")),
                     Change(CHANGE, r.member("D"), label="C's label")],
               "C removes B and relabels D (e0)")
    r.sync("P", "B")
    e2 = r.remove("B", "D", "B removes D (e2)")
    r.sync("P", "C", "B", "E")
    e3 = r.change("E", "D", tag="E's label", label="E relabels D (e3)")
    r.sync(*r.everyone())
    contest = set(r.all())
    junk = [r.act("M", [Change(CHANGE, r.member("D"), label=f"junk {n}")],
                  f"M, a reader, relabels D ({n})")
            for n in range(JUNK_AFTER_CONTEST + 1)]
    r.sync(*r.everyone())
    views = {"the contest alone": contest,
             f"with {JUNK_AFTER_CONTEST} of the reader's events":
                 contest | set(junk[:JUNK_AFTER_CONTEST]),
             "all": r.all()}
    return r, {"e0": e0, "e1": e1, "e2": e2, "e3": e3}, junk, views


def _invite_base(prefix: str, claims: int = PERSON, level: int = WRITE) -> tuple:
    r = setup([("P", ADMINISTER)], prefix)
    r.act("P", [_invite_grant(r, "I", claims=claims, level=level)], "P invites by link")
    r.sync("P", "I")
    return r, r.hist.signer("I")


def _claim(r: "Roster", by: str, claimant, label: str, **kw) -> bytes:
    """A successor: a person's ID given as an example label, or
    a device by name."""
    if isinstance(claimant, str) and claimant in r.hist.keys:
        d = r.hist.signer(claimant)
        c = Change(SUCCEED, (DEVICE, d.device_id), hybrid=d.xwing_public, mldsa=d.mldsa_public,
                   ed25519=d.ed_public)
    else:
        c = Change(SUCCEED, (PERSON, example(claimant)))
    return r.space_event(by, label, update_roster([c]), False, **kw)


def space_event_vectors() -> dict:
    """A space event's body shapes and body keys (keys.json's
    space_event_bodies), and events a replica cannot open (roster.json's
    unopened_events)."""
    # Space events: one shape for every change, and the late
    # joiner's body keys.
    r = Roster("P", "roster/late")
    r.hist.view["P"] = set(r.log.events)
    g_q = r.grant("P", "Q", ADMINISTER)
    d_p = r.deliver("P", "P delivers without rotating")
    pol = r.set_policy("P", {"forbid_agents": True}, "P forbids recovery agents")
    r.sync("P", "Q")
    d_q = r.deliver("Q", "Q delivers, concurrent with N's grant")
    g_n = r.grant("P", "N", WRITE, FROM_NOW_ON, label="P grants N write from now on")
    r.hist.device("N")
    r.sync("P", "Q", "N")
    heal = r.heal("P", "P heals after the merge")
    rem = r.remove("P", "Q", "P removes Q")
    r.sync("P", "Q", "N")
    unit = r.unit("N", "N writes after the merge")
    full = r.resolve()
    shapes = {}
    for i, what in ((g_q, "a grant"), (rem, "a removal"), (heal, "a rotation, no roster change"),
                    (pol, "a policy change that does not rotate"),
                    (d_p, "a delivery that does not rotate")):
        e = r.log.events[i]
        visible = kg.decode_cbor(e.body)
        d = full.decoded[i]
        shapes[what] = {"event": r.name(i), "visible_keys": sorted(visible),
                        "body_bytes": len(e.body), "sealed_bytes": len(visible[kg.P_SEALED]),
                        "body_key": h(d.body_key),
                        "commitment": h(visible[kg.P_COMMITMENT])}
    assert shapes["a grant"]["visible_keys"] == shapes["a removal"]["visible_keys"] \
        == shapes["a rotation, no roster change"]["visible_keys"]
    assert shapes["a policy change that does not rotate"]["visible_keys"] \
        == shapes["a delivery that does not rotate"]["visible_keys"]
    e = r.log.events[d_p]
    vis = read_visible(e)
    state = kg.decode_set(vis["sealed_under"])
    secret = kg.content_key(r.id, state, r.krot.__getitem__)
    derivation = {"event": r.name(d_p), "log": h(r.id), "author": h(e.author), "seq": e.seq,
                  "sealed_under": [r.name(x) for x in state], "state_content_key": h(secret),
                  "info": h(kg.seal_aad(r.id, e.author, e.seq)),
                  "body_key": h(body_key(e, vis, secret)),
                  "commitment": h(kg.body_commitment(body_key(e, vis, secret)))}
    assert derivation["body_key"] == h(full.decoded[d_p].body_key)
    g = r.log.events[r.genesis]
    gvis = read_visible(g)
    genesis_derivation = {"nonce": h(gvis["nonce"]), "author": h(g.author), "seq": g.seq,
                          "info": h(kg.seal_aad(gvis["nonce"], g.author, g.seq)),
                          "content_key": h(r.krot[r.genesis]),
                          "body_key": h(body_key(g, gvis, r.krot[r.genesis]))}
    held = {i: k for i, k in r.krot.items() if i == g_n or g_n in r.log.anc[i]}
    late = {}
    try:
        Space(r.log, keys=Keyring(dict(held)))
        late["without body keys"] = "accepted"
    except SpecError as error:
        late["without body keys"] = error.error
    assert late["without body keys"] == "Sealed"
    # The giver's snapshot taken at N's grant, before Q's concurrent delivery reached P.
    at_grant = Space(r.log, r.log.anc[g_n] | {g_n}, keys=r.keyring()).snapshot_keys(held)
    sp = Space(r.log, keys=Keyring(dict(held), dict(at_grant)))
    late["with body keys for the grant's past"] = r.summary(sp, extra=False)
    assert sp.status[d_q][1] == "Sealed" and sp.status[unit][1] == "Pending"
    # It judges as a replica that never received what it cannot open.
    held_ids = {i for i, v in sp.status.items() if v[1] in ("Sealed", "Pending")}
    smaller = Space(r.log, set(r.log.events) - held_ids, keys=r.keyring())
    assert all(sp.status[i] == smaller.status[i] for i in smaller.view)
    assert sp.roster == smaller.roster
    snap = full.snapshot_keys(held)
    sp = Space(r.log, keys=Keyring(dict(held), dict(snap)))
    late["with body keys for everything it cannot open"] = r.summary(sp, extra=False)
    assert late["with body keys for everything it cannot open"] == r.summary(full, extra=False)
    wrong = dict(snap)
    wrong[pol] = example("roster/late/wrong")
    sp = Space(r.log, keys=Keyring(dict(held), wrong))
    late["with a wrong body key for the policy change"] = r.summary(sp, extra=False)
    assert sp.status[pol][1] == "Sealed"
    se = {
        "history": r.hist.describe(),
        "shapes": shapes,
        "body_key": derivation,
        "genesis_body_key": genesis_derivation,
        "late_joiner": {"grant": r.name(g_n), "holds": [r.name(i) for i in sorted(held)],
                        "rotation_keys": {r.name(i): h(held[i]) for i in sorted(held)},
                        "snapshot_at_grant": [r.name(i) for i in at_grant],
                        "snapshot": {r.name(i): h(k) for i, k in snap.items()},
                        "wrong_body_key": h(wrong[pol]),
                        "views": late},
    }

    # An author that seals under a key other than the state's:
    # members refuse it; a newcomer handed the author's key opens it, and its
    # verdict is provisional; handed two keys for it, it holds it.
    r = Roster("P", "roster/split")
    r.hist.view["P"] = set(r.log.events)
    r.grant("P", "Q", ADMINISTER)
    r.sync("P", "Q")
    wrong = example("roster/split/not-the-state-key")
    state = r.current_state("Q")
    bad = r.hist.act("Q", KIND_SPACE, space_body(
        {"sealed_under": kg.encode_set(state)}, wrong,
        example("roster/split/seal-nonce")[:kg.NONCE_BYTES], update_roster([Change(
            POLICY, policy=spaces.encode_policy({"forbid_agents": True}))])),
        "Q seals a policy change under a key of its own")
    r.hist.uncitable.add(bad)
    g_n = r.grant("P", "N", WRITE, FROM_NOW_ON, label="P grants N write from now on")
    r.hist.device("N")
    r.sync("P", "Q", "N")
    member = r.resolve()
    e = r.log.events[bad]
    actual = kg.seal_key(wrong, r.id, e.author, e.seq)
    derived = body_key(e, read_visible(e), kg.content_key(r.id, state, r.krot.__getitem__))
    n_holds = {i: k for i, k in r.krot.items() if i == g_n or g_n in r.log.anc[i]}
    snap = member.snapshot_keys(n_holds)
    split = {"member": r.summary(member, extra=False)}
    lied = Space(r.log, keys=Keyring(dict(n_holds), {**snap, bad: actual}))
    split["newcomer handed the author's key"] = {**r.summary(lied, extra=False),
                                                 "provisional": [r.name(i) for i in
                                                                 sorted(lied.provisional)]}
    told = Space(r.log, keys=Keyring(dict(n_holds), {**snap, bad: [actual, derived]}))
    split["newcomer handed both keys"] = r.summary(told, extra=False)
    honest = Space(r.log, keys=Keyring(dict(n_holds), {**snap, bad: derived}))
    split["newcomer handed the derived key"] = r.summary(honest, extra=False)
    assert member.status[bad][1] == "BadSeal"
    assert lied.status[bad][0] and bad in lied.provisional
    assert told.status[bad][1] == "Sealed" and honest.status[bad][1] == "Sealed"
    se["wrong_seal"] = {
        "history": r.hist.describe(), "event": r.name(bad),
        "derived_body_key": h(derived), "author_secret": h(wrong), "author_body_key": h(actual),
        "newcomer": {"holds": [r.name(i) for i in sorted(n_holds)],
                     "rotation_keys": {r.name(i): h(n_holds[i]) for i in sorted(n_holds)},
                     "snapshot": {r.name(i): h(k) for i, k in snap.items()}},
        "views": split,
        "note": "The split is the accepted one: only a sender that hands "
                "a key other than the derived one causes it, and its signed snapshot names "
                "that key, so the lie is attributable."}

    # A merged state's key received whole (keys.md): an
    # event it opens is provisional; a mismatch holds the event, never BadSeal.
    r = Roster("P", "roster/whole")
    r.hist.view["P"] = set(r.log.events)
    r.grant("P", "Q", ADMINISTER)
    r.sync("P", "Q")
    hp = r.heal("P", "P heals")
    hq = r.heal("Q", "Q heals, concurrently")
    r.sync("P", "Q")
    dm = r.deliver("P", "P delivers under the merged state")
    merged = sorted([hp, hq])
    k_merged = kg.content_key(r.id, merged, r.krot.__getitem__)
    full = r.resolve()
    rots = {i: k for i, k in r.krot.items() if i not in merged}
    bodies = {i: full.decoded[i].body_key for i in merged}
    whole = Space(r.log, keys=Keyring(rots, bodies, {kg.encode_set(merged): k_merged}))
    junk = Space(r.log, keys=Keyring(rots, bodies, {kg.encode_set(merged): bytes(32)}))
    assert whole.status[dm][0] and dm in whole.provisional
    assert junk.status[dm][1] == "Sealed"
    se["whole_merged_key"] = {
        "history": r.hist.describe(), "event": r.name(dm),
        "merged_state": [r.name(i) for i in merged], "merged_key": h(k_merged),
        "rotation_keys": {r.name(i): h(rots[i]) for i in sorted(rots)},
        "body_keys": {r.name(i): h(bodies[i]) for i in sorted(bodies)},
        "views": {"the merged key received whole": {
                      **r.summary(whole, extra=False),
                      "provisional": [r.name(i) for i in sorted(whole.provisional)]},
                  "a wrong merged key received whole": r.summary(junk, extra=False)}}

    return se


def _roster_parts() -> dict:
    out: dict = {
        "construction": "the branching roster",
        "version": 1,
        "specification": "roster.md",
        "labels": {label.decode(): h(label) for label in NEW_LABELS},
        "parameters": {
            "event_kind": KIND_ROSTER,
            "body_types": {"genesis": GENESIS, "update": UPDATE},
            "ops": {v: k for k, v in OP_NAMES.items()},
            "member_types": {v: k for k, v in TYPE_NAMES.items()},
            "levels": {v: k for k, v in LEVEL_NAMES.items()},
            "history": {"from now on": FROM_NOW_ON, "with history": WITH_HISTORY},
            "via": {v: k for k, v in VIA_NAMES.items()},
            "capability_modes": {"extends": EXTENDS, "narrows": NARROWS},
            "duel_policies": {"both stand": DUEL_BOTH_STAND},
            "max_changes": MAX_CHANGES, "max_device_grants": MAX_DEVICE_GRANTS,
            "max_capabilities": MAX_CAPS, "refs_inner_key": S_REFS,
            "max_name_bytes": MAX_NAME_BYTES, "max_roster_events": MAX_ROSTER_EVENTS,
            "agreed_step_limit": events.AGREED_LIMIT,
            "max_record_bytes": MAX_RECORD_BYTES,
        },
        "note": ("Each device's Ed25519 seed is SHA-256 of 'frasil spec example/<prefix>/"
                 "<name>/ed25519', its ML-DSA-65 and X-Wing seeds crypto.md's fixture "
                 "derivations, and its member ID the device ID of the three keys. A "
                 "rotation's content key is SHA-256 of 'frasil spec example/<prefix>/"
                 "<label>/content-key', the genesis's label being 'genesis'. history_prefixes "
                 "gives each history's <prefix>; a case's list_prefixes and team_prefix give "
                 "those of the other logs it reads. Rotation slots and key-event bodies hold "
                 "minimal stand-in payloads (keys.md) that pass its checks: most rotate (read "
                 "and upload commitments only), a key event that responds is a grant rotation, "
                 "and one only delivers. A team whose rotations a notice names commits to real "
                 "grant keys, each derived from '<prefix>/<label>/grant-seed'."),
    }
    cases = []
    prefixes: dict = {}  # each case's space log prefix, by its name
    people: dict = {}  # each person built here, by its ID

    def person(*args, **kw) -> identity.Person:
        p = identity.Person(*args, **kw)
        people[p.id] = p
        return p

    def lists_held(r, lists) -> dict:
        """Which events of each person's list a view holds."""
        out = {}
        for pid, lst in sorted(lists.items(), key=lambda kv: r.persons[kv[0]]):
            out[r.persons[pid]] = ("every event" if set(lst.view) == set(lst.log.events)
                                   else [people[pid].hist.name(i)
                                         for i in lst.log.canonical(lst.view)])
        return out

    def with_lists(r, summary: dict, lists) -> dict:
        return {**summary, "lists_held": lists_held(r, lists)}

    def case(name, r, views, *, shape=None, notes=None, lists=None, spaces_=None, checks=None,
             spaces_by_view=None):
        entry = {"name": name}
        if shape:
            entry["shape"] = shape
        if notes:
            entry["notes"] = notes
        entry["events"] = r.hist.describe()
        entry["views"] = {}
        for vname, view in views.items():
            sp = r.resolve(view, lists, (spaces_by_view or {}).get(vname, spaces_))
            summ = r.summary(sp)
            entry["views"][vname] = {"holds": "every event" if view == r.all()
                                     else [r.name(i) for i in r.log.canonical(view)], **summ}
            if lists:
                entry["views"][vname]["lists_held"] = lists_held(r, lists)
            if checks and vname in checks and not checks[vname](sp, summ):
                _fail({"case": name, "view": vname, **summ})
        if lists:
            entry["list_prefixes"] = {r.persons[pid]: people[pid].prefix
                                      for pid in sorted(lists, key=lambda p: r.persons[p])}
        cases.append(entry)
        prefixes[name] = r.prefix
        return entry

    def removed(s, *names):
        return all(s["roster"].get(n) == "removed" for n in names)

    def present(s):
        return sorted(k for k, v in s["roster"].items() if v != "removed")

    # Key histories.
    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE), ("N", WRITE)], "roster/ex1")
    r.remove("P", "M")
    r.sync("P", "N")
    r.remove("Q", "N")
    r.sync("Q", "M")
    r.sync(*r.everyone())
    case("a cross-removal", r, {"all": r.all()},
         shape="concurrent removals of different members by two administrators",
         checks={"all": lambda sp, s: removed(s, "M", "N") and sorted(s["rotations_maximal"])
                 == ["P removes M", "Q removes N"]},
         notes="S holds both removals. M and N together hold both inputs: keys.md's "
               "heal test calls for a heal.")

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", ADMINISTER), ("N", WRITE)],
              "roster/ex2")
    r.remove("P", "M")
    r.remove("M", "N")
    r.sync("M", "Q")
    r.unit("Q", "Q writes under b's key")
    r.unit("N", "N writes, apart")
    r.sync("M", "Q", "N")
    bc = set(r.hist.view["Q"])
    r.sync(*r.everyone())
    case("a void rotation", r, {"rooms B and C": bc, "all": r.all()},
         shape="a removal voids the removed administrator's concurrent removal; a refused "
               "unit is valid again",
         checks={"rooms B and C": lambda sp, s: s["events"]["N writes, apart"].startswith(
                     "RefusedByRemoval"),
                 "all": lambda sp, s: s["events"]["M removes N"].startswith(
                     "RemovedConcurrently") and s["events"]["N writes, apart"] == "valid"
                 and removed(s, "M") and "N" in present(s)})

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE)], "roster/ex3")
    r.grant("P", "G", WRITE, FROM_NOW_ON)
    r.sync("P", "G")
    r.heal("Q")
    r.sync("Q", "M")
    r.unit("M")
    r.sync(*r.everyone())
    r.deliver("M", "M completes a delivery (no new state)")
    r.sync(*r.everyone())
    merged = r.all()
    r.remove("P", "G")
    r.sync(*r.everyone())
    case("a guest from now on", r, {"merged": merged, "all": r.all()},
         checks={"merged": lambda sp, s: sorted(s["rotations_maximal"])
                 == ["P grants G write from now on", "Q heals"]
                 and s["events"]["M completes a delivery (no new state)"] == "valid"},
         notes="S = {G's break, Q's heal}; no link reaches k_x; G waits for a history-free "
               "snapshot (keys.md). M's key event only delivers, so it is valid and "
               "not a rotation.")

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", ADMINISTER), ("N", WRITE),
               ("Z", WRITE)], "roster/ex4")
    r.remove("P", "Z")
    r.sync("P", "N")
    r.unit("N", "N writes in room A")
    r.sync("P", "N")
    r.remove("M", "N")
    r.sync("M", "Z")
    r.remove("Q", "M")
    r.sync("P", "N", "M", "Z")
    ab = set(r.hist.view["P"])
    r.heal("P", "P heals (H)")
    r.unit("P", "P writes under H")
    r.sync("P", "N", "M", "Z")
    r.sync(*r.everyone())
    case("a void input, learned late", r, {"rooms A and B": ab, "all": r.all()},
         checks={"rooms A and B": lambda sp, s: sorted(s["rotations_maximal"])
                 == ["M removes N", "P removes Z"],
                 "all": lambda sp, s: sorted(s["rotations_maximal"]) == ["P heals (H)",
                                                                         "Q removes M"]
                 and s["events"]["M removes N"].startswith("RemovedConcurrently")
                 and s["events"]["N writes in room A"] == "valid"},
         notes="S = {H, C}: M holds k_H and Z holds k_C. Only the heal test (keys.md) "
               "catches this. N works at once and gets the gap keys once the voiding of "
               "M's removal is stable.")

    # More histories.
    r = setup([("P", ADMINISTER), ("M", ADMINISTER), ("Q", ADMINISTER), ("N", WRITE)],
              "roster/c1")
    r.remove("P", "N")
    r.heal("P")
    r.sync("P", "Q")
    r.remove("M", "Q")
    r.sync("M", "N")
    r.sync(*r.everyone())
    case("a removal outside the merged state", r, {"all": r.all()},
         checks={"all": lambda sp, s: sorted(s["rotations_maximal"]) == ["M removes Q",
                                                                         "P heals"]},
         notes="N holds k_b and Q holds k_heal: the heal test calls for a heal; two "
               "removals in S did not.")

    r = setup([("P", ADMINISTER), ("R", ADMINISTER), ("Q", ADMINISTER), ("X", WRITE)],
              "roster/c2")
    r.sync("P", "Q")
    r.remove("P", "X")
    r.sync("P", "Q")
    r.grant("Q", "X", WRITE, label="Q grants X again")
    r.sync("P", "Q", "X")
    r.heal("P")
    r.sync("P", "Q", "X")
    r.remove("R", "Q")
    r.sync(*r.everyone())
    case("one removed member alone derives the key", r, {"all": r.all()},
         checks={"all": lambda sp, s: removed(s, "X") and s["events"][
             "Q grants X again"].startswith("RemovedConcurrently")},
         notes="X holds k_heal (wrapped while it was back) and k_R: the heal test calls "
               "for a heal.")

    r = Roster("P", "roster/c3")
    for n, lv in (("Q1", ADMINISTER), ("Q2", ADMINISTER), ("R", ADMINISTER), ("X", WRITE),
                  ("Y", WRITE), ("Z", WRITE)):
        r.hist.view["P"] = set(r.log.events)
        r.grant("P", n, lv)
    r.sync("P", "Q1", "Q2", "R", "X", "Y", "Z")
    r.remove("P", "X")
    r.remove("Q1", "Y")
    r.sync("Q1", "Q2")
    r.remove("R", "Z")
    r.sync("P", "Q1")
    r.heal("P", "P heals (H1)")
    r.sync("Q2", "R")
    r.heal("Q2", "Q2 heals (H2)")
    r.sync(*r.everyone())
    case("concurrent heals", r, {"all": r.all()},
         checks={"all": lambda sp, s: sorted(s["rotations_maximal"]) == ["P heals (H1)",
                                                                         "Q2 heals (H2)"]},
         notes="X holds k_H2, Z holds k_H1: the heal test calls for a second heal.")

    r = setup([("P", ADMINISTER), ("R", ADMINISTER), ("Q", ADMINISTER), ("W", WRITE)],
              "roster/c4")
    r.grant("P", "G", WRITE, FROM_NOW_ON)
    r.sync("P", "W", "G")
    r.heal("W")
    r.sync("P", "W", "G")
    r.remove("Q", "P")
    r.unit("Q", "Q writes under k_q")
    r.remove("R", "Q")
    r.sync("P", "W", "G", "Q")
    room12 = set(r.hist.view["P"])
    r.unit("W", "W writes under the merge key")
    r.sync(*r.everyone())
    case("a stale link and a 'from now on' guest", r, {"rooms 1 and 2": room12,
                                                            "all": r.all()},
         checks={"rooms 1 and 2": lambda sp, s: s["events"][
             "P grants G write from now on"].startswith("RemovedConcurrently"),
                 "all": lambda sp, s: "G" in present(s) and s["events"][
                     "Q removes P"].startswith("RemovedConcurrently")},
         notes="G's grant is void, then valid again. Links follow potential entitlement "
               ".")

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("Z", ADMINISTER)], "roster/c5")
    r.remove("P", "Q")
    r.remove("Q", "Z")
    r.remove("Z", "P")
    r.sync(*r.everyone())
    case("an odd cycle", r, {"all": r.all()},
         shape="a cycle of three with no mutual pair: the most senior author's action stands",
         checks={"all": lambda sp, s: present(s) == ["Z"]
                 and s["events"]["P removes Q"] == "valid (seniority)"})

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER)], "roster/c6")
    r.hist.device("H")
    r.grant("P", "H", WRITE, label="P grants H")
    r.remove("P", "H", "P removes H")
    r.grant("Q", "H", WRITE, label="Q grants H")
    r.remove("Q", "H", "Q removes H")
    r.grant("Q", "H", WRITE, label="Q grants H again")
    r.sync(*r.everyone())
    case("an even cycle with several answers", r, {"all": r.all()},
         shape="removals voiding concurrent grants whose authority depends on them",
         checks={"all": lambda sp, s: removed(s, "H")
                 and s["events"]["P grants H"] == "valid (seniority)"})

    r, roles, junk, views = _contest_with_junk("roster/junk-contest")

    def same_contest(sp, s):
        return (s["events"][r.name(roles["e3"])] == "NotAnAdministrator"
                and s["events"][r.name(roles["e2"])].startswith("RemovedConcurrently")
                and all(sp.status[j][1] == "NotAnAdministrator" for j in junk if j in sp.view)
                and not any(j in sp.contested for j in junk))

    case("a cycle the agreement step settles, beside a reader's roster events", r, views,
         shape="the agreement step voids an event the pick alone would make valid; the "
               "reader's events after the contest have no standing and are never contested",
         checks={v: same_contest for v in views},
         notes=f"The agreement step voids E's relabelling of D (e3): it is void in every "
               f"allowed assignment, and takes its class from the first, in which e1 is void. "
               f"Were the reader's events contested, each would wait on the contest, and "
               f"{JUNK_AFTER_CONTEST + 1} of them would bring the undecided events to "
               f"{JUNK_AFTER_CONTEST + 5}, past the agreement step's 16, and the pick "
               f"alone would make E's relabelling of D valid. No event in their past "
               f"names M at administer, so each is NotAnAdministrator before the procedure, "
               f"and every view gives the contest the same verdicts.")

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER)], "roster/c7")
    r.grant("P", "G", READ, FROM_NOW_ON)
    r.sync("P", "G")
    r.heal("Q")
    r.unit("Q", "Q writes under k_x")
    r.sync(*r.everyone())
    r.grant("P", "K", WRITE, WITH_HISTORY)
    r.sync(*r.everyone())
    case("a with-history member after a merge with a break", r, {"all": r.all()},
         notes="K reaches Q's unit's key as a gap key.")

    r = setup([("P", ADMINISTER), ("R", ADMINISTER), ("Q", ADMINISTER), ("W", WRITE),
               ("V", WRITE)], "roster/c8")
    r.grant("P", "G", READ, FROM_NOW_ON)
    r.sync("P", "W", "G")
    r.heal("W")
    r.sync("P", "W", "G")
    r.remove("Q", "P")
    r.sync("Q", "V")
    r.heal("V")
    r.sync("Q", "V")
    r.remove("R", "Q")
    r.sync("P", "W", "G", "Q", "V")
    rooms = set(r.hist.view["P"])
    r.unit("W", "W writes under k_{h,x}")
    r.sync(*r.everyone())
    case("a grant valid again misses an old merged key", r,
         {"rooms 1 and 2": rooms, "all": r.all()},
         checks={"rooms 1 and 2": lambda sp, s: "G" not in present(s),
                 "all": lambda sp, s: "G" in present(s)},
         notes="Wraps follow the merged roster for every key.")

    def c9_base(prefix):
        rr = setup([("P", ADMINISTER), ("X", WRITE)], prefix)
        rr.unit("X", "X writes 1")
        old = set(rr.hist.view["X"])
        rr.unit("X", "X writes 2")
        rr.sync("P", "X")
        return rr, old

    rr, old = c9_base("roster/c9a")
    rr.remove("P", "X")
    rr.unit("X", "X writes 3, not having seen its removal")
    x1 = rr.hist.by_name("X writes 1")
    rr.unit("X", "X, forked, writes again at seq 2 onto old heads", view=old,
            seq=rr.log.events[x1].seq + 1, prev=x1)
    rr.sync("P", "X")
    case("a backdated unit reusing a sequence number", rr, {"all": rr.all()},
         checks={"all": lambda sp, s: s["events"]["X writes 3, not having seen its removal"]
                 == "Forked" and s["events"]["X writes 2"] == "Forked"
                 and s["events"]["X writes 1"] == "valid"},
         notes="The reused sequence number is a fork: X is void from seq 2, its honest second "
               "unit included (the chain penalty).")

    rr, _ = c9_base("roster/c9b")
    rr.remove("P", "X")
    rr.unit("X", "X writes 3, not having seen its removal")
    rr.sync("P", "X")
    case("a unit concurrent with its writer's removal", rr, {"all": rr.all()},
         checks={"all": lambda sp, s: s["events"]["X writes 3, not having seen its removal"]
                 .startswith("RefusedByRemoval")
                 and s["frontiers"]["P removes X"]["heads"] == {"X": "X writes 2"}})

    rr, _ = c9_base("roster/c9c")
    rr.remove("P", "X")
    rr.grant("P", "X", WRITE, label="P grants X again")
    rr.sync("P", "X")
    rr.unit("X", "X writes 3, after the re-grant")
    rr.sync("P", "X")
    case("a unit after a re-grant", rr, {"all": rr.all()},
         checks={"all": lambda sp, s: s["events"]["X writes 3, after the re-grant"] == "valid"})

    xp = person("X1", "roster/c9d/list", linear=True)
    rr = Roster("P", "roster/c9d", keys={"X1": xp.hist.seed("X1")})
    rr.persons[xp.id] = "person X"
    rr.grant("P", "person X", WRITE)
    rr.sync("P", "X1")
    rr.unit("X1", "X1 writes")
    rr.sync("P", "X1")
    rr.remove("P", "person X")
    xp.add("X1", "X2", identity.DEVICE)
    rr.hist.keys["X2"] = xp.hist.seed("X2")
    rr.hist.view["X2"] = set(rr.hist.view["X1"])
    rr.unit("X2", "X2, added to X's list apart, writes")
    rr.sync("P", "X1", "X2")
    lists = {xp.id: xp.resolve()}
    e = case("a device the remover never knew", rr, {"all": rr.all()}, lists=lists,
             checks={"all": lambda sp, s: s["events"]["X2, added to X's list apart, writes"]
                     .startswith("RefusedByRemoval")
                     and s["frontiers"]["P removes person X"]["heads"] == {"X1": "X1 writes"}})
    e["lists"] = {"person X": xp.hist.describe()}

    r = Roster("P1", "roster/c10")
    for n, lv in (("P2", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE)):
        r.hist.view["P1"] = set(r.log.events)
        r.grant("P1", n, lv)
    r.sync("P1", "P2", "Q", "M")
    r.remove("P1", "M")
    r.unit("P1", "P1 writes after removing M")
    r.remove("Q", "P1")
    r.change("P2", "Q", WRITE, "P2 demotes Q to write")
    r.sync("P1", "Q", "M")
    ab = set(r.hist.view["P1"])
    r.sync(*r.everyone())
    voiding = (r.hist.by_name("Q removes P1"),)
    e = case("restored, then removed again", r, {"rooms A and B": ab, "all": r.all()},
             checks={"rooms A and B": lambda sp, s: "M" in present(s),
                     "all": lambda sp, s: removed(s, "M")
                     and s["events"]["P1 removes M"] == "valid"},
             notes="M is back in rooms A and B and out once P2's demotion of Q arrives. "
                   "M works at once and receives keys made while it was out "
                   "only once the voiding is stable.")
    sp_ab = r.resolve(ab)
    e["stability_in_rooms_A_and_B"] = {
        "voided": "P1 removes M",
        "voided_by": [r.name(x) for x in sp_ab.voiders(r.hist.by_name("P1 removes M"))],
        "administrators": sorted(r.hist.key_name(a) for a in sp_ab.administrators()),
        "stable": sp_ab.stable([r.hist.by_name("P1 removes M")] + list(voiding)),
    }

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER)], "roster/c11")
    r.grant("P", "G", ADMINISTER, FROM_NOW_ON)
    r.sync("P", "Q", "G")
    r.remove("G", "P")
    r.remove("G", "Q")
    r.grant("G", "K", WRITE, WITH_HISTORY)
    r.sync(*r.everyone())
    case("history whose only holders are out", r, {"all": r.all()},
         checks={"all": lambda sp, s: present(s) == ["G", "K"]},
         notes="Nobody current holds the keys before G's break: K's history is lost, a "
               "stated limit.")

    def duel(attacker, prefix):
        rr = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("S", ADMINISTER), ("M", WRITE)],
                   prefix)
        rr.hist.device("H")
        remover = "Q" if attacker == "P" else "P"
        removal = rr.remove(remover, attacker)
        rr.grant(remover, "H", WRITE, label=f"{remover} grants H (later work)")
        rr.unit(remover, f"{remover} writes (later work)")
        rr.sync(remover, attacker)
        seen = {i for i in rr.hist.view[attacker] if not rr.log.le(removal, i)}
        rr.remove(attacker, remover, f"{attacker} removes {remover}, backdated", view=seen)
        rr.sync(*rr.everyone())
        merged = rr.all()
        rr.grant("S", remover, ADMINISTER, label=f"S grants {remover} again")
        rr.sync(*rr.everyone())
        return rr, merged, remover

    for attacker, who in (("P", "senior"), ("Q", "junior")):
        rr, merged, remover = duel(attacker, f"roster/c12/{who}")
        if who == "senior":
            case(f"the backdated duel, {who} attacker", rr, {"merged": merged},
                 shape="a mutual pair of equal ranks: the more senior stands",
                 checks={"merged": lambda sp, s: removed(s, "Q") and "P" in present(s)
                         and s["events"]["Q grants H (later work)"].startswith(
                             "RemovedConcurrently") and bool(s["duels"])},
                 notes="P and Q hold the same rank; P, the more senior, stands, its "
                       "backdated removal of Q stands, and Q's removal of P and Q's later "
                       "work are void: a stolen senior device wins its duel.")
        else:
            case(f"the backdated duel, {who} attacker", rr, {"merged": merged},
                 shape="a mutual pair of equal ranks: the more senior stands",
                 checks={"merged": lambda sp, s: removed(s, "Q") and "P" in present(s)
                         and s["events"]["P grants H (later work)"] == "valid"
                         and bool(s["duels"])},
                 notes="P and Q hold the same rank; P, the more senior, removed Q, and Q's "
                       "backdated removal of P is void: a junior attacker gains nothing.")

    # Ranks (section 3.6): nobody acts on a higher rank, or above its own.
    r = Roster("P", "roster/ranks/lower")
    r.grant("P", "A", ADMINISTER, rank=10, label="P grants A administer at rank 10")
    r.grant("P", "B", ADMINISTER, rank=20, label="P grants B administer at rank 20")
    r.sync("P", "A", "B")
    r.remove("A", "B", "A, rank 10, removes B, rank 20")
    r.remove("B", "A", "B, rank 20, removes A, rank 10")
    r.grant("A", "C", ADMINISTER, rank=50, label="A grants C administer at rank 50")
    r.change("P", "B", ADMINISTER, rank=30, label="P sets B's rank to 30 in place")
    r.sync(*r.everyone())
    case("a lower rank acts on a higher one", r, {"all": r.all()},
         shape="ranks: HigherRank and RankInPlace",
         checks={"all": lambda sp, s: s["events"]["A, rank 10, removes B, rank 20"]
                 == "HigherRank" and s["events"]["B, rank 20, removes A, rank 10"] == "valid"
                 and s["events"]["A grants C administer at rank 50"].startswith(
                     ("HigherRank", "RemovedConcurrently"))
                 and s["events"]["P sets B's rank to 30 in place"] == "RankInPlace"
                 and s["roster"]["B"]["rank"] == 20},
         notes="A lower rank's removal of a higher one is void whether or not it is "
               "concurrent with anything; a rank is set when a device becomes an "
               "administrator and never changed in place.")
    r = Roster("P", "roster/ranks/thief")
    r.grant("P", "Q", ADMINISTER, rank=100, label="P grants Q administer at rank 100")
    r.grant("P", "A", ADMINISTER, rank=50, label="P grants A administer at rank 50")
    r.sync("P", "Q", "A")
    old = set(r.hist.view["A"])
    r.remove("Q", "A", "Q removes A, whose device is stolen")
    r.sync("P", "Q")
    r.hist.view["A"] = old
    r.remove("A", "Q", "the thief removes Q, backdated")
    r.remove("A", "P", "the thief removes P, backdated")
    r.sync(*r.everyone())
    case("a lower-rank thief's backdated removals", r, {"all": r.all()},
         shape="ranks: a lower rank never removes a higher one",
         checks={"all": lambda sp, s: removed(s, "A") and {"P", "Q"} <= set(present(s))
                 and s["events"]["the thief removes Q, backdated"] == "HigherRank"
                 and s["events"]["the thief removes P, backdated"] == "HigherRank"},
         notes="Without checkpoints or with them, the thief gains nothing.")

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE)], "roster/c12/genuine")
    r.remove("P", "Q")
    r.remove("Q", "P")
    r.sync(*r.everyone())
    case("a genuine mutual removal", r, {"all": r.all()},
         shape="a mutual pair of equal ranks: the more senior stands",
         checks={"all": lambda sp, s: present(s) == ["M", "P"]})

    # A remover raised after the attacker's last event (section 3.5.2,
    # "Neither undoes its partner's authority").
    def raised_remover(prefix, others=(), chain=False, honest=False, thief=False):
        rr = setup([("F", ADMINISTER), ("Q", ADMINISTER), ("H", ADMINISTER), ("R", WRITE),
                    ("P", WRITE), ("N", WRITE)], prefix)
        last = set(rr.hist.view["Q"])
        raiser = "F"
        if chain:
            rr.change("F", "R", ADMINISTER, "F raises R")
            rr.sync("F", "R")
            raiser = "R"
        rr.change(raiser, "P", ADMINISTER, f"{raiser} raises P")
        rr.sync(raiser, "P")
        rr.remove("P", "Q", "P removes Q")
        names = ["P", *others]
        rr.hist.view["Q"] = set(last)
        if thief:
            rr.grant("Q", "K", WRITE, label="Q grants K, backdated")
        rr.act("Q", [Change(REMOVE, rr.member(n)) for n in names],
               "Q removes " + " and ".join(names) + ", backdated")
        if thief:
            rr.change("Q", "N", label="Q relabels N", tag="n")
        if honest:
            rr.remove("H", "P", "H removes P, concurrently with the raise", view=last)
        rr.sync(*rr.everyone())
        return rr

    rr = raised_remover("roster/c12/raised")
    case("a counter-removal backdated before its remover's raise", rr, {"all": rr.all()},
         shape="a mutual pair of equal ranks: the more senior stands, and the raise stands",
         checks={"all": lambda sp, s: removed(s, "P") and "Q" in present(s)
                 and s["events"]["F raises P"] == "valid"
                 and s["events"]["P removes Q"].startswith("RemovedConcurrently")
                 and bool(s["duels"])},
         notes="At Q's event P is a writer, so it needs no twin and AdminAlone does not "
               "apply; its attack (c) on F's raise does not count. Q and P hold the same "
               "rank and Q is the more senior, so Q's removal of P stands and P's of Q is "
               "void: an attacker senior to its remover wins; F, raising P at a lower rank "
               "than Q's, would not have let P remove Q at all.")
    rr = raised_remover("roster/c12/raised-batch", others=("N",))
    case("a counter-removal in a batch, backdated before its remover's raise", rr,
         {"all": rr.all()},
         shape="no mutual pair: the batch falls to the removal of its author",
         checks={"all": lambda sp, s: removed(s, "Q") and "N" in present(s)
                 and s["roster"]["P"]["level"] == "administer"
                 and s["events"]["Q removes P and N, backdated"]
                 == "RemovedConcurrently by P removes Q"})
    rr = raised_remover("roster/c12/raised-chain", others=("R",), chain=True)
    case("a counter-removal of a remover and its raiser, both raised after it", rr,
         {"all": rr.all()},
         shape="a chain of two raises: neither falls to the counter-removal",
         checks={"all": lambda sp, s: removed(s, "Q")
                 and s["roster"]["P"]["level"] == "administer"
                 and s["roster"]["R"]["level"] == "administer"
                 and s["events"]["R raises P"] == "valid"})
    rr = raised_remover("roster/c12/raised-thief", thief=True)
    case("a thief's counter-removal among events that look honest", rr, {"all": rr.all()},
         shape="a mutual pair of equal ranks: the more senior, the thief, stands",
         checks={"all": lambda sp, s: removed(s, "P") and "Q" in present(s)
                 and "K" in present(s) and s["events"]["F raises P"] == "valid"
                 and s["events"]["P removes Q"].startswith("RemovedConcurrently")})
    rr = raised_remover("roster/c12/raised-honest", honest=True)
    case("an administrator's removal of a remover concurrent with its raise", rr,
         {"all": rr.all()},
         shape="only a duel partner's attacks are dropped",
         checks={"all": lambda sp, s: removed(s, "P") and "Q" in present(s)
                 and s["events"]["F raises P"] == "TargetRemovedConcurrently by "
                 "H removes P, concurrently with the raise"
                 and s["events"]["P removes Q"] == "NotAnAdministrator"},
         notes="H is no partner of P's removal of Q, so its attack (c) on the raise counts, "
               "and P was never an administrator in the merged roster.")

    r = setup([("F", ADMINISTER), ("Q", ADMINISTER), ("P", ADMINISTER), ("A", WRITE)],
              "roster/c12/accomplice")
    before = set(r.hist.view["P"])
    r.remove("Q", "P")
    r.hist.view["P"] = before
    r.change("P", "A", ADMINISTER, "P raises A, backdated")
    r.change("P", "P", WRITE, "P demotes itself to write")
    r.sync("P", "A")
    r.change("A", "P", ADMINISTER, "A raises P")
    r.sync("P", "A")
    r.remove("P", "Q", "P removes Q, backdated")
    r.sync(*r.everyone())
    case("a removed administrator that raises an accomplice to raise it back", r,
         {"all": r.all()},
         shape="the remover's own events stay attacked",
         checks={"all": lambda sp, s: removed(s, "P") and s["roster"]["A"]["level"] == "write"
                 and s["events"]["P raises A, backdated"].startswith("RemovedConcurrently")
                 and s["events"]["P removes Q, backdated"] == "NotAnAdministrator"})

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE)], "roster/c13")
    before = set(r.hist.view["P"])
    r.change("P", "P", WRITE, "P demotes itself to write")
    r.change("P", "P", READ, "P, restored, demotes itself to read", view=before)
    r.sync(*r.everyone())
    case("concurrent self-demotions", r, {"all": r.all()},
         shape="two self-demotions at one sequence number: a fork; both stand",
         checks={"all": lambda sp, s: s["roster"]["P"]["level"] == "read"
                 and s["events"]["P demotes itself to write"] == "valid"})

    # Backdating attackers.
    def chained(mode, prefix):
        rr = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE)], prefix)
        early = set(rr.hist.view["Q"])
        rr.grant("Q", "H", WRITE, label="Q grants H")
        rr.sync("Q", "P")
        rr.unit("P", "P writes (its last signed event)")
        rr.sync("Q", "P")
        rr.grant("Q", "K", WRITE, label="Q grants K")
        rr.remove("Q", "P", "Q removes P")
        rr.sync("Q", "P")
        if mode == "comply":
            view = set(early)
            for i in rr.hist.view["P"]:
                if rr.log.events[i].author == rr.hist.device("P"):
                    view |= rr.log.anc[i] | {i}
            rr.remove("P", "Q", "P removes Q, backdated, keeping its chain", view=view)
        else:
            last = max((i for i in early if rr.log.events[i].author == rr.hist.device("P")),
                       key=lambda i: rr.log.events[i].seq)
            rr.remove("P", "Q", "P removes Q, backdated, forking its chain", view=early,
                      seq=rr.log.events[last].seq + 1, prev=last)
        rr.sync(*rr.everyone())
        return rr

    rr = chained("comply", "roster/f8/comply")
    case("a backdating attacker that keeps its chain", rr, {"all": rr.all()},
         checks={"all": lambda sp, s: removed(s, "Q") and "P" in present(s)
                 and s["events"]["Q grants H"] == "valid"
                 and s["events"]["Q grants K"].startswith("RemovedConcurrently")},
         notes="It must cite its own last event, so it reaches only into its silent period.")
    rr = chained("fork", "roster/f8/fork")
    case("a backdating attacker that forks its chain", rr, {"all": rr.all()},
         checks={"all": lambda sp, s: s["events"]["P removes Q, backdated, forking its chain"]
                 == "Forked" and removed(s, "P") and "Q" in present(s)
                 and s["events"]["Q grants K"] == "valid"})

    r = Roster("P1", "roster/f8/selfdemotion")
    for n in ("P2", "Q"):
        r.hist.view["P1"] = set(r.log.events)
        r.grant("P1", n, ADMINISTER)
    r.sync("P1", "P2", "Q")
    before = set(r.hist.view["P1"])
    r.change("P1", "P1", WRITE, "P1 demotes itself to write")
    r.sync("P1", "P2", "Q")
    r.unit("P1", "P1 forks: a unit at the same seq", view=before)
    r.hist.view["P1"] |= r.hist.view["Q"]
    r.grant("P1", "H", WRITE, label="P1 grants H after its fork")
    r.sync(*r.everyone())
    case("a fork cannot erase its author's self-demotion", r, {"all": r.all()},
         checks={"all": lambda sp, s: s["roster"]["P1"]["level"] == "write"
                 and s["events"]["P1 grants H after its fork"] == "Forked"})

    for resync in (False, True):
        rr = setup([("P", ADMINISTER), ("X", WRITE)], f"roster/restore/{resync}")
        rr.unit("X", "X writes 1")
        backup = set(rr.hist.view["X"])
        rr.unit("X", "X writes 2")
        rr.sync("P", "X")
        rr.hist.view["X"] = backup
        if resync:
            rr.sync("P", "X")
        rr.unit("X", "X, restored, writes")
        rr.sync("P", "X")
        case("a restore that " + ("syncs before it writes" if resync
                                  else "writes before it syncs"), rr, {"all": rr.all()},
             checks={"all": (lambda sp, s: s["events"]["X writes 2"] == "valid") if resync
                     else (lambda sp, s: s["events"]["X writes 2"] == "Forked")},
             notes="a restored device fetches its latest sequence first.")

    rr = setup([("P", ADMINISTER), ("X", WRITE)], "roster/evidence")
    rr.unit("X", "X writes 1")
    before = set(rr.hist.view["X"])
    rr.unit("X", "X writes 2")
    rr.unit("X", "a unit at X's seq 2 this replica cannot open", view=before,
            body=b"sealed under no key the space holds")
    rr.sync("P", "X")
    case("a unit this replica cannot open still proves a fork", rr, {"all": rr.all()},
         checks={"all": lambda sp, s: s["events"]["X writes 2"] == "Forked"
                 and s["events"]["a unit at X's seq 2 this replica cannot open"] == "Sealed"
                 and s["forked"] == {"X": 2}},
         notes="events.md: evidence needs a verified signature, not an opened "
               "seal, so every replica holding the two events sees the fork alike.")

    # Every conflict shape, and the cases the notes left open.
    r = setup([("P", ADMINISTER), ("Q", ADMINISTER)], "roster/shape/target-removed")
    r.hist.device("H")
    r.grant("P", "H", WRITE, label="P grants H")
    r.sync("P", "Q")
    r.remove("P", "H", "P removes H")
    r.change("Q", "H", ADMINISTER, "Q promotes H to administer")
    r.sync(*r.everyone())
    case("a removal beats a concurrent change of the same member", r, {"all": r.all()},
         shape="a removal against a concurrent grant or change of its target",
         checks={"all": lambda sp, s: s["events"]["Q promotes H to administer"].startswith(
             "TargetRemovedConcurrently")})

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE)], "roster/shape/self")
    r.change("Q", "Q", WRITE, "Q demotes itself to write")
    r.remove("P", "Q")
    r.sync(*r.everyone())
    case("a self-demotion and a concurrent removal of its author both stand", r,
         {"all": r.all()}, shape="a self-demotion is immune to concurrency",
         checks={"all": lambda sp, s: removed(s, "Q")
                 and s["events"]["Q demotes itself to write"] == "valid"})

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE)], "roster/shape/two-removals")
    r.remove("P", "M", "P removes M")
    r.remove("Q", "M", "Q removes M")
    r.sync(*r.everyone())
    case("two concurrent removals of one member both stand", r, {"all": r.all()},
         checks={"all": lambda sp, s: s["events"]["P removes M"] == "valid"
                 and s["events"]["Q removes M"] == "valid"})

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE)], "roster/shape/demotion")
    r.change("P", "Q", WRITE, "P demotes Q to write")
    r.grant("Q", "H", WRITE, label="Q grants H")
    r.heal("Q", "Q heals")
    r.sync(*r.everyone())
    case("a demotion beats the demoted administrator's concurrent roster actions", r,
         {"all": r.all()},
         checks={"all": lambda sp, s: s["events"]["Q grants H"].startswith(
             "DemotedConcurrently") and s["events"]["Q heals"] == "valid"},
         notes="The heal needs only write, which Q keeps.")

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", ADMINISTER)], "roster/shape/mixed")
    r.change("P", "Q", WRITE, "P demotes Q to write")
    r.remove("Q", "P", "Q removes P")
    r.sync(*r.everyone())
    case("a removal and a demotion of each other: the more senior stands", r,
         {"all": r.all()}, shape="a mutual pair of equal ranks",
         checks={"all": lambda sp, s: "P" in present(s)
                 and s["roster"]["Q"]["level"] == "write"})

    r = setup([("P", ADMINISTER), ("N", WRITE)], "roster/shape/to-read")
    r.change("P", "N", READ, "P demotes N to read")
    r.unit("N", "N writes, apart")
    r.heal("N", "N heals, apart")
    r.sync(*r.everyone())
    case("a demotion to read refuses the member's concurrent writes", r, {"all": r.all()},
         shape="a demotion to read has a frontier like a removal",
         checks={"all": lambda sp, s: s["events"]["N writes, apart"].startswith(
             "RefusedByRemoval") and s["events"]["N heals, apart"].startswith(
             "RefusedByRemoval")})

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER)], "roster/shape/grants")
    r.grant("P", "H", ADMINISTER, WITH_HISTORY, label="P grants H administer with history",
            caps=(("drive", EXTENDS), ("export", EXTENDS)), tag="operator")
    r.grant("Q", "H", READ, FROM_NOW_ON, label="Q grants H read from now on",
            caps=(("drive", EXTENDS), ("suggest", NARROWS)), tag="monitor")
    r.sync(*r.everyone())
    case("concurrent grants of one member: the meet", r, {"all": r.all()},
         shape="decided here: the lowest level, extending capabilities in every grant, "
               "narrowing ones in any, history only if every grant gives it",
         checks={"all": lambda sp, s: s["roster"]["H"]["level"] == "read"
                 and s["roster"]["H"]["history"] == "from now on"
                 and s["roster"]["H"]["capabilities"] == [["drive", "extends"],
                                                          ["suggest", "narrows"]]})

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", ADMINISTER)], "roster/shape/demotions")
    r.change("P", "M", WRITE, "P demotes M to write")
    r.change("Q", "M", READ, "Q demotes M to read")
    r.sync(*r.everyone())
    case("concurrent demotions of one member: the lower level", r, {"all": r.all()},
         checks={"all": lambda sp, s: s["roster"]["M"]["level"] == "read"})

    # A change carries no session: whether it raises a guest is the
    # roster's at its place (section 3.6, step 2).
    r = setup([("P", ADMINISTER), ("Q", ADMINISTER)], "roster/shape/guest-raise")
    r.grant("P", "G", WRITE, FROM_NOW_ON, label="P grants G write for a session",
            session=example("roster/shape/guest-raise/session")[:16])
    r.sync(*r.everyone())
    r.change("Q", "G", ADMINISTER, "Q raises G to administer")
    r.sync(*r.everyone())
    case("a change that raises a guest to administer", r, {"all": r.all()},
         checks={"all": lambda sp, s: s["events"]["Q raises G to administer"]
                 == "AdministerNotDevice" and s["roster"]["G"]["level"] == "write"
                 and "session" in s["roster"]["G"]})

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER)], "roster/shape/guest-raise-concurrent")
    r.grant("P", "G", WRITE, label="P grants G write")
    r.change("P", "G", ADMINISTER, "P raises G to administer")
    r.grant("Q", "G", WRITE, FROM_NOW_ON, label="Q grants G write for a session",
            session=example("roster/shape/guest-raise-concurrent/session")[:16])
    r.sync(*r.everyone())
    r.change("Q", "G", ADMINISTER, "Q, having merged, raises G to administer")
    r.sync(*r.everyone())
    case("a raise concurrent with the grant that makes its member a guest", r,
         {"all": r.all()},
         notes="Both grants and P's raise stand, each at its place. The meet keeps the "
               "session and the lower level, so G is a guest at write; Q's raise after the "
               "merge is AdministerNotDevice.",
         checks={"all": lambda sp, s: s["events"]["P raises G to administer"] == "valid"
                 and s["events"]["Q grants G write for a session"] == "valid"
                 and s["events"]["Q, having merged, raises G to administer"]
                 == "AdministerNotDevice"
                 and s["roster"]["G"]["level"] == "write" and "session" in s["roster"]["G"]})

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER)], "roster/shape/guest-regrant")
    r.grant("P", "G", WRITE, FROM_NOW_ON, label="P grants G write for a session",
            session=example("roster/shape/guest-regrant/session")[:16])
    r.remove("P", "G", "P removes G")
    r.grant("P", "G", WRITE, label="P grants G write again, without a session")
    r.sync(*r.everyone())
    r.change("Q", "G", ADMINISTER, "Q raises G to administer")
    r.sync(*r.everyone())
    case("a former guest re-granted without a session may be raised", r, {"all": r.all()},
         notes="A change keeps session as granted; only a removal and a re-grant drop it.",
         checks={"all": lambda sp, s: s["events"]["Q raises G to administer"] == "valid"
                 and s["roster"]["G"]["level"] == "administer"
                 and "session" not in s["roster"]["G"]})

    r = Roster("P", "roster/shape/concurrent-admins")
    for n in ("Q", "C"):
        r.hist.view["P"] = set(r.log.events)
        r.grant("P", n, ADMINISTER)
    r.sync("P", "Q", "C")
    r.grant("P", "A", ADMINISTER)
    r.sync("P", "A")
    r.grant("Q", "B", ADMINISTER)
    r.sync("Q", "B")
    r.sync(*r.everyone())
    r.remove("A", "B")
    r.remove("B", "C")
    r.remove("C", "A")
    r.sync(*r.everyone())
    case("administrators granted concurrently, in an odd cycle", r, {"all": r.all()},
         shape="seniority between concurrent grants: height, then the hash of the grantee's "
               "key and the grant's parents",
         checks={"all": lambda sp, s: any(v == "valid (seniority)" for v in s["events"].values())})

    # The same seniority pick, where P's grant of A rests on P's units. A
    # partial replica that holds the space events witnesses only the units
    # they cite, so the lower bound it has for A's grant's height falls
    # below B's: taken as heights, they would make A senior and flip the
    # pick.
    r = Roster("P", "roster/shape/partial-heights")
    r.grant("P", "Q", ADMINISTER)
    g_q = r.log.canonical()[-1]
    r.sync("P", "Q")
    for n in (1, 2, 3):
        r.unit("P", f"P writes {n}")
    r.grant("P", "A", ADMINISTER, extra_parents=[g_q])
    r.unit("Q", "Q writes")
    r.grant("Q", "B", ADMINISTER, extra_parents=[g_q])
    r.sync(*r.everyone())
    r.grant("P", "D", ADMINISTER)
    r.sync(*r.everyone())
    r.remove("A", "B")
    r.remove("B", "D")
    r.remove("D", "A")
    r.sync(*r.everyone())
    entry = case("administrators granted concurrently after units, in an odd cycle, at a "
                 "partial replica", r, {"all": r.all()},
                 shape="the seniority pick of the cycle above, where one grant's height rests "
                       "on units a partial replica does not hold",
                 checks={"all": lambda sp, s: s["events"]["B removes D"] == "valid (seniority)"})
    frame = {i for i in r.all() if r.log.events[i].kind == KIND_SPACE}
    entry["partial_replica"] = partial_replica(r, frame)
    lower = entry["partial_replica"]["with_lower_bounds"]
    assert lower["A removes B"] == "valid (seniority)", lower
    assert entry["partial_replica"]["after_fetching"] != lower

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE), ("N", WRITE)],
              "roster/shape/admin-alone")
    r.act("P", [Change(REMOVE, r.member("Q")), Change(REMOVE, r.member("M"))],
          "P removes Q and M in one event")
    r.act("P", [Change(REMOVE, r.member("M")), Change(REMOVE, r.member("N"))],
          "P removes M and N in one event")
    r.sync(*r.everyone())
    case("an event that lowers an administrator names nobody else", r, {"all": r.all()},
         checks={"all": lambda sp, s: s["events"]["P removes Q and M in one event"]
                 == "AdminAlone" and s["events"]["P removes M and N in one event"] == "valid"})

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER)], "roster/shape/history-ends")
    r.grant("P", "K", WRITE, WITH_HISTORY, label="P grants K with history")
    r.sync(*r.everyone())
    r.remove("P", "K")
    r.sync(*r.everyone())
    r.grant("Q", "K", WRITE, FROM_NOW_ON, label="Q grants K again from now on")
    r.sync(*r.everyone())
    case("'with history' ends with its grant", r, {"all": r.all()},
         checks={"all": lambda sp, s: s["roster"]["K"]["history"] == "from now on"})

    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE)], "roster/shape/policy")
    r.set_policy("P", {"bounded_window": 86400, "agent_waiting_period": 96 * 3600},
                 "P sets a one-day window")
    r.set_policy("Q", {"bounded_window": 3600 * 6, "forbid_agents": True},
                 "Q sets a six-hour window and forbids agents")
    r.sync(*r.everyone())
    e = case("concurrent policy changes: each field's stricter value", r, {"all": r.all()})
    sp = r.resolve()
    e["policy"] = sp.space_policy
    assert sp.space_policy == {"agent_waiting_period": 96 * 3600, "gap_key_timeout": 7 * 86400,
                               "bounded_window": 6 * 3600, "online_freshness": None,
                               "forbid_agents": True}

    # Checks across logs: persons, spaces, replace.
    pb = person("b1", "roster/person/list", linear=True)
    pb.add("b1", "b2", identity.DEVICE)
    r = Roster("P", "roster/person", keys={n: pb.hist.seed(n) for n in ("b1", "b2")})
    r.persons[pb.id] = "person B"
    r.grant("P", "W", WRITE)
    r.grant("P", "person B", WRITE, label="P grants person B write")
    r.sync("P", "W", "b1", "b2")
    r.unit("b2", "b2 writes")
    r.heal("b2", "b2 heals")
    r.sync("P", "W", "b1", "b2")
    revoke = pb.revoke("b1", "b2", "b1 revokes b2 in B's list")
    r.unit("b2", "b2 writes before anyone in the space hears")
    r.sync("P", "W", "b2")
    before_response = r.all()
    r.heal("W", "W rotates in response to the revocation", refs=[(pb.id, revoke)])
    r.unit("b2", "b2 writes after the response, apart", view=before_response)
    r.sync("P", "W", "b1", "b2")
    full = {pb.id: pb.resolve()}
    e = case("a person grant, a revocation in the list, and the space's response", r,
             {"all": r.all()}, lists=full,
             shape="checks across logs: a list revocation ends a device's writes once a "
                   "writer of the space responds",
             checks={"all": lambda sp, s: s["events"]["b2 writes"] == "valid"
                     and s["events"]["b2 writes before anyone in the space hears"] == "valid"
                     and s["events"]["b2 writes after the response, apart"].startswith(
                         "RefusedAfterResponse")})
    e["lists"] = {"person B": pb.hist.describe()}
    sp_before = r.resolve(before_response, {pb.id: pb.resolve(pb.log.anc[revoke])})
    e["before the revocation, with the list as it was"] = with_lists(
        r, r.summary(sp_before, extra=False), {pb.id: pb.resolve(pb.log.anc[revoke])})
    e["without B's list"] = with_lists(r, r.summary(r.resolve(before_response, {}), extra=False),
                                       {})
    assert e["without B's list"]["events"]["b2 writes"] == "Pending"
    assert e["without B's list"]["events"]["b2 heals"] == "NoHybridKey"

    pt = person("p1", "roster/space/person", linear=True)
    # The team's rotations commit to real grant keys, so that the project's
    # response can carry a notice of the team's removal (keys.md, step 8).
    team = Roster("T0", "roster/space/team", grant_keys=True)
    team.persons[pt.id] = "person in T"
    team.grant("T0", "person in T", WRITE, label="T0 grants a person write")
    team.grant("T0", "t1", WRITE)
    team.grant("T0", "guest", WRITE, FROM_NOW_ON, session=example("roster/session")[:16],
               label="T0 grants guest write for a session")
    team.sync("T0", "t1", "guest")
    r = Roster("P", "roster/space/project",
               keys={**{n: team.hist.seed(n) for n in ("t1", "guest", "T0")},
                     "p1": pt.hist.seed("p1")})
    r.spaces[team.id] = "team T"
    r.grant("P", "team T", WRITE, label="P grants team T write")
    r.grant("P", "T0", WRITE, label="P grants T0 write")
    r.sync("P", "t1", "guest", "T0")
    r.unit("t1", "t1 writes through team T")
    r.unit("guest", "the team's guest writes")
    r.sync("P", "p1")
    r.unit("p1", "p1, through the team's person grant, writes")
    r.sync("P", "t1", "guest", "p1")
    tr = team.remove("T0", "t1", "T0 removes t1 from the team")
    before = set(r.hist.view["t1"])
    # T0, a member of both spaces, responds: a grant rotation whose refs
    # name the team's removal, with a notice of it.
    r.sync("P", "T0")
    r.heal("T0", "T0 rotates in response to the team's removal", refs=[(team.id, tr)],
           notices=[team.notice(tr)])
    r.unit("t1", "t1 writes, not having heard", view=before)
    r.sync("P", "t1", "guest", "p1")
    sp_team = team.resolve(None, {pt.id: pt.resolve()})
    e = case("a granted space: inheritance, guests, and a removal in the team", r,
             {"all": r.all()}, spaces_={team.id: sp_team},
             shape="frontiers in an inheriting space: the response's past",
             checks={"all": lambda sp, s: s["events"]["t1 writes through team T"] == "valid"
                     and s["events"]["T0 rotates in response to the team's removal"] == "valid"
                     and s["events"]["p1, through the team's person grant, writes"] == "valid"
                     and s["events"]["the team's guest writes"] == "NotAWriter"
                     and s["events"]["t1 writes, not having heard"].startswith(
                         "RefusedAfterResponse")})
    e["team"] = team.hist.describe()
    e["team_prefix"] = team.prefix
    e["lists"] = {"person in T": pt.hist.describe()}
    e["list_prefixes"] = {"person in T": pt.prefix}
    sp = r.resolve(None, None, {team.id: sp_team})
    k = r.hist.by_name("T0 rotates in response to the team's removal")
    f = sp.heads_of([team.hist.device("t1")], r.log.anc[k])
    e["cascade_frontier"] = {"response": r.name(k),
                             "heads": {"t1": r.name(f[team.hist.device("t1")])}}

    team2 = Roster("T0", "roster/space/team2")
    team2.grant("T0", "t1", WRITE)
    team2.grant("T0", "t3", WRITE)
    r2 = Roster("P", "roster/space/removal", keys={n: team2.hist.seed(n) for n in ("t1", "t3")})
    r2.spaces[team2.id] = "team T"
    r2.grant("P", "team T", WRITE, label="P grants team T write")
    r2.grant("P", "t3", WRITE, label="P grants t3 write directly")
    r2.sync("P", "t1", "t3")
    r2.unit("t1", "t1 writes through T")
    r2.unit("t3", "t3 writes")
    r2.sync("P", "t1", "t3")
    r2.remove("P", "team T", "P removes team T")
    r2.unit("t1", "t1 writes, apart")
    r2.unit("t3", "t3 writes, apart")
    r2.sync("P", "t1", "t3")
    e = case("removing a granted space: members granted directly keep writing", r2,
             {"all": r2.all()}, spaces_={team2.id: team2.resolve()},
             checks={"all": lambda sp, s: s["events"]["t1 writes, apart"].startswith(
                 "RefusedByRemoval") and s["events"]["t3 writes, apart"] == "valid"
                 and s["frontiers"]["P removes team T"]["heads"] == {
                     "t1": "t1 writes through T", "t3": "t3 writes"}})
    e["team"] = team2.hist.describe()
    e["team_prefix"] = team2.prefix

    # A device's highest level in the team and its highest over the paths
    # that propagate there are kept apart (section 3.3): g1 is a guest at
    # write and reaches the team at read through person H, g2 a guest at
    # read and at write through person I. The project grants the team at
    # write, so g1 reaches it at read, and g2 at write.
    ph = person("g1", "roster/propagating/person-h", linear=True)
    pi = person("g2", "roster/propagating/person-i", linear=True)
    team3 = Roster("T0", "roster/propagating/team",
                   keys={"g1": ph.hist.seed("g1"), "g2": pi.hist.seed("g2")})
    team3.persons[ph.id], team3.persons[pi.id] = "person H", "person I"
    team3.grant("T0", "g1", WRITE, FROM_NOW_ON, label="T0 grants g1 write for a session",
                session=example("roster/propagating/session-1")[:16])
    team3.grant("T0", "person H", READ, label="T0 grants person H read")
    team3.grant("T0", "g2", READ, FROM_NOW_ON, label="T0 grants g2 read for a session",
                session=example("roster/propagating/session-2")[:16])
    team3.grant("T0", "person I", WRITE, label="T0 grants person I write")
    lists3 = {ph.id: ph.resolve(), pi.id: pi.resolve()}
    sp_team3 = team3.resolve(None, lists3)
    r3 = Roster("P", "roster/propagating/project",
                keys={"g1": ph.hist.seed("g1"), "g2": pi.hist.seed("g2"),
                      "T0": team3.hist.seed("T0")})
    r3.spaces[team3.id] = "team T"
    r3.grant("P", "team T", WRITE, label="P grants team T write")
    r3.sync("P", "g1", "g2", "T0")
    r3.unit("g2", "g2, at write through person I, writes")
    r3.unit("g1", "g1, at read through person H, writes")
    r3.sync("P", "g1", "g2", "T0")
    e = case("a guest of a granted team that also reaches it through a person", r3,
             {"all": r3.all()}, spaces_={team3.id: sp_team3},
             notes="effective gives the project's effective membership at its merged "
                   "roster: each device's highest level, and its highest over the paths that "
                   "propagate.",
             checks={"all": lambda sp, s: s["events"]["g2, at write through person I, writes"]
                     == "valid" and s["events"]["g1, at read through person H, writes"]
                     == "NotAWriter"})
    e["team"] = team3.hist.describe()
    e["team_prefix"] = team3.prefix
    e["lists"] = {"person H": ph.hist.describe(), "person I": pi.hist.describe()}
    e["list_prefixes"] = {"person H": ph.prefix, "person I": pi.prefix}
    eff = r3.resolve(None, None, {team3.id: sp_team3})
    e["effective"] = {
        r3.hist.key_name(d): {"level": LEVEL_NAMES[lv],
                              "propagating_level": None if prop is None else LEVEL_NAMES[prop]}
        for d, (lv, prop) in sorted(eff.effective(eff.valid_roster).items())}
    assert e["effective"]["g1"] == {"level": "read", "propagating_level": "read"}, e["effective"]
    assert e["effective"]["g2"] == {"level": "write", "propagating_level": "write"}
    assert sp_team3.effective(sp_team3.valid_roster)[team3.hist.device("g1")] == (WRITE, READ)

    old = person("o1", "roster/replace/old", linear=True)
    new = person("n1", "roster/replace/new", linear=True)
    r = Roster("P", "roster/replace", keys={"o1": old.hist.seed("o1"), "n1": new.hist.seed("n1")})
    r.persons[old.id], r.persons[new.id] = "person O", "person O'"
    r.grant("P", "person O", WRITE, label="P grants person O write")
    r.grant("P", "o1", ADMINISTER, label="P grants o1 administer")
    r.sync("P", "o1", "n1")
    stolen = set(r.hist.view["o1"])
    r.act("P", [Change(REMOVE, (PERSON, old.id)),
                Change(GRANT, (PERSON, new.id), WRITE, None, None, WITH_HISTORY, VIA_CODE,
                       None, old.id)], "P replaces person O with person O'")
    r.remove("P", "o1", "P removes o1, O's administering device")
    r.unit("o1", "o1, stolen, writes", view=stolen)
    r.sync("P", "o1", "n1")
    r.unit("n1", "n1 writes")
    r.sync("P", "o1", "n1")
    e = case("social recovery: replace, and the old person's administering device", r,
             {"all": r.all()}, lists={old.id: old.resolve(), new.id: new.resolve()},
             checks={"all": lambda sp, s: removed(s, "person O", "o1")
                     and s["roster"]["person O'"]["replaces"] == "person O"
                     and s["events"]["n1 writes"] == "valid"
                     and s["events"]["o1, stolen, writes"].startswith("RefusedByRemoval")})
    e["lists"] = {"person O": old.hist.describe(), "person O'": new.hist.describe()}

    r = setup([("P", ADMINISTER), ("M", WRITE)], "roster/anchor")
    r.unit("M", "M writes")
    r.anchor("M", "M anchors")
    stranger = r.anchor("stranger", "a stranger anchors", view=set(r.hist.view["M"]))
    r.hist.uncitable.add(stranger)  # dropped: never a parent
    r.hist.act("stranger", 70, b"ignorable", "a stranger's event of kind 70",
               view=set(r.hist.view["M"]))
    r.hist.act("M", 70, b"ignorable", "M's event of kind 70")
    r.sync(*r.everyone())
    r.unit("P", "P writes after holding the stranger's events")
    case("anchors and ignorable events from a member and from a stranger", r, {"all": r.all()},
         checks={"all": lambda sp, s: s["events"]["M anchors"] == "valid (kept)"
                 and s["events"]["a stranger anchors"] == "Dropped"
                 and s["events"]["a stranger's event of kind 70"] == "Dropped"
                 and s["events"]["M's event of kind 70"] == "valid (kept)"},
         notes="A stranger's anchor is never verified: no record carries keys that hash to its "
               "kc, so it is dropped, and it is never cited (P's later unit does not name it). "
               "An ignorable kind from a device no record names is dropped too.")

    # Device keys bound by their hash (section 2.4; crypto.md, "Keys by their
    # hash"). An adversary that signs Ed25519 for P's key, and holds an
    # ML-DSA-65 key of its own, but not P's: its key set (P's Ed25519 key,
    # its ML-DSA-65 key, P's X-Wing key) has a kc and a device ID of its own.
    def lent(hist, name: str, victim: str, mldsa_seed: bytes, own_kc: bool = True):
        """The key holder `name`: `victim`'s Ed25519 seed beside another
        ML-DSA-65 seed and `victim`'s X-Wing key. With own_kc false its
        events name `victim`'s kc, so their ML-DSA-65 half is not the one
        that kc commits to."""
        v = hist.signer(victim)
        holder = hs.Signer(name, v.ed_seed, mldsa_seed, xwing_public=v.xwing_public)
        if not own_kc:
            holder = copy.copy(holder)
            holder.kc, holder.device_id = v.kc, v.device_id
        hist.keys[name] = v.ed_seed
        hist.signers[name] = holder
        hist.view[name] = set()
        return holder

    def lent_grant(holder, level: int = ADMINISTER) -> Change:
        return Change(GRANT, (DEVICE, holder.device_id), level, None, None, WITH_HISTORY,
                      VIA_CODE, None, None, holder.xwing_public, holder.mldsa_public, None,
                      holder.ed_public)

    def bound(s, pairs) -> bool:
        return all(s["events"][k] == v for k, v in pairs.items()) and "P" not in s.get(
            "forked", {})

    # A reader's event names P's Ed25519 key with the reader's own ML-DSA-65
    # key.
    r = setup([("P", ADMINISTER), ("R", READ)], "roster/bound/reader")
    other = lent(r.hist, "P's Ed25519 key, R's ML-DSA-65 key", "P", r.hist.signer("R").mldsa_seed)
    framed = lent(r.hist, "P's Ed25519 key, R's ML-DSA-65 key, P's kc", "P",
                  r.hist.signer("R").mldsa_seed, own_kc=False)
    r.act("R", [lent_grant(other)], "R grants P's Ed25519 key with its own ML-DSA-65 key",
          rotation=False)
    r.sync(*r.everyone())
    r.act(other.name, [Change(CHANGE, r.member("R"), WRITE)],
          "that key set raises R to write: another member, not P", rotation=False)
    r.hist.view[framed.name] = {r.genesis}
    r.act(framed.name, [Change(CHANGE, r.member("R"), WRITE)],
          "the same under P's own kc, at P's seq 2", rotation=False, seq=2, prev=r.genesis,
          unchecked=True)
    r.hist.view[other.name] = {r.genesis}
    r.act(other.name, [Change(CHANGE, r.member("R"), WRITE)],
          "that key set again at P's seq 2: its own chain, no fork of P", rotation=False,
          seq=2, prev=r.genesis)
    r.sync(*r.everyone())
    r.remove("P", "R", "P removes R")
    case("device keys bound by their hash: a reader's event names P's Ed25519 key with "
         "another ML-DSA-65 key", r, {"all": r.all()},
         checks={"all": lambda sp, s: bound(s, {
             "R grants P's Ed25519 key with its own ML-DSA-65 key": "NotAnAdministrator",
             "that key set raises R to write: another member, not P": "NotAnAdministrator",
             "the same under P's own kc, at P's seq 2": "BadSignature",
             "P removes R": "valid"}) and removed(s, "R")},
         notes="The reader's grant names the device ID of P's Ed25519 key, its own ML-DSA-65 "
               "key and P's X-Wing key: another member, which the grant, being void, does not "
               "admit, and which lends P no key. Events signed in full by that key set are "
               "that member's. Under P's own kc the ML-DSA-65 half does not verify "
               "(BadSignature), so a second event at a seq P used is no evidence, and P's "
               "removal of R stands.")

    # A removed member's rotating event does the same.
    r = setup([("P", ADMINISTER), ("Q", ADMINISTER)], "roster/bound/removed")
    other = lent(r.hist, "P's Ed25519 key, Q's ML-DSA-65 key", "P", r.hist.signer("Q").mldsa_seed)
    framed = lent(r.hist, "P's Ed25519 key, Q's ML-DSA-65 key, P's kc", "P",
                  r.hist.signer("Q").mldsa_seed, own_kc=False)
    r.remove("P", "Q", "P removes Q")
    r.sync("P", "Q")
    r.act("Q", [lent_grant(other)], "Q, removed, rotates and grants P's Ed25519 key with its "
          "own ML-DSA-65 key")
    r.sync(*r.everyone())
    r.act(other.name, [r.device_grant("Q", WRITE)],
          "that key set re-admits Q at write: another member, not P")
    r.hist.view[framed.name] = set(r.hist.view[other.name])
    r.act(framed.name, [r.device_grant("Q", WRITE)], "the same under P's own kc",
          unchecked=True)
    case("device keys bound by their hash: a removed member's rotation names P's Ed25519 key "
         "with another ML-DSA-65 key", r, {"all": r.all()},
         checks={"all": lambda sp, s: bound(s, {
             "Q, removed, rotates and grants P's Ed25519 key with its own ML-DSA-65 key":
                 "NotAnAdministrator",
             "that key set re-admits Q at write: another member, not P": "NotAnAdministrator",
             "the same under P's own kc": "BadSignature"}) and removed(s, "Q")})

    # A person's own list names P's Ed25519 key with another ML-DSA-65 key.
    pa = person("laptop", "roster/bound/list/person", linear=True)
    r = Roster("P", "roster/bound/list")
    other = lent(r.hist, "P's Ed25519 key, the person's ML-DSA-65 key", "P",
                 pa.hist.signer("laptop").mldsa_seed)
    framed = lent(r.hist, "P's Ed25519 key, the person's ML-DSA-65 key, P's kc", "P",
                  pa.hist.signer("laptop").mldsa_seed, own_kc=False)
    statement = identity.possession_statement(pa.id, pa.hist.device("laptop"), identity.DEVICE,
                                              other.ed_public, other.mldsa_public,
                                              other.xwing_public)
    pa.raw("laptop", identity.list_body(
        identity.ADD, identity.DEVICE, other.device_id, identity=other.ed_public,
        possession=identity.prove(other, statement), xwing=other.xwing_public,
        mldsa_public=other.mldsa_public), "laptop adds P's Ed25519 key with its own ML-DSA-65 key")
    r.persons[pa.id] = "person A"
    r.grant("P", "person A", WRITE, label="P grants person A write",
            refs=Roster.heads_ref(pa.id, pa.log))
    r.sync(*r.everyone())
    r.set_policy(other.name, {"forbid_agents": True},
                 "that key set changes the policy: person A's device, not P")
    r.set_policy(framed.name, {"forbid_agents": True}, "the same under P's own kc",
                 unchecked=True)
    e = case("device keys bound by their hash: a person's own list names P's Ed25519 key with "
             "another ML-DSA-65 key", r, {"all": r.all()}, lists={pa.id: pa.resolve()},
             checks={"all": lambda sp, s: bound(s, {
                 "that key set changes the policy: person A's device, not P":
                     "NotAnAdministrator",
                 "the same under P's own kc": "BadSignature"})},
             notes="The list's add is valid in person A's list and names a device ID of its "
                   "own. The space takes that device's keys from the list by their hash: "
                   "it writes as a device of person A and administers nothing. No key the "
                   "list carries hashes to P's kc, so the event under P's kc is "
                   "BadSignature.")
    e["lists"] = {"person A": pa.hist.describe()}

    # The waiting device.
    pa = person("laptop", "roster/waiting/list", linear=True)
    pa.add("laptop", "agent", identity.AGENT)
    pa.add("agent", "helped", identity.DEVICE, "agent adds helped")
    r = Roster("P", "roster/waiting", keys={"helped": pa.hist.seed("helped")})
    r.persons[pa.id] = "person A"
    r.grant("P", "person A", WRITE, label="P grants person A write")
    r.sync("P", "helped")
    r.heal("helped", "helped, waiting, rotates")
    r.unit("helped", "helped, waiting, writes")
    r.sync("P", "helped")
    before_confirm = {pa.id: pa.resolve()}
    pa.confirm("laptop", "helped", "laptop confirms helped")
    e = case("a device rooted in an agent writes, and makes no key event until confirmed", r,
             {"all": r.all()}, lists=before_confirm,
             checks={"all": lambda sp, s: s["events"]["helped, waiting, rotates"]
                     == "WaitingDevice" and s["events"]["helped, waiting, writes"] == "valid"},
             notes="Its units are accepted: they choose no key. Its key events are void "
                   "(WaitingDevice) until a confirm of it is in the person's merged list.")
    e["lists"] = {"person A": pa.hist.describe()}
    e["after the confirm"] = with_lists(
        r, r.summary(r.resolve(None, {pa.id: pa.resolve()}), extra=False), {pa.id: pa.resolve()})
    assert e["after the confirm"]["events"]["helped, waiting, rotates"] == "valid"

    # A path through a granted space is waiting when every path the device
    # has into that space is (section 3.10, step 3): helped sits in team T
    # only through person A's grant, so it waits in the project too, until
    # the team grants it directly.
    pw = person("laptop", "roster/waiting-team/list", linear=True)
    pw.add("laptop", "agent", identity.AGENT)
    pw.add("agent", "helped", identity.DEVICE, "agent adds helped")
    team4 = Roster("T0", "roster/waiting-team/team", keys={"helped": pw.hist.seed("helped")})
    team4.persons[pw.id] = "person A"
    team4.grant("T0", "person A", WRITE, label="T0 grants person A write")
    before_direct = set(team4.log.events)
    team4.grant("T0", "helped", WRITE, label="T0 grants helped write directly")
    lists4 = {pw.id: pw.resolve()}
    r = Roster("P", "roster/waiting-team/project",
               keys={"helped": pw.hist.seed("helped"), "T0": team4.hist.seed("T0")})
    r.spaces[team4.id] = "team T"
    r.grant("P", "team T", WRITE, label="P grants team T write")
    r.sync("P", "helped")
    r.heal("helped", "helped, waiting in the team, rotates")
    r.unit("helped", "helped, waiting in the team, writes")
    r.sync("P", "helped")
    views4 = {"before the team grants helped directly":
              {team4.id: team4.resolve(before_direct, lists4)},
              "after the team grants helped directly": {team4.id: team4.resolve(None, lists4)}}
    e = case("a device rooted in an agent that reaches the space only through a granted team",
             r, {v: r.all() for v in views4}, spaces_by_view=views4,
             checks={"before the team grants helped directly": lambda sp, s:
                     s["events"]["helped, waiting in the team, rotates"] == "WaitingDevice"
                     and s["events"]["helped, waiting in the team, writes"] == "valid",
                     "after the team grants helped directly": lambda sp, s:
                     s["events"]["helped, waiting in the team, rotates"] == "valid"},
             notes="Its only path is the team, and its only path into the team is person A's "
                   "grant, whose list holds it as rooted in the agent and not confirmed: the "
                   "team's path waits as the person's does. A device grant in the team lifts "
                   "it.")
    e["team"] = team4.hist.describe()
    e["team_prefix"] = team4.prefix
    e["lists"] = {"person A": pw.hist.describe()}
    for vname, held in views4.items():
        e["views"][vname]["team_held"] = (
            "every event" if set(held[team4.id].view) == team4.all()
            else [team4.name(i) for i in team4.log.canonical(held[team4.id].view)])

    # A fork in a person's list ends the device's writes once the space responds.
    pf = person("f1", "roster/fork/list", linear=True)
    pf.add("f1", "f2", identity.DEVICE)
    pf.hist.view["f2"] = set(pf.log.events)
    backup = set(pf.hist.view["f2"])
    pf.linear = False
    pf.add("f2", "f3", identity.DEVICE, "f2 adds f3")
    pf.hist.view["f2"] = backup
    pf.add("f2", "f4", identity.DEVICE, "f2, restored, adds f4 at the same seq")
    lst = pf.resolve()
    end = lst.ends(pf.hist.device("f2"))[-1]
    r = Roster("P", "roster/fork", keys={"f2": pf.hist.seed("f2")})
    r.persons[pf.id] = "person F"
    r.grant("P", "W", WRITE)
    r.grant("P", "person F", WRITE, label="P grants person F write")
    r.sync("P", "W", "f2")
    r.unit("f2", "f2 writes")
    r.sync("P", "W", "f2")
    before = set(r.hist.view["f2"])
    r.heal("W", "W responds to f2's fork", refs=[(pf.id, end)])
    r.unit("f2", "f2 writes, apart", view=before)
    r.sync("P", "W", "f2")
    e = case("a device that forks in its list loses its writes once the space responds", r,
             {"all": r.all()}, lists={pf.id: lst},
             checks={"all": lambda sp, s: s["events"]["f2 writes"] == "valid"
                     and s["events"]["f2 writes, apart"].startswith("RefusedAfterResponse")},
             notes="The end of a fork is the canonically later event of the evidence that "
                   "fixes its fork point.")
    e["lists"] = {"person F": pf.hist.describe()}
    e["fork_end"] = pf.hist.name(end)

    # A ref to an event of the person's list this replica does not hold: the
    # referring event waits, and nothing else does.
    pr = person("g1", "roster/refs/list", linear=True)
    pr.add("g1", "g2", identity.DEVICE)
    held = set(pr.log.events)
    rev = pr.revoke("g1", "g2", "g1 revokes g2")
    r = Roster("P", "roster/refs", keys={"g2": pr.hist.seed("g2")})
    r.persons[pr.id] = "person G"
    r.grant("P", "W", WRITE)
    r.grant("P", "X", WRITE)
    r.grant("P", "person G", WRITE, label="P grants person G write")
    r.sync("P", "W", "X", "g2")
    r.remove("P", "X", "P removes X")
    r.sync("P", "X")
    bogus = r.heal("X", "removed X cites an event person G's list never had",
                   refs=[(pr.id, example("roster/refs/no-such-event"))])
    r.hist.uncitable.add(bogus)  # nobody honest cites what it holds pending
    r.heal("W", "W responds to g2's revocation", refs=[(pr.id, rev)])
    r.unit("g2", "g2 writes, apart", view=set(r.hist.view["g2"]))
    r.sync("P", "W", "g2")
    e = case("a ref this replica cannot resolve holds the referring event, and nothing else", r,
             {"all": r.all()}, lists={pr.id: pr.resolve(held)},
             checks={"all": lambda sp, s:
                     s["events"]["W responds to g2's revocation"] == "Pending"
                     and s["events"]["removed X cites an event person G's list never had"]
                     == "Pending"
                     and s["events"]["g2 writes, apart"] == "valid"},
             notes="Without the revocation the replica judges as one that never received the "
                   "response, and fetches what it names from W. The removed "
                   "device's ref to an event that does not exist holds its own event for good, "
                   "and no other path.")
    e["lists"] = {"person G": pr.hist.describe()}
    e["with the revocation"] = with_lists(
        r, r.summary(r.resolve(None, {pr.id: pr.resolve()}), extra=False), {pr.id: pr.resolve()})
    assert e["with the revocation"]["events"]["g2 writes, apart"].startswith("RefusedAfterResponse")
    assert e["with the revocation"]["events"][
        "removed X cites an event person G's list never had"] == "Pending"

    # A grant carries the heads of the other log its author holds: an end
    # already in that past needs no response.
    ph = person("h1", "roster/known/list", linear=True)
    ph.add("h1", "h2", identity.DEVICE)
    ph.revoke("h1", "h2", "h1 revokes h2")
    for with_refs in (True, False):
        r = Roster("P", f"roster/known/{'refs' if with_refs else 'bare'}",
                   keys={"h2": ph.hist.seed("h2")})
        r.persons[ph.id] = "person H"
        refs = Roster.heads_ref(ph.id, ph.log) if with_refs else ()
        r.grant("P", "person H", WRITE, label="P grants person H write, citing H's list"
                if with_refs else "P grants person H write, citing nothing", refs=refs)
        r.sync("P", "h2")
        r.unit("h2", "h2, revoked before the grant, writes")
        r.sync("P", "h2")
        want = "RefusedAfterResponse" if with_refs else "valid"
        e = case("a device revoked before its person's grant" + (
                 ": the grant carries the list's heads" if with_refs else
                 ": a grant that carries nothing"), r, {"all": r.all()},
                 lists={ph.id: ph.resolve()},
                 checks={"all": lambda sp, s, w=want:
                         s["events"]["h2, revoked before the grant, writes"].startswith(w)},
                 notes="A grant's refs give the space the list as its author held it: a "
                       "revocation in that past is answered by the grant itself. A grant that "
                       "carries none leaves the device writing until a response, the "
                       "eventual-removal limit.")
        e["lists"] = {"person H": ph.hist.describe()}

    team = Roster("T0", "roster/known/team")
    team.grant("T0", "t1", WRITE)
    team.sync("T0", "t1")
    team.remove("T0", "t1", "T0 removes t1 from the team")
    r = Roster("P", "roster/known/project", keys={"t1": team.hist.seed("t1")})
    r.spaces[team.id] = "team T"
    r.grant("P", "team T", WRITE, label="P grants team T write, citing T's log",
            refs=Roster.heads_ref(team.id, team.log))
    r.sync("P", "t1")
    r.unit("t1", "t1, removed from the team before the grant, writes")
    r.sync("P", "t1")
    e = case("a device that left a granted team before the grant", r, {"all": r.all()},
             spaces_={team.id: team.resolve()},
             checks={"all": lambda sp, s: s["events"][
                 "t1, removed from the team before the grant, writes"].startswith(
                 "RefusedAfterResponse")},
             notes="The grant's refs name the team's heads; t1's removal is in their past.")
    e["team"] = team.hist.describe()
    e["team_prefix"] = team.prefix

    # A notice decides no verdict (keys.md, "Notices and space principals"):
    # the same events at a replica that holds the team's log as T0 does, at
    # one that also holds A2's concurrent removal of T0, which voids T0's
    # removal of t1 there, and at one that holds none of the team's log.
    team = Roster("T0", "roster/notices/team", grant_keys=True)
    team.grant("T0", "A2", ADMINISTER)
    team.grant("T0", "t1", WRITE)
    team.sync("T0", "A2", "t1")
    tr = team.remove("T0", "t1", "T0 removes t1 from the team")
    team.remove("A2", "T0", "A2 removes T0 from the team, concurrently")
    as_t0 = set(team.hist.view["T0"])
    r = Roster("P", "roster/notices/project", keys={"T0": team.hist.seed("T0")})
    r.spaces[team.id] = "team T"
    r.grant("P", "T0", WRITE, label="P grants T0 write")
    r.grant("P", "W", WRITE, label="P grants W write")
    r.sync("P", "T0", "W")
    r.grant("P", "team T", WRITE, label="P grants team T write, with a notice P cannot give",
            notices=[team.notice(team.id)])
    r.sync("P", "T0", "W")
    r.heal("T0", "T0 responds to the team's removal, with its notice", refs=[(team.id, tr)],
           notices=[team.notice(tr)])
    r.sync("T0", "W")
    r.heal("W", "W responds with a notice of a key the team did not commit to",
           refs=[(team.id, tr)], notices=[{**team.notice(tr), "public": team.grant_public[team.id]}])
    r.deliver("W", "W cites the team's removal with no notice", refs=[(team.id, tr)])
    r.sync("P", "T0", "W")
    views = {"with the team's log as T0 holds it": {team.id: team.resolve(as_t0)},
             "with the team's log in full": {team.id: team.resolve()},
             "without the team's log": {}}
    statuses = {}

    def same_verdicts(vname):
        def check(sp, s):
            statuses[vname] = s["events"]
            return True
        return check
    e = case("a notice decides no verdict", r, {v: r.all() for v in views},
             spaces_by_view=views, checks={v: same_verdicts(v) for v in views},
             notes="Each view holds every event of the project. The response's notice "
                   "admits a principal only where the team's log holds T0's removal of t1 as "
                   "valid; the other notices admit nothing anywhere. Verdicts agree in "
                   "every view that holds the cited events; the view without the team's log "
                   "holds the responses Pending until it fetches them.")
    names = {team.id: "team T"}
    for vname, held in views.items():
        sp = r.resolve(r.all(), None, held)
        e["views"][vname]["team_held"] = (
            [] if not held else "every event" if set(held[team.id].view) == team.all()
            else [team.name(i) for i in team.log.canonical(held[team.id].view)])
        e["views"][vname]["principals"] = [f"{names[s]}@{team.name(rot)}"
                                           for s, rot in sp.principals()]
    with_t0, full, none = (statuses[v] for v in views)
    assert with_t0 == full, (with_t0, full)
    assert with_t0["P grants team T write, with a notice P cannot give"] == "valid"
    assert none["P grants team T write, with a notice P cannot give"] == "valid"
    assert with_t0["T0 responds to the team's removal, with its notice"] == "valid"
    assert with_t0["W responds with a notice of a key the team did not commit to"] == "valid"
    assert with_t0["W cites the team's removal with no notice"] == "NoticeRequired"
    assert e["views"]["with the team's log as T0 holds it"]["principals"] == [
        "team T@T0 removes t1 from the team"]
    assert e["views"]["with the team's log in full"]["principals"] == []
    assert e["views"]["without the team's log"]["principals"] == []
    e["team"] = team.hist.describe()
    e["team_prefix"] = team.prefix

    # Two responses that end each other's author: decided once, in canonical
    # order, counting only responses decided before.
    pa = person("a1", "roster/mutual/A", linear=True)
    pa.add("a1", "a2", identity.DEVICE)
    xa = pa.revoke("a1", "a2", "a1 revokes a2")
    pb2 = person("b1", "roster/mutual/B", linear=True)
    pb2.add("b1", "b2", identity.DEVICE)
    xb = pb2.revoke("b1", "b2", "b1 revokes b2")
    r = Roster("P", "roster/mutual", keys={"a2": pa.hist.seed("a2"), "b2": pb2.hist.seed("b2")})
    r.persons[pa.id] = "person A"
    r.persons[pb2.id] = "person B"
    r.grant("P", "person A", WRITE, label="P grants person A write")
    r.grant("P", "person B", WRITE, label="P grants person B write")
    r.sync("P", "a2", "b2")
    ka = r.heal("a2", "a2 responds to b2's revocation", refs=[(pb2.id, xb)])
    kb = r.heal("b2", "b2 responds to a2's revocation", refs=[(pa.id, xa)])
    r.sync("P", "a2", "b2")
    mutual_lists = {pa.id: pa.resolve(), pb2.id: pb2.resolve()}
    first, second = sorted((ka, kb), key=r.log.order_key)
    e = case("two key events that each respond to the end of the other's author", r,
             {"all": r.all()}, lists=mutual_lists,
             checks={"all": lambda sp, s: sp.status[first][0]
                     and sp.status[second][1] == "RefusedAfterResponse"},
             notes="Judged by a fixed point, the two would refuse each other, then neither, "
                   "then both again. Each key event counts as responses only events decided "
                   "valid before it in canonical order, so the first stands and refuses the "
                   "second, at every replica.")
    e["lists"] = {"person A": pa.hist.describe(), "person B": pb2.hist.describe()}
    e["decided"] = {"first": r.name(first), "second": r.name(second)}

    # Full counts only valid roster events (with the limit lowered for the vector).
    r = setup([("P", ADMINISTER), ("M", WRITE)], "roster/full")
    for n in range(4):
        r.act("M", [Change(REMOVE, r.member("P"))], f"M's junk roster event {n}")
    r.sync(*r.everyone())
    r.grant("P", "H", WRITE, label="P grants H")
    r.grant("P", "J", WRITE, label="P grants J")
    saved = globals()["MAX_ROSTER_EVENTS"]
    globals()["MAX_ROSTER_EVENTS"] = 3
    try:
        e = case("junk roster events do not fill the roster (limit lowered to 3 here)", r,
                 {"all": r.all()},
                 checks={"all": lambda sp, s: s["events"]["P grants H"] == "valid"
                         and s["events"]["P grants J"] == "Full"},
                 notes="The limit counts valid roster events in the valid past, "
                       "so a writer's four void roster events count for nothing; with the "
                       "limit set to 3 for this vector, the genesis and two valid grants "
                       "fill it, and the third grant is Full.")
    finally:
        globals()["MAX_ROSTER_EVENTS"] = saved
    e["limit_for_this_vector"] = 3

    # Invites.
    r, inv = _invite_base("roster/invite-closed")
    before = set(r.hist.view["I"])
    r.persons[example("roster/bob")] = "Bob"
    r.persons[example("roster/carol")] = "Carol"
    honest = _claim(r, "I", "roster/bob", "Bob claims")
    r.sync("P", "I")
    close = r.act("P", [Change(REMOVE, (INVITE, inv.device_id))], "P closes the invite",
                  rotation=False)  # a close takes nothing from anyone: it need not rotate
    late = _claim(r, "I", "roster/carol", "Carol claims late, backdated", view=before)
    case("a late backdated claim after a close: void, and the honest claimant stands", r,
         {"all": r.all(), "before the close": r.all() - {close}},
         checks={"all": lambda sp, s: sp.status[honest][0] and sp.status[close][0]
                 and sp.status[late][1] == "RemovedConcurrently",
                 "before the close": lambda sp, s: sp.status[honest][1] == "ClaimRaced"
                 and sp.status[late][1] == "ClaimRaced"},
         notes="The inviter closes its invite "
               "once it holds a valid successor. A claim concurrent with the close is void "
               "by attack (a), so it races nothing. A replica that holds the late claim but "
               "not yet the close voids both until the close arrives.")
    r, inv = _invite_base("roster/invite-raced")
    before = set(r.hist.view["I"])
    r.persons[example("roster/bob")] = "Bob"
    r.persons[example("roster/carol")] = "Carol"
    honest = _claim(r, "I", "roster/bob", "Bob claims")
    late = _claim(r, "I", "roster/carol", "Carol claims late, backdated", view=before)
    r.sync("P", "I")
    after = r.act("P", [Change(REMOVE, (INVITE, inv.device_id))],
                  "P revokes the invite after seeing both claims")
    case("a late claim before any close voids both: the stated risk", r,
         {"before the revocation": r.all() - {after}, "all": r.all()},
         checks={"before the revocation": lambda sp, s: sp.status[honest][1] == "ClaimRaced"
                 and sp.status[late][1] == "ClaimRaced",
                 "all": lambda sp, s: sp.status[honest][1] == "ClaimRaced"
                 and sp.status[after][0]},
         notes="Until the inviter closes, a holder of the secret that claims "
               "concurrently voids the honest claim too. A close signed after both claims "
               "is concurrent with neither, so both stay void; it is then a revocation.")
    r, inv = _invite_base("roster/invite-resubmit", claims=DEVICE)
    before = set(r.hist.view["I"])
    r.hist.device("D")
    honest = _claim(r, "I", "D", "D claims for itself")
    r.sync("I", "D")
    u = r.unit("D", "D writes through its claim")
    late = _claim(r, "I", "roster/mallory", "a late claim, backdated", view=before)
    r.sync("P", "I", "D")
    regrant = r.grant("P", "D", WRITE, label="P grants D write directly")
    case("re-submission covers units refused as NotAWriter through a voided grant", r,
         {"all": r.all()},
         checks={"all": lambda sp, s: sp.status[u][1] == "NotAWriter"
                 and sp.status[regrant][0] and sp.resubmissions() == {
                     r.hist.device("D"): [u]}},
         notes="D wrote through its successor, which a raced claim voided, so "
               "its unit is NotAWriter; once D writes again it re-submits the unit.")

    # A unit refused as NotAWriter that no event voids: W, a writer, grants D
    # write, which is NotAnAdministrator, never valid and voided by nothing;
    # D writes, and is NotAWriter; P then grants D write, and D does not
    # re-submit the unit, which was never a writer's.
    r = setup([("P", ADMINISTER), ("W", WRITE)], "roster/never-voided")
    r.hist.device("D")
    bad = r.grant("W", "D", WRITE, label="W, a writer, grants D write")
    r.sync("W", "D")
    u = r.unit("D", "D writes through W's grant")
    r.sync("P", "W", "D")
    regrant = r.grant("P", "D", WRITE, label="P grants D write")
    case("a unit refused as NotAWriter that no event voids is not re-submitted", r,
         {"all": r.all()},
         checks={"all": lambda sp, s: sp.status[bad][1] == "NotAnAdministrator"
                 and sp.status[u][1] == "NotAWriter" and sp.voiders(u) == []
                 and sp.status[regrant][0] and sp.resubmissions() == {}},
         notes="Section 3.14, re-submission: D's unit has no events that void it, since "
               "the grant it wrote through was never valid rather than voided; D, a writer "
               "now, does not re-submit it, at a replica that kept everything and at one "
               "that froze the unit with no key 8 alike.")

    # Section 3.11, "A list at an event's place": persons A and B, granted
    # write. A's list adds d, and a1 copies the add into the space; d
    # writes. Then, for "moved", A revokes d and B adds it; for "second", B
    # adds it and A keeps it; each copied. d writes again. Apart, B adds e
    # and nobody copies it; e writes; the copy comes after. A replica that
    # holds every list event now reads d's first unit through A alone, and
    # e's unit has no path: a list event the unit's past does not carry
    # gives it none, for attribution and for validity alike.
    def attribution_of(r, sp, u, names):
        got = sp.attribution(u)
        return None if got is None else [
            [m[0], names.get(m[1], m[1].hex()[:12])] + m[2:] for m in got]

    for how in ("moved", "second"):
        pa = person("a1", f"roster/list-place/{how}/A", linear=True)
        pb = person("b1", f"roster/list-place/{how}/B", linear=True)
        seeds = {n: example(f"roster/list-place/{how}/{n}") for n in ("d", "e")}
        pa.hist.keys.update(seeds)
        pb.hist.keys.update(seeds)
        r = Roster("P", f"roster/list-place/{how}",
                   keys={"a1": pa.hist.seed("a1"), "b1": pb.hist.seed("b1"), **seeds})
        r.persons[pa.id], r.persons[pb.id] = "person A", "person B"
        r.grant("P", "person A", WRITE, label="P grants person A write", tag="Ann")
        r.grant("P", "person B", WRITE, label="P grants person B write", tag="Bea")
        r.sync("P", "a1", "b1")
        r.copy_list("a1", pa, [(pa.genesis, "a1", "add")], "a1 copies A's first event")
        r.copy_list("b1", pb, [(pb.genesis, "b1", "add")], "b1 copies B's first event")
        add_d = pa.add("a1", "d", identity.DEVICE, "a1 adds d to A")
        r.copy_list("a1", pa, [(add_d, "d", "add")], "a1 copies the add of d")
        r.sync("P", "a1", "b1", "d")
        u1 = r.unit("d", "d writes through A")
        r.sync("P", "a1", "b1", "d")
        if how == "moved":
            rev = pa.revoke("a1", "d", "a1 revokes d from A")
            r.copy_list("a1", pa, [(rev, "d", "revoke")], "a1 copies the revocation of d")
        add_b = pb.add("b1", "d", identity.DEVICE, "b1 adds d to B")
        r.copy_list("b1", pb, [(add_b, "d", "add")], "b1 copies the add of d")
        r.sync("P", "a1", "b1", "d")
        u2 = r.unit("d", "d writes again")
        r.sync("P", "a1", "b1", "d")
        add_e = pb.add("b1", "e", identity.DEVICE, "b1 adds e to B, copied nowhere yet")
        r.sync("P", "e")
        u3 = r.unit("e", "e writes before any copy of its add")
        r.sync("P", "b1", "e")
        r.copy_list("b1", pb, [(add_e, "e", "add")], "b1 copies the add of e, after e's unit")
        r.sync("P", "a1", "b1", "d", "e")
        lists = {pa.id: pa.resolve(), pb.id: pb.resolve()}
        names = {pa.id: "person A", pb.id: "person B", r.hist.device("d"): "d"}
        sp = r.resolve(None, lists)
        both = sorted([[PERSON, "person A", "Ann"], [PERSON, "person B", "Bea"]],
                      key=lambda m: {"person A": pa.id, "person B": pb.id}[m[1]])
        want = {"moved": ([[PERSON, "person A", "Ann"]], [[PERSON, "person B", "Bea"]]),
                "second": ([[PERSON, "person A", "Ann"]], both)}[how]
        got = (attribution_of(r, sp, u1, names), attribution_of(r, sp, u2, names))
        assert got == want, (how, got, want)
        assert sp.status[u3][1] == "NotAWriter" and sp.attribution(u3) is None, sp.status[u3]
        title = {"moved": "a device moved from one person's list to another after an edit",
                 "second": "a device added to a second person's list after an edit"}[how]
        e_ = case(title, r, {"all": r.all()}, lists=lists,
                  checks={"all": lambda sp, s: s["events"]["d writes through A"] == "valid"
                          and s["events"]["d writes again"] == "valid"
                          and s["events"]["e writes before any copy of its add"]
                          == "NotAWriter"},
                  notes="Section 3.11, \"A list at an event's place\": each unit reads a "
                        "person's list as the copies in its past carry it, so d's first unit "
                        "is attributed to A alone, though the replica now holds B's add of d, "
                        "and e's unit, whose past carries no add of e, has no path through B, "
                        "though the copy arrives later: validity and attribution read the same "
                        "place.")
        e_["attribution"] = {r.name(u): attribution_of(r, sp, u, names) for u in (u1, u2, u3)}
        e_["lists"] = {"person A": pa.hist.describe(), "person B": pb.hist.describe()}

    # A unit: refs this replica cannot resolve.
    r = setup([("P", ADMINISTER), ("W", WRITE), ("M", WRITE)], "roster/unit-refs")
    nowhere = (example("roster/unit-refs/log"), example("roster/unit-refs/event"))
    cites = r.unit("W", "W writes a unit citing an event nobody holds", refs=[nowhere])
    next_ = r.unit("W", "W writes on")
    other = r.unit("M", "M writes")
    case("a unit whose refs this replica cannot resolve holds only its own chain", r,
         {"all": r.all()},
         checks={"all": lambda sp, s: sp.status[cites][1] == "Pending"
                 and sp.status[next_][1] == "Pending" and sp.status[other][0]})
    out["cases"] = cases
    out["prefixes"] = prefixes

    # Stability.
    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE)], "roster/stability")
    rm = r.remove("P", "M", "P removes M")
    r.unit("M", "M writes, apart")
    r.sync("P", "Q", "M")
    unstable = r.all()
    r.heal("Q", "Q heals after seeing the removal")
    r.sync("P", "Q", "M")
    sp_u, sp_s = r.resolve(unstable), r.resolve()
    out["stability"] = {
        "events": r.hist.describe(), "target": r.name(rm),
        "cases": [
            {"view": "before Q signs anything after the removal",
             "holds": [r.name(i) for i in r.log.canonical(unstable)],
             "administrators": sorted(r.hist.key_name(a) for a in sp_u.administrators()),
             "stable": sp_u.stable(rm)},
            {"view": "after Q's heal", "holds": "every event",
             "administrators": sorted(r.hist.key_name(a) for a in sp_s.administrators()),
             "stable": sp_s.stable(rm)},
        ],
    }
    assert not sp_u.stable(rm) and sp_s.stable(rm)
    refused = r.hist.by_name("M writes, apart")
    out["stability"]["retention"] = [
        {"view": c, "first_seen": 1_000_000, "now": now, "gap_key_timeout": 7 * 86400,
         "may_drop": sp.may_drop(refused, 1_000_000, now)}
        for c, sp, now in (("before Q's heal, one day after", sp_u, 1_000_000 + 86400),
                           ("before Q's heal, seven days after", sp_u, 1_000_000 + 7 * 86400),
                           ("after Q's heal, at once", sp_s, 1_000_000))]
    assert [x["may_drop"] for x in out["stability"]["retention"]] == [False, True, True]

    se = space_event_vectors()
    out["space_events"] = se

    # Encodings.
    r = Roster("P", "roster/encodings", policy=spaces.encode_policy(
        {"agent_waiting_period": 96 * 3600}))
    r.hist.view["P"] = set(r.log.events)
    ids = [r.genesis,
           r.grant("P", "D", WRITE, label="P grants D write with capabilities and a label",
                   caps=(("drive", EXTENDS), ("suggest", NARROWS)), tag="operator"),
           r.grant("P", "G", WRITE, FROM_NOW_ON, session=example("roster/enc/session")[:16],
                   label="P grants a guest for a session"),
           r.change("P", "D", READ, "P demotes D to read"),
           r.set_policy("P", {"forbid_agents": True}, "P forbids recovery agents"),
           r.remove("P", "G", "P removes the guest")]
    out["encodings"] = {"space_id": h(r.id),
                        "events": [{"name": r.name(i), "body": h(r.log.events[i].body),
                                    "signed": h(r.log.events[i].signed), "id": h(i)}
                                   for i in ids]}

    # Refusals.
    negative, base = [], []

    def refuse_in(name, make, by="P", rotates=True, body=None):
        """`make` gives the roster part; `body`, when given, the whole body."""
        rr = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE)], "roster/neg")
        if not base:
            base.extend(rr.hist.describe())
        k = {n: rr.hist.device(n) for n in ("P", "Q", "M", "H")}
        rr.hist.view[by] = set(rr.log.events)
        if body is None:
            i = rr.space_event(by, "bad", make(rr, k), rotates)
        else:
            i = rr.hist.act(by, KIND_SPACE, body(rr, k), "bad")
        sp = rr.resolve()
        negative.append({"name": name, "by": by, "event": h(rr.log.events[i].signed),
                         "error": sp.status[i][1]})

    def upd(changes):
        return update_roster(changes)

    def grant_h(rr, level=WRITE, **kw):
        g = rr.device_grant("H", level, kw.get("history", WITH_HISTORY), VIA_CODE,
                            caps=kw.get("caps"), session=kw.get("session"))
        return g

    def sealed_body(rr, roster, payload=None, secret=None, nonce=None, tamper=False,
                    commitment=None):
        """A body sealed by hand, for the refusals."""
        secret = secret or example("roster/neg/content-key")
        payload = payload or {**rotation_payload(secret, "roster/neg/bad"), "always_seal": True}
        if roster is not None:
            payload = {**payload, "roster": roster}
        if commitment is not None:
            payload = {**payload, "commitment": commitment}
        if nonce is not None:
            payload = {**payload, "nonce": nonce}

        def build(log, author, seq):
            data = kg.encode_payload(payload, log, author, seq, secret,
                                     example("roster/neg/seal-nonce")[:kg.NONCE_BYTES])
            if tamper:
                sealed = kg.decode_cbor(data)[kg.P_SEALED]
                data = data.replace(sealed, sealed[:-1] + bytes([sealed[-1] ^ 1]))
            return data
        return build, secret

    def sealed_neg(name, make_body):
        """A space event whose body `make_body(rr, k)` returns (body, secret);
        the replica holds that secret as the new rotation's content key."""
        rr = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("M", WRITE)], "roster/neg")
        rr.hist.view["P"] = set(rr.log.events)
        k = {n: rr.hist.device(n) for n in ("P", "Q", "M", "H")}
        body, secret = make_body(rr, k)
        i = rr.hist.act("P", KIND_SPACE, body, "bad")
        keys = rr.keyring()
        keys.rotations[i] = secret
        sp = rr.resolve(keys=keys)
        negative.append({"name": name, "by": "P", "event": h(rr.log.events[i].signed),
                         "error": sp.status[i][1]})

    refuse_in("a roster part of type 2", lambda rr, k: cbor({0: 2, 1: []}))
    refuse_in("no changes", lambda rr, k: cbor({0: 1, 1: []}))
    refuse_in("a roster part with a key 2", lambda rr, k: cbor({0: 1, 1: [grant_h(rr).encode()],
                                                                2: b"x"}))
    refuse_in("one member twice", lambda rr, k: upd([Change(REMOVE, (DEVICE, k["M"])),
                                                     Change(REMOVE, (DEVICE, k["M"]))]))
    refuse_in("a grant without a history mode", lambda rr, k: cbor({0: 1, 1: [
        {a: b for a, b in grant_h(rr).encode().items() if a != C_HISTORY}]}))
    refuse_in("a device grant without an ML-DSA-65 key", lambda rr, k: cbor({0: 1, 1: [
        {a: b for a, b in grant_h(rr).encode().items() if a != C_MLDSA}]}))
    refuse_in("a device grant whose keys do not give its member ID: H's keys under M's "
              "device ID", lambda rr, k: cbor({0: 1, 1: [
                  {**grant_h(rr).encode(), C_MEMBER: [DEVICE, k["M"]]}]}))
    refuse_in("a device grant that names P's Ed25519 key with another ML-DSA-65 key under P's "
              "device ID", lambda rr, k: upd([Change(
                  GRANT, (DEVICE, k["P"]), WRITE, None, None, WITH_HISTORY, VIA_CODE, None, None,
                  rr.hist.xwing("P"), rr.hist.mldsa("H"), None, rr.hist.ed("P"))]))
    refuse_in("a change that changes nothing",
              lambda rr, k: cbor({0: 1, 1: [{0: CHANGE, 1: [DEVICE, k["M"]]}]}))
    refuse_in("capabilities out of order", lambda rr, k: upd([grant_h(
        rr, caps=(("suggest", NARROWS), ("drive", EXTENDS)))]))
    refuse_in("a session on a person grant", lambda rr, k: cbor({0: 1, 1: [
        {**Change(GRANT, (PERSON, example("p")), WRITE, None, None, WITH_HISTORY,
                  VIA_CODE).encode(), C_SESSION: bytes(16)}]}))
    refuse_in("a space granting itself", lambda rr, k: upd([Change(
        GRANT, (SPACE, rr.id), READ, None, None, WITH_HISTORY, VIA_NONE)]))
    refuse_in("replaces without removing the person it names", lambda rr, k: upd([Change(
        GRANT, (PERSON, example("p2")), WRITE, None, None, WITH_HISTORY, VIA_CODE, None,
        example("p1"))]))
    refuse_in("two policy changes", lambda rr, k: upd([
        Change(POLICY, policy=spaces.encode_policy({})),
        Change(POLICY, policy=spaces.encode_policy({"forbid_agents": True}))]))
    refuse_in("a policy holding a default value", lambda rr, k: upd([Change(
        POLICY, policy=cbor({1: 1, 2: 259200}))]))
    refuse_in("a device grant whose X-Wing key is not valid", lambda rr, k: upd([Change(
        GRANT, (DEVICE, k["H"]), WRITE, None, None, WITH_HISTORY, VIA_CODE, None, None,
        bytes(HYBRID_BYTES), rr.hist.mldsa("H"))]))
    refuse_in("an administer grant without a rank", lambda rr, k: upd([
        {k_: v for k_, v in grant_h(rr, ADMINISTER).encode().items() if k_ != C_RANK}]))
    refuse_in("a rank on a write grant", lambda rr, k: upd([
        {**grant_h(rr).encode(), C_RANK: 3}]))
    refuse_in("a rank above 255", lambda rr, k: upd([
        {**grant_h(rr, ADMINISTER).encode(), C_RANK: 256}]))
    refuse_in("a person granted administer", lambda rr, k: upd([Change(
        GRANT, (PERSON, example("p")), ADMINISTER, None, None, WITH_HISTORY, VIA_CODE)]))
    refuse_in("a guest granted administer",
              lambda rr, k: upd([grant_h(rr, ADMINISTER, session=bytes(16))]))
    refuse_in("a self-removal that rotates",
              lambda rr, k: upd([Change(REMOVE, (DEVICE, k["P"]))]))
    refuse_in("a writer signs a roster event", lambda rr, k: upd([grant_h(rr)]), by="M")
    refuse_in("an administrator grants itself", lambda rr, k: upd([Change(
        GRANT, (DEVICE, k["P"]), WRITE, None, None, WITH_HISTORY, VIA_CODE, None, None,
        rr.hist.xwing("P"), rr.hist.mldsa("P"))]))
    refuse_in("a grant of a member already in", lambda rr, k: upd([Change(
        GRANT, (DEVICE, k["M"]), READ, None, None, WITH_HISTORY, VIA_CODE, None, None,
        rr.hist.xwing("M"), rr.hist.mldsa("M"))]))
    refuse_in("a removal of a member not in", lambda rr, k: upd([Change(REMOVE,
                                                                        (DEVICE, k["H"]))]))
    refuse_in("an administrator raises itself", lambda rr, k: upd([Change(
        CHANGE, (DEVICE, k["P"]), None, None, "boss")]))
    refuse_in("an invite from now on that does not rotate",
              lambda rr, k: upd([_invite_grant(rr, "H", FROM_NOW_ON)]), rotates=False)
    refuse_in("an event lowering an administrator and another member",
              lambda rr, k: upd([Change(REMOVE, (DEVICE, k["Q"])),
                                 Change(REMOVE, (DEVICE, k["M"]))]))
    saved = globals()["MAX_DEVICE_GRANTS"]
    globals()["MAX_DEVICE_GRANTS"] = 1  # lowered for the vector, as Full's limit is
    try:
        refuse_in("more device grants than the limit (lowered to 1 for the vector)",
                  lambda rr, k: upd([grant_h(rr), rr.device_grant("J", WRITE)]))
    finally:
        globals()["MAX_DEVICE_GRANTS"] = saved
    refuse_in("a policy change sealed under a state a valid rotation in its past follows",
              None, body=lambda rr, k: space_body(
                  {"sealed_under": kg.encode_set([rr.genesis])}, rr.krot[rr.genesis],
                  example("roster/neg/stale/seal-nonce")[:kg.NONCE_BYTES],
                  upd([Change(POLICY, policy=spaces.encode_policy({"forbid_agents": True}))])))
    refuse_in("a delivery sealed under a state a valid rotation in its past follows", None,
              by="M", body=lambda rr, k: space_body(
                  {"sealed_under": kg.encode_set([rr.genesis])}, rr.krot[rr.genesis],
                  example("roster/neg/stale-key/seal-nonce")[:kg.NONCE_BYTES]))
    # The space event's own refusals.
    refuse_in("a space event with no sealed part", None, body=lambda rr, k: kg.encode_payload(
        rotation_payload(example("roster/neg/open"), "roster/neg/open")))
    refuse_in("a nonce outside a genesis", None, body=lambda rr, k: sealed_body(
        rr, upd([grant_h(rr)]), nonce=example("roster/neg/nonce")[:NONCE_BYTES])[0])
    sealed_neg("a commitment to another key", lambda rr, k: sealed_body(
        rr, upd([grant_h(rr)]), commitment=kg.body_commitment(example("roster/neg/other"))))
    sealed_neg("a sealed part that does not open under its key", lambda rr, k: sealed_body(
        rr, upd([grant_h(rr)]), tamper=True))
    sealed_neg("a sealed part with an unknown key 6", lambda rr, k: sealed_body(
        rr, None, payload={**rotation_payload(example("roster/neg/content-key"),
                                              "roster/neg/bad"),
                           "raw_inner": {6: kg.c_uint(1)}}))

    def outside_past(rr, k):
        # Q rotates where P cannot see it; P seals under Q's rotation anyway.
        rr.hist.view["Q"] = set(rr.log.events)
        q = rr.heal("Q", "Q heals, unseen by P")
        rr.hist.view["P"] = set(rr.log.events) - {q}
        secret = rr.krot[q]
        payload = {"sealed_under": kg.encode_set([q]), "always_seal": True,
                   "roster": upd([Change(REMOVE, (DEVICE, k["M"]))])}

        def build(log, author, seq):
            return kg.encode_payload(payload, log, author, seq,
                                     kg.content_key(rr.id, [q], rr.krot.__getitem__),
                                     example("roster/neg/seal-nonce")[:kg.NONCE_BYTES])
        return build, secret
    sealed_neg("sealed under a state not in its past", outside_past)
    # The refused geneses derive their inputs as every history does, under
    # their own prefix: <prefix>/nonce, and <prefix>/genesis/... for the
    # genesis's content key, payload and seal nonce.
    geneses = "roster/neg/genesis"
    founder_hist = History(geneses)
    founder = Change(GRANT, (DEVICE, founder_hist.device("F")), ADMINISTER, None, None,
                     WITH_HISTORY, VIA_NONE, None, None, founder_hist.xwing("F"), founder_hist.mldsa("F"))
    nonce = example(f"{geneses}/nonce")[:NONCE_BYTES]
    gsecret = example(f"{geneses}/genesis/content-key")
    gpayload = rotation_payload(gsecret, f"{geneses}/genesis")
    gseal = example(f"{geneses}/genesis/seal-nonce")[:kg.NONCE_BYTES]

    def genesis(roster, payload=gpayload, genesis_nonce=nonce):
        return space_body(payload, gsecret, gseal, roster, genesis_nonce)

    def no_nonce(log, author, seq):
        return kg.encode_payload({**gpayload, "always_seal": True,
                                  "roster": genesis_roster(founder)}, b"", author, seq, gsecret,
                                 gseal)
    for name, body in [
        ("a genesis with duel policy 1", genesis(genesis_roster(founder, duel=1))),
        ("a genesis whose policy has an unknown key 7",
         genesis(genesis_roster(founder, policy=cbor({1: 1, 7: 1})))),
        ("a genesis whose founder is another device", genesis(genesis_roster(Change(
            GRANT, (DEVICE, founder_hist.device("H")), ADMINISTER, None, None, WITH_HISTORY,
            VIA_NONE, None, None, founder_hist.xwing("H"), founder_hist.mldsa("H"))))),
        ("a genesis with an agent waiting period below 72 hours",
         genesis(genesis_roster(founder, policy=cbor({1: 1, 2: 3600})))),
        ("a genesis with no roster part", genesis(None)),
        ("a genesis without its nonce", no_nonce),
        ("a genesis that does not rotate", genesis(genesis_roster(founder), payload={
            "sealed_under": kg.encode_set([bytes(32)])})),
    ]:
        hist = History(geneses)
        gidx = hist.genesis("F", KIND_SPACE, body)
        try:
            Space(hist.log, keys=Keyring({gidx: gsecret}))
            error = "accepted"
        except SpecError as err:
            error = err.error
        negative.append({"name": name, "genesis": True, "event": h(hist.log.events[gidx].signed),
                         "error": error})
    out["negative"] = {"base": base, "cases": negative}
    return out


# roster.json's families: each history of _roster_parts by family, under the
# name roster.md's vocabulary gives it.
FAMILIES = {
    "concurrent_changes": [
        ("a removal beats a concurrent change of the same member", None),
        ("a self-demotion and a concurrent removal of its author both stand", None),
        ("two concurrent removals of one member both stand", None),
        ("a demotion beats the demoted administrator's concurrent roster actions", None),
        ("a removal and a demotion of each other: the more senior stands", None),
        ("concurrent grants of one member: the meet", None),
        ("concurrent demotions of one member: the lower level", None),
        ("a change that raises a guest to administer", None),
        ("a raise concurrent with the grant that makes its member a guest", None),
        ("a former guest re-granted without a session may be raised", None),
        ("an event that lowers an administrator names nobody else", None),
        ("'with history' ends with its grant", None),
        ("concurrent policy changes: each field's stricter value", None),
        ("junk roster events do not fill the roster (limit lowered to 3 here)", None),
    ],
    "bound_keys": [
        ("device keys bound by their hash: a reader's event names P's Ed25519 key with "
         "another ML-DSA-65 key", None),
        ("device keys bound by their hash: a removed member's rotation names P's Ed25519 key "
         "with another ML-DSA-65 key", None),
        ("device keys bound by their hash: a person's own list names P's Ed25519 key with "
         "another ML-DSA-65 key", None),
    ],
    "cycles": [
        ("an odd cycle", None),
        ("an even cycle with several answers", None),
        ("a cycle the agreement step settles, beside a reader's roster events", None),
        ("administrators granted concurrently, in an odd cycle", None),
        ("administrators granted concurrently after units, in an odd cycle, at a partial "
         "replica", None),
    ],
    "duels": [
        ("the backdated duel, senior attacker", None),
        ("the backdated duel, junior attacker", None),
        ("a genuine mutual removal", None),
        ("a lower rank acts on a higher one", None),
        ("a lower-rank thief's backdated removals", None),
        ("a counter-removal backdated before its remover's raise", None),
        ("a counter-removal in a batch, backdated before its remover's raise", None),
        ("a counter-removal of a remover and its raiser, both raised after it", None),
        ("a thief's counter-removal among events that look honest", None),
        ("an administrator's removal of a remover concurrent with its raise", None),
        ("a removed administrator that raises an accomplice to raise it back", None),
        ("concurrent self-demotions", None),
        ("a backdating attacker that keeps its chain", None),
        ("a backdating attacker that forks its chain", None),
        ("a fork cannot erase its author's self-demotion", None),
    ],
    "forks": [
        ("a backdated unit reusing a sequence number", None),
        ("a restore that writes before it syncs", None),
        ("a restore that syncs before it writes", None),
        ("a unit this replica cannot open still proves a fork", None),
    ],
    "writes": [
        ("a unit concurrent with its writer's removal", None),
        ("a unit after a re-grant", None),
        ("a device the remover never knew", None),
        ("a demotion to read refuses the member's concurrent writes", None),
    ],
    "key_histories": [
        ("a cross-removal", None),
        ("a void rotation", None),
        ("a guest from now on", None),
        ("a void input, learned late", None),
        ("a removal outside the merged state", None),
        ("one removed member alone derives the key", None),
        ("concurrent heals", None),
        ("a stale link and a 'from now on' guest", None),
        ("a with-history member after a merge with a break", None),
        ("a grant valid again misses an old merged key", None),
        ("restored, then removed again", None),
        ("history whose only holders are out", None),
    ],
    "across_logs": [
        ("a person grant, a revocation in the list, and the space's response", None),
        ("a device that forks in its list loses its writes once the space responds", None),
        ("a ref this replica cannot resolve holds the referring event, and nothing else", None),
        ("a device revoked before its person's grant: the grant carries the list's heads", None),
        ("a device revoked before its person's grant: a grant that carries nothing", None),
        ("a device that left a granted team before the grant", None),
        ("a notice decides no verdict", None),
        ("two key events that each respond to the end of the other's author", None),
        ("a device rooted in an agent writes, and makes no key event until confirmed", None),
        ("a device rooted in an agent that reaches the space only through a granted team",
         None),
        ("a granted space: inheritance, guests, and a removal in the team", None),
        ("removing a granted space: members granted directly keep writing", None),
        ("a guest of a granted team that also reaches it through a person", None),
        ("social recovery: replace, and the old person's administering device", None),
        ("anchors and ignorable events from a member and from a stranger", None),
        ("a unit whose refs this replica cannot resolve holds only its own chain", None),
        ("a unit refused as NotAWriter that no event voids is not re-submitted", None),
        ("a device moved from one person's list to another after an edit", None),
        ("a device added to a second person's list after an edit", None),
    ],
}
# ext-invite-links.json's histories that roster.py builds.
INVITE_CASES = [
    "a late backdated claim after a close: void, and the honest claimant stands",
    "a late claim before any close voids both: the stated risk",
    "re-submission covers units refused as NotAWriter through a voided grant",
]
INVITE_REFUSALS = ["an invite from now on that does not rotate"]

_PARTS: dict = {}


def _parts() -> dict:
    """_roster_parts, built once per process: it is deterministic."""
    if "v" not in _PARTS:
        _PARTS["v"] = _roster_parts()
    return _PARTS["v"]


def procedure_table(name: str, events: list, attacks: list, authority: list,
                    seniority: list) -> dict:
    """One case of `procedure_tables`: section 3.7's procedure over events,
    attacks and authority given as tables. `events` is [name, parents] in
    canonical order; each attack [attacker, target, class] counts; each
    authority row [event, "needs" or "bars", other, class] fails the event's
    authority unless (needs) or while (bars) the other event is valid."""
    order = [e for e, _ in events]
    parents = dict(events)

    def ancestors(e):
        out = set()
        for p in parents[e]:
            out |= {p} | ancestors(p)
        return out

    classes = {(x, e): c for x, e, c in attacks}

    def auth(e, status):
        for event, rule, other, cls in authority:
            if event == e and status.get(other, (False,))[0] != (rule == "needs"):
                return (False, cls)
        return (True, None)

    def run():
        return decide(order, lambda e: ancestors(e) & set(order),
                      lambda e: [x for x in order if (x, e) in classes], auth,
                      lambda x, e, status: False, lambda e, status: seniority.index(e))

    status = run()
    assert run() == status
    allowed = []
    for bits in itertools.product((False, True), repeat=len(order)):
        trial = {e: (b, "trial", None) for e, b in zip(order, bits)}
        if all(trial[e][0] == (auth(e, trial)[0] and not any(
                trial[x][0] for x in order if (x, e) in classes)) for e in order):
            allowed.append([e for e, b in zip(order, bits) if b])

    def verdict(e):
        valid, how, by = status[e]
        if valid:
            return {"status": "valid", "how": how}
        if how == "attacked":
            return {"status": "void", "class": classes[(by, e)], "by": by}
        return {"status": "void", "class": how}

    return {
        "name": name,
        "events": [{"name": e, "parents": ps} for e, ps in events],
        "attacks": [{"attacker": x, "target": e, "class": c} for x, e, c in attacks],
        "authority": [{"event": e, "rule": rule, "other": other, "class": c}
                      for e, rule, other, c in authority],
        "seniority": seniority,
        "allowed": allowed,
        "verdicts": {e: verdict(e) for e in order},
    }


def procedure_tables() -> list:
    """roster.json `procedure_tables`: section 3.7's steps 3 and 4 over
    hand-made tables."""
    agreed_void = procedure_table(
        "an event the agreement step voids stays void after the pick",
        events=[("e0", []), ("e1", []), ("e2", ["e1"]), ("e3", ["e0", "e2"])],
        attacks=[("e0", "e1", "TargetRemovedConcurrently"),
                 ("e0", "e2", "RemovedConcurrently"),
                 ("e2", "e0", "TargetRemovedConcurrently")],
        authority=[("e2", "needs", "e1", "NotAnAdministrator"),
                   ("e3", "needs", "e1", "NotAnAdministrator"),
                   ("e3", "bars", "e2", "NoSuchMember")],
        seniority=["e1", "e0", "e2", "e3"])
    # Agreement allows {e1, e2} first, then {e0}: e3 is void in both, and
    # takes its class from {e1, e2}. The pick then makes e1 valid and, a round
    # later, e0, which voids e2; at the end e3's authority holds and nothing
    # attacks it, yet it stays void.
    assert agreed_void["allowed"] == [["e1", "e2"], ["e0"]], agreed_void["allowed"]
    assert agreed_void["verdicts"] == {
        "e0": {"status": "valid", "how": "seniority"},
        "e1": {"status": "valid", "how": "seniority"},
        "e2": {"status": "void", "class": "RemovedConcurrently", "by": "e0"},
        "e3": {"status": "void", "class": "NoSuchMember"},
    }, agreed_void["verdicts"]
    return [agreed_void]


def roster_vectors() -> dict:
    """roster.json."""
    import clocks
    import spaces as sp_

    v = _parts()
    by_name = {c["name"]: c for c in v["cases"]}
    used = set(INVITE_CASES)
    out = {
        "specification": "roster.md",
        "labels": v["labels"],
        "parameters": v["parameters"],
        "note": v["note"],
        "encodings": v["encodings"],
        **sp_.roster_families(),
        "refused_events": {"base": v["negative"]["base"],
                           "cases": [c for c in v["negative"]["cases"]
                                     if c["name"] not in INVITE_REFUSALS]},
    }
    grant_graph = out.pop("grant_graph")
    effective = out.pop("effective_membership")
    for family, names in FAMILIES.items():
        rows = []
        for old, new in names:
            case = dict(by_name[old])
            case["name"] = new or old
            rows.append(case)
            used.add(old)
        out[family] = rows
    missing = set(by_name) - used
    assert not missing, missing
    out["grant_graph"] = grant_graph
    out["effective_membership"] = effective
    se = v["space_events"]
    out["unopened_events"] = {"late_joiner": {"history": se["history"], **se["late_joiner"]},
                              "wrong_seal": se["wrong_seal"],
                              "whole_merged_key": se["whole_merged_key"]}
    names = {c["name"] for family in FAMILIES for c in out[family]}
    out["history_prefixes"] = {
        "cases": {n: p for n, p in v["prefixes"].items() if n in names},
        "encodings": "roster/encodings",
        "refused_events": {"updates": "roster/neg", "geneses": "roster/neg/genesis"},
        "stability": "roster/stability",
        "unopened_events": {"late_joiner": "roster/late", "wrong_seal": "roster/split",
                            "whole_merged_key": "roster/whole"},
    }
    out["stability"] = v["stability"]
    out["refused_unit"] = clocks.decision_tables()["refused_unit"]
    out["procedure_tables"] = procedure_tables()
    import checkpoints  # roster.md, "Checkpoints"; it builds on this module
    out["checkpoints"] = checkpoints.checkpoint_vectors()
    return out


def invite_roster_family() -> dict:
    """ext-invite-links.json's histories that the roster builds: a late
    claim after a close and before any close, re-submission through a raced
    claim, and an invite "from now on" that does not rotate."""
    v = _parts()
    by_name = {c["name"]: c for c in v["cases"]}
    return {"histories": [by_name[n] for n in INVITE_CASES],
            "refused_events": {"base": v["negative"]["base"],
                               "cases": [c for c in v["negative"]["cases"]
                                         if c["name"] in INVITE_REFUSALS]}}


ext_invite_links_roster_cases = invite_roster_family


def _invite_and_storage_checks() -> None:
    """The invite key's successor and the skeleton's storage events, on
    small histories outside the vectors: ext-invite-links.md's and
    peers.md's vectors test the invite and the skeleton in full."""
    # Two concurrent successors whose chains do not share a seq: the second
    # skips through another author's event, so the chain's evidence alone
    # (fork point 2) would leave the first standing. Neither is closed, so
    # the race voids both.
    r, inv = _invite_base("roster/self-test/invite")
    before = set(r.hist.view["I"])
    s1 = _claim(r, "I", "roster/st/bob", "a claim at seq 1")
    other = r.unit("P", "P writes", view=before)
    s2 = _claim(r, "I", "roster/st/carol", "a claim at seq 2 after another author's event",
                view=before | {other}, seq=2, prev=other)
    sp = r.resolve()
    assert sp.status[s1][1] == "ClaimRaced" and sp.status[s2][1] == "ClaimRaced", \
        (sp.status[s1], sp.status[s2])
    assert sp.forks.get(inv.device_id) == 2
    assert sp.roster[(INVITE, inv.device_id)].present
    assert set(sp.voiders(s1)) == {s2}
    one = r.resolve(r.log.anc[s1] | {s1})
    assert one.status[s1][0] and not one.roster[(INVITE, inv.device_id)].present
    assert one.roster[(PERSON, example("roster/st/bob"))].via == VIA_LINK

    # An invite "from now on" that does not rotate.
    r = setup([("P", ADMINISTER)], "roster/self-test/invite-rotation")
    bad = r.act("P", [_invite_grant(r, "I", FROM_NOW_ON)], "P invites from now on, not rotating",
                rotation=False)
    assert r.resolve().status[bad][1] == "RotationRequired"

    # Storage events: a pseudonym's events count only under a record the
    # skeleton vouches for; a stranger's self-signed enrolment is dropped. A
    # writer request is judged as a unit; a skeleton event counts for
    # stability as the device its binding names.
    r = setup([("P", ADMINISTER), ("Q", ADMINISTER), ("W", WRITE)], "roster/self-test/storage")
    q0 = r.hist.without_xwing("Q0")
    r.hist.view["Q0"] = set(r.hist.view["Q"])
    enrol = r.hist.act("Q0", KIND_STORAGE, cbor({1: 1, 2: 2, 4: q0.mldsa_public}), "Q0 enrols")
    target = r.unit("W", "W writes")
    r.sync("P", "Q0", "W")
    ack = r.hist.act("Q0", KIND_STORAGE, cbor({1: 1, 2: 4}), "Q0 acknowledges")
    release = r.hist.act("W", KIND_STORAGE, cbor({1: 1, 2: 16, 3: bytes(16)}), "W releases")
    r.anchor("P", "P anchors")
    sp = r.resolve()
    assert sp.status[enrol][1] == "Dropped" and sp.status[ack][1] == "Dropped"
    assert sp.status[release] == (True, "rules", None)
    assert not sp.stable(target)  # Q's only later event is its pseudonym's

    class Vouched(StorageView):
        def pseudonym_keys(self, space, pseudonym):
            return [q0.mldsa_public] if pseudonym == q0.device_id else []

        def device_of(self, pseudonym):
            return r.hist.device("Q") if pseudonym == q0.device_id else None
    vouched = r.resolve(storage=Vouched())
    assert vouched.status[enrol] == (True, "kept", None)
    assert vouched.status[ack] == (True, "kept", None)
    assert vouched.stable(target)

    # A roster event that changes who administers names
    # its twin (key 15); a named twin not held keeps it pending (NoTwin) and
    # holds what follows; a failing one voids it (BadTwin); a missing name is
    # TwinRequired, and a name where none is needed UnexpectedTwin.
    r = setup([("P", ADMINISTER)], "roster/self-test/twin")
    r.grant("P", "A", ADMINISTER, label="P grants A administer",
            twin=example("roster/self-test/twin/a-twin"))
    r.sync("P", "A")
    twin_id = example("roster/self-test/twin/the-twin")
    promote = r.grant("P", "Q", ADMINISTER, label="P grants Q administer", twin=twin_id)
    r.sync("P", "Q")
    after = r.grant("Q", "W", WRITE, label="Q grants W write")
    r.sync("Q", "W")
    unit = r.unit("W", "W writes")
    side = r.grant("A", "V", WRITE, label="A grants V write, concurrently")
    bare = r.grant("A", "X", ADMINISTER, label="A grants X administer, naming no twin")
    extra = r.grant("A", "Y", WRITE, label="A grants Y write, naming a twin",
                    twin=example("roster/self-test/twin/needless"))

    class Twins(StorageView):
        def __init__(self, verdict):
            self.verdict = verdict

        def twin(self, space, event, named, place):
            return self.verdict if named == twin_id else None
    held = r.resolve(storage=Twins("NoTwin"))
    assert held.status[promote][1] == "NoTwin"
    assert held.status[after][1] == "Pending" and held.status[unit][1] == "Pending"
    assert held.status[side][0]
    assert held.status[bare][1] == "TwinRequired" and held.status[extra][1] == "UnexpectedTwin"
    void = r.resolve(storage=Twins("BadTwin"))
    assert void.status[promote][1] == "BadTwin"
    assert void.status[after][1] == "NotAnAdministrator" and not void.status[unit][0]
    assert r.resolve(storage=Twins(None)).status[unit][0]
    assert r.resolve().status[bare][0]  # a replica that models no skeleton
    try:
        Space(r.log, keys=r.keyring(), storage=type("Rootless", (StorageView,), {
            "twin": lambda self, space, event, named, place: "NoTwin" if event == r.genesis
            else None})())
        raise AssertionError("a genesis without its root is usable")
    except SpecError as error:
        assert error.error == "NoTwin"

    # The genesis carries the system stream ID.
    assert r.resolve().genesis_body.system_stream == example(
        "roster/self-test/twin/system-stream")[:16]


def _order_checks() -> None:
    """Orders and limits the vectors do not reach: refs past 64, an empty
    capability list, a founder with a label, device grants counted before
    any change is read, RotationRequired before StaleSeal, and a response
    that rotates without a grant rotation."""
    pair = [bytes(32), bytes(32)]
    assert events.expect_error(read_refs, []) == "Malformed"
    assert events.expect_error(read_refs, [[bytes([i]) * 32, bytes(32)] for i in range(65)]) \
        == "TooLarge"
    assert events.expect_error(read_refs, [pair, pair]) == "Malformed"
    r = setup([("P", ADMINISTER), ("M", WRITE)], "roster/self-test/order")
    k = {n: r.hist.device(n) for n in ("P", "M", "H", "J")}
    empty = {**r.device_grant("H", WRITE).encode(), C_CAPS: []}
    assert events.expect_error(_decode_base, empty, r.id) == "Malformed"

    def genesis_error(founder: Change) -> str:
        hist = History("roster/self-test/order/genesis")
        secret = example("roster/self-test/order/genesis/content-key")
        payload = {**rotation_payload(secret, "roster/self-test/order/genesis"),
                   "grant_rotation": True}
        body = space_body(payload, secret,
                          example("roster/self-test/order/genesis/seal-nonce")[:kg.NONCE_BYTES],
                          genesis_roster(founder),
                          example("roster/self-test/order/nonce")[:NONCE_BYTES])
        g = hist.genesis("F", KIND_SPACE, body)
        return events.expect_error(Space, hist.log, None, None, None, Keyring({g: secret}))
    hist = History("roster/self-test/order/genesis")
    founder = Change(GRANT, (DEVICE, hist.device("F")), ADMINISTER, None, None, WITH_HISTORY,
                     VIA_NONE, None, None, hist.xwing("F"), hist.mldsa("F"))
    assert genesis_error(founder) == "accepted"
    for extra in ({"label": "founder"}, {"caps": (("drive", EXTENDS),)},
                  {"session": bytes(16)}):
        bad = Change(**{**founder.__dict__, **extra})
        assert genesis_error(bad) in ("Malformed", "AdministerNotDevice"), extra
    assert genesis_error(Change(**{**founder.__dict__, "label": "founder"})) == "Malformed"

    # Two device grants past a limit lowered to 1, the second with an
    # invalid X-Wing key: step 8 counts them before step 9 reads either.
    saved = globals()["MAX_DEVICE_GRANTS"]
    globals()["MAX_DEVICE_GRANTS"] = 1
    try:
        r.hist.view["P"] = set(r.log.events)
        bad = Change(GRANT, (DEVICE, k["J"]), WRITE, None, None, WITH_HISTORY, VIA_CODE, None,
                     None, bytes(HYBRID_BYTES), r.hist.mldsa("J"))
        i = r.space_event("P", "two device grants", update_roster(
            [r.device_grant("H", WRITE), bad]), True)
        assert r.resolve().status[i][1] == "Malformed", r.resolve().status[i]
    finally:
        globals()["MAX_DEVICE_GRANTS"] = saved

    # A removal that does not rotate, sealed under a state a valid rotation
    # in its past follows: RotationRequired comes first.
    r = setup([("P", ADMINISTER), ("M", WRITE)], "roster/self-test/order/rotation")
    r.heal("P", "P heals")
    stale = r.hist.act("P", KIND_SPACE, space_body(
        {"sealed_under": kg.encode_set([r.genesis])}, r.krot[r.genesis],
        example("roster/self-test/order/rotation/seal-nonce")[:kg.NONCE_BYTES],
        update_roster([Change(REMOVE, r.member("M"))])), "P removes M without rotating")
    assert r.resolve().status[stale][1] == "RotationRequired", r.resolve().status[stale]

    # A response that rotates is a grant rotation; one that is not is void.
    pl = identity.Person("l1", "roster/self-test/order/list", linear=True)
    pl.add("l1", "l2", identity.DEVICE)
    end = pl.revoke("l1", "l2", "l1 revokes l2")
    for flags, verdict in (({}, "GrantKeyRequired"), (None, "rules")):
        r = Roster("P", f"roster/self-test/order/response/{verdict}",
                   keys={"l2": pl.hist.seed("l2")})
        r.persons[pl.id] = "person L"
        r.grant("P", "W", WRITE)
        r.grant("P", "person L", WRITE, label="P grants person L write")
        r.sync("P", "W", "l2")
        kw = {} if flags is None else {"flags": flags}
        x = r.heal("W", "W responds", refs=[(pl.id, end)], **kw)
        assert r.resolve(None, {pl.id: pl.resolve()}).status[x][1] == verdict


def _standing_checks() -> None:
    """Section 3.7's standing: a reader's roster events after a contest
    leave its verdicts as they are, at the agreement step's limit and past
    it; were they contested, one past the limit would hand the contest to
    the pick, which decides it otherwise. A reader raised concurrently with
    its own roster event still has no standing in that event's past."""
    global _STANDING
    r, roles, junk, views = _contest_with_junk("roster/junk-contest")
    alone, boundary, past = views.values()
    base = r.resolve(alone)
    for view in (boundary, past):
        sp = r.resolve(view)
        assert all(sp.status[e] == base.status[e] for e in alone), r.name(roles["e3"])
        assert not sp.unstanding.isdisjoint(junk) and set(sp.contested) == set(base.contested)
    _STANDING = False
    try:
        at_limit = r.resolve(boundary)
        over = r.resolve(past)
    finally:
        _STANDING = True
    # The agreement step voids e3, with its class under the first allowed
    # assignment, the one in which e1 is void.
    assert at_limit.status[roles["e3"]] == (False, "NotAnAdministrator", None)
    assert over.status[roles["e3"]][0], over.status[roles["e3"]]  # no agreement step

    r = setup([("P", ADMINISTER), ("M", READ), ("D", WRITE)], "roster/standing-raise")
    j = r.act("M", [Change(CHANGE, r.member("D"), label="junk")], "M relabels D")
    raise_ = r.change("P", "M", ADMINISTER, label="P raises M")
    r.sync(*r.everyone())
    after = r.change("M", "D", tag="M's label", label="M relabels D after its raise")
    for view in ({i for i in r.all() if i not in (raise_, after)}, r.all()):
        sp = r.resolve(view)
        assert sp.status[j] == (False, "NotAnAdministrator", None) and j in sp.unstanding
    sp = r.resolve(r.all())
    assert sp.status[raise_][0] and sp.status[after][0] and after in sp.contested


def self_test() -> None:
    _standing_checks()
    _invite_and_storage_checks()
    _order_checks()
    v = roster_vectors()
    inv = invite_roster_family()
    errors = {c["name"]: c["error"] for c in v["refused_events"]["cases"]
              + inv["refused_events"]["cases"]}
    expected = {
        "a roster part of type 2": "Malformed",
        "no changes": "Malformed",
        "a roster part with a key 2": "Malformed",
        "one member twice": "Malformed",
        "a grant without a history mode": "Malformed",
        "a device grant without an ML-DSA-65 key": "Malformed",
        "a device grant whose keys do not give its member ID: H's keys under M's device ID":
            "NotCommitted",
        "a device grant that names P's Ed25519 key with another ML-DSA-65 key under P's device "
        "ID": "NotCommitted",
        "a change that changes nothing": "Malformed",
        "capabilities out of order": "Malformed",
        "a session on a person grant": "Malformed",
        "a space granting itself": "Malformed",
        "replaces without removing the person it names": "Malformed",
        "two policy changes": "Malformed",
        "a policy holding a default value": "Malformed",
        "a device grant whose X-Wing key is not valid": "InvalidKey",
        "an administer grant without a rank": "Malformed",
        "a rank on a write grant": "Malformed",
        "a rank above 255": "Malformed",
        "a person granted administer": "AdministerNotDevice",
        "a guest granted administer": "AdministerNotDevice",
        "a self-removal that rotates": "SelfRotation",
        "a writer signs a roster event": "NotAnAdministrator",
        "an administrator grants itself": "SelfGrant",
        "a grant of a member already in": "AlreadyMember",
        "a removal of a member not in": "NoSuchMember",
        "an administrator raises itself": "SelfChange",
        "an event lowering an administrator and another member": "AdminAlone",
        "an invite from now on that does not rotate": "RotationRequired",
        "a genesis with duel policy 1": "UnknownPolicy",
        "a genesis whose policy has an unknown key 7": "Malformed",
        "a genesis whose founder is another device": "Malformed",
        "a genesis with an agent waiting period below 72 hours": "Malformed",
        "a genesis with no roster part": "Malformed",
        "a genesis without its nonce": "Malformed",
        "a genesis that does not rotate": "Malformed",
        "a space event with no sealed part": "Malformed",
        "a policy change sealed under a state a valid rotation in its past follows": "StaleSeal",
        "a delivery sealed under a state a valid rotation in its past follows": "StaleSeal",
        "more device grants than the limit (lowered to 1 for the vector)": "Malformed",
        "a nonce outside a genesis": "Malformed",
        "a commitment to another key": "BadSeal",
        "a sealed part that does not open under its key": "BadSeal",
        "a sealed part with an unknown key 6": "Malformed",
        "sealed under a state not in its past": "Malformed",
    }
    assert errors == expected, {k: (errors.get(k), e) for k, e in expected.items()
                                if errors.get(k) != e}
    assert v == roster_vectors()


if __name__ == "__main__":
    self_test()
    print(len(json.dumps(roster_vectors())))
