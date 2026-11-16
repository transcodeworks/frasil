"""Identity (identity.md), written from the specification, independently of
any implementation: a device's three key pairs and its device ID, the device-list event,
the possession statement, the list's checks and its merge by rank,
rootedness and confirm over a graph, recovery keys and passkey members with
their derivations, recovery entries, fingerprints, account links and pins.
A list names every list member by its device ID (crypto.md, "A device's
keys"), and checks an event's signature under the keys that hash to its kc."""

from __future__ import annotations

import base64
import hashlib
import json

import events
import history_sigs as hs
import mldsa
import xwing
from events import (
    KIND_DEVICE_LIST, KIND_UNIT, History, Log, cbor, decide, expect_error, h,
    is_bytes, is_uint, uncbor,
)
from formats import example, hybrid_key_valid, identifier_ok
from primitives import (
    SpecError, ed25519_public, ed25519_sign, ed25519_valid, ed25519_verify_strict, field,
    hkdf, hkdf_expand, hkdf_extract, sha256,
)

POSSESSION_LABEL = b"frasil/device-list/possession/v3"
LIST_SENIORITY_LABEL = b"frasil/device-list/seniority/v1"
ACCOUNT_LINK_LABEL = b"frasil/account-link/v1"
ACCOUNT_UNLINK_LABEL = b"frasil/account-unlink/v1"
FINGERPRINT_LABEL = b"frasil/key-fingerprint/v1"
RECOVERY_SALT = hs.RECOVERY_SALT                       # frasil/recovery/v1
RECOVERY_HYBRID_LABEL = b"frasil/recovery-key/hybrid/v1"
RECOVERY_MLDSA_LABEL = hs.RECOVERY_MLDSA_LABEL         # frasil/recovery-key/mldsa/v1
RECOVERY_FETCH_LABEL = b"frasil/recovery-key/fetch/v1"
PASSKEY_PRF_INPUT_LABEL = b"frasil/passkey-prf-input/v2"
PASSKEY_EXTRACT_SALT = hs.PASSKEY_EXTRACT_SALT         # frasil/passkey-extract/v1
PASSKEY_MEMBER_LABEL = b"frasil/passkey-member/v1"
PASSKEY_UNLOCK_LABEL = b"frasil/passkey-unlock/v1"
PASSKEY_HYBRID_LABEL = b"frasil/passkey/hybrid/v1"
PASSKEY_MLDSA_LABEL = hs.PASSKEY_MLDSA_LABEL           # frasil/passkey/mldsa/v1
PASSKEY_FETCH_LABEL = b"frasil/passkey/fetch/v1"
# Invite keys are ext-invite-links.md's; their derivation is kept here beside
# the other keys derived from a secret a person holds.
INVITE_SALT = hs.INVITE_SALT                           # frasil/invite/v1
INVITE_HYBRID_LABEL = b"frasil/invite/hybrid/v1"
INVITE_MLDSA_LABEL = hs.INVITE_MLDSA_LABEL             # frasil/invite/mldsa/v1
WEBAUTHN_PRF_CONTEXT = b"WebAuthn PRF\x00"
NEW_LABELS = [POSSESSION_LABEL, LIST_SENIORITY_LABEL, ACCOUNT_LINK_LABEL,
              ACCOUNT_UNLINK_LABEL, RECOVERY_FETCH_LABEL, PASSKEY_FETCH_LABEL]

ENTRY_VERSION = 3
ADD, REVOKE, CONFIRM, LIST_CHECKPOINT, ACK = 0, 1, 2, 3, 4
DEVICE, RECOVERY, PASSKEY, AGENT = 0, 1, 2, 3
ACTION_NAMES = {ADD: "add", REVOKE: "revoke", CONFIRM: "confirm", LIST_CHECKPOINT: "checkpoint",
                ACK: "ack"}
NAMING_ACTIONS = (ADD, REVOKE, CONFIRM)  # those that name a list member
KIND_NAMES = {DEVICE: "device", RECOVERY: "recovery key", PASSKEY: "passkey member",
              AGENT: "recovery agent"}
# identity.md: the body keys of a device-list event. Key 3 is the named list
# member's device ID; an add's key 7 its Ed25519 identity key.
B_VERSION, B_ACTION, B_KIND, B_DEVICE, B_POSSESSION, B_XWING, B_MLDSA, B_IDENTITY = range(8)
B_FOLLOWS, B_RECORD = 8, 9  # identity.md, "List checkpoints"
B_HYBRID = B_XWING
MLDSA_BYTES = hs.MLDSA_PUBLIC_KEY_BYTES
PROOF_BYTES = hs.HYBRID_SIGNATURE_BYTES
MAX_LIST_EVENTS = 4096
ZERO_PERSON = bytes(32)
# ext-recovery-agent.md: agent_waiting_period's default, and the period a
# verifier outside any space uses.
AGENT_WAIT_SECONDS = 259_200

# Rootedness: none, rooted in a passkey, rooted in an agent (fail closed: the
# larger wins when two adds disagree).
NONE, PASSKEY_ROOTED, AGENT_ROOTED = 0, 1, 2
ROOT_NAMES = {NONE: "none", PASSKEY_ROOTED: "passkey", AGENT_ROOTED: "agent"}

# ---------------------------------------------------------------------------
# Encoding.


def possession_statement(person_id: bytes, adder: bytes, kind: int, identity: bytes,
                         mldsa_public: bytes, xwing_public: bytes | None = None) -> bytes:
    """What the added keys sign, under scheme 2. The person ID is
    32 zero bytes for the list's first event, which the ID is the hash of.
    The adder is the device ID of the list member that signs the add, the
    event's author: the device itself in the first event. `identity` is the
    Ed25519 key. The X-Wing key's field is empty for an agent; the last
    field is the scheme, 2."""
    assert len(person_id) == 32 and len(adder) == 32 and len(mldsa_public) == MLDSA_BYTES
    return (POSSESSION_LABEL + field(person_id) + field(adder) + field(bytes([kind]))
            + field(identity) + field(mldsa_public) + field(xwing_public or b"")
            + field(bytes([events.SCHEME_HYBRID])))


def prove(signer: hs.Signer, statement: bytes) -> bytes:
    return hs.sign(signer, events.SCHEME_HYBRID, statement)


def proof_ok(identity: bytes, mldsa_public: bytes, statement: bytes, proof: bytes) -> bool:
    return (hs.verify_ed25519_half(identity, statement, proof)
            and hs.verify_mldsa_half(identity, mldsa_public, statement, proof))


def list_body(action: int, kind: int, device: bytes, *, identity: bytes | None = None,
              possession: bytes | None = None, xwing: bytes | None = None,
              mldsa_public: bytes | None = None) -> bytes:
    """Keys 0 to 3, `device` the named list member's device ID, and an add's
    keys 4 to 7."""
    body = {B_VERSION: ENTRY_VERSION, B_ACTION: action, B_KIND: kind, B_DEVICE: device}
    if identity is not None:
        body[B_IDENTITY] = identity
    if possession is not None:
        body[B_POSSESSION] = possession
    if xwing is not None:
        body[B_XWING] = xwing
    if mldsa_public is not None:
        body[B_MLDSA] = mldsa_public
    return cbor(body)


def encode_list_record(rec: dict) -> bytes:
    """identity.md, "List checkpoints": the record a list checkpoint carries."""
    out = {1: 1, 2: rec["epoch"],
           4: [[m["add"], m["root"], m["agent"] or b"", 1 if m["confirmed"] else 0,
                [m["seniority"][0], m["seniority"][1], m["seniority"][3]],
                m.get("rooting") or b""]
               for m in sorted(rec["members"], key=lambda m: m["device"])],
           5: [[d, s, i] for d, (s, i) in sorted(rec["tips"].items())],
           6: [[d, s] for d, s in sorted(rec["forks"].items())]}
    if rec.get("previous") is not None:
        out[3] = rec["previous"]
    if rec.get("heard"):
        # The heard devices (section 3.16, Effect): each by its add, with
        # its seniority, ascending by add ID.
        out[7] = [[add, [sen[0], sen[1], sen[3]]] for add, sen in sorted(rec["heard"].items())]
    return cbor(out)


def read_list_record(data: bytes) -> dict:
    """Reading a list record, in order: deterministic CBOR, a map with key 1
    (Malformed); version 1 (UnsupportedVersion); exactly its keys with their
    types (Malformed). Members are in device-ID order, which the reader
    learns from their adds; here their order is checked by add ID's place."""
    value = uncbor(data)
    if not isinstance(value, dict) or not is_uint(value.get(1)):
        raise SpecError("Malformed")
    if value[1] != 1:
        raise SpecError("UnsupportedVersion")
    if not {1, 2, 4, 5, 6} <= set(value) <= {1, 2, 3, 4, 5, 6, 7}:
        raise SpecError("Malformed")
    heard = {}
    if 7 in value:
        rows = value[7]
        if not (isinstance(rows, list) and rows and all(
                isinstance(x, list) and len(x) == 2 and is_bytes(x[0], 32)
                and isinstance(x[1], list) and len(x[1]) == 3 and is_uint(x[1][0])
                and is_uint(x[1][1]) and is_bytes(x[1][2], 32) for x in rows)) \
                or any(a[0] >= b[0] for a, b in zip(rows, rows[1:])):
            raise SpecError("Malformed")
        heard = {x[0]: (x[1][0], x[1][1], None, x[1][2]) for x in rows}
    epoch = value[2]
    if not is_uint(epoch) or epoch < 1 or (3 in value) != (epoch > 1) \
            or (3 in value and not is_bytes(value[3], 32)):
        raise SpecError("Malformed")
    members = []
    for m in value[4] if isinstance(value[4], list) else [None]:
        # [add, root, agent, confirmed, seniority, rooting]: `rooting` names
        # the first add that rooted the member in an agent, present exactly
        # when `root` is 2; `agent` likewise names that agent.
        if not (isinstance(m, list) and len(m) == 6 and is_bytes(m[0], 32)
                and m[1] in (NONE, PASSKEY_ROOTED, AGENT_ROOTED)
                and (m[2] == b"" or is_bytes(m[2], 32)) and m[3] in (0, 1)
                and isinstance(m[4], list) and len(m[4]) == 3 and is_uint(m[4][0])
                and is_uint(m[4][1]) and is_bytes(m[4][2], 32)
                and (m[5] == b"" or is_bytes(m[5], 32))
                and (m[5] != b"") == (m[1] == AGENT_ROOTED)
                and (m[2] != b"") == (m[1] == AGENT_ROOTED)):
            raise SpecError("Malformed")
        members.append({"add": m[0], "root": m[1], "agent": m[2] or None,
                        "confirmed": bool(m[3]),
                        "seniority": (m[4][0], m[4][1], None, m[4][2]),
                        "rooting": m[5] or None})
    tips, forks = {}, {}
    for table, out, width in ((value[5], tips, 3), (value[6], forks, 2)):
        if not isinstance(table, list):
            raise SpecError("Malformed")
        for row in table:
            if not (isinstance(row, list) and len(row) == width and is_bytes(row[0], 32)
                    and is_uint(row[1]) and row[1] >= 1 and (width == 2 or is_bytes(row[2], 32))):
                raise SpecError("Malformed")
            out[row[0]] = row[1] if width == 2 else (row[1], row[2])
        if any(a[0] >= b[0] for a, b in zip(table, table[1:])):
            raise SpecError("Malformed")
    return {"epoch": epoch, "previous": value.get(3), "members": members, "tips": tips,
            "forks": forks, "heard": heard}


class Body:
    def __init__(self, value: dict):
        self.action = value[B_ACTION]
        self.kind = value.get(B_KIND)
        self.device = value.get(B_DEVICE)
        self.follows = tuple(value.get(B_FOLLOWS, ()))
        self.record = read_list_record(value[B_RECORD]) if B_RECORD in value else None
        self.record_bytes = value.get(B_RECORD)
        self.identity = value.get(B_IDENTITY)  # an add's Ed25519 key
        self.possession = value.get(B_POSSESSION)
        self.xwing = value.get(B_XWING)
        self.mldsa = value.get(B_MLDSA)

    @property
    def hybrid(self) -> bytes | None:
        return self.xwing

    def keys(self) -> tuple:
        """What the device ID commits to: (ML-DSA-65 key, X-Wing key or None)."""
        return (self.mldsa, self.xwing)


def check_body(event: events.Event) -> Body:
    """The checks that need only the event."""
    value = uncbor(event.body)
    if not isinstance(value, dict) or value.get(B_VERSION) != ENTRY_VERSION:
        raise SpecError("Malformed")
    action = value.get(B_ACTION)
    if action not in ACTION_NAMES:
        raise SpecError("Malformed")
    if B_FOLLOWS in value:
        f = value[B_FOLLOWS]
        if event.genesis or not (isinstance(f, list) and 1 <= len(f) <= 4
                                 and all(is_bytes(x, 32) for x in f)
                                 and all(a < b for a, b in zip(f, f[1:]))):
            raise SpecError("Malformed")
    if action not in NAMING_ACTIONS:
        # A checkpoint carries its record; an ack nothing (identity.md, 3.16).
        allowed = {B_VERSION, B_ACTION, B_FOLLOWS} | ({B_RECORD} if action == LIST_CHECKPOINT
                                                       else set())
        if set(value) - allowed or (action == LIST_CHECKPOINT) != (B_RECORD in value):
            raise SpecError("Malformed")
        if event.genesis:
            raise SpecError("BadGenesis")
        if action == LIST_CHECKPOINT:
            if not is_bytes(value[B_RECORD]):
                raise SpecError("Malformed")
            read_list_record(value[B_RECORD])
        return Body(value)
    if value.get(B_KIND) not in KIND_NAMES:
        raise SpecError("Malformed")
    allowed = {B_VERSION, B_ACTION, B_KIND, B_DEVICE, B_FOLLOWS}
    if action == ADD:
        allowed |= {B_POSSESSION, B_XWING, B_MLDSA, B_IDENTITY}
        if B_POSSESSION not in value or B_MLDSA not in value or B_IDENTITY not in value:
            raise SpecError("Malformed")
    if set(value) - allowed or B_DEVICE not in value:
        raise SpecError("Malformed")
    if not is_bytes(value[B_DEVICE], 32):
        raise SpecError("Malformed")
    if action == ADD and (not is_bytes(value[B_POSSESSION], PROOF_BYTES)
                          or not is_bytes(value[B_MLDSA], MLDSA_BYTES)
                          or not is_bytes(value[B_IDENTITY], 32)):
        raise SpecError("Malformed")
    if B_XWING in value and (not is_bytes(value[B_XWING], xwing.XWING_PK_SIZE)
                             or value[B_KIND] == AGENT):
        raise SpecError("Malformed")
    if action == ADD and value[B_KIND] != AGENT and B_XWING not in value:
        raise SpecError("Malformed")  # a list member that receives wraps names its X-Wing key
    body = Body(value)
    # Step 3: the first event adds the device that signs it.
    if event.genesis and (action != ADD or body.kind != DEVICE or body.device != event.author):
        raise SpecError("BadGenesis")
    if action == ADD:
        if (not ed25519_valid(body.identity)
                or (body.xwing is not None and not hybrid_key_valid(body.xwing))):
            raise SpecError("InvalidKey")
        # Step 5: the keys give key 3 (crypto.md, "Keys by their hash").
        if hs.device_id_of(body.identity, body.mldsa, body.xwing) != body.device:
            raise SpecError("NotCommitted")
        person = ZERO_PERSON if event.genesis else event.log
        statement = possession_statement(person, event.author, body.kind, body.identity,
                                         body.mldsa, body.xwing)
        if not proof_ok(body.identity, body.mldsa, statement, body.possession):
            raise SpecError("BadPossession")
    return body


# ---------------------------------------------------------------------------
# State and the merge.


class Member:
    def __init__(self, body: Body):
        self.kind = body.kind
        self.device = body.device
        self.identity = body.identity  # its Ed25519 key
        self.xwing = body.xwing
        self.mldsa = body.mldsa
        self.adds: list[bytes] = []
        self.root = NONE
        self.agent_root: bytes | None = None  # the agent this member is rooted in
        self.agent_adds: list[bytes] = []  # the adds that rooted it in an agent
        self.revoked_by: list[bytes] = []
        self.confirmed_by: list[bytes] = []

    @property
    def hybrid(self) -> bytes | None:
        return self.xwing

    @property
    def active(self) -> bool:
        return not self.revoked_by

    @property
    def rooted(self) -> int:
        if self.kind == AGENT:
            return AGENT_ROOTED
        if self.kind == PASSKEY:
            return max(self.root, PASSKEY_ROOTED)
        return NONE if self.confirmed_by else self.root

    @property
    def rank(self) -> int:
        """1 is the highest."""
        if self.rooted == AGENT_ROOTED:
            return 4
        if self.kind == RECOVERY and self.rooted == NONE:
            return 1
        if self.kind == DEVICE and self.rooted == NONE:
            return 2
        return 3


class DeviceList:
    """The merged state of one person's list in a view."""

    def __init__(self, log: Log, view=None, keys=(), presets=None, base=None):
        """`keys` are (ML-DSA-65 key, X-Wing key or None) pairs this replica
        holds from other sources, beside the ones this list's adds carry.
        `presets` are verdicts decided before the merge (list checkpoints,
        follows that do not match); with `base`, the log is a list
        checkpoint's world (list_checkpoints.py): its root is the checkpoint,
        whose record's members are list members from the start."""
        self.log = log
        self.base = base
        self.epoch = base["record"]["epoch"] if base is not None else 0
        self.view = set(log.events if view is None else view)
        assert log.closed(self.view)
        self.person_id = log.id
        self.bodies: dict[bytes, Body] = {}
        self.structural: dict[bytes, str] = {}
        for i in self.view:
            try:
                self.bodies[i] = check_body(log.events[i])
            except SpecError as error:
                self.structural[i] = error.error
        if log.genesis in self.structural:
            raise SpecError(self.structural[log.genesis])
        # Step 7: each event's scheme-2 signature, under the keys that hash
        # to its kc, wherever this replica found them: the adds of this list,
        # or any other source it was given. The source vouches for nothing.
        # In a list checkpoint's world, only the record's adds and the
        # world's own adds (section 3.16).
        extra = keys if base is None else ()
        held = self.named_keys() + [k for k in extra if k not in self.named_keys()]
        for i in self.view:
            if i in self.structural:
                continue
            verdict = signature_ok(log.events[i], held)
            if verdict == "NoHybridKey" and base is not None:
                # In a list checkpoint's world the keys are the record's adds
                # and the world's own: an author none of them names is no
                # list member at any place there (section 3.16).
                verdict = "UntrustedSigner"
            if verdict is not True:
                self.structural[i] = verdict
        if log.genesis in self.structural:
            raise SpecError(self.structural[log.genesis])
        self.status: dict[bytes, tuple] = {}
        for i, v in (presets or {}).items():
            if i in self.view and i != log.genesis and i not in self.structural:
                self.status[i] = v
        self.forks = log.fork_points(self.view, lambda i: i not in self.structural)
        if base is not None:
            for author, seq in base["record"]["forks"].items():
                self.forks[author] = min(self.forks.get(author, seq), seq)
            for i in self.view:
                e = log.events[i]
                tip = base["record"]["tips"].get(e.author)
                if i != log.genesis and tip is not None and e.seq <= tip[0]:
                    self.forks[e.author] = min(self.forks.get(e.author, e.seq), e.seq)
        self._cache: dict[frozenset, dict] = {}
        self._resolve()

    def named_keys(self) -> list[tuple]:
        """The (ML-DSA-65 key, X-Wing key or None) pairs the adds of this
        list carry, in canonical order: a source of keys for any verifier,
        by their hash."""
        out = []
        for b in (self.base or {}).get("adds", {}).values():
            if b.keys() not in out:
                out.append(b.keys())
        for i in self.log.canonical(self.view):
            b = self.bodies.get(i)
            if b and b.action == ADD and b.keys() not in out:
                out.append(b.keys())
        return out

    def _base_members(self) -> dict:
        """The record's members, each from the add its entry names."""
        out = {}
        for m in self.base["record"]["members"]:
            body = self.base["adds"][m["add"]]
            member = Member(body)
            member.root = m["root"]
            member.agent_root = m["agent"]
            # The add that rooted it in an agent, kept with the record's
            # adds, from whose first sight a verifier counts the waiting
            # period (ext-recovery-agent.md).
            member.agent_adds = [m["rooting"]] if m["rooting"] else []
            member.confirmed_by = [self.log.genesis] if m["confirmed"] else []
            epoch, height, _, add = m["seniority"]
            member.base_seniority = (epoch, height, sha256(LIST_SENIORITY_LABEL + self.person_id
                                                           + body.device), add)
            member.base_add = m["add"]
            out[body.device] = member
        return out

    # -- state at a place
    def state(self, valid: frozenset) -> dict[bytes, Member]:
        hit = self._cache.get(valid)
        if hit is not None:
            return hit
        out: dict[bytes, Member] = self._base_members() if self.base is not None else {}
        ids = [i for i in self.log.canonical(valid)
               if not (self.base is not None and i == self.log.genesis)]
        for i in ids:
            b = self.bodies[i]
            if b.action == ADD:
                m = out.get(b.device)
                if m is None:
                    m = out[b.device] = Member(b)
                m.adds.append(i)
        for i in ids:
            b = self.bodies[i]
            if b.action == ADD:
                m = out[b.device]
                if i == self.log.genesis:
                    root = NONE
                else:
                    signer = self.state(self.place(i, valid)).get(self.log.events[i].author)
                    if signer is None:
                        # An assignment the procedure is trying, in which the
                        # add's author is no member at its place: the add is
                        # void there (section 3.3), and roots nothing.
                        continue
                    root = AGENT_ROOTED if signer.kind == AGENT else signer.rooted
                    if signer.kind == AGENT:
                        m.agent_root = m.agent_root or signer.device
                    elif signer.rooted == AGENT_ROOTED:
                        m.agent_root = m.agent_root or signer.agent_root
                    if b.kind == PASSKEY:
                        root = max(root, PASSKEY_ROOTED)
                if root == AGENT_ROOTED:
                    m.agent_adds.append(i)
                m.root = max(m.root, root)
            elif b.device not in out:
                continue  # an assignment the procedure is trying; nothing to apply
            elif b.action == REVOKE:
                out[b.device].revoked_by.append(i)
            else:
                out[b.device].confirmed_by.append(i)
        self._cache[valid] = out
        return out

    def place(self, i: bytes, valid) -> frozenset:
        return frozenset(p for p in self.log.anc[i] if p in valid)

    def _valid_from(self, status) -> frozenset:
        return frozenset([self.log.genesis] + [e for e, v in status.items() if v[0]])

    def _place_of(self, e, status) -> frozenset:
        return frozenset([self.log.genesis] + [p for p in self.log.anc[e]
                                                if p in status and status[p][0]])

    # -- the rules
    def auth(self, e: bytes, status) -> tuple:
        """The checks at the event's place, in their order."""
        S = self.state(self._place_of(e, status))
        event, b = self.log.events[e], self.bodies[e]
        s = S.get(event.author)
        if s is None or not s.active:
            return (False, "UntrustedSigner")
        if s.kind == AGENT and not ((b.action == ADD and b.kind == DEVICE)
                                    or (b.action == REVOKE and b.device == event.author)):
            return (False, "AgentLimited")
        if b.action == ADD:
            if b.kind == AGENT and not (s.kind in (DEVICE, RECOVERY) and s.rooted == NONE):
                return (False, "UntrustedSigner")
            if any(m.device == b.device or m.identity == b.identity or m.mldsa == b.mldsa
                   or (b.xwing is not None and m.xwing == b.xwing) for m in S.values()):
                return (False, "AlreadyListed")
            return self._full(e, status)
        if b.action == ACK:
            return self._full(e, status)  # an ack changes nothing (section 3.16)
        if b.action == LIST_CHECKPOINT:
            return (False, "UntrustedSigner")  # judged on its own past (list_checkpoints.py)
        if b.action == CONFIRM and (s.kind != DEVICE or s.rooted != NONE):
            return (False, "UntrustedSigner")
        m = S.get(b.device)
        if m is None or not m.active or m.kind != b.kind:
            return (False, "NotListed")
        if b.action == REVOKE:
            if m.kind == RECOVERY and s.rooted != NONE and b.device != event.author:
                return (False, "RecoveryKeyProtected")
            # Agent's limit: a list member rooted in
            # an agent revokes only list members rooted in the same agent,
            # until a confirm clears it.
            if s.rooted == AGENT_ROOTED and s.kind != AGENT and not (
                    m.rooted == AGENT_ROOTED and m.agent_root == s.agent_root):
                return (False, "AgentLimited")
            # An agent does not count: a person keeps a device, a passkey
            # member or a recovery key of their own; revoking the last of them
            # would hand the list to the agent.
            if not any(o.active and o.kind != AGENT for k, o in S.items() if k != b.device):
                return (False, "LastMember")
            return self._full(e, status)
        if m.kind not in (DEVICE, RECOVERY) or m.rooted == NONE:
            return (False, "NotPending")
        return self._full(e, status)

    def _full(self, e: bytes, status) -> tuple:
        """At most 4,096 valid list events in the event's
        valid past, itself included. Events that fail count for nothing."""
        if len(self._place_of(e, status)) + 1 > MAX_LIST_EVENTS:
            return (False, "Full")
        return (True, None)

    def self_revocation(self, e: bytes) -> bool:
        b = self.bodies[e]
        return b.action == REVOKE and b.device == self.log.events[e].author

    def attacks(self, x: bytes, e: bytes) -> str | None:
        """Does x void e when both are valid and concurrent?"""
        if not self.log.concurrent(x, e):
            return None
        bx, be = self.bodies[x], self.bodies[e]
        author = self.log.events[e].author
        if bx.action == REVOKE:
            if author == bx.device and not self.self_revocation(e):
                return "RevokedConcurrently"
            if be.action == CONFIRM and be.device == bx.device:
                return "TargetRevokedConcurrently"
        # Adds that name one Ed25519, X-Wing or ML-DSA-65 key without naming
        # the same device ID and kind: the first in canonical order stands.
        if bx.action == ADD and be.action == ADD and (bx.device, bx.kind) != (be.device, be.kind):
            overlap = (bx.identity == be.identity or bx.mldsa == be.mldsa
                       or (bx.xwing is not None and bx.xwing == be.xwing))
            if overlap and self.log.order_key(x) < self.log.order_key(e):
                return "AlreadyListed"
        return None

    def mutual(self, x: bytes, e: bytes) -> bool:
        bx, be = self.bodies[x], self.bodies[e]
        ax, ae = self.log.events[x].author, self.log.events[e].author
        return (bx.action == REVOKE and be.action == REVOKE and ax != ae
                and bx.device == ae and be.device == ax and self.log.concurrent(x, e))

    def rank_at(self, e: bytes, status) -> int:
        """Its author's rank at its place; an author that is no list member
        there has no authority (section 3.3) and ranks below every member."""
        m = self.state(self._place_of(e, status)).get(self.log.events[e].author)
        return m.rank if m is not None else 5

    def dropped(self, x: bytes, e: bytes, status):
        if not self.mutual(x, e):
            return False
        if not all(p in status for p in self.contested_past[x] | self.contested_past[e]):
            return None
        return self.rank_at(e, status) <= self.rank_at(x, status)

    def seniority(self, device: bytes, S) -> tuple:
        m = S[device]
        keys = [self.add_key(a) for a in m.adds]
        if getattr(m, "base_seniority", None) is not None:
            keys.append(m.base_seniority)
        return min(keys)

    def add_key(self, a: bytes) -> tuple:
        """The epoch, the height, then a hash of the person ID and the added
        device ID, which no signer chooses, then the add's ID."""
        return (self.epoch, self.log.height[a],
                sha256(LIST_SENIORITY_LABEL + self.person_id + self.bodies[a].device), a)

    def pick_key(self, e: bytes, status) -> tuple:
        S = self.state(self._place_of(e, status))
        author = self.log.events[e].author
        return (S[author].rank, self.seniority(author, S), self.log.height[e], e)

    def _resolve(self) -> None:
        log = self.log
        for i in self.view:
            if i == log.genesis:
                continue
            if i in self.structural:
                self.status[i] = (False, self.structural[i], None)
                continue
            if i in self.status:
                continue  # decided before the merge
            author = log.events[i].author
            if author in self.forks and log.events[i].seq >= self.forks[author] \
                    and not self.self_revocation(i):
                self.status[i] = (False, "Forked", None)
        contested = [i for i in log.canonical(self.view)
                     if i != log.genesis and i not in self.status]
        cset = set(contested)
        self.contested_past = {e: frozenset(p for p in log.anc[e] if p in cset) for e in contested}
        decided = decide(
            contested,
            lambda e: self.contested_past[e],
            lambda e: [x for x in contested if self.attacks(x, e)],
            self.auth,
            self.dropped,
            self.pick_key,
        )
        for e, v in decided.items():
            if not v[0] and v[1] == "attacked":
                v = (False, self.attacks(v[2], e), v[2])
            self.status[e] = v
        self.status[log.genesis] = (True, "genesis", None)
        self.valid = frozenset(i for i, v in self.status.items() if v[0])
        self.members = self.state(self.valid)

    # -- results
    def active_members(self) -> dict[bytes, Member]:
        return {k: m for k, m in self.members.items() if m.active and k not in self.forks}

    @property
    def dead(self) -> bool:
        return not self.active_members()

    def writers(self) -> dict[bytes, bytes]:
        """Every device or passkey a valid add names, with that add,
        revoked ones included: a revocation ends a path only once the space
        has answered it (roster.md). A space whose grant carried
        this list's heads answers every revocation in their past with the
        grant itself, so for that space this is the active filter, applied
        where the space can name what refused the write."""
        return {k: (m.adds[0] if m.adds else m.base_add) for k, m in self.members.items()
                if m.kind in (DEVICE, PASSKEY)}

    def ends(self, identity: bytes) -> list[bytes]:
        """roster.md: the events of this list that end a device's
        path through the person: its valid revocations, and for a fork the
        canonically later event of the evidence that fixes its fork point."""
        m = self.members.get(identity)
        out = sorted(m.revoked_by) if m else []
        if identity in self.forks:
            ev = [x for x in self.log.chain_evidence(self.view, lambda i: i not in self.structural)
                  if x["author"] == identity and x["fork_seq"] == self.forks[identity]]
            ev.sort(key=lambda x: self.log.order_key(max(x["first"], x["second"],
                                                         key=self.log.order_key)))
            out.append(max(ev[0]["first"], ev[0]["second"], key=self.log.order_key))
        return out

    def waiting(self, identity: bytes) -> bool:
        """roster.md: a member rooted in an agent and not confirmed,
        whose key events no space accepts (WaitingDevice)."""
        m = self.members.get(identity)
        return m is not None and m.kind != AGENT and m.rooted == AGENT_ROOTED

    def recipients(self, first_seen: dict | None = None, now: int | None = None,
                   wait: int | None = None, forbid_agents: bool = False) -> list:
        """Who receives wraps under a person grant, at this
        verifier. In core protocol 1 a waiting list member receives nothing
        until a confirm clears it. With `wait`, ext-recovery-agent.md's
        waiting period: a verifier vouches for it once `wait` seconds have
        passed since its own first sight of an add that roots it in the
        agent. In a space whose policy forbids agents, nothing while the
        list holds an active agent."""
        if forbid_agents and any(m.kind == AGENT for m in self.active_members().values()):
            return []
        out = []
        for k, m in self.active_members().items():
            if m.kind == AGENT:
                continue
            if m.rooted == AGENT_ROOTED:
                if wait is None:
                    continue
                seen = [first_seen[a] for a in m.agent_adds if a in (first_seen or {})]
                if not seen or now - min(seen) < wait:
                    continue
            out.append(k)
        return sorted(out)


_VERIFIED: dict = {}


def signature_ok(event: events.Event, keys) -> bool | str:
    """events.md, "The ML-DSA-65 half": True when the signature verifies
    under the keys among `keys` that hash to the event's kc; else
    "NoHybridKey" when none does, "BadSignature" when they do and it fails."""
    if event.scheme == events.SCHEME_ED25519:
        return True  # verified at decoding
    held = hs.keys_for(event.kc, keys)
    if held is None:
        return "NoHybridKey"
    hit = _VERIFIED.get((event.id, held[0]))
    if hit is None:
        fresh = events.decode_event(event.signed)
        try:
            events.verify_hybrid(fresh, [held])
            hit = True
        except SpecError:
            hit = "BadSignature"
        _VERIFIED[(event.id, held[0])] = hit
    return hit


# ---------------------------------------------------------------------------
# Account links.

L_VERSION, L_ORIGIN, L_SUBJECT, L_PERSON, L_NONCE, L_SIGNER, L_SIGNATURE = range(7)
U_VERSION, U_LINK, U_SIGNER, U_SIGNATURE = range(4)


def link_statement(origin: str, subject: str, person_id: bytes, nonce: bytes) -> bytes:
    return (ACCOUNT_LINK_LABEL + field(origin.encode()) + field(subject.encode())
            + field(person_id) + field(nonce))


def make_link(origin: str, subject: str, person_id: bytes, nonce: bytes,
              signer: hs.Signer) -> bytes:
    """`signer` is the list member's `ed || kc` (crypto.md, "A device's
    keys"); its Ed25519 key signs."""
    statement = link_statement(origin, subject, person_id, nonce)
    return cbor({L_VERSION: 1, L_ORIGIN: origin, L_SUBJECT: subject, L_PERSON: person_id,
                 L_NONCE: nonce, L_SIGNER: signer.signer_bytes,
                 L_SIGNATURE: ed25519_sign(signer.ed_seed, statement)})


def link_id(origin: str, subject: str, person_id: bytes, nonce: bytes) -> bytes:
    return sha256(link_statement(origin, subject, person_id, nonce))


def make_unlink(lid: bytes, signer: hs.Signer) -> bytes:
    return cbor({U_VERSION: 1, U_LINK: lid, U_SIGNER: signer.signer_bytes,
                 U_SIGNATURE: ed25519_sign(signer.ed_seed, ACCOUNT_UNLINK_LABEL + field(lid))})


def _text_ok(value) -> bool:
    return isinstance(value, str) and 1 <= len(value.encode()) <= 256 and identifier_ok(value)


def verify_link(record: bytes, lst: DeviceList | None = None, unlinks=()) -> dict:
    """The checks in their order."""
    value = uncbor(record)
    if not isinstance(value, dict) or set(value) != set(range(7)) or value[L_VERSION] != 1:
        raise SpecError("Malformed")
    if not (_text_ok(value[L_ORIGIN]) and _text_ok(value[L_SUBJECT])
            and is_bytes(value[L_PERSON], 32) and is_bytes(value[L_NONCE], 16)
            and is_bytes(value[L_SIGNER], 64) and is_bytes(value[L_SIGNATURE], 64)):
        raise SpecError("Malformed")
    ed, _, device = hs.split_signer(value[L_SIGNER])
    if not ed25519_valid(ed):
        raise SpecError("InvalidKey")
    statement = link_statement(value[L_ORIGIN], value[L_SUBJECT], value[L_PERSON],
                               value[L_NONCE])
    if not ed25519_verify_strict(ed, statement, value[L_SIGNATURE]):
        raise SpecError("BadSignature")
    lid = sha256(statement)
    if lst is not None:
        if lst.person_id != value[L_PERSON]:
            raise SpecError("WrongPerson")
        # Step 5: the signer's device ID, of its ed and kc.
        signer = lst.active_members().get(device)
        if signer is None or signer.kind not in (DEVICE, PASSKEY):
            raise SpecError("UntrustedSigner")
        for raw in unlinks:
            u = uncbor(raw)
            if not (isinstance(u, dict) and set(u) == set(range(4)) and u[U_VERSION] == 1
                    and is_bytes(u[U_LINK], 32) and is_bytes(u[U_SIGNER], 64)
                    and is_bytes(u[U_SIGNATURE], 64)):
                continue
            u_ed, _, u_device = hs.split_signer(u[U_SIGNER])
            ever = lst.members.get(u_device)
            if (u[U_LINK] == lid and ever is not None and ever.kind in (DEVICE, PASSKEY)
                    and ed25519_valid(u_ed)
                    and ed25519_verify_strict(u_ed, ACCOUNT_UNLINK_LABEL + field(lid),
                                              u[U_SIGNATURE])):
                raise SpecError("Unlinked")
    return {"link_id": lid, "person_id": value[L_PERSON]}


# ---------------------------------------------------------------------------
# Pins.


def check_pin(log: Log, pinned: set, offered: set) -> str:
    """Advanced, or the report RolledBack or ForkDetected."""
    if not pinned <= offered:
        return "RolledBack"
    if log.fork_points(offered) != log.fork_points(pinned):
        return "ForkDetected"
    return "Advanced"


# ---------------------------------------------------------------------------
# Keys derived from a secret the person holds.


def _keys_from(seeds: dict) -> dict:
    """Public keys of the identity, X-Wing, ML-DSA-65 and fetch seeds, and
    the keys commitment and device ID of the first three (crypto.md, "A
    device's keys"); no X-Wing seed for a holder that has none."""
    out = dict(seeds)
    out["identity"] = ed25519_public(seeds["identity_seed"])
    out["xwing"] = (xwing.xwing_public_key(seeds["xwing_seed"]) if "xwing_seed" in seeds
                    else None)
    out["mldsa_public"] = mldsa.mldsa_keygen(seeds["mldsa_seed"])[0]
    out["kc"] = hs.keys_commitment(out["mldsa_public"], out["xwing"])
    out["device_id"] = hs.device_id(out["identity"], out["kc"])
    if "fetch_seed" in seeds:
        out["fetch_key"] = ed25519_public(seeds["fetch_seed"])
    return out


def signer_of(keys: dict, name: str = "") -> hs.Signer:
    """The key holder of a dict of seeds, as `_keys_from` gives it."""
    return hs.Signer(name, keys["identity_seed"], keys["mldsa_seed"], keys.get("xwing_seed"))


def recovery_printed(secret: bytes) -> str:
    """Base32 of the secret and two check bytes, 55 characters
    in groups of four joined by "-"."""
    assert len(secret) == 32
    text = base64.b32encode(secret + sha256(secret)[:2]).decode().rstrip("=")
    assert len(text) == 55
    return "-".join(text[i:i + 4] for i in range(0, 55, 4))


def read_sheet(text: str) -> bytes:
    """The secret a recovery sheet's printed text gives."""
    s = "".join(c for c in text if c not in " -").upper()
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    if len(s) != 55 or any(c not in alphabet for c in s):
        raise SpecError("InvalidSheet")
    raw = base64.b32decode(s + "=")
    if base64.b32encode(raw).decode().rstrip("=") != s:
        raise SpecError("InvalidSheet")  # not canonical: unused bits set
    if raw[32:] != sha256(raw[:32])[:2]:
        raise SpecError("InvalidSheet")
    return raw[:32]


def recovery_keys(secret: bytes) -> dict:
    """A recovery key's seeds and keys, and its fetch key."""
    assert len(secret) == 32
    prk = hkdf_extract(RECOVERY_SALT, secret)
    infos = {"identity": b"ed25519", "xwing": RECOVERY_HYBRID_LABEL,
             "mldsa": RECOVERY_MLDSA_LABEL, "fetch": RECOVERY_FETCH_LABEL}
    seeds = {f"{k}_seed": hkdf_expand(prk, v, 32) for k, v in infos.items()}
    assert seeds["identity_seed"] == hkdf(RECOVERY_SALT, secret, b"ed25519")
    assert seeds["mldsa_seed"] == hs.recovery_mldsa_seed(secret)
    return {"secret": secret, "printed": recovery_printed(secret), "prk": prk, "infos": infos,
            **_keys_from(seeds)}


def passkey_prf_input() -> bytes:
    """The same for every person."""
    return sha256(PASSKEY_PRF_INPUT_LABEL)


def passkey_keys(person_id: bytes, output: bytes) -> dict:
    """One extract from the PRF output, then five
    expands whose infos each end with field(person_id)."""
    if len(person_id) != 32:
        raise SpecError("InvalidPersonId")
    if len(output) != 32:
        raise SpecError("InvalidPrfOutput")
    pid = field(person_id)
    infos = {
        "identity": PASSKEY_MEMBER_LABEL + field(b"ed25519") + pid,
        "xwing": PASSKEY_HYBRID_LABEL + pid,
        "mldsa": PASSKEY_MLDSA_LABEL + pid,
        "fetch": PASSKEY_FETCH_LABEL + pid,
        "unlock": PASSKEY_UNLOCK_LABEL + field(b"device-keys") + pid,
    }
    prk = hkdf_extract(PASSKEY_EXTRACT_SALT, output)
    seeds = {f"{k}_seed": hkdf_expand(prk, v, 32) for k, v in infos.items() if k != "unlock"}
    assert seeds["mldsa_seed"] == hs.passkey_mldsa_seed(output, person_id)
    return {"person_id": person_id, "prk": prk, "infos": infos, **_keys_from(seeds),
            "unlock_key": hkdf_expand(prk, infos["unlock"], 32)}


def enrol_passkey(person_id: bytes, first: bytes, second: bytes) -> dict:
    """And 2: two evaluations derive
    one list member, or nothing is signed."""
    a, b = passkey_keys(person_id, first), passkey_keys(person_id, second)
    if any(a[k] != b[k] for k in ("identity", "xwing", "mldsa_public")):
        raise SpecError("UnstablePrf")
    return a


def invite_keys(secret: bytes) -> dict:
    """An invite key's seeds and keys (ext-invite-links.md, "The secret, its
    keys and the link"), without the locator and the drop key."""
    assert len(secret) == 32
    prk = hkdf_extract(INVITE_SALT, secret)
    infos = {"identity": b"ed25519", "xwing": INVITE_HYBRID_LABEL, "mldsa": INVITE_MLDSA_LABEL}
    seeds = {f"{k}_seed": hkdf_expand(prk, v, 32) for k, v in infos.items()}
    assert seeds["mldsa_seed"] == hs.invite_mldsa_seed(secret)
    return {"secret": secret, "prk": prk, "infos": infos, **_keys_from(seeds)}


def fixture_keys(identity_seed: bytes) -> dict:
    """crypto.md, "A device's keys": a test fixture's three key pairs, from an
    identity seed alone, with its kc and device ID."""
    seeds = {"identity_seed": identity_seed,
             "xwing_seed": hs.device_hybrid_seed_fixture(identity_seed),
             "mldsa_seed": hs.device_mldsa_seed_fixture(identity_seed)}
    return _keys_from(seeds)


def agent_keys(identity_seed: bytes) -> dict:
    """A recovery agent's keys (ext-recovery-agent.md): an Ed25519 key and an
    ML-DSA-65 key, the fixture derivation's, and no X-Wing key; its kc hashes
    an empty X-Wing key."""
    return _keys_from({"identity_seed": identity_seed,
                       "mldsa_seed": hs.device_mldsa_seed_fixture(identity_seed)})


# ---------------------------------------------------------------------------
# Recovery entries.

E_VERSION, E_SPACE, E_KEY, E_MEMBER, E_SEED = range(5)


def recovery_entry(space: bytes, key: bytes, member: bytes | None = None,
                   seed: bytes | None = None) -> bytes:
    value = {E_VERSION: 1, E_SPACE: space, E_KEY: key}
    if member is not None:
        value[E_MEMBER] = member
    if seed is not None:
        value[E_SEED] = seed
    return cbor(value)


def read_recovery_entry(data: bytes, personal_space: bytes) -> dict:
    """Reader's checks in order."""
    try:
        value = uncbor(data)
    except SpecError as error:
        raise SpecError("Malformed") from error
    if not isinstance(value, dict) or not all(is_uint(k) for k in value):
        raise SpecError("Malformed")
    if value.get(E_VERSION) != 1:
        raise SpecError("UnsupportedVersion")
    own = E_MEMBER if value.get(E_SPACE) == personal_space else E_SEED
    if set(value) != {E_VERSION, E_SPACE, E_KEY, own}:
        raise SpecError("Malformed")
    if not all(is_bytes(value[k], 32) for k in (E_SPACE, E_KEY, own)):
        raise SpecError("Malformed")
    if not ed25519_valid(value[E_KEY]):
        raise SpecError("InvalidKey")
    if own == E_SEED and ed25519_public(value[E_SEED]) != value[E_KEY]:
        raise SpecError("Malformed")
    out = {"space": value[E_SPACE], "key": value[E_KEY]}
    out["member" if own == E_MEMBER else "seed"] = value[own]
    return out


# ---------------------------------------------------------------------------
# Fingerprints.

ALPHABET = "23456789abcdefghijkmnpqrstuvwxyz"
QR_PREFIX = "FRASIL-FP1:"
SEPARATORS = " \t\r\n-"
MAX_FINGERPRINT_INPUT = 128
FINGERPRINT_BITS = 120
VALUE_SYMBOLS = 24
GF32_MODULUS = 37  # x^5 + x^2 + 1


def times_x(s: int) -> int:
    t = s << 1
    return t ^ GF32_MODULUS if t >= 32 else t


def check(symbols: list[int]) -> int:
    """The check symbol of the 24 value symbols."""
    assert len(symbols) == VALUE_SYMBOLS
    acc = 0
    for d in symbols:
        acc = times_x(acc) ^ d
    return times_x(acc)


def _syndrome(symbols: list[int]) -> int:
    acc = 0
    for d in symbols:
        acc = times_x(acc) ^ d
    return acc


def fingerprint_characters(value: int) -> tuple[int, str]:
    assert 0 <= value < 1 << FINGERPRINT_BITS
    symbols = [(value >> (5 * (VALUE_SYMBOLS - 1 - i))) & 31 for i in range(VALUE_SYMBOLS)]
    c = check(symbols)
    assert _syndrome(symbols + [c]) == 0
    return c, "".join(ALPHABET[s] for s in symbols + [c])


def fingerprint(person_id: bytes, identity_key: bytes, mldsa_public: bytes,
                xwing_public: bytes) -> dict:
    """A fingerprint of keys. `xwing_public` is empty for an agent; `person_id` is 32
    zero bytes for a roster grant of a device."""
    if len(person_id) != 32:
        raise SpecError("InvalidPersonId")
    if (not ed25519_valid(identity_key) or len(mldsa_public) != MLDSA_BYTES
            or (xwing_public and not hybrid_key_valid(xwing_public))):
        raise SpecError("InvalidKey")
    digest_input = (FINGERPRINT_LABEL + person_id + identity_key + field(mldsa_public)
                    + field(xwing_public))
    digest = sha256(digest_input)
    value = int.from_bytes(digest[:15], "big")
    c, characters = fingerprint_characters(value)
    return {"digest_input": digest_input, "digest": digest, "value": value, "check": c,
            "characters": characters,
            "display": " ".join(characters[i:i + 5] for i in range(0, 25, 5)),
            "qr": QR_PREFIX + characters.upper()}


def parse_fingerprint(text: str) -> str:
    """In order. Returns the 25 characters."""
    if len(text) > MAX_FINGERPRINT_INPUT or any(ord(c) > 0x7F for c in text):
        raise SpecError("InvalidFingerprint")
    s = text.strip(" \t\r\n")
    if s[:len(QR_PREFIX)].upper() == QR_PREFIX:
        s = s[len(QR_PREFIX):]
    if ":" in s:
        raise SpecError("InvalidFingerprint")
    s = "".join(c for c in s if c not in SEPARATORS).lower()
    if len(s) != 25 or any(c not in ALPHABET for c in s):
        raise SpecError("InvalidFingerprint")
    symbols = [ALPHABET.index(c) for c in s]
    if symbols[24] != check(symbols[:24]):
        raise SpecError("FingerprintMistyped")
    return s


# ---------------------------------------------------------------------------
# Example lists.


class Person:
    """A person's list being built in the vectors, over a History of kind 1."""

    def __init__(self, first: str, prefix: str = "identity", linear: bool = False):
        self.linear = linear
        self.hist = History(prefix)
        self.prefix = prefix
        self.kinds: dict[str, int] = {}
        self.hybrids: dict[str, bytes | None] = {}
        dev = self.hist.device(first)
        sig = self.hist.signer(first)
        hyb = self.xwing(first)
        self.kinds[first], self.hybrids[first] = DEVICE, hyb
        proof = prove(sig, possession_statement(ZERO_PERSON, dev, DEVICE, sig.ed_public,
                                                sig.mldsa_public, hyb))
        body = list_body(ADD, DEVICE, dev, identity=sig.ed_public, possession=proof, xwing=hyb,
                         mldsa_public=sig.mldsa_public)
        self.genesis = self.hist.genesis(first, KIND_DEVICE_LIST, body, f"{first} starts the list")

    @property
    def log(self) -> Log:
        return self.hist.log

    @property
    def id(self) -> bytes:
        return self.hist.log.id

    def xwing(self, name: str) -> bytes | None:
        return self.hist.signer(name).xwing_public

    def add(self, signer: str, name: str, kind: int, label: str | None = None, *,
            hybrid: bool | None = None, xwing_key: bytes | None = None, **kw) -> bytes:
        """`xwing_key` names another X-Wing key than the list member's own,
        which gives another device ID. An agent has no X-Wing key unless
        `hybrid` says otherwise."""
        hybrid = (kind != AGENT) if hybrid is None else hybrid
        if not hybrid:
            self.hist.without_xwing(name)
        sig = self.hist.signer(name)
        hyb = (xwing_key or self.xwing(name)) if hybrid else None
        self.kinds[name], self.hybrids[name] = kind, hyb
        device = hs.device_id_of(sig.ed_public, sig.mldsa_public, hyb)
        proof = prove(sig, possession_statement(self.id, self.hist.device(signer), kind,
                                                sig.ed_public, sig.mldsa_public, hyb))
        body = list_body(ADD, kind, device, identity=sig.ed_public, possession=proof, xwing=hyb,
                         mldsa_public=sig.mldsa_public)
        return self._act(signer, body, label or f"{signer} adds {name}", **kw)

    def add_derived(self, signer: str, name: str, kind: int, keys: dict,
                    label: str | None = None, **kw) -> bytes:
        """An add of a list member whose keys derive from a secret (a passkey's
        PRF output, a recovery sheet: `keys` from passkey_keys or
        recovery_keys), carrying its own proof. It can then sign under
        `name`."""
        self.hist.keys[name] = keys["identity_seed"]
        self.hist.view.setdefault(name, set())
        member = signer_of(keys, name)
        self.hist.signers[name] = member
        self.kinds[name], self.hybrids[name] = kind, keys["xwing"]
        statement = possession_statement(self.id, self.hist.device(signer), kind,
                                         member.ed_public, member.mldsa_public, keys["xwing"])
        body = list_body(ADD, kind, member.device_id, identity=member.ed_public,
                         possession=prove(member, statement), xwing=keys["xwing"],
                         mldsa_public=member.mldsa_public)
        return self._act(signer, body, label or f"{signer} adds {name}", **kw)

    def revoke(self, signer: str, name: str, label: str | None = None, **kw) -> bytes:
        body = list_body(REVOKE, self.kinds[name], self.hist.device(name))
        return self._act(signer, body, label or f"{signer} revokes {name}", **kw)

    def confirm(self, signer: str, name: str, label: str | None = None, **kw) -> bytes:
        body = list_body(CONFIRM, self.kinds[name], self.hist.device(name))
        return self._act(signer, body, label or f"{signer} confirms {name}", **kw)

    def raw(self, signer: str, body: bytes, label: str, **kw) -> bytes:
        return self._act(signer, body, label, **kw)

    def _act(self, signer: str, body: bytes, label: str, **kw) -> bytes:
        """In a linear list every signer first holds every event."""
        self.hist.device(signer)
        if self.linear and "view" not in kw:
            self.hist.view[signer] = set(self.log.events)
        return self.hist.act(signer, KIND_DEVICE_LIST, body, label, **kw)

    def resolve(self, view=None) -> DeviceList:
        return DeviceList(self.log, view)

    def summary(self, lst: DeviceList) -> dict:
        n = self.hist.key_name
        return {
            "events": {self.hist.name(i): ("valid" if v[0] else v[1])
                       + (f" by {self.hist.name(v[2])}" if (not v[0] and v[2]) else "")
                       + (f" ({v[1]})" if v[0] and v[1] in ("agreed", "seniority") else "")
                       for i, v in sorted(lst.status.items(),
                                          key=lambda kv: self.log.order_key(kv[0]))},
            "members": {n(k): {"kind": KIND_NAMES[m.kind], "active": m.active,
                               "rooted": ROOT_NAMES[m.rooted], "rank": m.rank,
                               "forked_at": lst.forks.get(k)}
                        for k, m in sorted(lst.members.items(), key=lambda kv: n(kv[0]))},
            "active": sorted(n(k) for k in lst.active_members()),
            "dead": lst.dead,
        }


def personal_space_fixture(person: bytes) -> bytes:
    """A fixture standing for a person's personal space ID: SHA-256 of a
    label and the person ID, where a real one is the space's genesis ID."""
    return example("identity/personal-space/" + person.hex())


def _flip(data: bytes, i: int) -> bytes:
    return data[:i] + bytes([data[i] ^ 1]) + data[i + 1:]


def list_event_json(p: Person, lst: DeviceList, i: bytes) -> dict:
    """One list event: its body, signed bytes and ID, and for an add the
    statement its proof signs and the keys it names."""
    e = p.log.events[i]
    b = lst.bodies.get(i)
    row = {"name": p.hist.name(i), "author": p.hist.key_name(e.author), "seq": e.seq,
           "body": h(e.body), "signed": h(e.signed), "id": h(i)}
    if b is None:
        return row
    row.update({"action": ACTION_NAMES[b.action], "kind": KIND_NAMES[b.kind],
                "device": h(b.device)})
    if b.action == ADD:
        person = ZERO_PERSON if e.genesis else p.id
        row["identity"] = h(b.identity)
        row["kc"] = h(hs.keys_commitment(b.mldsa, b.xwing))
        row["statement"] = h(possession_statement(person, e.author, b.kind, b.identity, b.mldsa,
                                                  b.xwing))
        row["possession"] = h(b.possession)
        row["mldsa"] = h(b.mldsa)
        row["xwing"] = h(b.xwing) if b.xwing is not None else None
    return row


def _derived_json(d: dict, *names: str) -> dict:
    out = {}
    for n in names:
        v = d[n]
        out[n] = h(v) if isinstance(v, bytes) else v
    return out


def _persons_family() -> tuple[dict, Person, Person]:
    alice = Person("laptop", prefix="identity/alice")
    bob = Person("laptop", prefix="identity/bob")
    persons = {name: {"first_event": h(p.log.events[p.genesis].signed), "person_id": h(p.id),
                      "personal_space_id": h(personal_space_fixture(p.id)),
                      "first_device_kc": h(p.hist.signer("laptop").kc),
                      "first_device_id": h(p.hist.device("laptop"))}
               for name, p in (("alice", alice), ("bob", bob))}
    return persons, alice, bob


def _passkey_family(alice: Person, bob: Person) -> tuple[list, list]:
    out = []
    for name, person, output in [
        ("a passkey of a person", alice.id, example("identity/passkey-1/prf-output")),
        ("a second passkey of the same person", alice.id, example("identity/passkey-2/prf-output")),
        ("the first output under another person", bob.id, example("identity/passkey-1/prf-output")),
        ("an all-zero output", alice.id, bytes(32)),
    ]:
        d = passkey_keys(person, output)
        secrets = [d[k] for k in ("identity_seed", "xwing_seed", "mldsa_seed", "fetch_seed",
                                  "unlock_key")]
        assert len(set(secrets)) == 5 and output not in secrets
        assert ed25519_valid(d["identity"]) and hybrid_key_valid(d["xwing"])
        space = personal_space_fixture(person)
        out.append({
            "name": name, "person_id": h(person), "personal_space_id": h(space),
            "user_handle": h(person + space), "prf_input": h(passkey_prf_input()),
            "webauthn_salt": h(sha256(WEBAUTHN_PRF_CONTEXT + passkey_prf_input())),
            "prf_output": h(output), "prk": h(d["prk"]),
            "infos": {k: h(v) for k, v in d["infos"].items()},
            **_derived_json(d, "identity_seed", "identity", "xwing_seed", "xwing", "mldsa_seed",
                            "mldsa_public", "kc", "device_id", "fetch_seed", "fetch_key",
                            "unlock_key"),
        })
    assert out[0]["identity"] != out[2]["identity"] and out[0]["unlock_key"] != out[2]["unlock_key"]
    refusals = []
    one = example("identity/passkey-1/prf-output")
    for name, person, output in [
        ("a person ID of 31 bytes", alice.id[:31], one),
        ("a person ID of 33 bytes", alice.id + b"\x00", one),
        ("an empty person ID", b"", one),
        ("a PRF output of 31 bytes", alice.id, one[:31]),
        ("a PRF output of 33 bytes", alice.id, one + b"\x00"),
    ]:
        refusals.append({"name": name, "person_id": h(person), "prf_output": h(output),
                         "error": expect_error(passkey_keys, person, output)})
    return out, refusals


def _recovery_family(alice: Person) -> dict:
    secret = example("identity/recovery/secret")
    d = recovery_keys(secret)
    as_passkey = passkey_keys(alice.id, secret)
    assert as_passkey["identity"] != d["identity"]
    printed = d["printed"]
    reading = []
    for name, text in [
        ("as printed", printed),
        ("lower case, spaces for hyphens", printed.lower().replace("-", " ")),
        ("no separators", printed.replace("-", "")),
        ("one character changed", ("B" if printed[0] != "B" else "C") + printed[1:]),
        ("54 characters", printed.replace("-", "")[:54]),
        ("a character outside the alphabet", "1" + printed[1:]),
    ]:
        try:
            got = {"secret": h(read_sheet(text))}
        except SpecError as error:
            got = {"error": error.error}
        reading.append({"name": name, "text": text, **got})
    return {
        "secret": h(secret), "printed": printed, "salt": h(RECOVERY_SALT), "prk": h(d["prk"]),
        "infos": {k: h(v) for k, v in d["infos"].items()},
        **_derived_json(d, "identity_seed", "identity", "xwing_seed", "xwing", "mldsa_seed",
                        "mldsa_public", "kc", "device_id", "fetch_seed", "fetch_key"),
        "reading": reading,
        "same_bytes_as_prf_output": {
            "person_id": h(alice.id),
            **_derived_json(as_passkey, "identity", "xwing", "mldsa_public", "fetch_key",
                            "unlock_key")},
    }


def _entries_family(alice: Person) -> dict:
    personal = personal_space_fixture(alice.id)
    other = example("identity/entries/other-space")
    rk = recovery_keys(example("identity/recovery/secret"))
    seed = example("identity/entries/fetch-seed")
    small = bytes(32)  # an Ed25519 encoding of a small-order point: y = 0 is not; use 1
    small = (1).to_bytes(32, "little")  # the neutral point (0, 1)
    accepted = []
    for name, data in [
        ("the personal space's entry for a recovery key",
         recovery_entry(personal, rk["fetch_key"], member=rk["device_id"])),
        ("another space's entry, with its random fetch seed",
         recovery_entry(other, ed25519_public(seed), seed=seed)),
    ]:
        r = read_recovery_entry(data, personal)
        accepted.append({"name": name, "entry": h(data),
                         **{k: h(v) for k, v in r.items()}})
    refused = []
    for name, data in [
        ("both member and seed", cbor({E_VERSION: 1, E_SPACE: other, E_KEY: ed25519_public(seed),
                                       E_MEMBER: rk["device_id"], E_SEED: seed})),
        ("neither member nor seed", cbor({E_VERSION: 1, E_SPACE: other,
                                          E_KEY: ed25519_public(seed)})),
        ("the personal space's entry with a seed, not a member",
         recovery_entry(personal, ed25519_public(seed), seed=seed)),
        ("a seed that does not give the key",
         recovery_entry(other, rk["fetch_key"], seed=seed)),
        ("a key of small order", recovery_entry(personal, small, member=rk["device_id"])),
        ("version 2", cbor({E_VERSION: 2, E_SPACE: personal, E_KEY: rk["fetch_key"],
                            E_MEMBER: rk["device_id"]})),
        ("a key of 31 bytes", recovery_entry(personal, rk["fetch_key"][:31],
                                             member=rk["device_id"])),
    ]:
        refused.append({"name": name, "entry": h(data),
                        "error": expect_error(read_recovery_entry, data, personal)})
    return {"person_id": h(alice.id), "personal_space_id": h(personal), "accepted": accepted,
            "refused": refused}


POSSESSION_PREFIX = "identity/possession"


def _possession_base(sheet: dict, member: dict) -> Person:
    p = Person("laptop", prefix=POSSESSION_PREFIX, linear=True)
    p.add_derived("laptop", "recovery", RECOVERY, sheet,
                  "the device adds the recovery key it has just created")
    p.add_derived("laptop", "passkey", PASSKEY, member,
                  "the device adds a passkey member, derived in this browser")
    return p


def _possession_families() -> dict:
    from primitives import L, ed25519_sign_with_nonce, ed25519_verify_lenient

    person = Person("laptop", prefix=POSSESSION_PREFIX).id
    member = passkey_keys(person, example(f"{POSSESSION_PREFIX}/passkey/prf-output"))
    sheet = recovery_keys(example(f"{POSSESSION_PREFIX}/recovery/secret"))
    p = _possession_base(sheet, member)
    p.add("passkey", "browser", DEVICE, "the passkey member adds the browser that holds it")
    p.add("laptop", "phone", DEVICE,
          "the device adds a phone, whose proof came with the admission exchange")
    p.add("laptop", "agent", AGENT, "the device names a recovery agent: no X-Wing key")
    p.add("recovery", "tablet", DEVICE, "the recovery key adds a new device, which signed its proof")
    lst = p.resolve()
    assert all(v[0] for v in lst.status.values())
    cases = {
        p.genesis: "the first device",
        p.hist.by_name("the device adds the recovery key it has just created"): "a recovery key",
        p.hist.by_name("the device adds a passkey member, derived in this browser"):
            "a passkey member",
        p.hist.by_name("the passkey member adds the browser that holds it"):
            "a device added by a passkey member",
        p.hist.by_name("the device adds a phone, whose proof came with the admission exchange"):
            "a device added by another list member",
        p.hist.by_name("the device names a recovery agent: no X-Wing key"): "a recovery agent",
        p.hist.by_name("the recovery key adds a new device, which signed its proof"):
            "a device added by a recovery key",
    }
    adds = []
    for i in p.log.canonical():
        row = list_event_json(p, lst, i)
        row["case"] = cases[i]
        adds.append(row)

    phone = p.hist.signer("phone")
    phone_xwing = p.xwing("phone")
    laptop = p.hist.device("laptop")
    statement = possession_statement(person, laptop, DEVICE, phone.ed_public,
                                     phone.mldsa_public, phone_xwing)
    fields = [("label", POSSESSION_LABEL), ("person_id", field(person)),
              ("adder", field(laptop)),
              ("kind", field(bytes([DEVICE]))), ("identity", field(phone.ed_public)),
              ("mldsa", field(phone.mldsa_public)), ("xwing", field(phone_xwing)),
              ("scheme", field(bytes([2])))]
    assert b"".join(v for _, v in fields) == statement and len(statement) == 3326
    agent = p.hist.signer("agent")
    assert len(possession_statement(person, laptop, AGENT, agent.ed_public,
                                    agent.mldsa_public)) == 2110
    phone_proof = prove(phone, statement)
    field_by_field = {
        "fields": [{"field": n, "bytes": h(v)} for n, v in fields],
        "statement": h(statement), "statement_bytes": len(statement),
        "m_ed": h(hs.hybrid_ed25519_message(phone.ed_public, statement)),
        "possession": h(phone_proof),
    }

    def refuse(name: str, *, proof=None, statement=None, kind=DEVICE, ident=None,
               signer=None, xw=None, mld=None, device=None, lenient=False) -> dict:
        q = _possession_base(sheet, member)
        tablet = q.hist.signer("tablet")
        ident_ = ident if ident is not None else tablet.ed_public
        hyb = q.xwing("tablet") if xw is None else xw(q)
        mld = tablet.mldsa_public if mld is None else mld(q)
        if proof is None:
            stmt = statement(q, tablet) if statement else possession_statement(
                q.id, q.hist.device("laptop"), kind, ident_, mld, hyb)
            proof = prove(signer(q) if signer else tablet, stmt)
        elif callable(proof):
            proof = proof(q, tablet)
        device = hs.device_id_of(ident_, mld, hyb) if device is None else device(q)
        body = list_body(ADD, kind, device, identity=ident_, possession=proof, xwing=hyb,
                         mldsa_public=mld)
        bad = q.raw("laptop", body, name)
        record = {"name": name, "event": h(q.log.events[bad].signed), "possession": h(proof),
                  "error": q.resolve().status[bad][1]}
        if lenient:
            stmt = possession_statement(q.id, q.hist.device("laptop"), kind, ident_, mld, hyb)
            record["lenient_ed25519_half_accepts"] = ed25519_verify_lenient(
                ident_, hs.hybrid_ed25519_message(ident_, stmt), proof[:64])
        return record

    def other_statement(**over):
        def make(q, tablet):
            v = {"person": q.id, "adder": q.hist.device("laptop"), "kind": DEVICE,
                 "mldsa": tablet.mldsa_public, "xwing": q.xwing("tablet")}
            v.update({k: (f(q) if callable(f) else f) for k, f in over.items()})
            return possession_statement(v["person"], v["adder"], v["kind"], tablet.ed_public,
                                        v["mldsa"], v["xwing"])
        return make

    other_person = Person("laptop", prefix=f"{POSSESSION_PREFIX}/other").id
    stranger = events.signer_for(example(f"{POSSESSION_PREFIX}/stranger/ed25519"), "stranger")

    def honest(q, tablet):
        stmt = possession_statement(q.id, q.hist.device("laptop"), DEVICE, tablet.ed_public,
                                    tablet.mldsa_public, q.xwing("tablet"))
        return stmt, prove(tablet, stmt)

    def s_not_reduced(q, tablet):
        _, pr = honest(q, tablet)
        s = int.from_bytes(pr[32:64], "little") + L
        return pr[:32] + s.to_bytes(32, "little") + pr[64:]

    def r_neutral(q, tablet):
        stmt, pr = honest(q, tablet)
        m_ed = hs.hybrid_ed25519_message(tablet.ed_public, stmt)
        return ed25519_sign_with_nonce(tablet.ed_seed, m_ed, 0) + pr[64:]

    def scheme_zero(q, tablet):
        stmt, _ = honest(q, tablet)
        return stmt[:-5] + field(b"\x00")

    def lent_key(q):
        # The phone's Ed25519 key, which the forger can sign for, beside the
        # adder's own ML-DSA-65 key, under the phone's device ID.
        phone_, laptop_ = q.hist.signer("phone"), q.hist.signer("laptop")
        lender = hs.Signer("lent", phone_.ed_seed, laptop_.mldsa_seed,
                           xwing_public=phone_.xwing_public)
        return prove(lender, possession_statement(q.id, q.hist.device("laptop"), DEVICE,
                                                  phone_.ed_public, laptop_.mldsa_public,
                                                  phone_.xwing_public))

    small = (1).to_bytes(32, "little")
    refusals = [
        refuse("a proof for another person", statement=other_statement(person=other_person)),
        refuse("a proof over 32 zero bytes, after the first event",
               statement=other_statement(person=bytes(32))),
        refuse("a proof for another kind", statement=other_statement(kind=RECOVERY)),
        refuse("a proof for another adder: the passkey member, not the device that signs",
               statement=other_statement(adder=lambda q: q.hist.device("passkey"))),
        refuse("a proof naming another ML-DSA-65 key",
               statement=other_statement(mldsa=stranger.mldsa_public)),
        refuse("a proof naming another X-Wing key", statement=other_statement(
            xwing=xwing.xwing_public_key(example(f"{POSSESSION_PREFIX}/other-xwing")))),
        refuse("a proof that leaves out the X-Wing key the add names",
               statement=other_statement(xwing=None)),
        refuse("a proof whose statement says scheme 0", statement=scheme_zero),
        refuse("a proof by the approver", signer=lambda q: q.hist.signer("laptop")),
        refuse("a proof by a stranger's keys", signer=lambda q: stranger),
        refuse("an add whose keys do not give its key 3: the tablet's keys under the phone's "
               "device ID", device=lambda q: q.hist.device("phone")),
        refuse("an add that pairs the phone's Ed25519 key with the adder's own ML-DSA-65 key, "
               "under the phone's device ID",
               ident=p.hist.signer("phone").ed_public, mld=lambda q: q.hist.mldsa("laptop"),
               xw=lambda q: q.xwing("phone"), device=lambda q: q.hist.device("phone"),
               proof=lambda q, t: lent_key(q)),
        refuse("an Ed25519 half whose S is not reduced", proof=s_not_reduced, lenient=True),
        refuse("an Ed25519 half whose R is of small order, made by the key's holder",
               proof=r_neutral, lenient=True),
        refuse("a changed bit in the ML-DSA-65 half",
               proof=lambda q, t: _flip(honest(q, t)[1], 164)),
        refuse("an Ed25519 half alone, 64 bytes", proof=lambda q, t: honest(q, t)[1][:64]),
        refuse("an identity key of small order, with a proof of zero bytes", ident=small,
               proof=bytes(PROOF_BYTES)),
    ]

    mallory = Person("laptop", prefix=f"{POSSESSION_PREFIX}/mallory", linear=True)
    forged = []
    for name, i in [
        ("the victim's phone, with the proof it made for the victim's list",
         p.hist.by_name("the device adds a phone, whose proof came with the admission exchange")),
        ("the victim's first device, with the proof of the victim's first event", p.genesis),
        ("the victim's passkey member, with its proof",
         p.hist.by_name("the device adds a passkey member, derived in this browser")),
    ]:
        b = lst.bodies[i]
        bad = mallory.raw("laptop", list_body(ADD, b.kind, b.device, identity=b.identity,
                                              possession=b.possession, xwing=b.xwing,
                                              mldsa_public=b.mldsa), name)
        forged.append({"name": name, "event": h(mallory.log.events[bad].signed),
                       "error": mallory.resolve().status[bad][1]})
    # A forger that signs Ed25519 for the victim's phone adds the phone's
    # Ed25519 key with an ML-DSA-65 key and an X-Wing key of its own. The add
    # is valid in the forger's list, and names a device ID of its own: its
    # events are that device's, never the phone's, and no space that reads
    # the list takes a key for the phone from it.
    victim = p.hist.signer("phone")
    lent = hs.Signer("phone, lent", victim.ed_seed,
                     example(f"{POSSESSION_PREFIX}/mallory/lent/mldsa"),
                     example(f"{POSSESSION_PREFIX}/mallory/lent/xwing"))
    mallory.hist.keys["phone, lent"] = victim.ed_seed
    mallory.hist.signers["phone, lent"] = lent
    mallory.hist.view["phone, lent"] = set()
    add = mallory.raw("laptop", list_body(
        ADD, DEVICE, lent.device_id, identity=lent.ed_public,
        possession=prove(lent, possession_statement(mallory.id, mallory.hist.device("laptop"),
                                                    DEVICE, lent.ed_public, lent.mldsa_public,
                                                    lent.xwing_public)),
        xwing=lent.xwing_public, mldsa_public=lent.mldsa_public),
        "the victim's phone's Ed25519 key, with the forger's own ML-DSA-65 and X-Wing keys")
    mallory.hist.sync("laptop", "phone, lent")
    by_lent = mallory.raw("phone, lent", list_body(CONFIRM, DEVICE, lent.device_id),
                          "an event the lent key set signs: its author is not the phone")
    res = mallory.resolve()
    assert lent.device_id != victim.device_id
    assert mallory.log.events[by_lent].author == lent.device_id
    forged.append({"name": "the victim's phone's Ed25519 key, with the forger's own ML-DSA-65 "
                           "and X-Wing keys: a device ID of its own",
                   "event": h(mallory.log.events[add].signed),
                   "verdict": "valid" if res.status[add][0] else res.status[add][1],
                   "named_device_id": h(lent.device_id), "victim_device_id": h(victim.device_id),
                   "signed_by_that_key_set": h(mallory.log.events[by_lent].signed),
                   "its_author": h(mallory.log.events[by_lent].author)})
    return {
        "possession": {"person_id": h(person), "adds": adds, "field_by_field": field_by_field},
        "possession_refusals": refusals,
        "forged_list": {"person_id": h(person), "forger_person_id": h(mallory.id),
                        "forger_first_event": h(mallory.log.events[mallory.genesis].signed),
                        "events": forged},
    }


def _list_family() -> tuple[dict, Person, DeviceList]:
    p = Person("laptop", linear=True)
    p.add("laptop", "phone", DEVICE)
    p.add("laptop", "passkey", PASSKEY)
    p.add("passkey", "browser", DEVICE, "passkey adds browser, rooted in a passkey")
    p.add("laptop", "recovery", RECOVERY)
    p.confirm("laptop", "browser")
    p.add("laptop", "agent", AGENT)
    p.add("agent", "helped", DEVICE, "agent adds helped, rooted in the agent")
    p.revoke("phone", "browser")
    lst = p.resolve()
    n = p.hist.key_name
    return ({"person_id": h(p.id),
             "events": [list_event_json(p, lst, i) for i in p.log.canonical()],
             "result": p.summary(lst),
             "recipients": sorted(n(k) for k in lst.recipients()),
             "recipients_forbidding_agents": sorted(
                 n(k) for k in lst.recipients(forbid_agents=True))}, p, lst)


PASSKEY_LIST_PREFIX = "identity/passkey-list"
PASSKEY_LIST_STEPS = [
    ("the first device starts the list", None, DEVICE, "laptop", "laptop"),
    ("the device adds the recovery key", ADD, RECOVERY, "recovery-1", "laptop"),
    ("the device adds a passkey member, after two evaluations agree", ADD, PASSKEY, "passkey-1",
     "laptop"),
    ("the passkey member adds the browser that holds it, which is rooted in a passkey",
     ADD, DEVICE, "browser", "passkey-1"),
    ("the rooted browser adds a second passkey member", ADD, PASSKEY, "passkey-2", "browser"),
    ("the rooted browser revokes that passkey member", REVOKE, PASSKEY, "passkey-2", "browser"),
    ("the first device confirms the browser", CONFIRM, DEVICE, "browser", "laptop"),
    ("the confirmed browser adds a new recovery key", ADD, RECOVERY, "recovery-2", "browser"),
    ("the confirmed browser revokes the old recovery key", REVOKE, RECOVERY, "recovery-1",
     "browser"),
    ("the recovery key adds its replacement", ADD, RECOVERY, "recovery-3", "recovery-2"),
    ("the old recovery key revokes itself", REVOKE, RECOVERY, "recovery-2", "recovery-2"),
    ("the passkey member adds a tablet, which is rooted", ADD, DEVICE, "tablet", "passkey-1"),
    ("the rooted tablet adds a recovery key, which is rooted", ADD, RECOVERY, "recovery-4",
     "tablet"),
    ("that rooted recovery key revokes itself", REVOKE, RECOVERY, "recovery-4", "recovery-4"),
    ("the passkey member revokes the tablet", REVOKE, DEVICE, "tablet", "passkey-1"),
    ("the passkey member revokes itself", REVOKE, PASSKEY, "passkey-1", "passkey-1"),
    ("the recovery key adds a device, which is not rooted", ADD, DEVICE, "desk", "recovery-3"),
]


def _passkey_list_derived() -> tuple[bytes, dict]:
    person = Person("laptop", prefix=PASSKEY_LIST_PREFIX).id
    derived = {n: passkey_keys(person, example(f"{PASSKEY_LIST_PREFIX}/{n}/prf-output"))
               for n in ("passkey-1", "passkey-2")}
    derived.update({f"recovery-{i}": recovery_keys(
        example(f"{PASSKEY_LIST_PREFIX}/recovery-{i}/secret")) for i in (1, 2, 3, 4, 5)})
    return person, derived


def _passkey_list_build(count: int, derived: dict) -> tuple[Person, list]:
    p = Person("laptop", prefix=PASSKEY_LIST_PREFIX, linear=True)
    p.hist.names[p.genesis] = PASSKEY_LIST_STEPS[0][0]
    ids = [p.genesis]
    for description, action, kind, name, signer in PASSKEY_LIST_STEPS[1:count]:
        if action == ADD and name in derived:
            ids.append(p.add_derived(signer, name, kind, derived[name], description))
        elif action == ADD:
            ids.append(p.add(signer, name, kind, description))
        elif action == REVOKE:
            ids.append(p.revoke(signer, name, description))
        else:
            ids.append(p.confirm(signer, name, description))
    return p, ids


def _passkey_list_family() -> dict:
    person, derived = _passkey_list_derived()
    p, ids = _passkey_list_build(len(PASSKEY_LIST_STEPS), derived)
    assert p.id == person and len(ids) == 17
    lst = p.resolve()
    assert all(lst.status[i][0] for i in ids)
    events_ = []
    for (description, action, kind, name, signer), i in zip(PASSKEY_LIST_STEPS, ids):
        row = list_event_json(p, lst, i)
        row.update({"description": description, "names": name, "signed_by": signer})
        events_.append(row)
    return {
        "person_id": h(person),
        "derived": [{"name": n, "kind": KIND_NAMES[PASSKEY if n.startswith("passkey") else
                                                   RECOVERY],
                     ("prf_output" if n.startswith("passkey") else "secret"): h(
                         example(f"{PASSKEY_LIST_PREFIX}/{n}/"
                                 + ("prf-output" if n.startswith("passkey") else "secret"))),
                     **_derived_json(d, "identity", "xwing", "mldsa_public", "fetch_key")}
                    for n, d in derived.items()],
        "events": events_,
        "result": p.summary(lst),
    }


def _list_refusals_family() -> dict:
    """Events appended to a base list, each refused at decoding or at the
    event's place, with its class."""
    base: list = []
    cases = []

    def build_base() -> Person:
        q = Person("laptop", prefix="identity/refusals", linear=True)
        q.add("laptop", "phone", DEVICE)
        q.add("laptop", "passkey", PASSKEY)
        q.add("passkey", "browser", DEVICE, "passkey adds browser, rooted in a passkey")
        q.add("laptop", "recovery", RECOVERY)
        q.add("laptop", "agent", AGENT)
        for n in ("phone", "passkey", "browser", "recovery", "agent"):
            q.hist.sync("laptop", n)
        return q

    def refuse(name: str, build):
        q = build_base()
        base_ids = set(q.log.events)
        if not base:
            base.extend(q.hist.describe())
        bad = build(q)
        res = q.resolve()
        cases.append({"name": name,
                      "also_before": [d for d in q.hist.describe(q.log.anc[bad])
                                      if bytes.fromhex(d["id"]) not in base_ids],
                      "event": h(q.log.events[bad].signed),
                      "error": res.status[bad][1]})

    def tablet_add(q, change=None, over=None) -> bytes:
        t = q.hist.signer("tablet")
        b = {B_VERSION: ENTRY_VERSION, B_ACTION: ADD, B_KIND: DEVICE, B_DEVICE: t.device_id,
             B_POSSESSION: bytes(PROOF_BYTES), B_XWING: q.xwing("tablet"),
             B_MLDSA: t.mldsa_public, B_IDENTITY: t.ed_public}
        b.update(over or {})
        if change:
            b = change(b)
        return q.raw("laptop", cbor(b), "bad")

    without = lambda key: (lambda b: {k: v for k, v in b.items() if k != key})  # noqa: E731
    refuse("entry version 2", lambda q: tablet_add(q, over={B_VERSION: 2}))
    refuse("an add without its possession", lambda q: tablet_add(q, without(B_POSSESSION)))
    refuse("an add without an ML-DSA-65 key", lambda q: tablet_add(q, without(B_MLDSA)))
    refuse("an add without its Ed25519 key, key 7", lambda q: tablet_add(q, without(B_IDENTITY)))
    refuse("a device's add without an X-Wing key", lambda q: tablet_add(q, without(B_XWING)))
    refuse("an ML-DSA-65 key of 1,951 bytes",
           lambda q: tablet_add(q, over={B_MLDSA: q.hist.mldsa("tablet")[:-1]}))
    refuse("a revoke carrying a possession",
           lambda q: q.raw("laptop", cbor({**uncbor(list_body(REVOKE, DEVICE,
                                                              q.hist.device("phone"))),
                                           B_POSSESSION: bytes(PROOF_BYTES)}), "bad"))
    refuse("an unknown key 8", lambda q: tablet_add(q, over={8: b""}))
    refuse("an unknown kind, 4", lambda q: tablet_add(q, over={B_KIND: 4}))
    refuse("an unknown action, 5", lambda q: tablet_add(q, over={B_ACTION: 5}))
    refuse("an agent naming an X-Wing key",
           lambda q: q.add("laptop", "agent2", AGENT, "bad", hybrid=True))
    refuse("an X-Wing key with a coefficient of q = 3329", lambda q: tablet_add(
        q, over={B_XWING: bytes([0x01, 0x0D]) + q.xwing("tablet")[2:]}))
    refuse("an X-Wing key whose X25519 part is zero", lambda q: tablet_add(
        q, over={B_XWING: q.xwing("tablet")[:1184] + bytes(32)}))
    refuse("an identity key of small order",
           lambda q: tablet_add(q, over={B_IDENTITY: (1).to_bytes(32, "little")}))

    def bad_proof(q, person=None, kind=DEVICE, mldsa_key=None, ed_only=False, adder=None):
        t = q.hist.signer("tablet")
        st = possession_statement(q.id if person is None else person,
                                  adder or q.hist.device("laptop"), kind, t.ed_public,
                                  mldsa_key or t.mldsa_public, q.xwing("tablet"))
        proof = prove(t, st)
        if ed_only:
            proof = ed25519_sign(t.ed_seed, st) + proof[64:]
        return q.raw("laptop", list_body(ADD, DEVICE, t.device_id, identity=t.ed_public,
                                         possession=proof, xwing=q.xwing("tablet"),
                                         mldsa_public=t.mldsa_public),
                     "bad")

    refuse("a proof that binds 32 zero bytes, not the person ID",
           lambda q: bad_proof(q, person=ZERO_PERSON))
    refuse("a proof that names another kind", lambda q: bad_proof(q, kind=PASSKEY))
    refuse("a proof that names another adder, the phone",
           lambda q: bad_proof(q, adder=q.hist.device("phone")))
    refuse("a proof that binds another ML-DSA-65 key",
           lambda q: bad_proof(q, mldsa_key=q.hist.mldsa("phone")))
    refuse("a proof whose Ed25519 half is a scheme-0 signature of the statement",
           lambda q: bad_proof(q, ed_only=True))
    refuse("a device no add names signs an add",
           lambda q: q.add("stranger", "tablet", DEVICE, "bad"))
    refuse("a device no add names signs a revoke",
           lambda q: q.raw("stranger", list_body(REVOKE, DEVICE, q.hist.device("phone")), "bad"))
    refuse("an agent adds a passkey member", lambda q: q.add("agent", "tablet", PASSKEY, "bad"))
    refuse("an agent revokes a device", lambda q: q.revoke("agent", "phone", "bad"))
    refuse("an agent confirms", lambda q: q.confirm("agent", "browser", "bad"))
    refuse("a rooted device adds an agent", lambda q: q.add("browser", "agent2", AGENT, "bad"))
    refuse("the phone added again", lambda q: q.add("laptop", "phone", DEVICE, "bad"))
    refuse("a revoke naming a key not on the list",
           lambda q: q.raw("laptop", list_body(REVOKE, DEVICE, q.hist.device("tablet")), "bad"))
    refuse("a revoke naming the phone as a passkey member",
           lambda q: q.raw("laptop", list_body(REVOKE, PASSKEY, q.hist.device("phone")), "bad"))
    refuse("the passkey member revokes the recovery key",
           lambda q: q.revoke("passkey", "recovery", "bad"))
    refuse("a rooted device revokes the recovery key",
           lambda q: q.revoke("browser", "recovery", "bad"))
    refuse("the recovery key confirms the browser",
           lambda q: q.confirm("recovery", "browser", "bad"))
    refuse("the passkey member confirms the browser",
           lambda q: q.confirm("passkey", "browser", "bad"))
    refuse("the rooted browser confirms itself", lambda q: q.confirm("browser", "browser", "bad"))
    refuse("a confirm of the phone, which is not rooted",
           lambda q: q.confirm("laptop", "phone", "bad"))
    refuse("a confirm of a passkey member", lambda q: q.confirm("laptop", "passkey", "bad"))
    refuse("a confirm of the agent", lambda q: q.confirm("laptop", "agent", "bad"))

    def last_member(q):
        for n in ("phone", "passkey", "browser", "recovery", "agent"):
            q.revoke("laptop", n)
        return q.revoke("laptop", "laptop", "bad")

    def last_but_agent(q):
        for n in ("phone", "passkey", "browser", "recovery"):
            q.revoke("laptop", n)
        return q.revoke("laptop", "laptop", "bad")

    def revoked_signer(q):
        q.revoke("laptop", "phone")
        q.hist.sync("laptop", "phone")
        return q.add("phone", "tablet", DEVICE, "bad")

    refuse("the last active list member revokes itself", last_member)
    refuse("the last device revokes itself, leaving only the agent", last_but_agent)
    refuse("a revoked device signs", revoked_signer)
    return {"base": base, "cases": cases}


def _merges_family() -> list:
    merges = []

    def merge(name: str, build, expect: dict | None = None):
        q = Person("laptop", f"identity/merge/{len(merges)}")
        build(q)
        res = q.resolve()
        summary = q.summary(res)
        for k, v in (expect or {}).items():
            assert summary[k] == v, (name, k, summary[k], v)
        merges.append({"name": name, "log": q.hist.describe(), **summary})

    def two_devices(q, third=None):
        q.add("laptop", "phone", DEVICE)
        if third:
            q.add("laptop", third[0], third[1])
        q.hist.sync("laptop", "phone", *([third[0]] if third else []))

    merge("concurrent adds of two devices: both stand", lambda q: (
        two_devices(q), q.add("laptop", "tablet", DEVICE), q.add("phone", "watch", DEVICE)),
        {"active": ["laptop", "phone", "tablet", "watch"]})
    merge("one device added on both branches: one list member", lambda q: (
        two_devices(q), q.add("laptop", "tablet", DEVICE), q.add("phone", "tablet", DEVICE)),
        {"active": ["laptop", "phone", "tablet"]})

    def xwing_clash(q):
        two_devices(q)
        q.add("laptop", "tablet", DEVICE)
        q.add("phone", "watch", DEVICE, "phone adds watch with the tablet's X-Wing key",
              xwing_key=q.xwing("tablet"))

    merge("two adds name one X-Wing key: the later in canonical order is void", xwing_clash)
    merge("mutual revocation within a rank: both revoked", lambda q: (
        two_devices(q, ("recovery", RECOVERY)), q.revoke("laptop", "phone"),
        q.revoke("phone", "laptop")), {"active": ["recovery"]})
    merge("mutual revocation of the only two devices: the list is dead", lambda q: (
        two_devices(q), q.revoke("laptop", "phone"), q.revoke("phone", "laptop")),
        {"active": [], "dead": True})

    def ranks_differ(q):
        two_devices(q, ("passkey", PASSKEY))
        q.add("passkey", "browser", DEVICE, "passkey adds browser, rooted in a passkey")
        q.hist.sync("laptop", "phone", "passkey", "browser")
        q.revoke("laptop", "browser")
        q.revoke("browser", "laptop")

    merge("mutual revocation across ranks: the device that is not rooted wins", ranks_differ,
          {"active": ["laptop", "passkey", "phone"]})
    merge("the recovery key and a device revoke each other: the recovery key wins", lambda q: (
        two_devices(q, ("recovery", RECOVERY)), q.revoke("recovery", "phone"),
        q.revoke("phone", "recovery")), {"active": ["laptop", "recovery"]})

    def actions_of_revoked(q):
        two_devices(q)
        q.revoke("laptop", "phone")
        q.add("phone", "tablet", DEVICE)

    merge("a revocation voids the revoked device's concurrent add", actions_of_revoked,
          {"active": ["laptop"]})

    def confirm_vs_revoke(q):
        q.add("laptop", "passkey", PASSKEY)
        q.hist.sync("laptop", "passkey")
        q.add("passkey", "browser", DEVICE, "passkey adds browser, rooted in a passkey")
        q.add("laptop", "phone", DEVICE)
        q.hist.sync("laptop", "passkey", "browser", "phone")
        q.confirm("phone", "browser")
        q.revoke("laptop", "phone")

    merge("a revocation voids a concurrent confirm by the revoked device", confirm_vs_revoke)

    def cycle(q):
        q.add("laptop", "phone", DEVICE)
        q.add("laptop", "tablet", DEVICE)
        q.hist.sync("laptop", "phone", "tablet")
        q.revoke("laptop", "phone")
        q.revoke("phone", "tablet")
        q.revoke("tablet", "laptop")

    merge("a cycle of three within a rank: seniority decides", cycle, {"active": ["tablet"]})

    def self_revoke(q):
        two_devices(q, ("tablet", DEVICE))
        q.revoke("phone", "phone", "phone revokes itself")
        q.revoke("laptop", "phone")

    merge("a self-revocation and a concurrent revocation both stand", self_revoke)

    def list_fork(q):
        two_devices(q, ("tablet", DEVICE))
        backup = set(q.hist.view["phone"])
        q.add("phone", "watch", DEVICE)
        q.hist.view["phone"] = backup
        q.revoke("phone", "phone", "phone, restored, revokes itself at the same seq")
        q.hist.sync("laptop", "phone", "tablet")

    merge("a device forks its chain: void from the fork, its self-revocation stands", list_fork)

    def agent_limit(q):
        q.add("laptop", "agent", AGENT)
        q.hist.sync("laptop", "agent")
        q.add("agent", "helped", DEVICE, "agent adds helped")
        q.hist.sync("laptop", "agent", "helped")
        q.add("helped", "helped2", DEVICE, "helped adds helped2")
        q.revoke("helped", "helped2", "helped revokes helped2, rooted in the same agent")
        q.revoke("helped", "laptop", "helped revokes laptop")
        q.hist.sync("laptop", "agent", "helped")
        q.revoke("laptop", "helped", "laptop revokes helped")

    merge("the agent's limit: a device rooted in an agent revokes only list members rooted "
          "in the same agent", agent_limit, {"active": ["agent", "laptop"]})

    def agent_confirmed(q):
        q.add("laptop", "agent", AGENT)
        q.add("laptop", "phone", DEVICE)
        q.hist.sync("laptop", "agent", "phone")
        q.add("agent", "helped", DEVICE, "agent adds helped")
        q.hist.sync("laptop", "agent", "helped", "phone")
        q.confirm("laptop", "helped", "laptop confirms helped")
        q.hist.sync("laptop", "helped", "phone")
        q.revoke("helped", "phone", "helped, confirmed, revokes phone")

    merge("a confirm lifts the agent's limit", agent_confirmed,
          {"active": ["agent", "helped", "laptop"]})
    assert len(merges) == 14
    return merges


def _replayed_adds_family() -> list:
    """identity.md, "The possession statement": a list member that signs
    again, on its own chain, another member's add, proof included. The
    proof names the honest add's author, so the copy is BadPossession and
    the list member keeps the rank the honest add gives it."""
    cases = []

    def case(name: str, build, target: str, rank: int):
        q = Person("laptop", f"identity/replayed/{len(cases)}")
        copy = build(q)
        res = q.resolve()
        assert res.status[copy][:2] == (False, "BadPossession"), (name, res.status[copy])
        m = res.members[q.hist.device(target)]
        assert m.active and m.rooted == NONE and m.rank == rank, (name, m.rooted, m.rank)
        cases.append({"name": name, "log": q.hist.describe(), **q.summary(res)})

    def copy(q, signer: str, add: bytes, label: str) -> bytes:
        return q.raw(signer, q.log.events[add].body, label)

    def agent_named(q):
        q.add("laptop", "agent", AGENT)
        q.hist.sync("laptop", "agent")

    def by_agent(after: bool):
        def build(q):
            agent_named(q)
            honest = q.add("laptop", "target", DEVICE)
            if after:
                q.hist.sync("laptop", "agent")
            return copy(q, "agent", honest, "agent signs laptop's add of target again")
        return build

    def by_helped(after: bool):
        def build(q):
            agent_named(q)
            q.add("agent", "helped", DEVICE, "agent adds helped")
            q.hist.sync("agent", "helped")
            honest = q.add("laptop", "target", RECOVERY)
            if after:
                q.hist.sync("laptop", "helped")
            return copy(q, "helped", honest, "helped signs laptop's add of target again")
        return build

    def by_passkey(kind: int, after: bool):
        def build(q):
            q.add("laptop", "passkey", PASSKEY)
            q.hist.sync("laptop", "passkey")
            honest = q.add("laptop", "target", kind)
            if after:
                q.hist.sync("laptop", "passkey")
            return copy(q, "passkey", honest, "passkey signs laptop's add of target again")
        return build

    case("an agent signs again a device's add, concurrently", by_agent(False), "target", 2)
    case("an agent signs again a device's add, after it", by_agent(True), "target", 2)
    case("a device rooted in the agent signs again a recovery key's add, concurrently",
         by_helped(False), "target", 1)
    case("a device rooted in the agent signs again a recovery key's add, after it",
         by_helped(True), "target", 1)
    case("a passkey member signs again a device's add, concurrently",
         by_passkey(DEVICE, False), "target", 2)
    case("a passkey member signs again a recovery key's add, concurrently",
         by_passkey(RECOVERY, False), "target", 1)
    case("a passkey member signs again a device's add, after it",
         by_passkey(DEVICE, True), "target", 2)
    return cases


def _fingerprints_family(alice: Person, bob: Person) -> tuple[dict, dict]:
    laptop = alice.hist.signer("laptop")
    member = passkey_keys(alice.id, example("identity/fingerprint/passkey/prf-output"))
    kiosk = events.signer_for(example("identity/fingerprint/kiosk/ed25519"), "kiosk")
    kiosk_xwing = xwing.xwing_public_key(example("identity/fingerprint/kiosk/xwing"))
    agent = alice.hist.signer("agent")
    keys = {
        "laptop": (laptop.ed_public, laptop.mldsa_public, alice.xwing("laptop")),
        "passkey": (member["identity"], member["mldsa_public"], member["xwing"]),
        "kiosk": (kiosk.ed_public, kiosk.mldsa_public, kiosk_xwing),
        "agent": (agent.ed_public, agent.mldsa_public, b""),
    }
    cases = []
    for name, person, key in [
        ("a device on a person's list", alice.id, "laptop"),
        ("the same keys under another person", bob.id, "laptop"),
        ("a passkey member", alice.id, "passkey"),
        ("a device granted directly: 32 zero bytes for the person", bytes(32), "kiosk"),
        ("a recovery agent: no X-Wing key", alice.id, "agent"),
    ]:
        ident, mld, xw = keys[key]
        f = fingerprint(person, ident, mld, xw)
        cases.append({"name": name, "person_id": h(person), "identity": h(ident),
                      "mldsa": h(mld), "xwing": h(xw), "digest_input": h(f["digest_input"]),
                      "digest": h(f["digest"]), "value_120_bits": f"{f['value']:030x}",
                      "check": f["check"], "characters": f["characters"],
                      "display": f["display"], "qr": f["qr"]})
    assert cases[0]["characters"] != cases[1]["characters"]
    checks = []
    for name, value in [("zero", 0), ("every bit set", (1 << FINGERPRINT_BITS) - 1),
                        ("the lowest bit", 1), ("the highest bit", 1 << (FINGERPRINT_BITS - 1)),
                        ("the first five bits", 31 << (FINGERPRINT_BITS - 5))]:
        c, characters = fingerprint_characters(value)
        assert parse_fingerprint(characters) == characters
        checks.append({"name": name, "value_120_bits": f"{value:030x}", "check": c,
                       "characters": characters})
    ident, mld, xw = keys["laptop"]
    small = (1).to_bytes(32, "little")
    none_ = []
    for name, args in [
        ("an identity key of small order", (alice.id, small, mld, xw)),
        ("an X-Wing key with a coefficient of q = 3329",
         (alice.id, ident, mld, bytes([0x01, 0x0D]) + xw[2:])),
        ("an ML-DSA-65 key of 1,951 bytes", (alice.id, ident, mld[:-1], xw)),
        ("a person ID of 31 bytes", (alice.id[:31], ident, mld, xw)),
    ]:
        none_.append({"name": name, "person_id": h(args[0]), "identity": h(args[1]),
                      "mldsa": h(args[2]), "xwing": h(args[3]),
                      "error": expect_error(fingerprint, *args)})

    chars = cases[0]["characters"]
    groups = [chars[i:i + 5] for i in range(0, 25, 5)]
    accepted = []
    for name, text in [
        ("as displayed", cases[0]["display"]), ("no separators", chars),
        ("upper case", chars.upper()), ("hyphens between groups", "-".join(groups)),
        ("tabs and a trailing newline", "\t".join(groups) + "\n"),
        ("the QR form", cases[0]["qr"]), ("the QR form, prefix in lower case",
                                          "frasil-fp1:" + chars),
        ("the QR form with spaces", QR_PREFIX + " " + " ".join(groups).upper()),
    ]:
        assert parse_fingerprint(text) == chars
        accepted.append({"name": name, "input": text, "characters": chars})

    def replaced(position: int) -> str:
        following = ALPHABET[(ALPHABET.index(chars[position]) + 1) % 32]
        return chars[:position] + following + chars[position + 1:]

    def displayed(text: str) -> str:
        return " ".join(text[i:i + 5] for i in range(0, 25, 5))

    swapped = next(chars[:i] + chars[i + 1] + chars[i] + chars[i + 2:]
                   for i in range(24) if chars[i] != chars[i + 1])
    refused = [{"name": name, "input": text, "error": expect_error(parse_fingerprint, text)}
               for name, text in [
        ("24 characters", chars[:24]), ("26 characters", chars + "a"),
        ("the digit 0", "0" + chars[1:]), ("the digit 1", "1" + chars[1:]),
        ("the letter l", "l" + chars[1:]), ("the letter o", "o" + chars[1:]),
        ("a character outside ASCII", "а" + chars[1:]),
        ("an underscore separator", "_".join(groups)),
        ("another version's prefix", "FRASIL-FP2:" + chars.upper()),
        ("a colon elsewhere", chars[:10] + ":" + chars[10:]), ("a prefix alone", QR_PREFIX),
        ("empty", ""), ("longer than 128 characters", " " * 110 + chars),
        ("one character wrong, as displayed", displayed(replaced(7))),
        ("the check character wrong", replaced(24)),
        ("two adjacent characters exchanged, in the QR form", QR_PREFIX + swapped.upper()),
    ]]
    assert [r["error"] for r in refused].count("InvalidFingerprint") == 13
    assert [r["error"] for r in refused].count("FingerprintMistyped") == 3
    single = []
    for position in range(25):
        for replacement in ALPHABET:
            if replacement != chars[position]:
                typed = chars[:position] + replacement + chars[position + 1:]
                assert expect_error(parse_fingerprint, typed) == "FingerprintMistyped"
                single.append(typed)
    assert len(single) == 775
    exchanges = []
    for first in range(25):
        for second in range(first + 1, 25):
            if chars[first] != chars[second]:
                s = list(chars)
                s[first], s[second] = s[second], s[first]
                typed = "".join(s)
                assert expect_error(parse_fingerprint, typed) == "FingerprintMistyped"
                exchanges.append({"first": first, "second": second, "input": typed})
    symbols = [ALPHABET.index(c) for c in chars]
    symbols[0] ^= 1
    symbols[1] ^= times_x(1)
    double = "".join(ALPHABET[s] for s in symbols)
    assert parse_fingerprint(double) == double != chars
    return ({"alphabet": ALPHABET, "gf32_modulus": GF32_MODULUS, "cases": cases,
             "check_symbols": checks, "no_fingerprint": none_},
            {"characters": chars, "accepted": accepted, "refused": refused,
             "single_character_errors": {"error": "FingerprintMistyped", "inputs": single},
             "exchanges": {"error": "FingerprintMistyped", "inputs": exchanges},
             "undetected": {"name": "two characters wrong in a way the check cannot see",
                            "input": displayed(double), "characters": double}})


def _enrolment_family() -> list:
    person = Person("laptop", prefix="identity/enrolment").id
    output = example("identity/enrolment/prf-output")
    unstable = example("identity/enrolment/prf-output-unstable")
    m = enrol_passkey(person, output, output)
    return [
        {"name": "two evaluations agree", "person_id": h(person), "first_prf_output": h(output),
         "second_prf_output": h(output),
         **_derived_json(m, "identity", "xwing", "mldsa_public", "fetch_key")},
        {"name": "two evaluations disagree", "person_id": h(person),
         "first_prf_output": h(output), "second_prf_output": h(unstable),
         "error": expect_error(enrol_passkey, person, output, unstable)},
    ]


def _account_links_family(p: Person, lst: DeviceList) -> dict:
    origin, subject = "https://accounts.example", "person@example"
    nonce = example("identity/link-nonce")[:16]
    link = make_link(origin, subject, p.id, nonce, p.hist.signer("laptop"))
    lid = link_id(origin, subject, p.id, nonce)
    unlink = make_unlink(lid, p.hist.signer("phone"))
    other = Person("stranger", "identity/stranger")
    checks = []
    for name, record, against, unl in [
        ("accepted: signed by an active device", link, lst, ()),
        ("unlinked by another device", link, lst, (unlink,)),
        ("signed by a revoked device", make_link(origin, subject, p.id, nonce,
                                                 p.hist.signer("browser")), lst, ()),
        ("signed by the agent", make_link(origin, subject, p.id, nonce, p.hist.signer("agent")),
         lst, ()),
        ("the laptop's Ed25519 key under another kc: another device, on no list",
         make_link(origin, subject, p.id, nonce, hs.Signer(
             "laptop, another kc", p.hist.seed("laptop"), example("identity/link/other/mldsa"),
             example("identity/link/other/xwing"))), lst, ()),
        ("checked against another person's list", link, other.resolve(), ()),
        ("the subject changed after signing", cbor({**uncbor(link), L_SUBJECT: "eve@example"}),
         lst, ()),
    ]:
        try:
            outcome = {"link_id": h(verify_link(record, against, unl)["link_id"])}
        except SpecError as error:
            outcome = {"error": error.error}
        checks.append({"name": name, "record": h(record), "unlinks": [h(u) for u in unl],
                       **outcome})
    return {"person_id": h(p.id), "origin": origin, "subject": subject, "nonce": h(nonce),
            "statement": h(link_statement(origin, subject, p.id, nonce)), "link": h(link),
            "link_id": h(lid), "unlink_statement": h(ACCOUNT_UNLINK_LABEL + field(lid)),
            "unlink": h(unlink), "checks": checks}


def _pins_family() -> dict:
    q = Person("laptop", "identity/pins")
    q.add("laptop", "phone", DEVICE)
    q.hist.sync("laptop", "phone")
    pinned = set(q.log.events)
    q.add("phone", "tablet", DEVICE)
    grown = set(q.log.events)
    q.hist.view["phone"] = set(q.hist.view["phone"]) - {q.hist.by_name("phone adds tablet")}
    q.add("phone", "watch", DEVICE, "phone, restored, adds watch at the same seq")
    forked = set(q.log.events)
    cases = []
    for name, offered in [("a later state", grown),
                          ("an earlier state", pinned - {q.hist.by_name("laptop adds phone")}),
                          ("a state with a fork", forked)]:
        cases.append({"name": name, "pinned": sorted(q.hist.name(i) for i in pinned),
                      "offered": sorted(q.hist.name(i) for i in offered),
                      "result": check_pin(q.log, pinned, offered)})
    return {"events": q.hist.describe(), "cases": cases}


def identity_vectors() -> dict:
    persons, alice, bob = _persons_family()
    derivations, passkey_refusals = _passkey_family(alice, bob)
    possession = _possession_families()
    lst_json, p, lst = _list_family()
    fingerprints, parsing = _fingerprints_family(alice, bob)
    return {
        "specification": "identity.md",
        "parameters": {
            "event_kind": KIND_DEVICE_LIST, "entry_version": ENTRY_VERSION,
            "actions": {v: k for k, v in ACTION_NAMES.items()},
            "kinds": {v: k for k, v in KIND_NAMES.items()},
            "body_keys": {"version": B_VERSION, "action": B_ACTION, "kind": B_KIND,
                          "device": B_DEVICE, "possession": B_POSSESSION,
                          "xwing": B_XWING, "mldsa": B_MLDSA, "identity": B_IDENTITY},
            "ranks": {"1": "a recovery key that is not rooted",
                      "2": "a device that is not rooted",
                      "3": "a passkey member, and any list member rooted in a passkey",
                      "4": "an agent, and any list member rooted in an agent"},
            "max_list_events": MAX_LIST_EVENTS,
            "possession_statement_bytes": {"agent": 2110, "other": 3326},
            "note": ("Device seeds are crypto.md's test fixtures: each identity seed is "
                     "SHA-256 of a description, and its ML-DSA-65 and X-Wing seeds the fixture "
                     "derivations; an agent has no X-Wing key. "
                     "Each personal space ID is a fixture, SHA-256 of a description and the "
                     "person ID, standing for the space's genesis ID."),
        },
        "persons": persons,
        "list_checkpoints": __import__("list_checkpoints").list_checkpoint_vectors(),
        "passkey_derivations": derivations,
        "passkey_refusals": passkey_refusals,
        "recovery_keys": _recovery_family(alice),
        "recovery_entries": _entries_family(alice),
        **possession,
        "list": lst_json,
        "passkey_list": _passkey_list_family(),
        "list_refusals": _list_refusals_family(),
        "merges": _merges_family(),
        "replayed_adds": _replayed_adds_family(),
        "enrolment": _enrolment_family(),
        "fingerprints": fingerprints,
        "fingerprint_parsing": parsing,
        "account_links": _account_links_family(p, lst),
        "pins": _pins_family(),
    }


def ext_recovery_agent_vectors() -> dict:
    """ext-recovery-agent.json: the waiting decision on readings (clocks.py),
    and the list members each verifier wraps for while one waits."""
    import clocks

    q = Person("laptop", "identity/wait")
    q.add("laptop", "agent", AGENT)
    q.hist.sync("laptop", "agent")
    add_helped = q.add("agent", "helped", DEVICE, "agent adds helped")
    q.hist.sync("laptop", "agent", "helped")
    q.add("helped", "helped2", DEVICE, "helped adds helped2")
    # Both the laptop and the agent add `both`, concurrently, each with a
    # proof `both` signed for it: only the agent's add roots it in the
    # agent, so the wait counts from it.
    by_laptop = q.add("laptop", "both", DEVICE, "laptop adds both")
    by_agent = q.add("agent", "both", DEVICE, "agent adds both, concurrently")
    assert by_laptop not in q.log.anc[by_agent] and by_agent not in q.log.anc[by_laptop]
    res = q.resolve()
    assert res.members[q.hist.device("both")].agent_adds == [by_agent]
    later = q.hist.by_name("helped adds helped2")
    assert res.recipients() == sorted([q.hist.device("laptop")])
    W = AGENT_WAIT_SECONDS
    cases = []
    for name, first_seen, now in [
        ("at once", {add_helped: 1_000_000, later: 1_000_000}, 1_000_000),
        ("at 71 hours", {add_helped: 1_000_000, later: 1_000_000}, 1_000_000 + 71 * 3600),
        ("at 72 hours", {add_helped: 1_000_000, later: 1_000_000}, 1_000_000 + 72 * 3600),
        ("a late verifier, whose first sight was an hour ago",
         {add_helped: 2_000_000, later: 2_000_000}, 2_000_000 + 3600),
        ("the second device seen 71 hours after the first",
         {add_helped: 1_000_000, later: 1_000_000 + 71 * 3600}, 1_000_000 + 72 * 3600),
        ("a device the laptop added at once and the agent 71 hours later",
         {add_helped: 1_000_000, later: 1_000_000, by_laptop: 1_000_000,
          by_agent: 1_000_000 + 71 * 3600}, 1_000_000 + 72 * 3600),
    ]:
        cases.append({"name": name,
                      "first_sight": {q.hist.name(k): v for k, v in first_seen.items()},
                      "now": now, "agent_waiting_period": W,
                      "wraps_for": sorted(q.hist.key_name(k)
                                          for k in res.recipients(first_seen, now, W))})
    return {
        "specification": "ext-recovery-agent.md",
        "parameters": {"agent_waiting_period": {"default": W, "minimum": W,
                                                "maximum": 30 * 86400}},
        "waiting_decisions": clocks.waiting_decisions(),
        "recipients_while_waiting": {
            "note": ("Readings are the verifier's timeline in seconds; first_sight is each "
                     "verifier's own first sight of each add."),
            "events": q.hist.describe(), "cases": cases},
    }


def self_test() -> None:
    v = identity_vectors()
    errors = {c["name"]: c["error"] for c in v["list_refusals"]["cases"]}
    expected = {
        "entry version 2": "Malformed",
        "an add without its possession": "Malformed",
        "an add without an ML-DSA-65 key": "Malformed",
        "an add without its Ed25519 key, key 7": "Malformed",
        "a device's add without an X-Wing key": "Malformed",
        "an ML-DSA-65 key of 1,951 bytes": "Malformed",
        "a revoke carrying a possession": "Malformed",
        "an unknown key 8": "Malformed",
        "an unknown kind, 4": "Malformed",
        "an unknown action, 5": "Malformed",
        "an agent naming an X-Wing key": "Malformed",
        "an X-Wing key with a coefficient of q = 3329": "InvalidKey",
        "an X-Wing key whose X25519 part is zero": "InvalidKey",
        "an identity key of small order": "InvalidKey",
        "a proof that binds 32 zero bytes, not the person ID": "BadPossession",
        "a proof that names another kind": "BadPossession",
        "a proof that names another adder, the phone": "BadPossession",
        "a proof that binds another ML-DSA-65 key": "BadPossession",
        "a proof whose Ed25519 half is a scheme-0 signature of the statement": "BadPossession",
        "a device no add names signs an add": "NoHybridKey",
        "a device no add names signs a revoke": "NoHybridKey",
        "an agent adds a passkey member": "AgentLimited",
        "an agent revokes a device": "AgentLimited",
        "an agent confirms": "AgentLimited",
        "a rooted device adds an agent": "UntrustedSigner",
        "the phone added again": "AlreadyListed",
        "a revoke naming a key not on the list": "NotListed",
        "a revoke naming the phone as a passkey member": "NotListed",
        "the passkey member revokes the recovery key": "RecoveryKeyProtected",
        "a rooted device revokes the recovery key": "RecoveryKeyProtected",
        "the recovery key confirms the browser": "UntrustedSigner",
        "the passkey member confirms the browser": "UntrustedSigner",
        "the rooted browser confirms itself": "UntrustedSigner",
        "a confirm of the phone, which is not rooted": "NotPending",
        "a confirm of a passkey member": "NotPending",
        "a confirm of the agent": "NotPending",
        "the last active list member revokes itself": "LastMember",
        "the last device revokes itself, leaving only the agent": "LastMember",
        "a revoked device signs": "UntrustedSigner",
    }
    assert errors == expected, {k: (errors.get(k), e) for k, e in expected.items()
                                if errors.get(k) != e}
    pr = {c["name"]: c["error"] for c in v["possession_refusals"]}
    assert pr.pop("an Ed25519 half alone, 64 bytes") == "Malformed"
    assert pr.pop("an identity key of small order, with a proof of zero bytes") == "InvalidKey"
    assert [pr.pop(k) for k in [k for k in pr if k.startswith(
        ("an add whose keys do not give", "an add that pairs"))]] == ["NotCommitted"] * 2
    assert set(pr.values()) == {"BadPossession"}, pr
    forged = v["forged_list"]["events"]
    assert all(e["error"] == "BadPossession" for e in forged[:-1])
    assert forged[-1]["verdict"] == "valid"
    assert forged[-1]["its_author"] != forged[-1]["victim_device_id"]
    result = v["list"]["result"]
    assert result["members"]["browser"]["active"] is False
    assert result["members"]["helped"]["rooted"] == "agent"
    assert result["members"]["helped"]["rank"] == 4
    for c in v["replayed_adds"]:
        copies = [k for k in c["events"] if "again" in k]
        assert len(copies) == 1 and c["events"][copies[0]] == "BadPossession", c["name"]
        assert c["members"]["target"]["rooted"] == "none", c["name"]
    merges = {m["name"]: m for m in v["merges"]}
    clash = merges["two adds name one X-Wing key: the later in canonical order is void"]
    assert sorted(clash["active"]) in (["laptop", "phone", "tablet"], ["laptop", "phone", "watch"])
    conf = merges["a revocation voids a concurrent confirm by the revoked device"]
    assert conf["members"]["browser"]["rooted"] == "passkey"
    sr = merges["a self-revocation and a concurrent revocation both stand"]
    assert sr["active"] == ["laptop", "tablet"] and all(e == "valid" for e in sr["events"].values())
    fork = merges["a device forks its chain: void from the fork, its self-revocation stands"]
    assert fork["members"]["phone"]["active"] is False and "watch" not in fork["active"]
    limit = merges["the agent's limit: a device rooted in an agent revokes only list members "
                   "rooted in the same agent"]["events"]
    assert limit["helped revokes helped2, rooted in the same agent"] == "valid"
    assert limit["helped revokes laptop"] == "AgentLimited"
    assert limit["laptop revokes helped"] == "valid"
    assert any("seniority" in s for s in
               merges["a cycle of three within a rank: seniority decides"]["events"].values())
    entries = {c["name"]: c["error"] for c in v["recovery_entries"]["refused"]}
    assert entries["a key of small order"] == "InvalidKey"
    assert entries["version 2"] == "UnsupportedVersion"
    assert set(entries.values()) - {"InvalidKey", "UnsupportedVersion"} == {"Malformed"}
    links = {c["name"]: c for c in v["account_links"]["checks"]}
    assert "link_id" in links["accepted: signed by an active device"]
    assert links["unlinked by another device"]["error"] == "Unlinked"
    assert links["signed by a revoked device"]["error"] == "UntrustedSigner"
    assert links["signed by the agent"]["error"] == "UntrustedSigner"
    assert links["checked against another person's list"]["error"] == "WrongPerson"
    assert links["the subject changed after signing"]["error"] == "BadSignature"
    assert links["the laptop's Ed25519 key under another kc: another device, on no list"][
        "error"] == "UntrustedSigner"
    assert {c["name"]: c["result"] for c in v["pins"]["cases"]} == {
        "a later state": "Advanced", "an earlier state": "RolledBack",
        "a state with a fork": "ForkDetected"}
    assert v["enrolment"][1]["error"] == "UnstablePrf"
    assert [r.get("error") for r in v["recovery_keys"]["reading"]][:3] == [None] * 3
    w = ext_recovery_agent_vectors()
    waits = {c["name"]: c["wraps_for"] for c in w["recipients_while_waiting"]["cases"]}
    assert waits["at once"] == ["laptop"]
    assert waits["at 71 hours"] == ["laptop"]
    assert waits["at 72 hours"] == ["helped", "helped2", "laptop"]
    assert waits["a late verifier, whose first sight was an hour ago"] == ["laptop"]
    assert waits["the second device seen 71 hours after the first"] == ["helped", "laptop"]
    assert waits["a device the laptop added at once and the agent 71 hours later"] == [
        "helped", "helped2", "laptop"]
    lv = v["list"]
    assert lv["recipients"] == ["laptop", "passkey", "phone", "recovery"]
    assert lv["recipients_forbidding_agents"] == []


if __name__ == "__main__":
    self_test()
    print(len(json.dumps(identity_vectors())))
