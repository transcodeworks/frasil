"""Checkpoints (roster.md, "Checkpoints"; events.md, "Cuts"), written from the
specification, independently of any implementation: which events follow a
checkpoint, what makes one valid and when it takes effect, the world after it,
and the verdicts of a replica that holds a space's whole history and of one
that keeps only what roster.md, "Forgetting", lets it keep. A seeded model
check builds random histories with checkpoints, removals, backdated
counter-removals, forks, invite links, raced claims and closes, a granted
space with notices and responses, late branches and replicas that forget,
and checks that every replica reaches the same verdicts.

The world after a checkpoint is resolved by roster.py's own procedure, over a
log whose root is the checkpoint and whose events are those that follow it;
the record stands where a genesis's founder does. So a replica that forgot
what came before and one that did not run one function on one input. A
replica that forgot is given a log that holds only what it keeps (KeptLog),
so it cannot read anything else."""

from __future__ import annotations

import copy
import random
import sys
from dataclasses import dataclass, field as dc_field

import events
import identity
import keygraph as kg
import roster as R
import units
from events import KIND_ANCHOR, KIND_SPACE, KIND_UNIT, Log, h
from formats import example
from primitives import SpecError, sha256

LATE = "Late"
HELD = ("Sealed", "Pending", "NoHybridKey", "ExtensionRequired", "BadSeal")


def _topological(ids, parents_of) -> list:
    """`ids` with every parent among them before its child."""
    ids = set(ids)
    out, seen = [], set()
    for start in sorted(ids):
        stack = [(start, False)]
        while stack:
            i, done = stack.pop()
            if done:
                out.append(i)
                continue
            if i in seen:
                continue
            seen.add(i)
            stack.append((i, True))
            stack.extend((p, False) for p in parents_of(i) if p in ids and p not in seen)
    return out


class _Partial(Log):
    """A log over some of another log's events, each linked to its parents
    among them only, its height counted over them (roster.md, "The world
    after a checkpoint"): a parent outside counts for nothing."""

    def _link(self, log: Log, root: bytes, ids) -> None:
        self.anc, self.height, self.pending = {}, {}, {}
        for i in _topological(ids, lambda i: log.events[i].parents):
            ps = [p for p in log.events[i].parents if p in ids]
            anc = set()
            for p in ps:
                anc |= self.anc[p]
                anc.add(p)
            self.anc[i] = frozenset(anc)
            self.height[i] = 0 if i == root else 1 + max((self.height[p] for p in ps), default=0)
            self.events[i] = log.events[i]

    def chain_evidence(self, view=None, accepted=None) -> list[dict]:
        """Evidence among the log's events only: a prev outside is not
        checked (roster.md)."""
        ids = [i for i in self.canonical(view) if accepted is None or accepted(i)]
        out, slots = [], {}
        for i in ids:
            e = self.events[i]
            slots.setdefault((e.author, e.seq), []).append(i)
        for (author, seq), slot in sorted(slots.items()):
            slot = sorted(slot)
            for a, b in zip(slot, slot[1:]):
                out.append({"type": "duplicate", "author": author, "seq": seq, "first": a,
                            "second": b, "fork_seq": seq})
        for i in ids:
            e = self.events[i]
            if e.prev is None or e.prev not in self.events:
                continue
            if accepted is not None and not accepted(e.prev):
                continue
            p = self.events[e.prev]
            if p.author != e.author or p.seq != e.seq - 1:
                fork = min(e.seq, p.seq + 1) if p.author == e.author else e.seq
                out.append({"type": "skip", "author": e.author, "seq": e.seq, "first": i,
                            "second": e.prev, "fork_seq": fork})
        return out


class DerivedLog(_Partial):
    """The log of a checkpoint's world: the checkpoint as its root, at height
    0, and the events that follow it, each linked to its parents among them
    only, one more than the greatest height among them (roster.md, "The
    world after a checkpoint")."""

    def __init__(self, log: Log, root: bytes, members):
        self.id = log.id
        self.genesis = root
        self.events = {}
        self._link(log, root, set(members) | {root})


class KeptLog(_Partial):
    """What a replica that forgot holds of a space's log (roster.md,
    "Forgetting, and starting from a checkpoint"): the genesis, the kept
    checkpoint, the envelopes of the checkpoints its cuts reach, the late
    events and the events after it. `dropped` is the IDs of what it dropped,
    which it keeps so as to place an event that cites one."""

    def __init__(self, log: Log, keep, dropped=()):
        self.id = log.id
        self.genesis = log.genesis
        self.events = {}
        self.dropped = frozenset(dropped)
        self._link(log, log.genesis, set(keep) | {log.genesis})


class Ctx:
    """What a replica can read of the events of the log it holds: their
    envelopes, and their bodies under the keys it holds (fetching an event to
    read it is not placing it). `keys` is a roster.Keyring. A replica that
    forgot holds a KeptLog, `trusted` its kept checkpoint, and `envelopes`
    the checkpoints the kept one's cuts reach, which it holds as envelopes
    alone and never opens."""

    def __init__(self, log: Log, keys: R.Keyring, lists=None, spaces_=None, *,
                 trusted=(), objects=None, records=None, envelopes=(), skeleton=False,
                 kept_cut=None):
        """With `skeleton`, the space has an administrator skeleton
        (peers.md): each Space reads it through a twin view, a checkpoint's
        record carries `slot` entries and its twin is checked; `kept_cut` is
        the kept checkpoint's skeleton cut, at a replica that forgot."""
        self.skeleton = skeleton
        self.kept_cut = kept_cut
        self.trusted = frozenset(trusted)
        self.envelopes = frozenset(envelopes)
        # The objects this replica holds, by locator, and records it was
        # handed whole, by checkpoint (a forgetting replica keeps its own).
        self.objects = dict(objects or {})
        self.records = dict(records or {})
        self.log = log
        self.keys = keys
        self.lists = lists or {}
        self.spaces = spaces_ or {}
        self.memo: dict = {}
        genesis = R.decode_body(log.events[log.genesis], self._key(log.genesis))
        self.descriptor = genesis.descriptor
        self.system_stream = genesis.system_stream

    def _key(self, i: bytes) -> bytes | None:
        e = self.log.events[i]
        vis = R.read_visible(e)
        if vis["rotates"]:
            secret = self.keys.rotations.get(i)
        else:
            state = kg.decode_set(vis["sealed_under"])
            if not all(r in self.keys.rotations for r in state):
                return None
            secret = kg.content_key(self.log.id, state, self.keys.rotations.__getitem__)
        return None if secret is None else R.body_key(e, vis, secret)

    def checkpoint(self, i: bytes) -> R.Decoded | None:
        """The checkpoint's opened body, or None for any other event, and
        for a checkpoint this replica holds as an envelope alone."""
        k = ("cp", i)
        if k not in self.memo:
            out = None
            e = self.log.events.get(i)
            if e is not None and i not in self.envelopes and e.kind == KIND_SPACE \
                    and not e.genesis:
                try:
                    key = self._key(i)
                    if key is not None:
                        d = R.decode_body(e, key)
                        out = d if d.part is not None else None
                except SpecError:
                    out = None
            self.memo[k] = out
        return self.memo[k]

    def is_checkpoint(self, i: bytes) -> bool:
        """A checkpoint this replica opened, or one it keeps as an envelope:
        the IDs a valid cut names are checkpoints (events.md, "Cuts")."""
        return i in self.envelopes or self.checkpoint(i) is not None

    def record(self, i: bytes) -> dict | str | None:
        """Checkpoint i's record from the object its roster part names, or
        None while this replica cannot read it (roster.md, "The checkpoint
        record"): the checkpoint is then held as one it cannot open. A
        record that opens and does not match is BadCheckpoint ("bad")."""
        k = ("record", i)
        if k not in self.memo:
            if i in self.records:
                self.memo[k] = self.records[i]
            else:
                d = self.checkpoint(i)
                data = None if d is None else self.objects.get(d.part["locator"])
                secret = self.keys.rotations.get(i)
                if data is None or secret is None:
                    self.memo[k] = None
                else:
                    e = self.log.events[i]
                    try:
                        self.memo[k] = R.read_record_object(
                            data, self.log.id, secret, d.part,
                            self_ref=kg.self_ref(e.author, e.seq))[0]
                    except SpecError as error:
                        # A key or member type of a later document this
                        # replica lacks holds the checkpoint (roster.md,
                        # "The checkpoint record", step 3).
                        self.memo[k] = "ExtensionRequired" \
                            if error.error == "ExtensionRequired" else "bad"
            # A cut whose body uses a reserved key holds the checkpoint as
            # a record held for one does (roster.md, section 3.15.2, step 1;
            # peers.md, "Reserved cut keys").
            if isinstance(self.memo[k], dict) and self.skeleton and cut_held(self, i):
                self.memo[k] = "ExtensionRequired"
        return self.memo[k]

    def readable(self, i: bytes) -> bool:
        """Whether the checkpoint's record does not hold it: one held for a
        later document's key is readable once a step that reads no record
        voids it."""
        rec = self.record(i)
        if rec == "ExtensionRequired":
            return checkpoint_validity(self, i)[1] != "ExtensionRequired"
        return rec is not None

    def cuts(self, i: bytes) -> tuple:
        return self.log.events[i].cuts

    def reach(self, i: bytes) -> frozenset:
        """Every checkpoint an event's cuts reach: its cuts and, for each, the
        cuts that checkpoint declares, and so on (events.md, "Cuts"), through
        the envelopes this replica holds."""
        k = ("reach", i)
        if k not in self.memo:
            out = set()
            if i in self.log.events:
                for c in self.cuts(i):
                    out.add(c)
                    out |= self.reach(c)
            self.memo[k] = frozenset(out)
        return self.memo[k]

    def below(self, x: bytes, y: bytes) -> bool:
        """x ⊑ y: x is checkpoint y or one y's cuts reach."""
        return x == y or x in self.reach(y)

    def expected_cuts(self, i: bytes) -> set:
        """events.md, "Cuts": the maximal checkpoints among an event's
        parents and the cuts its parents declare. A parent this replica
        dropped is in its kept checkpoint's past and contributes nothing."""
        e = self.log.events[i]
        found = set()
        for p in e.parents:
            if p not in self.log.events:
                continue
            if self.is_checkpoint(p):
                found.add(p)
            found |= set(self.cuts(p))
        return {x for x in found if not any(x != y and self.below(x, y) for y in found)}

    def bad_cuts(self, i: bytes) -> bool:
        e = self.log.events[i]
        return not e.genesis and set(e.cuts) != self.expected_cuts(i)

    def follows(self, i: bytes, c: bytes) -> bool:
        """i is after checkpoint c: its cuts reach c (roster.md)."""
        return c in self.reach(i)

    def concurrent_checkpoints(self, x: bytes, y: bytes) -> bool:
        return not self.below(x, y) and not self.below(y, x)

    def reached_checkpoints(self, i: bytes) -> list:
        """The checkpoints i's cuts reach, those whose verdict this replica
        knows without opening first: its trusted ones, then those it opened."""
        out = [x for x in self.reach(i) if self.is_checkpoint(x)]
        return sorted(out, key=lambda x: (x not in self.trusted, x in self.envelopes, x))

    def valid_checkpoint(self, x: bytes) -> bool:
        if x in self.trusted:
            return True
        if x in self.envelopes:
            raise AssertionError("a verdict this replica cannot know was asked of it")
        return checkpoint_validity(self, x)[0]


# ---------------------------------------------------------------------------
# The world after a checkpoint.


@dataclass
class World:
    """A replica's verdicts over the events it holds."""
    status: dict
    chain: list  # the effective checkpoints, oldest first
    space: R.Space  # the Space whose roster is current
    valid_checkpoints: dict = dc_field(default_factory=dict)


def _space(ctx: Ctx, log: Log, view, presets, base=None) -> R.Space:
    k = ("space", id(log) if base is None else base["id"], frozenset(view),
         frozenset(presets.items()))
    if k not in ctx.memo:
        storage = twin_view(ctx, view, None if base is None else base["id"]) \
            if ctx.skeleton else None
        ctx.memo[k] = R.Space(log, set(view), ctx.lists, ctx.spaces, ctx.keys, storage,
                              presets=presets, base=base)
    return ctx.memo[k]


# ---------------------------------------------------------------------------
# The skeleton a replica reads (roster.md, "Other logs and extensions", Twins
# and the skeleton).


def peer_ctx(ctx: Ctx):
    """The skeleton events as a peer reads them, over what this replica
    holds: a replica that forgot under checkpoint c reads them as a peer
    that truncated under c's cut (peers.md, "Truncation")."""
    if "pctx" not in ctx.memo:
        import skeleton_cuts as SC
        if ctx.kept_cut is None:
            ctx.memo["pctx"] = SC.PCtx(ctx.log)
        else:
            ctx.memo["pctx"] = SC.PCtx(ctx.log, trusted={ctx.kept_cut},
                                       held=set(ctx.log.events))
    return ctx.memo["pctx"]


def cut_held(ctx: Ctx, c: bytes) -> bool:
    """Whether the cut checkpoint c names in visible key 15, held, uses a
    reserved key of a cut's body (peers.md, "Reserved cut keys")."""
    import storage as S
    t = twin_of(ctx, c)
    if t is None or t not in ctx.log.events:
        return False
    e = ctx.log.events[t]
    if e.kind != events.KIND_STORAGE:
        return False
    try:
        S.read_body(e.body)
    except SpecError as error:
        return error.error == "ExtensionRequired"
    return False


def twin_of(ctx: Ctx, c: bytes) -> bytes | None:
    """The twin a space event names in visible key 15."""
    return R.read_visible(ctx.log.events[c]).get("twin")


def twin_view(ctx: Ctx, view, c: bytes | None):
    """The skeleton a replica reads with a view: before any checkpoint in
    effect, the skeleton from its root; in checkpoint c's world, and in the
    past of a checkpoint whose predecessor is c, the skeleton after c's cut
    (peers.md, "The skeleton after a cut") over the skeleton events after c,
    whatever the peer's own rule says of that cut. A slot of the cut maps to
    the device and pseudonym of the entry of c's record that names it, and
    to no device when none does."""
    import skeleton_cuts as SC
    import storage as S
    if c is None:
        return S.TwinView(ctx.log, view)
    pctx = peer_ctx(ctx)
    cut = twin_of(ctx, c)
    k = ("world-skeleton", c, frozenset(view))
    if k not in ctx.memo:
        ctx.memo[k] = SC.world(pctx, cut, set(view) | {cut})
    sk = ctx.memo[k]
    mapping = {}
    rec = ctx.record(c)
    if isinstance(rec, dict):
        for m in rec["members"]:
            if m["slot"] is not None:
                mapping[tuple(m["slot"][:3])] = (m["member"][1], m["slot"][3])
    return S.ReplicaTwinView(ctx.log, view, sk, mapping)


def world_log(ctx: Ctx, c: bytes, held) -> DerivedLog:
    members = {i for i in held if i != c and ctx.follows(i, c)}
    k = ("dlog", c, frozenset(members))
    if k not in ctx.memo:
        ctx.memo[k] = DerivedLog(ctx.log, c, members)
    return ctx.memo[k]


def p_past(ctx: Ctx, c: bytes, x: bytes, held) -> frozenset:
    """x's past in c's world: what it reaches through events that follow c."""
    return world_log(ctx, c, held).anc[x] | {x}


def world_space(ctx: Ctx, c: bytes, view) -> R.Space:
    """The world of checkpoint c over `view`: c and events that follow it.
    Events with cuts that do not match are void (BadCuts); an event after c
    one of whose parents other than its prev is neither c nor after c is
    void (MixedCut), a parent this replica dropped included; a later
    checkpoint has the verdict of its own past."""
    view = {i for i in view if i == c or ctx.follows(i, c)}
    dlog = world_log(ctx, c, view)
    presets = {}
    for i in view - {c}:
        e = ctx.log.events[i]
        if ctx.bad_cuts(i):
            presets[i] = (False, "BadCuts", None)
        elif any(p != e.prev and p != c and not ctx.follows(p, c) for p in e.parents):
            presets[i] = (False, "MixedCut", None)
    for i in _topological(view - {c}, lambda i: dlog.events[i].parents):
        if i not in presets and ctx.checkpoint(i) is not None:
            presets[i] = checkpoint_validity(ctx, i)
    _hold_unreadable(ctx, view - {c}, presets, dlog.anc)
    base = {"id": c, "record": ctx.record(c), "descriptor": ctx.descriptor,
            "system_stream": ctx.system_stream}
    return _space(ctx, dlog, view, presets, base)


def _hold_unreadable(ctx: Ctx, view, presets: dict, anc) -> None:
    """A checkpoint whose record this replica cannot read is held as one it
    cannot open (Sealed), with every event after it (roster.md)."""
    held = {i for i in view if ctx.checkpoint(i) is not None and not ctx.readable(i)}
    extension = {i for i in held if ctx.record(i) == "ExtensionRequired" and not ctx.readable(i)}
    for i in held:
        presets[i] = (False, "ExtensionRequired" if i in extension else "Sealed", None)
    for i in view:
        if i not in held and anc[i] & held:
            presets[i] = (False, "ExtensionRequired" if anc[i] & extension else "Pending", None)


# ---------------------------------------------------------------------------
# A checkpoint: its record, its validity, its votes.


def _status_rank(status: int) -> int:
    return {R.INVITE_OPEN: 0, R.INVITE_USED: 1, R.INVITE_RACED: 2, R.INVITE_CLAIMED: 3}[status]


def _invite_entries(ctx: Ctx, sp: R.Space, prev: dict) -> dict:
    """roster.md, "The checkpoint record": each invite key in, or out only by
    valid successors, with its status; the predecessor's status counts as
    one more successor where it is not open."""
    out = {}
    root = sp.log.genesis
    keys = {m[1] for m in sp.roster if m[0] == R.INVITE}
    for k in sorted(keys):
        st = sp.roster[(R.INVITE, k)]
        if not st.present and not all(
                sp.is_successor(x) or (x == root and sp.root_successor(k)) for x in st.removed_by):
            continue  # revoked or closed: it leaves the record
        succ = [i for i in sp.view if sp.is_successor(i) and sp.ev(i).author == k]
        before = prev.get((R.INVITE, k))
        status = before["invite"] if before is not None else R.INVITE_OPEN
        claimant = before["claimant"] if before is not None else None
        for i in succ:
            v = sp.status.get(i, (False, None))
            mine = R.INVITE_CLAIMED if v[0] else \
                R.INVITE_RACED if v[1] == "ClaimRaced" else R.INVITE_USED
            if mine == R.INVITE_CLAIMED:
                claimant = sp.claimant(i)
            if _status_rank(mine) > _status_rank(status):
                status = mine
        out[k] = (status, claimant)
    return out


def _space_entry(sp: R.Space, space: bytes, prev: dict) -> dict:
    """A granted space's notices, floor and names (roster.md, "The checkpoint
    record"), the predecessor's as the world's root carries them."""
    valid = sp.valid()
    root = sp.log.genesis
    carried = [(e, n, a) for e, n, a in sp.carried_notices(valid) if n["space"] == space]
    by = {e for e, _, _ in carried}
    notices = sorted({(n["rotation"], n["public"], 1 if n["from_now_on"] else 0, a)
                      for e, n, a in carried
                      if not any(f != e and sp.log.le(e, f) for f in by)},
                     key=lambda n: R.cbor(list(n)))
    before = prev.get((R.SPACE, space))
    floor = bool(before and before["floor"]) or any(
        n["from_now_on"] for e, n, _ in carried if e != root)
    named = set(before["named"]) if before else set()
    for i in valid:
        named |= {x for log_id, x in sp.refs(i) if log_id == space}
    return {"notices": tuple(notices), "floor": floor, "named": tuple(sorted(named))}


def record_of(ctx: Ctx, sp: R.Space, previous: bytes | None) -> dict:
    """roster.md, "The checkpoint record": the roster, policy, chain tips and
    fork points of a world, with the epoch, each invite key's status and each
    granted space's notices, floor and names."""
    if previous is None:
        tips, epoch, prev = {}, 1, {}
    else:
        before = ctx.record(previous)
        tips, epoch = dict(before["tips"]), before["epoch"] + 1
        prev = {m["member"]: m for m in before["members"]}
    invites = _invite_entries(ctx, sp, prev)
    members = []
    for m, st in sorted(sp.roster.items()):
        entry = {"member": m, "level": None, "caps": frozenset(), "label": None,
                 "history": None, "via": None, "session": None, "replaces": None,
                 "seniority": None, "ed25519": None, "mldsa": None, "xwing": None, "slot": None,
                 "expires_at": None, "claims": None, "invite": None, "claimant": None,
                 "notices": (), "floor": False, "named": (), "rank": None}
        if m[0] == R.INVITE:
            if m[1] not in invites:
                continue
            entry["invite"], claimant = invites[m[1]]
            entry["ed25519"], entry["mldsa"], entry["xwing"] = sp.device_keys(m[1])
            if entry["invite"] == R.INVITE_CLAIMED:
                entry["claimant"] = claimant
                members.append(entry)
                continue
            grant = sp._invite_grant(st.grants, m[1])
            entry["claims"], entry["expires_at"] = grant.claims, grant.expires_at
        elif not st.present:
            continue
        entry.update(level=st.level, caps=st.caps, label=st.label, history=st.history,
                     via=st.via, session=st.session, replaces=st.replaces,
                     seniority=st.seniority, rank=st.rank if st.level == R.ADMINISTER else None)
        if m[0] == R.DEVICE:
            keys = sp.device_keys(m[1])
            assert keys is not None, "a device member's keys are held"
            entry["ed25519"], entry["mldsa"], entry["xwing"] = keys
            entry["expires_at"] = st.expires_at if st.session is not None else None
            if st.level == R.ADMINISTER and sp.storage is not None:
                slot = sp.storage.slot_entry(sp, m[1])
                entry["slot"] = None if slot is None else tuple(slot)
        if m[0] == R.SPACE:
            entry.update(_space_entry(sp, m[1], prev))
        members.append(entry)
    forks = dict(sp.forks)
    # Each author's greatest seq in the world, the smaller ID on a tie. A
    # skeleton cut is left out: it names the record's object, so the record
    # cannot count it (roster.md, "The checkpoint record").
    for i in sorted(sp.view):
        e = ctx.log.events[i]
        if e.kind == R.KIND_STORAGE and R.storage_record(e)["type"] == 7:
            continue
        if e.seq > tips.get(e.author, (0, b""))[0]:
            tips[e.author] = (e.seq, i)
    kept = {m["member"][1] for m in members if m["member"][0] == R.DEVICE
            and m["level"] == R.ADMINISTER and (R.DORMANT, R.EXTENDS) not in m["caps"]}
    return {"epoch": epoch, "previous": previous, "members": members,
            "policy": dict(sp.space_policy), "tips": tips, "forks": forks,
            "heard": heard_of(sp, kept)}


def checkpoint_validity(ctx: Ctx, c: bytes) -> tuple:
    """roster.md, "A checkpoint's validity", in order, on its own past alone."""
    k = ("valid", c)
    if c in ctx.trusted:
        return (True, "checkpoint", None)
    assert c not in ctx.envelopes, "a checkpoint kept as an envelope is never judged"
    if k in ctx.memo:
        return ctx.memo[k]
    ctx.memo[k] = (False, "Pending", None)  # a cycle never arises; guard anyway
    out = _validity(ctx, c)
    ctx.memo[k] = out
    return out


def _signature(ctx: Ctx, c: bytes, sp: R.Space) -> str | None:
    """Step 3: the checkpoint's signature, under the keys of its past as
    roster.md, "The world after a checkpoint", lets a replica take them: the
    records and events of that past, and the other logs it holds."""
    verdict = identity.signature_ok(ctx.log.events[c], sp.held_keys())
    return None if verdict is True else verdict


def _validity(ctx: Ctx, c: bytes) -> tuple:
    e = ctx.log.events[c]
    d = ctx.checkpoint(c)
    # 1. The event alone and its cuts; its record; no held checkpoint behind it.
    if ctx.bad_cuts(c):
        return (False, "BadCuts", None)
    record = ctx.record(c)
    if record is None:
        return (False, "Sealed", None)
    if record == "bad":
        return (False, "BadCheckpoint", None)
    # A record held for a later document's key (roster.md, section 3.15.2,
    # "A record held for a later document's key"): the steps that read no
    # record, 2 to 6, still decide, in order, its predecessor read from the
    # record's map alone; a failure is final, a step that holds holds it,
    # and one that passes them all stays held. A replica that forgot the
    # past cannot run them, and holds it.
    held_record = record == "ExtensionRequired"
    if held_record:
        raw = _raw_record(ctx, c)
        if raw is None or ctx.trusted:
            return (False, "ExtensionRequired", None)
        previous = raw.get(R.R_PREVIOUS)
    else:
        previous = record["previous"]
    pool = {x for x in ctx.log.anc[c]
            if previous is None or x == previous or ctx.follows(x, previous)}
    if any(ctx.checkpoint(x) is not None and not ctx.readable(x) for x in pool):
        return (False, "Pending", None)  # after a checkpoint it cannot read: held
    reached = ctx.reached_checkpoints(c)
    # 2. The predecessor.
    if previous is None:
        if any(ctx.valid_checkpoint(x) for x in reached):
            return (False, "BadCheckpoint", None)  # it names none, past a valid one
        past = ctx.log.anc[c]
        presets = _presets_outside(ctx, past)
        sp = _space(ctx, ctx.log, past, presets)
    else:
        # It names the latest checkpoint its cuts reach: every other one is
        # before it, or after it (and then it is made too early, below).
        if previous not in reached \
                or any(not ctx.below(x, previous) and not ctx.below(previous, x) for x in reached):
            return (False, "BadCheckpoint", None)
        if any(x != previous and ctx.below(previous, x) and ctx.valid_checkpoint(x)
               for x in reached):
            return (False, "CheckpointPending", None)  # a later checkpoint is in its past
        if not ctx.valid_checkpoint(previous):
            return (False, "BadCheckpoint", None)
        held = p_past(ctx, previous, c, _follow_set(ctx, previous, c)) - {c}
        held |= {previous}
        if any(ctx.checkpoint(i) is not None and checkpoint_validity(ctx, i)[0]
               for i in held - {previous}):
            return (False, "CheckpointPending", None)
        if not stable(ctx, previous, held):
            return (False, "CheckpointPending", None)  # made before its predecessor took effect
        sp = world_space(ctx, previous, held)
    # 3. Its signature.
    bad = _signature(ctx, c, sp)
    if bad is not None:
        if held_record and bad == "NoHybridKey":
            return (False, "ExtensionRequired", None)  # held either way
        return (False, bad, None)
    # 4 to 7: its fork point, its authority, keys.md's checks, its record.
    if e.author in sp.forks and e.seq >= sp.forks[e.author]:
        return (False, "Forked", None)
    me = sp.roster.get((R.DEVICE, e.author))
    if me is None or not me.present or me.level != R.ADMINISTER:
        return (False, "NotAnAdministrator", None)
    try:
        # An administrator never carries a session (section 3.6), so a
        # checkpoint's author always propagates: a checkpoint is a grant
        # rotation exactly when the space is not restricted.
        assert me.session is None
        kg.check_payload_context(d.payload, {
            "event": "genesis", "author_propagates": True,
            "restricted": (ctx.descriptor or {}).get("kind") == R.spaces.KIND_RESTRICTED})
    except SpecError as error:
        return (False, error.error, None)
    if held_record:
        return (False, "ExtensionRequired", None)
    # 7. Its twin, the skeleton cut, by peers.md's checks of a cut: before
    # the record, whose `slot` entries read the skeleton after the
    # predecessor's cut, which a valid cut proves in effect in its past.
    if ctx.skeleton:
        bad = _twin_cut(ctx, c)
        if bad is not None:
            return (False, bad, None)
    # 8. The record, byte for byte.
    derived = record_of(ctx, sp, previous)
    if R.encode_record(_compared(derived)) != R.encode_record(_compared(record)):
        return (False, "BadCheckpoint", None)
    # 9. The cut against the record: its slot entries, and its standing
    # entries exactly those the record gives.
    if ctx.skeleton:
        import skeleton_cuts as SC
        slots = [m["slot"] for m in record["members"] if m["slot"] is not None]
        if SC.against_record(peer_ctx(ctx), twin_of(ctx, c), slots) is not None:
            return (False, "BadTwin", None)
        want = sorted((x["slot"], x["order"], x["dormant"], x["pseudonym"] or b"")
                      for x in standing_of(ctx, record, sp))
        cut_body = peer_ctx(ctx).body(twin_of(ctx, c))
        have = sorted((x["slot"], x["order"], x["dormant"], x["pseudonym"] or b"")
                      for x in cut_body["standing"])
        if want != have:
            return (False, "BadTwin", None)
    return (True, "checkpoint", None)


def standing_of(ctx: Ctx, record: dict, sp: R.Space) -> list:
    """peers.md, "Storage events", a cut's standing entries: for each
    administrator of the record its `slot` entry's slot, and for each heard
    member the most senior slot made for it, out in the skeleton of the
    past, with the root or enrolment of the pseudonym enrolled in it. Orders
    are 1 to n over the entries, by rank then seniority as replicas order
    authority: a member with no slot has no entry and no order. Dormant: 0,
    a member that votes; 1, dormant; 2, a recovery member by the
    predecessor's record; 2 + k, without a predecessor, a dormant member
    whose grant was signed by a member that k - 1 entries outrank."""
    admins = {m["member"][1]: m for m in record["members"]
              if m["member"][0] == R.DEVICE and m["level"] == R.ADMINISTER}
    keys = {d: _key(m.get("rank"), _sen(ctx, d, m["seniority"])) for d, m in admins.items()}
    heard_rows = record.get("heard", {})
    for d, (sen, rank, _) in heard_rows.items():
        keys[d] = _key(rank, _sen(ctx, d, sen))
    entries = {}  # device -> (slot, pseudonym's root or enrolment, for an out slot)
    for d, m in admins.items():
        if m["slot"] is not None:
            entries[d] = (tuple(m["slot"][:3]), None)
    tv = sp.storage
    if tv is not None:
        for d in heard_rows:
            found = sorted((tv.sk.seniority(sl), sl) for sl, v in tv.sk.merged.items()
                           if not v["in"] and tv.slot_device(sl) == d)
            if found:
                sl = found[0][1]
                p = tv.sk.merged[sl].get("enrolled")
                entries[d] = (sl, tv.sk.enrolled_by.get(p) if p is not None else None)
    ranked = sorted(entries, key=lambda d: keys[d])
    order = {d: n + 1 for n, d in enumerate(ranked)}
    prev = ctx.record(record["previous"]) if record["previous"] is not None else None
    out = []
    for d, (sl, pseudonym) in entries.items():
        code = 0
        m = admins.get(d)
        if m is not None and (R.DORMANT, R.EXTENDS) in m["caps"]:
            code = 1
            if isinstance(prev, dict):
                if any(p_["member"] == (R.DEVICE, d) and p_["level"] == R.ADMINISTER
                       and (R.DORMANT, R.EXTENDS) in p_["caps"] for p_ in prev["members"]):
                    code = 2
            elif record["previous"] is None and m["seniority"][3] in ctx.log.events:
                granter = ctx.log.events[m["seniority"][3]].author
                if granter in keys and granter != d:
                    code = 3 + sum(1 for e in ranked if keys[e] < keys[granter])
        out.append({"slot": sl, "order": order[d], "dormant": code, "pseudonym": pseudonym})
    return out


def _twin_cut(ctx: Ctx, c: bytes) -> str | None:
    """roster.md, "A checkpoint's validity", step 7: visible key 15 names a
    skeleton cut (TwinRequired), held (NoTwin, held), that c cites and that
    passes peers.md's checks of a cut, steps 1 to 6 (BadTwin)."""
    import skeleton_cuts as SC
    t = twin_of(ctx, c)
    if t is None:
        return "TwinRequired"
    e = ctx.log.events[c]
    # One that does not cite the cut it names is BadTwin from its own
    # parents, without the cut: a peer holds such a cut pending, Unnamed,
    # and never serves it (peers.md, "Skeleton cuts").
    if t not in e.parents:
        return "BadTwin"
    if t not in ctx.log.events:
        return "NoTwin"
    pctx = peer_ctx(ctx)
    if t not in e.parents or not pctx.is_cut(t) or pctx.checkpoint_of(t) != c:
        return "BadTwin"
    # Its past is the cut's past and the cut: the skeleton peers read of the
    # cut's past is the one the record reads.
    if any(x != t and x not in ctx.log.anc[t] for x in e.parents if x in ctx.log.events):
        return "BadTwin"
    if not SC.validity(pctx, t)[0]:
        return "BadTwin"
    return None


def _compared(record: dict) -> dict:
    """The record as step 7 compares it: each space member's notices, floor
    and names left out, since they read which key events are valid, which
    can read another log (roster.md, "The checkpoint record"); the votes
    vouch for them."""
    out = dict(record)
    out["members"] = [{**m, "notices": (), "floor": False, "named": ()} for m in record["members"]]
    return out


def _follow_set(ctx: Ctx, c: bytes, x: bytes) -> set:
    """The events that follow c and are in x's past."""
    return {i for i in ctx.log.anc[x] | {x} if ctx.follows(i, c)}


def _presets_outside(ctx: Ctx, view) -> dict:
    """The verdicts decided before the procedure in a view with no checkpoint
    in effect: cuts that do not match, and each checkpoint's own validity."""
    out = {}
    for i in view:
        if ctx.log.events[i].genesis:
            continue
        if ctx.bad_cuts(i):
            out[i] = (False, "BadCuts", None)
        elif ctx.checkpoint(i) is not None:
            out[i] = checkpoint_validity(ctx, i)
    _hold_unreadable(ctx, set(view), out, ctx.log.anc)
    return out


def _sen(ctx: Ctx, member_id: bytes, seniority: tuple) -> tuple:
    """A seniority tuple (epoch, height, hash, grant), the hash filled in as
    roster.py's states carry it: the smaller tuple is the more senior."""
    epoch, height, _, grant = seniority
    return (epoch, height, R.sha256(R.SENIORITY_LABEL + ctx.log.id + member_id), grant)


def past_space(ctx: Ctx, c: bytes) -> R.Space:
    """The resolution of c's past, as its validity reads it (roster.md,
    section 3.15.2): without a predecessor its causal past, with p the
    world of p over the events after p that c reaches."""
    k = ("past-space", c)
    if k not in ctx.memo:
        previous = ctx.record(c)["previous"]
        if previous is None:
            past = ctx.log.anc[c]
            ctx.memo[k] = _space(ctx, ctx.log, past, _presets_outside(ctx, past))
        else:
            held = p_past(ctx, previous, c, _follow_set(ctx, previous, c)) - {c}
            ctx.memo[k] = world_space(ctx, previous, held | {previous})
    return ctx.memo[k]


def _lowers(sp: R.Space, i: bytes) -> list:
    """The device members roster event i lowers from administer at its
    place: removes, demotes below administer, or extends frasil.dormant to,
    each with its state there."""
    out = []
    S = sp.state(sp.place(i, sp.valid_roster))
    for ch in sp.changes(i):
        if ch.member is None or ch.member[0] != R.DEVICE:
            continue
        st = S.get(ch.member)
        if st is None or not st.present or st.level != R.ADMINISTER \
                or (R.DORMANT, R.EXTENDS) in st.caps:
            continue
        if ch.op == R.REMOVE or (ch.op == R.CHANGE and (
                (ch.level is not None and ch.level < R.ADMINISTER)
                or (R.DORMANT, R.EXTENDS) in (ch.caps or ()))):
            out.append((ch.member[1], st, S))
    return out


def heard_of(sp: R.Space, kept: set) -> dict:
    """roster.md, "Votes and effect", heard members of the view `sp`
    resolves: each device that a valid roster event of the view lowered
    from administer, that `kept` (the record's administrators without
    frasil.dormant) does not hold, and that no such event lowered while
    signed by itself or by a member senior to it at its place. A lowering
    after which a valid event raised it back to administer does not count.
    Each maps to its seniority there. A pure function of the view."""
    root = sp.log.genesis
    valid = [i for i in sp.view if i != root and sp.is_roster(i) and i in sp.valid_roster]
    found: dict = {}
    for i in valid:
        author = sp.ev(i).author
        for d, st, S in _lowers(sp, i):
            if any(i in sp.log.anc[j] and any(
                    ch.member == (R.DEVICE, d) and ch.level == R.ADMINISTER
                    and ch.op in (R.GRANT, R.CHANGE) for ch in sp.changes(j)) for j in valid):
                continue  # raised back afterwards
            by = S.get((R.DEVICE, author))
            senior = author == d or (by is not None and by.present
                                     and _key(by.rank, by.seniority) < _key(st.rank, st.seniority))
            was = found.get(d, (False, st.seniority, st.rank))
            found[d] = (was[0] or senior, min(was[1], st.seniority),
                        max(was[2] or 0, st.rank or 0))
    return {d: (sen, rank, sp.device_keys(d)) for d, (excused_, sen, rank) in found.items()
            if not excused_ and d not in kept}


def _key(rank, seniority) -> tuple:
    """The order of authority (roster.md, section 3.6): the higher rank,
    then the more senior; the smaller key outranks."""
    return (-(rank or 0), seniority)


def heard(ctx: Ctx, c: bytes) -> dict:
    """The heard members c's record carries (key 8), each with its
    seniority as roster.py's states carry it."""
    return {d: _key(rank, _sen(ctx, d, sen))
            for d, (sen, rank, _) in ctx.record(c).get("heard", {}).items()}


def heard_keys(ctx: Ctx, c: bytes) -> list:
    """The (ML-DSA-65 key, X-Wing key) pairs of c's heard members, which
    their votes are checked under (roster.md, "Votes and effect")."""
    return [(keys[1], keys[2]) for _, _, keys in ctx.record(c).get("heard", {}).values()]


def _recovery(ctx: Ctx, c: bytes, x: bytes, target_sen: tuple, target: bytes = None) -> bool:
    """roster.md, "Votes and effect": a recovery member that may excuse a
    member of c's electorate whatever their seniority: a member of c's
    record at administer whose capabilities extend frasil.dormant, and that
    is in c's predecessor's record so; without a predecessor, one whose
    grant in c's past its target or a member senior to it signed."""
    record = ctx.record(c)
    mine = next((m for m in record["members"] if m["member"] == (R.DEVICE, x)), None)
    if mine is None or mine["level"] != R.ADMINISTER or (R.DORMANT, R.EXTENDS) not in mine["caps"]:
        return False
    if (mine.get("rank") or 0) < -target_sen[0]:
        return False  # a recovery member excuses only up to its own rank
    previous = record["previous"]
    if previous is not None:
        prev = ctx.record(previous)
        return isinstance(prev, dict) and any(
            m["member"] == (R.DEVICE, x) and m["level"] == R.ADMINISTER
            and (R.DORMANT, R.EXTENDS) in m["caps"] for m in prev["members"])
    # Without a predecessor: its grant in c's past was signed by the target
    # or by an administrator of c's record that outranks it, by the record's
    # ranks and seniorities, which a cut's standing entries carry to a peer
    # (peers.md, "Storage events").
    grant = mine["seniority"][3]
    if grant not in ctx.log.events:
        return False
    granter = ctx.log.events[grant].author
    if granter == x:
        return False
    if granter == target:
        return True
    by = next((m for m in record["members"] if m["member"] == (R.DEVICE, granter)
               and m["level"] == R.ADMINISTER), None)
    if by is not None:
        return _key(by.get("rank"), _sen(ctx, granter, by["seniority"])) <= target_sen
    row = record.get("heard", {}).get(granter)
    return row is not None and _key(row[1], _sen(ctx, granter, row[0])) <= target_sen


def excused(ctx: Ctx, c: bytes, w: R.Space, named: dict) -> set:
    """roster.md, "Votes and effect": the members of the electorate excused,
    for good. Evidence of a member's fork in c's world; or a judged roster
    event after c whose signature verifies, whatever its verdict, that
    removes it, demotes it below administer or extends frasil.dormant to
    it, signed by a member of c's record at administer that is senior to
    it, or by a recovery member. A junior, c's author or not, excuses
    nobody senior to it: otherwise a removed administrator could sign c on
    an old view and remove everyone else after it."""
    out = {a for a in named if a in w.forks}
    record = ctx.record(c)
    admins = {m["member"][1]: _key(m.get("rank"), _sen(ctx, m["member"][1], m["seniority"]))
              for m in record["members"]
              if m["member"][0] == R.DEVICE and m["level"] == R.ADMINISTER}
    hear_keys = None
    for i in w.view - {c}:
        if not w.is_roster(i):
            continue
        author = w.ev(i).author
        if i not in w._signed:
            # A heard member's own events are checked under the keys the
            # record gives it.
            if author not in named or author in admins:
                continue
            if hear_keys is None:
                hear_keys = heard_keys(ctx, c)
            if identity.signature_ok(w.ev(i), hear_keys) is not True:
                continue
        elif w.status.get(i, (True, None))[1] in HELD:
            continue
        for ch in w.changes(i):
            if ch.member is None or ch.member[0] != R.DEVICE:
                continue
            target = ch.member[1]
            if target == author and target in named and ch.op in (R.REMOVE, R.CHANGE):
                out.add(target)  # it lowers itself: it accepts
                continue
            if author not in admins or target == author:
                continue
            if target not in named:
                continue
            if not (ch.op == R.REMOVE or (ch.op == R.CHANGE and (
                    (ch.level is not None and ch.level < R.ADMINISTER)
                    or (R.DORMANT, R.EXTENDS) in (ch.caps or ())))):
                continue
            if admins[author] < named[target] or _recovery(ctx, c, author, named[target],
                                                           target):
                out.add(target)
    return out & set(named)


def electorate(ctx: Ctx, c: bytes, held) -> set:
    """The devices a checkpoint waits for: the administrators of its record
    without `frasil.dormant`, and the heard members of its window, less
    those excused."""
    record = ctx.record(c)
    named = {m["member"][1]: _key(m.get("rank"), _sen(ctx, m["member"][1], m["seniority"]))
             for m in record["members"]
             if m["member"][0] == R.DEVICE and m["level"] == R.ADMINISTER
             and (R.DORMANT, R.EXTENDS) not in m["caps"]}
    named.update(heard(ctx, c))
    w = world_space(ctx, c, held | {c})
    return set(named) - excused(ctx, c, w, named)


def votes(ctx: Ctx, c: bytes, held) -> set:
    """The devices that voted for c: its author, by c itself; another, by
    any event after c whose signature verifies and whose cuts are correct
    and reach no checkpoint concurrent with c. A heard member's keys come
    from c's past, where its grant is."""
    w = world_space(ctx, c, held | {c})
    author = ctx.log.events[c].author
    out = {author}
    first: dict = {}
    hear = heard(ctx, c)
    past_keys = None
    for i in w.view - {c}:
        e = ctx.log.events[i]
        if e.kind >= 64 or ctx.bad_cuts(i):
            continue
        if i not in w._signed:
            if e.author not in hear:
                continue
            if past_keys is None:
                past_keys = heard_keys(ctx, c)
            if identity.signature_ok(e, past_keys) is not True:
                continue
        elif w.status.get(i, (True, None))[1] in HELD:
            continue  # held: as if this replica had not received it
        first.setdefault(e.author, []).append(i)
    for a, ids in first.items():
        # Once a device's chain follows c, no later event of it can vote for
        # a concurrent one without forking, and a vote is never taken back.
        if any(all(not ctx.concurrent_checkpoints(x, c) for x in ctx.reach(i)
                   if ctx.is_checkpoint(x)) for i in ids):
            out.add(a)
    return out


def waiting_for(ctx: Ctx, c: bytes, held) -> list:
    """roster.md, "Votes and effect", waiting for: the members of c's
    electorate that have not voted, which a client reports so that an
    application can show them and an administrator can remove one or mark it
    dormant."""
    held = {x for x in held if x == c or ctx.follows(x, c)}
    return sorted(electorate(ctx, c, held) - votes(ctx, c, held))


def stable(ctx: Ctx, c: bytes, held) -> bool:
    k = ("stable", c, frozenset(held))
    if k not in ctx.memo:
        held = set(held)
        ctx.memo[k] = electorate(ctx, c, held) <= votes(ctx, c, held)
    return ctx.memo[k]


# ---------------------------------------------------------------------------
# A replica's verdicts.


def effective_chain(ctx: Ctx, held, base: bytes | None) -> list:
    chain = [base] if base is not None else []
    current = base
    while True:
        cands = []
        for i in held:
            d = ctx.checkpoint(i)
            if d is None or i == current or not isinstance(ctx.record(i), dict) \
                    or ctx.record(i)["previous"] != current:
                continue
            if current is not None and not ctx.follows(i, current):
                continue
            if not checkpoint_validity(ctx, i)[0]:
                continue
            if stable(ctx, i, {x for x in held if x == i or ctx.follows(x, i)}):
                cands.append(i)
        if not cands:
            return chain
        current = min(cands)
        chain.append(current)


def judge(ctx: Ctx, held, base: bytes | None = None) -> World:
    """The verdicts of a replica holding `held`. With `base`, the replica
    keeps only checkpoint `base`, in effect, and what roster.md lets it keep
    (its Ctx holds a KeptLog); it forgot everything else."""
    held = set(held) - ctx.envelopes - {ctx.log.genesis if base is not None else None}
    k = ("judge", frozenset(held), base)
    if k in ctx.memo:
        return ctx.memo[k]
    # A checkpoint whose record object this replica lacks is held (Sealed),
    # with every event in whose past it is, whichever world that event
    # would be in; the replica judges the rest as if it had not received
    # them (roster.md, "The record object").
    unreadable = {i for i in held if ctx.checkpoint(i) is not None and not ctx.readable(i)}
    blocked = {i for i in held if i in unreadable or ctx.log.anc[i] & unreadable}
    if blocked:
        inner = judge(ctx, held - blocked, base)
        status = dict(inner.status)
        # A record using a later document's key or member type holds the
        # checkpoint and every event after it as ExtensionRequired.
        extension = {i for i in unreadable if ctx.record(i) == "ExtensionRequired"}
        for i in blocked:
            if i in extension or ctx.log.anc[i] & extension:
                status[i] = (False, "ExtensionRequired", None)
            else:
                status[i] = (False, "Sealed" if i in unreadable else "Pending", None)
        if base is not None and rival_checkpoints(ctx, held, base) & extension:
            # A rival whose record it cannot read for a later document's key
            # holds everything, as any rival does (roster.md, "A rival").
            for i in held:
                if i not in extension:
                    status[i] = (False, "Pending", None)
        out = World(status, inner.chain, inner.space)
        ctx.memo[k] = out
        return out
    chain = effective_chain(ctx, held, base)
    status: dict = {}
    if not chain:
        assert base is None
        sp = _space(ctx, ctx.log, held, _presets_outside(ctx, held))
        out = World(dict(sp.status), [], sp)
        ctx.memo[k] = out
        return out
    if base is None:
        before = judge(ctx, ctx.log.anc[chain[0]])
        status.update(before.status)
    for a, b in zip(chain, chain[1:]):
        w = world_space(ctx, a, p_past(ctx, a, b, {x for x in held if ctx.follows(x, a)}))
        status.update({i: v for i, v in w.status.items() if i != a})
        status[a] = (True, "checkpoint", None)
    last = chain[-1]
    sp = world_space(ctx, last, {x for x in held if x == last or ctx.follows(x, last)})
    status.update({i: v for i, v in sp.status.items() if i != last})
    status[last] = (True, "checkpoint", None)
    for i in held:
        if i not in status:
            status[i] = (False, LATE, last if ctx.log.events[i].kind == KIND_UNIT else None)
    if base is not None:
        rivals = rival_checkpoints(ctx, held, base)
        if rivals:
            # roster.md, "Forgetting", a rival: it cannot tell whether the
            # rival is valid, so whether its kept checkpoint stays in
            # effect. It holds pending every event it holds: the kept
            # checkpoint and what follows it, and the late events, which
            # are in the rival's past or after it if the rival wins.
            for i in held:
                status[i] = (False, "Pending", None)
    out = World(status, chain, sp)
    ctx.memo[k] = out
    return out


def _raw_record(ctx: Ctx, x: bytes):
    """A checkpoint's record object as a CBOR map, read no further: what a
    replica that lacks a later document reads of keys 2 and 3."""
    d = ctx.checkpoint(x)
    data = None if d is None else ctx.objects.get(d.part["locator"])
    secret = ctx.keys.rotations.get(x)
    if data is None or secret is None:
        return None
    e = ctx.log.events[x]
    try:
        plain = units.read_object(data, ctx.log.id, secret, d.part["locator"], record=True,
                                  self_ref=kg.self_ref(e.author, e.seq))
    except SpecError:
        return None
    value = R.uncbor(plain)
    if not isinstance(value, dict) or (R.R_PREVIOUS in value and not (
            isinstance(value[R.R_PREVIOUS], bytes) and len(value[R.R_PREVIOUS]) == 32)):
        return None
    return value


def rival_checkpoints(ctx: Ctx, held, base: bytes) -> set:
    k = ("rivals", base, frozenset(held))
    if k not in ctx.memo:
        ctx.memo[k] = _rivals(ctx, held, base)
    return ctx.memo[k]


def _rivals(ctx: Ctx, held, base: bytes) -> set:
    """roster.md, "Forgetting, and starting from a checkpoint", a rival: at
    a replica that forgot under `base`, a checkpoint concurrent with it that
    names base's predecessor, a checkpoint base's cuts reach, or none; whose
    ID is smaller than that of a checkpoint of base's chain it could replace
    (base, or one base's cuts reach after the one it names); that passes
    what the replica can check of it without its past (its cuts, its
    record, keys.md's checks as a genesis); and that is stable in what the
    replica holds after it. Were it valid it would take a place in base's
    chain, which only the forgotten past tells. A rival needs two
    electorates with no device in common (section 3.15.4)."""
    previous = ctx.record(base)["previous"]
    reached = set(ctx.reach(base))
    out = set()
    for x in held:
        if x == base or ctx.checkpoint(x) is None or not ctx.concurrent_checkpoints(x, base):
            continue
        rec = ctx.record(x)
        if ctx.bad_cuts(x):
            continue
        held_record = rec == "ExtensionRequired"
        if held_record:
            # A record this replica cannot read for a later document's key:
            # its predecessor is read from keys 2 and 3 alone, and it counts
            # as stable, since its votes cannot be checked (roster.md,
            # "A rival").
            raw = _raw_record(ctx, x)
            if raw is None:
                continue
            rec = {"previous": raw.get(R.R_PREVIOUS)}
        elif not isinstance(rec, dict):
            continue
        q = rec["previous"]
        if q is None:
            replaceable = {base} | reached
        elif q == previous or q in reached:
            replaceable = {base} | {y for y in reached if y != q and ctx.below(q, y)}
        else:
            continue
        if not any(x < y for y in replaceable):
            continue
        # What it can check of x without x's past: the event alone, its
        # record, and keys.md's checks as a genesis (section 3.15.2, steps
        # 1 and 6); the rest needs the past it forgot.
        try:
            kg.check_payload_context(ctx.checkpoint(x).payload, {
                "event": "genesis", "author_propagates": True,
                "restricted": (ctx.descriptor or {}).get("kind")
                == R.spaces.KIND_RESTRICTED})
        except SpecError:
            continue
        if held_record:
            out.add(x)
            continue
        # Judged apart, so that what it cannot tell leaves no verdict behind.
        apart = copy.copy(ctx)
        apart.memo = {}
        try:
            if stable(apart, x, {y for y in held if y == x or ctx.follows(y, x)}):
                out.add(x)
        except (KeyError, AssertionError, SpecError):
            # Its stability reads what the replica forgot (a checkpoint
            # after it whose validity needs its own past): it cannot tell.
            out.add(x)
    return out


# ---------------------------------------------------------------------------
# Building histories with checkpoints (the vectors' and the model check's).


def attach(r: R.Roster) -> None:
    """Teach a Roster builder to declare cuts and to follow its checkpoints:
    each device cites no event concurrent with the checkpoint it follows."""
    hist = r.hist
    r.checkpoints = getattr(r, "checkpoints", set())
    r.bad_checkpoints = getattr(r, "bad_checkpoints", set())

    def reach(i):
        out = set()
        for c in hist.log.events[i].cuts:
            out.add(c)
            out |= reach(c)
        return out

    def below(x, y):
        return x == y or x in reach(y)

    def cuts_for(parents):
        found = set()
        for p in parents:
            if p in r.checkpoints:
                found.add(p)
            found |= set(hist.log.events[p].cuts)
        return sorted(x for x in found if not any(x != y and below(x, y) for y in found))

    def followed(name, w):
        cps = [c for c in w if c in r.checkpoints and c not in r.bad_checkpoints
               and not contested(r, name, c, w)]
        top = [c for c in cps if not any(c != d and below(c, d) for d in cps)]
        if not top:
            return None
        author = hist.device(name)
        mine = [i for i in w if hist.log.events[i].author == author]
        if mine:
            last = max(mine, key=lambda i: hist.log.events[i].seq)
            own = [c for c in top if c == last or below(c, last) or c in reach(last)]
            if own:
                return min(own)
        return min(top)

    def fence(name, w):
        anc = hist.log.anc
        # A contested checkpoint, and everything after it, is never cited:
        # citing it would vote for it (roster.md, "Clients").
        bad = {c for c in w if c in r.checkpoints and contested(r, name, c, w)}
        out = {x for x in w if x in bad or anc[x] & bad}
        c = followed(name, w)
        if c is None:
            return out
        return out | {x for x in w if x != c and x not in anc[c] and c not in anc[x]}

    hist.fence = fence
    hist.cuts_for = cuts_for
    r.followed = followed


def contested(r: R.Roster, name: str, c: bytes, w) -> bool:
    """roster.md, "Clients", Contested checkpoints: the device `name`, whose
    view is `w`, does not follow checkpoint c, so never votes for it, when
    c's record leaves it heard (lowered from administer only by members
    junior to it), or when its view holds a valid roster event concurrent
    with c that lowers c's author or an administrator c's record keeps,
    signed by a member senior to the one it lowers."""
    w = frozenset(w)
    k = ("contested", name, c, w)
    memo = r.__dict__.setdefault("_contested", {})
    if k in memo:
        return memo[k]
    ctx = r.__dict__.get("_cctx")
    if ctx is None or ctx.log is not r.log:
        ctx = r._cctx = Ctx(r.log, r.keyring(), None,
                            getattr(r, "spaces_for_checkpoints", lambda: None)(),
                            objects=r.objects)
    out = False
    rec = ctx.record(c)
    if isinstance(rec, dict):
        me = r.hist.device(name)
        if me in rec.get("heard", {}):
            out = True
        else:
            kept = {m["member"][1] for m in rec["members"] if m["member"][0] == R.DEVICE
                    and m["level"] == R.ADMINISTER} | {r.log.events[c].author}
            anc = r.log.anc
            rivals = [x for x in w if x not in anc[c] and c not in anc[x] and x != c
                      and r.log.events[x].kind == R.KIND_SPACE]
            if rivals:
                sp = _space(ctx, ctx.log, w, _presets_outside(ctx, w))
                for x in rivals:
                    if not sp.is_roster(x) or x not in sp.valid_roster:
                        continue
                    S = sp.state(sp.place(x, sp.valid_roster))
                    by = S.get((R.DEVICE, sp.ev(x).author))
                    for d, st, _ in _lowers(sp, x):
                        if d in kept and by is not None and \
                                _key(by.rank, by.seniority) < _key(st.rank, st.seniority):
                            out = True
    memo[k] = out
    return out


_CHAIN = object()  # make_checkpoint's predecessor: the last in effect in its past


def make_checkpoint(r: R.Roster, by: str, label: str, *, tamper=None, twin_maker=None,
                    fence: bool = True, previous=_CHAIN, grant_rotation=None,
                    tamper_plain=None, **kw) -> bytes:
    """`by` signs a checkpoint over its view: the record of its past. An
    honest client follows (`fence`) and names the last checkpoint in effect in
    its past; a dishonest administrator may cite every head of its view,
    concurrent checkpoints included (`fence=False`), and name any
    `previous`, its record then derived from that predecessor's world over
    its past, or from its whole past for None."""
    attach(r)
    r.objects = getattr(r, "objects", {})
    hist = r.hist
    w = set(hist.view[by] if kw.get("view") is None else kw["view"])
    author = hist.device(by)
    mine = [i for i in w if hist.log.events[i].author == author]
    last = max(mine, key=lambda i: (hist.log.events[i].seq, i), default=None)
    parents = hist.parents_for(by, w, last, fence)
    past = set()
    for p in parents:
        past |= hist.log.anc[p] | {p}
    # The granted spaces' logs as its author holds them, for the record's
    # space entries (roster.md, "The checkpoint record").
    held_spaces = getattr(r, "spaces_for_checkpoints", lambda: None)()
    ctx = Ctx(r.log, r.keyring(), None, held_spaces, objects=getattr(r, "objects", {}),
              skeleton=hasattr(r, "twin_names"))
    world = judge(ctx, past)
    chosen = previous is not _CHAIN
    if not chosen:
        previous = world.chain[-1] if world.chain else None
    if previous is None:
        sp = world.space if not world.chain else _space(ctx, ctx.log, past,
                                                        _presets_outside(ctx, past))
    else:
        probe = {p for p in parents if p == previous or ctx.follows(p, previous)}
        held = {previous}
        for p in probe:
            held |= p_past(ctx, previous, p, {x for x in past if ctx.follows(x, previous)})
        sp = world_space(ctx, previous, held)
    record = record_of(ctx, sp, previous)
    if tamper is not None:
        record = tamper(record)
    plain = R.encode_record(record)
    if tamper_plain is not None:
        plain = tamper_plain(plain)
    # The record travels as an object sealed under the checkpoint's own
    # content key, its header naming the checkpoint by its self reference.
    secret = example(f"{r.prefix}/{label}/content-key")
    seq = 1 if last is None else hist.log.events[last].seq + 1
    obj = units.seal_object(r.id, secret, kg.self_ref(author, seq), plain)
    r.objects[obj["locator"]] = obj["bytes"]
    part = R.checkpoint_roster(plain, obj["locator"])
    if twin_maker is not None:
        # Its skeleton cut, signed first, which names the record's locator
        # and the standing the record gives (peers.md, "Skeleton cuts");
        # the checkpoint cites it.
        r._cut_standing = standing_of(ctx, record, sp)
        parents = set(parents) | set(twin_maker(obj["locator"], parents, past, fence))
    grant = not r.restricted if grant_rotation is None else grant_rotation
    i = r.space_event(by, label, part, True, flags={"grant_rotation": grant},
                      parents=parents, **{k: v for k, v in kw.items() if k != "view"})
    assert hist.log.events[i].seq == seq
    r.checkpoints.add(i)
    if tamper is not None or tamper_plain is not None:
        r.bad_checkpoints.add(i)
    return i


def starts_from(ctx: Ctx, c: bytes) -> str:
    """roster.md, "Starting from a checkpoint": a newcomer starts from the
    checkpoint a space snapshot names only once it reads its record; one
    whose record uses a key or member type a later document defines, which
    this implementation lacks, it refuses (ExtensionRequired) and tells the
    application the space needs a version it lacks."""
    rec = ctx.record(c)
    return "starts" if isinstance(rec, dict) else f"refused: {rec}"


def _extension_rival(prefix: str) -> dict:
    """roster.md, "A rival": P founds the space and grants W write. W signs
    a checkpoint whose record carries a record key 9, concurrently with P's
    checkpoint C, which takes effect. A replica that forgot under C, and
    lacks the document defining key 9, cannot read W's record nor judge
    W's authority without the past: W's checkpoint, whose ID is smaller,
    is a rival there, stable as far as it can tell, and it holds
    everything pending. A replica that holds the past judges the steps that
    read no record: W administers nothing, so its checkpoint is
    NotAnAdministrator, final, and C stays in effect."""
    for n in range(64):
        r = R.Roster("P", f"{prefix}/{n}")
        r.grant("P", "W", R.WRITE)
        r.sync("P", "W")

        def plain_edit(plain):
            value = R.uncbor(plain)
            value[R.RESERVED_RECORD_KEY] = 1
            return R.cbor(value)
        x = make_checkpoint(r, "W", "W checkpoints, its record using a later document's key",
                            tamper_plain=plain_edit)
        c = make_checkpoint(r, "P", "P checkpoints (C)")
        if x < c:
            break
    final = set(r.log.events)
    ctx = Ctx(r.log, r.keyring(), objects=r.objects)
    full = judge(ctx, final)
    assert full.chain == [c], [r.name(i) for i in full.chain]
    assert checkpoint_validity(ctx, x)[1] == "NotAnAdministrator"
    fctx, held = forget(ctx, c, final)
    assert x in held and rival_checkpoints(fctx, held, c) == {x}
    forgot = judge(fctx, held, c)
    assert all(forgot.status[i][1] == "Pending" for i in held if i != x), \
        {r.name(i): forgot.status[i] for i in held}
    return {"history_prefix": f"{prefix}/{n}", "events": r.hist.describe(),
            "kept": {r.name(i): ("valid" if v[0] else v[1])
                     for i, v in sorted(full.status.items(), key=lambda kv: r.log.order_key(kv[0]))},
            "forgot": {"rivals": [r.name(x)],
                       "verdicts": {r.name(i): ("valid" if v[0] else v[1])
                                    for i, v in sorted(forgot.status.items(),
                                                       key=lambda kv: r.log.order_key(kv[0]))}}}


def resolve_caps(states) -> tuple:
    """roster.md, section 3.3: the capabilities a device holds over several
    paths at its highest level, the meet of theirs: an extending one stays
    only if every path has it, a narrowing one if any has it. A name may so
    stay in both modes. Sorted by name then mode, as at-rest.md's key 6."""
    if not states:
        return ()
    top = max(s.level for s in states)
    at_top = [s for s in states if s.level == top]
    extends = [frozenset(c for c in s.caps if c[1] == R.EXTENDS) for s in at_top]
    narrows = frozenset().union(*(frozenset(c for c in s.caps if c[1] == R.NARROWS)
                                  for s in at_top))
    caps = frozenset.intersection(*extends) | narrows
    return (top, tuple(sorted(caps, key=lambda c: (c[0].encode(), c[1]))))


def unit_context(sp: R.Space, u: bytes) -> tuple:
    """units.md, the context of a unit: the capabilities its author holds at
    its place, as the adapter reads them: the meet over the paths that
    admit it at its highest level there, with that level."""
    S = sp.state(sp.place(u, sp.valid_roster))
    paths, _ = sp.paths(sp.ev(u).author, S, R.READ, at=u)
    return resolve_caps([S[m] for m in paths])


def frozen_outcomes(ctx: Ctx, world: World, held) -> dict:
    """units.md, "The past of a kept checkpoint": for each unit of the past
    of the last checkpoint of the chain in effect, its verdict and its
    context at its place, read in the view that judged it (the past of the
    first checkpoint of the chain whose past holds it), as a replica that
    forgets freezes them."""
    out = {}
    if not world.chain:
        return out
    last = world.chain[-1]
    for u in held:
        if ctx.log.events[u].kind != KIND_UNIT or u not in ctx.log.anc[last]:
            continue
        c = next(x for x in world.chain if u in ctx.log.anc[x])
        sp = past_space(ctx, c)
        # A unit late under an earlier checkpoint has no place in the world
        # that judged it: its verdict, Late, is all that is frozen.
        placed = u in sp.log.events and u in sp.view
        context = unit_context(sp, u) if placed else None
        # Its attribution there (roster.md, section 3.11), the members it
        # was written through with their labels at its place, or None when
        # the write rule voids it; and, for a void unit, the events that
        # void it, which decide whether its author re-submits it.
        attribution = sp.attribution(u) if placed else None
        voiders = tuple(sp.voiders(u)) if placed and not sp.status[u][0] else ()
        # The verdict and its class; for a late unit, which checkpoint the
        # replica names as refusing it reads its own chain, not the content.
        st = world.status.get(u)
        out[u] = (None if st is None else st[:2], context,
                  None if attribution is None else tuple(tuple(x) for x in attribution),
                  voiders)
    return out


def standing_at_root(ctx: Ctx, c: bytes, u: bytes) -> tuple:
    """What a replica that forgot would read, wrongly, for a unit of c's past
    were it to read its author at the root of c's world: the record's
    standing of the author, if the record lists it."""
    author = ctx.log.events[u].author
    for m in ctx.record(c)["members"]:
        if m["member"] == (R.DEVICE, author):
            return (m["level"], tuple(sorted(m["caps"], key=lambda x: (x[0].encode(), x[1]))))
    return ()


def _frozen_content(prefix: str) -> dict:
    """units.md, "The past of a kept checkpoint": P founds the space and
    grants C write with the capability suggest (narrows), D read and E
    write. C writes a unit, then P lowers C to read; D writes a unit, which
    a reader may not, then P raises D to write; E writes, then P removes E. P
    checkpoints. A replica that kept everything and one that forgot under
    the checkpoint read each unit with its author's capabilities at its
    place, frozen; the record's standing, which a replica must not read for
    them, differs for each. C is labelled Carol and E Eve when they write;
    P relabels C Caroline and removes E later, and each unit's attribution,
    frozen at its place, keeps the labels of then: Carol, and Eve, whom the
    current roster no longer holds. D's unit, which the write rule voids,
    is attributed to no member, and no event voids it, so D does not
    re-submit it."""
    r = R.Roster("P", prefix)
    r.grant("P", "C", R.WRITE, caps=(("suggest", R.NARROWS),), tag="Carol")
    r.grant("P", "D", R.READ)
    r.grant("P", "E", R.WRITE, tag="Eve")
    r.sync("P", "C", "D", "E")
    units_ = {}
    for who in ("C", "D", "E"):
        units_[who] = r.unit(who, f"{who} writes")
    r.sync("P", "C", "D", "E")
    r.change("P", "C", R.READ, "P lowers C to read")
    r.change("P", "C", label="P relabels C Caroline", tag="Caroline")
    r.change("P", "D", R.WRITE, "P raises D to write")
    r.remove("P", "E", "P removes E")
    r.sync("P", "C", "D", "E")
    c = make_checkpoint(r, "P", "P checkpoints")
    final = set(r.log.events)
    ctx = Ctx(r.log, r.keyring(), objects=r.objects)
    full = judge(ctx, final)
    assert full.chain == [c]
    frozen = frozen_outcomes(ctx, full, final)
    rows = {}
    names = {r.member(n)[1]: n for n in ("P", "C", "D", "E")}
    now = past_space(ctx, c).state(past_space(ctx, c).valid_roster)
    for who, u in units_.items():
        status, context, attribution, voiders = frozen[u]
        root = standing_at_root(ctx, c, u)
        assert context != root, (who, context, root)
        current = now.get(r.member(who))
        rows[r.name(u)] = {"verdict": "valid" if status[0] else status[1],
                           "context": [] if not context else
                           [context[0], [list(x) for x in context[1]]],
                           "record_standing": [] if not root else
                           [root[0], [list(x) for x in root[1]]],
                           "attribution": None if attribution is None else
                           [[a[0], names[a[1]]] + list(a[2:]) for a in attribution],
                           "current_label": current.label if current is not None
                           and current.present else None,
                           "voided_by": [r.name(x) for x in voiders]}
    assert rows[r.name(units_["C"])]["attribution"][0][2:] == ["Carol"]
    assert rows[r.name(units_["C"])]["current_label"] == "Caroline"
    assert rows[r.name(units_["E"])]["attribution"][0][2:] == ["Eve"]
    assert rows[r.name(units_["E"])]["current_label"] is None
    assert rows[r.name(units_["D"])]["attribution"] is None
    assert rows[r.name(units_["D"])]["voided_by"] == []
    # Two paths at one level, one extending a capability and the other
    # narrowing it: the meet keeps both modes, which key 6 then holds.
    both = resolve_caps([R.State(True, level=R.WRITE, caps=frozenset({("comment", R.EXTENDS)})),
                         R.State(True, level=R.WRITE, caps=frozenset({("comment", R.EXTENDS),
                                                                      ("comment", R.NARROWS)}))])
    assert both == (R.WRITE, (("comment", R.EXTENDS), ("comment", R.NARROWS))), both
    return {"history_prefix": prefix, "events": r.hist.describe(), "units": rows,
            "two_paths": {"paths": [[R.WRITE, [["comment", R.EXTENDS]]],
                                    [R.WRITE, [["comment", R.EXTENDS], ["comment", R.NARROWS]]]],
                          "frozen": [both[0], [list(x) for x in both[1]]]}}


def _extension_after_predecessor(prefix: str) -> dict:
    """roster.md, section 3.15.2, a record held for a later document's key,
    with a predecessor: P founds the space, grants A administer and W write,
    and checkpoints (C1); P and A vote, so C1 takes effect. Then W, and
    apart A, each sign a checkpoint whose record names C1 as predecessor and
    carries record key 9. Steps 2 to 6 read no record and still decide: W's
    is NotAnAdministrator, final, and A's, which passes them, stays held as
    ExtensionRequired."""
    r = R.Roster("P", prefix)
    r.grant("P", "A", R.ADMINISTER)
    r.grant("P", "W", R.WRITE)
    r.sync("P", "A", "W")
    c1 = make_checkpoint(r, "P", "P checkpoints (C1)")
    r.sync("P", "A", "W")
    r.anchor("A", "A votes")
    r.sync("P", "A", "W")

    def plain_edit(plain):
        value = R.uncbor(plain)
        value[R.RESERVED_RECORD_KEY] = 1
        return R.cbor(value)
    w = make_checkpoint(r, "W", "W checkpoints after C1, its record using key 9",
                        tamper_plain=plain_edit)
    a = make_checkpoint(r, "A", "A checkpoints after C1, its record using key 9",
                        tamper_plain=plain_edit, view=r.hist.view["A"])
    ctx = Ctx(r.log, r.keyring(), objects=r.objects)
    raw_w, raw_a = _raw_record(ctx, w), _raw_record(ctx, a)
    assert raw_w[R.R_PREVIOUS] == c1 and raw_a[R.R_PREVIOUS] == c1
    vw, va = checkpoint_validity(ctx, w)[1], checkpoint_validity(ctx, a)[1]
    assert (vw, va) == ("NotAnAdministrator", "ExtensionRequired"), (vw, va)
    world = judge(ctx, set(r.log.events))
    return {"history_prefix": prefix, "events": r.hist.describe(),
            "verdicts": {r.name(w): vw, r.name(a): va},
            "statuses": {r.name(i): ("valid" if v[0] else v[1])
                         for i, v in sorted(world.status.items(),
                                            key=lambda kv: r.log.order_key(kv[0]))}}


def _extension_checkpoints(prefix: str) -> dict:
    """roster.md, "Reading a record", step 3: P and B; P checkpoints with a
    record that carries a key a later document defines. A replica that
    lacks it holds the checkpoint as ExtensionRequired, with B's anchor
    after it, never votes for it, and a newcomer does not start from it."""
    out = {}
    for name, edit in (
            ("a record key 9", lambda v: v.__setitem__(R.RESERVED_RECORD_KEY, 1)),
            ("a member-entry key 22", lambda v: v[R.R_MEMBERS][0].__setitem__(
                R.RESERVED_MEMBER_KEY, 1)),
            ("a member of type 4", lambda v: v[R.R_MEMBERS].append(
                {R.M_MEMBER: [R.RESERVED_MEMBER_TYPE, bytes(32)]}))):
        tag = name.replace(" ", "-")
        r = R.Roster("P", f"{prefix}/{tag}")
        r.grant("P", "B", R.ADMINISTER)
        r.sync("P", "B")

        def plain_edit(plain, edit=edit):
            value = R.uncbor(plain)
            edit(value)
            return R.cbor(value)
        c = make_checkpoint(r, "P", "P checkpoints, its record using a later document's key",
                            tamper_plain=plain_edit)
        r.sync("P", "B")
        after = r.anchor("B", "B anchors after it")
        ctx = Ctx(r.log, r.keyring(), objects=r.objects)
        world = judge(ctx, set(r.log.events))
        assert world.status[c] == (False, "ExtensionRequired", None), world.status[c]
        assert world.status[after][1] == "ExtensionRequired", world.status[after]
        assert not world.chain
        start = starts_from(ctx, c)
        assert start == "refused: ExtensionRequired", start
        out[name] = {"history_prefix": f"{prefix}/{tag}", "events": r.hist.describe(),
                     "record_object": h(r.objects[ctx.checkpoint(c).part["locator"]]),
                     "verdicts": {r.name(i): ("valid" if v[0] else v[1])
                                  for i, v in sorted(world.status.items(),
                                                     key=lambda kv: r.log.order_key(kv[0]))},
                     "effective": [], "newcomer": start}
    return out


# ---------------------------------------------------------------------------
# The model check.


def forget(ctx: Ctx, base: bytes, final, *, keys=None, lists=None, spaces_=None,
           served=None):
    """What a replica that forgot under `base`, in effect, holds once it has
    received `final` (roster.md, "Forgetting, and starting from a
    checkpoint"): a Ctx over a KeptLog of the genesis, `base` with its
    record, the envelopes of the checkpoints its cuts reach, the late events
    and the events after it, and the set it judges: `base`, the events after
    it and the late ones. It reads nothing else: every other event is
    absent from its log, and it opens no kept envelope.

    With `served`, the replica is a newcomer that starts from `base`: it
    holds what a peer that truncated serves (`served`) and the envelopes a
    snapshot hands it (key 14), and holds no ID of what came before; each
    parent it fetches that the peer answers Missing for counts as dropped."""
    log = ctx.log
    after = {i for i in final if i == base or ctx.follows(i, base)}
    late = {i for i in final if i not in log.anc[base] and i not in after}
    envelopes = set(ctx.reach(base))
    keep = after | late | envelopes | {log.genesis}
    cut = None
    if ctx.skeleton:
        # The kept checkpoint's skeleton cut and the roots and enrolments
        # its slots name.
        import storage as S
        cut = twin_of(ctx, base)
        keep |= {cut} | {x["pseudonym"] for x in S.read_body(log.events[cut].body)["slots"]
                         if x["pseudonym"] is not None}
    if served is None:
        dropped = (log.anc[base] & set(final)) - keep
    else:
        keep = (keep & set(served)) | envelopes | {log.genesis}
        dropped = {p for i in keep for p in log.events[i].parents if p not in keep}
        assert not dropped - log.anc[base], "a peer answers Missing only for its past"
    kept = KeptLog(log, keep, dropped)
    record = ctx.record(base)
    fctx = Ctx(kept, ctx.keys if keys is None else keys,
               ctx.lists if lists is None else lists,
               ctx.spaces if spaces_ is None else spaces_,
               trusted={base}, objects=ctx.objects, records={base: record},
               envelopes=envelopes, skeleton=ctx.skeleton, kept_cut=cut)
    return fctx, after | late


def comparable(full: World, forgot: World, held) -> list:
    """Disagreements on the events both hold."""
    return [(i, full.status.get(i), forgot.status.get(i)) for i in sorted(held)
            if full.status.get(i) != forgot.status.get(i)]


DEVICES = ["P", "A", "B", "C", "W", "X"]


def _team(seed: int):
    """A granted space: its founder T0 and t1, each also able to act in the
    granting space through the grant, and t2, whom the team admits "from now
    on" later."""
    team = R.Roster("T0", f"model/{seed}/team", grant_keys=True)
    team.grant("T0", "t1", R.WRITE)
    team.sync("T0", "t1")
    return team


def _grant_rotation(team: R.Roster) -> bytes:
    """The team's current grant rotation as T0 holds it: its latest event
    that rotates the grant key, the genesis at first."""
    view = team.hist.view["T0"]
    rots = [i for i in view if i in team.grant_rotations]
    return max(rots, key=lambda i: (team.log.height[i], i))


PERSON_DEVICES = ("q2", "q3")


def _persons(r, seed: int):
    """Two persons the space grants write, Q (q1) and S (s1), each list's
    first event copied into the space; q2 and q3, which their lists add,
    revoke and move between them as the history goes."""
    pq = identity.Person("q1", f"model/{seed}/Q", linear=True)
    ps = identity.Person("s1", f"model/{seed}/S", linear=True)
    shared = {n: example(f"model/{seed}/{n}") for n in PERSON_DEVICES}
    pq.hist.keys.update(shared)
    ps.hist.keys.update(shared)
    r.hist.keys.update({"q1": pq.hist.seed("q1"), "s1": ps.hist.seed("s1"), **shared})
    r.persons[pq.id], r.persons[ps.id] = "person Q", "person S"
    return {"Q": pq, "S": ps}, {"Q": "q1", "S": "s1"}


def _person_step(r, rng, people, heads, lists_in, pending, step) -> tuple | None:
    """One step of the person-list histories: a list adds, revokes or moves
    a device, its copy published at once or later; a pending copy is
    published; or a person's device writes."""
    what = rng.random()
    if what < 0.08:
        # A list checkpoint, and every device the list holds votes; its copy
        # places the adds its record names, published at once or later.
        import list_checkpoints as L
        x = rng.choice(sorted(people))
        p, head = people[x], heads[x]
        lc = L.make_checkpoint(p, head, f"{step}: {head} checkpoints {x}'s list")
        for name in sorted(lists_in[x]):
            p.hist.sync(head, name)
            L.ack(p, name, f"{step}: {name} votes for {x}'s list checkpoint")
        p.hist.sync(head, *sorted(lists_in[x]))
        rec = L.LCtx(p.log).record(lc)
        named = [L.LCtx(p.log).body(m["add"]).device for m in rec["members"]]
        carried = [(lc, dev, "add") for dev in named]
        if rng.random() < 0.5:
            r.sync("P", head)
            u = r.unit(head, f"{step}: {head} copies {x}'s list checkpoint")
            R.record_copy(r.log, u, p.id, carried)
        else:
            pending.append((x, carried))
        return ("list checkpoint", x)
    if what < 0.3:
        who = rng.choice(PERSON_DEVICES)
        x = rng.choice(sorted(people))
        p, head = people[x], heads[x]
        if who in lists_in[x]:
            lid = p.revoke(head, who, f"{step}: {head} revokes {who} from {x}")
            lists_in[x].discard(who)
            carried = (lid, who, "revoke")
        else:
            lid = p.add(head, who, identity.DEVICE, f"{step}: {head} adds {who} to {x}")
            lists_in[x].add(who)
            carried = (lid, who, "add")
        if rng.random() < 0.5:
            r.sync("P", head)
            r.copy_list(head, p, [carried], f"{step}: {head} copies {p.hist.name(lid)}")
        else:
            pending.append((x, [(lid, None if carried[1] is None else p.hist.device(carried[1]),
                                 carried[2])]))
        return ("list", x)
    if what < 0.5 and pending:
        # A late copy; or, an indirect one: a copy of a later list event
        # only, which places nothing in its past (roster.md, "A list at an
        # event's place"), the earlier event left uncopied.
        x, carried = pending.pop(rng.randrange(len(pending)))
        head = heads[x]
        r.sync("P", head)
        u = r.unit(head, f"{step}: {head} copies {people[x].hist.name(carried[0][0])}, late")
        if rng.random() < 0.25:
            later = max(people[x].log.events, key=people[x].log.order_key)
            R.record_copy(r.log, u, people[x].id, [(later, None, None)])
            return ("indirect copy", x)
        R.record_copy(r.log, u, people[x].id, carried)
        return ("copy", x)
    who = rng.choice(PERSON_DEVICES + ("q1", "s1"))
    r.sync("P", who)
    r.unit(who, f"{step}: {who} writes")
    return ("person unit", who)


def lists_then(r, view) -> dict:
    """Each person's list as a replica that holds `view` of the space holds
    it: the list events the copies in `view` carry, with their past in the
    list's log."""
    out = {}
    for pid, p in getattr(r, "people_by_id", {}).items():
        carried = {lid for log, copy, lid, _, _ in R.LIST_COPIES.get(pid, ())
                   if log is r.log and copy in view}
        held = set()
        for lid in carried:
            held |= p.log.anc[lid] | {lid}
        out[pid] = identity.DeviceList(p.log, held or {p.log.genesis})
    return out


def random_history(seed: int, *, checkpoints: bool = True, steps: int = 36,
                   invites: bool = False, granted: bool = False, adversarial: bool = True,
                   persons: bool = False):
    """A random history. With `invites`, administrators grant invite keys
    (ext-invite-links.md), claims are signed, some raced on older views,
    some closed or revoked, and keys claimed or raced before a checkpoint
    sign again after it. With `granted`, the space grants a team space whose
    roster changes, and the team's founder responds with notices, "from now
    on" ones included (keys.md, "Notices and space principals")."""
    rng = random.Random(seed)
    # A dishonest administrator, drawn apart so that the honest steps keep
    # their draws: it takes another member's view, then checkpoints citing
    # every head (no fence), naming as predecessor the last in effect, an
    # earlier checkpoint, or none.
    adv = random.Random(seed * 7907 + 3) if adversarial else None
    team = _team(seed) if granted else None
    keys = {n: team.hist.seed(n) for n in ("T0", "t1")} if granted else None
    r = R.Roster("P", f"model/{seed}", keys=keys)
    attach(r)
    r.unit_seals = True  # units carry a key reference (units.md)
    # Administrators' ranks (roster.md, section 2.3), drawn apart: the
    # founder at the top, every other one at most its granter's.
    rk = random.Random(seed * 7907 + 23)
    r.ranks = {"P": R.MAX_RANK}
    r.ranks["A"] = rk.choice([100, 200, R.MAX_RANK])
    r.grant("P", "A", R.ADMINISTER, rank=r.ranks["A"])
    r.sync("P", "A")
    admins = {"P", "A"}
    members = {"P", "A"}
    people = heads = None
    lists_in = {"Q": set(), "S": set()}
    pending: list = []
    if persons:
        people, heads = _persons(r, seed)
        r.people_by_id = {p.id: p for p in people.values()}
        for x, p in sorted(people.items()):
            r.grant("P", f"person {x}", R.WRITE, label=f"P grants person {x} write",
                    tag=f"{x}-label")
        for x, p in sorted(people.items()):
            r.sync("P", heads[x])
            r.copy_list(heads[x], p, [(p.genesis, heads[x], "add")],
                        f"{heads[x]} copies {x}'s first event")
        pr = random.Random(seed * 7907 + 29)
    removed: set = set()
    log_ops = []
    snapshots = []
    claims: dict = {}  # invite key name -> {"open": bool, "views": [...], "n": count}
    if granted:
        team.grant_rotations = {team.genesis}
        r.spaces_for_checkpoints = lambda: {team.id: team.resolve(team.hist.view["T0"])}
        r.spaces[team.id] = "team T"
        r.grant("P", "team T", R.WRITE, label="P grants team T",
                notices=[team.notice(team.genesis)])
        r.sync("P", "A", "T0", "t1")
    # Two groups of administrators, cut off from each other, that each
    # checkpoint and remove the other, before or after their checkpoint:
    # two electorates with no device in common. Drawn apart too.
    spl = random.Random(seed * 7907 + 11) if adversarial and checkpoints else None
    # A removed administrator that, on its view from before its removal,
    # removes the others and checkpoints: alone, with another removed
    # administrator, or with a device it grants there (roster.md, section 4,
    # "A backdated checkpoint"). Drawn apart too.
    atk = random.Random(seed * 7907 + 17) if adversarial and checkpoints else None
    r.attacks = []
    for step in range(steps):
        op = rng.random()
        actors = sorted(admins - removed)
        if not actors:
            break
        if atk is not None and atk.random() < 0.08 and removed & {"A", "B", "C"} \
                and len(r.attacks) < 2:
            try:
                if _takeover(r, atk, sorted(removed & {"A", "B", "C"}), step):
                    log_ops.append(("takeover",))
                    snapshots.append({n: set(v) for n, v in r.hist.view.items()})
            except (SpecError, KeyError, StopIteration, ValueError, AssertionError):
                pass
        if spl is not None and spl.random() < 0.05 and len(actors) >= 2 \
                and ("split",) not in log_ops:
            try:
                if _split(r, spl, actors, step):
                    log_ops.append(("split",))
                    snapshots.append({n: set(v) for n, v in r.hist.view.items()})
            except (SpecError, KeyError, StopIteration, ValueError, AssertionError):
                pass
        if persons and pr.random() < 0.35:
            try:
                o = _person_step(r, pr, people, heads, lists_in, pending, step)
                if o:
                    log_ops.append(o)
            except (SpecError, KeyError, StopIteration, ValueError, AssertionError):
                pass
            snapshots.append({n: set(v) for n, v in r.hist.view.items()})
            continue
        by = rng.choice(actors)
        extra = rng.random()
        try:
            if invites and extra < 0.10:
                k = f"I{len(claims)}"
                history = rng.choice([R.FROM_NOW_ON, R.WITH_HISTORY])
                r.act(by, [R._invite_grant(r, k, history=history, level=R.WRITE,
                                           claims=R.DEVICE)], f"{step}: {by} invites {k}")
                r.sync(by, k)
                claims[k] = {"views": [set(r.hist.view[k])], "n": 0, "by": by}
                log_ops.append(("invite", by, k))
                continue
            if invites and claims and extra < 0.22:
                k = rng.choice(sorted(claims))
                info = claims[k]
                what = rng.random()
                if what < 0.5 or info["n"] == 0:
                    # A claim, on the key's latest view, or a racer's on an
                    # older one.
                    old = what < 0.25 and info["n"] > 0
                    saved = set(r.hist.view[k])
                    if old:
                        r.hist.view[k] = set(rng.choice(info["views"]))
                    else:
                        r.sync(info["by"], k)
                    claimant = f"J{k[1:]}x{info['n']}"
                    r.hist.signer(claimant)
                    try:
                        _claim_by(r, k, claimant, f"{step}: {k} claims for {claimant}"
                                  + (" on an old view" if old else ""))
                    finally:
                        r.hist.view[k] |= saved
                    info["n"] += 1
                    info["views"].append(set(r.hist.view[k]))
                    log_ops.append(("race" if old else "claim", k))
                else:
                    # A close, or a revocation: an administrator removes the key.
                    r.sync(by, k)
                    r.act(by, [R.Change(R.REMOVE, (R.INVITE, r.hist.device(k)))],
                          f"{step}: {by} removes {k}")
                    log_ops.append(("close", by, k))
                continue
            if granted and extra < 0.32:
                what = rng.random()
                if what < 0.35:
                    tr = team.remove("T0", "t1", f"{step}: T0 removes t1 from the team") \
                        if "t1" in team.hist.view and _in_team(team, "t1") else \
                        team.grant("T0", "t1", R.WRITE, label=f"{step}: T0 grants t1 again")
                    team.grant_rotations.add(tr)
                    r.sync("P", "T0")
                    r.heal("T0", f"{step}: T0 responds to the team's change",
                           refs=[(team.id, tr)], notices=[team.notice(tr)])
                    log_ops.append(("team", "change"))
                elif what < 0.6:
                    name = f"t{2 + sum(1 for o in log_ops if o[:2] == ('team', 'admit'))}"
                    g = team.grant("T0", name, R.WRITE, R.FROM_NOW_ON,
                                   label=f"{step}: T0 admits {name} from now on")
                    team.grant_rotations.add(g)
                    r.sync("P", "T0")
                    r.heal("T0", f"{step}: T0 responds to the team's break",
                           refs=[(team.id, g)], notices=[team.notice(g, from_now_on=True)],
                           flags={"grant_rotation": True, "break": True})
                    log_ops.append(("team", "admit"))
                else:
                    r.sync("P", "t1")
                    r.unit("t1", f"{step}: t1 writes through the team")
                    log_ops.append(("team", "unit"))
                continue
            if op < 0.18:
                who = rng.choice([d for d in DEVICES if d not in members] or ["X"])
                if who in members:
                    continue
                level = rng.choice([R.WRITE, R.ADMINISTER, R.READ])
                rank = None
                if level == R.ADMINISTER:
                    rank = min(rk.choice([50, 100, 150, 200, R.MAX_RANK]),
                               r.ranks.get(by, R.MAX_RANK))
                    r.ranks[who] = rank
                r.grant(by, who, level, label=f"{step}: {by} grants {who}", rank=rank)
                members.add(who)
                if level == R.ADMINISTER:
                    admins.add(who)
                log_ops.append(("grant", by, who))
            elif op < 0.28:
                cands = sorted(members - {by, "P"})
                if not cands:
                    continue
                who = rng.choice(cands)
                r.remove(by, who, label=f"{step}: {by} removes {who}")
                members.discard(who)
                admins.discard(who)
                removed.add(who)
                log_ops.append(("remove", by, who))
            elif op < 0.36 and removed & {"A", "B", "C"}:
                # A removed administrator signs a counter-removal on an old
                # view of its own: the backdated duel.
                attacker = rng.choice(sorted(removed & {"A", "B", "C"}))
                old = r.hist.view[attacker]
                target = rng.choice(sorted({"P", "A", "B", "C"} - {attacker}))
                try:
                    r.remove(attacker, target, label=f"{step}: {attacker} counter-removes {target}",
                             view=old)
                    log_ops.append(("backdate", attacker, target))
                except Exception:
                    pass
            elif op < 0.52:
                who = rng.choice(sorted(members))
                r.unit(who, f"{step}: {who} writes")
                log_ops.append(("unit", who))
            elif op < 0.62 and checkpoints:
                if adv is not None and adv.random() < 0.35:
                    other = adv.choice(sorted(n for n in r.hist.view if r.hist.view[n]))
                    r.hist.view[by] |= r.hist.view[other]
                    named = sorted(c for c in r.hist.view[by] if c in r.checkpoints)
                    pick = adv.random()
                    kw = {} if pick < 0.5 or not named else \
                        {"previous": None} if pick < 0.7 else {"previous": adv.choice(named)}
                    x = make_checkpoint(r, by, f"{step}: {by} checkpoints, unfenced",
                                        fence=False, **kw)
                    # Honest devices follow only a checkpoint they judge valid.
                    vctx = Ctx(r.log, r.keyring(), None,
                               getattr(r, "spaces_for_checkpoints", lambda: None)(),
                               objects=r.objects)
                    if not checkpoint_validity(vctx, x)[0]:
                        r.bad_checkpoints.add(x)
                    log_ops.append(("rogue checkpoint", by))
                else:
                    make_checkpoint(r, by, f"{step}: {by} checkpoints")
                    log_ops.append(("checkpoint", by))
            elif op < 0.70 and checkpoints:
                # a vote: an administrator writes after taking the checkpoint
                for name in sorted(admins - removed):
                    r.sync(name, by)
                    r.anchor(name, f"{step}: {name} votes")
                log_ops.append(("votes", by))
            elif op < 0.76:
                # a fork: a device signs again at a sequence number it used
                who = rng.choice(sorted(members))
                author = r.hist.device(who)
                mine = sorted((r.log.events[i].seq, i) for i in r.hist.view[who]
                              if r.log.events[i].author == author)
                if len(mine) >= 2:
                    seq, old = mine[-2]
                    prev = r.log.events[old].prev
                    view = r.log.anc[old] - set()
                    r.unit(who, f"{step}: {who} forks at {seq}", seq=seq, prev=prev,
                           view=view | ({prev} if prev else set()), fence=False)
                    log_ops.append(("fork", who))
            elif op < 0.82 and checkpoints:
                # a rogue event that cites what a checkpoint's followers do not
                who = rng.choice(sorted(members))
                w = r.hist.view[who]
                parents = set(r.log.heads(w))
                if adv is not None and adv.random() < 0.4:
                    # sealed under the genesis's state, before any checkpoint
                    r.unit(who, f"{step}: {who} cites everything, sealed under the genesis",
                           parents=parents,
                           body=R.unit_sealed_body([r.genesis], f"{step}: stale"))
                    log_ops.append(("stale unit", who))
                else:
                    r.unit(who, f"{step}: {who} cites everything", parents=parents)
                    log_ops.append(("rogue", who))
            else:
                pool = sorted(n for n in r.hist.view if r.hist.view[n] and n in members | admins)
                if len(pool) < 2:
                    continue
                a, b = rng.sample(pool, 2)
                r.sync(a, b)
                log_ops.append(("sync", a, b))
        except (SpecError, KeyError, StopIteration, ValueError, AssertionError):
            continue
        if checkpoints and r.checkpoints and rng.random() < 0.25:
            name = rng.choice(sorted(admins - removed) or ["P"])
            other = rng.choice(sorted(n for n in r.hist.view if r.hist.view[n]))
            r.sync(name, other)
            try:
                r.anchor(name, f"{step}: {name} syncs with {other} and anchors")
                log_ops.append(("vote", name))
            except (SpecError, KeyError, AssertionError):
                pass
        snapshots.append({n: set(v) for n, v in r.hist.view.items()})
    r.sync(*r.everyone())
    return r, log_ops, snapshots, team


def _split(r: R.Roster, rng: random.Random, admins: list, step: int) -> bool:
    """The administrators split in two groups that see only each other. In
    each, one administrator checkpoints, and an administrator of the group
    removes every administrator of the other group, before the checkpoint
    (any of them, the author included: the record then omits them) or after
    it (another than its author, so that it excuses them); every
    administrator of the group then votes. Each checkpoint can take effect
    in its group's view, with an electorate disjoint from the other's: a
    lone group is a removed administrator's backdated checkpoint (roster.md,
    section 4)."""
    admins = list(admins)
    rng.shuffle(admins)
    k = rng.randint(1, len(admins) - 1)
    groups = [admins[:k], admins[k:]]
    for g in groups:
        if len(g) > 1:
            r.sync(*g)
    for g, other in ((groups[0], groups[1]), (groups[1], groups[0])):
        after = len(g) > 1 and rng.random() < 0.5
        author = g[0]
        remover = g[1] if after else rng.choice(g)
        if not after:
            for o in other:
                r.remove(remover, o, label=f"{step}: {remover} removes {o}, cut off")
            if len(g) > 1:
                r.sync(*g)
        make_checkpoint(r, author, f"{step}: {author} checkpoints, cut off")
        if len(g) > 1:
            r.sync(*g)
        if after:
            for o in other:
                r.remove(remover, o, label=f"{step}: {remover} removes {o} after the checkpoint")
            r.sync(*g)
        for d in g:
            if d != author:
                r.sync(d, author)
                r.anchor(d, f"{step}: {d} votes, cut off")
        if len(g) > 1:
            r.sync(*g)
    return True


def _takeover(r: R.Roster, rng: random.Random, removed: list, step: int) -> bool:
    """A backdated checkpoint (roster.md, section 4): a removed
    administrator, on its stale view, removes every other administrator it
    sees there, one per event, then checkpoints citing its whole view.
    Sometimes a second removed administrator colludes, on the same view;
    sometimes the attacker first grants a device of its own administer
    there, which removes some of the others. Records the attack."""
    attacker = rng.choice(removed)
    view = set(r.hist.view[attacker])
    sp = r.resolve(view)
    me = sp.roster.get((R.DEVICE, r.hist.device(attacker)))
    if me is None or not me.present or me.level != R.ADMINISTER:
        return False
    helpers = [attacker]
    mode = rng.choice(["alone", "colluder", "sybil"])
    if mode == "colluder" and len(removed) > 1:
        other = rng.choice([x for x in removed if x != attacker])
        r.hist.view[other] = set(view) | r.hist.view[other]
        st = r.resolve(r.hist.view[other]).roster.get((R.DEVICE, r.hist.device(other)))
        if st is not None and st.present and st.level == R.ADMINISTER:
            helpers.append(other)
            r.hist.view[attacker] |= r.hist.view[other]
    elif mode == "sybil":
        z = "Z" if "Z" not in r.hist.view else None
        if z is not None:
            r.grant(attacker, z, R.ADMINISTER, label=f"{step}: {attacker} grants {z}, backdated")
            r.sync(attacker, z)
            helpers.append(z)
    names = {r.hist.device(n): n for n in r.hist.view if r.hist.view.get(n) is not None}
    victims = []
    for m, st in sorted(sp.roster.items()):
        if m[0] == R.DEVICE and st.present and st.level == R.ADMINISTER \
                and m[1] in names and names[m[1]] not in helpers:
            victims.append(names[m[1]])
    if not victims:
        return False
    for k, v in enumerate(victims):
        by = helpers[k % len(helpers)]
        r.sync(*helpers)
        r.remove(by, v, label=f"{step}: {by} removes {v}, backdated")
    r.sync(*helpers)
    c = make_checkpoint(r, attacker, f"{step}: {attacker} checkpoints, backdated", fence=False)
    for hlp in helpers[1:]:
        r.sync(hlp, attacker)
        r.anchor(hlp, f"{step}: {hlp} votes for the backdated checkpoint")
    keys = {n: _key(sp.roster[(R.DEVICE, r.hist.device(n))].rank,
                    sp.roster[(R.DEVICE, r.hist.device(n))].seniority) for n in victims}
    mine = _key(me.rank, me.seniority)
    if any(k[0] < mine[0] for k in keys.values()):
        standing = "lower"
    elif any(k < mine for k in keys.values()):
        standing = "equal, junior"
    elif me.rank == R.MAX_RANK:
        standing = "top"
    else:
        standing = "senior"
    r.attacks.append({"checkpoint": c, "attackers": helpers, "victims": victims,
                      "mode": mode if len(helpers) > 1 else "alone",
                      "junior": standing in ("lower", "equal, junior"), "standing": standing})
    return True


def _disjoint(ctx: Ctx, a: bytes, b: bytes, final) -> bool:
    """Two concurrent checkpoints whose electorates share no device."""
    ea = electorate(ctx, a, {x for x in final if x == a or ctx.follows(x, a)})
    eb = electorate(ctx, b, {x for x in final if x == b or ctx.follows(x, b)})
    return ctx.concurrent_checkpoints(a, b) and not (ea & eb)


def _in_team(team: R.Roster, name: str) -> bool:
    sp = team.resolve(team.hist.view["T0"])
    st = sp.roster.get((R.DEVICE, team.hist.device(name)))
    return st is not None and st.present


def _claim_by(r: R.Roster, key: str, claimant: str, label: str, view=None) -> bytes:
    """A successor by invite key `key` (ext-invite-links.md) claiming device
    `claimant`, on `view` or the key's own."""
    d = r.hist.signer(claimant)
    c = R.Change(R.SUCCEED, (R.DEVICE, d.device_id), hybrid=d.xwing_public, mldsa=d.mldsa_public,
                 ed25519=d.ed_public)
    kw = {} if view is None else {"view": view}
    return r.space_event(key, label, R.update_roster([c]), False, **kw)


def _roster_view(sp: R.Space) -> dict:
    """The merged roster, as two replicas can compare it."""
    return {m: (st.present, st.level, st.caps, st.label, st.history, st.via, st.session,
                st.replaces, st.seniority, st.expires_at) for m, st in sp.roster.items()
            if st.present}


def _is_successor(r: R.Roster, ctx: Ctx, i: bytes) -> bool:
    e = r.log.events[i]
    if e.kind != KIND_SPACE or e.genesis:
        return False
    try:
        key = ctx._key(i)
        body = None if key is None else R.decode_body(e, key)
    except SpecError:
        body = None
    return body is not None and bool(body.changes) and body.changes[0].op == R.SUCCEED


def _successors_after_successors(r: R.Roster, ctx: Ctx, full: World, final) -> list:
    """Successors that have in their past another successor of their key
    that their world opens: not late, and sealed under a state of its world
    (ext-invite-links.md, section 3.3, step 1, and "Across a checkpoint").
    Such a successor is InviteUsed over the whole past, so void at every
    replica whatever checkpoint lies between; a later checkpoint's record
    carries the earlier one as the key's status."""
    succ = [i for i in final if _is_successor(r, ctx, i)]
    out = []
    for i in succ:
        e = r.log.events[i]
        if any(x != i and r.log.events[x].author == e.author and x in r.log.anc[i]
               and full.status[x][1] not in (LATE, "StaleSeal", "Malformed") for x in succ):
            out.append(i)
    return out


def check_history(seed: int, *, checkpoints: bool = True, invites: bool = False,
                  granted: bool = False, persons: bool = False) -> dict:
    """(i) a replica that forgot, holding only what roster.md lets it keep,
    and one that did not agree on every event both hold, on the roster of
    their last world and on its space principals; (ii) the effective
    checkpoints only grow as events arrive, so a replica that forgot early
    and one that forgot late agree; (iii) without a checkpoint the verdicts
    are roster.py's own; (iv) a successor with a successor of its key in its
    past is void, whatever checkpoint lies between; (v) every record reads
    back to its own bytes. With `persons`, two persons' lists add, revoke
    and move devices, their copies published at once or later, and (viii)
    compares each unit's frozen attribution, read with the lists as a
    replica held them then, with the final one."""
    r, ops, snapshots, team = random_history(seed, checkpoints=checkpoints, invites=invites,
                                             granted=granted, persons=persons,
                                             steps=36 + 10 * (invites + granted + persons))
    spaces_ = {team.id: team.resolve()} if team is not None else None
    lists_ = {pid: p.resolve() for pid, p in getattr(r, "people_by_id", {}).items()} or None
    ctx = Ctx(r.log, r.keyring(), lists_, spaces_, objects=getattr(r, "objects", {}))
    final = set(r.log.events)
    full = judge(ctx, final)
    if lists_ is not None:
        # roster.md, "A list at an event's place": a replica that forgot a
        # list's past under its checkpoint places every add as one that kept
        # the list whole, indirect copies outstanding: the same verdicts and
        # attributions for every space event.
        import list_checkpoints as L
        whole, forgot = {}, {}
        for pid, p in r.people_by_id.items():
            lfinal = set(p.log.events)
            wl = L.judge(L.LCtx(p.log), lfinal)
            whole[pid] = wl.list
            if wl.chain:
                fl, fheld = L.forgetting(p.log, wl.chain[-1], lfinal)
                forgot[pid] = L.judge(fl, fheld, wl.chain[-1]).list
                out_lists = True
            else:
                forgot[pid] = wl.list
        if any(whole[pid] is not forgot[pid] for pid in whole):
            a_ = R.Space(r.log, final, whole, spaces_, keys=r.keyring())
            b_ = R.Space(r.log, final, forgot, spaces_, keys=r.keyring())
            for i in final:
                if r.log.events[i].kind != KIND_UNIT:
                    continue
                assert (a_.status.get(i), a_.attribution(i)) == \
                    (b_.status.get(i), b_.attribution(i)), \
                    ("a replica that forgot a list places otherwise", seed, r.name(i),
                     a_.status.get(i), b_.status.get(i))
            r.list_forgetting_compared = sum(1 for i in final
                                             if r.log.events[i].kind == KIND_UNIT)
    out = {"events": len(final), "checkpoints": len(r.checkpoints),
           "effective": len(full.chain), "forgetters": 0, "compared": 0, "late": 0,
           "principals_compared": 0, "rosters_compared": 0, "used_successors": 0,
           "invite_entries": 0, "space_entries": 0}
    out["late"] = sum(1 for v in full.status.values() if v[1] == LATE)
    out["list_forgetting_compared"] = getattr(r, "list_forgetting_compared", 0)
    out["classes"] = {}
    for v in full.status.values():
        name = "valid" if v[0] else v[1]
        out["classes"][name] = out["classes"].get(name, 0) + 1
    out["validity"] = {}
    for c in r.checkpoints:
        v = checkpoint_validity(ctx, c)[1]
        out["validity"][v] = out["validity"].get(v, 0) + 1
        rec = ctx.record(c)
        if isinstance(rec, dict):
            plain = R.encode_record(rec)
            assert R.encode_record(R.read_record(plain)) == plain, ("(v)", seed)
            out["invite_entries"] += sum(1 for m in rec["members"] if m["member"][0] == R.INVITE)
            out["space_entries"] += sum(1 for m in rec["members"]
                                        if m["member"][0] == R.SPACE and m["notices"])
    out["ops"] = {}
    for o in ops:
        out["ops"][o[0]] = out["ops"].get(o[0], 0) + 1
    # (vi) The backdated checkpoint: one by attackers junior to a victim
    # never takes effect; and no checkpoint in effect drops an administrator
    # that its past lowered only by members junior to it unless that
    # administrator voted for it or a senior member or a recovery member
    # excused it (roster.md, "Votes and effect").
    out["attacks"] = {}
    for a in getattr(r, "attacks", ()):
        name = f"{a['mode']}, {a.get('standing', 'senior')}"
        c = a["checkpoint"]
        won = c in full.chain
        if won and a["junior"]:
            # Only a heard victim's own vote, or its excuse (it forked, say),
            # lets it through: an unfenced event a dishonest step of the
            # builder made it sign.
            after = {x for x in final if x == c or ctx.follows(x, c)}
            victims = {r.hist.device(v) for v in a["victims"]}
            ok = votes(ctx, c, after) | excused(ctx, c, world_space(ctx, c, after),
                                                heard(ctx, c))
            assert victims & ok, \
                ("(vi) a junior's backdated checkpoint took effect", seed, r.name(c))
            name += ", a victim voted or was excused"
        row = out["attacks"].setdefault(name, [0, 0])
        row[0] += 1
        row[1] += won
    # (vii) No valid roster event lowers an administrator of a higher rank
    # than its author's, at its place (roster.md, section 3.6): in the
    # resolution without checkpoints and in the last world.
    out["lowerings_checked"] = 0
    plain_sp = R.Space(r.log, final, lists_, spaces_, keys=r.keyring())
    for sp_ in (plain_sp, full.space):
        for i in sp_.view:
            if not sp_.is_roster(i) or i not in sp_.valid_roster or i == sp_.log.genesis:
                continue
            S = sp_.state(sp_.place(i, sp_.valid_roster))
            by = S.get((R.DEVICE, sp_.ev(i).author))
            for d, st, _ in _lowers(sp_, i):
                assert by is not None and (by.rank or 0) >= (st.rank or 0), \
                    ("(vii) a lower rank lowered a higher one", seed, r.name(i))
                out["lowerings_checked"] += 1
    out["heard_checked"] = 0
    for c in full.chain:
        held_after = {x for x in final if x == c or ctx.follows(x, c)}
        sp = past_space(ctx, c)
        root = sp.log.genesis
        lowered: dict = {}
        for i in sp.view:
            if i == root or not sp.is_roster(i) or i not in sp.valid_roster:
                continue
            S = sp.state(sp.place(i, sp.valid_roster))
            by = S.get((R.DEVICE, sp.ev(i).author))
            for d, st, _ in _lowers(sp, i):
                back = any(i in sp.log.anc[j] and j in sp.valid_roster and any(
                    ch.member == (R.DEVICE, d) and ch.level == R.ADMINISTER
                    for ch in sp.changes(j)) for j in sp.view if sp.is_roster(j))
                if not back:
                    lowered.setdefault(d, []).append(
                        sp.ev(i).author == d or (by is not None and _key(by.rank, by.seniority)
                                                 < _key(st.rank, st.seniority)))
        rec = ctx.record(c)
        kept = {m["member"][1] for m in rec["members"] if m["member"][0] == R.DEVICE
                and m["level"] == R.ADMINISTER and (R.DORMANT, R.EXTENDS) not in m["caps"]}
        winners = {d for d, how in lowered.items() if not any(how) and d not in kept}
        if winners:
            named = {**{d: None for d in kept}, **heard(ctx, c)}
            w = world_space(ctx, c, held_after)
            ok = votes(ctx, c, held_after) | excused(ctx, c, w, heard(ctx, c))
            assert winners <= ok, ("(vi) a heard member neither voted nor was excused", seed,
                                   r.name(c))
            out["heard_checked"] += len(winners)
    if not checkpoints or not r.checkpoints:
        plain = R.Space(r.log, final, lists_, spaces_, keys=r.keyring())
        assert dict(plain.status) == full.status, ("(iii) differs", seed)
        out["plain"] = True
    for i in _successors_after_successors(r, ctx, full, final):
        assert not full.status[i][0], ("(iv) a used invite key claimed again", seed, r.name(i))
        out["used_successors"] += 1
    # The object form: a replica that lacks some checkpoints' record
    # objects judges as one that never received them nor what follows them;
    # once the objects arrive (late), it judges as the full replica.
    out["missing_objects"] = 0
    if r.checkpoints:
        rng = random.Random(seed * 7919)
        missing = {c for c in sorted(r.checkpoints) if rng.random() < 0.5}
        if missing:
            objs = {loc: data for loc, data in r.objects.items()
                    if not any(ctx.checkpoint(c).part["locator"] == loc for c in missing)}
            lctx = Ctx(r.log, r.keyring(), lists_, spaces_, objects=objs)
            lw = judge(lctx, final)
            removed = set(missing)
            for i in final:
                if r.log.anc[i] & missing:
                    removed.add(i)
            ref = judge(Ctx(r.log, r.keyring(), lists_, spaces_, objects=r.objects),
                        final - removed)
            # A held event's keys still count as a source (roster.md, "An
            # author's keys"), so the replica may verify an event that one
            # which never received them holds as NoHybridKey.
            # Its signatures still count as evidence of a fork (events.md).
            # One it drops for want of a record naming its author (Dropped)
            # is the same case.
            bad = [i for i in final - removed if lw.status[i] != ref.status[i]
                   and ref.status[i][1] not in HELD + ("Dropped",)
                   and lw.status[i][1] != "Forked"]
            assert not bad, ("a replica missing a record object decides otherwise", seed,
                             [(r.name(i), lw.status[i], ref.status[i]) for i in bad])
            # What follows an unreadable checkpoint is held, unless a checkpoint
            # in effect makes it late, which needs no record.
            # A class read from the visible part alone needs no record, and
            # an anchor or unit whose author's keys it lacks is dropped
            # (roster.md, "Strangers' events") whatever it follows.
            assert all(lw.status[i][1] in HELD + ("Malformed", "StaleSeal", "Dropped")
                       for i in removed), seed
            out["missing_objects"] = len(missing)
    # (ii): along every device's views in the order they were reached, the
    # effective chain only grows, and ends as the final one's prefix. (i):
    # a replica that forgot under each checkpoint some view had in effect.
    bases = []
    frozen_at: dict = {}
    out["disjoint"] = 0
    for snap in snapshots:
        for name, view in sorted(snap.items()):
            if not view or not r.log.closed(view):
                continue
            w = judge(ctx, view)
            # Stability is monotone: a checkpoint stable over this view is
            # stable over the final one (roster.md, "Votes and effect").
            for c in w.chain:
                assert stable(ctx, c, {x for x in final if x == c or ctx.follows(x, c)} | {c}), \
                    ("a checkpoint leaves stability as events arrive", seed, r.name(c))
                out["stable_monotone"] = out.get("stable_monotone", 0) + 1
            if w.chain and full.chain[:len(w.chain)] != w.chain:
                # Only two electorates with no device in common let a
                # chain be overtaken: the view's chain and the final one
                # part at concurrent checkpoints that are both stable.
                n = next(j for j, (a, b) in enumerate(zip(w.chain, full.chain)) if a != b) \
                    if any(a != b for a, b in zip(w.chain, full.chain)) else len(full.chain)
                assert n < len(full.chain) and full.chain[n] < w.chain[n] and _disjoint(
                    ctx, full.chain[n], w.chain[n], final), \
                    ("(ii) a chain that later replicas do not extend", seed, name)
                out["disjoint"] += 1
            if w.chain and w.chain[-1] not in bases:
                bases.append(w.chain[-1])
                # What a replica that forgot under it now freezes: each
                # kept unit's verdict and its author's context at its place.
                # With persons, the lists as this replica held them then:
                # the list events the copies in its view carry.
                vctx = ctx if lists_ is None else Ctx(
                    r.log, r.keyring(), lists_then(r, view), spaces_,
                    objects=getattr(r, "objects", {}))
                frozen_at[w.chain[-1]] = (tuple(w.chain), frozen_outcomes(vctx, w, view))
    # (viii) units.md, "The past of a kept checkpoint": what a replica froze
    # when it forgot is what one that kept everything shows for good, the
    # author's standing at the checkpoint notwithstanding.
    final_frozen = frozen_outcomes(ctx, full, final)
    out["units_frozen"] = out["standing_changed"] = 0
    for base, (chain_then, frozen) in frozen_at.items():
        if list(chain_then) != full.chain[:len(chain_then)]:
            continue
        for u, outcome in frozen.items():
            assert final_frozen.get(u, outcome) == outcome, \
                ("(viii) a frozen content outcome changed", seed, r.name(u), outcome,
                 final_frozen.get(u))
            # Keys 7 and 8 are never both: a unit the write rule admits is
            # attributed, one it voids carries what voids it.
            assert outcome[2] is None or (outcome[3] == () and outcome[2]), \
                ("(viii) a frozen unit attributed and voided", seed, r.name(u), outcome)
            out["units_frozen"] += 1
            out["attributed"] = out.get("attributed", 0) + (outcome[2] is not None)
            out["standing_changed"] += outcome[1] != standing_at_root(ctx, base, u)
    for base in bases:
        fctx, held = forget(ctx, base, final)
        forgot = judge(fctx, held, base)
        diff = comparable(full, forgot, held)
        if rival_checkpoints(fctx, held, base):
            # A stable rival it cannot judge (a disjoint split, or a rival
            # every voter of which is dishonest): what it cannot judge it
            # holds pending, and it never decides otherwise.
            assert all(b[1] == "Pending" for i, a, b in diff), \
                ("(i) a replica that forgot under an overtaken checkpoint decides", seed,
                 [(r.name(i), a, b) for i, a, b in diff if b[1] != "Pending"])
            out["rival_pending"] = out.get("rival_pending", 0) + 1
            continue
        assert base in full.chain, ("(i) overtaken without a rival", seed, r.name(base))
        assert not diff, ("(i) a forgetting replica disagrees", seed, r.name(base),
                          [(r.name(i), a, b) for i, a, b in diff])
        assert forgot.chain == full.chain[full.chain.index(base):], ("(i) chains", seed)
        assert _roster_view(forgot.space) == _roster_view(full.space), ("(i) rosters", seed)
        out["rosters_compared"] += 1
        if team is not None:
            assert forgot.space.principals() == full.space.principals(), \
                ("(i) principals", seed, r.name(base))
            out["principals_compared"] += 1
        out["forgetters"] += 1
        out["compared"] += len(held)
    return out


def model_check(seeds, *, quiet: bool = False) -> dict:
    """Seeds whose number is 0 mod 4 build no checkpoint; odd seeds add
    invite links; seeds 1 and 2 mod 3 add a granted space."""
    total = {"histories": 0, "events": 0, "checkpoints": 0, "effective": 0, "forgetters": 0,
             "compared": 0, "late": 0, "plain": 0, "classes": {}, "validity": {}, "ops": {},
             "longest_chain": 0, "with_invites": 0, "with_granted": 0}
    for seed in seeds:
        invites, granted = seed % 2 == 1, seed % 3 != 0
        res = check_history(seed, checkpoints=seed % 4 != 0, invites=invites, granted=granted)
        total["histories"] += 1
        total["with_invites"] += invites
        total["with_granted"] += granted
        for k in ("events", "checkpoints", "effective", "forgetters", "compared", "late",
                  "missing_objects", "principals_compared", "rosters_compared",
                  "used_successors", "invite_entries", "space_entries", "disjoint",
                  "rival_pending", "heard_checked", "lowerings_checked"):
            total[k] = total.get(k, 0) + res.get(k, 0)
        total["plain"] += 1 if res.get("plain") else 0
        total["longest_chain"] = max(total["longest_chain"], res["effective"])
        for key in ("classes", "validity", "ops"):
            for name, n in res[key].items():
                total[key][name] = total[key].get(name, 0) + n
        for name, (n, won) in res["attacks"].items():
            row = total.setdefault("attacks", {}).setdefault(name, [0, 0])
            row[0] += n
            row[1] += won
        if not quiet:
            print(seed, res, file=sys.stderr)
    return total


# ---------------------------------------------------------------------------
# Self-test and vectors.


def _scenario(prefix: str):
    """Founder P and administrator A; writer W. A checkpoint by P, A's vote,
    a removal after it, and an offline A' branch that the checkpoint makes
    late."""
    r = R.Roster("P", prefix)
    attach(r)
    r.grant("P", "A", R.ADMINISTER)
    r.grant("P", "W", R.WRITE)
    r.sync("P", "A", "W")
    late = r.grant("A", "X", R.WRITE, label="A grants X, offline")  # A has not seen the checkpoint
    cp = make_checkpoint(r, "P", "P checkpoints")
    r.sync("P", "W")
    u = r.unit("W", "W writes after the checkpoint")
    r.sync("P", "A")
    vote = r.anchor("A", "A votes")
    r.sync("P", "A", "W")
    rem = r.remove("P", "W", "P removes W")
    r.sync(*r.everyone())
    return r, {"late": late, "checkpoint": cp, "unit": u, "vote": vote, "remove": rem}


def _freeze(prefix: str):
    """A roster part of a type this replica does not know (3), signed by an
    administrator, while the founder grants W concurrently: both are held,
    and so is everything outside the unknown event's past."""
    r = R.Roster("P", prefix)
    r.grant("P", "A", R.ADMINISTER)
    r.sync("P", "A")
    unknown = r.space_event("A", "A signs a roster part of type 3", R.cbor({0: 3}), False)
    concurrent = r.grant("P", "W", R.WRITE, label="P grants W, concurrently")
    r.sync("P", "A")
    after = r.unit("P", "P writes after both")
    return r, {"unknown": unknown, "concurrent": concurrent, "after": after}


def _raced_scenario(prefix: str):
    """ext-invite-links.md, "Across a checkpoint": P invites K; Bob's claim
    s1 and Mallory's s2, on the same view, race, so both are void; P's
    checkpoint holds both in its past, and A votes. After it, K signs s3, as
    Mallory would to claim the link again: it is InviteUsed, as over the
    whole past, and the record shows K raced. P then revokes K."""
    r = R.Roster("P", prefix)
    attach(r)
    r.grant("P", "A", R.ADMINISTER)
    r.sync("P", "A")
    r.act("P", [R._invite_grant(r, "K", history=R.FROM_NOW_ON, level=R.WRITE, claims=R.DEVICE)],
          "P invites K")
    r.sync("P", "K")
    view = set(r.hist.view["K"])
    s1 = _claim_by(r, "K", "Bob", "K claims for Bob (s1)")
    after_s1 = set(r.hist.view["K"])
    r.hist.view["K"] = set(view)
    s2 = _claim_by(r, "K", "Mallory", "K claims for Mallory (s2), concurrently")
    r.hist.view["K"] |= after_s1
    r.sync("P", "A", "K")
    cp = make_checkpoint(r, "P", "P checkpoints")
    r.sync("P", "A")
    vote = r.anchor("A", "A votes")
    r.sync("P", "A", "K")
    s3 = _claim_by(r, "K", "Mallory", "K claims for Mallory again after the checkpoint (s3)")
    r.sync("P", "K")
    revoke = r.act("P", [R.Change(R.REMOVE, (R.INVITE, r.hist.device("K")))], "P revokes K")
    r.sync(*r.everyone())
    return r, {"s1": s1, "s2": s2, "checkpoint": cp, "vote": vote, "s3": s3, "revoke": revoke}


def _granted_scenario(prefix: str):
    """roster.md, "Other logs and extensions": the space grants team T with a
    notice; T admits t2 "from now on", and T0 responds with a "from now on"
    notice, a floor. P checkpoints, A votes: in the checkpoint's world T's
    principal is the past's, and the record keeps the notice, the floor and
    the team's events the responses named."""
    team = R.Roster("T0", f"{prefix}/team", grant_keys=True)
    team.grant("T0", "t1", R.WRITE)
    team.sync("T0", "t1")
    r = R.Roster("P", prefix, keys={n: team.hist.seed(n) for n in ("T0", "t1")})
    attach(r)
    r.spaces[team.id] = "team T"
    r.spaces_for_checkpoints = lambda: {team.id: team.resolve(team.hist.view["T0"])}
    r.grant("P", "A", R.ADMINISTER)
    r.grant("P", "team T", R.WRITE, label="P grants team T", notices=[team.notice(team.genesis)])
    r.sync("P", "A", "T0", "t1")
    g = team.grant("T0", "t2", R.WRITE, R.FROM_NOW_ON, label="T0 admits t2 from now on")
    response = r.heal("T0", "T0 responds to the team's break", refs=[(team.id, g)],
                      notices=[team.notice(g, from_now_on=True)],
                      flags={"grant_rotation": True, "break": True})
    r.sync("P", "A", "T0")
    cp = make_checkpoint(r, "P", "P checkpoints")
    r.sync("P", "A")
    vote = r.anchor("A", "A votes")
    r.sync("P", "A", "t1", "T0")
    unit = r.unit("t1", "t1 writes through the team after the checkpoint")
    r.sync(*r.everyone())
    return r, team, {"break": g, "response": response, "checkpoint": cp, "vote": vote,
                     "unit": unit}


def _stale_predecessor(prefix: str):
    """A checkpoint whose predecessor a replica forgot (roster.md, "A
    checkpoint's validity"): P checkpoints K1, A votes; P checkpoints K2
    naming K1, A votes, so K2 takes effect. Then A, and P, each sign a
    checkpoint naming K1 as predecessor although their cuts reach K2: X and
    Y. Both are CheckpointPending at a replica that kept everything and at
    one that kept K2 and holds K1 as an envelope alone."""
    r = R.Roster("P", prefix)
    attach(r)
    r.grant("P", "A", R.ADMINISTER)
    r.sync("P", "A")
    k1 = make_checkpoint(r, "P", "P checkpoints (K1)")
    r.sync("P", "A")
    r.anchor("A", "A votes for K1")
    r.sync("P", "A")
    k2 = make_checkpoint(r, "P", "P checkpoints again (K2)")
    r.sync("P", "A")
    v2 = r.anchor("A", "A votes for K2")
    r.sync("P", "A")
    x = make_checkpoint(r, "A", "A checkpoints naming K1 (X)", previous=k1)
    y = make_checkpoint(r, "P", "P checkpoints naming K1 (Y)", previous=k1)
    r.sync(*r.everyone())
    after = r.anchor("A", "A writes after all")
    r.sync(*r.everyone())
    return r, {"K1": k1, "K2": k2, "vote": v2, "X": x, "Y": y, "after": after}


def _backdated_scenario(prefix: str):
    """roster.md, "Votes and effect", not by its author: P removes A. A,
    on a view before its removal, checkpoints (X), then removes P after X.
    A's removal of P excuses no one from X, since A is X's author, so X
    waits for P's vote and never takes effect, and P's removal of A
    stands."""
    r = R.Roster("P", prefix)
    attach(r)
    r.grant("P", "A", R.ADMINISTER)
    r.sync("P", "A")
    old = set(r.hist.view["A"])
    removal = r.remove("P", "A", "P removes A")
    r.hist.view["A"] = old
    x = make_checkpoint(r, "A", "A checkpoints on its old view (X)")
    counter = r.remove("A", "P", "A removes P after X")
    r.sync(*r.everyone())
    ctx = Ctx(r.log, r.keyring(), objects=r.objects)
    full = judge(ctx, set(r.log.events))
    assert checkpoint_validity(ctx, x)[0] and full.chain == [], [r.name(c) for c in full.chain]
    assert waiting_for(ctx, x, set(r.log.events)) == [r.hist.device("P")]
    assert full.status[removal][0], full.status[removal]
    return {"r": r, "ev": {"removal": removal, "X": x, "counter": counter}, "full": full,
            "ctx": ctx}


def _disjoint_scenario(prefix: str, recovery: bool = True):
    """roster.md, "Votes and effect": two groups of administrators with no
    device in common. P founds the space and grants Q, A and B administer,
    and, with `recovery`, R administer marked frasil.dormant, the space
    recovery member. P and Q see only each other, as do A, B and R. P
    checkpoints c1 and Q removes A and B after it, excusing both, being
    senior to them; A checkpoints c2 and B removes P and Q after it, which
    excuses neither, B being junior to both. With R, R removes P and Q after
    c2 too, and excuses both: a recovery member excuses anyone. So c2 takes
    effect in its group's view only with R. Once the groups meet, a replica
    that kept everything puts the smaller ID in effect; one that forgot
    under the other holds it as a rival, and every event it holds pending."""
    r = R.Roster("P", prefix)
    attach(r)
    for who in ("Q", "A", "B"):
        r.grant("P", who, R.ADMINISTER)
    if recovery:
        r.grant("P", "R", R.ADMINISTER, caps=((R.DORMANT, R.EXTENDS),),
                label="P grants R administer, dormant: the recovery member")
    group = ("A", "B", "R") if recovery else ("A", "B")
    r.sync("P", "Q", *group)
    c1 = make_checkpoint(r, "P", "P checkpoints (c1)")
    c2 = make_checkpoint(r, "A", "A checkpoints concurrently (c2)")
    r.sync("P", "Q")
    r.sync(*group)
    qa = r.remove("Q", "A", "Q removes A after c1")
    qb = r.remove("Q", "B", "Q removes B after c1")
    bp = r.remove("B", "P", "B removes P after c2")
    bq = r.remove("B", "Q", "B removes Q after c2")
    if recovery:
        r.sync(*group)
        r.remove("R", "P", "R, the recovery member, removes P after c2")
        r.sync(*group)
        r.remove("R", "Q", "R removes Q after c2")
    r.sync(*group)
    group1, group2 = set(r.hist.view["Q"]), set(r.hist.view["B"])
    r.sync(*r.everyone())
    after = r.anchor("P", "P writes once the groups meet")
    return r, {"c1": c1, "c2": c2, "qa": qa, "qb": qb, "bp": bp, "bq": bq, "after": after,
               "group1": group1, "group2": group2}


def _disjoint_checks(prefix: str) -> dict:
    # Without a recovery member, B, junior to P and Q, excuses neither:
    # c2 waits for both for good, and no chain ever moves.
    q, qev = _disjoint_scenario(f"{prefix}/no-recovery", recovery=False)
    qctx = Ctx(q.log, q.keyring(), objects=q.objects)
    assert judge(qctx, qev["group2"]).chain == []
    assert sorted(waiting_for(qctx, qev["c2"], set(q.log.events))) == sorted(
        [q.hist.device("P"), q.hist.device("Q")])
    assert judge(qctx, set(q.log.events)).chain == [qev["c1"]]
    r, ev = _disjoint_scenario(prefix)
    ctx = Ctx(r.log, r.keyring(), objects=r.objects)
    final = set(r.log.events)
    g1, g2 = judge(ctx, ev["group1"]), judge(ctx, ev["group2"])
    assert g1.chain == [ev["c1"]] and g2.chain == [ev["c2"]], (g1.chain, g2.chain)
    full = judge(ctx, final)
    win, lose = sorted((ev["c1"], ev["c2"]))
    assert full.chain == [win]
    assert full.status[lose][1] == LATE
    fctx, held = forget(ctx, lose, final)
    forgot = judge(fctx, held, lose)
    assert rival_checkpoints(fctx, held, lose) == {win}
    assert all(forgot.status[i][1] == "Pending" for i in held)
    wctx, wheld = forget(ctx, win, final)
    wforgot = judge(wctx, wheld, win)
    assert not comparable(full, wforgot, wheld)
    return {"r": r, "ev": ev, "full": full, "win": win, "lose": lose, "held": held,
            "forgot": forgot, "wheld": wheld, "wforgot": wforgot, "plain": (q, qev)}


def _guests_and_restricted(prefix: str) -> dict:
    """roster.md, "Other logs and extensions", guests and restricted spaces,
    and section 3.15.2, step 6:

    - P grants guest G write with a session and `expires_at`, checkpoints,
      and A votes: the record keeps G's session and `expires_at`; G writes
      after the checkpoint, and P then ends G's session by removing it.
    - A restricted space F checkpoints, as no grant rotation, and its
      administrator votes.
    - Refused checkpoints: one by the guest, which propagates nowhere and
      administers nothing (NotAnAdministrator, before keys.md's checks);
      one in P's space that is no grant rotation (GrantKeyRequired); one in
      F that is a grant rotation (GrantKeyNotAllowed)."""
    import dataclasses
    import spaces
    r = R.Roster("P", f"{prefix}/guest")
    attach(r)
    r.grant("P", "A", R.ADMINISTER)
    g = dataclasses.replace(r.device_grant("G", R.WRITE, session=example(f"{prefix}/session")[:16]),
                            expires_at=2_000_000_000)
    r.act("P", [g], "P grants guest G write until 2033")
    r.sync("P", "A", "G")
    cp = make_checkpoint(r, "P", "P checkpoints")
    r.sync("P", "A", "G")
    vote = r.anchor("A", "A votes")
    r.sync("P", "A", "G")
    unit = r.unit("G", "G writes after the checkpoint")
    r.sync("P", "G")
    end = r.remove("P", "G", "P ends G's session")
    r.sync(*r.everyone())
    ctx = Ctx(r.log, r.keyring(), objects=r.objects)
    full = judge(ctx, set(r.log.events))
    assert full.chain == [cp], [r.name(c) for c in full.chain]
    entry = next(m for m in ctx.record(cp)["members"] if m["member"] == (R.DEVICE, r.hist.device("G")))
    assert entry["session"] is not None and entry["expires_at"] == 2_000_000_000
    assert full.status[unit][0] and full.status[end][0]
    fctx, held = forget(ctx, cp, set(r.log.events))
    forgot = judge(fctx, held, cp)
    assert not comparable(full, forgot, held)
    assert _roster_view(forgot.space) == _roster_view(full.space)

    # The refused ones, each on its own branch of another space.
    q = R.Roster("P", f"{prefix}/refused")
    attach(q)
    q.grant("P", "A", R.ADMINISTER)
    h = dataclasses.replace(q.device_grant("H", R.WRITE, session=example(f"{prefix}/h")[:16]),
                            expires_at=2_000_000_000)
    q.act("P", [h], "P grants guest H write until 2033")
    q.sync("P", "A", "H")
    guest_cp = make_checkpoint(q, "H", "H, a guest, checkpoints")
    no_grant = make_checkpoint(q, "A", "A checkpoints, no grant rotation", grant_rotation=False)
    qctx = Ctx(q.log, q.keyring(), objects=q.objects)
    assert checkpoint_validity(qctx, guest_cp)[1] == "NotAnAdministrator"
    assert checkpoint_validity(qctx, no_grant)[1] == "GrantKeyRequired"

    f = R.Roster("F", f"{prefix}/restricted", descriptor=spaces.encode_descriptor(
        spaces.KIND_RESTRICTED, example(f"{prefix}/parent")))
    attach(f)
    f.grant("F", "B", R.ADMINISTER)
    f.sync("F", "B")
    granting = make_checkpoint(f, "B", "B checkpoints F as a grant rotation", grant_rotation=True)
    f.hist.view["B"].discard(granting)
    fcp = make_checkpoint(f, "F", "F checkpoints")
    f.sync("F", "B")
    fvote = f.anchor("B", "B votes")
    f.sync("F", "B")
    fctx_ = Ctx(f.log, f.keyring(), objects=f.objects)
    ffull = judge(fctx_, set(f.log.events))
    assert ffull.chain == [fcp], [f.name(c) for c in ffull.chain]
    assert checkpoint_validity(fctx_, granting)[1] == "GrantKeyNotAllowed"
    f2, fheld = forget(fctx_, fcp, set(f.log.events))
    fforgot = judge(f2, fheld, fcp)
    assert not comparable(ffull, fforgot, fheld)
    return {"guest": {"r": r, "full": full, "forgot": forgot, "held": held,
                      "checkpoint": cp, "ctx": ctx},
            "refused": {"r": q, "ctx": qctx, "ids": [guest_cp, no_grant]},
            "restricted": {"r": f, "full": ffull, "forgot": fforgot, "held": fheld,
                           "checkpoint": fcp, "refused": [granting], "ctx": fctx_,
                           "vote": fvote}}


def _granted_checkpoint_scenario(prefix: str):
    """roster.md, "Other logs and extensions", a granted space checkpoints:
    P's space grants team T; T0 checkpoints T (cT), t1 votes, so cT takes
    effect in T. cT is a grant rotation of T, a change for P's space, and
    T0 responds there by delivery: a key event whose refs name cT and that
    notices (T, cT). P then checkpoints its own space and A votes."""
    team = R.Roster("T0", f"{prefix}/team", grant_keys=True)
    attach(team)
    team.grant("T0", "t1", R.WRITE)
    team.sync("T0", "t1")
    r = R.Roster("P", prefix, keys={n: team.hist.seed(n) for n in ("T0", "t1")})
    attach(r)
    r.spaces[team.id] = "team T"
    r.grant("P", "A", R.ADMINISTER)
    r.grant("P", "team T", R.WRITE, label="P grants team T", notices=[team.notice(team.genesis)])
    r.sync("P", "A", "T0", "t1")
    ct = make_checkpoint(team, "T0", "T0 checkpoints the team (cT)")
    team.sync("T0", "t1")
    tvote = team.anchor("t1", "t1 votes for cT")
    team.sync("T0", "t1")
    response = r.heal("T0", "T0 responds to the team's checkpoint", refs=[(team.id, ct)],
                      notices=[team.notice(ct)])
    r.spaces_for_checkpoints = lambda: {team.id: judge(
        Ctx(team.log, team.keyring(), objects=team.objects), set(team.log.events)).space}
    r.sync("P", "A", "T0")
    cp = make_checkpoint(r, "P", "P checkpoints")
    r.sync("P", "A")
    vote = r.anchor("A", "A votes")
    r.sync("P", "A", "t1", "T0")
    unit = r.unit("t1", "t1 writes through the team after both checkpoints")
    r.sync(*r.everyone())
    return r, team, {"cT": ct, "team_vote": tvote, "response": response, "checkpoint": cp,
                     "vote": vote, "unit": unit}


def _granted_checkpoint_checks(prefix: str) -> dict:
    """The team's checkpoint seen by a replica of P's space that holds the
    team whole and by one that holds only the team's world after cT, each
    with P's space whole or forgotten under P's checkpoint: the response's
    principal (T, cT) is in force at all four, and their verdicts agree."""
    r, team, ev = _granted_checkpoint_scenario(prefix)
    tctx = Ctx(team.log, team.keyring(), objects=team.objects)
    tfull = judge(tctx, set(team.log.events))
    assert tfull.chain == [ev["cT"]], [team.name(c) for c in tfull.chain]
    tf, theld = forget(tctx, ev["cT"], set(team.log.events))
    tforgot = judge(tf, theld, ev["cT"])
    out = {}
    for tname, tsp in (("team whole", tfull.space), ("team forgotten", tforgot.space)):
        spaces_ = {team.id: tsp}
        ctx = Ctx(r.log, r.keyring(), None, spaces_, objects=r.objects)
        full = judge(ctx, set(r.log.events))
        assert full.chain == [ev["checkpoint"]], [r.name(c) for c in full.chain]
        assert full.space.principals() == [(team.id, ev["cT"])], full.space.principals()
        assert full.status[ev["response"]][0] and full.status[ev["unit"]][0]
        fctx, held = forget(ctx, ev["checkpoint"], set(r.log.events))
        forgot = judge(fctx, held, ev["checkpoint"])
        assert not comparable(full, forgot, held)
        assert forgot.space.principals() == full.space.principals()
        out[tname] = {"full": full, "forgot": forgot, "held": held}
    assert {i: v for i, v in out["team whole"]["full"].status.items()} == \
        {i: v for i, v in out["team forgotten"]["full"].status.items()}
    return {"r": r, "team": team, "ev": ev, "tfull": tfull, "tforgot": tforgot,
            "theld": theld, **out}


def _scenario_checks(prefix: str) -> dict:
    """Runs the raced and granted scenarios at a replica that kept everything
    and one that forgot; returns what the vectors show."""
    r, ev = _raced_scenario(f"{prefix}/raced")
    ctx = Ctx(r.log, r.keyring(), objects=r.objects)
    full = judge(ctx, set(r.log.events))
    assert full.chain == [ev["checkpoint"]], [r.name(c) for c in full.chain]
    assert full.status[ev["s1"]][1] == "ClaimRaced" and full.status[ev["s2"]][1] == "ClaimRaced"
    assert full.status[ev["s3"]][1] == "InviteUsed", full.status[ev["s3"]]
    assert full.status[ev["revoke"]][0], full.status[ev["revoke"]]
    k = r.hist.device("K")
    entry = next(m for m in ctx.record(ev["checkpoint"])["members"] if m["member"] == (R.INVITE, k))
    assert entry["invite"] == R.INVITE_RACED and entry["expires_at"] is not None
    fctx, held = forget(ctx, ev["checkpoint"], set(r.log.events))
    forgot = judge(fctx, held, ev["checkpoint"])
    assert not comparable(full, forgot, held)
    raced = {"r": r, "ev": ev, "full": full, "held": held, "forgot": forgot, "ctx": ctx}

    r, team, ev = _granted_scenario(f"{prefix}/granted")
    spaces_ = {team.id: team.resolve()}
    ctx = Ctx(r.log, r.keyring(), None, spaces_, objects=r.objects)
    full = judge(ctx, set(r.log.events))
    assert full.chain == [ev["checkpoint"]], [r.name(c) for c in full.chain]
    plain = R.Space(r.log, r.log.anc[ev["checkpoint"]], None, spaces_, r.keyring())
    assert full.space.principals() == plain.principals() == [(team.id, ev["break"])], \
        (full.space.principals(), plain.principals())
    entry = next(m for m in ctx.record(ev["checkpoint"])["members"]
                 if m["member"] == (R.SPACE, team.id))
    assert entry["floor"] and entry["named"] == (ev["break"],)
    assert [n[0] for n in entry["notices"]] == [ev["break"]] and entry["notices"][0][2] == 1
    assert full.status[ev["unit"]][0], full.status[ev["unit"]]
    fctx, held = forget(ctx, ev["checkpoint"], set(r.log.events))
    forgot = judge(fctx, held, ev["checkpoint"])
    assert not comparable(full, forgot, held)
    assert forgot.space.principals() == full.space.principals()
    granted = {"r": r, "team": team, "ev": ev, "full": full, "held": held, "forgot": forgot,
               "ctx": ctx}
    return {"raced": raced, "granted": granted}


def _record_refusals(plain_devices: bytes, plain_space: bytes, plain_invite: bytes) -> list:
    """Records that do not read (roster.md, "The checkpoint record"), each
    from a record that does, with one thing changed, and the class."""
    from primitives import ed25519_valid

    def edit(plain, change):
        value = R.uncbor(plain)
        change(value)
        return R.cbor(value)

    def member(value, mtype, n=0):
        return [m for m in value[R.R_MEMBERS] if m[R.M_MEMBER][0] == mtype][n]

    bad_ed = next(bytes([b]) + bytes(31) for b in range(256)
                  if not ed25519_valid(bytes([b]) + bytes(31)))
    cases = [
        ("a version other than 1", plain_devices,
         lambda v: v.__setitem__(R.R_VERSION, 2), "UnsupportedVersion"),
        ("a device member without its X-Wing key", plain_devices,
         lambda v: member(v, R.DEVICE).pop(R.M_XWING), "Malformed"),
        ("a space member with a device's key", plain_space,
         lambda v: member(v, R.SPACE).__setitem__(R.M_MLDSA, member(v, R.DEVICE)[R.M_MLDSA]),
         "Malformed"),
        ("a slot whose pseudonym is neither 32 nor 0 bytes", plain_devices,
         lambda v: member(v, R.DEVICE).__setitem__(R.M_SLOT, [bytes(32), 0, bytes(32), bytes(5)]),
         "Malformed"),
        ("an invite key's status 4", plain_invite,
         lambda v: member(v, R.INVITE).__setitem__(R.M_INVITE, 4), "Malformed"),
        ("an invite key without expires_at", plain_invite,
         lambda v: member(v, R.INVITE).pop(R.M_EXPIRES), "Malformed"),
        ("a floor of 2", plain_space,
         lambda v: member(v, R.SPACE).__setitem__(R.M_FLOOR, 2), "Malformed"),
        ("an invalid Ed25519 key", plain_devices,
         lambda v: member(v, R.DEVICE).__setitem__(R.M_ED25519, bad_ed), "InvalidKey"),
        ("keys of another device", plain_devices,
         lambda v: member(v, R.DEVICE).__setitem__(
             R.M_ED25519, member(v, R.DEVICE, 1)[R.M_ED25519]), "NotCommitted"),
        # Reserved for later documents: held at an implementation that lacks
        # them, before anything else of the record is read.
        ("a record key 9", plain_devices,
         lambda v: v.__setitem__(R.RESERVED_RECORD_KEY, 0), "ExtensionRequired"),
        ("a member-entry key 22", plain_devices,
         lambda v: member(v, R.DEVICE).__setitem__(R.RESERVED_MEMBER_KEY, 0),
         "ExtensionRequired"),
        ("a member of type 4", plain_devices,
         lambda v: member(v, R.DEVICE).__setitem__(
             R.M_MEMBER, [R.RESERVED_MEMBER_TYPE, member(v, R.DEVICE)[R.M_MEMBER][1]]),
         "ExtensionRequired"),
        ("a record key 9 beside a malformed member entry", plain_devices,
         lambda v: (v.__setitem__(R.RESERVED_RECORD_KEY, 0),
                    member(v, R.DEVICE).pop(R.M_XWING)), "ExtensionRequired"),
    ]
    # Faults far apart, which a reader that reads the record as it streams
    # meets in the other order than the steps: the earlier step stands
    # wherever it lies (roster.md, "Reading it as it streams").
    SENTINEL = 0x01234567

    def non_minimal_last_tip(value):
        value[R.R_TIPS][-1][1] = SENTINEL

    def devices(value):
        return [m for m in value[R.R_MEMBERS] if m[R.M_MEMBER][0] == R.DEVICE]

    def reserved_first_non_minimal_last(value):
        value[R.R_MEMBERS][0][R.RESERVED_MEMBER_KEY] = 0
        non_minimal_last_tip(value)

    def widen(data):
        short = b"\x1a" + SENTINEL.to_bytes(4, "big")
        assert data.count(short) == 1
        return data.replace(short, b"\x1b" + SENTINEL.to_bytes(8, "big"))
    far = [
        ("a member-entry key 22 in the first entry, and an integer not in its shortest "
         "form in the last tip", plain_devices, reserved_first_non_minimal_last, widen,
         "Malformed"),
        ("a member of type 4 first, and a tip of two elements last", plain_devices,
         lambda v: (v[R.R_MEMBERS][0].__setitem__(
             R.M_MEMBER, [R.RESERVED_MEMBER_TYPE, v[R.R_MEMBERS][0][R.M_MEMBER][1]]),
                    v[R.R_TIPS].__setitem__(-1, v[R.R_TIPS][-1][:2])), None,
         "ExtensionRequired"),
        ("keys of another device in the first device member, and an invalid Ed25519 key "
         "in the last", plain_devices,
         lambda v: (devices(v)[0].__setitem__(R.M_ED25519, devices(v)[1][R.M_ED25519]),
                    devices(v)[-1].__setitem__(R.M_ED25519, bad_ed)), None, "InvalidKey"),
        ("the first and the last member entries swapped", plain_devices,
         lambda v: v.__setitem__(R.R_MEMBERS, [v[R.R_MEMBERS][-1]] + v[R.R_MEMBERS][1:-1]
                                 + [v[R.R_MEMBERS][0]]), None, "Malformed"),
    ]
    out = []
    for name, plain, change, error in cases:
        data = edit(plain, change)
        try:
            R.read_record(data)
            got = "ok"
        except SpecError as e:
            got = e.error
        assert got == error, (name, got, error)
        out.append({"name": name, "record": h(data), "error": error})
    for name, plain, change, post, error in far:
        data = edit(plain, change)
        if post is not None:
            data = post(data)
        try:
            R.read_record(data)
            got = "ok"
        except SpecError as e:
            got = e.error
        assert got == error, (name, got, error)
        out.append({"name": name, "record": h(data), "error": error})
    return out


def _record_object_order(plain: bytes, epoch: int) -> list:
    """roster.md, "Reading it as it streams", and units.md, "Reading an
    object": record objects of many small chunks whose faults a reader that
    reads as the chunks open meets in another order than the steps. Each
    reads with the same class whole and by chunks: a record that uses a
    reserved key in its first chunk is still not read when a later chunk
    does not open, when the object ID is another plaintext's, or when the
    checkpoint binds another digest; and stored bytes cut at a chunk
    boundary are not the object, so the reader fetches it again."""
    import hashlib
    import hmac
    from primitives import xchacha20poly1305_seal
    space = example("checkpoints/record-order/space")
    k_r = example("checkpoints/record-order/k_R")
    ref = kg.self_ref(example("checkpoints/record-order/author"), 5)
    chunk = 256
    value = R.uncbor(plain)
    value[R.R_MEMBERS][0][R.RESERVED_MEMBER_KEY] = 0
    reserved = R.cbor(value)

    def seal(plaintext, oid_of=None, corrupt_last=False):
        keys = units.object_keys(k_r)
        oid = hmac.new(keys["id_key"], plaintext if oid_of is None else oid_of,
                       hashlib.sha256).digest()
        okey = hmac.new(keys["seal_key"], oid, hashlib.sha256).digest()
        size = len(plaintext)
        header = units.object_header(oid, ref, size)
        count = units.chunk_count(size, chunk)
        sealed = []
        for i in range(count):
            part = plaintext[i * chunk:(i + 1) * chunk]
            aad = units.chunk_aad(space, oid, size, i)
            nonce = hmac.new(keys["nonce_key"], aad + part,
                             hashlib.sha256).digest()[:units.NONCE_BYTES]
            # The author seals its last chunk under another index's
            # associated data: the stored bytes are the object the locator
            # names, and that chunk does not open.
            used = units.chunk_aad(space, oid, size, i + 1) if corrupt_last and i == count - 1 \
                else aad
            sealed.append(nonce + xchacha20poly1305_seal(okey, nonce, part, used))
        data = units.u32be(len(header)) + header + b"".join(sealed)
        return data, oid + sha256(data), sealed

    def part_of(locator, plaintext):
        return {"locator": locator, "size": len(plaintext),
                "digest": sha256(R.RECORD_LABEL + plaintext), "epoch": epoch}
    ok, ok_locator, _ = seal(reserved)
    late, late_locator, _ = seal(reserved, corrupt_last=True)
    other_id, other_locator, _ = seal(reserved, oid_of=reserved + b"another")
    whole, whole_locator, whole_chunks = seal(plain)
    cases = [
        ("a record that uses a member-entry key 22 in its first chunk", ok,
         part_of(ok_locator, reserved)),
        ("the same record, its last chunk sealed so that it does not open", late,
         part_of(late_locator, reserved)),
        ("the same record, under the object ID of another plaintext", other_id,
         part_of(other_locator, reserved)),
        ("the same record, the checkpoint binding the digest of another", ok,
         {**part_of(ok_locator, reserved), "digest": sha256(R.RECORD_LABEL + plain)}),
        ("a well-formed record, the stored bytes cut at a chunk boundary",
         whole[:-len(whole_chunks[-1])], part_of(whole_locator, plain)),
    ]
    out = []
    for name, data, part in cases:
        got = []
        for by_chunks in (False, True):
            try:
                R.read_record_object(data, space, k_r, part, self_ref=ref, chunk=chunk,
                                     by_chunks=by_chunks)
                got.append("read")
            except SpecError as e:
                got.append(e.error)
        assert got[0] == got[1], (name, got)
        fetch_again = sha256(data) != part["locator"][32:]
        checkpoint = "held, fetched again" if fetch_again else \
            "ExtensionRequired" if got[0] == "ExtensionRequired" else "BadCheckpoint"
        out.append({"name": name, "object": h(data), "locator": h(part["locator"]),
                    "size": part["size"], "digest": h(part["digest"]), "epoch": epoch,
                    "chunk": chunk, "class": got[0], "checkpoint": checkpoint})
    assert [o["class"] for o in out] == ["ExtensionRequired", "Decrypt", "ObjectMismatch",
                                        "BadCheckpoint", "ObjectMismatch"], out
    assert [o["checkpoint"] for o in out] == ["ExtensionRequired", "BadCheckpoint",
                                             "BadCheckpoint", "BadCheckpoint",
                                             "held, fetched again"], out
    return {"space": h(space), "content_key": h(k_r), "self_reference": h(ref), "cases": out}


def _entry_json(m: dict) -> dict:
    out = {"member": [m["member"][0], h(m["member"][1])]}
    if m["invite"] is not None:
        out["invite"] = m["invite"]
        if m["claimant"] is not None:
            out["claimant"] = [m["claimant"][0], h(m["claimant"][1])]
        if m["expires_at"] is not None:
            out["expires_at"] = m["expires_at"]
            out["claims"] = m["claims"]
    if m["notices"]:
        out["notices"] = [{"rotation": h(n[0]), "break": n[2], "author": h(n[3])}
                          for n in m["notices"]]
    if m["floor"]:
        out["floor"] = 1
    if m["named"]:
        out["named"] = [h(x) for x in m["named"]]
    return out


def _takeover_scenario(prefix: str, kind: str):
    """roster.md, section 4, "A backdated checkpoint", and "Votes and
    effect", heard members. Administrators P (the founder, most senior),
    then Q, then A and B, in order of seniority; `kind`:

    - "junior": P removes A; A, on its view from before, removes P and Q
      and checkpoints (X). P and Q are heard by X, lowered by a junior, so
      X waits for both for good. P checkpoints (H), A excused, P being
      senior to it; Q votes; H takes effect.
    - "colluding": P removes A and B; on their old view A removes P and B
      removes Q, A checkpoints (X) and B votes: X waits for P and Q. P's H
      takes effect.
    - "senior": P's device is stolen. Q removes P; the thief, on P's old
      view, removes Q and A and checkpoints (X): both were lowered by a
      member senior to them, so X takes effect on P's vote alone. Q's H
      hears P and waits for it for good: the senior thief wins.
    - "lower": Q holds rank 200 and A rank 100; Q removes A; A, on its old
      view, removes Q and P, both void (HigherRank), and checkpoints (X),
      whose record keeps them: X waits for both for good. P's H takes
      effect.
    - "recovery": P's device is lost, and R, the recovery member P granted
      administer marked frasil.dormant, is held by the person. Q removes P
      and checkpoints (H), which hears P; R removes P after H, which excuses
      P whatever their seniority; A votes; H takes effect."""
    r = R.Roster("P", f"{prefix}/{kind}")
    attach(r)
    names = ["Q", "A", "B"] if kind == "colluding" else ["Q", "A"]
    ranks = {"Q": 200, "A": 100} if kind == "lower" else {}
    for who in names:
        r.grant("P", who, R.ADMINISTER, rank=ranks.get(who))
    if kind == "recovery":
        r.grant("P", "R", R.ADMINISTER, caps=((R.DORMANT, R.EXTENDS),),
                label="P grants R administer, dormant: the recovery member")
    r.sync("P", *names, *(["R"] if kind == "recovery" else []))
    ev = {}
    if kind in ("junior", "colluding", "lower"):
        attackers = ["A", "B"] if kind == "colluding" else ["A"]
        old = {a: set(r.hist.view[a]) for a in attackers}
        for a in attackers:
            ev[f"P removes {a}"] = r.remove("P", a, f"P removes {a}")
        r.sync("P", "Q")
        if kind == "colluding":
            r.hist.view["A"] = old["A"] | old["B"]
            r.hist.view["B"] = set(r.hist.view["A"])
        r.remove("A", "P", "A removes P, backdated")
        if kind in ("junior", "lower"):
            r.remove("A", "Q", "A removes Q, backdated")
        else:
            r.sync("A", "B")
            r.remove("B", "Q", "B removes Q, backdated")
            r.sync("A", "B")
        ev["X"] = make_checkpoint(r, "A", "A checkpoints, backdated (X)", fence=False)
        if kind == "colluding":
            r.sync("A", "B")
            r.anchor("B", "B votes for X")
        ev["H"] = make_checkpoint(r, "P", "P checkpoints (H)")
        r.sync("P", "Q")
        r.anchor("Q", "Q votes for H")
    elif kind == "senior":
        old = set(r.hist.view["P"])
        ev["Q removes P"] = r.remove("Q", "P", "Q removes P, whose device is stolen")
        r.sync("Q", "A")
        ev["H"] = make_checkpoint(r, "Q", "Q checkpoints (H)")
        r.sync("Q", "A")
        r.anchor("A", "A votes for H")
        r.hist.view["P"] = old
        r.remove("P", "Q", "the thief removes Q, backdated")
        r.remove("P", "A", "the thief removes A, backdated")
        ev["X"] = make_checkpoint(r, "P", "the thief checkpoints, backdated (X)", fence=False)
    else:
        r.sync("Q", "A")
        ev["Q removes P"] = r.remove("Q", "P", "Q removes P, whose device is lost")
        r.sync("Q", "A", "R")
        ev["H"] = make_checkpoint(r, "Q", "Q checkpoints (H)")
        r.sync("Q", "A", "R")
        r.anchor("A", "A votes for H")
        ev["before R"] = set(r.log.events)
        r.sync("Q", "A", "R")
        ev["R removes P"] = r.remove("R", "P", "R, the recovery member, removes P after H")
    r.sync(*[n for n in r.everyone() if not (kind == "senior" and n == "P")])
    return r, ev


def _takeover_checks(prefix: str) -> dict:
    out = {}
    for kind in ("junior", "colluding", "senior", "recovery", "lower"):
        r, ev = _takeover_scenario(prefix, kind)
        ctx = Ctx(r.log, r.keyring(), objects=r.objects)
        final = set(r.log.events)
        full = judge(ctx, final)
        dev = r.hist.device
        if kind in ("junior", "colluding"):
            assert sorted(heard(ctx, ev["X"])) == sorted([dev("P"), dev("Q")])
            assert sorted(waiting_for(ctx, ev["X"], final)) == sorted([dev("P"), dev("Q")])
            assert full.chain == [ev["H"]], [r.name(c) for c in full.chain]
            assert not heard(ctx, ev["H"])
        elif kind == "senior":
            assert full.chain == [ev["X"]], [r.name(c) for c in full.chain]
            assert waiting_for(ctx, ev["H"], final) == [dev("P")]
        elif kind == "lower":
            assert not heard(ctx, ev["X"])
            assert sorted(waiting_for(ctx, ev["X"], final)) == sorted([dev("P"), dev("Q")])
            assert full.chain == [ev["H"]], [r.name(c) for c in full.chain]
        else:
            before = judge(ctx, ev["before R"])
            assert before.chain == [] and waiting_for(ctx, ev["H"], ev["before R"]) == [dev("P")]
            assert full.chain == [ev["H"]], [r.name(c) for c in full.chain]
        out[kind] = {"r": r, "ev": ev, "ctx": ctx, "full": full}
    return out


def _person_across_list(prefix: str) -> dict:
    """roster.md, "Other logs and extensions", What an unlisted device
    loses: P grants W and person B; B's device b2 writes and heals; b1
    revokes b2 in B's list; b2 writes before the space hears and after W's
    response, apart. Then b1 adds b3 and checkpoints B's list, and b3 votes:
    the list checkpoint, in effect, does not list b2. A replica that kept
    B's whole list (and so b2's keys) and one that forgot it both drop every
    unit of b2, before the checkpoint as after; the one that kept the keys
    drops b2's key event too, and the one that lacks them holds it
    (NoHybridKey), never judged. Without the list checkpoint, b2's units
    before the response stand."""
    import list_checkpoints as L
    pb = identity.Person("b1", f"{prefix}/list", linear=True)
    pb.add("b1", "b2", identity.DEVICE)
    r = R.Roster("P", prefix, keys={n: pb.hist.seed(n) for n in ("b1", "b2")})
    r.persons[pb.id] = "person B"
    r.grant("P", "W", R.WRITE)
    r.grant("P", "person B", R.WRITE, label="P grants person B write")
    r.sync("P", "W", "b1", "b2")
    u1 = r.unit("b2", "b2 writes")
    heal = r.heal("b2", "b2 heals")
    r.sync("P", "W", "b1", "b2")
    revoke = pb.revoke("b1", "b2", "b1 revokes b2 in B's list")
    u2 = r.unit("b2", "b2 writes before anyone in the space hears")
    r.sync("P", "W", "b2")
    before = r.all()
    r.heal("W", "W rotates in response to the revocation", refs=[(pb.id, revoke)])
    u3 = r.unit("b2", "b2 writes after the response, apart", view=before)
    r.sync("P", "W", "b1", "b2")
    plain = r.resolve(lists={pb.id: pb.resolve()})
    pb.add("b1", "b3", identity.DEVICE, "b1 adds b3")
    lc = L.make_checkpoint(pb, "b1", "b1 checkpoints B's list")
    pb.hist.sync("b1", "b3")
    L.ack(pb, "b3", "b3 votes")
    final = set(pb.log.events)
    whole = L.judge(L.LCtx(pb.log), final)
    assert whole.chain == [lc], [pb.hist.name(c) for c in whole.chain]
    fl, fheld = L.forgetting(pb.log, lc, final)
    forgot = L.judge(fl, fheld, lc)
    every_key = identity.DeviceList(pb.log, final).named_keys()
    full = R.Space(r.log, None, {pb.id: whole.list}, None, r.keyring(), extra_keys=every_key)
    kept = R.Space(r.log, None, {pb.id: forgot.list}, None, r.keyring())
    assert plain.status[u1][0] and plain.status[u2][0] and not plain.status[u3][0]
    for u in (u1, u2, u3):
        assert full.status[u][1] == kept.status[u][1] == "Dropped", \
            (r.name(u), full.status[u], kept.status[u])
    assert full.status[heal][1] == "Dropped" and kept.status[heal][1] == "NoHybridKey", \
        (full.status[heal], kept.status[heal])
    others = set(r.log.events) - {u1, u2, u3, heal}
    assert all(full.status[i] == kept.status[i] for i in others)
    assert all(full.status[i][0] for i in others)  # W's response resolves its ref
    return {"r": r, "pb": pb, "plain": plain, "full": full, "kept": kept,
            "checkpoint": lc, "list_held": sorted(pb.hist.name(i) for i in fheld)}


def _adversarial_checks(prefix: str) -> dict:
    out = {}
    r, ev = _stale_predecessor(f"{prefix}/stale-predecessor")
    ctx = Ctx(r.log, r.keyring(), objects=r.objects)
    full = judge(ctx, set(r.log.events))
    assert full.chain == [ev["K1"], ev["K2"]]
    assert full.status[ev["X"]][1] == full.status[ev["Y"]][1] == "CheckpointPending"
    fctx, held = forget(ctx, ev["K2"], set(r.log.events))
    assert ev["K1"] in fctx.envelopes
    forgot = judge(fctx, held, ev["K2"])
    assert not comparable(full, forgot, held)
    out["stale_predecessor"] = {"r": r, "full": full, "forgot": forgot, "held": held,
                                "note": "X and Y name K1, held as an envelope alone at a "
                                        "replica that kept K2, as predecessor while their cuts "
                                        "reach K2: CheckpointPending at both replicas"}
    out["backdated"] = _backdated_scenario(f"{prefix}/backdated")
    out["disjoint"] = _disjoint_checks(f"{prefix}/disjoint")
    out["guests"] = _guests_and_restricted(f"{prefix}/guests")
    out["granted_checkpoint"] = _granted_checkpoint_checks(f"{prefix}/granted-checkpoint")
    out["person_across_list"] = _person_across_list(f"{prefix}/person-across-list")
    out["takeover"] = _takeover_checks(f"{prefix}/takeover")
    return out


def _verdicts(r, world, ids) -> dict:
    return {r.name(i): "valid" if world.status[i][0] else world.status[i][1]
            for i in sorted(ids, key=r.log.order_key)}


def _adversarial_vectors(prefix: str) -> dict:
    """roster.json `checkpoints`: dishonest and cross-log histories, each with
    the verdicts of a replica that kept everything and of one that forgot."""
    a = _adversarial_checks(prefix)
    out = {}
    x = a["stale_predecessor"]
    r = x["r"]
    out["stale_predecessor"] = {"history_prefix": f"{prefix}/stale-predecessor",
                                "events": r.hist.describe(), "note": x["note"],
                                "full": {"effective": [r.name(c) for c in x["full"].chain],
                                         "verdicts": _verdicts(r, x["full"], r.log.events)},
                                "forgot": {"holds": sorted(r.name(i) for i in x["held"]),
                                           "verdicts": _verdicts(r, x["forgot"], x["held"])}}
    x = a["backdated"]
    r = x["r"]
    out["backdated"] = {"history_prefix": f"{prefix}/backdated", "events": r.hist.describe(),
                        "note": "A's checkpoint, signed on a view before its removal, waits "
                                "for P: A's removal of P after it excuses no one, A being its "
                                "author",
                        "waiting_for": [r.hist.key_name(d) for d in waiting_for(
                            x["ctx"], x["ev"]["X"], set(r.log.events))],
                        "full": {"effective": [r.name(c) for c in x["full"].chain],
                                 "verdicts": _verdicts(r, x["full"], r.log.events)}}
    x = a["disjoint"]
    r = x["r"]
    out["disjoint"] = {"history_prefix": f"{prefix}/disjoint", "events": r.hist.describe(),
                       "note": "two electorates with no device in common: the smaller ID "
                               "takes effect; a replica that forgot under the other holds "
                               "it as a rival, and every event it holds pending",
                       "group_views": {
                           "P and Q": [r.name(c) for c in judge(
                               Ctx(r.log, r.keyring(), objects=r.objects),
                               x["ev"]["group1"]).chain],
                           "A and B": [r.name(c) for c in judge(
                               Ctx(r.log, r.keyring(), objects=r.objects),
                               x["ev"]["group2"]).chain]},
                       "full": {"effective": [r.name(c) for c in x["full"].chain],
                                "verdicts": _verdicts(r, x["full"], r.log.events)},
                       "forgot_under_loser": {"kept": r.name(x["lose"]),
                                              "holds": sorted(r.name(i) for i in x["held"]),
                                              "verdicts": _verdicts(r, x["forgot"], x["held"])},
                       "forgot_under_winner": {"kept": r.name(x["win"]),
                                               "holds": sorted(r.name(i) for i in x["wheld"]),
                                               "verdicts": _verdicts(r, x["wforgot"],
                                                                     x["wheld"])}}
    g = a["guests"]
    for key in ("guest", "restricted"):
        x = g[key]
        r = x["r"]
        out[key] = {"history_prefix": f"{prefix}/guests/{key}", "events": r.hist.describe(),
                    "record": h(R.encode_record(x["ctx"].record(x["checkpoint"]))),
                    "full": {"effective": [r.name(c) for c in x["full"].chain],
                             "verdicts": _verdicts(r, x["full"], r.log.events)},
                    "forgot": {"holds": sorted(r.name(i) for i in x["held"]),
                               "verdicts": _verdicts(r, x["forgot"], x["held"])}}
    x = g["refused"]
    r = x["r"]
    out["step_6"] = {"history_prefix": f"{prefix}/guests/refused", "events": r.hist.describe(),
                     "note": "a guest's checkpoint is NotAnAdministrator before keys.md is "
                             "read; a checkpoint is a grant rotation exactly when the space "
                             "is not restricted",
                     "verdicts": {r.name(i): checkpoint_validity(x["ctx"], i)[1]
                                  for i in x["ids"]},
                     "restricted": {g["restricted"]["r"].name(i): checkpoint_validity(
                         g["restricted"]["ctx"], i)[1] for i in g["restricted"]["refused"]}}
    for kind, x in a["takeover"].items():
        r, ev, ctx = x["r"], x["ev"], x["ctx"]
        out[f"takeover_{kind}"] = {
            "history_prefix": f"{prefix}/takeover/{kind}", "events": r.hist.describe(),
            "note": {"junior": "a junior's backdated checkpoint hears its seniors and waits "
                               "for them for good; the honest checkpoint takes effect",
                     "colluding": "two junior devices gain nothing either",
                     "senior": "a thief holding the most senior device takes the space: its "
                               "victims were lowered by a member senior to them",
                     "recovery": "a lost most senior device is excused by the recovery "
                                 "member",
                     "lower": "a thief of rank 100 cannot remove ranks 200 and 255 at all; its "
                              "record keeps them, and its checkpoint waits for them"}[kind],
            "heard": {r.name(c): sorted(r.hist.key_name(d) for d in heard(ctx, c))
                      for c in (ev.get("X"), ev.get("H")) if c is not None},
            "waiting_for": {r.name(c): [r.hist.key_name(d) for d in waiting_for(
                ctx, c, set(r.log.events))] for c in (ev.get("X"), ev.get("H"))
                if c is not None},
            "full": {"effective": [r.name(c) for c in x["full"].chain],
                     "verdicts": _verdicts(r, x["full"], r.log.events)}}
    x = a["person_across_list"]
    r = x["r"]
    out["person_across_list"] = {
        "history_prefix": f"{prefix}/person-across-list", "events": r.hist.describe(),
        "list_prefix": f"{prefix}/person-across-list/list", "list": x["pb"].hist.describe(),
        "note": "B's list checkpoint, in effect, does not list b2: every unit of b2 is "
                "Dropped, those before the checkpoint too, at a replica that kept B's whole "
                "list and at one that forgot it; b2's key event is Dropped where b2's keys "
                "are held and NoHybridKey (held) where they are not",
        "list_checkpoint": x["pb"].hist.name(x["checkpoint"]),
        "list_held_after_forgetting": x["list_held"],
        "without_list_checkpoint": _verdicts(r, x["plain"], r.log.events),
        "whole_list": _verdicts(r, x["full"], r.log.events),
        "forgotten_list": _verdicts(r, x["kept"], r.log.events)}
    x = a["granted_checkpoint"]
    r, team = x["r"], x["team"]
    out["granted_checkpoint"] = {
        "history_prefix": f"{prefix}/granted-checkpoint", "events": r.hist.describe(),
        "team_prefix": team.prefix, "team": team.hist.describe(),
        "note": "the team's checkpoint is a grant rotation of it; the granting space "
                "responds by delivery, noticing it; the principal is in force whether the "
                "team is held whole or from its checkpoint on",
        "principals": [[h(s_), team.name(rot)] for s_, rot in
                       x["team whole"]["full"].space.principals()],
        "full": {"verdicts": _verdicts(r, x["team whole"]["full"], r.log.events)},
        "forgot": {"holds": sorted(r.name(i) for i in x["team forgotten"]["held"]),
                   "verdicts": _verdicts(r, x["team forgotten"]["forgot"],
                                         x["team forgotten"]["held"])}}
    return out


def _scenario_vectors(prefix: str) -> dict:
    sc = _scenario_checks(prefix)
    out = {}
    for key in ("raced", "granted"):
        x = sc[key]
        r, ev, full, forgot, held, ctx = x["r"], x["ev"], x["full"], x["forgot"], x["held"], x["ctx"]
        rec = ctx.record(ev["checkpoint"])
        plain = R.encode_record(rec)

        def verdicts(world, ids, r=r):
            return {r.name(i): "valid" if world.status[i][0] else world.status[i][1]
                    for i in sorted(ids, key=r.log.order_key)}
        entry = {"history_prefix": f"{prefix}/{key}", "events": r.hist.describe(),
                 "checkpoint": r.name(ev["checkpoint"]), "record": h(plain),
                 "entries": [_entry_json(m) for m in rec["members"]
                             if m["member"][0] in (R.INVITE, R.SPACE)],
                 "full": {"effective": [r.name(c) for c in full.chain],
                          "verdicts": verdicts(full, r.log.events)},
                 "forgot": {"holds": sorted(r.name(i) for i in held),
                            "verdicts": verdicts(forgot, held)}}
        if key == "granted":
            team = x["team"]
            entry["team_prefix"] = team.prefix
            entry["team"] = team.hist.describe()
            entry["principals"] = [[h(s_), team.name(rot)] for s_, rot in full.space.principals()]
        out[key] = entry
    return out


def self_test() -> None:
    r, ev = _scenario("checkpoints/self-test")
    ctx = Ctx(r.log, r.keyring(), objects=getattr(r, "objects", {}))
    full = judge(ctx, set(r.log.events))
    assert full.chain == [ev["checkpoint"]], "the checkpoint takes effect once A votes"
    assert full.status[ev["late"]][1] == LATE, "A's offline grant concurrent with it is late"
    assert full.status[ev["remove"]][0] and full.status[ev["unit"]][0]
    # Before A votes, it is not in effect, and A's grant stands.
    before = judge(ctx, {i for i in r.log.events
                         if i != ev["vote"] and ev["vote"] not in r.log.anc[i]})
    assert before.chain == [] and before.status[ev["late"]][0]
    assert waiting_for(ctx, ev["checkpoint"], set(before.status)) == [r.hist.device("A")]
    assert waiting_for(ctx, ev["checkpoint"], set(r.log.events)) == []
    # A replica that forgot agrees.
    fctx, held = forget(ctx, ev["checkpoint"], set(r.log.events))
    forgot = judge(fctx, held, ev["checkpoint"])
    assert not comparable(full, forgot, held)
    # Cuts that do not match their parents.
    assert not any(ctx.bad_cuts(i) for i in r.log.events)
    # A tampered record is void; it never takes effect.
    r2, _ = R.Roster("P", "checkpoints/tampered"), None
    attach(r2)
    r2.grant("P", "A", R.ADMINISTER)

    def lie(rec):
        rec = dict(rec)
        rec["members"] = [m for m in rec["members"] if m["member"][1] != r2.hist.device("A")]
        return rec
    bad = make_checkpoint(r2, "P", "P checkpoints and leaves A out", tamper=lie)
    ctx2 = Ctx(r2.log, r2.keyring(), objects=getattr(r2, "objects", {}))
    assert checkpoint_validity(ctx2, bad) == (False, "BadCheckpoint", None)
    assert judge(ctx2, set(r2.log.events)).chain == []
    # The record reads back.
    d = ctx.checkpoint(ev["checkpoint"])
    plain = R.encode_record(ctx.record(ev["checkpoint"]))
    assert R.encode_record(R.read_record(plain)) == plain
    # Without its record object, a checkpoint is held with what follows it,
    # and the rest is judged as if it had not arrived.
    lacking = Ctx(r.log, r.keyring())
    removed = {ev["checkpoint"]} | {i for i in r.log.events if ev["checkpoint"] in r.log.anc[i]}
    w = judge(lacking, set(r.log.events))
    ref = judge(Ctx(r.log, r.keyring(), objects=r.objects), set(r.log.events) - removed)
    assert w.status[ev["checkpoint"]][1] == "Sealed"
    assert all(w.status[i] == ref.status[i] for i in set(r.log.events) - removed)
    assert all(w.status[i][1] in ("Sealed", "Pending") for i in removed)
    # A later rule this replica lacks stops its view at that event's past.
    r3, ev3 = _freeze("checkpoints/freeze")
    sp = R.Space(r3.log, keys=r3.keyring())
    for name in ("unknown", "concurrent", "after"):
        assert sp.status[ev3[name]][1] == "ExtensionRequired", (name, sp.status[ev3[name]])
    assert sp.status[r3.log.anc[ev3["unknown"]] and max(
        r3.log.anc[ev3["unknown"]], key=r3.log.order_key)][0]
    # A raced invite and a granted space across a checkpoint.
    sc = _scenario_checks("checkpoints/self-test")
    _record_refusals(plain, R.encode_record(sc["granted"]["ctx"].record(
        sc["granted"]["ev"]["checkpoint"])), R.encode_record(sc["raced"]["ctx"].record(
            sc["raced"]["ev"]["checkpoint"])))
    # Checkpoints an administrator signs dishonestly, and cases across
    # logs: a predecessor held as an envelope alone, a backdated checkpoint
    # whose author excuses no one, two disjoint electorates, guests,
    # restricted spaces and step 6, a granted space's checkpoint, a person
    # member across a list checkpoint.
    _adversarial_checks("checkpoints/self-test")
    # A short model check, with invites and a granted space.
    model_check(range(1, 7), quiet=True)


def checkpoint_vectors() -> dict:
    """roster.json's `checkpoints` family."""
    r, ev = _scenario("checkpoints/vector")
    ctx = Ctx(r.log, r.keyring(), objects=getattr(r, "objects", {}))
    full = judge(ctx, set(r.log.events))
    fctx, held = forget(ctx, ev["checkpoint"], set(r.log.events))
    forgot = judge(fctx, held, ev["checkpoint"])

    def verdicts(world, ids):
        out = {}
        for i in sorted(ids, key=r.log.order_key):
            v = world.status[i]
            out[r.name(i)] = "valid" if v[0] else v[1]
        return out
    d = ctx.checkpoint(ev["checkpoint"])
    r3, ev3 = _freeze("checkpoints/freeze")
    sp3 = R.Space(r3.log, keys=r3.keyring())
    rec = ctx.record(ev["checkpoint"])
    plain = R.encode_record(rec)
    sc = _scenario_checks("checkpoints/refusals")
    refusals = _record_refusals(plain, R.encode_record(sc["granted"]["ctx"].record(
        sc["granted"]["ev"]["checkpoint"])), R.encode_record(sc["raced"]["ctx"].record(
            sc["raced"]["ev"]["checkpoint"])))
    return {
        "record_refusals": refusals,
        "record_object_order": _record_object_order(plain, rec["epoch"]),
        "extension_required": _extension_checkpoints("checkpoints/extension"),
        "extension_rival": _extension_rival("checkpoints/extension-rival"),
        "extension_after_predecessor": _extension_after_predecessor(
            "checkpoints/extension-after-predecessor"),
        "frozen_content": _frozen_content("checkpoints/frozen-content"),
        "freeze": {"history_prefix": "checkpoints/freeze", "events": r3.hist.describe(),
                   "verdicts": {r3.name(i): "valid" if sp3.status[i][0] else sp3.status[i][1]
                                for i in r3.log.canonical()}},
        "record_read": {"epoch": rec["epoch"],
                        "members": [{"member": [m["member"][0], h(m["member"][1])],
                                     "level": m["level"], "history": m["history"],
                                     "seniority": [m["seniority"][0], m["seniority"][1],
                                                   h(m["seniority"][3])]}
                                    for m in rec["members"]],
                        "tips": {h(a): [s_, h(i)] for a, (s_, i) in sorted(rec["tips"].items())},
                        "forks": {h(a): s_ for a, s_ in sorted(rec["forks"].items())}},
        "history_prefix": "checkpoints/vector",
        "events": r.hist.describe(),
        "checkpoint": {"name": r.name(ev["checkpoint"]), "record": h(plain),
                       "digest": h(sha256(R.RECORD_LABEL + plain)), "size": len(plain),
                       "locator": h(d.part["locator"]),
                       "object": h(r.objects[d.part["locator"]]),
                       "epoch": rec["epoch"]},
        "full": {"effective": [r.name(c) for c in full.chain],
                 "verdicts": verdicts(full, r.log.events)},
        "forgot": {"holds": sorted(r.name(i) for i in held),
                   "verdicts": verdicts(forgot, held)},
        **_scenario_vectors("checkpoints/vector"),
        "adversarial": _adversarial_vectors("checkpoints/vector"),
    }


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    print(model_check(range(1, n + 1)))
