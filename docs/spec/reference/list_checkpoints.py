"""List checkpoints (identity.md, "List checkpoints"), written from the
specification: a person's list fixed at a point every active device agreed
on, after which a holder of the list keeps only the list's first event, the
checkpoint, the adds its record names and what follows. The rules are
roster.md's checkpoints read for a list, and the world after a list
checkpoint is identity.md's merge itself, over a log rooted at the
checkpoint. A seeded model check builds random lists with adds, revocations,
concurrent branches, forks, checkpoints and acks, and checks that a holder
that forgot and one that did not agree."""

from __future__ import annotations

import copy
import random
import sys

import identity as I
from checkpoints import DerivedLog
from events import Log, cbor, h, uncbor
from primitives import SpecError

LATE = "Late"
HELD = ("Pending", "NoHybridKey")


class LCtx:
    """What a holder of a person's list reads. A holder that keeps everything
    reads every event of the log. One that forgot under a kept checkpoint
    (`trusted`) reads only what identity.md, "List checkpoints", lets it
    keep: `held`, the checkpoint and the events after it, which it judges,
    and `alone`, kept as events alone: the list's first event, the adds its
    record names (each member's and the add that rooted it in an agent),
    the checkpoints the kept one's `follows` reach, and the late events.
    Reading anything else is a fault of the model, not a verdict."""

    def __init__(self, log: Log, *, trusted=(), held=None, alone=()):
        self.log = log
        self.trusted = frozenset(trusted)
        self.held = None if held is None else frozenset(held)
        self.readable = None if held is None else frozenset(held) | frozenset(alone)
        self.memo: dict = {}

    def can_read(self, i: bytes) -> bool:
        return i in self.log.events and (self.readable is None or i in self.readable)

    def ev(self, i: bytes):
        assert self.can_read(i), "a holder that forgot reads a forgotten event"
        return self.log.events[i]

    def body(self, i: bytes):
        k = ("body", i)
        if k not in self.memo:
            try:
                self.memo[k] = I.check_body(self.ev(i))
            except SpecError:
                self.memo[k] = None
        return self.memo[k]

    def is_checkpoint(self, i: bytes) -> bool:
        """An ID that is no event this holder reads is no list checkpoint:
        every checkpoint a held event can reach is kept (the kept one's
        reach, the late ones), so one it forgot is none it needs."""
        if not self.can_read(i):
            return False
        b = self.body(i)
        return b is not None and b.action == I.LIST_CHECKPOINT

    def record(self, i: bytes) -> dict:
        return self.body(i).record

    def follows_of(self, i: bytes) -> tuple:
        b = self.body(i)
        return b.follows if b is not None else ()

    def reach(self, i: bytes) -> frozenset:
        k = ("reach", i)
        if k not in self.memo:
            out = set()
            for c in self.follows_of(i):
                out.add(c)
                if self.can_read(c):
                    out |= self.reach(c)
            self.memo[k] = frozenset(out)
        return self.memo[k]

    def below(self, x: bytes, y: bytes) -> bool:
        return x == y or x in self.reach(y)

    def bad_follows(self, i: bytes) -> bool:
        """events.md, "Cuts", over this list's checkpoints. A parent that a
        holder forgot is in its kept checkpoint's past, so all it could add
        is at or before that checkpoint, which a parent after it already
        reaches: it adds nothing (identity.md, "List checkpoints")."""
        e = self.ev(i)
        if e.genesis:
            return False
        found = set()
        for p in e.parents:
            if not self.can_read(p):
                continue
            if self.is_checkpoint(p):
                found.add(p)
            found |= set(self.follows_of(p))
        expected = {x for x in found if not any(x != y and self.below(x, y) for y in found)}
        return set(self.follows_of(i)) != expected

    def follows(self, i: bytes, c: bytes) -> bool:
        return c in self.reach(i)

    def concurrent(self, x: bytes, y: bytes) -> bool:
        return not self.below(x, y) and not self.below(y, x)


def world_log(ctx: LCtx, c: bytes, held) -> DerivedLog:
    members = {i for i in held if i != c and ctx.follows(i, c)}
    k = ("dlog", c, frozenset(members))
    if k not in ctx.memo:
        ctx.memo[k] = DerivedLog(ctx.log, c, members)
    return ctx.memo[k]


def _list(ctx: LCtx, log, view, presets, base=None) -> I.DeviceList:
    k = ("list", id(log) if base is None else base["id"], frozenset(view),
         frozenset(presets.items()))
    if k not in ctx.memo:
        ctx.memo[k] = I.DeviceList(log, set(view), presets=presets, base=base)
    return ctx.memo[k]


def world(ctx: LCtx, c: bytes, view) -> I.DeviceList:
    """The world of list checkpoint c over `view`: c and the events after it."""
    view = {i for i in view if i == c or ctx.follows(i, c)}
    dlog = world_log(ctx, c, view)
    presets = {}
    for i in view - {c}:
        e = ctx.ev(i)
        if ctx.bad_follows(i):
            presets[i] = (False, "BadCuts", None)
        elif any(p != e.prev and p != c and not ctx.follows(p, c) for p in e.parents):
            presets[i] = (False, "MixedCut", None)
        elif ctx.is_checkpoint(i):
            presets[i] = validity(ctx, i)
    record = ctx.record(c)
    adds = {m["add"]: ctx.body(m["add"]) for m in record["members"]}
    return _list(ctx, dlog, view, presets, {"id": c, "record": record, "adds": adds})


def _presets_outside(ctx: LCtx, view) -> dict:
    out = {}
    for i in view:
        if ctx.ev(i).genesis:
            continue
        if ctx.bad_follows(i):
            out[i] = (False, "BadCuts", None)
        elif ctx.is_checkpoint(i):
            out[i] = validity(ctx, i)
    return out


def record_of(ctx: LCtx, lst: I.DeviceList, previous: bytes | None) -> dict:
    """identity.md, "List checkpoints": the record of a list's view."""
    members, tips = [], {}
    if previous is not None:
        prev = ctx.record(previous)
        epoch = prev["epoch"] + 1
        tips = dict(prev["tips"])
    else:
        epoch = 1
    active = lst.active_members()
    for device, m in sorted(active.items()):
        add = m.adds[0] if m.adds else m.base_add
        members.append({"device": device, "add": add, "root": m.root, "agent": m.agent_root,
                        "confirmed": bool(m.confirmed_by),
                        "seniority": lst.seniority(device, lst.members),
                        "rooting": m.agent_adds[0] if m.agent_adds else None})
    for i in sorted(lst.view):
        e = ctx.ev(i)
        if e.seq > tips.get(e.author, (0, b""))[0]:
            tips[e.author] = (e.seq, i)
    tips = {a: t for a, t in tips.items() if a in active}
    return {"epoch": epoch, "previous": previous, "members": members, "tips": tips,
            "forks": dict(lst.forks), "heard": heard_of(lst, set(active))}


def _outranks(lst: I.DeviceList, S: dict, a: bytes, b: bytes) -> bool:
    """identity.md, "List checkpoints", Effect: list member a outranks b at
    a place whose state is S: a higher rank (section 3.4), or the same rank
    and a more senior add."""
    ma, mb = S.get(a), S.get(b)
    if ma is None or mb is None:
        return False
    return (ma.rank, lst.seniority(a, S)) < (mb.rank, lst.seniority(b, S))


def heard_of(lst: I.DeviceList, active: set) -> dict:
    """identity.md, "List checkpoints", Effect, heard devices of the view
    `lst` resolves: each device, waited for at its place (a device not
    rooted, or confirmed), that a valid revoke of the view names, that is
    not active there, and that no valid revoke of the view names while
    signed by itself or by a member that outranks it. Each maps, by the add
    that gives its keys, to its seniority there."""
    found: dict = {}
    for i in sorted(lst.valid, key=lst.log.order_key):
        b = lst.bodies.get(i)
        if b is None or b.action != I.REVOKE or i == lst.log.genesis:
            continue
        S = lst.state(lst.place(i, lst.valid))
        m = S.get(b.device)
        if m is None or m.kind != I.DEVICE or m.rooted != I.NONE:
            continue
        author = lst.log.events[i].author
        excusing = author == b.device or _outranks(lst, S, author, b.device)
        sen = lst.seniority(b.device, S)
        # Its earliest valid add in the view, in canonical order (identity.md,
        # "List checkpoints", key 7), whichever revoke names it first.
        whole = lst.members.get(b.device, m)
        add = whole.adds[0] if whole.adds else whole.base_add
        was = found.get(b.device, (False, sen, add))
        found[b.device] = (was[0] or excusing, min(was[1], sen), was[2])
    return {add: sen for d, (excused_, sen, add) in found.items()
            if not excused_ and d not in active}


def validity(ctx: LCtx, c: bytes) -> tuple:
    k = ("valid", c)
    if c in ctx.trusted:
        return (True, "checkpoint", None)
    if k not in ctx.memo:
        ctx.memo[k] = (False, "Pending", None)
        ctx.memo[k] = _validity(ctx, c)
    return ctx.memo[k]


def _validity(ctx: LCtx, c: bytes) -> tuple:
    """identity.md, "List checkpoints", its validity, in order, on its own
    past alone, with only what a holder that forgot still reads."""
    e = ctx.ev(c)
    # 1. The event alone (section 3.1, steps 1 to 6, decided before this
    #    runs) and its follows.
    if ctx.bad_follows(c):
        return (False, "BadCuts", None)
    record = ctx.record(c)
    previous = record["previous"]
    reached = sorted((x for x in ctx.reach(c) if ctx.is_checkpoint(x)),
                     key=lambda x: (x not in ctx.trusted, x))
    if previous is None:
        # 2. Without a predecessor: no checkpoint its follows reach is valid.
        #    The kept checkpoint, valid, is tried first: a holder that forgot
        #    decides from it alone.
        if any(validity(ctx, x)[0] for x in reached):
            return (False, "BadCheckpoint", None)
        past = ctx.log.anc[c]
        lst = _list(ctx, ctx.log, past, _presets_outside(ctx, past))
    else:
        # 2. With a predecessor p: p is a checkpoint its follows reach, and
        #    every one they reach is at or before p, or after p;
        if not ctx.is_checkpoint(previous) or previous not in reached \
                or any(ctx.concurrent(x, previous) for x in reached):
            return (False, "BadCheckpoint", None)
        #    none they reach after p is valid (the kept one first);
        if any(x != previous and ctx.below(previous, x) and validity(ctx, x)[0]
               for x in reached):
            return (False, "CheckpointPending", None)
        #    p is valid;
        if not validity(ctx, previous)[0]:
            return (False, "BadCheckpoint", None)
        #    p is in effect in the view of p and the events after it in its
        #    past, which holds no other valid checkpoint.
        pool = ctx.log.anc[c] | {c} if ctx.held is None else ctx.held
        members = {i for i in pool if ctx.follows(i, previous)}
        held = (world_log(ctx, previous, members).anc[c] | {previous}) - {c}
        if any(ctx.is_checkpoint(i) and validity(ctx, i)[0] for i in held - {previous}):
            return (False, "CheckpointPending", None)
        if not stable(ctx, previous, held):
            return (False, "CheckpointPending", None)
        lst = world(ctx, previous, held)
    # 3. Its signature, under the keys of the adds of its past: the
    #    predecessor's record's and those after it. An author no add there
    #    names is no list member there.
    verdict = I.signature_ok(e, lst.named_keys())
    if verdict == "NoHybridKey":
        return (False, "UntrustedSigner", None)
    if verdict is not True:
        return (False, verdict, None)
    # 4. Its author's fork point there is above its seq.
    if e.author in lst.forks and e.seq >= lst.forks[e.author]:
        return (False, "Forked", None)
    # 5. Its author is an active device or recovery key there that is not
    #    rooted; a confirm clears a device's rootedness.
    me = lst.members.get(e.author)
    if me is None or not me.active or me.kind not in (I.DEVICE, I.RECOVERY) \
            or me.rooted != I.NONE:
        return (False, "UntrustedSigner", None)
    # 6. Its record is the record of its past, byte for byte.
    if I.encode_list_record(record_of(ctx, lst, previous)) != ctx.body(c).record_bytes:
        return (False, "BadCheckpoint", None)
    return (True, "checkpoint", None)


def _counts(ctx: LCtx, c: bytes, w: I.DeviceList, i: bytes) -> bool:
    """Event i of c's world counts toward c's effect: judged (not held), its
    signature verified, its follows correct, and reaching no list checkpoint
    concurrent with c."""
    return (w.status.get(i, (True, None))[1] not in HELD and i not in w.structural
            and not ctx.bad_follows(i)
            and all(not ctx.concurrent(x, c) for x in ctx.reach(i) if ctx.is_checkpoint(x)))


def electorate(ctx: LCtx, c: bytes, held) -> set:
    """The devices c waits for: the record's devices that are not rooted, a
    confirmed one included, but those excused, which only grows as events
    arrive: one with evidence of its fork in c's world, and one a revocation
    after c names that a device or recovery key of the record that may sign
    a checkpoint, other than c's author, signed and that counts as that
    signer's vote. A revocation
    that a later merge voids still excuses: otherwise its target would
    return to the electorate and the checkpoint could leave effect."""
    w = world(ctx, c, held | {c})
    record = ctx.record(c)
    named, signers = set(), set()
    for m in record["members"]:
        b = ctx.body(m["add"])
        unrooted = m["root"] == I.NONE or m["confirmed"]
        if b.kind == I.DEVICE and unrooted:
            named.add(b.device)
        if b.kind in (I.DEVICE, I.RECOVERY) and unrooted:
            signers.add(b.device)
    # The heard devices, ranked as unrooted devices with their recorded
    # seniority.
    hear = {}
    for add, sen in record.get("heard", {}).items():
        d = ctx.body(add).device
        hear[d] = (sen[0], sen[1], I.sha256(I.LIST_SENIORITY_LABEL + ctx.log.id + d), sen[3])
    named |= set(hear)
    excused = set(w.forks) & named
    root = w.members
    for i in w.view - {c}:
        b = w.bodies.get(i)
        if b is None or b.action != I.REVOKE or b.device not in named:
            continue
        author = ctx.ev(i).author
        if author == b.device:
            # It revokes itself: it accepts. A heard device's signature is
            # checked under the add the record names for it.
            if _counts(ctx, c, w, i) or (author in hear and w.structural.get(i) ==
                                         "UntrustedSigner" and I.signature_ok(
                                             ctx.ev(i), [ctx.body(a).keys() for a in
                                                         record["heard"]]) is True):
                excused.add(author)
            continue
        if author not in signers or not _counts(ctx, c, w, i):
            continue
        # Only a member that outranks its target excuses it, c's author
        # included: a junior excuses nobody senior to it, so a revoked
        # device cannot sign c on an old view and revoke the others.
        if b.device in hear:
            ma = root.get(author)
            mine = None if ma is None else (ma.rank, w.seniority(author, root))
            if mine is not None and mine < (2, hear[b.device]):  # an unrooted device's rank
                excused.add(b.device)
        elif _outranks(w, root, author, b.device):
            excused.add(b.device)
    return named - excused


def votes(ctx: LCtx, c: bytes, held) -> set:
    """The devices that voted for c. A heard device's events, whose add the
    world does not name, are checked under the keys of its add, which the
    record names."""
    w = world(ctx, c, held | {c})
    out = {ctx.ev(c).author}
    hear = {}
    for add in ctx.record(c).get("heard", {}):
        b = ctx.body(add)
        if b is not None:
            hear[b.device] = b.keys()
    for i in w.view - {c}:
        e = ctx.ev(i)
        if _counts(ctx, c, w, i):
            out.add(e.author)
        elif w.structural.get(i) == "UntrustedSigner" and e.author in hear \
                and I.signature_ok(e, [hear[e.author]]) is True and not ctx.bad_follows(i) \
                and all(not ctx.concurrent(x, c) for x in ctx.reach(i) if ctx.is_checkpoint(x)):
            out.add(e.author)
    return out


def stable(ctx: LCtx, c: bytes, held) -> bool:
    k = ("stable", c, frozenset(held))
    if k not in ctx.memo:
        held = set(held)
        ctx.memo[k] = electorate(ctx, c, held) <= votes(ctx, c, held)
    return ctx.memo[k]


class World:
    def __init__(self, status, chain, lst):
        self.status, self.chain, self.list = status, chain, lst


def effective_chain(ctx: LCtx, held, base) -> list:
    chain = [base] if base is not None else []
    current = base
    while True:
        cands = [i for i in held if ctx.is_checkpoint(i) and i != current
                 and ctx.record(i)["previous"] == current
                 and (current is None or ctx.follows(i, current)) and validity(ctx, i)[0]
                 and stable(ctx, i, {x for x in held if x == i or ctx.follows(x, i)})]
        if not cands:
            return chain
        current = min(cands)
        chain.append(current)


def judge(ctx: LCtx, held, base: bytes | None = None) -> World:
    held = set(held)
    k = ("judge", frozenset(held), base)
    if k in ctx.memo:
        return ctx.memo[k]
    chain = effective_chain(ctx, held, base)
    status: dict = {}
    if not chain:
        lst = _list(ctx, ctx.log, held, _presets_outside(ctx, held))
        out = World(dict(lst.status), [], lst)
        ctx.memo[k] = out
        return out
    if base is None:
        status.update(judge(ctx, ctx.log.anc[chain[0]]).status)
    for a, b in zip(chain, chain[1:]):
        members = {x for x in held if ctx.follows(x, a)}
        w = world(ctx, a, world_log(ctx, a, members).anc[b] | {b})
        status.update({i: v for i, v in w.status.items() if i != a})
        status[a] = (True, "checkpoint", None)
    last = chain[-1]
    lst = world(ctx, last, {x for x in held if x == last or ctx.follows(x, last)})
    # The events before the checkpoint in effect: a holder keeps them or
    # their IDs, so a space's ref to one resolves (roster.md, section 3.15.8).
    lst.before_checkpoint = frozenset(ctx.log.anc[last])
    status.update({i: v for i, v in lst.status.items() if i != last})
    status[last] = (True, "checkpoint", None)
    for i in held:
        status.setdefault(i, (False, LATE, None))
    if base is not None and rival_checkpoints(ctx, base):
        # identity.md, "List checkpoints", a rival: were it valid it would
        # take the place of a checkpoint of base's chain, which only the
        # forgotten past tells, so the holder holds base and everything
        # after it pending.
        for i in held:
            if i == base or ctx.follows(i, base):
                status[i] = (False, "Pending", None)
    out = World(status, chain, lst)
    ctx.memo[k] = out
    return out


def rival_checkpoints(ctx: LCtx, base: bytes) -> set:
    """identity.md, "List checkpoints", a rival, at a holder that forgot
    under `base`: a list checkpoint concurrent with it, kept alone as a
    late event, that names base's predecessor or one base's follows reach,
    or none; whose ID is smaller than that of a checkpoint of base's chain
    it could replace; that passes section 3.1; and that is stable in what
    the holder holds after it. One whose record names an add the holder
    does not hold it cannot tell, and counts as a rival."""
    previous = ctx.record(base)["previous"]
    reached = {x for x in ctx.reach(base)}
    pool = ctx.readable if ctx.readable is not None else set(ctx.log.events)
    out = set()
    for x in pool:
        if x == base or not ctx.is_checkpoint(x) or not ctx.concurrent(x, base):
            continue
        q = ctx.record(x)["previous"]
        if q is None:
            replaceable = {base} | reached
        elif q == previous or q in reached:
            replaceable = {base} | {y for y in reached if y != q and ctx.below(q, y)}
        else:
            continue
        if not any(x < y for y in replaceable) or ctx.bad_follows(x):
            continue
        if not all(ctx.can_read(m["add"]) for m in ctx.record(x)["members"]):
            out.add(x)
            continue
        after = {y for y in pool if y == x or ctx.follows(y, x)}
        # Judged apart, so that what it cannot tell leaves no verdict behind.
        apart = copy.copy(ctx)
        apart.memo = {}
        try:
            if stable(apart, x, after):
                out.add(x)
        except (AssertionError, KeyError, SpecError):
            out.add(x)  # it needs an event the holder forgot: it cannot tell
    return out


def kept(ctx: LCtx, base: bytes, final) -> tuple[set, set]:
    """What a holder that forgot under `base` keeps (identity.md, "List
    checkpoints", Forgetting): the checkpoint and the events after it,
    which it judges; and, as events alone, the list's first event, the adds
    its record names, the checkpoints its follows reach and the late
    events."""
    held = {i for i in final if i == base or ctx.follows(i, base)}
    alone = {ctx.log.genesis}
    for m in ctx.record(base)["members"]:
        alone.add(m["add"])
        if m["rooting"]:
            alone.add(m["rooting"])
    alone |= set(ctx.record(base).get("heard", {}))
    alone |= {x for x in ctx.reach(base) if x in ctx.log.events}
    alone |= {i for i in final if i not in held and i not in ctx.log.anc[base]}
    return held, alone


def forgetting(log: Log, base: bytes, final) -> tuple[LCtx, set]:
    held, alone = kept(LCtx(log), base, final)
    return LCtx(log, trusted={base}, held=held, alone=alone), held


# ---------------------------------------------------------------------------
# Building lists with checkpoints.


def attach(p: I.Person) -> None:
    hist = p.hist
    p.checkpoints = getattr(p, "checkpoints", set())
    ctx_body = {}

    def follows_of(i):
        if i not in ctx_body:
            try:
                ctx_body[i] = I.check_body(hist.log.events[i]).follows
            except SpecError:
                ctx_body[i] = ()
        return ctx_body[i]

    def reach(i):
        out = set()
        for c in follows_of(i):
            out.add(c)
            out |= reach(c)
        return out

    def below(x, y):
        return x == y or x in reach(y)

    def follows_for(parents):
        found = set()
        for q in parents:
            if q in p.checkpoints:
                found.add(q)
            found |= set(follows_of(q))
        return sorted(x for x in found if not any(x != y and below(x, y) for y in found))

    def body_hook(body, parents):
        value = uncbor(body)
        f = follows_for(parents)
        if f:
            value[I.B_FOLLOWS] = f
        else:
            value.pop(I.B_FOLLOWS, None)
        return cbor(value)

    def fence(name, w):
        anc = hist.log.anc
        ctx = LCtx(p.log)
        chain = set(judge(ctx, set(w)).chain) if any(x in p.checkpoints for x in w) else set()
        # A contested checkpoint not in effect, and what follows it, is never
        # cited: citing it would vote for it (identity.md, "Clients").
        bad = {x for x in w if x in p.checkpoints and x not in chain
               and contested(p, name, x, w)}
        out = {x for x in w if x in bad or anc[x] & bad}
        c = followed(p, name, w)
        if c is None:
            return out
        return out | {x for x in w if x != c and x not in anc[c] and c not in anc[x]}

    hist.body_hook = body_hook
    hist.fence = fence


def followed(p: I.Person, name: str, w) -> bytes | None:
    """roster.md, "Clients", Following, read for a list: the latest valid
    checkpoint of the device's view whose chain it is on: the last in
    effect, or a valid one waiting for votes whose predecessor is that one,
    the one the device's own events already follow first, else the smallest
    ID."""
    hist = p.hist
    w = set(w)
    if not any(c in p.checkpoints for c in w):
        return None
    ctx = LCtx(p.log)
    wld = judge(ctx, w)
    current = wld.chain[-1] if wld.chain else None
    cands = sorted(c for c in w if ctx.is_checkpoint(c) and c != current
                   and ctx.record(c)["previous"] == current
                   and (current is None or ctx.follows(c, current))
                   and validity(ctx, c)[0] and not contested(p, name, c, w))
    if not cands:
        return current
    author = hist.device(name)
    mine = [i for i in w if hist.log.events[i].author == author]
    if mine:
        last = max(mine, key=lambda i: hist.log.events[i].seq)
        own = [c for c in cands if c == last or ctx.follows(last, c)]
        if own:
            return own[0]
    return cands[0]


def contested(p: I.Person, name: str, c: bytes, w) -> bool:
    """identity.md, "List checkpoints", Clients: device `name`, whose view
    is `w`, does not follow list checkpoint c when c's record hears it
    (revoked only by members it outranks), or when its view holds a valid
    revoke concurrent with c that names c's author or a device c's record
    keeps, signed by a member that outranks its target."""
    w = frozenset(w)
    memo = p.__dict__.setdefault("_contested", {})
    k = (name, c, w)
    if k in memo:
        return memo[k]
    ctx = LCtx(p.log)
    rec = ctx.record(c)
    me = p.hist.device(name)
    out = any(ctx.body(add) is not None and ctx.body(add).device == me
              for add in rec.get("heard", {}))
    if not out:
        anc = p.log.anc
        rivals = [x for x in w if x != c and x not in anc[c] and c not in anc[x]]
        if rivals:
            lst = _list(ctx, ctx.log, w, _presets_outside(ctx, w))
            kept = {ctx.body(m["add"]).device for m in rec["members"]} | {ctx.ev(c).author}
            for x in rivals:
                b = lst.bodies.get(x)
                if b is None or b.action != I.REVOKE or x not in lst.valid \
                        or b.device not in kept:
                    continue
                S = lst.state(lst.place(x, lst.valid))
                if _outranks(lst, S, p.log.events[x].author, b.device):
                    out = True
    memo[k] = out
    return out


_CHAIN = object()


def make_checkpoint(p: I.Person, by: str, label: str, *, fence: bool = True, previous=_CHAIN,
                    **kw) -> bytes:
    """`by` checkpoints its list. A dishonest device may cite every head
    (`fence=False`) and name any `previous`, its record derived from that
    predecessor's world over its past, or its whole past for None."""
    attach(p)
    hist = p.hist
    w = set(hist.view[by])
    author = hist.device(by)
    mine = [i for i in w if hist.log.events[i].author == author]
    last = max(mine, key=lambda i: (hist.log.events[i].seq, i), default=None)
    parents = hist.parents_for(by, w, last, fence)
    past = set()
    for q in parents:
        past |= hist.log.anc[q] | {q}
    ctx = LCtx(p.log)
    wld = judge(ctx, past)
    if previous is _CHAIN:
        previous = wld.chain[-1] if wld.chain else None
    if previous is None:
        lst = wld.list if not wld.chain else _list(ctx, ctx.log, past,
                                                   _presets_outside(ctx, past))
    else:
        members = {x for x in past if ctx.follows(x, previous)}
        held = {previous}
        for q in parents:
            if q == previous or ctx.follows(q, previous):
                held |= world_log(ctx, previous, members).anc[q] | {q}
        lst = world(ctx, previous, held)
    record = I.encode_list_record(record_of(ctx, lst, previous))
    body = cbor({I.B_VERSION: I.ENTRY_VERSION, I.B_ACTION: I.LIST_CHECKPOINT,
                 I.B_RECORD: record})
    i = p._act(by, body, label, parents=parents, **kw)
    p.checkpoints.add(i)
    return i


def ack(p: I.Person, by: str, label: str, **kw) -> bytes:
    attach(p)
    return p._act(by, cbor({I.B_VERSION: I.ENTRY_VERSION, I.B_ACTION: I.ACK}), label, **kw)


# ---------------------------------------------------------------------------
# The model check.

NAMES = ["D0", "D1", "D2", "D3", "D4", "D5"]
AGENT_NAMES = ["R1", "R2", "R3"]  # devices added through an agent, or by those


def random_list(seed: int, *, checkpoints: bool = True, steps: int = 30,
                adversarial: bool = True):
    rng = random.Random(seed)
    # A dishonest device, drawn apart: it takes another's view and
    # checkpoints citing every head, naming the last in effect, an earlier
    # checkpoint, or none, as its predecessor.
    adv = random.Random(seed * 7907 + 5) if adversarial else None
    p = I.Person("D0", f"lists/{seed}")
    attach(p)
    active, revoked, agent = {"D0"}, set(), set()
    snaps = []
    ops: dict = {}
    if seed % 2:
        # A person that named an agent, which added devices, one of them
        # confirmed: they are list members when checkpoints are made.
        p.add("D0", "D1", I.DEVICE, "D0 adds D1")
        p.add("D0", "AG", I.AGENT, "D0 names the agent")
        p.hist.sync("D0", "D1", "AG")
        p.add("AG", "R1", I.DEVICE, "the agent adds R1")
        p.hist.sync("D0", "D1", "AG", "R1")
        p.add("R1", "R2", I.DEVICE, "R1 adds R2")
        p.hist.sync("D0", "D1", "AG", "R1", "R2")
        if seed % 4 == 1:
            p.confirm("D0", "R1", "D0 confirms R1")
        p.hist.sync("D0", "D1", "AG", "R1", "R2")
        active |= {"D1", "AG", "R1", "R2"}
        agent |= {"R1", "R2"}
        ops["agent"] = 1
    # Two groups of the person's devices, cut off from each other, that each
    # checkpoint and revoke the other (before or after their checkpoint):
    # two electorates with no device in common. Drawn apart too.
    spl = random.Random(seed * 7907 + 11) if adversarial and checkpoints else None
    # A revoked device that, on its view from before its revocation, revokes
    # the others and checkpoints: alone, with another revoked device, or
    # with a device it adds there. Drawn apart too.
    atk = random.Random(seed * 7907 + 17) if adversarial and checkpoints else None
    p.attacks = []
    for step in range(steps):
        if atk is not None and atk.random() < 0.08 and revoked & set(NAMES) \
                and len(p.attacks) < 2:
            try:
                if _takeover(p, atk, sorted(revoked & set(NAMES)), step):
                    ops["takeover"] = ops.get("takeover", 0) + 1
                    snaps.append({n: set(v) for n, v in p.hist.view.items()})
            except (SpecError, KeyError, ValueError, AssertionError):
                pass
        if spl is not None and spl.random() < 0.06 and "split" not in ops:
            try:
                if _split(p, spl, sorted(active & set(NAMES)), step):
                    ops["split"] = ops.get("split", 0) + 1
                    snaps.append({n: set(v) for n, v in p.hist.view.items()})
            except (SpecError, KeyError, ValueError, AssertionError):
                pass
        by = rng.choice(sorted(active))
        op = rng.random()
        if 0.42 <= op < 0.68 and rng.random() < 0.75 and active & set(NAMES):
            # checkpoints and acks come mostly from the person's own devices
            by = rng.choice(sorted(active & set(NAMES)))
        try:
            if op < 0.18:
                if "AG" in active and rng.random() < 0.5:
                    # the agent, or a device rooted in it, adds a device
                    by = rng.choice(sorted(({"AG"} | agent) & active))
                pool = AGENT_NAMES if by in agent or p.kinds.get(by) == I.AGENT else NAMES
                who = next((n for n in pool if n not in active and n not in revoked), None)
                if who is None:
                    continue
                p.add(by, who, I.DEVICE, f"{step}: {by} adds {who}")
                p.hist.sync(by, who)
                active.add(who)
                if pool is AGENT_NAMES:
                    agent.add(who)
                    # an add rooted in an agent is relayed to every member at
                    # once (ext-recovery-agent.md, "Relay and veto")
                    p.hist.sync(*sorted(active))
                ops["add"] = ops.get("add", 0) + 1
            elif op < 0.23:
                # a device names an agent, which adds devices rooted in it
                if "AG" in p.kinds:
                    continue
                p.add(by, "AG", I.AGENT, f"{step}: {by} names the agent")
                active.add("AG")
                p.hist.sync(*sorted(active))
                ops["agent"] = ops.get("agent", 0) + 1
            elif op < 0.28 and agent & active:
                # a device of the person confirms one rooted in the agent
                who = rng.choice(sorted(agent & active))
                by = rng.choice(sorted((active & set(NAMES)) or {"D0"}))
                p.confirm(by, who, f"{step}: {by} confirms {who}")
                ops["confirm"] = ops.get("confirm", 0) + 1
            elif op < 0.36 and len(active) > 1:
                who = rng.choice(sorted(active - {by}))
                p.revoke(by, who, f"{step}: {by} revokes {who}")
                active.discard(who)
                revoked.add(who)
                ops["revoke"] = ops.get("revoke", 0) + 1
            elif op < 0.42 and revoked:
                # a revoked device acts on its old view, as a late branch
                who = rng.choice(sorted(revoked))
                target = rng.choice(sorted(set(NAMES[:4]) - {who}))
                if target in p.kinds:
                    p.revoke(who, target, f"{step}: {who} revokes {target} late")
                    ops["late"] = ops.get("late", 0) + 1
            elif op < 0.54 and checkpoints:
                if adv is not None and adv.random() < 0.35:
                    other = adv.choice(sorted(n for n in p.hist.view if p.hist.view[n]))
                    p.hist.view[by] |= p.hist.view[other]
                    named = sorted(c for c in p.hist.view[by] if c in p.checkpoints)
                    pick = adv.random()
                    kw = {} if pick < 0.5 or not named else \
                        {"previous": None} if pick < 0.7 else {"previous": adv.choice(named)}
                    make_checkpoint(p, by, f"{step}: {by} checkpoints, unfenced", fence=False,
                                    **kw)
                    ops["rogue checkpoint"] = ops.get("rogue checkpoint", 0) + 1
                else:
                    make_checkpoint(p, by, f"{step}: {by} checkpoints")
                    ops["checkpoint"] = ops.get("checkpoint", 0) + 1
            elif op < 0.60 and checkpoints:
                # a round of votes: the person's devices take the proposer's
                # view and ack
                for name in sorted(active - {"AG"}):
                    p.hist.sync(name, by)
                    try:
                        ack(p, name, f"{step}: {name} votes")
                    except (SpecError, KeyError, ValueError, AssertionError):
                        pass
                ops["votes"] = ops.get("votes", 0) + 1
            elif op < 0.68 and checkpoints:
                other = rng.choice(sorted(n for n in p.hist.view if p.hist.view[n]))
                p.hist.sync(by, other)
                ack(p, by, f"{step}: {by} syncs with {other} and acks")
                ops["ack"] = ops.get("ack", 0) + 1
            elif op < 0.71:
                author = p.hist.device(by)
                mine = sorted((p.log.events[i].seq, i) for i in p.hist.view[by]
                              if p.log.events[i].author == author)
                if len(mine) >= 2:
                    seq, old = mine[-2]
                    prev = p.log.events[old].prev
                    p._act(by, cbor({I.B_VERSION: I.ENTRY_VERSION, I.B_ACTION: I.ACK}),
                           f"{step}: {by} forks at {seq}", seq=seq, prev=prev,
                           view=p.log.anc[old] | {prev}, fence=False)
                    ops["fork"] = ops.get("fork", 0) + 1
            else:
                pool = sorted(n for n in p.hist.view if p.hist.view[n])
                if len(pool) >= 2:
                    a, b = rng.sample(pool, 2)
                    p.hist.sync(a, b)
        except (SpecError, KeyError, ValueError, AssertionError):
            continue
        snaps.append({n: set(v) for n, v in p.hist.view.items()})
    p.hist.sync(*list(p.hist.view))
    return p, snaps, ops


def _takeover(p: I.Person, rng: random.Random, revoked: list, step: int) -> bool:
    """A backdated list checkpoint: a revoked device, on its stale view,
    revokes every other active device it sees there, then checkpoints
    citing its whole view; sometimes with a second revoked device on the
    same view, or with a device it adds there first. Records the attack."""
    attacker = rng.choice(revoked)
    view = set(p.hist.view[attacker])
    ctx = LCtx(p.log)
    lst = judge(ctx, view).list
    me = p.hist.device(attacker)
    S = lst.members
    mine = S.get(me)
    if mine is None or not mine.active or mine.kind != I.DEVICE or mine.rooted != I.NONE:
        return False
    helpers = [attacker]
    mode = rng.choice(["alone", "colluder", "sybil"])
    if mode == "colluder" and len(revoked) > 1:
        other = rng.choice([x for x in revoked if x != attacker])
        p.hist.view[other] = set(view) | p.hist.view[other]
        helpers.append(other)
        p.hist.view[attacker] |= p.hist.view[other]
    elif mode == "sybil" and "D5" not in p.kinds:
        p.add(attacker, "D5", I.DEVICE, f"{step}: {attacker} adds D5, backdated")
        p.hist.sync(attacker, "D5")
        helpers.append("D5")
    names = {p.hist.device(n): n for n in p.hist.view}
    victims = [names[d] for d, m in sorted(S.items()) if d in names and m.active
               and m.kind == I.DEVICE and names[d] not in helpers]
    if not victims:
        return False
    for k, v in enumerate(victims):
        by = helpers[k % len(helpers)]
        p.hist.sync(*helpers)
        p.revoke(by, v, f"{step}: {by} revokes {v}, backdated")
    p.hist.sync(*helpers)
    c = make_checkpoint(p, attacker, f"{step}: {attacker} checkpoints, backdated", fence=False)
    for hlp in helpers[1:]:
        p.hist.sync(hlp, attacker)
        ack(p, hlp, f"{step}: {hlp} votes for the backdated checkpoint", fence=False)
    junior = any(_outranks(lst, S, p.hist.device(v), me) for v in victims)
    p.attacks.append({"checkpoint": c, "attackers": helpers, "victims": victims,
                      "mode": mode if len(helpers) > 1 else "alone", "junior": junior})
    return True


def _split(p: I.Person, rng: random.Random, devices: list, step: int) -> bool:
    """The person's unrooted devices split in two groups that see only each
    other. In each, one device checkpoints, and a device of the group
    revokes every device of the other group, before the checkpoint (any
    device) or after it (another than its author, so that it excuses);
    every device of the group then acks. Each checkpoint can take effect in
    its group's view with an electorate disjoint from the other's."""
    if len(devices) < 2:
        return False
    devices = list(devices)
    rng.shuffle(devices)
    k = rng.randint(1, len(devices) - 1)
    groups = [devices[:k], devices[k:]]
    for g in groups:
        p.hist.sync(*g) if len(g) > 1 else None
    for g, other in ((groups[0], groups[1]), (groups[1], groups[0])):
        after = len(g) > 1 and rng.random() < 0.5
        author = g[0]
        remover = g[1] if after else rng.choice(g)
        if not after:
            for o in other:
                p.revoke(remover, o, f"{step}: {remover} revokes {o}, cut off")
            if len(g) > 1:
                p.hist.sync(*g)
        make_checkpoint(p, author, f"{step}: {author} checkpoints, cut off")
        if len(g) > 1:
            p.hist.sync(*g)
        if after:
            for o in other:
                p.revoke(remover, o, f"{step}: {remover} revokes {o} after the checkpoint")
            p.hist.sync(*g)
        for d in g:
            if d != author:
                p.hist.sync(d, author)
                ack(p, d, f"{step}: {d} votes, cut off")
        if len(g) > 1:
            p.hist.sync(*g)
    return True


def _disjoint(ctx: LCtx, a: bytes, b: bytes, final) -> bool:
    """Two concurrent checkpoints whose electorates share no device."""
    ea = electorate(ctx, a, {x for x in final if x == a or ctx.follows(x, a)})
    eb = electorate(ctx, b, {x for x in final if x == b or ctx.follows(x, b)})
    return ctx.concurrent(a, b) and not (ea & eb)


def _vouching(lst: I.DeviceList) -> list:
    """What a verifier needs of each active list member to vouch for it:
    its kind, its rootedness, its agent and the add whose first sight starts
    its waiting period (ext-recovery-agent.md)."""
    return sorted((d, m.kind, m.rooted, m.agent_root, tuple(m.agent_adds[:1]))
                  for d, m in lst.active_members().items())


def check_list(seed: int, *, checkpoints: bool = True) -> dict:
    """(i) a holder that forgot, reading only what it keeps, agrees with one
    that kept everything on every verdict, the active members and what a
    verifier vouches by; (ii) chains grow by prefix; (iii) no checkpoint, no
    change."""
    p, snaps, ops = random_list(seed, checkpoints=checkpoints)
    ctx = LCtx(p.log)
    final = set(p.log.events)
    full = judge(ctx, final)
    out = {"events": len(final), "checkpoints": len(getattr(p, "checkpoints", ())),
           "effective": len(full.chain), "forgetters": 0, "compared": 0,
           "late": sum(1 for v in full.status.values() if v[1] == LATE),
           "agent_rooted_kept": 0, "confirmed_kept": 0}
    out["classes"] = {}
    for v in full.status.values():
        name = "valid" if v[0] else v[1]
        out["classes"][name] = out["classes"].get(name, 0) + 1
    out["ops"] = ops
    if not getattr(p, "checkpoints", None):
        plain = I.DeviceList(p.log, final)
        assert dict(plain.status) == full.status, ("(iii) a list differs", seed)
        out["plain"] = 1
    # (vi) A backdated checkpoint by devices that a victim outranks never
    # takes effect, unless a heard victim voted for it (a dishonest step).
    out["attacks"] = {}
    for a in getattr(p, "attacks", ()):
        c = a["checkpoint"]
        won = c in full.chain
        name = f"{a['mode']}, {'junior' if a['junior'] else 'senior'}"
        if won and a["junior"]:
            after = {x for x in final if x == c or ctx.follows(x, c)}
            heard_devices = {ctx.body(x).device for x in ctx.record(c).get("heard", {})}
            assert heard_devices & votes(ctx, c, after), \
                ("(vi) a junior's backdated list checkpoint took effect", seed, p.hist.name(c))
            name += ", a victim voted"
        out["attacks"].setdefault(name, [0, 0])
        out["attacks"][name][0] += 1
        out["attacks"][name][1] += won
    seen = set()
    for snap in snaps:
        for name, view in sorted(snap.items()):
            if not view or not p.log.closed(view):
                continue
            w = judge(ctx, view)
            if w.chain and full.chain[:len(w.chain)] != w.chain:
                # (ii) A chain moves only to a smaller ID, at two concurrent
                # checkpoints with electorates that share no device
                # (identity.md, "List checkpoints", Effect).
                n = next((j for j, (a, b) in enumerate(zip(w.chain, full.chain)) if a != b),
                         len(full.chain))
                assert n < len(full.chain) and full.chain[n] < w.chain[n] and _disjoint(
                    ctx, full.chain[n], w.chain[n], final), ("(ii) lists", seed, name)
                out["switched"] = out.get("switched", 0) + 1
            if w.chain and w.chain[-1] not in seen:
                base = w.chain[-1]
                seen.add(base)
                fctx, held = forgetting(p.log, base, final)
                forgot = judge(fctx, held, base)
                diff = [(p.hist.name(i), full.status[i], forgot.status[i]) for i in held
                        if full.status[i] != forgot.status[i]]
                if rival_checkpoints(fctx, base):
                    # A rival it cannot judge: it holds pending, and never
                    # decides otherwise.
                    assert all(b[1] == "Pending" for _, a, b in diff), \
                        ("(i) a list holder with a rival decides", seed, name, diff)
                    out["rival_pending"] = out.get("rival_pending", 0) + 1
                    continue
                assert base in full.chain, ("(i) overtaken without a rival", seed, name)
                assert not diff, ("(i) a list holder that forgot disagrees", seed, name, diff)
                assert _vouching(full.list) == _vouching(forgot.list), ("vouching", seed)
                rec = ctx.record(base)
                out["agent_rooted_kept"] += sum(1 for m in rec["members"] if m["rooting"])
                out["confirmed_kept"] += sum(1 for m in rec["members"]
                                             if m["confirmed"] and m["root"] != I.NONE)
                out["forgetters"] += 1
                out["compared"] += len(held)
    return out


def model_check(seeds, quiet=True) -> dict:
    total: dict = {"histories": 0, "plain": 0, "classes": {}, "ops": {}}
    for seed in seeds:
        res = check_list(seed, checkpoints=seed % 4 != 0)
        total["histories"] += 1
        for k, v in res.items():
            if k == "attacks":
                for name, (n, won) in v.items():
                    row = total.setdefault(k, {}).setdefault(name, [0, 0])
                    row[0] += n
                    row[1] += won
            elif isinstance(v, dict):
                for name, n in v.items():
                    total[k][name] = total[k].get(name, 0) + n
            else:
                total[k] = total.get(k, 0) + v
        if not quiet:
            print(seed, res, file=sys.stderr)
    return total


def _scenario(prefix: str):
    """D0 adds D1 and D2 and names an agent, which adds R1 and R2; D0
    confirms R1. D2 revokes D1 while D0, unaware, checkpoints. D1, the
    confirmed R1 and D2 ack after it, so D2's revocation is late; R2, still
    rooted in the agent, is not waited for and its add's rooting is kept."""
    p = I.Person("D0", prefix)
    attach(p)
    p.add("D0", "D1", I.DEVICE, "D0 adds D1")
    p.add("D0", "D2", I.DEVICE, "D0 adds D2")
    p.add("D0", "AG", I.AGENT, "D0 names the agent")
    p.hist.sync("D0", "AG")
    p.add("AG", "R1", I.DEVICE, "the agent adds R1")
    p.add("AG", "R2", I.DEVICE, "the agent adds R2")
    p.hist.sync("D0", "AG", "D1", "D2", "R1", "R2")
    p.confirm("D0", "R1", "D0 confirms R1")
    p.hist.sync("D0", "D1", "D2", "R1")
    late = p.revoke("D2", "D1", "D2 revokes D1, unaware")
    cp = make_checkpoint(p, "D0", "D0 checkpoints")
    p.hist.sync("D0", "D1", "R1", "R2")
    a1 = ack(p, "D1", "D1 acks")
    ar = ack(p, "R1", "R1, confirmed, acks")
    p.hist.sync("D0", "D1", "D2", "R1", "R2")
    a2 = ack(p, "D2", "D2 acks")
    p.hist.sync("D0", "D1", "D2", "R1", "R2")
    again = p.revoke("D2", "D1", "D2 revokes D1 again")
    return p, {"late": late, "checkpoint": cp, "ack1": a1, "ack_r1": ar, "ack2": a2,
               "again": again}


def _forged(p: I.Person, by: str, label: str) -> bytes:
    """A checkpoint by `by` whose ML-DSA-65 half does not verify: its last
    signature byte flipped after signing."""
    import events as E
    real = E.sign_fields

    def flip(fields, signer):
        outer = uncbor(real(fields, signer))
        sig = outer[1][:-1] + bytes([outer[1][-1] ^ 1])
        return cbor([outer[0], sig])
    E.sign_fields = flip
    try:
        return make_checkpoint(p, by, label, unchecked=True)
    finally:
        E.sign_fields = real


def _signatures(prefix: str):
    """Two checkpoints over D0 and D1's list: one whose signature fails, and
    one by a device that no add of its past names."""
    p = I.Person("D0", prefix)
    attach(p)
    p.add("D0", "D1", I.DEVICE, "D0 adds D1")
    p.hist.sync("D0", "D1")
    forged = _forged(p, "D1", "D1 checkpoints, its signature broken")
    p.hist.view["X"] = set(p.hist.view["D0"]) - {forged}
    stranger = make_checkpoint(p, "X", "X, on no list, checkpoints")
    return p, {"forged": forged, "stranger": stranger}


def _record_refusals(rec: bytes) -> list:
    """Records refused when a list checkpoint is read alone (section 3.1,
    step 2): each case the record bytes and the class."""
    value = uncbor(rec)
    out = []

    def case(name, v):
        data = cbor(v)
        try:
            I.read_list_record(data)
            error = None
        except SpecError as e:
            error = e.error
        out.append({"name": name, "record": h(data), "error": error})
    case("version 2", {**value, 1: 2})
    m = value[4][0]
    case("a member entry of five elements", {**value, 4: [m[:5]] + value[4][1:]})
    rooted = next(x for x in value[4] if x[1] == I.AGENT_ROOTED)
    plain = next(x for x in value[4] if x[1] == I.NONE)
    case("an agent-rooted member without its rooting add",
         {**value, 4: [x if x is not rooted else x[:5] + [b""] for x in value[4]]})
    case("an agent-rooted member without its agent",
         {**value, 4: [x if x is not rooted else x[:2] + [b""] + x[3:] for x in value[4]]})
    case("a rooting add on a member that is not rooted in an agent",
         {**value, 4: [x if x is not plain else x[:5] + [rooted[5]] for x in value[4]]})
    case("an agent named for a member that is not rooted in an agent",
         {**value, 4: [x if x is not plain else x[:2] + [rooted[2]] + x[3:] for x in value[4]]})
    return out


def _stolen(prefix: str):
    """identity.md, "List checkpoints", Effect: a stolen device excuses no
    one from its own checkpoint. D0 revokes D2. D2, on its view before
    that, checkpoints and revokes D0 and D1 after it: the checkpoint waits
    for D0 and D1, never takes effect, and D0's revocation stands."""
    p = I.Person("D0", prefix)
    attach(p)
    p.add("D0", "D1", I.DEVICE, "D0 adds D1")
    p.add("D0", "D2", I.DEVICE, "D0 adds D2")
    p.hist.sync("D0", "D1", "D2")
    old = set(p.hist.view["D2"])
    revoke = p.revoke("D0", "D2", "D0 revokes D2, stolen")
    p.hist.view["D2"] = old
    cp = make_checkpoint(p, "D2", "D2 checkpoints on its old view")
    r0 = p.revoke("D2", "D0", "D2 revokes D0 after its checkpoint")
    r1 = p.revoke("D2", "D1", "D2 revokes D1 after its checkpoint")
    p.hist.sync(*list(p.hist.view))
    ctx = LCtx(p.log)
    full = judge(ctx, set(p.log.events))
    assert validity(ctx, cp)[0] and full.chain == [], [p.hist.name(c) for c in full.chain]
    assert full.status[revoke][0], full.status[revoke]
    waits = electorate(ctx, cp, set(p.log.events)) - votes(ctx, cp, set(p.log.events))
    assert waits == {p.hist.device("D0"), p.hist.device("D1")}
    return p, {"revoke": revoke, "checkpoint": cp, "r0": r0, "r1": r1}, full, waits


def self_test() -> None:
    _stolen("lists/self-test/stolen")
    _disjoint_checks("lists/self-test/disjoint")
    _takeover_checks("lists/self-test/takeover")
    p, ev = _scenario("lists/self-test")
    ctx = LCtx(p.log)
    full = judge(ctx, set(p.log.events))
    assert full.chain == [ev["checkpoint"]]
    assert full.status[ev["late"]][1] == LATE and full.status[ev["again"]][0]
    # The confirmed R1 is waited for; R2, rooted in the agent, and the agent
    # are not.
    held_before = {i for i in p.log.events if i != ev["ack_r1"]
                   and ev["ack_r1"] not in p.log.anc[i]}
    assert judge(ctx, held_before).chain == []
    names = {p.hist.device(n) for n in ("D0", "D1", "D2", "R1")}
    assert electorate(ctx, ev["checkpoint"], {ev["checkpoint"]}) == names
    rec = ctx.record(ev["checkpoint"])
    r2 = next(m for m in rec["members"] if ctx.body(m["add"]).device == p.hist.device("R2"))
    assert r2["rooting"] == p.hist.by_name("the agent adds R2") and not r2["confirmed"]
    fctx, held = forgetting(p.log, ev["checkpoint"], set(p.log.events))
    forgot = judge(fctx, held, ev["checkpoint"])
    assert all(full.status[i] == forgot.status[i] for i in held)
    assert _vouching(full.list) == _vouching(forgot.list)
    again = {**rec, "members": [{**m, "device": ctx.body(m["add"]).device}
                                for m in rec["members"]]}
    assert I.encode_list_record(again) == ctx.body(ev["checkpoint"]).record_bytes
    # Signatures are checked on a checkpoint's own past.
    q, sv = _signatures("lists/self-test/signatures")
    qctx = LCtx(q.log)
    assert validity(qctx, sv["forged"])[1] == "BadSignature"
    assert validity(qctx, sv["stranger"])[1] == "UntrustedSigner"
    assert {c["name"]: c["error"] for c in _record_refusals(
        ctx.body(ev["checkpoint"]).record_bytes)} == {
        "version 2": "UnsupportedVersion",
        "a member entry of five elements": "Malformed",
        "an agent-rooted member without its rooting add": "Malformed",
        "an agent-rooted member without its agent": "Malformed",
        "a rooting add on a member that is not rooted in an agent": "Malformed",
        "an agent named for a member that is not rooted in an agent": "Malformed"}
    model_check(range(1, 6))


def _disjoint_scenario(prefix: str, recovery: bool = True):
    """identity.md, "List checkpoints", Effect: D0 adds D1, D2 and D3 and,
    with `recovery`, a recovery key K. D0 and D1 see only each other, as do
    D2, D3 and K. D0 checkpoints (c1) and D1 revokes D2 and D3 after it,
    excusing them, D1 outranking both; D2 checkpoints (c2), and D3 revokes
    D0 and D1 after it, which excuses neither, D3 being junior to both; with
    K, K revokes them too, and excuses both, a recovery key outranking every
    device. So c2 takes effect in its group's view only with K. Once the
    groups meet, the smaller ID takes effect at every holder; a holder that
    forgot under the other holds a rival, and holds what it judges
    pending."""
    p = I.Person("D0", prefix)
    attach(p)
    for d in ("D1", "D2", "D3"):
        p.add("D0", d, I.DEVICE, f"D0 adds {d}")
    if recovery:
        p.add("D0", "K", I.RECOVERY, "D0 adds the recovery key K")
    group = ("D2", "D3", "K") if recovery else ("D2", "D3")
    p.hist.sync("D0", "D1", *group)
    c1 = make_checkpoint(p, "D0", "D0 checkpoints (c1)")
    c2 = make_checkpoint(p, "D2", "D2 checkpoints, cut off (c2)")
    p.hist.sync("D0", "D1")
    p.hist.sync(*group)
    for x in ("D2", "D3"):
        p.revoke("D1", x, f"D1 revokes {x} after c1")
    for x in ("D0", "D1"):
        p.revoke("D3", x, f"D3 revokes {x} after c2")
    if recovery:
        p.hist.sync(*group)
        for x in ("D0", "D1"):
            p.revoke("K", x, f"K revokes {x} after c2")
    p.hist.sync(*group)
    group1, group2 = set(p.hist.view["D1"]), set(p.hist.view["D3"])
    p.hist.sync("D0", "D1", *group)
    after = ack(p, "D0", "D0 acks once the groups meet")
    return p, {"c1": c1, "c2": c2, "group1": group1, "group2": group2, "after": after}


def _disjoint_checks(prefix: str) -> dict:
    q, qev = _disjoint_scenario(f"{prefix}/no-recovery", recovery=False)
    qctx = LCtx(q.log)
    assert judge(qctx, qev["group2"]).chain == []
    assert judge(qctx, set(q.log.events)).chain == [qev["c1"]]
    p, ev = _disjoint_scenario(prefix)
    ctx = LCtx(p.log)
    final = set(p.log.events)
    g1, g2 = judge(ctx, ev["group1"]), judge(ctx, ev["group2"])
    assert g1.chain == [ev["c1"]] and g2.chain == [ev["c2"]], (g1.chain, g2.chain)
    assert _disjoint(ctx, ev["c1"], ev["c2"], final)
    full = judge(ctx, final)
    win, lose = sorted((ev["c1"], ev["c2"]))
    assert full.chain == [win] and full.status[lose][1] == LATE
    fl, held = forgetting(p.log, lose, final)
    assert rival_checkpoints(fl, lose) == {win}
    forgot = judge(fl, held, lose)
    assert all(forgot.status[i][1] == "Pending" for i in held)
    wl, wheld = forgetting(p.log, win, final)
    wforgot = judge(wl, wheld, win)
    assert all(wforgot.status[i] == full.status[i] for i in wheld)
    return {"p": p, "ev": ev, "g1": g1, "g2": g2, "full": full, "win": win, "lose": lose,
            "held": held, "forgot": forgot, "wheld": wheld, "wforgot": wforgot}


def _takeover_scenario(prefix: str, kind: str):
    """identity.md, "List checkpoints", Effect, heard devices. D0 adds D1
    and D2, so D0 outranks D1, which outranks D2; with "recovery", D0 adds a
    recovery key K too.

    - "junior": D0 revokes D2; D2, on its view from before, revokes D0 and
      D1 and checkpoints (X), which hears both and waits for them for good;
      D0 checkpoints (H), D1 acks, and H takes effect.
    - "senior": D0 is stolen; D1 revokes it; the thief, on D0's old view,
      revokes D1 and D2 and checkpoints (X), which takes effect on its own
      vote; D1's H hears D0 and waits for it for good.
    - "recovery": D0 is lost; D1 revokes it and checkpoints (H), which hears
      D0; K revokes D0 after H, which excuses it; D2 acks; H takes effect."""
    p = I.Person("D0", f"{prefix}/{kind}")
    attach(p)
    p.add("D0", "D1", I.DEVICE, "D0 adds D1")
    p.add("D0", "D2", I.DEVICE, "D0 adds D2")
    if kind == "recovery":
        p.add("D0", "K", I.RECOVERY, "D0 adds the recovery key K")
    p.hist.sync("D0", "D1", "D2", *(["K"] if kind == "recovery" else []))
    ev = {}
    if kind == "junior":
        old = set(p.hist.view["D2"])
        p.revoke("D0", "D2", "D0 revokes D2")
        p.hist.sync("D0", "D1")
        p.hist.view["D2"] = old
        p.revoke("D2", "D0", "D2 revokes D0, backdated")
        p.revoke("D2", "D1", "D2 revokes D1, backdated")
        ev["X"] = make_checkpoint(p, "D2", "D2 checkpoints, backdated (X)", fence=False)
        ev["H"] = make_checkpoint(p, "D0", "D0 checkpoints (H)")
        p.hist.sync("D0", "D1")
        ack(p, "D1", "D1 votes for H")
    elif kind == "senior":
        old = set(p.hist.view["D0"])
        p.revoke("D1", "D0", "D1 revokes D0, stolen")
        p.hist.sync("D1", "D2")
        ev["H"] = make_checkpoint(p, "D1", "D1 checkpoints (H)")
        p.hist.sync("D1", "D2")
        ack(p, "D2", "D2 votes for H")
        p.hist.view["D0"] = old
        p.revoke("D0", "D1", "the thief revokes D1, backdated")
        p.revoke("D0", "D2", "the thief revokes D2, backdated")
        ev["X"] = make_checkpoint(p, "D0", "the thief checkpoints, backdated (X)", fence=False)
    else:
        p.revoke("D1", "D0", "D1 revokes D0, lost")
        p.hist.sync("D1", "D2", "K")
        ev["H"] = make_checkpoint(p, "D1", "D1 checkpoints (H)")
        p.hist.sync("D1", "D2", "K")
        ack(p, "D2", "D2 votes for H")
        ev["before K"] = set(p.log.events)
        p.hist.sync("D1", "D2", "K")
        p.revoke("K", "D0", "K revokes D0 after H")
    return p, ev


def _takeover_checks(prefix: str) -> dict:
    out = {}
    for kind in ("junior", "senior", "recovery"):
        p, ev = _takeover_scenario(prefix, kind)
        ctx = LCtx(p.log)
        final = set(p.log.events)
        full = judge(ctx, final)
        dev = p.hist.device
        after = {k: {x for x in final if x == c or ctx.follows(x, c)}
                 for k, c in ev.items() if k in ("X", "H")}
        waits = {k: electorate(ctx, ev[k], after[k]) - votes(ctx, ev[k], after[k])
                 for k in after}
        if kind == "junior":
            assert waits["X"] == {dev("D0"), dev("D1")} and full.chain == [ev["H"]]
        elif kind == "senior":
            assert full.chain == [ev["X"]] and waits["H"] == {dev("D0")}
        else:
            before = judge(ctx, ev["before K"])
            assert before.chain == [] and full.chain == [ev["H"]]
        out[kind] = {"p": p, "ev": ev, "full": full, "waits": waits}
    return out


def _sealed_copy(p: I.Person, base: bytes) -> dict:
    """identity.md, "List checkpoints", Spaces: what a sealed copy of a list
    with a checkpoint in effect carries, and the frasil:system snapshot
    state that carries it, with key 5, the IDs of the events forgotten."""
    import units
    fl, held = forgetting(p.log, base, set(p.log.events))
    carried = sorted(fl.readable)
    forgotten = sorted(set(p.log.events) - set(fl.readable))
    state = units.system_snapshot_state([p.log.events[i].signed for i in carried], [],
                                        forgotten={p.id: forgotten})
    assert units.read_system_state(state)[5] == [[p.id, sorted(forgotten)]]
    return {"carries": [p.hist.name(i) for i in sorted(carried, key=p.log.order_key)],
            "forgotten": [p.hist.name(i) for i in sorted(forgotten, key=p.log.order_key)],
            "system_state": h(state)}


def list_checkpoint_vectors() -> dict:
    """identity.json's `list_checkpoints` family."""
    p, ev = _scenario("lists/vector")
    ctx = LCtx(p.log)
    full = judge(ctx, set(p.log.events))
    fctx, held = forgetting(p.log, ev["checkpoint"], set(p.log.events))
    forgot = judge(fctx, held, ev["checkpoint"])

    def verdicts(w, ids):
        return {p.hist.name(i): "valid" if w.status[i][0] else w.status[i][1]
                for i in sorted(ids, key=p.log.order_key)}
    names = p.hist.key_name
    rec = ctx.record(ev["checkpoint"])
    q, sv = _signatures("lists/vector/signatures")
    qctx = LCtx(q.log)
    return {
        "history_prefix": "lists/vector",
        "events": p.hist.describe(),
        "record": h(ctx.body(ev["checkpoint"]).record_bytes),
        "electorate": sorted(names(d) for d in electorate(ctx, ev["checkpoint"],
                                                          {ev["checkpoint"]})),
        "full": {"effective": [p.hist.name(c) for c in full.chain],
                 "verdicts": verdicts(full, p.log.events),
                 "active": sorted(names(d) for d in full.list.active_members())},
        "forgot": {"holds": sorted(p.hist.name(i) for i in held),
                   "keeps_alone": sorted(p.hist.name(i) for i in fctx.readable - held),
                   "rooting_adds": {names(ctx.body(m["add"]).device): p.hist.name(m["rooting"])
                                    for m in rec["members"] if m["rooting"]},
                   "verdicts": verdicts(forgot, held),
                   "active": sorted(names(d) for d in forgot.list.active_members())},
        "signatures": {"history_prefix": "lists/vector/signatures",
                       "events": q.hist.describe(),
                       "verdicts": {q.hist.name(i): validity(qctx, i)[1]
                                    for i in sorted(sv.values(), key=q.log.order_key)}},
        "record_refusals": _record_refusals(ctx.body(ev["checkpoint"]).record_bytes),
        "stolen": _stolen_vector("lists/vector/stolen"),
        "sealed_copy": _sealed_copy(p, ev["checkpoint"]),
        "disjoint": _disjoint_vector("lists/vector/disjoint"),
        "takeover": _takeover_vectors("lists/vector/takeover"),
    }


def _takeover_vectors(prefix: str) -> dict:
    out = {}
    for kind, x in _takeover_checks(prefix).items():
        p = x["p"]
        out[kind] = {"history_prefix": f"{prefix}/{kind}", "events": p.hist.describe(),
                     "waiting_for": {p.hist.name(x["ev"][k]): sorted(
                         p.hist.key_name(d) for d in w) for k, w in x["waits"].items()},
                     "effective": [p.hist.name(c) for c in x["full"].chain],
                     "verdicts": {p.hist.name(i): "valid" if x["full"].status[i][0]
                                  else x["full"].status[i][1]
                                  for i in sorted(p.log.events, key=p.log.order_key)}}
    return out


def _disjoint_vector(prefix: str) -> dict:
    x = _disjoint_checks(prefix)
    p = x["p"]

    def verdicts(w, ids):
        return {p.hist.name(i): "valid" if w.status[i][0] else w.status[i][1]
                for i in sorted(ids, key=p.log.order_key)}
    return {"history_prefix": prefix, "events": p.hist.describe(),
            "note": "two groups of the person's devices that each revoked the other after "
                    "their own checkpoint: each takes effect in its group's view, the smaller "
                    "ID once both are held; a holder that forgot under the other holds a "
                    "rival and holds what it judges pending",
            "group_views": {"D0 and D1": [p.hist.name(c) for c in x["g1"].chain],
                            "D2 and D3": [p.hist.name(c) for c in x["g2"].chain]},
            "full": {"effective": [p.hist.name(c) for c in x["full"].chain],
                     "verdicts": verdicts(x["full"], p.log.events)},
            "forgot_under_loser": {"kept": p.hist.name(x["lose"]),
                                   "holds": sorted(p.hist.name(i) for i in x["held"]),
                                   "verdicts": verdicts(x["forgot"], x["held"])},
            "forgot_under_winner": {"kept": p.hist.name(x["win"]),
                                    "holds": sorted(p.hist.name(i) for i in x["wheld"]),
                                    "verdicts": verdicts(x["wforgot"], x["wheld"])}}


def _stolen_vector(prefix: str) -> dict:
    p, ev, full, waits = _stolen(prefix)
    return {"history_prefix": prefix, "events": p.hist.describe(),
            "note": "a revoked device's checkpoint on its old view, and its revocations of "
                    "every other device after it: its author excuses no one, so it waits "
                    "for D0 and D1 and never takes effect",
            "effective": [p.hist.name(c) for c in full.chain],
            "waiting_for": sorted(p.hist.key_name(d) for d in waits),
            "verdicts": {p.hist.name(i): "valid" if full.status[i][0] else full.status[i][1]
                         for i in sorted(p.log.events, key=p.log.order_key)}}


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 40
    print(model_check(range(1, n + 1), quiet=False))
