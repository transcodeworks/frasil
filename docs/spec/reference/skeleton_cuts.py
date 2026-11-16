"""Skeleton cuts (peers.md, "Skeleton cuts" and "Truncation"), written from the
specification: a peer, which opens nothing, learns from a space checkpoint's
twin the administrator slots at that point, starts the skeleton afresh from
it once every enrolled slot acknowledged an event after the checkpoint, and
may then delete what came before. A seeded model check builds random
skeletons (administrators granted and enrolled, removed, acknowledging,
erasing) with cuts, and checks that a peer that truncated and one that kept
everything reach the same verdicts, administrators and stability."""

from __future__ import annotations

import random
import sys

import checkpoints as CP
import events
import roster
import storage as S
from events import KIND_SPACE, KIND_STORAGE, cbor, h, is_bytes, uncbor
from formats import example
from primitives import SpecError


def _names(e):
    """The twin a space event names in visible key 15, if any."""
    try:
        value = S.kg.decode_cbor(e.body)
    except SpecError:
        return None
    return value.get(S.P_TWIN) if isinstance(value, dict) else None


class PCtx:
    """What a peer reads: envelopes, storage bodies and visible parts. A peer
    that truncated (`held`) reads only what it holds: nothing of an event it
    deleted, not even its envelope."""

    def __init__(self, log, *, trusted=(), held=None):
        self.log = log
        self.trusted = frozenset(trusted)
        self.held = None if held is None else frozenset(held)
        self.memo: dict = {}
        # twin -> the space event naming it; a cut's only when that event
        # cites it and every other parent of it is in the cut's past
        # (peers.md, "Skeleton cuts", the checkpoint of a cut).
        view = set(log.events) if held is None else set(held)
        self.names = {}
        for t, i in S.named_twins(log, view).items():
            self.names[t] = i
        for i in log.canonical(view):
            e = log.events[i]
            if e.kind != events.KIND_SPACE:
                continue
            for t, n in list(self.names.items()):
                if n != i:
                    continue
                b = self.body(t)
                if b is None or b["type"] != S.CUT:
                    continue
                # A parent it does not hold (deleted when it truncated, or
                # dropped when it forgot) is in the kept cut's past.
                if t not in e.parents or not all(p == t or p in log.anc[t] or not self.holds(p)
                                                 for p in e.parents):
                    # Not this cut's checkpoint: the next event that names
                    # it and passes, if any, is.
                    del self.names[t]
                    nxt = next((j for j in log.canonical(view)
                                if j != i and log.events[j].kind == events.KIND_SPACE
                                and t in log.events[j].parents
                                and all(p == t or p in log.anc[t] or not self.holds(p)
                                        for p in log.events[j].parents)
                                and _names(log.events[j]) == t), None)
                    if nxt is not None:
                        self.names[t] = nxt

    def holds(self, i) -> bool:
        return i in self.log.events and (self.held is None or i in self.held)

    def body(self, i):
        k = ("body", i)
        if k not in self.memo:
            if not self.holds(i):
                self.memo[k] = None
                return None
            e = self.log.events[i]
            try:
                self.memo[k] = S.read_body(e.body) if e.kind == KIND_STORAGE else None
            except SpecError:
                self.memo[k] = None
        return self.memo[k]

    def is_cut(self, i) -> bool:
        b = self.body(i)
        return b is not None and b["type"] == S.CUT

    def checkpoint_of(self, cut):
        """The space event that names the cut in visible key 15: its
        checkpoint, to a peer."""
        return self.names.get(cut)

    def reach(self, i) -> frozenset:
        k = ("reach", i)
        if k not in self.memo:
            out = set()
            for c in self.log.events[i].cuts:
                out.add(c)
                if self.holds(c):  # the envelopes the peer keeps (peers.md)
                    out |= self.reach(c)
            self.memo[k] = frozenset(out)
        return self.memo[k]

    def follows_cut(self, i, cut) -> bool:
        """i follows the checkpoint that names `cut`, by its cuts, or is that
        checkpoint."""
        c = self.checkpoint_of(cut)
        return c is not None and (i == c or c in self.reach(i))


def world_log(ctx: PCtx, cut, held) -> CP.DerivedLog:
    members = {i for i in held if i != cut and ctx.follows_cut(i, cut)}
    k = ("dlog", cut, frozenset(members))
    if k not in ctx.memo:
        ctx.memo[k] = CP.DerivedLog(ctx.log, cut, members)
    return ctx.memo[k]


def late_at_peer(ctx: PCtx, cut, held) -> set:
    """peers.md, "Skeleton cuts", late skeleton events: with `cut` in effect,
    the skeleton events but cuts held that are neither in its past, nor the
    cut, nor follow its checkpoint. Stored, with no effect. A cut keeps its
    own checks, on its own past, wherever it stands."""
    c = ctx.checkpoint_of(cut)
    past = ctx.log.anc[c] | {c}
    return {i for i in held if i not in past and not ctx.follows_cut(i, cut)
            and ctx.body(i) is not None and ctx.body(i)["type"] in S.SKELETON_TYPES
            and ctx.body(i)["type"] != S.CUT}


def late_enrolment_check(ctx: PCtx, i, held):
    """peers.md, "What a late enrolment opens": a late enrolment is stored
    only if its seq is 1 and its author is no pseudonym whose root or
    enrolment the peer holds before it (BadSignature, as section 3.11, step
    3, classes them), its mldsa beside an empty X-Wing key hashes to its kc
    (NotCommitted), and it verifies under its own keys (BadSignature).
    None when it passes, or is no enrolment."""
    b = ctx.body(i)
    if b is None or b["type"] != S.ENROL:
        return None
    e = ctx.log.events[i]
    known = any(j != i and ctx.log.events[j].author == e.author and ctx.body(j) is not None
                and ctx.body(j)["type"] in (S.ROOT, S.ENROL)
                and ctx.log.order_key(j) < ctx.log.order_key(i) for j in held)
    if e.seq != 1 or known:
        return (False, "BadSignature", None)
    if S.hs.keys_commitment(b["mldsa"], None) != e.kc:
        return (False, "NotCommitted", None)
    if not S.hs.verify_mldsa_half(e.ed, b["mldsa"], events.signing_input(e.event_bytes),
                                  e.signature):
        return (False, "BadSignature", None)
    return None


def world(ctx: PCtx, cut, view) -> S.Skeleton:
    late = late_at_peer(ctx, cut, view)
    everything = frozenset(view)
    view = {i for i in view if i == cut or ctx.follows_cut(i, cut)}
    dlog = world_log(ctx, cut, view)
    presets = {i: validity(ctx, i) for i in view - {cut} if ctx.is_cut(i)}
    b = ctx.body(cut)
    k = ("world", cut, frozenset(view), frozenset(late))
    if k not in ctx.memo:
        sk = S.Skeleton(dlog, view, base={"epoch": b["epoch"], "slots": b["slots"],
                                          "enrolments": enrolments(ctx, cut)},
                        presets=presets)
        # Stored, never refused or held for being late; no effect. A late
        # enrolment is first checked on its own (peers.md, "What a late
        # enrolment opens"), with section 3.11's classes for the same
        # checks: refused otherwise.
        for i in late:
            sk.status[i] = late_enrolment_check(ctx, i, everything) or (False, "Late", None)
        ctx.memo[k] = sk
    return ctx.memo[k]


def enrolments(ctx: PCtx, cut) -> dict:
    """The roots and enrolments a cut's slot entries name, by event ID: the
    peer holds them in the cut's past and keeps them after truncation
    (peers.md, "Truncation")."""
    out = {}
    for s in ctx.body(cut)["slots"]:
        if s["pseudonym"] is not None:
            assert ctx.holds(s["pseudonym"]), "a named enrolment is kept"
            out[s["pseudonym"]] = ctx.log.events[s["pseudonym"]]
    return out


def summary(sk: S.Skeleton) -> list:
    """The slot entries of a skeleton's merged state: every administrator
    slot that is in, with its keys, seniority and enrolled pseudonym's root
    or enrolment."""
    out = []
    for slot in sk.administrators():
        meta = sk.slots[slot]
        pseudonym = sk.merged[slot]["enrolled"]
        out.append({"slot": slot, "slot_ed": meta["slot_ed"],
                    "slot_mldsa_hash": meta["slot_mldsa_hash"], "seniority": sk.seniority(slot),
                    "pseudonym": sk.enrolled_by.get(pseudonym) if pseudonym else None,
                    "rank": meta["rank"]})
    return out


def _entries(slots) -> list:
    return [[S.slot_ref(*s["slot"]), s["slot_ed"] or b"", s["slot_mldsa_hash"] or b"",
             [s["seniority"][0], s["seniority"][1], s["seniority"][3]], s["pseudonym"] or b"",
             s.get("rank", S.MAX_RANK)]
            for s in sorted(slots, key=lambda s: events.cbor(S.slot_ref(*s["slot"])))]


def validity(ctx: PCtx, cut) -> tuple:
    """peers.md, "Skeleton cuts", what a peer checks, in order: the body
    reads (a cut is_cut only once it does); its author is an enrolled
    pseudonym the peer holds and the event verifies under its key; a stored
    space event names it; its epoch; its author's slot in, enrolled to it, in
    the merged skeleton of its past; its slots exactly those."""
    k = ("valid", cut)
    if cut in ctx.trusted:
        return (True, "cut", None)
    if k in ctx.memo:
        return ctx.memo[k]
    ctx.memo[k] = (False, "Pending", None)
    ctx.memo[k] = _validity(ctx, cut)
    return ctx.memo[k]


def _validity(ctx: PCtx, cut) -> tuple:
    e = ctx.log.events[cut]
    pool = ctx.log.anc[cut] if ctx.held is None else ctx.log.anc[cut] & ctx.held
    base = None
    if ctx.held is not None:
        base = next((t for t in ctx.trusted if t in pool), None)
    # Step 2: a stored space event names it, cites it, and holds nothing
    # outside its past: its checkpoint.
    if ctx.checkpoint_of(cut) is None:
        return (False, "Unnamed", None)
    sk = skeleton_of(ctx, pool, base)
    # Step 3: its epoch, against L, the last cut in effect in its past. Its
    # checkpoint follows L's, and every checkpoint its cuts reach is at or
    # before L's or after it: read from envelopes alone, so that a peer
    # that truncated under L decides it as one that kept everything. No
    # valid cut after L's checkpoint is one its checkpoint follows, as no
    # valid checkpoint after a predecessor may be (roster.md).
    if base is not None and not stable(ctx, base, pool):
        return (False, "CutPending", None)
    ch = ctx.memo[("sk", frozenset(pool), base, "chain")]
    mine = ctx.checkpoint_of(cut)
    reached = ctx.reach(mine)
    last = ctx.checkpoint_of(ch[-1]) if ch else None

    def below(x, y):
        return x == y or x in ctx.reach(y)
    if last is not None and (last not in reached or any(
            not below(x, last) and not below(last, x) for x in reached)):
        return (False, "CutPending", None)
    expected = ctx.body(ch[-1])["epoch"] + 1 if ch else 1
    later = [x for x in pool if ctx.is_cut(x) and ctx.checkpoint_of(x) in reached
             and ctx.checkpoint_of(x) != mine
             and (last is None or (ctx.checkpoint_of(x) != last
                                   and below(last, ctx.checkpoint_of(x))))
             and validity(ctx, x)[0]]
    if later or ctx.body(cut)["epoch"] != expected:
        return (False, "CutPending", None)
    # Step 4: its author's slot is in, enrolled to it, in the merged
    # skeleton of its past; whatever the peer holds of other enrolments.
    slot = sk.slot_of.get(e.author)
    st = sk.merged.get(slot)
    if st is None or not st["in"] or st["enrolled"] != e.author:
        return (False, "NotAnAdministrator", None)
    # Step 5: it verifies under the key of the root or enrolment that
    # enrolled it there.
    key = sk.key_of.get(e.author)
    if key is None or not S.hs.verify_mldsa_half(e.ed, key, events.signing_input(e.event_bytes),
                                                 e.signature):
        return (False, "BadSignature", None)
    # Step 6.
    if _entries(summary(sk)) != _entries(ctx.body(cut)["slots"]):
        return (False, "BadCut", None)
    # Step 7: each standing entry names a slot of the cut, or one the peer
    # holds that is out there; orders 1 to n, each once; a dormant value
    # from 3 is 2 + another entry's order.
    standing = ctx.body(cut)["standing"]
    mine = {s_["slot"] for s_ in ctx.body(cut)["slots"]}
    orders = sorted(x["order"] for x in standing)
    n = len(standing)

    def out_ok(x):
        # A slot not in, with a root or an enrolment of it the peer holds,
        # or none.
        st = sk.merged.get(x["slot"])
        if st is not None and st["in"]:
            return False
        p = x["pseudonym"]
        if p is None:
            return True
        pb = ctx.body(p)
        return pb is not None and ((pb["type"] == S.ENROL and pb["slot"] == x["slot"])
                                   or (pb["type"] == S.ROOT and x["slot"][2] == p))
    if orders != list(range(1, n + 1)) or any(
            (x["pseudonym"] is not None) if x["slot"] in mine else not out_ok(x)
            for x in standing) or any(
            x["dormant"] >= 3 and not 1 <= x["dormant"] - 2 <= n + 1 for x in standing):
        return (False, "BadCut", None)
    return (True, "cut", None)


def pseudonym_key(ctx: PCtx, e) -> bytes | None:
    """The ML-DSA-65 key that a root or enrolment the peer holds, by e's
    author, carries for it, when it hashes to e's kc."""
    k = ("pkey", e.author, e.kc)
    if k not in ctx.memo:
        ctx.memo[k] = _pseudonym_key(ctx, e)
    return ctx.memo[k]


def _pseudonym_key(ctx: PCtx, e) -> bytes | None:
    for i in ctx.log.events:
        x = ctx.log.events[i]
        if x.author != e.author or x.kind != KIND_STORAGE:
            continue
        b = ctx.body(i)
        if b is not None and b["type"] in (S.ROOT, S.ENROL) \
                and S.hs.keys_commitment(b["mldsa"], None) == e.kc:
            return b["mldsa"]
    return None


def _below(ctx: PCtx, x, y) -> bool:
    return x == y or x in ctx.reach(y)


def _votes_cleanly(ctx: PCtx, i, c) -> bool:
    """An event after checkpoint c whose cuts reach no checkpoint concurrent
    with it: exclusive, as a device's vote is."""
    return all(_below(ctx, x, c) or _below(ctx, c, x) for x in ctx.reach(i))


def slot_pseudonyms(ctx: PCtx, cut, slot, held) -> set:
    """peers.md, "Skeleton cuts", votes: the pseudonyms that vote for a slot:
    the one the cut's entry names; one whose enrolment of the slot follows
    the checkpoint; for a slot that is out, the one its standing entry
    names, enrolled in it."""
    out = set()
    for s_ in ctx.body(cut)["slots"]:
        if s_["slot"] == slot and s_["pseudonym"] is not None:
            out.add(ctx.log.events[s_["pseudonym"]].author)
    for x in ctx.body(cut)["standing"]:
        if x["slot"] == slot and x["pseudonym"] is not None and ctx.holds(x["pseudonym"]):
            out.add(ctx.log.events[x["pseudonym"]].author)  # an out slot's
    for i in held:
        b = ctx.body(i)
        if b is not None and b["type"] == S.ENROL and b["slot"] == slot \
                and ctx.follows_cut(i, cut):
            out.add(ctx.log.events[i].author)
    return out


def verified(ctx: PCtx, i) -> bool:
    """A skeleton event whose ML-DSA-65 half the peer verified, under the key
    the root or enrolment of its author that it holds gives (section 3.11)."""
    k = ("verified", i)
    if k not in ctx.memo:
        e = ctx.log.events[i]
        key = pseudonym_key(ctx, e)
        ctx.memo[k] = key is not None and S.hs.verify_mldsa_half(
            e.ed, key, events.signing_input(e.event_bytes), e.signature)
    return ctx.memo[k]


def excusing(ctx: PCtx, cut, held) -> dict:
    """peers.md, "Skeleton cuts", waited and excused slots: for each slot
    the cut waits for, the lowerings that excuse it. A lower or disown of
    it after the checkpoint, reaching no concurrent checkpoint, whatever its
    verdict, by its own pseudonym, or by a slot of the cut's whose standing
    outranks it (a lower order), or by a recovery slot of a rank at least
    its own (dormant 2, or 2 + k with k at most its order)."""
    c = ctx.checkpoint_of(cut)
    body = ctx.body(cut)
    standing = {x["slot"]: x for x in body["standing"]}
    in_cut = {s_["slot"]: s_ for s_ in body["slots"]}
    rank = {sl: s_["rank"] for sl, s_ in in_cut.items()}
    for i in ctx.log.events:  # an out slot's rank, from the change that made it
        b = ctx.body(i)
        if b is not None and b["type"] == S.CHANGE and "grants" in b:
            for k, g in enumerate(b["grants"]):
                rank.setdefault((b["twin"], k, i), g[S.G_RANK])
    waited = [sl for sl, x in standing.items() if x["dormant"] == 0]
    voters = {sl: slot_pseudonyms(ctx, cut, sl, held) for sl in standing}
    out = {sl: set() for sl in waited}
    for i in held:
        b = ctx.body(i)
        if b is None or not ctx.follows_cut(i, cut) or not _votes_cleanly(ctx, i, c) \
                or not verified(ctx, i):
            continue
        target = b.get("lower") if b["type"] == S.CHANGE else (
            b["slot"] if b["type"] == S.DISOWN else None)
        if target not in out:
            continue
        author = ctx.log.events[i].author
        if author in voters[target]:
            out[target].add(i)  # it lowers itself
            continue
        mine = standing[target]
        for t, x in standing.items():
            if t not in in_cut or author not in voters[t]:
                continue
            d = x["dormant"]
            if x["order"] < mine["order"] or (
                    d >= 2 and rank.get(t, 0) >= rank.get(target, S.MAX_RANK)
                    and (d == 2 or d - 2 <= mine["order"])):
                out[target].add(i)
    return out


def stable(ctx: PCtx, cut, held) -> bool:
    """peers.md, "Skeleton cuts", in effect at the peer: every slot the cut
    waits for has a vote or is excused. Votes and excuses only accumulate,
    so it holds over every superset of a view it holds over."""
    c = ctx.checkpoint_of(cut)
    held = set(held)
    body = ctx.body(cut)
    excuses = excusing(ctx, cut, held)
    for x in body["standing"]:
        if x["dormant"] != 0:
            continue
        sl = x["slot"]
        if excuses.get(sl):
            continue
        who = slot_pseudonyms(ctx, cut, sl, held)
        if not any(ctx.log.events[i].author in who and ctx.follows_cut(i, cut)
                   and ctx.log.events[i].kind == KIND_STORAGE and _votes_cleanly(ctx, i, c)
                   and verified(ctx, i)
                   for i in held):
            return False
    return True


def chain(ctx: PCtx, held, base=None) -> list:
    out = [base] if base is not None else []
    current = base
    while True:
        epoch = ctx.body(current)["epoch"] + 1 if current is not None else 1
        cands = [i for i in held if ctx.is_cut(i) and i != current
                 and ctx.body(i)["epoch"] == epoch and validity(ctx, i)[0]
                 and (current is None or ctx.follows_cut(ctx.checkpoint_of(i), current))
                 and stable(ctx, i, held)]
        if current is not None:
            cands = [i for i in cands if ctx.checkpoint_of(i) != ctx.checkpoint_of(current)]
        if not cands:
            return out
        current = min(cands, key=lambda i: ctx.checkpoint_of(i))
        out.append(current)


def skeleton_of(ctx: PCtx, held, base=None) -> S.Skeleton:
    """The skeleton a peer resolves over what it holds: from its last cut in
    effect, or from the root."""
    held = set(held)
    k = ("sk", frozenset(held), base)
    if k not in ctx.memo:
        ch = chain(ctx, held, base)
        if ch:
            ctx.memo[k] = world(ctx, ch[-1], held)
        else:
            presets = {i: validity(ctx, i) for i in held if ctx.is_cut(i)}
            ctx.memo[k] = S.Skeleton(ctx.log, held, presets=presets)
        ctx.memo[k + ("chain",)] = ch
    return ctx.memo[k]


def kept_in_past(ctx: PCtx, cut) -> set:
    """peers.md, "Truncation", what is always kept of the checkpoint's past:
    the genesis; the cut; the envelopes of the checkpoints its cuts reach;
    the roots and enrolments its slot entries name; every release and
    restore; and every unit, which leaves a peer only by collection. The
    record object is no event."""
    c = ctx.checkpoint_of(cut)
    log = ctx.log
    out = {log.genesis, cut} | set(ctx.reach(c))
    out |= {s["pseudonym"] for s in ctx.body(cut)["slots"] if s["pseudonym"] is not None}
    # and those of the out slots its standing entries name, whose votes a
    # peer that truncated still counts.
    out |= {x["pseudonym"] for x in ctx.body(cut)["standing"] if x["pseudonym"] is not None}
    streams: dict = {}
    # A request late under a cut before this one counts for nothing, though
    # this checkpoint's past holds it.
    before = chain(ctx, log.anc[c])
    for i in log.anc[c]:
        b = ctx.body(i) if log.events[i].kind == KIND_STORAGE else None
        if b is not None and b["type"] in S.WRITER_TYPES:
            if b.get("stream") is None:
                out.add(i)  # a restore naming a snapshot unit
            elif not late_under(ctx, i, before):
                streams.setdefault(b["stream"], set()).add(i)
        if log.events[i].kind == events.KIND_UNIT:
            out.add(i)
    # Of each stream's releases and restores, the maximal ones, found while
    # the whole past is held: they are concurrent with each other.
    for ids in streams.values():
        out |= {i for i in ids if not any(i in log.anc[j] for j in ids)}
    return out & log.anc[c] | {cut}


def request_state(ctx: PCtx, held, x, base=None) -> str:
    """peers.md, "Erasure", steps 0 and 1, for an erasure or credentials
    request `x` the peer holds: Late, under the cut in effect; Wait, while
    it is concurrent with a cut that can still take effect (valid, not in
    effect, of a later epoch than the cut in effect, or of the epoch of a
    cut in effect whose checkpoint has a larger ID); otherwise Free, for
    stability or the timeout to decide."""
    held = set(held)
    ch = chain(ctx, held, base)
    cur = ch[-1] if ch else None
    # Late under any cut of the chain, though a later checkpoint's past
    # holds it: its verdict stays Late.
    if late_under(ctx, x, ch):
        return "Late"
    epoch = ctx.body(cur)["epoch"] if cur is not None else 0
    at = {ctx.body(j)["epoch"]: j for j in ch}
    for k in held:
        if not ctx.is_cut(k) or k in ch or not validity(ctx, k)[0]:
            continue
        e = ctx.body(k)["epoch"]
        if not (e > epoch or (e in at and ctx.checkpoint_of(k) < ctx.checkpoint_of(at[e]))):
            continue
        ck = ctx.checkpoint_of(k)
        if x not in ctx.log.anc[ck] and x != k and not ctx.follows_cut(x, k):
            return "Wait"
    return "Free"


ERASURE_LATE = 97  # transport.md's message type, ignorable
STANDING_ENROLLED, STANDING_OTHER, STANDING_OUT = 0, 1, 2


def own_slot(ctx: PCtx, author: bytes):
    """The administrator slot a pseudonym holds: the one its enrolment
    names, or, for the root's pseudonym, the slot a cut lists enrolled to
    its root; None when neither is found."""
    for i in ctx.log.events:
        e = ctx.log.events[i]
        if e.author != author or e.kind != KIND_STORAGE:
            continue
        b = ctx.body(i)
        if b is not None and b["type"] == S.ENROL:
            return b["slot"]
        if b is not None and b["type"] == S.ROOT:
            for k in ctx.log.events:
                if ctx.is_cut(k):
                    for s_ in ctx.body(k)["slots"]:
                        if s_["pseudonym"] == i:
                            return s_["slot"]
    return None


def erasure_answer(ctx: PCtx, held, x, base=None) -> dict:
    """peers.md, "A device's own erasure": what a peer answers to the
    pseudonym that stores erasure `x` again. `erased` once carried out (the
    caller's to say); here, Late under the chain: ErasureLate, with the cut
    in effect, that cut's checkpoint, and the standing of the pseudonym's
    slot in the cut; else an acknowledgement."""
    held = set(held)
    ch = chain(ctx, held, base)
    if not late_under(ctx, x, ch):
        return {"answer": "acknowledged"}
    # The cut in effect, which a peer that truncated holds too: the erasure
    # is late under it or under a cut before it, late for good either way,
    # and the slot's standing there is what the device needs now.
    k = ch[-1]
    author = ctx.log.events[x].author
    slot = own_slot(ctx, author)
    entry = next((s_ for s_ in ctx.body(k)["slots"] if s_["slot"] == slot), None)
    if entry is None:
        standing = STANDING_OUT
    elif entry["pseudonym"] is not None and ctx.log.events[entry["pseudonym"]].author == author:
        standing = STANDING_ENROLLED
    else:
        standing = STANDING_OTHER
    return {"answer": "late", "cut": k, "checkpoint": ctx.checkpoint_of(k), "slot": slot,
            "standing": standing,
            "entry": None if entry is None else ("none" if entry["pseudonym"] is None
                                                 else "named")}


def erasure_late_message(log, space: bytes, x, answer: dict) -> bytes:
    """transport.md's ErasureLate, type 97."""
    return cbor({0: ERASURE_LATE, 1: space, 2: x, 3: log.events[answer["cut"]].signed,
                 4: answer["checkpoint"], 5: answer["standing"]})


def residue_check(message: bytes, space: bytes, x: bytes, slot) -> dict:
    """What the residue checks of an ErasureLate without any key of the
    space (peers.md, "What the residue checks"): the message reads, names
    this space and erasure; the cut's envelope decodes, its Ed25519 half
    verifies, and it is of this space; it is a storage event of type 7 whose
    body reads; and the cut lists the residue's slot exactly when the
    standing is 0 or 1. Everything else, the checkpoint the message names
    by ID included, is the peer's word."""
    m = uncbor(message)
    if not (isinstance(m, dict) and set(m) == {0, 1, 2, 3, 4, 5} and m[0] == ERASURE_LATE
            and m[1] == space and m[2] == x and m[5] in (0, 1, 2)
            and is_bytes(m[3]) and is_bytes(m[4], 32)):
        raise SpecError("Malformed")
    try:
        cut = events.decode_event(m[3])
    except SpecError:
        raise SpecError("PeerError")
    if cut.log != space or cut.kind != KIND_STORAGE:
        raise SpecError("PeerError")
    try:
        body = S.read_body(cut.body)
    except SpecError:
        raise SpecError("PeerError")
    if body["type"] != S.CUT:
        raise SpecError("PeerError")
    entry = next((s_ for s_ in body["slots"] if s_["slot"] == slot), None)
    if (entry is not None) != (m[5] != STANDING_OUT):
        raise SpecError("PeerError")
    # Standing 0 says the entry names this pseudonym's root or enrolment, so
    # it names one; standing 1 with a named entry is another pseudonym's.
    if m[5] == STANDING_ENROLLED and entry["pseudonym"] is None:
        raise SpecError("PeerError")
    named = entry is not None and entry["pseudonym"] is not None
    return {"checkpoint": m[4], "cut": cut.id, "standing": m[5],
            "entry": None if entry is None else ("named" if named else "none"),
            "action": residue_action(m[5], named)}


def residue_action(standing: int, named: bool) -> str:
    """peers.md, "A device's own erasure": what the residue does on the
    peer's word. Standing 0, or 1 with the cut naming no pseudonym for the
    slot: it asks for a welcome and judges once back in. Standing 1 with
    the cut naming another pseudonym: the slot is enrolled, no enrolment of
    it can be valid again (section 3.12, AlreadyEnrolled), so it reports
    SlotHeld and asks nothing. Standing 2: it can no longer erase."""
    if standing == STANDING_OUT:
        return "cannot erase"
    if standing == STANDING_OTHER and named:
        return "slot held"
    return "back in"


def after_back_in(ctx: PCtx, cut, slot, author: bytes, held) -> tuple:
    """peers.md, "Back in": once the device holds the space again, what
    becomes of its erasure, read in the world after the cut: re-sign with
    its pseudonym when the slot is enrolled to it; enrol again when the
    slot is unenrolled there; else the slot is held by an enrolment after
    the checkpoint by another pseudonym, whose binding says whether it is
    another installation of this device or another device (SlotHeld).
    Returns (outcome, the holding enrolment or None)."""
    w = world(ctx, cut, held)
    for s_ in ctx.body(cut)["slots"]:
        if s_["slot"] == slot and s_["pseudonym"] is not None:
            holder = s_["pseudonym"]
            mine = ctx.log.events[holder].author == author
            return ("sign again" if mine else "slot held", None if mine else holder)
    later = [i for i in held if ctx.body(i) is not None and ctx.body(i)["type"] == S.ENROL
             and ctx.body(i)["slot"] == slot and ctx.follows_cut(i, cut) and w.valid(i)]
    if later:
        return ("slot held", later[0])
    return ("enrol again", None)


def late_under(ctx: PCtx, i, ch) -> bool:
    """Whether event i is late under some cut of the chain `ch`: neither in
    its checkpoint's past, nor its checkpoint, nor after it."""
    for k in ch:
        c = ctx.checkpoint_of(k)
        if i != c and i not in ctx.log.anc[c] and not ctx.follows_cut(i, k):
            return True
    return False


def released_at_peer(ctx: PCtx, held, stream, base=None) -> bool:
    """peers.md, "Release and restore": whether `stream` is released at a
    peer that holds `held`, truncated under `base` when given. With a cut in
    effect, the requests counted are those of its checkpoint's past and
    those after it, each of which holds that whole past; one late under any
    cut of the chain, a release or a restore, counts for nothing, though a
    later checkpoint's past holds it. A peer that truncated holds only the maximal requests of the
    past, which are concurrent with each other, and reads no order among
    them; between events after `base`'s checkpoint it reads parents, which
    it holds."""
    held = set(held)
    log = ctx.log
    reqs = {i: ctx.body(i) for i in held if ctx.body(i) is not None
            and ctx.body(i)["type"] in S.WRITER_TYPES and ctx.body(i).get("stream") == stream}
    ch = chain(ctx, held, base)
    past_of_base = log.anc[ctx.checkpoint_of(base)] if base is not None else set()

    def before(x, y):  # x is before y, as the peer can tell
        if base is not None and x in past_of_base:
            return y not in past_of_base and ctx.follows_cut(y, base)
        return x in log.anc[y]
    reqs = {i: b for i, b in reqs.items() if not late_under(ctx, i, ch)}
    if not any(b["type"] == S.RELEASE for b in reqs.values()):
        return False
    maximal = [i for i in reqs if not any(j != i and before(i, j) for j in reqs)]
    return all(reqs[i]["type"] == S.RELEASE for i in maximal)


def may_truncate(ctx: PCtx, cut, view) -> bool:
    """peers.md, "Truncation", when: every erasure and credentials request in
    the checkpoint's past is carried out or void at the peer. With no
    timeline here, carried out means stable at the peer, in the skeleton
    those requests were judged in: the one before the cut, from the cut in
    effect before it, over everything the peer holds."""
    c = ctx.checkpoint_of(cut)
    view = set(view)
    ch = chain(ctx, view)
    if cut not in ch:
        return False  # only under a cut in effect
    k = ch.index(cut)
    if k > 0:
        sk = world(ctx, ch[k - 1], view)
    else:
        sk = S.Skeleton(ctx.log, view, presets={i: validity(ctx, i) for i in view
                                                if ctx.is_cut(i)})
    wsk = world(ctx, cut, view)
    for i in ctx.log.anc[c]:
        b = sk.body.get(i)
        if b is not None and b["type"] in (S.ERASE, S.CREDENTIALS) \
                and sk.valid(i) and not stable_past(sk, wsk, i):
            return False
    return True


def stable_past(sk: S.Skeleton, wsk: S.Skeleton, target) -> bool:
    """peers.md, "Skeleton cuts", requests of the cut's past: stability in
    the skeleton before the cut (`sk`), over every event the peer holds,
    where a slot of the cut also acknowledges by any skeleton event after
    the cut of the pseudonym enrolled in it in the world after the cut
    (`wsk`), at the cut or later. Every such event holds the cut's past."""
    for slot in sk.stability_set():
        key = sk.merged.get(slot, {}).get("enrolled")
        if key is not None and key in sk.forks:
            continue
        if any(sk.log.le(target, a) for a in sk.acknowledging(slot)):
            continue
        if slot in wsk.base_slots:
            p = wsk.merged.get(slot, {}).get("enrolled")
            if p is not None and p not in wsk.forks and any(
                    wsk.log.events[j].author == p for j in wsk.skeleton if j != wsk.root):
                continue
        return False
    return True


def truncated(ctx: PCtx, cut, final) -> set:
    """What a peer keeps after truncating under `cut`: everything outside the
    checkpoint's past (the checkpoint, the events that follow it, and late
    events), and what is always kept of that past."""
    c = ctx.checkpoint_of(cut)
    out = {i for i in final if i not in ctx.log.anc[c]} | (kept_in_past(ctx, cut) & set(final))
    # The root or enrolment of each pseudonym that signed an erasure the
    # peer holds late, so that it still accepts its present and answers it
    # with its slot's standing (peers.md, "Truncation").
    ch = chain(ctx, set(final))
    for i in list(out):
        b = ctx.body(i) if ctx.log.events[i].kind == KIND_STORAGE else None
        if b is None or b["type"] != S.ERASE or not late_under(ctx, i, ch):
            continue
        author = ctx.log.events[i].author
        out |= {j for j in ctx.log.anc[c] & set(final) if ctx.log.events[j].author == author
                and ctx.log.events[j].kind == KIND_STORAGE and ctx.body(j) is not None
                and ctx.body(j)["type"] in (S.ROOT, S.ENROL)}
    return out


def against_record(ctx: PCtx, cut, record_slots) -> str | None:
    """peers.md, "Skeleton cuts", the replica's check against the record:
    the cut declares the same cuts as its checkpoint, and each `slot` entry
    (c, index, maker, pseudonym's device ID or empty) of the record's
    administrators names a slot of the cut whose entry names a root or
    enrolment by that pseudonym, or is empty exactly when the record's is.
    The cut's other slots, planted ones and those whose disown a replica
    deems justified, map to no device. BadTwin otherwise."""
    c = ctx.checkpoint_of(cut)
    if c is None or tuple(ctx.log.events[cut].cuts) != tuple(ctx.log.events[c].cuts):
        return "BadTwin"  # the cut follows what its checkpoint follows
    mine = {}
    for s_ in ctx.body(cut)["slots"]:
        pid = s_["pseudonym"]
        mine[s_["slot"]] = b"" if pid is None else ctx.log.events[pid].author
    for x in record_slots:
        if mine.get(tuple(x[:3])) != x[3]:
            return "BadTwin"
    return None


def record_slots_of(r, c) -> list:
    """The `slot` entries a replica that holds checkpoint c's whole past
    derives for the record's administrators (roster.md, "The checkpoint
    record", key 13)."""
    rep = S.Replica(r, r.log.anc[c])
    admins = rep.sp.administrators()
    return [x for x in (rep.tv.slot_entry(rep.sp, d) for d in admins) if x is not None]


def cut_at_limit() -> dict:
    """peers.json's `skeleton_cuts` limit: a cut with 512 slot entries, every
    one enrolled, each with its slot keys and seniority and naming its
    enrolment by ID, signed by a pseudonym; its size beside the 262,144-byte
    bound of a storage event; and one entry more, Malformed."""
    from primitives import ed25519_public
    hist = events.History("skeleton-cuts/limit")
    hist.without_xwing("P0")
    space = example("skeleton-cuts/limit/space")

    def entry(i):
        return {"slot": (example(f"skeleton-cuts/limit/c/{i}"), i % 64,
                         example(f"skeleton-cuts/limit/maker/{i}")),
                "slot_ed": ed25519_public(example(f"skeleton-cuts/limit/slot-ed/{i}")),
                "slot_mldsa_hash": example(f"skeleton-cuts/limit/slot-mldsa/{i}"),
                "seniority": (2 ** 32 - 1, 2 ** 32 - 1, None,
                              example(f"skeleton-cuts/limit/maker/{i}")),
                "pseudonym": example(f"skeleton-cuts/limit/enrolment/{i}")}
    # The most standing entries: one per slot, and as many heard members'
    # slots besides, with the largest orders.
    standing = [{"slot": entry(i)["slot"], "order": i + 1, "dormant": 0}
                for i in range(S.MAX_CUT_SLOTS)] + [
        {"slot": (example(f"skeleton-cuts/limit/heard-c/{i}"), 63,
                  example(f"skeleton-cuts/limit/heard-maker/{i}")),
         "order": S.MAX_CUT_SLOTS + i + 1, "dormant": 0,
         "pseudonym": example(f"skeleton-cuts/limit/heard-enrolment/{i}")}
        for i in range(S.MAX_STANDING - S.MAX_CUT_SLOTS)]
    body = S.cut_body(example("skeleton-cuts/limit/twin"), example("skeleton-cuts/limit/salt"),
                      example("skeleton-cuts/limit/record") * 2, 2 ** 32 - 1,
                      [entry(i) for i in range(S.MAX_CUT_SLOTS)], standing)
    assert len(S.read_body(body)["slots"]) == S.MAX_CUT_SLOTS
    assert len(S.read_body(body)["standing"]) == S.MAX_STANDING
    # Its prev is among its parents, as events.md requires, and the parents
    # are still as many as an event may cite.
    prev = example("skeleton-cuts/limit/prev")
    parents = sorted([prev] + [example(f"skeleton-cuts/limit/parent/{i}")
                               for i in range(events.MAX_PARENTS - 1)])
    fields = events.event_fields(KIND_STORAGE, hist.signer("P0"), 2 ** 32 - 1, body, log=space,
                                 prev=prev, parents=parents,
                                 cuts=[example(f"skeleton-cuts/limit/cut/{i}")
                                       for i in range(4)])
    signed = events.sign_fields(fields, hist.signer("P0"))
    assert len(signed) <= S.MAX_STORAGE_EVENT
    decoded = events.decode_event(signed)  # well formed: Malformed would raise
    assert decoded.prev == prev and prev in decoded.parents
    over = S.cut_body(example("skeleton-cuts/limit/twin"), example("skeleton-cuts/limit/salt"),
                      example("skeleton-cuts/limit/record") * 2, 1,
                      [entry(i) for i in range(S.MAX_CUT_SLOTS + 1)], standing[:1])
    try:
        S.read_body(over)
        raise AssertionError("513 slot entries read")
    except SpecError as error:
        assert error.error == "Malformed"
    bad_ed = S.cut_body(example("skeleton-cuts/limit/twin"), example("skeleton-cuts/limit/salt"),
                        example("skeleton-cuts/limit/record") * 2, 1,
                        [entry(0) | {"slot_ed": bytes(31) + b"\x80"}], standing[:1])
    no_standing = S.cut_body(example("skeleton-cuts/limit/twin"),
                             example("skeleton-cuts/limit/salt"),
                             example("skeleton-cuts/limit/record") * 2, 1, [entry(0)], [])
    over_standing = S.cut_body(example("skeleton-cuts/limit/twin"),
                               example("skeleton-cuts/limit/salt"),
                               example("skeleton-cuts/limit/record") * 2, 1, [entry(0)],
                               standing + [{"slot": (bytes(32), 0, bytes(32)),
                                            "order": S.MAX_STANDING + 1, "dormant": 0}])
    for name, data in (("no standing entry", no_standing),
                       ("1,025 standing entries", over_standing)):
        try:
            S.read_body(data)
            raise AssertionError(name)
        except SpecError as error:
            assert error.error == "Malformed", (name, error.error)
    bad_class = "InvalidKey"
    try:
        S.read_body(bad_ed)
        raise AssertionError("an invalid slot_ed read")
    except SpecError as error:
        bad_class = error.error
    assert bad_class == "InvalidKey"
    return {"slots": S.MAX_CUT_SLOTS, "body": h(body), "body_bytes": len(body),
            "signed": h(signed), "signed_bytes": len(signed),
            "storage_event_bound": S.MAX_STORAGE_EVENT,
            "note": "512 enrolled slot entries, 1,024 standing entries, the largest seniority "
                    "values, a full set of parents and 4 cuts: within the bound, with "
                    f"{S.MAX_STORAGE_EVENT - len(signed)} bytes to spare",
            "refusals": [{"name": "513 slot entries", "body": h(over), "class": "Malformed"},
                         {"name": "no standing entry", "body": h(no_standing),
                          "class": "Malformed"},
                         {"name": "1,025 standing entries", "body": h(over_standing),
                          "class": "Malformed"},
                         {"name": "a slot_ed that is no valid Ed25519 key", "body": h(bad_ed),
                          "class": bad_class}]}


# ---------------------------------------------------------------------------
# Building skeletons with cuts.


def make_cut(r: S.StorageRoster, by: str, pseudonym: str, label: str, *, detached=False,
             **kw) -> tuple:
    """`by` checkpoints the space; its pseudonym signs the checkpoint's cut
    first, naming the record object's locator, and the checkpoint names the
    cut as its twin and cites it. `fence=False` makes a dishonest
    administrator's: the checkpoint and its cut cite every head of their
    views, concurrent checkpoints included."""
    CP.attach(r)
    p = r.predict(by, label)
    out = {}

    def twin_maker(locator, parents, past, fence=True):
        # The cut cites every other parent of its checkpoint, beside its
        # pseudonym's previous event (peers.md, "Skeleton cuts"): the
        # checkpoint's past is the cut's and the cut, so the skeleton the
        # peer reads of the cut's past is the one the record's slot entries
        # read, and the cut follows what its checkpoint follows.
        r.hist.without_xwing(pseudonym)
        author = r.hist.device(pseudonym)
        mine = [i for i in r.hist.view[pseudonym] if r.log.events[i].author == author]
        tview = set(past)
        for i in mine:
            tview |= r.log.anc[i] | {i}
        pctx = PCtx(r.log)
        sk = skeleton_of(pctx, tview)
        ch = pctx.memo[("sk", frozenset(tview), None, "chain")]
        epoch = (pctx.body(ch[-1])["epoch"] + 1) if ch else 1
        s = r.hist.act(pseudonym, KIND_STORAGE,
                       S.cut_body(p["c"], p["salt"], locator, epoch, summary(sk),
                                  getattr(r, "_cut_standing", ())),
                       f"{pseudonym}: cut of {label}", view=tview, parents=set(parents),
                       fence=fence)
        r._next_twin = s
        out["cut"] = s
        # A dishonest device names the cut without citing it.
        return [] if detached else [s]
    c = CP.make_checkpoint(r, by, label, twin_maker=twin_maker, **kw)
    r.twin_names[c] = out["cut"]
    return c, out["cut"]


PSEUDO = {"P": "P0", "A": "A1", "B": "B1", "C": "C1"}
AGAIN = {"A": "A2", "B": "B2", "C": "C2"}
LATE_EPISODES = 0.75  # the fraction of random histories given a late enrolment


def enrol_again(r, pctx: PCtx, who: str, granted: dict, cut, label: str):
    """peers.md, "A late enrolment": once the cut is in effect, a device whose
    enrolment is late under it enrols the same slot again, under a new
    pseudonym, after the checkpoint, its binding sealed as peers.md, section
    2.5, says (under the twin_secret of the checkpoint its cuts name whose
    cut lists the slot); then the new pseudonym acknowledges."""
    c = pctx.checkpoint_of(cut)
    fresh = AGAIN[who]
    e = r.enrol(fresh, who, granted[who], 0, label, view=r.hist.view[who])
    assert c in r.log.events[e].cuts or any(c in pctx.reach(x) for x in r.log.events[e].cuts)
    r.sync(who, fresh)
    a = r.request(fresh, S.ack_body(), f"{label}: {fresh} acknowledges", view=r.hist.view[fresh])
    r.sync(who, fresh)
    return e, a


def late_enrolment(pctx: PCtx, cut, held, r, who: str) -> bool:
    """Whether `who`'s enrolment is late at the peer under `cut`: its slot is a
    slot of the cut that names no enrolment of its pseudonym, and its
    enrolment is held, neither in the checkpoint's past nor after it."""
    p = r.hist.device(PSEUDO[who])
    mine = [i for i in held if r.log.events[i].author == p and pctx.body(i) is not None
            and pctx.body(i)["type"] == S.ENROL]
    return bool(mine) and all(i in late_at_peer(pctx, cut, held) for i in mine) and any(
        s_["slot"] == r.admin_slot[who] and s_["pseudonym"] not in mine
        for s_ in pctx.body(cut)["slots"])


def random_skeleton(seed: int, steps: int = 22, adversarial: bool = True):
    """With `adversarial`, an administrator sometimes acts dishonestly: it
    takes another's view and checkpoints, or acknowledges, citing every head
    it holds, concurrent checkpoints included (no fence)."""
    rng = random.Random(seed)
    adv = random.Random(seed * 7907 + 1)
    r = S.StorageRoster("P", f"skeleton-cuts/{seed}")
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    admins = {"P"}
    enrolled = {"P"}
    # Ranks (roster.md, section 2.3), drawn apart: 255, 200 or 100, never
    # above the granter's; the founder at 255.
    rk = random.Random(seed * 7907 + 29)
    ranks = {"P": S.MAX_RANK}
    r.rank_attempts = 0
    # Events a dishonest step signed: unfenced acknowledgements, and the
    # checkpoints and cuts signed on another's view or unfenced.
    r.dishonest = set()
    cuts = []
    rogues: list = []
    unenrolled: dict = {}
    granted: dict = {}
    r.apart_enrolments = 0
    # An administrator granted and not enrolled enrols, after syncing or on
    # its own view (apart), drawn apart from the other choices.
    late_rng = random.Random(seed * 7907 + 53)
    snaps = []
    # In a stated fraction of histories, it starts with a late enrolment: P
    # grants C administer; C enrols apart and acknowledges, while P
    # checkpoints without it and votes; C syncs, follows the checkpoint,
    # votes and enrols again, its new enrolment the slot's vote; P then
    # removes C, which takes no further part.
    r.late_episode = False
    r.re_enrolments = []
    episode = random.Random(seed * 7907 + 71)
    if episode.random() < LATE_EPISODES:
        R_, _ = r.grant_admin("P", "P0", "C", "P grants C administer", rank=100)
        r.sync("P", "P0", "C")
        r.enrol("C1", "C", R_, 0, "C1 enrols apart")
        r.sync("C", "C1")
        r.request("C1", S.ack_body(), "C1 acknowledges apart", view=r.hist.view["C1"])
        r.sync("C", "C1")
        c_, cut_ = make_cut(r, "P", "P0", "P checkpoints, without C's enrolment")
        r.sync("P", "P0")
        r.anchor("P", "P votes, C apart")
        r.sync("P", "P0")
        r.request("P0", S.ack_body(), "P0 votes, C apart",
                  view=r.hist.view["P0"] | r.hist.view["P"])
        r.sync(*r.everyone())
        r.anchor("C", "C votes, its enrolment late")
        pctx = PCtx(r.log)
        e, a = enrol_again(r, pctx, "C", {"C": R_}, cut_, "C enrols again")
        r.re_enrolments.append(("C", e, a, cut_))
        r.sync(*r.everyone())
        r.remove_admin("P", "P0", "C", "P removes C")
        r.sync(*r.everyone())
        r.late_episode = True
    for step in range(steps):
        by = rng.choice(sorted(admins & enrolled))
        op = rng.random()
        enrols_now = bool(unenrolled) and late_rng.random() < 0.3
        try:
            if enrols_now:
                who = sorted(unenrolled)[0]
                apart = late_rng.random() < 0.6
                if not apart:
                    r.sync(who, by)
                R_ = unenrolled.pop(who)
                r.enrol(PSEUDO[who], who, R_, 0, f"{step}: {who} enrols"
                        + (" apart" if apart else " late"))
                r.sync(who, PSEUDO[who])
                if apart:
                    # Enrolled on its own view, perhaps concurrently with a
                    # cut, and built on: its pseudonym acknowledges and its
                    # device anchors before they meet anyone.
                    r.apart_enrolments += 1
                    r.request(PSEUDO[who], S.ack_body(),
                              f"{step}: {PSEUDO[who]} acknowledges apart",
                              view=r.hist.view[PSEUDO[who]])
                    r.sync(who, PSEUDO[who])
                    r.anchor(who, f"{step}: {who} anchors apart")
                    if by != who and late_rng.random() < 0.9:
                        # Meanwhile another administrator checkpoints
                        # without it: the enrolment is concurrent with the
                        # cut.
                        c_, cut_ = make_cut(r, by, PSEUDO[by],
                                            f"{step}: {by} checkpoints apart from {who}")
                        cuts.append(cut_)
                else:
                    r.sync(by, PSEUDO[by], who, PSEUDO[who])
                enrolled.add(who)
            elif op < 0.2 and len(admins) < 3:
                who = next(n for n in ("A", "B") if n not in admins)
                ranks[who] = min(rk.choice([S.MAX_RANK, 200, 100]), ranks[by])
                R_, s = r.grant_admin(by, PSEUDO[by], who,
                                      f"{step}: {by} grants {who} at rank {ranks[who]}",
                                      rank=ranks[who])
                granted[who] = R_
                r.sync(by, PSEUDO[by], who)
                admins.add(who)
                if rng.random() < 0.6:
                    r.enrol(PSEUDO[who], who, R_, 0, f"{step}: {who} enrols")
                    r.sync(by, PSEUDO[by], who, PSEUDO[who])
                    enrolled.add(who)
                else:
                    # Granted, not enrolled yet: a checkpoint meanwhile
                    # records its slot with an empty pseudonym.
                    unenrolled[who] = R_
            elif op < 0.3 and len(admins) > 1:
                who = rng.choice(sorted(admins - {by, "P"}) or [None])
                if who is None:
                    continue
                # An honest administrator removes no higher rank; now and
                # then one tries (HigherRank at replicas and at the peer).
                attempt = ranks[who] > ranks[by]
                if attempt and rk.random() >= 0.5:
                    continue
                r.remove_admin(by, PSEUDO[by], who, f"{step}: {by} removes {who}"
                               + (", a higher rank" if attempt else ""))
                if attempt:
                    r.rank_attempts += 1
                    continue
                admins.discard(who)
                enrolled.discard(who)
                unenrolled.pop(who, None)
            elif op < 0.55:
                name = rng.choice(sorted(admins & enrolled))
                r.sync(name, PSEUDO[name])
                rogue = adversarial and adv.random() < 0.2
                ack = r.request(PSEUDO[name], S.ack_body(),
                                f"{step}: {PSEUDO[name]} acknowledges"
                                + (", unfenced" if rogue else ""),
                                view=r.hist.view[name] | r.hist.view[PSEUDO[name]],
                                **({"fence": False} if rogue else {}))
                if rogue:
                    r.dishonest.add(ack)
                # Its device votes in the space too (roster.md, "Votes and
                # effect"), by an anchor.
                r.sync(name, PSEUDO[name])
                r.anchor(name, f"{step}: {name} votes")
            elif op < 0.6:
                name = rng.choice(sorted(admins & enrolled))
                r.request(PSEUDO[name], S.erase_body(), f"{step}: {PSEUDO[name]} erases",
                          view=r.hist.view[PSEUDO[name]])
            elif op < 0.65:
                # A credentials request naming the genesis's entry.
                name = rng.choice(sorted(admins & enrolled))
                live = [(S.kg.encode_set((r.genesis,)),
                         S.kg.read_credential(r.krot[r.genesis])["public"])]
                r.request(PSEUDO[name], S.credentials_body(live=live),
                          f"{step}: {PSEUDO[name]} asks for credentials",
                          view=r.hist.view[PSEUDO[name]])
            elif op < 0.72:
                # A writer releases or restores a stream (peers.md, "Release
                # and restore"): truncation must keep what decides it.
                name = rng.choice(sorted(admins))
                stream = S.stream(rng.choice(("x", "y")))
                body = S.release_body(stream) if rng.random() < 0.6 else S.restore_body(stream)
                r.request(name, body, f"{step}: {name} releases or restores",
                          view=r.hist.view[name])
            elif op < 0.85:
                rogue = adversarial and adv.random() < 0.35
                if rogue:
                    # A dishonest administrator: it takes another member's
                    # view, then checkpoints without fencing.
                    other = adv.choice(sorted(n for n in r.hist.view if r.hist.view[n]))
                    r.hist.view[by] |= r.hist.view[other]
                    r.hist.view[PSEUDO[by]] |= r.hist.view[other]
                detached = rogue and adv.random() < 0.3
                c, cut = make_cut(r, by, PSEUDO[by],
                                  f"{step}: {by} checkpoints" + (", unfenced" if rogue else "")
                                  + (", naming a cut it does not cite" if detached else ""),
                                  fence=not rogue, detached=detached)
                cuts.append(cut)
                if rogue:
                    rogues.append(cut)
                    r.dishonest |= {c, cut}
            else:
                names = sorted(admins | {PSEUDO[a] for a in admins})
                a, b = rng.sample(names, 2)
                r.sync(a, b)
        except (SpecError, KeyError, StopIteration, ValueError, AssertionError):
            continue
        snaps.append({n: set(v) for n, v in r.hist.view.items()})
    r.sync(*r.everyone())
    # peers.md, "A late enrolment": an administrator whose enrolment is late
    # under the cut in effect enrols again after it, and its device votes.
    # It does so once it votes for the checkpoint, since the cut waits for
    # its slot's vote, which the new enrolment is: here, for the valid cut of
    # the latest checkpoint that the device follows.
    pctx = PCtx(r.log)
    final = set(r.log.events)
    skeleton_of(pctx, final)
    ch = pctx.memo[("sk", frozenset(final), None, "chain")]
    pending = sorted((k for k in final if pctx.is_cut(k) and validity(pctx, k)[0]
                      and k not in ch), key=lambda k: (-pctx.body(k)["epoch"], k))
    for who in sorted(admins & enrolled - {"P"}):
        if who not in AGAIN or who not in granted:
            continue
        followed = r.followed(who, r.hist.view[who])
        cut = next((k for k in pending + ch[::-1] if pctx.checkpoint_of(k) == followed), None)
        if cut is None or not late_enrolment(pctx, cut, final, r, who):
            # Else the earliest pending cut that waits for its slot: the
            # device follows that checkpoint and votes for it.
            fallback = next((k for k in sorted(pending, key=lambda k: (pctx.body(k)["epoch"], k))
                             if any(x["slot"] == r.admin_slot[who] and x["dormant"] == 0
                                    for x in pctx.body(k)["standing"])), None)
            if fallback is not None:
                ck = pctx.checkpoint_of(fallback)
                r.hist.view[who] |= r.log.anc[ck] | {ck}
                if r.followed(who, r.hist.view[who]) == ck:
                    cut = fallback
        if cut is not None and r.followed(who, r.hist.view[who]) == pctx.checkpoint_of(cut) \
                and late_enrolment(pctx, cut, final, r, who):
            e, a = enrol_again(r, pctx, who, granted, cut, f"{who} enrols again")
            r.re_enrolments.append((who, e, a, cut))
    if r.re_enrolments:
        r.sync(*r.everyone())
        for who, *_ in r.re_enrolments:
            r.anchor(who, f"{who} votes after enrolling again")
        r.sync(*r.everyone())
    r.rogue_cuts = rogues
    return r, cuts, snaps


def check_skeleton(seed: int) -> dict:
    r, cuts, snaps = random_skeleton(seed)
    final = set(r.log.events)
    full_ctx = PCtx(r.log)
    full = skeleton_of(full_ctx, final)
    ch = full_ctx.memo[("sk", frozenset(final), None, "chain")]
    out = {"events": len(final), "cuts": len(cuts), "effective": len(ch), "peers": 0,
           "compared": 0, "waited": 0, "streams_compared": 0, "records_checked": 0,
           "unfenced_cuts": len(getattr(r, "rogue_cuts", ())), "cut_verdicts": {},
           "rank_attempts": getattr(r, "rank_attempts", 0),
           "higher_rank_at_peer": sum(1 for v in full.status.values() if v[1] == "HigherRank"),
           "apart_enrolments": getattr(r, "apart_enrolments", 0),
           "late_at_peer": sum(1 for v in full.status.values() if v[1] == "Late"),
           "re_enrolments": len(getattr(r, "re_enrolments", ()))}
    # A late skeleton event is stored and has no effect; a device that
    # enrolled late enrols again after the cut, validly there.
    for who, e, a, cut in getattr(r, "re_enrolments", ()):
        if cut in ch:
            # Valid in the world after the cut it was made after.
            w = world(full_ctx, cut, final)
            assert w.valid(e), ("a re-enrolment is void", seed, r.name(e), w.status.get(e))
            out["bound_peer"] = out.get("bound_peer", 0) + 1
    for cut in cuts:
        v = validity(full_ctx, cut)[1] if not validity(full_ctx, cut)[0] else "valid"
        out["cut_verdicts"][v] = out["cut_verdicts"].get(v, 0) + 1
    # The replica's check of each cut against its checkpoint's record: the
    # record of every checkpoint valid at a replica passes it (its step 9),
    # and one entry changed fails it.
    rctx = CP.Ctx(r.log, r.keyring(), objects=getattr(r, "objects", {}), skeleton=True)
    for cut in cuts:
        c = full_ctx.checkpoint_of(cut)
        if c is None or not CP.checkpoint_validity(rctx, c)[0]:
            continue
        assert validity(full_ctx, cut)[0], ("a valid checkpoint's cut is void", seed, r.name(cut))
        slots = [m["slot"] for m in rctx.record(c)["members"] if m["slot"] is not None]
        assert against_record(full_ctx, cut, slots) is None, \
            ("a valid cut fails the record check", seed, r.name(cut))
        if slots:
            wrong = [tuple(slots[0][:3]) + (bytes(32),)] + slots[1:]
            assert against_record(full_ctx, cut, wrong) == "BadTwin"
        out["records_checked"] += 1
    # peers.md, "Erasure", step 1: a request the peer may carry out (Free)
    # at some point, with what it holds then (every event signed so far), is
    # never made late by a cut it held then. A cut it did not hold yet and
    # that makes it late is one no honest administrator votes for at a peer
    # that carried out an erasure, since that peer acknowledges nothing more.
    final_ch = ch
    signed: set = set()
    freed: dict = {}
    for snap in snaps:
        signed |= set().union(*snap.values()) if snap else set()
        if not r.log.closed(signed):
            continue
        sctx = PCtx(r.log)
        for i in signed:
            b = sctx.body(i)
            if b is not None and b["type"] in (S.ERASE, S.CREDENTIALS) and i not in freed \
                    and request_state(sctx, signed, i) == "Free":
                freed[i] = frozenset(k for k in signed if sctx.is_cut(k))
    out["requests_freed"] = len(freed)
    if final_ch:
        last = final_ch[-1]
        c_last = full_ctx.checkpoint_of(last)
        for i, cuts_then in freed.items():
            late = i not in r.log.anc[c_last] and not full_ctx.follows_cut(i, last)
            if late:
                making = [k for k in final_ch if i not in r.log.anc[full_ctx.checkpoint_of(k)]
                          and not full_ctx.follows_cut(i, k)]
                assert not (set(making) & cuts_then), \
                    ("a request carried out is made late by a cut the peer held", seed, r.name(i))
                out["late_after_carry_out"] = out.get("late_after_carry_out", 0) + 1
    # peers.md, "The peer's answer to a late erasure": each erasure the
    # peer holds late, and has not carried out, is answered ErasureLate,
    # which the residue's checks pass, naming a cut of the chain whose
    # checkpoint makes it late; one carried out is answered `erased`, never
    # ErasureLate, though a cut that makes it late reaches the peer after.
    out["erasures_answered_late"] = out["erasures_answered_erased"] = 0
    late_answers = {}
    for i in sorted(final, key=r.log.order_key):
        b = full_ctx.body(i) if r.log.events[i].kind == KIND_STORAGE else None
        if b is None or b["type"] != S.ERASE:
            continue
        if i in freed:
            out["erasures_answered_erased"] += 1
            continue
        answer = erasure_answer(full_ctx, final, i)
        if answer["answer"] != "late":
            assert request_state(full_ctx, final, i) != "Late", ("late, unanswered", seed)
            continue
        assert request_state(full_ctx, final, i) == "Late" and answer["cut"] in ch, \
            ("an erasure answered late that is not", seed, r.name(i))
        msg = erasure_late_message(r.log, r.log.genesis, i, answer)
        got = residue_check(msg, r.log.genesis, i, answer["slot"])
        assert got["standing"] == answer["standing"] and got["entry"] == answer["entry"], seed
        # Standing 1 told apart: a named entry is another pseudonym's, which
        # holds the slot for good; an empty one sends the residue back in,
        # where the world after the cut says whether to enrol again or the
        # slot is held. Either way, no enrolment it could sign is refused
        # without the residue having said so.
        key = f"standing {got['standing']}, {got['entry']}: {got['action']}"
        if got["standing"] != STANDING_OUT:
            back = after_back_in(full_ctx, answer["cut"], answer["slot"],
                                 r.log.events[i].author, final)
            if got["entry"] == "named" and got["standing"] == STANDING_OTHER:
                assert back[0] == "slot held", (seed, r.name(i), back)
            key += f", back in: {back[0]}"
        out.setdefault("late_answer_kinds", {})
        out["late_answer_kinds"][key] = out["late_answer_kinds"].get(key, 0) + 1
        late_answers[i] = answer
        out["erasures_answered_late"] += 1
    seen = set()
    out["monotone_checked"] = 0
    for snap in snaps:
        for name, view in sorted(snap.items()):
            if not view or not r.log.closed(view):
                continue
            vctx = PCtx(r.log)
            skeleton_of(vctx, view)
            # peers.md, "In effect at the peer": monotone. A cut in effect
            # over this view is in effect over every superset, the final
            # one included.
            for k in view:
                if vctx.is_cut(k) and validity(vctx, k)[0] and stable(vctx, k, view):
                    assert stable(full_ctx, k, final), \
                        ("a cut leaves effect as events arrive", seed, r.name(k))
                    out["monotone_checked"] += 1
            vch = vctx.memo[("sk", frozenset(view), None, "chain")]
            assert not vch or ch[:len(vch)] == vch, ("(ii) a peer's cuts", seed)
            if not vch or vch[-1] in seen:
                continue
            seen.add(vch[-1])
            base = vch[-1]
            # Truncation waits for erasures and credentials requests in the
            # checkpoint's past (peers.md, "Truncation").
            if not may_truncate(full_ctx, base, final):
                out["waited"] += 1
                continue
            held = truncated(full_ctx, base, final)
            assert r.log.genesis in held
            tctx = PCtx(r.log, trusted={base}, held=held)
            trimmed = skeleton_of(tctx, held, base)
            # A peer that truncated under the cut a device enrolled again
            # after holds the new enrolment, valid, the slot enrolled to it.
            for who, e, _, cut in getattr(r, "re_enrolments", ()):
                if cut == base:
                    tw = world(tctx, base, held)
                    assert e in held and tw.valid(e), \
                        ("a truncated peer loses an enrolment made again", seed, who)
                    out["bound_truncated"] = out.get("bound_truncated", 0) + 1
            for i in held:
                if r.log.events[i].kind != KIND_STORAGE or i == base:
                    continue
                assert full.status.get(i) == trimmed.status.get(i), \
                    ("(i) a peer that truncated disagrees", seed, r.name(i), full.status.get(i),
                     trimmed.status.get(i))
                if S.read_body(r.log.events[i].body)["type"] in S.REQUEST_TYPES:
                    assert full.stable(i) == trimmed.stable(i), ("stability", seed, r.name(i))
            assert full.administrators() == trimmed.administrators(), ("administrators", seed)
            # A peer that truncated answers each late erasure it holds as one
            # that kept everything: the same cut, checkpoint and standing.
            for i, answer in late_answers.items():
                if i in held:
                    t_answer = erasure_answer(tctx, held, i, base)
                    assert t_answer == answer, ("a truncated peer answers otherwise", seed,
                                                r.name(i), answer, t_answer)
                    out["late_answers_truncated"] = out.get("late_answers_truncated", 0) + 1
            # What is released is decided alike: every release and restore
            # is kept.
            # What is released is decided alike by a peer that kept
            # everything and one that truncated, which holds the maximal
            # requests of the past and reads no order among them.
            for name in ("x", "y"):
                stream = S.stream(name)
                a_ = released_at_peer(full_ctx, final, stream)
                b_ = released_at_peer(tctx, held, stream, base)
                assert a_ == b_, ("released", seed, name, a_, b_)
                out["streams_compared"] += 1
                out["released"] = out.get("released", 0) + a_
            out["peers"] += 1
            out["compared"] += len(held)
    out.update(check_replicas(r, final, getattr(r, "re_enrolments", ())))
    return out


def world_binding(ctx, base, held):
    """The twin view of checkpoint `base`'s world over what a replica holds
    after it, which maps its skeleton's pseudonyms to devices."""
    after = {x for x in held if x == base or ctx.follows(x, base)}
    return CP.world_space(ctx, base, after | {base}).storage


def check_replicas(r, final, re_enrolments=()) -> dict:
    """The space replicas of a skeleton history (roster.md, "Other logs and
    extensions", Twins and the skeleton): one that keeps everything and one
    that forgot under each checkpoint in effect, holding only the kept
    checkpoint, its cut and the enrolments it names, agree on every event
    both hold, twins and records' `slot` entries included."""
    rctx = CP.Ctx(r.log, r.keyring(), objects=getattr(r, "objects", {}), skeleton=True)
    rfull = CP.judge(rctx, final)
    out = {"space_effective": len(rfull.chain), "replicas": 0, "replica_compared": 0,
           "slot_entries": 0, "empty_pseudonyms": 0, "space_validity": {}}
    for c in sorted(r.checkpoints):
        v = CP.checkpoint_validity(rctx, c)[1]
        out["space_validity"][v] = out["space_validity"].get(v, 0) + 1
        rec = rctx.record(c)
        if isinstance(rec, dict):
            for m in rec["members"]:
                if m["slot"] is not None:
                    out["slot_entries"] += 1
                    out["empty_pseudonyms"] += m["slot"][3] == b""
    out["newcomers"] = 0
    pctx = PCtx(r.log)
    skeleton_of(pctx, final)
    peer_chain = pctx.memo[("sk", frozenset(final), None, "chain")]
    # peers.md, "Skeleton cuts", what the peer cannot see: a cut in effect
    # at the peer has its checkpoint in effect at a replica that holds the
    # same events, honest clients voting with device and pseudonym alike.
    # The model's administrators acknowledge whatever they hold, so a cut
    # whose checkpoint replicas find void can get every vote here; honest
    # ones vote only for a valid checkpoint (roster.md, "Clients"), so only
    # a cut of a valid checkpoint is held to the rule.
    ahead = [k for k in peer_chain if pctx.checkpoint_of(k) not in rfull.chain]
    valid_ahead = [k for k in ahead
                   if CP.checkpoint_validity(rctx, pctx.checkpoint_of(k))[0]]
    out["peer_ahead_void_checkpoint"] = len(ahead) - len(valid_ahead)
    out["peer_ahead"] = len(valid_ahead)
    # The safety invariant of the cut rule: a peer never has a cut in effect
    # for a valid checkpoint that replicas do not have in effect, unless a
    # dishonest signer's own event is among what it counted: without every
    # dishonest event, the cut is not in effect at the peer.
    dishonest = set(getattr(r, "dishonest", set()))
    # A pseudonym's vote whose device never votes for the same checkpoint
    # breaks the duty to vote with both (peers.md, "The administrator's
    # duties"): the model's devices and pseudonyms follow checkpoints
    # apart, so such an event is a dishonest signer's too.
    device_of = {r.hist.device(p): r.hist.device(d)
                 for m in (PSEUDO, AGAIN) for d, p in m.items() if p in r.hist.signers}
    names = S.named_twins(r.log, set(final))
    for k in valid_ahead:
        ck = pctx.checkpoint_of(k)
        # A lowering that excuses at the peer, whose roster event replicas
        # do not hold valid: a lowering no roster event made, which only a
        # dishonest outranking administrator signs.
        for lows in excusing(pctx, k, set(final)).values():
            for low in lows:
                R_ = names.get(low)
                if R_ is None or not rfull.status.get(R_, (False,))[0]:
                    dishonest.add(low)
        for i in final:
            d = device_of.get(r.log.events[i].author)
            if d is None or not (i == ck or pctx.follows_cut(i, k)):
                continue
            if not any(r.log.events[j].author == d and (j == ck or ck in r.log.anc[j])
                       for j in final):
                dishonest.add(i)
    honest_view = set(final) - dishonest
    for k in valid_ahead:
        hctx = PCtx(r.log)
        honestly = k not in dishonest and pctx.checkpoint_of(k) not in dishonest \
            and stable(hctx, k, honest_view)
        assert not honestly, ("a cut in effect at the peer, not at replicas, on honest events",
                              r.name(k), [r.name(x) for x in rfull.chain],
                              [r.hist.key_name(d) for d in CP.electorate(rctx,
                               pctx.checkpoint_of(k), final)],
                              [r.hist.key_name(d) for d in CP.votes(rctx,
                               pctx.checkpoint_of(k), final)])
        out["peer_ahead_dishonest"] = out.get("peer_ahead_dishonest", 0) + 1
    for base in rfull.chain:
        # A newcomer that starts from base (roster.md, "Starting from a
        # checkpoint"), with what a peer that truncated under base's cut
        # serves: a parent the peer answers Missing for counts as dropped.
        cut = CP.twin_of(rctx, base)
        if cut in peer_chain and may_truncate(pctx, cut, final):
            nctx, nheld = CP.forget(rctx, base, final, served=truncated(pctx, cut, final))
            fresh = CP.judge(nctx, nheld, base)
            diff = CP.comparable(rfull, fresh, nheld)
            if CP.rival_checkpoints(nctx, nheld, base):
                assert all(b[1] == "Pending" for _, a, b in diff), ("a newcomer decides", r.name(base))
                out["rival_pending"] = out.get("rival_pending", 0) + 1
            else:
                assert not diff, ("a newcomer disagrees", r.name(base),
                                  [(r.name(i), a, b) for i, a, b in diff])
                out["newcomers"] += 1
                for who, e, _, cut_ in re_enrolments:
                    if cut_ == cut and e in nheld:
                        tv = world_binding(nctx, base, nheld)
                        assert tv.device_of(r.hist.device(AGAIN[who])) == r.hist.device(who), \
                            ("a newcomer binds no device to an enrolment made again", who)
                        out["bound_newcomer"] = out.get("bound_newcomer", 0) + 1
        fctx, held = CP.forget(rctx, base, final)
        forgot = CP.judge(fctx, held, base)
        diff = CP.comparable(rfull, forgot, held)
        if CP.rival_checkpoints(fctx, held, base):
            # A rival it cannot judge (roster.md, "Forgetting"): it holds
            # what it holds pending, and never decides otherwise.
            assert all(b[1] == "Pending" for _, a, b in diff), \
                ("a space replica with a rival decides", r.name(base))
            out["rival_pending"] = out.get("rival_pending", 0) + 1
            continue
        assert not diff, ("a space replica that forgot disagrees", r.name(base),
                          [(r.name(i), a, b) for i, a, b in diff])
        assert CP._roster_view(forgot.space) == CP._roster_view(rfull.space)
        # An enrolment after the checkpoint, sealed under its twin_secret,
        # binds the device alike at a replica that kept everything and one
        # that forgot; the late one binds none.
        if True:
            for who, e, _, cut in re_enrolments:
                if CP.twin_of(rctx, base) != cut:
                    continue
                fresh, late = r.hist.device(AGAIN[who]), r.hist.device(PSEUDO[who])
                # Read in the world of the checkpoint whose cut it was made
                # after, where it is, whatever checkpoints followed.
                for c_, v_ in ((rctx, final), (fctx, held)):
                    tv = world_binding(c_, base, v_)
                    assert tv.device_of(fresh) == r.hist.device(who), \
                        ("an enrolment after the cut binds no device", r.name(e))
                    assert tv.device_of(late) is None, ("a late enrolment binds", who)
                out["bound_again"] = out.get("bound_again", 0) + 1
        out["replicas"] += 1
        out["replica_compared"] += len(held)
    return out


def model_check(seeds, quiet=True) -> dict:
    total: dict = {"histories": 0}
    for seed in seeds:
        res = check_skeleton(seed)
        total["histories"] += 1
        for k, v in res.items():
            if isinstance(v, dict):
                for name, n in v.items():
                    total.setdefault(k, {})[name] = total.get(k, {}).get(name, 0) + n
            else:
                total[k] = total.get(k, 0) + v
        if not quiet:
            print(seed, res, file=sys.stderr)
    return total


def _scenario(prefix: str):
    """P founds the space and grants A administer; A enrols; P releases a
    stream and P0 asks for credentials; P checkpoints, with its cut; both
    acknowledge after it; then P removes A and P0 acknowledges."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A")
    r.enrol("A1", "A", ra, 0, "A1 enrols")
    r.sync("P", "P0", "A", "A1")
    rel = r.request("P", S.release_body(S.stream("x")), "P releases stream x",
                    view=r.hist.view["P"])
    live = [(S.kg.encode_set((r.genesis,)), S.kg.read_credential(r.krot[r.genesis])["public"])]
    cred = r.request("P0", S.credentials_body(live=live), "P0 asks for credentials",
                     view=r.hist.view["P0"] | r.hist.view["P"])
    r.sync("P", "P0", "A", "A1")
    c, cut = make_cut(r, "P", "P0", "P checkpoints")
    r.sync("P", "P0", "A", "A1")
    a0 = r.request("P0", S.ack_body(), "P0 acknowledges", view=r.hist.view["P"])
    a1 = r.request("A1", S.ack_body(), "A1 acknowledges", view=r.hist.view["A"])
    r.sync("P", "P0", "A", "A1")
    rm, _ = r.remove_admin("P", "P0", "A", "P removes A")
    r.sync("P", "P0", "A", "A1")
    a2 = r.request("P0", S.ack_body(), "P0 acknowledges the removal", view=r.hist.view["P"])
    r.sync("P", "P0", "A", "A1")
    return r, {"checkpoint": c, "cut": cut, "ack0": a0, "ack1": a1, "remove": rm, "ack2": a2,
               "release": rel, "credentials": cred}


def _waiting_scenario(prefix: str):
    """peers.md, "Truncation", the wait: P and A administer, A enrolled; P
    grants B administer, and B has not enrolled. P0 asks for erasure, then
    P checkpoints with its cut, and P0 and A1 acknowledge after it. The cut
    waits for B's slot too, which the record names: it is not in effect
    until B enrols after the checkpoint, its enrolment the slot's vote, and
    the erasure waits for B's slot, so a peer may not truncate. B enrols and
    acknowledges: the cut takes effect, the erasure is carried out, and the
    peer may truncate."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A")
    r.enrol("A1", "A", ra, 0, "A1 enrols")
    r.sync("P", "P0", "A", "A1")
    rb, _ = r.grant_admin("P", "P0", "B", "P grants B administer")
    r.sync("P", "P0", "A", "A1", "B")
    erase = r.request("P0", S.erase_body(), "P0 asks for erasure",
                      view=r.hist.view["P0"] | r.hist.view["P"])
    r.sync("P", "P0", "A", "A1", "B")
    c, cut = make_cut(r, "P", "P0", "P checkpoints")
    r.sync("P", "P0", "A", "A1", "B")
    r.request("P0", S.ack_body(), "P0 acknowledges", view=r.hist.view["P"])
    r.request("A1", S.ack_body(), "A1 acknowledges", view=r.hist.view["A"] | r.hist.view["P"])
    r.sync("P", "P0", "A", "A1", "B")
    before = set(r.log.events)
    r.enrol("B1", "B", rb, 0, "B1 enrols")
    r.sync("P", "P0", "A", "A1", "B", "B1")
    r.request("B1", S.ack_body(), "B1 acknowledges", view=r.hist.view["B1"] | r.hist.view["P"])
    r.sync("P", "P0", "A", "A1", "B", "B1")
    return r, {"checkpoint": c, "cut": cut, "erase": erase, "before": before}


def _waiting_checks(prefix: str) -> dict:
    r, ev = _waiting_scenario(prefix)
    out = {}
    for name, view in (("before B enrols", ev["before"]), ("after B acknowledges",
                                                            set(r.log.events))):
        ctx = PCtx(r.log)
        skeleton_of(ctx, view)
        ch = ctx.memo[("sk", frozenset(view), None, "chain")]
        assert ch == ([] if name == "before B enrols" else [ev["cut"]]), \
            (name, [r.name(x) for x in ch])
        out[name] = {"in_effect": [r.name(x) for x in ch],
                     "may_truncate": bool(ch) and may_truncate(ctx, ev["cut"], view)}
    assert not out["before B enrols"]["may_truncate"]
    assert out["after B acknowledges"]["may_truncate"]
    return {"r": r, "ev": ev, "states": out}


def _absent_scenario(prefix: str, removal: str | None):
    """peers.md, "Skeleton cuts", waited and excused slots: P founds the
    space; A, B and C administer at P's rank, granted in that order, each
    enrolled. B enrols and never returns. P checkpoints; P, A and C vote,
    each by an anchor and by its pseudonym. Then `removal`: A, senior to B,
    removes it ("senior"); C, junior to it, does ("junior"); or nobody does
    (None). The pseudonyms acknowledge after the removal."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    names = {"A": "A1", "B": "B1", "C": "C1"}
    for who in ("A", "B", "C"):
        R_, _ = r.grant_admin("P", "P0", who, f"P grants {who} administer", rank=S.MAX_RANK)
        r.sync("P", "P0", who)
        r.enrol(names[who], who, R_, 0, f"{names[who]} enrols")
        r.sync(*r.everyone())
    c, cut = make_cut(r, "P", "P0", "P checkpoints")
    r.sync(*r.everyone())
    for who, p in (("P", "P0"), ("A", "A1"), ("C", "C1")):
        r.sync(who, p, "P")
        r.anchor(who, f"{who} votes")
        r.sync(who, p)
        r.request(p, S.ack_body(), f"{p} votes", view=r.hist.view[p] | r.hist.view[who])
        r.sync(*[n for n in r.everyone() if n not in ("B", "B1")])
    if removal is not None:
        by = {"senior": "A", "junior": "C"}[removal]
        r.remove_admin(by, names[by], "B", f"{by} removes B, {removal} to it")
        r.sync(*[n for n in r.everyone() if n not in ("B", "B1")])
        for who, p in (("P", "P0"), ("A", "A1"), ("C", "C1")):
            r.request(p, S.ack_body(), f"{p} acknowledges the removal",
                      view=r.hist.view[p] | r.hist.view[who])
            r.sync(*[n for n in r.everyone() if n not in ("B", "B1")])
    return r, {"checkpoint": c, "cut": cut}


def _absent_checks(prefix: str) -> dict:
    """The cut takes effect at the peer exactly when its checkpoint does at
    a replica: with the senior's removal, both; with the junior's, or none,
    neither."""
    out = {}
    for removal, expected in (("senior", True), ("junior", False), (None, False)):
        name = removal or "none"
        r, ev = _absent_scenario(f"{prefix}/{name}", removal)
        final = set(r.log.events)
        ctx = PCtx(r.log)
        skeleton_of(ctx, final)
        peer = ctx.memo[("sk", frozenset(final), None, "chain")] == [ev["cut"]]
        rctx = CP.Ctx(r.log, r.keyring(), objects=r.objects, skeleton=True)
        rfull = CP.judge(rctx, final)
        replica = rfull.chain == [ev["checkpoint"]]
        assert peer == replica == expected, (name, peer, replica)
        out[name] = {"r": r, "ev": ev, "peer": peer, "replica": replica,
                     "standing": ctx.body(ev["cut"])["standing"], "rfull": rfull}
    return out


def _concurrent_request_scenario(prefix: str):
    """peers.md, "Erasure", steps 0 and 1: P and A administer, each
    enrolled. A1 asks for erasure on A's view; apart, P checkpoints, its cut
    leaving the erasure out. A peer that holds both waits: the cut can still
    take effect. P, A and their pseudonyms vote; the cut takes effect, and
    the erasure is late, void at the peer and at replicas alike. A signs it
    again after the checkpoint, and the new one is free to be carried
    out."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A")
    r.enrol("A1", "A", ra, 0, "A1 enrols")
    r.sync(*r.everyone())
    erase = r.request("A1", S.erase_body(), "A1 asks for erasure, apart",
                      view=r.hist.view["A1"] | r.hist.view["A"])
    c, cut = make_cut(r, "P", "P0", "P checkpoints, without the erasure")
    both = set(r.log.events)
    r.sync(*r.everyone())
    for who, p in (("P", "P0"), ("A", "A1")):
        r.anchor(who, f"{who} votes")
        r.sync(who, p)
        r.request(p, S.ack_body(), f"{p} votes", view=r.hist.view[p] | r.hist.view[who])
        r.sync(*r.everyone())
    voted = set(r.log.events)
    again = r.request("A1", S.erase_body(), "A1 asks for erasure again, after the checkpoint",
                      view=r.hist.view["A1"] | r.hist.view["A"])
    r.sync(*r.everyone())
    return r, {"checkpoint": c, "cut": cut, "erase": erase, "again": again, "both": both,
               "voted": voted}


def _concurrent_request_checks(prefix: str) -> dict:
    r, ev = _concurrent_request_scenario(prefix)
    final = set(r.log.events)
    states = {}
    for name, view in (("the peer holds the erasure and the cut", ev["both"]),
                       ("the cut in effect", ev["voted"]), ("signed again", final)):
        ctx = PCtx(r.log)
        states[name] = {"erasure": request_state(ctx, view, ev["erase"])}
        if ev["again"] in view:
            states[name]["again"] = request_state(ctx, view, ev["again"])
    assert states["the peer holds the erasure and the cut"]["erasure"] == "Wait", states
    assert states["the cut in effect"]["erasure"] == "Late", states
    assert states["signed again"] == {"erasure": "Late", "again": "Free"}, states
    rctx = CP.Ctx(r.log, r.keyring(), objects=r.objects, skeleton=True)
    rfull = CP.judge(rctx, final)
    assert rfull.chain == [ev["checkpoint"]]
    ctx = PCtx(r.log)
    full = skeleton_of(ctx, final)
    assert full.status[ev["erase"]] == (False, "Late", None), full.status.get(ev["erase"])
    # peers.md, "The peer's answer to a late erasure": A1, its residue
    # storing the erasure again, is answered ErasureLate, naming P's cut and
    # checkpoint, its slot still enrolled to A1 there; while the cut can
    # still take effect, the peer only acknowledges. The residue checks what
    # needs no key, and a peer that lies about the standing is caught.
    space = r.log.genesis
    waiting = erasure_answer(PCtx(r.log), ev["both"], ev["erase"])
    assert waiting == {"answer": "acknowledged"}, waiting
    answer = erasure_answer(PCtx(r.log), ev["voted"], ev["erase"])
    assert answer["answer"] == "late" and answer["cut"] == ev["cut"] \
        and answer["checkpoint"] == ev["checkpoint"] \
        and answer["standing"] == STANDING_ENROLLED, answer
    assert erasure_answer(PCtx(r.log), final, ev["again"]) == {"answer": "acknowledged"}
    message = erasure_late_message(r.log, space, ev["erase"], answer)
    checked = residue_check(message, space, ev["erase"], answer["slot"])
    assert checked == {"checkpoint": ev["checkpoint"], "cut": ev["cut"],
                       "standing": STANDING_ENROLLED, "entry": "named",
                       "action": "back in"}
    lying = cbor({**uncbor(message), 5: STANDING_OUT})
    refusals = {}
    for name, bad in (("a standing of 2 while the cut lists the slot", lying),
                      ("a checkpoint's envelope in place of the cut's",
                       cbor({**uncbor(message), 3: r.log.events[ev["checkpoint"]].signed})),
                      ("another erasure's ID", cbor({**uncbor(message), 2: bytes(32)}))):
        try:
            residue_check(bad, space, ev["erase"], answer["slot"])
            refusals[name] = None
        except SpecError as e:
            refusals[name] = e.error
    assert refusals == {"a standing of 2 while the cut lists the slot": "PeerError",
                        "a checkpoint's envelope in place of the cut's": "PeerError",
                        "another erasure's ID": "Malformed"}, refusals
    return {"r": r, "ev": ev, "states": states, "full": full,
            "erasure_late": {"space": h(space), "erasure": h(ev["erase"]),
                             "slot": [h(answer["slot"][0]), answer["slot"][1],
                                      h(answer["slot"][2])],
                             "message": h(message), "checkpoint": h(ev["checkpoint"]),
                             "cut": h(ev["cut"]), "standing": STANDING_ENROLLED,
                             "refusals": [{"name": n, "message": h(b), "error": refusals[n]}
                                          for n, b in (("a standing of 2 while the cut lists "
                                                        "the slot", lying),)] +
                             [{"name": n, "error": refusals[n]} for n in
                              ("a checkpoint's envelope in place of the cut's",
                               "another erasure's ID")]}}


def slot_limit_checks(n: int, prefix: str = "skeleton-cuts/slot-limit") -> dict:
    """peers.md, "Storage events", the cut's bound, on a real skeleton: P
    founds the space and grants n - 1 devices administer, 64 to an update,
    each enrolling its slot. P checkpoints. At n = 512 the cut lists every
    slot and is valid; it takes effect once every slot votes, and not while
    one has not. At n = 513 its body is Malformed: no cut, so the space
    takes no checkpoint until it removes an administrator."""
    r = S.StorageRoster("P", f"{prefix}/{n}")
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    names = [f"D{i}" for i in range(n - 1)]
    for b in range(0, len(names), 64):
        batch = names[b:b + 64]
        granted, _ = r.grant_admin("P", "P0", batch, f"P grants {batch[0]} to {batch[-1]}")
        r.sync("P", "P0", *batch)
        for k, d in enumerate(batch):
            r.enrol(f"{d}p", d, granted, k, f"{d}p enrols")
        r.sync("P", "P0", *batch, *[f"{d}p" for d in batch])
    c, cut = make_cut(r, "P", "P0", "P checkpoints")
    out = {"administrators": n, "cut_bytes": len(r.log.events[cut].signed)}
    try:
        body = S.read_body(r.log.events[cut].body)
    except SpecError as e:
        assert n > S.MAX_CUT_SLOTS and e.error == "Malformed", (n, e.error)
        ctx = PCtx(r.log)
        assert not ctx.is_cut(cut) and chain(ctx, set(r.log.events)) == []
        out["cut"] = e.error
        return out
    assert len(body["slots"]) == n <= S.MAX_CUT_SLOTS
    r.sync(*r.everyone())
    votes = []
    for p_ in ["P0"] + [f"{d}p" for d in names]:
        votes.append(r.request(p_, S.ack_body(), f"{p_} votes", view=set(r.hist.view["P"])
                               | r.hist.view[p_]))
    final = set(r.log.events)
    ctx = PCtx(r.log)
    assert validity(ctx, cut)[0] and stable(ctx, cut, final)
    missing = final - {votes[-1]}
    assert not stable(PCtx(r.log), cut, missing)
    out.update(cut="valid", in_effect_with_every_vote=True, in_effect_with_one_missing=False)
    return out


def _held_cut_checks(prefix: str) -> dict:
    """peers.md, "Reserved cut keys": P and A administer, each enrolled. A1
    asks for erasure, apart, while P checkpoints with a cut whose body
    carries key 9, a later document's. Every one votes. At a peer that
    lacks that document the cut reads as ExtensionRequired: it is no cut,
    never in effect, and the erasure, which a cut that could still take
    effect would hold, is free. At a replica the checkpoint is held as
    ExtensionRequired, with every event after it, as for a record that
    uses a reserved key."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A")
    r.enrol("A1", "A", ra, 0, "A1 enrols")
    r.sync(*r.everyone())
    erase = r.request("A1", S.erase_body(), "A1 asks for erasure, apart",
                      view=r.hist.view["A1"] | r.hist.view["A"])
    plain = S.cut_body

    def with_key_9(*args, **kw):
        value = uncbor(plain(*args, **kw))
        value[S.RESERVED_CUT_KEY] = b"a later document's"
        return cbor(value)
    S.cut_body = with_key_9
    try:
        c, cut = make_cut(r, "P", "P0", "P checkpoints, its cut using key 9")
    finally:
        S.cut_body = plain
    r.sync(*r.everyone())
    for who, p_ in (("P", "P0"), ("A", "A1")):
        r.anchor(who, f"{who} votes")
        r.sync(who, p_)
        r.request(p_, S.ack_body(), f"{p_} votes", view=r.hist.view[p_] | r.hist.view[who])
        r.sync(*r.everyone())
    after = r.anchor("P", "P writes on")
    r.sync(*r.everyone())
    final = set(r.log.events)
    try:
        S.read_body(r.log.events[cut].body)
        read = "read"
    except SpecError as e:
        read = e.error
    assert read == "ExtensionRequired", read
    ctx = PCtx(r.log)
    assert not ctx.is_cut(cut) and chain(ctx, final) == []
    state = request_state(ctx, final, erase)
    assert state == "Free", state
    rctx = CP.Ctx(r.log, r.keyring(), objects=r.objects, skeleton=True)
    world = CP.judge(rctx, final)
    assert world.status[c] == (False, "ExtensionRequired", None), world.status[c]
    assert world.status[after][1] == "ExtensionRequired", world.status[after]
    return {"r": r, "checkpoint": c, "cut": cut, "erase": erase, "after": after,
            "peer": {"cut": read, "in_effect": False, "erasure": state},
            "replica": {"checkpoint": world.status[c][1],
                        "after": world.status[after][1]}}


def _slot_held_scenario(prefix: str, case: str):
    """peers.md, "A device's own erasure", standing 1 told apart. P and A
    administer; P0 is enrolled. A's first installation enrols A1 and asks
    for erasure, apart from everyone, while P checkpoints: A1's enrolment
    and its erasure are late. For "another", a second installation of A,
    restored from an earlier copy of its store that still held the slot
    token, has enrolled the slot as A3 before the checkpoint, so the cut
    lists the slot with A3. For "none", the cut lists the slot with no
    pseudonym, and the second installation, doing its duty after the
    checkpoint, enrols the slot again as A3 (its vote). P0 and A3 vote; the
    cut takes effect."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A")
    base = set(r.hist.view["A"])
    other = None
    if case == "another":
        other = r.enrol("A3", "A", ra, 0, "A3, another installation of A, enrols", view=base)
        r.sync("P", "P0", "A3")
    a1 = r.enrol("A1", "A", ra, 0, "A1 enrols, apart", view=base)
    r.sync("A", "A1")
    erase = r.request("A1", S.erase_body(), "A1 asks for erasure, apart",
                      view=r.hist.view["A1"] | r.hist.view["A"])
    c, cut = make_cut(r, "P", "P0", "P checkpoints")
    r.sync("P", "P0")
    r.request("P0", S.ack_body(), "P0 votes", view=r.hist.view["P0"] | r.hist.view["P"])
    r.sync("P", "P0")
    if case == "none":
        other = r.enrol("A3", "A", ra, 0,
                        "A3, another installation of A, enrols the slot after the checkpoint",
                        view=set(r.hist.view["P"]))
        r.sync("P", "P0", "A3")
    r.request("A3", S.ack_body(), "A3 votes", view=r.hist.view["A3"] | r.hist.view["P"])
    r.sync("P", "P0", "A3")
    r.anchor("P", "P votes")
    final = set(r.log.events)
    return r, {"checkpoint": c, "cut": cut, "erase": erase, "a1": a1, "other": other,
               "final": final, "grant": ra}


def _slot_held_checks(prefix: str) -> dict:
    out = {}
    for case in ("another", "none"):
        r, ev = _slot_held_scenario(f"{prefix}/{case}", case)
        final, space = ev["final"], r.log.genesis
        ctx = PCtx(r.log)
        assert chain(ctx, final) == [ev["cut"]], case
        answer = erasure_answer(ctx, final, ev["erase"])
        assert answer["answer"] == "late" and answer["standing"] == STANDING_OTHER, answer
        message = erasure_late_message(r.log, space, ev["erase"], answer)
        checked = residue_check(message, space, ev["erase"], answer["slot"])
        want = {"another": ("named", "slot held"), "none": ("none", "back in")}[case]
        assert (checked["entry"], checked["action"]) == want, (case, checked)
        author = r.log.events[ev["erase"]].author
        back = after_back_in(ctx, ev["cut"], answer["slot"], author, final)
        assert back == ("slot held", ev["other"]), (case, back)
        # The holder is another installation of A: its binding names A's
        # device, at a replica that holds the space.
        rctx = CP.Ctx(r.log, r.keyring(), objects=r.objects, skeleton=True)
        tv = world_binding(rctx, ev["checkpoint"], final)
        assert tv.device_of(r.hist.device("A3")) == r.hist.device("A"), case
        # An enrolment of the slot again, after the cut, is refused: the
        # slot is enrolled to A3 in the world after it.
        again = r.enrol("A2", "A", ev["grant"], 0, "A2, A's first installation, back in, "
                        "enrols the slot again", view=set(r.hist.view["P"]))
        w = world(PCtx(r.log), ev["cut"], set(r.log.events))
        assert w.status.get(again, (True,))[1] == "AlreadyEnrolled", (case, w.status.get(again))
        out[case] = {"r": r, "ev": ev, "message": message, "answer": answer, "checked": checked,
                     "again": again, "again_status": w.status.get(again)[1]}
    return out


def _release_order_scenario(prefix: str):
    """peers.md, "Truncation": P restores stream x, anchors, then releases
    it, the release reaching the restore only through the anchor. P
    checkpoints and both pseudonyms and devices vote. A peer that truncated
    holds the release alone, the maximal request, and finds x released as
    one that kept everything; one that kept every request of the past and
    read their order from what it holds would find them concurrent, and the
    restore winning."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    stream = S.stream("x")
    restore = r.request("P", S.restore_body(stream), "P restores x")
    r.anchor("P", "P anchors")
    release = r.request("P", S.release_body(stream), "P releases x, after its restore")
    r.sync("P", "P0")
    c, cut = make_cut(r, "P", "P0", "P checkpoints")
    r.sync("P", "P0")
    r.anchor("P", "P votes")
    r.sync("P", "P0")
    r.request("P0", S.ack_body(), "P0 votes", view=r.hist.view["P0"] | r.hist.view["P"])
    r.sync("P", "P0")
    return r, {"checkpoint": c, "cut": cut, "restore": restore, "release": release,
               "stream": stream}


def _release_order_checks(prefix: str) -> dict:
    r, ev = _release_order_scenario(prefix)
    final = set(r.log.events)
    ctx = PCtx(r.log)
    skeleton_of(ctx, final)
    assert ctx.memo[("sk", frozenset(final), None, "chain")] == [ev["cut"]]
    held = truncated(ctx, ev["cut"], final)
    assert ev["release"] in held and ev["restore"] not in held
    tctx = PCtx(r.log, trusted={ev["cut"]}, held=held)
    kept = released_at_peer(ctx, final, ev["stream"])
    trimmed = released_at_peer(tctx, held, ev["stream"], ev["cut"])
    # Had the peer kept both, it could not order them through the anchor
    # it deleted: they would read as concurrent, and the restore win.
    both = held | {ev["restore"]}
    old = released_at_peer(PCtx(r.log, trusted={ev["cut"]}, held=both), both, ev["stream"],
                           ev["cut"])
    assert kept and trimmed and not old, (kept, trimmed, old)
    # A replica that forgot under the checkpoint keeps, of the past's
    # requests, the maximal ones of each stream (units.md, "Release, restore
    # and erasure at a replica"), and finds the same.
    rctx = CP.Ctx(r.log, r.keyring(), objects=r.objects, skeleton=True)
    fctx, fheld = CP.forget(rctx, ev["checkpoint"], final)
    maximal = {i for i in kept_in_past(ctx, ev["cut"])
               if ctx.body(i) is not None and ctx.body(i)["type"] in S.WRITER_TYPES}
    rkeep = set(fheld) | maximal | {r.log.genesis, ev["cut"]}
    forgot = released_at_peer(PCtx(r.log, trusted={ev["cut"]}, held=rkeep), rkeep,
                              ev["stream"], ev["cut"])
    assert forgot, forgot
    return {"r": r, "ev": ev, "held": held, "kept": kept, "truncated": trimmed,
            "forgot": forgot, "keeping_every_request": old}


def _detached_scenario(prefix: str):
    """peers.md, "Skeleton cuts", the checkpoint of a cut: P and A
    administer; P's device names its pseudonym's cut in a checkpoint that
    does not cite it. No stored space event both names and cites the cut, so
    a peer holds it Unnamed, kept everything or not, and a replica finds
    the checkpoint BadTwin."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A")
    r.enrol("A1", "A", ra, 0, "A1 enrols")
    r.sync(*r.everyone())
    c, cut = make_cut(r, "P", "P0", "P checkpoints, naming a cut it does not cite",
                      detached=True)
    r.sync(*r.everyone())
    for who, p in (("P", "P0"), ("A", "A1")):
        r.anchor(who, f"{who} anchors")
        r.sync(who, p)
        r.request(p, S.ack_body(), f"{p} acknowledges", view=r.hist.view[p] | r.hist.view[who])
        r.sync(*r.everyone())
    return r, {"checkpoint": c, "cut": cut}


def _detached_checks(prefix: str) -> dict:
    r, ev = _detached_scenario(prefix)
    final = set(r.log.events)
    ctx = PCtx(r.log)
    assert ctx.checkpoint_of(ev["cut"]) is None
    assert validity(ctx, ev["cut"])[1] == "Unnamed"
    skeleton_of(ctx, final)
    assert ctx.memo[("sk", frozenset(final), None, "chain")] == []
    rctx = CP.Ctx(r.log, r.keyring(), objects=r.objects, skeleton=True)
    verdict = CP.checkpoint_validity(rctx, ev["checkpoint"])
    assert verdict[1] == "BadTwin", verdict
    return {"r": r, "ev": ev, "peer": validity(ctx, ev["cut"])[1], "replica": verdict[1]}


def _round_of_checkpoints(r, n: int, prefix: str) -> list:
    """`n` checkpoints in a row by P, each voted for by P and A, devices and
    pseudonyms alike, before the next is proposed."""
    out = []
    for k in range(n):
        c, cut = make_cut(r, "P", "P0", f"{prefix}P checkpoints ({k + 1})")
        r.sync(*r.everyone())
        for who, p in (("P", "P0"), ("A", "A1")):
            r.anchor(who, f"{prefix}{who} votes ({k + 1})")
            r.sync(who, p)
            r.request(p, S.ack_body(), f"{prefix}{p} votes ({k + 1})",
                      view=r.hist.view[p] | r.hist.view[who])
            r.sync(*r.everyone())
        out.append((c, cut))
    return out


def _peerless_checks(prefix: str) -> dict:
    """peers.md, "Between members": a space whose members never reach a
    peer checkpoints three times in a row, its cuts taking effect by the
    peer's rule over what the members hold; and one that checkpoints once
    with its peer, twice apart from it, after which the peer catches up,
    finds the same chain, truncates under the last cut, and agrees with one
    that kept everything."""
    out = {}
    r = S.StorageRoster("P", f"{prefix}/never")
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A")
    r.enrol("A1", "A", ra, 0, "A1 enrols")
    r.sync(*r.everyone())
    made = _round_of_checkpoints(r, 3, "")
    final = set(r.log.events)
    ctx = PCtx(r.log)
    skeleton_of(ctx, final)
    members = ctx.memo[("sk", frozenset(final), None, "chain")]
    assert members == [cut for _, cut in made], [r.name(x) for x in members]
    rctx = CP.Ctx(r.log, r.keyring(), objects=r.objects, skeleton=True)
    assert CP.judge(rctx, final).chain == [c for c, _ in made]
    out["never"] = {"r": r, "chain": [r.name(x) for x in members]}

    r = S.StorageRoster("P", f"{prefix}/apart")
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A")
    r.enrol("A1", "A", ra, 0, "A1 enrols")
    r.sync(*r.everyone())
    made = _round_of_checkpoints(r, 1, "with the peer: ")
    at_peer = set(r.log.events)
    made += _round_of_checkpoints(r, 2, "apart: ")
    final = set(r.log.events)
    pctx = PCtx(r.log)
    skeleton_of(pctx, at_peer)
    before = pctx.memo[("sk", frozenset(at_peer), None, "chain")]
    assert before == [made[0][1]]
    ctx = PCtx(r.log)
    full = skeleton_of(ctx, final)
    after = ctx.memo[("sk", frozenset(final), None, "chain")]
    assert after == [cut for _, cut in made]
    last = after[-1]
    assert may_truncate(ctx, last, final)
    held = truncated(ctx, last, final)
    trimmed = skeleton_of(PCtx(r.log, trusted={last}, held=held), held, last)
    assert all(full.status.get(i) == trimmed.status.get(i) for i in held if i != last)
    assert full.administrators() == trimmed.administrators()
    out["apart"] = {"r": r, "before": [r.name(x) for x in before],
                    "after": [r.name(x) for x in after],
                    "holds": sorted(r.name(i) for i in held)}
    return out


def _late_then_past_checks(prefix: str) -> dict:
    """peers.md, "Release and restore": A releases stream x apart, while P
    checkpoints (C1) without it; C1 takes effect, and the release is late.
    A's device then votes, its prev the release, and A checkpoints (C2), so
    that C2's past holds the late release. It still counts for nothing: x
    is not released under C2, at a peer that kept everything and at one
    that truncated under C2, and its verdict stays Late."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A")
    r.enrol("A1", "A", ra, 0, "A1 enrols")
    r.sync(*r.everyone())
    stream = S.stream("x")
    release = r.request("A", S.release_body(stream), "A releases x, apart")
    made = _round_of_checkpoints(r, 1, "C1: ")
    made += [(None, None)]
    c2, cut2 = make_cut(r, "A", "A1", "A checkpoints (C2)")
    r.sync(*r.everyone())
    for who, p in (("P", "P0"), ("A", "A1")):
        r.anchor(who, f"{who} votes for C2")
        r.sync(who, p)
        r.request(p, S.ack_body(), f"{p} votes for C2", view=r.hist.view[p] | r.hist.view[who])
        r.sync(*r.everyone())
    final = set(r.log.events)
    ctx = PCtx(r.log)
    skeleton_of(ctx, final)
    ch = ctx.memo[("sk", frozenset(final), None, "chain")]
    assert ch == [made[0][1], cut2], [r.name(x) for x in ch]
    assert release in r.log.anc[c2]
    kept = released_at_peer(ctx, final, stream)
    held = truncated(ctx, cut2, final)
    trimmed = released_at_peer(PCtx(r.log, trusted={cut2}, held=held), held, stream, cut2)
    assert not kept and not trimmed, (kept, trimmed)
    return {"r": r, "release": release, "kept": kept, "truncated": trimmed,
            "holds": sorted(r.name(i) for i in held)}


def _no_slot_checks(prefix: str) -> dict:
    """peers.md, "Storage events", standing entries: P, A and B administer,
    each enrolled; P disowns B's administrator slot, so the skeleton holds
    no slot for B, an administrator in the roster. P checkpoints: the cut's
    standing entries are P's and A's, ordered 1 and 2 with no gap for B. A
    peer finds the cut valid (step 7) and a replica the checkpoint valid,
    its standing entries those the record gives."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    for who, p in (("A", "A1"), ("B", "B1")):
        R_, _ = r.grant_admin("P", "P0", who, f"P grants {who} administer")
        r.sync("P", "P0", who)
        r.enrol(p, who, R_, 0, f"{p} enrols")
        r.sync(*r.everyone())
    r.request("P0", S.disown_body(r.admin_slot["B"]), "P0 disowns B's administrator slot",
              view=r.hist.view["P0"] | r.hist.view["P"])
    r.sync(*r.everyone())
    c, cut = make_cut(r, "P", "P0", "P checkpoints, B without a slot")
    ctx = PCtx(r.log)
    standing = ctx.body(cut)["standing"]
    assert sorted(x["order"] for x in standing) == [1, 2], standing
    assert validity(ctx, cut)[0], validity(ctx, cut)
    rctx = CP.Ctx(r.log, r.keyring(), objects=r.objects, skeleton=True)
    verdict = CP.checkpoint_validity(rctx, c)
    assert verdict[0], verdict
    return {"r": r, "cut": cut, "standing": standing, "peer": validity(ctx, cut)[1],
            "replica": verdict[1]}


def _heard_vote_checks(prefix: str) -> dict:
    """peers.md, "Skeleton cuts": P founds the space; A, then B, administer
    at its rank, each enrolled. B removes A, its senior, so the checkpoint P
    makes hears A: its standing names A's out slot with A1's enrolment. A,
    heard, does not vote; P, its senior, removes it again after the
    checkpoint, which excuses it at the peer and at replicas; P and B vote,
    and the cut takes effect. P checkpoints again, and P and B vote. A peer
    that truncated under the first cut keeps A1's enrolment, and agrees
    with a peer that kept everything on the second cut."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    for who, p in (("A", "A1"), ("B", "B1")):
        R_, _ = r.grant_admin("P", "P0", who, f"P grants {who} administer", rank=S.MAX_RANK)
        r.sync("P", "P0", who)
        r.enrol(p, who, R_, 0, f"{p} enrols")
        r.sync(*r.everyone())
    r.remove_admin("B", "B1", "A", "B removes A, its senior")
    r.sync(*r.everyone())
    made = []
    for k in (1, 2):
        c, cut = make_cut(r, "P", "P0", f"P checkpoints ({k})")
        r.sync(*r.everyone())
        # A, heard, never votes for a checkpoint that hears it (roster.md,
        # 3.15.7): P, its senior, excuses it by removing it again, a removal
        # void at replicas, A being no member, but an excuse at both.
        if k == 1:
            r.remove_admin("P", "P0", "A", "P removes A after the checkpoint, excusing it")
            r.sync(*r.everyone())
        for who, p in (("P", "P0"), ("B", "B1")):
            r.anchor(who, f"{who} votes ({k})")
            r.sync(who, p)
            r.request(p, S.ack_body(), f"{p} votes ({k})", view=r.hist.view[p] | r.hist.view[who])
            r.sync(*r.everyone())
        made.append((c, cut))
    final = set(r.log.events)
    ctx = PCtx(r.log)
    full = skeleton_of(ctx, final)
    first = made[0][1]
    heard = [x for x in ctx.body(first)["standing"] if x["pseudonym"] is not None]
    assert len(heard) == 1 and ctx.log.events[heard[0]["pseudonym"]].author == r.hist.device("A1")
    ch = ctx.memo[("sk", frozenset(final), None, "chain")]
    assert ch == [cut for _, cut in made], [r.name(x) for x in ch]
    held = truncated(ctx, first, final)
    assert heard[0]["pseudonym"] in held
    tctx = PCtx(r.log, trusted={first}, held=held)
    trimmed = skeleton_of(tctx, held, first)
    tch = tctx.memo[("sk", frozenset(held), first, "chain")]
    assert tch == ch, [r.name(x) for x in tch]
    assert all(full.status.get(i) == trimmed.status.get(i) for i in held if i != first)
    # Replicas agree: A, heard, voted nothing, and P's removal excuses it,
    # so both checkpoints take effect there as both cuts do at the peer.
    rctx = CP.Ctx(r.log, r.keyring(), objects=r.objects, skeleton=True)
    rchain = CP.judge(rctx, final).chain
    assert rchain == [c for c, _ in made], [r.name(x) for x in rchain]
    return {"r": r, "chain": [r.name(x) for x in ch], "holds": sorted(r.name(i) for i in held),
            "replica_chain": [r.name(x) for x in rchain]}


def _late_enrolment_refusals(prefix: str) -> dict:
    """peers.md, "What a late enrolment opens": with a cut in effect, three
    late enrolments are refused with section 3.11's classes: a second
    enrolment by a pseudonym the peer holds (BadSignature), one whose
    mldsa does not give its kc (NotCommitted), and one whose ML-DSA-65 half
    does not verify (BadSignature); a well-formed late one is Late."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    rb, _ = r.grant_admin("P", "P0", "B", "P grants B administer")
    r.sync("P", "P0", "B")
    good = r.enrol("B1", "B", rb, 0, "B1 enrols, apart")
    b = S.read_body(r.log.events[good].body)
    view = set(r.hist.view["B1"])
    second = r.hist.act("B1", KIND_STORAGE, r.log.events[good].body,
                        "B1 enrols a second time, apart", view=view)
    other = r.hist.without_xwing("B2").mldsa_public
    r.hist.without_xwing("X")
    wrong_kc = r.hist.act("X", KIND_STORAGE,
                          S.enrol_body(b["slot"], other, b["slot_mldsa"], b["authorization"],
                                       b["binding"]), "X enrols with another key, apart",
                          view=view)
    a3 = r.hist.without_xwing("A3")
    # A3's Ed25519 key and kc beside another ML-DSA-65 key: its ML-DSA-65
    # half does not verify under the key its body carries, which its kc
    # commits to.
    import copy as _copy
    forger = S.hs.Signer("A3, forged", a3.ed_seed, r.hist.signer("B2").mldsa_seed)
    forger = _copy.copy(forger)
    forger.kc, forger.device_id = a3.kc, a3.device_id
    r.hist.keys["A3, forged"] = a3.ed_seed
    r.hist.signers["A3, forged"] = forger
    r.hist.view["A3, forged"] = set(view)
    bad_sig = r.hist.act("A3, forged", KIND_STORAGE,
                         S.enrol_body(b["slot"], a3.mldsa_public, b["slot_mldsa"],
                                      b["authorization"], b["binding"]),
                         "A3 enrols, its signature broken, apart", view=view, unchecked=True)
    c, cut = make_cut(r, "P", "P0", "P checkpoints")
    r.sync("P", "P0")
    r.anchor("P", "P votes")
    r.sync("P", "P0")
    r.request("P0", S.ack_body(), "P0 votes", view=r.hist.view["P0"] | r.hist.view["P"])
    r.sync(*r.everyone())
    r.enrol("B2", "B", rb, 0, "B2 enrols again, after the checkpoint", view=r.hist.view["P"])
    r.sync(*r.everyone())
    r.anchor("B", "B votes")
    final = set(r.log.events)
    ctx = PCtx(r.log)
    sk = skeleton_of(ctx, final)
    assert ctx.memo[("sk", frozenset(final), None, "chain")] == [cut]
    got = {n: sk.status[i][1] for n, i in (("good", good), ("second", second),
                                          ("wrong_kc", wrong_kc), ("bad_sig", bad_sig))}
    assert got == {"good": "Late", "second": "BadSignature", "wrong_kc": "NotCommitted",
                   "bad_sig": "BadSignature"}, got
    return {"r": r, "verdicts": {r.name(i): sk.status[i][1]
                                 for i in (good, second, wrong_kc, bad_sig)}}


def _late_enrolment_scenario(prefix: str):
    """peers.md, "Late skeleton events" and "A late enrolment": P and A
    administer, A enrolled; P grants B administer and asks for erasure. Apart
    from them, B enrols (B1), B1 acknowledges, and B's device anchors on top
    of both. Meanwhile P checkpoints: its cut lists B's slot with no
    pseudonym. P0 and A1 acknowledge after it and A votes, so the cut takes
    effect at the peer. B then syncs: its enrolment is late. B's device votes
    by an anchor whose prev is its late anchor, and B enrols the same slot
    again (B2) after the checkpoint, sealed under its twin_secret, and B2
    acknowledges."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A")
    r.enrol("A1", "A", ra, 0, "A1 enrols")
    r.sync("P", "P0", "A", "A1")
    rb, _ = r.grant_admin("P", "P0", "B", "P grants B administer")
    r.sync("P", "P0", "A", "A1", "B")
    erase = r.request("P0", S.erase_body(), "P0 asks for erasure",
                      view=r.hist.view["P0"] | r.hist.view["P"])
    r.sync("P", "P0", "A", "A1")
    late = r.enrol("B1", "B", rb, 0, "B1 enrols, concurrently with the checkpoint")
    r.sync("B", "B1")
    late_ack = r.request("B1", S.ack_body(), "B1 acknowledges, on its late enrolment",
                         view=r.hist.view["B1"])
    r.sync("B", "B1")
    late_anchor = r.anchor("B", "B anchors on its late enrolment")
    c, cut = make_cut(r, "P", "P0", "P checkpoints")
    r.sync("P", "P0", "A", "A1")
    r.request("P0", S.ack_body(), "P0 acknowledges", view=r.hist.view["P"])
    r.request("A1", S.ack_body(), "A1 acknowledges", view=r.hist.view["A"] | r.hist.view["P"])
    r.sync("P", "P0", "A", "A1")
    r.anchor("A", "A votes")
    r.sync("P", "P0", "A", "A1", "B", "B1")
    vote = r.anchor("B", "B votes, its prev the late anchor")
    r.sync("P", "P0", "A", "A1", "B", "B1")
    before = set(r.log.events)
    pctx = PCtx(r.log)
    skeleton_of(pctx, before)
    again, again_ack = enrol_again(r, pctx, "B", {"B": rb}, cut,
                                   "B2 enrols the same slot again, after the checkpoint")
    r.sync(*r.everyone())
    return r, {"checkpoint": c, "cut": cut, "erase": erase, "late": late,
               "late_ack": late_ack, "late_anchor": late_anchor, "vote": vote,
               "again": again, "again_ack": again_ack, "before": before, "grant_b": rb}


def _late_enrolment_checks(prefix: str) -> dict:
    r, ev = _late_enrolment_scenario(prefix)
    final = set(r.log.events)
    ctx = PCtx(r.log)
    full = skeleton_of(ctx, final)
    assert ctx.memo[("sk", frozenset(final), None, "chain")] == [ev["cut"]]
    slot = r.admin_slot["B"]
    entry = next(s_ for s_ in ctx.body(ev["cut"])["slots"] if s_["slot"] == slot)
    assert entry["pseudonym"] is None
    # The peer stores the late events and gives them no effect; B2's
    # enrolment is valid in the world after the cut.
    for k in ("late", "late_ack"):
        assert full.status[ev[k]] == (False, "Late", None), (k, full.status.get(ev[k]))
    assert full.valid(ev["again"]) and full.merged[slot]["enrolled"] == r.hist.device("B2")
    # The erasure of the cut's past waits for B's slot until B2 is enrolled;
    # B2's events acknowledge it, though in the skeleton before the cut B's
    # slot is enrolled to B1, which acknowledged before the erasure reached
    # it.
    bctx = PCtx(r.log)
    states = {"before B enrols again": may_truncate(bctx, ev["cut"], ev["before"]),
              "after B enrols again": may_truncate(ctx, ev["cut"], final)}
    assert states == {"before B enrols again": False, "after B enrols again": True}, states
    # A peer that truncated agrees.
    held = truncated(ctx, ev["cut"], final)
    trimmed = skeleton_of(PCtx(r.log, trusted={ev["cut"]}, held=held), held, ev["cut"])
    assert all(full.status.get(i) == trimmed.status.get(i) for i in held if i != ev["cut"])
    assert full.administrators() == trimmed.administrators()
    # Replicas: B's vote counts, so the checkpoint takes effect; B2 binds B,
    # B1 binds nothing, at a replica that kept everything and one that
    # forgot.
    rctx = CP.Ctx(r.log, r.keyring(), objects=r.objects, skeleton=True)
    rfull = CP.judge(rctx, final)
    assert rfull.chain == [ev["checkpoint"]]
    assert rfull.status[ev["vote"]][0] and rfull.status[ev["late_anchor"]][1] == "Late"
    fctx, fheld = CP.forget(rctx, ev["checkpoint"], final)
    forgot = CP.judge(fctx, fheld, ev["checkpoint"])
    assert not CP.comparable(rfull, forgot, fheld)
    bindings = {}
    for name, world_ in (("kept", rfull), ("forgot", forgot)):
        tv = world_.space.storage
        bindings[name] = {p: (r.hist.key_name(tv.device_of(r.hist.device(p)))
                              if tv.device_of(r.hist.device(p)) else None)
                          for p in ("A1", "B1", "B2")}
    assert bindings["kept"] == bindings["forgot"] == {"A1": "A", "B1": None, "B2": "B"}, bindings
    # Sealed under the twin_secret of the roster event that granted the slot
    # instead, B2's binding would not open.
    b = S.read_body(r.log.events[ev["again"]].body)
    wrong = S.twin_of(r, ev["grant_b"])["secret"]
    try:
        S.open_binding(b["binding"], wrong, r.log.id, b["slot"][0], b["slot"][1],
                       r.hist.device("B2"))
        opens = True
    except SpecError:
        opens = False
    assert not opens
    return {"r": r, "ev": ev, "full": full, "trimmed": trimmed, "held": held,
            "may_truncate": states, "rfull": rfull, "forgot": forgot, "fheld": fheld,
            "bindings": bindings["kept"]}


def _concurrent_scenario(prefix: str):
    """A dishonest administrator's cut that reaches unordered checkpoints:
    P and A administer, each enrolled. P checkpoints B and A concurrently
    checkpoints Y, each with its cut; P0 and A1 acknowledge after B alone, so
    B's cut takes effect and Y's never does. P then takes every view and
    checkpoints X without fencing: X follows both B and Y."""
    r = S.StorageRoster("P", prefix)
    CP.attach(r)
    r.root("P0")
    r.sync("P", "P0")
    ra, _ = r.grant_admin("P", "P0", "A", "P grants A administer")
    r.sync("P", "P0", "A")
    r.enrol("A1", "A", ra, 0, "A1 enrols")
    r.sync("P", "P0", "A", "A1")
    b, bcut = make_cut(r, "P", "P0", "P checkpoints (B)")
    y, ycut = make_cut(r, "A", "A1", "A checkpoints concurrently (Y)")
    r.sync("P", "P0")
    a0 = r.request("P0", S.ack_body(), "P0 acknowledges B", view=r.hist.view["P"])
    view = r.hist.view["A1"] | r.hist.view["P"]
    a1 = r.request("A1", S.ack_body(), "A1 acknowledges B", view=view, fence=False,
                   parents=set(r.log.heads(r.hist.view["P"])) | {ycut})
    r.sync("P", "P0", "A", "A1")
    x, xcut = make_cut(r, "P", "P0", "P checkpoints, unfenced (X)", fence=False)
    r.sync("P", "P0", "A", "A1")
    return r, {"B": b, "Bcut": bcut, "Y": y, "Ycut": ycut, "ack0": a0, "ack1": a1, "X": x,
               "Xcut": xcut}


def self_test() -> None:
    r, ev = _scenario("skeleton-cuts/self-test")
    ctx = PCtx(r.log)
    final = set(r.log.events)
    assert validity(ctx, ev["cut"]) == (True, "cut", None)
    full = skeleton_of(ctx, final)
    assert ctx.memo[("sk", frozenset(final), None, "chain")] == [ev["cut"]]
    held = truncated(ctx, ev["cut"], final)
    trimmed = skeleton_of(PCtx(r.log, trusted={ev["cut"]}, held=held), held, ev["cut"])
    assert full.administrators() == trimmed.administrators() and len(full.administrators()) == 1
    assert all(full.status.get(i) == trimmed.status.get(i) for i in held if i != ev["cut"])
    # What truncation keeps: the genesis, the enrolments the cut names, the
    # release that keeps stream x released; not the carried-out request.
    assert may_truncate(ctx, ev["cut"], final)
    assert r.log.genesis in held and ev["release"] in held and ev["credentials"] not in held
    assert all(s_["pseudonym"] in held for s_ in ctx.body(ev["cut"])["slots"] if s_["pseudonym"])
    reqs = {ev["release"]: S.read_body(r.log.events[ev["release"]].body)}
    assert S.released(r.log, reqs, S.stream("x")) and not S.released(r.log, {}, S.stream("x"))
    # The replica's check against the record.
    slots = record_slots_of(r, ev["checkpoint"])
    assert len(slots) == 2 and against_record(ctx, ev["cut"], slots) is None
    wrong = [tuple(slots[0][:3]) + (b"",)] + slots[1:]
    assert against_record(ctx, ev["cut"], wrong) == "BadTwin"
    absent = [(bytes(32), 0, bytes(32), slots[0][3])] + slots[1:]
    assert against_record(ctx, ev["cut"], absent) == "BadTwin"
    cut_at_limit()
    _case_checks("skeleton-cuts/self-test")
    model_check(range(1, 4))


def _case_checks(prefix: str) -> dict:
    """A dishonest administrator's cut reaching unordered checkpoints, the
    truncation wait, and a record whose `slot` entries carry an empty
    pseudonym, judged by replicas that keep everything and forget."""
    out = {}
    r, ev = _concurrent_scenario(f"{prefix}/concurrent")
    ctx = PCtx(r.log)
    final = set(r.log.events)
    full = skeleton_of(ctx, final)
    assert validity(ctx, ev["Ycut"])[0] and validity(ctx, ev["Xcut"])[1] == "CutPending"
    held = truncated(ctx, ev["Bcut"], final)
    tctx = PCtx(r.log, trusted={ev["Bcut"]}, held=held)
    trimmed = skeleton_of(tctx, held, ev["Bcut"])
    assert all(full.status.get(i) == trimmed.status.get(i) for i in held if i != ev["Bcut"])
    assert trimmed.status[ev["Xcut"]][1] == "CutPending"
    out["concurrent"] = {"r": r, "ev": ev, "full": full, "trimmed": trimmed, "held": held}
    w = _waiting_checks(f"{prefix}/waiting")
    r = w["r"]
    rctx = CP.Ctx(r.log, r.keyring(), objects=r.objects, skeleton=True)
    rec = rctx.record(w["ev"]["checkpoint"])
    slots = {r.hist.key_name(m["member"][1]): m["slot"] for m in rec["members"]
             if m["slot"] is not None}
    assert slots["B"][3] == b"" and slots["A"][3] == r.hist.device("A1"), slots
    assert CP.checkpoint_validity(rctx, w["ev"]["checkpoint"])[0]
    reps = check_replicas(r, set(r.log.events))
    out["waiting"] = {**w, "rctx": rctx, "record": rec, "replicas": reps}
    out["late_enrolment"] = _late_enrolment_checks(f"{prefix}/late-enrolment")
    out["absent"] = _absent_checks(f"{prefix}/absent")
    out["concurrent_request"] = _concurrent_request_checks(f"{prefix}/concurrent-request")
    out["slot_held"] = _slot_held_checks(f"{prefix}/slot-held")
    out["held_cut"] = _held_cut_checks(f"{prefix}/held-cut")
    out["release_order"] = _release_order_checks(f"{prefix}/release-order")
    out["detached"] = _detached_checks(f"{prefix}/detached")
    out["peerless"] = _peerless_checks(f"{prefix}/peerless")
    out["late_then_past"] = _late_then_past_checks(f"{prefix}/late-then-past")
    out["no_slot"] = _no_slot_checks(f"{prefix}/no-slot")
    out["heard_vote"] = _heard_vote_checks(f"{prefix}/heard-vote")
    out["late_enrolment_refusals"] = _late_enrolment_refusals(f"{prefix}/late-refusals")
    return out


def _case_vectors(prefix: str) -> dict:
    x = _case_checks(prefix)
    c = x["concurrent"]
    r = c["r"]

    def verdicts(sk, ids):
        return {r.name(i): ("valid" if sk.status[i][0] else sk.status[i][1])
                for i in sorted(ids, key=r.log.order_key)
                if i in sk.status and r.log.events[i].kind == KIND_STORAGE}
    concurrent = {"history_prefix": f"{prefix}/concurrent", "events": r.hist.describe(),
                  "note": "X's cut reaches B's checkpoint, whose cut is in effect, and Y's, "
                          "concurrent with it: CutPending at a peer that kept everything and "
                          "at one that truncated under B",
                  "cut_verdicts": {r.name(c["ev"][k]): validity(PCtx(r.log), c["ev"][k])[1]
                                   for k in ("Bcut", "Ycut", "Xcut")},
                  "kept": {"verdicts": verdicts(c["full"], r.log.events)},
                  "truncated": {"holds": sorted(r.name(i) for i in c["held"]),
                                "verdicts": verdicts(c["trimmed"], c["held"])}}
    w = x["waiting"]
    r = w["r"]
    rec = w["record"]
    waiting = {"history_prefix": f"{prefix}/waiting", "events": r.hist.describe(),
               "note": "an erasure that waits for B's slot, granted and not yet enrolled, "
                       "keeps a peer from truncating until B enrols and acknowledges; the "
                       "checkpoint's record gives B's slot an empty pseudonym",
               "may_truncate": w["states"],
               "record": h(R_encode(rec)),
               "slots": {r.hist.key_name(m["member"][1]): [h(m["slot"][0]), m["slot"][1],
                                                          r.name(m["slot"][2]),
                                                          h(m["slot"][3])]
                         for m in rec["members"] if m["slot"] is not None},
               "space_verdicts": {r.name(i): ("valid" if v[0] else v[1]) for i, v in sorted(
                   CP.judge(w["rctx"], set(r.log.events)).status.items(),
                   key=lambda kv: r.log.order_key(kv[0]))}}
    le = x["late_enrolment"]
    r = le["r"]
    ev = le["ev"]

    def space_verdicts(world_, ids):
        return {r.name(i): ("valid" if world_.status[i][0] else world_.status[i][1])
                for i in sorted(ids, key=r.log.order_key) if i in world_.status}
    late_enrolment = {
        "history_prefix": f"{prefix}/late-enrolment",
        "events": r.hist.describe(),
        "note": "B enrols concurrently with P's checkpoint, whose cut lists B's slot with no "
                "pseudonym; B1 acknowledges and B's device anchors on top of the enrolment. "
                "The peer stores the late events with no effect (Late), so B's vote, whose prev "
                "is its late anchor, is placed and counts, and the checkpoint takes effect. B "
                "enrols the slot again after the checkpoint (B2), its binding sealed under the "
                "checkpoint's twin_secret: valid at the peer, and bound to B at a replica that "
                "kept everything and at one that forgot. The erasure in the checkpoint's past "
                "waits for B's slot until B2 acknowledges it",
        "peer": {"kept": {"verdicts": verdicts(le["full"], r.log.events)},
                 "truncated": {"holds": sorted(r.name(i) for i in le["held"]),
                               "verdicts": verdicts(le["trimmed"], le["held"])},
                 "may_truncate": le["may_truncate"]},
        "binding_secret": {"B2": "the checkpoint's twin_secret", "B1": "the twin_secret of "
                           "the roster event that granted B's slot"},
        "bindings": le["bindings"],
        "replica": {"chain": [r.name(i) for i in le["rfull"].chain],
                    "kept": space_verdicts(le["rfull"], [ev["late_anchor"], ev["vote"],
                                                         ev["checkpoint"]]),
                    "forgot": space_verdicts(le["forgot"], [ev["late_anchor"], ev["vote"],
                                                            ev["checkpoint"]])}}
    absent = {}
    for name, a_ in x["absent"].items():
        r = a_["r"]
        absent[name] = {
            "history_prefix": f"{prefix}/absent/{name}", "events": r.hist.describe(),
            "standing": [[h(st["slot"][0]), st["slot"][1], r.name(st["slot"][2]),
                          st["order"], st["dormant"]] for st in a_["standing"]],
            "cut_in_effect_at_the_peer": a_["peer"],
            "checkpoint_in_effect_at_a_replica": a_["replica"]}
    cr = x["concurrent_request"]
    r = cr["r"]
    concurrent_request = {
        "history_prefix": f"{prefix}/concurrent-request", "events": r.hist.describe(),
        "note": "an erasure concurrent with a cut waits while the cut can still take effect, "
                "is void (Late) once it does, at the peer and at replicas alike, and its "
                "author signs it again after the checkpoint",
        "states": cr["states"], "peer_verdicts": verdicts(cr["full"], r.log.events),
        "erasure_late": {**cr["erasure_late"],
                         "note": "peers.md, \"The peer's answer to a late erasure\": once the "
                                 "cut is in effect, A1 storing its erasure again is answered "
                                 "ErasureLate (transport.md, type 97): the cut's signed "
                                 "envelope, its checkpoint's ID and A1's slot standing, 0, "
                                 "still enrolled to A1; the residue checks what needs no key, "
                                 "and the rest is the peer's word"}}
    hc = x["held_cut"]
    held_cut = {"history_prefix": f"{prefix}/held-cut", "events": hc["r"].hist.describe(),
                "note": "a cut whose body uses key 9, a later document's: at a peer that lacks "
                        "it, ExtensionRequired, no cut, never in effect, holding no request; at "
                        "a replica, its checkpoint held as ExtensionRequired with every event "
                        "after it",
                "cut": hc["r"].name(hc["cut"]), "cut_body": h(hc["r"].log.events[hc["cut"]].body),
                "peer": {**hc["peer"], "erasure_event": hc["r"].name(hc["erase"])},
                "replica": {**hc["replica"], "checkpoint_event": hc["r"].name(hc["checkpoint"]),
                            "after_event": hc["r"].name(hc["after"])}}
    slot_held = {}
    for case, sh in x["slot_held"].items():
        r = sh["r"]
        ans = sh["answer"]
        slot_held[case] = {
            "history_prefix": f"{prefix}/slot-held/{case}", "events": r.hist.describe(),
            "note": {"another": "the cut lists A's slot with A3, another installation of A: "
                                "standing 1 with a named entry; the residue reports SlotHeld "
                                "and asks for no welcome",
                     "none": "the cut lists A's slot with no pseudonym, and A3, another "
                             "installation of A, enrolled it after the checkpoint: standing 1 "
                             "with an empty entry; the residue asks for a welcome, and once "
                             "back in finds the slot held by A3, bound to A's device "
                             "(SlotHeld)"}[case],
            "space": h(r.log.genesis), "erasure": r.name(sh["ev"]["erase"]),
            "slot": [h(ans["slot"][0]), ans["slot"][1], h(ans["slot"][2])],
            "message": h(sh["message"]), "standing": ans["standing"],
            "cut_entry": sh["checked"]["entry"], "residue_action": sh["checked"]["action"],
            "back_in": "slot held", "holder": r.name(sh["ev"]["other"]),
            "holder_binding": "A's device: another installation of A",
            "enrolling_again": {"event": r.name(sh["again"]), "verdict": sh["again_status"]}}
    ro = x["release_order"]
    r = ro["r"]
    release_order = {
        "history_prefix": f"{prefix}/release-order", "events": r.hist.describe(),
        "note": "a restore, an anchor and a release of stream x before the checkpoint: a peer "
                "that truncated keeps the release alone, the maximal request, and finds x "
                "released as one that kept everything, and as a replica that forgot; kept "
                "beside the restore without the anchor between them, the two would read as "
                "concurrent and the restore win",
        "truncated_holds": sorted(r.name(i) for i in ro["held"]),
        "released": {"kept everything": ro["kept"], "truncated": ro["truncated"],
                     "a replica that forgot": ro["forgot"],
                     "kept every request, ordered from what it holds":
                         ro["keeping_every_request"]}}
    dt = x["detached"]
    r = dt["r"]
    detached = {"history_prefix": f"{prefix}/detached", "events": r.hist.describe(),
                "note": "a checkpoint names its cut in visible key 15 without citing it: the "
                        "cut stays Unnamed at every peer, and the checkpoint is BadTwin at "
                        "replicas",
                "cut": dt["peer"], "checkpoint": dt["replica"]}
    pl = x["peerless"]
    peerless = {
        "never": {"history_prefix": f"{prefix}/peerless/never",
                  "events": pl["never"]["r"].hist.describe(), "chain": pl["never"]["chain"]},
        "apart": {"history_prefix": f"{prefix}/peerless/apart",
                  "events": pl["apart"]["r"].hist.describe(),
                  "chain_at_the_peer_before": pl["apart"]["before"],
                  "chain_once_it_catches_up": pl["apart"]["after"],
                  "truncated_holds": pl["apart"]["holds"]}}
    lp = x["late_then_past"]
    r = lp["r"]
    late_then_past = {
        "history_prefix": f"{prefix}/late-then-past", "events": r.hist.describe(),
        "note": "a release late under the first checkpoint, in the second one's past through "
                "its author's chain, counts for nothing under the second: x is not released, "
                "at a peer that kept everything and at one that truncated under the second",
        "released": {"kept everything": lp["kept"], "truncated": lp["truncated"]},
        "truncated_holds": lp["holds"]}
    ns = x["no_slot"]
    no_slot = {"history_prefix": f"{prefix}/no-slot", "events": ns["r"].hist.describe(),
               "standing": [[h(st["slot"][0]), st["slot"][1], ns["r"].name(st["slot"][2]),
                             st["order"], st["dormant"]] for st in ns["standing"]],
               "cut": ns["peer"], "checkpoint": ns["replica"]}
    hv = x["heard_vote"]
    heard_vote = {"history_prefix": f"{prefix}/heard-vote", "events": hv["r"].hist.describe(),
                  "chain": hv["chain"], "replica_chain": hv["replica_chain"],
                  "truncated_holds": hv["holds"]}
    lr = x["late_enrolment_refusals"]
    late_refusals = {"history_prefix": f"{prefix}/late-refusals",
                     "events": lr["r"].hist.describe(), "verdicts": lr["verdicts"]}
    return {"unordered_cuts": concurrent, "truncation_wait": waiting, "detached": detached,
            "peerless": peerless, "late_then_past": late_then_past, "no_slot": no_slot,
            "heard_vote": heard_vote, "late_enrolment_refusals": late_refusals,
            "late_enrolment": late_enrolment, "absent_administrator": absent,
            "concurrent_request": concurrent_request, "release_order": release_order,
            "slot_held": slot_held, "held_cut": held_cut}


def R_encode(rec) -> bytes:
    return roster.encode_record(rec)


def skeleton_cut_vectors() -> dict:
    """peers.json's `skeleton_cuts` family."""
    r, ev = _scenario("skeleton-cuts/vector")
    ctx = PCtx(r.log)
    final = set(r.log.events)
    full = skeleton_of(ctx, final)
    held = truncated(ctx, ev["cut"], final)
    trimmed = skeleton_of(PCtx(r.log, trusted={ev["cut"]}, held=held), held, ev["cut"])

    def verdicts(sk, ids):
        return {r.name(i): ("valid" if sk.status[i][0] else sk.status[i][1])
                for i in sorted(ids, key=r.log.order_key)
                if i in sk.status and r.log.events[i].kind == KIND_STORAGE}
    slots = sorted(record_slots_of(r, ev["checkpoint"]))
    wrong = [tuple(slots[0][:3]) + (b"",)] + slots[1:]
    absent = [(bytes(32), 0, bytes(32), slots[0][3])] + slots[1:]
    record_check = [
        {"name": name, "slots": [[h(x[0]), x[1], h(x[2]), h(x[3])] for x in v],
         "verdict": against_record(ctx, ev["cut"], v) or "valid"}
        for name, v in (("the record's slot entries", slots),
                        ("an entry naming no pseudonym where the cut's slot has one", wrong),
                        ("an entry naming a slot the cut lacks", absent))]
    return {
        "history_prefix": "skeleton-cuts/vector",
        "limit": cut_at_limit(),
        "record_check": record_check,
        "may_truncate": may_truncate(ctx, ev["cut"], final),
        "events": r.hist.describe(),
        "cut": {"name": r.name(ev["cut"]), "body": h(r.log.events[ev["cut"]].body),
                "checkpoint": r.name(ev["checkpoint"])},
        "kept": {"verdicts": verdicts(full, final),
                 "administrators": [[h(s[0]), s[1], r.name(s[2]) if s[2] in r.log.events
                                     else h(s[2])] for s in full.administrators()]},
        "truncated": {"holds": sorted(r.name(i) for i in held),
                      "verdicts": verdicts(trimmed, held),
                      "administrators": [[h(s[0]), s[1], r.name(s[2]) if s[2] in r.log.events
                                          else h(s[2])] for s in trimmed.administrators()]},
        **_case_vectors("skeleton-cuts/vector"),
    }


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    print(model_check(range(1, n + 1), quiet=False))
