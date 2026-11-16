"""Guests (ext-guests.md), protocol 1, written from the specification, independently
of any implementation: the guest preset and its `frasil.nothing-at-rest`
capability, ending a session in one roster event and a session's expiry at
administering devices, a leave request and what an administering device
does with it, the writer's own decision under a session's expiry, the
bounded window and online-only, which events follow a device's own and the
heartbeat decision, a session with no peer, and what a carve-out's guest
resolves along its grant path. Resolution is roster.py's, which reads
change key 13 itself; the timed rules use clocks.py's estimates."""

from __future__ import annotations

import admission as adm
import clocks
import history_sigs as hs
import identity
import keygraph as kg
import roster
import spaces
from events import cbor, h, is_bytes, uncbor
from formats import example
from primitives import SpecError, field, sha256

LEAVE_REQUEST_LABEL = b"frasil/leave-request/v1"
NEW_LABELS = [LEAVE_REQUEST_LABEL]

NOTHING_AT_REST = "frasil.nothing-at-rest"   # a narrowing capability
RESERVED_CAPABILITY_PREFIX = "frasil."
LEAVE_REQUEST_CONTENT = "frasil/leave-request"
VERSION = 1
SESSION_BYTES = 16
MAX_GRANTS = 64
SESSION_LIFETIME_MAX = 2_592_000   # session_lifetime's maximum, 30 days
SESSION_SKEW = 60                  # session_skew (overview.md, "Every timer")


# ---------------------------------------------------------------------------
# The guest preset ("The guest preset").


def preset(keys: adm.DeviceKeys, level: int, session: bytes, *, nothing_at_rest: bool = False,
           expires_at: int | None = None, caps=(), label: str | None = None,
           via: int = roster.VIA_CODE) -> adm.RawChange:
    """A device grant with `session`, "from now on", never administer, and the
    `frasil.nothing-at-rest` capability when asked for."""
    assert level in (roster.READ, roster.WRITE) and len(session) == SESSION_BYTES
    all_caps = list(caps) + ([(NOTHING_AT_REST, roster.NARROWS)] if nothing_at_rest else [])
    all_caps.sort(key=lambda c: c[0].encode())
    return adm.guest_grant(keys, level, session, expires_at=expires_at, caps=all_caps or None,
                           label=label, via=via, history=roster.FROM_NOW_ON)


def is_guest(state: roster.State) -> bool:
    return state.present and state.session is not None


def nothing_at_rest(state: roster.State) -> bool:
    return (NOTHING_AT_REST, roster.NARROWS) in state.caps


def end_session(sp: roster.Space, session: bytes) -> list:
    """"Ending a session": the removals of every guest of this session, in
    one event; more than 256 go in several."""
    members = sorted(m for m, s in sp.roster.items() if s.present and s.session == session)
    return [adm.RawChange({0: roster.REMOVE, 1: [m[0], m[1]]}) for m in members]


def session_expiry(expires_at: int | None, first_sight: dict, now: dict) -> str:
    """"Ending a session", at an administering device, for one guest grant in
    force: "Remove" or "Open". A grant without expires_at is never removed
    by clock."""
    return clocks.session_expiry(expires_at, first_sight, now, SESSION_LIFETIME_MAX)


def guest_due(grants: list, now: dict) -> bool:
    """A guest is due when any of its grants in force gives Remove. Each
    grant is {"expires_at": ..., "first_sight": reading}."""
    return any(session_expiry(g["expires_at"], g["first_sight"], now) == "Remove"
               for g in grants)


# ---------------------------------------------------------------------------
# A leave request ("The leave request", "A leave request").


def leave_request(space: bytes, member: tuple, grants, request_id: bytes,
                  device: bytes) -> bytes:
    return cbor({1: VERSION, 2: space, 3: [member[0], member[1]], 4: sorted(set(grants)),
                 5: request_id, 6: device})


def sign_leave(record: bytes, signer: hs.Signer) -> bytes:
    return adm.sign_record(LEAVE_REQUEST_LABEL, record, signer)


def read_leave(signed: bytes, keys_of) -> dict:
    """"A leave request", steps 1 to 3: both maps, the keys, the signature.
    `keys_of(device, member)` gives the device's (Ed25519, ML-DSA-65,
    X-Wing) key sets from any source; only one can hash to its device ID
    (crypto.md, "A device's keys")."""
    outer = adm._map(signed, {1, 2}, {1, 2})
    if not is_bytes(outer[1]) or not is_bytes(outer[2], hs.HYBRID_SIGNATURE_BYTES):
        raise SpecError("Malformed")
    v = adm._map(outer[1], set(range(1, 7)), set(range(1, 7)))
    if v[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if not (is_bytes(v[2], 32) and isinstance(v[3], list) and len(v[3]) == 2
            and v[3][0] in (roster.DEVICE, roster.PERSON) and is_bytes(v[3][1], 32)
            and isinstance(v[4], list) and 1 <= len(v[4]) <= MAX_GRANTS
            and all(is_bytes(x, 32) for x in v[4]) and all(a < b for a, b in zip(v[4], v[4][1:]))
            and is_bytes(v[5], 16) and is_bytes(v[6], 32)):
        raise SpecError("Malformed")
    held = next((k for k in keys_of(v[6], tuple(v[3])) if hs.device_id_of(*k) == v[6]), None)
    if held is None:
        raise SpecError("NoHybridKey")
    if not identity.proof_ok(held[0], held[1], LEAVE_REQUEST_LABEL + field(outer[1]),
                             outer[2]):
        raise SpecError("BadSignature")
    return {"space": v[2], "member": tuple(v[3]), "grants": v[4], "request": v[5],
            "device": v[6], "trigger": sha256(signed)}


def on_leave(signed: bytes, sp: roster.Space, me: bytes, administrators, step: int = 2) -> dict:
    """"A leave request", at an administering device, steps 1 to 9: whether
    it removes the member, and after what delay."""
    def keys_of(device: bytes, member: tuple):
        """Step 2: the keys this device holds, from the device's grant, the
        person's list, or any other source the space's records give."""
        return sp.key_sets()

    try:
        req = read_leave(signed, keys_of)
    except SpecError as error:
        return {"outcome": error.error}
    if req["space"] != sp.log.id:
        return {"outcome": "WrongSpace"}
    st = sp.roster.get(req["member"])
    if st is None or not st.present:
        return {"outcome": "NoSuchMember"}
    if req["member"][0] == roster.DEVICE and req["member"][1] != req["device"]:
        return {"outcome": "NotTheMember"}
    if req["member"][0] == roster.PERSON:
        lst = sp.lists.get(req["member"][1])
        if lst is None or req["device"] not in lst.writers():
            return {"outcome": "NotTheMember"}
    if set(req["grants"]) != set(st.grants):
        return {"outcome": "Stale"}
    if req["member"][0] == roster.DEVICE and st.level == roster.ADMINISTER:
        return {"outcome": "MemberAdministers"}
    order = kg.rank_order(sp.log.id, req["trigger"], sorted(administrators))
    pos = order.index(me)
    return {"outcome": "Remove", "rank": pos, "delay": clocks.rotation_delay(pos, step)}


# ---------------------------------------------------------------------------
# The writer's decision ("The writer's decision").


def may_seal(state: dict, now: dict) -> str:
    """"The writer's decision", in order: whether this device seals a unit, a
    key event, a roster event or an ephemeral message in the space now.
    Anchors (heartbeats) seal nothing and are never held back. No replica
    refuses anything for this: the rule binds the writer alone.
    `session_expires_at` is the earliest expires_at of its grants in force."""
    if state.get("left"):
        return "Left"
    exp = state.get("session_expires_at")
    if exp is not None and clocks.check_expiry(exp, now["wall"], SESSION_LIFETIME_MAX,
                                               SESSION_SKEW) != "ok":
        return "SessionEnded"
    policy = state.get("policy", {})
    if policy.get("bounded_window") is not None:
        followed_at = state.get("followed") or state["admitted"]
        if clocks.bounded_window(followed_at, now, policy["bounded_window"]) == "WindowElapsed":
            return "WindowElapsed"
    if policy.get("online_freshness") is not None:
        if clocks.online_only(state.get("last_sync"), now, policy["online_freshness"]) \
                == "NotOnline":
            return "NotOnline"
    return "MayWrite"


def followers(log, valid, device: bytes) -> dict:
    """"Followed": for each event of `device`, the valid events of other
    devices that hold it in their past. `valid(i)` is the replica's verdict;
    a valid event's author reaches the space at its place. Void, refused
    and forked events do not count."""
    own = [i for i in log.canonical() if log.events[i].author == device]
    out = {}
    for e in own:
        out[e] = [i for i in log.canonical()
                  if i != e and log.events[i].author != device and valid(i)
                  and e in log.anc[i]]
    return out


def followed(log, valid, device: bytes, signed_at: dict, admitted: dict) -> dict:
    """`followed`: this device's reading when it signed its newest event
    that another member follows, and at first its first sight of its own
    admission."""
    rows = [{"follows": e, "valid": True, "member": True, "other": True}
            for e, by in followers(log, valid, device).items() if by and e in signed_at]
    return clocks.acknowledged(signed_at, rows) or admitted


def heartbeat(last_signed: dict, last_heartbeat: dict | None, now: dict, window: int,
              unanswered: bool) -> str:
    """"Heartbeats", in order: "Heartbeat" or "Wait"."""
    return clocks.heartbeat(last_signed, last_heartbeat, now, window, unanswered)


# ---------------------------------------------------------------------------
# Vectors: ext-guests.json.


def _err(function, *args, **kw) -> str:
    try:
        function(*args, **kw)
    except SpecError as error:
        return error.error
    return "accepted"


def _resolve(r, view=None, **kw):
    return adm.AdmissionSpace(r.log, view, keys=r.keyring(), **kw)


def _session_vectors() -> dict:
    """A host, two guests of one session and one of another; the session
    ends in one event; a guest's unit concurrent with it."""
    r = roster.Roster("H", "guests/session")
    s1 = example("guests/session/one")[:16]
    s2 = example("guests/session/two")[:16]
    g1, g2, g3 = (adm.roster_device_keys(r, n) for n in ("G1", "G2", "G3"))
    host = r.hist.device("H")
    grant1 = preset(g1, roster.WRITE, s1, nothing_at_rest=True, expires_at=1_760_014_400,
                    caps=[("drive", roster.EXTENDS)], label="Operator")
    e1 = adm.admission_event(r, "H", [grant1, preset(g2, roster.READ, s1,
                                                     expires_at=1_760_014_400)],
                             "H admits G1 and G2 (session one)", brk=True,
                             recipients=[(host, r.hist.xwing("H"), True, True),
                                         (g1.device_id, g1.hybrid, True, False),
                                         (g2.device_id, g2.hybrid, False, False)])
    adm.admission_event(r, "H", [preset(g3, roster.WRITE, s2)], "H admits G3 (session two)",
                        brk=True, recipients=[(host, r.hist.xwing("H"), True, True),
                                              (g3.device_id, g3.hybrid, True, False)])
    r.sync("H", "G1", "G2", "G3")
    u_before = r.unit("G1", "G1 writes before the end")
    heal = r.heal("G1", "G1 heals (a key event)")
    r.sync("H", "G1")
    vg = set(r.hist.view["G1"])
    sp_mid = _resolve(r)
    ends = end_session(sp_mid, s1)
    end = r.act("H", ends, "H ends session one")
    r.hist.view["G1"] = vg
    u_conc = r.unit("G1", "G1 writes, concurrent with the end")
    tries = r.act("G2", [roster.Change(roster.REMOVE, (roster.DEVICE, g2.device_id))],
                  "G2 tries to remove itself", rotation=False)
    sp = _resolve(r)
    out = adm.summary(r, sp)
    out["end_event"] = h(r.log.events[end].signed)
    out["first_admission"] = h(r.log.events[e1].signed)
    out["changes_in_the_end"] = len(ends)
    out["guests"] = {r.member_name(m): {"guest": is_guest(s), "nothing_at_rest":
                                        nothing_at_rest(s)}
                     for m, s in sorted(sp_mid.roster.items()) if s.present}
    assert u_before and heal and u_conc and tries
    return out


def _nothing_at_rest_meet() -> dict:
    """Two administering devices grant one guest concurrently, one asking
    for nothing at rest; the meet keeps the narrowing capability."""
    r = roster.Roster("H", "guests/meet")
    r.hist.view["H"] = set(r.log.events)
    r.grant("H", "K", roster.ADMINISTER, roster.WITH_HISTORY, label="H grants K administer")
    r.sync("H", "K")
    g = adm.roster_device_keys(r, "G")
    s = example("guests/meet/session")[:16]
    r.act("H", [preset(g, roster.WRITE, s, nothing_at_rest=True)], "H admits G, nothing at rest")
    r.act("K", [preset(g, roster.WRITE, s)], "K admits G")
    sp = _resolve(r)
    st = sp.roster[(roster.DEVICE, g.device_id)]
    return {"events": adm.summary(r, sp)["events"],
            "capabilities": sorted([n, m] for n, m in st.caps),
            "nothing_at_rest": nothing_at_rest(st)}


def _leave_vectors() -> dict:
    r = roster.Roster("H", "guests/leave")
    r.hist.view["H"] = set(r.log.events)
    r.grant("H", "K", roster.ADMINISTER, roster.WITH_HISTORY, label="H grants K administer")
    r.sync("H", "K")
    g = adm.roster_device_keys(r, "G")
    s = example("guests/leave/session")[:16]
    gr = r.act("H", [preset(g, roster.WRITE, s)], "H admits G")
    r.sync("H", "K", "G")
    sp = _resolve(r)
    rid = example("guests/leave/request")[:16]
    record = leave_request(r.id, (roster.DEVICE, g.device_id), [gr], rid, g.device_id)
    signed = sign_leave(record, g.signer)
    admins = [r.hist.device("H"), r.hist.device("K")]
    decisions = {name: on_leave(signed, sp, r.hist.device(name), admins) for name in ("H", "K")}
    # Another device signs a leave for G; a leave naming a grant no longer in force.
    other = adm.roster_device_keys(r, "K")
    forged = sign_leave(leave_request(r.id, (roster.DEVICE, g.device_id), [gr], rid, other.device_id),
                        other.signer)
    stale = sign_leave(leave_request(r.id, (roster.DEVICE, g.device_id),
                                     [example("guests/leave/old-grant")], rid, g.device_id),
                       g.signer)
    tampered = cbor({1: leave_request(r.id, (roster.DEVICE, g.device_id), [gr],
                                      example("guests/leave/other-request")[:16], g.device_id),
                     2: uncbor(signed)[2]})
    refusals = {
        "signed by another device": on_leave(forged, sp, admins[0], admins)["outcome"],
        "naming a grant no longer in force": on_leave(stale, sp, admins[0], admins)["outcome"],
        "a changed request ID": on_leave(tampered, sp, admins[0], admins)["outcome"],
        "for another space": on_leave(sign_leave(leave_request(
            example("guests/leave/other"), (roster.DEVICE, g.device_id), [gr], rid, g.device_id),
            g.signer), sp, admins[0], admins)["outcome"],
        "a device member at administer": on_leave(sign_leave(leave_request(
            r.id, (roster.DEVICE, admins[1]), sorted(sp.roster[(roster.DEVICE,
                                                                 admins[1])].grants), rid,
            admins[1]), other.signer), sp, admins[0], admins)["outcome"],
    }
    first = min(decisions, key=lambda n: decisions[n]["rank"])
    rem = r.act(first, [roster.Change(roster.REMOVE, (roster.DEVICE, g.device_id))],
                f"{first} removes G on its leave request")
    after = _resolve(r)
    return {"record": h(record), "signed": h(signed),
            "guest": {"ed25519_seed": h(g.signer.ed_seed)},
            "trigger": h(sha256(signed)), "decisions": decisions,
            "refusals": [{"name": n, "outcome": o} for n, o in refusals.items()],
            "removal": h(r.log.events[rem].signed),
            "after": adm.summary(r, after)}


W = 1_760_000_000


def _rd(tl, wall, run=1):
    return {"timeline": tl, "wall": wall, "run": run}


def _writer_decisions() -> dict:
    """"The writer's decision" over readings."""
    win = 3600
    rows = []

    def row(desc, state, now):
        rows.append({"description": desc, "state": state, "now": now,
                     "outcome": may_seal(state, now)})

    rd = _rd
    row("no policy", {"policy": {}, "admitted": rd(0, W)}, rd(10, W + 10))
    row("bounded window, followed 59 minutes ago",
        {"policy": {"bounded_window": win}, "admitted": rd(0, W), "followed": rd(0, W)},
        rd(3540, W + 3540))
    row("bounded window, followed an hour ago",
        {"policy": {"bounded_window": win}, "admitted": rd(0, W), "followed": rd(0, W)},
        rd(3600, W + 3600))
    row("bounded window, the wall clock moved forward an hour while off",
        {"policy": {"bounded_window": win}, "admitted": rd(0, W), "followed": rd(0, W)},
        rd(60, W + 3660, 2))
    row("bounded window, no known wall clock, after a restart",
        {"policy": {"bounded_window": win}, "admitted": rd(0, None), "followed": rd(0, None)},
        rd(5, None, 2))
    row("online-only, synced 4 minutes ago",
        {"policy": {"online_freshness": 300}, "admitted": rd(0, W), "last_sync": rd(100, W + 100)},
        rd(340, W + 340))
    row("online-only, synced 5 minutes ago",
        {"policy": {"online_freshness": 300}, "admitted": rd(0, W), "last_sync": rd(100, W + 100)},
        rd(400, W + 400))
    row("online-only, never synced",
        {"policy": {"online_freshness": 300}, "admitted": rd(0, W)}, rd(10, W + 10))
    row("both policies, the window open and the sync stale",
        {"policy": {"bounded_window": win, "online_freshness": 300}, "admitted": rd(0, W),
         "followed": rd(0, W), "last_sync": rd(0, W)}, rd(600, W + 600))
    row("a guest before its session's expiry",
        {"policy": {}, "admitted": rd(0, W), "session_expires_at": W + 3600},
        rd(3599, W + 3599))
    row("a guest at its session's expiry",
        {"policy": {}, "admitted": rd(0, W), "session_expires_at": W + 3600},
        rd(3600, W + 3600))
    row("a guest past its session's expiry",
        {"policy": {}, "admitted": rd(0, W), "session_expires_at": W + 3600},
        rd(3601, W + 3601))
    row("a guest whose wall clock is not known",
        {"policy": {}, "admitted": rd(0, None), "session_expires_at": W + 3600},
        rd(10, None))
    row("a guest whose expires_at is beyond session_lifetime's maximum and session_skew",
        {"policy": {}, "admitted": rd(0, W),
         "session_expires_at": W + 10 + SESSION_LIFETIME_MAX + SESSION_SKEW + 1},
        rd(10, W + 10))
    row("a member that has sent its leave request", {"policy": {}, "admitted": rd(0, W),
                                                     "left": True}, rd(1, W + 1))
    merged = roster.merge_policies([
        {"agent_waiting_period": 259200, "gap_key_timeout": 604800, "bounded_window": 7200,
         "online_freshness": None, "forbid_agents": False},
        {"agent_waiting_period": 259200, "gap_key_timeout": 604800, "bounded_window": 3600,
         "online_freshness": 300, "forbid_agents": False}])
    return {
        "decisions": rows,
        "policy_encodings": {
            "bounded window of an hour": h(spaces.encode_policy({"bounded_window": 3600})),
            "online-only at the default": h(spaces.encode_policy({"online_freshness": 300})),
            "both": h(spaces.encode_policy({"bounded_window": 86400, "online_freshness": 60})),
        },
        "concurrent_policies_merged": merged,
    }


def _session_expiry() -> dict:
    """"Ending a session": session_expiry at and around each bound, and a
    guest due when any of its grants is."""
    exp = W + 3600
    rd = _rd
    rows = []
    for desc, e, first, now in (
            ("before expires_at", exp, rd(0, W), rd(3599, W + 3599)),
            ("at expires_at", exp, rd(0, W), rd(3600, W + 3600)),
            ("after expires_at", exp, rd(0, W), rd(3601, W + 3601)),
            ("no known wall clock, one second before the maximum", exp, rd(0, None),
             rd(SESSION_LIFETIME_MAX - 1, None)),
            ("no known wall clock, at the maximum", exp, rd(0, None),
             rd(SESSION_LIFETIME_MAX, None)),
            ("a wall clock behind expires_at, at the maximum on the timeline",
             W + 2 * SESSION_LIFETIME_MAX, rd(0, W), rd(SESSION_LIFETIME_MAX, W + 10)),
            ("no known wall clock, early", exp, rd(0, None), rd(10, None)),
            ("no expires_at, at the maximum", None, rd(0, W),
             rd(SESSION_LIFETIME_MAX, W + SESSION_LIFETIME_MAX))):
        rows.append({"description": desc, "expires_at": e, "first_sight": first, "now": now,
                     "outcome": session_expiry(e, first, now)})
    now = rd(4000, W + 4000)
    grants = [{"expires_at": W + 86400, "first_sight": rd(0, W)},
              {"expires_at": exp, "first_sight": rd(100, W + 100)}]
    due = {"description": "a guest with two grants in force, one past its expires_at",
           "grants": grants, "now": now,
           "outcomes": [session_expiry(g["expires_at"], g["first_sight"], now) for g in grants],
           "due": guest_due(grants, now)}
    return {"session_lifetime_max": SESSION_LIFETIME_MAX, "decisions": rows, "due": due}


def _followed_vectors() -> dict:
    """"Followed": which events of W another member follows. H follows W's
    first unit; X, removed concurrently, holds W's second unit in its past,
    and its refused unit does not count; W's own later unit follows its
    third, and does not count either."""
    r = roster.Roster("H", "guests/followed")
    r.hist.view["H"] = set(r.log.events)
    r.grant("H", "W", roster.WRITE, roster.WITH_HISTORY, label="H grants W write")
    r.grant("H", "X", roster.WRITE, roster.WITH_HISTORY, label="H grants X write")
    r.sync("H", "W", "X")
    u1 = r.unit("W", "W's first unit")
    r.sync("H", "W")
    h1 = r.unit("H", "H's unit, following W's first")
    r.sync("H", "W")
    u2 = r.unit("W", "W's second unit")
    r.sync("W", "X")
    before = set(r.hist.view["H"])
    x1 = r.unit("X", "X's unit, following W's second")
    r.hist.view["H"] = before
    r.remove("H", "X", "H removes X, concurrently")
    u3 = r.unit("W", "W's third unit")
    u4 = r.unit("W", "W's fourth unit, following its own third")
    sp = _resolve(r)
    valid = lambda i: sp.status[i][0]  # noqa: E731
    w = r.hist.device("W")
    signed_at = {u1: _rd(100, W + 100), u2: _rd(200, W + 200), u3: _rd(300, W + 300),
                 u4: _rd(400, W + 400)}
    admitted = _rd(0, W)
    got = followed(r.log, valid, w, signed_at, admitted)
    assert got == signed_at[u1] and x1 and h1
    by = followers(r.log, valid, w)
    return {"events": adm.summary(r, sp)["events"],
            "device": "W", "admitted": admitted,
            "own_events": [{"event": r.name(e), "signed_at": signed_at.get(e),
                            "followed_by": [r.name(i) for i in by[e]]}
                           for e in r.log.canonical() if e in by and e in signed_at],
            "followed": got}


def _heartbeat_vectors() -> list:
    """"Heartbeats" over readings, under a bounded window of an hour."""
    win = 3600
    rd = _rd
    rows = []
    for desc, last_signed, last_hb, now, unanswered in (
            ("a heartbeat 20 minutes ago", rd(0, W), rd(2400, W + 2400), rd(3600, W + 3600),
             True),
            ("nothing signed for half the window", rd(0, W), None, rd(1800, W + 1800), False),
            ("signed 10 minutes ago, nothing unanswered", rd(1200, W + 1200), None,
             rd(1800, W + 1800), False),
            ("signed 10 minutes ago, another member's anchor unanswered", rd(1200, W + 1200),
             None, rd(1800, W + 1800), True),
            ("a heartbeat half a window ago, nothing signed since", rd(0, W), rd(0, W),
             rd(1800, W + 1800), False)):
        rows.append({"description": desc, "window": win, "last_signed": last_signed,
                     "last_heartbeat": last_hb, "now": now, "unanswered": unanswered,
                     "outcome": heartbeat(last_signed, last_hb, now, win, unanswered)})
    return rows


def _offgrid_vectors() -> dict:
    """"A session with no peer": content made a space on the host's device,
    and a guest admitted by code over a nearby connection."""
    r = roster.Roster("host", "guests/offgrid")
    guest = adm.roster_device_keys(r, "guest")
    host = r.hist.device("host")
    session = example("guests/offgrid/session")[:16]
    channel = example("guests/offgrid/exporter")
    offer = adm.encode_offer(roster.WRITE, roster.FROM_NOW_ON, label="Guest",
                             caps=[(NOTHING_AT_REST, roster.NARROWS)], session=session)
    joiner = adm.Joiner(adm.CTX_SPACE, example("guests/offgrid/request")[:16], 1_760_000_900,
                        example("guests/offgrid/eph-j"), example("guests/offgrid/nonce-j"),
                        "Sam's laptop", keys=guest, channel=channel)
    appr = adm.Approver(host, adm.CTX_SPACE, r.id, r.log.heads(r.hist.view["host"]), offer,
                        "Ada's space", example("guests/offgrid/eph-i"),
                        example("guests/offgrid/nonce-i"), channel=channel)
    resp = appr.on_request(joiner.start(), 1_760_000_100, adm.eseed("guests/offgrid/enc-1"))
    jr = joiner.on_response(resp, 1_760_000_110, adm.eseed("guests/offgrid/enc-2"))
    ar = appr.on_reveal(jr["reveal"], 1_760_000_120)
    g = adm.admission_event(r, "host", [preset(guest, roster.WRITE, session, nothing_at_rest=True,
                                                label="Guest")],
                            "the host admits the guest", brk=True,
                            recipients=[(host, r.hist.xwing("host"), True, True),
                                        (guest.device_id, guest.hybrid, True, False)])
    r.sync("host", "guest")
    r.unit("guest", "the guest edits")
    r.sync("host", "guest")
    end = r.act("host", end_session(_resolve(r), session), "the host ends the session")
    sp = _resolve(r)
    ev = r.log.events[g]
    own = adm.own_bundle(ev, guest.device_id, guest.hybrid_seed)
    decoded = roster.decode_body(ev, roster.body_key(ev, roster.read_visible(ev),
                                                     own["bundle"]["content"]))
    return {"genesis": h(r.log.events[r.genesis].signed), "space": h(r.id),
            "codes": [ar["code"], jr["code"]],
            "grant_check": _err(adm.check_grant, ev, decoded, r.log, joiner.response, joiner),
            "grant": h(ev.signed), "end": h(r.log.events[end].signed),
            "result": adm.summary(r, sp)}


def _carve_out_vectors() -> dict:
    """"A carve-out's guest": a guest of a carve-out N resolves P's roster
    from the events and body keys its snapshot carries, and judges a P
    member's unit in N."""
    # N's creator C is a writer of P; M is a writer of P only. The same keys
    # sign in both histories.
    p = roster.Roster("PA", "guests/carve/P")
    p.hist.keys["C"] = example("guests/carve/N/C/ed25519")  # the seed N's history gives C
    p.hist.view.setdefault("C", set())
    p.hist.view["PA"] = set(p.log.events)
    p.grant("PA", "C", roster.WRITE, roster.WITH_HISTORY, label="PA grants C write")
    p.grant("PA", "M", roster.WRITE, roster.WITH_HISTORY, label="PA grants M write")
    p.grant("PA", "X", roster.WRITE, roster.WITH_HISTORY, label="PA grants X write")
    p.remove("PA", "X", "PA removes X")
    p.sync("PA", "M", "C")
    n = roster.Roster("C", "guests/carve/N",
                      descriptor=spaces.encode_descriptor(spaces.KIND_CARVE_OUT, p.id))
    assert n.hist.device("C") == p.hist.device("C")
    n.hist.keys["M"] = p.hist.keys["M"]
    n.hist.view.setdefault("M", set())
    guest = adm.roster_device_keys(n, "guest")
    session = example("guests/carve/session")[:16]
    founder = n.hist.device("C")
    first = adm.admission_event(
        n, "C", [roster.Change(roster.GRANT, (roster.SPACE, p.id), roster.WRITE, None, None,
                                roster.WITH_HISTORY, roster.VIA_NONE),
                  preset(guest, roster.WRITE, session)],
        "N's first update: P at write, the guest from now on", brk=True,
        refs=roster.Roster.heads_ref(p.id, p.log, p.hist.view["C"]),
        recipients=[(founder, n.hist.xwing("C"), True, True),
                    (guest.device_id, guest.hybrid, True, False)])
    n.sync("C", "M", "guest")
    unit = n.unit("M", "M writes in N through P")
    # What a member of both holds, and what the guest receives.
    p_full = adm.AdmissionSpace(p.log, None, keys=p.keyring())
    p_keys = p_full.snapshot_keys([])
    n_full = adm.AdmissionSpace(n.log, None, keys=n.keyring(), spaces_={p.id: p_full})
    n_keys = n_full.snapshot_keys([first])
    p_guest = adm.AdmissionSpace(p.log, None, keys=roster.Keyring({}, dict(p_keys)))
    n_guest = adm.AdmissionSpace(n.log, None, keys=roster.Keyring({first: n.krot[first]},
                                                                   dict(n_keys)),
                                 spaces_={p.id: p_guest})
    n_alone = adm.AdmissionSpace(n.log, None, keys=roster.Keyring({first: n.krot[first]},
                                                                   dict(n_keys)))
    return {
        "P": adm.summary(p, p_guest), "N_with_P": adm.summary(n, n_guest, {p.id: "P"}),
        "N_without_P": adm.summary(n, n_alone)["events"],
        "snapshot_carries": {"N body keys": sorted(n.name(i) for i in n_keys),
                             "P events": [p.name(i) for i in p.log.canonical()],
                             "P body keys": sorted(p.name(i) for i in p_keys)},
        "unit": n.name(unit),
    }


def ext_guests_vectors() -> dict:
    return {
        "parameters": {"nothing_at_rest": NOTHING_AT_REST,
                       "reserved_capability_prefix": RESERVED_CAPABILITY_PREFIX,
                       "leave_request_content": LEAVE_REQUEST_CONTENT,
                       "label": LEAVE_REQUEST_LABEL.decode(),
                       "session_bytes": SESSION_BYTES,
                       "session_lifetime_max": SESSION_LIFETIME_MAX,
                       "session_skew": SESSION_SKEW},
        "sessions": {**_session_vectors(), "offer_expiry": adm.ext_guests_offer_expiry()},
        "nothing_at_rest_meet": _nothing_at_rest_meet(),
        "leave_requests": _leave_vectors(),
        "session_expiry": _session_expiry(),
        "writer_decisions": _writer_decisions(),
        "followed": _followed_vectors(),
        "heartbeats": _heartbeat_vectors(),
        "off_grid": _offgrid_vectors(),
        "carve_out_guest": _carve_out_vectors(),
    }


def self_test() -> None:
    for a in NEW_LABELS:
        for b in adm.NEW_LABELS:
            assert not a.startswith(b) and not b.startswith(a)
    v = ext_guests_vectors()
    s = v["sessions"]
    ev = s["events"]
    assert ev["H ends session one"] == "valid"
    assert ev["G1 writes before the end"] == "valid"
    assert ev["G1 heals (a key event)"] == "valid"
    assert ev["G1 writes, concurrent with the end"].startswith("RefusedByRemoval")
    assert ev["G2 tries to remove itself"] == "NotAnAdministrator"
    assert s["roster"]["G1"] == "out" and s["roster"]["G2"] == "out"
    assert s["roster"]["G3"]["session"] and s["changes_in_the_end"] == 2
    assert s["guests"]["G1"] == {"guest": True, "nothing_at_rest": True}
    assert s["guests"]["G2"] == {"guest": True, "nothing_at_rest": False}
    assert s["guests"]["H"] == {"guest": False, "nothing_at_rest": False}
    m = v["nothing_at_rest_meet"]
    assert m["nothing_at_rest"] and all(x == "valid" for x in m["events"].values())
    lv = v["leave_requests"]
    assert all(d["outcome"] == "Remove" for d in lv["decisions"].values())
    assert sorted(d["rank"] for d in lv["decisions"].values()) == [0, 1]
    assert [r["outcome"] for r in lv["refusals"]] == [
        "NotTheMember", "Stale", "BadSignature", "WrongSpace", "MemberAdministers"], \
        lv["refusals"]
    assert lv["after"]["roster"]["G"] == "out"
    outcomes = [x["outcome"] for x in v["writer_decisions"]["decisions"]]
    assert outcomes == ["MayWrite", "MayWrite", "WindowElapsed", "WindowElapsed",
                        "WindowElapsed", "MayWrite", "NotOnline", "NotOnline", "NotOnline",
                        "MayWrite", "MayWrite", "SessionEnded", "SessionEnded", "SessionEnded",
                        "Left"], outcomes
    se = [x["outcome"] for x in v["session_expiry"]["decisions"]]
    assert se == ["Open", "Remove", "Remove", "Open", "Remove", "Remove", "Open", "Open"], se
    assert v["session_expiry"]["due"]["due"] is True
    assert v["session_expiry"]["due"]["outcomes"] == ["Open", "Remove"]
    fo = v["followed"]
    assert fo["events"]["X's unit, following W's second"].startswith("RefusedByRemoval"), fo
    assert fo["followed"]["timeline"] == 100
    hb = [x["outcome"] for x in v["heartbeats"]]
    assert hb == ["Wait", "Heartbeat", "Wait", "Heartbeat", "Heartbeat"], hb
    og = v["off_grid"]
    assert og["codes"][0] == og["codes"][1] and og["grant_check"] == "accepted"
    assert og["result"]["roster"]["guest"] == "out"
    assert all(x == "valid" for x in og["result"]["events"].values())
    co = v["carve_out_guest"]
    assert co["N_with_P"]["events"][co["unit"]] == "valid"
    assert co["N_without_P"][co["unit"]] == "Pending"
    assert co["P"]["roster"]["X"] == "out"


if __name__ == "__main__":
    self_test()
    print("guests: self-test passed")
