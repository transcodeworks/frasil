"""Spaces, written from the specification, independently of any implementation: the
space descriptor and the space policy (roster.md, "The space descriptor" and
"The space policy"), stream IDs (units.md, "Streams"), the grant graph with
its cycle and depth rules and effective membership (roster.md, "Grants of
spaces and effective membership"), which spaces rotate after a change and
who rotates them (keys.md, "Cascades" and "The rank and the delay"), and
ext-restricted-spaces.md's restricted spaces, carve-outs and move records.

Rosters are inputs: roster.md's procedure decides which roster events are
valid, and the examples here give each space's resolved direct grants."""

from __future__ import annotations

from dataclasses import dataclass, field as dc_field

import keygraph as kg
from formats import cbor_bytes, cbor_text, example
from primitives import SpecError, field, sha256

NEW_LABELS: list[bytes] = []  # the rotation rank's label is keys.md's

VERSION = 1
KIND_SPACE, KIND_RESTRICTED, KIND_CARVE_OUT = 0, 1, 2
KIND_NAMES = {KIND_SPACE: "space", KIND_RESTRICTED: "restricted", KIND_CARVE_OUT: "carve-out"}
STREAM_BYTES = 16
SPACE_ID_BYTES = 32
MAX_GRANT_DEPTH = 8
INHERITING_WARNING = 1024
MAX_STREAMS_DEFAULT = 65536
MAX_STREAMS_CEILING = 1048576
MAX_NAME_BYTES = 1022
READ, WRITE, ADMIN = kg.READ, kg.WRITE, kg.ADMIN
LEVEL_NAMES = kg.LEVEL_NAMES

# ---------------------------------------------------------------------------
# The space descriptor (roster.md, "The space descriptor").


MAX_APPLICATION_BYTES = 255


def encode_descriptor(kind: int, parent: bytes | None = None,
                      application: str | None = None) -> bytes:
    pairs = [(1, kg.c_uint(VERSION))]
    if kind != KIND_SPACE:
        pairs.append((2, kg.c_uint(kind)))
        pairs.append((3, cbor_bytes(parent)))
    if application is not None:
        pairs.append((4, cbor_text(application)))
    return kg.c_map(pairs)


RESERVED_KIND, RESERVED_KEY = 3, 5


def read_descriptor(data: bytes) -> dict:
    """roster.md, "The space descriptor": reading a descriptor, in order."""
    value = kg.decode_cbor(data, text=True)
    if not isinstance(value, dict) or not isinstance(value.get(1), int):
        raise SpecError("Malformed")
    if value[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if not all(isinstance(k, int) and k >= 1 for k in value):
        raise SpecError("Malformed")
    kind = value.get(2, KIND_SPACE)
    if 2 in value and not (isinstance(kind, int) and kind >= 1):
        raise SpecError("Malformed")
    # roster.md, "The space descriptor": a kind from 3, or a key from 5, is
    # a later document's. This implementation defines none: it checks
    # nothing more, and holds the space's other events (ExtensionRequired).
    if kind >= RESERVED_KIND or any(k >= RESERVED_KEY for k in value):
        return {"kind": kind, "parent": None, "application": None, "reserved": True}
    parent = value.get(3)
    if (kind == KIND_SPACE) != (parent is None):
        raise SpecError("Malformed")
    if parent is not None and (not isinstance(parent, bytes) or len(parent) != SPACE_ID_BYTES):
        raise SpecError("Malformed")
    application = value.get(4)
    if application is not None and (
            not isinstance(application, str)
            or not 1 <= len(application.encode()) <= MAX_APPLICATION_BYTES):
        raise SpecError("Malformed")
    return {"kind": kind, "parent": parent, "application": application}


# ---------------------------------------------------------------------------
# The space policy (roster.md, "The space policy"), with the ranges of
# overview.md, "Every timer".

HOUR, DAY = 3600, 86400
POLICY_FIELDS = {
    # key: (name, default or None for "off", minimum, maximum), in seconds
    2: ("agent_waiting_period", 72 * HOUR, 72 * HOUR, 30 * DAY),
    3: ("bounded_window", None, HOUR, 90 * DAY),
    4: ("online_freshness", None, 30, HOUR),
    5: ("gap_key_timeout", 7 * DAY, HOUR, 90 * DAY),
}
POLICY_FORBID_AGENTS = 6


def encode_policy(values: dict) -> bytes:
    pairs = [(1, kg.c_uint(VERSION))]
    for key, (name, default, _, _) in POLICY_FIELDS.items():
        if values.get(name) is not None and values[name] != default:
            pairs.append((key, kg.c_uint(values[name])))
    if values.get("forbid_agents"):
        pairs.append((POLICY_FORBID_AGENTS, kg.c_uint(1)))
    return kg.c_map(pairs)


def read_policy(data: bytes) -> dict:
    """roster.md, "The space policy": reading a policy, in order. A value
    is written only when it differs from its default, so a policy has one
    encoding."""
    value = kg.decode_cbor(data)
    if not isinstance(value, dict) or not isinstance(value.get(1), int):
        raise SpecError("Malformed")
    if value[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if set(value) - {1, POLICY_FORBID_AGENTS} - set(POLICY_FIELDS):
        raise SpecError("Malformed")
    out = {}
    for key, (name, default, low, high) in POLICY_FIELDS.items():
        if key not in value:
            out[name] = default
            continue
        v = value[key]
        if not isinstance(v, int) or v == default or not low <= v <= high:
            raise SpecError("Malformed")
        out[name] = v
    if POLICY_FORBID_AGENTS in value and value[POLICY_FORBID_AGENTS] != 1:
        raise SpecError("Malformed")
    out["forbid_agents"] = POLICY_FORBID_AGENTS in value
    return out


# ---------------------------------------------------------------------------
# Streams (units.md, "Streams").


def check_stream(stream: bytes) -> bytes:
    if len(stream) != STREAM_BYTES or stream == bytes(STREAM_BYTES):
        raise SpecError("Malformed")
    return stream


def stream_limit_ok(count: int, limit: int) -> bool:
    assert 1 <= limit <= MAX_STREAMS_CEILING
    return count <= limit


# ---------------------------------------------------------------------------
# The move record and the index pointer (ext-restricted-spaces.md, "The move
# record").


def encode_move(to_space: bytes, to_stream: bytes, name: str | None = None) -> bytes:
    check_stream(to_stream)
    assert len(to_space) == SPACE_ID_BYTES
    pairs = [(1, kg.c_uint(VERSION)), (2, cbor_bytes(to_space)), (3, cbor_bytes(to_stream))]
    if name is not None:
        pairs.append((4, cbor_text(name)))
    return kg.c_map(pairs)


def _decode_with_text(data: bytes):
    """decode_cbor plus one text value, the optional name at key 4."""
    from formats import Reader, TEXT, UNSIGNED, MAP
    reader = Reader(data)
    n = reader.head(MAP)
    out, last = {}, 0
    for _ in range(n):
        if not reader.data or reader.data[0] >> 5 != UNSIGNED:
            raise SpecError("Malformed")
        key = reader.head(UNSIGNED)
        if key <= last:
            raise SpecError("Malformed")
        last = key
        if key == 4:
            out[key] = reader.text(MAX_NAME_BYTES)
        else:
            out[key] = kg._item(reader, 1)
    if reader.data:
        raise SpecError("Malformed")
    return out


def read_move(data: bytes) -> dict:
    """ext-restricted-spaces.md, "The move record": reading one, in order;
    the same map is the pointer entry's value."""
    value = _decode_with_text(data)
    if not isinstance(value.get(1), int):
        raise SpecError("Malformed")
    if value[1] != VERSION:
        raise SpecError("UnsupportedVersion")
    if set(value) - {1, 2, 3, 4}:
        raise SpecError("Malformed")
    to_space, to_stream = value.get(2), value.get(3)
    if not isinstance(to_space, bytes) or len(to_space) != SPACE_ID_BYTES:
        raise SpecError("Malformed")
    if not isinstance(to_stream, bytes):
        raise SpecError("Malformed")
    check_stream(to_stream)
    return {"to_space": to_space, "to_stream": to_stream, "name": value.get(4)}


# ---------------------------------------------------------------------------
# The grant graph and effective membership (roster.md, "Grants of spaces and
# effective membership"), and cascades (keys.md, "Cascades").


@dataclass(frozen=True)
class Grant:
    """A valid grant in force in a space's roster (roster.md), as resolved."""
    event: bytes                 # the grant event's ID
    kind: str                    # "device", "person" or "space"
    target: str                  # a device name, a person name or a space name
    level: int
    session: bool = False        # device grants only: the guest preset
    from_now_on: bool = False
    capabilities: tuple = ()     # ((name, "extends" | "narrows"), ...)


@dataclass
class Space:
    name: str
    kind: int = KIND_SPACE
    parent: str | None = None
    grants: list = dc_field(default_factory=list)
    # A descriptor carrying a key from 5, whatever its kind (roster.md,
    # "The space descriptor").
    reserved_key: bool = False

    @property
    def id(self) -> bytes:
        return example(f"spaces/space/{self.name}")


@dataclass(frozen=True)
class Reach:
    """How a device reaches a space: its effective grant there."""
    level: int
    propagates: bool
    prop_level: int          # its level over the paths that propagate
    extends: tuple
    narrows: tuple
    depth: int
    session: bool
    # Over the paths that propagate at prop_level: what a space that grants
    # this one passes on, beside prop_level.
    prop_narrows: tuple = ()
    prop_depth: int = 0


def effective_edges(spaces: dict) -> dict:
    """roster.md, "Grants of spaces and effective membership": which space
    grants count. A grant of a restricted space never does. Then, while some counted edges close a cycle, the one among
    them whose granting space ID is highest stops counting. Then the edges are
    kept from the roots down, nearest first, the lower granting space ID first
    among equals, each unless it would make a chain of more than 8 spaces.
    Space IDs are fixed when the spaces are made, so no granter can grind them; the
    grant's event ID breaks only the last ties. Returns {event: reason or
    None}."""
    verdict = {}
    live = []
    for s in sorted(spaces.values(), key=lambda x: x.id):
        for g in s.grants:
            if g.kind != "space":
                continue
            if g.target not in spaces:
                verdict[g.event] = "UnknownSpace"
            elif spaces[g.target].kind == KIND_RESTRICTED:
                verdict[g.event] = "GrantOfRestricted"
            elif spaces[g.target].kind >= RESERVED_KIND or spaces[g.target].reserved_key:
                # roster.md, 3.3: a space whose descriptor a later document
                # defines is never reached through a grant, at every
                # implementation.
                verdict[g.event] = "GrantOfReserved"
            elif g.target == s.name:
                verdict[g.event] = "GrantCycle"
            else:
                live.append((g.event, s.name, g.target))

    def order(edge):
        event, granter, grantee = edge
        return (spaces[granter].id, spaces[grantee].id, event)

    def reaches(a, b):   # a path of live grants from a to b
        seen, todo = set(), [a]
        while todo:
            x = todo.pop()
            if x == b:
                return True
            if x not in seen:
                seen.add(x)
                todo.extend(t for _, f, t in live if f == x)
        return False

    def up(x):     # the longest chain of granters ending at x, counted in spaces
        return 1 + max((up(f) for _, f, t in live if t == x), default=0)

    def down(x):   # the longest chain of grantees starting at x, counted in spaces
        return 1 + max((down(t) for _, f, t in live if f == x), default=0)

    while True:
        cycle = [e for e in live if reaches(e[2], e[1])]
        if not cycle:
            break
        drop = max(cycle, key=order)
        live.remove(drop)
        verdict[drop[0]] = "GrantCycle"
    # Depth: take the acyclic edges from the roots down, nearest first, and
    # keep each unless the chain of kept edges through it would pass 8
    # spaces. So the edges farthest from a root are the ones that stop
    # counting, and no more of them than the limit needs.
    acyclic = list(live)

    def dist(x):   # the longest chain of granters above x
        return max((dist(f) + 1 for _, f, t in acyclic if t == x), default=0)

    live = []
    for e in sorted(acyclic, key=lambda e: (dist(e[1]), order(e))):
        live.append(e)
        if up(e[1]) + down(e[2]) > MAX_GRANT_DEPTH:
            live.remove(e)
            verdict[e[0]] = "GrantTooDeep"
    for e in live:
        verdict[e[0]] = None
    return verdict


def _combine(paths: list) -> Reach:
    """The level is the highest over every path. Over the paths
    at that level, the depth is the least, an extending capability stays only
    if every one of them carries it, and a narrowing one if any does: the
    merge fails closed, as roster.md's merge of concurrent states does. The
    paths that propagate are merged alike, apart (roster.md, 3.3): their
    highest level, and over those at it the narrowing capabilities of any
    and the least depth, which a granting space passes on."""
    level = max(p["level"] for p in paths)
    strongest = [p for p in paths if p["level"] == level]
    extends = set.intersection(*(set(p["extends"]) for p in strongest))
    narrows = set.union(*(set(p["narrows"]) for p in strongest))
    propagating = [p for p in paths if p["propagates"]]
    prop_level = max((p["level"] for p in propagating), default=0)
    prop_strongest = [p for p in propagating if p["level"] == prop_level]
    return Reach(level, bool(propagating), prop_level,
                 tuple(sorted(extends)), tuple(sorted(narrows)),
                 min(p["depth"] for p in strongest), all(p["session"] for p in paths),
                 tuple(sorted(set().union(*(set(p["narrows"]) for p in prop_strongest)))),
                 min((p["depth"] for p in prop_strongest), default=0))


def effective(spaces: dict, persons: dict, name: str, edges: dict | None = None,
              _stack: tuple = ()) -> dict:
    """Every device that reaches `name`, with its effective grant."""
    if edges is None:
        edges = effective_edges(spaces)
    space = spaces[name]
    paths: dict = {}

    def offer(device, **path):
        paths.setdefault(device, []).append(path)

    for g in space.grants:
        ext = {n for n, m in g.capabilities if m == "extends"}
        nar = {n for n, m in g.capabilities if m == "narrows"}
        if g.kind == "device":
            offer(g.target, level=g.level, propagates=not g.session, extends=ext, narrows=nar,
                  depth=1, session=g.session)
        elif g.kind == "person":
            for d in persons[g.target]:
                offer(d, level=g.level, propagates=True, extends=ext, narrows=nar, depth=1,
                      session=False)
        elif edges.get(g.event) is None and g.target not in _stack:
            inner = effective(spaces, persons, g.target, edges, _stack + (name,))
            for d, r in inner.items():
                if not r.propagates:
                    continue  # a guest of the granted space gains nothing here
                # Administer never flows; an extending capability comes only
                # from this space's own grant, a narrowing one from any on the
                # path.
                offer(d, level=min(g.level, r.prop_level, WRITE), propagates=True,
                      extends=ext, narrows=nar | set(r.prop_narrows), depth=r.prop_depth + 1,
                      session=False)
    out = {d: _combine(ps) for d, ps in paths.items()}
    if space.kind == KIND_RESTRICTED:
        parent = effective(spaces, persons, space.parent, edges, _stack + (name,))
        out = {d: Reach(min(r.level, parent[d].level), r.propagates and parent[d].propagates,
                        min(r.prop_level, parent[d].prop_level), r.extends, r.narrows, r.depth,
                        r.session, r.prop_narrows, r.prop_depth)
               for d, r in out.items() if d in parent}
    return out


def unrestricted(spaces: dict, persons: dict, name: str) -> dict:
    """ext-restricted-spaces.md, "Membership of a restricted space": its own
    membership, before it is narrowed by its parent's: what decides whether it
    rotates."""
    space = spaces[name]
    if space.kind != KIND_RESTRICTED:
        return effective(spaces, persons, name)
    copy = dict(spaces)
    copy[name] = Space(name, KIND_SPACE, None, space.grants)
    return effective(copy, persons, name)


def reached_by(spaces: dict, name: str) -> list:
    """Every space that `name`'s propagating members reach through grants,
    transitively, nearest first."""
    edges = effective_edges(spaces)
    out, frontier = [], [name]
    while frontier:
        nxt = []
        for x in frontier:
            for s in sorted(spaces):
                for g in spaces[s].grants:
                    if (g.kind == "space" and g.target == x and edges.get(g.event) is None
                            and s not in out and s != name):
                        out.append(s)
                        nxt.append(s)
        frontier = nxt
    return out


def cascade(before: dict, after: dict, persons: dict, changed: str, change: str) -> dict:
    """keys.md, "Cascades": which spaces rotate after a change to `changed`,
    and how.
    `change` is "removal" (a roster or device-list change that may lose
    devices), "break" (a from-now-on admission of a propagating member) or
    "grant-heal". Returns {space: "rotates" | "breaks" | reason it does not}."""
    out = {}
    names = sorted(after)
    for s in names:
        if s == changed:
            continue
        if change in ("break", "grant-heal"):
            out[s] = ({"break": "breaks", "grant-heal": "rotates"}[change]
                      if s in reached_by(after, changed) else "not reached")
            continue
        old = unrestricted(before, persons, s)
        new = unrestricted(after, persons, s)
        lost = sorted(d for d in old if d not in new)
        out[s] = ("rotates: loses " + ", ".join(lost)) if lost else "keeps its key"
    return out


# ---------------------------------------------------------------------------
# A carve-out (ext-restricted-spaces.md, "Creating a carve-out").


def carve_out_levels(parent_members: dict, grant_level: int) -> dict:
    """ext-restricted-spaces.md, "Creating a carve-out": the level each of the
    parent's members has in the carve-out through its grant of the parent: the lower of the grant's level
    and the member's, administer capped at write. Administer in the carve-out
    comes only from its direct grants to the parent's administrator devices."""
    return {d: min(grant_level, r.prop_level, WRITE) for d, r in parent_members.items()
            if r.propagates}


# ---------------------------------------------------------------------------
# Vectors: roster.json's and ext-restricted-spaces.json's families.


def h(value: bytes) -> str:
    return value.hex()


def _eid(name: str) -> bytes:
    return example(f"spaces/event/{name}")


PERSONS = {"alice": ["a-laptop", "a-phone"], "bob": ["b-laptop"], "carol": ["c-laptop"],
           "dave": ["d-laptop"], "erin": ["e-laptop"], "frank": ["f-laptop"]}


def reference_spaces(bob_in_project: bool = False, core: bool = False) -> dict:
    """The reference deployment: a team T, two projects P and Q
    that grant it, a carve-out N of P for a guest, and a private folder F
    restricted under P."""
    T = Space("T", grants=[
        Grant(_eid("T/alice"), "person", "alice", WRITE),
        Grant(_eid("T/bob"), "person", "bob", WRITE, capabilities=(("suggest", "narrows"),)),
        Grant(_eid("T/carol"), "person", "carol", READ),
        Grant(_eid("T/a-laptop"), "device", "a-laptop", ADMIN),
        Grant(_eid("T/guest"), "device", "tg-device", WRITE, session=True, from_now_on=True),
    ])
    P = Space("P", grants=[
        Grant(_eid("P/T"), "space", "T", WRITE),
        Grant(_eid("P/erin"), "person", "erin", WRITE),
        Grant(_eid("P/a-laptop"), "device", "a-laptop", ADMIN),
    ] + ([Grant(_eid("P/bob"), "person", "bob", WRITE)] if bob_in_project else []))
    Q = Space("Q", grants=[Grant(_eid("Q/T"), "space", "T", READ),
                           Grant(_eid("Q/a-laptop"), "device", "a-laptop", ADMIN),
                           Grant(_eid("Q/F"), "space", "F", READ)])
    N = Space("N", KIND_CARVE_OUT, "P", grants=[
        Grant(_eid("N/P"), "space", "P", WRITE, capabilities=(("comment", "extends"),)),
        Grant(_eid("N/a-laptop"), "device", "a-laptop", ADMIN),
        Grant(_eid("N/guest"), "device", "g-tablet", WRITE, session=True, from_now_on=True),
    ])
    F = Space("F", KIND_RESTRICTED, "P", grants=[
        Grant(_eid("F/bob"), "person", "bob", WRITE),
        Grant(_eid("F/erin"), "person", "erin", READ),
        Grant(_eid("F/dave"), "person", "dave", WRITE),
        Grant(_eid("F/a-laptop"), "device", "a-laptop", ADMIN),
    ])
    if core:  # without ext-restricted-spaces.md's carve-out and restricted space, and
        # with a space S that grants nothing the team reaches
        Q.grants = [g for g in Q.grants if g.target != "F"]
        S = Space("S", grants=[Grant(_eid("S/erin"), "person", "erin", WRITE),
                               Grant(_eid("S/a-laptop"), "device", "a-laptop", ADMIN)])
        return {s.name: s for s in (T, P, Q, S)}
    return {s.name: s for s in (T, P, Q, N, F)}


def _members_json(members: dict, propagating: bool = False) -> dict:
    """Each device's effective grant; with `propagating`, also its level over
    the paths that propagate, or None."""
    return {d: {"level": LEVEL_NAMES[r.level], "propagates": r.propagates,
                "extends": list(r.extends), "narrows": list(r.narrows), "depth": r.depth,
                **({"propagating_level": LEVEL_NAMES[r.prop_level] if r.propagates else None}
                   if propagating else {})}
            for d, r in sorted(members.items())}


def _spaces_json(spaces: dict) -> list:
    return [{"name": s.name, "id": h(s.id), "kind": KIND_NAMES[s.kind], "parent": s.parent,
             "grants": [{"event": h(g.event), "kind": g.kind, "target": g.target,
                         "level": LEVEL_NAMES[g.level], "session": g.session,
                         "from_now_on": g.from_now_on,
                         "capabilities": [list(c) for c in g.capabilities]}
                        for g in s.grants]} for s in spaces.values()]


def membership_vectors(core: bool = False) -> dict:
    spaces = reference_spaces(core=core)
    edges = effective_edges(spaces)
    return {"persons": PERSONS, "spaces": _spaces_json(spaces),
            "edges": [{"event": h(e), "verdict": v or "effective"} for e, v in sorted(edges.items())],
            "effective": {name: _members_json(effective(spaces, PERSONS, name))
                          for name in sorted(spaces)}}


PROPAGATING_PERSONS = {"hana": ["g-one"], "ivan": ["g-two"]}


def propagating_spaces() -> dict:
    """roster.md, 3.3: a device's highest level and its highest over the
    paths that propagate are kept apart. In the team, g-one is a guest at
    write and reaches it at read through hana; g-two a guest at read, and
    at write through ivan. The project grants the team at write."""
    team = Space("Team", grants=[
        Grant(_eid("Team/g-one"), "device", "g-one", WRITE, session=True, from_now_on=True,
              capabilities=(("comment", "narrows"),)),
        Grant(_eid("Team/hana"), "person", "hana", READ,
              capabilities=(("suggest", "narrows"),)),
        Grant(_eid("Team/g-two"), "device", "g-two", READ, session=True, from_now_on=True),
        Grant(_eid("Team/ivan"), "person", "ivan", WRITE),
    ])
    project = Space("Project", grants=[Grant(_eid("Project/Team"), "space", "Team", WRITE)])
    return {s.name: s for s in (team, project)}


def propagating_path_vectors() -> dict:
    spaces = propagating_spaces()
    edges = effective_edges(spaces)
    return {"persons": PROPAGATING_PERSONS, "spaces": _spaces_json(spaces),
            "edges": [{"event": h(e), "verdict": v or "effective"} for e, v in sorted(edges.items())],
            "effective": {name: _members_json(effective(spaces, PROPAGATING_PERSONS, name), True)
                          for name in sorted(spaces)}}


def graph_rule_vectors() -> list:
    out = []
    # A cycle made by concurrent grants: X grants Y on one branch, Y grants X on another.
    X = Space("X", grants=[Grant(_eid("cycle/X-grants-Y"), "space", "Y", WRITE),
                           Grant(_eid("cycle/x"), "device", "x-device", WRITE)])
    Y = Space("Y", grants=[Grant(_eid("cycle/Y-grants-X"), "space", "X", WRITE),
                           Grant(_eid("cycle/y"), "device", "y-device", WRITE)])
    spaces = {"X": X, "Y": Y}
    out.append({"name": "two concurrent grants that close a cycle: the one whose granting "
                        "space ID is higher stops counting", "spaces": _spaces_json(spaces),
                "edges": [{"event": h(e), "verdict": v or "effective"}
                          for e, v in sorted(effective_edges(spaces).items())],
                "effective": {n: _members_json(effective(spaces, {}, n)) for n in sorted(spaces)}})
    # A chain of ten spaces: S0 grants S1 grants ... S9.
    chain = {}
    for i in range(10):
        grants = [Grant(_eid(f"chain/s{i}/device"), "device", f"s{i}-device", WRITE)]
        if i < 9:
            grants.append(Grant(_eid(f"chain/S{i}-grants-S{i + 1}"), "space", f"S{i + 1}", WRITE))
        chain[f"S{i}"] = Space(f"S{i}", grants=grants)
    verdicts = effective_edges(chain)
    out.append({"name": "a chain of ten spaces: the edge farthest from the root stops "
                        "counting, so the chain keeps 8 spaces from its root",
                "spaces": _spaces_json(chain),
                "edges": [{"event": h(e), "verdict": v or "effective"}
                          for e, v in sorted(verdicts.items())],
                "reach_of_s9_device": sorted(n for n in chain
                                             if "s9-device" in effective(chain, {}, n))})
    assert sum(1 for v in verdicts.values() if v == "GrantTooDeep") >= 1
    # A grant of a restricted space.
    ref = reference_spaces()
    out.append({"name": "a grant of a restricted space never counts",
                "edge": h(_eid("Q/F")), "verdict": effective_edges(ref)[_eid("Q/F")]})
    # roster.md, 3.3 and "Checks across logs", "Paths": a grant of a space
    # passes on only what the device's propagating paths there give. A
    # guest grant in the granted space passes on nothing, neither a path
    # nor capabilities, even at the level of a path that propagates: carol's
    # laptop is a guest at write in Y with comment and suggest, and reaches
    # Y at write through carol, so it reaches X at write with neither.
    Y = Space("Y", grants=[
        Grant(_eid("guest/bob"), "person", "bob", WRITE, capabilities=(("suggest", "narrows"),)),
        Grant(_eid("guest/b-laptop"), "device", "b-laptop", WRITE, session=True),
        Grant(_eid("guest/carol"), "person", "carol", WRITE),
        Grant(_eid("guest/c-laptop"), "device", "c-laptop", WRITE, session=True,
              capabilities=(("comment", "extends"), ("suggest", "narrows"))),
        Grant(_eid("guest/g-tablet"), "device", "g-tablet", WRITE, session=True),
        Grant(_eid("guest/y-admin"), "device", "y-admin", ADMIN),
    ])
    X = Space("X", grants=[Grant(_eid("guest/X-grants-Y"), "space", "Y", WRITE),
                           Grant(_eid("guest/x-admin"), "device", "x-admin", ADMIN)])
    spaces = {"X": X, "Y": Y}
    persons = {"bob": ["b-laptop"], "carol": ["c-laptop"]}
    members = {n: effective(spaces, persons, n) for n in sorted(spaces)}
    out.append({"name": "guest grants inside a granted space: they pass on nothing through "
                        "the grant, neither a path nor capabilities, even at the level of a "
                        "path that propagates",
                "spaces": _spaces_json(spaces), "persons": persons,
                "edges": [{"event": h(e), "verdict": v or "effective"}
                          for e, v in sorted(effective_edges(spaces).items())],
                "effective": {n: _members_json(m) for n, m in members.items()}})
    assert members["X"]["b-laptop"].narrows == ("suggest",)
    assert members["Y"]["c-laptop"].narrows == ("suggest",)
    assert members["X"]["c-laptop"].level == WRITE
    assert members["X"]["c-laptop"].narrows == () and members["X"]["c-laptop"].extends == ()
    assert "g-tablet" not in members["X"] and "g-tablet" in members["Y"]
    return out


def cascade_vectors(core: bool = False) -> list:
    out = []
    base = reference_spaces(core=core)

    def without(spaces, space, event):
        copy = {n: Space(s.name, s.kind, s.parent, list(s.grants)) for n, s in spaces.items()}
        copy[space].grants = [g for g in copy[space].grants if g.event != event]
        return copy

    def case(title, before, after, changed, change, persons=PERSONS):
        result = cascade(before, after, persons, changed, change)
        out.append({"name": title, "changed": changed, "change": change,
                    "before": _spaces_json(before), "after": _spaces_json(after),
                    "persons": persons, "result": result})
        return result

    r = case("bob leaves the team", base, without(base, "T", _eid("T/bob")), "T", "removal")
    assert r["P"].startswith("rotates")
    assert core or (r["N"].startswith("rotates") and r["F"] == "keeps its key")
    r = case("the team's guest leaves: the team's content key only", base,
             without(base, "T", _eid("T/guest")), "T", "removal")
    assert all(v == "keeps its key" for k, v in r.items())
    r = case("erin leaves the project", base, without(base, "P", _eid("P/erin")), "P", "removal")
    assert core or (r["N"].startswith("rotates") and r["F"] == "keeps its key")
    assert r["T"] == "keeps its key"
    both = reference_spaces(bob_in_project=True, core=core)
    r = case("bob leaves the team but is also granted the project directly", both,
             without(both, "T", _eid("T/bob")), "T", "removal")
    assert r["P"] == "keeps its key" and r["Q"].startswith("rotates")
    persons = {**PERSONS, "bob": ["b-laptop", "b-old-phone"]}
    after_persons = PERSONS
    old_t = effective(base, persons, "T")
    rows = {}
    for name in sorted(base):
        old = unrestricted(base, persons, name)
        new = unrestricted(base, after_persons, name)
        lost = sorted(d for d in old if d not in new and old[d].propagates)
        rows[name] = ("rotates: loses " + ", ".join(lost)) if lost else "keeps its key"
    out.append({"name": "bob's device list revokes an old phone: every space that reaches it "
                        "rotates, with no roster event", "changed": "bob's device list",
                "change": "removal", "before": _spaces_json(base), "after": _spaces_json(base),
                "persons_before": persons, "persons_after": after_persons, "result": rows})
    assert "b-old-phone" in old_t and rows["P"].startswith("rotates")
    after = {n: Space(s.name, s.kind, s.parent, list(s.grants)) for n, s in base.items()}
    after["T"].grants.append(Grant(_eid("T/frank"), "person", "frank", WRITE, from_now_on=True))
    r = case("the team admits frank from now on: every space it reaches breaks", base, after, "T",
             "break")
    assert r["P"] == "breaks" and r["Q"] == "breaks" and (core or r["N"] == "breaks")
    r = case("the team heals its grant key", base, base, "T", "grant-heal")
    assert r["P"] == "rotates" and (core or r["F"] == "not reached")
    return out


def rank_vectors() -> dict:
    """keys.md, "Cascades": after bob leaves T, the candidates for P's cascade are
    P's writer devices that propagate and are propagating members of T after
    the change, ranked as keys.md, "The rank and the delay", ranks them."""
    before = reference_spaces()
    after = {n: Space(s.name, s.kind, s.parent, [g for g in s.grants if g.event != _eid("T/bob")])
             for n, s in before.items()}
    trigger = _eid("T/removal-of-bob")
    p = after["P"].id
    in_p = effective(after, PERSONS, "P")
    in_t = effective(after, PERSONS, "T")
    candidates = {d: _device(d)["device_id"] for d, r in in_p.items()
                  if r.propagates and r.level >= WRITE and d in in_t and in_t[d].propagates}
    by_key = {v: k for k, v in candidates.items()}
    rows = []
    for position, device in enumerate(kg.rank_order(p, trigger, list(candidates.values()))):
        r = kg.rank_value(p, trigger, device)
        rows.append({"position": position, "device": by_key[device], "device_id": h(device),
                     "value": r["value"], "delay_seconds": kg.rank_delay(position, 2)})
    return {"space": h(p), "trigger": h(trigger), "rotation_step": 2,
            "not_candidates": {"b-laptop": "removed from T", "c-laptop": "reads P",
                               "e-laptop": "not a member of T: it cannot know T's new grant key"},
            "ranks": rows}


def _device(name: str) -> dict:
    """A device by crypto.md's fixture derivations, named by its device ID."""
    import history_sigs as hs
    signer = hs.fixture_signer(example(f"spaces/device/{name}/ed25519"), name)
    return {"name": name, "identity_seed": signer.ed_seed, "identity": signer.ed_public,
            "hybrid_seed": signer.xwing_seed, "hybrid": signer.xwing_public,
            "device_id": signer.device_id}


def carve_out_vectors() -> dict:
    """N's log, built as events (events.py) of kind 2, the space
    event: each body a rotation payload (keygraph.py) whose sealed part holds
    the roster part (roster.py): the genesis, the update that grants P and
    admits the guest, and the guest's removal. roster.py opens and resolves it
    with the three rotations' content keys and finds every event valid."""
    import events
    import roster as rs
    spaces = reference_spaces()
    P = spaces["P"]
    hist = events.History("spaces/device")
    admin, guest = _device("a-laptop"), _device("g-tablet")
    assert hist.device("a-laptop") == admin["device_id"]
    assert hist.device("g-tablet") == guest["device_id"]
    p_rotation = example("spaces/P/rotation/genesis")
    p_grant = kg.grant_key_pair(example("spaces/P/genesis/grant"))
    p_commitment = kg.grant_commitment(p_grant["public"], False)
    sec = {e: {k: example(f"spaces/N/{e}/{k}") for k in ("content", "upload", "grant")}
           for e in ("genesis", "admit", "leave")}

    def eseed(label):
        return example(f"spaces/N/eseed/{label}") + example(f"spaces/N/eseed/{label}/2")

    def commits(e):
        return {"read": kg.read_credential(sec[e]["content"])["public"],
                "upload": kg.upload_key(sec[e]["upload"])["public"]}

    def device_change(d, level, history, via, session=None):
        """A device grant carries its Ed25519, X-Wing and ML-DSA-65 keys,
        which give its member ID (roster.md, "A device's keys")."""
        return rs.Change(rs.GRANT, (rs.DEVICE, d["device_id"]), level, None, None, history, via,
                         session, None, d["hybrid"], hist.mldsa(d["name"]),
                         ed25519=d["identity"])

    # 1. The genesis: the creator alone. Inside a genesis, wraps and the
    # sealed part bind the genesis's nonce as their log field (keys.md): the space ID is the genesis's own hash.
    nonce = example("spaces/N/nonce")[:16]
    founder = device_change(admin, rs.ADMINISTER, rs.WITH_HISTORY, rs.VIA_NONE)
    own1 = kg.self_ref(admin["device_id"], 1)
    full1 = kg.make_bundle(**sec["genesis"])
    g_public = kg.grant_key_pair(sec["genesis"]["grant"])["public"]
    genesis_visible = {"rotates": True, "grant_commitment": kg.grant_commitment(g_public, False),
                       **commits("genesis"), "grant_rotation": True,
                       "deliveries": [{"key": own1, "grant": own1, "wraps": [kg.seal_bundle_wrap(
                           nonce, own1, own1, admin["device_id"], admin["hybrid"], full1,
                           eseed("genesis"))["wrap"]]}],
                       "nonce": nonce, "roster": rs.genesis_roster(
                           founder, descriptor=encode_descriptor(KIND_CARVE_OUT, P.id))}
    genesis_payload = kg.encode_payload(genesis_visible, nonce, admin["device_id"], 1,
                                        sec["genesis"]["content"],
                                        example("spaces/N/seal/genesis")[:kg.NONCE_BYTES])
    opened1 = kg.open_sealed(kg.read_payload(genesis_payload, admin["device_id"], 1),
                             sec["genesis"]["content"], nonce, admin["device_id"], 1)
    kg.check_payload_context(opened1, {"event": "genesis", "author_propagates": True})
    n_id = hist.genesis("a-laptop", rs.KIND_SPACE, genesis_payload, "N's genesis")
    g_name = kg.encode_set([n_id])

    # 2. The update: N grants P at write with history, and the guest from now
    # on. The guest's admission is a break; nothing earlier was ever wrapped
    # for anyone but the creator. One delivery: the guest's wrap simply holds
    # no grant seed.
    admit_changes = [
        rs.Change(rs.GRANT, (rs.SPACE, P.id), rs.WRITE, (("comment", rs.EXTENDS),), None,
                  rs.WITH_HISTORY, rs.VIA_NONE),
        device_change(guest, rs.WRITE, rs.FROM_NOW_ON, rs.VIA_CODE,
                      example("spaces/N/session")[:16]),
    ]
    own2 = kg.self_ref(admin["device_id"], 2)
    admit = sec["admit"]
    full2 = kg.make_bundle(content=admit["content"], upload=admit["upload"],
                           grant=sec["genesis"]["grant"])
    # The own delivery names both states by the self reference; sealed key 1
    # says which grant state its grant slot carries: the genesis's.
    admin_wrap = kg.seal_bundle_wrap(n_id, own2, own2, admin["device_id"], admin["hybrid"],
                                     full2, eseed("admit/admin"))
    guest_wrap = kg.seal_bundle_wrap(n_id, own2, own2, guest["device_id"], guest["hybrid"],
                                     kg.make_bundle(content=admit["content"],
                                                    upload=admit["upload"]),
                                     eseed("admit/guest"))
    space_wrap = kg.seal_space_wrap(n_id, own2, own2, P.id, p_rotation, p_grant["public"],
                                    full2, eseed("admit/P"))
    # P's members are entitled to N's history from its start, the genesis
    # included: a space wrap of {genesis} for P.
    genesis_space_wrap = kg.seal_space_wrap(n_id, g_name, g_name, P.id, p_rotation,
                                            p_grant["public"], full1, eseed("admit/P/genesis"))
    admit_payload = kg.encode_payload({
        "rotates": True, "grant_commitment": kg.filler_commitment(admit["content"]),
        **commits("admit"), "break": True,
        "grant_state": g_name,
        "deliveries": [{"key": own2, "grant": own2,
                        "wraps": [admin_wrap["wrap"], guest_wrap["wrap"]],
                        "space_wraps": [space_wrap["wrap"]]},
                       {"key": g_name, "grant": g_name,
                        "space_wraps": [genesis_space_wrap["wrap"]]}],
        "gaps": [kg.gap_record(kg.KIND_CONTENT, g_name)],
        "notices": [{"space": P.id, "rotation": p_rotation, "public": p_grant["public"]}],
        "roster": rs.update_roster(admit_changes)},
        n_id, admin["device_id"], 2, admit["content"],
        example("spaces/N/seal/admit")[:kg.NONCE_BYTES])
    parsed = kg.open_sealed(kg.read_payload(admit_payload, admin["device_id"], 2),
                            admit["content"], n_id, admin["device_id"], 2)
    kg.check_payload_context(parsed, {"event": "roster", "admits_from_now_on": True,
                                      "admits_propagating": False, "author_propagates": True})
    kg.check_notice(parsed["notices"][0], {"grant_commitment": p_commitment}, True)
    assert parsed["grant_state"] == g_name
    opened = kg.open_space_wrap(space_wrap["wrap"], n_id, own2, own2, P.id, p_rotation,
                                p_grant["xwing_seed"])
    kg.check_commitment({k: v for k, v in opened.items() if k != "grant"}, parsed)
    assert opened["grant"] == sec["genesis"]["grant"]
    index, guest_bundle = kg.find_own_wrap(parsed["deliveries"][0]["wraps"], n_id, own2, own2,
                                           guest["device_id"], guest["hybrid_seed"])
    # A member of P opens N's genesis: the {genesis} space wrap gives it the
    # genesis's content key, from which it derives the genesis's body key.
    from_p = kg.open_space_wrap(genesis_space_wrap["wrap"], n_id, g_name, g_name, P.id,
                                p_rotation, p_grant["xwing_seed"])
    genesis_body_key = kg.seal_key(from_p["content"], nonce, admin["device_id"], 1)
    genesis_opened = kg.open_with_body_key(kg.read_payload(genesis_payload, admin["device_id"], 1),
                                           genesis_body_key, nonce, admin["device_id"], 1)
    assert genesis_opened["roster"] is not None
    assert index == 1 and "grant" not in guest_bundle
    admit_id = hist.act("a-laptop", rs.KIND_SPACE, admit_payload,
                        "N grants P and admits the guest")

    # 3. The guest leaves: a content rotation only, wrapped for the
    # administrator, space-wrapped for P, and linked back.
    own3 = kg.self_ref(admin["device_id"], 3)
    leave = sec["leave"]
    full3 = kg.make_bundle(content=leave["content"], upload=leave["upload"],
                           grant=sec["genesis"]["grant"])
    leave_payload = kg.encode_payload({
        "rotates": True, "grant_commitment": kg.filler_commitment(leave["content"]),
        **commits("leave"),
        "grant_state": g_name,
        "deliveries": [{"key": own3, "grant": own3, "wraps": [kg.seal_bundle_wrap(
            n_id, own3, own3, admin["device_id"], admin["hybrid"], full3,
            eseed("leave/admin"))["wrap"]],
            "space_wraps": [kg.seal_space_wrap(n_id, own3, own3, P.id, p_rotation,
                                               p_grant["public"], full3,
                                               eseed("leave/P"))["wrap"]]}],
        "links": [kg.seal_link(kg.KIND_CONTENT, n_id, own3, kg.encode_set([admit_id]),
                               leave["content"], admit["content"],
                               example("spaces/N/leave/link")[:kg.NONCE_BYTES])["link"]],
        "roster": rs.update_roster([rs.Change(rs.REMOVE, (rs.DEVICE, guest["device_id"]))])},
        n_id, admin["device_id"], 3, leave["content"],
        example("spaces/N/seal/leave")[:kg.NONCE_BYTES])
    kg.check_payload_context(
        kg.open_sealed(kg.read_payload(leave_payload, admin["device_id"], 3), leave["content"],
                       n_id, admin["device_id"], 3),
        {"event": "roster", "removes": True, "removes_propagating": False,
         "author_propagates": True})
    leave_id = hist.act("a-laptop", rs.KIND_SPACE, leave_payload, "N removes the guest")

    resolved = rs.Space(hist.log, keys=rs.Keyring({n_id: sec["genesis"]["content"],
                                                   admit_id: admit["content"],
                                                   leave_id: leave["content"]}))
    assert {n_id, admit_id, leave_id} <= resolved.valid()
    assert resolved.rotations() == [leave_id]
    for i in (admit_id, leave_id):
        e = hist.log.events[i]
        assert kg.read_payload(e.body, e.author, e.seq)["rotates"]
    members_p = effective(spaces, PERSONS, "P")
    #  (units.md): the document's new stream in N
    # commits to its adapter type over a fresh salt.
    salt = example("spaces/N/stream-salt")[:16]
    raw = b"frasil:loro"
    stream = sha256(b"frasil/stream-id/v1" + bytes([len(raw)]) + raw + salt)[:STREAM_BYTES]
    move = encode_move(n_id, stream, "Budget 2027")
    assert read_move(move)["to_stream"] == stream
    log = []
    for i in (n_id, admit_id, leave_id):
        e = hist.log.events[i]
        log.append({"name": hist.name(i), "id": h(i), "seq": e.seq, "body": h(e.body),
                    "signed": h(e.signed)})
    return {
        "parent": {"name": "P", "id": h(P.id), "grant_rotation": h(p_rotation),
                   "grant_commitment": h(p_commitment),
                   "grant_seed": h(example("spaces/P/genesis/grant")),
                   "grant_key": {"xwing_seed": h(p_grant["xwing_seed"]),
                                 "public": h(p_grant["public"])}},
        "carve_out": {
            "id": h(n_id), "genesis_nonce": h(nonce),
            "descriptor": h(encode_descriptor(KIND_CARVE_OUT, P.id)),
            "creator": {"name": admin["name"], "identity_seed": h(admin["identity_seed"]),
                        "hybrid_seed": h(admin["hybrid_seed"]),
                        "mldsa": h(hist.mldsa("a-laptop")), "device_id": h(admin["device_id"])},
            "guest": {"name": guest["name"], "identity_seed": h(guest["identity_seed"]),
                      "hybrid_seed": h(guest["hybrid_seed"]), "device_id": h(guest["device_id"])},
            "secrets": {e: {k: h(x) for k, x in v.items()} for e, v in sec.items()},
            "payloads": {"genesis": h(genesis_payload), "admit": h(admit_payload),
                         "leave": h(leave_payload)},
            "log": log,
            "valid_by_roster_py": True,
            "p_member_opens_genesis": {
                "space_wrap": h(genesis_space_wrap["wrap"]),
                "genesis_content_key": h(from_p["content"]),
                "genesis_body_key": h(genesis_body_key),
                "genesis_commitment": h(kg.body_commitment(genesis_body_key))},
        },
        "levels_through_the_grant_of_P_at_write": {
            d: LEVEL_NAMES[x] for d, x in sorted(carve_out_levels(members_p, WRITE).items())},
        "effective_in_N": _members_json(effective(spaces, PERSONS, "N")),
        "document": {"stream_in_P": h(example("spaces/P/stream/budget")[:STREAM_BYTES]),
                     "stream_in_N": h(stream), "stream_type": raw.decode(), "stream_salt": h(salt),
                     "move_record": h(move), "pointer_entry": h(move)},
    }


def format_vectors() -> dict:
    parent = example("spaces/space/P")
    descriptors = [{"name": n, "descriptor": h(d), "kind": KIND_NAMES[k],
                    "application": read_descriptor(d)["application"]} for n, d, k in [
        ("a space", encode_descriptor(KIND_SPACE), KIND_SPACE),
        ("a restricted space under P", encode_descriptor(KIND_RESTRICTED, parent), KIND_RESTRICTED),
        ("a carve-out of P", encode_descriptor(KIND_CARVE_OUT, parent), KIND_CARVE_OUT),
        ("a space an application calls \"notes\"",
         encode_descriptor(KIND_SPACE, application="notes"), KIND_SPACE),
        ("a restricted space with an application kind of 255 bytes",
         encode_descriptor(KIND_RESTRICTED, parent, "k" * 255), KIND_RESTRICTED),
    ]]
    bad_descriptors = []
    for name, data in [
        ("version 2", kg.c_map([(1, kg.c_uint(2))])),
        ("a restricted space without a parent", kg.c_map([(1, kg.c_uint(1)), (2, kg.c_uint(1))])),
        ("kind 0 written out", kg.c_map([(1, kg.c_uint(1)), (2, kg.c_uint(0))])),
        ("a parent without a kind", kg.c_map([(1, kg.c_uint(1)), (3, cbor_bytes(parent))])),
        ("a parent of 31 bytes", kg.c_map([(1, kg.c_uint(1)), (2, kg.c_uint(1)),
                                           (3, cbor_bytes(parent[:31]))])),
        ("a text key", kg.c_map([(1, kg.c_uint(1))]) [:0] + bytes([0xA2]) + kg.c_uint(1)
         + kg.c_uint(1) + cbor_text("kind") + kg.c_uint(3)),
        ("an empty application kind", kg.c_map([(1, kg.c_uint(1)), (4, cbor_text(""))])),
        ("an application kind of 256 bytes",
         kg.c_map([(1, kg.c_uint(1)), (4, cbor_text("k" * 256))])),
        ("an application kind in bytes", kg.c_map([(1, kg.c_uint(1)), (4, cbor_bytes(b"notes"))])),
    ]:
        try:
            read_descriptor(data)
        except SpecError as error:
            bad_descriptors.append({"name": name, "descriptor": h(data), "error": error.error})
            continue
        raise AssertionError(name)
    # Kinds from 3 and keys from 5 are later documents': read, and the
    # space's other events held (ExtensionRequired), never Malformed.
    held_descriptors = []
    for name, data in [
        ("kind 3, with keys this document does not define",
         kg.c_map([(1, kg.c_uint(1)), (2, kg.c_uint(3)), (9, cbor_bytes(parent))])),
        ("a space with key 5", kg.c_map([(1, kg.c_uint(1)), (5, kg.c_uint(0))])),
        ("a restricted space with key 7 and no parent",
         kg.c_map([(1, kg.c_uint(1)), (2, kg.c_uint(1)), (7, cbor_text("x"))])),
    ]:
        d = read_descriptor(data)
        assert d["reserved"], name
        held_descriptors.append({"name": name, "descriptor": h(data), "kind": d["kind"],
                                 "outcome": "ExtensionRequired"})
    stream = example("spaces/stream")[:STREAM_BYTES]
    streams = {"good": [h(stream)], "negative": []}
    for name, data in [("15 bytes", stream[:15]), ("17 bytes", stream + b"\x00"),
                       ("all zero", bytes(STREAM_BYTES))]:
        try:
            check_stream(data)
        except SpecError as error:
            streams["negative"].append({"name": name, "stream": h(data), "error": error.error})
    to_space = example("spaces/space/N")
    moves = [{"name": "with a cached name", "record": h(encode_move(to_space, stream, "Budget 2027"))},
             {"name": "without a name", "record": h(encode_move(to_space, stream))}]
    bad_moves = []
    for name, data in [
        ("version 2", kg.c_map([(1, kg.c_uint(2))])),
        ("a stream of zeros", kg.c_map([(1, kg.c_uint(1)), (2, cbor_bytes(to_space)),
                                        (3, cbor_bytes(bytes(16)))])),
        ("a space of 31 bytes", kg.c_map([(1, kg.c_uint(1)), (2, cbor_bytes(to_space[:31])),
                                          (3, cbor_bytes(stream))])),
        ("an unknown key", kg.c_map([(1, kg.c_uint(1)), (2, cbor_bytes(to_space)),
                                     (3, cbor_bytes(stream)), (5, kg.c_uint(1))])),
        ("an empty name", kg.c_map([(1, kg.c_uint(1)), (2, cbor_bytes(to_space)),
                                    (3, cbor_bytes(stream))]) [:0] + bytes([0xA4]) + kg.c_uint(1)
         + kg.c_uint(1) + kg.c_uint(2) + cbor_bytes(to_space) + kg.c_uint(3) + cbor_bytes(stream)
         + kg.c_uint(4) + bytes([0x60])),
        ("a name of 1023 bytes", kg.c_map([(1, kg.c_uint(1)), (2, cbor_bytes(to_space)),
                                           (3, cbor_bytes(stream)), (4, cbor_text("x" * 1023))])),
    ]:
        try:
            read_move(data)
        except SpecError as error:
            bad_moves.append({"name": name, "record": h(data), "error": error.error})
            continue
        raise AssertionError(name)
    policies = []
    for name, values in [("every default", {}),
                         ("a longer agent wait, a bounded window of 1 day, gap keys after 2 days, "
                          "agents forbidden",
                          {"agent_waiting_period": 7 * DAY, "bounded_window": DAY,
                           "gap_key_timeout": 2 * DAY, "forbid_agents": True}),
                         ("online-only, with 5 minutes' freshness", {"online_freshness": 300})]:
        data = encode_policy(values)
        policies.append({"name": name, "policy": h(data), "read": read_policy(data)})
    bad_policies = []
    for name, data in [
        ("version 2", kg.c_map([(1, kg.c_uint(2))])),
        ("a default written out", kg.c_map([(1, kg.c_uint(1)), (5, kg.c_uint(7 * DAY))])),
        ("an agent wait shorter than 72 hours", kg.c_map([(1, kg.c_uint(1)), (2, kg.c_uint(HOUR))])),
        ("gap keys after 91 days", kg.c_map([(1, kg.c_uint(1)), (5, kg.c_uint(91 * DAY))])),
        ("a freshness of 29 seconds", kg.c_map([(1, kg.c_uint(1)), (4, kg.c_uint(29))])),
        ("forbid_agents of 0", kg.c_map([(1, kg.c_uint(1)), (6, kg.c_uint(0))])),
        ("an unknown key", kg.c_map([(1, kg.c_uint(1)), (7, kg.c_uint(1))])),
    ]:
        try:
            read_policy(data)
        except SpecError as error:
            bad_policies.append({"name": name, "policy": h(data), "error": error.error})
            continue
        raise AssertionError(name)
    return {"descriptors": descriptors, "descriptor_negative": bad_descriptors,
            "descriptor_held": held_descriptors,
            "policies": policies, "policy_negative": bad_policies,
            "streams": streams, "moves": moves, "move_negative": bad_moves}


def held_space_vectors() -> dict:
    """roster.md, "The space descriptor": a genesis whose descriptor is of a
    kind from 3, or carries a key from 5, at an implementation that lacks the
    document defining it: the genesis is read, every later event is held
    (ExtensionRequired); and a grant of such a space never counts."""
    import roster as R
    out = []
    for name, data in [
            ("descriptor kind 3", kg.c_map([(1, kg.c_uint(1)), (2, kg.c_uint(3))])),
            ("descriptor key 5", kg.c_map([(1, kg.c_uint(1)), (5, kg.c_uint(1))]))]:
        tag = name.replace(" ", "-")
        r = R.Roster("P", f"spaces/held/{tag}", descriptor=data)
        r.grant("P", "B", R.WRITE)
        r.sync("P", "B")
        r.anchor("B", "B anchors")
        sp = R.Space(r.log, keys=r.keyring())
        verdicts = {r.name(i): ("valid" if v[0] else v[1])
                    for i, v in sorted(sp.status.items(), key=lambda kv: r.log.order_key(kv[0]))}
        assert all(v == "ExtensionRequired" for n, v in verdicts.items()
                   if n != "P creates the space"), verdicts
        out.append({"name": name, "descriptor": h(data), "history_prefix": f"spaces/held/{tag}",
                    "events": r.hist.describe(), "verdicts": verdicts})
    X = Space("X", grants=[Grant(_eid("X/Z"), "space", "Z", WRITE),
                           Grant(_eid("X/K"), "space", "K", WRITE)])
    Z = Space("Z", 3)
    K = Space("K", reserved_key=True)  # an ordinary kind, with descriptor key 5
    edges = effective_edges({"X": X, "Z": Z, "K": K})
    assert edges[_eid("X/Z")] == edges[_eid("X/K")] == "GrantOfReserved"
    return {"genesis": out,
            "grant": {"name": "a grant of a space of descriptor kind 3 never counts, at every "
                              "implementation",
                      "edge": h(_eid("X/Z")), "verdict": edges[_eid("X/Z")]},
            "grant_key_5": {"name": "a grant of an ordinary space whose descriptor carries key "
                                    "5 never counts either",
                            "edge": h(_eid("X/K")), "verdict": edges[_eid("X/K")]}}


def roster_families() -> dict:
    """roster.json's descriptors, policies, grant_graph and
    effective_membership."""
    f = format_vectors()
    return {
        "descriptors": {"accepted": f["descriptors"], "refusals": f["descriptor_negative"],
                        "held": f["descriptor_held"]},
        "held_spaces": held_space_vectors(),
        "policies": {"accepted": f["policies"], "refusals": f["policy_negative"]},
        "grant_graph": graph_rule_vectors(),
        "effective_membership": {**membership_vectors(core=True),
                                 "propagating_paths": propagating_path_vectors()},
    }


def restricted_families() -> dict:
    """ext-restricted-spaces.json's restricted_membership,
    restricted_rotations, carve_out, move_records and move_record_refusals."""
    f = format_vectors()
    return {
        "restricted_membership": membership_vectors(),
        "restricted_rotations": cascade_vectors(),
        "carve_out": carve_out_vectors(),
        "move_records": f["moves"],
        "move_record_refusals": f["move_negative"],
    }


def stream_vectors() -> dict:
    """Stream IDs, accepted and refused, for units.json."""
    return format_vectors()["streams"]


def self_test() -> None:
    for new in NEW_LABELS:
        for other in kg.NEW_LABELS + NEW_LABELS:
            if other is not new:
                assert not other.startswith(new) and not new.startswith(other), (new, other)
    assert read_descriptor(encode_descriptor(KIND_SPACE)) == {"kind": KIND_SPACE, "parent": None,
                                                              "application": None}
    spaces = reference_spaces()
    n = effective(spaces, PERSONS, "N")
    assert n["g-tablet"].level == WRITE and not n["g-tablet"].propagates
    assert "tg-device" not in effective(spaces, PERSONS, "P")    # guests do not propagate
    assert n["a-laptop"].level == ADMIN                          # by its direct grant only
    assert n["b-laptop"].level == WRITE and "suggest" in n["b-laptop"].narrows
    assert n["b-laptop"].extends == ("comment",)
    # The guest's path does not hide the person's, which propagates.
    ps = propagating_spaces()
    team, project = (effective(ps, PROPAGATING_PERSONS, n) for n in ("Team", "Project"))
    assert team["g-one"].level == WRITE and team["g-one"].prop_level == READ
    assert project["g-one"].level == READ and project["g-one"].narrows == ("suggest",)
    assert project["g-one"].depth == 2 and project["g-two"].level == WRITE
    assert project["g-two"].narrows == ()
    f = effective(spaces, PERSONS, "F")
    assert "d-laptop" not in f and f["e-laptop"].level == READ   # narrowed by P
    assert roster_families() == roster_families(), "the vectors are not deterministic"
    assert restricted_families() == restricted_families()
