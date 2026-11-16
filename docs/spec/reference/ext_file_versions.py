"""File versions and retention (ext-file-versions.md), protocol 1, written
from the specification, independently of any implementation: the
supersessions a writer derives from a Blobs stream's stamps, the checks at
a replica, the supersession set a Blobs replica keeps beside its entries,
the pairs a compactor lists and a replica's check of them, and a peer's
listings, heads, depth and retention, with the cadence a client follows.

Units at the peer are modelled as what a peer reads of them: an ID, a
stream, `objects`, `supersedes`, the peer's first sight, and whether the
unit is a snapshot unit, replaced, released, stable at the peer or held as
fork evidence. The Blobs stream is adapters.py's, with the stamps of
adapter-records.md."""

from __future__ import annotations

from adapters import DEVICES, Blobs, blob_entry, blobs_content, check_blobs
from clocks import DAY, HOUR, elapsed_lower
from events import h, uncbor
from formats import example
from primitives import sha256
from units import MAX_SUPERSESSIONS

# ext-file-versions.md, "Settings".
MAX_FILE_VERSIONS = {"default": 100, "min": 1, "max": 1024}
FILE_VERSION_RETENTION = {"default": 7 * DAY, "min": 0, "max": 365 * DAY}
VERSION_COMPACTION_INTERVAL = {"default": DAY, "min": HOUR, "max": 7 * DAY}
T_DEFAULT = 7 * DAY  # erasure_timeout's default (overview.md)
CLASSES = ["BadSupersession"]


def sort_supersessions(items) -> list[tuple]:
    """Strictly ascending by their bytes, without repeats."""
    return sorted({tuple(s) for s in items}, key=lambda s: b"".join(s))


def hexed(s) -> list[str]:
    return [h(x) for x in s]


# ---------------------------------------------------------------------------
# 3.1 Superseding: what a writer puts in `supersedes`.

def supersessions_for(state: Blobs, parents, successor: bytes) -> list[tuple]:
    """One supersession per parent whose entry the writer holds, current, in
    this stream: the entry's stamp gives the listing, the entry its
    locator. An absent or removed parent gets none."""
    out = []
    for handle in parents:
        held = state.entries.get(handle)
        if held is None or held[0] is None:
            continue
        entry, stamp = held
        out.append((successor, stamp[2], entry[1]))
    return sort_supersessions(out)


# ---------------------------------------------------------------------------
# 3.2 The checks at a replica.

def check_supersessions(supersedes, puts: set, snapshot_unit: bool, current: set):
    """Each supersession passes or is `BadSupersession`: in a log unit its
    successor is a put's locator; in a snapshot unit its successor and
    predecessor are current entries' locators."""
    ok, bad = [], []
    for s in supersedes:
        s = tuple(s)
        if snapshot_unit:
            good = s[0] in current and s[1] in current
        else:
            good = s[0] in puts
        (ok if good else bad).append(s)
    return ok, bad


# ---------------------------------------------------------------------------
# 3.3 The supersession set, 3.4 compacting and 3.5 checking a snapshot.

class VersionedBlobs(Blobs):
    """A Blobs stream's state with the supersession set Σ: triples
    (listing, predecessor, successor)."""

    def __init__(self):
        super().__init__()
        self.sigma: set[tuple] = set()
        self.reports: list[dict] = []

    def apply(self, cs: dict) -> None:
        super().apply(cs)
        v = cs["value"]
        if 4 in v:
            return
        puts = {op[1][1] for op in v[3] if len(op) == 2}
        ok, bad = check_supersessions(cs.get("supersedes", []), puts, False, set())
        for s, listing, p in ok:
            self.sigma.add((listing, p, s))
        for s in bad:
            self.reports.append({"unit": h(cs["id"]), "supersession": hexed(s),
                                 "class": "BadSupersession"})

    def current(self) -> dict:
        return {hd: (e, s) for hd, (e, s) in self.entries.items() if e is not None}

    def current_locators(self) -> set:
        return {e[1] for e, _ in self.current().values()}

    def load(self, state: bytes, supersedes=()) -> None:
        """Load a snapshot state, then the snapshot unit's pairs: each
        `[S, P]` that passes maps to every entry whose locator is P."""
        value = uncbor(state)
        self.max_clock = value[2]
        for handle, entry, clock, author, event_id in value[3]:
            self.entries[handle] = (entry if entry != [] else None, (clock, author, event_id))
        if 4 in value:
            self.suggestions = {i: (a, c) for i, a, c in value[4]}
        ok, bad = check_supersessions(supersedes, set(), True, self.current_locators())
        for s, p in ok:
            for entry, stamp in self.current().values():
                if entry[1] == p:
                    self.sigma.add((stamp[2], p, s))
        for s in bad:
            self.reports.append({"unit": "snapshot", "supersession": hexed(s),
                                 "class": "BadSupersession"})

    def superseded(self) -> dict:
        """Each superseded current entry, by handle, with its successors: a
        locator of a current entry other than itself."""
        cur = self.current()
        out = {}
        for hd, (entry, stamp) in cur.items():
            others = {e[1] for o, (e, _) in cur.items() if o != hd}
            successors = sorted({s for listing, p, s in self.sigma
                                 if listing == stamp[2] and p == entry[1] and s in others})
            if successors:
                out[hd] = successors
        return out

    def suggestion_locators(self) -> set:
        out = set()
        for _, content in self.suggestions.values():
            for op in uncbor(content)[3]:
                if len(op) == 2:
                    out.add(op[1][1])
        return out

    def snapshot_supersedes(self) -> list[tuple]:
        """Section 3.4: `[S, P]` for each locator P every current entry of
        which is superseded and no open suggestion's put names."""
        sup, skip = self.superseded(), self.suggestion_locators()
        by_locator: dict[bytes, list] = {}
        for hd, (entry, _) in self.current().items():
            by_locator.setdefault(entry[1], []).append(hd)
        pairs = set()
        for p, handles in by_locator.items():
            if p in skip or not all(hd in sup for hd in handles):
                continue
            for hd in handles:
                for s in sup[hd]:
                    pairs.add((s, p))
        return sort_supersessions(pairs)


def check_snapshot_supersedes(derived: list, listed) -> str:
    """Section 3.5: a key 8 present and different is BadCompaction; one
    absent passes and loads nothing."""
    if listed is None:
        return "accepted, nothing loaded"
    return "accepted" if sort_supersessions(listed) == sort_supersessions(derived) \
        else "BadCompaction"


# ---------------------------------------------------------------------------
# 3.6 to 3.9: a peer's listings, heads, depth and retention.

class Peer:
    def __init__(self, timeout: int = T_DEFAULT,
                 max_file_versions: int = MAX_FILE_VERSIONS["default"],
                 file_version_retention: int = FILE_VERSION_RETENTION["default"]):
        self.units: dict[bytes, dict] = {}
        self.holds: set[bytes] = set()
        self.timeout = timeout
        self.max_file_versions = max_file_versions
        self.file_version_retention = file_version_retention

    def store(self, uid: bytes, stream: bytes, objects, supersedes=(), *, seen: int,
              snapshot: bool = False, stable: bool = False, released: bool = False,
              evidence: bool = False, cover=()) -> dict:
        """Store a unit as the peer reads it. A snapshot unit replaces its
        cover, and the peer fixes `since` for its own listings then."""
        unit = {"id": uid, "stream": stream, "objects": list(objects),
                "supersedes": [tuple(s) for s in supersedes], "seen": seen,
                "snapshot": snapshot, "stable": stable, "released": released,
                "evidence": evidence, "replaced": False, "since": {}}
        if snapshot:
            for s, p in unit["supersedes"]:
                cover_listings = [(c, p) for c in cover if p in self.units[c]["objects"]]
                sinces = [self.since(c, p) for c, _ in cover_listings]
                if cover_listings and all(x is not None for x in sinces):
                    unit["since"][p] = max(sinces)
                else:
                    unit["since"][p] = seen
            for c in cover:
                self.units[c]["replaced"] = True
        self.units[uid] = unit
        return unit

    def stored(self, u: dict) -> bool:
        return not u["replaced"] and not u["released"]

    def listings(self) -> list[tuple]:
        return [(u["id"], o) for u in self.units.values() if self.stored(u) for o in u["objects"]]

    def superseders(self, uid: bytes, o: bytes) -> list[tuple]:
        """The units that supersede the listing (uid, o), each with its
        successor."""
        u = self.units[uid]
        if not self.stored(u) or o not in u["objects"]:
            return []
        out = []
        for v in self.units.values():
            if not self.stored(v) or v["evidence"] or v["stream"] != u["stream"]:
                continue
            if v["snapshot"]:
                if v["id"] == uid:
                    out += [(v["id"], s) for s, p in v["supersedes"] if p == o]
            else:
                out += [(v["id"], s) for s, listing, p in v["supersedes"]
                        if listing == uid and p == o]
        return out

    def since(self, uid: bytes, o: bytes):
        u = self.units[uid]
        sups = self.superseders(uid, o)
        if not sups:
            return None
        if u["snapshot"] and o in u["since"]:
            return u["since"][o]
        return min(self.units[v]["seen"] for v, _ in sups)

    def heads(self) -> set:
        return {o for uid, o in self.listings() if not self.superseders(uid, o)}

    def edges(self) -> set:
        out = set()
        for uid, o in self.listings():
            for _, s in self.superseders(uid, o):
                out.add((s, o))
        return out

    def depth(self, o: bytes):
        edges = self.edges()
        frontier, seen, d = self.heads(), set(self.heads()), 0
        while frontier:
            if o in frontier:
                return d
            nxt = {p for s, p in edges if s in frontier and p not in seen}
            seen |= nxt
            frontier, d = nxt, d + 1
        return None

    def retain(self, o: bytes, now: int, *, with_holds: bool = True) -> tuple[str, int]:
        """Section 3.8, in order: the outcome and the step that decided."""
        listings = [(uid, x) for uid, x in self.listings() if x == o]
        if not listings:
            return "peers.md decides", 1
        if with_holds and o in self.holds:
            return "Keep", 2
        sups = {l: self.superseders(*l) for l in listings}
        if any(not s for s in sups.values()):
            return "Keep", 3
        for listing, superseders in sups.items():
            gated = [self.units[v] for v, _ in superseders]
            if not any(u["stable"] or now - u["seen"] >= self.timeout for u in gated):
                return "Keep", 4
        depth = self.depth(o)
        if depth is None or depth >= self.max_file_versions:
            return "Collect", 5
        since = max(self.since(*l) for l in listings)
        if now - since >= self.file_version_retention:
            return "Collect", 6
        return "Keep", 7


def compact_due(first: dict | None, now: dict, interval: int) -> str:
    """Section 3.11: whether a client compacts a Blobs stream now."""
    if first is None:
        return "Wait"
    if elapsed_lower(first, now) >= interval:
        return "Compact"
    return "Wait"


def reading(t: int) -> dict:
    return {"timeline": t, "wall": None, "run": 1}


# ---------------------------------------------------------------------------
# The vectors.

SPACE = example("versions/space")
STREAM = sha256(b"versions/stream")[:16]
KEY_REF = bytes([1]) + example("versions/rotation")


def loc(name: str) -> bytes:
    """A locator: object ID || SHA-256 of the stored object (units.md)."""
    tag = b"versions/object/" + name.encode()
    return sha256(tag) + sha256(tag + b"/digest")


def uid(name: str) -> bytes:
    return sha256(b"versions/unit/" + name.encode())


def hd(name: str) -> bytes:
    return sha256(b"versions/handle/" + name.encode())[:16]


class Stream:
    """A Blobs stream as the writers of the `writer` family see it."""

    def __init__(self):
        self.state = VersionedBlobs()
        self.plain = Blobs()
        self.units: list[dict] = []
        self.clock = 0

    def put(self, name: str, author: str, handle: str, obj: str, parents=(), note: str = "",
            size: int = 100) -> dict:
        self.clock += 1
        locator = loc(obj)
        parent_handles = [hd(p) for p in parents]
        consulted = {}
        for p in parents:
            held = self.state.entries.get(hd(p))
            if held is not None and held[0] is not None:
                consulted[p] = {"listing": h(held[1][2]), "locator": h(held[0][1])}
            else:
                consulted[p] = None
        supersedes = supersessions_for(self.state, parent_handles, locator)
        content = blobs_content(self.clock, [[hd(handle), blob_entry(locator, KEY_REF, size)]])
        return self._unit(name, author, content, [locator], supersedes, note,
                          {"handle": handle, "object": obj, "parents": list(parents),
                           "consulted": consulted})

    def remove(self, name: str, author: str, handle: str, note: str = "") -> dict:
        self.clock += 1
        content = blobs_content(self.clock, [[hd(handle)]])
        return self._unit(name, author, content, [], [], note, {"handle": handle})

    def _unit(self, name, author, content, objects, supersedes, note, shown) -> dict:
        value = check_blobs(content, objects, [])
        cs = {"id": uid(name), "author": DEVICES[author], "clock": value[2], "value": value,
              "content": content, "objects": objects, "supersedes": supersedes}
        self.state.apply(cs)
        self.plain.apply(cs)
        self.units.append(cs)
        cs["shown"] = {"name": name, "note": note, "author": author, "clock": cs["clock"],
                       "id": h(cs["id"]), **shown, "content": h(content),
                       "objects": hexed(objects),
                       "supersedes": [hexed(s) for s in supersedes]}
        return cs


def writer_stream() -> Stream:
    """One file F with versions, a file G holding F's oldest bytes, and a
    file H whose handle a writer removed."""
    s = Stream()
    s.put("u1", "A", "h1", "O1", note="file F's first version")
    s.put("ug", "B", "hg", "O1", note="file G, the same bytes as F's first version")
    s.put("u2", "A", "h2", "O2", ["h1"], note="a plain save of F")
    s.put("u3", "B", "h3", "O3", ["h1"], note="a save of F from a stale copy: a second head")
    s.put("u4", "A", "h4", "O4", ["h2", "h3"], note="a resolution with merged bytes")
    s.put("u5", "B", "h5", "O5", ["h4"], note="a save of F")
    s.put("u6", "A", "h6", "O6", ["h4"], note="a save of F concurrent with u5")
    s.put("u7", "A", "h7", "O5", ["h5", "h6"],
          note="a pick: u5's bytes put again under a new handle")
    s.put("u8", "A", "hH", "O8", note="file H")
    s.remove("u9", "B", "hH", note="H's handle removed")
    s.put("u10", "A", "h10", "O10", ["hH"],
          note="a save of H from a removed parent: no supersession")
    return s


def _writer_family(s: Stream) -> dict:
    return {"space": h(SPACE), "stream": h(STREAM), "key_reference": h(KEY_REF),
            "devices": {n: h(DEVICES[n]) for n in ("A", "B")},
            "handles": {n: h(hd(n)) for n in ("h1", "hg", "h2", "h3", "h4", "h5", "h6", "h7",
                                              "hH", "h10", "h11")},
            "objects": {n: h(loc(n)) for n in ("O1", "O2", "O3", "O4", "O5", "O6", "O8", "O10",
                                               "O11")},
            "units": [u["shown"] for u in s.units]}


def _replica_checks() -> list[dict]:
    out = []
    # A log unit whose supersession's successor is listed but put by no op.
    put, extra, old = loc("O1"), loc("Ox"), loc("O0")
    content = blobs_content(1, [[hd("h1"), blob_entry(put, KEY_REF, 1)]])
    st = VersionedBlobs()
    st.apply({"id": uid("c1"), "author": DEVICES["A"], "clock": 1,
              "value": check_blobs(content, [put, extra], []), "content": content,
              "objects": [put, extra], "supersedes": [(extra, uid("c0"), old)]})
    out.append({"name": "a log unit whose successor no put names", "content": h(content),
                "objects": hexed([put, extra]), "supersedes": [hexed((extra, uid("c0"), old))],
                "reports": st.reports, "entries_after": [h(hd("h1"))],
                "supersession_set": []})
    # A snapshot unit whose pair names a predecessor no current entry holds.
    st2 = VersionedBlobs()
    st2.apply({"id": uid("c2"), "author": DEVICES["A"], "clock": 1,
               "value": check_blobs(content, [put], []), "content": content,
               "objects": [put], "supersedes": []})
    state = st2.snapshot()
    loaded = VersionedBlobs()
    loaded.load(state, [(put, old)])
    out.append({"name": "a snapshot unit whose predecessor is not current", "state": h(state),
                "supersedes": [hexed((put, old))], "reports": loaded.reports,
                "entries_after": [h(hd("h1"))], "supersession_set": []})
    return out


def _sigma_shown(st: VersionedBlobs) -> list:
    return [hexed(t) for t in sorted(st.sigma, key=lambda t: b"".join(t))]


def _superseded_shown(st: VersionedBlobs) -> dict:
    return {h(hd_): hexed(succ) for hd_, succ in sorted(st.superseded().items())}


def _supersession_set(s: Stream) -> dict:
    units = s.units
    orders = [list(range(len(units))), list(reversed(range(len(units)))),
              [i for i in range(len(units)) if i % 2 == 0] + [i for i in range(len(units)) if i % 2],
              [len(units) - 1] + list(range(len(units) - 1))]
    results = set()
    for order in orders:
        st = VersionedBlobs()
        for i in order:
            st.apply(units[i])
        results.add((frozenset(st.sigma), st.snapshot()))
    assert len(results) == 1
    st = VersionedBlobs()
    for u in units:
        st.apply(u)
    before = {"supersession_set": _sigma_shown(st), "superseded": _superseded_shown(st)}
    # A successor's handle removed: h4 goes, and h2 and h3 are heads again.
    s2 = Stream()
    for u in units:
        s2.state.apply(u)
        s2.plain.apply(u)
    s2.clock = s.clock
    removal = s2.remove("u12", "A", "h4", note="the resolution's handle removed")
    after = {"removed": removal["shown"], "supersession_set": _sigma_shown(s2.state),
             "superseded": _superseded_shown(s2.state)}
    assert hd("h2") not in s2.state.superseded() and hd("h5") in s2.state.superseded()
    return {"orders": [[units[i]["shown"]["name"] for i in o] for o in orders],
            "after_all": before, "after_removal": after}


def _compaction(s: Stream) -> dict:
    st = s.state
    pairs = st.snapshot_supersedes()
    state = st.snapshot()
    assert state == s.plain.snapshot()
    assert (loc("O1"), loc("O1")) not in pairs and all(p != loc("O5") for _, p in pairs)
    objects = st.objects()
    # A second compaction over a cover that starts from the first: load the
    # state and the pairs, then apply a save from the pick.
    second = VersionedBlobs()
    second.load(state, pairs)
    loaded = _sigma_shown(second)
    s2 = Stream()
    s2.state, s2.plain, s2.clock = second, Blobs(), s.clock
    s2.plain.load = None
    u11 = s2.put("u11", "B", "h11", "O11", ["h7"], note="a save of F from the pick")
    pairs2 = second.snapshot_supersedes()
    return {"first": {"objects": hexed(objects), "supersedes": [hexed(p) for p in pairs],
                      "state": h(state), "state_equals_adapter_blobs": True,
                      "superseded": _superseded_shown(st),
                      "left_out": {"O1": "file G's entry holds it unsuperseded",
                                   "O5": "the pick's entry holds it unsuperseded",
                                   "O8": "its handle was removed: not current"}},
            "second": {"loaded_supersession_set": loaded, "unit": u11["shown"],
                       "supersedes": [hexed(p) for p in pairs2],
                       "superseded": _superseded_shown(second),
                       "note": "h5's supersession was not carried, since h7 held O5 "
                               "unsuperseded at the first compaction; O5 stays a head until "
                               "a writer removes h5 (section 3.1)"}}


def _compaction_checks(s: Stream) -> list[dict]:
    derived = s.state.snapshot_supersedes()
    false_pair = (loc("O10"), loc("O1"))
    cases = [("matches the replica's derivation", derived),
             ("lists a pair the cover does not support", derived + [false_pair]),
             ("omits a pair", derived[1:]),
             ("carries no key 8", None)]
    out = []
    for name, listed in cases:
        out.append({"name": name, "derived": [hexed(p) for p in derived],
                    "listed": None if listed is None else [hexed(p) for p in listed],
                    "outcome": check_snapshot_supersedes(derived, listed)})
    return out


def _listings() -> dict:
    X, Y, R = sha256(b"versions/stream/X")[:16], sha256(b"versions/stream/Y")[:16], \
        sha256(b"versions/stream/R")[:16]
    p = Peer()
    oa, ob, oc, od, oe, og, oh, oz, orr, or2 = (loc(n) for n in
                                                ("La", "Lb", "Lc", "Ld", "Le", "Lg", "Lh", "Lz",
                                                 "Lr", "Lr2"))
    p.store(uid("la"), X, [oa], seen=100)
    p.store(uid("lb"), X, [ob], [(ob, uid("la"), oa)], seen=200)
    p.store(uid("lc"), Y, [oc], [(oc, uid("la"), oa)], seen=210)
    p.store(uid("ld"), X, [od], [(od, uid("unknown"), oa)], seen=220)
    p.store(uid("le"), X, [oe], [(oe, uid("la"), oz)], seen=230)
    p.store(uid("lr1"), R, [orr], seen=240, released=True)
    p.store(uid("lr2"), R, [or2], [(or2, uid("lr1"), orr)], seen=250, released=True)
    p.store(uid("lg"), X, [og], [(og, uid("la"), oa)], seen=260, evidence=True)
    p.store(uid("lh"), X, [oh], [(oh, uid("la"), oa)], seen=300)
    names = {uid("la"): "la", uid("lb"): "lb", uid("lc"): "lc", uid("ld"): "ld", uid("le"): "le",
             uid("lr1"): "lr1", uid("lr2"): "lr2", uid("lg"): "lg", uid("lh"): "lh"}
    rows = []
    for u, o in p.listings():
        sups = p.superseders(u, o)
        rows.append({"unit": names[u], "object": h(o),
                     "superseded_by": [names[v] for v, _ in sups],
                     "since": p.since(u, o)})
    assert rows[0]["superseded_by"] == ["lb", "lh"] and rows[0]["since"] == 200
    return {"units": [{"name": names[u["id"]], "id": h(u["id"]), "stream": h(u["stream"]),
                       "objects": hexed(u["objects"]),
                       "supersedes": [hexed(s) for s in u["supersedes"]], "seen": u["seen"],
                       "released": u["released"], "evidence": u["evidence"]}
                      for u in p.units.values()],
            "notes": {"lc": "another stream", "ld": "a listing the peer does not hold",
                      "le": "a predecessor the named unit does not list",
                      "lr1, lr2": "a released stream", "lg": "fork evidence",
                      "lh": "a second superseder: since stays the earliest"},
            "listings": rows, "heads": hexed(sorted(p.heads()))}


def _after_compaction() -> dict:
    X, Y = sha256(b"versions/stream/X")[:16], sha256(b"versions/stream/Y")[:16]
    p = Peer()
    o1, o2, o3 = loc("A1"), loc("A2"), loc("A3")
    p.store(uid("a1"), X, [o1], seen=100)
    p.store(uid("a2"), X, [o2], [(o2, uid("a1"), o1)], seen=200)
    p.store(uid("a3"), X, [o3], [(o3, uid("a2"), o2)], seen=300)
    before = [{"unit": n, "since": p.since(uid(n), o)} for n, o in (("a1", o1), ("a2", o2))]
    s = p.store(uid("s"), X, [o1, o2, o3], [(o2, o1), (o3, o2)], seen=400, snapshot=True,
                cover=[uid("a1"), uid("a2"), uid("a3")])
    inherited = {"O1": p.since(uid("s"), o1), "O2": p.since(uid("s"), o2)}
    assert inherited == {"O1": 200, "O2": 300}
    # A cover listing the peer never saw superseded: the snapshot's own sight.
    q = Peer()
    oa, ob = loc("B1"), loc("B2")
    q.store(uid("b1"), Y, [oa], seen=100)
    q.store(uid("b2"), Y, [ob], [(ob, uid("lost"), oa)], seen=200)
    q.store(uid("s2"), Y, [oa, ob], [(ob, oa)], seen=500, snapshot=True,
            cover=[uid("b1"), uid("b2")])
    assert q.since(uid("s2"), oa) == 500
    return {"inherited": {"cover": before, "snapshot": {"id": h(s["id"]), "seen": 400,
                                                       "supersedes": [hexed(x) for x in
                                                                      s["supersedes"]]},
                          "since": inherited,
                          "heads": hexed(sorted(p.heads()))},
            "reset": {"snapshot_seen": 500, "since": {"B1": q.since(uid("s2"), oa)},
                      "note": "b2 named a listing the peer does not hold, so b1's listing "
                              "was never superseded there"}}


def _heads_and_depth() -> dict:
    X = sha256(b"versions/stream/X")[:16]
    out = {}
    # A chain of seven versions.
    p = Peer()
    chain = [loc(f"V{i}") for i in range(7)]
    p.store(uid("v0"), X, [chain[0]], seen=0)
    for i in range(1, 7):
        p.store(uid(f"v{i}"), X, [chain[i]], [(chain[i], uid(f"v{i - 1}"), chain[i - 1])],
                seen=1000 * i)
    out["chain"] = {"heads": hexed(sorted(p.heads())),
                    "depth": {f"V{i}": p.depth(chain[i]) for i in range(7)}}
    assert out["chain"]["depth"] == {f"V{i}": 6 - i for i in range(7)}
    # Two heads from one parent, and their resolution.
    p = Peer()
    oa, ob, oc, od = loc("Ba"), loc("Bb"), loc("Bc"), loc("Bd")
    p.store(uid("ba"), X, [oa], seen=0)
    p.store(uid("bb"), X, [ob], [(ob, uid("ba"), oa)], seen=100)
    p.store(uid("bc"), X, [oc], [(oc, uid("ba"), oa)], seen=110)
    branch = {"heads": hexed(sorted(p.heads())),
              "depth": {n: p.depth(o) for n, o in (("Ba", oa), ("Bb", ob), ("Bc", oc))}}
    p.store(uid("bd"), X, [od], sort_supersessions([(od, uid("bb"), ob), (od, uid("bc"), oc)]),
            seen=200)
    resolved = {"heads": hexed(sorted(p.heads())),
                "depth": {n: p.depth(o) for n, o in (("Ba", oa), ("Bb", ob), ("Bc", oc),
                                                     ("Bd", od))}}
    assert branch["depth"] == {"Ba": 1, "Bb": 0, "Bc": 0}
    assert resolved["depth"] == {"Ba": 2, "Bb": 1, "Bc": 1, "Bd": 0}
    out["branch"] = {"open": branch, "resolved": resolved}
    # A version restored from a copy: a cycle of objects, broken by listings.
    p = Peer()
    orr, oh1, oh2 = loc("Rr"), loc("Rh1"), loc("Rh2")
    p.store(uid("rr"), X, [orr], seen=0)
    p.store(uid("rh1"), X, [oh1], [(oh1, uid("rr"), orr)], seen=100)
    p.store(uid("rh2"), X, [oh2], [(oh2, uid("rh1"), oh1)], seen=200)
    p.store(uid("rr2"), X, [orr], [(orr, uid("rh2"), oh2)], seen=300)
    out["restored"] = {"heads": hexed(sorted(p.heads())),
                       "depth": {n: p.depth(o) for n, o in (("Rr", orr), ("Rh1", oh1),
                                                            ("Rh2", oh2))}}
    assert out["restored"]["depth"] == {"Rr": 0, "Rh2": 1, "Rh1": 2}
    # The same bytes as an old version of one file and the current version
    # of another.
    p = Peer()
    ox, oy = loc("Dx"), loc("Dy")
    p.store(uid("dx"), X, [ox], seen=0)
    p.store(uid("dy"), X, [oy], [(oy, uid("dx"), ox)], seen=100)
    p.store(uid("dz"), X, [ox], seen=150)
    out["same_bytes"] = {"heads": hexed(sorted(p.heads())),
                         "depth": {"Dx": p.depth(ox), "Dy": p.depth(oy)}}
    assert out["same_bytes"]["depth"] == {"Dx": 0, "Dy": 0}
    # A cycle without a head: two writers each naming the other's listing.
    p = Peer()
    op_, oq = loc("Cp"), loc("Cq")
    p.store(uid("cp"), X, [op_], [(op_, uid("cq"), oq)], seen=0)
    p.store(uid("cq"), X, [oq], [(oq, uid("cp"), op_)], seen=100)
    out["headless"] = {"heads": hexed(sorted(p.heads())),
                       "depth": {"Cp": p.depth(op_), "Cq": p.depth(oq)}}
    assert out["headless"]["depth"] == {"Cp": None, "Cq": None}
    return out


def _decisions() -> dict:
    X = sha256(b"versions/stream/X")[:16]
    T, retention = T_DEFAULT, 3 * DAY
    p = Peer(T, 5, retention)
    chain = [loc(f"V{i}") for i in range(7)]
    seen = [1000 * i for i in range(7)]
    p.store(uid("v0"), X, [chain[0]], seen=seen[0], stable=True)
    for i in range(1, 7):
        p.store(uid(f"v{i}"), X, [chain[i]], [(chain[i], uid(f"v{i - 1}"), chain[i - 1])],
                seen=seen[i], stable=True)
    rows = []

    def row(name, o, now, **flags):
        holds = flags.get("hold", False)
        p.holds = {o} if holds else set()
        for u in p.units.values():
            u["stable"] = flags.get("stable", True)
        outcome, step = p.retain(o, now)
        rows.append({"name": name, "object": h(o) if o in chain else None, "now": now,
                     "stable": flags.get("stable", True), "hold": holds,
                     "depth": p.depth(o) if o in chain else None,
                     "since": (max(p.since(u, x) for u, x in p.listings() if x == o)
                               if o in chain and p.depth(o) else None),
                     "outcome": outcome, "step": step})
        p.holds = set()
        return outcome, step

    assert row("no listing", loc("none"), 6000) == ("peers.md decides", 1)
    assert row("a live hold", chain[0], 10**7, hold=True) == ("Keep", 2)
    assert row("the head", chain[6], 10**7) == ("Keep", 3)
    assert row("not yet stable, within T", chain[5], seen[6] + T - 1, stable=False) == ("Keep", 4)
    assert row("not stable, T reached", chain[5], seen[6] + T, stable=False) == ("Collect", 6)
    assert row("past the count", chain[0], seen[6]) == ("Collect", 5)
    assert row("at the count", chain[1], seen[6]) == ("Collect", 5)
    assert row("within the count, within the retention", chain[2], seen[3] + retention - 1) \
        == ("Keep", 7)
    assert row("within the count, at the retention", chain[2], seen[3] + retention) \
        == ("Collect", 6)
    assert row("the version beneath the head, before its retention", chain[5],
               seen[6] + retention - 1) == ("Keep", 7)
    assert row("the version beneath the head, at its retention", chain[5],
               seen[6] + retention) == ("Collect", 6)
    return {"parameters": {"erasure_timeout": T, "max_file_versions": 5,
                           "file_version_retention": retention},
            "chain": [{"unit": f"v{i}", "object": h(chain[i]), "seen": seen[i]}
                      for i in range(7)],
            "cases": rows}


def _holds() -> dict:
    B = sha256(b"versions/stream/B")[:16]
    retention = 3 * DAY
    p = Peer(T_DEFAULT, 5, retention)
    oa, ob = loc("Ha"), loc("Hb")
    p.store(uid("hb1"), B, [oa], seen=100, stable=True)
    p.store(uid("hb2"), B, [ob], [(ob, uid("hb1"), oa)], seen=200, stable=True)
    rows = []
    for name, o, now in (("a reference to an old version, within the retention", oa,
                          200 + retention - 1),
                         ("a reference to an old version, at the retention", oa,
                          200 + retention),
                         ("a reference to the current version", ob, 10**7)):
        outcome, step = p.retain(o, now, with_holds=False)
        rows.append({"name": name, "object": h(o), "now": now, "retain": outcome, "step": step,
                     "hold_live": outcome != "Collect"})
    assert [r["hold_live"] for r in rows] == [True, False, True]
    return {"holding_space_units": [{"name": n, "objects": hexed(u["objects"]),
                                     "supersedes": [hexed(s) for s in u["supersedes"]],
                                     "seen": u["seen"]}
                                    for n, u in zip(("hb1", "hb2"), p.units.values())],
            "cases": rows}


def _cadence() -> list[dict]:
    interval = VERSION_COMPACTION_INTERVAL["default"]
    first = reading(1000)
    rows = []
    for name, f, now in (("no supersession since the last snapshot", None, reading(10**6)),
                         ("before the interval", first, reading(1000 + interval - 1)),
                         ("at the interval", first, reading(1000 + interval))):
        rows.append({"name": name, "first": f, "now": now, "interval": interval,
                     "outcome": compact_due(f, now, interval)})
    assert [r["outcome"] for r in rows] == ["Wait", "Wait", "Compact"]
    return rows


def ext_file_versions_vectors() -> dict:
    s = writer_stream()
    return {
        "specification": "ext-file-versions.md",
        "parameters": {"max_file_versions": MAX_FILE_VERSIONS,
                       "file_version_retention": FILE_VERSION_RETENTION,
                       "version_compaction_interval": VERSION_COMPACTION_INTERVAL,
                       "max_supersessions": MAX_SUPERSESSIONS, "classes": CLASSES},
        "writer": _writer_family(s),
        "replica_checks": _replica_checks(),
        "supersession_set": _supersession_set(s),
        "compaction": _compaction(writer_stream()),
        "compaction_checks": _compaction_checks(writer_stream()),
        "listings": _listings(),
        "after_compaction": _after_compaction(),
        "heads_and_depth": _heads_and_depth(),
        "decisions": _decisions(),
        "holds": _holds(),
        "cadence": _cadence(),
    }


def self_test() -> None:
    s = writer_stream()
    sup = {u["shown"]["name"]: u["supersedes"] for u in s.units}
    assert sup["u10"] == [] and len(sup["u4"]) == 2 and len(sup["u7"]) == 2
    # The pick supersedes with its own bytes: successor equals predecessor.
    assert any(x[0] == x[2] for x in sup["u7"])
    superseded = s.state.superseded()
    assert hd("hg") not in superseded and hd("h7") not in superseded
    assert hd("h1") in superseded and hd("h5") in superseded
    v = ext_file_versions_vectors()
    assert v["decisions"]["cases"][-1]["outcome"] == "Collect"
