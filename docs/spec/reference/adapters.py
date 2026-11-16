"""The built-in adapters (adapter-loro.md, adapter-records.md and
adapter-blobs.md), protocol 1, written from the specification, independently of any
implementation.

Loro: the content framing around Loro's own bytes, peer IDs bound to a
writer and an incarnation, the checks over a blob's metadata, and the
snapshot state (Loro itself is not implemented here; its blob is an opaque
stand-in and its metadata an input). Records: changesets, the logical clock
with its floor and admission, per-cell merge by stamp, suggestions,
snapshots and history-free exports, byte for byte. Blobs: entries over the
same clock, named by handle, each naming an object by locator, and
references, which carry the source space and the object's key.
"""

from __future__ import annotations

import itertools

import keygraph
from events import cbor, is_bytes, is_uint, nesting, uncbor
from formats import example
from primitives import SpecError, sha256

LORO_PEER_LABEL = b"frasil/loro-peer/v1"
NEW_LABELS = [LORO_PEER_LABEL]

VERSION = 1
TYPE_LORO = "frasil:loro"
TYPE_RECORDS = "frasil:records"
TYPE_BLOBS = "frasil:blobs"
SUGGEST = "suggest"
EXTENDS, NARROWS = 0, 1
LORO_EDIT, LORO_SUGGESTION, LORO_ACCEPT, LORO_DISMISS = range(4)
MAX_OPS = 65536
MAX_BLOB_OPS = 1024
MAX_TARGETS = 64
VALUE_DEPTH = 8  # adapter-records.md: how many levels a value's item nests
MAX_BLOB_SIZE = 1 << 40
U64_MAX = (1 << 64) - 1
LORO_VERSION = "1.17.0"


def h(value: bytes) -> str:
    return value.hex()


def expect_error(function, *args, **kwargs) -> str:
    try:
        function(*args, **kwargs)
    except SpecError as error:
        return error.error
    raise AssertionError(f"{function.__name__} accepted what it must refuse")


def ascending(items) -> bool:
    return all(a < b for a, b in zip(items, items[1:]))


def u64be(value: int) -> bytes:
    return value.to_bytes(8, "big")


def narrowed(capabilities, name: str) -> bool:
    return any(n == name and m == NARROWS for n, m in capabilities)


# ---------------------------------------------------------------------------
# Loro (adapter-loro.md).


def loro_peer(space: bytes, stream: bytes, author: bytes, incarnation: int) -> dict:
    digest = sha256(LORO_PEER_LABEL + space + stream + author + u64be(incarnation))
    raw = int.from_bytes(digest[:8], "big")
    return {"digest": digest, "first_8": raw, "peer": raw % U64_MAX}


def loro_content(role: int, *, incarnation: int | None = None, blob: bytes | None = None,
                 targets=None) -> bytes:
    value = {1: VERSION, 2: role}
    if incarnation is not None:
        value[3] = incarnation
    if blob is not None:
        value[4] = blob
    if targets is not None:
        value[5] = sorted(targets)
    return cbor(value)


def read_loro(content: bytes) -> dict:
    """adapter-loro.md, "The checks", step 1."""
    value = uncbor(content)
    if not isinstance(value, dict) or not is_uint(value.get(1)):
        raise SpecError("Malformed")
    if value[1] != VERSION:
        raise SpecError("UnknownContentVersion")
    role = value.get(2)
    if role not in (LORO_EDIT, LORO_SUGGESTION, LORO_ACCEPT, LORO_DISMISS):
        raise SpecError("Malformed")
    if role in (LORO_EDIT, LORO_SUGGESTION):
        if sorted(value) != [1, 2, 3, 4] or not is_uint(value[3]) or value[3] < 1 \
                or not is_bytes(value[4]):
            raise SpecError("Malformed")
    else:
        t = value.get(5)
        if sorted(value) != [1, 2, 5] or not isinstance(t, list) \
                or not 1 <= len(t) <= MAX_TARGETS or not all(is_bytes(x, 32) for x in t) \
                or not ascending(t):
            raise SpecError("Malformed")
    return value


def check_loro(content: bytes, ctx: dict, meta: dict | None, earlier_spans, base_counters: dict,
               held_suggestions, resubmitted=()) -> str:
    """adapter-loro.md, "The checks", steps 1 to 7 in order. `meta` is what
    Loro's decode_import_blob_meta gives: {"mode": ..., "spans": {peer:
    (start, end)}} for the peers the blob advances. `earlier_spans` are
    (peer, start, end) of Loro units of this stream earlier in canonical
    order; `base_counters` the counters the base snapshot holds per peer;
    `held_suggestions` the suggestions held as units or in the base
    snapshot's keys 3 and 4. `resubmitted` are the earlier spans of the units
    this unit re-submits, through its `resubmits` and theirs, with the same
    content: step 6 does not count them (units.md, "Re-submission")."""
    value = read_loro(content)
    role = value[2]
    # 2. The suggest check: a suggester writes only suggestions.
    if role != LORO_SUGGESTION and narrowed(ctx["capabilities"], SUGGEST):
        return "CapabilityRefused"
    if role in (LORO_ACCEPT, LORO_DISMISS):
        for t in value[5]:
            if t not in held_suggestions:
                return "TargetNotHeld"
        return "accepted"
    s = value[3]
    if s > ctx["seq"] or (role == LORO_SUGGESTION and s != ctx["seq"]):
        return "LoroIncarnation"
    if meta is None or meta.get("mode") != "updates":
        return "LoroMalformed"
    own = loro_peer(ctx["space"], ctx["stream"], ctx["author"], s)["peer"]
    spans = meta["spans"]
    if set(spans) != {own} or not spans[own][0] < spans[own][1]:
        return "LoroForeignPeer"
    start, end = spans[own]
    skip = list(resubmitted)
    for span in earlier_spans:
        if tuple(span) in [tuple(x) for x in skip]:
            skip.remove(next(x for x in skip if tuple(x) == tuple(span)))
            continue  # a unit it re-submits, the same operations
        peer, a, b = span
        if peer == own and a < end and start < b:
            return "LoroOverlap"
    if start < base_counters.get(own, 0):
        return "LoroOverlap"
    return "accepted"


def loro_state(main: bytes, suggestions=(), dismissed=()) -> bytes:
    """adapter-loro.md, "The snapshot state": the main document, the open
    suggestions (key 3) and the dismissed ones (key 4), each as [unit ID,
    author, incarnation, blob], ascending by unit ID."""
    value = {1: VERSION, 2: main}
    if suggestions:
        value[3] = [list(s) for s in sorted(suggestions)]
    if dismissed:
        value[4] = [list(s) for s in sorted(dismissed)]
    return cbor(value)


# ---------------------------------------------------------------------------
# The logical clock, shared by Records and Blobs (adapter-records.md, "The
# logical clock").


def admitted(changesets: dict, base_max_clock: int = 0) -> tuple[set, int]:
    """The least fixed point: a changeset is admitted once its clock is at
    most one more than the floor, the floor being the base snapshot's
    max_clock and the clocks of admitted changesets."""
    floor, done = base_max_clock, set()
    progress = True
    while progress:
        progress = False
        for i, cs in changesets.items():
            if i not in done and cs["clock"] <= floor + 1:
                done.add(i)
                floor = max(floor, cs["clock"])
                progress = True
    return done, floor


def next_clock(changesets: dict, base_max_clock: int = 0) -> int:
    """A writer's clock: one more than the writer's floor, over admitted
    changesets only; one waiting as ClockAhead does not count."""
    return admitted(changesets, base_max_clock)[1] + 1


def check_compaction(capabilities) -> str:
    """The suggest check on a snapshot unit: every built-in adapter refuses
    one, a seed included, from a writer narrowed by suggest."""
    return "CapabilityRefused" if narrowed(capabilities, SUGGEST) else "accepted"


def stamp(cs: dict) -> tuple:
    return (cs["clock"], cs["author"], cs["id"])


# ---------------------------------------------------------------------------
# Records (adapter-records.md).


def _text_ok(value, lo: int, hi: int) -> bool:
    return isinstance(value, str) and lo <= len(value.encode()) <= hi


def _value_ok(value) -> bool:
    """`[]` or `[v]`, with v nesting at most VALUE_DEPTH levels."""
    return isinstance(value, list) and len(value) in (0, 1) \
        and all(nesting(v) <= VALUE_DEPTH for v in value)


def _uint(value) -> bool:
    return is_uint(value) and value >= 0


def _marker_ok(value) -> bool:
    """A marker's value: `[1]` or `[]`."""
    return value == [] or (len(value) == 1 and _uint(value[0]) and value[0] == 1)


def records_content(clock: int, ops, *, suggestion: bool = False, accepts=None,
                    dismisses=None, time: int | None = None) -> bytes:
    value = {1: VERSION, 2: clock, 3: [list(o) for o in ops]}
    if time is not None:
        value[7] = time
    if suggestion:
        value[4] = 1
    if accepts:
        value[5] = sorted(accepts)
    if dismisses:
        value[6] = sorted(dismisses)
    return cbor(value, records=True)


def read_records(content: bytes) -> dict:
    """adapter-records.md, "The checks", steps 1 to 3."""
    value = uncbor(content, records=True)
    if not isinstance(value, dict) or not is_uint(value.get(1)):
        raise SpecError("Malformed")
    if value[1] != VERSION:
        raise SpecError("UnknownContentVersion")
    if any(k not in range(1, 8) for k in value) or any(k not in value for k in (1, 2, 3)):
        raise SpecError("Malformed")
    if not is_uint(value[2]) or value[2] < 1:
        raise SpecError("Malformed")
    if 7 in value and not _uint(value[7]):
        raise SpecError("Malformed")
    ops = value[3]
    if not isinstance(ops, list) or not 1 <= len(ops) <= MAX_OPS:
        raise SpecError("Malformed")
    cells = set()
    for op in ops:
        if not (isinstance(op, list) and len(op) == 4 and _text_ok(op[0], 1, 255)
                and is_bytes(op[1]) and 1 <= len(op[1]) <= 1024 and _text_ok(op[2], 0, 255)
                and _value_ok(op[3])):
            raise SpecError("Malformed")
        if op[2] == "" and not _marker_ok(op[3]):
            raise SpecError("Malformed")
        cell = (op[0], op[1], op[2])
        if cell in cells:
            raise SpecError("Malformed")
        cells.add(cell)
    read_suggestion_keys(value)
    return value


def read_suggestion_keys(value: dict) -> None:
    """Keys 4 to 6 of a Records changeset, which a Blobs unit shares: key 4
    is 1; keys 5 and 6 are 1 to 64 event IDs, strictly ascending, and never
    appear with key 4 (step 3)."""
    if 4 in value and value[4] != 1:
        raise SpecError("Malformed")
    for k in (5, 6):
        if k in value:
            t = value[k]
            if not isinstance(t, list) or not 1 <= len(t) <= MAX_TARGETS \
                    or not all(is_bytes(x, 32) for x in t) or not ascending(t):
                raise SpecError("Malformed")
    if 4 in value and (5 in value or 6 in value):
        raise SpecError("Malformed")


def suggest_check(value: dict, capabilities) -> None:
    """Records and Blobs: a writer narrowed by suggest writes only
    suggestions, without accepts or dismisses."""
    if narrowed(capabilities, SUGGEST) and (4 not in value or 5 in value or 6 in value):
        raise SpecError("CapabilityRefused")


def check_records(content: bytes, capabilities) -> dict:
    """adapter-records.md, "The checks", steps 1 to 4; step 5, admission,
    is `admitted` over the counted changesets."""
    value = read_records(content)
    suggest_check(value, capabilities)
    return value


class Records:
    """A Records stream's state: cells with their stamps, and the suggestion
    layer. `apply` is commutative and idempotent (adapter-records.md,
    "Merge and rebuild")."""

    def __init__(self, snapshot: bytes | None = None):
        self.cells: dict[tuple, tuple] = {}
        self.suggestions: dict[bytes, tuple] = {}
        self.closed: set = set()
        self.max_clock = 0
        if snapshot is not None:
            self.load(snapshot)

    def apply(self, cs: dict) -> None:
        v = cs["value"]
        if 4 in v:
            if cs["id"] not in self.closed:
                self.suggestions[cs["id"]] = (cs["author"], cs["content"])
            return
        for target in v.get(5, []) + v.get(6, []):
            self.closed.add(target)
            self.suggestions.pop(target, None)
        s = stamp(cs)
        for table, key, column, value in v[3]:
            cell = (table, key, column)
            if cell not in self.cells or s > self.cells[cell][1]:
                self.cells[cell] = (value, s, v.get(7))
        self.max_clock = max(self.max_clock, cs["clock"])

    def rows(self) -> dict:
        """Visible rows: those whose marker holds [1], with their columns."""
        out: dict = {}
        for (table, key, column), (value, *_) in sorted(self.cells.items()):
            if column == "" and value == [1]:
                out.setdefault(table, {})[key.hex()] = {
                    c: v for (t2, k2, c), (v, *_) in sorted(self.cells.items())
                    if (t2, k2) == (table, key) and c != ""}
        return out

    def snapshot(self, history_free: bool = False) -> bytes:
        tables: dict = {}
        for (table, key, column), (value, s, time) in self.cells.items():
            tables.setdefault(table, {}).setdefault(key, []).append(
                [column, value, s[0], s[1], s[2]] + ([] if time is None else [time]))
        out = []
        for table in sorted(tables, key=lambda t: t.encode()):
            rows = []
            for key in sorted(tables[table]):
                cells = sorted(tables[table][key], key=lambda c: c[0].encode())
                rows.append([key, cells])
            out.append([table, rows])
        value = {1: VERSION, 2: self.max_clock, 3: out}
        if self.suggestions and not history_free:
            value[4] = [[i, a, c] for i, (a, c) in sorted(self.suggestions.items())]
        return cbor(value, records=True)

    def load(self, data: bytes) -> None:
        """adapter-records.md, "The snapshot state", read as strictly as it is
        written, so that each state has one encoding: keys 1 to 3, and key 4
        only when it holds a suggestion; tables, rows and cells strictly
        ascending; no empty `rows`, `cells` or key 4; each cell's column and
        value as section 2.1 and a changeset give them, and its stamp; each
        suggestion's content a suggestion changeset. Else Malformed."""
        value = uncbor(data, records=True)
        if not isinstance(value, dict) or any(k not in (1, 2, 3, 4) for k in value) \
                or any(k not in value for k in (1, 2, 3)):
            raise SpecError("Malformed")
        if not _uint(value[1]) or value[1] != VERSION or not _uint(value[2]) \
                or not isinstance(value[3], list):
            raise SpecError("Malformed")
        cells: dict = {}
        tables = []
        for entry in value[3]:
            if not (isinstance(entry, list) and len(entry) == 2 and _text_ok(entry[0], 1, 255)
                    and isinstance(entry[1], list) and entry[1]):
                raise SpecError("Malformed")
            table, rows = entry
            tables.append(table.encode())
            keys = []
            for row in rows:
                if not (isinstance(row, list) and len(row) == 2 and is_bytes(row[0])
                        and 1 <= len(row[0]) <= 1024 and isinstance(row[1], list) and row[1]):
                    raise SpecError("Malformed")
                key, row_cells = row
                keys.append(key)
                columns = []
                for cell in row_cells:
                    if not (isinstance(cell, list) and len(cell) in (5, 6)
                            and _text_ok(cell[0], 0, 255) and _value_ok(cell[1])
                            and (cell[0] != "" or _marker_ok(cell[1])) and _uint(cell[2])
                            and is_bytes(cell[3], 32) and is_bytes(cell[4], 32)
                            and (len(cell) == 5 or _uint(cell[5]))):
                        raise SpecError("Malformed")
                    column, v, clock, author, i = cell[:5]
                    columns.append(column.encode())
                    time = cell[5] if len(cell) == 6 else None
                    cells[(table, key, column)] = (v, (clock, author, i), time)
                if not ascending(columns):
                    raise SpecError("Malformed")
            if not ascending(keys):
                raise SpecError("Malformed")
        if not ascending(tables):
            raise SpecError("Malformed")
        suggestions: dict = {}
        if 4 in value:
            rows = value[4]
            if not isinstance(rows, list) or not rows:
                raise SpecError("Malformed")
            for row in rows:
                if not (isinstance(row, list) and len(row) == 3 and is_bytes(row[0], 32)
                        and is_bytes(row[1], 32) and is_bytes(row[2])):
                    raise SpecError("Malformed")
                try:
                    suggestion = 4 in read_records(row[2])
                except SpecError:
                    suggestion = False
                if not suggestion:
                    raise SpecError("Malformed")
                suggestions[row[0]] = (row[1], row[2])
            if not ascending([row[0] for row in rows]):
                raise SpecError("Malformed")
        self.max_clock = value[2]
        self.cells.update(cells)
        self.suggestions.update(suggestions)


def records_rebuild(changesets: dict, accepted: set, base: bytes | None = None,
                    order=None) -> Records:
    """Rebuild: load the base, then apply the accepted, admitted changesets."""
    state = Records(base)
    done, floor = admitted(changesets, state.max_clock)
    for i in (order or sorted(changesets)):
        if i in done and i in accepted:
            state.apply(changesets[i])
    state.max_clock = max(state.max_clock, floor)  # every admitted clock, any verdict
    return state

# ---------------------------------------------------------------------------
# Blobs (adapter-blobs.md).


def blob_entry(object_id: bytes, key_ref: bytes, size: int, media_type: str | None = None,
               name: str | None = None, *, source: bytes | None = None,
               object_key: bytes | None = None) -> dict:
    """An entry; with `source` and `object_key`, a reference."""
    value = {1: object_id, 2: key_ref, 3: size}
    if media_type is not None:
        value[4] = media_type
    if name is not None:
        value[5] = name
    if source is not None:
        value[6] = source
    if object_key is not None:
        value[7] = object_key
    return value


def blobs_content(clock: int, ops, *, suggestion: bool = False, accepts=None,
                  dismisses=None) -> bytes:
    value = {1: VERSION, 2: clock, 3: [list(o) for o in ops]}
    if suggestion:
        value[4] = 1
    if accepts:
        value[5] = sorted(accepts)
    if dismisses:
        value[6] = sorted(dismisses)
    return cbor(value)


def _key_ref_ok(value) -> bool:
    """keys.md, "Reading a unit's key reference", step 1: one rotation set."""
    if not is_bytes(value):
        return False
    try:
        keygraph.decode_set(value)
    except SpecError:
        return False
    return True


def _entry_ok(e) -> bool:
    """An entry's keys, types and lengths; keys 6 and 7, a reference's,
    both or neither."""
    return (isinstance(e, dict) and all(k in range(1, 8) for k in e)
            and all(k in e for k in (1, 2, 3)) and is_bytes(e[1], 64)
            and _key_ref_ok(e[2]) and is_uint(e[3]) and e[3] <= MAX_BLOB_SIZE
            and (4 not in e or _text_ok(e[4], 1, 255))
            and (5 not in e or _text_ok(e[5], 1, 1022))
            and (6 in e) == (7 in e)
            and (6 not in e or (is_bytes(e[6], 32) and is_bytes(e[7], 32))))


def is_reference(entry: dict) -> bool:
    """adapter-blobs.md, "Content": an entry with keys 6 and 7."""
    return 6 in entry


def read_blobs(content: bytes, objects) -> dict:
    """adapter-blobs.md, "The checks", steps 1 to 3."""
    value = uncbor(content)
    if not isinstance(value, dict) or not is_uint(value.get(1)):
        raise SpecError("Malformed")
    if value[1] != VERSION:
        raise SpecError("UnknownContentVersion")
    if any(k not in range(1, 7) for k in value) or any(k not in value for k in (1, 2, 3)) \
            or not is_uint(value[2]) or value[2] < 1:
        raise SpecError("Malformed")
    read_suggestion_keys(value)
    ops = value[3]
    if not isinstance(ops, list) or not 1 <= len(ops) <= MAX_BLOB_OPS:
        raise SpecError("Malformed")
    handles = set()
    for op in ops:
        if not (isinstance(op, list) and len(op) in (1, 2) and is_bytes(op[0], 16)):
            raise SpecError("Malformed")
        if op[0] in handles:
            raise SpecError("Malformed")
        handles.add(op[0])
        if len(op) == 2 and not _entry_ok(op[1]):
            raise SpecError("Malformed")
    for op in ops:
        if len(op) == 2 and op[1][1] not in objects:
            raise SpecError("ObjectNotListed")
    return value


def check_blobs(content: bytes, objects, capabilities) -> dict:
    """adapter-blobs.md, "The checks", steps 1 to 4; step 5, admission, is
    `admitted` over the counted units."""
    value = read_blobs(content, objects)
    suggest_check(value, capabilities)
    return value


class Blobs:
    """A Blobs stream's state: each handle's entry, or none, with its stamp,
    and the suggestion layer (adapter-blobs.md, "Merge and rebuild")."""

    def __init__(self):
        self.entries: dict[bytes, tuple] = {}
        self.suggestions: dict[bytes, tuple] = {}
        self.closed: set = set()
        self.max_clock = 0

    def apply(self, cs: dict) -> None:
        v = cs["value"]
        if 4 in v:
            if cs["id"] not in self.closed:
                self.suggestions[cs["id"]] = (cs["author"], cs["content"])
            return
        for target in v.get(5, []) + v.get(6, []):
            self.closed.add(target)
            self.suggestions.pop(target, None)
        s = stamp(cs)
        for op in v[3]:
            entry = op[1] if len(op) == 2 else None
            if op[0] not in self.entries or s > self.entries[op[0]][1]:
                self.entries[op[0]] = (entry, s)
        self.max_clock = max(self.max_clock, cs["clock"])

    def snapshot(self, history_free: bool = False) -> bytes:
        rows = []
        for handle in sorted(self.entries):
            entry, s = self.entries[handle]
            if history_free and entry is None:
                continue
            rows.append([handle, entry if entry is not None else [], s[0], s[1], s[2]])
        value = {1: VERSION, 2: self.max_clock, 3: rows}
        if self.suggestions and not history_free:
            value[4] = [[i, a, c] for i, (a, c) in sorted(self.suggestions.items())]
        return cbor(value)

    def objects(self) -> list:
        """The locators a snapshot unit lists, besides its snapshot object:
        every current entry's, and every put's in an open suggestion."""
        out = {e[1] for e, _ in self.entries.values() if e is not None}
        for _, content in self.suggestions.values():
            for op in uncbor(content)[3]:
                if len(op) == 2:
                    out.add(op[1][1])
        return sorted(out)


# ---------------------------------------------------------------------------
# The vectors: adapter-loro.json, adapter-records.json, adapter-blobs.json.

SPACE = example("adapters/space")
STREAM = sha256(b"adapters/stream")[:16]
DEVICES = {n: sha256(b"adapters/device/" + n.encode()) for n in ("A", "B", "C", "D")}


def changeset(name: str, author: str, content: bytes, ids: dict) -> dict:
    value = read_records(content)
    ids[name] = sha256(b"adapters/unit/" + name.encode())
    return {"id": ids[name], "author": DEVICES[author], "clock": value[2], "value": value,
            "content": content, "name": name}


def compaction_check_vectors(adapter: str) -> list:
    """The suggest check on a snapshot unit, for one adapter."""
    rows = []
    for name, caps in (("a full writer", []), ("a suggester", [[SUGGEST, NARROWS]]),
                       ("a writer granted suggest with mode extends", [[SUGGEST, EXTENDS]])):
        rows.append({"writer": name, "capabilities": caps, "adapter": adapter,
                     "snapshot_unit": check_compaction(caps)})
    assert [r["snapshot_unit"] for r in rows] == ["accepted", "CapabilityRefused", "accepted"]
    return rows


def adapter_records_vectors() -> dict:
    ids: dict = {}
    t, r1, r2 = "entries", b"row-1", b"row-2"
    cs = {}

    def add(name, author, content):
        cs[name] = changeset(name, author, content, ids)

    add("c1", "A", records_content(1, [[t, r1, "", [1]], [t, r1, "who", ["Ann"]],
                                       [t, r1, "hours", [8]]]))
    add("c2", "B", records_content(2, [[t, r1, "hours", [7]]]))
    add("c3", "C", records_content(2, [[t, r1, "hours", [9]], [t, r2, "", [1]],
                                       [t, r2, "who", ["Cy"]]]))
    add("c4", "A", records_content(3, [[t, r1, "", []]]))
    add("c5", "B", records_content(9, [[t, r2, "who", ["Bea"]]]))           # clock ahead
    add("c6", "C", records_content(3, [[t, r2, "hours", [4]]], suggestion=True))
    add("c7", "D", records_content(3, [[t, r2, "who", ["Dee"]]]))          # D was removed
    # c8 re-inserts row 1, whose other cells come back, and adopts c6's op.
    add("c8", "A", records_content(4, [[t, r1, "", [1]], [t, r2, "hours", [4]]],
                                   accepts=[ids["c6"]]))
    notes = {
        "c1": "a row inserted",
        "c2": "a tie at clock 2 with c3, broken by writer",
        "c3": "a tie at clock 2 with c2, broken by writer; a second row inserted",
        "c4": "row 1 deleted",
        "c5": "a clock ahead of the floor",
        "c6": "a suggestion",
        "c7": "a changeset of a device whose removal is learned late",
        "c8": "row 1 inserted again, and the accept of c6, adopting its op",
    }
    by_id = {c["id"]: c for c in cs.values()}
    names = {c["id"]: n for n, c in cs.items()}
    done, floor = admitted(by_id)
    accepted = {c["id"] for n, c in cs.items() if n != "c7"}
    orders = [sorted(by_id), sorted(by_id, reverse=True),
              [cs[n]["id"] for n in ("c8", "c3", "c6", "c1", "c4", "c2", "c5", "c7")]]
    snaps = set()
    for order in orders:
        st = records_rebuild(by_id, accepted, order=order)
        snaps.add(st.snapshot())
    assert len(snaps) == 1
    final = records_rebuild(by_id, accepted)
    with_d = records_rebuild(by_id, accepted | {cs["c7"]["id"]})
    # Compaction and a rebuild from the snapshot.
    first = {i: c for i, c in by_id.items() if names[i] in ("c1", "c2", "c3")}
    base = records_rebuild(first, accepted).snapshot()
    rest = {i: c for i, c in by_id.items() if names[i] not in ("c1", "c2", "c3")}
    from_base = records_rebuild(rest, accepted, base)
    assert from_base.snapshot() == final.snapshot()
    hf = final.snapshot(history_free=True)
    # The suggestion: c8 accepted c6, so it left the layer.
    assert not final.suggestions
    open_suggestion = records_rebuild(by_id, accepted - {cs["c8"]["id"]})
    assert cs["c6"]["id"] in open_suggestion.suggestions
    refusals = []
    for name, content, caps, cls in (
            ("a cell twice", records_content(1, [[t, r1, "who", ["a"]], [t, r1, "who", ["b"]]]),
             [], "Malformed"),
            ("a marker of [2]", records_content(1, [[t, r1, "", [2]]]), [], "Malformed"),
            ("an empty table name", records_content(1, [["", r1, "who", ["a"]]]), [], "Malformed"),
            ("a value of two items", records_content(1, [[t, r1, "who", ["a", "b"]]]), [],
             "Malformed"),
            ("clock 0", cbor({1: 1, 2: 0, 3: [[t, r1, "who", ["a"]]]}), [], "Malformed"),
            ("accepts in a suggestion", cbor({1: 1, 2: 1, 3: [[t, r1, "who", ["a"]]], 4: 1,
                                              5: [ids["c6"]]}), [], "Malformed"),
            ("an unknown version, 2", cbor({1: 2, 2: 1, 3: []}), [], "UnknownContentVersion"),
            ("a suggester's plain changeset", records_content(1, [[t, r1, "who", ["a"]]]),
             [[SUGGEST, NARROWS]], "CapabilityRefused"),
            ("a suggester's accept", records_content(1, [[t, r1, "who", ["a"]]],
                                                     accepts=[ids["c6"]]),
             [[SUGGEST, NARROWS]], "CapabilityRefused")):
        got = expect_error(check_records, content, caps)
        assert got == cls, (name, got)
        refusals.append({"name": name, "content": h(content), "capabilities": caps, "class": cls})
    check_records(cs["c6"]["content"], [[SUGGEST, NARROWS]])
    # A value at the nesting limit, and one beyond it. The state the first
    # yields nests to the decoders' own limit, and loads.
    nesting_rows = []
    for depth in (VALUE_DEPTH, VALUE_DEPTH + 1):
        item = 0
        for _ in range(depth):
            item = [item]
        name = f"a value nested {depth} deep"
        content = records_content(1, [[t, r1, "", [1]], [t, r1, "tree", [item]]])
        row = {"name": name, "author": DEVICES["A"].hex(), "content": h(content)}
        try:
            one = changeset(f"nesting-{depth}", "A", content, ids)
            state = records_rebuild({one["id"]: one}, {one["id"]}).snapshot()
            assert Records(state).snapshot() == state
            row.update({"id": h(one["id"]), "result": "accepted", "state": h(state)})
        except SpecError as error:
            row["result"] = error.error
        nesting_rows.append(row)
    assert [r["result"] for r in nesting_rows] == ["accepted", "Malformed"], nesting_rows
    # Typed values (section 2.1, the records subset): accepted in one
    # changeset and its state, and items outside the subset refused.
    typed_rows = []
    typed = [("an integer", 7), ("negative one", -1), ("-2^63", -2**63), ("-2^64", -2**64),
             ("false", False), ("true", True), ("1.5", 1.5), ("negative zero", -0.0),
             ("infinity", float("inf")), ("a list of mixed types", [0.25, -3, True, "x"])]
    ops = [[t, r1, "", [1]]] + [[t, r1, name, [v]] for name, v in typed]
    content = records_content(1, ops)
    one = changeset("typed", "A", content, ids)
    state = records_rebuild({one["id"]: one}, {one["id"]}).snapshot()
    assert Records(state).snapshot() == state
    typed_rows.append({"name": "every type the records subset adds, in one changeset",
                       "author": DEVICES["A"].hex(), "content": h(content), "id": h(one["id"]),
                       "result": "accepted", "state": h(state)})
    # The value [0] is the content's last two bytes, 0x81 0x00: the item
    # replaces its last byte.
    plain = records_content(1, [[t, r1, "v", [0]]])
    assert plain.endswith(b"\x81\x00")
    for name, raw in [
            ("a NaN", b"\xfb\x7f\xf8" + bytes(6)),
            ("1.5 as a half-precision float", b"\xf9\x3e\x00"),
            ("1.5 as a single-precision float", b"\xfa\x3f\xc0\x00\x00"),
            ("null", b"\xf6"),
            ("undefined", b"\xf7"),
            ("the simple value 16", b"\xf0"),
            ("-1 in a head that is not the shortest", b"\x38\x00"),
            ("a tag", b"\xc1\x00")]:
        bad = plain[:-1] + raw
        got = expect_error(check_records, bad, [])
        typed_rows.append({"name": name, "author": DEVICES["A"].hex(), "content": h(bad),
                           "id": None, "result": got, "state": None})
    negative_clock = cbor({1: 1, 2: -1, 3: [[t, r1, "v", [0]]]}, records=True)
    typed_rows.append({"name": "a negative clock, outside a value", "author": DEVICES["A"].hex(),
                       "content": h(negative_clock), "id": None,
                       "result": expect_error(check_records, negative_clock, []), "state": None})
    assert [r["result"] for r in typed_rows] == ["accepted"] + ["Malformed"] * 9, typed_rows
    # Change times (sections 2.2 and 2.3): each cell keeps the time the
    # changeset that wrote it claims, and the row's last change is the cell
    # with the greatest stamp.
    t0 = 1_700_000_000
    timed = {
        "t1": records_content(1, [[t, r1, "", [1]], [t, r1, "who", ["Ann"]]], time=t0),
        "t2": records_content(2, [[t, r1, "who", ["Bob"]]]),
        "t3": records_content(3, [[t, r1, "note", ["x"]]], time=t0 + 100),
    }
    authors = {"t1": "A", "t2": "B", "t3": "A"}
    timed_cs = {n: changeset(n, authors[n], c, ids) for n, c in timed.items()}
    timed_state = records_rebuild({c["id"]: c for c in timed_cs.values()},
                                  {c["id"] for c in timed_cs.values()})
    timed_snapshot = timed_state.snapshot()
    assert Records(timed_snapshot).snapshot() == timed_snapshot
    cells = {c: (n, timed_state.cells[(t, r1, c)][2]) for c, n in
             (("", "t1"), ("who", "t2"), ("note", "t3"))}
    last = max((timed_state.cells[(t, r1, c)][1], c) for c in ("", "who", "note"))[1]
    time_refusals = []
    for name, content in [
            ("a time in text", cbor({1: 1, 2: 1, 3: [[t, r1, "v", [0]]], 7: "now"},
                                    records=True)),
            ("a negative time", cbor({1: 1, 2: 1, 3: [[t, r1, "v", [0]]], 7: -1},
                                     records=True))]:
        time_refusals.append({"name": name, "content": h(content),
                              "class": expect_error(check_records, content, [])})
    bad_cell = cbor({1: 1, 2: 1, 3: [[t, [[r1, [["", [1], 1, DEVICES["A"], ids["t1"],
                                                    t0, 0]]]]]]}, records=True)
    assert expect_error(Records, bad_cell) == "Malformed"
    times = {
        "changesets": [{"name": n, "author": DEVICES[authors[n]].hex(),
                        "id": h(timed_cs[n]["id"]), "content": h(c)}
                       for n, c in timed.items()],
        "table": t, "key": h(r1),
        "cells": [{"column": c, "written_by": n, "time": tm} for c, (n, tm) in cells.items()],
        "last_change": {"column": last, "by": cells[last][0], "time": cells[last][1]},
        "state": h(timed_snapshot),
        "refusals": time_refusals,
        "state_refusals": [{"name": "a cell of seven items", "state": h(bad_cell),
                            "class": "Malformed"}],
    }
    assert [r["class"] for r in time_refusals] == ["Malformed", "Malformed"], time_refusals
    return {
        "parameters": {"space": h(SPACE), "stream": h(STREAM),
                       "devices": {n: h(d) for n, d in DEVICES.items()}},
        "changesets": [{"name": n, "note": notes[n], "author": c["author"].hex(),
                        "id": h(c["id"]), "clock": c["clock"], "content": h(c["content"])}
                       for n, c in cs.items()],
        "admission": {"admitted": sorted(names[i] for i in done), "floor": floor,
                      "waiting": sorted(names[i] for i in set(by_id) - done),
                      "waiting_class": "ClockAhead"},
        "writer_clock": {
            "held": sorted(names[i] for i in by_id),
            "floor": floor,
            "next_clock": next_clock(by_id),
            "not": max(c["clock"] for c in cs.values()) + 1,
            "why": "c5's clock 9 waits as ClockAhead and does not count"},
        "merge_orders": {
            "accepted": sorted(names[i] for i in accepted),
            "orders": [[names[i] for i in o] for o in orders],
            "snapshot": h(final.snapshot()),
            "rows": {tb: {k: v for k, v in rows.items()} for tb, rows in final.rows().items()}},
        "rebuilds": {
            "with_removed_device": {
                "snapshot": h(with_d.snapshot()),
                "note": "c7 applied, before its writer's removal was learned; the snapshot "
                        "under merge_orders is the rebuild without it"},
            "from_snapshot": {
                "base_of": ["c1", "c2", "c3"], "base": h(base),
                "then_applied": sorted(names[i] for i in rest if i in done and i in accepted),
                "same_as_full": True}},
        "history_free": h(hf),
        "suggestions": {
            "suggester_suggestion": {"content": h(cs["c6"]["content"]),
                                     "capabilities": [[SUGGEST, NARROWS]],
                                     "result": "accepted"},
            "open_without_accept": {"left_out": "c8", "snapshot": h(open_suggestion.snapshot())}},
        "content_refusals": refusals,
        "compaction_checks": compaction_check_vectors(TYPE_RECORDS),
        "value_nesting": nesting_rows,
        "value_types": typed_rows,
        "change_times": times,
    }


def adapter_loro_vectors() -> dict:
    a = DEVICES["A"]
    peers = []
    for author, s in (("A", 5), ("A", 12), ("B", 5)):
        p = loro_peer(SPACE, STREAM, DEVICES[author], s)
        peers.append({"author": h(DEVICES[author]), "incarnation": s, "digest": h(p["digest"]),
                      "first_8": p["first_8"], "peer": p["peer"]})
    blob = b"stand-in for Loro's export bytes"
    sugg = sha256(b"adapters/suggestion")
    contents = {
        "edit": loro_content(LORO_EDIT, incarnation=5, blob=blob),
        "suggestion": loro_content(LORO_SUGGESTION, incarnation=9, blob=blob),
        "accept": loro_content(LORO_ACCEPT, targets=[sugg]),
        "dismiss": loro_content(LORO_DISMISS, targets=[sugg]),
    }
    own = loro_peer(SPACE, STREAM, a, 5)["peer"]
    other = loro_peer(SPACE, STREAM, DEVICES["B"], 5)["peer"]
    ctx = {"space": SPACE, "stream": STREAM, "author": a, "seq": 7, "capabilities": []}
    cases = []

    def case(name, content, meta, earlier=(), base=None, held=(), capabilities=(), seq=7,
             resubmitted=()):
        c = dict(ctx, capabilities=[list(x) for x in capabilities], seq=seq)
        verdict = check_loro(content, c, meta, earlier, base or {}, set(held), resubmitted)
        cases.append({"name": name, "author": h(a), "content": h(content), "seq": seq,
                      "capabilities": [list(x) for x in capabilities],
                      "meta": None if meta is None else {
                          "mode": meta["mode"],
                          "spans": [[p, s, e] for p, (s, e) in sorted(meta["spans"].items())]},
                      "earlier_spans": [list(x) for x in earlier], "base_counters":
                      [[p, n] for p, n in sorted((base or {}).items())],
                      "held_suggestions": [h(x) for x in held], "verdict": verdict,
                      **({"resubmitted_spans": [list(x) for x in resubmitted]}
                         if resubmitted else {})})
        return verdict

    upd = {"mode": "updates", "spans": {own: (10, 20)}}
    peer9 = loro_peer(SPACE, STREAM, a, 9)["peer"]
    assert case("an edit that continues its incarnation", contents["edit"], upd,
                earlier=[(own, 0, 10)]) == "accepted"
    assert case("a gap, which Loro holds pending", contents["edit"],
                {"mode": "updates", "spans": {own: (12, 20)}}, earlier=[(own, 0, 10)]) == "accepted"
    assert case("an overlap with an earlier unit", contents["edit"], upd,
                earlier=[(own, 0, 15)]) == "LoroOverlap"
    assert case("an overlap with the base snapshot", contents["edit"], upd,
                base={own: 15}) == "LoroOverlap"
    # units.md, "Re-submission": a late edit, re-sent after the checkpoint
    # with the same content and `resubmits` naming it; a replica that holds
    # both does not count the late one against it. One that forgot, or never
    # held it, has no earlier span: the same verdict.
    assert case("a late edit re-sent, both held", contents["edit"], upd,
                earlier=[(own, 0, 10), (own, 10, 20)],
                resubmitted=[(own, 10, 20)]) == "accepted"
    assert case("a late edit re-sent, only the re-sent one held", contents["edit"], upd,
                earlier=[(own, 0, 10)]) == "accepted"
    assert case("another writer's peer", contents["edit"],
                {"mode": "updates", "spans": {other: (0, 4)}}) == "LoroForeignPeer"
    assert case("two peers", contents["edit"],
                {"mode": "updates", "spans": {own: (10, 20), other: (0, 4)}}) == "LoroForeignPeer"
    assert case("a snapshot blob", contents["edit"], {"mode": "snapshot", "spans": {}}) \
        == "LoroMalformed"
    assert case("an unreadable blob", contents["edit"], None) == "LoroMalformed"
    assert case("an incarnation after its seq", contents["edit"], upd, seq=4) == "LoroIncarnation"
    assert case("a suggestion not at its own seq", contents["suggestion"],
                {"mode": "updates", "spans": {peer9: (0, 3)}}, seq=10) == "LoroIncarnation"
    assert case("a suggester's suggestion at its own seq", contents["suggestion"],
                {"mode": "updates", "spans": {peer9: (0, 3)}},
                seq=9, capabilities=[(SUGGEST, NARROWS)]) == "accepted"
    assert case("a suggester's edit", contents["edit"], upd,
                capabilities=[(SUGGEST, NARROWS)]) == "CapabilityRefused"
    assert case("an accept of a suggestion not held", contents["accept"], None) == "TargetNotHeld"
    assert case("an accept", contents["accept"], None, held=[sugg]) == "accepted"
    assert case("a dismiss", contents["dismiss"], None, held=[sugg]) == "accepted"
    assert case("a suggester's accept", contents["accept"], None, held=[sugg],
                capabilities=[(SUGGEST, NARROWS)]) == "CapabilityRefused"
    assert case("a suggester's dismiss", contents["dismiss"], None, held=[sugg],
                capabilities=[(SUGGEST, NARROWS)]) == "CapabilityRefused"
    assert len(cases) == 19
    refusals = []
    for name, content, cls in (
            ("an unknown version, 2", cbor({1: 2, 2: 0, 3: 1, 4: b""}), "UnknownContentVersion"),
            ("role 4", cbor({1: 1, 2: 4, 3: 1, 4: b""}), "Malformed"),
            ("an edit without a blob", cbor({1: 1, 2: 0, 3: 1}), "Malformed"),
            ("an accept with a blob", cbor({1: 1, 2: 2, 4: b"", 5: [sugg]}), "Malformed"),
            ("incarnation 0", cbor({1: 1, 2: 0, 3: 0, 4: b""}), "Malformed")):
        got = expect_error(read_loro, content)
        assert got == cls
        refusals.append({"name": name, "content": h(content), "class": cls})
    suggestion = (sugg, DEVICES["C"], 9, b"stand-in for a suggestion's blob")
    open_state = loro_state(b"stand-in for a Loro snapshot", [suggestion])
    compacted = loro_state(b"stand-in for a Loro snapshot with its history",
                           dismissed=[suggestion])
    return {"parameters": {"loro_version": LORO_VERSION, "space": h(SPACE),
                           "stream": h(STREAM)},
            "peer_ids": peers,
            "contents": {n: h(c) for n, c in contents.items()}, "checks": cases,
            "content_refusals": refusals,
            "snapshot_state": {
                "open_suggestion": {"suggestions": [h(suggestion[0])], "state": h(open_state)},
                "compacted_with_dismissed": {"dismissed": [h(suggestion[0])],
                                             "state": h(compacted)}},
            "compaction_checks": compaction_check_vectors(TYPE_LORO)}


def adapter_blobs_vectors() -> dict:
    ids: dict = {}
    key_ref = bytes([1]) + example("adapters/rotation")
    # Locators: object ID || SHA-256 of the stored object (units.md).
    o1 = sha256(b"adapters/object/1") + sha256(b"adapters/object/1/digest")
    o2 = sha256(b"adapters/object/2") + sha256(b"adapters/object/2/digest")
    hd1, hd2 = sha256(b"adapters/handle/1")[:16], sha256(b"adapters/handle/2")[:16]
    contents = {
        "b1": ("A", blobs_content(1, [[hd1, blob_entry(o1, key_ref, 4_000_000, "video/mp4",
                                                       "clip.mp4")]]), [o1]),
        "b2": ("B", blobs_content(1, [[hd2, blob_entry(o2, key_ref, 120, "image/png")]]), [o2]),
        "b3": ("A", blobs_content(2, [[hd2]]), []),
    }
    notes = {"b1": "a put", "b2": "a put", "b3": "a remove of b2's handle"}
    cs = {}
    for name, (author, content, objects) in contents.items():
        value = check_blobs(content, objects, [])
        ids[name] = sha256(b"adapters/blob-unit/" + name.encode())
        cs[name] = {"id": ids[name], "author": DEVICES[author], "clock": value[2],
                    "value": value, "content": content, "objects": objects}
    results = set()
    orders = list(itertools.permutations(cs))
    for order in orders:
        st = Blobs()
        for n in order:
            st.apply(cs[n])
        results.add(st.snapshot())
    assert len(results) == 1
    st = Blobs()
    for n in cs:
        st.apply(cs[n])
    refusals = []
    for name, content, objects, cls in (
            ("an object not listed", contents["b1"][1], [], "ObjectNotListed"),
            ("a handle twice", blobs_content(1, [[hd1], [hd1]]), [], "Malformed"),
            ("a 15-byte handle", blobs_content(1, [[hd1[:15]]]), [], "Malformed"),
            ("an entry without a size", blobs_content(1, [[hd1, {1: o1, 2: key_ref}]]), [o1],
             "Malformed")):
        got = expect_error(read_blobs, content, objects)
        assert got == cls
        refusals.append({"name": name, "content": h(content), "objects": [h(o) for o in objects],
                         "class": cls})
    return {"units": [{"name": n, "note": notes[n], "id": h(c["id"]),
                       "author": c["author"].hex(), "clock": c["clock"],
                       "objects": [h(o) for o in c["objects"]], "content": h(c["content"])}
                      for n, c in cs.items()],
            "merge_orders": {"orders": [list(o) for o in orders], "snapshot": h(st.snapshot())},
            "history_free": h(st.snapshot(history_free=True)),
            "snapshot_unit_objects": [h(o) for o in st.objects()],
            "content_refusals": refusals,
            "compaction_checks": compaction_check_vectors(TYPE_BLOBS),
            "references": reference_vectors()}


SOURCE_SPACE = example("adapters/source-space")
SOURCE_KEY = example("adapters/source-content-key")


def reference_vectors() -> dict:
    """adapter-blobs.md, "References": an object sealed in a source space, a
    unit of this space that puts a reference to it, the object read with the
    entry's key alone, and two refusals."""
    import units
    key_ref = bytes([1]) + example("adapters/source-rotation")
    plaintext = b"a cue's audio, stored once in its library"
    obj = units.seal_object(SOURCE_SPACE, SOURCE_KEY, key_ref, plaintext, chunk=16)
    locator, okey = obj["locator"], obj["object_key"]
    assert okey == units.object_key(SOURCE_KEY, obj["id"])
    handle = sha256(b"adapters/handle/reference")[:16]
    entry = blob_entry(locator, key_ref, len(plaintext), "audio/ogg", "cue.ogg",
                       source=SOURCE_SPACE, object_key=okey)
    content = blobs_content(1, [[handle, entry]])
    value = check_blobs(content, [locator], [])
    put = value[3][0][1]
    assert is_reference(put) and put[7] == okey and put[6] == SOURCE_SPACE
    # A reader of this space opens the object with the entry's key alone; the
    # chunks' associated data name the source.
    opened = units.read_object(obj["bytes"], put[6], None, put[1], chunk=16, okey=put[7])
    assert opened == plaintext
    assert expect_error(units.read_object, obj["bytes"], SPACE, None, locator, 16,
                        okey) == "Decrypt"
    refusals = []
    for name, bad in (("a reference without its object key",
                       blob_entry(locator, key_ref, 1, source=SOURCE_SPACE)),
                      ("a 31-byte object key",
                       blob_entry(locator, key_ref, 1, source=SOURCE_SPACE,
                                  object_key=okey[:31]))):
        c = blobs_content(1, [[handle, bad]])
        cls = expect_error(read_blobs, c, [locator])
        assert cls == "Malformed"
        refusals.append({"name": name, "content": h(c), "objects": [h(locator)], "class": cls})
    return {"source_space": h(SOURCE_SPACE), "source_content_key": h(SOURCE_KEY),
            "key_reference": h(key_ref), "chunk_bytes": 16, "plaintext": h(plaintext),
            "object": {"id": h(obj["id"]), "object_key": h(okey), "locator": h(locator),
                       "bytes": h(obj["bytes"])},
            "unit": {"space": h(SPACE), "handle": h(handle), "objects": [h(locator)],
                     "content": h(content)},
            "opened": h(opened),
            "refusals": refusals}


def self_test() -> None:
    p = loro_peer(SPACE, STREAM, DEVICES["A"], 1)
    assert p["peer"] < U64_MAX
    key_ref = bytes([1]) + example("adapters/rotation")
    o = bytes(64)
    hd = bytes(16)
    # Blobs: the size bound, the key reference, and keys 4 to 6.
    read_blobs(blobs_content(1, [[hd, blob_entry(o, key_ref, MAX_BLOB_SIZE)]]), [o])
    for bad in (blobs_content(1, [[hd, blob_entry(o, key_ref, MAX_BLOB_SIZE + 1)]]),
                blobs_content(1, [[hd, blob_entry(o, b"\x01" + bytes(31), 1)]]),
                blobs_content(1, [[hd, blob_entry(o, key_ref + bytes(32), 1)]]),
                cbor({1: 1, 2: 1, 3: [[hd]], 4: 1, 6: [bytes(32)]}),
                cbor({1: 1, 2: 1, 3: [[hd]], 4: 2})):
        assert expect_error(read_blobs, bad, [o]) == "Malformed"
    suggestion = blobs_content(1, [[hd, blob_entry(o, key_ref, 1)]], suggestion=True)
    check_blobs(suggestion, [o], [[SUGGEST, NARROWS]])
    assert expect_error(check_blobs, blobs_content(1, [[hd]]), [], [[SUGGEST, NARROWS]]) \
        == "CapabilityRefused"
    st = Blobs()
    st.apply({"id": bytes(32), "author": DEVICES["A"], "clock": 1, "content": suggestion,
              "value": read_blobs(suggestion, [o])})
    assert st.objects() == [o] and not st.entries
    adapter_loro_vectors()
    adapter_records_vectors()
    adapter_blobs_vectors()
