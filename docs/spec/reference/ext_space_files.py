"""Space files (ext-space-files.md), written from the specification,
independently of any implementation: the file and its records, the
manifest, the way in and its seal under a file key, files of a space with
each way in, appends and a truncated tail, and the roads in: a member, a
claimant, a reader by keys, and nobody."""

from __future__ import annotations

import unicodedata

import admission as adm
import at_rest
import events
import ext_invite_links as eil
import keygraph as kg
import roster
import storage
import units
from events import cbor, h, is_bytes, is_uint, uncbor
from formats import REVISION, example, u32be
from primitives import SpecError, hkdf, sha256, xchacha20poly1305_open, xchacha20poly1305_seal

# ---------------------------------------------------------------------------
# Labels and limits (ext-space-files.md, "The file", "Records", "The way in").

KEY_LABEL = b"frasil/space-file/key/v1"
WAY_IN_LABEL = b"frasil/space-file/way-in/v1"
NEW_LABELS = [KEY_LABEL, WAY_IN_LABEL]

MAGIC_PREFIX = b"FRASIL-SPACE-FILE/"
MAGIC = MAGIC_PREFIX + b"1\n"
MAX_RECORD = 1_052_672
MAX_EVENT = 1_048_576
MAX_HEADS = 4096
MAX_STREAMS = 4096
MAX_OBJECTS = 4096
MAX_SECRETS = 64
MAX_FRAGMENTS = 64
MAX_TEXT = 255
MAX_KIND = 64
NONE = bytes(32)

T_MANIFEST, T_WAY_IN, T_EVENT, T_SNAPSHOT, T_OBJECT_HEADER, T_OBJECT_CHUNK, T_SECTION = range(7)
RESERVED_UNTIL = 63
TYPE_NAMES = {T_MANIFEST: "Manifest", T_WAY_IN: "WayIn", T_EVENT: "Event", T_SNAPSHOT: "Snapshot",
              T_OBJECT_HEADER: "ObjectHeader", T_OBJECT_CHUNK: "ObjectChunk",
              T_SECTION: "Section"}
FULL, FROM_SNAPSHOT = 0, 1
FRAGMENT_BYTES = 97
WAY_IN_VERSION = 1


def kind_ok(value) -> bool:
    """A kind string: 1 to 64 bytes of UTF-8 without a control character
    or white space (ext-drive.md, "Values")."""
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= MAX_KIND:
        return False
    return not any(ch.isspace() or unicodedata.category(ch) == "Cc" for ch in value)


def _ascending(items, size: int) -> bool:
    return all(is_bytes(i, size) for i in items) and all(a < b for a, b in zip(items, items[1:]))


def _text(value, limit: int = MAX_TEXT) -> bool:
    return isinstance(value, str) and 1 <= len(value.encode()) <= limit


def _err(function, *args, **kwargs) -> str:
    try:
        function(*args, **kwargs)
    except SpecError as error:
        return error.error
    return "accepted"


# ---------------------------------------------------------------------------
# Records.


def encode_record(body: dict) -> bytes:
    data = cbor(body)
    if len(data) > MAX_RECORD:
        raise SpecError("TooLarge")
    return u32be(len(data)) + data


def manifest(space: bytes, kind: str, heads, exporter: bytes, *, streams=None, history: int = FULL,
             objects=(), time: int | None = None) -> dict:
    value = {0: T_MANIFEST, 1: space, 2: kind, 3: sorted(heads), 5: history, 6: sorted(objects),
             7: exporter, 9: REVISION}
    if streams is not None:
        value[4] = sorted(set(streams))
    if time is not None:
        value[8] = time
    return value


def read_manifest(body: dict) -> dict:
    """The manifest's keys and limits (ext-space-files.md, "The manifest").
    The revision is checked first."""
    if body.get(9) != REVISION:
        raise SpecError("RevisionMismatch")
    if not {1, 2, 3, 5, 6, 7, 9} <= set(body) <= {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}:
        raise SpecError("Malformed")
    if not (is_bytes(body[1], 32) and kind_ok(body[2]) and isinstance(body[3], list)
            and 1 <= len(body[3]) <= MAX_HEADS and _ascending(body[3], 32)
            and body[5] in (FULL, FROM_SNAPSHOT) and isinstance(body[6], list)
            and len(body[6]) <= MAX_OBJECTS and _ascending(body[6], 64)
            and is_bytes(body[7], 32)):
        raise SpecError("Malformed")
    if 4 in body and not (isinstance(body[4], list) and 1 <= len(body[4]) <= MAX_STREAMS
                          and _ascending(body[4], 16)):
        raise SpecError("Malformed")
    if 8 in body and not is_uint(body[8]):
        raise SpecError("Malformed")
    return {"space": body[1], "kind": body[2], "heads": body[3], "streams": body.get(4),
            "history": body[5], "objects": body[6], "exporter": body[7], "time": body.get(8)}


def read_record(body: dict) -> dict:
    """One record's body, by type: its fields, exactly."""
    if not isinstance(body, dict) or not is_uint(body.get(0)):
        raise SpecError("Malformed")
    t = body[0]
    if t == T_MANIFEST:
        return {"type": t, **read_manifest(body)}
    if t == T_WAY_IN:
        if set(body) == {0, 2}:
            if not is_bytes(body[2]):
                raise SpecError("Malformed")
            return {"type": t, "clear": body[2]}
        if set(body) == {0, 3}:
            if not is_bytes(body[3]):
                raise SpecError("Malformed")
            return {"type": t, "sealed": body[3]}
        raise SpecError("Malformed")
    if t == T_EVENT:
        if set(body) != {0, 2} or not is_bytes(body[2]) or not 1 <= len(body[2]) <= MAX_EVENT:
            raise SpecError("Malformed")
        return {"type": t, "event": body[2]}
    if t == T_SNAPSHOT:
        if set(body) != {0, 2} or not is_bytes(body[2]):
            raise SpecError("Malformed")
        return {"type": t, "snapshot": body[2]}
    if t == T_OBJECT_HEADER:
        if set(body) != {0, 2, 3} or not is_bytes(body[2], 64) or not is_bytes(body[3]):
            raise SpecError("Malformed")
        return {"type": t, "locator": body[2], "header": body[3]}
    if t == T_OBJECT_CHUNK:
        if set(body) != {0, 2, 3, 4} or not is_bytes(body[2], 64) or not is_uint(body[3]) \
                or not is_bytes(body[4]) or not 40 <= len(body[4]) <= MAX_EVENT:
            raise SpecError("Malformed")
        return {"type": t, "locator": body[2], "index": body[3], "chunk": body[4]}
    if t == T_SECTION:
        if set(body) != {0, 2, 3, 4} or not kind_ok(body[2]) or not _text(body[3]) \
                or not is_bytes(body[4]):
            raise SpecError("Malformed")
        return {"type": t, "kind": body[2], "name": body[3], "bytes": body[4]}
    if t <= RESERVED_UNTIL:
        raise SpecError("UnsupportedVersion")
    return {"type": t, "ignored": True}


# ---------------------------------------------------------------------------
# The way in.


def way_in_body(secrets, fragments=(), label: str | None = None) -> bytes:
    value = {1: WAY_IN_VERSION, 2: [[i, k] for i, k in sorted(secrets)], 3: list(fragments)}
    if label is not None:
        value[4] = label
    return cbor(value)


def read_way_in(body: bytes, space: bytes) -> dict:
    """Reading a way-in body, in order (ext-space-files.md, "The way in")."""
    value = uncbor(body)
    if not isinstance(value, dict) or not {1, 2, 3} <= set(value) <= {1, 2, 3, 4}:
        raise SpecError("Malformed")
    if not (is_uint(value[1]) and isinstance(value[2], list) and isinstance(value[3], list)
            and len(value[2]) <= MAX_SECRETS and len(value[3]) <= MAX_FRAGMENTS):
        raise SpecError("Malformed")
    for pair in value[2]:
        if not (isinstance(pair, list) and len(pair) == 2 and is_bytes(pair[0], 32)
                and is_bytes(pair[1], 32)):
            raise SpecError("Malformed")
    if not _ascending([p[0] for p in value[2]], 32):
        raise SpecError("Malformed")
    if 4 in value and not _text(value[4]):
        raise SpecError("Malformed")
    if value[1] != WAY_IN_VERSION:
        raise SpecError("UnsupportedVersion")
    fragments = []
    for raw in value[3]:
        if not is_bytes(raw, FRAGMENT_BYTES):
            raise SpecError("Malformed")
        link = adm.read_link_fragment(adm.link_fragment_raw(raw))
        if link["space"] != space:
            raise SpecError("Malformed")
        fragments.append(link)
    return {"secrets": [(p[0], p[1]) for p in value[2]], "fragments": fragments,
            "label": value.get(4)}


def sealing_key(file_key: bytes) -> bytes:
    if len(file_key) != 32:
        raise SpecError("Malformed")
    return hkdf(NONE, file_key, KEY_LABEL)


def way_in_aad(space: bytes) -> bytes:
    return WAY_IN_LABEL + space


def seal_way_in(file_key: bytes, nonce: bytes, body: bytes, space: bytes) -> bytes:
    return nonce + xchacha20poly1305_seal(sealing_key(file_key), nonce, body, way_in_aad(space))


def open_way_in(file_key: bytes, sealed: bytes, space: bytes) -> bytes:
    if len(sealed) < 40:
        raise SpecError("Malformed")
    try:
        return xchacha20poly1305_open(sealing_key(file_key), sealed[:24], sealed[24:],
                                      way_in_aad(space))
    except Exception:
        raise SpecError("Decrypt")


# ---------------------------------------------------------------------------
# Reading a file.


def read_magic(data: bytes) -> None:
    head = data[:len(MAGIC)]
    if head == MAGIC:
        return
    version = head[len(MAGIC_PREFIX):-1]
    if head.startswith(MAGIC_PREFIX) and head.endswith(b"\n") and version.isdigit():
        raise SpecError("UnsupportedVersion")
    raise SpecError("NotASpaceFile")


def _cbor_head(body: bytes, at: int, major: int) -> tuple[int, int]:
    """The argument of the CBOR head at `at`, which must be of `major`, and
    the offset after it: one byte for an argument below 24, else one more
    byte of length marker and 1, 2, 4 or 8 of argument."""
    if at >= len(body) or body[at] >> 5 != major:
        raise SpecError("Malformed")
    low = body[at] & 0x1F
    if low < 24:
        return low, at + 1
    width = {24: 1, 25: 2, 26: 4, 27: 8}.get(low)
    if width is None or at + 1 + width > len(body):
        raise SpecError("Malformed")
    return int.from_bytes(body[at + 1:at + 1 + width], "big"), at + 1 + width


def record_type(body: bytes) -> int:
    """A record's type from its body's first bytes: deterministic CBOR puts
    key 0 first (ext-space-files.md, "The manifest", sniffing), after the
    map's head, which is one byte for up to 23 keys and longer for more."""
    _, at = _cbor_head(body, 0, 5)                   # the map's head
    if at >= len(body) or body[at] != 0x00:          # key 0
        raise SpecError("Malformed")
    code, _ = _cbor_head(body, at + 1, 0)            # the type, unsigned
    return code


def _walk(data: bytes):
    """Each record's body, as (offset, body), stopping at a length past the
    end; a length over the limit is `TooLarge` wherever it stands ("The
    file")."""
    at = len(MAGIC)
    while at + 4 <= len(data):
        n = int.from_bytes(data[at:at + 4], "big")
        if n > MAX_RECORD:
            raise SpecError("TooLarge")
        if at + 4 + n > len(data):
            return
        yield at, data[at + 4:at + 4 + n]
        at += 4 + n


def read_file(data: bytes) -> dict:
    """Every record of a file, with the order rules of "Order and limits";
    the last manifest read whole wins, with the records before it, and a
    tail after it that does not read is ignored ("Appending and
    truncation")."""
    read_magic(data)
    records = []
    manifests: list[int] = []        # indexes in `records`
    bad_after: int | None = None     # a record that did not read: an unfinished append
    truncated = False
    end = len(MAGIC)                 # where the records read whole end
    for at, body in _walk(data):
        end = at + 4 + len(body)
        try:
            record = read_record(uncbor(body))
        except SpecError as error:
            if error.error == "Malformed" and manifests:
                bad_after = bad_after if bad_after is not None else len(records)
                truncated = True
                continue
            raise
        if record["type"] == T_MANIFEST:
            if bad_after is not None:
                raise SpecError("Malformed")
            manifests.append(len(records))
        records.append(record)
    if end < len(data):              # a length past the end: a tail cut short
        truncated = True
    if not manifests:
        if bad_after is None and any(r["type"] != T_MANIFEST for r in records):
            raise SpecError("Malformed")
        raise SpecError("Malformed")
    last = manifests[-1]
    if len(records) > last + 1:
        truncated = True
    records = records[:last + 1]
    first = records[manifests[0]]
    for m in manifests[1:]:
        if any(records[m][k] != first[k] for k in ("space", "kind", "streams", "history",
                                                     "exporter")):
            raise SpecError("Malformed")
    # Order: one way in and one snapshot, before any event, in the export's
    # segment; chunks after their header.
    way_in = snapshot = None
    seen_event = False
    headers: set = set()
    for index, r in enumerate(records):
        t = r["type"]
        if t == T_WAY_IN:
            if way_in is not None or seen_event or index > manifests[0]:
                raise SpecError("Malformed")
            way_in = r
        elif t == T_SNAPSHOT:
            if snapshot is not None or seen_event or index > manifests[0] \
                    or first["history"] != FROM_SNAPSHOT:
                raise SpecError("Malformed")
            snapshot = r
        elif t == T_EVENT:
            seen_event = True
        elif t == T_OBJECT_HEADER:
            headers.add(r["locator"])
        elif t == T_OBJECT_CHUNK:
            if r["locator"] not in headers:
                raise SpecError("Malformed")
    if (first["history"] == FROM_SNAPSHOT) != (snapshot is not None):
        raise SpecError("Malformed")
    sections = {}
    for r in records:
        if r["type"] == T_SECTION:
            sections[(r["kind"], r["name"])] = r["bytes"]
    return {"manifest": records[last], "first": first, "records": records,
            "way_in": way_in, "snapshot": snapshot, "truncated": truncated,
            "events": [r["event"] for r in records if r["type"] == T_EVENT],
            "objects": _objects(records), "sections": sections}


def _objects(records) -> dict:
    out: dict = {}
    for r in records:
        if r["type"] == T_OBJECT_HEADER:
            out[r["locator"]] = {"header": r["header"], "chunks": {}}
        elif r["type"] == T_OBJECT_CHUNK:
            out[r["locator"]]["chunks"][r["index"]] = r["chunk"]
    return out


def sniff(data: bytes) -> dict:
    """The magic, the way in's record and the first manifest: the records
    walked by length and type, no event decoded, nothing opened."""
    read_magic(data)
    way_in = "none"
    for _, body in _walk(data):
        t = record_type(body)
        if t == T_WAY_IN:
            record = read_record(uncbor(body))
            way_in = "sealed" if "sealed" in record else "clear"
        elif t == T_MANIFEST:
            first = read_record(uncbor(body))
            return {"space": first["space"], "kind": first["kind"], "history": first["history"],
                    "way_in": way_in}
        elif T_SECTION < t <= RESERVED_UNTIL:
            raise SpecError("UnsupportedVersion")      # a reserved type, "The file"
    raise SpecError("Malformed")


# ---------------------------------------------------------------------------
# Writing a file.


def write_file(space: bytes, kind: str, heads, exporter: bytes, *, events=(), way_in=None,
               snapshot: bytes | None = None, objects=(), sections=(), streams=None,
               time: int | None = None) -> bytes:
    """Export, in the order of "Export": the manifest, the way in, the
    snapshot, the events, the objects, the sections. `way_in` is a body in
    the clear, or ("sealed", bytes). `objects` are (locator, header,
    chunks)."""
    history = FULL if snapshot is None else FROM_SNAPSHOT
    out = MAGIC
    if way_in is not None:
        if isinstance(way_in, tuple):
            out += encode_record({0: T_WAY_IN, 3: way_in[1]})
        else:
            out += encode_record({0: T_WAY_IN, 2: way_in})
    if snapshot is not None:
        out += encode_record({0: T_SNAPSHOT, 2: snapshot})
    for signed in events:
        out += encode_record({0: T_EVENT, 2: signed})
    for locator, header, chunks in objects:
        out += encode_record({0: T_OBJECT_HEADER, 2: locator, 3: header})
        for i, chunk in enumerate(chunks):
            out += encode_record({0: T_OBJECT_CHUNK, 2: locator, 3: i, 4: chunk})
    for kind_, name, data in sections:
        out += encode_record({0: T_SECTION, 2: kind_, 3: name, 4: data})
    out += encode_record(manifest(space, kind, heads, exporter, streams=streams,
                                  history=history, objects=[o[0] for o in objects], time=time))
    return out


def append_file(data: bytes, space: bytes, heads, exporter: bytes, events=(), objects=(),
                time: int | None = None) -> bytes:
    """Append, in order: the last manifest names this space; then the events
    and objects since it, and a new manifest with the first manifest's
    streams, history and exporter."""
    read = read_file(data)
    if read["manifest"]["space"] != space:
        raise SpecError("OtherSpace")
    first = read["first"]
    # The file as the last manifest described it: a truncated tail goes.
    kept = _whole(data, read)
    out = kept
    for signed in events:
        out += encode_record({0: T_EVENT, 2: signed})
    for locator, header, chunks in objects:
        out += encode_record({0: T_OBJECT_HEADER, 2: locator, 3: header})
        for i, chunk in enumerate(chunks):
            out += encode_record({0: T_OBJECT_CHUNK, 2: locator, 3: i, 4: chunk})
    embedded = sorted(set(read["manifest"]["objects"]) | {o[0] for o in objects})
    out += encode_record(manifest(space, first["kind"], heads, first["exporter"],
                                  streams=first["streams"], history=first["history"],
                                  objects=embedded, time=time))
    return out


def _whole(data: bytes, read: dict) -> bytes:
    """The bytes up to and including the last manifest read whole."""
    end = len(MAGIC)
    for at, body in _walk(data):
        if record_type(body) == T_MANIFEST and read_record(uncbor(body)) == read["manifest"]:
            end = at + 4 + len(body)
    return data[:end]


# ---------------------------------------------------------------------------
# The roads in (ext-space-files.md, "Import", "The claim from a file",
# "Reading by keys").


def import_file(data: bytes, kinds, *, holds: bool | str = False, file_key: bytes | None = None,
                claim=None, stubs=()) -> dict:
    """Steps 1 to 7 of "Import": the road in, or the class that stops the
    import. `holds` says whether the device holds the space already, as a
    member (True) or by keys alone ("keys"); `claim(fragment)` runs "The
    claim from a file"'s checks for the device that would claim, and
    returns the offer or raises the refusal; `stubs` are the unit IDs a
    snapshot's stubs stand for, which placement counts as held."""
    read = read_file(data)                                               # 1
    m = read["manifest"]
    if m["kind"] not in kinds:                                           # 2
        raise SpecError("WrongKind")
    if holds:                                                            # 3
        return {"road": "Rereading" if holds == "keys" else "Member", "read": read}
    way_in = read["way_in"]                                              # 4
    if way_in is None:
        raise SpecError("NoWayIn")                                       # 7
    if "sealed" in way_in:
        if file_key is None:
            raise SpecError("Sealed")
        body = open_way_in(file_key, way_in["sealed"], m["space"])
    else:
        body = way_in["clear"]
    opened = read_way_in(body, m["space"])
    refused = None
    for index, fragment in enumerate(opened["fragments"]):               # 5
        if claim is None:
            break
        try:
            offer = claim(fragment)
        except SpecError as error:
            refused = error
            continue
        return {"road": "Invited", "read": read, "fragment": fragment, "index": index,
                "offer": {**offer, "label": opened["label"]}}
    if opened["secrets"]:                                                # 6
        secrets = dict(opened["secrets"])
        check_secrets(read, secrets)                                     # 3.6, step 1
        placed = place_events(read, stubs)                               # 3.6, step 3
        frame_check(read, placed)                                        # 3.6, step 4
        return {"road": "Reading", "read": read, "secrets": secrets, "placed": placed}
    if refused is not None:                                              # 7
        raise refused
    raise SpecError("NoWayIn")


def check_secrets(read: dict, secrets: dict) -> None:
    """"Reading by keys", step 1: each rotation secret's read credential is
    the one its rotation's visible key 11 names (keys.md, "Taking a key"),
    else `KeyMismatch`."""
    visible = {}
    for signed in read["events"]:
        e = events.decode_event(signed)
        if e.kind == events.KIND_SPACE:
            visible[e.id] = roster.read_visible(e)
    for rotation, k in secrets.items():
        v = visible.get(rotation)
        if v is None or not v["rotates"] or kg.read_credential(k)["public"] != v["read"]:
            raise SpecError("KeyMismatch")


def place_events(read: dict, stubs=()) -> set:
    """"Order and limits": the file's events placed as a replica places a
    peer's, each once its parents are placed or stubbed; one before a
    parent waits for it, one held already changes nothing. The IDs placed."""
    placed: set = set(stubs)
    waiting: dict = {}
    for signed in read["events"]:
        e = events.decode_event(signed)
        waiting.setdefault(e.id, set(e.parents))
    progress = True
    while progress:
        progress = False
        for i, parents in list(waiting.items()):
            if parents <= placed:
                placed.add(i)
                del waiting[i]
                progress = True
    return placed - set(stubs)


def frame_check(read: dict, placed: set) -> None:
    """"Reading by keys", step 4, as far as this module models it: every
    head of the manifest is placed, else `Pending`. Whether each is valid
    is roster.md's resolution, which the vectors run separately."""
    if any(head not in placed for head in read["manifest"]["heads"]):
        raise SpecError("Pending")


# ---------------------------------------------------------------------------
# The vectors' space: a founder A, a second administering device B, an
# invite by link, and units in a records stream.

KIND = "example.notes"
STREAM_SALT = example("space-files/stream-salt")[:16]
STREAM = units.stream_id(units.TYPE_RECORDS, STREAM_SALT)
NOW = adm.INVITE_EXPIRES - 3600


class Built:
    """The space, built with storage.py's roster so that it carries its
    skeleton (peers.md, "The skeleton"): the root a replica needs to use
    the genesis, and the twin of the grant that adds an administrator.
    Real units of units.md in one records stream, and the invite the file
    carries."""

    def __init__(self, prefix: str = "space-files"):
        self.secret = example(f"{prefix}/invite/secret")
        self.keys = adm.invite_keys(self.secret)
        r = storage.StorageRoster("A", prefix)
        self.r = r
        r.root("A0", "A")
        r.sync("A", "A0")
        self.grant, _ = r.grant_admin("A", "A0", "B", "A grants B administer")
        r.sync("A", "A0", "B")
        self.units: list[bytes] = []
        self.unit("A", b"row 1")
        r.sync("A", "B")
        self.unit("B", b"row 2")
        r.sync("A", "B")
        # The invite, from now on: the claimant starts from the file's
        # snapshot. It cites the maximal space event too (roster.md, "The
        # roster part"), so that the claimant, which holds the units before
        # its base as stubs, orders the rotations.
        self.entry = adm.admission_event(
            r, "A", [adm.invite_grant(self.keys, roster.WRITE, roster.FROM_NOW_ON,
                                      adm.INVITE_EXPIRES, roster.DEVICE, label="Invited by file")],
            "A invites by file", brk=True,
            recipients=[(self.keys["device_id"], self.keys["hybrid"], True, True)],
            extra_parents=[self.grant])
        r.sync("A", "B")
        self.base = sorted(r.log.heads())
        self.unit("A", b"row 3 after the snapshot's base")
        r.sync("A", "B")
        self.fragment = adm.link_fragment(self.secret, self.entry, r.id)
        self.raw_fragment = bytes([1]) + self.secret + self.entry + r.id

    def state_of(self, by: str):
        state = self.r.current_state(by)
        return kg.encode_set(state), kg.content_key(self.r.id, state, self.r.krot.__getitem__)

    def unit(self, by: str, content: bytes) -> bytes:
        """A unit of the records stream: every unit of an application
        stream carries the stream's opening (units.md, "Streams")."""
        key_ref, k = self.state_of(by)
        inner = units.encode_inner(units.TYPE_RECORDS, content,
                                   opening=(units.TYPE_RECORDS, STREAM_SALT))
        label = f"{by} writes {content.decode()}"
        nonce = sha256(b"space-files/unit-nonce/" + label.encode())[:units.NONCE_BYTES]

        def body(log, author, seq):
            aad = units.unit_aad(log, author, seq, STREAM, key_ref)
            return units.encode_body(STREAM, key_ref, units.seal(k, nonce, inner, aad))
        i = self.r.hist.act(by, units.KIND_UNIT, body, label)
        self.units.append(i)
        return i

    def events(self, view=None) -> list[bytes]:
        return [self.r.log.events[i].signed for i in self.r.log.canonical(view)]

    def secrets(self) -> list:
        return sorted(self.r.krot.items())

    def snapshot(self) -> bytes:
        """The space snapshot a newcomer admitted from now on starts from,
        taken at the invite's base by A: the body keys of the space events
        the invite key cannot open, and stubs for the units in the base's
        past, which the newcomer does not receive."""
        past = set(self.base) | set().union(*(self.r.log.anc[i] for i in self.base))
        full = self.r.resolve(past)
        body_keys = sorted(full.snapshot_keys([self.entry]).items())
        stubs = []
        for i in sorted(past):
            e = self.r.log.events[i]
            if e.kind == units.KIND_UNIT:
                stubs.append((i, e.author, e.seq, self.r.log.height[i], units.KIND_UNIT, STREAM))
        snap = units.space_snapshot_map(self.r.id, self.r.hist.signer("A").signer_bytes,
                                        self.base, stubs,
                                        body_keys, [], [], [], system=self.system())
        return units.sign_space_snapshot(self.r.hist.signer("A"), snap)

    def system(self) -> bytes:
        return sha256(b"space-files/system-stream")[:16]

    def events_after_base(self) -> list[bytes]:
        """A snapshot file's events: the frame whole, and the units outside
        the snapshot's base."""
        base_past = set(self.base) | set().union(*(self.r.log.anc[i] for i in self.base))
        return [self.r.log.events[i].signed for i in self.r.log.canonical()
                if self.r.log.events[i].kind != units.KIND_UNIT or i not in base_past]


def open_units(built: Built, signed_units, key_of) -> list:
    """Each unit opened under the unit key of the state its key reference
    names, derived from the rotation secrets `key_of` gives."""
    out = []
    for signed in signed_units:
        event = events.decode_event(signed)
        body = units.read_body(event.body)
        ref = body[units.B_KEY]
        ids = [ref[1 + 32 * j: 33 + 32 * j] for j in range(ref[0])]
        k = kg.content_key(built.r.id, ids, key_of)
        inner = units.open_unit(signed, k)
        out.append({"author": built.r.hist.key_name(event.author), "seq": event.seq,
                    "content": inner[units.I_CONTENT].decode()})
    return out


def _roster_summary(built: Built, sp) -> dict:
    summary = built.r.summary(sp, extra=False)
    return {"events": summary["events"], "roster": summary["roster"]}


# ---------------------------------------------------------------------------
# The vectors.


def _records_family(built: Built, file_key: bytes) -> tuple[list, list]:
    r = built.r
    rows = []
    heads = sorted(r.log.heads())
    specimens = [
        ("a manifest", manifest(r.id, KIND, heads, r.hist.device("A"), time=NOW)),
        ("a manifest of some streams", manifest(r.id, KIND, heads, r.hist.device("A"),
                                                streams=[STREAM], history=FROM_SNAPSHOT)),
        ("a way in, in the clear", {0: T_WAY_IN, 2: way_in_body(built.secrets())}),
        ("an event", {0: T_EVENT, 2: r.log.events[r.genesis].signed}),
        ("a snapshot", {0: T_SNAPSHOT, 2: built.snapshot()}),
        ("an object header", {0: T_OBJECT_HEADER, 2: bytes(64), 3: b"header"}),
        ("an object chunk", {0: T_OBJECT_CHUNK, 2: bytes(64), 3: 0, 4: bytes(40)}),
        ("a section", {0: T_SECTION, 2: "example.layout", 3: "window", 4: b"{}"}),
        ("an ignorable record of type 64", {0: 64, 1: "anything"}),
        ("an ignorable record with 24 keys, whose map head is two bytes",
         {0: 64, **{k: 0 for k in range(1, 24)}}),
    ]
    for name, body in specimens:
        record = encode_record(body)
        assert record_type(record[4:]) == body[0], name
        read = read_record(uncbor(record[4:]))
        rows.append({"name": name, "type": body[0], "type_name": TYPE_NAMES.get(body[0], "ignored"),
                     "record": h(record), "read": at_rest._plain({
                         k: v for k, v in read.items() if k != "type"})})
    refusals = []

    def refuse(name, body, cls):
        try:
            record = encode_record(body)
            got = _err(read_record, uncbor(record[4:]))
            shown = h(record)
        except SpecError as error:
            got, shown = error.error, None
        assert got == cls, (name, got, cls)
        refusals.append({"name": name, **({"record": shown} if shown else {}), "class": cls})

    over = len(cbor({0: T_SECTION, 2: "x", 3: "big", 4: bytes(70_000)})) - 70_000
    at_limit = {0: T_SECTION, 2: "x", 3: "big", 4: bytes(MAX_RECORD - over)}
    assert len(cbor(at_limit)) == MAX_RECORD
    rows.append({"name": "a section of a body at the limit", "type": T_SECTION,
                 "type_name": "Section", "body_bytes": MAX_RECORD,
                 "section": {"kind": "x", "name": "big", "zero_bytes": MAX_RECORD - over},
                 "record_sha256": h(sha256(encode_record(at_limit)))})
    refuse("a body one byte over the limit", {0: T_SECTION, 2: "x", 3: "big",
                                              4: bytes(MAX_RECORD + 1 - over)}, "TooLarge")
    refuse("a reserved type", {0: 7}, "UnsupportedVersion")
    refuse("a manifest without heads", {0: T_MANIFEST, 1: r.id, 2: KIND, 3: [], 5: 0, 6: [],
                                        7: r.hist.device("A"), 9: REVISION}, "Malformed")
    refuse("a manifest with history 2", {0: T_MANIFEST, 1: r.id, 2: KIND, 3: heads, 5: 2, 6: [],
                                         7: r.hist.device("A"), 9: REVISION}, "Malformed")
    refuse("a kind with a space", {0: T_MANIFEST, 1: r.id, 2: "not a kind", 3: heads, 5: 0,
                                   6: [], 7: r.hist.device("A"), 9: REVISION}, "Malformed")
    refuse("a way in with both forms", {0: T_WAY_IN, 2: b"", 3: b""}, "Malformed")
    refuse("an event record with an unknown key", {0: T_EVENT, 2: b"x", 5: 1}, "Malformed")
    refuse("a chunk shorter than a nonce and a tag", {0: T_OBJECT_CHUNK, 2: bytes(64), 3: 0,
                                                        4: bytes(39)}, "Malformed")
    refuse("a section name of 256 bytes", {0: T_SECTION, 2: "x", 3: "n" * 256, 4: b""},
           "Malformed")
    return rows, refusals


def _way_in_family(built: Built, file_key: bytes) -> dict:
    r = built.r
    body = way_in_body(built.secrets(), [built.raw_fragment], "the show's keys")
    nonce = example("space-files/way-in/nonce")[:24]
    sealed = seal_way_in(file_key, nonce, body, r.id)
    assert open_way_in(file_key, sealed, r.id) == body
    opened = read_way_in(body, r.id)
    other = bytes([1]) + built.secret + built.entry + example("space-files/other-space")
    refusals = []
    for name, fn, cls in [
        ("the wrong file key", lambda: open_way_in(example("space-files/wrong-key"), sealed, r.id),
         "Decrypt"),
        ("another space's associated data", lambda: open_way_in(
            file_key, sealed, example("space-files/other-space")), "Decrypt"),
        ("a sealed form of 39 bytes", lambda: open_way_in(file_key, sealed[:39], r.id),
         "Malformed"),
        ("a fragment of another space", lambda: read_way_in(
            way_in_body(built.secrets(), [other]), r.id), "Malformed"),
        ("version 2", lambda: read_way_in(cbor({1: 2, 2: [], 3: []}), r.id),
         "UnsupportedVersion"),
        ("65 secrets", lambda: read_way_in(cbor({1: 1, 2: [[bytes([i]) + bytes(31), bytes(32)]
                                                           for i in range(65)], 3: []}), r.id),
         "Malformed"),
        ("secrets out of order", lambda: read_way_in(cbor({1: 1, 2: [[bytes([2]) + bytes(31),
                                                                      bytes(32)],
                                                                     [bytes([1]) + bytes(31),
                                                                      bytes(32)]], 3: []}), r.id),
         "Malformed"),
    ]:
        got = _err(fn)
        assert got == cls, (name, got, cls)
        refusals.append({"name": name, "class": cls})
    return {
        "file_key": h(file_key), "sealing_key": h(sealing_key(file_key)),
        "space": h(r.id), "aad": h(way_in_aad(r.id)), "nonce": h(nonce),
        "body": h(body),
        "read": {"secrets": {r.name(i): h(k) for i, k in opened["secrets"]},
                 "fragments": [built.fragment], "label": opened["label"]},
        "sealed": h(sealed),
        "refusals": refusals,
    }


def _files_family(built: Built, file_key: bytes) -> dict:
    r = built.r
    exporter = r.hist.device("A")
    heads = sorted(r.log.heads())
    full_events = built.events()
    keys_in = way_in_body(built.secrets(), label="read-only copy")
    sealed_in = ("sealed", seal_way_in(file_key, example("space-files/files/nonce")[:24],
                                       keys_in, r.id))
    by_keys = write_file(r.id, KIND, heads, exporter, events=full_events, way_in=keys_in,
                         time=NOW)
    sealed = write_file(r.id, KIND, heads, exporter, events=full_events, way_in=sealed_in,
                        time=NOW)
    nobody = write_file(r.id, KIND, heads, exporter, events=full_events, time=NOW)
    sniffed = {name: at_rest._plain(sniff(f)) for name, f in
               (("by_keys", by_keys), ("sealed", sealed), ("nobody", nobody))}

    # The reference state: every rotation's secret, every event.
    full = r.resolve()
    reference = {"roster": _roster_summary(built, full),
                 "units": open_units(built, [r.log.events[i].signed for i in built.units],
                                     r.krot.__getitem__)}

    # A member that holds the space: nothing new; a reader by keys that
    # holds it already: the same, still with no grant.
    member = import_file(by_keys, [KIND], holds=True)
    assert member["road"] == "Member"
    assert import_file(by_keys, [KIND], holds="keys")["road"] == "Rereading"
    held = set(r.log.events)
    new = [e for e in member["read"]["events"] if events.decode_event(e).id not in held]

    # A reader by keys: derives the content keys, resolves and opens.
    reading = import_file(by_keys, [KIND], holds=False)
    assert reading["road"] == "Reading"
    secrets = reading["secrets"]
    reader_space = roster.Space(r.log, keys=roster.Keyring(dict(secrets)))
    reader = {"roster": _roster_summary(built, reader_space),
              "units": open_units(built, [r.log.events[i].signed for i in built.units],
                                  secrets.__getitem__),
              "content_keys": {r.name(i): h(k) for i, k in sorted(secrets.items())},
              "current_state_key": h(kg.content_key(r.id, full.rotations(), secrets.__getitem__)),
              "level": None}
    assert reader["roster"] == reference["roster"] and reader["units"] == reference["units"]

    # The sealed way in, with and without the key; and nobody.
    sealed_without = _err(import_file, sealed, [KIND], holds=False)
    sealed_with = import_file(sealed, [KIND], holds=False, file_key=file_key)["road"]
    nobody_road = _err(import_file, nobody, [KIND], holds=False)
    # A rotation secret that is not its rotation's: the first secret's
    # bytes altered.
    altered = [(i, k if n else bytes(32)) for n, (i, k) in enumerate(built.secrets())]
    wrong_secret = write_file(r.id, KIND, heads, exporter, events=full_events,
                              way_in=way_in_body(altered), time=NOW)
    wrong_secret_road = _err(import_file, wrong_secret, [KIND], holds=False)
    # The events out of parent order: the last first. Read all the same.
    shuffled = write_file(r.id, KIND, heads, exporter, events=full_events[-1:] + full_events[:-1],
                          way_in=keys_in, time=NOW)
    shuffled_road = import_file(shuffled, [KIND], holds=False)
    assert shuffled_road["placed"] == set(r.log.events)
    # A head the file does not hold.
    missing_head = write_file(r.id, KIND, sorted(heads + [example("space-files/missing-head")]),
                              exporter, events=full_events, way_in=keys_in, time=NOW)
    missing_head_road = _err(import_file, missing_head, [KIND], holds=False)
    return {
        "note": "the full-history file: its way in holds every rotation's content key",
        "heads": [r.name(i) for i in heads],
        "events": [r.name(events.decode_event(e).id) for e in full_events],
        "by_keys": h(by_keys), "sealed": h(sealed), "nobody": h(nobody),
        "wrong_secret": h(wrong_secret), "shuffled": h(shuffled), "missing_head": h(missing_head),
        "sniffed": sniffed,
        "reference": reference,
        "roads": {
            "a member that holds the space": {"road": "Member", "new_events": len(new)},
            "a reader by keys that holds the space": "Rereading",
            "a reader by keys": {"road": "Reading", **reader},
            "a sealed way in without the key": sealed_without,
            "a sealed way in with the key": sealed_with,
            "no way in": nobody_road,
            "another kind": _err(import_file, by_keys, ["example.other"], holds=False),
            "a rotation secret that misses its rotation's read credential": wrong_secret_road,
            "the events out of parent order": {"road": shuffled_road["road"],
                                               "placed": len(shuffled_road["placed"])},
            "a head the file does not hold": missing_head_road,
        },
    }


def _snapshot_family(built: Built) -> dict:
    r = built.r
    exporter = r.hist.device("A")
    heads = sorted(r.log.heads())
    snapshot = built.snapshot()
    after = built.events_after_base()
    invite_in = way_in_body([], [built.raw_fragment], "for the venue machine")
    data = write_file(r.id, KIND, heads, exporter, events=after, way_in=invite_in,
                      snapshot=snapshot, time=NOW)
    read = read_file(data)
    assert read["snapshot"]["snapshot"] == snapshot and read["events"] == after
    snap = units.read_space_snapshot(snapshot, r.id, [r.hist.held_keys("A")])

    # The claimant: a device C, with the invite's wrap from the entry,
    # which the file carries among the frame's events. "The claim from a
    # file", steps 1 to 4, as the import calls them for each fragment.
    keys = built.keys
    body_keys = dict((i, k) for i, k in snap["value"][6])
    stubs = {s[0] for s in snap["value"][5]}

    def claim(fragment: dict) -> dict:
        if fragment["entry"] not in r.log.events:
            raise SpecError("NoWrap")                                   # 2: no such entry
        entry_event = r.log.events[fragment["entry"]]
        found = adm.own_bundle(entry_event, keys["device_id"], keys["hybrid_seed"])
        space_for_k = adm.AdmissionSpace(r.log, None, keys=roster.Keyring(
            {fragment["entry"]: found["bundle"]["content"]}, body_keys))
        if adm.check_claimable(space_for_k, fragment["entry"], keys["device_id"]) != "Open":
            raise SpecError("InviteUsed")
        if eil.check_claim_expiry(adm.INVITE_EXPIRES, NOW) != "ok":
            raise SpecError("Expired")
        return {"inviter": r.hist.key_name(entry_event.author), "level": "write",
                "expires_at": adm.INVITE_EXPIRES}

    invited = import_file(data, [KIND], holds=False, claim=claim, stubs=stubs)
    assert invited["road"] == "Invited" and invited["index"] == 0
    own = adm.own_bundle(r.log.events[built.entry], keys["device_id"], keys["hybrid_seed"])
    claimant_space = adm.AdmissionSpace(r.log, None, keys=roster.Keyring(
        {built.entry: own["bundle"]["content"]}, body_keys))
    claimable = adm.check_claimable(claimant_space, built.entry, keys["device_id"])
    expiry = eil.check_claim_expiry(adm.INVITE_EXPIRES, NOW)
    # A fragment naming an entry the file lacks, first: skipped for the
    # second. Alone, with the keys beside it: the keys road.
    bogus = bytes([1]) + built.secret + example("space-files/bogus-entry") + r.id
    skipped_first = write_file(r.id, KIND, heads, exporter, events=after,
                               way_in=way_in_body([], [bogus, built.raw_fragment]),
                               snapshot=snapshot, time=NOW)
    skipped = import_file(skipped_first, [KIND], holds=False, claim=claim, stubs=stubs)
    assert skipped["road"] == "Invited" and skipped["index"] == 1
    fallthrough_file = write_file(r.id, KIND, heads, exporter, events=after,
                                  way_in=way_in_body(built.secrets(), [bogus]),
                                  snapshot=snapshot, time=NOW)
    fallthrough = import_file(fallthrough_file, [KIND], holds=False, claim=claim, stubs=stubs)
    assert fallthrough["road"] == "Reading"
    refused_alone = _err(import_file, write_file(r.id, KIND, heads, exporter, events=after,
                                                 way_in=way_in_body([], [bogus]),
                                                 snapshot=snapshot, time=NOW),
                         [KIND], holds=False, claim=claim, stubs=stubs)
    assert refused_alone == "NoWrap"
    # C signs the successor as K, in the vectors' history.
    r.hist.device("C")
    eil._participant(r, "invite", keys, r.hist.view["A"])
    successor = eil._claim(r, (roster.DEVICE, r.hist.device("C")), "C claims from the file",
                           adm.roster_device_keys(r, "C"))
    after_claim = r.resolve()
    summary = _roster_summary(built, after_claim)
    refusals = []
    for name, fn, cls in [
        ("an event before the snapshot", lambda: read_file(
            MAGIC + encode_record({0: T_EVENT, 2: after[0]})
            + encode_record({0: T_SNAPSHOT, 2: snapshot})
            + encode_record(manifest(r.id, KIND, heads, exporter, history=FROM_SNAPSHOT))),
         "Malformed"),
        ("two snapshots", lambda: read_file(
            MAGIC + encode_record({0: T_SNAPSHOT, 2: snapshot}) * 2
            + encode_record(manifest(r.id, KIND, heads, exporter, history=FROM_SNAPSHOT))),
         "Malformed"),
        ("a snapshot in a full-history file", lambda: read_file(
            MAGIC + encode_record({0: T_SNAPSHOT, 2: snapshot})
            + encode_record(manifest(r.id, KIND, heads, exporter))), "Malformed"),
        ("history 1 without a snapshot", lambda: read_file(
            MAGIC + encode_record(manifest(r.id, KIND, heads, exporter, history=FROM_SNAPSHOT))),
         "Malformed"),
    ]:
        got = _err(fn)
        assert got == cls, (name, got, cls)
        refusals.append({"name": name, "class": cls})
    return {
        "file": h(data), "snapshot": h(snapshot),
        "base": [r.name(i) for i in built.base],
        "events": [r.name(events.decode_event(e).id) for e in after],
        "note": "the frame whole, and of the stream only the unit after the base",
        "snapshot_body_keys": {r.name(i): h(k) for i, k in sorted(body_keys.items())},
        "claimant": {
            "road": "Invited", "fragment": built.fragment, "invite_entry": r.name(built.entry),
            "wrap_index": own["index"], "content_key": h(own["bundle"]["content"]),
            "claimable": claimable, "expiry": expiry,
            "offer": at_rest._plain(invited["offer"]),
            "on_consent": "Claimed",
            "successor": {"name": "C claims from the file",
                          "signed": h(r.log.events[successor].signed), "level": "write"},
            "roster_after": summary["roster"],
        },
        "skipped_first": {"file": h(skipped_first), "road": "Invited", "fragment_index": 1},
        "fallthrough": {"file": h(fallthrough_file), "road": "Reading"},
        "refused_alone": refused_alone,
        "refusals": refusals,
    }


def _appends_family(built: Built) -> dict:
    r = built.r
    exporter = r.hist.device("A")
    all_events = built.events()
    first_part = all_events[:3]
    heads_1 = sorted(r.log.heads({events.decode_event(e).id for e in first_part}))
    base = write_file(r.id, KIND, heads_1, exporter, events=first_part,
                      way_in=way_in_body(built.secrets()), time=NOW)
    heads_2 = sorted(r.log.heads())
    appended = append_file(base, r.id, heads_2, exporter, events=all_events[3:], time=NOW + 60)
    read = read_file(appended)
    assert [r.name(i) for i in read["manifest"]["heads"]] == [r.name(i) for i in heads_2]
    assert len(read["events"]) == len(all_events)
    # A tail cut short: the first manifest describes the file.
    truncated = appended[:len(base) + 10]
    read_t = read_file(truncated)
    assert read_t["truncated"] and read_t["manifest"]["heads"] == heads_1
    assert len(read_t["events"]) == len(first_part)
    # A record that does not read before the last manifest refuses the file.
    broken = base + u32be(3) + b"\xff\xff\xff" + appended[len(base):]
    refused = _err(read_file, broken)
    wrong = _err(append_file, base, example("space-files/other-space"), heads_2, exporter)
    return {
        "exported": h(base), "appended": h(appended),
        "first_manifest_heads": [r.name(i) for i in heads_1],
        "last_manifest_heads": [r.name(i) for i in heads_2],
        "events_read": len(read["events"]),
        "truncated": {"file": h(truncated), "manifest_heads": [r.name(i) for i in heads_1],
                      "events_read": len(read_t["events"]), "tail_ignored": True},
        "a record that does not read before the last manifest": refused,
        "an append to another space": wrong,
    }


def _with_manifest(data: bytes, change) -> bytes:
    """A file whose manifests `change` alters, each record otherwise as it was."""
    out = data[:len(MAGIC)]
    for _, body in _walk(data):
        value = uncbor(body)
        if value[0] == T_MANIFEST:
            change(value)
        out += encode_record(value)
    return out


def _refusals_family(built: Built) -> list:
    r = built.r
    exporter = r.hist.device("A")
    heads = sorted(r.log.heads())
    ok = write_file(r.id, KIND, heads, exporter, events=built.events(), time=NOW)
    cases = [
        ("not a space file", b"PK\x03\x04" + ok[4:], "NotASpaceFile"),
        ("a magic of version 2", MAGIC_PREFIX + b"2\n" + ok[len(MAGIC):], "UnsupportedVersion"),
        ("a reserved record type", MAGIC + encode_record({0: 9}) + ok[len(MAGIC):],
         "UnsupportedVersion"),
        ("no manifest", MAGIC + encode_record({0: T_EVENT, 2: b"x"}), "Malformed"),
        ("only a magic", MAGIC, "Malformed"),
        ("a length over the limit", MAGIC + u32be(MAX_RECORD + 1) + bytes(16), "TooLarge"),
        ("a length over the limit after the last manifest",
         ok + u32be(MAX_RECORD + 1) + bytes(16), "TooLarge"),
        ("a reserved record type after the last manifest", ok + encode_record({0: 9}),
         "UnsupportedVersion"),
        ("a manifest without its revision", _with_manifest(ok, lambda m: m.pop(9)),
         "RevisionMismatch"),
        ("a manifest of another revision",
         _with_manifest(ok, lambda m: m.__setitem__(9, REVISION + 1)),
         "RevisionMismatch"),
    ]
    out = []
    for name, data, cls in cases:
        got = _err(import_file, data, [KIND], holds=False)
        assert got == cls, (name, got, cls)
        sniffed = _err(sniff, data)
        out.append({"name": name, "file": h(data), "class": cls,
                    "sniff_refuses": sniffed == cls})
    return out


def _held_object_family() -> dict:
    """An object embedded from a plaintext the application holds: its header
    and chunks as a held put seals them, which are the stored object's."""
    S = [units.ROT["A"]]
    key_ref = kg.encode_set(S)
    k = units.state_key(S)
    plaintext = bytes(range(150))
    provider = at_rest.Provider()
    token = b"attachments/big.bin"
    provider.put(token, plaintext, example("at-rest/held/stamp/attachments/big.bin")[:16])
    put = at_rest.put_held(units.SPACE, k, key_ref, provider, token, 64)
    expected = units.seal_object(units.SPACE, k, key_ref, plaintext, 64)
    chunks = [c["sealed"] for c in put["chunks"]]
    assert chunks == [c["sealed"] for c in expected["chunks"]]
    records = encode_record({0: T_OBJECT_HEADER, 2: put["locator"], 3: put["header"]})
    for i, chunk in enumerate(chunks):
        records += encode_record({0: T_OBJECT_CHUNK, 2: put["locator"], 3: i, 4: chunk})
    return {"chunk_bytes": 64, "token": h(token), "locator": h(put["locator"]),
            "records": h(records), "stored_object": h(expected["bytes"]),
            "equals": "units.json objects, case \"three chunks, the chunk size lowered to 64\""}


def ext_space_files_vectors() -> dict:
    built = Built()
    file_key = example("space-files/file-key")
    rows, refusals = _records_family(built, file_key)
    files = _files_family(built, file_key)
    snapshot = _snapshot_family(built)
    r = built.r
    return {
        "specification": "ext-space-files.md",
        "fixtures": {
            "space": h(r.id), "kind": KIND, "stream": h(STREAM),
            "devices": {n: h(r.hist.device(n)) for n in ("A", "B", "C")},
            "invite": {"secret": h(built.secret), "entry": h(built.entry),
                       "fragment": built.fragment, "raw_fragment": h(built.raw_fragment),
                       "key": h(built.keys["device_id"]), "expires_at": adm.INVITE_EXPIRES,
                       "now": NOW},
            "rotations": {r.name(i): h(k) for i, k in built.secrets()},
            "events": r.hist.describe(),
            "file_key": h(file_key),
        },
        "records": rows,
        "record_refusals": refusals,
        "way_in": _way_in_family(built, file_key),
        "files": files,
        "snapshot_file": snapshot,
        "appends": _appends_family(built),
        "refusals": _refusals_family(built),
        "held_object": _held_object_family(),
    }


def self_test() -> None:
    for a in NEW_LABELS:
        for b in NEW_LABELS:
            assert a is b or not a.startswith(b), (a, b)
    v = ext_space_files_vectors()
    roads = v["files"]["roads"]
    assert roads["a member that holds the space"]["new_events"] == 0
    assert roads["a reader by keys"]["road"] == "Reading"
    assert roads["a sealed way in without the key"] == "Sealed"
    assert roads["a sealed way in with the key"] == "Reading"
    assert roads["no way in"] == "NoWayIn"
    assert roads["another kind"] == "WrongKind"
    assert roads["a rotation secret that misses its rotation's read credential"] == "KeyMismatch"
    assert roads["the events out of parent order"]["road"] == "Reading"
    assert roads["a head the file does not hold"] == "Pending"
    assert v["snapshot_file"]["claimant"]["claimable"] == "Open"
    assert v["snapshot_file"]["claimant"]["road"] == "Invited"
    assert v["snapshot_file"]["skipped_first"]["fragment_index"] == 1
    assert v["snapshot_file"]["fallthrough"]["road"] == "Reading"
    assert [x["class"] for x in v["refusals"]] == [
        "NotASpaceFile", "UnsupportedVersion", "UnsupportedVersion", "Malformed", "Malformed",
        "TooLarge", "TooLarge", "UnsupportedVersion", "RevisionMismatch", "RevisionMismatch"]
    assert [x["sniff_refuses"] for x in v["refusals"]] == [True] * 6 + [False, False, True, True]
    assert v["appends"]["truncated"]["tail_ignored"]
    assert v["appends"]["an append to another space"] == "OtherSpace"
    assert v["appends"]["a record that does not read before the last manifest"] == "Malformed"
    assert v == ext_space_files_vectors(), "the vectors are not deterministic"


if __name__ == "__main__":
    self_test()
    print("ext_space_files: self-test passed")
