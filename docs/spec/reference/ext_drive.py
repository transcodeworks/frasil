"""The drive extension (ext-drive.md), protocol 1, written from the
specification, independently of any implementation: the forms of its
values, reading a drive's tree, what a reader shows, and each change with
its checks in their order.

Loro itself is not modelled. A tree is the root containers' values, as
ext-drive.md's section 5 writes them: `document` and `purged` as maps, and
`entries` as a list of roots, each node `{"fields": map, "children": list}`
with its children in Loro's order. A change applies Loro's own operations to
that model: a node created or moved as its parent's last child, a node
deleted with every node inside it, and a map key set or deleted."""

from __future__ import annotations

import copy
import unicodedata

from formats import example

KIND = "frasil:drive"
DOCUMENT, ENTRIES, PURGED = "document", "entries", "purged"
FOLDER, FILE, DOC = "folder", "file", "document"
MAX_NAME_BYTES = 255
MAX_KIND_BYTES = 64
MAX_MEDIA_TYPE_BYTES = 255
MAX_META_KEY_BYTES = 255
MAX_COUNT = 2**53 - 1
TOKEN = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+.^_`|~-")

CLASSES = ["NotADrive", "InvalidValue", "NoSuchEntry", "EntryExists", "CannotHold",
           "MoveIntoItself", "AlreadyListed", "AlreadyTrashed", "NotTrashed",
           "NotAFile", "VersionExists", "NoSuchVersion", "VersionIsHead",
           "VersionHasParents"]
MAX_PARENTS = 64


class Refused(Exception):
    def __init__(self, cls: str):
        assert cls in CLASSES, cls
        super().__init__(cls)
        self.cls = cls


# ---------------------------------------------------------------------------
# 2.1 Values

def control(c: str) -> bool:
    return unicodedata.category(c) == "Cc"


def white_space(c: str) -> bool:
    # Unicode's White_Space property. Python's isspace adds U+001C to
    # U+001F, which are controls and refused as such anyway.
    return c.isspace()


def is_name(v) -> bool:
    return (isinstance(v, str) and 1 <= len(v.encode()) <= MAX_NAME_BYTES
            and not any(c == "/" or control(c) for c in v))


def is_kind_string(v) -> bool:
    return (isinstance(v, str) and 1 <= len(v.encode()) <= MAX_KIND_BYTES
            and not any(control(c) or white_space(c) for c in v))


def lower_hex(v, digits: int) -> bool:
    return isinstance(v, str) and len(v) == digits and all(c in "0123456789abcdef" for c in v)


def is_entry_id(v) -> bool:
    return lower_hex(v, 32)


def is_stream_id(v) -> bool:
    return lower_hex(v, 32) and v != "0" * 32


def is_handle(v) -> bool:
    return lower_hex(v, 32)


def is_media_type(v) -> bool:
    if not isinstance(v, str) or len(v.encode()) > MAX_MEDIA_TYPE_BYTES:
        return False
    essence, has_parameters, parameters = v.partition(";")
    kind, slash, subtype = essence.partition("/")

    def token(part: str) -> bool:
        return part != "" and all(c in TOKEN for c in part)

    return (slash == "/" and token(kind) and token(subtype)
            and (not has_parameters or all(0x20 <= ord(c) <= 0x7e for c in parameters)))


def is_meta_key(v) -> bool:
    return (isinstance(v, str) and 1 <= len(v.encode()) <= MAX_META_KEY_BYTES
            and not any(control(c) for c in v))


def is_count(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= MAX_COUNT


def read_count(v):
    """A count from an I64 in range, or a Double that holds one; else None."""
    if is_count(v):
        return v
    if isinstance(v, float) and v.is_integer() and 0 <= v <= MAX_COUNT:
        return int(v)
    return None


def is_meta_value(v) -> bool:
    """Not a container. In this model a dict is a map container, so a meta
    value is a scalar here."""
    return v is None or isinstance(v, (bool, int, float, str))


def is_parents(v, own: str) -> bool:
    """Section 2.4: 0 to 64 handles, no handle twice, none the record's
    own."""
    return (isinstance(v, list) and len(v) <= MAX_PARENTS and all(is_handle(p) for p in v)
            and len(set(v)) == len(v) and own not in v)


def read_record(handle, v):
    """Section 2.4: a version record of its form, read, or None. Inside
    `versions` a dict is a map value, not a container (section 5)."""
    if not is_handle(handle) or not isinstance(v, dict):
        return None
    if any(k not in ("stream", "size", "at", "parents") for k in v):
        return None
    if not is_stream_id(v.get("stream")) or not is_parents(v.get("parents"), handle):
        return None
    return {"stream": v["stream"], "size": read_count(v.get("size")),
            "at": read_count(v.get("at")), "parents": list(v["parents"])}


def heads(blob: str, versions: dict) -> list[str]:
    """Section 2.4: the handles of the records no record names in
    `parents`; `blob` alone when there is no record, or none is a head."""
    named = {p for record in versions.values() for p in record["parents"]}
    found = sorted(handle for handle in versions if handle not in named)
    return found or [blob]


# ---------------------------------------------------------------------------
# 3.2 Reading the tree

class Read:
    """A drive as a reader reads it."""

    def __init__(self, tree: dict):
        if tree[DOCUMENT].get("kind") != KIND:
            raise Refused("NotADrive")
        self.tree = tree
        self.entries: list[dict] = []
        self.by_id: dict[str, dict] = {}
        # Every node, readable or not: its parent node, by Python identity.
        self.node_parent: dict[int, dict | None] = {}
        self.node_of: dict[str, dict] = {}
        self._index(tree[ENTRIES], None)
        self._walk(tree[ENTRIES], None)

    def _index(self, nodes: list, parent):
        for node in nodes:
            self.node_parent[id(node)] = parent
            self._index(node["children"], node)

    def _walk(self, nodes: list, parent_entry):
        for node in nodes:
            entry = parse(node["fields"])
            if entry is None or entry["id"] in self.by_id:
                continue
            holds = parent_entry is not None and parent_entry["kind"] not in (FILE, DOC)
            entry["parent"] = parent_entry["id"] if holds else None
            entry["order"] = len(self.entries)
            self.entries.append(entry)
            self.by_id[entry["id"]] = entry
            self.node_of[entry["id"]] = node
            self._walk(node["children"], entry)

    def trashed_itself(self, e: dict) -> bool:
        return e["trashed"] is not None

    def in_trash(self, e: dict) -> bool:
        while e is not None:
            if self.trashed_itself(e):
                return True
            e = self.by_id.get(e["parent"]) if e["parent"] else None
        return False

    def listing(self, folder: str | None) -> list[list[str]]:
        items = [e for e in self.entries
                 if e["parent"] == folder and not self.trashed_itself(e)]
        return [[e["id"], shown] for e, shown in
                zip(items, shown_names([(e["name"], e["kind"] == FILE) for e in items]))]

    def trash(self) -> list[str]:
        items = [e for e in self.entries if self.trashed_itself(e)
                 and not (e["parent"] and self.in_trash(self.by_id[e["parent"]]))]
        items.sort(key=lambda e: (-e["trashed"], e["order"]))
        return [e["id"] for e in items]

    def stream_entries(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for e in self.entries:
            if e["kind"] == DOC:
                out.setdefault(e["stream"], e["id"])
        return out

    def node_within(self, node: dict, top: dict) -> bool:
        """Whether `node` is `top` or inside it in `entries`."""
        while node is not None:
            if node is top:
                return True
            node = self.node_parent[id(node)]
        return False

    def entries_within(self, top: dict) -> list[dict]:
        return [e for e in self.entries if self.node_within(self.node_of[e["id"]], top)]

    def view(self) -> dict:
        holders = [e for e in self.entries if e["kind"] not in (FILE, DOC)]
        return {
            "entries": [dict(e) for e in self.entries],
            "listings": {"": self.listing(None),
                         **{e["id"]: self.listing(e["id"]) for e in holders}},
            "trash": self.trash(),
            "in_trash": [e["id"] for e in self.entries if self.in_trash(e)],
            "streams": self.stream_entries(),
            "conflicts": [e["id"] for e in self.entries if e["conflict"]],
        }


def parse(fields: dict) -> dict | None:
    """Section 3.2, steps 3 and 5, for one node's metadata map."""
    eid_, kind, name = fields.get("id"), fields.get("kind"), fields.get("name")
    if not is_entry_id(eid_) or not is_kind_string(kind) or not isinstance(name, str):
        return None
    entry = {"id": eid_, "kind": kind, "name": name, "parent": None, "order": None,
             "added": read_count(fields.get("added")), "at": read_count(fields.get("at")),
             "trashed": None, "stream": None, "blob": None, "size": None, "type": None,
             "docKind": None, "meta": {}, "versions": {}, "heads": [], "conflict": False}
    if "trashed" in fields:
        trashed = read_count(fields["trashed"])
        entry["trashed"] = 0 if trashed is None else trashed
    if kind == FILE:
        if not is_stream_id(fields.get("stream")) or not is_handle(fields.get("blob")):
            return None
        entry["stream"], entry["blob"] = fields["stream"], fields["blob"]
        entry["size"] = read_count(fields.get("size"))
        entry["type"] = fields["type"] if is_media_type(fields.get("type")) else None
        raw = fields.get("versions")
        if isinstance(raw, dict):
            for handle, value in raw.items():
                record = read_record(handle, value)
                if record is not None:
                    entry["versions"][handle] = record
        entry["heads"] = heads(entry["blob"], entry["versions"])
        entry["conflict"] = len(entry["heads"]) > 1
    elif kind == DOC:
        if not is_stream_id(fields.get("stream")) or not is_kind_string(fields.get("docKind")):
            return None
        entry["stream"], entry["docKind"] = fields["stream"], fields["docKind"]
    if isinstance(fields.get("meta"), dict):
        entry["meta"] = copy.deepcopy(fields["meta"])
    return entry


# ---------------------------------------------------------------------------
# 3.3 Shown names

def numbered(name: str, n: int, is_file: bool) -> str:
    dot = name.rfind(".")
    if is_file and dot > 0:
        return f"{name[:dot]} ({n}){name[dot:]}"
    return f"{name} ({n})"


def shown_names(items: list[tuple[str, bool]]) -> list[str]:
    names = {name for name, _ in items}
    shown: set[str] = set()
    out = []
    for name, is_file in items:
        result = name
        if name in shown:
            n = 2
            while numbered(name, n, is_file) in shown or numbered(name, n, is_file) in names:
                n += 1
            result = numbered(name, n, is_file)
        shown.add(result)
        out.append(result)
    return out


# ---------------------------------------------------------------------------
# 3.4 Changes

def record(stream: str, size, at, parents: list[str]) -> dict:
    """A version record as a writer writes it (section 2.4)."""
    out = {"stream": stream}
    if size is not None:
        out["size"] = size
    if at is not None:
        out["at"] = at
    out["parents"] = list(parents)
    return out


def named_blobs(e: dict) -> set[tuple[str, str]]:
    """The blobs a file entry names, by `blob` and by its records."""
    out = {(e["stream"], e["blob"])}
    for handle, rec in e["versions"].items():
        out.add((rec["stream"], handle))
    return out


def apply(tree: dict, change: dict) -> tuple[dict, list[list[str]]]:
    """The tree after `change`, and the blobs a purge releases; raises
    Refused with the first check that fails."""
    tree = copy.deepcopy(tree)
    drive = Read(tree)                                   # 1. NotADrive
    op, at = change["op"], change.get("at")
    released: list[list[str]] = []

    def stamp(fields: dict, key: str):
        if at is not None:
            fields[key] = at

    def children_of(parent_id):
        return tree[ENTRIES] if parent_id is None else drive.node_of[parent_id]["children"]

    def parent_ok(parent_id):
        if parent_id is None:
            return
        if parent_id not in drive.by_id:
            raise Refused("NoSuchEntry")
        if drive.by_id[parent_id]["kind"] != FOLDER:
            raise Refused("CannotHold")

    def entry(entry_id):
        if entry_id not in drive.by_id:
            raise Refused("NoSuchEntry")
        return drive.by_id[entry_id], drive.node_of[entry_id]

    if op == "add":
        kind = change["kind"]
        ok = is_entry_id(change["id"]) and is_name(change["name"]) and kind in (FOLDER, FILE, DOC)
        if kind == FILE:
            ok = ok and is_stream_id(change["stream"]) and is_handle(change["blob"])
            ok = ok and (change.get("size") is None or is_count(change["size"]))
            ok = ok and (change.get("type") is None or is_media_type(change["type"]))
        if kind == DOC:
            ok = ok and is_stream_id(change["stream"]) and is_kind_string(change["docKind"])
        if not ok:
            raise Refused("InvalidValue")                # 2.
        if change["id"] in drive.by_id:
            raise Refused("EntryExists")                 # 3.
        parent_ok(change["parent"])                      # 4., 5.
        if kind == DOC and (change["stream"] in drive.stream_entries()
                            or change["stream"] in tree[PURGED]):
            raise Refused("AlreadyListed")               # 6.
        fields = {"id": change["id"], "kind": kind, "name": change["name"]}
        stamp(fields, "added")
        stamp(fields, "at")
        if kind == FILE:
            fields["stream"], fields["blob"] = change["stream"], change["blob"]
            if change.get("size") is not None:
                fields["size"] = change["size"]
            if change.get("type") is not None:
                fields["type"] = change["type"]
        if kind == DOC:
            fields["stream"], fields["docKind"] = change["stream"], change["docKind"]
        fields["meta"] = {}
        if kind == FILE:
            fields["versions"] = {change["blob"]: record(change["stream"], change.get("size"),
                                                     at, [])}
        children_of(change["parent"]).append({"fields": fields, "children": []})
    elif op == "set_blob":
        ok = is_handle(change["blob"]) and is_stream_id(change["stream"])
        ok = ok and (change.get("size") is None or is_count(change["size"]))
        ok = ok and (change.get("type") is None or is_media_type(change["type"]))
        ok = ok and is_parents(change["parents"], change["blob"])
        if not ok:
            raise Refused("InvalidValue")                # 2.
        e, target = entry(change["id"])                   # 3.
        if e["kind"] != FILE:
            raise Refused("NotAFile")                    # 4.
        if change["blob"] in e["versions"]:
            raise Refused("VersionExists")               # 5.
        fields = target["fields"]
        current = fields["blob"]
        takes_place = current in change["parents"]
        if not isinstance(fields.get("versions"), dict):
            fields["versions"] = {}
        if takes_place:
            fields["blob"], fields["stream"] = change["blob"], change["stream"]
            stamp(fields, "at")
            for key in ("size", "type"):
                if change.get(key) is not None:
                    fields[key] = change[key]
                else:
                    fields.pop(key, None)
        elif current not in fields["versions"]:
            fields["versions"][current] = record(fields["stream"], fields.get("size"), None, [])
        fields["versions"][change["blob"]] = record(change["stream"], change.get("size"), at,
                                                   change["parents"])
    elif op == "forget_version":
        if not is_handle(change["handle"]):
            raise Refused("InvalidValue")                # 2.
        e, target = entry(change["id"])                   # 3.
        if e["kind"] != FILE:
            raise Refused("NotAFile")                    # 4.
        versions = target["fields"].get("versions")
        if not isinstance(versions, dict) or change["handle"] not in versions:
            raise Refused("NoSuchVersion")               # 5., a value of any form
        # A value of the wrong form is no record and names no parents.
        record_ = e["versions"].get(change["handle"])
        if change["handle"] in e["heads"]:
            raise Refused("VersionIsHead")               # 6.
        if record_ is not None and any(p in e["versions"] for p in record_["parents"]):
            raise Refused("VersionHasParents")           # 7.
        versions.pop(change["handle"])
    elif op == "rename":
        if not is_name(change["name"]):
            raise Refused("InvalidValue")
        _, target = entry(change["id"])
        target["fields"]["name"] = change["name"]
        stamp(target["fields"], "at")
    elif op == "move":
        _, target = entry(change["id"])
        parent_ok(change["parent"])
        if change["parent"] is not None and drive.node_within(
                drive.node_of[change["parent"]], target):
            raise Refused("MoveIntoItself")
        holder = drive.node_parent[id(target)]
        (tree[ENTRIES] if holder is None else holder["children"]).remove(target)
        children_of(change["parent"]).append(target)
        stamp(target["fields"], "at")
    elif op == "trash":
        e, target = entry(change["id"])
        if drive.trashed_itself(e):
            raise Refused("AlreadyTrashed")
        target["fields"]["trashed"] = at if at is not None else 0
    elif op == "restore":
        e, target = entry(change["id"])
        if not drive.trashed_itself(e):
            raise Refused("NotTrashed")
        del target["fields"]["trashed"]
        stamp(target["fields"], "at")
    elif op == "purge":
        _, target = entry(change["id"])
        gone = drive.entries_within(target)
        gone_ids = {e["id"] for e in gone}
        kept = {pair for e in drive.entries if e["kind"] == FILE and e["id"] not in gone_ids
                for pair in named_blobs(e)}
        freed = {pair for e in gone if e["kind"] == FILE for pair in named_blobs(e)} - kept
        released = [list(pair) for pair in sorted(freed)]
        for e in gone:
            if e["kind"] == DOC:
                tree[PURGED][e["stream"]] = at if at is not None else 0
        holder = drive.node_parent[id(target)]
        (tree[ENTRIES] if holder is None else holder["children"]).remove(target)
    elif op == "set_meta":
        if not is_meta_key(change["key"]) or not is_meta_value(change["value"]):
            raise Refused("InvalidValue")
        _, target = entry(change["id"])
        if not isinstance(target["fields"].get("meta"), dict):
            target["fields"]["meta"] = {}
        target["fields"]["meta"][change["key"]] = change["value"]
    elif op == "delete_meta":
        if not is_meta_key(change["key"]):
            raise Refused("InvalidValue")
        _, target = entry(change["id"])
        meta = target["fields"].get("meta")
        if isinstance(meta, dict):
            meta.pop(change["key"], None)
    else:
        raise AssertionError(op)
    return tree, released


# ---------------------------------------------------------------------------
# Vectors

def eid(name: str) -> str:
    return example(f"drive/entry/{name}")[:16].hex()


def sid(name: str) -> str:
    return example(f"drive/stream/{name}")[:16].hex()


def hid(name: str) -> str:
    return example(f"drive/blob/{name}")[:16].hex()


AT = 1_792_000_000


def node(fields: dict, *children: dict) -> dict:
    return {"fields": fields, "children": list(children)}


def folder(name: str, *children, label: str | None = None, **extra) -> dict:
    return node({"id": eid(label or name), "kind": FOLDER, "name": name, "added": AT,
                 "at": AT, **extra, "meta": {}}, *children)


def file(name: str, blob: str, *children, label: str | None = None, stream: str = "files",
         versions: dict | None = None, **extra) -> dict:
    fields = {"id": eid(label or name), "kind": FILE, "name": name, "added": AT, "at": AT,
              "stream": sid(stream), "blob": hid(blob), **extra, "meta": {}}
    if versions is not None:
        fields["versions"] = versions
    return node(fields, *children)


def rec(*parents: str, stream: str = "files", size: int | None = None,
        at: int | None = AT) -> dict:
    """A version record for the vectors, its parents by blob label."""
    return record(sid(stream), size, at, [hid(p) for p in parents])


def versioned(name: str, *labels: str, **kw) -> dict:
    """A file whose versions form a chain, the last label its `blob`."""
    versions = {}
    for i, label in enumerate(labels):
        versions[hid(label)] = rec(*labels[i - 1:i]) if i else rec()
    return file(name, labels[-1], versions=versions, **kw)


def document(name: str, stream: str, doc_kind: str = "example.notebook",
             label: str | None = None, **extra) -> dict:
    return node({"id": eid(label or name), "kind": DOC, "name": name, "added": AT, "at": AT,
                 "stream": sid(stream), "docKind": doc_kind, **extra, "meta": {}})


def drive_tree(*roots: dict, purged: dict | None = None) -> dict:
    return {DOCUMENT: {"kind": KIND}, ENTRIES: list(roots), PURGED: purged or {}}


def values_family() -> dict:
    return {
        "names": [[v, is_name(v)] for v in [
            "Report.pdf", "a", "x" * 255, "é" * 127, "Été 2026", "", "x" * 256, "é" * 128,
            "a/b", "tab\there", "line\nbreak", "del\x7f", "c1\x85", " leading space",
            "zero​width"]],
        "entry_ids": [[v, is_entry_id(v)] for v in [
            eid("a"), "0" * 32, eid("a").upper(), eid("a")[:31], eid("a") + "0",
            "g" * 32]],
        "kind_strings": [[v, is_kind_string(v)] for v in [
            "folder", "example.note", "example:sheet", "k" * 64, "", "k" * 65, "a b",
            "a　b", "a b", "a\nb", "a﻿b"]],
        "stream_ids": [[v, is_stream_id(v)] for v in [
            sid("files"), "0" * 32, sid("files").upper(), sid("files")[:30]]],
        "handles": [[v, is_handle(v)] for v in [hid("a"), "0" * 32, hid("a")[:31]]],
        "media_types": [[v, is_media_type(v)] for v in [
            "image/png", "application/vnd.api+json", 'text/plain; charset="utf-8"',
            "text/plain;", "a/b;~ !", "", "text", "text/", "/plain", "text/plain/x",
            "text /plain", "text/plain ;a", "text/plain;é", "text/plain;\t", "té/x",
            "a/" + "b" * 253, "a/" + "b" * 254]],
        "meta_keys": [[v, is_meta_key(v)] for v in [
            "example.color", "k", "k" * 255, "", "k" * 256, "a\nb", "with space"]],
        "counts": [[v, read_count(v)] for v in [
            0, 5, MAX_COUNT, MAX_COUNT + 1, -1, 5.0, 5.5, float(MAX_COUNT), -1.0, 1e300,
            "5", True, None]],
    }


def names_family() -> list[dict]:
    cases = [
        ("no two alike", [("A", False), ("B", False)]),
        ("a second folder of one name", [("Draft", False), ("Draft", False)]),
        ("three files of one name, numbered before the extension",
         [("photo.jpg", True), ("photo.jpg", True), ("photo.jpg", True)]),
        ("a later sibling already has the numbered name",
         [("a.txt", True), ("a.txt", True), ("a (2).txt", True)]),
        ("a file whose only dot is its first byte", [(".env", True), (".env", True)]),
        ("a file with two dots", [("take.tar.gz", True), ("take.tar.gz", True)]),
        ("a file ending in a dot", [("a.", True), ("a.", True)]),
        ("a folder whose name has a dot", [("v1.2", False), ("v1.2", False)]),
        ("a file and a folder of one name", [("notes", False), ("notes", True)]),
        ("names compared byte for byte",
         [("Café", False), ("Café", False), ("café", False), ("Café", False)]),
    ]
    return [{"description": d, "items": [[n, f] for n, f in items],
             "shown": shown_names(items)} for d, items in cases]


def reading_family() -> list[dict]:
    out = []

    def case(description: str, tree: dict):
        try:
            view = Read(tree).view()
            out.append({"description": description, "tree": tree, "verdict": "read", **view})
        except Refused as refusal:
            out.append({"description": description, "tree": tree, "verdict": refusal.cls})

    case("folders, files and a document, with a file numbered", drive_tree(
        folder("Projects",
               file("plan.pdf", "plan", type="application/pdf", size=1200),
               file("plan.pdf", "plan-2", label="plan.pdf/2", size=900),
               document("Minutes", "minutes")),
        folder("Archive"),
        file("readme.txt", "readme", type="text/plain", size=12)))
    case("nodes a reader skips, and what is inside them", drive_tree(
        node({"kind": FOLDER, "name": "No ID", "meta": {}},
             folder("Inside a node without an ID")),
        folder("Kept", label="dup"),
        folder("Same ID later", folder("Inside the duplicate"), label="dup"),
        node({"id": eid("no-blob"), "kind": FILE, "name": "no blob", "stream": sid("files"),
              "meta": {}}),
        node({"id": eid("bad-kind"), "kind": "has space", "name": "x", "meta": {}}),
        node({"id": eid("bad-name"), "kind": FOLDER, "name": 7, "meta": {}}),
        node({"id": eid("bad-doc"), "kind": DOC, "name": "doc", "stream": sid("d"),
              "meta": {}})))
    case("an application's kind holds an entry; an entry under a file shows at the root",
         drive_tree(
             node({"id": eid("note"), "kind": "example.note", "name": "Hamlet",
                   "example.unknown": True, "meta": {"example.color": "red"}},
                  file("sketch.png", "sketch")),
             file("song.mp3", "song", folder("Stray", label="stray"))))
    case("counts written as doubles, a trashed folder, and fields of the wrong form",
         drive_tree(
             folder("Old", file("a.txt", "a"), folder("Deep", file("b.txt", "b")),
                    trashed=AT + 10),
             folder("Also old", trashed=AT + 20),
             file("c.txt", "c", label="c-trashed", trashed=AT + 10),
             file("d.txt", "d", label="d", size=12.0, type="not a type",
                  added=float(AT), at=1.5),
             node({"id": eid("odd-trash"), "kind": FOLDER, "name": "Trashed oddly",
                   "trashed": "yes", "meta": "not a map"})))
    case("two document entries name one stream; the stream's entry is the first", drive_tree(
        document("Budget", "budget"),
        folder("Copies", document("Budget", "budget", label="budget-2"))))
    case("files and their versions: none recorded, a chain, two heads, a cycle, and a "
         "record of the wrong form", drive_tree(
        file("legacy.txt", "legacy"),
        versioned("chain.txt", "c1", "c2", "c3"),
        file("conflict.txt", "k2", versions={hid("k1"): rec(), hid("k2"): rec("k1"),
                                              hid("k3"): rec("k1")}),
        file("cycle.txt", "y1", versions={hid("y1"): rec("y2"), hid("y2"): rec("y1")}),
        file("odd.txt", "o2", versions={hid("o1"): rec(), hid("o2"): {"stream": sid("files")},
                                         "not a handle": rec(), hid("o3"): rec("o3"),
                                         hid("o4"): "text"})))
    case("a document that is not a drive", {DOCUMENT: {"kind": "example.notes"},
                                            ENTRIES: [], PURGED: {}})
    case("a document without a kind", {DOCUMENT: {}, ENTRIES: [], PURGED: {}})
    return out


def changes_family() -> list[dict]:
    base = drive_tree(
        folder("A", file("a.txt", "a"), folder("A1")),
        folder("B"),
        file("song.mp3", "song", folder("Stray", label="stray")),
        file("copy.txt", "a", label="copy"),
        document("Minutes", "minutes"),
        folder("Bin", document("Old minutes", "old"), file("b.txt", "b"),
               trashed=AT),
        node({"kind": FOLDER, "name": "skipped", "meta": {}}, folder("kept as it is")),
        purged={sid("gone"): AT - 100})
    later = AT + 60
    out = []

    def case(description: str, change: dict, tree: dict = base):
        try:
            after, released = apply(tree, change)
            item = {"description": description, "before": tree, "change": change,
                    "verdict": "applied", "after": after}
            if change["op"] == "purge":
                item["released"] = released
        except Refused as refusal:
            item = {"description": description, "before": tree, "change": change,
                    "verdict": refusal.cls}
        out.append(item)

    add = {"op": "add", "parent": None, "at": later}
    case("add a folder at the root", {**add, "id": eid("new"), "kind": FOLDER, "name": "New"})
    case("add a file in a folder, with its size and type",
         {**add, "id": eid("new"), "parent": eid("A"), "kind": FILE, "name": "c.png",
          "stream": sid("files"), "blob": hid("c"), "size": 2048, "type": "image/png"})
    case("add a document, its writer's clock not known",
         {**add, "id": eid("new"), "kind": DOC, "name": "Sheet", "stream": sid("sheet"),
          "docKind": "example.spreadsheet", "at": None})
    case("add a name already shown in the folder",
         {**add, "id": eid("new"), "kind": FOLDER, "name": "A"})
    case("add with a name holding a slash",
         {**add, "id": eid("new"), "kind": FOLDER, "name": "a/b"})
    case("add with an entry ID of the wrong form",
         {**add, "id": "NEW", "kind": FOLDER, "name": "New"})
    case("add an application's kind", {**add, "id": eid("new"), "kind": "example.note",
                                       "name": "Note"})
    case("add a file whose size is beyond a count",
         {**add, "id": eid("new"), "kind": FILE, "name": "big", "stream": sid("files"),
          "blob": hid("big"), "size": MAX_COUNT + 1, "type": None})
    case("add under an entry ID the drive holds",
         {**add, "id": eid("A"), "kind": FOLDER, "name": "Again"})
    case("add into an entry that does not exist",
         {**add, "id": eid("new"), "parent": eid("nowhere"), "kind": FOLDER, "name": "New"})
    case("add into a file", {**add, "id": eid("new"), "parent": eid("song.mp3"),
                             "kind": FOLDER, "name": "New"})
    case("add a document for a stream that has an entry",
         {**add, "id": eid("new"), "kind": DOC, "name": "Again", "stream": sid("minutes"),
          "docKind": "example.notebook"})
    case("add a document for a stream whose entry was purged",
         {**add, "id": eid("new"), "kind": DOC, "name": "Back", "stream": sid("gone"),
          "docKind": "example.notebook"})
    case("rename", {"op": "rename", "id": eid("a.txt"), "name": "b.txt", "at": later})
    case("rename to a name of the wrong form",
         {"op": "rename", "id": eid("a.txt"), "name": "", "at": later})
    case("rename an entry that does not exist",
         {"op": "rename", "id": eid("nowhere"), "name": "x", "at": later})
    case("move a folder into another, last among its children",
         {"op": "move", "id": eid("A1"), "parent": eid("B"), "at": later})
    case("move an entry to the root", {"op": "move", "id": eid("a.txt"), "parent": None,
                                       "at": later})
    case("move an entry shown at the root out of the file it is under",
         {"op": "move", "id": eid("stray"), "parent": eid("B"), "at": later})
    case("move a folder into itself",
         {"op": "move", "id": eid("A"), "parent": eid("A"), "at": later})
    case("move a folder into a folder inside it",
         {"op": "move", "id": eid("A"), "parent": eid("A1"), "at": later})
    case("move a file under the entry shown at the root beneath it",
         {"op": "move", "id": eid("song.mp3"), "parent": eid("stray"), "at": later})
    case("move into a document",
         {"op": "move", "id": eid("B"), "parent": eid("Minutes"), "at": later})
    case("move into an entry that does not exist",
         {"op": "move", "id": eid("B"), "parent": eid("nowhere"), "at": later})
    case("trash a folder", {"op": "trash", "id": eid("A"), "at": later})
    case("trash, the writer's clock not known", {"op": "trash", "id": eid("A"), "at": None})
    case("trash an entry trashed already", {"op": "trash", "id": eid("Bin"), "at": later})
    case("trash an entry inside something trashed",
         {"op": "trash", "id": eid("b.txt"), "at": later})
    case("restore", {"op": "restore", "id": eid("Bin"), "at": later})
    case("restore an entry not trashed itself",
         {"op": "restore", "id": eid("b.txt"), "at": later})
    case("purge a folder: its documents are recorded and its unshared blobs released",
         {"op": "purge", "id": eid("Bin"), "at": later})
    case("purge a file whose blob another entry names: nothing is released",
         {"op": "purge", "id": eid("copy"), "at": later})
    case("purge a file and the entry under it",
         {"op": "purge", "id": eid("song.mp3"), "at": None})
    case("purge a file with versions: each version's blob is released",
         {"op": "purge", "id": eid("chain.txt"), "at": later},
         drive_tree(versioned("chain.txt", "c1", "c2", "c3"), file("copy.txt", "c1")))
    case("purge an entry that does not exist", {"op": "purge", "id": eid("nowhere"),
                                                "at": later})
    case("set a meta key", {"op": "set_meta", "id": eid("A"), "key": "example.color",
                            "value": "blue"})
    case("set a meta key of the wrong form", {"op": "set_meta", "id": eid("A"), "key": "",
                                              "value": 1})
    case("set a meta key on an entry without a meta map",
         {"op": "set_meta", "id": eid("odd"), "key": "example.pinned", "value": True},
         drive_tree(node({"id": eid("odd"), "kind": FOLDER, "name": "Odd"})))
    case("delete a meta key", {"op": "delete_meta", "id": eid("note"),
                               "key": "example.color"},
         drive_tree(node({"id": eid("note"), "kind": "example.note", "name": "Hamlet",
                          "meta": {"example.color": "red", "example.size": 3}})))
    case("a change to a document that is not a drive",
         {"op": "rename", "id": eid("A"), "name": "x", "at": later},
         {DOCUMENT: {"kind": "example.notes"}, ENTRIES: [], PURGED: {}})
    return out


def versions_family() -> list[dict]:
    """Section 3.4's Set blob and Forget version, and section 3.5's
    concurrent Set blobs."""
    later = AT + 60
    base = drive_tree(
        folder("Docs", versioned("plan.txt", "p1", "p2", "p3")),
        file("legacy.txt", "legacy"),
        file("conflict.txt", "k2", versions={hid("k1"): rec(), hid("k2"): rec("k1"),
                                              hid("k3"): rec("k1")}))
    out = []

    def case(description: str, changes: list[dict], tree: dict = base):
        item = {"description": description, "before": tree, "changes": changes}
        try:
            after = tree
            for change in changes:
                after, _ = apply(after, change)
            heads_after = {e["id"]: e["heads"] for e in Read(after).entries if e["kind"] == FILE}
            item |= {"verdict": "applied", "after": after, "heads": heads_after}
        except Refused as refusal:
            item["verdict"] = refusal.cls
        out.append(item)

    def set_blob(entry: str, blob: str, *parents: str, size=None, type_=None, at=later):
        return {"op": "set_blob", "id": eid(entry), "blob": hid(blob), "stream": sid("files"),
                "size": size, "type": type_, "parents": [hid(p) for p in parents], "at": at}

    def forget(entry: str, blob: str):
        return {"op": "forget_version", "id": eid(entry), "handle": hid(blob)}

    case("a plain save: a new blob whose parent is the head",
         [set_blob("plan.txt", "p4", "p3", size=1300, type_="text/plain")])
    case("a save from a stale copy: a second head", [set_blob("plan.txt", "p4", "p2")])
    case("a resolution naming both heads, with merged bytes",
         [set_blob("conflict.txt", "k4", "k2", "k3", size=90)])
    case("a pick: one head's bytes put again under a new handle",
         [set_blob("conflict.txt", "k5", "k2", "k3")])
    case("a first Set blob on a file without records",
         [set_blob("legacy.txt", "l2", "legacy")])
    case("a stale save on a file without records: the current version stays a head",
         [set_blob("legacy.txt", "l2", "older")])
    case("a save from the other head: it replaces that head, and the current version stays",
         [set_blob("conflict.txt", "k4", "k3")])
    case("a Set blob with no parents: a head beside the current one",
         [set_blob("plan.txt", "p4")])
    case("a Set blob whose writer's clock is not known, without size or type",
         [set_blob("plan.txt", "p4", "p3", at=None)])
    case("a Set blob on a folder", [set_blob("Docs", "d1")])
    case("a Set blob under a handle that has a record", [set_blob("plan.txt", "p2", "p3")])
    case("a Set blob whose parents name the new handle", [set_blob("plan.txt", "p4", "p4")])
    case("a Set blob on an entry that does not exist", [set_blob("nowhere", "p4")])
    case("Forget version of the oldest record", [forget("plan.txt", "p1")])
    case("Forget version in order: the oldest, then its child",
         [forget("plan.txt", "p1"), forget("plan.txt", "p2")])
    case("Forget version of a head", [forget("plan.txt", "p3")])
    case("Forget version of a record whose parent has a record",
         [forget("plan.txt", "p2")])
    case("Forget version of a handle without a record", [forget("plan.txt", "p9")])
    case("Forget version on a folder", [forget("Docs", "p1")])
    case("Forget version of a value of the wrong form: deleted",
         [forget("junk.txt", "j1")],
         drive_tree(file("junk.txt", "j2", versions={hid("j1"): {"stream": 7, "parents": []},
                                                     hid("j2"): rec()})))
    case("a Set blob after its parent was forgotten: the heads are unchanged",
         [forget("plan.txt", "p1"), set_blob("plan.txt", "p4", "p1")])
    # Two concurrent Set blobs, merged in both of Loro's orders.
    one, two = set_blob("plan.txt", "a1", "p3", size=10), set_blob("plan.txt", "b1", "p3", size=20)
    merged = []
    for order in ((one, two), (two, one)):
        after = base
        for change in order:
            after, _ = apply(after, change)
        plan = Read(after).by_id[eid("plan.txt")]
        merged.append({"order": [c["blob"] for c in order], "after": after,
                       "blob": plan["blob"], "heads": plan["heads"],
                       "conflict": plan["conflict"]})
    assert merged[0]["heads"] == merged[1]["heads"] and merged[0]["blob"] != merged[1]["blob"]
    out.append({"description": "two concurrent Set blobs: one blob kept, both records, two "
                               "heads", "before": base, "changes": [one, two],
                "verdict": "applied", "merged": merged})
    return out


def ext_drive_vectors() -> dict:
    return {
        "specification": "ext-drive.md",
        "parameters": {
            "kind": KIND,
            "containers": {"document": DOCUMENT, "entries": ENTRIES, "purged": PURGED},
            "entry_kinds": [FOLDER, FILE, DOC],
            "max_name_bytes": MAX_NAME_BYTES,
            "max_kind_bytes": MAX_KIND_BYTES,
            "max_media_type_bytes": MAX_MEDIA_TYPE_BYTES,
            "max_meta_key_bytes": MAX_META_KEY_BYTES,
            "max_count": MAX_COUNT,
            "max_parents": MAX_PARENTS,
            "classes": CLASSES,
        },
        "values": values_family(),
        "names": names_family(),
        "reading": reading_family(),
        "changes": changes_family(),
        "versions": versions_family(),
    }


def self_test() -> None:
    assert numbered("photo.jpg", 2, True) == "photo (2).jpg"
    assert numbered(".env", 2, True) == ".env (2)"
    assert numbered("Hamlet v1.2", 2, False) == "Hamlet v1.2 (2)"
    assert shown_names([("a.txt", True), ("a.txt", True), ("a (2).txt", True)]) == \
        ["a.txt", "a (3).txt", "a (2).txt"]
    v = ext_drive_vectors()
    verdicts = [c["verdict"] for c in v["changes"]] + [c["verdict"] for c in v["versions"]]
    for cls in CLASSES:
        assert cls in verdicts, cls
    files = {c["description"]: c for c in v["reading"]}[
        "files and their versions: none recorded, a chain, two heads, a cycle, and a "
        "record of the wrong form"]
    by_name = {e["name"]: e for e in files["entries"]}
    assert by_name["legacy.txt"]["heads"] == [hid("legacy")]
    assert by_name["chain.txt"]["heads"] == [hid("c3")]
    assert by_name["conflict.txt"]["conflict"] and len(by_name["conflict.txt"]["heads"]) == 2
    assert by_name["cycle.txt"]["heads"] == [hid("y1")]
    assert sorted(by_name["odd.txt"]["versions"]) == [hid("o1")]
    assert files["conflicts"] == [eid("conflict.txt")]
    versions_purge = next(c for c in v["changes"]
                          if c["description"].startswith("purge a file with versions"))
    assert versions_purge["released"] == sorted([[sid("files"), hid("c2")],
                                                 [sid("files"), hid("c3")]])
    reading = {c["description"]: c for c in v["reading"]}
    skipped = reading["nodes a reader skips, and what is inside them"]
    assert [e["name"] for e in skipped["entries"]] == ["Kept"], skipped["entries"]
    app = reading["an application's kind holds an entry; an entry under a file shows at the root"]
    parents = {e["name"]: e["parent"] for e in app["entries"]}
    assert parents == {"Hamlet": None, "sketch.png": eid("note"), "song.mp3": None,
                       "Stray": None}, parents
    purge = next(c for c in v["changes"] if c["description"].startswith("purge a folder"))
    assert purge["released"] == [[sid("files"), hid("b")]], purge["released"]
    assert sid("old") in purge["after"][PURGED]
