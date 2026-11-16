"""Restricted spaces and carve-outs (ext-restricted-spaces.md), protocol 1:
the vectors of ext-restricted-spaces.json, written from the specification,
independently of any implementation.

A restricted space's keys, reference and sealed names are keygraph.py's;
descriptors, effective membership, the carve-out and the move record are
spaces.py's; rosters are roster.py's. This module adds what only the
extension decides: the parent of a restricted space ("The parent of a
restricted space"), when a restricted space rotates ("Keys of a restricted
space"), and late writes to a moved document and their re-application
("Moved documents").
"""

from __future__ import annotations

import adapters
import keygraph as kg
import roster as rs
import spaces
import units
from events import h
from formats import example
from primitives import SpecError


def _eid(name: str) -> bytes:
    return example(f"ext-restricted/event/{name}")


# ---------------------------------------------------------------------------
# The parent of a restricted space.


def parent_verdict(descriptor: dict | None, held: dict) -> str | None:
    """"The parent of a restricted space": None when the roster decides,
    else the verdict of every event of the space. `held` maps the space IDs
    whose genesis this replica holds to their descriptors."""
    if descriptor is None or descriptor["kind"] != spaces.KIND_RESTRICTED:
        return None
    parent = held.get(descriptor["parent"])
    if parent is None:
        return "Pending"
    if parent["kind"] == spaces.KIND_RESTRICTED:
        return "RestrictedParent"
    return None


def judge(r: rs.Roster, held: dict) -> dict:
    """Each event of r's log: the parent's verdict, or else roster.py's."""
    sp = rs.Space(r.log, keys=r.keyring())
    verdict = parent_verdict(sp.genesis_body.descriptor, held)
    if verdict is None:
        out = {r.name(r.genesis): "valid"}
        out.update(r.summary(sp, extra=False)["events"])
        return out
    return {r.name(i): verdict for i in r.log.canonical()}


def restricted_parent_vectors() -> list:
    g = rs.Roster("G", "ext-restricted/parent/G")
    p = rs.Roster("P", "ext-restricted/parent/P",
                  descriptor=spaces.encode_descriptor(spaces.KIND_RESTRICTED, g.id))
    held = {g.id: rs.Space(g.log, keys=g.keyring()).genesis_body.descriptor,
            p.id: rs.Space(p.log, keys=p.keyring()).genesis_body.descriptor}
    missing = example("ext-restricted/parent/a space not held")
    out = []
    for name, parent, expected in (
            ("a restricted space under G, whose genesis is held", g.id, "valid"),
            ("a restricted space whose parent's genesis is not held", missing, "Pending"),
            ("a restricted space whose parent P is restricted", p.id, "RestrictedParent")):
        f = rs.Roster("F", f"ext-restricted/parent/F/{expected}",
                      descriptor=spaces.encode_descriptor(spaces.KIND_RESTRICTED, parent))
        f.hist.view["F"] = set(f.log.events)
        f.grant("F", "W", rs.WRITE, label="F grants W write")
        events = judge(f, held)
        assert set(events.values()) == {expected}, (name, events)
        out.append({"name": name, "parent": h(parent),
                    "held_geneses": {h(k): spaces.KIND_NAMES[v["kind"]]
                                     for k, v in sorted(held.items())},
                    "log": [{"name": f.name(i), "signed": h(f.log.events[i].signed)}
                            for i in f.log.canonical()],
                    "rotation_content_keys": {f.name(i): h(k) for i, k in
                                              sorted(f.krot.items(),
                                                     key=lambda kv: f.log.order_key(kv[0]))},
                    "events": events})
    return out


# ---------------------------------------------------------------------------
# Membership and rotations of a restricted space.


def _members_json(members: dict) -> dict:
    return {d: {"level": spaces.LEVEL_NAMES[r.level], "propagates": r.propagates}
            for d, r in sorted(members.items())}


def restricted_membership_vectors() -> dict:
    """The reference deployment's F: dave is granted F and is not in P."""
    ref = spaces.reference_spaces()
    own = spaces.unrestricted(ref, spaces.PERSONS, "F")
    parent = spaces.effective(ref, spaces.PERSONS, "P")
    eff = spaces.effective(ref, spaces.PERSONS, "F")
    assert "d-laptop" in own and "d-laptop" not in eff
    return {"persons": spaces.PERSONS,
            "spaces": [{"name": s.name, "id": h(s.id), "kind": spaces.KIND_NAMES[s.kind],
                        "parent": s.parent,
                        "grants": [{"event": h(g.event), "kind": g.kind, "target": g.target,
                                    "level": spaces.LEVEL_NAMES[g.level],
                                    "session": g.session} for g in s.grants]}
                       for s in ref.values()],
            "F_own_roster": _members_json(own),
            "P": _members_json(parent),
            "F_effective": _members_json(eff),
            "not_in_P": sorted(d for d in own if d not in parent)}


def f_rotates(before: dict, after: dict, persons_before: dict, persons_after: dict) -> str:
    """"Keys of a restricted space": F rotates by keys.md's rules applied to
    its membership before P narrows it: a device lost, or one lowered to
    read. A change of P alone never rotates F."""
    old = spaces.unrestricted(before, persons_before, "F")
    new = spaces.unrestricted(after, persons_after, "F")
    lost = sorted(d for d in old if d not in new)
    lowered = sorted(d for d in old if d in new and old[d].level >= spaces.WRITE
                     and new[d].level < spaces.WRITE)
    if lost:
        return "rotates: loses " + ", ".join(lost)
    if lowered:
        return "rotates: lowers " + ", ".join(lowered) + " to read"
    return "keeps its key"


def _deployment() -> dict:
    """The reference deployment, with a space S that F grants at read."""
    ref = spaces.reference_spaces()
    s = spaces.Space("S", grants=[spaces.Grant(_eid("S/frank"), "person", "frank", spaces.WRITE)])
    f = ref["F"]
    ref["F"] = spaces.Space(f.name, f.kind, f.parent,
                            list(f.grants) + [spaces.Grant(_eid("F/S"), "space", "S",
                                                           spaces.READ)])
    ref["S"] = s
    return ref


def _edited(base: dict, space: str, *, drop=None, replace=None) -> dict:
    out = {n: spaces.Space(x.name, x.kind, x.parent, list(x.grants)) for n, x in base.items()}
    grants = out[space].grants
    if drop is not None:
        grants[:] = [g for g in grants if g.event != drop]
    if replace is not None:
        grants[:] = [replace if g.event == replace.event else g for g in grants]
    return out


def restricted_rotation_vectors() -> list:
    base = _deployment()
    persons = spaces.PERSONS
    with_phone = {**persons, "bob": ["b-laptop", "b-old-phone"]}
    ev = spaces._eid
    rows = []
    for change, why, before, after, pb, pa in (
            ("F removes dave, who is not in P", "a removal in F",
             base, _edited(base, "F", drop=ev("F/dave")), persons, persons),
            ("F lowers bob to read", "a demotion to read in F",
             base, _edited(base, "F", replace=spaces.Grant(ev("F/bob"), "person", "bob",
                                                           spaces.READ)), persons, persons),
            ("bob's device list revokes an old phone", "a revocation in the list of a person "
             "F grants", base, base, with_phone, persons),
            ("S, which F grants, removes frank", "a loss in a space F grants",
             base, _edited(base, "S", drop=_eid("S/frank")), persons, persons),
            ("P removes erin", "a change of P: P's next key already denies erin F's next key",
             base, _edited(base, "P", drop=ev("P/erin")), persons, persons),
            ("bob leaves T, which P grants", "a change of a space P grants",
             base, _edited(base, "T", drop=ev("T/bob")), persons, persons),
            ("P lowers its grant of T to read", "a change of P",
             base, _edited(base, "P", replace=spaces.Grant(ev("P/T"), "space", "T",
                                                           spaces.READ)), persons, persons)):
        rows.append({"change": change, "why": why,
                     "F": f_rotates(before, after, pb, pa),
                     "F_own_before": _members_json(spaces.unrestricted(before, pb, "F")),
                     "F_own_after": _members_json(spaces.unrestricted(after, pa, "F"))})
    assert [r["F"].split(":")[0] for r in rows] == ["rotates"] * 4 + ["keeps its key"] * 3, rows
    return rows


# ---------------------------------------------------------------------------
# The carve-out, moves and late writes.


def carve_out_vectors() -> dict:
    """spaces.py's carve-out, with the guest's wrap found by trial."""
    v = spaces.carve_out_vectors()
    c = v["carve_out"]
    admin = bytes.fromhex(c["creator"]["device_id"])
    guest = bytes.fromhex(c["guest"]["device_id"])
    n_id = bytes.fromhex(c["id"])
    payload = kg.read_payload(bytes.fromhex(c["payloads"]["admit"]), admin, 2)
    opened = kg.open_sealed(payload, bytes.fromhex(c["secrets"]["admit"]["content"]), n_id,
                            admin, 2)
    own = kg.self_ref(admin, 2)
    index, bundle = kg.find_own_wrap(opened["deliveries"][0]["wraps"], n_id, own, own, guest,
                                     bytes.fromhex(c["guest"]["hybrid_seed"]))
    assert "grant" not in bundle
    v["guest_wrap_by_trial"] = {"delivery": 0, "index": index, "bundle_holds": sorted(bundle),
                                "content": h(bundle["content"])}
    return v


def move_record_vectors() -> tuple[list, list]:
    f = spaces.format_vectors()
    refused = [{"name": m["name"], "record": m["record"], "class": m["error"]}
               for m in f["move_negative"]]
    return f["moves"], refused


def late_write_vectors() -> dict:
    """A Records document of P moves to N. Units of the original stream, the
    move unit aside, in the past of no accepted move unit are late; each is
    re-applied in N's stream by its author if it writes in N, and by no other
    device, so it shows once there."""
    p_space, n_space = example("ext-restricted/late/P"), example("ext-restricted/late/N")
    salt_p, salt_n = example("ext-restricted/late/salt P")[:16], \
        example("ext-restricted/late/salt N")[:16]
    stream_p = units.stream_id(units.TYPE_RECORDS, salt_p)
    stream_n = units.stream_id(units.TYPE_RECORDS, salt_n)
    devices = {n: example(f"ext-restricted/late/device {n}") for n in ("A", "B", "C", "G")}
    # Writer devices of N: G, the guest, writes in N but authored nothing in P,
    # and C, a writer of P, does not write in N.
    writers_n = ["A", "B", "G"]
    move = spaces.encode_move(n_space, stream_n, "Budget")
    t, r1 = "entries", b"row-1"
    spec = [  # name, author, parents, content or None for the move unit
        ("u1", "A", [], adapters.records_content(1, [[t, r1, "", [1]], [t, r1, "who", ["Ann"]]])),
        ("u2", "B", ["u1"], adapters.records_content(2, [[t, r1, "hours", [7]]])),
        ("m", "A", ["u2"], None),
        ("u3", "B", ["u2"], adapters.records_content(3, [[t, r1, "hours", [9]]])),
        ("u4", "C", ["u3"], adapters.records_content(4, [[t, r1, "who", ["Cy"]]])),
        ("u5", "A", ["m"], adapters.records_content(3, [[t, r1, "who", ["Ann B."]]])),
    ]
    ids = {n: _eid(f"late/{n}") for n, *_ in spec}
    past: dict = {}
    for name, _, parents, _ in spec:
        past[name] = set(parents).union(*(past[p] for p in parents)) if parents else set()
    late = [n for n, *_ in spec if n != "m" and n not in past["m"]]
    assert late == ["u3", "u4", "u5"], late
    rows = []
    inners = {}
    for name, author, parents, content in spec:
        inner = units.encode_inner(units.TYPE_MOVE if content is None else units.TYPE_RECORDS,
                                   move if content is None else content,
                                   opening=(units.TYPE_RECORDS, salt_p))
        inners[name] = inner
        rows.append({"name": name, "id": h(ids[name]), "author": author,
                     "parents": [h(ids[p]) for p in parents], "inner": h(inner),
                     "late": name in late})
    reapply = []
    for name in late:
        author = dict((n, a) for n, a, *_ in spec)[name]
        reapply.append({"late_write": name, "author": author,
                        "reapplied_by": author if author in writers_n else None})
    # B re-applies its own late write u3 in N's stream, with its own clock.
    ops = adapters.read_records(dict((n, c) for n, _, _, c in spec)["u3"])[3]
    content = adapters.records_content(1, ops)
    copied = units.encode_inner(units.TYPE_RECORDS, content, copied_from=[p_space, ids["u3"]],
                                opening=(units.TYPE_RECORDS, salt_n))
    value = units.read_inner(copied, False)
    assert value[units.I_COPIED_FROM] == [p_space, ids["u3"]]
    return {"original": {"space": h(p_space), "stream": h(stream_p), "salt": h(salt_p),
                         "type": units.TYPE_RECORDS},
            "new": {"space": h(n_space), "stream": h(stream_n), "salt": h(salt_n)},
            "move_record": h(move),
            "devices": {n: h(k) for n, k in devices.items()},
            "writers_of_N": writers_n,
            "units": rows, "late": late, "reapply": reapply,
            "reapplied": {"by": "B", "late_write": "u3", "content": h(content),
                          "inner": h(copied),
                          "copied_from": [h(p_space), h(ids["u3"])]}}


# ---------------------------------------------------------------------------
# The file.


def ext_restricted_spaces_vectors() -> dict:
    moves, refused = move_record_vectors()
    return {
        **kg.restricted_families(),
        "restricted_parent": restricted_parent_vectors(),
        "restricted_membership": restricted_membership_vectors(),
        "restricted_rotations": restricted_rotation_vectors(),
        "carve_out": carve_out_vectors(),
        "move_records": moves,
        "move_record_refusals": refused,
        "late_writes": late_write_vectors(),
    }


def self_test() -> None:
    assert parent_verdict({"kind": spaces.KIND_SPACE, "parent": None}, {}) is None
    v = ext_restricted_spaces_vectors()
    assert list(v) == ["restricted_keys", "reference_refusals", "restricted_space_event",
                       "restricted_names", "restricted_parent", "restricted_membership",
                       "restricted_rotations", "carve_out", "move_records",
                       "move_record_refusals", "late_writes"], list(v)
    assert len(v["move_records"]) == 2 and len(v["move_record_refusals"]) == 6
    assert v["carve_out"]["guest_wrap_by_trial"]["bundle_holds"] == ["content", "upload"]
    late = {r["late_write"]: r for r in v["late_writes"]["reapply"]}
    assert [late[n]["reapplied_by"] for n in ("u3", "u4", "u5")] == ["B", None, "A"], late
    try:
        spaces.read_move(bytes.fromhex(v["move_record_refusals"][0]["record"]))
        raise AssertionError("a refused move record was read")
    except SpecError:
        pass
    assert v == ext_restricted_spaces_vectors(), "the vectors are not deterministic"


if __name__ == "__main__":
    self_test()
    print("ext_restricted: self-test passed")
