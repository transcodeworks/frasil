"""Invite links (ext-invite-links.md), protocol 1: the vectors of
ext-invite-links.json, written from the specification, independently of
any implementation.

The constructions live where their core hooks are: the secret's keys, the
fragment, the drop, the invite grant, the successor and the claimant's
walk in admission.py; the drop's messages and a peer's drop store in
handshakes.py; member type 3, op 4, the race rule and attack (d) in
roster.py; who receives what in keygraph.py; invite_expiry in clocks.py.
This module assembles the families of the document's "Test vectors", and
adds the refused inputs with their bytes and the expiry decisions.
"""

from __future__ import annotations

import admission as adm
import clocks
import handshakes
import keygraph as kg
import roster
from events import cbor, h
from formats import example
from primitives import SpecError

LINK_LIFETIME_MAX = 604_800   # link_lifetime's maximum, 7 days
LINK_SKEW = 60                # link_skew (overview.md, "Every timer")
ROTATION_STEP = 2             # rotation_step's default
_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def _err(function, *args, **kw) -> str:
    try:
        function(*args, **kw)
    except SpecError as error:
        return error.error
    return "accepted"


def check_claim_expiry(expires_at: int, now_wall: int | None) -> str:
    """"Claiming", step 10: check_expiry(expires_at, the claimant's wall
    clock, 604,800, link_skew). "ok", or Expired or Malformed."""
    return clocks.check_expiry(expires_at, now_wall, LINK_LIFETIME_MAX, LINK_SKEW)


# ---------------------------------------------------------------------------
# Building histories on admission.py's helpers.


def _participant(r: roster.Roster, name: str, keys: dict, view) -> None:
    """The claimant signs as the invite key: a participant of the history
    whose keys the link's secret derives."""
    r.hist.keys[name] = keys["ed_seed"]
    r.hist.signers[name] = keys["signer"]
    r.hist.view[name] = set(view)


def _base(keys: dict, prefix: str, claims: int = roster.PERSON):
    r = roster.Roster("A", prefix)
    r.hist.view["A"] = set(r.log.events)
    r.grant("A", "B", roster.ADMINISTER, roster.WITH_HISTORY, label="A grants B administer")
    r.sync("A", "B")
    e = adm.admission_event(r, "A", [adm.invite_grant(keys, roster.WRITE, roster.FROM_NOW_ON,
                                                      adm.INVITE_EXPIRES, claims,
                                                      label="Invited")],
                            "A invites by link", brk=True,
                            recipients=[(keys["device_id"], keys["hybrid"], True, True)])
    r.sync("A", "B")
    _participant(r, "invite", keys, r.hist.view["A"])
    return r, e


def _claim(r: roster.Roster, member: tuple, label: str, device=None) -> bytes:
    return r.space_event("invite", label,
                         roster.update_roster([adm.successor(member, device)]), False)


# roster.py's cases, in the extension's vocabulary.
ROSTER_CASES = {
    "a late backdated claim after a close: void, and the honest claimant stands": (
        "a late claim after a close",
        "The inviter closes its invite once it holds a valid successor. A claim concurrent "
        "with the close is void by attack (a), so it races nothing. A replica that holds the "
        "late claim but not yet the close voids both until the close arrives."),
    "a late claim before any close voids both: the stated risk": (
        "a late claim before any close",
        "Until the inviter closes, a holder of the secret that claims concurrently voids the "
        "honest claim too. A close signed after both claims is concurrent with neither, so "
        "both stay void; it is then a revocation."),
    "re-submission covers units refused as NotAWriter through a voided grant": (
        "re-submission through a raced claim",
        "D wrote through its successor, which a raced claim voided, so its unit is "
        "NotAWriter; once D writes again it re-submits the unit."),
    "an invite from now on that does not rotate": (
        "an invite from now on that does not rotate",
        "An invite from now on is a break, and a break rotates."),
}


def _histories() -> list:
    """`histories`: admission.py's cases, with each event's status and the
    roster, then roster.py's, renamed."""
    out = []
    for name, case in adm.ext_invite_links_histories().items():
        if name == "a late claim after a close":
            continue  # roster.py's case shows it in two views
        out.append({"name": name, **case})
    built = roster.ext_invite_links_roster_cases()
    for case in built["histories"]:
        name, note = ROSTER_CASES[case["name"]]
        out.append({"name": name, "note": note,
                    **{k: v for k, v in case.items() if k not in ("name", "notes")}})
    for case in built["refused_events"]["cases"]:
        name, note = ROSTER_CASES[case["name"]]
        out.append({"name": name, "note": note, "base": built["refused_events"]["base"],
                    **{k: v for k, v in case.items() if k not in ("name", "notes")}})
    names = [c["name"] for c in out]
    assert len(names) == len(set(names)), names
    return out


# ---------------------------------------------------------------------------
# Refused inputs, each with its bytes.


def _links() -> list:
    """`links`: refused fragments, each with its text."""
    secret = adm._invite_secret()
    entry, space = example("admission/invite/entry"), example("admission/invite/space")
    good = adm.link_fragment(secret, entry, space)
    out = []
    for name, text in (
            ("a fragment of version 2",
             adm.link_fragment_raw(b"\x02" + secret + entry + space)),
            ("a fragment of version 0",
             adm.link_fragment_raw(b"\x00" + secret + entry + space)),
            ("a fragment with padding", good + "="),
            ("a fragment one byte short",
             adm.link_fragment_raw(b"\x01" + secret + entry + space[:-1])),
            ("a fragment one byte long",
             adm.link_fragment_raw(b"\x01" + secret + entry + space + b"\x00")),
            ("a fragment in standard base64", good.replace("-", "+").replace("_", "/") + "+"),
            ("a fragment whose last character sets a bit beyond the 97 bytes",
             good[:-1] + _B64[_B64.index(good[-1]) ^ 1]),
            ("an empty fragment", "")):
        out.append({"name": name, "fragment": text, "class": _err(adm.read_link_fragment, text)})
    return out


def _drops(derivations: dict) -> dict:
    secret = adm._invite_secret()
    sealed = adm.ext_invite_links_drops()
    drop = bytes.fromhex(sealed["drop"])
    nonce = bytes.fromhex(sealed["nonce"])
    wrap = bytes.fromhex(sealed["opened"]["wrap"])
    refused = []
    for name, key, data in (
            ("opened with another secret", example("admission/invite/other"), drop),
            ("39 bytes", secret, drop[:adm.DROP_MIN_BYTES - 1]),
            ("65,537 bytes", secret, drop + bytes(adm.DROP_MAX_BYTES - len(drop) + 1)),
            ("a damaged tag", secret, drop[:-1] + bytes([drop[-1] ^ 1])),
            ("a plaintext that is not a map", secret, adm.seal_drop(secret, cbor([1]), nonce)),
            ("version 2", secret,
             adm.seal_drop(secret, cbor({1: 2, 2: b"k", 3: b"", 4: wrap, 5: []}), nonce)),
            ("a wrap of 1,235 bytes", secret,
             adm.seal_drop(secret, cbor({1: 1, 2: b"k", 3: b"", 4: wrap[:-1], 5: []}), nonce)),
            ("nine peer hints", secret,
             adm.seal_drop(secret, cbor({1: 1, 2: b"k", 3: b"", 4: wrap,
                                         5: ["https://peer.example"] * 9}), nonce))):
        row = {"name": name, "secret": h(key), "class": _err(adm.open_drop, key, data)}
        if len(data) < 4096:
            row["drop"] = h(data)
        else:
            row["drop_prefix"] = h(data[:len(drop)])
            row["drop_bytes"] = len(data)
        refused.append(row)
    at_peer = handshakes.ext_invite_links_drops(bytes.fromhex(derivations["locator"]), drop,
                                                bytes.fromhex(derivations["space"]))
    assert at_peer["address"] == derivations["drop_address"]
    sealed.pop("refused_drops")
    return {"sealed": sealed, "refused_drops": refused, **at_peer}


def _refused_changes() -> list:
    """`refused_changes`: grants and successors refused by shape, with the
    change map each is."""
    keys = adm.invite_keys(adm._invite_secret())
    bob = example("admission/person/bob")
    out = []

    def add(name, change):
        out.append({"name": name, "change": h(cbor(change)),
                    "class": _err(adm.decode_change, change, bytes(32))})

    base = adm.invite_grant(keys, roster.WRITE, roster.FROM_NOW_ON, 1, roster.PERSON).value
    for name, changes in (
            ("an invite at administer", {2: roster.ADMINISTER}),
            ("an invite with no expires_at", {adm.C_EXPIRES: None}),
            ("an invite with no claims", {adm.C_CLAIMS: None}),
            ("an invite with via code", {6: roster.VIA_CODE}),
            ("a guest invite that a person claims", {7: bytes(16)}),
            ("an invite that a space claims", {adm.C_CLAIMS: roster.SPACE}),
            ("an invite that replaces", {8: bytes(32)}),
            ("an invite whose keys do not give K: another device's Ed25519 key",
             {12: adm.device_keys("x").identity})):
        m = dict(base)
        for k, v in changes.items():
            if v is None:
                m.pop(k)
            else:
                m[k] = v
        add(name, m)
    add("op 5", {0: 5, 1: [roster.PERSON, bob]})
    add("a change (op 1) of an invite", {0: roster.CHANGE, 1: [adm.INVITE, keys["device_id"]],
                                         2: roster.READ})
    add("a successor naming a level", {0: adm.SUCCEED, 1: [roster.PERSON, bob],
                                       2: roster.READ})
    add("a successor granting a space", {0: adm.SUCCEED, 1: [roster.SPACE, bob]})
    dev = adm.device_keys("claimant")
    add("a device successor without its keys", {0: adm.SUCCEED, 1: [roster.DEVICE,
                                                                     dev.device_id]})
    add("a person successor with device keys",
        {0: adm.SUCCEED, 1: [roster.PERSON, bob], 9: dev.hybrid, 10: dev.signer.mldsa_public,
         12: dev.identity})
    add("a device successor whose keys do not give its device ID",
        {0: adm.SUCCEED, 1: [roster.DEVICE, dev.device_id], 9: dev.hybrid,
         10: dev.signer.mldsa_public, 12: adm.device_keys("x").identity})
    return out


# ---------------------------------------------------------------------------
# Expiry: invite_expiry, the claimant's check, and the delays.


def _expiry() -> dict:
    decisions = clocks.decision_tables()["invite_expiry"]
    w = adm.INVITE_EXPIRES
    claimant = []
    for name, now in (("the claimant's wall clock is not known", None),
                      ("one second before expires_at", w - 1),
                      ("at expires_at", w),
                      ("one second after expires_at", w + 1),
                      ("expires_at at the furthest: 604,800 and link_skew ahead",
                       w - LINK_LIFETIME_MAX - LINK_SKEW),
                      ("expires_at one second beyond the furthest",
                       w - LINK_LIFETIME_MAX - LINK_SKEW - 1)):
        claimant.append({"case": name, "expires_at": w, "now_wall": now,
                         "lifetime": LINK_LIFETIME_MAX, "skew": LINK_SKEW,
                         "outcome": check_claim_expiry(w, now)})
    # The delays, over a space's administering devices: the close after a
    # successor, and the revocation at expiry.
    keys = adm.invite_keys(adm._invite_secret())
    r, e = _base(keys, "ext-invite-links/delays")
    s = _claim(r, (roster.PERSON, example("admission/person/bob")), "Bob claims")
    admins = {r.hist.device("A"): "A", r.hist.device("B"): "B"}
    delays = []
    for act, trigger, inviter_at_once in (("the close", s, True),
                                          ("the revocation at expiry", e, False)):
        order = kg.rank_order(r.id, trigger, sorted(admins))
        rows = []
        for position, device in enumerate(order):
            at_once = inviter_at_once and admins[device] == "A"
            rows.append({"device": admins[device], "device_id": h(device), "position": position,
                         "delay_seconds": 0 if at_once else
                         clocks.rotation_delay(position, ROTATION_STEP),
                         **({"note": "the inviter's client closes at once"} if at_once else {})})
        delays.append({"act": act, "trigger": h(trigger), "space": h(r.id),
                       "rotation_step": ROTATION_STEP, "devices": rows})
    return {"link_lifetime_max": LINK_LIFETIME_MAX, "link_skew": LINK_SKEW,
            "invite_expiry": decisions, "claimant_check": claimant, "delays": delays}


# ---------------------------------------------------------------------------
# The file.


def ext_invite_links_vectors() -> dict:
    derivations = adm.ext_invite_links_derivations()
    return {
        "derivations": derivations,
        "links": _links(),
        "drops": _drops(derivations),
        "encodings": adm.ext_invite_links_encodings(),
        "refused_changes": _refused_changes(),
        "histories": _histories(),
        "claims": adm.ext_invite_links_claims(),
        "keys": kg.invite_keys_family(),
        "expiry": _expiry(),
    }


def self_test() -> None:
    assert check_claim_expiry(100, None) == "Expired"
    assert check_claim_expiry(100 + LINK_LIFETIME_MAX + LINK_SKEW, 100) == "ok"
    assert check_claim_expiry(101 + LINK_LIFETIME_MAX + LINK_SKEW, 100) == "Malformed"
    v = ext_invite_links_vectors()
    links = {x["name"]: x["class"] for x in v["links"]}
    assert links["a fragment of version 2"] == "UnsupportedVersion"
    assert all(c in ("Malformed", "UnsupportedVersion") for c in links.values()), links
    assert [x["class"] for x in v["drops"]["refused_drops"]] == [
        "Decrypt", "Malformed", "Malformed", "Decrypt", "Malformed", "UnsupportedVersion",
        "Malformed", "Malformed"], v["drops"]["refused_drops"]
    assert all(x["class"] != "accepted" for x in v["refused_changes"]), v["refused_changes"]
    hs_ = {c["name"]: c for c in v["histories"]}
    assert hs_["a claim after a race"]["events"]["Dan claims after the race"] == "InviteUsed"
    late = hs_["a late claim before any close"]["views"]["before the revocation"]["events"]
    assert late["Bob claims"] == "ClaimRaced", late
    assert [x["outcome"] for x in v["expiry"]["claimant_check"]] == [
        "Expired", "ok", "ok", "Expired", "ok", "Malformed"]
    assert v == ext_invite_links_vectors(), "the vectors are not deterministic"


if __name__ == "__main__":
    self_test()
    print("ext_invite_links: self-test passed")
