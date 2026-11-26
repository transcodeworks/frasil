"""Time (overview.md, "Time"): the local timeline, the two estimates of
elapsed time, every timer, check_expiry and check_policy, and each timed rule
of the other documents as a decision from its inputs.

Nothing here reads a real clock. Every function takes the readings it
decides from, so the vectors are tables of inputs and outcomes. No timed
rule decides whether a signed event is valid: each decides only what one
device does next (sign, wrap, write, claim, erase, reclaim), and a peer's
rules only what the peer does with its own storage. Time adds no label.
"""

from __future__ import annotations

import math

NEW_LABELS: list[bytes] = []

MINUTE = 60
HOUR = 60 * MINUTE
DAY = 24 * HOUR

# ---------------------------------------------------------------------------
# overview.md, "Every timer", in seconds. `default` is None where the
# document gives no number ("default_text" then says what it gives);
# `minimum` and `maximum` are None where the range has no such bound.


def _t(name, bounds, default, minimum, maximum, set_by, counted, in_, default_text=None):
    row = {"name": name, "bounds": bounds, "default": default, "minimum": minimum,
           "maximum": maximum, "set_by": set_by, "counted": counted, "in": in_}
    if default_text is not None:
        row["default_text"] = default_text
    return row


PARAMETERS = [
    _t("admission_code_lifetime", "an admission code request", 900, 900, 900, "protocol",
       "wall, the joiner's clock", ["admission.md"]),
    _t("admission_code_skew", "an admission code request", 60, 60, 60, "protocol", "wall",
       ["admission.md"]),
    _t("exchange_mailbox_lifetime", "an exchange mailbox", None, None, 1020, "the peer",
       "the peer's timeline", ["transport.md"], "expires_at + 60; at most 1,020 after the request"),
    _t("gap_key_timeout", "a restored member's gap keys; keeping a refused unit's content; "
       "settling a snapshot; a replica dropping erased content without stability", 7 * DAY, HOUR,
       90 * DAY, "space policy", "lower, from each holder's first sight of the restoring merge, "
       "the refusing event, the snapshot or the erasure",
       ["keys.md", "roster.md", "units.md", "peers.md"]),
    _t("rotation_step", "the cascade delay, per rank", 2, 1, 10, "the implementation",
       "lower, from first sight of the trigger", ["keys.md"]),
    _t("rotation_rank_cap", "the highest rank the delay counts", 63, 63, 63, "protocol", None,
       ["keys.md"]),
    _t("anchor_interval", "anchors", DAY, HOUR, 7 * DAY, "the implementation",
       "lower, from the device's last anchor in the space", ["crypto.md"]),
    _t("replica_release_retention", "release at a replica", 30 * DAY, 30 * DAY, None,
       "the application", "lower, from first sight of the release", ["units.md"]),
    _t("erasure_timeout", "erasure, credentials requests, reclaiming a release and collection, "
       "without stability at the peer", 7 * DAY, HOUR, 90 * DAY, "the operator",
       "lower, the peer's, from acceptance", ["peers.md"]),
    _t("release_retention", "release at a peer", 30 * DAY, 0, 365 * DAY, "the operator",
       "lower, the peer's, from acceptance", ["peers.md"]),
    _t("orphan_grace", "an object no unit references", DAY, HOUR, 30 * DAY, "the operator",
       "lower, the peer's, from first sight of the object", ["peers.md"]),
    _t("file_version_retention", "an old version of a file, superseded at every listing",
       7 * DAY, 0, 365 * DAY, "the operator",
       "lower, the peer's, from first sight of the earliest superseding unit",
       ["ext-file-versions.md"]),
    _t("version_compaction_interval", "compacting a Blobs stream whose units since its last "
       "snapshot carry supersessions", DAY, HOUR, 7 * DAY, "the implementation",
       "lower, from the client's first sight of the first such unit",
       ["ext-file-versions.md"]),
    _t("handshake_deadline", "a handshake, to the first Admit or refusal", 10, 10, 10, "protocol",
       "monotonic", ["transport.md"]),
    _t("probation", "an unknown member after a proven key state", 30, 30, 30, "protocol",
       "monotonic", ["transport.md"], "30, and 4,096 events"),
    _t("endpoint_rotation", "a device's member endpoint key", DAY, None, DAY, "the implementation",
       "the device's timeline", ["transport.md"], "24 hours, and at each new network"),
    _t("gossip_interval", "head gossip and member addresses, per attach", 5, 5, None, "the implementation",
       "monotonic", ["transport.md"]),
    _t("withholding_grace", "a peer's Missing for a head statement's heads before it shows "
       "withholding", 300, 60, 3600, "the implementation",
       "monotonic, from the peer's first Missing for them", ["units.md"]),
    _t("present_retry", "presenting a refused read credential again", 1, 1, 30,
       "the implementation", "monotonic", ["transport.md"]),
    _t("reconnect_wait", "the random wait before the first attempt after a reconnect close", 5,
       5, 5, "protocol", "monotonic", ["transport.md"]),
    _t("reconnect_wait_cap", "the bound of that wait, doubled after each failed attempt", 60,
       60, 60, "protocol", "monotonic", ["transport.md"]),
    _t("reconnect_drain", "a stopping peer's wait for an import or a pending create before it "
       "drops the connection", 60, 0, 600, "the operator", "monotonic", ["transport.md"]),
    _t("pairing_deadline", "nearby pairing", 90, 90, 90, "protocol", "monotonic",
       ["transport.md"]),
    _t("mailbox_retention", "a person's or a device's mailbox", None, None, 30 * DAY,
       "the operator", "the peer's timeline", ["transport.md"], "the operator's"),
    _t("uncollected_retention", "an item of a device mailbox that is not claimed", 72 * HOUR,
       HOUR, 30 * DAY, "the operator", "the peer's timeline, from the deposit",
       ["transport.md"]),
    _t("welcome_retention", "a welcome its signer keeps waiting to hand over or deposit",
       30 * DAY, 30 * DAY, 30 * DAY, "protocol", "the signer's timeline, from keeping it",
       ["admission.md", "at-rest.md"]),
    _t("link_lifetime", "an invite, ended by a revocation", 7 * DAY, 15 * MINUTE, 7 * DAY,
       "the inviter's client", "wall, the inviter's clock; lower, from each administering "
       "device's first sight, for the maximum", ["ext-invite-links.md"]),
    _t("session_lifetime", "a guest session, ended by a removal", None, 15 * MINUTE, 30 * DAY,
       "the granter's client", "as link_lifetime", ["ext-guests.md"], "none"),
    _t("bounded_window", "writing without hearing from another member", None, HOUR, 90 * DAY,
       "space policy", "upper, from the signing of this device's newest event another member "
       "has followed", ["ext-guests.md"], "off"),
    _t("online_freshness", "writing without a recent sync with a peer of the space", None, 30,
       HOUR, "space policy", "upper, from the last completed sync", ["ext-guests.md"],
       "off; 300 when on"),
    _t("agent_waiting_period", "trusting a device an agent added", 72 * HOUR, 72 * HOUR,
       30 * DAY, "space policy", "lower, from each verifier's first sight of the add",
       ["ext-recovery-agent.md"]),
    _t("ephemeral_send_deadline", "an ephemeral frame in its sender's queue", 2, 2, 2,
       "protocol", "monotonic", ["ext-ephemeral.md"]),
    _t("ephemeral_key_wait", "ephemeral frames held for a rotation the receiver lacks", 5, 5, 5,
       "protocol", "monotonic", ["ext-ephemeral.md"]),
    _t("ticket_lifetime", "a library ticket", None, None, DAY, "the issuer",
       "wall, the peer's clock", ["ext-libraries.md"], "the issuer's"),
    _t("ticket_skew", "a library ticket", 60, 60, 60, "protocol", "wall", ["ext-libraries.md"]),
    _t("detached_grace", "a detached space's data at a peer", 30 * DAY, DAY, 365 * DAY,
       "the operator", "lower, the peer's, from detachment", ["ext-libraries.md"]),
    _t("token_period", "a deposit key's issuing, then its accepting only", 7 * DAY, DAY,
       30 * DAY, "the operator", "upper, the keys' shard's, from the key's start: issuing for one period, "
       "then accepting only until two have passed",
       ["ext-deposit-tokens.md"]),
    _t("allowance_window", "a library's deposit allowance", DAY, DAY, DAY, "protocol",
       "lower, the library's, from the window's first draw", ["ext-deposit-tokens.md"]),
    _t("signed_request_lifetime", "a device-signed request", 60, 60, 60, "protocol",
       "wall, the signer's clock", ["ext-app-requests.md"]),
    _t("signed_request_skew", "a device-signed request", 60, 60, 60, "protocol", "wall",
       ["ext-app-requests.md"]),
]
_BY_NAME = {p["name"]: p for p in PARAMETERS}
ONLINE_FRESHNESS_WHEN_ON = 300

# The space-policy values every replica checks; a client checks the two
# lifetimes the same way before it signs an expiry.
POLICY_PARAMETERS = ("gap_key_timeout", "bounded_window", "online_freshness",
                     "agent_waiting_period")


def check_policy(name: str, value) -> str:
    """overview.md, check_policy, in order: "ok" or "Malformed"."""
    p = _BY_NAME[name]
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return "Malformed"
    if (p["minimum"] is not None and value < p["minimum"]) or \
            (p["maximum"] is not None and value > p["maximum"]):
        return "Malformed"
    return "ok"


parameter_check = check_policy


# ---------------------------------------------------------------------------
# The local timeline.


class Timeline:
    """The local timeline of one device.

    It is a count of seconds; only differences between readings mean
    anything. While the device runs it follows the monotonic clock, so a
    change to the wall clock is not counted. Each reading is kept with the
    wall clock's value at that moment. At a start (and at a resume after a
    suspend in which the monotonic clock stopped), the timeline adds the
    wall clock's advance since the last kept reading, never less than zero;
    a device whose wall clock is not known to be set adds nothing. A reading
    holds the wall clock whenever it is known at that moment, even if it was
    not at the start."""

    def __init__(self) -> None:
        self.kept: tuple[int, int | None] | None = None  # (timeline, wall)
        self.run = 0
        self._base: int | None = None
        self._mono0: int | None = None

    def start(self, wall: int | None, mono: int) -> None:
        self.run += 1
        if self.kept is None:
            base = 0
        else:
            last_tl, last_wall = self.kept
            if wall is not None and last_wall is not None:
                base = last_tl + max(0, wall - last_wall)
            else:
                base = last_tl
        self._base, self._mono0 = base, mono
        self.kept = (base, wall)

    resume = start

    def read(self, mono: int, wall: int | None) -> dict:
        assert self._base is not None and mono >= self._mono0
        tl = self._base + (mono - self._mono0)
        self.kept = (tl, wall)
        return {"timeline": tl, "wall": wall, "run": self.run}


def elapsed_lower(since: dict, now: dict) -> float:
    """The lower estimate, the timeline's advance."""
    return now["timeline"] - since["timeline"]


def elapsed_upper(since: dict, now: dict) -> float:
    """The upper estimate, the larger of the timeline's and the
    wall clock's advance; unbounded across a restart of a device whose wall
    clock is not known."""
    lower = elapsed_lower(since, now)
    if since["wall"] is not None and now["wall"] is not None:
        return max(lower, now["wall"] - since["wall"])
    if since["run"] == now["run"]:
        return lower
    return math.inf


# ---------------------------------------------------------------------------
# The rules.


def check_expiry(expires_at: int, now_wall: int | None, lifetime: int, skew: int) -> str:
    """overview.md, check_expiry, in order: "ok", "Expired" or "Malformed".
    A receiver whose wall clock is not known refuses."""
    if now_wall is None:
        return "Expired"
    if expires_at > now_wall + lifetime + skew:
        return "Malformed"
    if now_wall > expires_at:
        return "Expired"
    return "ok"


expiry_check = check_expiry


def agent_waiting_period(first_sight: dict, now: dict, period: int,
                         confirmed: bool = False, vetoed: bool = False) -> str:
    """ext-recovery-agent.md, agent_waiting: whether this verifier vouches
    for a device an agent added."""
    if vetoed:
        return "Vetoed"
    if confirmed:
        return "Vouched"
    return "Vouched" if elapsed_lower(first_sight, now) >= period else "Waiting"


def bounded_window(acknowledged: dict, now: dict, window: int) -> str:
    """ext-guests.md: "MayWrite" or "WindowElapsed". `acknowledged` is this device's own
    reading when it signed the newest of its events that an accepted event of
    another member follows: never the time an event arrived."""
    return "MayWrite" if elapsed_upper(acknowledged, now) < window else "WindowElapsed"


def heartbeat(last_signed: dict, last_heartbeat: dict | None, now: dict, window: int,
              unanswered: bool) -> str:
    """ext-guests.md: whether a device under the bounded window signs an anchor as a
    heartbeat: "Heartbeat" or "Wait". At most one per half window."""
    half = window // 2
    if last_heartbeat is not None and elapsed_lower(last_heartbeat, now) < half:
        return "Wait"
    if elapsed_upper(last_signed, now) >= half or unanswered:
        return "Heartbeat"
    return "Wait"


def acknowledged(own_signed: dict, followers: list[dict]) -> dict | None:
    """ext-guests.md: the reading at which this device signed the newest of its own
    events that a counting event follows. `own_signed` maps each of this
    device's events to the reading when it signed it; each follower is
    {"follows": an own event in its past, "valid": a valid event,
    "member": its author a member at its place, "other": another device}."""
    best = None
    for f in followers:
        if f["valid"] and f["member"] and f["other"]:
            reading = own_signed[f["follows"]]
            if best is None or reading["timeline"] > best["timeline"]:
                best = reading
    return best


def online_only(last_sync: dict | None, now: dict, freshness: int) -> str:
    """ext-guests.md: "MayWrite" or "NotOnline". A last_sync kept at rest counts across
    a restart, on the upper estimate."""
    if last_sync is None:
        return "NotOnline"
    return "MayWrite" if elapsed_upper(last_sync, now) < freshness else "NotOnline"


def invite_expiry(expires_at: int, first_sight: dict, now: dict,
                  lifetime_max: int = 7 * DAY) -> str:
    """ext-invite-links.md, at an administering device: "Revoke" once the wall clock passes
    expires_at or the device has held the open invite for the maximum."""
    if now["wall"] is not None and now["wall"] >= expires_at:
        return "Revoke"
    if elapsed_lower(first_sight, now) >= lifetime_max:
        return "Revoke"
    return "Open"


def may_claim(expires_at: int, now_wall: int | None) -> str:
    """ext-invite-links.md, at a claimant: a courtesy, never a validity check."""
    if now_wall is not None and now_wall > expires_at:
        return "Expired"
    return "Claim"


def session_expiry(expires_at: int | None, first_sight: dict, now: dict,
                   lifetime_max: int = 30 * DAY) -> str:
    """ext-guests.md, at an administering device: "Remove" or "Open". A session with
    no expiry is ended only by an application's removal."""
    if expires_at is None:
        return "Open"
    if now["wall"] is not None and now["wall"] >= expires_at:
        return "Remove"
    if elapsed_lower(first_sight, now) >= lifetime_max:
        return "Remove"
    return "Open"


def erasure(stable: bool, accepted: dict, now: dict, timeout: int) -> str:
    """peers.md, at a peer: "Execute" once stable or after T."""
    if stable or elapsed_lower(accepted, now) >= timeout:
        return "Execute"
    return "Wait"


def gap_keys(stable: bool, first_sight: dict, now: dict, timeout: int) -> str:
    """keys.md, at a replica holding gap keys: "Wrap" once stable or after T_gap."""
    if stable or elapsed_lower(first_sight, now) >= timeout:
        return "Wrap"
    return "Wait"


def refused_unit(stable: bool, first_sight: dict, now: dict, timeout: int, own: bool) -> str:
    """roster.md: whether a replica may drop a refused unit's content. Storage,
    never validity: the author always keeps its own."""
    if own:
        return "Keep"
    if stable or elapsed_lower(first_sight, now) >= timeout:
        return "MayDrop"
    return "Keep"


def release(stable: bool, released: dict, now: dict, retention: int,
            timeout: int | None = None) -> str:
    """units.md and peers.md: "Reclaim" only after the retention, and once stable or, at a
    peer, after T (`timeout`), which stands in where a slot never signs. A
    replica passes no T."""
    waited = elapsed_lower(released, now)
    if waited >= retention and (stable or (timeout is not None and waited >= timeout)):
        return "Reclaim"
    return "Keep"


def collect(cancelled: bool, stable: bool, seen: dict, now: dict, timeout: int) -> str:
    """peers.md, at a peer: a snapshot's cover."""
    if cancelled:
        return "Keep"
    if stable or elapsed_lower(seen, now) >= timeout:
        return "Collect"
    return "Keep"


def orphan(referenced: bool, first_sight: dict, now: dict, grace: int) -> str:
    """peers.md, at a peer: an object no unit lists."""
    if referenced:
        return "Keep"
    if elapsed_lower(first_sight, now) >= grace:
        return "Collect"
    return "Keep"


def rotation_delay(rank: int, step: int = 2) -> int:
    """keys.md: the seconds an informed writer of rank `rank` (0 first) waits
    before it rotates an inheriting space."""
    assert rank >= 0
    return min(rank, _BY_NAME["rotation_rank_cap"]["default"]) * step


def anchor_due(last_anchor: dict | None, now: dict, interval: int, uncovered: bool) -> str:
    """crypto.md, "Anchors and coverage", timed here: "Anchor" or "Wait"."""
    if not uncovered:
        return "Wait"
    if last_anchor is None or elapsed_lower(last_anchor, now) >= interval:
        return "Anchor"
    return "Wait"


# ---------------------------------------------------------------------------
# Vectors.

WALL0 = 1_790_000_000  # 2026-09-21T13:46:40Z: any instant would do


def _scenario(description: str, steps: list) -> dict:
    t = Timeline()
    out = []
    for step in steps:
        action = step[0]
        if action in ("start", "resume"):
            getattr(t, action)(step[1], step[2])
            out.append({"action": action, "wall": step[1], "mono": step[2]})
        else:
            reading = t.read(step[1], step[2])
            out.append({"action": "read", "mono": step[1], "wall": step[2], "reading": reading})
    return {"description": description, "steps": out}


def _readings(scenario: dict) -> list[dict]:
    return [s["reading"] for s in scenario["steps"] if s["action"] == "read"]


def _timelines() -> tuple[list, list]:
    w = WALL0
    scenarios = [
        _scenario("a run with no jumps", [
            ("start", w, 50), ("read", 50, w), ("read", 110, w + 60), ("read", 3650, w + 3600)]),
        _scenario("the wall clock jumps forward an hour while the device runs: not counted", [
            ("start", w, 0), ("read", 10, w + 10), ("read", 20, w + 3620), ("read", 30, w + 3630)]),
        _scenario("the wall clock jumps back an hour while the device runs: not counted", [
            ("start", w, 0), ("read", 10, w + 10), ("read", 20, w - 3580), ("read", 30, w - 3570)]),
        _scenario("a restart after a day switched off: the day counts", [
            ("start", w, 0), ("read", 100, w + 100),
            ("start", w + 100 + DAY, 7), ("read", 7, w + 100 + DAY), ("read", 67, w + 160 + DAY)]),
        _scenario("a restart after the clock was set back while off: the time off counts as zero", [
            ("start", w, 0), ("read", 100, w + 100),
            ("start", w - 7200, 3), ("read", 3, w - 7200), ("read", 63, w - 7140)]),
        _scenario("a jump while running, then a restart: only the time off counts", [
            ("start", w, 0), ("read", 100, w + 100), ("read", 110, w + 3710),
            ("start", w + 3710 + 600, 0), ("read", 0, w + 4310)]),
        _scenario("a device whose wall clock is not known (no battery-backed clock, no time sync)", [
            ("start", None, 0), ("read", 100, None),
            ("start", None, 0), ("read", 0, None), ("read", 50, None)]),
        _scenario("a suspend that stops the monotonic clock is a resume", [
            ("start", w, 0), ("read", 100, w + 100),
            ("resume", w + 3700, 100), ("read", 100, w + 3700), ("read", 160, w + 3760)]),
        _scenario("a wall clock that becomes known while the device runs is read from then on", [
            ("start", None, 0), ("read", 100, None), ("read", 200, w + 200),
            ("start", w + 200 + HOUR, 0), ("read", 0, w + 200 + HOUR)]),
    ]

    # Estimates between readings of the scenarios above.
    estimates = []
    for scenario, pairs in ((scenarios[1], [(0, 2)]), (scenarios[3], [(0, 1), (0, 2)]),
                            (scenarios[4], [(0, 2)]), (scenarios[6], [(0, 2), (1, 2)])):
        readings = _readings(scenario)
        for a, b in pairs:
            lower = elapsed_lower(readings[a], readings[b])
            upper = elapsed_upper(readings[a], readings[b])
            estimates.append({
                "scenario": scenario["description"], "since": readings[a], "now": readings[b],
                "lower": lower, "upper": "unbounded" if math.isinf(upper) else upper,
            })

    return scenarios, estimates


def _r(tl, wall, run=1):
    return {"timeline": tl, "wall": wall, "run": run}


def decision_tables() -> dict:
    """Each timed rule of the other documents, as a table of inputs and
    outcomes. The document that owns a rule takes its table into its own
    vectors."""
    w = WALL0
    r = _r
    decisions = {}
    decisions["agent_waiting_period"] = [
        {"first_sight": fs, "now": now, "period": p, "confirmed": c, "vetoed": v,
         "outcome": agent_waiting_period(fs, now, p, c, v)}
        for fs, now, p, c, v in [
            (r(0, w), r(72 * HOUR - 1, w + 72 * HOUR - 1), 72 * HOUR, False, False),
            (r(0, w), r(72 * HOUR, w + 72 * HOUR), 72 * HOUR, False, False),
            (r(0, w), r(72 * HOUR, w + 72 * HOUR), 7 * DAY, False, False),
            (r(0, w), r(HOUR, w + HOUR), 72 * HOUR, True, False),
            (r(0, w), r(80 * HOUR, w + 80 * HOUR), 72 * HOUR, False, True),
            # A late verifier: its first sight is 10 days after the entry.
            (r(10 * DAY, w + 10 * DAY), r(11 * DAY, w + 11 * DAY), 72 * HOUR, False, False),
            # The wall clock says 3 days, the timeline 1 hour: it waits.
            (r(0, w), r(HOUR, w + 72 * HOUR), 72 * HOUR, False, False),
        ]
    ]
    decisions["bounded_window"] = [
        {"last_heard": lh, "now": now, "window": win, "outcome": bounded_window(lh, now, win)}
        for lh, now, win in [
            (r(0, w), r(DAY - 1, w + DAY - 1), DAY),
            (r(0, w), r(DAY, w + DAY), DAY),
            # The timeline says an hour, the wall clock two days: it stops.
            (r(0, w), r(HOUR, w + 2 * DAY), DAY),
            # The wall clock went back: the timeline still counts.
            (r(0, w), r(DAY, w - DAY), DAY),
            # An unknown wall clock across a restart: it stops.
            (r(0, None, 1), r(5, None, 2), DAY),
            (r(0, None, 1), r(5, None, 1), DAY),
        ]
    ]
    decisions["heartbeat"] = [
        {"last_signed": ls, "last_heartbeat": lh, "now": now, "window": win, "unanswered": u,
         "outcome": heartbeat(ls, lh, now, win, u)}
        for ls, lh, now, win, u in [
            (r(0, w), None, r(HOUR, w + HOUR), DAY, False),
            (r(0, w), None, r(12 * HOUR, w + 12 * HOUR), DAY, False),
            (r(0, w), None, r(HOUR, w + HOUR), DAY, True),
            # An answer within half a window of its own last heartbeat waits.
            (r(0, w), r(6 * HOUR, w + 6 * HOUR), r(13 * HOUR, w + 13 * HOUR), DAY, True),
            (r(0, w), r(6 * HOUR, w + 6 * HOUR), r(18 * HOUR, w + 18 * HOUR), DAY, True),
        ]
    ]
    decisions["online_only"] = [
        {"last_sync": ls, "now": now, "freshness": f, "outcome": online_only(ls, now, f)}
        for ls, now, f in [
            (None, r(0, w), 300),
            (r(0, w), r(299, w + 299), 300),
            (r(0, w), r(300, w + 300), 300),
            # Kept at rest across a quick restart, with a known wall clock.
            (r(0, w, 1), r(70, w + 70, 2), 300),
            # Across a restart without a known wall clock: sync again.
            (r(0, None, 1), r(5, None, 2), 300),
        ]
    ]
    own = {"e1": r(0, w), "e2": r(HOUR, w + HOUR), "e3": r(2 * HOUR, w + 2 * HOUR)}
    decisions["acknowledged"] = [
        {"own_signed": own, "followers": fs, "acknowledged": acknowledged(own, fs)}
        for fs in [
            [{"follows": "e1", "valid": True, "member": True, "other": True},
             {"follows": "e2", "valid": True, "member": True, "other": True}],
            # A removed device's event, and a void one, follow e3: neither counts.
            [{"follows": "e1", "valid": True, "member": True, "other": True},
             {"follows": "e3", "valid": True, "member": False, "other": True},
             {"follows": "e3", "valid": False, "member": True, "other": True}],
            # This device's own later event does not acknowledge it.
            [{"follows": "e3", "valid": True, "member": True, "other": False}],
        ]
    ]
    decisions["invite_expiry"] = [
        {"expires_at": e, "first_sight": fs, "now": now, "outcome": invite_expiry(e, fs, now)}
        for e, fs, now in [
            (w + DAY, r(0, w), r(HOUR, w + HOUR)),
            (w + DAY, r(0, w), r(DAY, w + DAY)),
            # An expiry beyond the maximum: the device revokes 7 days after first sight.
            (w + 30 * DAY, r(0, w), r(7 * DAY, w + 7 * DAY)),
            # A device whose wall clock is unknown still revokes at the maximum.
            (w + DAY, r(0, None), r(7 * DAY, None)),
        ]
    ]
    decisions["may_claim"] = [
        {"expires_at": e, "now_wall": n, "outcome": may_claim(e, n)}
        for e, n in [(w + 60, w), (w + 60, w + 60), (w + 60, w + 61)]
    ]
    decisions["session_expiry"] = [
        {"expires_at": e, "first_sight": fs, "now": now, "outcome": session_expiry(e, fs, now)}
        for e, fs, now in [
            (None, r(0, w), r(60 * DAY, w + 60 * DAY)),
            (w + 2 * HOUR, r(0, w), r(HOUR, w + HOUR)),
            (w + 2 * HOUR, r(0, w), r(2 * HOUR, w + 2 * HOUR)),
            (w + 90 * DAY, r(0, w), r(30 * DAY, w + 30 * DAY)),
        ]
    ]
    decisions["erasure"] = [
        {"stable": s, "accepted": a, "now": now, "timeout": t, "outcome": erasure(s, a, now, t)}
        for s, a, now, t in [
            (True, r(0, w), r(1, w + 1), 7 * DAY),
            (False, r(0, w), r(7 * DAY - 1, w + 7 * DAY - 1), 7 * DAY),
            (False, r(0, w), r(7 * DAY, w + 7 * DAY), 7 * DAY),
            (False, r(0, w), r(HOUR, w + HOUR), HOUR),
        ]
    ]
    decisions["gap_keys"] = [
        {"stable": s, "first_sight": fs, "now": now, "timeout": t, "outcome": gap_keys(s, fs, now, t)}
        for s, fs, now, t in [
            (True, r(0, w), r(1, w + 1), 7 * DAY),
            (False, r(0, w), r(6 * DAY, w + 6 * DAY), 7 * DAY),
            (False, r(0, w), r(7 * DAY, w + 7 * DAY), 7 * DAY),
        ]
    ]
    decisions["refused_unit"] = [
        {"stable": st, "first_sight": fs, "now": now, "timeout": t, "own": own,
         "outcome": refused_unit(st, fs, now, t, own)}
        for st, fs, now, t, own in [
            (True, r(0, w), r(1, w + 1), 7 * DAY, False),
            # An organisation space: never stable; dropped after the timeout.
            (False, r(0, w), r(6 * DAY, w + 6 * DAY), 7 * DAY, False),
            (False, r(0, w), r(7 * DAY, w + 7 * DAY), 7 * DAY, False),
            # The author keeps its own, whatever the time.
            (True, r(0, w), r(400 * DAY, w + 400 * DAY), 7 * DAY, True),
        ]
    ]
    decisions["release"] = [
        {"stable": s, "released": rel, "now": now, "retention": ret, "timeout": t,
         "outcome": release(s, rel, now, ret, t)}
        for s, rel, now, ret, t in [
            (True, r(0, w), r(29 * DAY, w + 29 * DAY), 30 * DAY, None),
            (True, r(0, w), r(30 * DAY, w + 30 * DAY), 30 * DAY, None),
            (False, r(0, w), r(90 * DAY, w + 90 * DAY), 30 * DAY, None),
            (True, r(0, w), r(0, w), 0, None),
            # At a peer of an organisation space: never stable; T stands in.
            (False, r(0, w), r(30 * DAY, w + 30 * DAY), 30 * DAY, 7 * DAY),
            (False, r(0, w), r(HOUR, w + HOUR), 0, 7 * DAY),
        ]
    ]
    decisions["collect"] = [
        {"cancelled": c, "stable": st, "seen": seen, "now": now, "timeout": t,
         "outcome": collect(c, st, seen, now, t)}
        for c, st, seen, now, t in [
            (False, True, r(0, w), r(1, w + 1), 7 * DAY),
            (False, False, r(0, w), r(7 * DAY - 1, w + 7 * DAY - 1), 7 * DAY),
            (False, False, r(0, w), r(7 * DAY, w + 7 * DAY), 7 * DAY),
            (True, True, r(0, w), r(30 * DAY, w + 30 * DAY), 7 * DAY),
        ]
    ]
    decisions["orphan"] = [
        {"referenced": ref, "first_sight": fs, "now": now, "grace": g,
         "outcome": orphan(ref, fs, now, g)}
        for ref, fs, now, g in [
            (False, r(0, w), r(DAY - 1, w + DAY - 1), DAY),
            (False, r(0, w), r(DAY, w + DAY), DAY),
            (True, r(0, w), r(30 * DAY, w + 30 * DAY), DAY),
        ]
    ]
    decisions["rotation_delay"] = [
        {"rank": rank, "step": step, "delay": rotation_delay(rank, step)}
        for rank, step in [(0, 2), (1, 2), (10, 2), (63, 2), (64, 2), (89, 2), (89, 10)]
    ]
    decisions["anchor_due"] = [
        {"last_anchor": la, "now": now, "interval": i, "uncovered": u, "outcome": anchor_due(la, now, i, u)}
        for la, now, i, u in [
            (None, r(0, w), DAY, True),
            (r(0, w), r(DAY - 1, w + DAY - 1), DAY, True),
            (r(0, w), r(DAY, w + DAY), DAY, True),
            (r(0, w), r(5 * DAY, w + 5 * DAY), DAY, False),
        ]
    ]
    return decisions


def waiting_decisions() -> list:
    """ext-recovery-agent.json's waiting_decisions."""
    return [{"first_sight": d["first_sight"], "now": d["now"], "agent_waiting_period": d["period"],
             "confirmed": d["confirmed"], "vetoed": d["vetoed"], "outcome": d["outcome"]}
            for d in decision_tables()["agent_waiting_period"]]


def cbor_nesting() -> list:
    """overview.md, "Deterministic CBOR": items at and beyond the deepest
    nesting a decoder accepts."""
    from events import MAX_DEPTH, cbor, nesting, uncbor
    from primitives import SpecError

    def arrays(depth):
        value = 0
        for _ in range(depth):
            value = [value]
        return value

    def maps(depth):
        value = 0
        for _ in range(depth):
            value = {0: value}
        return value

    rows = []
    for name, value in [
        (f"an array nested {MAX_DEPTH} deep", arrays(MAX_DEPTH)),
        (f"an array nested {MAX_DEPTH + 1} deep", arrays(MAX_DEPTH + 1)),
        (f"a map nested {MAX_DEPTH} deep", maps(MAX_DEPTH)),
        (f"a map nested {MAX_DEPTH + 1} deep", maps(MAX_DEPTH + 1)),
    ]:
        encoding = cbor(value)
        try:
            uncbor(encoding)
            result = "accepted"
        except SpecError as error:
            result = error.error
        rows.append({"name": name, "depth": nesting(value), "encoding": encoding.hex(),
                     "result": result})
    assert [r["result"] for r in rows] == ["accepted", "Malformed"] * 2, rows
    return rows


def overview_vectors() -> dict:
    """overview.json: the timer table in seconds, timelines with their
    estimates, check_expiry and check_policy at and beyond each edge, and
    CBOR nesting at and beyond the limit."""
    w = WALL0
    scenarios, estimates = _timelines()
    expiry = []
    for value, lifetime, skew in [("an admission code request", 900, 60),
                                  ("a library ticket's not_after", DAY, 60),
                                  ("a device-signed request", 60, 60)]:
        far = lifetime + skew
        for name, e, n in [
            ("the receiver's wall clock is not known", w + 10, None),
            ("at the furthest expires_at", w + far, w),
            ("one second beyond the furthest", w + far + 1, w),
            ("at expires_at", w + 10, w + 10),
            ("one second after expires_at", w + 10, w + 11),
        ]:
            expiry.append({"value": value, "case": name, "expires_at": e, "now_wall": n,
                           "lifetime": lifetime, "skew": skew,
                           "outcome": check_expiry(e, n, lifetime, skew)})
    policy = []
    for name in POLICY_PARAMETERS + ("link_lifetime", "session_lifetime"):
        p = _BY_NAME[name]
        values = [p["minimum"] - 1, p["minimum"], p["maximum"], p["maximum"] + 1]
        for value in values:
            policy.append({"name": name, "value": value, "outcome": check_policy(name, value)})
    for name, value in [("agent_waiting_period", "259200"), ("bounded_window", -3600)]:
        policy.append({"name": name, "value": value, "outcome": check_policy(name, value)})
    return {
        "specification": "overview.md",
        "units": "seconds",
        "timers": PARAMETERS,
        "online_freshness_when_on": ONLINE_FRESHNESS_WHEN_ON,
        "policy_values": list(POLICY_PARAMETERS),
        "timelines": scenarios,
        "estimates": estimates,
        "check_expiry": expiry,
        "check_policy": policy,
        "cbor_nesting": cbor_nesting(),
    }


def self_test() -> None:
    v = overview_vectors()
    d = decision_tables()
    # The timeline never runs backward, and ignores jumps while running.
    for scenario in v["timelines"]:
        values = [s["reading"]["timeline"] for s in scenario["steps"] if s["action"] == "read"]
        assert values == sorted(values), scenario["description"]
    jump = _readings(v["timelines"][1])
    assert [x["timeline"] for x in jump] == [10, 20, 30]
    restart = _readings(v["timelines"][3])
    assert restart[-2]["timeline"] == 100 + DAY
    unknown = _readings(v["timelines"][6])
    assert [x["timeline"] for x in unknown] == [100, 100, 150]
    # A wall clock known mid-run is read, and the time off then counts.
    learned = _readings(v["timelines"][8])
    assert [x["wall"] is None for x in learned] == [True, False, False]
    assert [x["timeline"] for x in learned] == [100, 200, 200 + HOUR]
    for p in PARAMETERS:
        if p["default"] is not None:
            assert check_policy(p["name"], p["default"]) == "ok", p["name"]
    assert [c["outcome"] for c in v["check_expiry"][:5]] == [
        "Expired", "ok", "Malformed", "ok", "Expired"]
    assert [c["outcome"] for c in v["check_policy"][:4]] == ["Malformed", "ok", "ok", "Malformed"]
    assert v["check_policy"][-2]["outcome"] == v["check_policy"][-1]["outcome"] == "Malformed"
    # The directions: a wrong wall clock never shortens a wait, and never
    # lengthens a window.
    since = {"timeline": 0, "wall": WALL0, "run": 1}
    fast = {"timeline": 60, "wall": WALL0 + 10 * DAY, "run": 1}
    assert agent_waiting_period(since, fast, 72 * HOUR) == "Waiting"
    assert bounded_window(since, fast, DAY) == "WindowElapsed"
    assert rotation_delay(1000) == 126
    acks = d["acknowledged"]
    assert acks[1]["acknowledged"]["timeline"] == 0 and acks[2]["acknowledged"] is None
    assert [x["outcome"] for x in d["online_only"]][-2:] == ["MayWrite", "NotOnline"]
    assert [x["outcome"] for x in d["release"]] == [
        "Keep", "Reclaim", "Keep", "Reclaim", "Reclaim", "Keep"]
    assert [x["outcome"] for x in d["collect"]] == ["Collect", "Keep", "Collect", "Keep"]
    assert [x["outcome"] for x in d["orphan"]] == ["Keep", "Collect", "Keep"]
    assert [x["outcome"] for x in waiting_decisions()] == [
        "Waiting", "Vouched", "Waiting", "Vouched", "Vetoed", "Waiting", "Waiting"]


if __name__ == "__main__":
    self_test()
    print("ok")
