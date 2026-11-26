//! Time (overview.md, "Time").
//!
//! Time decides what a device does next. It never decides whether an event
//! is valid. Nothing here reads a clock: every function takes the readings
//! and instants it decides from.
//!
//! - [`Timeline`]: the local timeline, and its [`Reading`]s.
//! - [`lower`] and [`upper`]: the two estimates of elapsed time.
//! - [`check_expiry`]: an instant exchanged between parties.
//! - [`check_policy`]: a duration a signed space policy carries, or a
//!   lifetime a client is about to sign.
//! - [`Timer`] and [`TimerSpec`]: every timer, its default and its range.

use crate::cbor::Value;
use crate::errors::ErrorClass;

const MINUTE: u64 = 60;
const HOUR: u64 = 60 * MINUTE;
const DAY: u64 = 24 * HOUR;

// ---------------------------------------------------------------------------
// The local timeline.

/// A reading `(T, W, run)`: the timeline, the wall clock or none, and the
/// number of the start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Reading {
    /// `T`: seconds on the device's timeline, from 0 at its first start.
    pub timeline: u64,
    /// `W`: the wall clock, in seconds since 1970-01-01T00:00:00Z as POSIX
    /// counts them, or `None` when it is not known.
    pub wall: Option<u64>,
    /// The number of the start, from 1.
    pub run: u64,
}

/// One device's local timeline (overview.md, "The local timeline").
///
/// While the device runs, the timeline follows the monotonic clock, so a
/// change to the wall clock is not counted, then or later. At a start, or a
/// resume after a suspend in which the monotonic clock stopped, it adds the
/// wall clock's advance since the last kept reading, never less than zero,
/// and nothing without a known wall clock on both sides.
///
/// Each [`read`](Self::read) becomes the kept reading. The device keeps
/// [`kept`](Self::kept) at rest at least once a minute while it runs, and at
/// shutdown, and gives it to the next [`start`](Self::start). After a crash,
/// the time since the last kept reading then counts once, as time off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timeline {
    kept: Reading,
    base: u64,
    mono0: u64,
}

impl Timeline {
    /// Starts the timeline, from the reading kept at rest or, at the
    /// device's first start, from none. `wall` is the wall clock now, or
    /// `None` when it is not known; `mono` is the monotonic clock now.
    pub fn start(kept: Option<Reading>, wall: Option<u64>, mono: u64) -> Self {
        let (base, run) = match kept {
            None => (0, 1),
            Some(kept) => (Self::base(kept, wall), kept.run.saturating_add(1)),
        };
        Self {
            kept: Reading {
                timeline: base,
                wall,
                run,
            },
            base,
            mono0: mono,
        }
    }

    /// Resumes after a suspend in which the monotonic clock stopped: a new
    /// start from the kept reading.
    pub fn resume(&mut self, wall: Option<u64>, mono: u64) {
        *self = Self::start(Some(self.kept), wall, mono);
    }

    /// The base of a start: `T_k + max(0, W − W_k)` when the wall clock is
    /// known now and was known at the kept reading, otherwise `T_k`.
    fn base(kept: Reading, wall: Option<u64>) -> u64 {
        match (wall, kept.wall) {
            (Some(now), Some(then)) => kept.timeline.saturating_add(now.saturating_sub(then)),
            _ => kept.timeline,
        }
    }

    /// Reads the timeline: `T = base + (monotonic clock − M0)`, with the wall
    /// clock now (or `None` when it is not known) and the run. The reading
    /// becomes the kept one.
    pub fn read(&mut self, mono: u64, wall: Option<u64>) -> Reading {
        let reading = Reading {
            timeline: self.base.saturating_add(mono.saturating_sub(self.mono0)),
            wall,
            run: self.kept.run,
        };
        self.kept = reading;
        reading
    }

    /// The last reading, for the device to keep at rest.
    pub fn kept(&self) -> Reading {
        self.kept
    }
}

// ---------------------------------------------------------------------------
// The two estimates.

/// An upper estimate of elapsed time: a count of seconds, or unbounded.
/// `Seconds` of any count orders below `Unbounded`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Elapsed {
    /// At most this many seconds.
    Seconds(u64),
    /// No bound: across a restart without a known wall clock.
    Unbounded,
}

impl Elapsed {
    /// Whether at least `seconds` may have passed: for a rule that stops
    /// acting after a time.
    pub fn at_least(self, seconds: u64) -> bool {
        match self {
            Self::Seconds(elapsed) => elapsed >= seconds,
            Self::Unbounded => true,
        }
    }
}

/// The lower estimate, `N.T − S.T`: the timeline's advance from `since` to
/// `now`. A rule that waits before acting uses it.
pub fn lower(since: &Reading, now: &Reading) -> u64 {
    now.timeline.saturating_sub(since.timeline)
}

/// The upper estimate. A rule that stops acting after a time uses it.
///
/// - `max(N.T − S.T, N.W − S.W)` when both wall clocks are known;
/// - `N.T − S.T` otherwise, within one run;
/// - unbounded otherwise, across a restart.
pub fn upper(since: &Reading, now: &Reading) -> Elapsed {
    let lower = lower(since, now);
    match (since.wall, now.wall) {
        (Some(then), Some(wall)) => Elapsed::Seconds(lower.max(wall.saturating_sub(then))),
        _ if since.run == now.run => Elapsed::Seconds(lower),
        _ => Elapsed::Unbounded,
    }
}

// ---------------------------------------------------------------------------
// Instants exchanged between parties.

/// `check_expiry` (overview.md, "Instants exchanged between parties"), in
/// order:
///
/// 1. The receiver's wall clock is known, else `Expired`.
/// 2. `expires_at <= now_wall + lifetime + skew`, else `Malformed`.
/// 3. `now_wall <= expires_at`, else `Expired`.
///
/// `now_wall` is the receiver's wall clock, or `None` when it is not known.
/// The sum saturates at 2^64 − 1 and never overflows.
pub fn check_expiry(
    expires_at: u64,
    now_wall: Option<u64>,
    lifetime: u64,
    skew: u64,
) -> Result<(), ErrorClass> {
    let Some(now_wall) = now_wall else {
        return Err(ErrorClass::Expired);
    };
    if expires_at > now_wall.saturating_add(lifetime).saturating_add(skew) {
        return Err(ErrorClass::Malformed);
    }
    if now_wall > expires_at {
        return Err(ErrorClass::Expired);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Policy values.

/// `check_policy` (overview.md, "Policy values and a peer's clock"), in
/// order:
///
/// 1. `value` is an unsigned integer, else `Malformed`.
/// 2. `minimum(name) <= value <= maximum(name)`, else `Malformed`.
///
/// Returns the value in seconds. A replica runs it on each duration a signed
/// space policy carries, and a client on each lifetime it is about to sign.
pub fn check_policy(timer: Timer, value: &Value) -> Result<u64, ErrorClass> {
    let seconds = value.as_unsigned()?;
    if !timer.spec().allows(seconds) {
        return Err(ErrorClass::Malformed);
    }
    Ok(seconds)
}

// ---------------------------------------------------------------------------
// Every timer.

/// Who sets a timer's value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SetBy {
    /// Fixed by the protocol.
    Protocol,
    /// A signed space policy, which every replica checks.
    SpacePolicy,
    /// The implementation.
    Implementation,
    /// The application.
    Application,
    /// A peer's operator.
    Operator,
    /// The peer.
    Peer,
    /// The inviter's client.
    InvitersClient,
    /// The granter's client.
    GrantersClient,
    /// A library ticket's issuer.
    Issuer,
}

impl SetBy {
    /// How overview.md's table writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::SpacePolicy => "space policy",
            Self::Implementation => "the implementation",
            Self::Application => "the application",
            Self::Operator => "the operator",
            Self::Peer => "the peer",
            Self::InvitersClient => "the inviter's client",
            Self::GrantersClient => "the granter's client",
            Self::Issuer => "the issuer",
        }
    }
}

/// One row of overview.md's "Every timer". Durations are in seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimerSpec {
    /// The timer.
    pub timer: Timer,
    /// Its name, such as `gap_key_timeout`.
    pub name: &'static str,
    /// What it bounds.
    pub bounds: &'static str,
    /// Its default, in seconds; `None` where the table gives no number.
    pub default: Option<u64>,
    /// The table's default where it is not a plain number of seconds, or
    /// says more than one.
    pub default_text: Option<&'static str>,
    /// The least value its range allows; `None` where the range has no
    /// lower bound.
    pub minimum: Option<u64>,
    /// The greatest value its range allows; `None` where the range has no
    /// upper bound.
    pub maximum: Option<u64>,
    /// Who sets it.
    pub set_by: SetBy,
    /// How it is counted; `None` where it counts nothing.
    pub counted: Option<&'static str>,
    /// The documents that use it.
    pub documents: &'static [&'static str],
}

impl TimerSpec {
    /// Whether `seconds` is within the timer's range.
    pub fn allows(&self, seconds: u64) -> bool {
        self.minimum.is_none_or(|minimum| minimum <= seconds)
            && self.maximum.is_none_or(|maximum| seconds <= maximum)
    }

    /// Whether the protocol fixes the value: its range is one value.
    pub fn is_fixed(&self) -> bool {
        self.minimum.is_some() && self.minimum == self.maximum
    }
}

/// Every timer of overview.md's "Every timer", in its order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Timer {
    /// An admission code request's lifetime.
    AdmissionCodeLifetime,
    /// The skew allowed on an admission code request.
    AdmissionCodeSkew,
    /// An exchange mailbox's lifetime.
    ExchangeMailboxLifetime,
    /// Gap keys, refused units' content, snapshots and erased content.
    GapKeyTimeout,
    /// The cascade delay, per rank.
    RotationStep,
    /// The highest rank the cascade delay counts.
    RotationRankCap,
    /// The interval between anchors.
    AnchorInterval,
    /// Release at a replica.
    ReplicaReleaseRetention,
    /// `T`: erasure and the like without stability at the peer.
    ErasureTimeout,
    /// Release at a peer.
    ReleaseRetention,
    /// An object no unit references.
    OrphanGrace,
    /// An old version of a file, superseded at every listing.
    FileVersionRetention,
    /// Compacting a Blobs stream whose units since its last snapshot carry
    /// supersessions.
    VersionCompactionInterval,
    /// A handshake, to the first `Admit` or refusal.
    HandshakeDeadline,
    /// An unknown member after a proven key state.
    Probation,
    /// A device's member endpoint key.
    EndpointRotation,
    /// Head gossip, per attach.
    GossipInterval,
    /// A peer's `Missing` for a head statement's heads before it shows
    /// withholding.
    WithholdingGrace,
    /// The first wait before a refused read credential is presented again.
    PresentRetry,
    /// The bound of the random wait before reconnecting after a `reconnect`
    /// close.
    ReconnectWait,
    /// The cap on that bound, doubled after each failed attempt.
    ReconnectWaitCap,
    /// A stopping peer's wait for an import or a pending create.
    ReconnectDrain,
    /// Nearby pairing.
    PairingDeadline,
    /// A person's or a device's mailbox.
    MailboxRetention,
    /// An item of a device mailbox that is not claimed.
    UncollectedRetention,
    /// A welcome its signer keeps waiting to hand over or deposit.
    WelcomeRetention,
    /// An invite, ended by a revocation.
    LinkLifetime,
    /// A guest session, ended by a removal.
    SessionLifetime,
    /// Writing without hearing from another member.
    BoundedWindow,
    /// Writing without a recent sync with a peer of the space.
    OnlineFreshness,
    /// Trusting a device an agent added.
    AgentWaitingPeriod,
    /// An ephemeral frame in its sender's queue.
    EphemeralSendDeadline,
    /// Ephemeral frames held for a rotation the receiver lacks.
    EphemeralKeyWait,
    /// A library ticket's lifetime.
    TicketLifetime,
    /// The skew allowed on a library ticket.
    TicketSkew,
    /// A detached space's data at a peer.
    DetachedGrace,
    /// A deposit key's issuing, then its accepting only.
    TokenPeriod,
    /// A library's deposit allowance.
    AllowanceWindow,
    /// A device-signed request's lifetime.
    SignedRequestLifetime,
    /// The skew allowed on a device-signed request.
    SignedRequestSkew,
}

/// `online_freshness`'s value when a space turns it on without giving one.
pub const ONLINE_FRESHNESS_WHEN_ON: u64 = 300;

/// The timers a signed space policy carries, whose values every replica
/// checks with [`check_policy`].
pub const POLICY_VALUES: [Timer; 4] = [
    Timer::GapKeyTimeout,
    Timer::BoundedWindow,
    Timer::OnlineFreshness,
    Timer::AgentWaitingPeriod,
];

impl Timer {
    /// Every timer, in the table's order.
    pub const ALL: [Timer; 40] = {
        let mut all = [Timer::AdmissionCodeLifetime; 40];
        let mut index = 0;
        while index < 40 {
            all[index] = TIMERS[index].timer;
            index += 1;
        }
        all
    };

    /// The timer's row of the table.
    pub fn spec(self) -> &'static TimerSpec {
        &TIMERS[self as usize]
    }

    /// The timer's name, such as `gap_key_timeout`.
    pub fn name(self) -> &'static str {
        self.spec().name
    }

    /// The timer of this name.
    pub fn from_name(name: &str) -> Option<Self> {
        TIMERS
            .iter()
            .find(|spec| spec.name == name)
            .map(|spec| spec.timer)
    }
}

#[allow(clippy::too_many_arguments)]
const fn row(
    timer: Timer,
    name: &'static str,
    bounds: &'static str,
    default: Option<u64>,
    minimum: Option<u64>,
    maximum: Option<u64>,
    set_by: SetBy,
    counted: Option<&'static str>,
    documents: &'static [&'static str],
    default_text: Option<&'static str>,
) -> TimerSpec {
    TimerSpec {
        timer,
        name,
        bounds,
        default,
        default_text,
        minimum,
        maximum,
        set_by,
        counted,
        documents,
    }
}

/// overview.md's "Every timer", in seconds, one row per [`Timer`] in its
/// order.
pub const TIMERS: [TimerSpec; 40] = [
    row(
        Timer::AdmissionCodeLifetime,
        "admission_code_lifetime",
        "an admission code request",
        Some(900),
        Some(900),
        Some(900),
        SetBy::Protocol,
        Some("wall, the joiner's clock"),
        &["admission.md"],
        None,
    ),
    row(
        Timer::AdmissionCodeSkew,
        "admission_code_skew",
        "an admission code request",
        Some(60),
        Some(60),
        Some(60),
        SetBy::Protocol,
        Some("wall"),
        &["admission.md"],
        None,
    ),
    row(
        Timer::ExchangeMailboxLifetime,
        "exchange_mailbox_lifetime",
        "an exchange mailbox",
        None,
        None,
        Some(1020),
        SetBy::Peer,
        Some("the peer's timeline"),
        &["transport.md"],
        Some("expires_at + 60; at most 1,020 after the request"),
    ),
    row(
        Timer::GapKeyTimeout,
        "gap_key_timeout",
        "a restored member's gap keys; keeping a refused unit's content; settling a \
         snapshot; a replica dropping erased content without stability",
        Some(7 * DAY),
        Some(HOUR),
        Some(90 * DAY),
        SetBy::SpacePolicy,
        Some(
            "lower, from each holder's first sight of the restoring merge, the refusing \
             event, the snapshot or the erasure",
        ),
        &["keys.md", "roster.md", "units.md", "peers.md"],
        None,
    ),
    row(
        Timer::RotationStep,
        "rotation_step",
        "the cascade delay, per rank",
        Some(2),
        Some(1),
        Some(10),
        SetBy::Implementation,
        Some("lower, from first sight of the trigger"),
        &["keys.md"],
        None,
    ),
    row(
        Timer::RotationRankCap,
        "rotation_rank_cap",
        "the highest rank the delay counts",
        Some(63),
        Some(63),
        Some(63),
        SetBy::Protocol,
        None,
        &["keys.md"],
        None,
    ),
    row(
        Timer::AnchorInterval,
        "anchor_interval",
        "anchors",
        Some(DAY),
        Some(HOUR),
        Some(7 * DAY),
        SetBy::Implementation,
        Some("lower, from the device's last anchor in the space"),
        &["crypto.md"],
        None,
    ),
    row(
        Timer::ReplicaReleaseRetention,
        "replica_release_retention",
        "release at a replica",
        Some(30 * DAY),
        Some(30 * DAY),
        None,
        SetBy::Application,
        Some("lower, from first sight of the release"),
        &["units.md"],
        None,
    ),
    row(
        Timer::ErasureTimeout,
        "erasure_timeout",
        "erasure, credentials requests, reclaiming a release and collection, without \
         stability at the peer",
        Some(7 * DAY),
        Some(HOUR),
        Some(90 * DAY),
        SetBy::Operator,
        Some("lower, the peer's, from acceptance"),
        &["peers.md"],
        None,
    ),
    row(
        Timer::ReleaseRetention,
        "release_retention",
        "release at a peer",
        Some(30 * DAY),
        Some(0),
        Some(365 * DAY),
        SetBy::Operator,
        Some("lower, the peer's, from acceptance"),
        &["peers.md"],
        None,
    ),
    row(
        Timer::OrphanGrace,
        "orphan_grace",
        "an object no unit references",
        Some(DAY),
        Some(HOUR),
        Some(30 * DAY),
        SetBy::Operator,
        Some("lower, the peer's, from first sight of the object"),
        &["peers.md"],
        None,
    ),
    row(
        Timer::FileVersionRetention,
        "file_version_retention",
        "an old version of a file, superseded at every listing",
        Some(7 * DAY),
        Some(0),
        Some(365 * DAY),
        SetBy::Operator,
        Some("lower, the peer's, from first sight of the earliest superseding unit"),
        &["ext-file-versions.md"],
        None,
    ),
    row(
        Timer::VersionCompactionInterval,
        "version_compaction_interval",
        "compacting a Blobs stream whose units since its last snapshot carry supersessions",
        Some(DAY),
        Some(HOUR),
        Some(7 * DAY),
        SetBy::Implementation,
        Some("lower, from the client's first sight of the first such unit"),
        &["ext-file-versions.md"],
        None,
    ),
    row(
        Timer::HandshakeDeadline,
        "handshake_deadline",
        "a handshake, to the first Admit or refusal",
        Some(10),
        Some(10),
        Some(10),
        SetBy::Protocol,
        Some("monotonic"),
        &["transport.md"],
        None,
    ),
    row(
        Timer::Probation,
        "probation",
        "an unknown member after a proven key state",
        Some(30),
        Some(30),
        Some(30),
        SetBy::Protocol,
        Some("monotonic"),
        &["transport.md"],
        Some("30, and 4,096 events"),
    ),
    row(
        Timer::EndpointRotation,
        "endpoint_rotation",
        "a device's member endpoint key",
        Some(DAY),
        None,
        Some(DAY),
        SetBy::Implementation,
        Some("the device's timeline"),
        &["transport.md"],
        Some("24 hours, and at each new network"),
    ),
    row(
        Timer::GossipInterval,
        "gossip_interval",
        "head gossip and member addresses, per attach",
        Some(5),
        Some(5),
        None,
        SetBy::Implementation,
        Some("monotonic"),
        &["transport.md"],
        None,
    ),
    row(
        Timer::WithholdingGrace,
        "withholding_grace",
        "a peer's Missing for a head statement's heads before it shows withholding",
        Some(300),
        Some(60),
        Some(3600),
        SetBy::Implementation,
        Some("monotonic, from the peer's first Missing for them"),
        &["units.md"],
        None,
    ),
    row(
        Timer::PresentRetry,
        "present_retry",
        "presenting a refused read credential again",
        Some(1),
        Some(1),
        Some(30),
        SetBy::Implementation,
        Some("monotonic"),
        &["transport.md"],
        None,
    ),
    row(
        Timer::ReconnectWait,
        "reconnect_wait",
        "the random wait before the first attempt after a reconnect close",
        Some(5),
        Some(5),
        Some(5),
        SetBy::Protocol,
        Some("monotonic"),
        &["transport.md"],
        None,
    ),
    row(
        Timer::ReconnectWaitCap,
        "reconnect_wait_cap",
        "the bound of that wait, doubled after each failed attempt",
        Some(60),
        Some(60),
        Some(60),
        SetBy::Protocol,
        Some("monotonic"),
        &["transport.md"],
        None,
    ),
    row(
        Timer::ReconnectDrain,
        "reconnect_drain",
        "a stopping peer's wait for an import or a pending create before it drops the connection",
        Some(60),
        Some(0),
        Some(600),
        SetBy::Operator,
        Some("monotonic"),
        &["transport.md"],
        None,
    ),
    row(
        Timer::PairingDeadline,
        "pairing_deadline",
        "nearby pairing",
        Some(90),
        Some(90),
        Some(90),
        SetBy::Protocol,
        Some("monotonic"),
        &["transport.md"],
        None,
    ),
    row(
        Timer::MailboxRetention,
        "mailbox_retention",
        "a person's or a device's mailbox",
        None,
        None,
        Some(30 * DAY),
        SetBy::Operator,
        Some("the peer's timeline"),
        &["transport.md"],
        Some("the operator's"),
    ),
    row(
        Timer::UncollectedRetention,
        "uncollected_retention",
        "an item of a device mailbox that is not claimed",
        Some(72 * HOUR),
        Some(HOUR),
        Some(30 * DAY),
        SetBy::Operator,
        Some("the peer's timeline, from the deposit"),
        &["transport.md"],
        None,
    ),
    row(
        Timer::WelcomeRetention,
        "welcome_retention",
        "a welcome its signer keeps waiting to hand over or deposit",
        Some(30 * DAY),
        Some(30 * DAY),
        Some(30 * DAY),
        SetBy::Protocol,
        Some("the signer's timeline, from keeping it"),
        &["admission.md", "at-rest.md"],
        None,
    ),
    row(
        Timer::LinkLifetime,
        "link_lifetime",
        "an invite, ended by a revocation",
        Some(7 * DAY),
        Some(15 * MINUTE),
        Some(7 * DAY),
        SetBy::InvitersClient,
        Some(
            "wall, the inviter's clock; lower, from each administering device's first \
             sight, for the maximum",
        ),
        &["ext-invite-links.md"],
        None,
    ),
    row(
        Timer::SessionLifetime,
        "session_lifetime",
        "a guest session, ended by a removal",
        None,
        Some(15 * MINUTE),
        Some(30 * DAY),
        SetBy::GrantersClient,
        Some("as link_lifetime"),
        &["ext-guests.md"],
        Some("none"),
    ),
    row(
        Timer::BoundedWindow,
        "bounded_window",
        "writing without hearing from another member",
        None,
        Some(HOUR),
        Some(90 * DAY),
        SetBy::SpacePolicy,
        Some("upper, from the signing of this device's newest event another member has followed"),
        &["ext-guests.md"],
        Some("off"),
    ),
    row(
        Timer::OnlineFreshness,
        "online_freshness",
        "writing without a recent sync with a peer of the space",
        None,
        Some(30),
        Some(HOUR),
        SetBy::SpacePolicy,
        Some("upper, from the last completed sync"),
        &["ext-guests.md"],
        Some("off; 300 when on"),
    ),
    row(
        Timer::AgentWaitingPeriod,
        "agent_waiting_period",
        "trusting a device an agent added",
        Some(72 * HOUR),
        Some(72 * HOUR),
        Some(30 * DAY),
        SetBy::SpacePolicy,
        Some("lower, from each verifier's first sight of the add"),
        &["ext-recovery-agent.md"],
        None,
    ),
    row(
        Timer::EphemeralSendDeadline,
        "ephemeral_send_deadline",
        "an ephemeral frame in its sender's queue",
        Some(2),
        Some(2),
        Some(2),
        SetBy::Protocol,
        Some("monotonic"),
        &["ext-ephemeral.md"],
        None,
    ),
    row(
        Timer::EphemeralKeyWait,
        "ephemeral_key_wait",
        "ephemeral frames held for a rotation the receiver lacks",
        Some(5),
        Some(5),
        Some(5),
        SetBy::Protocol,
        Some("monotonic"),
        &["ext-ephemeral.md"],
        None,
    ),
    row(
        Timer::TicketLifetime,
        "ticket_lifetime",
        "a library ticket",
        None,
        None,
        Some(DAY),
        SetBy::Issuer,
        Some("wall, the peer's clock"),
        &["ext-libraries.md"],
        Some("the issuer's"),
    ),
    row(
        Timer::TicketSkew,
        "ticket_skew",
        "a library ticket",
        Some(60),
        Some(60),
        Some(60),
        SetBy::Protocol,
        Some("wall"),
        &["ext-libraries.md"],
        None,
    ),
    row(
        Timer::DetachedGrace,
        "detached_grace",
        "a detached space's data at a peer",
        Some(30 * DAY),
        Some(DAY),
        Some(365 * DAY),
        SetBy::Operator,
        Some("lower, the peer's, from detachment"),
        &["ext-libraries.md"],
        None,
    ),
    row(
        Timer::TokenPeriod,
        "token_period",
        "a deposit key's issuing, then its accepting only",
        Some(7 * DAY),
        Some(DAY),
        Some(30 * DAY),
        SetBy::Operator,
        Some(
            "upper, the keys' shard's, from the key's start: issuing for one period, then \
             accepting only until two have passed",
        ),
        &["ext-deposit-tokens.md"],
        None,
    ),
    row(
        Timer::AllowanceWindow,
        "allowance_window",
        "a library's deposit allowance",
        Some(DAY),
        Some(DAY),
        Some(DAY),
        SetBy::Protocol,
        Some("lower, the library's, from the window's first draw"),
        &["ext-deposit-tokens.md"],
        None,
    ),
    row(
        Timer::SignedRequestLifetime,
        "signed_request_lifetime",
        "a device-signed request",
        Some(60),
        Some(60),
        Some(60),
        SetBy::Protocol,
        Some("wall, the signer's clock"),
        &["ext-app-requests.md"],
        None,
    ),
    row(
        Timer::SignedRequestSkew,
        "signed_request_skew",
        "a device-signed request",
        Some(60),
        Some(60),
        Some(60),
        SetBy::Protocol,
        Some("wall"),
        &["ext-app-requests.md"],
        None,
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_is_in_timer_order() {
        for (index, spec) in TIMERS.iter().enumerate() {
            assert_eq!(spec.timer as usize, index, "{}", spec.name);
            assert_eq!(Timer::ALL[index], spec.timer);
            assert_eq!(Timer::from_name(spec.name), Some(spec.timer));
            if let Some(default) = spec.default {
                assert!(spec.allows(default), "{}", spec.name);
            }
        }
        assert_eq!(Timer::from_name("absent"), None);
        assert!(
            Timer::OnlineFreshness
                .spec()
                .allows(ONLINE_FRESHNESS_WHEN_ON)
        );
        assert!(Timer::HandshakeDeadline.spec().is_fixed());
        assert!(!Timer::GossipInterval.spec().is_fixed());
    }

    #[test]
    fn expiry_saturates() {
        assert_eq!(check_expiry(u64::MAX, Some(u64::MAX - 1), 900, 60), Ok(()));
        assert_eq!(check_expiry(u64::MAX, Some(1), u64::MAX, u64::MAX), Ok(()));
        assert_eq!(
            check_expiry(u64::MAX - 1, Some(u64::MAX), u64::MAX, 60),
            Err(ErrorClass::Expired)
        );
        assert_eq!(
            check_expiry(1000, Some(0), 900, 60),
            Err(ErrorClass::Malformed)
        );
    }

    #[test]
    fn policy_values_must_be_unsigned_and_in_range() {
        let check = |value: Value| check_policy(Timer::GapKeyTimeout, &value);
        assert_eq!(check(Value::Unsigned(HOUR)), Ok(HOUR));
        assert_eq!(check(Value::from("3600")), Err(ErrorClass::Malformed));
        assert_eq!(check(Value::Unsigned(HOUR - 1)), Err(ErrorClass::Malformed));
        assert_eq!(
            check_policy(Timer::ReplicaReleaseRetention, &Value::Unsigned(u64::MAX)),
            Ok(u64::MAX)
        );
    }

    #[test]
    fn upper_estimates_order_and_compare() {
        assert!(Elapsed::Seconds(u64::MAX) < Elapsed::Unbounded);
        assert!(Elapsed::Unbounded.at_least(u64::MAX));
        assert!(Elapsed::Seconds(10).at_least(10));
        assert!(!Elapsed::Seconds(9).at_least(10));
    }

    #[test]
    fn a_wall_clock_that_becomes_known_mid_run_is_read() {
        let mut timeline = Timeline::start(None, None, 0);
        let reading = timeline.read(5, Some(1_790_000_000));
        assert_eq!(reading.wall, Some(1_790_000_000));
        // A monotonic clock read below its start does not go back.
        assert_eq!(Timeline::start(None, None, 10).read(3, None).timeline, 0);
    }
}
