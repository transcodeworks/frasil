//! The peer's settings, from `FRASIL_*` environment variables.
//!
//! [`Settings`] holds the operator's choices that peers.md leaves to the
//! operator: its timers (overview.md, "Every timer": `erasure_timeout`,
//! `release_retention`, `orphan_grace`, `mailbox_retention`,
//! `cut_retention`), the
//! `credential_cap` and `pending_cap` (peers.md, "Limits"), each space's
//! quota and rates (peers.md, "Quotas and rates"), the limits on device
//! mailboxes (transport.md, 3.14 Mailboxes: deposits are "subject to the
//! peer's rate limits"), and which creates it accepts (peers.md, "Hosting a
//! space"). [`Config`] adds where the peer
//! listens and stores.

use frasil_base::time::Timer;
use frasil_peers::limits::MAX_FILE_VERSIONS_RANGE;
use std::net::SocketAddr;
use std::path::PathBuf;

/// A setting that does not read, or is out of its range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl core::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

/// Which creates the peer accepts (peers.md, 3.1 Hosting a space: the
/// operator's policy).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Hosting {
    /// The default: no space is hosted for a stranger. With
    /// ext-libraries.md on, a space is stored only once a ticket attached
    /// it to an open library (ext-libraries.md, 1 Overview, and 3.3
    /// Attaching), and a create without a ticket is refused `no_library`;
    /// the operator hands out access by handing out tickets. With the
    /// extension off, a core peer, there is no create: a space this peer
    /// does not host answers `no_library`.
    #[default]
    Closed,
    /// Any connection may create a space whose genesis it stores first.
    /// With ext-libraries.md on, such a space is attached to the open
    /// library (ext-libraries.md, 2.4 Settings), which the operator names
    /// ([`crate::libraries::LibrarySettings::open_library`]): with none
    /// named, a create without a ticket is refused `no_library` as under
    /// [`Hosting::Closed`], and [`Config::from_env`] refuses the setting.
    /// Anyone who reaches the peer may then fill it, one space at a time,
    /// up to the space quota each, bounded only by the open library's
    /// quota when it has one.
    Open,
}

/// The extensions the peer serves, which the operator chooses with
/// `FRASIL_EXTENSIONS`: [`Extensions::DEFAULT`], ext-libraries.md and
/// ext-deposit-tokens.md, unless it names others. Every extension is built into `frasil-relay`.
/// One that is off is as absent as if it were not: the peer lists no
/// service of it, reads none of its message types, mailbox kinds or
/// routes, and keeps none of its records.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Extensions {
    /// ext-ephemeral.md: relaying each space's ephemeral channel among the
    /// connections that hold its live right. Off, the peer drops
    /// `Ephemeral` and `Gone`.
    pub ephemeral: bool,
    /// ext-file-versions.md: retention of superseded objects, under
    /// `max_file_versions` and `file_version_retention`.
    pub file_versions: bool,
    /// ext-invite-links.md: mailbox kind 4, invite drops counted in usage,
    /// `MailboxDelete`, and `GET /frasil/p1/mailbox/4/{address}`.
    pub invite_links: bool,
    /// ext-libraries.md: service 5, `LibraryAttach`, `HoldObject`,
    /// attachments, ledgers, the library checks before a store, and the
    /// operator's library routes.
    pub libraries: bool,
    /// ext-deposit-tokens.md: service 6, `deposit`; message types 40 to 43;
    /// `MailboxPut` key 7 and `Authorization: Frasil-Token` on the deposit
    /// route; the token budget; `deposit_keys` in discovery; and each
    /// library's allowance. A peer implements it only together with
    /// ext-libraries.md, so it needs `libraries` on.
    pub deposit_tokens: bool,
}

impl Extensions {
    /// No extension: the core peer.
    pub const NONE: Self = Self {
        ephemeral: false,
        file_versions: false,
        invite_links: false,
        libraries: false,
        deposit_tokens: false,
    };

    /// What a peer serves when the operator names no extension:
    /// ext-libraries.md, so that a space is hosted only under a ticket of
    /// an issuer the peer trusts, its own operator's by default, and
    /// ext-deposit-tokens.md, so that a deposit into a device mailbox can
    /// carry a token drawn against a library rather than the anonymous
    /// budget alone.
    pub const DEFAULT: Self = Self {
        libraries: true,
        deposit_tokens: true,
        ..Self::NONE
    };

    /// Every extension `frasil-relay` implements.
    pub const ALL: Self = Self {
        ephemeral: true,
        file_versions: true,
        invite_links: true,
        libraries: true,
        deposit_tokens: true,
    };

    /// The names `FRASIL_EXTENSIONS` takes, in the order they print.
    pub const NAMES: [&'static str; 5] = [
        "ephemeral",
        "file-versions",
        "invite-links",
        "libraries",
        "deposit-tokens",
    ];

    /// Reads a list of extension names, separated by spaces or commas, or
    /// `none` for the core peer. A name may carry the prefix `ext-`, as the
    /// specification's documents do.
    ///
    /// # Errors
    ///
    /// A name that is no extension of `frasil-relay`'s, or a list that
    /// turns on `deposit-tokens` without `libraries`.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let mut extensions = Self::NONE;
        if text.trim() == "none" {
            return Ok(extensions);
        }
        for name in text
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|name| !name.is_empty())
        {
            let flag = match name.strip_prefix("ext-").unwrap_or(name) {
                "ephemeral" => &mut extensions.ephemeral,
                "file-versions" => &mut extensions.file_versions,
                "invite-links" => &mut extensions.invite_links,
                "libraries" => &mut extensions.libraries,
                "deposit-tokens" => &mut extensions.deposit_tokens,
                _ => {
                    return Err(ConfigError(format!(
                        "FRASIL_EXTENSIONS names `{name}`, which is not one of {}",
                        Self::NAMES.join(", ")
                    )));
                }
            };
            *flag = true;
        }
        extensions.check()?;
        Ok(extensions)
    }

    /// Whether the extensions can be on together: ext-deposit-tokens.md is
    /// implemented only together with ext-libraries.md.
    ///
    /// # Errors
    ///
    /// `deposit-tokens` without `libraries`.
    pub fn check(&self) -> Result<(), ConfigError> {
        if self.deposit_tokens && !self.libraries {
            return Err(ConfigError(
                "FRASIL_EXTENSIONS turns on deposit-tokens without libraries, which it needs"
                    .into(),
            ));
        }
        Ok(())
    }

    /// The names of the extensions that are on.
    pub fn names(&self) -> Vec<&'static str> {
        let on = [
            self.ephemeral,
            self.file_versions,
            self.invite_links,
            self.libraries,
            self.deposit_tokens,
        ];
        Self::NAMES
            .into_iter()
            .zip(on)
            .filter_map(|(name, on)| on.then_some(name))
            .collect()
    }

    /// The message types and mailbox kinds the transport reads for them
    /// (transport.md, "Frames").
    pub(crate) fn frames(&self) -> frasil_transport::frame::Extensions {
        frasil_transport::frame::Extensions {
            libraries: self.libraries,
            invite_links: self.invite_links,
            // A peer is never a member: it reads no member connection.
            next_endpoints: false,
            deposit_tokens: self.deposit_tokens,
        }
    }
}

impl core::fmt::Display for Extensions {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let names = self.names();
        if names.is_empty() {
            f.write_str("none")
        } else {
            f.write_str(&names.join(", "))
        }
    }
}

/// The default rates of peers.md, "Quotas and rates".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rates {
    /// Presents per connection, per minute.
    pub presents_per_minute: usize,
    /// Space events stored per author per space, per hour; and, apart,
    /// per entry stored under (peers.md, 3.20 Quotas and rates).
    pub space_events_per_hour: usize,
    /// Storage events stored per author per space, per hour; and, apart,
    /// per entry stored under.
    pub storage_events_per_hour: usize,
    /// Merge statements per space, per hour.
    pub merges_per_hour: usize,
    /// ext-ephemeral.md: the `Ephemeral` frames one connection sends in a
    /// second, at most, up to that many at once after a quiet second; the
    /// peer drops the rest unread, as the lossy channel drops any frame
    /// (ext-ephemeral.md, 3.7 Relaying, "applies its own rate limits per
    /// connection").
    pub ephemeral_frames_per_second: usize,
}

impl Rates {
    /// peers.md's defaults, and 200 ephemeral frames per connection per
    /// second.
    pub const DEFAULT: Self = Self {
        presents_per_minute: 64,
        space_events_per_hour: 600,
        storage_events_per_hour: 600,
        merges_per_hour: 64,
        ephemeral_frames_per_second: 200,
    };
}

/// The peer's limits on device mailboxes (transport.md, 2.7 Mailboxes and
/// 3.14 Mailboxes). Anyone deposits, with no credential, "subject to the
/// peer's rate limits"; each mailbox holds at most 64 items and 4 MiB by
/// the spec, and these bound all of them together and how fast one source
/// deposits.
///
/// The caps are split evenly among the peer's mailbox shards, so that the
/// node that keeps a shard decides its deposits alone and the shards
/// together never pass them. They are transport.md's peer's caps ("The
/// peer's caps"), and with ext-deposit-tokens its anonymous budget: a
/// deposit that would take a shard past either cap first evicts, oldest
/// first, anonymous items of mailboxes that are not claimed, unless its own
/// mailbox is not claimed; if room is still lacking it is refused `busy`
/// and evicts nothing. No item of a claimed mailbox is evicted for another
/// mailbox's deposit (crate `device_mail`). A source past its rate is
/// refused `rate_limited`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceMailLimits {
    /// The items every device mailbox holds together, at most.
    pub items: usize,
    /// The bytes of items every device mailbox holds together, at most.
    pub bytes: usize,
    /// The deposits one source makes in a minute, at most, as the node it
    /// reaches counts them: the client's address (crate `source`), the
    /// forwarded one behind a trusted proxy. An iroh connection with no
    /// direct path has no source, and only the caps bound it.
    pub deposits_per_minute: usize,
}

impl DeviceMailLimits {
    /// The defaults: 65,536 items and 256 MiB, as admission.md caps
    /// exchange mailboxes, and 120 deposits per source per minute.
    pub const DEFAULT: Self = Self {
        items: 65_536,
        bytes: 256 << 20,
        deposits_per_minute: 120,
    };

    /// The least `items` the settings accept: one per mailbox shard.
    pub const MIN_ITEMS: usize = 16;

    /// The least `bytes` the settings accept: one device mailbox's 4 MiB,
    /// so that each of the 16 mailbox shards holds an item of the largest
    /// size.
    pub const MIN_BYTES: usize = frasil_transport::mailbox::DEVICE_MAILBOX_BYTES;
}

/// What the peer's connections may hold, together and each, and how long
/// it waits on them. A party that proved nothing reaches the peer through
/// a connection: these bound what it makes the peer keep before it proves
/// a credential (overview.md, 3 Threats, "A stranger"), and what a device
/// that stops reading pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionLimits {
    /// Open connections, at most: TCP connections to the HTTP listener,
    /// WebSockets among them, and device-to-peer connections on the iroh
    /// binding. Past it a new one is answered 503 `busy` over HTTP, or
    /// closed `busy` on iroh.
    pub max_connections: usize,
    /// Open connections from one source, at most; 0 sets no limit. The
    /// source is the client's address (crate `source`): over HTTP the
    /// TCP connection's remote address, or for a connection from one of
    /// [`Settings::trusted_proxies`] the address its forwarding header
    /// names, and over iroh the address of a direct path. Behind a reverse
    /// proxy, name it in `FRASIL_TRUSTED_PROXIES` so that each client
    /// counts apart: the proxy's own TCP connections then count toward
    /// [`ConnectionLimits::max_connections`] alone, and each WebSocket
    /// toward its client's cap. Without that setting every client behind
    /// the proxy shares the proxy's address, and this cap holds them all
    /// together. The default leaves room for two connections per device:
    /// a device keeps one for its spaces and a collecting connection for
    /// its own device mailbox at each peer.
    pub max_connections_per_source: usize,
    /// Seconds a new HTTP connection has to send its first request's
    /// head; past them it is closed.
    pub header_read_timeout: u64,
    /// Seconds a connection may stay with nothing read or written: an HTTP
    /// connection between requests, and on either binding a device-to-peer
    /// connection that holds no grant and sends nothing after its `Hello`.
    /// A connection that holds a grant, such as one subscribed to live
    /// delivery, stays while it answers the keep-alive. An HTTP connection
    /// waits at least three keep-alive intervals.
    pub idle_timeout: u64,
    /// Seconds between the WebSocket pings the peer sends (RFC 6455, 5.5.2
    /// Ping), the server binding's keep-alive. A WebSocket from which
    /// nothing, a pong included, arrives for three intervals is gone, and
    /// closed. The iroh binding keeps QUIC's own.
    pub keepalive_interval: u64,
    /// Seconds one message may take to write to a device; a device that
    /// reads no faster is closed.
    pub write_timeout: u64,
    /// Bytes of messages queued for one connection, live deliveries and
    /// control messages, at most; past it a live delivery is dropped, as
    /// past the queue's 1,024 messages.
    pub queued_bytes: usize,
    /// Messages per minute, per connection, that name a space the
    /// connection holds no grant in, presents aside: a create's genesis,
    /// sync and requests before any credential is proved. Past it a request
    /// is refused `rate_limited`, an event too, and anything else dropped.
    pub ungranted_per_minute: usize,
    /// Objects one connection uploads at once over a sync or object
    /// stream, whose sealed chunks the peer holds until they fill a piece.
    pub staged_objects: usize,
    /// Administration connections of one space, at most: a further present
    /// of an administrator pseudonym is refused `busy`.
    pub admin_connections_per_space: usize,
}

impl ConnectionLimits {
    /// The defaults: 16,384 connections, 512 per source, 30 seconds for a
    /// request's head, 300 seconds idle, a ping every 30 seconds, 30 seconds
    /// per write, 16 MiB queued per connection, 64 messages per minute
    /// naming spaces without a grant, 16 objects staged per connection, and
    /// 16 administration connections per space.
    pub const DEFAULT: Self = Self {
        max_connections: 16_384,
        max_connections_per_source: 512,
        header_read_timeout: 30,
        idle_timeout: 300,
        keepalive_interval: 30,
        write_timeout: 30,
        queued_bytes: 16 << 20,
        ungranted_per_minute: 64,
        staged_objects: 16,
        admin_connections_per_space: 16,
    };
}

/// How the peer commits its records in groups: writers that commit within
/// `window` of the first share one transaction and one sync, up to
/// `commits` commits or `bytes` bytes. A write is acknowledged only once
/// its group is durable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupCommit {
    /// How long a group waits for more writers after its first.
    pub window: std::time::Duration,
    /// The most commits in one group.
    pub commits: usize,
    /// The most bytes of records in one group; a commit larger than this
    /// is a group of its own.
    pub bytes: usize,
}

impl GroupCommit {
    /// The defaults: a 2 ms window, 1,024 commits, 16 MiB.
    pub const DEFAULT: Self = Self {
        window: std::time::Duration::from_millis(2),
        commits: 1024,
        bytes: 16 << 20,
    };
}

/// The operator's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// `erasure_timeout`, T, in seconds.
    pub erasure_timeout: u64,
    /// `release_retention`, in seconds.
    pub release_retention: u64,
    /// `orphan_grace`, in seconds.
    pub orphan_grace: u64,
    /// `cut_retention`, in seconds: how long a space's skeleton cut is in
    /// effect at the peer before the peer truncates the history before its
    /// checkpoint (peers.md, "Truncation"). 0 to 365 days; 30 by default.
    pub cut_retention: u64,
    /// `max_file_versions` (ext-file-versions.md): the versions of a file
    /// kept, the current one among them.
    pub max_file_versions: u64,
    /// `file_version_retention`, in seconds (ext-file-versions.md).
    pub file_version_retention: u64,
    /// `mailbox_retention`, in seconds.
    pub mailbox_retention: u64,
    /// `uncollected_retention`, in seconds: how long an item deposited in
    /// a device mailbox that is not claimed is kept, unless its device
    /// collects by then (transport.md, 3.14 Mailboxes, "Claimed device
    /// mailboxes"). At most `mailbox_retention`.
    pub uncollected_retention: u64,
    /// `credential_cap`: live entries per space.
    pub credential_cap: usize,
    /// `pending_cap`: pending events per space.
    pub pending_cap: usize,
    /// Each space's quota, in bytes.
    pub space_quota: u64,
    /// `max_streams_per_space` (units.md).
    pub max_streams_per_space: u64,
    /// Which creates the peer accepts: [`Hosting::Closed`] by default.
    pub hosting: Hosting,
    /// The rates.
    pub rates: Rates,
    /// The limits on device mailboxes.
    pub device_mail: DeviceMailLimits,
    /// What connections may hold, and how long the peer waits on them.
    pub connections: ConnectionLimits,
    /// The reverse proxies the operator trusts to name the client's
    /// address in `X-Forwarded-For`; none by default, so that no header is
    /// read (crate `source`).
    pub trusted_proxies: crate::source::TrustedProxies,
    /// The origin clients connect to, such as `https://peer.example.org`:
    /// the server binding's channel hashes it (transport.md, "The server
    /// binding"). Without one, the peer takes `http://` and the request's
    /// `Host`, which serves only a peer reached directly, in development.
    pub origin: Option<String>,
    /// The origin native clients connect to directly, such as
    /// `https://sync.example.org`, when browsers reach the peer at
    /// [`Settings::origin`] through another origin's proxy. A WebSocket
    /// request that carries no `Origin` header, as a native client's does,
    /// binds its channel to this origin; one that carries it, as a
    /// browser's always does, to [`Settings::origin`]. Without one, every
    /// connection binds to [`Settings::origin`].
    pub native_origin: Option<String>,
    /// Where a person sees usage and quotas, for the discovery document.
    pub account_url: Option<String>,
    /// The iroh relays the discovery document names, HTTPS URLs, whether or
    /// not the peer serves the iroh binding: a device whose application
    /// names none registers with them (transport.md, "The server
    /// binding"), and the peer's own iroh endpoint does too.
    pub relays: Vec<String>,
    /// The extensions that are on.
    pub extensions: Extensions,
    /// ext-libraries.md's peer settings: the trusted issuers or the
    /// operator's own, `detached_grace`, the default quota of each kind of
    /// library ID, and the open library.
    pub libraries: crate::libraries::LibrarySettings,
    /// ext-deposit-tokens.md's peer settings: the default allowance and
    /// share of a library, `token_period`, the token budget and the limit
    /// on refused tokens.
    pub deposit_tokens: crate::deposit::DepositSettings,
    /// How records are committed in groups.
    pub group_commit: GroupCommit,
    /// How long, in seconds of the peer's timeline, a space stays in
    /// memory after its last use. A sweep closes a space idle that long
    /// with nothing waiting in it and no connection on it; its next use
    /// opens it from its records.
    pub idle_close: u64,
    /// `reconnect_drain`, in seconds (overview.md, 6.8 Every timer): how
    /// long a stopping peer waits for a connection with an import in
    /// progress or a create pending before it drops it; it closes every
    /// other connection with `reconnect` at once.
    pub reconnect_drain: u64,
}

impl Settings {
    /// A core peer that hosts any space a connection creates: no
    /// extension, and [`Hosting::Open`]. It is what a test or an embedding
    /// of the peer starts from when it wants the core protocol alone; an
    /// operator's peer starts from [`Settings::default`]. A caller that
    /// turns ext-libraries.md on in these settings names the open library
    /// too, or the peer hosts no space without a ticket.
    pub fn open_core() -> Self {
        Self {
            hosting: Hosting::Open,
            extensions: Extensions::NONE,
            ..Self::default()
        }
    }
}

/// The operator's defaults: ext-libraries.md and ext-deposit-tokens.md on
/// ([`Extensions::DEFAULT`]), and [`Hosting::Closed`], so that a new peer
/// hosts a space only once a ticket attached it to a library. [`crate::run`] makes the operator's
/// own issuer the trusted one when no other is set.
impl Default for Settings {
    fn default() -> Self {
        Self {
            erasure_timeout: default_of(Timer::ErasureTimeout),
            release_retention: default_of(Timer::ReleaseRetention),
            orphan_grace: default_of(Timer::OrphanGrace),
            cut_retention: frasil_peers::limits::CUT_RETENTION,
            max_file_versions: frasil_peers::limits::MAX_FILE_VERSIONS,
            file_version_retention: default_of(Timer::FileVersionRetention),
            mailbox_retention: Timer::MailboxRetention
                .spec()
                .maximum
                .unwrap_or(30 * 86_400),
            uncollected_retention: default_of(Timer::UncollectedRetention),
            credential_cap: frasil_peers::limits::CREDENTIAL_CAP,
            pending_cap: frasil_peers::limits::PENDING_CAP,
            space_quota: 1 << 30,
            max_streams_per_space: frasil_transport::peer::Limits::PROTOCOL.max_streams_per_space,
            hosting: Hosting::Closed,
            rates: Rates::DEFAULT,
            device_mail: DeviceMailLimits::DEFAULT,
            connections: ConnectionLimits::DEFAULT,
            trusted_proxies: crate::source::TrustedProxies::default(),
            origin: None,
            native_origin: None,
            account_url: None,
            relays: Vec::new(),
            extensions: Extensions::DEFAULT,
            libraries: crate::libraries::LibrarySettings::default(),
            deposit_tokens: crate::deposit::DepositSettings::default(),
            group_commit: GroupCommit::DEFAULT,
            idle_close: 600,
            reconnect_drain: default_of(Timer::ReconnectDrain),
        }
    }
}

fn default_of(timer: Timer) -> u64 {
    timer.spec().default.expect("the timer has a default")
}

/// Where object chunks live (peers.md, "Objects").
#[derive(Clone, PartialEq, Eq)]
pub enum ObjectsConfig {
    /// A directory on a local filesystem.
    Files(PathBuf),
    /// An S3-compatible bucket.
    S3(S3Config),
}

impl core::fmt::Debug for ObjectsConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Files(path) => f.debug_tuple("Files").field(path).finish(),
            Self::S3(config) => f.debug_tuple("S3").field(config).finish(),
        }
    }
}

/// An S3-compatible bucket. Credentials come from these settings only, and
/// never appear in errors or debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct S3Config {
    /// An HTTPS endpoint, or loopback HTTP for local development.
    pub endpoint: String,
    /// The signing region, such as `auto`.
    pub region: String,
    /// An existing private bucket.
    pub bucket: String,
    /// The access key ID.
    pub access_key: String,
    /// The secret access key.
    pub secret_key: String,
    /// A prefix for every key in the bucket.
    pub prefix: String,
    /// Path-style addressing, which most self-hosted services need.
    pub path_style: bool,
}

impl core::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("path_style", &self.path_style)
            .field("credentials", &"[redacted]")
            .finish()
    }
}

/// Where the peer keeps its records: its shards (crate `shards`).
// Read once at start, so the larger variant costs nothing to keep inline.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, PartialEq, Eq)]
pub enum StoreConfig {
    /// Each shard's SQLite file, under this directory, is its copy of
    /// record.
    Directory(PathBuf),
    /// A bucket is the copy of record, and each shard's SQLite file a
    /// working copy in a cache directory.
    Bucket {
        /// The bucket: the object store's settings, without its prefix.
        s3: S3Config,
        /// The prefix of every key of the records, apart from the
        /// objects'.
        prefix: String,
        /// The directory of the working copies.
        cache: PathBuf,
        /// The node's name in the bucket, kept in the data directory.
        node: PathBuf,
        /// In single-node mode, how often the node reads its records in
        /// the bucket.
        fence_every: std::time::Duration,
    },
}

impl core::fmt::Debug for StoreConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Directory(path) => f.debug_tuple("Directory").field(path).finish(),
            Self::Bucket {
                s3,
                prefix,
                cache,
                node,
                fence_every,
            } => f
                .debug_struct("Bucket")
                .field("s3", s3)
                .field("prefix", prefix)
                .field("cache", cache)
                .field("node", node)
                .field("fence_every", fence_every)
                .finish(),
        }
    }
}

/// The iroh binding's listener (transport.md, "The iroh binding").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohConfig {
    /// The UDP socket to bind. Its home relays are [`Settings::relays`].
    pub bind: SocketAddr,
}

/// iroh's relay server, run inside the peer so that devices can use it as
/// their iroh relay: it forwards the QUIC packets of two endpoints that
/// have no direct path, and reads none of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrohRelayConfig {
    /// The relay's listener: plain HTTP behind a reverse proxy that
    /// terminates TLS, or HTTPS with [`IrohRelayConfig::tls`].
    pub listen: SocketAddr,
    /// The relay's own certificate, if it terminates TLS itself.
    pub tls: Option<RelayTls>,
    /// QUIC address discovery's UDP socket, which needs
    /// [`IrohRelayConfig::tls`]. Devices look for it on port 7842.
    pub quic: Option<SocketAddr>,
}

/// A certificate and key the relay serves HTTPS and QUIC with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTls {
    /// The certificate chain, PEM.
    pub cert: PathBuf,
    /// The private key, PEM.
    pub key: PathBuf,
    /// The plain HTTP listener for the captive-portal probe, which iroh
    /// serves beside HTTPS.
    pub http_listen: SocketAddr,
}

/// Everything the peer runs with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// The HTTP listener; a reverse proxy terminates TLS in front of it.
    pub listen: SocketAddr,
    /// The directory of the database, the iroh key and, by default, the
    /// object chunks.
    pub data_dir: PathBuf,
    /// The iroh listener, or none.
    pub iroh: Option<IrohConfig>,
    /// The embedded iroh relay, or none.
    pub iroh_relay: Option<IrohRelayConfig>,
    /// Where object chunks live.
    pub objects: ObjectsConfig,
    /// Where the records live.
    pub store: StoreConfig,
    /// The cluster this node is a member of, or none for a peer on one
    /// machine.
    pub cluster: Option<crate::cluster::ClusterConfig>,
    /// The operator's settings.
    pub settings: Settings,
}

impl Config {
    /// Reads the configuration from `FRASIL_*` variables:
    ///
    /// - `FRASIL_EXTENSIONS`, the extensions that are on, separated by
    ///   spaces or commas: `ephemeral`, `file-versions`, `invite-links`,
    ///   `libraries`, `deposit-tokens` (with `libraries` only), or `none`;
    ///   `libraries` and `deposit-tokens` by default. `FRASIL_MAX_FILE_VERSIONS` and
    ///   `FRASIL_FILE_VERSION_RETENTION` are file-versions' settings, and
    ///   `FRASIL_LIBRARY_ISSUERS`, `FRASIL_DETACHED_GRACE`,
    ///   `FRASIL_LIBRARY_QUOTAS`, `FRASIL_OPEN_LIBRARY` and
    ///   `FRASIL_OPERATOR_TOKEN` libraries', and `FRASIL_DEPOSIT_ALLOWANCE`,
    ///   `FRASIL_SPACE_SHARE`, `FRASIL_TOKEN_PERIOD`,
    ///   `FRASIL_TOKEN_BUDGET_ITEMS`, `FRASIL_TOKEN_BUDGET_BYTES` and
    ///   `FRASIL_REFUSED_TOKENS_PER_MINUTE` deposit tokens' (crate
    ///   `deposit`); each is refused while its extension is off. Without
    ///   `FRASIL_LIBRARY_ISSUERS`, [`crate::run`] trusts the operator's own
    ///   issuer (crate `libraries`, `operator`);
    /// - `FRASIL_HOSTING` (`closed` or `open`, default `closed`): with
    ///   libraries on, `open` attaches a create without a ticket to the
    ///   library `FRASIL_OPEN_LIBRARY` names, and is refused without it;
    ///   `FRASIL_OPEN_LIBRARY` is refused with `closed`;
    /// - `FRASIL_TRUSTED_PROXIES`: the reverse proxies whose
    ///   `X-Forwarded-For` names the client, as addresses or networks
    ///   (`10.0.0.0/8`), separated by spaces or commas; none by default
    ///   (crate `source`);
    /// - `FRASIL_LISTEN` (default `127.0.0.1:8787`), `FRASIL_DATA_DIR`
    ///   (default `./frasil-data`), `FRASIL_ORIGIN`, `FRASIL_NATIVE_ORIGIN`,
    ///   `FRASIL_ACCOUNT_URL`, `FRASIL_RELAYS` (iroh relays, HTTPS URLs,
    ///   space separated);
    /// - `FRASIL_IROH` (`on` or `off`, default `on`), `FRASIL_IROH_BIND`
    ///   (default `0.0.0.0:0`);
    /// - `FRASIL_RELAY_LISTEN`, which turns the embedded iroh relay on, with
    ///   `FRASIL_RELAY_TLS_CERT` and `FRASIL_RELAY_TLS_KEY` (PEM files, both
    ///   or neither), `FRASIL_RELAY_HTTP_LISTEN` (with TLS, default
    ///   `127.0.0.1:0`) and `FRASIL_RELAY_QUIC` (with TLS);
    /// - `FRASIL_OBJECTS` (`files` or `s3`), with `FRASIL_S3_ENDPOINT`,
    ///   `FRASIL_S3_REGION`, `FRASIL_S3_BUCKET`, `FRASIL_S3_ACCESS_KEY`,
    ///   `FRASIL_S3_SECRET_KEY`, `FRASIL_S3_PREFIX`, `FRASIL_S3_PATH_STYLE`;
    /// - `FRASIL_ERASURE_TIMEOUT`, `FRASIL_RELEASE_RETENTION`,
    ///   `FRASIL_ORPHAN_GRACE`, `FRASIL_MAILBOX_RETENTION`,
    ///   `FRASIL_UNCOLLECTED_RETENTION` (at most `mailbox_retention`),
    ///   `FRASIL_RECONNECT_DRAIN` in seconds, each
    ///   within overview.md's range; `FRASIL_CUT_RETENTION` in seconds (0
    ///   to 365 days, default 30 days); `FRASIL_CREDENTIAL_CAP` (16 to 4,096),
    ///   `FRASIL_PENDING_CAP`, `FRASIL_SPACE_QUOTA_BYTES`;
    /// - `FRASIL_DEVICE_MAILBOX_ITEMS` (at least 16),
    ///   `FRASIL_DEVICE_MAILBOX_BYTES` (at least 4 MiB) and
    ///   `FRASIL_DEVICE_MAILBOX_DEPOSITS_PER_MINUTE` (at least 1): the
    ///   [`DeviceMailLimits`];
    /// - `FRASIL_MAX_CONNECTIONS`, `FRASIL_MAX_CONNECTIONS_PER_SOURCE` (0
    ///   for none), `FRASIL_HEADER_READ_TIMEOUT`, `FRASIL_IDLE_TIMEOUT`,
    ///   `FRASIL_KEEPALIVE_INTERVAL`, `FRASIL_WRITE_TIMEOUT` (each 1 to
    ///   86,400 seconds), `FRASIL_QUEUED_BYTES` (at least 1 MiB),
    ///   `FRASIL_UNGRANTED_PER_MINUTE`, `FRASIL_STAGED_OBJECTS` and
    ///   `FRASIL_ADMIN_CONNECTIONS_PER_SPACE`: [`ConnectionLimits`];
    /// - `FRASIL_EPHEMERAL_FRAMES_PER_SECOND` (at least 1, default 200):
    ///   [`Rates::ephemeral_frames_per_second`], with ext-ephemeral on;
    /// - `FRASIL_STORE` (`directory` or `bucket`, default `directory`): the
    ///   records' shards under the data directory's `shards`, or in the
    ///   bucket the `FRASIL_S3_*` settings name, under `FRASIL_STORE_PREFIX`
    ///   (default `records/`), with their working copies in
    ///   `FRASIL_SHARD_CACHE` (default the data directory's `cache`), and,
    ///   without a cluster, `FRASIL_FENCE_INTERVAL` (1 to 3,600 seconds), how
    ///   often the node reads its records in the bucket;
    /// - `FRASIL_GROUP_COMMIT_MS`, the group commit's window in
    ///   milliseconds (0 to 100; default 2, or 20 with a bucket, where each
    ///   group is one PUT per shard), and `FRASIL_IDLE_CLOSE`, the seconds a
    ///   space, or a shard of spaces, stays open after its last use
    ///   (default 600).
    ///
    /// # Errors
    ///
    /// A variable that does not read, or is out of its range.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|name| std::env::var(name).ok().filter(|v| !v.is_empty()))
    }

    /// [`Config::from_env`] over any lookup, for tests.
    ///
    /// # Errors
    ///
    /// As [`Config::from_env`].
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let parse_addr = |name: &str, default: &str| -> Result<SocketAddr, ConfigError> {
            get(name)
                .unwrap_or_else(|| default.to_owned())
                .parse()
                .map_err(|_| ConfigError(format!("{name} is not a socket address")))
        };
        let data_dir = get("FRASIL_DATA_DIR").map_or_else(|| "./frasil-data".into(), PathBuf::from);
        let mut settings = Settings::default();
        let timer = |name: &str, which: Timer, value: &mut u64| -> Result<(), ConfigError> {
            if let Some(text) = get(name) {
                let seconds: u64 = text
                    .parse()
                    .map_err(|_| ConfigError(format!("{name} is not a number of seconds")))?;
                if !which.spec().allows(seconds) {
                    return Err(ConfigError(format!(
                        "{name} is outside {}'s range",
                        which.name()
                    )));
                }
                *value = seconds;
            }
            Ok(())
        };
        timer(
            "FRASIL_ERASURE_TIMEOUT",
            Timer::ErasureTimeout,
            &mut settings.erasure_timeout,
        )?;
        timer(
            "FRASIL_RELEASE_RETENTION",
            Timer::ReleaseRetention,
            &mut settings.release_retention,
        )?;
        timer(
            "FRASIL_ORPHAN_GRACE",
            Timer::OrphanGrace,
            &mut settings.orphan_grace,
        )?;
        timer(
            "FRASIL_FILE_VERSION_RETENTION",
            Timer::FileVersionRetention,
            &mut settings.file_version_retention,
        )?;
        if let Some(text) = get("FRASIL_CUT_RETENTION") {
            settings.cut_retention = text
                .parse()
                .ok()
                .filter(|&seconds: &u64| seconds <= frasil_peers::limits::MAX_CUT_RETENTION)
                .ok_or_else(|| {
                    ConfigError(
                        "FRASIL_CUT_RETENTION is not a number of seconds from 0 to 365 days".into(),
                    )
                })?;
        }
        if let Some(text) = get("FRASIL_MAX_FILE_VERSIONS") {
            let (low, high) = MAX_FILE_VERSIONS_RANGE;
            settings.max_file_versions = text
                .parse()
                .ok()
                .filter(|versions| (low..=high).contains(versions))
                .ok_or_else(|| {
                    ConfigError(format!(
                        "FRASIL_MAX_FILE_VERSIONS is not a count from {low} to {high}"
                    ))
                })?;
        }
        timer(
            "FRASIL_RECONNECT_DRAIN",
            Timer::ReconnectDrain,
            &mut settings.reconnect_drain,
        )?;
        timer(
            "FRASIL_MAILBOX_RETENTION",
            Timer::MailboxRetention,
            &mut settings.mailbox_retention,
        )?;
        timer(
            "FRASIL_UNCOLLECTED_RETENTION",
            Timer::UncollectedRetention,
            &mut settings.uncollected_retention,
        )?;
        if settings.uncollected_retention > settings.mailbox_retention {
            return Err(ConfigError(
                "FRASIL_UNCOLLECTED_RETENTION is longer than mailbox_retention".into(),
            ));
        }
        if let Some(text) = get("FRASIL_CREDENTIAL_CAP") {
            let cap: usize = text
                .parse()
                .ok()
                .filter(|cap| {
                    (frasil_peers::limits::MIN_CREDENTIAL_CAP
                        ..=frasil_peers::limits::MAX_CREDENTIAL_CAP)
                        .contains(cap)
                })
                .ok_or_else(|| ConfigError("FRASIL_CREDENTIAL_CAP is not 16 to 4,096".into()))?;
            settings.credential_cap = cap;
        }
        if let Some(text) = get("FRASIL_PENDING_CAP") {
            settings.pending_cap = text
                .parse()
                .ok()
                .filter(|&cap: &usize| cap >= 1)
                .ok_or_else(|| ConfigError("FRASIL_PENDING_CAP is not a count".into()))?;
        }
        let at_least = |name: &str, least: usize, value: &mut usize| -> Result<(), ConfigError> {
            if let Some(text) = get(name) {
                *value = text
                    .parse()
                    .ok()
                    .filter(|&count: &usize| count >= least)
                    .ok_or_else(|| {
                        ConfigError(format!("{name} is not a count of {least} or more"))
                    })?;
            }
            Ok(())
        };
        at_least(
            "FRASIL_DEVICE_MAILBOX_ITEMS",
            DeviceMailLimits::MIN_ITEMS,
            &mut settings.device_mail.items,
        )?;
        at_least(
            "FRASIL_DEVICE_MAILBOX_BYTES",
            DeviceMailLimits::MIN_BYTES,
            &mut settings.device_mail.bytes,
        )?;
        at_least(
            "FRASIL_DEVICE_MAILBOX_DEPOSITS_PER_MINUTE",
            1,
            &mut settings.device_mail.deposits_per_minute,
        )?;
        at_least(
            "FRASIL_EPHEMERAL_FRAMES_PER_SECOND",
            1,
            &mut settings.rates.ephemeral_frames_per_second,
        )?;
        let limits = &mut settings.connections;
        at_least("FRASIL_MAX_CONNECTIONS", 1, &mut limits.max_connections)?;
        at_least(
            "FRASIL_MAX_CONNECTIONS_PER_SOURCE",
            0,
            &mut limits.max_connections_per_source,
        )?;
        at_least("FRASIL_QUEUED_BYTES", 1 << 20, &mut limits.queued_bytes)?;
        at_least(
            "FRASIL_UNGRANTED_PER_MINUTE",
            1,
            &mut limits.ungranted_per_minute,
        )?;
        at_least("FRASIL_STAGED_OBJECTS", 1, &mut limits.staged_objects)?;
        at_least(
            "FRASIL_ADMIN_CONNECTIONS_PER_SPACE",
            1,
            &mut limits.admin_connections_per_space,
        )?;
        let seconds = |name: &str, value: &mut u64| -> Result<(), ConfigError> {
            if let Some(text) = get(name) {
                *value = text
                    .parse()
                    .ok()
                    .filter(|&seconds: &u64| (1..=86_400).contains(&seconds))
                    .ok_or_else(|| ConfigError(format!("{name} is not 1 to 86,400 seconds")))?;
            }
            Ok(())
        };
        seconds(
            "FRASIL_HEADER_READ_TIMEOUT",
            &mut limits.header_read_timeout,
        )?;
        seconds("FRASIL_IDLE_TIMEOUT", &mut limits.idle_timeout)?;
        seconds("FRASIL_KEEPALIVE_INTERVAL", &mut limits.keepalive_interval)?;
        seconds("FRASIL_WRITE_TIMEOUT", &mut limits.write_timeout)?;
        if let Some(text) = get("FRASIL_SPACE_QUOTA_BYTES") {
            settings.space_quota = text
                .parse()
                .map_err(|_| ConfigError("FRASIL_SPACE_QUOTA_BYTES is not a count".into()))?;
        }
        let s3 = |what: &str| -> Result<S3Config, ConfigError> {
            let need = |name: &str| {
                get(name).ok_or_else(|| ConfigError(format!("{name} is needed for {what}")))
            };
            Ok(S3Config {
                endpoint: need("FRASIL_S3_ENDPOINT")?,
                region: get("FRASIL_S3_REGION").unwrap_or_else(|| "auto".into()),
                bucket: need("FRASIL_S3_BUCKET")?,
                access_key: need("FRASIL_S3_ACCESS_KEY")?,
                secret_key: need("FRASIL_S3_SECRET_KEY")?,
                prefix: get("FRASIL_S3_PREFIX").unwrap_or_default(),
                path_style: get("FRASIL_S3_PATH_STYLE").as_deref() == Some("true"),
            })
        };
        let store = match get("FRASIL_STORE").as_deref() {
            None | Some("directory") => StoreConfig::Directory(data_dir.join("shards")),
            Some("bucket") => {
                let prefix = get("FRASIL_STORE_PREFIX").unwrap_or_else(|| "records/".into());
                let objects_prefix = get("FRASIL_S3_PREFIX").unwrap_or_default();
                if prefix.is_empty() || prefix.starts_with('/') || prefix == objects_prefix {
                    return Err(ConfigError(
                        "FRASIL_STORE_PREFIX is empty, absolute, or the objects' prefix".into(),
                    ));
                }
                settings.group_commit.window = std::time::Duration::from_millis(20);
                StoreConfig::Bucket {
                    s3: s3("FRASIL_STORE=bucket")?,
                    prefix,
                    cache: get("FRASIL_SHARD_CACHE")
                        .map_or_else(|| data_dir.join("cache"), PathBuf::from),
                    node: data_dir.join("node"),
                    fence_every: fence_every(&get)?,
                }
            }
            Some(_) => {
                return Err(ConfigError(
                    "FRASIL_STORE is not directory or bucket".into(),
                ));
            }
        };
        if let Some(text) = get("FRASIL_GROUP_COMMIT_MS") {
            let millis: u64 = text
                .parse()
                .ok()
                .filter(|&millis| millis <= 100)
                .ok_or_else(|| ConfigError("FRASIL_GROUP_COMMIT_MS is not 0 to 100".into()))?;
            settings.group_commit.window = std::time::Duration::from_millis(millis);
        }
        if let Some(text) = get("FRASIL_IDLE_CLOSE") {
            settings.idle_close = text
                .parse()
                .map_err(|_| ConfigError("FRASIL_IDLE_CLOSE is not a count of seconds".into()))?;
        }
        settings.hosting = match get("FRASIL_HOSTING").as_deref() {
            None | Some("closed") => Hosting::Closed,
            Some("open") => Hosting::Open,
            Some(_) => return Err(ConfigError("FRASIL_HOSTING is not closed or open".into())),
        };
        if let Some(text) = get("FRASIL_TRUSTED_PROXIES") {
            settings.trusted_proxies = crate::source::TrustedProxies::parse(&text)?;
        }
        settings.origin = get("FRASIL_ORIGIN")
            .map(|origin| check_origin("FRASIL_ORIGIN", &origin).map(|()| origin))
            .transpose()?;
        settings.native_origin = get("FRASIL_NATIVE_ORIGIN")
            .map(|origin| check_origin("FRASIL_NATIVE_ORIGIN", &origin).map(|()| origin))
            .transpose()?;
        settings.account_url = get("FRASIL_ACCOUNT_URL");
        settings.relays = get("FRASIL_RELAYS")
            .unwrap_or_default()
            .split_whitespace()
            .map(str::to_owned)
            .collect();
        check_relays(&settings.relays)?;
        settings.extensions = match get("FRASIL_EXTENSIONS") {
            Some(text) => Extensions::parse(&text)?,
            None => Extensions::DEFAULT,
        };
        check_extension_settings(&get, settings.extensions)?;
        if settings.extensions.libraries {
            settings.libraries = crate::libraries::LibrarySettings::from_lookup(&get)?;
            match settings.hosting {
                // A create without a ticket is the operator's own hosting
                // (ext-libraries.md, 2.4 Settings, "open library"): the
                // operator says which library takes it.
                Hosting::Open if settings.libraries.open_library.is_none() => {
                    return Err(ConfigError(
                        "FRASIL_HOSTING=open hosts every space created without a ticket, \
                         and FRASIL_OPEN_LIBRARY names no library to attach them to: name \
                         one, such as FRASIL_OPEN_LIBRARY=open:public, or set \
                         FRASIL_HOSTING=closed to host only the spaces a ticket attached"
                            .into(),
                    ));
                }
                Hosting::Closed if settings.libraries.open_library.is_some() => {
                    return Err(ConfigError(
                        "FRASIL_OPEN_LIBRARY takes creates without a ticket, which \
                         FRASIL_HOSTING=closed refuses: set FRASIL_HOSTING=open as well"
                            .into(),
                    ));
                }
                _ => {}
            }
        }
        if settings.extensions.deposit_tokens {
            settings.deposit_tokens = crate::deposit::DepositSettings::from_lookup(&get)?;
        }
        let iroh = match get("FRASIL_IROH").as_deref() {
            None | Some("on") => Some(IrohConfig {
                bind: parse_addr("FRASIL_IROH_BIND", "0.0.0.0:0")?,
            }),
            Some("off") => None,
            Some(_) => return Err(ConfigError("FRASIL_IROH is not on or off".into())),
        };
        let iroh_relay = match get("FRASIL_RELAY_LISTEN") {
            None => {
                if get("FRASIL_RELAY_TLS_CERT").is_some()
                    || get("FRASIL_RELAY_TLS_KEY").is_some()
                    || get("FRASIL_RELAY_QUIC").is_some()
                {
                    return Err(ConfigError(
                        "the iroh relay's settings need FRASIL_RELAY_LISTEN".into(),
                    ));
                }
                None
            }
            Some(_) => {
                let tls = match (get("FRASIL_RELAY_TLS_CERT"), get("FRASIL_RELAY_TLS_KEY")) {
                    (Some(cert), Some(key)) => Some(RelayTls {
                        cert: cert.into(),
                        key: key.into(),
                        http_listen: parse_addr("FRASIL_RELAY_HTTP_LISTEN", "127.0.0.1:0")?,
                    }),
                    (None, None) => None,
                    _ => {
                        return Err(ConfigError(
                            "FRASIL_RELAY_TLS_CERT and FRASIL_RELAY_TLS_KEY go together".into(),
                        ));
                    }
                };
                let quic = match get("FRASIL_RELAY_QUIC") {
                    Some(_) if tls.is_none() => {
                        return Err(ConfigError(
                            "FRASIL_RELAY_QUIC needs FRASIL_RELAY_TLS_CERT and FRASIL_RELAY_TLS_KEY"
                                .into(),
                        ));
                    }
                    Some(_) => Some(parse_addr("FRASIL_RELAY_QUIC", "")?),
                    None => None,
                };
                Some(IrohRelayConfig {
                    listen: parse_addr("FRASIL_RELAY_LISTEN", "")?,
                    tls,
                    quic,
                })
            }
        };
        let objects = match get("FRASIL_OBJECTS").as_deref() {
            None | Some("files") => ObjectsConfig::Files(data_dir.join("objects")),
            Some("s3") => ObjectsConfig::S3(s3("s3")?),
            Some(_) => return Err(ConfigError("FRASIL_OBJECTS is not files or s3".into())),
        };
        let cluster = match get("FRASIL_CLUSTER_KEY") {
            None => None,
            Some(key) => {
                if !matches!(store, StoreConfig::Bucket { .. })
                    || !matches!(objects, ObjectsConfig::S3(_))
                {
                    return Err(ConfigError(
                        "a cluster needs FRASIL_STORE=bucket and FRASIL_OBJECTS=s3: its nodes \
                         share one bucket"
                            .into(),
                    ));
                }
                Some(cluster_config(&get, &key, &parse_addr)?)
            }
        };
        if cluster.is_none()
            && let Some(name) = [
                "FRASIL_CLUSTER_LISTEN",
                "FRASIL_CLUSTER_ADVERTISE",
                "FRASIL_CLUSTER_SEEDS",
                "FRASIL_CLUSTER_BOOTSTRAP",
            ]
            .into_iter()
            .find(|name| get(name).is_some())
        {
            return Err(ConfigError(format!("{name} needs FRASIL_CLUSTER_KEY")));
        }
        if get("FRASIL_FENCE_INTERVAL").is_some()
            && (cluster.is_some() || !matches!(store, StoreConfig::Bucket { .. }))
        {
            return Err(ConfigError(
                "FRASIL_FENCE_INTERVAL is for a single node on a bucket: FRASIL_STORE=bucket \
                 without FRASIL_CLUSTER_KEY"
                    .into(),
            ));
        }
        Ok(Self {
            listen: parse_addr("FRASIL_LISTEN", "127.0.0.1:8787")?,
            data_dir,
            iroh,
            iroh_relay,
            objects,
            store,
            cluster,
            settings,
        })
    }
}

/// The settings of each extension, which only that extension reads.
const EXTENSION_SETTINGS: [(&str, &[&str]); 4] = [
    ("ephemeral", &["FRASIL_EPHEMERAL_FRAMES_PER_SECOND"]),
    (
        "file-versions",
        &["FRASIL_MAX_FILE_VERSIONS", "FRASIL_FILE_VERSION_RETENTION"],
    ),
    (
        "libraries",
        &[
            "FRASIL_LIBRARY_ISSUERS",
            "FRASIL_DETACHED_GRACE",
            "FRASIL_LIBRARY_QUOTAS",
            "FRASIL_OPEN_LIBRARY",
            "FRASIL_OPERATOR_TOKEN",
        ],
    ),
    ("deposit-tokens", &crate::deposit::DepositSettings::NAMES),
];

/// A setting of an extension that is off is refused, so that a peer never
/// runs without an extension its operator configured.
fn check_extension_settings(
    get: &impl Fn(&str) -> Option<String>,
    extensions: Extensions,
) -> Result<(), ConfigError> {
    for (extension, names) in EXTENSION_SETTINGS {
        let on = match extension {
            "ephemeral" => extensions.ephemeral,
            "file-versions" => extensions.file_versions,
            "deposit-tokens" => extensions.deposit_tokens,
            _ => extensions.libraries,
        };
        if let Some(name) = names.iter().find(|name| !on && get(name).is_some()) {
            return Err(ConfigError(format!(
                "{name} is a setting of the {extension} extension, which is off: add \
                 {extension} to FRASIL_EXTENSIONS"
            )));
        }
    }
    Ok(())
}

/// The cluster's settings, `FRASIL_CLUSTER_*` (crate `cluster`).
fn cluster_config(
    get: &impl Fn(&str) -> Option<String>,
    key: &str,
    parse_addr: &impl Fn(&str, &str) -> Result<SocketAddr, ConfigError>,
) -> Result<crate::cluster::ClusterConfig, ConfigError> {
    use crate::cluster::lease::Timing;
    let key = zeroize::Zeroizing::new(
        crate::util::unhex::<32>(key.trim())
            .ok_or_else(|| ConfigError("FRASIL_CLUSTER_KEY is not 64 hex digits".into()))?,
    );
    if crate::cluster::handshake::is_zero(&key) {
        return Err(ConfigError(format!(
            "FRASIL_CLUSTER_KEY: {}",
            crate::cluster::ZERO_KEY
        )));
    }
    // Loopback unless the operator names the interface the other nodes
    // reach: whoever reaches the port may take handshake slots.
    let listen = parse_addr("FRASIL_CLUSTER_LISTEN", "127.0.0.1:8788")?;
    let advertise = match get("FRASIL_CLUSTER_ADVERTISE") {
        Some(address) => address,
        None if !listen.ip().is_unspecified() => listen.to_string(),
        None => {
            return Err(ConfigError(
                "FRASIL_CLUSTER_ADVERTISE names where other nodes reach this one, \
                 when FRASIL_CLUSTER_LISTEN binds every address"
                    .into(),
            ));
        }
    };
    let seeds: Vec<String> = get("FRASIL_CLUSTER_SEEDS")
        .map(|seeds| {
            seeds
                .split(',')
                .map(str::trim)
                .filter(|seed| !seed.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let bootstrap = match get("FRASIL_CLUSTER_BOOTSTRAP").as_deref() {
        None | Some("false") => false,
        Some("true") => true,
        Some(_) => {
            return Err(ConfigError(
                "FRASIL_CLUSTER_BOOTSTRAP is not true or false".into(),
            ));
        }
    };
    if !bootstrap && seeds.is_empty() {
        return Err(ConfigError(
            "a node that does not bootstrap the cluster joins it through FRASIL_CLUSTER_SEEDS"
                .into(),
        ));
    }
    let number = |name: &str, default: u64, range: std::ops::RangeInclusive<u64>| match get(name) {
        None => Ok(default),
        Some(text) => text
            .parse::<u64>()
            .ok()
            .filter(|n| range.contains(n))
            .ok_or_else(|| {
                ConfigError(format!(
                    "{name} is not {} to {}",
                    range.start(),
                    range.end()
                ))
            }),
    };
    let capacity = number("FRASIL_CLUSTER_CAPACITY", 100, 1..=10_000)? as u32;
    let spaces_per_connection = number(
        "FRASIL_CLUSTER_SPACES_PER_CONNECTION",
        crate::cluster::SPACES_PER_CONNECTION as u64,
        1..=65_536,
    )? as usize;
    let defaults = Timing::DEFAULT;
    let timing = Timing {
        lease: std::time::Duration::from_millis(number(
            "FRASIL_CLUSTER_LEASE_MS",
            defaults.lease.as_millis() as u64,
            500..=60_000,
        )?),
        renew: std::time::Duration::from_millis(number(
            "FRASIL_CLUSTER_RENEW_MS",
            defaults.renew.as_millis() as u64,
            50..=10_000,
        )?),
        drift: number(
            "FRASIL_CLUSTER_DRIFT_PERCENT",
            (defaults.drift * 100.0) as u64,
            1..=49,
        )? as f64
            / 100.0,
        put_timeout: std::time::Duration::from_millis(number(
            "FRASIL_CLUSTER_PUT_TIMEOUT_MS",
            defaults.put_timeout.as_millis() as u64,
            50..=30_000,
        )?),
    };
    if let Some(why) = timing.check() {
        return Err(ConfigError(format!("the cluster's lease timing: {why}")));
    }
    Ok(crate::cluster::ClusterConfig {
        key,
        listen,
        advertise,
        seeds,
        capacity,
        bootstrap,
        timing,
        spaces_per_connection,
    })
}

/// An origin: a scheme, a host and an optional port, nothing else.
/// `FRASIL_FENCE_INTERVAL`, or the default for a metered store.
fn fence_every(get: &impl Fn(&str) -> Option<String>) -> Result<std::time::Duration, ConfigError> {
    let Some(text) = get("FRASIL_FENCE_INTERVAL") else {
        return Ok(crate::shards::fence::READING_EVERY);
    };
    text.parse()
        .ok()
        .filter(|seconds| (1..=3_600).contains(seconds))
        .map(std::time::Duration::from_secs)
        .ok_or_else(|| ConfigError("FRASIL_FENCE_INTERVAL is not 1 to 3,600 seconds".into()))
}

fn check_origin(name: &str, origin: &str) -> Result<(), ConfigError> {
    let rest = origin
        .strip_prefix("https://")
        .or_else(|| origin.strip_prefix("http://"))
        .ok_or_else(|| ConfigError(format!("{name} is not an http or https origin")))?;
    if rest.is_empty() || rest.contains(['/', '?', '#', '@']) {
        return Err(ConfigError(format!(
            "{name} has a path, query, fragment or credentials"
        )));
    }
    Ok(())
}

/// Relay URLs: at most 4 (transport.md's tickets), HTTPS, with no
/// credentials, query or fragment.
fn check_relays(relays: &[String]) -> Result<(), ConfigError> {
    if relays.len() > 4 {
        return Err(ConfigError("at most 4 iroh relays".into()));
    }
    for relay in relays {
        let Some(rest) = relay.strip_prefix("https://") else {
            return Err(ConfigError("iroh relays are https URLs".into()));
        };
        if rest.is_empty() || rest.contains(['?', '#', '@']) || relay.len() > 2048 {
            return Err(ConfigError(
                "iroh relays have no credentials, query or fragment".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn config(vars: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let vars: BTreeMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::from_lookup(|name| vars.get(name).cloned())
    }

    /// The cluster's settings, as `cluster_config` reads them.
    fn cluster(vars: &[(&str, &str)]) -> Result<crate::cluster::ClusterConfig, ConfigError> {
        let vars: BTreeMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let get = |name: &str| vars.get(name).cloned();
        let parse_addr = |name: &str, default: &str| -> Result<SocketAddr, ConfigError> {
            get(name)
                .unwrap_or_else(|| default.to_owned())
                .parse()
                .map_err(|_| ConfigError(format!("{name} is not a socket address")))
        };
        let key = get("FRASIL_CLUSTER_KEY").unwrap_or_default();
        cluster_config(&get, &key, &parse_addr)
    }

    /// An all-zero cluster key is refused, and the links listen on
    /// loopback unless the operator names an interface.
    #[test]
    fn the_cluster_key_is_no_zeros_and_the_links_listen_on_loopback() {
        let seed = ("FRASIL_CLUSTER_BOOTSTRAP", "true");
        let zeros = "0".repeat(64);
        let refused = cluster(&[("FRASIL_CLUSTER_KEY", &zeros), seed]).unwrap_err();
        assert!(refused.0.contains("all zeros"), "{}", refused.0);
        let key = "07".repeat(32);
        let config = cluster(&[("FRASIL_CLUSTER_KEY", &key), seed]).unwrap();
        assert!(config.listen.ip().is_loopback());
        assert_eq!(config.advertise, "127.0.0.1:8788");
        assert_eq!(
            config.spaces_per_connection,
            crate::cluster::SPACES_PER_CONNECTION
        );
        assert!(
            !format!("{config:?}").contains("0707"),
            "the key is never printed"
        );
        let open = cluster(&[
            ("FRASIL_CLUSTER_KEY", &key),
            seed,
            ("FRASIL_CLUSTER_LISTEN", "0.0.0.0:8788"),
        ]);
        assert!(open.is_err(), "every address needs an advertised one");
        assert!(
            cluster(&[
                ("FRASIL_CLUSTER_KEY", &key),
                seed,
                ("FRASIL_CLUSTER_SPACES_PER_CONNECTION", "0"),
            ])
            .is_err()
        );
    }

    #[test]
    fn defaults_follow_the_timer_table() {
        let config = config(&[]).unwrap();
        assert_eq!(config.settings.erasure_timeout, 7 * 86_400);
        assert_eq!(config.settings.release_retention, 30 * 86_400);
        assert_eq!(config.settings.orphan_grace, 86_400);
        assert_eq!(config.settings.cut_retention, 30 * 86_400);
        assert_eq!(config.settings.credential_cap, 256);
        assert_eq!(config.settings.reconnect_drain, 60);
        assert_eq!(config.settings.connections.max_connections, 16_384);
        assert_eq!(config.settings.connections.max_connections_per_source, 512);
        assert!(config.iroh.is_some());
    }

    #[test]
    fn connection_limits_read_within_their_ranges() {
        let config = config(&[
            ("FRASIL_MAX_CONNECTIONS", "100"),
            ("FRASIL_MAX_CONNECTIONS_PER_SOURCE", "0"),
            ("FRASIL_IDLE_TIMEOUT", "60"),
            ("FRASIL_QUEUED_BYTES", "2097152"),
        ])
        .unwrap();
        let limits = config.settings.connections;
        assert_eq!(limits.max_connections, 100);
        assert_eq!(limits.max_connections_per_source, 0);
        assert_eq!(limits.idle_timeout, 60);
        assert_eq!(limits.queued_bytes, 2 << 20);
        assert_eq!(
            limits.write_timeout,
            ConnectionLimits::DEFAULT.write_timeout
        );
        assert!(config_err("FRASIL_MAX_CONNECTIONS", "0"));
        assert!(config_err("FRASIL_IDLE_TIMEOUT", "0"));
        assert!(config_err("FRASIL_KEEPALIVE_INTERVAL", "86401"));
        assert!(config_err("FRASIL_QUEUED_BYTES", "1024"));
        assert!(config_err("FRASIL_STAGED_OBJECTS", "0"));
    }

    fn config_err(name: &str, value: &str) -> bool {
        config(&[(name, value)]).is_err()
    }

    #[test]
    fn ranges_are_checked() {
        assert!(config(&[("FRASIL_ERASURE_TIMEOUT", "60")]).is_err());
        assert!(config(&[("FRASIL_ERASURE_TIMEOUT", "3600")]).is_ok());
        assert!(config(&[("FRASIL_CREDENTIAL_CAP", "8")]).is_err());
        assert!(config(&[("FRASIL_RECONNECT_DRAIN", "601")]).is_err());
        assert!(config(&[("FRASIL_CUT_RETENTION", "31536001")]).is_err());
        assert!(config(&[("FRASIL_CUT_RETENTION", "a month")]).is_err());
        assert_eq!(
            config(&[("FRASIL_CUT_RETENTION", "0")])
                .unwrap()
                .settings
                .cut_retention,
            0
        );
        assert!(config(&[("FRASIL_DEVICE_MAILBOX_ITEMS", "15")]).is_err());
        assert!(config(&[("FRASIL_DEVICE_MAILBOX_BYTES", "4194303")]).is_err());
        assert!(config(&[("FRASIL_DEVICE_MAILBOX_DEPOSITS_PER_MINUTE", "0")]).is_err());
        let ephemeral = ("FRASIL_EXTENSIONS", "ephemeral");
        assert!(config(&[ephemeral, ("FRASIL_EPHEMERAL_FRAMES_PER_SECOND", "0")]).is_err());
        // A setting of the ephemeral extension while it is off.
        assert!(config(&[("FRASIL_EPHEMERAL_FRAMES_PER_SECOND", "50")]).is_err());
        assert_eq!(
            config(&[ephemeral, ("FRASIL_EPHEMERAL_FRAMES_PER_SECOND", "50")])
                .unwrap()
                .settings
                .rates
                .ephemeral_frames_per_second,
            50
        );
        assert_eq!(
            config(&[])
                .unwrap()
                .settings
                .rates
                .ephemeral_frames_per_second,
            200
        );
        let limits = config(&[
            ("FRASIL_DEVICE_MAILBOX_ITEMS", "16"),
            ("FRASIL_DEVICE_MAILBOX_BYTES", "4194304"),
            ("FRASIL_DEVICE_MAILBOX_DEPOSITS_PER_MINUTE", "1"),
        ])
        .unwrap()
        .settings
        .device_mail;
        assert_eq!(
            (limits.items, limits.bytes, limits.deposits_per_minute),
            (16, 4 << 20, 1)
        );
        assert_eq!(
            config(&[("FRASIL_RECONNECT_DRAIN", "0")])
                .unwrap()
                .settings
                .reconnect_drain,
            0
        );
        assert!(config(&[("FRASIL_ORIGIN", "https://peer.example.org/x")]).is_err());
        assert!(config(&[("FRASIL_NATIVE_ORIGIN", "wss://sync.example.org")]).is_err());
        assert_eq!(
            config(&[("FRASIL_NATIVE_ORIGIN", "https://sync.example.org")])
                .unwrap()
                .settings
                .native_origin
                .as_deref(),
            Some("https://sync.example.org")
        );
        assert!(config(&[("FRASIL_RELAYS", "http://relay.example.org")]).is_err());
        let relays = config(&[
            ("FRASIL_IROH", "off"),
            (
                "FRASIL_RELAYS",
                "https://a.example.org https://b.example.org",
            ),
        ])
        .unwrap();
        assert_eq!(relays.iroh, None);
        assert_eq!(
            relays.settings.relays,
            ["https://a.example.org", "https://b.example.org"]
        );
        assert!(config(&[("FRASIL_OBJECTS", "s3")]).is_err());
    }

    #[test]
    fn records_live_in_a_directory_or_a_bucket() {
        let plain = config(&[("FRASIL_DATA_DIR", "/srv/frasil")]).unwrap();
        assert_eq!(
            plain.store,
            StoreConfig::Directory(PathBuf::from("/srv/frasil/shards"))
        );
        assert_eq!(plain.settings.group_commit.window.as_millis(), 2);
        assert!(config(&[("FRASIL_STORE", "bucket")]).is_err());
        let s3 = [
            ("FRASIL_DATA_DIR", "/srv/frasil"),
            ("FRASIL_STORE", "bucket"),
            ("FRASIL_S3_ENDPOINT", "https://s3.example.org"),
            ("FRASIL_S3_BUCKET", "b"),
            ("FRASIL_S3_ACCESS_KEY", "a"),
            ("FRASIL_S3_SECRET_KEY", "s"),
        ];
        let bucket = config(&s3).unwrap();
        let StoreConfig::Bucket { prefix, cache, .. } = &bucket.store else {
            panic!("a bucket");
        };
        assert_eq!(prefix, "records/");
        assert_eq!(cache, &PathBuf::from("/srv/frasil/cache"));
        assert_eq!(bucket.settings.group_commit.window.as_millis(), 20);
        let mut windowed = s3.to_vec();
        windowed.push(("FRASIL_GROUP_COMMIT_MS", "50"));
        windowed.push(("FRASIL_SHARD_CACHE", "/var/cache/frasil"));
        let windowed = config(&windowed).unwrap();
        assert_eq!(windowed.settings.group_commit.window.as_millis(), 50);
        let mut same = s3.to_vec();
        same.push(("FRASIL_STORE_PREFIX", "objects/"));
        same.push(("FRASIL_S3_PREFIX", "objects/"));
        assert!(config(&same).is_err());
    }

    #[test]
    fn the_fence_interval_is_a_single_nodes_on_a_bucket() {
        let s3 = [
            ("FRASIL_STORE", "bucket"),
            ("FRASIL_S3_ENDPOINT", "https://s3.example.org"),
            ("FRASIL_S3_BUCKET", "b"),
            ("FRASIL_S3_ACCESS_KEY", "a"),
            ("FRASIL_S3_SECRET_KEY", "s"),
        ];
        let every = |vars: &[(&'static str, &'static str)]| {
            let StoreConfig::Bucket { fence_every, .. } = config(vars).unwrap().store else {
                panic!("a bucket");
            };
            fence_every
        };
        assert_eq!(every(&s3), crate::shards::fence::READING_EVERY);
        for (text, seconds) in [("1", 1), ("600", 600), ("3600", 3600)] {
            let mut set = s3.to_vec();
            set.push(("FRASIL_FENCE_INTERVAL", text));
            assert_eq!(every(&set).as_secs(), seconds);
        }
        for text in ["0", "3601", "-1", "1.5", "three"] {
            let mut set = s3.to_vec();
            set.push(("FRASIL_FENCE_INTERVAL", text));
            assert!(config(&set).is_err(), "{text}");
        }
        assert!(config(&[("FRASIL_FENCE_INTERVAL", "60")]).is_err());
    }

    /// An Ed25519 public key: the base point.
    const ISSUER: &str = "5866666666666666666666666666666666666666666666666666666666666666";

    #[test]
    fn libraries_and_deposit_tokens_are_on_until_the_operator_names_others() {
        let defaults = config(&[]).unwrap().settings;
        assert_eq!(defaults.extensions, Extensions::DEFAULT);
        assert_eq!(defaults.extensions.to_string(), "libraries, deposit-tokens");
        assert_eq!(
            defaults.deposit_tokens,
            crate::deposit::DepositSettings::default()
        );
        // Deposit tokens' settings are read with the extensions unset.
        let period = config(&[("FRASIL_TOKEN_PERIOD", "86400")]).unwrap();
        assert_eq!(period.settings.deposit_tokens.token_period, 86_400);
        assert_eq!(defaults.hosting, Hosting::Closed);
        assert!(defaults.trusted_proxies.is_empty());
        assert_eq!(Settings::default().extensions, Extensions::DEFAULT);
        assert_eq!(Settings::default().hosting, Hosting::Closed);
        let core = Settings::open_core();
        assert_eq!(
            (core.extensions, core.hosting),
            (Extensions::NONE, Hosting::Open)
        );
        // `none` is the core peer.
        let none = config(&[("FRASIL_EXTENSIONS", "none")]).unwrap();
        assert_eq!(none.settings.extensions, Extensions::NONE);
        assert_eq!(Extensions::NONE.to_string(), "none");
        let issuer = ISSUER;
        let all = config(&[
            (
                "FRASIL_EXTENSIONS",
                "ephemeral, file-versions,invite-links libraries deposit-tokens",
            ),
            ("FRASIL_LIBRARY_ISSUERS", issuer),
        ])
        .unwrap();
        assert_eq!(all.settings.extensions, Extensions::ALL);
        assert_eq!(
            all.settings.extensions.to_string(),
            "ephemeral, file-versions, invite-links, libraries, deposit-tokens"
        );
        // The specification's names, with `ext-`, are the same extensions.
        let prefixed = config(&[("FRASIL_EXTENSIONS", "ext-invite-links ext-ephemeral")])
            .unwrap()
            .settings
            .extensions;
        assert_eq!(
            prefixed,
            Extensions {
                ephemeral: true,
                invite_links: true,
                ..Extensions::NONE
            }
        );
        assert!(prefixed.frames().invite_links);
        assert!(!prefixed.frames().libraries);
    }

    #[test]
    fn an_unknown_extension_fails() {
        let error = config(&[("FRASIL_EXTENSIONS", "ephemeral drive")]).unwrap_err();
        assert!(error.0.contains("`drive`"), "{error}");
        assert!(
            error
                .0
                .contains("ephemeral, file-versions, invite-links, libraries, deposit-tokens")
        );
        assert!(config(&[("FRASIL_EXTENSIONS", "ext-")]).is_err());
    }

    #[test]
    fn deposit_tokens_need_libraries_and_read_their_settings() {
        // ext-deposit-tokens.md: a peer implements it only together with
        // ext-libraries.md.
        let error = config(&[("FRASIL_EXTENSIONS", "deposit-tokens")]).unwrap_err();
        assert!(error.0.contains("without libraries"), "{error}");
        let on = |extra: &[(&'static str, &'static str)]| {
            let mut vars = vec![("FRASIL_EXTENSIONS", "libraries deposit-tokens")];
            vars.extend_from_slice(extra);
            config(&vars)
        };
        let defaults = on(&[]).unwrap().settings;
        assert!(defaults.extensions.deposit_tokens);
        assert!(defaults.extensions.frames().deposit_tokens);
        assert_eq!(
            defaults.deposit_tokens,
            crate::deposit::DepositSettings::default()
        );
        let set = on(&[
            ("FRASIL_DEPOSIT_ALLOWANCE", "100"),
            ("FRASIL_SPACE_SHARE", "0"),
            ("FRASIL_TOKEN_PERIOD", "86400"),
            ("FRASIL_TOKEN_BUDGET_ITEMS", "1000"),
            ("FRASIL_TOKEN_BUDGET_BYTES", "8388608"),
            ("FRASIL_REFUSED_TOKENS_PER_MINUTE", "5"),
        ])
        .unwrap()
        .settings
        .deposit_tokens;
        assert_eq!(
            (set.deposit_allowance, set.space_share, set.token_period),
            (100, 0, 86_400)
        );
        assert_eq!((set.budget.items, set.budget.bytes), (1000, 8 << 20));
        assert_eq!(set.refused_per_minute, 5);
        for bad in [
            ("FRASIL_DEPOSIT_ALLOWANCE", "65537"),
            ("FRASIL_SPACE_SHARE", "65"),
            ("FRASIL_TOKEN_PERIOD", "86399"),
            ("FRASIL_TOKEN_PERIOD", "2592001"),
            ("FRASIL_TOKEN_BUDGET_ITEMS", "15"),
            ("FRASIL_TOKEN_BUDGET_BYTES", "1"),
            ("FRASIL_REFUSED_TOKENS_PER_MINUTE", "0"),
        ] {
            assert!(on(&[bad]).is_err(), "{bad:?}");
        }
        // Its settings are refused while it is off.
        let off = config(&[
            ("FRASIL_EXTENSIONS", "libraries"),
            ("FRASIL_TOKEN_PERIOD", "86400"),
        ])
        .unwrap_err();
        assert!(off.0.contains("deposit-tokens"), "{off}");
    }

    #[test]
    fn libraries_take_creates_without_a_ticket_only_when_hosting_is_open() {
        // No issuer named: the operator's own is trusted at start, and the
        // peer hosts no space without a ticket.
        let closed = config(&[]).unwrap().settings;
        assert!(closed.libraries.issuers.is_empty());
        assert!(closed.libraries.open_library.is_none());
        // An open library needs open hosting.
        let error = config(&[("FRASIL_OPEN_LIBRARY", "operator:open")]).unwrap_err();
        assert!(error.0.contains("FRASIL_HOSTING"), "{error}");
        let named = config(&[
            ("FRASIL_HOSTING", "open"),
            ("FRASIL_OPEN_LIBRARY", "operator:open"),
        ])
        .unwrap();
        assert_eq!(
            named.settings.libraries.open_library.unwrap().as_str(),
            "operator:open"
        );
        assert_eq!(named.settings.hosting, Hosting::Open);
        // Open hosting names its library: none is filled in, and the
        // refusal says both ways out.
        let error = config(&[("FRASIL_HOSTING", "open")]).unwrap_err();
        assert!(error.0.contains("FRASIL_OPEN_LIBRARY"), "{error}");
        assert!(error.0.contains("FRASIL_HOSTING=closed"), "{error}");
        let error = config(&[
            ("FRASIL_HOSTING", "open"),
            ("FRASIL_EXTENSIONS", "libraries ephemeral"),
        ])
        .unwrap_err();
        assert!(error.0.contains("FRASIL_OPEN_LIBRARY"), "{error}");
        // The core peer has no open library, whatever its hosting.
        let core = config(&[("FRASIL_EXTENSIONS", "none"), ("FRASIL_HOSTING", "open")]).unwrap();
        assert_eq!(core.settings.hosting, Hosting::Open);
        assert!(core.settings.libraries.open_library.is_none());
        let issued = config(&[("FRASIL_LIBRARY_ISSUERS", ISSUER)]).unwrap();
        assert_eq!(issued.settings.libraries.issuers.len(), 1);
        assert!(config(&[("FRASIL_HOSTING", "public")]).is_err());
    }

    #[test]
    fn an_off_extensions_settings_fail() {
        for (name, value, extension) in [
            ("FRASIL_MAX_FILE_VERSIONS", "10", "file-versions"),
            ("FRASIL_FILE_VERSION_RETENTION", "86400", "file-versions"),
            ("FRASIL_OPEN_LIBRARY", "operator:open", "libraries"),
            ("FRASIL_LIBRARY_ISSUERS", "33", "libraries"),
            ("FRASIL_DETACHED_GRACE", "86400", "libraries"),
            ("FRASIL_LIBRARY_QUOTAS", "personal=1", "libraries"),
            ("FRASIL_OPERATOR_TOKEN", "0123456789abcdef", "libraries"),
        ] {
            let error = config(&[(name, value), ("FRASIL_EXTENSIONS", "none")]).unwrap_err();
            assert!(
                error.0.contains(name) && error.0.contains(extension),
                "{error}"
            );
        }
        let versions = config(&[
            ("FRASIL_EXTENSIONS", "file-versions"),
            ("FRASIL_MAX_FILE_VERSIONS", "10"),
        ])
        .unwrap();
        assert_eq!(versions.settings.max_file_versions, 10);
    }

    #[test]
    fn the_iroh_relay_is_on_when_it_has_a_listener() {
        assert_eq!(config(&[]).unwrap().iroh_relay, None);
        let plain = config(&[("FRASIL_RELAY_LISTEN", "127.0.0.1:3340")])
            .unwrap()
            .iroh_relay
            .unwrap();
        assert_eq!(plain.listen, "127.0.0.1:3340".parse().unwrap());
        assert_eq!((plain.tls, plain.quic), (None, None));
        let tls = config(&[
            ("FRASIL_RELAY_LISTEN", "0.0.0.0:443"),
            ("FRASIL_RELAY_TLS_CERT", "/etc/relay/cert.pem"),
            ("FRASIL_RELAY_TLS_KEY", "/etc/relay/key.pem"),
            ("FRASIL_RELAY_QUIC", "0.0.0.0:7842"),
        ])
        .unwrap()
        .iroh_relay
        .unwrap();
        assert_eq!(tls.tls.unwrap().cert, PathBuf::from("/etc/relay/cert.pem"));
        assert_eq!(tls.quic, Some("0.0.0.0:7842".parse().unwrap()));
        // A setting without a listener, half a certificate, or QUIC
        // without TLS.
        assert!(config(&[("FRASIL_RELAY_QUIC", "0.0.0.0:7842")]).is_err());
        assert!(
            config(&[
                ("FRASIL_RELAY_LISTEN", "0.0.0.0:443"),
                ("FRASIL_RELAY_TLS_CERT", "/etc/relay/cert.pem"),
            ])
            .is_err()
        );
        assert!(
            config(&[
                ("FRASIL_RELAY_LISTEN", "0.0.0.0:3340"),
                ("FRASIL_RELAY_QUIC", "0.0.0.0:7842"),
            ])
            .is_err()
        );
        assert!(config(&[("FRASIL_RELAY_LISTEN", "relay")]).is_err());
    }
}
