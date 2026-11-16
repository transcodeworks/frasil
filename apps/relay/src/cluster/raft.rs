//! Raft among a region's nodes, through openraft: the log, the vote and
//! snapshots on each node's disk, a state machine that holds only the
//! membership and the renewals of leases, and the network over the
//! internal links.
//!
//! No record of the peer goes through Raft. Its state is [`Membership`]: the
//! cluster's ID, a numbered epoch, and each node's address, capacity, iroh
//! endpoint key, whether shards are placed on it, and the last epoch it
//! confirmed it gave up what it no longer owns.
//!
//! The log, the vote, what is committed and the snapshot are kept in a
//! `frasil-store` store: a small SQLite file in the data directory, under
//! the addresses `v`, `c`, `p`, `s` and `l` with the entry's index.

// openraft's storage error is its own, and large; its traits return it.
#![allow(clippy::result_large_err)]

pub use super::json::{Applied, Command, Member, Membership, TypeConfig};
use super::link::{LinkError, Links, NodeId};
use super::wire::{RAFT_APPEND, RAFT_SNAPSHOT, RAFT_VOTE};
use openraft::error::{
    InstallSnapshotError, NetworkError, RPCError, RaftError, RemoteError, Unreachable,
};
use openraft::network::RPCOption;
use openraft::raft::{
    AppendEntriesRequest, AppendEntriesResponse, InstallSnapshotRequest, InstallSnapshotResponse,
    VoteRequest, VoteResponse,
};
use openraft::storage::{LogState, RaftLogReader, RaftSnapshotBuilder, RaftStorage, Snapshot};
use openraft::{
    BasicNode, Entry, EntryPayload, LogId, OptionalSend, RaftNetwork, RaftNetworkFactory,
    SnapshotMeta, StorageError, StorageIOError, StoredMembership, Vote,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// The Raft node.
pub type Raft = openraft::Raft<TypeConfig>;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What applying a command tells the node.
pub type OnApply = Arc<dyn Fn(&Command, &Membership) + Send + Sync>;

/// A snapshot as kept on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Kept {
    meta: SnapshotMeta<NodeId, BasicNode>,
    data: Vec<u8>,
}

/// The state machine, as a snapshot holds it.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Machine {
    applied: Option<LogId<NodeId>>,
    membership: StoredMembership<NodeId, BasicNode>,
    state: Membership,
}

struct Inner {
    disk: Arc<dyn frasil_store::Store>,
    vote: Option<Vote<NodeId>>,
    committed: Option<LogId<NodeId>>,
    purged: Option<LogId<NodeId>>,
    log: BTreeMap<u64, Entry<TypeConfig>>,
    machine: Machine,
    snapshot: Option<Kept>,
    snapshots: u64,
}

/// The log, the vote and the state machine of one node, kept on disk.
#[derive(Clone)]
pub struct Store {
    inner: Arc<Mutex<Inner>>,
    on_apply: OnApply,
    state: Arc<tokio::sync::watch::Sender<Arc<Membership>>>,
}

impl core::fmt::Debug for Store {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

fn ready<T>(
    future: frasil_store::BoxFuture<'_, Result<T, frasil_store::StoreError>>,
) -> Result<T, String> {
    use futures_util::FutureExt;
    match future.now_or_never() {
        Some(result) => result.map_err(|e| e.to_string()),
        None => Err("the store answered asynchronously".into()),
    }
}

fn io_error(text: impl ToString) -> StorageError<NodeId> {
    StorageIOError::write(&LinkError::failed(text.to_string())).into()
}

fn log_address(index: u64) -> Vec<u8> {
    let mut address = b"l".to_vec();
    address.extend_from_slice(&index.to_be_bytes());
    address
}

impl Store {
    /// The store over `disk`, read back.
    ///
    /// # Errors
    ///
    /// If `disk` cannot be read, or holds what does not read.
    pub fn open(disk: Arc<dyn frasil_store::Store>, on_apply: OnApply) -> Result<Self, String> {
        let read = |address: &[u8]| ready(disk.get(address));
        fn json<T: serde::de::DeserializeOwned>(
            bytes: Option<Vec<u8>>,
        ) -> Result<Option<T>, String> {
            bytes
                .map(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
                .transpose()
        }
        let vote = json(read(b"v")?)?;
        let committed = json::<Option<LogId<NodeId>>>(read(b"c")?)?.flatten();
        let purged = json::<Option<LogId<NodeId>>>(read(b"p")?)?.flatten();
        let snapshot: Option<Kept> = json(read(b"s")?)?;
        let mut log = BTreeMap::new();
        for (address, bytes) in ready(disk.scan(b"l"))? {
            let Some(index) = address
                .get(1..9)
                .and_then(|b| <[u8; 8]>::try_from(b).ok())
                .map(u64::from_be_bytes)
            else {
                continue;
            };
            let entry: Entry<TypeConfig> =
                serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
            log.insert(index, entry);
        }
        let machine = match &snapshot {
            Some(kept) => serde_json::from_slice(&kept.data).map_err(|e| e.to_string())?,
            None => Machine::default(),
        };
        let (state, _) = tokio::sync::watch::channel(Arc::new(machine.state.clone()));
        Ok(Self {
            inner: Arc::new(Mutex::new(Inner {
                disk,
                vote,
                committed,
                purged,
                log,
                machine,
                snapshot,
                snapshots: 0,
            })),
            on_apply,
            state: Arc::new(state),
        })
    }

    /// The membership as last applied, and its changes.
    pub fn watch(&self) -> tokio::sync::watch::Receiver<Arc<Membership>> {
        self.state.subscribe()
    }

    /// The membership as last applied.
    pub fn membership(&self) -> Arc<Membership> {
        self.state.borrow().clone()
    }

    /// The store the log is kept in, which also keeps the node's own
    /// timeline reading.
    pub fn disk(&self) -> Arc<dyn frasil_store::Store> {
        lock(&self.inner).disk.clone()
    }

    /// Whether the node has any Raft state: a vote, a log or a snapshot.
    pub fn initialized(&self) -> bool {
        let inner = lock(&self.inner);
        inner.vote.is_some() || !inner.log.is_empty() || inner.snapshot.is_some()
    }

    fn write(
        &self,
        puts: Vec<(Vec<u8>, Vec<u8>)>,
        deletes: Vec<Vec<u8>>,
    ) -> Result<(), StorageError<NodeId>> {
        let disk = lock(&self.inner).disk.clone();
        match ready(disk.commit(&frasil_store::Commit::new(puts, deletes))) {
            Ok(true) => Ok(()),
            Ok(false) => Err(io_error("the Raft store refused a write")),
            Err(error) => Err(io_error(error)),
        }
    }

    fn json<T: Serialize>(value: &T) -> Result<Vec<u8>, StorageError<NodeId>> {
        serde_json::to_vec(value).map_err(io_error)
    }

    fn publish(&self, state: &Membership) {
        self.state.send_replace(Arc::new(state.clone()));
    }
}

impl RaftLogReader<TypeConfig> for Store {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + OptionalSend>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeId>> {
        let inner = lock(&self.inner);
        Ok(inner.log.range(range).map(|(_, e)| e.clone()).collect())
    }
}

impl RaftSnapshotBuilder<TypeConfig> for Store {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeId>> {
        let kept = {
            let mut inner = lock(&self.inner);
            inner.snapshots += 1;
            let data = serde_json::to_vec(&inner.machine).map_err(io_error)?;
            let last = inner.machine.applied;
            let id = match last {
                Some(last) => format!("{}-{}-{}", last.leader_id, last.index, inner.snapshots),
                None => format!("--{}", inner.snapshots),
            };
            Kept {
                meta: SnapshotMeta {
                    last_log_id: last,
                    last_membership: inner.machine.membership.clone(),
                    snapshot_id: id,
                },
                data,
            }
        };
        self.write(vec![(b"s".to_vec(), Self::json(&kept)?)], Vec::new())?;
        lock(&self.inner).snapshot = Some(kept.clone());
        Ok(Snapshot {
            meta: kept.meta,
            snapshot: Box::new(Cursor::new(kept.data)),
        })
    }
}

impl RaftStorage<TypeConfig> for Store {
    type LogReader = Self;
    type SnapshotBuilder = Self;

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), StorageError<NodeId>> {
        self.write(vec![(b"v".to_vec(), Self::json(vote)?)], Vec::new())?;
        lock(&self.inner).vote = Some(*vote);
        Ok(())
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, StorageError<NodeId>> {
        Ok(lock(&self.inner).vote)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeId>>,
    ) -> Result<(), StorageError<NodeId>> {
        self.write(vec![(b"c".to_vec(), Self::json(&committed)?)], Vec::new())?;
        lock(&self.inner).committed = committed;
        Ok(())
    }

    async fn read_committed(&mut self) -> Result<Option<LogId<NodeId>>, StorageError<NodeId>> {
        Ok(lock(&self.inner).committed)
    }

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeId>> {
        let inner = lock(&self.inner);
        let last = inner
            .log
            .values()
            .next_back()
            .map(|e| e.log_id)
            .or(inner.purged);
        Ok(LogState {
            last_purged_log_id: inner.purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn append_to_log<I>(&mut self, entries: I) -> Result<(), StorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + OptionalSend,
    {
        let entries: Vec<Entry<TypeConfig>> = entries.into_iter().collect();
        let mut puts = Vec::with_capacity(entries.len());
        for entry in &entries {
            puts.push((log_address(entry.log_id.index), Self::json(entry)?));
        }
        self.write(puts, Vec::new())?;
        let mut inner = lock(&self.inner);
        for entry in entries {
            inner.log.insert(entry.log_id.index, entry);
        }
        Ok(())
    }

    async fn delete_conflict_logs_since(
        &mut self,
        log_id: LogId<NodeId>,
    ) -> Result<(), StorageError<NodeId>> {
        let gone: Vec<u64> = lock(&self.inner)
            .log
            .range(log_id.index..)
            .map(|(&i, _)| i)
            .collect();
        self.write(Vec::new(), gone.iter().map(|&i| log_address(i)).collect())?;
        let mut inner = lock(&self.inner);
        for index in gone {
            inner.log.remove(&index);
        }
        Ok(())
    }

    async fn purge_logs_upto(&mut self, log_id: LogId<NodeId>) -> Result<(), StorageError<NodeId>> {
        let gone: Vec<u64> = lock(&self.inner)
            .log
            .range(..=log_id.index)
            .map(|(&i, _)| i)
            .collect();
        let mut deletes: Vec<Vec<u8>> = gone.iter().map(|&i| log_address(i)).collect();
        deletes.dedup();
        self.write(vec![(b"p".to_vec(), Self::json(&Some(log_id))?)], deletes)?;
        let mut inner = lock(&self.inner);
        for index in gone {
            inner.log.remove(&index);
        }
        inner.purged = Some(log_id);
        Ok(())
    }

    async fn last_applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, BasicNode>), StorageError<NodeId>>
    {
        let inner = lock(&self.inner);
        Ok((inner.machine.applied, inner.machine.membership.clone()))
    }

    async fn apply_to_state_machine(
        &mut self,
        entries: &[Entry<TypeConfig>],
    ) -> Result<Vec<Applied>, StorageError<NodeId>> {
        let mut out = Vec::with_capacity(entries.len());
        let mut applied_commands = Vec::new();
        let state = {
            let mut inner = lock(&self.inner);
            for entry in entries {
                inner.machine.applied = Some(entry.log_id);
                match &entry.payload {
                    EntryPayload::Blank => out.push(Applied {
                        ok: true,
                        epoch: inner.machine.state.epoch,
                        joined: 0,
                    }),
                    EntryPayload::Normal(command) => {
                        out.push(inner.machine.state.apply(command));
                        applied_commands.push((command.clone(), inner.machine.state.clone()));
                    }
                    EntryPayload::Membership(membership) => {
                        inner.machine.membership =
                            StoredMembership::new(Some(entry.log_id), membership.clone());
                        out.push(Applied {
                            ok: true,
                            epoch: inner.machine.state.epoch,
                            joined: 0,
                        });
                    }
                }
            }
            inner.machine.state.clone()
        };
        for (command, after) in &applied_commands {
            (self.on_apply)(command, after);
        }
        self.publish(&state);
        Ok(out)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeId>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, BasicNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeId>> {
        let data = snapshot.into_inner();
        let machine: Machine = serde_json::from_slice(&data).map_err(io_error)?;
        let kept = Kept {
            meta: meta.clone(),
            data,
        };
        self.write(vec![(b"s".to_vec(), Self::json(&kept)?)], Vec::new())?;
        let state = {
            let mut inner = lock(&self.inner);
            inner.machine = machine;
            inner.snapshot = Some(kept);
            inner.machine.state.clone()
        };
        self.publish(&state);
        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeId>> {
        Ok(lock(&self.inner).snapshot.clone().map(|kept| Snapshot {
            meta: kept.meta,
            snapshot: Box::new(Cursor::new(kept.data)),
        }))
    }
}

/// The nonce a node's Raft store was made with, drawn the first time: a
/// node's ID derives from its name and this, so that a node whose Raft
/// state was lost joins as a new node and never votes twice under one ID.
///
/// # Errors
///
/// If the store cannot be read or written.
pub fn nonce(disk: &Arc<dyn frasil_store::Store>) -> Result<[u8; 8], String> {
    if let Some(bytes) = ready(disk.get(b"i"))? {
        return <[u8; 8]>::try_from(bytes.as_slice())
            .map_err(|_| "the Raft store's nonce is not 8 bytes".to_owned());
    }
    let nonce = *frasil_crypto::random_bytes::<8>()
        .map_err(|_| "no randomness for the Raft store's nonce".to_owned())?;
    match ready(disk.commit(&frasil_store::Commit::new(
        vec![(b"i".to_vec(), nonce.to_vec())],
        Vec::new(),
    )))? {
        true => Ok(nonce),
        false => Err("the Raft store refused its nonce".into()),
    }
}

/// Raft's network: each RPC is a request on the internal link.
#[derive(Debug, Clone)]
pub struct Network {
    links: Arc<Links>,
}

impl Network {
    /// The network over a node's links.
    pub fn new(links: Arc<Links>) -> Self {
        Self { links }
    }
}

/// One peer of Raft's network.
#[derive(Debug)]
pub struct Client {
    links: Arc<Links>,
    target: NodeId,
}

impl RaftNetworkFactory<TypeConfig> for Network {
    type Network = Client;

    async fn new_client(&mut self, target: NodeId, node: &BasicNode) -> Client {
        self.links.know(target, &node.addr);
        Client {
            links: self.links.clone(),
            target,
        }
    }
}

impl Client {
    async fn rpc<Q: Serialize, A: serde::de::DeserializeOwned, E>(
        &self,
        tag: u8,
        request: &Q,
        option: &RPCOption,
    ) -> Result<A, RPCError<NodeId, BasicNode, RaftError<NodeId, E>>>
    where
        E: std::error::Error + serde::de::DeserializeOwned,
    {
        let body = serde_json::to_vec(request)
            .map_err(|e| RPCError::Network(NetworkError::new(&LinkError::failed(e.to_string()))))?;
        let answer = self
            .links
            .call(self.target, tag, body, option.hard_ttl())
            .await
            .map_err(|e| RPCError::Unreachable(Unreachable::new(&e)))?;
        let answer: Result<A, RaftError<NodeId, E>> = serde_json::from_slice(&answer)
            .map_err(|e| RPCError::Network(NetworkError::new(&LinkError::failed(e.to_string()))))?;
        answer.map_err(|e| RPCError::RemoteError(RemoteError::new(self.target, e)))
    }
}

impl RaftNetwork<TypeConfig> for Client {
    async fn append_entries(
        &mut self,
        rpc: AppendEntriesRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<AppendEntriesResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.rpc(RAFT_APPEND, &rpc, &option).await
    }

    async fn install_snapshot(
        &mut self,
        rpc: InstallSnapshotRequest<TypeConfig>,
        option: RPCOption,
    ) -> Result<
        InstallSnapshotResponse<NodeId>,
        RPCError<NodeId, BasicNode, RaftError<NodeId, InstallSnapshotError>>,
    > {
        self.rpc(RAFT_SNAPSHOT, &rpc, &option).await
    }

    async fn vote(
        &mut self,
        rpc: VoteRequest<NodeId>,
        option: RPCOption,
    ) -> Result<VoteResponse<NodeId>, RPCError<NodeId, BasicNode, RaftError<NodeId>>> {
        self.rpc(RAFT_VOTE, &rpc, &option).await
    }
}

/// Answers a peer's Raft RPC, whose tag and JSON body it reads: the JSON
/// of its answer, or none for a tag that is not Raft's.
pub async fn serve(raft: &Raft, tag: u8, body: &[u8]) -> Option<Vec<u8>> {
    let json = |value: &dyn erased::Json| value.to_json();
    match tag {
        RAFT_APPEND => {
            let request: AppendEntriesRequest<TypeConfig> = serde_json::from_slice(body).ok()?;
            Some(json(&raft.append_entries(request).await))
        }
        RAFT_VOTE => {
            let request: VoteRequest<NodeId> = serde_json::from_slice(body).ok()?;
            Some(json(&raft.vote(request).await))
        }
        RAFT_SNAPSHOT => {
            let request: InstallSnapshotRequest<TypeConfig> = serde_json::from_slice(body).ok()?;
            Some(json(&raft.install_snapshot(request).await))
        }
        _ => None,
    }
}

mod erased {
    /// A value that serializes to JSON.
    pub trait Json {
        fn to_json(&self) -> Vec<u8>;
    }

    impl<T: serde::Serialize> Json for T {
        fn to_json(&self) -> Vec<u8> {
            serde_json::to_vec(self).unwrap_or_default()
        }
    }
}

/// openraft's settings for a lease renewed every `renew`: a heartbeat
/// four times as often, and an election after one and a half to three
/// renewals unheard, which [`super::lease::Timing::check`] counts against
/// a lease, so that a leader lost is replaced before leases end.
///
/// # Errors
///
/// If openraft refuses them.
pub fn config(renew: Duration) -> Result<openraft::Config, String> {
    let renew = renew.as_millis().max(20) as u64;
    openraft::Config {
        cluster_name: "frasil-relay".into(),
        heartbeat_interval: (renew / 4).max(5),
        election_timeout_min: renew * 3 / 2,
        election_timeout_max: renew * 3,
        snapshot_policy: openraft::SnapshotPolicy::LogsSinceLast(2000),
        max_in_snapshot_log_to_keep: 200,
        ..openraft::Config::default()
    }
    .validate()
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(n: u8) -> Member {
        Member {
            name: format!("{n}"),
            address: format!("node-{n}"),
            capacity: 100,
            iroh: None,
            placed: true,
            confirmed: 0,
            run: u64::from(n),
            joined: 0,
        }
    }

    #[test]
    fn the_membership_raises_its_epoch_at_each_change_of_placement() {
        let mut state = Membership::default();
        assert!(
            state
                .apply(&Command::Init {
                    cluster: "c".into()
                })
                .ok
        );
        assert!(
            !state
                .apply(&Command::Init {
                    cluster: "d".into()
                })
                .ok
        );
        let joined = state.apply(&Command::Join {
            node: 1,
            member: member(1),
        });
        assert_eq!(joined.epoch, 1);
        state.apply(&Command::Join {
            node: 2,
            member: member(2),
        });
        assert_eq!(state.epoch, 2);
        assert!(!state.settled());
        state.apply(&Command::Confirm { node: 1, epoch: 2 });
        state.apply(&Command::Confirm { node: 2, epoch: 9 });
        assert_eq!(state.nodes[&2].confirmed, 2, "never past the epoch");
        assert!(state.settled());
        let renewed = state.apply(&Command::Renew { node: 2, run: 2 });
        assert!(renewed.ok);
        assert_eq!(renewed.joined, 2);
        assert!(!state.apply(&Command::Renew { node: 3, run: 3 }).ok);
        assert!(
            !state.apply(&Command::Renew { node: 2, run: 9 }).ok,
            "another process under the node's name holds no lease"
        );
        // The same process joining again moves nothing.
        state.apply(&Command::Join {
            node: 2,
            member: member(2),
        });
        assert_eq!(state.epoch, 2);
        state.apply(&Command::Leave { node: 2 });
        assert_eq!((state.epoch, state.placed().len()), (3, 1));
        assert!(!state.settled(), "the leaver confirms what it gave up");
        state.apply(&Command::Remove { node: 2 });
        assert_eq!(state.epoch, 4);
        assert!(!state.nodes.contains_key(&2));
    }

    #[test]
    fn the_store_reads_back_its_log_and_vote() {
        let disk: Arc<dyn frasil_store::Store> = Arc::new(frasil_store::MemoryStore::new());
        let on_apply: OnApply = Arc::new(|_, _| {});
        let mut store = Store::open(disk.clone(), on_apply.clone()).unwrap();
        assert!(!store.initialized());
        let vote = Vote::new(3, 1);
        let entry = Entry::<TypeConfig> {
            log_id: LogId::new(openraft::CommittedLeaderId::new(3, 1), 1),
            payload: EntryPayload::Normal(Command::Renew { node: 1, run: 1 }),
        };
        futures_util::FutureExt::now_or_never(async {
            store.save_vote(&vote).await.unwrap();
            store.append_to_log([entry.clone()]).await.unwrap();
        })
        .unwrap();
        let mut again = Store::open(disk, on_apply).unwrap();
        assert!(again.initialized());
        let (read_vote, entries) = futures_util::FutureExt::now_or_never(async {
            (
                again.read_vote().await.unwrap(),
                again.try_get_log_entries(0..10).await.unwrap(),
            )
        })
        .unwrap();
        assert_eq!(read_vote, Some(vote));
        assert_eq!(entries, vec![entry]);
    }
}
