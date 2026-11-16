//! The iroh binding's listener (transport.md, "The iroh binding"):
//! `frasil/p1/peer` connections.
//!
//! The peer, the listener, opens the control stream and sends `PeerHello`
//! on it first (transport.md, sections 3.10 and 3.16). The device opens one
//! sync stream per space after `Granted`, and object streams for uploads;
//! the peer answers on each sync stream, and opens an object stream of its
//! own for each transfer it sends.

use crate::session::Session;
use crate::state::Outgoing;
use crate::util::log;
use crate::{Shared, Stop};
use frasil_events::EventId;
use frasil_iroh::{Alpn, Connection, Endpoint, Error, FrameReceiver, FrameSender, Stream};
use frasil_transport::frame::{ConnectionKind, Message, MessageType};
use frasil_transport::messages::{Scope, Sync};
use frasil_transport::{Closed, Code};
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::sync::mpsc;

/// What the connection's readers hand its main loop.
enum Inbound {
    /// A message read on a stream.
    Message(Message),
    /// A sync stream the device opened: its sending half.
    SyncStream(EventId, FrameSender),
    /// A reader failed: close with this.
    Failed(Error),
}

/// Accepts connections until the endpoint closes.
pub(crate) async fn accept(shared: Arc<Shared>, endpoint: Endpoint) {
    while let Some(incoming) = endpoint.accept().await {
        match incoming {
            Ok(connection) => {
                tokio::spawn(run(shared.clone(), Arc::new(connection)));
            }
            Err(error) => log(format_args!("an iroh connection failed: {error}")),
        }
    }
}

/// Reads a stream's messages into the main loop. On a sync or object
/// stream, each `Sync` must name the stream's own space.
fn read_stream(
    mut receiver: FrameReceiver,
    space: Option<EventId>,
    inbound: mpsc::Sender<Inbound>,
) {
    tokio::spawn(async move {
        loop {
            let item = match receiver.receive().await {
                Ok(Some(message)) => {
                    if let Some(space) = space
                        && message.kind == MessageType::Sync
                        && Sync::read(&message, ConnectionKind::DeviceToPeer)
                            .map(|sync| sync.scope != Scope::Space(*space.as_bytes()))
                            .unwrap_or(true)
                    {
                        Inbound::Failed(Error::Protocol(Closed::of(
                            frasil_base::ErrorClass::Malformed,
                        )))
                    } else {
                        Inbound::Message(message)
                    }
                }
                Ok(None) => return,
                Err(error) => Inbound::Failed(error),
            };
            let failed = matches!(item, Inbound::Failed(_));
            if inbound.send(item).await.is_err() || failed {
                return;
            }
        }
    });
}

/// One `frasil/p1/peer` connection, closed when it ends. Past the
/// operator's caps on open connections it is closed `busy` at once. Its
/// source is the address of a direct path, or none (crate `source`): an
/// endpoint key costs a device nothing to draw again.
async fn run(shared: Arc<Shared>, connection: Arc<Connection>) {
    let source = crate::source::of_iroh(&connection);
    let Some(_permit) = shared.connections.admit(&source) else {
        connection.close(Code::Busy);
        return;
    };
    if serve(shared, &connection, source).await {
        connection.close(Code::Done);
    }
}

/// Serves a connection; whether to close it with `done` after.
async fn serve(shared: Arc<Shared>, connection: &Arc<Connection>, source: String) -> bool {
    let mut stop = shared.stop.subscribe();
    if connection.alpn() != Alpn::Peer {
        connection.close(Code::UnsupportedVersion);
        return true;
    }
    let ephemeral = shared.settings.extensions.ephemeral;
    let limits = shared.settings.connections;
    let write = std::time::Duration::from_secs(limits.write_timeout);
    let (mut session, hello, mut outbox) =
        match Session::start(shared, connection.channel(), false, source) {
            Ok(started) => started,
            Err(closed) => {
                connection.close(closed.code);
                return true;
            }
        };
    // The peer opens the control stream and writes first.
    let (mut control, control_receiver) = match connection.control().await {
        Ok(control) => control,
        Err(error) => {
            log(format_args!("an iroh control stream failed: {error}"));
            return true;
        }
    };
    if control.send(&hello).await.is_err() {
        return true;
    }
    let (inbound_tx, mut inbound) = mpsc::channel::<Inbound>(64);
    read_stream(control_receiver, None, inbound_tx.clone());
    // QUIC orders each stream alone: a device's first sync stream, or a
    // datagram, may reach this end before the `Hello` on the control
    // stream, which every other message follows (transport.md, 3.10). They
    // are read only once the `Hello` is.
    let (hello_tx, hello_rx) = tokio::sync::watch::channel(false);
    // ext-ephemeral.md: frames that come as datagrams, read only while the
    // extension is on.
    if ephemeral {
        let connection = connection.clone();
        let inbound_tx = inbound_tx.clone();
        let mut hello = hello_rx.clone();
        tokio::spawn(async move {
            if hello.wait_for(|read| *read).await.is_err() {
                return;
            }
            while let Ok(message) = connection.receive_datagram().await {
                if inbound_tx.send(Inbound::Message(message)).await.is_err() {
                    return;
                }
            }
        });
    }
    {
        let connection = connection.clone();
        let inbound_tx = inbound_tx.clone();
        let mut hello = hello_rx;
        tokio::spawn(async move {
            if hello.wait_for(|read| *read).await.is_err() {
                return;
            }
            loop {
                match connection.accept_stream().await {
                    Ok(Stream::Sync {
                        scope: Scope::Space(space),
                        sender,
                        receiver,
                    }) => {
                        let space = EventId(space);
                        if inbound_tx
                            .send(Inbound::SyncStream(space, sender))
                            .await
                            .is_err()
                        {
                            return;
                        }
                        read_stream(receiver, Some(space), inbound_tx.clone());
                    }
                    Ok(Stream::Object {
                        scope: Scope::Space(space),
                        receiver,
                    }) => read_stream(receiver, Some(EventId(space)), inbound_tx.clone()),
                    // ext-ephemeral.md's; read by a peer that relays, and
                    // dropped by one that does not.
                    Ok(Stream::Ephemeral { receiver }) if ephemeral => {
                        read_stream(receiver, None, inbound_tx.clone());
                    }
                    Ok(Stream::Ephemeral { receiver }) => drop(receiver),
                    Ok(_) => {
                        let _ = inbound_tx
                            .send(Inbound::Failed(Error::Protocol(Closed::of(
                                frasil_base::ErrorClass::Malformed,
                            ))))
                            .await;
                        return;
                    }
                    Err(error) => {
                        let _ = inbound_tx.send(Inbound::Failed(error)).await;
                        return;
                    }
                }
            }
        });
    }
    drop(inbound_tx);
    let mut sync_streams: BTreeMap<EventId, FrameSender> = BTreeMap::new();
    let deadline = tokio::time::sleep(frasil_iroh::HANDSHAKE_DEADLINE);
    tokio::pin!(deadline);
    let mut stopping = *stop.borrow_and_update();
    let mut watching = true;
    // QUIC keeps the connection alive, and finds it gone; a connection that
    // holds no grant and sent nothing for `idle_timeout` after its `Hello`
    // is closed `done`.
    let idle = std::time::Duration::from_secs(limits.idle_timeout);
    let every = std::time::Duration::from_secs(limits.keepalive_interval);
    let mut check = tokio::time::interval_at(tokio::time::Instant::now() + every, every);
    check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut spoke = tokio::time::Instant::now();
    loop {
        // The peer stops: `reconnect` once nothing holds the connection,
        // after the drain too, as for a connection that arrives then; only
        // one still held is dropped, left to the endpoint's close
        // (transport.md, 3.10, "Reconnecting elsewhere").
        match stopping {
            Stop::Reconnect | Stop::Drop if session.may_reconnect() => {
                connection.close(Code::Reconnect);
                return false;
            }
            Stop::Drop => return false,
            _ => {}
        }
        let outgoing = tokio::select! {
            changed = stop.changed(), if watching => {
                match changed {
                    Ok(()) => stopping = *stop.borrow_and_update(),
                    Err(_) => watching = false,
                }
                Vec::new()
            }
            _ = check.tick() => {
                if session.opened() && !session.holds_grant() && spoke.elapsed() >= idle {
                    connection.close(Code::Done);
                    return false;
                }
                Vec::new()
            }
            item = inbound.recv() => match item {
                Some(Inbound::Message(message)) => {
                    spoke = tokio::time::Instant::now();
                    match session.on_message(&message).await {
                        Ok(outgoing) => {
                            if message.kind == MessageType::Hello {
                                let _ = hello_tx.send(true);
                            }
                            outgoing
                        }
                        Err(closed) => {
                            log(format_args!("closing an iroh connection: {closed}"));
                            connection.close(closed.code);
                            return true;
                        }
                    }
                }
                Some(Inbound::SyncStream(space, sender)) => {
                    sync_streams.insert(space, sender);
                    Vec::new()
                }
                Some(Inbound::Failed(error)) => {
                    if let Some(code) = error.code().filter(|_| matches!(error, Error::Protocol(_))) {
                        connection.close(code);
                    }
                    return true;
                }
                None => return true,
            },
            Some(out) = outbox.recv() => {
                session.dequeued(&out);
                vec![out]
            }
            () = &mut deadline, if !session.opened() => {
                connection.close(Code::Timeout);
                return true;
            }
        };
        // What the message is answered at once, then every batch of the
        // answers the session serves in batches, before the connection's
        // next message is read: one batch is held at a time, and each
        // write waits at most `write_timeout` (units.md, "Sync").
        let mut outgoing: std::collections::VecDeque<Outgoing> = outgoing.into();
        loop {
            let out = match outgoing.pop_front() {
                Some(out) => out,
                None => match session.next_answer().await {
                    Some(out) => out,
                    None => break,
                },
            };
            // The cluster moves load, or a live delivery ended with its
            // entry (transport.md, 3.10; peers.md, 3.6 Retirement and the
            // cap, "Connections").
            if out == Outgoing::Reconnect {
                if session.may_reconnect() {
                    connection.close(Code::Reconnect);
                    return false;
                }
                session.declined_reconnect();
                continue;
            }
            let sending = async {
                match out {
                    Outgoing::Control(bytes) => control.send(&bytes).await,
                    Outgoing::Sync(space, bytes) => match sync_streams.get_mut(&space) {
                        Some(sender) => sender.send(&bytes).await,
                        // No sync stream of the space yet: what would travel
                        // on it waits for the device's next request.
                        None => Ok(()),
                    },
                    Outgoing::Object(space, messages) => {
                        send_object(connection, space, messages).await
                    }
                    // Lossy: a frame the path cannot carry is dropped.
                    Outgoing::Ephemeral(bytes) => connection.send_lossy(&bytes).await.map(drop),
                    Outgoing::Reconnect => Ok(()),
                }
            };
            match tokio::time::timeout(write, sending).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    log(format_args!("an iroh send failed: {error}"));
                    return true;
                }
                Err(_) => {
                    log("an iroh connection took a message too slowly: closing it");
                    return true;
                }
            }
        }
    }
}

/// One object transfer, on an object stream the peer opens.
async fn send_object(
    connection: &Connection,
    space: EventId,
    messages: Vec<Vec<u8>>,
) -> Result<(), Error> {
    let mut sender = connection
        .open_object(Scope::Space(*space.as_bytes()))
        .await?;
    for message in messages {
        sender.send(&message).await?;
    }
    sender.finish()
}
