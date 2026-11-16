//! Frasil's observed reads and feeds as Tauri events, for a front end that
//! runs over a Rust process holding the device.
//!
//! Each function starts a feed on Tauri's async runtime and emits every
//! value under one event name to one target, such as the label of the
//! window that asked for it (`window.label()`), rather than to every
//! window. The front end listens on that window, with
//! `getCurrentWebviewWindow().listen(name, …)`. A listener for any target,
//! `listen` from `@tauri-apps/api/event`, hears an event whatever its
//! target, so give the event permissions (`core:event:default`) only to the
//! windows that load the application's own pages. A feed runs until its
//! [`Subscription`] is cancelled or dropped, so keep it, for example in the
//! application's managed state, for as long as the front end listens.
//!
//! An observed read is emitted as an [`Emitted`]: `{ status, value, error }`,
//! with `status` one of `"loading"`, `"ready"` and `"failed"`, the same shape
//! as `@frasil/client`'s observation stores.

use frasil::{Device, Observed, Status};
use serde::Serialize;
use tauri::async_runtime::JoinHandle;
use tauri::{AppHandle, Emitter, EventTarget, Runtime};

/// A feed that emits until it is cancelled or dropped.
#[derive(Debug)]
pub struct Subscription {
    task: Option<JoinHandle<()>>,
}

impl Subscription {
    /// Stops the feed: nothing more is emitted.
    pub fn cancel(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// One observation, as emitted.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Emitted<T> {
    /// `"loading"`, `"ready"` or `"failed"`.
    pub status: &'static str,
    /// The value last read, once a read succeeded.
    pub value: Option<T>,
    /// Why the last read failed, under `"failed"`.
    pub error: Option<String>,
}

fn emitted<T: Clone>(observation: &frasil::Observation<T>) -> Emitted<T> {
    Emitted {
        status: match observation.status {
            Status::Ready => "ready",
            Status::Failed => "failed",
            _ => "loading",
        },
        value: observation.value.as_deref().cloned(),
        error: observation.error.as_ref().map(|error| format!("{error:#}")),
    }
}

/// Emits an observed read under `event` to `target`: its current
/// observation at once, then each one that differs.
pub fn emit_observed<R, T>(
    app: &AppHandle<R>,
    target: impl Into<EventTarget>,
    event: impl Into<String>,
    mut observed: Observed<T>,
) -> Subscription
where
    R: Runtime,
    T: Serialize + Clone + PartialEq + Send + Sync + 'static,
{
    let app = app.clone();
    let target = target.into();
    let event = event.into();
    let task = tauri::async_runtime::spawn(async move {
        let mut observation = observed.get();
        loop {
            let _ = app.emit_to(target.clone(), &event, emitted(&observation));
            match observed.changed().await {
                Some(next) => observation = next,
                None => return,
            }
        }
    });
    Subscription { task: Some(task) }
}

/// Emits under `event` to `target` whether the space has nothing unsent
/// ([`frasil::Space::observe_durable`]): `value` is `true` once every change
/// this device made there is acknowledged.
pub fn emit_durable<R: Runtime>(
    app: &AppHandle<R>,
    target: impl Into<EventTarget>,
    event: impl Into<String>,
    space: &frasil::Space,
) -> Subscription {
    emit_observed(app, target, event, space.observe_durable())
}

/// Where a blob's bytes stand, as emitted: `{ kind }`, one of `"readable"`,
/// `"fetching"` (with `done` and `total`), `"missing"`, `"keysPending"` and
/// `"withdrawn"`, as `@frasil/client` names them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum BlobStatus {
    /// The device holds the bytes whole.
    Readable,
    /// A peer or member is sending them.
    Fetching {
        /// The bytes fetched so far, by share of the object.
        done: u64,
        /// The blob's size.
        total: u64,
    },
    /// Nothing is sending them now.
    Missing,
    /// The key they are sealed under has not reached this device yet.
    KeysPending,
    /// A held file changed or is gone; peers and members still have them.
    Withdrawn,
}

impl From<frasil::BlobStatus> for BlobStatus {
    fn from(status: frasil::BlobStatus) -> Self {
        match status {
            frasil::BlobStatus::Readable => Self::Readable,
            frasil::BlobStatus::Fetching { done, total } => Self::Fetching { done, total },
            frasil::BlobStatus::KeysPending => Self::KeysPending,
            frasil::BlobStatus::Withdrawn => Self::Withdrawn,
            _ => Self::Missing,
        }
    }
}

/// Emits a blob's status under `event` to `target` as its bytes arrive,
/// are fetched or are withdrawn ([`frasil::Blobs::observe_status`]).
pub fn emit_blob_status<R: Runtime>(
    app: &AppHandle<R>,
    target: impl Into<EventTarget>,
    event: impl Into<String>,
    blobs: &frasil::Blobs,
    blob: frasil::BlobId,
) -> Subscription {
    let app = app.clone();
    let target = target.into();
    let event = event.into();
    let mut observed = blobs.observe_status(blob);
    let task = tauri::async_runtime::spawn(async move {
        let mut observation = observed.get();
        loop {
            let Emitted {
                status,
                value,
                error,
            } = emitted(&observation);
            let _ = app.emit_to(
                target.clone(),
                &event,
                Emitted {
                    status,
                    value: value.map(BlobStatus::from),
                    error,
                },
            );
            match observed.changed().await {
                Some(next) => observation = next,
                None => return,
            }
        }
    });
    Subscription { task: Some(task) }
}

/// Something a device holds for the first time, as emitted: `{ kind:
/// "space", space }` or `{ kind: "stream", space, stream }`, IDs in
/// hexadecimal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Arrival {
    /// A space: its streams follow.
    Space {
        /// The space's ID.
        space: String,
    },
    /// A stream of a space.
    Stream {
        /// The space's ID.
        space: String,
        /// The stream's ID.
        stream: String,
    },
}

/// Emits under `event` to `target` each space and stream the device holds
/// for the first time, from now on ([`Device::arrivals`]).
pub async fn emit_arrivals<R: Runtime>(
    app: &AppHandle<R>,
    target: impl Into<EventTarget>,
    event: impl Into<String>,
    device: &Device,
) -> Subscription {
    let app = app.clone();
    let target = target.into();
    let event = event.into();
    let mut arrivals = device.arrivals().await;
    let task = tauri::async_runtime::spawn(async move {
        while let Some(arrival) = arrivals.next().await {
            let arrival = match arrival {
                frasil::Arrival::Space(space) => Arrival::Space {
                    space: space.to_string(),
                },
                frasil::Arrival::Stream { space, stream } => Arrival::Stream {
                    space: space.to_string(),
                    stream: stream.to_string(),
                },
                _ => continue,
            };
            let _ = app.emit_to(target.clone(), &event, arrival);
        }
    });
    Subscription { task: Some(task) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tauri::Listener;

    /// Collects the payloads of an event, as a front end would hear them.
    fn heard<R: Runtime>(app: &AppHandle<R>, event: &str) -> Arc<Mutex<Vec<String>>> {
        let heard = Arc::new(Mutex::new(Vec::new()));
        let into = heard.clone();
        app.listen(event, move |e| {
            into.lock().unwrap().push(e.payload().to_owned());
        });
        heard
    }

    async fn until(heard: &Arc<Mutex<Vec<String>>>, wanted: &str) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !heard.lock().unwrap().iter().any(|p| p == wanted) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{wanted} not heard: {:?}", heard.lock().unwrap()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn feeds_reach_the_front_end_as_events() {
        let app = tauri::test::mock_app();
        let handle = app.handle().clone();
        let device = Device::open(frasil::Storage::Memory, &[1; 32])
            .await
            .unwrap();
        let arrivals = heard(&handle, "arrivals");
        // The mock app has no window: its own listeners are the target.
        let _arriving = emit_arrivals(&handle, EventTarget::App, "arrivals", &device).await;
        let space = device.create_space().await.unwrap();
        until(
            &arrivals,
            &format!(r#"{{"kind":"space","space":"{}"}}"#, space.id()),
        )
        .await;

        // No peer: the space has something unsent.
        let durable = heard(&handle, "durable");
        let _durable = emit_durable(&handle, EventTarget::App, "durable", &space);
        until(&durable, r#"{"status":"ready","value":false,"error":null}"#).await;

        let blobs = space.create_blobs().unwrap();
        let blob = blobs.put(None, b"bytes").await.unwrap();
        let status = heard(&handle, "status");
        let mut watching = emit_blob_status(&handle, EventTarget::App, "status", &blobs, blob);
        until(
            &status,
            r#"{"status":"ready","value":{"kind":"readable"},"error":null}"#,
        )
        .await;
        watching.cancel();
        device.close().await.unwrap();
    }
}
