//! Where a device runs its background work: tokio's runtime by default, or
//! the tasks and timers an application supplies where tokio has none, such
//! as a browser's event loop.

use frasil_store::BoxFuture;
use frasil_store::store::{MaybeSend, MaybeSync};
use std::time::Duration;

/// Runs a device's background work: its upkeep and its connections.
pub trait Tasks: MaybeSend + MaybeSync {
    /// Runs a task in the background, to its end.
    fn spawn(&self, task: BoxFuture<'static, ()>);

    /// A future that is ready once `duration` has passed.
    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()>;
}

/// Tokio's runtime: the one the application opened the device in, so that
/// a call made from a thread outside it, such as an interface's, still runs
/// its background work there.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Default)]
pub(crate) struct Tokio(Option<tokio::runtime::Handle>);

#[cfg(not(target_arch = "wasm32"))]
impl Tokio {
    /// The runtime the calling task runs in, if any.
    pub(crate) fn current() -> Self {
        Self(tokio::runtime::Handle::try_current().ok())
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl Tasks for Tokio {
    fn spawn(&self, task: BoxFuture<'static, ()>) {
        match &self.0 {
            Some(runtime) => drop(runtime.spawn(task)),
            None => drop(tokio::spawn(task)),
        }
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}
