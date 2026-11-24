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

    /// Runs a task in the background if something can run it now, and
    /// says whether it took it: `false` drops the task unrun, and never
    /// panics. The device calls it where it cannot fail, as when a read is
    /// dropped, and does the work later when it was not taken. By default
    /// it is [`spawn`](Self::spawn), which takes every task.
    fn try_spawn(&self, task: BoxFuture<'static, ()>) -> bool {
        self.spawn(task);
        true
    }

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

    /// With no runtime to run it, the one the device was opened in or
    /// the caller's, the task is not taken: `tokio::spawn` would panic.
    fn try_spawn(&self, task: BoxFuture<'static, ()>) -> bool {
        let runtime = self
            .0
            .clone()
            .or_else(|| tokio::runtime::Handle::try_current().ok());
        match runtime {
            Some(runtime) => {
                drop(runtime.spawn(task));
                true
            }
            None => false,
        }
    }

    fn sleep(&self, duration: Duration) -> BoxFuture<'static, ()> {
        Box::pin(tokio::time::sleep(duration))
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::{Tasks, Tokio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// Outside any runtime, a task that must not fail to be handed over
    /// is refused, where `spawn` would panic.
    #[test]
    fn a_task_no_runtime_can_run_is_not_taken() {
        let ran = Arc::new(AtomicBool::new(false));
        let task = {
            let ran = ran.clone();
            Box::pin(async move { ran.store(true, Ordering::SeqCst) })
        };
        assert!(!Tokio::current().try_spawn(task));
        assert!(!ran.load(Ordering::SeqCst));
    }

    /// The runtime the device was opened in takes a task from a thread
    /// outside it.
    #[test]
    fn the_devices_runtime_takes_a_task_from_another_thread() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let tasks = runtime.block_on(async { Tokio::current() });
        let (done, wait) = std::sync::mpsc::channel();
        let task = Box::pin(async move {
            let _ = done.send(());
        });
        assert!(
            std::thread::spawn(move || tasks.try_spawn(task))
                .join()
                .unwrap()
        );
        wait.recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
    }
}
