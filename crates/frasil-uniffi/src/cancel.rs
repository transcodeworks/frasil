//! Ending a call before it has its answer: a [`Cancellation`] the
//! application cancels, and work that ends when its caller stops waiting.

use crate::{FrasilError, runtime};
use std::sync::Arc;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Cancels the calls it is given to: each fails at once. One cancellation
/// can be given to any number of calls.
///
/// Swift does not end a call when its task is cancelled: the call runs on
/// to its answer, which the cancelled task then gets. A Swift caller gives
/// the call one of these and cancels it from the task's cancellation
/// handler. A Kotlin coroutine that is cancelled ends the calls that take
/// a cancellation by itself, and may be given one as well.
#[derive(uniffi::Object)]
pub struct Cancellation {
    cancelled: watch::Sender<bool>,
}

#[uniffi::export]
impl Cancellation {
    /// A cancellation that has not been asked for yet.
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            cancelled: watch::Sender::new(false),
        })
    }

    /// Cancels every call given this: those waiting fail now, and one
    /// given it later fails at once.
    pub fn cancel(&self) {
        self.cancelled.send_replace(true);
    }

    /// Whether it was cancelled.
    pub fn is_cancelled(&self) -> bool {
        *self.cancelled.borrow()
    }
}

impl Cancellation {
    /// A flag that is raised once this is cancelled.
    pub(crate) fn flag(&self) -> watch::Receiver<bool> {
        self.cancelled.subscribe()
    }
}

/// The flag of a call's cancellation, if it was given one.
pub(crate) fn flag_of(cancellation: Option<&Arc<Cancellation>>) -> Option<watch::Receiver<bool>> {
    cancellation.map(|cancellation| cancellation.flag())
}

/// Ready once `flag` is raised; never for none, nor for a flag that can no
/// longer be raised.
pub(crate) async fn raised(flag: Option<&mut watch::Receiver<bool>>) {
    let waited = match flag {
        Some(flag) => flag.wait_for(|raised| *raised).await.is_ok(),
        None => false,
    };
    if !waited {
        std::future::pending::<()>().await;
    }
}

/// What a call fails with once its cancellation is cancelled.
pub(crate) fn cancelled(what: &str) -> FrasilError {
    FrasilError::Failed {
        reason: format!("{what} was cancelled"),
    }
}

/// Runs `work` on the bindings' runtime and waits for it. When the caller
/// stops waiting, as a cancelled coroutine does, the work is dropped at
/// its next wait: nothing of it runs on.
pub(crate) async fn run_while_awaited<T: Send + 'static>(
    work: impl Future<Output = T> + Send + 'static,
) -> T {
    struct Awaited<T>(JoinHandle<T>);
    impl<T> Drop for Awaited<T> {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let mut task = Awaited(runtime().spawn(work));
    match (&mut task.0).await {
        Ok(value) => value,
        Err(error) => std::panic::resume_unwind(error.into_panic()),
    }
}

#[cfg(test)]
mod tests {
    use super::{Cancellation, flag_of, raised, run_while_awaited};
    use std::time::Duration;
    use tokio::sync::oneshot;

    /// Says so when it is dropped.
    struct Dropped(Option<oneshot::Sender<()>>);

    impl Drop for Dropped {
        fn drop(&mut self) {
            if let Some(dropped) = self.0.take() {
                let _ = dropped.send(());
            }
        }
    }

    /// Work whose caller stops waiting is dropped, with what it held.
    #[tokio::test]
    async fn work_ends_when_its_caller_stops_waiting() {
        let (dropped, was_dropped) = oneshot::channel();
        let (started, has_started) = oneshot::channel();
        let held = Dropped(Some(dropped));
        let call = tokio::spawn(run_while_awaited(async move {
            let _held = held;
            let _ = started.send(());
            std::future::pending::<()>().await;
        }));
        has_started.await.unwrap();
        call.abort();
        tokio::time::timeout(Duration::from_secs(10), was_dropped)
            .await
            .expect("the work is dropped")
            .unwrap();
    }

    /// A flag is raised by its cancellation, before or after it is asked
    /// for, and a call given none never sees one.
    #[tokio::test]
    async fn a_cancellation_raises_its_flag() {
        let cancellation = Cancellation::new();
        let mut flag = flag_of(Some(&cancellation));
        let waiting = tokio::spawn(async move { raised(flag.as_mut()).await });
        cancellation.cancel();
        tokio::time::timeout(Duration::from_secs(10), waiting)
            .await
            .expect("the flag is raised")
            .unwrap();
        let mut late = flag_of(Some(&cancellation));
        raised(late.as_mut()).await;
        assert!(cancellation.is_cancelled());

        let none = tokio::time::timeout(Duration::from_millis(50), raised(None)).await;
        assert!(none.is_err());
    }
}
