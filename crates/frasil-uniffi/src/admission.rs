//! Admitting a device into a space over a nearby connection: one device
//! invites, the other joins by the invitation's text, and both people
//! compare an admission code (admission.md, "Nearby pairing").

use crate::cancel::{cancelled, flag_of, raised, run_while_awaited};
use crate::{Cancellation, Device, FrasilError, Result, Space, run};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tokio::sync::{oneshot, watch};

/// How long a listener has to answer: `admission_code_lifetime`
/// (overview.md, "Every timer"), which the newcomer counts from the moment
/// it asks. Past it the inviting device refuses the admission as `Expired`
/// whatever the people answer.
const CONFIRM_WITHIN: Duration = Duration::from_secs(900);

/// Asks this device's person whether an admission goes on.
#[uniffi::export(with_foreign)]
pub trait AdmissionListener: Send + Sync {
    /// Both screens show the six-digit `code`, and `name` is what the
    /// other device calls itself: `true` when this device's person saw
    /// that code on both. `false` refuses the admission, and so does a
    /// listener that throws.
    ///
    /// It is called once, on a thread started for it, and may wait there
    /// for the person's answer. The admission waits at most 15 minutes,
    /// the life of an admission code, and counts no answer by then as
    /// `false`. When the call that gave the listener ends first, because
    /// it was cancelled or the time passed, the answer counts for nothing
    /// and nothing waits for it: take the question off the screen and
    /// return, since the thread is the listener's until it does.
    fn confirm(&self, code: String, name: String) -> Result<bool>;
}

/// Asks `listener` on a thread of its own, for at most `within` and until
/// `abandoned` is raised: `false` for no answer by then, for a listener
/// that failed, and when no thread could be started. The thread is not
/// one of the runtime's: a listener that never answers holds none of the
/// threads the device works on.
async fn confirmed(
    listener: Arc<dyn AdmissionListener>,
    code: String,
    name: String,
    mut abandoned: Option<watch::Receiver<bool>>,
    within: Duration,
) -> bool {
    let (answer, answered) = oneshot::channel();
    let asking = std::thread::Builder::new()
        .name("frasil-admission".into())
        .spawn(move || {
            let confirmed = matches!(listener.confirm(code, name), Ok(true));
            // Nothing waits for an answer that comes too late.
            let _ = answer.send(confirmed);
        });
    if asking.is_err() {
        return false;
    }
    tokio::select! {
        biased;
        () = raised(abandoned.as_mut()) => false,
        () = tokio::time::sleep(within) => false,
        // A listener that panicked gave no answer.
        answer = answered => answer.unwrap_or(false),
    }
}

/// The level of a nearby admission by its name. Nearby admission carries
/// no rank, so it admits at most `write` (roster.md, 2.3 Changes,
/// "Ranks").
fn nearby_level(name: &str) -> Result<frasil::Level> {
    match frasil::Level::from_name(name) {
        Some(level) if level != frasil::Level::Administer => Ok(level),
        _ => Err(FrasilError::Failed {
            reason: "the level of a nearby admission is read or write; to make the newcomer \
                     an administrator, admit it at write, then raise it at a rank"
                .into(),
        }),
    }
}

/// Where an invitation stands.
enum Stage {
    /// Hosted, and no call has waited for its newcomer.
    Hosted(frasil::Invitation),
    /// A call waits for its newcomer.
    Waiting,
    /// A call waited until the admission ended, admitted or refused.
    Ended,
    /// The call that waited was cancelled.
    Abandoned,
}

impl Stage {
    /// Why an invitation at this stage cannot be waited for.
    fn spent(&self) -> FrasilError {
        FrasilError::Failed {
            reason: match self {
                Self::Hosted(_) | Self::Waiting => {
                    "another call is waiting for this invitation's newcomer"
                }
                Self::Ended => {
                    "the invitation is spent: its admission ended, and an invitation admits \
                     one newcomer; invite again"
                }
                Self::Abandoned => {
                    "the invitation is spent: the call that waited for its newcomer was \
                     cancelled, which abandoned the invitation; invite again"
                }
            }
            .into(),
        }
    }
}

/// Marks an invitation abandoned when the call that waits for its
/// newcomer ends before the admission does.
struct Wait {
    stage: Arc<Mutex<Stage>>,
    abandoned: watch::Sender<bool>,
    ended: bool,
}

impl Wait {
    /// The admission ended while the call waited.
    fn end(&mut self) {
        self.ended = true;
        *self.stage.lock().unwrap_or_else(PoisonError::into_inner) = Stage::Ended;
    }
}

impl Drop for Wait {
    fn drop(&mut self) {
        if !self.ended {
            *self.stage.lock().unwrap_or_else(PoisonError::into_inner) = Stage::Abandoned;
            self.abandoned.send_replace(true);
        }
    }
}

/// An invitation into a space, waiting for its newcomer.
#[derive(uniffi::Object)]
pub struct Invitation {
    text: String,
    stage: Arc<Mutex<Stage>>,
    /// Raised once the invitation is abandoned: its listener's answer no
    /// longer counts.
    abandoned: watch::Sender<bool>,
}

#[uniffi::export(async_runtime = "tokio")]
impl Invitation {
    /// The text the newcomer enters in `Device::join`: show it, or a QR
    /// code of it, or send it to the person invited. It names nothing of
    /// the space and admits no one by itself; whoever reads it learns the
    /// addresses this device listens on.
    pub fn text(&self) -> String {
        self.text.clone()
    }

    /// Waits until the newcomer is admitted, however long one takes to
    /// come: only the comparison of the code has a time limit, 15 minutes
    /// from the newcomer's asking. It fails when either person did not
    /// confirm the code and when the connection fails.
    ///
    /// Cancelling it abandons the invitation: `cancellation` cancelled, or
    /// the caller no longer waiting, as a cancelled coroutine. The call
    /// fails, a listener being asked is waited for no longer, and a
    /// newcomer that comes, or came, is refused as if this device's
    /// person had not confirmed the code.
    ///
    /// An invitation is waited for once. A second call fails and says
    /// why: the invitation is spent, because its admission ended or
    /// because the first call was cancelled; invite again.
    #[uniffi::method(default(cancellation = None))]
    pub async fn admitted(&self, cancellation: Option<Arc<Cancellation>>) -> Result<()> {
        let hosted = {
            let mut stage = self.stage.lock().unwrap_or_else(PoisonError::into_inner);
            match std::mem::replace(&mut *stage, Stage::Waiting) {
                Stage::Hosted(hosted) => hosted,
                other => {
                    let spent = other.spent();
                    *stage = other;
                    return Err(spent);
                }
            }
        };
        let mut wait = Wait {
            stage: self.stage.clone(),
            abandoned: self.abandoned.clone(),
            ended: false,
        };
        let mut cancel = flag_of(cancellation.as_ref());
        run_while_awaited(async move {
            tokio::select! {
                biased;
                () = raised(cancel.as_mut()) => Err(cancelled("the admission")),
                admitted = hosted.admitted() => {
                    wait.end();
                    Ok(admitted?)
                }
            }
        })
        .await
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Space {
    /// Invites a device into the space at `level`: `read` or `write`. A
    /// nearby admission makes no administrator: admit the newcomer at
    /// `write`, then `raise` it at a rank. The invitation's text goes to
    /// the newcomer, whose person enters it in `Device::join`; `name` is
    /// what the newcomer's screen shows for this device, and `listener` is
    /// asked whether this device's person saw the same admission code on
    /// both screens. The newcomer reads what is written after its
    /// admission. A device hosts one invitation at a time; a new one
    /// replaces the last. It fails unless this device administers the
    /// space.
    pub async fn invite(
        &self,
        level: String,
        name: String,
        listener: Arc<dyn AdmissionListener>,
    ) -> Result<Arc<Invitation>> {
        let level = nearby_level(&level)?;
        let space = self.inner.clone();
        let abandoned = watch::Sender::new(false);
        let flag = abandoned.subscribe();
        let invitation = run(async move {
            space
                .invite(level, &name, move |code, newcomer| {
                    confirmed(listener, code, newcomer, Some(flag), CONFIRM_WITHIN)
                })
                .await
        })
        .await?;
        Ok(Arc::new(Invitation {
            text: invitation.text().to_owned(),
            stage: Arc::new(Mutex::new(Stage::Hosted(invitation))),
            abandoned,
        }))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl Device {
    /// Joins a space by the text of an invitation another device shows.
    /// `name` is what the other screen shows for this device, and
    /// `listener` is asked whether this device's person saw the same
    /// admission code on both screens, within 15 minutes of this call's
    /// asking the other device. It fails for text that is no invitation,
    /// when a person did not confirm the code, and when the other device
    /// is not reachable.
    ///
    /// Cancelling it abandons the admission: `cancellation` cancelled, or
    /// the caller no longer waiting, as a cancelled coroutine. The call
    /// fails, its work stops where it stands, and a listener being asked
    /// is waited for no longer. The device has joined nothing.
    #[uniffi::method(default(cancellation = None))]
    pub async fn join(
        &self,
        invitation: String,
        name: String,
        listener: Arc<dyn AdmissionListener>,
        cancellation: Option<Arc<Cancellation>>,
    ) -> Result<Arc<Space>> {
        let device = self.inner.clone();
        let mut cancel = flag_of(cancellation.as_ref());
        let space = run_while_awaited(async move {
            tokio::select! {
                biased;
                () = raised(cancel.as_mut()) => Err(cancelled("the admission")),
                joined = device.join(&invitation, &name, move |code, host| {
                    confirmed(listener, code, host, None, CONFIRM_WITHIN)
                }) => Ok(joined?),
            }
        })
        .await?;
        Ok(self.space_of(space))
    }
}

#[cfg(test)]
mod tests {
    use super::{AdmissionListener, CONFIRM_WITHIN, confirmed, nearby_level};
    use crate::{Cancellation, Device, DeviceOptions, FrasilError, Result};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::Duration;

    /// A listener that notes what it is shown, waits until it is released,
    /// then gives its answer.
    struct Asked {
        answer: Result<bool>,
        state: Mutex<State>,
        changed: Condvar,
    }

    #[derive(Default)]
    struct State {
        shown: Option<(String, String)>,
        released: bool,
        returned: bool,
    }

    impl Asked {
        /// A listener that answers `answer` as soon as it is asked.
        fn answering(answer: bool) -> Arc<Self> {
            let asked = Self::held(Ok(answer));
            asked.release();
            asked
        }

        /// A listener that waits for [`release`](Self::release).
        fn held(answer: Result<bool>) -> Arc<Self> {
            Arc::new(Self {
                answer,
                state: Mutex::default(),
                changed: Condvar::new(),
            })
        }

        fn release(&self) {
            self.state.lock().unwrap().released = true;
            self.changed.notify_all();
        }

        /// Waits until `check` holds of the listener.
        fn until(&self, check: impl Fn(&State) -> bool) {
            let state = self.state.lock().unwrap();
            let (_state, timed_out) = self
                .changed
                .wait_timeout_while(state, Duration::from_secs(30), |state| !check(state))
                .unwrap();
            assert!(!timed_out.timed_out(), "the listener was not asked in time");
        }

        /// The code and the name the listener was shown, once it is asked.
        async fn shown(self: &Arc<Self>) -> (String, String) {
            let asked = self.clone();
            tokio::task::spawn_blocking(move || {
                asked.until(|state| state.shown.is_some());
                asked.state.lock().unwrap().shown.clone().unwrap()
            })
            .await
            .unwrap()
        }

        /// Waits until the listener's thread has its answer back.
        async fn returned(self: &Arc<Self>) {
            let asked = self.clone();
            tokio::task::spawn_blocking(move || asked.until(|state| state.returned))
                .await
                .unwrap();
        }
    }

    impl AdmissionListener for Asked {
        fn confirm(&self, code: String, name: String) -> Result<bool> {
            let mut state = self.state.lock().unwrap();
            state.shown = Some((code, name));
            self.changed.notify_all();
            let mut state = self
                .changed
                .wait_while(state, |state| !state.released)
                .unwrap();
            state.returned = true;
            self.changed.notify_all();
            self.answer.clone()
        }
    }

    fn says(error: &FrasilError, part: &str) -> bool {
        error.to_string().contains(part)
    }

    async fn device(key: u8) -> Arc<Device> {
        let options = DeviceOptions { loopback: true };
        Device::open_in_memory(vec![key; 32], Some(options))
            .await
            .unwrap()
    }

    /// The names of the levels a nearby admission grants, and the refusal
    /// of every other, which says what to do instead.
    #[test]
    fn a_nearby_admission_grants_read_or_write() {
        assert_eq!(nearby_level("read"), Ok(frasil::Level::Read));
        assert_eq!(nearby_level("write"), Ok(frasil::Level::Write));
        for refused in ["administer", "Write", "", "owner"] {
            let error = nearby_level(refused).unwrap_err();
            assert!(says(&error, "read or write"), "{error}");
            assert!(says(&error, "raise"), "{error}");
        }
    }

    /// An invitation at `administer` is refused before anything is hosted.
    #[tokio::test]
    async fn an_invitation_to_administer_is_refused() {
        let host = device(1).await;
        let space = host.create_space().await.unwrap();
        let invited = space
            .invite("administer".into(), "host".into(), Asked::answering(true))
            .await;
        assert!(invited.is_err_and(|error| says(&error, "read or write")));
        host.shutdown().await.unwrap();
    }

    /// A listener's answer counts; one that fails, and one that does not
    /// answer in time or before the admission is abandoned, refuse, and
    /// nothing waits for the listener after that.
    #[tokio::test]
    async fn a_listener_that_fails_or_does_not_answer_refuses() {
        let ask = |listener: Arc<Asked>, abandoned, within| {
            confirmed(listener, "123456".into(), "other".into(), abandoned, within)
        };
        assert!(ask(Asked::answering(true), None, CONFIRM_WITHIN).await);
        assert!(!ask(Asked::answering(false), None, CONFIRM_WITHIN).await);
        let failing = Asked::held(Err(FrasilError::Failed {
            reason: "the screen is gone".into(),
        }));
        failing.release();
        assert!(!ask(failing, None, CONFIRM_WITHIN).await);

        // No answer in time: refused, with the listener still asked.
        let slow = Asked::held(Ok(true));
        assert!(!ask(slow.clone(), None, Duration::from_millis(20)).await);
        assert_eq!(slow.shown().await.0, "123456");
        slow.release();
        slow.returned().await;

        // Abandoned while the listener is asked: refused at once.
        let abandoned = tokio::sync::watch::Sender::new(false);
        let parked = Asked::held(Ok(true));
        let asking = tokio::spawn(ask(
            parked.clone(),
            Some(abandoned.subscribe()),
            CONFIRM_WITHIN,
        ));
        parked.shown().await;
        abandoned.send_replace(true);
        assert!(!asking.await.unwrap());
        parked.release();
        parked.returned().await;
    }

    /// A join whose listener never answers ends when it is cancelled and
    /// when its caller stops waiting, and the device joins nothing; the
    /// same device then joins by a new invitation.
    #[tokio::test]
    async fn a_join_is_abandoned_while_its_listener_is_asked() {
        let host = device(11).await;
        let newcomer = device(12).await;
        let space = host.create_space().await.unwrap();

        // Cancelled by its cancellation. The inviting device's person does
        // not confirm here: a device that confirmed has granted, whatever
        // the newcomer does after.
        let invitation = space
            .invite("write".into(), "host".into(), Asked::answering(false))
            .await
            .unwrap();
        let parked = Asked::held(Ok(true));
        let cancellation = Cancellation::new();
        let joining = tokio::spawn({
            let (newcomer, listener, text) = (newcomer.clone(), parked.clone(), invitation.text());
            let cancellation = cancellation.clone();
            async move {
                newcomer
                    .join(text, "newcomer".into(), listener, Some(cancellation))
                    .await
            }
        });
        let (code, name) = parked.shown().await;
        assert_eq!((code.len(), name.as_str()), (6, "host"));
        cancellation.cancel();
        let joined = tokio::time::timeout(Duration::from_secs(30), joining)
            .await
            .expect("a cancelled join ends")
            .unwrap();
        assert!(joined.is_err_and(|error| says(&error, "the admission was cancelled")));
        assert!(newcomer.spaces().await.is_empty());
        parked.release();
        parked.returned().await;

        // Abandoned by its caller, as a cancelled coroutine does.
        let invitation = space
            .invite("write".into(), "host".into(), Asked::answering(false))
            .await
            .unwrap();
        let parked = Asked::held(Ok(true));
        let joining = tokio::spawn({
            let (newcomer, listener, text) = (newcomer.clone(), parked.clone(), invitation.text());
            async move { newcomer.join(text, "newcomer".into(), listener, None).await }
        });
        parked.shown().await;
        joining.abort();
        assert!(joining.await.is_err_and(|ended| ended.is_cancelled()));
        // The listener's answer goes nowhere: nothing is joined by it.
        parked.release();
        parked.returned().await;
        assert!(newcomer.spaces().await.is_empty());

        // A join given a cancellation that was cancelled fails at once.
        let joined = newcomer
            .join(
                invitation.text(),
                "newcomer".into(),
                Asked::answering(true),
                Some(cancellation),
            )
            .await;
        assert!(joined.is_err_and(|error| says(&error, "cancelled")));

        let invitation = space
            .invite("write".into(), "host".into(), Asked::answering(true))
            .await
            .unwrap();
        let joined = newcomer
            .join(
                invitation.text(),
                "newcomer".into(),
                Asked::answering(true),
                None,
            )
            .await
            .unwrap();
        invitation.admitted(None).await.unwrap();
        assert_eq!(joined.id(), space.id());
        newcomer.shutdown().await.unwrap();
        host.shutdown().await.unwrap();
    }

    /// An invitation whose wait is dropped, as a cancelled coroutine drops
    /// it, is abandoned: the newcomer is refused without the inviting
    /// device's listener being waited for, and a second wait says why the
    /// invitation is spent.
    #[tokio::test]
    async fn an_invitation_is_abandoned_when_its_wait_is_dropped() {
        let host = device(21).await;
        let newcomer = device(22).await;
        let space = host.create_space().await.unwrap();
        let parked = Asked::held(Ok(true));
        let invitation = space
            .invite("write".into(), "host".into(), parked.clone())
            .await
            .unwrap();
        let waiting = tokio::spawn({
            let invitation = invitation.clone();
            async move { invitation.admitted(None).await }
        });
        let joining = tokio::spawn({
            let (newcomer, text) = (newcomer.clone(), invitation.text());
            async move {
                newcomer
                    .join(text, "newcomer".into(), Asked::answering(true), None)
                    .await
            }
        });
        // A second wait while the first waits.
        parked.shown().await;
        let second = invitation.admitted(None).await;
        assert!(second.is_err_and(|error| says(&error, "another call is waiting")));

        waiting.abort();
        assert!(waiting.await.is_err_and(|ended| ended.is_cancelled()));
        let joined = tokio::time::timeout(Duration::from_secs(30), joining)
            .await
            .expect("the newcomer is refused")
            .unwrap();
        assert!(joined.is_err());
        assert!(newcomer.spaces().await.is_empty());
        assert_eq!(space.members().await.unwrap().len(), 1);

        let spent = invitation.admitted(None).await.unwrap_err();
        assert!(says(&spent, "the invitation is spent"), "{spent}");
        assert!(says(&spent, "was cancelled"), "{spent}");
        assert!(says(&spent, "invite again"), "{spent}");
        parked.release();
        parked.returned().await;
        newcomer.shutdown().await.unwrap();
        host.shutdown().await.unwrap();
    }
}
