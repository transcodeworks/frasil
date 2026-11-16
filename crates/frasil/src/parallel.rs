//! Work spread over the machine's cores: independent checks and openings
//! that each read their own bytes. Natively, tasks run on scoped threads,
//! the calling thread among them; on wasm32, in turn.

use frasil_units::objects::{InTurn, Task, Tasks};

/// Below this many bytes of work, tasks run in turn: starting threads would
/// cost more than it saves.
pub(crate) const PARALLEL_BYTES: usize = 256 * 1024;

/// The work an event's decoding counts for against [`PARALLEL_BYTES`]: its
/// signature check outweighs its bytes, so a few events go at once.
pub(crate) const EVENT_WORK: usize = 64 * 1024;

/// [`Tasks`] over the machine's cores.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Cores;

impl Tasks for Cores {
    #[cfg(not(target_arch = "wasm32"))]
    fn run<'a>(&self, tasks: Vec<Task<'a>>) {
        let threads = std::thread::available_parallelism()
            .map_or(1, std::num::NonZeroUsize::get)
            .min(tasks.len());
        if threads <= 1 {
            return InTurn.run(tasks);
        }
        let queue = std::sync::Mutex::new(tasks.into_iter());
        let work = || {
            loop {
                let next = queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .next();
                match next {
                    Some(task) => task(),
                    None => break,
                }
            }
        };
        std::thread::scope(|scope| {
            for _ in 1..threads {
                scope.spawn(work);
            }
            work();
        });
    }

    #[cfg(target_arch = "wasm32")]
    fn run<'a>(&self, tasks: Vec<Task<'a>>) {
        InTurn.run(tasks);
    }
}

/// The tasks to use for work of this many bytes.
pub(crate) fn for_bytes(bytes: usize) -> &'static dyn Tasks {
    if bytes >= PARALLEL_BYTES {
        &Cores
    } else {
        &InTurn
    }
}

/// `f` of each item, in order, over the machine's cores when the work is at
/// least [`PARALLEL_BYTES`].
pub(crate) fn map<T: Send, R: Send>(
    items: Vec<T>,
    bytes: usize,
    f: impl Fn(T) -> R + Sync,
) -> Vec<R> {
    let mut out: Vec<Option<R>> = Vec::new();
    out.resize_with(items.len(), || None);
    let f = &f;
    let tasks: Vec<Task<'_>> = items
        .into_iter()
        .zip(out.iter_mut())
        .map(|(item, slot)| -> Task<'_> { Box::new(move || *slot = Some(f(item))) })
        .collect();
    for_bytes(bytes).run(tasks);
    out.into_iter()
        .map(|r| r.expect("every task ran"))
        .collect()
}
