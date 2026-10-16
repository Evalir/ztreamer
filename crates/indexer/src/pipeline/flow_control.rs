//! A channel from the fetch workers to the coordinator that limits the bytes in flight.
//!
//! Before a worker sends a block, it waits until the block fits in the limit. A block fits when
//! the bytes in flight and the block size are not more than the limit. The block at
//! `next_height` always fits. Only this block lets the builder write more blocks. If this block
//! waits, a deadlock occurs. The coordinator gives the bytes back when it puts blocks in a batch.

use std::{
    cell::Cell,
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        mpsc::{Receiver, RecvTimeoutError, SyncSender, sync_channel},
    },
};

use crate::{codec::CompactBlockRecord, parser::ParsedCompactBlock};

use super::PipelineError;

/// Makes a channel with a limit of `limit` bytes in flight.
pub(crate) fn channel(limit: usize, next_height: u64) -> (ThrottledSender, ThrottledReceiver) {
    let (tx, rx) = sync_channel(0);
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            in_flight: 0,
            next_height,
            cancelled: false,
        }),
        changed: Condvar::new(),
        limit,
    });
    (
        ThrottledSender {
            tx,
            shared: Arc::clone(&shared),
            segment: Cell::new(None),
        },
        ThrottledReceiver { rx, shared },
    )
}

/// The state that the senders and the receiver share. The condition variable wakes the senders
/// that wait when the state changes.
struct Shared {
    state: Mutex<State>,
    changed: Condvar,
    limit: usize,
}

struct State {
    /// The bytes that workers sent and that the coordinator did not put in a batch yet.
    in_flight: usize,
    /// The first height that the coordinator does not have.
    next_height: u64,
    /// When this flag is set, the senders that wait stop with an error.
    cancelled: bool,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("flow control lock is not poisoned")
    }

    fn cancel(&self) {
        self.lock().cancelled = true;
        self.changed.notify_all();
    }
}

/// The sender of a worker.
#[derive(Clone)]
pub(crate) struct ThrottledSender {
    tx: SyncSender<ParsedCompactBlock>,
    shared: Arc<Shared>,
    /// The next height to send in the current segment, and the last height of the segment.
    segment: Cell<Option<(u64, u64)>>,
}

impl ThrottledSender {
    /// Starts a segment. The worker must then send each height from `start` to `end`, in
    /// ascending order.
    pub(crate) fn begin_segment(&self, start: u32, end: u32) {
        self.segment.set(Some((u64::from(start), u64::from(end))));
    }

    /// The result is an error if the worker did not send all heights of the segment.
    pub(crate) fn end_segment(&self) -> Result<(), PipelineError> {
        match self.segment.take() {
            Some((next, end)) if next <= end => Err(PipelineError::SourceGap {
                expected: next as u32,
                actual: None,
            }),
            _ => Ok(()),
        }
    }

    /// Waits until the block fits in the limit, then sends it.
    /// The result is an error if the pipeline stopped, or if the block is not the next height
    /// of the segment. A missing height must not cause a wait: if the block at `next_height`
    /// never comes, all workers wait for all time.
    pub(crate) fn send(&self, block: ParsedCompactBlock) -> Result<(), PipelineError> {
        self.advance_segment(block.height)?;
        let height = u64::from(block.height);
        let bytes = CompactBlockRecord::encoded_size_bound(&block.transactions)
            .map_err(crate::ingest::IngestError::from)?;
        let shared = &*self.shared;
        let mut state = shared
            .changed
            .wait_while(shared.lock(), |state| {
                !state.cancelled
                    && height != state.next_height
                    && state.in_flight + bytes > shared.limit
            })
            .expect("flow control lock is not poisoned");
        if state.cancelled {
            return Err(PipelineError::Worker);
        }
        state.in_flight += bytes;
        drop(state);
        self.tx.send(block).map_err(|_| PipelineError::Worker)
    }

    /// Checks that `height` is the next height of the current segment, then moves the segment
    /// to the height after it. With no segment, all heights pass.
    fn advance_segment(&self, height: u32) -> Result<(), PipelineError> {
        let Some((next, end)) = self.segment.get() else {
            return Ok(());
        };
        if u64::from(height) != next || u64::from(height) > end {
            return Err(PipelineError::SourceGap {
                expected: next as u32,
                actual: Some(height),
            });
        }
        self.segment.set(Some((next + 1, end)));
        Ok(())
    }

    /// Stops all senders that wait. Use this when a worker fails.
    /// The failed worker can have the block at `next_height`, and no other worker can send it.
    pub(crate) fn cancel(&self) {
        self.shared.cancel();
    }
}

impl Drop for ThrottledSender {
    fn drop(&mut self) {
        // A panic in a worker also stops the other workers.
        if std::thread::panicking() {
            self.cancel();
        }
    }
}

/// The receiver of the coordinator. When it is dropped, also after an error, all senders that
/// wait stop.
pub(crate) struct ThrottledReceiver {
    rx: Receiver<ParsedCompactBlock>,
    shared: Arc<Shared>,
}

impl ThrottledReceiver {
    /// Waits for a block for at most `timeout`. After all senders are dropped, the result is
    /// [`RecvTimeoutError::Disconnected`].
    pub(crate) fn recv_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> Result<ParsedCompactBlock, RecvTimeoutError> {
        self.rx.recv_timeout(timeout)
    }

    /// Stops all senders: a sender that waits, or that sends later, gets an error. Blocks that
    /// were already sent can still be received.
    pub(crate) fn cancel(&self) {
        self.shared.cancel();
    }

    /// Sets the first height that the coordinator does not have.
    /// The worker with the block at this height can then send it.
    pub(crate) fn set_next_height(&self, next_height: u64) {
        let mut state = self.shared.lock();
        if state.next_height != next_height {
            state.next_height = next_height;
            self.shared.changed.notify_all();
        }
    }

    /// Gives back the bytes of the blocks that the coordinator put in a batch.
    pub(crate) fn release(&self, bytes: usize) {
        if bytes > 0 {
            let mut state = self.shared.lock();
            state.in_flight = state.in_flight.saturating_sub(bytes);
            self.shared.changed.notify_all();
        }
    }
}

impl Drop for ThrottledReceiver {
    fn drop(&mut self) {
        self.shared.cancel();
    }
}
