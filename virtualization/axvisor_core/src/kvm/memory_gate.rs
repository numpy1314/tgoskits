// SPDX-License-Identifier: Apache-2.0
//! Quiesce all guest entries before replacing a userspace memory slot.
use alloc::sync::Arc;
use core::sync::atomic::{AtomicUsize, Ordering};

use axvisor_api::sync::WaitQueue;

use super::state::{VcpuOperationGuard, VcpuOperationLock};

const WRITER: usize = 1 << (usize::BITS - 1);

pub(super) struct MemoryGate {
    state: AtomicUsize,
    writers: Arc<VcpuOperationLock>,
    wait: WaitQueue,
}

impl MemoryGate {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: AtomicUsize::new(0),
            writers: VcpuOperationLock::new(),
            wait: WaitQueue::new(),
        })
    }

    pub fn read(self: &Arc<Self>) -> ReadGuard {
        let gate = self.clone();
        self.wait.wait_until(move || {
            gate.state
                .fetch_update(Ordering::Acquire, Ordering::Relaxed, |state| {
                    (state < WRITER - 1).then_some(state + 1)
                })
                .is_ok()
        });
        ReadGuard(self.clone())
    }

    pub fn write(self: &Arc<Self>) -> WriteGuard {
        let serial = self.writers.lock();
        self.state.fetch_or(WRITER, Ordering::AcqRel);
        let gate = self.clone();
        self.wait
            .wait_until(move || gate.state.load(Ordering::Acquire) == WRITER);
        WriteGuard {
            gate: self.clone(),
            _serial: serial,
        }
    }
}

pub(super) struct ReadGuard(Arc<MemoryGate>);
impl Drop for ReadGuard {
    fn drop(&mut self) {
        if self.0.state.fetch_sub(1, Ordering::Release) == WRITER + 1 {
            self.0.wait.wake_all();
        }
    }
}

pub(super) struct WriteGuard {
    gate: Arc<MemoryGate>,
    _serial: VcpuOperationGuard,
}
impl Drop for WriteGuard {
    fn drop(&mut self) {
        self.gate.state.store(0, Ordering::Release);
        self.gate.wait.wake_all();
    }
}
