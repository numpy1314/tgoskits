// Copyright 2025 The Axvisor Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Runtime state for the KVM-compatible control endpoint.
//!
//! Pure ioctl payloads are imported from `kvm-uapi`. The types defined here own
//! AxVisor and host-control resources, so they intentionally remain in
//! axvisor_core.

#[cfg(target_arch = "x86_64")]
use alloc::collections::BTreeSet;
use alloc::{
    collections::{BTreeMap, VecDeque},
    sync::Arc,
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(all(target_arch = "x86_64", feature = "vmx"))]
use axaddrspace::GuestPhysAddr;
use axaddrspace::device::AccessWidth;
use axvisor_api::{control as api_control, sync::WaitQueue, task::TaskHandle};
use axvm::AxVMRef;
#[cfg(target_arch = "x86_64")]
use hashbrown::HashMap;
#[cfg(target_arch = "x86_64")]
type MappedPages = HashMap<u64, MappedMemoryPage>;
#[cfg(not(target_arch = "x86_64"))]
type MappedPages = BTreeMap<u64, MappedMemoryPage>;
#[cfg(not(all(target_arch = "aarch64", feature = "arm-vhe")))]
pub(in crate::kvm) use kvm_uapi::OneReg;
#[cfg(target_arch = "x86_64")]
pub(in crate::kvm) use kvm_uapi::x86::{PvClockVcpuTimeInfo, PvClockWallClock};
pub(in crate::kvm) use kvm_uapi::{
    KvmCpuidEntry2, KvmEnableCap, KvmIoEventFd, KvmIrqFd, UserspaceMemoryRegion,
};

#[cfg(target_arch = "x86_64")]
use crate::kvm::abi;
use crate::vmm::interrupt::VirtualInterrupt;

#[derive(Clone)]
pub(in crate::kvm) enum ControlFileState {
    System,
    Vm(VmFileState),
    Vcpu(VcpuFileState),
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    ArmDevice(u64),
}

#[derive(Clone)]
pub(in crate::kvm) struct VmFileState {
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    pub arm_ipa_bits: u8,
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    pub arm_cache_ready: bool,
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    pub memory_gate: Arc<super::memory_gate::MemoryGate>,
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    pub arm_gic: Arc<ax_kspin::SpinNoIrq<super::arm_gic::Gic>>,
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    pub arm_devices: Vec<u64>,
    pub(in crate::kvm) vm: AxVMRef,
    /// Set once the VM file descriptor is closed.  The VM state must remain
    /// reachable while vCPU file descriptors are still open, matching Linux
    /// KVM's reference-counted VM lifetime.
    pub(in crate::kvm) vm_fd_closed: bool,
    pub(in crate::kvm) memory_slots: BTreeMap<u32, MemorySlot>,
    pub(in crate::kvm) ioeventfds: BTreeMap<IoEventFdKey, IoEventFd>,
    pub(in crate::kvm) irqfds: BTreeMap<IrqFdKey, IrqFd>,
    pub(in crate::kvm) gsi_routes: BTreeMap<u32, GsiRoute>,
    pub(in crate::kvm) vcpu_files: BTreeMap<u32, api_control::ControlFileId>,
    pub(in crate::kvm) clock: Vec<u8>,
    pub(in crate::kvm) pit2: Vec<u8>,
    #[cfg(target_arch = "x86_64")]
    pub(in crate::kvm) irqchips: [Vec<u8>; abi::KVM_NR_IRQCHIPS],
    pub(in crate::kvm) tsc_khz: u32,
    pub(in crate::kvm) tss_addr: Option<usize>,
    pub(in crate::kvm) identity_map_addr: Option<u64>,
    pub(in crate::kvm) irqchip_created: bool,
    pub(in crate::kvm) pit2_created: bool,
    pub(in crate::kvm) gsi_routing_count: u32,
    #[cfg(target_arch = "x86_64")]
    pub(in crate::kvm) userspace_eoi_vectors: BTreeSet<u8>,
}

/// Host-side state associated with one KVM vCPU fd.
///
/// Some fields, such as FPU/LAPIC/XSAVE blobs, are stored as opaque bytes
/// because the current control endpoint only needs to preserve KVM ABI payloads.
#[derive(Clone)]
pub(in crate::kvm) struct VcpuFileState {
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    pub arm_initialized: bool,
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    pub arm_start: Option<(u64, u64)>,
    pub(in crate::kvm) vm_file: api_control::ControlFileId,
    pub(in crate::kvm) vcpu_id: u32,
    pub(in crate::kvm) mmap_area: api_control::MmapAreaId,
    pub(in crate::kvm) mp_state: u32,
    pub(in crate::kvm) halted: bool,
    pub(in crate::kvm) pending_interrupts: VecDeque<VirtualInterrupt>,
    pub(in crate::kvm) pending_mmio_read: Option<PendingMmioRead>,
    pub(in crate::kvm) pending_io_read: Option<PendingIoRead>,
    #[cfg(all(target_arch = "x86_64", feature = "vmx"))]
    pub(in crate::kvm) pending_startup_entry: Option<GuestPhysAddr>,
    pub(in crate::kvm) cpuid: Vec<KvmCpuidEntry2>,
    pub(in crate::kvm) emulated_msrs: BTreeMap<u32, u64>,
    pub(in crate::kvm) fpu: Vec<u8>,
    pub(in crate::kvm) vcpu_events: Vec<u8>,
    pub(in crate::kvm) xsave: Vec<u8>,
    pub(in crate::kvm) xcrs: Vec<u8>,
    pub(in crate::kvm) signal_mask: Vec<u8>,
    pub(in crate::kvm) lapic: Vec<u8>,
    pub(in crate::kvm) vapic_addr: Option<u64>,
    pub(in crate::kvm) operation_lock: Arc<VcpuOperationLock>,
}

/// Serializes stateful ioctls issued through one KVM vCPU file.
///
/// KVM userspace may hand a vCPU fd between host threads while interrupting an
/// earlier `KVM_RUN`.  AxVCpu's architectural state is intentionally owned by
/// only one host task at a time, so the control endpoint must provide the same
/// per-vCPU serialization that Linux KVM provides around vCPU ioctls.
pub(in crate::kvm) struct VcpuOperationLock {
    held: AtomicBool,
    wait_queue: WaitQueue,
}

impl VcpuOperationLock {
    pub(in crate::kvm) fn new() -> Arc<Self> {
        Arc::new(Self {
            held: AtomicBool::new(false),
            wait_queue: WaitQueue::new(),
        })
    }

    pub(in crate::kvm) fn lock(self: &Arc<Self>) -> VcpuOperationGuard {
        if self
            .held
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            let lock = Arc::clone(self);
            self.wait_queue.wait_until(move || {
                lock.held
                    .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            });
        }
        VcpuOperationGuard {
            lock: Arc::clone(self),
        }
    }
}

pub(in crate::kvm) struct VcpuOperationGuard {
    lock: Arc<VcpuOperationLock>,
}

impl Drop for VcpuOperationGuard {
    fn drop(&mut self) {
        self.lock.held.store(false, Ordering::Release);
        self.lock.wait_queue.wake_one();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::kvm) struct PendingMmioRead {
    pub(in crate::kvm) reg: usize,
    pub(in crate::kvm) width: AccessWidth,
    pub(in crate::kvm) reg_width: AccessWidth,
    pub(in crate::kvm) signed_ext: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::kvm) enum PendingIoRead {
    Accumulator {
        width: AccessWidth,
    },
    String {
        width: AccessWidth,
        addr: axaddrspace::GuestPhysAddr,
        repeat: bool,
        remaining: u64,
        next_rip: u64,
        address_size: u8,
        decrement: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::kvm) struct MemorySlot {
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    pub arm_pages: Arc<[axaddrspace::HostPhysAddr]>,
    pub(in crate::kvm) flags: u32,
    pub(in crate::kvm) guest_phys_addr: u64,
    pub(in crate::kvm) memory_size: u64,
    pub(in crate::kvm) userspace_addr: u64,
    pub(in crate::kvm) user_address_space: api_control::UserAddressSpaceId,
    pub(in crate::kvm) pinned_pages: api_control::PinnedUserPagesId,
    pub(in crate::kvm) mapped_pages: MappedPages,
}

#[derive(Clone, Debug)]
pub(in crate::kvm) struct MappedMemoryPage {
    pub(in crate::kvm) pinned_pages: PinnedPageGroup,
    pub(in crate::kvm) writable: bool,
}

#[derive(Clone, Debug)]
pub(in crate::kvm) struct PinnedPageGroup {
    pub(in crate::kvm) id: api_control::PinnedUserPagesId,
    remaining: Arc<AtomicUsize>,
}

impl PinnedPageGroup {
    #[cfg(target_arch = "x86_64")]
    pub(in crate::kvm) fn new(id: api_control::PinnedUserPagesId, pages: usize) -> Self {
        Self {
            id,
            remaining: Arc::new(AtomicUsize::new(pages.max(1))),
        }
    }

    pub(in crate::kvm) fn release(&self) {
        if self.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
            let _ = api_control::release_pinned_user_pages(self.id);
        }
    }
}

impl PartialEq for PinnedPageGroup {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for PinnedPageGroup {}
impl PartialEq for MappedMemoryPage {
    fn eq(&self, other: &Self) -> bool {
        self.pinned_pages == other.pinned_pages && self.writable == other.writable
    }
}
impl Eq for MappedMemoryPage {}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::kvm) struct IoEventFdKey {
    pub(in crate::kvm) addr: u64,
    pub(in crate::kvm) datamatch: u64,
    pub(in crate::kvm) pio: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::kvm) struct IoEventFd {
    pub(in crate::kvm) addr: u64,
    pub(in crate::kvm) len: u32,
    pub(in crate::kvm) datamatch: u64,
    pub(in crate::kvm) user_fd_ref: api_control::UserFdRefId,
    pub(in crate::kvm) flags: u32,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(in crate::kvm) struct IrqFdKey {
    pub(in crate::kvm) gsi: u32,
    pub(in crate::kvm) fd: u32,
}

#[derive(Clone, Debug)]
pub(in crate::kvm) struct IrqFd {
    pub(in crate::kvm) user_fd_ref: api_control::UserFdRefId,
    pub(in crate::kvm) cancel: Arc<AtomicBool>,
    pub(in crate::kvm) _task: TaskHandle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::kvm) enum GsiRoute {
    IrqChip {
        pin: u32,
    },
    Msi {
        address_lo: u32,
        address_hi: u32,
        data: u32,
    },
}

impl VmFileState {
    pub(super) fn has_live_children(&self) -> bool {
        #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
        if !self.arm_devices.is_empty() {
            return true;
        }
        !self.vcpu_files.is_empty()
    }
}
