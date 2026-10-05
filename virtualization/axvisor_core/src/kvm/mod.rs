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

//! AxVisor KVM-compatible host control endpoint callbacks.

mod abi;
#[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
mod arm;
#[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
mod arm_gic;
mod cpuid;
mod eventfd;
mod memory;
#[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
mod memory_gate;
mod run;
mod state;
mod util;
mod vcpu;
mod vm;

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub use abi::public::*;
use abi::*;
use ax_errno::{AxError, AxResult, ax_err};
use ax_kspin::SpinNoIrq as Mutex;
#[cfg(all(target_arch = "x86_64", feature = "vmx"))]
use axaddrspace::GuestPhysAddr;
use axvisor_api::control::{self as api_control, ControlOps};
use cpuid::{get_cpuid2, get_supported_cpuid, set_cpuid2};
use eventfd::{
    read_ioeventfd, read_irqfd, set_gsi_routing, set_irq_line, signal_msi, stop_irqfd,
    update_ioeventfd, update_irqfd,
};
use memory::{read_userspace_memory_region, set_user_memory_region, unmap_memory_slot};
use run::run_vcpu_file;
use state::*;
use vcpu::*;
use vm::*;

use crate::vmm::interrupt::{InterruptRoute, VirtualInterrupt};

static REGISTERED: AtomicBool = AtomicBool::new(false);
static NEXT_CONTROL_FILE_ID: AtomicU64 = AtomicU64::new(1);
pub(in crate::kvm) static CONTROL_FILES: Mutex<
    BTreeMap<api_control::ControlFileId, ControlFileState>,
> = Mutex::new(BTreeMap::new());
const KVM_CONTROL_OPS: ControlOps = ControlOps { open, close, ioctl };

/// Registers the host-visible KVM-compatible control endpoint.
pub fn init() -> AxResult {
    if REGISTERED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return Ok(());
    }

    if let Err(err) = api_control::register_endpoint(KVM_CONTROL_OPS) {
        REGISTERED.store(false, Ordering::Release);
        return Err(err);
    }

    info!("AxVisor KVM control endpoint registered: kvm");
    Ok(())
}

/// Shuts down host control endpoint state.
pub fn shutdown() -> AxResult {
    // Current host adapters publish the control endpoint for the host lifetime.
    Ok(())
}

fn open() -> AxResult<api_control::ControlFileId> {
    create_control_file(ControlFileState::System)
}

fn close(control_file: api_control::ControlFileId) -> AxResult {
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    {
        let parent = match CONTROL_FILES.lock().get(&control_file) {
            Some(ControlFileState::ArmDevice(vm_file)) => Some(*vm_file),
            _ => None,
        };
        if let Some(parent) = parent {
            return arm::close_device(control_file, parent);
        }
    }
    enum CloseAction {
        Vcpu(api_control::MmapAreaId),
        Vm {
            control_file: api_control::ControlFileId,
            irqfds: Vec<IrqFd>,
        },
        None,
    }

    let action = {
        let mut control_files = CONTROL_FILES.lock();
        let Some(state) = control_files.get(&control_file) else {
            return ax_err!(NotFound);
        };
        match state {
            ControlFileState::Vm(_) => {
                // Keep the VM state alive until all vCPU fds have closed. The
                // VM fd can be dropped before vCPU fds during process exit.
                let has_vcpus = match control_files.get_mut(&control_file) {
                    Some(ControlFileState::Vm(vm)) => {
                        if vm.has_live_children() {
                            vm.vm_fd_closed = true;
                            true
                        } else {
                            false
                        }
                    }
                    _ => unreachable!(),
                };
                if has_vcpus {
                    CloseAction::None
                } else {
                    let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file)
                    else {
                        unreachable!()
                    };
                    let irqfds = core::mem::take(&mut vm.irqfds).into_values().collect();
                    // Keep the VM entry in CONTROL_FILES while irqfd listeners
                    // are stopped.  Listeners may still perform one final
                    // lookup after cancellation and must not observe NotFound
                    // merely because teardown began.
                    CloseAction::Vm {
                        control_file,
                        irqfds,
                    }
                }
            }
            ControlFileState::Vcpu(_) => {
                let Some(ControlFileState::Vcpu(vcpu)) = control_files.remove(&control_file) else {
                    unreachable!()
                };
                let cleanup_vm =
                    if let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&vcpu.vm_file) {
                        vm.vcpu_files.remove(&vcpu.vcpu_id);
                        vm.vm_fd_closed && !vm.has_live_children()
                    } else {
                        false
                    };
                if cleanup_vm {
                    // The closing vCPU has already been removed from
                    // `vm.vcpu_files`, so the VM cleanup loop below cannot
                    // release its mmap area. Release this last vCPU mapping
                    // explicitly before destroying the VM state.
                    let _ = api_control::release_mmap_area(vcpu.mmap_area);
                    let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&vcpu.vm_file)
                    else {
                        unreachable!()
                    };
                    let irqfds = core::mem::take(&mut vm.irqfds).into_values().collect();
                    CloseAction::Vm {
                        control_file: vcpu.vm_file,
                        irqfds,
                    }
                } else {
                    CloseAction::Vcpu(vcpu.mmap_area)
                }
            }
            #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
            ControlFileState::ArmDevice(_) => unreachable!(),
            ControlFileState::System => {
                control_files.remove(&control_file);
                CloseAction::None
            }
        }
    };

    match action {
        CloseAction::Vm {
            control_file,
            irqfds,
        } => {
            // Stop irqfd listeners before tearing down the VM and its vCPU
            // resources.  A listener may be woken by a final device interrupt
            // while the VM control-file entry is being removed; stopping and
            // joining it first prevents delivery attempts against a deleted
            // VM (and the resulting NotFound warning storm).
            for irqfd in irqfds {
                stop_irqfd(irqfd);
            }
            let vm = match CONTROL_FILES.lock().remove(&control_file) {
                Some(ControlFileState::Vm(vm)) => vm,
                _ => return ax_err!(NotFound),
            };
            let _ = vm.vm.shutdown();
            // KVM-created vCPUs are registered in the VMM task table.  Join
            // and remove them before dropping the VM so their stacks and VM
            // references do not accumulate across repeated VM lifetimes.
            #[cfg(not(all(target_arch = "aarch64", feature = "arm-vhe")))]
            crate::vmm::vcpus::cleanup_vm_vcpus(vm.vm.id());
            for ioeventfd in vm.ioeventfds.into_values() {
                let _ = api_control::release_user_fd_ref(ioeventfd.user_fd_ref);
            }
            for memory_slot in vm.memory_slots.into_values() {
                unmap_memory_slot(&vm.vm, memory_slot);
            }
            for vcpu_file in vm.vcpu_files.into_values() {
                if let Some(ControlFileState::Vcpu(vcpu)) = CONTROL_FILES.lock().remove(&vcpu_file)
                {
                    let _ = api_control::release_mmap_area(vcpu.mmap_area);
                }
            }
        }
        CloseAction::Vcpu(mmap_area) => {
            let _ = api_control::release_mmap_area(mmap_area);
        }
        CloseAction::None => {}
    }
    Ok(())
}

fn create_control_file(
    control_file_state: ControlFileState,
) -> AxResult<api_control::ControlFileId> {
    let control_file = next_control_file_id()?;
    CONTROL_FILES
        .lock()
        .insert(control_file, control_file_state);
    Ok(control_file)
}

pub(crate) fn queue_control_vcpu_interrupt(route: InterruptRoute) -> AxResult {
    let mut control_files = CONTROL_FILES.lock();
    let vcpu_file = control_vcpu_file_by_vm_id(&control_files, route.vm_id, route.vcpu_id)?;
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&vcpu_file) else {
        return Err(AxError::NotFound);
    };
    vcpu.halted = false;
    vcpu.pending_interrupts.push_back(route.interrupt);
    Ok(())
}

pub(crate) fn control_vcpu_mask(vm_id: usize) -> Option<usize> {
    let control_files = CONTROL_FILES.lock();
    let vm = control_files.iter().find_map(|(_, state)| match state {
        ControlFileState::Vm(vm) if vm.vm.id() == vm_id => Some(vm),
        _ => None,
    })?;

    Some(vm.vcpu_files.keys().fold(0usize, |mask, &vcpu_id| {
        mask | 1usize.checked_shl(vcpu_id).unwrap_or(usize::MAX)
    }))
}

fn control_vcpu_file_by_vm_id(
    control_files: &BTreeMap<api_control::ControlFileId, ControlFileState>,
    vm_id: usize,
    vcpu_id: usize,
) -> AxResult<api_control::ControlFileId> {
    let vm_file = control_files
        .iter()
        .find_map(|(control_file, state)| match state {
            ControlFileState::Vm(vm) if vm.vm.id() == vm_id => Some(*control_file),
            _ => None,
        })
        .ok_or(AxError::NotFound)?;
    match control_files.get(&vm_file) {
        Some(ControlFileState::Vm(vm)) => vm.vcpu_files.get(&(vcpu_id as u32)).copied(),
        _ => None,
    }
    .ok_or(AxError::NotFound)
}

#[cfg(any(target_arch = "x86_64", target_arch = "riscv64"))]
pub(in crate::kvm) fn vcpu_file_by_id(
    control_file: api_control::ControlFileId,
    vcpu_id: usize,
) -> AxResult<api_control::ControlFileId> {
    let vm_file = {
        let control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vcpu(vcpu)) = control_files.get(&control_file) else {
            return ax_err!(NotFound);
        };
        vcpu.vm_file
    };

    let control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get(&vm_file) else {
        return ax_err!(NotFound);
    };
    vm.vcpu_files
        .get(&(vcpu_id as u32))
        .copied()
        .ok_or(AxError::InvalidInput)
}

#[cfg(any(target_arch = "riscv64", all(target_arch = "x86_64", feature = "svm")))]
pub(in crate::kvm) fn set_vcpu_file_mp_state_by_id(
    control_file: api_control::ControlFileId,
    vcpu_id: usize,
    mp_state: u32,
) -> AxResult {
    let target_file = vcpu_file_by_id(control_file, vcpu_id)?;
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&target_file) else {
        return ax_err!(NotFound);
    };
    vcpu.mp_state = mp_state;
    if mp_state == KVM_MP_STATE_RUNNABLE {
        vcpu.halted = false;
    }
    Ok(())
}

#[cfg(all(target_arch = "x86_64", feature = "vmx"))]
pub(in crate::kvm) fn queue_vcpu_startup_by_id(
    control_file: api_control::ControlFileId,
    vcpu_id: usize,
    entry_point: GuestPhysAddr,
) -> AxResult {
    let target_file = vcpu_file_by_id(control_file, vcpu_id)?;
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&target_file) else {
        return ax_err!(NotFound);
    };
    vcpu.pending_startup_entry = Some(entry_point);
    vcpu.mp_state = KVM_MP_STATE_SIPI_RECEIVED;
    vcpu.halted = false;
    Ok(())
}

pub(in crate::kvm) fn take_control_vcpu_interrupts(
    control_file: api_control::ControlFileId,
) -> Vec<VirtualInterrupt> {
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
        return Vec::new();
    };
    if !vcpu.pending_interrupts.is_empty() {
        vcpu.halted = false;
    }
    vcpu.pending_interrupts.drain(..).collect()
}

fn next_control_file_id() -> AxResult<api_control::ControlFileId> {
    let control_file = NEXT_CONTROL_FILE_ID.fetch_add(1, Ordering::Relaxed);
    if control_file == 0 {
        return ax_err!(OutOfRange);
    }
    Ok(control_file)
}

fn control_file_state(control_file: api_control::ControlFileId) -> AxResult<ControlFileState> {
    match CONTROL_FILES.lock().get(&control_file).cloned() {
        Some(control_file_state) => Ok(control_file_state),
        None => ax_err!(NotFound),
    }
}

fn ioctl(control_file: api_control::ControlFileId, cmd: u32, arg: usize) -> AxResult<isize> {
    match control_file_state(control_file)? {
        #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
        ControlFileState::ArmDevice(vm) => arm::device_ioctl(vm, cmd, arg),
        ControlFileState::System => system_ioctl(cmd, arg),
        ControlFileState::Vm(_) => vm_ioctl(control_file, cmd, arg),
        ControlFileState::Vcpu(_) => vcpu_ioctl(control_file, cmd, arg),
    }
}

fn system_ioctl(cmd: u32, arg: usize) -> AxResult<isize> {
    match cmd {
        KVM_GET_API_VERSION => Ok(KVM_API_VERSION as isize),
        KVM_GET_MSR_INDEX_LIST => get_msr_index_list(arg),
        KVM_CHECK_EXTENSION => Ok(check_extension(arg) as isize),
        KVM_GET_VCPU_MMAP_SIZE => Ok(KVM_VCPU_MMAP_SIZE as isize),
        KVM_GET_SUPPORTED_CPUID => get_supported_cpuid(arg),
        KVM_X86_GET_MCE_CAP_SUPPORTED if cfg!(target_arch = "x86_64") => {
            api_control::copy_to_user(arg, &0u64.to_ne_bytes())?;
            Ok(0)
        }
        KVM_CREATE_VM => {
            #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
            let ipa_bits = if arg == 0 {
                40
            } else if (32..=axvm::arm_ipa_bits()).contains(&arg) {
                arg as u8
            } else {
                return ax_err!(InvalidInput);
            };
            let vm_file = create_vm_file()?;
            #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
            if let Some(ControlFileState::Vm(vm)) = CONTROL_FILES.lock().get_mut(&vm_file) {
                vm.arm_ipa_bits = ipa_bits;
            }
            match api_control::create_user_fd(vm_file, KVM_CONTROL_OPS, None) {
                Ok(fd) => Ok(fd as isize),
                Err(err) => {
                    let _ = close(vm_file);
                    Err(err)
                }
            }
        }
        _ => {
            debug!("unsupported KVM system ioctl cmd={cmd:#x} arg={arg:#x}");
            ax_err!(Unsupported)
        }
    }
}

fn vm_ioctl(control_file: api_control::ControlFileId, cmd: u32, arg: usize) -> AxResult<isize> {
    match cmd {
        KVM_CHECK_EXTENSION => Ok(check_extension(arg) as isize),
        KVM_CREATE_VCPU => create_vcpu_file(control_file, arg),
        #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
        KVM_ARM_PREFERRED_TARGET => arm::preferred_target(arg),
        #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
        KVM_CREATE_DEVICE => arm::create_device(control_file, arg),
        KVM_SET_USER_MEMORY_REGION => {
            let region = read_userspace_memory_region(arg)?;
            set_user_memory_region(control_file, region)?;
            Ok(0)
        }
        KVM_IOEVENTFD => {
            let ioeventfd = read_ioeventfd(arg)?;
            update_ioeventfd(control_file, ioeventfd)?;
            Ok(0)
        }
        KVM_SET_TSS_ADDR => set_tss_addr(control_file, arg),
        KVM_SET_IDENTITY_MAP_ADDR => set_identity_map_addr(control_file, arg),
        KVM_CREATE_IRQCHIP => create_irqchip(control_file),
        KVM_IRQ_LINE => set_irq_line(control_file, arg),
        #[cfg(target_arch = "x86_64")]
        KVM_GET_IRQCHIP => get_irqchip(control_file, arg),
        #[cfg(target_arch = "x86_64")]
        KVM_SET_IRQCHIP => set_irqchip(control_file, arg),
        KVM_CREATE_PIT2 => create_pit2(control_file, arg),
        KVM_GET_PIT2 => get_vm_blob(control_file, arg, |vm| &vm.pit2),
        KVM_SET_PIT2 => set_vm_blob(
            control_file,
            arg,
            KVM_PIT_STATE2_SIZE as usize,
            |vm, bytes| {
                vm.pit2 = bytes;
            },
        ),
        KVM_GET_CLOCK => get_vm_blob(control_file, arg, |vm| &vm.clock),
        KVM_SET_CLOCK => set_vm_blob(
            control_file,
            arg,
            KVM_CLOCK_DATA_SIZE as usize,
            |vm, bytes| {
                vm.clock = bytes;
            },
        ),
        KVM_GET_TSC_KHZ => get_tsc_khz(control_file),
        KVM_SET_TSC_KHZ => set_tsc_khz(control_file, arg),
        KVM_SET_GSI_ROUTING => set_gsi_routing(control_file, arg),
        KVM_IRQFD => {
            let irqfd = read_irqfd(arg)?;
            update_irqfd(control_file, irqfd)?;
            Ok(0)
        }
        KVM_SIGNAL_MSI => signal_msi(control_file, arg),
        KVM_ENABLE_CAP => enable_cap(arg),
        _ => {
            debug!("unsupported KVM VM ioctl cmd={cmd:#x} arg={arg:#x}");
            Err(AxError::Unsupported)
        }
    }
}

fn enable_cap(arg: usize) -> AxResult<isize> {
    let enable_cap = read_enable_cap(arg)?;
    if enable_cap.flags != 0 || enable_cap.args.iter().any(|arg| *arg != 0) {
        return ax_err!(Unsupported);
    }
    if check_extension(enable_cap.cap as usize) == 0 {
        return ax_err!(Unsupported);
    }
    Ok(0)
}

fn vcpu_ioctl(control_file: api_control::ControlFileId, cmd: u32, arg: usize) -> AxResult<isize> {
    // Serialize ioctls that access architectural vCPU state with KVM_RUN so a
    // vCPU fd can safely be handed between userspace threads. Control-only
    // operations, especially interrupt injection and MP-state changes, must
    // remain available while KVM_RUN is blocked in the guest.
    let _operation_guard = if matches!(
        cmd,
        KVM_RUN
            | KVM_GET_REGS
            | KVM_SET_REGS
            | KVM_GET_SREGS
            | KVM_SET_SREGS
            | KVM_GET_MSRS
            | KVM_SET_MSRS
            | KVM_SET_CPUID2
            | KVM_GET_ONE_REG
            | KVM_SET_ONE_REG
            | KVM_ARM_VCPU_INIT
            | KVM_GET_REG_LIST
            | KVM_GET_DEBUGREGS
            | KVM_SET_DEBUGREGS
    ) {
        let operation_lock = {
            let control_files = CONTROL_FILES.lock();
            let Some(ControlFileState::Vcpu(vcpu)) = control_files.get(&control_file) else {
                return ax_err!(NotFound);
            };
            vcpu.operation_lock.clone()
        };
        Some(operation_lock.lock())
    } else {
        None
    };

    match cmd {
        #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
        KVM_ARM_VCPU_INIT => arm::init_vcpu(control_file, arg),
        KVM_RUN => run_vcpu_file(control_file),
        KVM_GET_REGS => get_kvm_regs(control_file, arg),
        KVM_SET_REGS => set_kvm_regs(control_file, arg),
        KVM_GET_SREGS => get_kvm_sregs(control_file, arg),
        KVM_SET_SREGS => set_kvm_sregs(control_file, arg),
        KVM_GET_MSRS => get_msrs(control_file, arg),
        KVM_SET_MSRS => set_msrs(control_file, arg),
        KVM_SET_SIGNAL_MASK => set_signal_mask(control_file, arg),
        KVM_GET_FPU => get_vcpu_blob(control_file, arg, |vcpu| &vcpu.fpu),
        KVM_SET_FPU => set_fpu(control_file, arg),
        KVM_GET_LAPIC => get_lapic(control_file, arg),
        KVM_SET_LAPIC => set_lapic(control_file, arg),
        KVM_SET_CPUID2 => set_cpuid2(control_file, arg),
        KVM_GET_CPUID2 => get_cpuid2(control_file, arg),
        KVM_SET_VAPIC_ADDR => set_vapic_addr(control_file, arg),
        KVM_GET_ONE_REG => get_one_reg(control_file, arg),
        KVM_SET_ONE_REG => set_one_reg(control_file, arg),
        KVM_GET_REG_LIST => get_reg_list(control_file, arg),
        KVM_INTERRUPT => kvm_interrupt(control_file, arg),
        KVM_GET_MP_STATE => get_mp_state(control_file, arg),
        KVM_SET_MP_STATE => set_mp_state(control_file, arg),
        KVM_GET_VCPU_EVENTS => get_vcpu_blob(control_file, arg, |vcpu| &vcpu.vcpu_events),
        KVM_SET_VCPU_EVENTS => set_vcpu_blob(
            control_file,
            arg,
            KVM_X86_VCPU_EVENTS_SIZE as usize,
            |vcpu, bytes| {
                vcpu.vcpu_events = bytes;
            },
        ),
        KVM_GET_DEBUGREGS => get_kvm_debugregs(control_file, arg),
        KVM_SET_DEBUGREGS => set_kvm_debugregs(control_file, arg),
        KVM_GET_XSAVE | KVM_GET_XSAVE2 => get_vcpu_blob(control_file, arg, |vcpu| &vcpu.xsave),
        KVM_SET_XSAVE => set_vcpu_blob(
            control_file,
            arg,
            KVM_X86_XSAVE_SIZE as usize,
            |vcpu, bytes| {
                vcpu.xsave = bytes;
            },
        ),
        KVM_GET_XCRS => get_vcpu_blob(control_file, arg, |vcpu| &vcpu.xcrs),
        KVM_SET_XCRS => set_vcpu_blob(
            control_file,
            arg,
            KVM_X86_XCRS_SIZE as usize,
            |vcpu, bytes| {
                vcpu.xcrs = bytes;
            },
        ),
        KVM_KVMCLOCK_CTRL => Ok(0),
        KVM_ENABLE_CAP => enable_cap(arg),
        _ => {
            debug!("unsupported KVM vCPU ioctl cmd={cmd:#x} arg={arg:#x}");
            Err(AxError::Unsupported)
        }
    }
}

fn check_extension(capability: usize) -> usize {
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    return match capability {
        KVM_CAP_IRQCHIP
        | KVM_CAP_IRQFD
        | KVM_CAP_DEVICE_CTRL
        | KVM_CAP_ARM_PSCI_0_2
        | KVM_CAP_USER_MEMORY
        | KVM_CAP_IOEVENTFD
        | KVM_CAP_MP_STATE
        | KVM_CAP_ONE_REG
        | KVM_CAP_IMMEDIATE_EXIT
        | KVM_CAP_IOEVENTFD_ANY_LENGTH
        | KVM_CAP_DESTROY_MEMORY_REGION_WORKS
        | KVM_CAP_JOIN_MEMORY_REGIONS_WORKS => 1,
        KVM_CAP_NR_VCPUS | KVM_CAP_MAX_VCPUS => KVM_MAX_VCPUS,
        KVM_CAP_NR_MEMSLOTS => KVM_MAX_MEMORY_SLOTS,
        KVM_CAP_ARM_VM_IPA_SIZE => axvm::arm_ipa_bits(),
        _ => 0,
    };
    #[cfg(not(all(target_arch = "aarch64", feature = "arm-vhe")))]
    match capability {
        KVM_CAP_IRQCHIP => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_USER_MEMORY => 1,
        KVM_CAP_SET_TSS_ADDR => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_EXT_CPUID => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_IOEVENTFD => 1,
        KVM_CAP_NR_VCPUS => KVM_MAX_VCPUS,
        KVM_CAP_MAX_VCPUS => KVM_MAX_VCPUS,
        KVM_CAP_NR_MEMSLOTS => KVM_MAX_MEMORY_SLOTS,
        KVM_CAP_MP_STATE => 1,
        KVM_CAP_DESTROY_MEMORY_REGION_WORKS => 1,
        KVM_CAP_IRQ_ROUTING => usize::from(cfg!(target_arch = "x86_64")) * KVM_MAX_IRQ_ROUTES,
        KVM_CAP_JOIN_MEMORY_REGIONS_WORKS => 1,
        KVM_CAP_MCE => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_IRQFD => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_PIT2 => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_PIT_STATE2 => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_SET_IDENTITY_MAP_ADDR => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_ADJUST_CLOCK => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_INTERNAL_ERROR_DATA => 1,
        KVM_CAP_DEBUGREGS => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_X86_ROBUST_SINGLESTEP => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_VCPU_EVENTS => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_XCRS => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_XSAVE => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_ONE_REG => usize::from(cfg!(target_arch = "riscv64")),
        KVM_CAP_SIGNAL_MSI => usize::from(cfg!(target_arch = "x86_64")),
        KVM_CAP_IOEVENTFD_ANY_LENGTH => 1,
        KVM_CAP_IMMEDIATE_EXIT => 1,
        KVM_CAP_XSAVE2 => 0,
        _ => 0,
    }
}

fn read_enable_cap(arg: usize) -> AxResult<KvmEnableCap> {
    let mut bytes = [0u8; KVM_ENABLE_CAP_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;

    let mut args = [0u64; 4];
    for (index, arg) in args.iter_mut().enumerate() {
        let offset = 8 + index * 8;
        *arg = u64::from_ne_bytes(bytes[offset..offset + 8].try_into().unwrap());
    }

    Ok(KvmEnableCap {
        cap: u32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
        flags: u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        args,
    })
}
