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

use ax_errno::{AxErrorKind, AxResult, ax_err};
use axvcpu::AxVCpuExitReason;
use axvisor_api::control as api_control;
#[cfg(target_arch = "aarch64")]
mod arm64;
mod exit;
#[cfg(target_arch = "riscv64")]
mod riscv;
mod x86;

#[cfg(target_arch = "aarch64")]
use arm64::{
    ArmPsciOutcome, handle_cpu_up, handle_in_kernel_device_exit, handle_psci_hypercall,
    handle_send_ipi,
};
use exit::{complete_io_read, complete_mmio_read, kvm_exit_reason, prepare_userspace_exit};
#[cfg(target_arch = "riscv64")]
use riscv::{handle_cpu_up, handle_send_ipi};
#[cfg(target_arch = "x86_64")]
pub(in crate::kvm) use x86::apply_kvm_pv_msr_write;
#[cfg(target_arch = "x86_64")]
use x86::{
    handle_control_ioapic_eoi, handle_cpu_up, handle_in_kernel_device_exit, handle_kvm_msr_write,
    inject_in_kernel_device_irqs,
};
use x86::{update_vcpu_run_interrupt_state, vcpu_run_irq_window_open};

use super::{CONTROL_FILES, ControlFileState, take_control_vcpu_interrupts};
#[cfg(target_arch = "x86_64")]
use crate::kvm::eventfd::is_userspace_eoi_vector;
#[cfg(target_arch = "x86_64")]
use crate::kvm::memory::handle_memory_slot_page_fault;
use crate::{
    kvm::{
        abi::raw as abi,
        eventfd::signal_matching_ioeventfd,
        util::{read_vcpu_run_u8, write_vcpu_run_u32},
    },
    vmm::interrupt::inject_virtual_interrupt,
};

pub(in crate::kvm) fn run_vcpu_file(control_file: api_control::ControlFileId) -> AxResult<isize> {
    let (
        vm,
        vm_file,
        vcpu_id,
        vcpu,
        mp_state,
        pending_mmio_read,
        pending_io_read,
        signal_mask,
        irqchip_created,
        pit2_created,
    ) = {
        let mut control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vcpu(vcpu)) = control_files.get(&control_file) else {
            return ax_err!(NotFound);
        };
        let Some(ControlFileState::Vm(vm)) = control_files.get(&vcpu.vm_file) else {
            return ax_err!(NotFound);
        };
        let irqchip_created = vm.irqchip_created;
        let pit2_created = vm.pit2_created;
        let vm = vm.vm.clone();
        let vm_file = vcpu.vm_file;
        let vcpu_id = vcpu.vcpu_id as usize;
        let mp_state = vcpu.mp_state;
        let pending_mmio_read = vcpu.pending_mmio_read;
        let pending_io_read = vcpu.pending_io_read;
        let signal_mask = vcpu.signal_mask.clone();
        let Some(ControlFileState::Vcpu(vcpu_file_state)) = control_files.get_mut(&control_file)
        else {
            return ax_err!(NotFound);
        };
        vcpu_file_state.pending_mmio_read = None;
        vcpu_file_state.pending_io_read = None;
        let Some(vcpu) = vm.vcpu(vcpu_id) else {
            return ax_err!(NotFound);
        };
        (
            vm,
            vm_file,
            vcpu_id,
            vcpu,
            mp_state,
            pending_mmio_read,
            pending_io_read,
            signal_mask,
            irqchip_created,
            pit2_created,
        )
    };
    #[cfg(not(target_arch = "x86_64"))]
    let _ = (vm_file, irqchip_created, pit2_created);

    let _context_guard = crate::context::bind_current_vcpu_context(vm.id(), vcpu_id);
    #[cfg(target_arch = "aarch64")]
    let arm_run_state = {
        let files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vcpu(state)) = files.get(&control_file) else {
            return ax_err!(NotFound);
        };
        state.arm_run_state.clone()
    };

    // `exit_reason` is only meaningful when KVM_RUN returns successfully. Do
    // not leave a previous userspace exit visible when this invocation is
    // interrupted or otherwise returns before entering the guest.
    write_vcpu_run_u32(
        control_file,
        abi::KVM_RUN_EXIT_REASON_OFFSET,
        abi::KVM_EXIT_UNKNOWN,
    )?;

    if mp_state != abi::KVM_MP_STATE_RUNNABLE {
        wait_until_vcpu_runnable(control_file, &vcpu, &signal_mask)?;
    }

    if !vm.running() {
        let boot_result = vm.boot();
        // Multiple userspace-managed vCPUs may issue their first KVM_RUN
        // concurrently. Another vCPU completing boot makes this call
        // successful even if our racing boot attempt observed Running.
        if !vm.running() {
            boot_result?;
        }
    }

    if let Some(pending) = pending_mmio_read {
        complete_mmio_read(control_file, &vcpu, pending)?;
    }
    if let Some(pending) = pending_io_read {
        complete_io_read(control_file, &vm, &vcpu, pending)?;
    }

    if read_vcpu_run_u8(control_file, abi::KVM_RUN_IMMEDIATE_EXIT_OFFSET)? != 0 {
        update_vcpu_run_interrupt_state(control_file, &vcpu)?;
        return Err(AxErrorKind::Interrupted.into());
    }

    let exit_reason = loop {
        // VM shutdown may be initiated by closing the VM fd while a vCPU fd
        // is still open.  Stop KVM_RUN promptly so the last AxVM reference is
        // released before a subsequent VM is created.
        if vm.stopping() || vm.stopped() {
            update_vcpu_run_interrupt_state(control_file, &vcpu)?;
            return Err(AxErrorKind::Interrupted.into());
        }
        if current_vcpu_mp_state(control_file)? != abi::KVM_MP_STATE_RUNNABLE {
            wait_until_vcpu_runnable(control_file, &vcpu, &signal_mask)?;
        }
        #[cfg(target_arch = "aarch64")]
        apply_pending_arm_reset(control_file, &vcpu)?;
        for interrupt in take_control_vcpu_interrupts(control_file) {
            inject_virtual_interrupt(interrupt, &vcpu)?;
        }
        if vcpu_run_interrupted(control_file, &signal_mask)? {
            update_vcpu_run_interrupt_state(control_file, &vcpu)?;
            return Err(AxErrorKind::Interrupted.into());
        }
        if vcpu_run_irq_window_open(control_file, &vcpu)? {
            break abi::KVM_EXIT_IRQ_WINDOW_OPEN;
        }

        #[cfg(target_arch = "aarch64")]
        let run_result = vm.run_vcpu_raw_control(
            vcpu_id,
            |_, _| Ok(false),
            || arm_run_state.enter(),
            || arm_run_state.leave(),
        );
        #[cfg(not(target_arch = "aarch64"))]
        let run_result = vm.run_vcpu_raw(vcpu_id, |addr, access_flags| {
            #[cfg(target_arch = "x86_64")]
            {
                handle_memory_slot_page_fault(vm_file, addr, access_flags)
            }
            #[cfg(not(target_arch = "x86_64"))]
            {
                let _ = (addr, access_flags);
                Ok(false)
            }
        });
        let exit_reason = match run_result {
            Ok(exit_reason) => exit_reason,
            Err(_) => {
                write_vcpu_run_u32(
                    control_file,
                    abi::KVM_RUN_INTERNAL_SUBERROR_OFFSET,
                    abi::KVM_INTERNAL_ERROR_EMULATION,
                )?;
                write_vcpu_run_u32(control_file, abi::KVM_RUN_INTERNAL_NDATA_OFFSET, 0)?;
                break abi::KVM_EXIT_INTERNAL_ERROR;
            }
        };

        #[cfg(target_arch = "x86_64")]
        if handle_in_kernel_device_exit(&vm, &vcpu, irqchip_created, pit2_created, &exit_reason)? {
            continue;
        }
        #[cfg(target_arch = "aarch64")]
        if handle_in_kernel_device_exit(&vm, &vcpu, irqchip_created, &exit_reason)? {
            continue;
        }

        match exit_reason {
            AxVCpuExitReason::Nothing => {}
            AxVCpuExitReason::PreemptionTimer
            | AxVCpuExitReason::ExternalInterrupt { .. }
            | AxVCpuExitReason::InterruptEnd { .. } => {
                crate::vmm::vcpus::handle_internal_exit(&vm, &vcpu, &exit_reason);
                #[cfg(target_arch = "x86_64")]
                {
                    if let AxVCpuExitReason::InterruptEnd { vector } = exit_reason {
                        handle_control_ioapic_eoi(&vm, &vcpu, irqchip_created, vector);
                        if let Some(vector) = vector
                            && is_userspace_eoi_vector(vm_file, vector)
                        {
                            crate::kvm::util::write_vcpu_run_u8(
                                control_file,
                                abi::KVM_RUN_IOAPIC_EOI_VECTOR_OFFSET,
                                vector,
                            )?;
                            break abi::KVM_EXIT_IOAPIC_EOI;
                        }
                    }
                    inject_in_kernel_device_irqs(&vm, &vcpu, irqchip_created, pit2_created);
                }
                axvisor_api::task::yield_now();
            }
            #[cfg(target_arch = "x86_64")]
            AxVCpuExitReason::Halt if irqchip_created => wait_for_halted_vcpu_wakeup(
                control_file,
                &vm,
                &vcpu,
                irqchip_created,
                pit2_created,
                &signal_mask,
            )?,
            AxVCpuExitReason::MmioWrite { addr, width, data }
                if signal_matching_ioeventfd(
                    control_file,
                    addr.as_usize() as u64,
                    width,
                    data,
                    false,
                )? => {}
            AxVCpuExitReason::IoWrite { port, width, data }
                if signal_matching_ioeventfd(
                    control_file,
                    port.number() as u64,
                    width,
                    data,
                    true,
                )? => {}
            #[cfg(target_arch = "x86_64")]
            AxVCpuExitReason::Hypercall {
                nr: abi::KVM_HC_CLOCK_PAIRING,
                ..
            } => {
                vcpu.set_gpr(abi::X86_RAX_REG_INDEX, (-abi::KVM_ENOSYS) as usize);
                axvisor_api::task::yield_now();
            }
            #[cfg(target_arch = "aarch64")]
            AxVCpuExitReason::Hypercall { nr, args } => {
                match handle_psci_hypercall(control_file, &vm, &vcpu, nr, args)? {
                    Some(ArmPsciOutcome::Continue) => {}
                    Some(ArmPsciOutcome::SystemEvent { kind }) => {
                        debug_assert!(
                            kind == abi::KVM_SYSTEM_EVENT_SHUTDOWN
                                || kind == abi::KVM_SYSTEM_EVENT_RESET
                        );
                        break abi::KVM_EXIT_SYSTEM_EVENT;
                    }
                    None => {
                        let reason = AxVCpuExitReason::Hypercall { nr, args };
                        prepare_userspace_exit(control_file, &reason)?;
                        break kvm_exit_reason(&reason);
                    }
                }
            }
            #[cfg(target_arch = "aarch64")]
            AxVCpuExitReason::CpuUp {
                target_cpu,
                entry_point,
                arg,
            } => {
                handle_cpu_up(
                    control_file,
                    &vm,
                    &vcpu,
                    target_cpu as usize,
                    entry_point,
                    arg,
                )?;
                axvisor_api::task::yield_now();
            }
            #[cfg(target_arch = "x86_64")]
            AxVCpuExitReason::SysRegWrite { addr, value }
                if handle_kvm_msr_write(&vm, &vcpu, addr.addr(), value)? =>
            {
                super::set_emulated_msr(control_file, addr.addr() as u32, value)?;
                axvisor_api::task::yield_now();
            }
            #[cfg(target_arch = "x86_64")]
            AxVCpuExitReason::CpuUp {
                target_cpu,
                entry_point,
                ..
            } => {
                handle_cpu_up(control_file, &vm, target_cpu as usize, entry_point)?;
                axvisor_api::task::yield_now();
            }
            #[cfg(target_arch = "riscv64")]
            AxVCpuExitReason::CpuUp {
                target_cpu,
                entry_point,
                arg,
            } => {
                handle_cpu_up(
                    control_file,
                    &vm,
                    &vcpu,
                    target_cpu as usize,
                    entry_point,
                    arg,
                )?;
                axvisor_api::task::yield_now();
            }
            #[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
            AxVCpuExitReason::SendIPI {
                target_cpu,
                target_cpu_aux,
                send_to_all,
                send_to_self,
                vector,
            } => {
                handle_send_ipi(
                    &vm,
                    vcpu_id,
                    target_cpu as usize,
                    target_cpu_aux as usize,
                    send_to_all,
                    send_to_self,
                    vector as usize,
                )?;
                axvisor_api::task::yield_now();
            }
            exit_reason => {
                let kvm_reason = kvm_exit_reason(&exit_reason);
                prepare_userspace_exit(control_file, &exit_reason)?;
                break kvm_reason;
            }
        }
    };
    update_vcpu_run_interrupt_state(control_file, &vcpu)?;
    write_vcpu_run_u32(control_file, abi::KVM_RUN_EXIT_REASON_OFFSET, exit_reason)?;
    Ok(0)
}

fn wait_until_vcpu_runnable(
    control_file: api_control::ControlFileId,
    vcpu: &axvm::AxVCpuRef,
    signal_mask: &[u8],
) -> AxResult {
    loop {
        if vcpu_run_interrupted(control_file, signal_mask)? {
            return Err(AxErrorKind::Interrupted.into());
        }
        #[cfg(all(target_arch = "x86_64", feature = "vmx"))]
        {
            if let Some(entry_point) = take_current_vcpu_startup(control_file)? {
                vcpu.set_entry(entry_point)?;
                set_current_vcpu_mp_state(control_file, abi::KVM_MP_STATE_RUNNABLE)?;
            }
        }
        #[cfg(not(all(target_arch = "x86_64", feature = "vmx")))]
        let _ = vcpu;
        if current_vcpu_mp_state(control_file)? == abi::KVM_MP_STATE_RUNNABLE {
            return Ok(());
        }
        #[cfg(target_arch = "aarch64")]
        {
            let run_state = {
                let files = CONTROL_FILES.lock();
                let Some(ControlFileState::Vcpu(state)) = files.get(&control_file) else {
                    return ax_err!(NotFound);
                };
                state.arm_run_state.clone()
            };
            api_control::wait_control_until(
                run_state.wait_queue.as_raw(),
                alloc::boxed::Box::new(move || match current_vcpu_mp_state(control_file) {
                    Ok(state) => state == abi::KVM_MP_STATE_RUNNABLE,
                    Err(_) => true,
                }),
                signal_mask,
            )?;
        }
        #[cfg(not(target_arch = "aarch64"))]
        axvisor_api::task::yield_now();
    }
}

#[cfg(target_arch = "aarch64")]
pub(in crate::kvm) fn apply_pending_arm_reset(
    control_file: api_control::ControlFileId,
    vcpu: &axvm::AxVCpuRef,
) -> AxResult {
    let reset = {
        let mut files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vcpu(state)) = files.get_mut(&control_file) else {
            return ax_err!(NotFound);
        };
        state.pending_arm_reset.take()
    };
    if let Some(reset) = reset {
        // Entry stays blocked while the target's operation-lock owner restores
        // the architectural reset state, without holding CONTROL_FILES.
        let result = arm64::apply_pending_arm_reset(vcpu, reset);
        let mut files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vcpu(state)) = files.get_mut(&control_file) else {
            return ax_err!(NotFound);
        };
        if result.is_ok() {
            // Reset disables both guest timers. Remove stale timer assertions
            // while retaining unrelated device and interprocessor interrupts.
            state
                .pending_interrupts
                .retain(|irq| !matches!(irq.vector, 27 | 30));
            state.pending_mmio_read = None;
            state.pending_io_read = None;
        } else if state.pending_arm_reset.is_none() {
            // Invalid startup state must not leave RUNNABLE permanently
            // spinning at a closed entry gate. A failed architectural reset
            // invalidates this vCPU, so userspace must recreate it.
            state.mp_state = abi::KVM_MP_STATE_STOPPED;
        }
        state.arm_run_state.entry_blocked.store(
            state.mp_state != abi::KVM_MP_STATE_RUNNABLE || state.pending_arm_reset.is_some(),
            core::sync::atomic::Ordering::SeqCst,
        );
        result?;
    }
    Ok(())
}

#[cfg(all(target_arch = "x86_64", feature = "vmx"))]
fn take_current_vcpu_startup(
    control_file: api_control::ControlFileId,
) -> AxResult<Option<axaddrspace::GuestPhysAddr>> {
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    Ok(vcpu.pending_startup_entry.take())
}

#[cfg(all(target_arch = "x86_64", feature = "vmx"))]
fn set_current_vcpu_mp_state(control_file: api_control::ControlFileId, mp_state: u32) -> AxResult {
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vcpu.mp_state = mp_state;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn wait_for_halted_vcpu_wakeup(
    control_file: api_control::ControlFileId,
    vm: &axvm::AxVMRef,
    vcpu: &axvm::AxVCpuRef,
    irqchip_created: bool,
    pit2_created: bool,
    signal_mask: &[u8],
) -> AxResult {
    set_current_vcpu_halted(control_file, true)?;
    loop {
        if vcpu_run_interrupted(control_file, signal_mask)? {
            set_current_vcpu_halted(control_file, false)?;
            return Err(AxErrorKind::Interrupted.into());
        }
        crate::vmm::timer::check_events();
        if current_vcpu_has_pending_interrupt(control_file)? || vcpu.has_pending_event() {
            set_current_vcpu_halted(control_file, false)?;
            return Ok(());
        }
        if !current_vcpu_halted(control_file)? {
            return Ok(());
        }
        if inject_in_kernel_device_irqs(vm, vcpu, irqchip_created, pit2_created) {
            set_current_vcpu_halted(control_file, false)?;
            return Ok(());
        }
        axvisor_api::task::yield_now();
    }
}

fn vcpu_run_interrupted(
    control_file: api_control::ControlFileId,
    signal_mask: &[u8],
) -> AxResult<bool> {
    if read_vcpu_run_u8(control_file, abi::KVM_RUN_IMMEDIATE_EXIT_OFFSET)? != 0 {
        return Ok(true);
    }
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    {
        api_control::current_thread_has_pending_signal(signal_mask)
    }
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    {
        let _ = signal_mask;
        Ok(false)
    }
}

fn current_vcpu_mp_state(control_file: api_control::ControlFileId) -> AxResult<u32> {
    let control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get(&control_file) else {
        return ax_err!(NotFound);
    };
    Ok(vcpu.mp_state)
}

#[cfg(target_arch = "x86_64")]
fn set_current_vcpu_halted(control_file: api_control::ControlFileId, halted: bool) -> AxResult {
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vcpu.halted = halted;
    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn current_vcpu_halted(control_file: api_control::ControlFileId) -> AxResult<bool> {
    let control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get(&control_file) else {
        return ax_err!(NotFound);
    };
    Ok(vcpu.halted)
}

#[cfg(target_arch = "x86_64")]
fn current_vcpu_has_pending_interrupt(control_file: api_control::ControlFileId) -> AxResult<bool> {
    let control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get(&control_file) else {
        return ax_err!(NotFound);
    };
    Ok(!vcpu.pending_interrupts.is_empty())
}
