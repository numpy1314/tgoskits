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

use ax_errno::{AxError, AxResult};
use axvcpu::AxVCpuExitReason;
use axvisor_api::control as api_control;
use axvm::AxVMRef;

use super::super::{
    CONTROL_FILES, ControlFileState, prepare_system_event, queue_arm_cpu_on, stop_arm_vcpu,
};
use crate::{
    arch::aarch64::{
        PSCI_INTERNAL_FAILURE, PSCI_INVALID_PARAMS, PSCI_MPIDR_HWID_MASK, PSCI_NOT_SUPPORTED,
        PSCI_SUCCESS, PSCI_VERSION_0_2, PsciCall, decode_psci, psci_affinity_mask,
    },
    kvm::{
        abi::raw as abi,
        util::{
            access_width_mask, control_file_mmap_area, sign_extend_value, write_vcpu_run_u32,
            write_vcpu_run_u64,
        },
    },
    vmm::{
        interrupt::{VcpuInterruptTarget, VirtualInterrupt, deliver_targeted_interrupt},
        vcpus::{guest_cpu_id_for_vcpu, guest_cpu_id_to_vcpu_id},
    },
};

pub(super) enum ArmPsciOutcome {
    Continue,
    SystemEvent { kind: u32 },
}

pub(super) fn apply_pending_arm_reset(
    vcpu: &axvm::AxVCpuRef,
    reset: super::super::state::ArmPendingReset,
) -> AxResult {
    vcpu.manipulate_arch_vcpu(axvcpu::VCpuState::Free, axvcpu::VCpuState::Free, |arch| {
        arch.reset_guest_state(reset.pc, reset.arg, reset.be)
    })
}

pub(super) fn handle_psci_hypercall(
    control_file: api_control::ControlFileId,
    vm: &AxVMRef,
    vcpu: &axvm::AxVCpuRef,
    function: u64,
    args: [u64; 6],
) -> AxResult<Option<ArmPsciOutcome>> {
    let Some(call) = decode_psci(function, args) else {
        return Ok(None);
    };
    let result = match call {
        PsciCall::Version => PSCI_VERSION_0_2 as i64,
        PsciCall::MigrateInfoType => 2,
        PsciCall::CpuOff => {
            stop_arm_vcpu(control_file)?;
            PSCI_SUCCESS
        }
        PsciCall::CpuOn {
            target,
            entry,
            context,
        } => cpu_on(control_file, vm, vcpu, target, entry, context)?,
        PsciCall::AffinityInfo { target, level } => affinity_info(control_file, vm, target, level)?,
        PsciCall::SystemOff | PsciCall::SystemReset => {
            let kind = if call == PsciCall::SystemOff {
                abi::KVM_SYSTEM_EVENT_SHUTDOWN
            } else {
                abi::KVM_SYSTEM_EVENT_RESET
            };
            prepare_system_event(control_file, kind)?;
            // Native KVM preloads an error in case userspace resumes this
            // stopped context without reinitializing the guest.
            vcpu.set_gpr(0, PSCI_INTERNAL_FAILURE as usize);
            let area = control_file_mmap_area(control_file)?;
            api_control::write_mmap_area(
                area,
                abi::KVM_RUN_SYSTEM_EVENT_OFFSET,
                &[0; abi::KVM_RUN_SYSTEM_EVENT_SIZE],
            )?;
            write_vcpu_run_u32(control_file, abi::KVM_RUN_SYSTEM_EVENT_TYPE_OFFSET, kind)?;
            write_vcpu_run_u32(control_file, abi::KVM_RUN_SYSTEM_EVENT_NDATA_OFFSET, 1)?;
            write_vcpu_run_u64(control_file, abi::KVM_RUN_SYSTEM_EVENT_DATA_OFFSET, 0)?;
            return Ok(Some(ArmPsciOutcome::SystemEvent { kind }));
        }
        PsciCall::Unsupported => PSCI_NOT_SUPPORTED,
    };
    vcpu.set_gpr(0, result as usize);
    Ok(Some(ArmPsciOutcome::Continue))
}

fn cpu_on(
    control_file: api_control::ControlFileId,
    vm: &AxVMRef,
    source: &axvm::AxVCpuRef,
    target: u64,
    entry: u64,
    context: u64,
) -> AxResult<i64> {
    if target & !PSCI_MPIDR_HWID_MASK != 0 || entry & 3 != 0 {
        return Ok(PSCI_INVALID_PARAMS);
    }
    let Some(target_id) = guest_cpu_id_to_vcpu_id(vm, target as usize) else {
        return Ok(PSCI_INVALID_PARAMS);
    };
    let be = source.get_arch_reg(kvm_uapi::arm64::KVM_REG_ARM64_SCTLR_EL1)? & (1 << 25) != 0;
    queue_arm_cpu_on(control_file, target_id, entry, context, be)
}

fn affinity_info(
    control_file: api_control::ControlFileId,
    vm: &AxVMRef,
    target: u64,
    level: u64,
) -> AxResult<i64> {
    if target & !PSCI_MPIDR_HWID_MASK != 0 {
        return Ok(PSCI_INVALID_PARAMS);
    }
    let Some(mask) = psci_affinity_mask(level) else {
        return Ok(PSCI_INVALID_PARAMS);
    };
    let files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(source)) = files.get(&control_file) else {
        return Err(AxError::NotFound);
    };
    let Some(ControlFileState::Vm(vm_file)) = files.get(&source.vm_file) else {
        return Err(AxError::NotFound);
    };
    let mut found = false;
    for (&id, file) in &vm_file.vcpu_files {
        if guest_cpu_id_for_vcpu(vm, id as usize) as u64 & mask != target & mask {
            continue;
        }
        let Some(ControlFileState::Vcpu(target)) = files.get(file) else {
            continue;
        };
        found = true;
        if target.mp_state != abi::KVM_MP_STATE_STOPPED {
            return Ok(0);
        }
    }
    Ok(if found { 1 } else { PSCI_INVALID_PARAMS })
}

pub(super) fn handle_cpu_up(
    control_file: axvisor_api::control::ControlFileId,
    vm: &AxVMRef,
    vcpu: &axvm::AxVCpuRef,
    target_cpu: usize,
    entry_point: axaddrspace::GuestPhysAddr,
    arg: u64,
) -> AxResult {
    let result = cpu_on(
        control_file,
        vm,
        vcpu,
        target_cpu as u64,
        entry_point.as_usize() as u64,
        arg,
    )?;
    vcpu.set_return_value(result as usize);
    Ok(())
}

pub(super) fn handle_send_ipi(
    vm: &AxVMRef,
    current_vcpu_id: usize,
    target_cpu: usize,
    target_cpu_aux: usize,
    send_to_all: bool,
    send_to_self: bool,
    vector: usize,
) -> AxResult {
    let target = if send_to_all {
        VcpuInterruptTarget::All {
            current_vcpu_id,
            include_current: send_to_self,
        }
    } else if send_to_self {
        VcpuInterruptTarget::Vcpu(current_vcpu_id)
    } else {
        VcpuInterruptTarget::GuestCpuMask {
            mask: target_cpu_aux,
            base: target_cpu,
        }
    };
    deliver_targeted_interrupt(vm, target, VirtualInterrupt::edge(vector))
}

pub(super) fn handle_in_kernel_device_exit(
    vm: &AxVMRef,
    vcpu: &axvm::AxVCpuRef,
    irqchip_created: bool,
    exit_reason: &AxVCpuExitReason,
) -> AxResult<bool> {
    if !irqchip_created {
        return Ok(false);
    }

    match exit_reason {
        AxVCpuExitReason::MmioRead {
            addr,
            width,
            reg,
            reg_width,
            signed_ext,
        } if vm.get_devices().find_mmio_dev(*addr).is_some() => {
            let raw = vm.get_devices().handle_mmio_read(*addr, *width)?;
            let masked = raw & access_width_mask(*width);
            let value = if *signed_ext {
                sign_extend_value(masked, *width)
            } else {
                masked & access_width_mask(*reg_width)
            };
            vcpu.set_gpr(*reg, value);
            Ok(true)
        }
        AxVCpuExitReason::MmioWrite { addr, width, data }
            if vm.get_devices().find_mmio_dev(*addr).is_some() =>
        {
            vm.get_devices()
                .handle_mmio_write(*addr, *width, *data as usize)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}
