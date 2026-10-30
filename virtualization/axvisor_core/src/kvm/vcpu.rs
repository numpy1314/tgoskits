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

use alloc::{vec, vec::Vec};

use ax_errno::{AxError, AxResult, ax_err};
use axvisor_api::control as api_control;

use super::{CONTROL_FILES, ControlFileState, OneReg, VcpuFileState};
#[cfg(target_arch = "x86_64")]
use crate::kvm::run::apply_kvm_pv_msr_write;
use crate::{
    kvm::{
        abi::raw as abi,
        util::{checked_add, read_u32_user, read_u64_user, write_u32_user, write_u64_user},
    },
    vmm::interrupt::VirtualInterrupt,
};

pub(in crate::kvm) fn get_msr_index_list(arg: usize) -> AxResult<isize> {
    let requested = read_u32_user(arg)? as usize;
    write_u32_user(arg, abi::SUPPORTED_X86_MSRS.len() as u32)?;
    if requested < abi::SUPPORTED_X86_MSRS.len() {
        return ax_err!(ArgumentListTooLong);
    }

    let mut offset = checked_add(arg, abi::KVM_MSR_LIST_SIZE as usize)?;
    for msr in abi::SUPPORTED_X86_MSRS {
        write_u32_user(offset, *msr)?;
        offset = checked_add(offset, 4)?;
    }
    Ok(0)
}

pub(in crate::kvm) fn get_vcpu_blob<F>(
    control_file: api_control::ControlFileId,
    arg: usize,
    get: F,
) -> AxResult<isize>
where
    F: FnOnce(&VcpuFileState) -> &Vec<u8>,
{
    let bytes = {
        let control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vcpu(vcpu)) = control_files.get(&control_file) else {
            return ax_err!(NotFound);
        };
        get(vcpu).clone()
    };
    api_control::copy_to_user(arg, &bytes)?;
    Ok(0)
}

pub(in crate::kvm) fn set_vcpu_blob<F>(
    control_file: api_control::ControlFileId,
    arg: usize,
    len: usize,
    set: F,
) -> AxResult<isize>
where
    F: FnOnce(&mut VcpuFileState, Vec<u8>),
{
    let mut bytes = vec![0u8; len];
    api_control::copy_from_user(arg, &mut bytes)?;

    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    set(vcpu, bytes);
    Ok(0)
}

pub(in crate::kvm) fn set_signal_mask(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let len = read_u32_user(arg)? as usize;
    if len > abi::KVM_SIGNAL_MASK_MAX_LEN {
        return ax_err!(InvalidInput);
    }
    let mut signal_mask = vec![0u8; len];
    if len != 0 {
        api_control::copy_from_user(
            checked_add(arg, abi::KVM_SIGNAL_MASK_SIZE as usize)?,
            &mut signal_mask,
        )?;
    }

    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vcpu.signal_mask = signal_mask;
    Ok(0)
}

pub(in crate::kvm) fn get_mp_state(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get(&control_file) else {
        return ax_err!(NotFound);
    };
    write_u32_user(arg, vcpu.mp_state)?;
    Ok(0)
}

pub(in crate::kvm) fn set_mp_state(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let mp_state = read_u32_user(arg)?;
    #[cfg(target_arch = "aarch64")]
    {
        if !matches!(
            mp_state,
            abi::KVM_MP_STATE_RUNNABLE | abi::KVM_MP_STATE_STOPPED
        ) {
            return ax_err!(Unsupported);
        }
        super::set_arm_vcpu_mp_state(control_file, mp_state)?;
        Ok(0)
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        if mp_state > abi::KVM_MP_STATE_SUSPENDED {
            return ax_err!(Unsupported);
        }

        let mut control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
            return ax_err!(NotFound);
        };
        vcpu.mp_state = mp_state;
        if mp_state == abi::KVM_MP_STATE_RUNNABLE {
            vcpu.halted = false;
        }
        Ok(0)
    }
}

pub(in crate::kvm) fn get_one_reg(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let one_reg = read_one_reg(arg)?;
    let vcpu = get_vcpu(control_file)?;
    #[cfg(target_arch = "aarch64")]
    super::run::apply_pending_arm_reset(control_file, &vcpu)?;
    #[cfg(target_arch = "aarch64")]
    if one_reg.id == kvm_uapi::arm64::KVM_REG_ARM_PSCI_VERSION {
        write_u64_user(
            one_reg.addr as usize,
            crate::arch::aarch64::PSCI_VERSION_0_2,
        )?;
        return Ok(0);
    }
    let value = vcpu.get_arch_reg(one_reg.id)?;
    write_u64_user(one_reg.addr as usize, value)?;
    Ok(0)
}

pub(in crate::kvm) fn set_one_reg(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let one_reg = read_one_reg(arg)?;
    let vcpu = get_vcpu(control_file)?;
    #[cfg(target_arch = "aarch64")]
    super::run::apply_pending_arm_reset(control_file, &vcpu)?;
    let value = read_u64_user(one_reg.addr as usize)?;
    #[cfg(target_arch = "aarch64")]
    if one_reg.id == kvm_uapi::arm64::KVM_REG_ARM_PSCI_VERSION {
        return if value == crate::arch::aarch64::PSCI_VERSION_0_2 {
            Ok(0)
        } else {
            ax_err!(InvalidInput)
        };
    }
    vcpu.set_arch_reg(one_reg.id, value)?;
    Ok(0)
}

#[cfg(target_arch = "aarch64")]
pub(in crate::kvm) fn arm_vcpu_init(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    use kvm_uapi::arm64::{
        KVM_ARM_TARGET_GENERIC_V8, KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2,
    };

    let mut bytes = [0u8; abi::KVM_ARM_VCPU_INIT_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;
    let target = u32::from_ne_bytes(bytes[..4].try_into().unwrap());
    let mut features = [0u32; 7];
    for (index, feature) in features.iter_mut().enumerate() {
        let offset = 4 + index * 4;
        *feature = u32::from_ne_bytes(bytes[offset..offset + 4].try_into().unwrap());
    }

    let supported_features = (1u32 << KVM_ARM_VCPU_POWER_OFF) | (1u32 << KVM_ARM_VCPU_PSCI_0_2);
    if target != KVM_ARM_TARGET_GENERIC_V8
        || features[0] & !supported_features != 0
        || features[0] & (1u32 << KVM_ARM_VCPU_PSCI_0_2) == 0
        || features[1..].iter().any(|feature| *feature != 0)
    {
        return ax_err!(Unsupported);
    }

    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    if vcpu.initialized {
        // Repeated INIT requires architectural/cache reset support. Do not
        // claim that clearing this boolean implements the native operation.
        return ax_err!(BadState);
    }
    drop(control_files);
    let mp_state = if features[0] & (1u32 << KVM_ARM_VCPU_POWER_OFF) != 0 {
        abi::KVM_MP_STATE_STOPPED
    } else {
        abi::KVM_MP_STATE_RUNNABLE
    };
    super::set_arm_vcpu_mp_state(control_file, mp_state)?;
    // INIT owns this vCPU's operation lock, so KVM_RUN cannot observe this
    // intermediate state. Publish initialized after the power-state change;
    // a concurrent system stop after that change must remain STOPPED.
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vcpu.initialized = true;
    Ok(0)
}

pub(in crate::kvm) fn get_reg_list(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let vcpu = get_vcpu(control_file)?;
    let reg_ids = vcpu.arch_reg_ids();
    #[cfg(target_arch = "aarch64")]
    let arm_reg_ids = {
        let mut ids = reg_ids.to_vec();
        ids.push(kvm_uapi::arm64::KVM_REG_ARM_PSCI_VERSION);
        ids
    };
    #[cfg(target_arch = "aarch64")]
    let reg_ids = arm_reg_ids.as_slice();
    let requested = read_u64_user(arg)? as usize;
    write_u64_user(arg, reg_ids.len() as u64)?;
    if requested < reg_ids.len() {
        return ax_err!(ArgumentListTooLong);
    }

    let mut offset = arg.checked_add(8).ok_or(AxError::InvalidInput)?;
    for reg_id in reg_ids {
        write_u64_user(offset, *reg_id)?;
        offset = offset.checked_add(8).ok_or(AxError::InvalidInput)?;
    }
    Ok(0)
}

pub(in crate::kvm) fn get_kvm_regs(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let mut bytes = [0u8; abi::KVM_X86_REGS_SIZE as usize];
    get_vcpu(control_file)?.get_kvm_regs(&mut bytes)?;
    api_control::copy_to_user(arg, &bytes)?;
    Ok(0)
}

pub(in crate::kvm) fn set_kvm_regs(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let mut bytes = [0u8; abi::KVM_X86_REGS_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;
    get_vcpu(control_file)?.set_kvm_regs(&bytes)?;
    Ok(0)
}

pub(in crate::kvm) fn get_kvm_sregs(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let mut bytes = [0u8; abi::KVM_X86_SREGS_SIZE as usize];
    get_vcpu(control_file)?.get_kvm_sregs(&mut bytes)?;
    api_control::copy_to_user(arg, &bytes)?;
    Ok(0)
}

pub(in crate::kvm) fn set_kvm_sregs(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let mut bytes = [0u8; abi::KVM_X86_SREGS_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;
    get_vcpu(control_file)?.set_kvm_sregs(&bytes)?;
    Ok(0)
}

pub(in crate::kvm) fn get_kvm_debugregs(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let mut bytes = [0; abi::KVM_X86_DEBUGREGS_SIZE as usize];
    get_vcpu(control_file)?.get_kvm_debugregs(&mut bytes)?;
    api_control::copy_to_user(arg, &bytes)?;
    Ok(0)
}

pub(in crate::kvm) fn set_kvm_debugregs(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let mut bytes = [0; abi::KVM_X86_DEBUGREGS_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;
    get_vcpu(control_file)?.set_kvm_debugregs(&bytes)?;
    Ok(0)
}

pub(in crate::kvm) fn set_msrs(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let nmsrs = read_u32_user(arg)? as usize;
    if nmsrs > abi::KVM_MAX_MSR_ENTRIES {
        return ax_err!(InvalidInput);
    }
    let entries_offset = checked_add(arg, abi::KVM_MSRS_SIZE as usize)?;
    let mut entries = Vec::with_capacity(nmsrs);
    for index in 0..nmsrs {
        let offset = checked_add(entries_offset, index * abi::KVM_MSR_ENTRY_SIZE)?;
        let msr_index = read_u32_user(offset)?;
        let data = read_u64_user(checked_add(offset, 8)?)?;
        entries.push((msr_index, data));
    }

    let vcpu = get_vcpu(control_file)?;
    #[cfg(target_arch = "x86_64")]
    let vm = get_vcpu_vm(control_file)?;
    let mut processed = 0;
    for (index, data) in entries {
        #[cfg(target_arch = "x86_64")]
        if is_kvm_pv_msr(index) {
            apply_kvm_pv_msr_write(&vm, &vcpu, index as usize, data)?;
            set_emulated_msr(control_file, index, data)?;
            processed += 1;
            continue;
        }
        #[cfg(target_arch = "x86_64")]
        if is_mtrr_msr(index) {
            set_emulated_msr(control_file, index, data)?;
            processed += 1;
            continue;
        }
        match vcpu.set_kvm_msr(index, data) {
            Ok(()) => processed += 1,
            Err(AxError::Unsupported) => {
                crate::println!("KVM_SET_MSRS stopped at unsupported MSR {index:#x}");
                break;
            }
            Err(err) => return Err(err),
        }
    }
    Ok(processed)
}

pub(in crate::kvm) fn get_msrs(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let nmsrs = read_u32_user(arg)? as usize;
    if nmsrs > abi::KVM_MAX_MSR_ENTRIES {
        return ax_err!(InvalidInput);
    }
    let entries_offset = checked_add(arg, abi::KVM_MSRS_SIZE as usize)?;
    let vcpu = get_vcpu(control_file)?;

    let mut processed = 0;
    for index in 0..nmsrs {
        let offset = checked_add(entries_offset, index * abi::KVM_MSR_ENTRY_SIZE)?;
        let msr_index = read_u32_user(offset)?;
        let data = if is_emulated_msr(msr_index) {
            get_emulated_msr(control_file, msr_index)?
        } else {
            match vcpu.get_kvm_msr(msr_index) {
                Ok(data) => data,
                Err(AxError::Unsupported) => break,
                Err(err) => return Err(err),
            }
        };
        write_u64_user(checked_add(offset, 8)?, data)?;
        processed += 1;
    }
    Ok(processed as isize)
}

pub(in crate::kvm) fn set_fpu(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let mut bytes = vec![0u8; abi::KVM_X86_FPU_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vcpu.fpu = bytes;
    Ok(0)
}

pub(in crate::kvm) fn get_lapic(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let mut lapic = [0u8; abi::KVM_X86_LAPIC_STATE_SIZE as usize];
    get_vcpu(control_file)?.get_kvm_lapic(&mut lapic)?;
    api_control::copy_to_user(arg, &lapic)?;
    Ok(0)
}

pub(in crate::kvm) fn set_lapic(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let mut bytes = [0u8; abi::KVM_X86_LAPIC_STATE_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;
    get_vcpu(control_file)?.set_kvm_lapic(&bytes)?;
    Ok(0)
}

pub(in crate::kvm) fn set_vapic_addr(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let vapic_addr = read_u64_user(arg)?;
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vcpu.vapic_addr = Some(vapic_addr);
    Ok(0)
}

pub(in crate::kvm) fn kvm_interrupt(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let irq = read_u32_user(arg)?;
    let interrupt = match irq {
        #[cfg(target_arch = "riscv64")]
        abi::KVM_INTERRUPT_SET => VirtualInterrupt::edge(abi::RISCV_S_EXT_VECTOR),
        #[cfg(not(target_arch = "riscv64"))]
        abi::KVM_INTERRUPT_SET => VirtualInterrupt::edge(1),
        #[cfg(target_arch = "riscv64")]
        abi::KVM_INTERRUPT_UNSET => VirtualInterrupt::deassert(abi::RISCV_S_EXT_VECTOR),
        #[cfg(not(target_arch = "riscv64"))]
        abi::KVM_INTERRUPT_UNSET => VirtualInterrupt::deassert(1),
        // The x86 KVM ABI carries an 8-bit interrupt vector here. gVisor uses
        // ordinary vectors for its bounce interrupt; preserve the historical
        // SET/UNSET encodings above while accepting the complete x86 range.
        #[cfg(not(target_arch = "riscv64"))]
        irq if irq < 256 => VirtualInterrupt::edge(irq as usize),
        _ => return ax_err!(Unsupported),
    };
    crate::vmm::interrupt::inject_virtual_interrupt(interrupt, &get_vcpu(control_file)?)?;
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vcpu.halted = false;
    Ok(0)
}

pub(in crate::kvm) fn default_fpu() -> Vec<u8> {
    let mut fpu = vec![0; abi::KVM_X86_FPU_SIZE as usize];
    fpu[128..130].copy_from_slice(&0x37fu16.to_ne_bytes());
    fpu[408..412].copy_from_slice(&0x1f80u32.to_ne_bytes());
    fpu
}

pub(in crate::kvm) fn default_xcrs() -> Vec<u8> {
    let mut xcrs = vec![0; abi::KVM_X86_XCRS_SIZE as usize];
    xcrs[0..4].copy_from_slice(&1u32.to_ne_bytes());
    xcrs[8..12].copy_from_slice(&0u32.to_ne_bytes());
    xcrs[16..24].copy_from_slice(&1u64.to_ne_bytes());
    xcrs
}

pub(in crate::kvm) fn get_vcpu(
    control_file: api_control::ControlFileId,
) -> AxResult<axvm::AxVCpuRef> {
    let (vm, vcpu_id) = {
        let control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vcpu(vcpu)) = control_files.get(&control_file) else {
            return ax_err!(NotFound);
        };
        let Some(ControlFileState::Vm(vm)) = control_files.get(&vcpu.vm_file) else {
            return ax_err!(NotFound);
        };
        (vm.vm.clone(), vcpu.vcpu_id as usize)
    };

    vm.vcpu(vcpu_id).ok_or(AxError::InvalidInput)
}

#[cfg(target_arch = "x86_64")]
fn get_vcpu_vm(control_file: api_control::ControlFileId) -> AxResult<axvm::AxVMRef> {
    let control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get(&control_file) else {
        return ax_err!(NotFound);
    };
    let Some(ControlFileState::Vm(vm)) = control_files.get(&vcpu.vm_file) else {
        return ax_err!(NotFound);
    };
    Ok(vm.vm.clone())
}

#[cfg(target_arch = "x86_64")]
pub(in crate::kvm) fn is_kvm_pv_msr(index: u32) -> bool {
    matches!(
        index as usize,
        abi::MSR_KVM_WALL_CLOCK
            | abi::MSR_KVM_SYSTEM_TIME
            | abi::MSR_KVM_WALL_CLOCK_NEW
            | abi::MSR_KVM_SYSTEM_TIME_NEW
    )
}

#[cfg(not(target_arch = "x86_64"))]
pub(in crate::kvm) fn is_kvm_pv_msr(_index: u32) -> bool {
    false
}

#[cfg(target_arch = "x86_64")]
fn is_mtrr_msr(index: u32) -> bool {
    matches!(index, 0x200..=0x20f | 0x250 | 0x258..=0x259 | 0x268..=0x26f | 0x2ff)
}

#[cfg(not(target_arch = "x86_64"))]
fn is_mtrr_msr(_index: u32) -> bool {
    false
}

fn is_emulated_msr(index: u32) -> bool {
    is_kvm_pv_msr(index) || is_mtrr_msr(index)
}

#[cfg(target_arch = "x86_64")]
pub(in crate::kvm) fn set_emulated_msr(
    control_file: api_control::ControlFileId,
    index: u32,
    value: u64,
) -> AxResult {
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vcpu.emulated_msrs.insert(index, value);
    Ok(())
}

fn get_emulated_msr(control_file: api_control::ControlFileId, index: u32) -> AxResult<u64> {
    let control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.get(&control_file) else {
        return ax_err!(NotFound);
    };
    Ok(vcpu.emulated_msrs.get(&index).copied().unwrap_or(0))
}

fn read_one_reg(arg: usize) -> AxResult<OneReg> {
    let mut bytes = [0u8; abi::KVM_ONE_REG_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;

    Ok(OneReg {
        id: u64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
        addr: u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
    })
}
