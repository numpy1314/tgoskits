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

use alloc::{
    collections::{BTreeMap, VecDeque},
    format, vec,
    vec::Vec,
};

use ax_errno::{AxError, AxResult, ax_err};
use axvisor_api::control as api_control;
use axvm::{AxVM, VMStatus, config::AxVMConfig};

use super::{
    CONTROL_FILES, ControlFileState, KVM_CONTROL_OPS, VcpuFileState, VcpuOperationLock,
    VmFileState, next_control_file_id,
};
use crate::kvm::{
    abi::raw as abi,
    util::read_u32_user,
    vcpu::{default_fpu, default_xcrs},
};

pub(in crate::kvm) fn create_vm_file() -> AxResult<api_control::ControlFileId> {
    let control_file = next_control_file_id()?;
    let vm_id = control_file_id_to_usize(control_file)?;
    let config =
        AxVMConfig::new_host_controlled(vm_id, format!("kvm-vm-{vm_id}"), abi::KVM_MAX_VCPUS);
    let vm = AxVM::new(config)?;
    vm.init()?;
    vm.set_vm_status(VMStatus::Loaded);

    CONTROL_FILES.lock().insert(
        control_file,
        ControlFileState::Vm(VmFileState {
            #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
            arm_ipa_bits: 40,
            #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
            arm_cache_ready: false,
            #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
            memory_gate: super::memory_gate::MemoryGate::new(),
            #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
            arm_gic: alloc::sync::Arc::new(ax_kspin::SpinNoIrq::new(super::arm_gic::Gic::new())),
            #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
            arm_devices: Vec::new(),
            vm,
            vm_fd_closed: false,
            memory_slots: BTreeMap::new(),
            ioeventfds: BTreeMap::new(),
            irqfds: BTreeMap::new(),
            gsi_routes: BTreeMap::new(),
            vcpu_files: BTreeMap::new(),
            clock: vec![0; abi::KVM_CLOCK_DATA_SIZE as usize],
            pit2: vec![0; abi::KVM_PIT_STATE2_SIZE as usize],
            #[cfg(target_arch = "x86_64")]
            irqchips: core::array::from_fn(|chip_id| {
                let mut state = vec![0; abi::KVM_IRQCHIP_SIZE as usize];
                state[..4].copy_from_slice(&(chip_id as u32).to_ne_bytes());
                state
            }),
            tsc_khz: 0,
            tss_addr: None,
            identity_map_addr: None,
            irqchip_created: false,
            pit2_created: false,
            gsi_routing_count: 0,
            #[cfg(target_arch = "x86_64")]
            userspace_eoi_vectors: Default::default(),
        }),
    );
    Ok(control_file)
}

pub(in crate::kvm) fn create_vcpu_file(
    control_file: api_control::ControlFileId,
    vcpu_id: usize,
) -> AxResult<isize> {
    let vcpu_id = u32::try_from(vcpu_id).map_err(|_| AxError::InvalidInput)?;
    let mmap_area = api_control::create_mmap_area(abi::KVM_VCPU_MMAP_SIZE)?;

    let result = (|| -> AxResult<api_control::ControlFileId> {
        let mut control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
            return ax_err!(NotFound);
        };
        if vcpu_id as usize >= vm.vm.vcpu_num() {
            return ax_err!(InvalidInput);
        }
        if vm.vcpu_files.contains_key(&vcpu_id) {
            return ax_err!(AlreadyExists);
        }

        #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
        if vm.arm_gic.lock().initialized {
            return ax_err!(ResourceBusy);
        }
        let vcpu_file = next_control_file_id()?;
        // On x86, userspace is responsible for starting every vCPU when no
        // in-kernel irqchip is present. RISC-V secondary harts must remain
        // stopped until the boot hart starts them through SBI HSM.
        #[cfg(target_arch = "x86_64")]
        let mp_state = if vcpu_id == 0 || !vm.irqchip_created {
            abi::KVM_MP_STATE_RUNNABLE
        } else {
            abi::KVM_MP_STATE_STOPPED
        };
        #[cfg(not(target_arch = "x86_64"))]
        let mp_state = if vcpu_id == 0 {
            abi::KVM_MP_STATE_RUNNABLE
        } else {
            abi::KVM_MP_STATE_STOPPED
        };
        vm.vcpu_files.insert(vcpu_id, vcpu_file);
        control_files.insert(
            vcpu_file,
            ControlFileState::Vcpu(VcpuFileState {
                #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
                arm_initialized: false,
                #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
                arm_start: None,
                vm_file: control_file,
                vcpu_id,
                mmap_area,
                mp_state,
                halted: false,
                pending_interrupts: VecDeque::new(),
                pending_mmio_read: None,
                pending_io_read: None,
                #[cfg(all(target_arch = "x86_64", feature = "vmx"))]
                pending_startup_entry: None,
                cpuid: Vec::new(),
                emulated_msrs: BTreeMap::new(),
                fpu: default_fpu(),
                vcpu_events: vec![0; abi::KVM_X86_VCPU_EVENTS_SIZE as usize],
                xsave: vec![0; abi::KVM_X86_XSAVE_SIZE as usize],
                xcrs: default_xcrs(),
                signal_mask: Vec::new(),
                lapic: vec![0; abi::KVM_X86_LAPIC_STATE_SIZE as usize],
                vapic_addr: None,
                operation_lock: VcpuOperationLock::new(),
            }),
        );
        Ok(vcpu_file)
    })();
    let vcpu_file = match result {
        Ok(id) => id,
        Err(error) => {
            let _ = api_control::release_mmap_area(mmap_area);
            return Err(error);
        }
    };

    match api_control::create_user_fd(vcpu_file, KVM_CONTROL_OPS, Some(mmap_area)) {
        Ok(fd) => Ok(fd as isize),
        Err(err) => {
            let _ = remove_vcpu_file(vcpu_file);
            Err(err)
        }
    }
}

pub(in crate::kvm) fn set_tss_addr(
    control_file: api_control::ControlFileId,
    addr: usize,
) -> AxResult<isize> {
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vm.tss_addr = Some(addr);
    Ok(0)
}

pub(in crate::kvm) fn set_identity_map_addr(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    if !cfg!(target_arch = "x86_64") {
        return ax_err!(Unsupported);
    }
    let mut bytes = [0u8; core::mem::size_of::<u64>()];
    api_control::copy_from_user(arg, &mut bytes)?;
    let addr = u64::from_ne_bytes(bytes);
    if addr & 0xfff != 0 {
        return ax_err!(InvalidInput);
    }

    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vm.identity_map_addr = Some(addr);
    Ok(0)
}

pub(in crate::kvm) fn create_irqchip(control_file: api_control::ControlFileId) -> AxResult<isize> {
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vm.irqchip_created = true;
    Ok(0)
}

#[cfg(target_arch = "x86_64")]
pub(in crate::kvm) fn get_irqchip(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let chip_id = read_u32_user(arg)? as usize;
    let control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get(&control_file) else {
        return ax_err!(NotFound);
    };
    if !vm.irqchip_created {
        return ax_err!(InvalidInput);
    }
    let state = vm.irqchips.get(chip_id).ok_or(AxError::InvalidInput)?;
    api_control::copy_to_user(arg, state)?;
    Ok(0)
}

#[cfg(target_arch = "x86_64")]
pub(in crate::kvm) fn set_irqchip(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let mut state = vec![0; abi::KVM_IRQCHIP_SIZE as usize];
    api_control::copy_from_user(arg, &mut state)?;
    let chip_id = u32::from_ne_bytes(state[..4].try_into().unwrap());

    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    if !vm.irqchip_created {
        return ax_err!(InvalidInput);
    }
    let stored = vm
        .irqchips
        .get_mut(chip_id as usize)
        .ok_or(AxError::InvalidInput)?;

    if chip_id == abi::KVM_IRQCHIP_IOAPIC {
        let selector = read_u32_at(&state, abi::KVM_IOAPIC_IOREGSEL_OFFSET)?;
        let id = read_u32_at(&state, abi::KVM_IOAPIC_ID_OFFSET)?;
        let irr = read_u32_at(&state, abi::KVM_IOAPIC_IRR_OFFSET)?;
        let mut redirection_table = [0u64; abi::KVM_X86_IOAPIC_NUM_PINS as usize];
        for (index, entry) in redirection_table.iter_mut().enumerate() {
            let offset = abi::KVM_IOAPIC_REDIRENT_OFFSET + index * core::mem::size_of::<u64>();
            *entry = read_u64_at(&state, offset)?;
        }
        if !vm
            .vm
            .get_devices()
            .x86_ioapic_replace_state(selector, id, irr, redirection_table)
        {
            return ax_err!(NotFound);
        }
    }

    *stored = state;
    Ok(0)
}

#[cfg(target_arch = "x86_64")]
fn read_u32_at(bytes: &[u8], offset: usize) -> AxResult<u32> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(AxError::InvalidInput)?
        .try_into()
        .map_err(|_| AxError::InvalidInput)?;
    Ok(u32::from_ne_bytes(value))
}

#[cfg(target_arch = "x86_64")]
fn read_u64_at(bytes: &[u8], offset: usize) -> AxResult<u64> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(AxError::InvalidInput)?
        .try_into()
        .map_err(|_| AxError::InvalidInput)?;
    Ok(u64::from_ne_bytes(value))
}

pub(in crate::kvm) fn create_pit2(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let flags = read_u32_user(arg)?;
    if flags & !abi::KVM_PIT_VALID_FLAGS != 0 {
        return ax_err!(InvalidInput);
    }

    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vm.pit2_created = true;
    Ok(0)
}

pub(in crate::kvm) fn get_vm_blob<F>(
    control_file: api_control::ControlFileId,
    arg: usize,
    get: F,
) -> AxResult<isize>
where
    F: FnOnce(&VmFileState) -> &Vec<u8>,
{
    let bytes = {
        let control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = control_files.get(&control_file) else {
            return ax_err!(NotFound);
        };
        get(vm).clone()
    };
    api_control::copy_to_user(arg, &bytes)?;
    Ok(0)
}

pub(in crate::kvm) fn set_vm_blob<F>(
    control_file: api_control::ControlFileId,
    arg: usize,
    len: usize,
    set: F,
) -> AxResult<isize>
where
    F: FnOnce(&mut VmFileState, Vec<u8>),
{
    let mut bytes = vec![0u8; len];
    api_control::copy_from_user(arg, &mut bytes)?;

    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    set(vm, bytes);
    Ok(0)
}

pub(in crate::kvm) fn get_tsc_khz(control_file: api_control::ControlFileId) -> AxResult<isize> {
    let control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get(&control_file) else {
        return ax_err!(NotFound);
    };
    Ok(vm.tsc_khz as isize)
}

pub(in crate::kvm) fn set_tsc_khz(
    control_file: api_control::ControlFileId,
    khz: usize,
) -> AxResult<isize> {
    let khz = u32::try_from(khz).map_err(|_| AxError::InvalidInput)?;
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vm.tsc_khz = khz;
    Ok(0)
}

fn remove_vcpu_file(vcpu_file: api_control::ControlFileId) -> AxResult {
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(vcpu)) = control_files.remove(&vcpu_file) else {
        return ax_err!(NotFound);
    };
    if let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&vcpu.vm_file) {
        vm.vcpu_files.remove(&vcpu.vcpu_id);
    }
    let _ = api_control::release_mmap_area(vcpu.mmap_area);
    Ok(())
}

fn control_file_id_to_usize(control_file: api_control::ControlFileId) -> AxResult<usize> {
    let value = control_file as usize;
    if value as api_control::ControlFileId != control_file {
        return ax_err!(OutOfRange);
    }
    Ok(value)
}
