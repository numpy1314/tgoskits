// SPDX-License-Identifier: Apache-2.0
//! ARM KVM frontend: byte-oriented UAPI parsing, no host kernel types.
use alloc::sync::Arc;

use ax_errno::{AxError, AxResult};
use ax_kspin::SpinNoIrq;
use axvcpu::AxVCpuExitReason;
use axvisor_api::control as api;
use kvm_uapi::ioctl::public::{KVM_GET_DEVICE_ATTR, KVM_HAS_DEVICE_ATTR, KVM_SET_DEVICE_ATTR};

use super::{
    CONTROL_FILES, ControlFileState, KVM_CONTROL_OPS, abi::raw as abi, arm_gic::Gic, util::*,
    vcpu::get_vcpu,
};

pub(super) fn counter() -> u64 {
    let v;
    unsafe { core::arch::asm!("isb","mrs {}, cntpct_el0",out(reg)v) };
    v
}
fn gic(vm_file: u64) -> AxResult<Arc<SpinNoIrq<Gic>>> {
    let files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = files.get(&vm_file) else {
        return Err(AxError::NotFound);
    };
    Ok(vm.arm_gic.clone())
}

pub(super) fn preferred_target(arg: usize) -> AxResult<isize> {
    let mut data = [0u8; 32];
    data[..4].copy_from_slice(&5u32.to_ne_bytes());
    api::copy_to_user(arg, &data)?;
    Ok(0)
}
pub(super) fn init_vcpu(file: u64, arg: usize) -> AxResult<isize> {
    let mut data = [0u8; 32];
    api::copy_from_user(arg, &mut data)?;
    let target = u32::from_ne_bytes(data[..4].try_into().unwrap());
    let features = u32::from_ne_bytes(data[4..8].try_into().unwrap());
    if target != 5 || features & !5 != 0 || features & 4 == 0 || data[8..].iter().any(|v| *v != 0) {
        return Err(AxError::InvalidInput);
    }
    let mut files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(v)) = files.get_mut(&file) else {
        return Err(AxError::NotFound);
    };
    if v.arm_initialized {
        return Err(AxError::InvalidInput);
    }
    v.arm_initialized = true;
    v.mp_state = if features & 1 != 0 {
        abi::KVM_MP_STATE_STOPPED
    } else {
        abi::KVM_MP_STATE_RUNNABLE
    };
    Ok(0)
}
pub(super) fn check_initialized(file: u64) -> AxResult {
    let files = CONTROL_FILES.lock();
    match files.get(&file) {
        Some(ControlFileState::Vcpu(v)) if v.arm_initialized => Ok(()),
        _ => Err(AxError::InvalidInput),
    }
}
pub(super) fn one_reg(file: u64, arg: usize, write: bool) -> AxResult<isize> {
    check_initialized(file)?;
    let id = read_u64_user(arg)?;
    let address = read_u64_user(checked_add(arg, 8)?)? as usize;
    let size = 1usize
        .checked_shl(((id >> 52) & 15) as u32)
        .ok_or(AxError::InvalidInput)?;
    if size > 16 {
        return Err(AxError::InvalidInput);
    }
    let v = get_vcpu(file)?;
    let state = v.get_arch_vcpu();
    let mut data = [0u8; 16];
    if write {
        api::copy_from_user(address, &mut data[..size])?;
        state.write_register(id, &data[..size])?;
    } else {
        state.read_register(id, &mut data[..size])?;
        api::copy_to_user(address, &data[..size])?;
    }
    Ok(0)
}
pub(super) fn reg_list(file: u64, arg: usize) -> AxResult<isize> {
    check_initialized(file)?;
    let ids = get_vcpu(file)?.get_arch_vcpu().register_ids();
    let n = read_u64_user(arg)?;
    write_u64_user(arg, ids.len() as u64)?;
    if n < ids.len() as u64 {
        return Err(AxError::ArgumentListTooLong);
    }
    for (i, id) in ids.iter().enumerate() {
        write_u64_user(checked_add(arg, 8 + i * 8)?, *id)?;
    }
    Ok(0)
}

pub(super) fn create_device(vm_file: u64, arg: usize) -> AxResult<isize> {
    let kind = read_u32_user(arg)?;
    let flags = read_u32_user(checked_add(arg, 8)?)?;
    if kind != 7 || flags & !1 != 0 {
        return Err(AxError::Unsupported);
    }
    if flags == 1 {
        return Ok(0);
    }
    let file = super::next_control_file_id()?;
    {
        let mut files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = files.get_mut(&vm_file) else {
            return Err(AxError::NotFound);
        };
        if !vm.arm_devices.is_empty() {
            return Err(AxError::AlreadyExists);
        }
        vm.arm_devices.push(file);
        files.insert(file, ControlFileState::ArmDevice(vm_file));
    }
    match api::create_user_fd_at(file, KVM_CONTROL_OPS, checked_add(arg, 4)?) {
        Ok(()) => Ok(0),
        Err(e) => {
            close_device(file, vm_file)?;
            Err(e)
        }
    }
}

pub(super) fn close_device(file: u64, vm_file: u64) -> AxResult {
    let cleanup = {
        let mut files = CONTROL_FILES.lock();
        files.remove(&file);
        if let Some(ControlFileState::Vm(vm)) = files.get_mut(&vm_file) {
            vm.arm_devices.retain(|id| *id != file);
            vm.vm_fd_closed && vm.vcpu_files.is_empty() && vm.arm_devices.is_empty()
        } else {
            false
        }
    };
    if cleanup {
        super::close(vm_file)?;
    }
    Ok(())
}

pub(super) fn device_ioctl(vm_file: u64, cmd: u32, arg: usize) -> AxResult<isize> {
    if !matches!(
        cmd,
        KVM_SET_DEVICE_ATTR | KVM_GET_DEVICE_ATTR | KVM_HAS_DEVICE_ATTR
    ) {
        return Err(AxError::Unsupported);
    }
    let mut data = [0u8; 24];
    api::copy_from_user(arg, &mut data)?;
    let flags = u32::from_ne_bytes(data[..4].try_into().unwrap());
    let group = u32::from_ne_bytes(data[4..8].try_into().unwrap());
    let attr = u64::from_ne_bytes(data[8..16].try_into().unwrap());
    let addr = u64::from_ne_bytes(data[16..24].try_into().unwrap()) as usize;
    if flags != 0 || !matches!((group, attr), (0, 2 | 3) | (3, 0) | (4, 0)) {
        return Err(AxError::Unsupported);
    }
    if cmd == KVM_HAS_DEVICE_ATTR {
        return Ok(0);
    }
    let vgic = gic(vm_file)?;
    if cmd == KVM_GET_DEVICE_ATTR {
        // Userspace faults may sleep; never copy while holding SpinNoIrq.
        let value = {
            let g = vgic.lock();
            match group {
                0 => if attr == 2 { g.dist } else { g.redist }.ok_or(AxError::NotFound)?,
                3 => g.nr_irqs as u64,
                _ => return Err(AxError::Unsupported),
            }
        };
        if group == 0 {
            write_u64_user(addr, value)?;
        } else {
            write_u32_user(addr, value as u32)?;
        }
        return Ok(0);
    }
    let value = match group {
        0 => read_u64_user(addr)?,
        3 => u64::from(read_u32_user(addr)?),
        _ => 0,
    };
    // Same lock order as CREATE_VCPU: freeze the CPU set through GIC INIT.
    let files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = files.get(&vm_file) else {
        return Err(AxError::NotFound);
    };
    let cpus = vm.vcpu_files.len();
    let ipa_limit = 1u64 << vm.arm_ipa_bits;
    // KVM permits VGIC INIT after CREATE_VCPU and before VCPU_INIT.
    let valid_cpus = vm
        .vcpu_files
        .keys()
        .enumerate()
        .all(|(index, id)| *id as usize == index);
    let mut g = vgic.lock();
    if g.initialized {
        return Err(AxError::ResourceBusy);
    }
    match group {
        0 => {
            if value & 0xffff != 0 || value >= ipa_limit {
                return Err(AxError::InvalidInput);
            }
            let slot = if attr == 2 {
                &mut g.dist
            } else {
                &mut g.redist
            };
            if slot.is_some() {
                return Err(AxError::AlreadyExists);
            }
            *slot = Some(value);
        }
        3 => {
            if !(64..=1024).contains(&value) || value % 32 != 0 {
                return Err(AxError::InvalidInput);
            }
            g.nr_irqs = value as usize;
        }
        4 => {
            let d = g.dist.ok_or(AxError::InvalidInput)?;
            let r = g.redist.ok_or(AxError::InvalidInput)?;
            if cpus == 0
                || cpus > 8
                || !valid_cpus
                || d + 0x10000 > ipa_limit
                || r + cpus as u64 * 0x20000 > ipa_limit
                || d < r + cpus as u64 * 0x20000 && r < d + 0x10000
            {
                return Err(AxError::InvalidInput);
            }
            g.cpus = cpus;
            g.initialized = true;
        }
        _ => return Err(AxError::Unsupported),
    }
    Ok(0)
}
pub(super) fn irqfd(vm_file: u64, gsi: u32) -> AxResult {
    gic(vm_file)?.lock().pulse(0, gsi as usize + 32)
}
pub(super) fn irq_line(vm_file: u64, arg: usize) -> AxResult<isize> {
    let irq = read_u32_user(arg)?;
    let level = read_u32_user(checked_add(arg, 4)?)?;
    if level > 1 {
        return Err(AxError::InvalidInput);
    }
    let kind = (irq >> 24) & 15;
    let cpu = ((irq >> 16) & 255) as usize;
    let id = (irq & 65535) as usize;
    if !(kind == 1 && id >= 32 || kind == 2 && (16..32).contains(&id)) {
        return Err(AxError::InvalidInput);
    }
    gic(vm_file)?.lock().line(cpu, id, level != 0)?;
    Ok(0)
}
pub(super) fn feed(vm_file: u64, cpu: usize, vcpu: &axvm::AxVCpuRef) -> AxResult {
    gic(vm_file)?.lock().feed(cpu, vcpu);
    Ok(())
}

pub(super) fn exit(
    vm_file: u64,
    cpu: usize,
    vcpu: &axvm::AxVCpuRef,
    reason: &AxVCpuExitReason,
) -> AxResult<bool> {
    let vgic = gic(vm_file)?;
    vgic.lock().sync(cpu, vcpu);
    match reason {
        AxVCpuExitReason::Hypercall { nr, args }
            if matches!(*nr as u32, 0x84000004 | 0xc4000004) =>
        {
            let files = CONTROL_FILES.lock();
            let Some(ControlFileState::Vm(vm)) = files.get(&vm_file) else {
                return Err(AxError::NotFound);
            };
            let result = if args[1] > 3 || args[0] >= 8 {
                -2
            } else {
                let mut result = -2;
                for (&id, file) in &vm.vcpu_files {
                    if args[1] == 0 && u64::from(id) != args[0] {
                        continue;
                    }
                    if let Some(ControlFileState::Vcpu(v)) = files.get(file) {
                        let state = if v.arm_start.is_some() {
                            2
                        } else {
                            i64::from(v.mp_state != abi::KVM_MP_STATE_RUNNABLE)
                        };
                        result = match (result, state) {
                            (0, _) | (_, 0) => 0,
                            (2, _) | (_, 2) => 2,
                            _ => 1,
                        };
                    }
                }
                result
            };
            vcpu.set_return_value(result as usize);
            Ok(true)
        }
        AxVCpuExitReason::CpuDown { .. } => {
            let mut files = CONTROL_FILES.lock();
            let Some(ControlFileState::Vm(vm)) = files.get(&vm_file) else {
                return Err(AxError::NotFound);
            };
            let file = *vm.vcpu_files.get(&(cpu as u32)).ok_or(AxError::NotFound)?;
            if let Some(ControlFileState::Vcpu(v)) = files.get_mut(&file) {
                v.mp_state = abi::KVM_MP_STATE_STOPPED;
            }
            Ok(true)
        }
        AxVCpuExitReason::MmioRead {
            addr,
            width,
            reg,
            reg_width,
            signed_ext,
        } => {
            let Some(value) = vgic
                .lock()
                .mmio(addr.as_usize() as u64, usize::from(*width), None)
            else {
                return Ok(false);
            };
            let value = value?;
            let bits = usize::from(*width) * 8;
            let value = if *signed_ext && bits < 64 {
                ((value << (64 - bits)) as i64 >> (64 - bits)) as u64
            } else {
                value
            };
            let value = if usize::from(*reg_width) == 4 {
                value as u32 as u64
            } else {
                value
            };
            vcpu.set_gpr(*reg, value as usize);
            Ok(true)
        }
        AxVCpuExitReason::MmioWrite { addr, width, data } => {
            match vgic
                .lock()
                .mmio(addr.as_usize() as u64, usize::from(*width), Some(*data))
            {
                Some(result) => {
                    result?;
                    Ok(true)
                }
                None => Ok(false),
            }
        }
        AxVCpuExitReason::SysRegWrite { addr, value } if addr.addr() == 0xc65d => {
            vgic.lock().sgi(cpu, *value);
            Ok(true)
        }
        AxVCpuExitReason::Halt => {
            axvisor_api::task::yield_now();
            Ok(true)
        }
        AxVCpuExitReason::CpuUp {
            target_cpu,
            entry_point,
            arg,
        } => {
            if *target_cpu >= 8 || entry_point.as_usize() & 3 != 0 {
                vcpu.set_return_value((-2i64) as usize);
                return Ok(true);
            }
            let target = *target_cpu as usize;
            let mut files = CONTROL_FILES.lock();
            let Some(ControlFileState::Vm(vm)) = files.get(&vm_file) else {
                return Err(AxError::NotFound);
            };
            if entry_point.as_usize() as u64 >= 1u64 << vm.arm_ipa_bits {
                vcpu.set_return_value((-2i64) as usize);
                return Ok(true);
            }
            let Some(target_file) = vm.vcpu_files.get(&(target as u32)).copied() else {
                vcpu.set_return_value((-2i64) as usize);
                return Ok(true);
            };

            let Some(ControlFileState::Vcpu(v)) = files.get_mut(&target_file) else {
                return Err(AxError::NotFound);
            };
            if !v.arm_initialized {
                vcpu.set_return_value((-2i64) as usize);
                return Ok(true);
            }
            if v.arm_start.is_some() {
                vcpu.set_return_value((-5i64) as usize);
                return Ok(true);
            }
            if v.mp_state == abi::KVM_MP_STATE_RUNNABLE {
                vcpu.set_return_value((-4i64) as usize);
                return Ok(true);
            }
            v.arm_start = Some((entry_point.as_usize() as u64, *arg));
            vcpu.set_return_value(0);
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Only the owning KVM_RUN task may reset the architectural vCPU state.
pub(super) fn consume_startup(file: u64, vcpu: &axvm::AxVCpuRef) -> AxResult {
    let mut files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vcpu(v)) = files.get_mut(&file) else {
        return Err(AxError::NotFound);
    };
    if let Some((pc, arg)) = v.arm_start.take() {
        vcpu.get_arch_vcpu().reset_for_psci(pc, arg);
        v.mp_state = abi::KVM_MP_STATE_RUNNABLE;
    }
    Ok(())
}
