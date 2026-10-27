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

use alloc::{collections::BTreeMap, format, sync::Arc};
use core::sync::atomic::{AtomicBool, Ordering};

use ax_errno::{AxError, AxErrorKind, AxResult, ax_err};
use axaddrspace::device::AccessWidth;
use axvisor_api::{
    control as api_control,
    task::{self as api_task, TaskHandle, TaskOptions},
};
#[cfg(target_arch = "x86_64")]
use kvm_uapi::KvmIrqLevel;
use kvm_uapi::{KvmMsi, x86::decode_msi_route};
#[cfg(target_arch = "x86_64")]
use vm_interrupt::InterruptTriggerMode;

use super::{CONTROL_FILES, ControlFileState};
use crate::{
    kvm::{
        abi::raw as abi,
        state::{GsiRoute, IoEventFd, IoEventFdKey, IrqFd, IrqFdKey, KvmIoEventFd, KvmIrqFd},
        util::{access_width_bytes, access_width_mask, checked_add, read_u32_user},
    },
    vmm::interrupt::{InterruptRoute, VirtualInterrupt, deliver_interrupt},
};

// KVM IRQFD/IOEVENTFD payloads are plain UAPI data. The registered listeners and
// host file references are runtime state and are kept in axvisor_core::kvm.

pub(in crate::kvm) fn set_gsi_routing(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let routes = read_gsi_routes(arg)?;
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };
    vm.gsi_routing_count = routes.len() as u32;
    vm.gsi_routes = routes;
    Ok(0)
}

#[cfg(target_arch = "x86_64")]
pub(in crate::kvm) fn set_irq_line(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    let irq_level = read_irq_level(arg)?;
    if irq_level.level > 1 || irq_level.irq >= abi::KVM_X86_IOAPIC_NUM_PINS {
        return ax_err!(InvalidInput);
    }

    let (vm, pin) = {
        let control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = control_files.get(&control_file) else {
            return ax_err!(NotFound);
        };
        if !vm.irqchip_created {
            return ax_err!(InvalidInput);
        }
        let pin = match vm.gsi_routes.get(&irq_level.irq).copied() {
            Some(GsiRoute::IrqChip { pin }) => pin,
            Some(GsiRoute::Msi { .. }) => return ax_err!(InvalidInput),
            None => irq_level.irq,
        };
        if pin >= abi::KVM_X86_IOAPIC_NUM_PINS {
            return ax_err!(InvalidInput);
        }
        (vm.vm.clone(), pin)
    };

    if let Some(irq) = vm
        .get_devices()
        .x86_ioapic_set_gsi_level(pin as usize, irq_level.level != 0)
    {
        deliver_interrupt(InterruptRoute::new(
            vm.id(),
            irq.target_vcpu,
            VirtualInterrupt::with_trigger(
                irq.vector as usize,
                if irq.level_triggered {
                    InterruptTriggerMode::LevelTriggered
                } else {
                    InterruptTriggerMode::EdgeTriggered
                },
            ),
        ));
    }
    Ok(0)
}

#[cfg(target_arch = "x86_64")]
fn read_irq_level(arg: usize) -> AxResult<KvmIrqLevel> {
    let mut bytes = [0u8; abi::KVM_IRQ_LEVEL_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;
    Ok(KvmIrqLevel {
        irq: u32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
        level: u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
    })
}

#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", feature = "arm-vhe")
)))]
pub(in crate::kvm) fn set_irq_line(
    _control_file: api_control::ControlFileId,
    _arg: usize,
) -> AxResult<isize> {
    ax_err!(Unsupported)
}

pub(in crate::kvm) fn update_irqfd(
    control_file: api_control::ControlFileId,
    irqfd: KvmIrqFd,
) -> AxResult {
    validate_irqfd(irqfd)?;

    let key = IrqFdKey {
        gsi: irqfd.gsi,
        fd: irqfd.fd,
    };
    let user_fd_ref = if irqfd.flags & abi::KVM_IRQFD_FLAG_DEASSIGN == 0 {
        Some(api_control::get_user_fd_ref(
            i32::try_from(irqfd.fd).map_err(|_| AxError::InvalidInput)?,
        )?)
    } else {
        None
    };

    let old_irqfd = if irqfd.flags & abi::KVM_IRQFD_FLAG_DEASSIGN != 0 {
        let mut control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
            return ax_err!(NotFound);
        };
        Some(vm.irqfds.remove(&key).ok_or(AxError::NotFound)?)
    } else {
        {
            let control_files = CONTROL_FILES.lock();
            if !matches!(
                control_files.get(&control_file),
                Some(ControlFileState::Vm(_))
            ) {
                if let Some(user_fd_ref) = user_fd_ref {
                    let _ = api_control::release_user_fd_ref(user_fd_ref);
                }
                return ax_err!(NotFound);
            }
        }

        let user_fd_ref = user_fd_ref.unwrap();
        let (cancel, task) = start_irqfd_listener(control_file, irqfd.gsi, user_fd_ref);

        let mut control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
            drop(control_files);
            stop_irqfd(IrqFd {
                user_fd_ref,
                cancel,
                _task: task,
            });
            return ax_err!(NotFound);
        };
        let old_irqfd = vm.irqfds.remove(&key);
        vm.irqfds.insert(
            key,
            IrqFd {
                user_fd_ref,
                cancel,
                _task: task,
            },
        );
        old_irqfd
    };

    if let Some(old_irqfd) = old_irqfd {
        stop_irqfd(old_irqfd);
    }
    Ok(())
}

fn validate_irqfd(irqfd: KvmIrqFd) -> AxResult {
    if irqfd.flags & !abi::KVM_IRQFD_VALID_FLAGS != 0 {
        return ax_err!(InvalidInput);
    }
    if irqfd.flags & abi::KVM_IRQFD_FLAG_RESAMPLE != 0 {
        return ax_err!(Unsupported);
    }
    if i32::try_from(irqfd.fd).is_err() {
        return ax_err!(InvalidInput);
    }
    Ok(())
}

pub(in crate::kvm) fn read_ioeventfd(arg: usize) -> AxResult<KvmIoEventFd> {
    let mut bytes = [0u8; abi::KVM_IOEVENTFD_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;

    Ok(KvmIoEventFd {
        datamatch: u64::from_ne_bytes(bytes[0..8].try_into().unwrap()),
        addr: u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
        len: u32::from_ne_bytes(bytes[16..20].try_into().unwrap()),
        fd: i32::from_ne_bytes(bytes[20..24].try_into().unwrap()),
        flags: u32::from_ne_bytes(bytes[24..28].try_into().unwrap()),
    })
}

pub(in crate::kvm) fn read_irqfd(arg: usize) -> AxResult<KvmIrqFd> {
    let mut bytes = [0u8; abi::KVM_IRQFD_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;

    Ok(KvmIrqFd {
        fd: u32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
        gsi: u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        flags: u32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
        resamplefd: u32::from_ne_bytes(bytes[12..16].try_into().unwrap()),
    })
}

pub(in crate::kvm) fn signal_msi(
    control_file: api_control::ControlFileId,
    arg: usize,
) -> AxResult<isize> {
    if !cfg!(target_arch = "x86_64") {
        return ax_err!(Unsupported);
    }
    let msi = read_msi(arg)?;
    let (vm_id, active_vcpu_mask) = {
        let mut control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
            return ax_err!(NotFound);
        };
        let active_vcpu_mask = vm
            .vcpu_files
            .keys()
            .filter(|vcpu_id| **vcpu_id < u64::BITS)
            .fold(0u64, |mask, vcpu_id| mask | (1u64 << vcpu_id));
        #[cfg(target_arch = "x86_64")]
        {
            let route =
                decode_msi_route(msi, active_vcpu_mask).map_err(|_| AxError::Unsupported)?;
            if route.level_triggered {
                vm.userspace_eoi_vectors.insert(route.vector);
            }
        }
        (vm.vm.id(), active_vcpu_mask)
    };
    deliver_msi(vm_id, active_vcpu_mask, msi)?;
    Ok(0)
}

#[cfg(target_arch = "x86_64")]
pub(in crate::kvm) fn is_userspace_eoi_vector(
    control_file: api_control::ControlFileId,
    vector: u8,
) -> bool {
    let control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get(&control_file) else {
        return false;
    };
    vm.userspace_eoi_vectors.contains(&vector)
}

fn read_msi(arg: usize) -> AxResult<KvmMsi> {
    let mut bytes = [0u8; abi::KVM_MSI_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;
    Ok(KvmMsi {
        address_lo: u32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
        address_hi: u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        data: u32::from_ne_bytes(bytes[8..12].try_into().unwrap()),
        flags: u32::from_ne_bytes(bytes[12..16].try_into().unwrap()),
        devid: u32::from_ne_bytes(bytes[16..20].try_into().unwrap()),
    })
}

fn read_gsi_routes(arg: usize) -> AxResult<BTreeMap<u32, GsiRoute>> {
    let route_count = read_u32_user(arg)? as usize;
    if route_count > abi::KVM_MAX_IRQ_ROUTES {
        return ax_err!(InvalidInput);
    }

    let mut routes = BTreeMap::new();
    let mut offset = checked_add(arg, abi::KVM_IRQ_ROUTING_SIZE as usize)?;
    for _ in 0..route_count {
        let gsi = read_u32_user(offset)?;
        let route_type = read_u32_user(checked_add(offset, 4)?)?;
        let flags = read_u32_user(checked_add(offset, 8)?)?;
        if flags != 0 {
            return ax_err!(Unsupported);
        }

        let route = match route_type {
            abi::KVM_IRQ_ROUTING_IRQCHIP => {
                let pin = read_u32_user(checked_add(offset, 20)?)?;
                GsiRoute::IrqChip { pin }
            }
            abi::KVM_IRQ_ROUTING_MSI => {
                let address_lo = read_u32_user(checked_add(offset, 16)?)?;
                let address_hi = read_u32_user(checked_add(offset, 20)?)?;
                let data = read_u32_user(checked_add(offset, 24)?)?;
                GsiRoute::Msi {
                    address_lo,
                    address_hi,
                    data,
                }
            }
            _ => return ax_err!(Unsupported),
        };
        routes.insert(gsi, route);
        offset = checked_add(offset, abi::KVM_IRQ_ROUTING_ENTRY_SIZE)?;
    }

    Ok(routes)
}

fn start_irqfd_listener(
    vm_file: api_control::ControlFileId,
    gsi: u32,
    user_fd_ref: api_control::UserFdRefId,
) -> (Arc<AtomicBool>, TaskHandle) {
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_for_task = cancel.clone();
    let task = api_task::spawn_task(
        TaskOptions {
            name: format!("kvm-irqfd-{vm_file}-{gsi}"),
            stack_size: 64 * 1024,
            cpu_set: None,
        },
        move || irqfd_listener_loop(vm_file, gsi, user_fd_ref, cancel_for_task),
    );
    (cancel, task)
}

pub(in crate::kvm) fn stop_irqfd(irqfd: IrqFd) {
    irqfd.cancel.store(true, Ordering::Release);
    wake_cancelled_irqfd(irqfd.user_fd_ref);
    // The listener owns a host task (and its kernel stack).  Wait for it to
    // observe the cancellation and exit before dropping the VM state, so
    // repeated VM create/destroy cycles do not leak tasks until spawn fails.
    api_task::join_task(irqfd._task);
    // Release the eventfd reference only after the listener has stopped.  It
    // may still be reading the reference while cancellation is being
    // observed, so releasing it before join races with the listener.
    let _ = api_control::release_user_fd_ref(irqfd.user_fd_ref);
}

fn wake_cancelled_irqfd(user_fd_ref: api_control::UserFdRefId) {
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    match api_control::cancel_user_fd_wait(user_fd_ref) {
        Ok(()) => return,
        Err(err) if AxErrorKind::try_from(err) == Ok(AxErrorKind::Unsupported) => {}
        Err(err) => {
            warn!("KVM irqfd wait cancellation failed: {err:?}");
        }
    }
    // Keep the existing wakeup for hosts without a cancellable readiness wait.
    let _ = api_control::write_user_fd_ref(user_fd_ref, &1u64.to_ne_bytes());
}

fn wait_irqfd_readable(_user_fd_ref: api_control::UserFdRefId) -> AxResult {
    #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
    match api_control::wait_user_fd_readable(_user_fd_ref) {
        Err(err) if AxErrorKind::try_from(err) == Ok(AxErrorKind::Unsupported) => {}
        result => return result,
    }
    api_task::yield_now();
    Ok(())
}

fn irqfd_listener_loop(
    vm_file: api_control::ControlFileId,
    gsi: u32,
    user_fd_ref: api_control::UserFdRefId,
    cancel: Arc<AtomicBool>,
) {
    while !cancel.load(Ordering::Acquire) {
        let mut bytes = [0u8; 8];
        match api_control::read_user_fd_ref(user_fd_ref, &mut bytes) {
            Ok(read_len) if read_len == core::mem::size_of::<u64>() => {
                if cancel.load(Ordering::Acquire) {
                    break;
                }
                if u64::from_ne_bytes(bytes) != 0
                    && let Err(err) = inject_irqfd_gsi(vm_file, gsi)
                {
                    warn!("KVM irqfd injection failed for GSI {gsi}: {err:?}");
                }
            }
            Ok(_) => api_task::yield_now(),
            Err(err) if AxErrorKind::try_from(err) == Ok(AxErrorKind::WouldBlock) => {
                if let Err(err) = wait_irqfd_readable(user_fd_ref)
                    && AxErrorKind::try_from(err) != Ok(AxErrorKind::Interrupted)
                {
                    debug!("KVM irqfd readiness wait failed for GSI {gsi}: {err:?}");
                    break;
                }
            }
            Err(err) if AxErrorKind::try_from(err) == Ok(AxErrorKind::Interrupted) => {
                api_task::yield_now();
            }
            Err(err) => {
                debug!("KVM irqfd listener exiting for GSI {gsi}: {err:?}");
                break;
            }
        }
    }
}

#[cfg(not(all(target_arch = "aarch64", feature = "arm-vhe")))]
fn inject_irqfd_gsi(control_file: api_control::ControlFileId, gsi: u32) -> AxResult {
    let (vm, route, active_vcpu_mask) = {
        let control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = control_files.get(&control_file) else {
            return ax_err!(NotFound);
        };
        let route = vm
            .gsi_routes
            .get(&gsi)
            .copied()
            .unwrap_or(GsiRoute::IrqChip { pin: gsi });
        let active_vcpu_mask = vm
            .vcpu_files
            .keys()
            .filter(|vcpu_id| **vcpu_id < u64::BITS)
            .fold(0u64, |mask, vcpu_id| mask | (1u64 << vcpu_id));
        (vm.vm.clone(), route, active_vcpu_mask)
    };

    match route {
        #[cfg(target_arch = "x86_64")]
        GsiRoute::IrqChip { pin } => {
            let Some(irq) = vm.get_devices().x86_ioapic_assert_gsi(pin as usize) else {
                return Ok(());
            };
            deliver_interrupt(InterruptRoute::new(
                vm.id(),
                irq.target_vcpu,
                VirtualInterrupt::with_trigger(
                    irq.vector as usize,
                    if irq.level_triggered {
                        InterruptTriggerMode::LevelTriggered
                    } else {
                        InterruptTriggerMode::EdgeTriggered
                    },
                ),
            ));
            Ok(())
        }
        #[cfg(not(target_arch = "x86_64"))]
        GsiRoute::IrqChip { pin } => {
            deliver_interrupt(InterruptRoute::new(
                vm.id(),
                0,
                VirtualInterrupt::edge(legacy_gsi_vector(pin) as usize),
            ));
            Ok(())
        }
        GsiRoute::Msi {
            address_lo,
            address_hi,
            data,
        } => deliver_msi(
            vm.id(),
            active_vcpu_mask,
            KvmMsi {
                address_lo,
                address_hi,
                data,
                flags: 0,
                devid: 0,
            },
        ),
    }
}

fn deliver_msi(vm_id: usize, active_vcpu_mask: u64, msi: KvmMsi) -> AxResult {
    let route = decode_msi_route(msi, active_vcpu_mask).map_err(|_| AxError::Unsupported)?;
    #[cfg(target_arch = "x86_64")]
    let trigger = if route.level_triggered {
        InterruptTriggerMode::LevelTriggered
    } else {
        InterruptTriggerMode::EdgeTriggered
    };
    #[cfg(target_arch = "x86_64")]
    let interrupt = VirtualInterrupt::with_trigger(route.vector as usize, trigger);
    #[cfg(not(target_arch = "x86_64"))]
    let interrupt = VirtualInterrupt::edge(route.vector as usize);
    for vcpu_id in 0..u64::BITS as usize {
        if route.target_mask & (1u64 << vcpu_id) != 0 {
            deliver_interrupt(InterruptRoute::new(vm_id, vcpu_id, interrupt));
        }
    }
    Ok(())
}

#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", feature = "arm-vhe")
)))]
fn legacy_gsi_vector(gsi: u32) -> u8 {
    0x20u8.saturating_add(gsi.min(0xdf) as u8)
}

pub(in crate::kvm) fn update_ioeventfd(
    control_file: api_control::ControlFileId,
    ioeventfd: KvmIoEventFd,
) -> AxResult {
    validate_ioeventfd(ioeventfd)?;

    let key = IoEventFdKey {
        addr: ioeventfd.addr,
        datamatch: ioeventfd.datamatch,
        pio: ioeventfd.flags & abi::KVM_IOEVENTFD_FLAG_PIO != 0,
    };
    let user_fd_ref = if ioeventfd.flags & abi::KVM_IOEVENTFD_FLAG_DEASSIGN == 0 {
        Some(api_control::get_user_fd_ref(ioeventfd.fd)?)
    } else {
        None
    };
    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
        if let Some(user_fd_ref) = user_fd_ref {
            let _ = api_control::release_user_fd_ref(user_fd_ref);
        }
        return ax_err!(NotFound);
    };

    if ioeventfd.flags & abi::KVM_IOEVENTFD_FLAG_DEASSIGN != 0 {
        let existing = vm.ioeventfds.remove(&key).ok_or(AxError::NotFound)?;
        let _ = api_control::release_user_fd_ref(existing.user_fd_ref);
    } else {
        if let Some(existing) = vm.ioeventfds.remove(&key) {
            let _ = api_control::release_user_fd_ref(existing.user_fd_ref);
        }
        vm.ioeventfds.insert(
            key,
            IoEventFd {
                addr: ioeventfd.addr,
                len: ioeventfd.len,
                datamatch: ioeventfd.datamatch,
                user_fd_ref: user_fd_ref.unwrap(),
                flags: ioeventfd.flags,
            },
        );
    }
    Ok(())
}

fn validate_ioeventfd(ioeventfd: KvmIoEventFd) -> AxResult {
    if ioeventfd.flags & !abi::KVM_IOEVENTFD_VALID_FLAGS != 0 {
        return ax_err!(InvalidInput);
    }
    if !matches!(ioeventfd.len, 0 | 1 | 2 | 4 | 8) {
        return ax_err!(InvalidInput);
    }
    if ioeventfd.len == 0 && ioeventfd.flags & abi::KVM_IOEVENTFD_FLAG_DATAMATCH != 0 {
        return ax_err!(InvalidInput);
    }
    if ioeventfd.fd < 0 {
        return ax_err!(InvalidInput);
    }
    Ok(())
}

pub(in crate::kvm) fn signal_matching_ioeventfd(
    control_file: api_control::ControlFileId,
    addr: u64,
    width: AccessWidth,
    data: u64,
    pio: bool,
) -> AxResult<bool> {
    let ioeventfd = {
        let control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vcpu(vcpu)) = control_files.get(&control_file) else {
            return ax_err!(NotFound);
        };
        let Some(ControlFileState::Vm(vm)) = control_files.get(&vcpu.vm_file) else {
            return ax_err!(NotFound);
        };
        vm.ioeventfds
            .values()
            .find(|ioeventfd| ioeventfd_matches(ioeventfd, addr, width, data, pio))
            .copied()
    };

    if let Some(ioeventfd) = ioeventfd {
        let written = api_control::write_user_fd_ref(ioeventfd.user_fd_ref, &1u64.to_ne_bytes())?;
        if written != core::mem::size_of::<u64>() {
            return Err(AxError::Io);
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

fn ioeventfd_matches(
    ioeventfd: &IoEventFd,
    addr: u64,
    width: AccessWidth,
    data: u64,
    pio: bool,
) -> bool {
    if (ioeventfd.flags & abi::KVM_IOEVENTFD_FLAG_PIO != 0) != pio {
        return false;
    }
    if ioeventfd.addr != addr || (ioeventfd.len != 0 && ioeventfd.len != access_width_bytes(width))
    {
        return false;
    }
    if ioeventfd.flags & abi::KVM_IOEVENTFD_FLAG_DATAMATCH == 0 {
        return true;
    }
    let mask = access_width_mask(width) as u64;
    (data & mask) == (ioeventfd.datamatch & mask)
}

#[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
fn inject_irqfd_gsi(file: u64, gsi: u32) -> AxResult {
    super::arm::irqfd(file, gsi)
}
#[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
pub(in crate::kvm) fn set_irq_line(file: u64, arg: usize) -> AxResult<isize> {
    super::arm::irq_line(file, arg)
}
