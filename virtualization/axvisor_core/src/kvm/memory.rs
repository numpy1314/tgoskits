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

use ax_errno::{AxError, AxResult, ax_err};
use axaddrspace::{GuestPhysAddr, HostPhysAddr, MappingFlags};
use axvisor_api::control as api_control;
use axvm::AxVMRef;

use super::{CONTROL_FILES, ControlFileState};
#[cfg(target_arch = "x86_64")]
use crate::kvm::state::{MappedMemoryPage, PinnedPageGroup};
use crate::kvm::{
    abi::raw as abi,
    state::{MemorySlot, UserspaceMemoryRegion, VmFileState},
};

// UserspaceMemoryRegion is a plain KVM UAPI payload. MemorySlot below adds the
// host backing state and therefore remains local to axvisor_core.

#[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
pub(in crate::kvm) fn set_user_memory_region(
    control_file: api_control::ControlFileId,
    region: UserspaceMemoryRegion,
) -> AxResult {
    validate_memory_region(region)?;
    if region.guest_phys_addr + region.memory_size > (1u64 << 48) {
        return ax_err!(InvalidInput);
    }
    let (gate, vm_ref, ipa_bits) = {
        let files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = files.get(&control_file) else {
            return ax_err!(NotFound);
        };
        (vm.memory_gate.clone(), vm.vm.clone(), vm.arm_ipa_bits)
    };
    if region.guest_phys_addr + region.memory_size > (1u64 << ipa_bits) {
        return ax_err!(InvalidInput);
    }
    // No host spinlock is held while waiting for running vCPUs or pinning RAM.
    let _writer = gate.write();
    let cache_ready = {
        let files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = files.get(&control_file) else {
            return ax_err!(NotFound);
        };
        if region.memory_size != 0 {
            ensure_no_memory_overlap(vm, region.slot, &region.into())?;
        }
        vm.arm_cache_ready
    };
    let mut new_slot: MemorySlot = region.into();
    if region.memory_size != 0 {
        let mm = api_control::retain_current_user_address_space()?;
        let result = api_control::pin_user_pages(
            mm,
            region.userspace_addr as usize,
            region.memory_size as usize,
            true,
        );
        let release = api_control::release_user_address_space(mm);
        let pinned = result?;
        if let Err(error) = release {
            let _ = api_control::release_pinned_user_pages(pinned.id);
            return Err(error);
        }
        if pinned.pages.len() != region.memory_size as usize / abi::PAGE_SIZE_USIZE {
            let _ = api_control::release_pinned_user_pages(pinned.id);
            return ax_err!(InvalidInput);
        }
        new_slot.pinned_pages = pinned.id;
        new_slot.arm_pages = pinned
            .pages
            .into_iter()
            .map(|p| HostPhysAddr::from(p.as_usize()))
            .collect();
    }
    if cache_ready {
        clean_arm_pages(&new_slot.arm_pages);
    }
    let old_slot = {
        let mut files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = files.get_mut(&control_file) else {
            if new_slot.pinned_pages != 0 {
                let _ = api_control::release_pinned_user_pages(new_slot.pinned_pages);
            }
            return ax_err!(NotFound);
        };
        vm.memory_slots.remove(&region.slot)
    };
    if let Some(old) = &old_slot {
        // Retain old pins until the new mapping is committed or rolled back.
        for index in 0..old.arm_pages.len() {
            if let Err(error) = vm_ref.unmap_region(
                GuestPhysAddr::from(old.guest_phys_addr as usize + index * abi::PAGE_SIZE_USIZE),
                abi::PAGE_SIZE_USIZE,
            ) {
                // An inconsistent table must not resume or release still-mapped pins.
                let _ = vm_ref.shutdown();
                if let Some(ControlFileState::Vm(vm)) = CONTROL_FILES.lock().get_mut(&control_file)
                {
                    vm.memory_slots.insert(region.slot, old_slot.unwrap());
                }
                if new_slot.pinned_pages != 0 {
                    let _ = api_control::release_pinned_user_pages(new_slot.pinned_pages);
                }
                return Err(error);
            }
        }
    }
    let result = map_arm_slot(&vm_ref, &new_slot);
    if result.is_err() {
        if let Some(old) = old_slot {
            if map_arm_slot(&vm_ref, &old).is_err() {
                // Never resume a VM whose rollback could not allocate tables.
                let _ = vm_ref.shutdown();
            }
            if let Some(ControlFileState::Vm(vm)) = CONTROL_FILES.lock().get_mut(&control_file) {
                vm.memory_slots.insert(region.slot, old);
            }
        }
        if new_slot.pinned_pages != 0 {
            let _ = api_control::release_pinned_user_pages(new_slot.pinned_pages);
        }
        return result;
    }
    if let Some(old) = old_slot {
        let _ = api_control::release_pinned_user_pages(old.pinned_pages);
    }
    if region.memory_size != 0 {
        let mut files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = files.get_mut(&control_file) else {
            drop(files);
            unmap_memory_slot(&vm_ref, new_slot);
            return ax_err!(NotFound);
        };
        vm.memory_slots.insert(region.slot, new_slot);
    }
    Ok(())
}

#[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
fn map_arm_slot(vm: &AxVMRef, slot: &MemorySlot) -> AxResult {
    let regions: alloc::vec::Vec<_> = slot
        .arm_pages
        .iter()
        .enumerate()
        .map(|(index, &hpa)| {
            (
                GuestPhysAddr::from(slot.guest_phys_addr as usize + index * abi::PAGE_SIZE_USIZE),
                hpa,
            )
        })
        .collect();
    vm.map_regions_linear(
        &regions,
        abi::PAGE_SIZE_USIZE,
        MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE | MappingFlags::USER,
    )
}

#[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
fn clean_arm_pages(pages: &[HostPhysAddr]) {
    for page in pages {
        let address =
            axvisor_api::memory::phys_to_virt(axvisor_api::memory::PhysAddr::from(page.as_usize()));
        crate::arch::clean_dcache_range(address, abi::PAGE_SIZE_USIZE);
    }
    // The VMM loads the image after registering RAM. Publish those writes
    // before the first entry, including on CPUs without IDC/DIC coherence.
    unsafe {
        core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb");
    }
}

#[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
pub(super) fn prepare_arm_execution(file: u64) -> AxResult {
    let gate = {
        let files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = files.get(&file) else {
            return ax_err!(NotFound);
        };
        if vm.arm_cache_ready {
            return Ok(());
        }
        vm.memory_gate.clone()
    };
    let _writer = gate.write();
    let pages: alloc::vec::Vec<_> = {
        let files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = files.get(&file) else {
            return ax_err!(NotFound);
        };
        if vm.arm_cache_ready {
            return Ok(());
        }
        vm.memory_slots
            .values()
            .map(|slot| slot.arm_pages.clone())
            .collect()
    };
    for group in pages {
        clean_arm_pages(&group);
    }
    let mut files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = files.get_mut(&file) else {
        return ax_err!(NotFound);
    };
    vm.arm_cache_ready = true;
    Ok(())
}

pub(in crate::kvm) fn read_userspace_memory_region(arg: usize) -> AxResult<UserspaceMemoryRegion> {
    let mut bytes = [0u8; abi::KVM_USERSPACE_MEMORY_REGION_SIZE as usize];
    api_control::copy_from_user(arg, &mut bytes)?;

    Ok(UserspaceMemoryRegion {
        slot: u32::from_ne_bytes(bytes[0..4].try_into().unwrap()),
        flags: u32::from_ne_bytes(bytes[4..8].try_into().unwrap()),
        guest_phys_addr: u64::from_ne_bytes(bytes[8..16].try_into().unwrap()),
        memory_size: u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
        userspace_addr: u64::from_ne_bytes(bytes[24..32].try_into().unwrap()),
    })
}

#[cfg(not(all(target_arch = "aarch64", feature = "arm-vhe")))]
pub(in crate::kvm) fn set_user_memory_region(
    control_file: api_control::ControlFileId,
    region: UserspaceMemoryRegion,
) -> AxResult {
    validate_memory_region(region)?;

    let mut control_files = CONTROL_FILES.lock();
    let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
        return ax_err!(NotFound);
    };

    if region.memory_size == 0 {
        if let Some(old_slot) = vm.memory_slots.remove(&region.slot) {
            unmap_memory_slot(&vm.vm, old_slot);
        }
        return Ok(());
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        let vm_ref = vm.vm.clone();
        ensure_no_memory_overlap(vm, region.slot, &region.into())?;
        drop(control_files);

        let user_address_space = api_control::retain_current_user_address_space()?;
        let pinned_result = api_control::pin_user_pages(
            user_address_space,
            region.userspace_addr as usize,
            region.memory_size as usize,
            true,
        );
        let release_result = api_control::release_user_address_space(user_address_space);
        let pinned = match pinned_result {
            Ok(pinned) => {
                if let Err(err) = release_result {
                    let _ = api_control::release_pinned_user_pages(pinned.id);
                    return Err(err);
                }
                pinned
            }
            Err(err) => {
                let _ = release_result;
                return Err(err);
            }
        };
        let pinned_pages = pinned.id;
        if let Err(err) = map_pinned_user_memory(&vm_ref, region, &pinned) {
            let _ = api_control::release_pinned_user_pages(pinned_pages);
            return Err(err);
        }
        let new_slot = MemorySlot {
            pinned_pages,
            ..region.into()
        };

        let mut control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
            unmap_memory_slot(&vm_ref, new_slot);
            return ax_err!(NotFound);
        };
        if let Err(err) = ensure_no_memory_overlap(vm, region.slot, &new_slot) {
            unmap_memory_slot(&vm_ref, new_slot);
            return Err(err);
        }
        if let Some(old_slot) = vm.memory_slots.insert(region.slot, new_slot) {
            unmap_memory_slot(&vm.vm, old_slot);
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    {
        let mut new_slot: MemorySlot = region.into();
        ensure_no_memory_overlap(vm, region.slot, &new_slot)?;
        drop(control_files);

        new_slot.user_address_space = api_control::retain_current_user_address_space()?;

        let mut control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&control_file) else {
            let _ = api_control::release_user_address_space(new_slot.user_address_space);
            return ax_err!(NotFound);
        };
        if let Err(err) = ensure_no_memory_overlap(vm, region.slot, &new_slot) {
            let _ = api_control::release_user_address_space(new_slot.user_address_space);
            return Err(err);
        }
        if let Some(old_slot) = vm.memory_slots.remove(&region.slot) {
            unmap_memory_slot(&vm.vm, old_slot);
        }
        vm.memory_slots.insert(region.slot, new_slot);
        Ok(())
    }
}

/// Resolves a KVM userspace-backed guest page after a nested page fault.
///
/// KVM memory slots describe an address translation rather than a request to
/// commit their entire userspace range. In particular, gVisor registers sparse
/// ranges that are several GiB large. Resolve only the faulting page and retain
/// its host pin until the slot is removed.
#[cfg(target_arch = "x86_64")]
pub(in crate::kvm) fn handle_memory_slot_page_fault(
    vm_file: api_control::ControlFileId,
    fault_addr: GuestPhysAddr,
    access_flags: MappingFlags,
) -> AxResult<bool> {
    handle_memory_slot_page_fault_inner(vm_file, fault_addr, access_flags, false)
}

#[cfg(target_arch = "x86_64")]
fn handle_memory_slot_page_fault_inner(
    vm_file: api_control::ControlFileId,
    fault_addr: GuestPhysAddr,
    access_flags: MappingFlags,
    prefetched: bool,
) -> AxResult<bool> {
    let fault_gpa = fault_addr.as_usize() as u64;
    let page_gpa = align_down_to_page(fault_gpa);
    let snapshot = {
        let mut control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&vm_file) else {
            return ax_err!(NotFound);
        };
        let Some((&slot_id, slot)) = memory_slot_for_gpa(vm, fault_gpa) else {
            return Ok(false);
        };
        let write_fault = access_flags.contains(MappingFlags::WRITE);
        if slot
            .mapped_pages
            .get(&page_gpa)
            .is_some_and(|page| !write_fault || page.writable)
        {
            return Ok(true);
        }
        MemorySlotSnapshot::new(slot_id, slot, page_gpa)?
    };

    // Match Linux KVM's GUP fast path: for a read fault, first try to retain a
    // writable page. If the host mapping is read-only, fall back to a normal
    // read pin. This lets the common anonymous/RAM case stay writable from the
    // first EPT mapping, avoiding a second read->write EPT fault, while still
    // preserving read-only userspace mappings and their COW semantics.
    let write_fault = access_flags.contains(MappingFlags::WRITE);
    let (pinned, writable) = if write_fault {
        (
            api_control::pin_user_pages(
                snapshot.user_address_space,
                snapshot.page_hva,
                abi::PAGE_SIZE_USIZE,
                true,
            )?,
            true,
        )
    } else {
        match api_control::pin_user_pages(
            snapshot.user_address_space,
            snapshot.page_hva,
            abi::PAGE_SIZE_USIZE,
            true,
        ) {
            Ok(pinned) => (pinned, true),
            Err(_) => (
                api_control::pin_user_pages(
                    snapshot.user_address_space,
                    snapshot.page_hva,
                    abi::PAGE_SIZE_USIZE,
                    false,
                )?,
                false,
            ),
        }
    };
    if pinned.pages.len() != 1 {
        let _ = api_control::release_pinned_user_pages(pinned.id);
        return ax_err!(InvalidInput);
    }
    let page_hpa = pinned.pages[0];

    let mut replaced_page = None;
    let result = {
        let mut control_files = CONTROL_FILES.lock();
        let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&vm_file) else {
            drop(control_files);
            let _ = api_control::release_pinned_user_pages(pinned.id);
            return ax_err!(NotFound);
        };
        let Some(slot) = vm.memory_slots.get_mut(&snapshot.slot_id) else {
            drop(control_files);
            let _ = api_control::release_pinned_user_pages(pinned.id);
            return Ok(true);
        };
        if !snapshot.matches(slot) {
            drop(control_files);
            let _ = api_control::release_pinned_user_pages(pinned.id);
            return Ok(true);
        }
        if slot
            .mapped_pages
            .get(&page_gpa)
            .is_some_and(|page| !writable || page.writable)
        {
            drop(control_files);
            let _ = api_control::release_pinned_user_pages(pinned.id);
            return Ok(true);
        }

        if let Some(old_page) = slot.mapped_pages.remove(&page_gpa) {
            vm.vm
                .unmap_region(GuestPhysAddr::from(page_gpa as usize), abi::PAGE_SIZE_USIZE)?;
            replaced_page = Some(old_page);
        }
        let mut flags = MappingFlags::READ | MappingFlags::EXECUTE | MappingFlags::USER;
        if writable {
            flags |= MappingFlags::WRITE;
        }
        match vm.vm.map_region(
            GuestPhysAddr::from(page_gpa as usize),
            HostPhysAddr::from(page_hpa.as_usize()),
            abi::PAGE_SIZE_USIZE,
            flags,
        ) {
            Ok(()) => {
                slot.mapped_pages.insert(
                    page_gpa,
                    MappedMemoryPage {
                        pinned_pages: PinnedPageGroup::new(pinned.id, 1),
                        writable,
                    },
                );
                Ok(true)
            }
            Err(err) => Err(err),
        }
    };

    if result.is_err() {
        let _ = api_control::release_pinned_user_pages(pinned.id);
    }
    if let Some(old_page) = replaced_page {
        old_page.pinned_pages.release();
    }

    // Once the faulting page is installed, opportunistically probe a bounded
    // forward window. Force COW while pinning so the EPT mapping and the VMM's
    // userspace mapping keep referring to the same page. The speculative EPT
    // entries remain read-only and are upgraded by the normal write-fault path.
    if result.is_ok() && !prefetched && write_fault {
        let slot_end = snapshot
            .guest_phys_addr
            .saturating_add(snapshot.memory_size);
        let count = ((slot_end.saturating_sub(page_gpa)) / abi::PAGE_SIZE_USIZE as u64)
            .saturating_sub(1)
            .min(63) as usize;
        if count > 0 {
            if let Ok(batch) = api_control::pin_user_pages(
                snapshot.user_address_space,
                snapshot.page_hva + abi::PAGE_SIZE_USIZE,
                count * abi::PAGE_SIZE_USIZE,
                true,
            ) {
                if batch.pages.is_empty() {
                    let _ = api_control::release_pinned_user_pages(batch.id);
                    return result;
                }
                let group = PinnedPageGroup::new(batch.id, batch.pages.len());
                let flags = MappingFlags::READ | MappingFlags::EXECUTE | MappingFlags::USER;
                let mut failed = 0usize;
                let mut control_files = CONTROL_FILES.lock();
                if let Some(ControlFileState::Vm(vm)) = control_files.get_mut(&vm_file) {
                    if let Some(slot) = vm.memory_slots.get_mut(&snapshot.slot_id) {
                        let mut regions = alloc::vec::Vec::with_capacity(batch.pages.len());
                        for (index, page_hpa) in batch.pages.iter().enumerate() {
                            let next_gpa =
                                page_gpa + (index as u64 + 1) * abi::PAGE_SIZE_USIZE as u64;
                            if snapshot.matches(slot) && !slot.mapped_pages.contains_key(&next_gpa)
                            {
                                regions.push((
                                    GuestPhysAddr::from(next_gpa as usize),
                                    HostPhysAddr::from(page_hpa.as_usize()),
                                ));
                            } else {
                                failed += 1;
                            }
                        }
                        if vm
                            .vm
                            .map_regions_linear(&regions, abi::PAGE_SIZE_USIZE, flags)
                            .is_ok()
                        {
                            for (gpa, _) in regions {
                                slot.mapped_pages.insert(
                                    gpa.as_usize() as u64,
                                    MappedMemoryPage {
                                        pinned_pages: group.clone(),
                                        writable: false,
                                    },
                                );
                            }
                        } else {
                            failed += regions.len();
                        }
                    } else {
                        failed = batch.pages.len();
                    }
                } else {
                    failed = batch.pages.len();
                }
                drop(control_files);
                for _ in 0..failed {
                    group.release();
                }
            }
        }
    }
    result
}

fn validate_memory_region(region: UserspaceMemoryRegion) -> AxResult {
    if region.slot as usize >= abi::KVM_MAX_MEMORY_SLOTS {
        return ax_err!(InvalidInput);
    }
    if region.flags & !abi::KVM_MEM_ALLOWED_FLAGS != 0 {
        return ax_err!(InvalidInput);
    }
    if !is_page_aligned(region.guest_phys_addr)
        || !is_page_aligned(region.memory_size)
        || (region.memory_size != 0 && !is_page_aligned(region.userspace_addr))
    {
        return ax_err!(InvalidInput);
    }
    region
        .guest_phys_addr
        .checked_add(region.memory_size)
        .ok_or(AxError::InvalidInput)?;
    region
        .userspace_addr
        .checked_add(region.memory_size)
        .ok_or(AxError::InvalidInput)?;
    Ok(())
}

impl From<UserspaceMemoryRegion> for MemorySlot {
    fn from(region: UserspaceMemoryRegion) -> Self {
        Self {
            #[cfg(all(target_arch = "aarch64", feature = "arm-vhe"))]
            arm_pages: Default::default(),
            flags: region.flags,
            guest_phys_addr: region.guest_phys_addr,
            memory_size: region.memory_size,
            userspace_addr: region.userspace_addr,
            user_address_space: 0,
            pinned_pages: 0,
            mapped_pages: Default::default(),
        }
    }
}

#[cfg(not(any(
    target_arch = "x86_64",
    all(target_arch = "aarch64", feature = "arm-vhe")
)))]
fn map_pinned_user_memory(
    vm: &AxVMRef,
    region: UserspaceMemoryRegion,
    pinned: &api_control::PinnedUserPages,
) -> AxResult {
    let page_count = region.memory_size as usize / abi::PAGE_SIZE_USIZE;
    if pinned.pages.len() != page_count {
        return ax_err!(InvalidInput);
    }

    let flags =
        MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE | MappingFlags::USER;
    for (mapped_pages, (page_index, page_hpa)) in pinned.pages.iter().enumerate().enumerate() {
        let page_gpa = region.guest_phys_addr as usize + page_index * abi::PAGE_SIZE_USIZE;
        if let Err(err) = vm.map_region(
            GuestPhysAddr::from(page_gpa),
            HostPhysAddr::from(page_hpa.as_usize()),
            abi::PAGE_SIZE_USIZE,
            flags,
        ) {
            for rollback_index in 0..mapped_pages {
                let rollback_gpa =
                    region.guest_phys_addr as usize + rollback_index * abi::PAGE_SIZE_USIZE;
                let _ = vm.unmap_region(GuestPhysAddr::from(rollback_gpa), abi::PAGE_SIZE_USIZE);
            }
            return Err(err);
        }
    }

    Ok(())
}

pub(in crate::kvm) fn unmap_memory_slot(vm: &AxVMRef, slot: MemorySlot) {
    if slot.pinned_pages != 0 {
        let page_count = slot.memory_size as usize / abi::PAGE_SIZE_USIZE;
        for page_index in 0..page_count {
            let page_gpa = slot.guest_phys_addr as usize + page_index * abi::PAGE_SIZE_USIZE;
            let _ = vm.unmap_region(GuestPhysAddr::from(page_gpa), abi::PAGE_SIZE_USIZE);
        }
        let _ = api_control::release_pinned_user_pages(slot.pinned_pages);
        if slot.user_address_space != 0 {
            let _ = api_control::release_user_address_space(slot.user_address_space);
        }
        return;
    }

    for (page_gpa, mapped_page) in slot.mapped_pages {
        let _ = vm.unmap_region(GuestPhysAddr::from(page_gpa as usize), abi::PAGE_SIZE_USIZE);
        mapped_page.pinned_pages.release();
    }
    if slot.user_address_space != 0 {
        let _ = api_control::release_user_address_space(slot.user_address_space);
    }
}

fn ensure_no_memory_overlap(vm: &VmFileState, slot_id: u32, new_slot: &MemorySlot) -> AxResult {
    let new_end = new_slot
        .guest_phys_addr
        .checked_add(new_slot.memory_size)
        .ok_or(AxError::InvalidInput)?;

    for (&existing_slot_id, existing_slot) in vm.memory_slots.iter() {
        if existing_slot_id == slot_id {
            continue;
        }

        let existing_end = existing_slot
            .guest_phys_addr
            .checked_add(existing_slot.memory_size)
            .ok_or(AxError::InvalidInput)?;
        if new_slot.guest_phys_addr < existing_end && existing_slot.guest_phys_addr < new_end {
            return ax_err!(InvalidInput);
        }
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
fn memory_slot_for_gpa(vm: &VmFileState, gpa: u64) -> Option<(&u32, &MemorySlot)> {
    vm.memory_slots.iter().find(|(_, slot)| {
        slot.guest_phys_addr <= gpa && gpa < slot.guest_phys_addr + slot.memory_size
    })
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MemorySlotSnapshot {
    slot_id: u32,
    page_gpa: u64,
    flags: u32,
    guest_phys_addr: u64,
    memory_size: u64,
    userspace_addr: u64,
    user_address_space: api_control::UserAddressSpaceId,
    page_hva: usize,
}

#[cfg(target_arch = "x86_64")]
impl MemorySlotSnapshot {
    fn new(slot_id: u32, slot: &MemorySlot, page_gpa: u64) -> AxResult<Self> {
        let page_offset = page_gpa
            .checked_sub(slot.guest_phys_addr)
            .ok_or(AxError::InvalidInput)?;
        let page_hva = slot
            .userspace_addr
            .checked_add(page_offset)
            .and_then(|addr| usize::try_from(addr).ok())
            .ok_or(AxError::InvalidInput)?;
        Ok(Self {
            slot_id,
            page_gpa,
            flags: slot.flags,
            guest_phys_addr: slot.guest_phys_addr,
            memory_size: slot.memory_size,
            userspace_addr: slot.userspace_addr,
            user_address_space: slot.user_address_space,
            page_hva,
        })
    }

    fn matches(self, slot: &MemorySlot) -> bool {
        self.flags == slot.flags
            && self.guest_phys_addr == slot.guest_phys_addr
            && self.memory_size == slot.memory_size
            && self.userspace_addr == slot.userspace_addr
            && self.user_address_space == slot.user_address_space
    }
}

const fn is_page_aligned(addr: u64) -> bool {
    addr & (abi::PAGE_SIZE - 1) == 0
}

#[cfg(target_arch = "x86_64")]
const fn align_down_to_page(addr: u64) -> u64 {
    addr & !(abi::PAGE_SIZE - 1)
}
