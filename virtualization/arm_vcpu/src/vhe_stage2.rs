// SPDX-License-Identifier: Apache-2.0
//! Hardware root for CPUs that cannot start Stage-2 translation at level 0.
use ax_errno::{AxError, AxResult};
use axvisor_api::memory::{self, PhysAddr};

/// A 40/42-bit IPA requires 2/8 concatenated L1 tables on a 40/42-bit CPU.
/// The shared address-space manager retains its ordinary four-level tree.
#[derive(Debug)]
pub(super) struct ConcatRoot {
    base: PhysAddr,
    pages: usize,
}

impl ConcatRoot {
    pub fn new(ipa_bits: usize) -> AxResult<Self> {
        let pages = 1 << (ipa_bits - 39);
        let base = memory::alloc_contiguous_frames(pages, pages * 4096).ok_or(AxError::NoMemory)?;
        Ok(Self { base, pages })
    }

    pub fn address(&self) -> u64 {
        self.base.as_usize() as u64
    }

    /// Refresh while guest entries are quiescent with respect to mapping edits.
    ///
    /// # Safety
    /// `software_root` is a live four-level table tree owned by this VM.
    pub unsafe fn refresh(&self, software_root: u64) -> AxResult {
        let root =
            memory::phys_to_virt(PhysAddr::from(software_root as usize)).as_usize() as *const u64;
        let destination = memory::phys_to_virt(self.base).as_usize() as *mut u8;
        for index in 0..self.pages {
            let entry = unsafe { root.add(index).read() };
            if entry & 1 == 0 {
                unsafe {
                    core::ptr::write_bytes(destination.add(index * 4096), 0, 4096);
                }
            } else if entry & 3 == 3 {
                let pa = PhysAddr::from((entry & 0x0000_ffff_ffff_f000) as usize);
                let source = memory::phys_to_virt(pa).as_usize() as *const u8;
                unsafe {
                    core::ptr::copy_nonoverlapping(source, destination.add(index * 4096), 4096);
                }
            } else {
                return Err(AxError::BadState);
            }
        }
        unsafe {
            core::arch::asm!("dsb ishst");
        }
        Ok(())
    }
}

impl Drop for ConcatRoot {
    fn drop(&mut self) {
        memory::dealloc_contiguous_frames(self.base, self.pages);
    }
}
