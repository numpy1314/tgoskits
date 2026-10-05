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

#![no_std]
#![cfg(target_arch = "aarch64")]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate log;
#[cfg(feature = "vhe")]
extern crate alloc;

mod context_frame;
#[macro_use]
mod exception_utils;
mod exception;
#[cfg(not(feature = "vhe"))]
mod pcpu;
mod smc;
mod vcpu;

#[cfg(feature = "vhe")]
pub mod vhe;
#[cfg(feature = "vhe")]
mod vhe_regs;
#[cfg(feature = "vhe")]
mod vhe_stage2;
#[cfg(feature = "vhe-selftest")]
pub mod vhe_test;

#[cfg(not(feature = "vhe"))]
pub use self::{
    pcpu::Aarch64PerCpu,
    vcpu::{Aarch64VCpu, Aarch64VCpuCreateConfig, Aarch64VCpuSetupConfig},
};
#[cfg(feature = "vhe")]
pub use self::{
    vcpu::{Aarch64VCpuCreateConfig, Aarch64VCpuSetupConfig},
    vhe::{PerCpu as Aarch64PerCpu, Vcpu as Aarch64VCpu},
};

/// context frame for aarch64
pub type TrapFrame = context_frame::Aarch64ContextFrame;

/// Returns the page table depth used by the shared address-space manager.
///
/// Hosted VHE uses a four-level software tree and, where required, a
/// concatenated hardware L1 root. The standalone backend selects by PA size:
/// - 44+ bit PA → 4 levels (48-bit IPA)
/// - < 44 bit PA → 3 levels (39-bit IPA)
pub fn max_guest_page_table_levels() -> usize {
    #[cfg(feature = "vhe")]
    return 4;
    #[cfg(not(feature = "vhe"))]
    vcpu::max_gpt_level(vcpu::pa_bits())
}

/// Return if current platform support virtualization extension.
pub fn has_hardware_support() -> bool {
    #[cfg(feature = "vhe")]
    {
        let el: u64;
        let mmfr1: u64;
        unsafe {
            core::arch::asm!("mrs {}, CurrentEL", "mrs {}, id_aa64mmfr1_el1", out(reg) el, out(reg) mmfr1);
        }
        el == 8 && (mmfr1 >> 8) & 15 == 1
    }
    #[cfg(not(feature = "vhe"))]
    true
}
