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

use core::arch::asm;

use aarch64_cpu::registers::*;
use arm_gic_driver::sys_reg::{
    ICH_AP0R0_EL2, ICH_AP0R1_EL2, ICH_AP0R2_EL2, ICH_AP0R3_EL2, ICH_AP1R0_EL2, ICH_AP1R1_EL2,
    ICH_AP1R2_EL2, ICH_AP1R3_EL2, ICH_HCR_EL2, ICH_VMCR_EL2, ICH_VTR_EL2, ich_lr_el2_get,
    ich_lr_el2_set,
};
use tock_registers::LocalRegisterCopy;

const MAX_GIC_LIST_REGISTERS: usize = 16;

/// Per-vCPU state held in the GICv3 virtual CPU interface.
#[derive(Debug, Default)]
pub(crate) struct VirtualGicState {
    vmcr: u64,
    ap0r: [u64; 4],
    ap1r: [u64; 4],
    list_registers: [u64; MAX_GIC_LIST_REGISTERS],
}

impl VirtualGicState {
    pub(crate) fn reset_timer_interrupts(&mut self) -> ax_errno::AxResult {
        let priority_bits = ICH_VTR_EL2.read(ICH_VTR_EL2::PREBITS) + 1;
        if crate::interrupt_reset::clear_timer_interrupts(
            &mut self.list_registers,
            &mut self.ap0r,
            &mut self.ap1r,
            self.vmcr,
            priority_bits as u32,
        ) {
            Ok(())
        } else {
            Err(ax_errno::AxError::Unsupported)
        }
    }

    pub(crate) fn inject_interrupt(&mut self, vector: usize) -> bool {
        const LR_PENDING: u64 = 1 << 62;
        const LR_GROUP1: u64 = 1 << 60;
        const LR_STATE_MASK: u64 = 0b11 << 62;
        const LR_VINTID_MASK: u64 = u32::MAX as u64;

        if let Some(lr) = self
            .list_registers
            .iter_mut()
            .take(gic_list_register_count())
            .find(|lr| **lr & LR_STATE_MASK != 0 && **lr & LR_VINTID_MASK == vector as u64)
        {
            *lr |= LR_PENDING;
            return true;
        }

        let Some(lr) = self
            .list_registers
            .iter_mut()
            .take(gic_list_register_count())
            .find(|lr| **lr & LR_STATE_MASK == 0)
        else {
            return false;
        };
        *lr = vector as u64 | LR_GROUP1 | LR_PENDING;
        true
    }

    pub(crate) unsafe fn save(&mut self) {
        unsafe {
            ICH_HCR_EL2.set(0);
            asm!("dsb sy", "isb");
            self.vmcr = ICH_VMCR_EL2.get();
            save_active_priorities(&mut self.ap0r, &mut self.ap1r);
            for (index, lr) in self
                .list_registers
                .iter_mut()
                .take(gic_list_register_count())
                .enumerate()
            {
                *lr = ich_lr_el2_get(index).get();
            }
        }
    }

    pub(crate) unsafe fn restore(&self) {
        unsafe {
            ICH_VMCR_EL2.set(self.vmcr);
            restore_active_priorities(&self.ap0r, &self.ap1r);
            for (index, &lr) in self
                .list_registers
                .iter()
                .take(gic_list_register_count())
                .enumerate()
            {
                ich_lr_el2_set(index, LocalRegisterCopy::new(lr));
            }
            asm!("isb");
        }
    }
}

fn gic_list_register_count() -> usize {
    (ICH_VTR_EL2.read(ICH_VTR_EL2::LISTREGS) as usize + 1).min(MAX_GIC_LIST_REGISTERS)
}

fn gic_active_priority_register_count() -> usize {
    match ICH_VTR_EL2.read(ICH_VTR_EL2::PREBITS) + 1 {
        7 => 4,
        6 => 2,
        _ => 1,
    }
}

unsafe fn save_active_priorities(ap0r: &mut [u64; 4], ap1r: &mut [u64; 4]) {
    ap0r[0] = ICH_AP0R0_EL2.get();
    ap1r[0] = ICH_AP1R0_EL2.get();
    if gic_active_priority_register_count() >= 2 {
        ap0r[1] = ICH_AP0R1_EL2.get();
        ap1r[1] = ICH_AP1R1_EL2.get();
    }
    if gic_active_priority_register_count() == 4 {
        ap0r[2] = ICH_AP0R2_EL2.get();
        ap0r[3] = ICH_AP0R3_EL2.get();
        ap1r[2] = ICH_AP1R2_EL2.get();
        ap1r[3] = ICH_AP1R3_EL2.get();
    }
}

unsafe fn restore_active_priorities(ap0r: &[u64; 4], ap1r: &[u64; 4]) {
    ICH_AP0R0_EL2.set(ap0r[0]);
    ICH_AP1R0_EL2.set(ap1r[0]);
    if gic_active_priority_register_count() >= 2 {
        ICH_AP0R1_EL2.set(ap0r[1]);
        ICH_AP1R1_EL2.set(ap1r[1]);
    }
    if gic_active_priority_register_count() == 4 {
        ICH_AP0R2_EL2.set(ap0r[2]);
        ICH_AP0R3_EL2.set(ap0r[3]);
        ICH_AP1R2_EL2.set(ap1r[2]);
        ICH_AP1R3_EL2.set(ap1r[3]);
    }
}

/// Floating-point and SIMD state switched between the host and guest.
#[repr(C, align(16))]
#[derive(Debug, Default)]
pub(crate) struct FpState {
    regs: [u128; 32],
    fpcr: u32,
    fpsr: u32,
}

impl FpState {
    pub(crate) fn save(&mut self) {
        unsafe { fpstate_save(self) }
    }

    pub(crate) fn restore(&self) {
        unsafe { fpstate_restore(self) }
    }
}

#[unsafe(naked)]
unsafe extern "C" fn fpstate_save(_state: &mut FpState) {
    core::arch::naked_asm!(
        ".arch armv8",
        "mrs x9, fpcr",
        "mrs x10, fpsr",
        "str w9, [x0, 32 * 16]",
        "str w10, [x0, 32 * 16 + 4]",
        "st1 {{v0.16b-v3.16b}}, [x0], #64",
        "st1 {{v4.16b-v7.16b}}, [x0], #64",
        "st1 {{v8.16b-v11.16b}}, [x0], #64",
        "st1 {{v12.16b-v15.16b}}, [x0], #64",
        "st1 {{v16.16b-v19.16b}}, [x0], #64",
        "st1 {{v20.16b-v23.16b}}, [x0], #64",
        "st1 {{v24.16b-v27.16b}}, [x0], #64",
        "st1 {{v28.16b-v31.16b}}, [x0], #64",
        "ret",
    )
}

#[unsafe(naked)]
unsafe extern "C" fn fpstate_restore(_state: &FpState) {
    core::arch::naked_asm!(
        ".arch armv8",
        "ldr w9, [x0, 32 * 16]",
        "ldr w10, [x0, 32 * 16 + 4]",
        "ld1 {{v0.16b-v3.16b}}, [x0], #64",
        "ld1 {{v4.16b-v7.16b}}, [x0], #64",
        "ld1 {{v8.16b-v11.16b}}, [x0], #64",
        "ld1 {{v12.16b-v15.16b}}, [x0], #64",
        "ld1 {{v16.16b-v19.16b}}, [x0], #64",
        "ld1 {{v20.16b-v23.16b}}, [x0], #64",
        "ld1 {{v24.16b-v27.16b}}, [x0], #64",
        "ld1 {{v28.16b-v31.16b}}, [x0], #64",
        "msr fpcr, x9",
        "msr fpsr, x10",
        "isb",
        "ret",
    )
}

/// Host register state overwritten while a guest is active.
#[derive(Default)]
pub(crate) struct HostSystemRegisters {
    daif: u64,
    hcr_el2: u64,
    vbar_el2: u64,
    cptr_el2: u64,
    cnthctl_el2: u64,
    cntvoff_el2: u64,
    vtcr_el2: u64,
    vttbr_el2: u64,
    vmpidr_el2: u64,
    ich_hcr_el2: u64,
    tpidr_el0: u64,
    tpidrro_el0: u64,
    sp_el0: u64,
}

impl HostSystemRegisters {
    pub(crate) unsafe fn store(&mut self) {
        unsafe {
            asm!("mrs {0}, DAIF", out(reg) self.daif);
            asm!("msr daifset, #2");
            asm!("mrs {0}, HCR_EL2", out(reg) self.hcr_el2);
            asm!("mrs {0}, VBAR_EL2", out(reg) self.vbar_el2);
            asm!("mrs {0}, CPTR_EL2", out(reg) self.cptr_el2);
            asm!("mrs {0}, CNTHCTL_EL2", out(reg) self.cnthctl_el2);
            asm!("mrs {0}, CNTVOFF_EL2", out(reg) self.cntvoff_el2);
            asm!("mrs {0}, VTCR_EL2", out(reg) self.vtcr_el2);
            asm!("mrs {0}, VTTBR_EL2", out(reg) self.vttbr_el2);
            asm!("mrs {0}, VMPIDR_EL2", out(reg) self.vmpidr_el2);
            asm!("mrs {0}, ICH_HCR_EL2", out(reg) self.ich_hcr_el2);
            asm!("mrs {0}, TPIDR_EL0", out(reg) self.tpidr_el0);
            asm!("mrs {0}, TPIDRRO_EL0", out(reg) self.tpidrro_el0);
            asm!("mrs {0}, SP_EL0", out(reg) self.sp_el0);
        }
    }

    pub(crate) fn vhe_enabled(&self) -> bool {
        self.hcr_el2 & HCR_EL2::E2H::SET.value != 0
    }

    pub(crate) unsafe fn restore(&self) {
        unsafe {
            // Re-establish the saved register view first. All exceptions remain
            // masked until the complete host state is back in place.
            asm!("msr HCR_EL2, {0}", in(reg) self.hcr_el2);
            asm!("isb");
            asm!("msr CPTR_EL2, {0}", in(reg) self.cptr_el2);
            asm!("msr CNTHCTL_EL2, {0}", in(reg) self.cnthctl_el2);
            asm!("msr CNTVOFF_EL2, {0}", in(reg) self.cntvoff_el2);
            asm!("msr VTCR_EL2, {0}", in(reg) self.vtcr_el2);
            asm!("msr VTTBR_EL2, {0}", in(reg) self.vttbr_el2);
            asm!("msr VMPIDR_EL2, {0}", in(reg) self.vmpidr_el2);
            asm!("msr ICH_HCR_EL2, {0}", in(reg) self.ich_hcr_el2);
            asm!("msr TPIDR_EL0, {0}", in(reg) self.tpidr_el0);
            asm!("msr TPIDRRO_EL0, {0}", in(reg) self.tpidrro_el0);
            asm!("msr SP_EL0, {0}", in(reg) self.sp_el0);
            asm!("msr VBAR_EL2, {0}", in(reg) self.vbar_el2);
            asm!("isb");
        }
    }

    pub(crate) unsafe fn restore_daif(&self) {
        unsafe { asm!("msr DAIF, {0}", in(reg) self.daif) }
    }
}

/// Represents the VM context for a guest virtual machine in a hypervisor environment.
///
/// The `GuestSystemRegisters` structure contains various registers and states needed to manage
/// and restore the context of a virtual machine (VM). This includes timer registers,
/// system control registers, exception registers, and hypervisor-specific registers.
///
/// The structure is aligned to 16 bytes to ensure proper memory alignment for efficient access.
#[repr(C)]
#[repr(align(16))]
#[derive(Debug, Clone, Copy, Default)]
pub struct GuestSystemRegisters {
    // generic timer
    pub cntvoff_el2: u64,
    pub(crate) cntp_cval_el0: u64,
    pub(crate) cntv_cval_el0: u64,
    pub cntkctl_el1: u32,
    pub(crate) cntp_ctl_el0: u32,
    pub(crate) cntv_ctl_el0: u32,
    pub cnthctl_el2: u64,

    // virtual MPIDR
    pub vmpidr_el2: u64,

    // 64bit EL1/EL0 register
    sp_el1: u64,
    elr_el1: u64,
    spsr_el1: u32,
    pub sctlr_el1: u32,
    actlr_el1: u64,
    cpacr_el1: u32,
    ttbr0_el1: u64,
    ttbr1_el1: u64,
    tcr_el1: u64,
    esr_el1: u32,
    far_el1: u64,
    par_el1: u64,
    mair_el1: u64,
    amair_el1: u64,
    vbar_el1: u64,
    contextidr_el1: u32,
    tpidr_el0: u64,
    tpidr_el1: u64,
    tpidrro_el0: u64,

    // hypervisor context
    pub hcr_el2: u64,
    pub vttbr_el2: u64,
    pub pmcr_el0: u64,
    pub vtcr_el2: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuestTimerRegisters {
    cntvoff_el2: u64,
    cntp_cval_el0: u64,
    cntv_cval_el0: u64,
    cntkctl_el1: u32,
    cntp_ctl_el0: u32,
    cntv_ctl_el0: u32,
    cnthctl_el2: u64,
}

impl GuestSystemRegisters {
    /// Reset an offline vCPU's EL1/EL0 state without changing its VM resources
    /// or virtual-counter epoch. CPU_ON must not restart the VM-wide clock.
    pub(crate) fn reset_for_cpu_on(&mut self, be: bool) {
        *self = Self {
            cntvoff_el2: self.cntvoff_el2,
            cnthctl_el2: self.cnthctl_el2,
            vmpidr_el2: self.vmpidr_el2,
            hcr_el2: self.hcr_el2,
            vttbr_el2: self.vttbr_el2,
            vtcr_el2: self.vtcr_el2,
            sctlr_el1: 0x30c5_0830 | if be { 1 << 25 } else { 0 },
            ..Self::default()
        };
    }

    pub(crate) fn sp_el1(&self) -> u64 {
        self.sp_el1
    }

    pub(crate) fn set_sp_el1(&mut self, value: u64) {
        self.sp_el1 = value;
    }

    /// Resets the VM context by setting all registers to zero.
    ///
    /// This method allows the `GuestSystemRegisters` instance to be reused by resetting
    /// its state to the default values (all zeros).
    #[allow(unused)]
    pub fn reset(&mut self) {
        *self = GuestSystemRegisters::default()
    }

    /// Stores the current values of all relevant registers into the `GuestSystemRegisters` structure.
    ///
    /// This method uses inline assembly to read the values of various system registers
    /// and stores them in the corresponding fields of the `GuestSystemRegisters` structure.
    pub unsafe fn store(&mut self, vhe: bool) {
        unsafe {
            if vhe {
                asm!("mrs {0}, S3_5_C14_C2_2", out(reg) self.cntp_cval_el0);
                asm!("mrs {0}, S3_5_C14_C3_2", out(reg) self.cntv_cval_el0);
                asm!("mrs {0:x}, S3_5_C14_C1_0", out(reg) self.cntkctl_el1);
                asm!("mrs {0:x}, S3_5_C14_C2_1", out(reg) self.cntp_ctl_el0);
                asm!("mrs {0:x}, S3_5_C14_C3_1", out(reg) self.cntv_ctl_el0);
            } else {
                asm!("mrs {0}, CNTP_CVAL_EL0", out(reg) self.cntp_cval_el0);
                asm!("mrs {0}, CNTV_CVAL_EL0", out(reg) self.cntv_cval_el0);
                asm!("mrs {0:x}, CNTKCTL_EL1", out(reg) self.cntkctl_el1);
                asm!("mrs {0:x}, CNTP_CTL_EL0", out(reg) self.cntp_ctl_el0);
                asm!("mrs {0:x}, CNTV_CTL_EL0", out(reg) self.cntv_ctl_el0);
            }
            // TVAL registers are intentionally NOT saved.
            // They are derived values (TVAL = CVAL - CNTVCT) and restoring them
            // would overwrite CVAL with an incorrect deadline. See restore().
            asm!("mrs {0}, SP_EL1", out(reg) self.sp_el1);
            if vhe {
                asm!("mrs {0}, S3_5_C4_C0_1", out(reg) self.elr_el1);
                asm!("mrs {0:x}, S3_5_C4_C0_0", out(reg) self.spsr_el1);
                asm!("mrs {0:x}, S3_5_C1_C0_0", out(reg) self.sctlr_el1);
                asm!("mrs {0:x}, S3_5_C1_C0_2", out(reg) self.cpacr_el1);
                asm!("mrs {0}, S3_5_C2_C0_0", out(reg) self.ttbr0_el1);
                asm!("mrs {0}, S3_5_C2_C0_1", out(reg) self.ttbr1_el1);
                asm!("mrs {0}, S3_5_C2_C0_2", out(reg) self.tcr_el1);
                asm!("mrs {0:x}, S3_5_C5_C2_0", out(reg) self.esr_el1);
                asm!("mrs {0}, S3_5_C6_C0_0", out(reg) self.far_el1);
            } else {
                asm!("mrs {0}, ELR_EL1", out(reg) self.elr_el1);
                asm!("mrs {0:x}, SPSR_EL1", out(reg) self.spsr_el1);
                asm!("mrs {0:x}, SCTLR_EL1", out(reg) self.sctlr_el1);
                asm!("mrs {0:x}, CPACR_EL1", out(reg) self.cpacr_el1);
                asm!("mrs {0}, TTBR0_EL1", out(reg) self.ttbr0_el1);
                asm!("mrs {0}, TTBR1_EL1", out(reg) self.ttbr1_el1);
                asm!("mrs {0}, TCR_EL1", out(reg) self.tcr_el1);
                asm!("mrs {0:x}, ESR_EL1", out(reg) self.esr_el1);
                asm!("mrs {0}, FAR_EL1", out(reg) self.far_el1);
            }
            asm!("mrs {0}, PAR_EL1", out(reg) self.par_el1);
            if vhe {
                asm!("mrs {0}, S3_5_C10_C2_0", out(reg) self.mair_el1);
                asm!("mrs {0}, S3_5_C10_C3_0", out(reg) self.amair_el1);
                asm!("mrs {0}, S3_5_C12_C0_0", out(reg) self.vbar_el1);
                asm!("mrs {0:x}, S3_5_C13_C0_1", out(reg) self.contextidr_el1);
            } else {
                asm!("mrs {0}, MAIR_EL1", out(reg) self.mair_el1);
                asm!("mrs {0}, AMAIR_EL1", out(reg) self.amair_el1);
                asm!("mrs {0}, VBAR_EL1", out(reg) self.vbar_el1);
                asm!("mrs {0:x}, CONTEXTIDR_EL1", out(reg) self.contextidr_el1);
            }
            asm!("mrs {0}, TPIDR_EL0", out(reg) self.tpidr_el0);
            asm!("mrs {0}, TPIDR_EL1", out(reg) self.tpidr_el1);
            asm!("mrs {0}, TPIDRRO_EL0", out(reg) self.tpidrro_el0);

            if vhe {
                // Prevent live guest timer PPIs from remaining asserted after
                // returning to the VHE execution context.
                asm!(
                    "orr x9, {cntp_ctl:x}, #2\n\
                     msr S3_5_C14_C2_1, x9\n\
                     orr x9, {cntv_ctl:x}, #2\n\
                     msr S3_5_C14_C3_1, x9\n\
                     isb",
                    cntp_ctl = in(reg) self.cntp_ctl_el0,
                    cntv_ctl = in(reg) self.cntv_ctl_el0,
                    out("x9") _,
                );
            } else {
                asm!("mrs {0}, PMCR_EL0", out(reg) self.pmcr_el0);
                asm!("mrs {0}, ACTLR_EL1", out(reg) self.actlr_el1);
            }
            // println!("save sctlr {:x}", self.sctlr_el1);
        }
    }

    /// Restores the values of all relevant system registers from the `GuestSystemRegisters` structure.
    ///
    /// This method uses inline assembly to write the values stored in the `GuestSystemRegisters` structure
    /// back to the system registers. This is essential for restoring the state of a virtual machine
    /// or thread during context switching.
    ///
    /// Each system register is restored with its corresponding value from the `GuestSystemRegisters`, ensuring
    /// that the virtual machine or thread resumes execution with the correct context.
    pub unsafe fn restore(&self, vhe: bool) {
        unsafe {
            asm!("msr VTCR_EL2, {0}", in(reg) self.vtcr_el2);
            asm!("msr VTTBR_EL2, {0}", in(reg) self.vttbr_el2);
            // Keep the active VHE register view while the S3_5_* encodings
            // below access the guest EL1 register bank from EL2.
            let hcr = self.hcr_el2 | if vhe { HCR_EL2::E2H::SET.value } else { 0 };
            asm!("msr HCR_EL2, {0}", in(reg) hcr);
            asm!("isb");

            let timer = self.timer_registers();
            asm!("msr CNTVOFF_EL2, {0}", in(reg) timer.cntvoff_el2);
            if vhe {
                asm!("msr S3_5_C14_C1_0, {0:x}", in (reg) timer.cntkctl_el1);
            } else {
                asm!("msr CNTKCTL_EL1, {0:x}", in (reg) timer.cntkctl_el1);
            }
            asm!("msr CNTHCTL_EL2, {0}", in(reg) timer.cnthctl_el2);

            // Restore CTL first (with ENABLE cleared to avoid spurious interrupts),
            // then CVAL (absolute deadline), then CTL again with the real value.
            //
            // IMPORTANT: Do NOT restore TVAL registers here!
            // Writing CNTP_TVAL_EL0 / CNTV_TVAL_EL0 implicitly overwrites the
            // corresponding CVAL register (CVAL = CNTVCT + TVAL). Because the
            // counter (CNTVCT/CNTPCT) has advanced since the values were saved,
            // restoring TVAL would push the timer deadline into the future on every
            // VM exit, causing guest timers (e.g. nanosleep / timerfd) to never fire.
            // Restoring only CVAL preserves the original absolute deadline.
            if vhe {
                asm!("msr S3_5_C14_C2_1, xzr");
                asm!("msr S3_5_C14_C3_1, xzr");
                asm!("msr S3_5_C14_C2_2, {0}", in(reg) timer.cntp_cval_el0);
                asm!("msr S3_5_C14_C3_2, {0}", in(reg) timer.cntv_cval_el0);
                asm!("msr S3_5_C14_C2_1, {0:x}", in(reg) timer.cntp_ctl_el0);
                asm!("msr S3_5_C14_C3_1, {0:x}", in(reg) timer.cntv_ctl_el0);
            } else {
                asm!("msr CNTP_CTL_EL0, xzr");
                asm!("msr CNTV_CTL_EL0, xzr");
                asm!("msr CNTP_CVAL_EL0, {0}", in(reg) timer.cntp_cval_el0);
                asm!("msr CNTV_CVAL_EL0, {0}", in(reg) timer.cntv_cval_el0);
                asm!("msr CNTP_CTL_EL0, {0:x}", in(reg) timer.cntp_ctl_el0);
                asm!("msr CNTV_CTL_EL0, {0:x}", in(reg) timer.cntv_ctl_el0);
            }
            // The restoration of SP_EL0 is done in `exception_return_el2`,
            // which move the value from `self.ctx.sp_el0` to `SP_EL0`.
            // asm!("msr SP_EL0, {0}", in(reg) self.sp_el0);
            asm!("msr SP_EL1, {0}", in(reg) self.sp_el1);
            if vhe {
                asm!("msr S3_5_C4_C0_1, {0}", in(reg) self.elr_el1);
                asm!("msr S3_5_C4_C0_0, {0:x}", in(reg) self.spsr_el1);
                asm!("msr S3_5_C1_C0_0, {0:x}", in(reg) self.sctlr_el1);
                asm!("msr S3_5_C1_C0_2, {0:x}", in(reg) self.cpacr_el1);
                asm!("msr S3_5_C2_C0_0, {0}", in(reg) self.ttbr0_el1);
                asm!("msr S3_5_C2_C0_1, {0}", in(reg) self.ttbr1_el1);
                asm!("msr S3_5_C2_C0_2, {0}", in(reg) self.tcr_el1);
                asm!("msr S3_5_C5_C2_0, {0:x}", in(reg) self.esr_el1);
                asm!("msr S3_5_C6_C0_0, {0}", in(reg) self.far_el1);
            } else {
                asm!("msr ELR_EL1, {0}", in(reg) self.elr_el1);
                asm!("msr SPSR_EL1, {0:x}", in(reg) self.spsr_el1);
                asm!("msr SCTLR_EL1, {0:x}", in(reg) self.sctlr_el1);
                asm!("msr CPACR_EL1, {0:x}", in(reg) self.cpacr_el1);
                asm!("msr TTBR0_EL1, {0}", in(reg) self.ttbr0_el1);
                asm!("msr TTBR1_EL1, {0}", in(reg) self.ttbr1_el1);
                asm!("msr TCR_EL1, {0}", in(reg) self.tcr_el1);
                asm!("msr ESR_EL1, {0:x}", in(reg) self.esr_el1);
                asm!("msr FAR_EL1, {0}", in(reg) self.far_el1);
            }
            asm!("msr PAR_EL1, {0}", in(reg) self.par_el1);
            if vhe {
                asm!("msr S3_5_C10_C2_0, {0}", in(reg) self.mair_el1);
                asm!("msr S3_5_C10_C3_0, {0}", in(reg) self.amair_el1);
                asm!("msr S3_5_C12_C0_0, {0}", in(reg) self.vbar_el1);
                asm!("msr S3_5_C13_C0_1, {0:x}", in(reg) self.contextidr_el1);
            } else {
                asm!("msr MAIR_EL1, {0}", in(reg) self.mair_el1);
                asm!("msr AMAIR_EL1, {0}", in(reg) self.amair_el1);
                asm!("msr VBAR_EL1, {0}", in(reg) self.vbar_el1);
                asm!("msr CONTEXTIDR_EL1, {0:x}", in(reg) self.contextidr_el1);
            }
            asm!("msr TPIDR_EL0, {0}", in(reg) self.tpidr_el0);
            asm!("msr TPIDR_EL1, {0}", in(reg) self.tpidr_el1);
            asm!("msr TPIDRRO_EL0, {0}", in(reg) self.tpidrro_el0);

            if !vhe {
                asm!("msr PMCR_EL0, {0}", in(reg) self.pmcr_el0);
                asm!("msr ACTLR_EL1, {0}", in(reg) self.actlr_el1);
            }

            asm!("msr VMPIDR_EL2, {0}", in(reg) self.vmpidr_el2);
        }
    }

    fn timer_registers(&self) -> GuestTimerRegisters {
        GuestTimerRegisters {
            cntvoff_el2: self.cntvoff_el2,
            cntp_cval_el0: self.cntp_cval_el0,
            cntv_cval_el0: self.cntv_cval_el0,
            cntkctl_el1: self.cntkctl_el1,
            cntp_ctl_el0: self.cntp_ctl_el0,
            cntv_ctl_el0: self.cntv_ctl_el0,
            cnthctl_el2: self.cnthctl_el2,
        }
    }
}
