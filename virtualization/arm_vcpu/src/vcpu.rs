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

use alloc::boxed::Box;

use aarch64_cpu::registers::*;
use ax_errno::AxResult;
use axaddrspace::{GuestPhysAddr, HostPhysAddr, device::SysRegAddr};
use axvcpu::{AxArchVCpu, AxVCpuExitReason};

use crate::{
    TrapFrame,
    exception::{TrapKind, handle_exception_sync},
    exception_utils::exception_class_value,
    state::{FpState, GuestSystemRegisters, HostSystemRegisters, VirtualGicState},
};

mod kvm_regs;

unsafe extern "C" {
    fn exception_vector_base_vcpu();
}

/// (v)CPU register state that must be saved or restored when entering/exiting a VM or switching
/// between VMs.
#[repr(C)]
#[derive(Clone, Debug, Copy, Default)]
#[allow(dead_code)]
pub struct VmCpuRegisters {
    /// guest trap context
    pub trap_context_regs: TrapFrame,
    /// virtual machine system regs setting
    pub vm_system_regs: GuestSystemRegisters,
}

/// A virtual CPU within a guest
#[repr(C)]
#[derive(Debug)]
pub struct Aarch64VCpu {
    // DO NOT modify `guest_regs` and `host_stack_top` and their order unless you do know what you are doing!
    // DO NOT add anything before or between them unless you do know what you are doing!
    ctx: TrapFrame,
    host_stack_top: u64,
    guest_system_regs: GuestSystemRegisters,
    virtual_gic_state: Box<VirtualGicState>,
    fp_state: Box<FpState>,
    /// The MPIDR_EL1 value for the vCPU.
    mpidr: u64,
}

/// Configuration for creating a new `Aarch64VCpu`
#[derive(Clone, Debug, Default)]
pub struct Aarch64VCpuCreateConfig {
    /// The MPIDR_EL1 value for the new vCPU,
    /// which is used to identify the CPU in a multiprocessor system.
    /// Note: mind CPU cluster.
    // FIXME: Handle its interaction with the virtual GIC.
    pub mpidr_el1: u64,
    /// The address of the device tree blob.
    pub dtb_addr: usize,
}

/// Configuration for setting up a new `Aarch64VCpu`
#[derive(Clone, Debug, Default)]
pub struct Aarch64VCpuSetupConfig {
    /// Should the hypervisor passthrough interrupts to the guest?
    pub passthrough_interrupt: bool,
    /// Should the hypervisor passthrough timers to the guest?
    pub passthrough_timer: bool,
}

impl axvcpu::AxArchVCpu for Aarch64VCpu {
    type CreateConfig = Aarch64VCpuCreateConfig;

    type SetupConfig = Aarch64VCpuSetupConfig;

    fn new(_vm_id: usize, _vcpu_id: usize, config: Self::CreateConfig) -> AxResult<Self> {
        let mut ctx = TrapFrame::default();
        ctx.set_argument(config.dtb_addr);

        let fp_state = Box::<FpState>::new_zeroed();
        let virtual_gic_state = Box::<VirtualGicState>::new_zeroed();

        Ok(Self {
            ctx,
            host_stack_top: 0,
            guest_system_regs: GuestSystemRegisters::default(),
            // SAFETY: VirtualGicState contains only integers and has no invalid bit patterns.
            virtual_gic_state: unsafe { virtual_gic_state.assume_init() },
            // SAFETY: FpState contains only integers and has no invalid bit patterns.
            fp_state: unsafe { fp_state.assume_init() },
            mpidr: config.mpidr_el1,
        })
    }

    fn setup(&mut self, config: Self::SetupConfig) -> AxResult {
        self.init_hv(config);
        Ok(())
    }

    fn set_entry(&mut self, entry: GuestPhysAddr) -> AxResult {
        debug!("set vcpu entry:{entry:?}");
        self.set_elr(entry.as_usize());
        Ok(())
    }

    fn set_ept_root(&mut self, ept_root: HostPhysAddr) -> AxResult {
        debug!("set vcpu ept root:{ept_root:#x}");
        self.guest_system_regs.vttbr_el2 = ept_root.as_usize() as u64;
        Ok(())
    }

    fn run(&mut self) -> AxResult<AxVCpuExitReason> {
        let mut host_system_regs = HostSystemRegisters::default();
        let mut host_fp_state = FpState::default();
        let host_vhe;

        // Run guest.
        let exit_reson = unsafe {
            // Save host state before selecting the guest register banks.
            host_system_regs.store();
            host_vhe = host_system_regs.vhe_enabled();
            host_fp_state.save();
            VBAR_EL2.set(exception_vector_base_vcpu as *const () as usize as _);
            self.restore_vm_system_regs(host_vhe);
            self.virtual_gic_state.restore();
            self.fp_state.restore();
            self.run_guest()
        };

        unsafe {
            // Save all guest state while HCR_EL2 still selects the guest EL1
            // register bank, then restore the host state before executing the
            // regular VM-exit handler.
            self.fp_state.save();
            self.virtual_gic_state.save();
            self.guest_system_regs.store(host_vhe);
            host_system_regs.restore();
            host_fp_state.restore();
            host_system_regs.restore_daif();
        };

        let trap_kind = TrapKind::try_from(exit_reson as u8).expect("Invalid TrapKind");
        self.vmexit_handler(trap_kind)
    }

    fn bind(&mut self) -> AxResult {
        Ok(())
    }

    fn unbind(&mut self) -> AxResult {
        Ok(())
    }

    fn set_gpr(&mut self, idx: usize, val: usize) {
        self.ctx.set_gpr(idx, val);
    }

    fn get_arch_reg(&self, reg_id: u64) -> AxResult<u64> {
        self.get_kvm_arch_reg(reg_id)
    }

    fn arch_reg_ids(&self) -> &'static [u64] {
        self.kvm_arch_reg_ids()
    }

    fn set_arch_reg(&mut self, reg_id: u64, value: u64) -> AxResult {
        self.set_kvm_arch_reg(reg_id, value)
    }

    fn inject_interrupt(&mut self, vector: usize) -> AxResult {
        if self.virtual_gic_state.inject_interrupt(vector) {
            Ok(())
        } else {
            ax_errno::ax_err!(ResourceBusy, "No free GIC list register")
        }
    }

    fn set_return_value(&mut self, val: usize) {
        // Return value is stored in x0.
        self.ctx.set_argument(val);
    }
}

// Private function
impl Aarch64VCpu {
    /// Apply a queued PSCI CPU_ON reset to this vCPU's saved state.
    ///
    /// The caller must own the target vCPU outside guest execution. VM memory,
    /// MPIDR, Stage-2 configuration, virtual-counter offset and queued VGIC
    /// interrupts other than the reset timer outputs remain attached to this
    /// vCPU. All ordinary guest registers,
    /// FP/SIMD state and local timer programming start from reset values.
    pub fn reset_guest_state(&mut self, pc: u64, arg: u64, be: bool) -> AxResult {
        if pc & 3 != 0 {
            return Err(ax_errno::AxError::InvalidInput);
        }
        self.virtual_gic_state.reset_timer_interrupts()?;
        self.ctx = TrapFrame::default();
        self.ctx.elr = pc;
        self.ctx.gpr[0] = arg;
        self.host_stack_top = 0;
        self.guest_system_regs.reset_for_cpu_on(be);
        *self.fp_state = FpState::default();
        Ok(())
    }

    fn init_hv(&mut self, config: Aarch64VCpuSetupConfig) {
        self.ctx.spsr = (SPSR_EL1::M::EL1h
            + SPSR_EL1::I::Masked
            + SPSR_EL1::F::Masked
            + SPSR_EL1::A::Masked
            + SPSR_EL1::D::Masked)
            .value;
        self.init_vm_context(config);
    }

    /// Init guest context. Also set some el2 register value.
    fn init_vm_context(&mut self, config: Aarch64VCpuSetupConfig) {
        // CNTHCTL_EL2.modify(CNTHCTL_EL2::EL1PCEN::SET + CNTHCTL_EL2::EL1PCTEN::SET);
        // Set CNTVOFF_EL2 to the current physical counter so the guest's
        // virtual counter (CNTVCT_EL0 = CNTPCT_EL0 - CNTVOFF_EL2) starts near zero.
        let cntpct: u64;
        unsafe { core::arch::asm!("mrs {0}, CNTPCT_EL0", out(reg) cntpct) };
        self.guest_system_regs.cntvoff_el2 = cntpct;
        self.guest_system_regs.cntkctl_el1 = 0;
        self.guest_system_regs.cnthctl_el2 = if config.passthrough_timer {
            (CNTHCTL_EL2::EL1PCEN::SET + CNTHCTL_EL2::EL1PCTEN::SET).into()
        } else {
            (CNTHCTL_EL2::EL1PCEN::CLEAR + CNTHCTL_EL2::EL1PCTEN::CLEAR).into()
        };

        self.guest_system_regs.sctlr_el1 = 0x30C50830;
        self.guest_system_regs.pmcr_el0 = 0;

        self.guest_system_regs.vtcr_el2 = probe_vtcr_support()
            + (VTCR_EL2::TG0::Granule4KB
                + VTCR_EL2::SH0::Inner
                + VTCR_EL2::ORGN0::NormalWBRAWA
                + VTCR_EL2::IRGN0::NormalWBRAWA)
                .value;

        let mut hcr_el2 =
            HCR_EL2::VM::Enable + HCR_EL2::TSC::EnableTrapEl1SmcToEl2 + HCR_EL2::RW::EL1IsAarch64;
        if feature_id_state_requires_filtering() {
            hcr_el2 += HCR_EL2::TID3::SET;
        }
        if !config.passthrough_interrupt {
            // Route physical IRQ/FIQ exceptions to EL2. Guest interrupts are
            // delivered through the GICv3 virtual CPU interface (ICH LRs).
            hcr_el2 += HCR_EL2::IMO::EnableVirtualIRQ + HCR_EL2::FMO::EnableVirtualFIQ;
        }

        self.guest_system_regs.hcr_el2 = hcr_el2.into();

        // Set VMPIDR_EL2, which provides the value of the Virtualization Multiprocessor ID.
        // This is the value returned by Non-secure EL1 reads of MPIDR.
        let mut vmpidr = 1 << 31;
        // Note: mind CPU cluster here.
        vmpidr |= self.mpidr;
        self.guest_system_regs.vmpidr_el2 = vmpidr;
    }

    /// Set exception return pc
    fn set_elr(&mut self, elr: usize) {
        self.ctx.set_exception_pc(elr);
    }

    /// Get general purpose register
    #[allow(unused)]
    fn get_gpr(&self, idx: usize) {
        self.ctx.gpr(idx);
    }
}

/// Private functions related to vcpu runtime control flow.
impl Aarch64VCpu {
    /// Save host context and run guest.
    ///
    /// When a VM-Exit happens when guest's vCpu is running,
    /// the control flow will be redirected to this function through `return_run_guest`.
    #[unsafe(naked)]
    unsafe extern "C" fn run_guest(&mut self) -> usize {
        // Fixes: https://github.com/arceos-hypervisor/arm_vcpu/issues/22
        //
        // The original issue seems to be caused by an unexpected compiler optimization that takes
        // the dummy return value `0` of `run_guest` as the actual return value. By replacing the
        // original `run_guest` with the current naked one, we eliminate the dummy code path of the
        // original version, and ensure that the compiler does not perform any unexpected return
        // value optimization.
        core::arch::naked_asm!(
            // Save host context.
            save_regs_to_stack!(),
            // Save current host stack top to `self.host_stack_top`.
            //
            // 'extern "C"' here specifies the aapcs64 calling convention, according to which
            // the first and only parameter, the pointer of self, should be in x0:
            "mov x9, sp",
            "add x0, x0, {host_stack_top_offset}",
            "str x9, [x0]",
            // Go to `context_vm_entry`.
            "b context_vm_entry",
            // Panic if the control flow comes back here, which should never happen.
            "b {run_guest_panic}",
            host_stack_top_offset = const core::mem::size_of::<TrapFrame>(),
            run_guest_panic = sym Self::run_guest_panic,
        );
    }

    /// This function is called when the control flow comes back to `run_guest`. To provide a error
    /// message for debugging purposes.
    ///
    /// This function may fail as the stack may have been corrupted when this function is called.
    /// But we won't handle it here for now.
    unsafe fn run_guest_panic() -> ! {
        panic!("run_guest_panic");
    }

    /// Restores guest system control registers.
    unsafe fn restore_vm_system_regs(&mut self, vhe: bool) {
        unsafe {
            // load system regs
            if vhe {
                core::arch::asm!("msr CPTR_EL2, {0}", in(reg) 3u64 << 20);
            } else {
                core::arch::asm!("msr CPTR_EL2, xzr");
            }
            self.guest_system_regs.restore(vhe);
            // Enable the architectural GICv3 virtual CPU interface while the
            // guest is running. A guest using the system-register interface
            // (ICC_*) acknowledges virtual Group 1 interrupts through it.
            core::arch::asm!(
                "msr ich_hcr_el2, {hcr}\n\
                 isb",
                hcr = in(reg) 1u64,
            );
            core::arch::asm!(
                "
                ic  iallu
                tlbi	alle2
                tlbi	alle1         // Flush tlb
                dsb	nsh
                isb"
            );
        }
    }

    /// Handle VM-Exits.
    ///
    /// Parameters:
    /// - `exit_reason`: The reason why the VM-Exit happened in [`TrapKind`].
    ///
    /// Returns:
    /// - [`AxVCpuExitReason`]: a wrappered VM-Exit reason needed to be handled by the hypervisor.
    ///
    /// This function may panic for unhandled exceptions.
    fn vmexit_handler(&mut self, exit_reason: TrapKind) -> AxResult<AxVCpuExitReason> {
        trace!(
            "Aarch64VCpu vmexit_handler() esr:{:#x} ctx:{:#x?}",
            exception_class_value(),
            self.ctx
        );

        let result = match exit_reason {
            TrapKind::Synchronous => handle_exception_sync(&mut self.ctx),
            TrapKind::Irq => {
                let vector = axvisor_api::arch::fetch_irq();
                let inject_virtual_timer =
                    vector == 27 || self.guest_system_regs.cntv_ctl_el0 & 0x7 == 0x5;
                let inject_physical_timer =
                    vector == 30 || self.guest_system_regs.cntp_ctl_el0 & 0x7 == 0x5;

                // A higher-priority physical IRQ can hide an expired timer
                // PPI from HPPIR. Derive the level-triggered timer state from
                // its saved control register as well, then mask it until EL1
                // observes ISTATUS and programs the next deadline.
                if inject_virtual_timer {
                    self.guest_system_regs.cntv_ctl_el0 |= 0x2;
                    if !self.virtual_gic_state.inject_interrupt(27) {
                        warn!("No free GIC list register for virtual timer interrupt");
                    }
                }
                if inject_physical_timer {
                    self.guest_system_regs.cntp_ctl_el0 |= 0x2;
                    if !self.virtual_gic_state.inject_interrupt(30) {
                        warn!("No free GIC list register for physical timer interrupt");
                    }
                }
                if vector == 27 || vector == 30 {
                    Ok(AxVCpuExitReason::Nothing)
                } else if vector >= 1020 {
                    // GICv3 reserves 1020..=1023 for special/spurious IDs;
                    // there is no host interrupt for the generic VMM loop to
                    // dispatch in this case.
                    Ok(AxVCpuExitReason::Nothing)
                } else {
                    Ok(AxVCpuExitReason::ExternalInterrupt { vector })
                }
            }
            _ => panic!("Unhandled exception {:?}", exit_reason),
        };

        match result {
            Ok(AxVCpuExitReason::SysRegRead { addr, reg }) => {
                if let Some(exit_reason) =
                    self.builtin_sysreg_access_handler(addr, false, 0, reg)?
                {
                    return Ok(exit_reason);
                }

                result
            }
            Ok(AxVCpuExitReason::SysRegWrite { addr, value }) => {
                if let Some(exit_reason) =
                    self.builtin_sysreg_access_handler(addr, true, value, 0)?
                {
                    return Ok(exit_reason);
                }

                result
            }
            r => r,
        }
    }

    /// Handle system register access that can and should be handled by the VCpu itself.
    ///
    /// Return `Ok(None)` if the system register access is not handled by the VCpu itself,
    fn builtin_sysreg_access_handler(
        &mut self,
        addr: SysRegAddr,
        write: bool,
        value: u64,
        reg: usize,
    ) -> AxResult<Option<AxVCpuExitReason>> {
        const SYSREG_ICC_SGI1R_EL1: SysRegAddr = SysRegAddr::new(0x3A_3016); // ICC_SGI1R_EL1
        const SYSREG_ID_AA64MMFR0_EL1: SysRegAddr = SysRegAddr::new(0x30_000E);
        const OP0_MASK: usize = 0b11 << 20;
        const OP1_MASK: usize = 0b111 << 14;
        const CRN_MASK: usize = 0b1111 << 10;
        const CRM_MASK: usize = 0b1111 << 1;

        let encoding = addr.addr();
        let crm = (encoding & CRM_MASK) >> 1;
        let is_feature_id_register =
            encoding & (OP0_MASK | OP1_MASK | CRN_MASK) == 0b11 << 20 && (1..=7).contains(&crm);

        if !write && is_feature_id_register {
            let value = if addr == SYSREG_ID_AA64MMFR0_EL1 {
                ID_AA64MMFR0_EL1.read(ID_AA64MMFR0_EL1::PARange) as usize
            } else {
                0
            };
            self.set_gpr(reg, value);
            return Ok(Some(AxVCpuExitReason::Nothing));
        }

        match (addr, write) {
            (SYSREG_ICC_SGI1R_EL1, true) => {
                debug!("arm_vcpu ICC_SGI1R_EL1 write: {value:#x}");

                // TODO: support RangeSelector

                let intid = (value >> 24) & 0b1111;
                let irm = ((value >> 40) & 0b1) != 0;

                // IRM == 1 => send to all except self
                if irm {
                    debug!("arm_vcpu ICC_SGI1R_EL1 write: irm == 1, send to all except self");

                    return Ok(Some(AxVCpuExitReason::SendIPI {
                        target_cpu: 0,
                        target_cpu_aux: 0,
                        send_to_all: true,
                        send_to_self: false,
                        vector: intid,
                    }));
                }

                let aff3 = (value >> 48) & 0xff;
                let aff2 = (value >> 32) & 0xff;
                let aff1 = (value >> 16) & 0xff;
                let target_list = value & 0xffff;

                debug!(
                    "arm_vcpu ICC_SGI1R_EL1 write: aff3:{aff3:#x} aff2:{aff2:#x} aff1:{aff1:#x} \
                     intid:{intid:#x} target_list:{target_list:#x}"
                );

                Ok(Some(AxVCpuExitReason::SendIPI {
                    target_cpu: (aff3 << 24) | (aff2 << 16) | (aff1 << 8),
                    target_cpu_aux: target_list,
                    send_to_all: false,
                    send_to_self: false,
                    vector: intid,
                }))
            }
            (SYSREG_ICC_SGI1R_EL1, false) => {
                // ICC_SGI1R_EL1 is WO, we take it as RAZ.
                self.set_gpr(reg, 0);
                Ok(Some(AxVCpuExitReason::Nothing))
            }
            _ => {
                // If the system register access is not handled by the VCpu itself,
                // we return None to let the hypervisor handle it.
                Ok(None)
            }
        }
    }
}

fn feature_id_state_requires_filtering() -> bool {
    let pfr0 = ID_AA64PFR0_EL1.get();
    let pfr1 = ID_AA64PFR1_EL1.get();
    let isar1 = ID_AA64ISAR1_EL1.get();
    (pfr0 & ((0xf << 32) | (0xf << 40) | (0xf << 44))) != 0
        || (pfr1 & ((0xf << 8) | (0xf << 16) | (0xf << 24) | (0xf << 44))) != 0
        || (isar1 & ((0xf << 4) | (0xf << 8) | (0xf << 24) | (0xf << 28))) != 0
}

pub(crate) fn pa_bits() -> usize {
    match ID_AA64MMFR0_EL1.read_as_enum(ID_AA64MMFR0_EL1::PARange) {
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_32) => 32,
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_36) => 36,
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_40) => 40,
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_42) => 42,
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_44) => 44,
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_48) => 48,
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_52) => 52,
        _ => 32,
    }
}

#[allow(dead_code)]
pub(crate) fn current_gpt_level() -> usize {
    let t0sz = VTCR_EL2.read(VTCR_EL2::T0SZ) as usize;
    match t0sz {
        16..=25 => 4,
        26..=35 => 3,
        _ => 2,
    }
}

pub(crate) fn max_gpt_level(pa_bits: usize) -> usize {
    match pa_bits {
        44.. => 4,
        _ => 3,
    }
}

fn probe_vtcr_support() -> u64 {
    let pa_bits = pa_bits();

    let mut val = match max_gpt_level(pa_bits) {
        4 => VTCR_EL2::SL0::Granule4KBLevel0 + VTCR_EL2::T0SZ.val(64 - 48),
        _ => VTCR_EL2::SL0::Granule4KBLevel1 + VTCR_EL2::T0SZ.val(64 - 39),
    };

    match pa_bits {
        52..=64 => val += VTCR_EL2::PS::PA_52B_4PB,
        48..=51 => val += VTCR_EL2::PS::PA_48B_256TB,
        44..=47 => val += VTCR_EL2::PS::PA_44B_16TB,
        42..=43 => val += VTCR_EL2::PS::PA_42B_4TB,
        40..=41 => val += VTCR_EL2::PS::PA_40B_1TB,
        36..=39 => val += VTCR_EL2::PS::PA_36B_64GB,
        _ => val += VTCR_EL2::PS::PA_32B_4GB,
    }

    val.value
}
