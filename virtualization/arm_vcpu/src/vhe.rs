// SPDX-License-Identifier: Apache-2.0
//! VHE guest state owned by the shared Core. No host OS registers are retained
//! between calls. The host adapter supplies a CPU/FP/exception ownership token.
use core::{
    arch::{asm, global_asm},
    mem::offset_of,
};

use ax_errno::{AxError, AxResult};
use axaddrspace::{GuestPhysAddr, HostPhysAddr, MappingFlags, device::AccessWidth};
use axvcpu::{AxArchPerCpu, AxArchVCpu, AxVCpuExitReason};

use crate::{Aarch64VCpuCreateConfig, Aarch64VCpuSetupConfig};

global_asm!(include_str!("vhe.S"));
unsafe extern "C" {
    fn axvisor_vhe_switch(state: *mut core::ffi::c_void);
}

/// All fields consumed by vhe.S have fixed offsets, asserted below.
#[repr(C, align(16))]
#[derive(Debug)]
pub struct Vcpu {
    pub x: [u64; 31],
    pub sp_el0: u64,
    pub pc: u64,
    pub pstate: u64,
    pub sys: [u64; 22],
    pub fp: [u128; 32],
    pub fpcr: u64,
    pub fpsr: u64,
    pub vttbr: u64,
    pub vtcr: u64,
    pub mpidr: u64,
    pub esr: u64,
    pub far: u64,
    pub hpfar: u64,
    pub exit_kind: u64,
    pub timer_cval: u64,
    pub timer_ctl: u64,
    pub cntvoff: u64,
    pub lrs: [u64; 16],
    pub vmcr: u64,
    pub aprs: [u64; 8],
    pub afsr1: u64,
    pub ptimer_cval: u64,
    pub ptimer_ctl: u64,
    pub csselr: u64,
    software_root: u64,
    concat_root: Option<super::vhe_stage2::ConcatRoot>,
}
const _: () = {
    assert!(offset_of!(Vcpu, sys) == 272);
    assert!(offset_of!(Vcpu, fp) == 448);
    assert!(offset_of!(Vcpu, vttbr) == 976);
    assert!(offset_of!(Vcpu, esr) == 1000);
    assert!(offset_of!(Vcpu, exit_kind) == 1024);
    assert!(offset_of!(Vcpu, lrs) == 1056);
    assert!(offset_of!(Vcpu, vmcr) == 1184);
    assert!(offset_of!(Vcpu, aprs) == 1192);
    assert!(offset_of!(Vcpu, afsr1) == 1256);
};

/// Implemented IPA width, capped to the four-level 4 KiB format.
pub fn ipa_bits() -> usize {
    let mmfr: u64;
    unsafe { asm!("mrs {}, id_aa64mmfr0_el1", out(reg) mmfr) };
    [32, 36, 40, 42, 44, 48][(mmfr & 15).min(5) as usize]
}

/// Stage-2 hardware geometry; 40/42-bit CPUs use concatenated L1 roots.
pub fn vtcr() -> u64 {
    let mmfr: u64;
    unsafe { asm!("mrs {}, id_aa64mmfr0_el1", out(reg) mmfr) };
    (1 << 31)
        | ((mmfr & 15).min(5) << 16)
        | (3 << 12)
        | (1 << 10)
        | (1 << 8)
        | ((if ipa_bits() < 44 { 1 } else { 2 }) << 6)
        | (64 - ipa_bits() as u64)
}

pub fn counter() -> u64 {
    let value;
    unsafe { asm!("isb", "mrs {}, cntpct_el0", out(reg) value) };
    value
}

impl Vcpu {
    pub fn new_state(mpidr: u64) -> Self {
        let mut s = Self {
            x: [0; 31],
            sp_el0: 0,
            pc: 0,
            pstate: 0x3c5,
            sys: [0; 22],
            fp: [0; 32],
            fpcr: 0,
            fpsr: 0,
            vttbr: 0,
            vtcr: vtcr(),
            mpidr: mpidr | (1 << 31),
            esr: 0,
            far: 0,
            hpfar: 0,
            exit_kind: 0,
            timer_cval: 0,
            timer_ctl: 0,
            cntvoff: 0,
            lrs: [0; 16],
            vmcr: (0xff << 24) | 2,
            aprs: [0; 8],
            afsr1: 0,
            ptimer_cval: 0,
            ptimer_ctl: 0,
            csselr: 0,
            software_root: 0,
            concat_root: None,
        };
        s.sys[3] = 0x30c50830; // SCTLR_EL1 reset, MMU and caches off.
        s.sys[4] = 3 << 20; // CPACR_EL1: guest FPSIMD enabled.
        s
    }

    /// Reset an offline vCPU for PSCI CPU_ON while preserving its Stage-2 root.
    pub fn reset_for_psci(&mut self, pc: u64, arg: u64) {
        let root = self.vttbr;
        let software_root = self.software_root;
        let concat_root = self.concat_root.take();
        *self = Self::new_state(self.mpidr);
        self.vttbr = root;
        self.software_root = software_root;
        self.concat_root = concat_root;
        self.pc = pc;
        self.x[0] = arg;
    }

    /// Execute with the host token held and all exceptions masked.
    ///
    /// # Safety
    /// The caller owns this vCPU, its live Stage-2 tables and mapped pages, and
    /// holds `vhe_host_enter` until the call returns. No mapping may change.
    pub unsafe fn switch(&mut self) {
        unsafe { axvisor_vhe_switch((self as *mut Self).cast()) };
    }

    fn ipa(&self) -> GuestPhysAddr {
        GuestPhysAddr::from_usize((((self.hpfar & 0xfffffffff0) << 8) | (self.far & 4095)) as usize)
    }

    fn psci(&mut self) -> AxVCpuExitReason {
        let id = self.x[0] as u32;
        let args: [u64; 6] = core::array::from_fn(|i| {
            if id & (1 << 30) == 0 {
                self.x[i + 1] as u32 as u64
            } else {
                self.x[i + 1]
            }
        });
        let ret: i64 = match id {
            0x84000000 => 0x10000,
            0x84000003 | 0xc4000003 => {
                return AxVCpuExitReason::CpuUp {
                    target_cpu: args[0],
                    entry_point: GuestPhysAddr::from_usize(args[1] as usize),
                    arg: args[2],
                };
            }
            0x84000002 => return AxVCpuExitReason::CpuDown { _state: 0 },
            0x84000008 | 0x84000009 => return AxVCpuExitReason::SystemDown,
            0x8400000a => match self.x[1] as u32 {
                0x84000000 | 0x84000002 | 0x84000003 | 0xc4000003 | 0x84000004 | 0xc4000004
                | 0x84000008 | 0x84000009 | 0x8400000a => 0,
                _ => -1,
            },
            0x84000004 | 0xc4000004 => {
                return AxVCpuExitReason::Hypercall {
                    nr: self.x[0],
                    args,
                };
            }
            0x80000000 => 0x10001,
            0x80000001 => -1,
            _ if id & 0xff000000 == 0x84000000 || id & 0xff000000 == 0xc4000000 => -1,
            _ => {
                return AxVCpuExitReason::Hypercall {
                    nr: self.x[0],
                    args,
                };
            }
        };
        self.x[0] = ret as u64;
        AxVCpuExitReason::Nothing
    }

    fn sysreg(&mut self) -> AxResult<AxVCpuExitReason> {
        let iss = self.esr;
        let reg = ((iss >> 5) & 31) as usize;
        let key = (((iss >> 20) & 3) << 14)
            | (((iss >> 14) & 7) << 11)
            | (((iss >> 10) & 15) << 7)
            | (((iss >> 1) & 15) << 3)
            | ((iss >> 17) & 7);
        let read = iss & 1 != 0;
        let value = if reg == 31 { 0 } else { self.x[reg] };
        let result = match key {
            0xd801 => {
                let v;
                unsafe { asm!("mrs {}, ctr_el0",out(reg)v) };
                v
            }
            0xc800 => 2, // Minimal 64-byte cache line; CLIDR advertises no set/way caches.
            0xc801 | 0xc807 => 0,
            0xd000 => {
                if !read {
                    self.csselr = value & 15;
                }
                self.csselr
            }
            0xc081 => {
                if !read {
                    self.sys[20] = value;
                }
                self.sys[20]
            }
            0x43b2 | 0x43d2 | 0x43f2 if !read => {
                unsafe { asm!("dsb ish") };
                0
            }

            0x8012 => {
                if !read {
                    self.sys[19] = value & (1 << 12);
                }
                self.sys[19]
            }
            _ if key & 0xf000 == 0x8000 => 0, // Trapped debug state; no passthrough.

            // ID_AA64PFR0: AArch64 EL0/1, FPSIMD and GICv3, no SVE/EL2/EL3.
            0xc020 => 0x11 | (1 << 24),
            0xc021 | 0xc022 | 0xc029 | 0xc031 | 0xc032 | 0xc039 | 0xc03a | 0xc03b | 0xc03c => 0,
            0xc028 => 6, // DebugVer; PMU absent.
            0xc030 => {
                let v;
                unsafe { asm!("mrs {}, id_aa64isar0_el1", out(reg) v) };
                v
            }
            0xc038 => crate::vhe_regs::id_register(0xc038).unwrap(), /* Host-bounded PA, 4K, no 64K/16K granule. */
            0xdf11 => {
                if !read {
                    self.ptimer_ctl = value & 3;
                }
                self.ptimer_ctl | (u64::from(counter() >= self.ptimer_cval) << 2)
            }
            0xdf12 => {
                if !read {
                    self.ptimer_cval = value;
                }
                self.ptimer_cval
            }
            0xdf10 => {
                let now = counter();
                if !read {
                    self.ptimer_cval = now.wrapping_add(value as i32 as i64 as u64);
                }
                self.ptimer_cval.wrapping_sub(now) as u32 as u64
            }
            0xdf19 => {
                // CNTV_CTL_EL0
                if !read {
                    self.timer_ctl = value & 3;
                }
                self.timer_ctl
                    | (u64::from(counter().wrapping_sub(self.cntvoff) >= self.timer_cval) << 2)
            }
            0xdf1a => {
                if !read {
                    self.timer_cval = value;
                }
                self.timer_cval
            }
            0xdf18 => {
                // TVAL is signed and derived from the absolute deadline.
                let now = counter().wrapping_sub(self.cntvoff);
                if !read {
                    self.timer_cval = now.wrapping_add(value as i32 as i64 as u64);
                }
                self.timer_cval.wrapping_sub(now) as u32 as u64
            }
            0xc65d if !read => {
                self.pc += 4;
                return Ok(AxVCpuExitReason::SysRegWrite {
                    addr: axaddrspace::device::SysRegAddr(key as usize),
                    value,
                });
            }
            // Unknown ID registers are architecturally RAZ in this profile.
            _ if key & 0xff80 == 0xc000 && (key & 0x78) >= 0x20 => 0,
            _ => {
                log::error!(
                    "VHE unsupported sysreg {key:#x} read={read} pc={:#x}",
                    self.pc
                );
                return Err(AxError::Unsupported);
            }
        };
        if read && reg != 31 {
            self.x[reg] = result;
        }
        self.pc += 4;
        Ok(AxVCpuExitReason::Nothing)
    }

    pub fn exit(&mut self) -> AxResult<AxVCpuExitReason> {
        if self.exit_kind == 1 {
            return Ok(AxVCpuExitReason::PreemptionTimer);
        }
        if self.exit_kind != 0 {
            return Err(AxError::BadState);
        }
        match self.esr >> 26 {
            0x16 => Ok(self.psci()),
            0x17 => {
                self.pc += 4;
                Ok(self.psci())
            }
            0x01 => {
                self.pc += 4;
                Ok(AxVCpuExitReason::Halt)
            }
            0x18 => self.sysreg(),
            0x20 | 0x24 => Ok(AxVCpuExitReason::NestedPageFault {
                addr: self.ipa(),
                access_flags: if self.esr >> 26 == 0x20 {
                    MappingFlags::EXECUTE
                } else if self.esr & (1 << 6) != 0 {
                    MappingFlags::WRITE
                } else {
                    MappingFlags::READ
                },
            }),
            _ => {
                log::error!(
                    "VHE exception kind={} esr={:#x} pc={:#x} far={:#x}",
                    self.exit_kind,
                    self.esr,
                    self.pc,
                    self.far
                );
                Err(AxError::Unsupported)
            }
        }
    }
}

impl AxArchVCpu for Vcpu {
    type CreateConfig = Aarch64VCpuCreateConfig;
    type SetupConfig = Aarch64VCpuSetupConfig;
    fn new(_: usize, _: usize, c: Self::CreateConfig) -> AxResult<Self> {
        let mut s = Self::new_state(c.mpidr_el1);
        s.x[0] = c.dtb_addr as u64;
        Ok(s)
    }
    fn setup(&mut self, _: Self::SetupConfig) -> AxResult {
        Ok(())
    }
    fn set_entry(&mut self, entry: GuestPhysAddr) -> AxResult {
        self.pc = entry.as_usize() as u64;
        Ok(())
    }
    fn set_ept_root(&mut self, root: HostPhysAddr) -> AxResult {
        self.software_root = root.as_usize() as u64;
        if ipa_bits() < 44 {
            if self.concat_root.is_none() {
                self.concat_root = Some(super::vhe_stage2::ConcatRoot::new(ipa_bits())?);
            }
            self.vttbr = self.concat_root.as_ref().unwrap().address();
        } else {
            self.vttbr = self.software_root;
        }
        Ok(())
    }
    fn run(&mut self) -> AxResult<AxVCpuExitReason> {
        let flags: u64;
        let hcr: u64;
        unsafe { asm!("mrs {}, daif","mrs {}, hcr_el2",out(reg) flags,out(reg) hcr) };
        if flags & 0x3c0 != 0x3c0 || hcr & (1 << 34) == 0 {
            return Err(AxError::BadState);
        }
        if let Some(root) = &self.concat_root {
            unsafe { root.refresh(self.software_root)? };
        }
        unsafe { self.switch() };
        self.exit()
    }
    fn bind(&mut self) -> AxResult {
        Ok(())
    }
    fn unbind(&mut self) -> AxResult {
        Ok(())
    }
    fn set_gpr(&mut self, reg: usize, value: usize) {
        if reg < 31 {
            self.x[reg] = value as u64;
        }
    }
    fn set_return_value(&mut self, value: usize) {
        self.x[0] = value as u64;
    }
    fn inject_interrupt(&mut self, vector: usize) -> AxResult {
        let vtr: u64;
        unsafe { asm!("mrs {}, ich_vtr_el2",out(reg) vtr) };
        let count = ((vtr & 31) + 1).min(16) as usize;
        if self.lrs[..count]
            .iter()
            .any(|v| v & 0xffffffff == vector as u64 && v >> 62 != 0)
        {
            return Ok(());
        }
        let lr = self.lrs[..count]
            .iter_mut()
            .find(|v| **v >> 62 == 0)
            .ok_or(AxError::ResourceBusy)?;
        *lr = (1 << 62) | (1 << 60) | (0x80 << 48) | vector as u64;
        Ok(())
    }
    fn decode_nested_page_fault(&mut self) -> AxResult<Option<AxVCpuExitReason>> {
        if self.esr >> 26 != 0x24 || self.esr & (1 << 24) == 0 {
            log::warn!(
                "VHE Stage-2 fault esr={:#x} pc={:#x} ipa={:#x} vtcr={:#x}",
                self.esr,
                self.pc,
                self.ipa().as_usize(),
                self.vtcr
            );
            return Ok(None);
        }
        let reg = ((self.esr >> 16) & 31) as usize;
        let width = AccessWidth::try_from(1 << ((self.esr >> 22) & 3))
            .map_err(|_| AxError::InvalidInput)?;
        let result = if self.esr & (1 << 6) != 0 {
            AxVCpuExitReason::MmioWrite {
                addr: self.ipa(),
                width,
                data: if reg == 31 { 0 } else { self.x[reg] },
            }
        } else {
            AxVCpuExitReason::MmioRead {
                addr: self.ipa(),
                width,
                reg,
                reg_width: if self.esr & (1 << 15) != 0 {
                    AccessWidth::Qword
                } else {
                    AccessWidth::Dword
                },
                signed_ext: self.esr & (1 << 21) != 0,
            }
        };
        self.pc += 4;
        Ok(Some(result))
    }
}

pub struct PerCpu {
    enabled: bool,
}
impl AxArchPerCpu for PerCpu {
    fn new(_: usize) -> AxResult<Self> {
        Ok(Self { enabled: false })
    }
    fn is_enabled(&self) -> bool {
        self.enabled
    }
    fn hardware_enable(&mut self) -> AxResult {
        let token = axvisor_api::arch::vhe_host_enter()?;
        axvisor_api::arch::vhe_host_exit(token);
        self.enabled = true;
        Ok(())
    }
    fn hardware_disable(&mut self) -> AxResult {
        self.enabled = false;
        Ok(())
    }
    fn max_guest_page_table_levels(&self) -> usize {
        4
    }
}
