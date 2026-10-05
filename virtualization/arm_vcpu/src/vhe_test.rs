// SPDX-License-Identifier: Apache-2.0
//! On-target VHE smoke gates. Uses the production world switch and real Stage-2.
use core::arch::{asm, global_asm};

use ax_errno::{AxError, AxResult};
use axvisor_api::{arch, memory, time};

use crate::vhe::Vcpu;

global_asm!(
    r#"
.section .text.axvisor_vhe_test_guest,"ax"
.balign 4
.global axvisor_vhe_test_start
.global axvisor_vhe_test_loop
.global axvisor_vhe_test_end
axvisor_vhe_test_start:
    mov x1, #0x40000000
    add x1, x1, #0x1000
    ldr x1, [x1]
    mov x0, #0x55
    hvc #0
axvisor_vhe_test_loop:
    msr daifset, #15
    b .
axvisor_vhe_test_end:
"#
);
unsafe extern "C" {
    fn axvisor_vhe_test_start();
    fn axvisor_vhe_test_loop();
    fn axvisor_vhe_test_end();
}

struct Frame(memory::PhysAddr);
impl Frame {
    fn new() -> AxResult<Self> {
        memory::alloc_frame().map(Self).ok_or(AxError::NoMemory)
    }
    fn ptr(&self) -> *mut u64 {
        memory::phys_to_virt(self.0).as_usize() as *mut u64
    }
    fn pa(&self) -> u64 {
        self.0.as_usize() as u64
    }
}
impl Drop for Frame {
    fn drop(&mut self) {
        memory::dealloc_frame(self.0);
    }
}

fn host_state() -> [u64; 28] {
    let mut state = [0; 28];
    unsafe {
        asm!(
            "mrs x9, hcr_el2", "str x9, [{out}, #0]",
            "mrs x9, vbar_el2", "str x9, [{out}, #8]",
            "mrs x9, tpidr_el2", "str x9, [{out}, #16]",
            "mrs x9, sp_el0", "str x9, [{out}, #24]",
            "mrs x9, cnthctl_el2", "str x9, [{out}, #32]",
            "mrs x9, cptr_el2", "str x9, [{out}, #40]",
            "mrs x9, cntvoff_el2", "str x9, [{out}, #48]",
            "mrs x9, vtcr_el2", "str x9, [{out}, #56]",
            "mrs x9, vttbr_el2", "str x9, [{out}, #64]",
            "mrs x9, mdcr_el2", "str x9, [{out}, #72]",
            "mrs x9, mdscr_el1", "str x9, [{out}, #80]",
            "mrs x9, ich_hcr_el2", "str x9, [{out}, #88]",
            "mrs x9, ich_vmcr_el2", "str x9, [{out}, #96]",
            "mrs x9, icc_sre_el1", "str x9, [{out}, #104]",
            "mrs x9, hstr_el2", "str x9, [{out}, #112]",
            "mrs x9, vpidr_el2", "str x9, [{out}, #120]",
            "mrs x9, vmpidr_el2", "str x9, [{out}, #128]",
            "mrs x9, par_el1", "str x9, [{out}, #136]",
            "mrs x9, actlr_el1", "str x9, [{out}, #144]",
            "mrs x9, elr_el2", "str x9, [{out}, #152]",
            "mrs x9, spsr_el2", "str x9, [{out}, #160]",
            "mrs x9, esr_el2", "str x9, [{out}, #168]",
            "mrs x9, far_el2", "str x9, [{out}, #176]",
            "mrs x9, hpfar_el2", "str x9, [{out}, #184]",
            "mrs x9, tpidr_el0", "str x9, [{out}, #192]",
            "mrs x9, tpidrro_el0", "str x9, [{out}, #200]",
            "mrs x9, cntv_cval_el0", "str x9, [{out}, #208]",
            "mrs x9, cntv_ctl_el0", "str x9, [{out}, #216]",
            out=in(reg)state.as_mut_ptr(), out("x9") _,
        )
    };
    state
}

fn run_once(v: &mut Vcpu) -> AxResult {
    let token = arch::vhe_host_enter()?;
    let before = host_state();
    unsafe { v.switch() };
    let after = host_state();
    arch::vhe_host_exit(token);
    if before != after {
        for (i, (a, b)) in before.iter().zip(&after).enumerate() {
            if a != b {
                log::error!("VHE host register index={i} before={a:#x} after={b:#x}");
            }
        }
        return Err(AxError::BadState);
    }
    Ok(())
}

/// The external runner must enforce a watchdog: a broken IRQ exit cannot time
/// itself out from the CPU trapped in the guest.
pub fn run() -> AxResult {
    for iteration in 0..3 {
        let l1 = Frame::new()?;
        let l2 = Frame::new()?;
        let l3 = Frame::new()?;
        let code = Frame::new()?;
        let a = Frame::new()?;
        let b = Frame::new()?;
        let start = axvisor_vhe_test_start as *const () as usize;
        let len = axvisor_vhe_test_end as *const () as usize - start;
        unsafe {
            core::ptr::copy_nonoverlapping(start as *const u8, code.ptr() as *mut u8, len);
            for offset in (0..4096).step_by(64) {
                asm!("dc cvau, {}",in(reg) (code.ptr() as usize+offset));
            }
            asm!("dsb ish", "ic ialluis", "dsb ish", "isb");
            l1.ptr().add(1).write(l2.pa() | 3);
            l2.ptr().write(l3.pa() | 3);
            // Normal WB, inner shareable, AF, S2 read/write and executable.
            l3.ptr().write(code.pa() | 0x7ff);
            l3.ptr().add(1).write(a.pa() | 0x7ff);
            a.ptr().write(0x12345678);
            b.ptr().write(0xabcdef01);
        }
        let mut v = Vcpu::new_state(0);
        v.vttbr = l1.pa();
        v.vtcr = (v.vtcr & !255) | 0x59;
        v.pc = 0x40000000;
        loop {
            run_once(&mut v)?;
            if v.exit_kind != 1 {
                break;
            }
        }
        if v.exit_kind != 0 || v.esr >> 26 != 0x16 || v.x[0] != 0x55 || v.x[1] != 0x12345678 {
            log::error!(
                "VHE selftest entry: kind={} esr={:#x} pc={:#x} x0={:#x} x1={:#x}",
                v.exit_kind,
                v.esr,
                v.pc,
                v.x[0],
                v.x[1]
            );
            return Err(AxError::BadState);
        }
        unsafe {
            l3.ptr().add(1).write(b.pa() | 0x7ff);
        }
        v.pc = 0x40000000;
        loop {
            run_once(&mut v)?;
            if v.exit_kind != 1 {
                break;
            }
        }
        if v.esr >> 26 != 0x16 || v.x[1] != 0xabcdef01 {
            return Err(AxError::BadState);
        }
        log::info!("VHE-TEST entry-remap-host-restore iteration={iteration} registers=28 PASS");
        v.pc = 0x40000000 + (axvisor_vhe_test_loop as *const () as usize - start) as u64;
        let before = time::current_time_nanos();
        time::set_oneshot_timer(core::time::Duration::from_nanos(before + 5_000_000));
        run_once(&mut v)?;
        if v.exit_kind != 1 {
            return Err(AxError::BadState);
        }
        log::info!(
            "VHE-TEST masked-guest-forced-exit iteration={iteration} elapsed_ns={} PASS",
            time::current_time_nanos() - before
        );
        // The guest is no longer installed on this CPU before Frames drop.
    }
    log::info!("VHE-TEST destroy-recreate PASS");
    Ok(())
}
