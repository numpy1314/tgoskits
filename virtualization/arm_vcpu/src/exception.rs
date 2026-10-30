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

use aarch64_cpu::registers::{ESR_EL2, HCR_EL2, Readable, SCTLR_EL1, VTCR_EL2, VTTBR_EL2};
use ax_errno::{AxError, AxResult};
use axaddrspace::device::{AccessWidth, SysRegAddr};
use axvcpu::AxVCpuExitReason;
use log::error;

use crate::{
    TrapFrame,
    exception_utils::{
        exception_class, exception_class_value, exception_data_abort_access_is_write,
        exception_data_abort_access_reg, exception_data_abort_access_reg_width,
        exception_data_abort_access_width, exception_data_abort_handleable,
        exception_data_abort_is_permission_fault, exception_data_abort_is_translate_fault,
        exception_esr, exception_fault_addr, exception_next_instruction_step,
        exception_sysreg_addr, exception_sysreg_direction_write, exception_sysreg_gpr,
    },
    smc::{FirmwareAction, FirmwareConduit, classify_firmware_call},
};

numeric_enum_macro::numeric_enum! {
#[repr(u8)]
#[derive(Debug)]
pub enum TrapKind {
    Synchronous = 0,
    Irq = 1,
    Fiq = 2,
    SError = 3,
}
}

/// Equals to [`TrapKind::Synchronous`], used in exception.S.
const EXCEPTION_SYNC: usize = TrapKind::Synchronous as usize;
/// Equals to [`TrapKind::Irq`], used in exception.S.
const EXCEPTION_IRQ: usize = TrapKind::Irq as usize;

#[repr(u8)]
#[derive(Debug)]
#[allow(unused)]
enum TrapSource {
    CurrentSpEl0 = 0,
    CurrentSpElx = 1,
    LowerAArch64 = 2,
    LowerAArch32 = 3,
}

core::arch::global_asm!(
    include_str!("exception.S"),
    exception_sync = const EXCEPTION_SYNC,
    exception_irq = const EXCEPTION_IRQ,
);

/// Handles synchronous exceptions that occur during the execution of a guest VM.
///
/// This function examines the exception class (EC) to determine the cause of the exception
/// and then handles it accordingly.
///
/// Currently we just handle exception type including data abort (`DataAbortLowerEL`) and hypervisor call (`HVC64)`.
///
/// # Arguments
///
/// * `ctx` - A mutable reference to the `TrapFrame`, which contains the saved state of the guest VM's CPU registers at the time of the exception.
///
/// # Returns
///
/// An `AxResult` containing an `AxVCpuExitReason` indicating the reason for the VM exit.
/// This could be due to a hypervisor call (`Hypercall`) or other reasons such as data aborts.
///
/// # Panics
///
/// If an unhandled exception class is encountered, the function will panic, outputting
/// details about the exception including the instruction pointer, faulting address, exception
/// syndrome register (ESR), and system control registers.
pub fn handle_exception_sync(ctx: &mut TrapFrame) -> AxResult<AxVCpuExitReason> {
    match exception_class() {
        Some(ESR_EL2::EC::Value::DataAbortLowerEL) => {
            let elr = ctx.exception_pc();
            let val = elr + exception_next_instruction_step();
            ctx.set_exception_pc(val);
            handle_data_abort(ctx)
        }
        Some(ESR_EL2::EC::Value::HVC64) => Ok(handle_firmware_call(ctx, FirmwareConduit::Hvc)),
        Some(ESR_EL2::EC::Value::TrappedMsrMrs) => handle_system_register(ctx),
        Some(ESR_EL2::EC::Value::SMC64) => Ok(handle_firmware_call(ctx, FirmwareConduit::Smc)),
        _ => {
            panic!(
                "handler not presents for EC_{} @ipa 0x{:x}, @pc 0x{:x}, @esr 0x{:x},
                @sctlr_el1 0x{:x}, @vttbr_el2 0x{:x}, @vtcr_el2: {:#x} hcr: {:#x} ctx:{}",
                exception_class_value(),
                exception_fault_addr()?,
                (*ctx).exception_pc(),
                exception_esr(),
                SCTLR_EL1.get() as usize,
                VTTBR_EL2.get() as usize,
                VTCR_EL2.get() as usize,
                HCR_EL2.get() as usize,
                ctx
            );
        }
    }
}

fn handle_data_abort(context_frame: &mut TrapFrame) -> AxResult<AxVCpuExitReason> {
    let addr = exception_fault_addr()?;
    let access_width = exception_data_abort_access_width();
    let is_write = exception_data_abort_access_is_write();
    // let sign_ext = exception_data_abort_access_is_sign_ext();
    let reg = exception_data_abort_access_reg();
    let reg_width = exception_data_abort_access_reg_width();

    trace!(
        "Data fault @{:?}, ELR {:#x}, esr: 0x{:x}",
        addr,
        context_frame.exception_pc(),
        exception_esr(),
    );

    let width = match AccessWidth::try_from(access_width) {
        Ok(access_width) => access_width,
        Err(_) => return Err(AxError::InvalidInput),
    };

    let reg_width = match AccessWidth::try_from(reg_width) {
        Ok(reg_width) => reg_width,
        Err(_) => return Err(AxError::InvalidInput),
    };

    if !exception_data_abort_handleable() {
        panic!(
            "Core data abort not handleable {:#x}, esr {:#x}",
            addr,
            exception_esr()
        );
    }

    if !exception_data_abort_is_translate_fault() {
        if exception_data_abort_is_permission_fault() {
            return Err(AxError::Unsupported);
        } else {
            panic!("Core data abort is not translate fault {:#x}", addr,);
        }
    }

    if is_write {
        return Ok(AxVCpuExitReason::MmioWrite {
            addr,
            width,
            data: context_frame.gpr(reg) as u64,
        });
    }
    Ok(AxVCpuExitReason::MmioRead {
        addr,
        width,
        reg,
        reg_width,
        signed_ext: false,
    })
}

/// Handles a system register access exception.
///
/// This function processes the exception by reading or writing to a system register
/// based on the information in the `context_frame`.
///
/// # Arguments
/// * `context_frame` - A mutable reference to the trap frame containing the CPU state.
///
/// # Returns
/// * `AxResult<AxVCpuExitReason>` - An `AxResult` containing an `AxVCpuExitReason` indicating
///   whether the operation was a read or write and the relevant details.
fn handle_system_register(context_frame: &mut TrapFrame) -> AxResult<AxVCpuExitReason> {
    let iss = ESR_EL2.read(ESR_EL2::ISS);

    let addr = exception_sysreg_addr(iss.try_into().unwrap());
    let elr = context_frame.exception_pc();
    let val = elr + exception_next_instruction_step();
    let write = exception_sysreg_direction_write(iss);
    let reg = exception_sysreg_gpr(iss) as usize;
    context_frame.set_exception_pc(val);
    if write {
        return Ok(AxVCpuExitReason::SysRegWrite {
            addr: SysRegAddr::new(addr),
            value: context_frame.gpr(reg) as u64,
        });
    }
    Ok(AxVCpuExitReason::SysRegRead {
        addr: SysRegAddr::new(addr),
        reg,
    })
}

/// Classifies guest requests without invoking physical firmware. PSCI is
/// interpreted by the shared Core, which owns VM/vCPU lifecycle state.
fn handle_firmware_call(ctx: &mut TrapFrame, conduit: FirmwareConduit) -> AxVCpuExitReason {
    let plan = classify_firmware_call(
        conduit,
        ESR_EL2.read(ESR_EL2::ISS) as u16,
        ctx.elr,
        ctx.gpr[0],
        [
            ctx.gpr[1], ctx.gpr[2], ctx.gpr[3], ctx.gpr[4], ctx.gpr[5], ctx.gpr[6],
        ],
    );
    ctx.elr = plan.resume_pc;
    match plan.action {
        FirmwareAction::Hypercall { nr, args } => AxVCpuExitReason::Hypercall { nr, args },
        FirmwareAction::NotSupported => {
            ctx.gpr[0] = u64::MAX;
            AxVCpuExitReason::Nothing
        }
    }
}

/// Handles IRQ exceptions that occur from the current exception level.
/// Dispatches IRQs to the appropriate handler provided by the underlying host OS,
/// which is provided by `axvisor_api::irq::handle_irq()`.
#[unsafe(no_mangle)]
fn current_el_irq_handler(_tf: &mut TrapFrame) {
    // TODO: consider if returning AxVCpuExitReason::ExternalInterrupt (or another enum variant) is
    // better than directly calling the handler here.
    let irq = axvisor_api::arch::fetch_irq();
    axvisor_api::irq::handle_irq(irq as usize);
}

/// Handles synchronous exceptions that occur from the current exception level.
#[unsafe(no_mangle)]
fn current_el_sync_handler(tf: &mut TrapFrame) {
    let esr = ESR_EL2.extract();
    let ec = ESR_EL2.read(ESR_EL2::EC);
    let iss = ESR_EL2.read(ESR_EL2::ISS);

    error!("ESR_EL2: {:#x}", esr.get());
    error!("Exception Class: {ec:#x}");
    error!("Instruction Specific Syndrome: {iss:#x}");

    panic!(
        "Unhandled synchronous exception from current EL: {:#x?}",
        tf
    );
}

/// A trampoline function for sp switching during handling VM exits,
/// when **there is a active VCPU running**, which means that the host context is stored
/// into host stack in `run_guest` function.
///
/// # Functionality
///
/// 1. **Restore Previous Host Stack pointor:**
///     - The guest context frame is aleady saved by `SAVE_REGS_FROM_EL1` macro in exception.S.
///       This function firstly adjusts the `sp` to skip the exception frame
///       (adding `34 * 8` to the stack pointer) according to the memory layout of `Aarch64VCpu` struct,
///       which makes current `sp` point to the address of `host_stack_top`.
///       The host stack top value is restored by `ldr`.
///
/// 2. **Restore Host Context:**
///     - The `restore_regs_from_stack!()` macro is invoked to restore the host function context
///       from the stack. This macro handles the restoration of the host's callee-saved general-purpose
///       registers (`x19` to `x30`).
///
/// 3. **Restore Host Control Flow:**
///     - The `ret` instruction is used to return control to the host context after
///       the guest context has been saved in `Aarch64VCpu` struct and the host context restored.
///       Finally the control flow is returned back to `Aarch64VCpu.run()` in [vcpu.rs].
///
/// # Notes
///
/// - This function is typically invoked when a VM exit occurs, requiring the
///   hypervisor to switch context from the guest to the host. The precise control
///   over stack and register management ensures that the transition is smooth and
///   that the host can correctly resume execution.
///
/// - The `options(noreturn)` directive indicates that this function will not return
///   to its caller, as control will be transferred back to the host context via `ret`.
///
/// - This function is not typically called directly from Rust code. Instead, it is
///   invoked as part of the low-level hypervisor or VM exit handling routines.
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn vmexit_trampoline() -> ! {
    core::arch::naked_asm!(
        // Curretly `sp` points to the base address of `Aarch64VCpu.ctx`, which stores guest's `TrapFrame`.
        "add x9, sp, 34 * 8", // Skip the exception frame.
        // Currently `x9` points to `&Aarch64VCpu.host_stack_top`, see `run_guest()` in vcpu.rs.
        "ldr x10, [x9]", // Get `host_stack_top` value from `&Aarch64VCpu.host_stack_top`.
        "mov sp, x10",   // Set `sp` as the host stack top.
        restore_regs_from_stack!(), // Restore host function context frame.
        "ret", /* Control flow is handed back to Aarch64VCpu.run(), simulating the normal return of the `run_guest` function. */
    )
}

/// Deal with invalid aarch64 exception.
#[unsafe(no_mangle)]
fn invalid_exception_el2(tf: &mut TrapFrame, kind: TrapKind, source: TrapSource) {
    panic!(
        "Invalid exception {:?} from {:?}:\n{:#x?}",
        kind, source, tf
    );
}
