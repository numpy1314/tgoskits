#[cfg(all(
    feature = "external-base",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "loongarch64"
    )
))]
unsafe extern "C" {
    /// Resolve the per-CPU area for the currently running host CPU.
    ///
    /// The provider owns CPU identification and must return the base address
    /// of the area corresponding to the calling context.
    fn ax_percpu_current_base() -> usize;
}

/// Reads the architecture-specific per-CPU data register.
///
/// This register is used to hold the per-CPU data base on each CPU.
pub fn read_percpu_reg() -> usize {
    let tp;
    unsafe {
        cfg_if::cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                #[cfg(feature = "external-base")]
                {
                    tp = ax_percpu_current_base();
                }
                #[cfg(not(feature = "external-base"))]
                {
                    #[cfg(target_os = "linux")]
                    {
                        tp = GS;
                    }
                    #[cfg(target_os = "none")]
                    {
                        tp = x86::msr::rdmsr(x86::msr::IA32_GS_BASE) as usize
                    }
                    #[cfg(all(not(target_os = "linux"), not(target_os = "none")))]
                    {
                        unimplemented!()
                    }
                }
            } else if #[cfg(all(
                feature = "external-base",
                any(target_arch = "aarch64", target_arch = "loongarch64")
            ))] {
                tp = ax_percpu_current_base();
            } else if #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))] {
                core::arch::asm!("mv {}, gp", out(reg) tp)
            } else if #[cfg(all(target_arch = "aarch64", not(feature = "arm-el2")))] {
                core::arch::asm!("mrs {}, TPIDR_EL1", out(reg) tp)
            } else if #[cfg(all(target_arch = "aarch64", feature = "arm-el2"))] {
                core::arch::asm!("mrs {}, TPIDR_EL2", out(reg) tp)
            } else if #[cfg(target_arch = "loongarch64")] {
                // Register Convention
                // https://docs.kernel.org/arch/loongarch/introduction.html#gprs
                core::arch::asm!("move {}, $r21", out(reg) tp)
            }
        }
    }
    tp
}

/// Writes the architecture-specific per-CPU data register.
///
/// This register is used to hold the per-CPU data base on each CPU.
///
/// # Safety
///
/// This function is unsafe because it writes the low-level register directly.
#[cfg(all(
    feature = "external-base",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "loongarch64"
    )
))]
pub unsafe fn write_percpu_reg(_tp: usize) {}

/// Writes the native per-CPU register when the host does not own its base.
///
/// # Safety
/// The caller must own the per-CPU register and provide valid backing memory.
#[cfg(not(all(
    feature = "external-base",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "loongarch64"
    )
)))]
pub unsafe fn write_percpu_reg(tp: usize) {
    unsafe {
        cfg_if::cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                #[cfg(feature = "external-base")]
                {
                    // The Linux kernel owns GS; the host callback selects the
                    // current area on every access, so no register write is
                    // needed here.
                    let _ = tp;
                }
                #[cfg(not(feature = "external-base"))]
                {
                    #[cfg(target_os = "linux")]
                    {
                        GS = tp;
                    }
                    #[cfg(target_os = "none")]
                    {
                        x86::msr::wrmsr(x86::msr::IA32_GS_BASE, tp as u64);
                    }
                    #[cfg(all(not(target_os = "linux"), not(target_os = "none")))]
                    {
                        unimplemented!()
                    }
                    SELF_PTR.write_current_raw(tp);
                }
            } else if #[cfg(all(target_arch = "aarch64", feature = "external-base"))] {
                // TPIDR_EL1/EL2 belong to the host kernel.
                let _ = tp;
            } else if #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))] {
                core::arch::asm!("mv gp, {}", in(reg) tp)
            } else if #[cfg(all(target_arch = "aarch64", not(feature = "arm-el2")))] {
                core::arch::asm!("msr TPIDR_EL1, {}", in(reg) tp)
            } else if #[cfg(all(target_arch = "aarch64", feature = "arm-el2"))] {
                core::arch::asm!("msr TPIDR_EL2, {}", in(reg) tp)
            } else if #[cfg(target_arch = "loongarch64")] {
                core::arch::asm!("move $r21, {}", in(reg) tp)
            }
        }
    }
}

/// To use `ax_percpu::__priv::NoPreemptGuard::new()` and `ax_percpu::percpu_area_base()` in macro expansion.
#[allow(unused_imports)]
use crate as ax_percpu;

/// On x86, we use `gs:SELF_PTR` to store the address of the per-CPU data area base.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
#[ax_percpu_macros::def_percpu]
static SELF_PTR: usize = 0;

#[cfg(target_os = "linux")]
static mut GS: usize = 0;

/// .
/// # Safety
#[cfg(target_os = "linux")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __get_gs() -> usize {
    unsafe { GS }
}
