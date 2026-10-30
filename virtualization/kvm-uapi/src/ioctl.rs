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

//! Linux KVM ioctl numbers and shared ABI constants.
//!
//! The `public` module is the user-visible KVM API surface returned by
//! axvisor_core. The constants outside it are lower-level layout details used
//! while parsing ioctl payloads and the vCPU run page.

pub mod public {
    use super::*;

    /// Current Linux KVM userspace API version.
    pub const KVM_API_VERSION: usize = 12;

    /// Returns [`KVM_API_VERSION`].
    pub const KVM_GET_API_VERSION: u32 = ioc(KVMIO, 0x00);
    /// Creates a VM fd.
    pub const KVM_CREATE_VM: u32 = ioc(KVMIO, 0x01);
    /// Returns the x86 MSR indices supported by this KVM-compatible endpoint.
    pub const KVM_GET_MSR_INDEX_LIST: u32 = iowr(KVMIO, 0x02, KVM_MSR_LIST_SIZE);
    /// Checks whether a KVM capability is supported.
    pub const KVM_CHECK_EXTENSION: u32 = ioc(KVMIO, 0x03);
    /// Returns the size of the vCPU mmap area.
    pub const KVM_GET_VCPU_MMAP_SIZE: u32 = ioc(KVMIO, 0x04);
    /// Returns the x86 CPUID entries supported by this KVM-compatible endpoint.
    pub const KVM_GET_SUPPORTED_CPUID: u32 = iowr(KVMIO, 0x05, KVM_CPUID2_SIZE);
    /// Creates a vCPU fd on a VM fd.
    pub const KVM_CREATE_VCPU: u32 = ioc(KVMIO, 0x41);
    /// Configures one userspace-backed guest memory slot on a VM fd.
    pub const KVM_SET_USER_MEMORY_REGION: u32 = iow(KVMIO, 0x46, KVM_USERSPACE_MEMORY_REGION_SIZE);
    /// Sets the x86 TSS address.
    pub const KVM_SET_TSS_ADDR: u32 = ioc(KVMIO, 0x47);
    /// Sets the x86 identity-map address used by the in-kernel IRQ chip.
    pub const KVM_SET_IDENTITY_MAP_ADDR: u32 = iow(KVMIO, 0x48, KVM_IDENTITY_MAP_ADDR_SIZE);
    /// Creates an in-kernel x86 IRQ chip.
    pub const KVM_CREATE_IRQCHIP: u32 = ioc(KVMIO, 0x60);
    /// Sets the level of an x86 GSI input line.
    pub const KVM_IRQ_LINE: u32 = iow(KVMIO, 0x61, KVM_IRQ_LEVEL_SIZE);
    /// Gets the state of an x86 in-kernel interrupt controller.
    pub const KVM_GET_IRQCHIP: u32 = iowr(KVMIO, 0x62, KVM_IRQCHIP_SIZE);
    /// Sets the state of an x86 in-kernel interrupt controller.
    pub const KVM_SET_IRQCHIP: u32 = ior(KVMIO, 0x63, KVM_IRQCHIP_SIZE);
    /// Sets x86 GSI routing.
    pub const KVM_SET_GSI_ROUTING: u32 = iow(KVMIO, 0x6a, KVM_IRQ_ROUTING_SIZE);
    /// Registers or unregisters an eventfd as an x86 interrupt source.
    pub const KVM_IRQFD: u32 = iow(KVMIO, 0x76, KVM_IRQFD_SIZE);
    /// Creates an in-kernel x86 PIT.
    pub const KVM_CREATE_PIT2: u32 = iow(KVMIO, 0x77, KVM_PIT_CONFIG_SIZE);
    /// Registers or unregisters an eventfd for guest I/O writes.
    pub const KVM_IOEVENTFD: u32 = iow(KVMIO, 0x79, KVM_IOEVENTFD_SIZE);
    /// Sets x86 VM clock data.
    pub const KVM_SET_CLOCK: u32 = iow(KVMIO, 0x7b, KVM_CLOCK_DATA_SIZE);
    /// Gets x86 VM clock data.
    pub const KVM_GET_CLOCK: u32 = ior(KVMIO, 0x7c, KVM_CLOCK_DATA_SIZE);
    /// Runs a vCPU until it exits to userspace.
    pub const KVM_RUN: u32 = ioc(KVMIO, 0x80);
    /// Gets x86 general-purpose register state.
    pub const KVM_GET_REGS: u32 = ior(KVMIO, 0x81, KVM_X86_REGS_SIZE);
    /// Sets x86 general-purpose register state.
    pub const KVM_SET_REGS: u32 = iow(KVMIO, 0x82, KVM_X86_REGS_SIZE);
    /// Gets x86 special register state.
    pub const KVM_GET_SREGS: u32 = ior(KVMIO, 0x83, KVM_X86_SREGS_SIZE);
    /// Sets x86 special register state.
    pub const KVM_SET_SREGS: u32 = iow(KVMIO, 0x84, KVM_X86_SREGS_SIZE);
    /// Injects or clears an architecture-specific vCPU interrupt.
    pub const KVM_INTERRUPT: u32 = iow(KVMIO, 0x86, KVM_INTERRUPT_SIZE);
    /// Gets x86 MSR state.
    pub const KVM_GET_MSRS: u32 = iowr(KVMIO, 0x88, KVM_MSRS_SIZE);
    /// Sets x86 MSR state.
    pub const KVM_SET_MSRS: u32 = iow(KVMIO, 0x89, KVM_MSRS_SIZE);
    /// Sets a vCPU signal mask.
    pub const KVM_SET_SIGNAL_MASK: u32 = iow(KVMIO, 0x8b, KVM_SIGNAL_MASK_SIZE);
    /// Gets x86 FPU state.
    pub const KVM_GET_FPU: u32 = ior(KVMIO, 0x8c, KVM_X86_FPU_SIZE);
    /// Sets x86 FPU state.
    pub const KVM_SET_FPU: u32 = iow(KVMIO, 0x8d, KVM_X86_FPU_SIZE);
    /// Gets x86 LAPIC state.
    pub const KVM_GET_LAPIC: u32 = ior(KVMIO, 0x8e, KVM_X86_LAPIC_STATE_SIZE);
    /// Sets x86 LAPIC state.
    pub const KVM_SET_LAPIC: u32 = iow(KVMIO, 0x8f, KVM_X86_LAPIC_STATE_SIZE);
    /// Sets x86 CPUID entries.
    pub const KVM_SET_CPUID2: u32 = iow(KVMIO, 0x90, KVM_CPUID2_SIZE);
    /// Gets x86 CPUID entries configured on this vCPU.
    pub const KVM_GET_CPUID2: u32 = iowr(KVMIO, 0x91, KVM_CPUID2_SIZE);
    /// Sets the guest physical address of the x86 virtual-APIC page.
    pub const KVM_SET_VAPIC_ADDR: u32 = iow(KVMIO, 0x93, KVM_VAPIC_ADDR_SIZE);
    /// Returns the vCPU MP state.
    pub const KVM_GET_MP_STATE: u32 = ior(KVMIO, 0x98, KVM_MP_STATE_SIZE);
    /// Sets the vCPU MP state.
    pub const KVM_SET_MP_STATE: u32 = iow(KVMIO, 0x99, KVM_MP_STATE_SIZE);
    /// Returns the x86 machine-check capabilities available to guests.
    pub const KVM_X86_GET_MCE_CAP_SUPPORTED: u32 = ior(KVMIO, 0x9d, KVM_X86_MCE_CAP_SIZE);
    /// Gets x86 PIT state.
    pub const KVM_GET_PIT2: u32 = ior(KVMIO, 0x9f, KVM_PIT_STATE2_SIZE);
    /// Gets x86 vCPU event state.
    pub const KVM_GET_VCPU_EVENTS: u32 = ior(KVMIO, 0x9f, KVM_X86_VCPU_EVENTS_SIZE);
    /// Sets x86 PIT state.
    pub const KVM_SET_PIT2: u32 = iow(KVMIO, 0xa0, KVM_PIT_STATE2_SIZE);
    /// Sets x86 vCPU event state.
    pub const KVM_SET_VCPU_EVENTS: u32 = iow(KVMIO, 0xa0, KVM_X86_VCPU_EVENTS_SIZE);
    /// Gets x86 debug register state.
    pub const KVM_GET_DEBUGREGS: u32 = ior(KVMIO, 0xa1, KVM_X86_DEBUGREGS_SIZE);
    /// Sets x86 debug register state.
    pub const KVM_SET_DEBUGREGS: u32 = iow(KVMIO, 0xa2, KVM_X86_DEBUGREGS_SIZE);
    /// Sets x86 TSC frequency in kHz.
    pub const KVM_SET_TSC_KHZ: u32 = ioc(KVMIO, 0xa2);
    /// Gets x86 TSC frequency in kHz.
    pub const KVM_GET_TSC_KHZ: u32 = ioc(KVMIO, 0xa3);
    /// Enables a KVM capability on a VM or vCPU fd.
    pub const KVM_ENABLE_CAP: u32 = iow(KVMIO, 0xa3, KVM_ENABLE_CAP_SIZE);
    /// Gets x86 XSAVE state.
    pub const KVM_GET_XSAVE: u32 = ior(KVMIO, 0xa4, KVM_X86_XSAVE_SIZE);
    /// Sets x86 XSAVE state.
    pub const KVM_SET_XSAVE: u32 = iow(KVMIO, 0xa5, KVM_X86_XSAVE_SIZE);
    /// Injects an x86 MSI into a VM.
    pub const KVM_SIGNAL_MSI: u32 = iow(KVMIO, 0xa5, KVM_MSI_SIZE);
    /// Gets x86 XCR state.
    pub const KVM_GET_XCRS: u32 = ior(KVMIO, 0xa6, KVM_X86_XCRS_SIZE);
    /// Sets x86 XCR state.
    pub const KVM_SET_XCRS: u32 = iow(KVMIO, 0xa7, KVM_X86_XCRS_SIZE);
    /// Gets one architecture-specific vCPU register.
    pub const KVM_GET_ONE_REG: u32 = iow(KVMIO, 0xab, KVM_ONE_REG_SIZE);
    /// Sets one architecture-specific vCPU register.
    pub const KVM_SET_ONE_REG: u32 = iow(KVMIO, 0xac, KVM_ONE_REG_SIZE);
    /// Stops x86 kvmclock updates.
    pub const KVM_KVMCLOCK_CTRL: u32 = ioc(KVMIO, 0xad);
    /// Initializes an AArch64 vCPU from a preferred target description.
    pub const KVM_ARM_VCPU_INIT: u32 = iow(KVMIO, 0xae, KVM_ARM_VCPU_INIT_SIZE);
    /// Gets the preferred AArch64 vCPU target for a VM.
    pub const KVM_ARM_PREFERRED_TARGET: u32 = ior(KVMIO, 0xaf, KVM_ARM_VCPU_INIT_SIZE);
    /// Gets the architecture-specific vCPU register IDs supported by this vCPU.
    pub const KVM_GET_REG_LIST: u32 = iowr(KVMIO, 0xb0, KVM_REG_LIST_SIZE);
    /// Gets x86 XSAVE state using the KVM_CAP_XSAVE2 ioctl number.
    pub const KVM_GET_XSAVE2: u32 = ior(KVMIO, 0xcf, KVM_X86_XSAVE_SIZE);
    /// Creates a device fd associated with a VM.
    pub const KVM_CREATE_DEVICE: u32 = iowr(KVMIO, 0xe0, KVM_CREATE_DEVICE_SIZE);
    /// Sets an attribute on a KVM device fd.
    pub const KVM_SET_DEVICE_ATTR: u32 = iow(KVMIO, 0xe1, KVM_DEVICE_ATTR_SIZE);
    /// Checks whether a KVM device fd supports an attribute.
    pub const KVM_HAS_DEVICE_ATTR: u32 = iow(KVMIO, 0xe3, KVM_DEVICE_ATTR_SIZE);

    pub const KVM_CAP_IRQCHIP: usize = 0;
    pub const KVM_CAP_USER_MEMORY: usize = 3;
    pub const KVM_CAP_SET_TSS_ADDR: usize = 4;
    pub const KVM_CAP_EXT_CPUID: usize = 7;
    pub const KVM_CAP_NR_VCPUS: usize = 9;
    pub const KVM_CAP_NR_MEMSLOTS: usize = 10;
    pub const KVM_CAP_MP_STATE: usize = 14;
    pub const KVM_CAP_DESTROY_MEMORY_REGION_WORKS: usize = 21;
    pub const KVM_CAP_IRQ_ROUTING: usize = 25;
    pub const KVM_CAP_JOIN_MEMORY_REGIONS_WORKS: usize = 30;
    pub const KVM_CAP_MCE: usize = 31;
    pub const KVM_CAP_IRQFD: usize = 32;
    pub const KVM_CAP_PIT2: usize = 33;
    pub const KVM_CAP_PIT_STATE2: usize = 35;
    pub const KVM_CAP_IOEVENTFD: usize = 36;
    pub const KVM_CAP_SET_IDENTITY_MAP_ADDR: usize = 37;
    pub const KVM_CAP_ADJUST_CLOCK: usize = 39;
    pub const KVM_CAP_INTERNAL_ERROR_DATA: usize = 40;
    pub const KVM_CAP_VCPU_EVENTS: usize = 41;
    pub const KVM_CAP_DEBUGREGS: usize = 50;
    pub const KVM_CAP_X86_ROBUST_SINGLESTEP: usize = 51;
    pub const KVM_CAP_XSAVE: usize = 55;
    pub const KVM_CAP_XCRS: usize = 56;
    pub const KVM_CAP_MAX_VCPUS: usize = 66;
    pub const KVM_CAP_ONE_REG: usize = 70;
    pub const KVM_CAP_SIGNAL_MSI: usize = 77;
    pub const KVM_CAP_ARM_PSCI: usize = 87;
    pub const KVM_CAP_DEVICE_CTRL: usize = 89;
    pub const KVM_CAP_ARM_PSCI_0_2: usize = 102;
    pub const KVM_CAP_IOEVENTFD_ANY_LENGTH: usize = 122;
    pub const KVM_CAP_IMMEDIATE_EXIT: usize = 136;
    pub const KVM_CAP_XSAVE2: usize = 208;
    pub const KVM_CAP_SYSTEM_EVENT_DATA: usize = 215;
}

// Linux reserves ioctl type 0xae for KVM.
pub const KVMIO: u32 = 0xae;

#[cfg(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
))]
pub const KVM_MAX_VCPUS: usize = 8;
#[cfg(not(any(
    target_arch = "aarch64",
    target_arch = "riscv64",
    target_arch = "x86_64"
)))]
pub const KVM_MAX_VCPUS: usize = 1;
/// Maximum number of userspace memory slots supported by one VM.
///
/// KVM users such as gVisor map the host address space as a collection of
/// physical regions and rely on the legacy KVM baseline of 256 slots.  The
/// control implementation stores slots dynamically, so this is an ABI limit
/// rather than a preallocated resource cost.
pub const KVM_MAX_MEMORY_SLOTS: usize = 256;
pub const KVM_MAX_CPUID_ENTRIES: usize = 256;
pub const KVM_MAX_MSR_ENTRIES: usize = 256;
pub const KVM_VCPU_MMAP_SIZE: usize = 0x1000;
pub const KVM_MSR_LIST_SIZE: u32 = 4;
pub const KVM_CPUID2_SIZE: u32 = 8;
pub const KVM_CPUID_ENTRY2_SIZE: usize = 40;
pub const KVM_MSRS_SIZE: u32 = 8;
pub const KVM_MSR_ENTRY_SIZE: usize = 16;
pub const KVM_USERSPACE_MEMORY_REGION_SIZE: u32 = 32;
pub const KVM_IDENTITY_MAP_ADDR_SIZE: u32 = 8;
pub const KVM_IOEVENTFD_SIZE: u32 = 64;
pub const KVM_CLOCK_DATA_SIZE: u32 = 48;
pub const KVM_IRQ_ROUTING_SIZE: u32 = 8;
pub const KVM_IRQ_LEVEL_SIZE: u32 = 8;
pub const KVM_IRQCHIP_SIZE: u32 = 520;
pub const KVM_IRQCHIP_STATE_SIZE: usize = 512;
pub const KVM_NR_IRQCHIPS: usize = 3;
pub const KVM_IRQCHIP_IOAPIC: u32 = 2;
pub const KVM_IOAPIC_IOREGSEL_OFFSET: usize = 16;
pub const KVM_IOAPIC_ID_OFFSET: usize = 20;
pub const KVM_IOAPIC_IRR_OFFSET: usize = 24;
pub const KVM_IOAPIC_REDIRENT_OFFSET: usize = 32;
pub const KVM_IRQ_ROUTING_ENTRY_SIZE: usize = 48;
pub const KVM_MAX_IRQ_ROUTES: usize = 4096;
pub const KVM_X86_IOAPIC_NUM_PINS: u32 = 24;
pub const KVM_IRQ_ROUTING_IRQCHIP: u32 = 1;
pub const KVM_IRQ_ROUTING_MSI: u32 = 2;
pub const KVM_IRQFD_SIZE: u32 = 32;
pub const KVM_MSI_SIZE: u32 = 32;
pub const KVM_IRQFD_FLAG_DEASSIGN: u32 = 1 << 0;
pub const KVM_IRQFD_FLAG_RESAMPLE: u32 = 1 << 1;
pub const KVM_IRQFD_VALID_FLAGS: u32 = KVM_IRQFD_FLAG_DEASSIGN | KVM_IRQFD_FLAG_RESAMPLE;
pub const KVM_PIT_CONFIG_SIZE: u32 = 64;
pub const KVM_PIT_STATE2_SIZE: u32 = 112;
pub const KVM_PIT_VALID_FLAGS: u32 = 1;
pub const KVM_SIGNAL_MASK_SIZE: u32 = 4;
pub const KVM_SIGNAL_MASK_MAX_LEN: usize = 128;
pub const KVM_ENABLE_CAP_SIZE: u32 = 104;
pub const KVM_INTERRUPT_SIZE: u32 = 4;
pub const KVM_MP_STATE_SIZE: u32 = 4;
pub const KVM_ONE_REG_SIZE: u32 = 16;
pub const KVM_ARM_VCPU_INIT_SIZE: u32 = 32;
pub const KVM_CREATE_DEVICE_SIZE: u32 = 12;
pub const KVM_DEVICE_ATTR_SIZE: u32 = 24;
pub const KVM_REG_LIST_SIZE: u32 = 8;
pub const KVM_X86_REGS_SIZE: u32 = 18 * 8;
#[cfg(target_arch = "x86_64")]
pub const KVM_X86_REGS_RFLAGS_OFFSET: usize = 17 * 8;
pub const KVM_X86_SREGS_SIZE: u32 = 312;
pub const KVM_X86_FPU_SIZE: u32 = 416;
pub const KVM_X86_VCPU_EVENTS_SIZE: u32 = 64;
pub const KVM_X86_MCE_CAP_SIZE: u32 = 8;
pub const KVM_X86_DEBUGREGS_SIZE: u32 = 128;
pub const KVM_X86_XSAVE_SIZE: u32 = 4096;
pub const KVM_X86_XCRS_SIZE: u32 = 392;
pub const KVM_X86_LAPIC_STATE_SIZE: u32 = 1024;
pub const KVM_VAPIC_ADDR_SIZE: u32 = 8;
pub const KVM_MP_STATE_RUNNABLE: u32 = 0;
pub const KVM_MP_STATE_UNINITIALIZED: u32 = 1;
pub const KVM_MP_STATE_INIT_RECEIVED: u32 = 2;
pub const KVM_MP_STATE_HALTED: u32 = 3;
pub const KVM_MP_STATE_SIPI_RECEIVED: u32 = 4;
pub const KVM_MP_STATE_STOPPED: u32 = 5;
pub const KVM_MP_STATE_CHECK_STOP: u32 = 6;
pub const KVM_MP_STATE_OPERATING: u32 = 7;
pub const KVM_MP_STATE_LOAD: u32 = 8;
pub const KVM_MP_STATE_AP_RESET_HOLD: u32 = 9;
pub const KVM_MP_STATE_SUSPENDED: u32 = 10;
pub const KVM_MEM_ALLOWED_FLAGS: u32 = 0;
#[cfg(target_arch = "x86_64")]
pub const X86_RFLAGS_IF: u64 = 1 << 9;
pub const KVM_IOEVENTFD_FLAG_DATAMATCH: u32 = 1 << 0;
pub const KVM_IOEVENTFD_FLAG_PIO: u32 = 1 << 1;
pub const KVM_IOEVENTFD_FLAG_DEASSIGN: u32 = 1 << 2;
pub const KVM_IOEVENTFD_VALID_FLAGS: u32 =
    KVM_IOEVENTFD_FLAG_DATAMATCH | KVM_IOEVENTFD_FLAG_PIO | KVM_IOEVENTFD_FLAG_DEASSIGN;
pub const KVM_INTERRUPT_SET: u32 = u32::MAX;
pub const KVM_INTERRUPT_UNSET: u32 = u32::MAX - 1;
#[cfg(target_arch = "x86_64")]
pub const MSR_KVM_WALL_CLOCK: usize = 0x11;
#[cfg(target_arch = "x86_64")]
pub const MSR_KVM_SYSTEM_TIME: usize = 0x12;
#[cfg(target_arch = "x86_64")]
pub const MSR_KVM_WALL_CLOCK_NEW: usize = 0x4b56_4d00;
#[cfg(target_arch = "x86_64")]
pub const MSR_KVM_SYSTEM_TIME_NEW: usize = 0x4b56_4d01;
#[cfg(target_arch = "x86_64")]
pub const KVM_SYSTEM_TIME_ENABLE: u64 = 1;
#[cfg(target_arch = "x86_64")]
pub const KVM_ENOSYS: isize = 1000;
#[cfg(target_arch = "x86_64")]
pub const KVM_HC_CLOCK_PAIRING: u64 = 9;
#[cfg(target_arch = "x86_64")]
pub const PVCLOCK_TSC_STABLE_BIT: u8 = 1 << 0;
#[cfg(target_arch = "x86_64")]
pub const KVM_RUN_REQUEST_INTERRUPT_WINDOW_OFFSET: usize = 0;
pub const KVM_RUN_IMMEDIATE_EXIT_OFFSET: usize = 1;
pub const KVM_RUN_EXIT_REASON_OFFSET: usize = 8;
#[cfg(target_arch = "x86_64")]
pub const KVM_RUN_READY_FOR_INTERRUPT_INJECTION_OFFSET: usize = 12;
#[cfg(target_arch = "x86_64")]
pub const KVM_RUN_IF_FLAG_OFFSET: usize = 13;
#[cfg(target_arch = "x86_64")]
pub const KVM_RUN_FLAGS_OFFSET: usize = 14;
pub const KVM_RUN_INTERNAL_SUBERROR_OFFSET: usize = 32;
pub const KVM_RUN_INTERNAL_NDATA_OFFSET: usize = 36;
pub const KVM_RUN_FAIL_ENTRY_HARDWARE_REASON_OFFSET: usize = 32;
pub const KVM_RUN_IO_DIRECTION_OFFSET: usize = 32;
pub const KVM_RUN_IO_SIZE_OFFSET: usize = 33;
pub const KVM_RUN_IO_PORT_OFFSET: usize = 34;
pub const KVM_RUN_IO_COUNT_OFFSET: usize = 36;
pub const KVM_RUN_IO_DATA_OFFSET_OFFSET: usize = 40;
pub const KVM_RUN_IO_DATA_OFFSET: usize = 0x100;
pub const KVM_EXIT_IO_IN: u8 = 0;
pub const KVM_EXIT_IO_OUT: u8 = 1;
pub const KVM_RUN_MMIO_PHYS_ADDR_OFFSET: usize = 32;
pub const KVM_RUN_MMIO_DATA_OFFSET: usize = 40;
pub const KVM_RUN_MMIO_LEN_OFFSET: usize = 48;
pub const KVM_RUN_MMIO_IS_WRITE_OFFSET: usize = 52;
#[cfg(target_arch = "x86_64")]
pub const KVM_RUN_IOAPIC_EOI_VECTOR_OFFSET: usize = 32;
pub const KVM_EXIT_UNKNOWN: u32 = 0;
pub const KVM_EXIT_IO: u32 = 2;
pub const KVM_EXIT_HLT: u32 = 5;
pub const KVM_EXIT_MMIO: u32 = 6;
pub const KVM_EXIT_IRQ_WINDOW_OPEN: u32 = 7;
pub const KVM_EXIT_SHUTDOWN: u32 = 8;
pub const KVM_EXIT_FAIL_ENTRY: u32 = 9;
pub const KVM_EXIT_INTR: u32 = 10;
pub const KVM_EXIT_INTERNAL_ERROR: u32 = 17;
pub const KVM_EXIT_SYSTEM_EVENT: u32 = 24;
pub const KVM_SYSTEM_EVENT_SHUTDOWN: u32 = 1;
pub const KVM_SYSTEM_EVENT_RESET: u32 = 2;
pub const KVM_RUN_SYSTEM_EVENT_OFFSET: usize = 32;
pub const KVM_RUN_SYSTEM_EVENT_TYPE_OFFSET: usize = 32;
pub const KVM_RUN_SYSTEM_EVENT_NDATA_OFFSET: usize = 36;
pub const KVM_RUN_SYSTEM_EVENT_DATA_OFFSET: usize = 40;
pub const KVM_RUN_SYSTEM_EVENT_SIZE: usize = 8 + 16 * 8;
#[cfg(target_arch = "x86_64")]
pub const KVM_EXIT_IOAPIC_EOI: u32 = 26;
pub const KVM_INTERNAL_ERROR_EMULATION: u32 = 1;
pub const KVM_EXIT_MEMORY_FAULT: u32 = 39;
#[cfg(target_arch = "x86_64")]
pub const KVM_CPUID_FLAG_SIGNIFICANT_INDEX: u32 = 1;
#[cfg(target_arch = "riscv64")]
pub const RISCV_S_EXT_VECTOR: usize = (1usize << (usize::BITS - 1)) + 9;
pub const PAGE_SIZE: u64 = 4096;
pub const PAGE_SIZE_USIZE: usize = PAGE_SIZE as usize;
pub const X86_RAX_REG_INDEX: usize = 0;
pub const SUPPORTED_X86_MSRS: &[u32] = &[
    0x0000_0010, // IA32_TSC
    0x0000_0011, // MSR_KVM_WALL_CLOCK
    0x0000_0012, // MSR_KVM_SYSTEM_TIME
    0x0000_001b, // IA32_APIC_BASE
    0x0000_003b, // IA32_TSC_ADJUST
    0x0000_0140, // IA32_MISC_FEATURES_ENABLES
    0x0000_0174, // IA32_SYSENTER_CS
    0x0000_0175, // IA32_SYSENTER_ESP
    0x0000_0176, // IA32_SYSENTER_EIP
    0x0000_01a0, // IA32_MISC_ENABLE
    0x0000_0200, // MTRR_PHYS_BASE_0
    0x0000_0201, // MTRR_PHYS_MASK_0
    0x0000_0202, // MTRR_PHYS_BASE_1
    0x0000_0203, // MTRR_PHYS_MASK_1
    0x0000_0204, // MTRR_PHYS_BASE_2
    0x0000_0205, // MTRR_PHYS_MASK_2
    0x0000_0206, // MTRR_PHYS_BASE_3
    0x0000_0207, // MTRR_PHYS_MASK_3
    0x0000_0208, // MTRR_PHYS_BASE_4
    0x0000_0209, // MTRR_PHYS_MASK_4
    0x0000_020a, // MTRR_PHYS_BASE_5
    0x0000_020b, // MTRR_PHYS_MASK_5
    0x0000_020c, // MTRR_PHYS_BASE_6
    0x0000_020d, // MTRR_PHYS_MASK_6
    0x0000_020e, // MTRR_PHYS_BASE_7
    0x0000_020f, // MTRR_PHYS_MASK_7
    0x0000_0250, // MTRR_FIX_64K_00000
    0x0000_0258, // MTRR_FIX_16K_80000
    0x0000_0259, // MTRR_FIX_16K_A0000
    0x0000_0268, // MTRR_FIX_4K_C0000
    0x0000_0269, // MTRR_FIX_4K_C8000
    0x0000_026a, // MTRR_FIX_4K_D0000
    0x0000_026b, // MTRR_FIX_4K_D8000
    0x0000_026c, // MTRR_FIX_4K_E0000
    0x0000_026d, // MTRR_FIX_4K_E8000
    0x0000_026e, // MTRR_FIX_4K_F0000
    0x0000_026f, // MTRR_FIX_4K_F8000
    0x0000_0277, // IA32_PAT
    0x0000_02ff, // MTRR_DEF_TYPE
    0xc000_0080, // EFER
    0xc000_0081, // STAR
    0xc000_0082, // LSTAR
    0xc000_0083, // CSTAR
    0xc000_0084, // SYSCALL_MASK
    0xc000_0100, // FS_BASE
    0xc000_0101, // GS_BASE
    0xc000_0102, // KERNEL_GS_BASE
    0x4b56_4d00, // MSR_KVM_WALL_CLOCK_NEW
    0x4b56_4d01, // MSR_KVM_SYSTEM_TIME_NEW
];

pub const fn ioc(type_: u32, nr: u32) -> u32 {
    (type_ << 8) | nr
}

pub const fn iow(type_: u32, nr: u32, size: u32) -> u32 {
    const IOC_WRITE: u32 = 1;
    const IOC_TYPESHIFT: u32 = 8;
    const IOC_SIZESHIFT: u32 = 16;
    const IOC_DIRSHIFT: u32 = 30;

    (IOC_WRITE << IOC_DIRSHIFT) | (size << IOC_SIZESHIFT) | (type_ << IOC_TYPESHIFT) | nr
}

pub const fn ior(type_: u32, nr: u32, size: u32) -> u32 {
    const IOC_READ: u32 = 2;
    const IOC_TYPESHIFT: u32 = 8;
    const IOC_SIZESHIFT: u32 = 16;
    const IOC_DIRSHIFT: u32 = 30;

    (IOC_READ << IOC_DIRSHIFT) | (size << IOC_SIZESHIFT) | (type_ << IOC_TYPESHIFT) | nr
}

pub const fn iowr(type_: u32, nr: u32, size: u32) -> u32 {
    const IOC_WRITE: u32 = 1;
    const IOC_READ: u32 = 2;
    const IOC_TYPESHIFT: u32 = 8;
    const IOC_SIZESHIFT: u32 = 16;
    const IOC_DIRSHIFT: u32 = 30;

    ((IOC_WRITE | IOC_READ) << IOC_DIRSHIFT)
        | (size << IOC_SIZESHIFT)
        | (type_ << IOC_TYPESHIFT)
        | nr
}
