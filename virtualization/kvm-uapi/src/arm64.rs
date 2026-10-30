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

//! AArch64-specific Linux KVM ABI definitions.

pub const KVM_ARM_TARGET_GENERIC_V8: u32 = 5;
pub const KVM_ARM_VCPU_POWER_OFF: usize = 0;
pub const KVM_ARM_VCPU_PSCI_0_2: usize = 2;

pub const KVM_ARM_IRQ_TYPE_SHIFT: u32 = 24;
pub const KVM_ARM_IRQ_TYPE_MASK: u32 = 0xf;
pub const KVM_ARM_IRQ_NUM_MASK: u32 = 0xffff;
pub const KVM_ARM_IRQ_TYPE_SPI: u32 = 1;

pub const KVM_REG_ARM64: u64 = 0x6000_0000_0000_0000;
pub const KVM_REG_SIZE_U64: u64 = 0x0030_0000_0000_0000;
pub const KVM_REG_ARM_CORE: u64 = 0x0010 << 16;
pub const KVM_REG_ARM64_SYSREG: u64 = 0x0013 << 16;
pub const KVM_REG_ARM_FW: u64 = 0x0014 << 16;
pub const KVM_REG_ARM_PSCI_VERSION: u64 = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_FW;

pub const KVM_REG_ARM64_CORE_X0: u64 = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE;
pub const KVM_REG_ARM64_CORE_SP_EL0: u64 = KVM_REG_ARM64_CORE_X0 + 62;
pub const KVM_REG_ARM64_CORE_PC: u64 = KVM_REG_ARM64_CORE_X0 + 64;
pub const KVM_REG_ARM64_CORE_PSTATE: u64 = KVM_REG_ARM64_CORE_X0 + 66;
pub const KVM_REG_ARM64_CORE_SP_EL1: u64 = KVM_REG_ARM64_CORE_X0 + 68;

pub const fn sys_reg(op0: u64, op1: u64, crn: u64, crm: u64, op2: u64) -> u64 {
    KVM_REG_ARM64
        | KVM_REG_SIZE_U64
        | KVM_REG_ARM64_SYSREG
        | ((op0 & 0x3) << 14)
        | ((op1 & 0x7) << 11)
        | ((crn & 0xf) << 7)
        | ((crm & 0xf) << 3)
        | (op2 & 0x7)
}

pub const KVM_REG_ARM64_MPIDR_EL1: u64 = sys_reg(3, 0, 0, 0, 5);
pub const KVM_REG_ARM64_SCTLR_EL1: u64 = sys_reg(3, 0, 1, 0, 0);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KvmDeviceAttr {
    pub flags: u32,
    pub group: u32,
    pub attr: u64,
    pub addr: u64,
}

pub const KVM_DEV_TYPE_ARM_VGIC_V3: u32 = 7;
pub const KVM_DEV_TYPE_ARM_VGIC_ITS: u32 = 8;
pub const KVM_CREATE_DEVICE_TEST: u32 = 1;

pub const KVM_DEV_ARM_VGIC_GRP_ADDR: u32 = 0;
pub const KVM_DEV_ARM_VGIC_GRP_NR_IRQS: u32 = 3;
pub const KVM_DEV_ARM_VGIC_GRP_CTRL: u32 = 4;
pub const KVM_DEV_ARM_VGIC_CTRL_INIT: u64 = 0;
pub const KVM_VGIC_V3_ADDR_TYPE_DIST: u64 = 2;
pub const KVM_VGIC_V3_ADDR_TYPE_REDIST: u64 = 3;
pub const KVM_VGIC_ITS_ADDR_TYPE: u64 = 4;
