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

use aarch64_cpu_ext::registers::*;
use ax_memory_addr::VirtAddr;

pub(crate) const PSCI_VERSION_0_2: u64 = 2;
#[cfg(feature = "control")]
#[cfg(feature = "control")]
pub(crate) const PSCI_SUCCESS: i64 = 0;
pub(crate) const PSCI_NOT_SUPPORTED: i64 = -1;
pub(crate) const PSCI_INVALID_PARAMS: i64 = -2;
#[cfg(feature = "control")]
#[cfg(feature = "control")]
pub(crate) const PSCI_INTERNAL_FAILURE: i64 = -6;
pub(crate) const PSCI_MPIDR_HWID_MASK: u64 = 0x00ff_00ff_ffff;

/// Host-independent decoding shared by the control and static ARM frontends.
/// The current profile advertises PSCI 0.2 only. Unimplemented standard-service
/// calls return a guest error; non-PSCI HVCs retain their existing dispatch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PsciCall {
    Version,
    CpuOff,
    CpuOn {
        target: u64,
        entry: u64,
        context: u64,
    },
    AffinityInfo {
        target: u64,
        level: u64,
    },
    MigrateInfoType,
    SystemOff,
    SystemReset,
    Unsupported,
}

pub(crate) fn decode_psci(function: u64, mut args: [u64; 6]) -> Option<PsciCall> {
    let function = function as u32;
    // PSCI belongs to SMCCC's Standard Service owner (4). Other owners may
    // belong to a private HVC interface and must keep their existing path.
    if (function >> 24) & 0x3f != 4 {
        return None;
    }
    if function & (1 << 30) == 0 {
        for argument in &mut args {
            *argument = u64::from(*argument as u32);
        }
    }
    Some(match function {
        0x8400_0000 => PsciCall::Version,
        0x8400_0002 => PsciCall::CpuOff,
        0x8400_0003 | 0xc400_0003 => PsciCall::CpuOn {
            target: args[0],
            entry: args[1],
            context: args[2],
        },
        0x8400_0004 | 0xc400_0004 => PsciCall::AffinityInfo {
            target: args[0],
            level: args[1],
        },
        0x8400_0006 => PsciCall::MigrateInfoType,
        0x8400_0008 => PsciCall::SystemOff,
        0x8400_0009 => PsciCall::SystemReset,
        // CPU_SUSPEND requires the control timer-aware idle protocol, which
        // is not implemented in this lifecycle change. FEATURES/RESET2 need
        // PSCI 1.x and likewise must not be advertised prematurely.
        _ => PsciCall::Unsupported,
    })
}

#[cfg(feature = "control")]
#[cfg(feature = "control")]
pub(crate) fn psci_affinity_mask(level: u64) -> Option<u64> {
    match level {
        0 => Some(PSCI_MPIDR_HWID_MASK),
        1 => Some(0x00ff_00ff_ff00),
        2 => Some(0x00ff_00ff_0000),
        3 => Some(0x00ff_0000_0000),
        _ => None,
    }
}

pub(crate) fn clean_dcache_range(addr: VirtAddr, size: usize) {
    aarch64_cpu_ext::cache::dcache_range(
        aarch64_cpu_ext::cache::CacheOp::Clean,
        addr.as_usize(),
        size,
    );
}

pub fn hardware_check() {
    let pa_bits = match ID_AA64MMFR0_EL1.read_as_enum(ID_AA64MMFR0_EL1::PARange) {
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_32) => 32,
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_36) => 36,
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_40) => 40,
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_42) => 42,
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_44) => 44,
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_48) => 48,
        Some(ID_AA64MMFR0_EL1::PARange::Value::Bits_52) => 52,
        _ => 32,
    };

    let level = match pa_bits {
        44.. => 4,
        _ => 3,
    };

    #[cfg(feature = "ept-level-4")]
    {
        if level < 4 {
            panic!(
                "4-level EPT feature is enabled, but the hardware only supports {}-level page \
                 tables. Please disable the 4-level EPT feature or use hardware that supports \
                 4-level page tables.",
                level
            );
        }
    }
    #[cfg(not(feature = "ept-level-4"))]
    {
        if level > 3 {
            panic!(
                "The hardware supports {}-level page tables, but the 4-level EPT feature is not \
                 enabled. Please enable the 4-level EPT feature to utilize the hardware's full \
                 capabilities.",
                level
            );
        }
    }
}

#[cfg(test)]
mod psci_tests {
    use super::{PsciCall, decode_psci};

    #[test]
    fn preserves_non_standard_service_hypercalls() {
        assert_eq!(decode_psci(3, [0; 6]), None);
        assert_eq!(decode_psci(0x8200_abcd, [0; 6]), None);
        assert_eq!(
            decode_psci(0x8400_abcd, [0; 6]),
            Some(PsciCall::Unsupported)
        );
    }

    #[test]
    fn distinguishes_exact_ids_and_argument_width() {
        assert_eq!(
            decode_psci(0xc400_0008, [0; 6]),
            Some(PsciCall::Unsupported)
        );
        let args = [0x1_0000_0001, 0x2_0000_1000, 0x3_0000_0007, 0, 0, 0];
        assert_eq!(
            decode_psci(0x8400_0003, args),
            Some(PsciCall::CpuOn {
                target: 1,
                entry: 0x1000,
                context: 7
            })
        );
        assert_eq!(
            decode_psci(0xc400_0003, args),
            Some(PsciCall::CpuOn {
                target: args[0],
                entry: args[1],
                context: args[2]
            })
        );
    }
}
