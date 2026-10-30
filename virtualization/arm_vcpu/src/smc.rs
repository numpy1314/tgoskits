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

//! Guest firmware-call admission. Guest arguments never invoke physical EL3.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FirmwareConduit {
    Hvc,
    Smc,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FirmwareAction {
    Hypercall { nr: u64, args: [u64; 6] },
    NotSupported,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct FirmwareCallPlan {
    pub resume_pc: u64,
    pub action: FirmwareAction,
}

/// PSCI uses the standard-service owner, including unimplemented function IDs.
/// The shared PSCI decoder decides which exact IDs and versions are supported.
fn is_psci_call(function: u64) -> bool {
    (function as u32 >> 24) & 0x3f == 4
}

pub(crate) fn classify_firmware_call(
    conduit: FirmwareConduit,
    immediate: u16,
    exception_pc: u64,
    function: u64,
    args: [u64; 6],
) -> FirmwareCallPlan {
    // HVC's ELR already points past the instruction. A trapped SMC's ELR
    // points at the instruction, including when its immediate is invalid.
    let resume_pc = match conduit {
        FirmwareConduit::Hvc => exception_pc,
        FirmwareConduit::Smc => exception_pc.wrapping_add(4),
    };
    let action = if conduit == FirmwareConduit::Smc && immediate != 0 {
        FirmwareAction::NotSupported
    } else if is_psci_call(function) {
        FirmwareAction::Hypercall {
            // SMCCC function IDs are 32-bit. Parameter narrowing belongs to
            // the shared decoder so both frontends follow the same rule.
            nr: function as u32 as u64,
            args,
        }
    } else if conduit == FirmwareConduit::Hvc {
        // Preserve the existing private hypercall namespace and arguments.
        FirmwareAction::Hypercall { nr: function, args }
    } else {
        FirmwareAction::NotSupported
    };
    FirmwareCallPlan { resume_pc, action }
}
