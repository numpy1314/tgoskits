// SPDX-License-Identifier: Apache-2.0
// The admission policy is pure: run with rustc --test on the build host too.
#[path = "../src/smc.rs"]
mod smc;

use smc::{FirmwareAction, FirmwareConduit, classify_firmware_call};

#[test]
fn hvc_and_smc_route_psci_to_the_same_shared_dispatch() {
    // Cover CPU_ON32/64, OFF, RESET, RESET2 and an unimplemented standard call.
    let args = [0xffff_ffff_0000_0001, 0xffff_ffff_0000_1000, 3, 4, 5, 6];
    for nr in [
        0x8400_0003,
        0xc400_0003,
        0x8400_0008,
        0x8400_0009,
        0xc400_0012,
        0x8400_00ff,
    ] {
        let hvc = classify_firmware_call(FirmwareConduit::Hvc, 0, 0x1004, nr, args);
        let smc = classify_firmware_call(FirmwareConduit::Smc, 0, 0x1000, nr, args);
        assert_eq!(hvc, smc);
        assert_eq!(hvc.resume_pc, 0x1004);
        assert_eq!(hvc.action, FirmwareAction::Hypercall { nr, args });
    }
}

#[test]
fn reserved_smc_immediates_are_rejected_and_the_pc_progresses() {
    for imm in [1, 0x1234, u16::MAX] {
        for nr in [0x8400_0009, 0xc400_0003, 3] {
            let call = classify_firmware_call(FirmwareConduit::Smc, imm, 0x1000, nr, [0; 6]);
            assert_eq!(call.action, FirmwareAction::NotSupported);
            assert_eq!(call.resume_pc, 0x1004);
        }
    }
}

#[test]
fn non_psci_smc_never_becomes_a_private_hypercall_or_physical_call() {
    for nr in [3, 0x8000_0000, 0x8300_0009, 0x8500_0009, 0xffff_ffff] {
        let call = classify_firmware_call(FirmwareConduit::Smc, 0, 0x1000, nr, [0; 6]);
        assert_eq!(call.action, FirmwareAction::NotSupported);
        assert_eq!(call.resume_pc, 0x1004);
    }
}

#[test]
fn private_hvc_retains_its_original_function_number_and_registers() {
    let nr = 0x1234_5678_0000_0003;
    let args = [u64::MAX, 1, 2, 3, 4, 5];
    let call = classify_firmware_call(FirmwareConduit::Hvc, 0xabcd, 0x1004, nr, args);
    assert_eq!(call.resume_pc, 0x1004);
    assert_eq!(call.action, FirmwareAction::Hypercall { nr, args });
}

#[test]
fn psci_function_ids_are_32_bit_but_arguments_reach_the_shared_decoder() {
    let nr = 0xdead_beef_c400_0003;
    let args = [u64::MAX, 0xffff_0000_1234_5678, u64::MAX, 0, 0, 0];
    let call = classify_firmware_call(FirmwareConduit::Smc, 0, 0x1000, nr, args);
    assert_eq!(
        call.action,
        FirmwareAction::Hypercall {
            nr: 0xc400_0003,
            args
        }
    );
}
