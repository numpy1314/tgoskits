// SPDX-License-Identifier: Apache-2.0
//! Saved GIC state affected by resetting the per-vCPU architectural timers.

fn active_priority(lr: u64, priority_bits: u32, vmcr: u64) -> Option<(usize, usize, u64)> {
    if lr & (1 << 63) == 0 {
        return None;
    }
    let group = (lr >> 60 & 1) as usize;
    // APRs track group priority, not subpriority. Group 1 uses VBPR1
    // unless VCBPR selects VBPR0; their binary-point encodings differ.
    let shift = if group == 0 || vmcr & (1 << 4) != 0 {
        ((vmcr >> 21) & 7) as u32 + 1
    } else {
        ((vmcr >> 18) & 7) as u32
    }
    .max(8 - priority_bits);
    let mask = (0xffu64 << shift) & 0xff;
    let priority = ((lr >> 48) & mask) >> (8 - priority_bits);
    Some((group, (priority / 32) as usize, 1 << (priority % 32)))
}

/// Remove timer INTIDs without discarding another device's pending/active IRQ.
/// The APR width follows ICH_VTR_EL2.PREbits; reject an unsupported encoding
/// before changing any state.
pub(crate) fn clear_timer_interrupts(
    list_registers: &mut [u64],
    ap0r: &mut [u64; 4],
    ap1r: &mut [u64; 4],
    vmcr: u64,
    priority_bits: u32,
) -> bool {
    if !(5..=7).contains(&priority_bits) {
        return false;
    }
    let mut removed_priorities = [[0u64; 4]; 2];
    for lr in list_registers.iter_mut() {
        if matches!(*lr as u32, 27 | 30) {
            if let Some((group, register, bit)) = active_priority(*lr, priority_bits, vmcr) {
                removed_priorities[group][register] |= bit;
            }
            *lr = 0;
        }
    }
    // Different active LRs can share a group/preemption priority. Retain the
    // APR bit whenever a surviving interrupt still accounts for it.
    for &lr in list_registers.iter() {
        if let Some((group, register, bit)) = active_priority(lr, priority_bits, vmcr) {
            removed_priorities[group][register] &= !bit;
        }
    }
    for index in 0..4 {
        ap0r[index] &= !removed_priorities[0][index];
        ap1r[index] &= !removed_priorities[1][index];
    }
    true
}
