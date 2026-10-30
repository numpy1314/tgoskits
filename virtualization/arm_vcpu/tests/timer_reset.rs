// SPDX-License-Identifier: Apache-2.0
#[path = "../src/interrupt_reset.rs"]
mod interrupt_reset;

use interrupt_reset::clear_timer_interrupts;

fn lr(intid: u32, group: u64, priority: u64, state: u64) -> u64 {
    intid as u64 | group << 60 | priority << 48 | state << 62
}

#[test]
fn reset_deasserts_timer_pending_and_active_lrs_without_losing_other_irqs() {
    let spi = lr(48, 1, 0x80, 1);
    let sgi = lr(3, 0, 0x40, 2);
    let mut list = [lr(27, 1, 0x20, 1), lr(30, 1, 0x30, 3), spi, sgi];
    let mut ap0r = [1 << 8, 0, 0, 0];
    let mut ap1r = [1 << 6, 0, 0, 0];
    assert!(clear_timer_interrupts(
        &mut list, &mut ap0r, &mut ap1r, 0, 5
    ));
    assert_eq!(list, [0, 0, spi, sgi]);
    assert_eq!(ap0r, [1 << 8, 0, 0, 0]);
    assert_eq!(ap1r, [0; 4]);
}

#[test]
fn a_surviving_irq_at_the_same_priority_keeps_its_active_priority_bit() {
    let mut list = [lr(27, 1, 0x40, 2), lr(55, 1, 0x40, 2)];
    let mut ap0r = [0; 4];
    let mut ap1r = [1 << 8, 0, 0, 0];
    assert!(clear_timer_interrupts(
        &mut list, &mut ap0r, &mut ap1r, 0, 5
    ));
    assert_eq!(list[0], 0);
    assert_ne!(list[1], 0);
    assert_eq!(ap1r[0], 1 << 8);
}

#[test]
fn active_priority_cleanup_tracks_group_and_implemented_priority_width() {
    for bits in 5..=7 {
        let mut list = [lr(27, 0, 0xe0, 2), lr(30, 1, 0xa0, 3)];
        let mut ap0r = [0; 4];
        let mut ap1r = [0; 4];
        let first = 0xe0usize >> (8 - bits);
        let second = 0xa0usize >> (8 - bits);
        ap0r[first / 32] = 1 << (first % 32);
        ap1r[second / 32] = 1 << (second % 32);
        assert!(clear_timer_interrupts(
            &mut list, &mut ap0r, &mut ap1r, 0, bits
        ));
        assert_eq!(list, [0; 2]);
        assert_eq!(ap0r, [0; 4]);
        assert_eq!(ap1r, [0; 4]);
    }
}

#[test]
fn unsupported_priority_encoding_does_not_partially_reset_state() {
    let mut list = [lr(27, 1, 0, 3)];
    let mut ap0r = [1; 4];
    let mut ap1r = [1; 4];
    let before = (list, ap0r, ap1r);
    assert!(!clear_timer_interrupts(
        &mut list, &mut ap0r, &mut ap1r, 0, 8
    ));
    assert_eq!((list, ap0r, ap1r), before);
}

#[test]
fn binary_point_grouping_preserves_other_active_interrupts() {
    // Both raw priorities map to group priority 0x40 with VBPR1=5.
    let mut list = [lr(27, 1, 0x40, 2), lr(49, 1, 0x58, 2)];
    let mut ap0r = [0; 4];
    let mut ap1r = [1 << 8, 0, 0, 0];
    assert!(clear_timer_interrupts(
        &mut list,
        &mut ap0r,
        &mut ap1r,
        5 << 18,
        5
    ));
    assert_eq!(ap1r[0], 1 << 8);
    // With VCBPR, Group 1 instead uses VBPR0. VBPR1 must be ignored.
    list = [lr(30, 1, 0x40, 2), lr(50, 1, 0x60, 2)];
    let vmcr = (1 << 4) | (5 << 21);
    assert!(clear_timer_interrupts(
        &mut list, &mut ap0r, &mut ap1r, vmcr, 5
    ));
    assert_eq!(ap1r[0], 1 << 8);
}
