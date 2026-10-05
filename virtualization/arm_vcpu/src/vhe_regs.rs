// SPDX-License-Identifier: Apache-2.0
//! AArch64 KVM one-register representation of the shared VHE state.
use core::arch::asm;

use ax_errno::{AxError, AxResult};

use super::vhe::{Vcpu, counter};

const CORE: u64 = 0x6030_0000_0010_0000;
const SYS: u64 = 0x6030_0000_0013_0000;
const SYS_MAP: &[(u16, usize)] = &[
    (0xc080, 3),
    (0xc082, 4),
    (0xc100, 5),
    (0xc101, 6),
    (0xc102, 7),
    (0xc290, 8),
    (0xc288, 21),
    (0xc300, 9),
    (0xc510, 10),
    (0xc518, 11),
    (0xc600, 12),
    (0xc681, 13),
    (0xc684, 14),
    (0xde82, 15),
    (0xde83, 16),
    (0xc3a0, 17),
    (0xc708, 18),
    (0x8012, 19),
    (0xc081, 20),
];

pub fn id_register(key: u16) -> Option<u64> {
    Some(match key {
        0xc000 => {
            let v;
            unsafe { asm!("mrs {}, midr_el1",out(reg)v) };
            v
        }
        0xc020 => 0x11 | (1 << 24),
        0xc021 | 0xc022 | 0xc029 | 0xc031 | 0xc032 | 0xc039 | 0xc03a | 0xc03b | 0xc03c => 0,
        0xc028 => 6,
        0xc030 => {
            let v;
            unsafe { asm!("mrs {}, id_aa64isar0_el1",out(reg)v) };
            v
        }
        0xc038 => {
            let v: u64;
            unsafe { asm!("mrs {}, id_aa64mmfr0_el1",out(reg)v) };
            (v & 15).min(5) | (15 << 24)
        }
        _ => return None,
    })
}

impl Vcpu {
    pub fn read_register(&self, id: u64, buf: &mut [u8]) -> AxResult {
        let size = 1usize
            .checked_shl(((id >> 52) & 15) as u32)
            .ok_or(AxError::InvalidInput)?;
        if buf.len() != size {
            return Err(AxError::InvalidInput);
        }
        let family = id & 0xfff0_ffff_ffff_0000;
        let offset = (id & 0xffff) as usize;
        let value: u128 = match family {
            CORE if offset < 62 && offset.is_multiple_of(2) => self.x[offset / 2] as u128,
            CORE => {
                (match offset {
                    62 => self.sp_el0,
                    64 => self.pc,
                    66 => self.pstate,
                    68 => self.sys[0],
                    70 => self.sys[1],
                    72 => self.sys[2],
                    _ => return Err(AxError::NotFound),
                }) as u128
            }
            0x6040_0000_0010_0000
                if (84..212).contains(&offset) && (offset - 84).is_multiple_of(4) =>
            {
                self.fp[(offset - 84) / 4]
            }
            0x6020_0000_0010_0000 => match offset {
                212 => self.fpsr as u128,
                213 => self.fpcr as u128,
                _ => return Err(AxError::NotFound),
            },
            SYS => {
                if let Some((_, index)) = SYS_MAP.iter().find(|(key, _)| *key == offset as u16) {
                    self.sys[*index] as u128
                } else {
                    match offset {
                        0xc005 => self.mpidr as u128,
                        0xc289 => self.afsr1 as u128,
                        0xd000 => self.csselr as u128,
                        0xdf00 => {
                            let v: u64;
                            unsafe { asm!("mrs {}, cntfrq_el0",out(reg)v) };
                            v as u128
                        }
                        0xdf11 => self.ptimer_ctl as u128,
                        0xdf12 => self.ptimer_cval as u128,
                        0xdf19 => self.timer_ctl as u128,
                        0xdf02 => self.timer_cval as u128,
                        0xdf1a => counter().wrapping_sub(self.cntvoff) as u128,
                        _ => id_register(offset as u16).ok_or(AxError::NotFound)? as u128,
                    }
                }
            }
            0x6030_0000_0014_0000 => match offset {
                0 => 0x10000,
                1..=3 => 0,
                _ => return Err(AxError::NotFound),
            },
            _ => return Err(AxError::NotFound),
        };
        buf.copy_from_slice(&value.to_ne_bytes()[..size]);
        Ok(())
    }

    pub fn write_register(&mut self, id: u64, buf: &[u8]) -> AxResult {
        let mut old = [0u8; 16];
        if buf.len() > 16 {
            return Err(AxError::InvalidInput);
        }
        self.read_register(id, &mut old[..buf.len()])?;
        let mut bytes = [0u8; 16];
        bytes[..buf.len()].copy_from_slice(buf);
        let value = u128::from_ne_bytes(bytes);
        let offset = (id & 0xffff) as usize;
        match id & 0xfff0_ffff_ffff_0000 {
            CORE if offset < 62 => self.x[offset / 2] = value as u64,
            CORE => match offset {
                62 => self.sp_el0 = value as u64,
                64 => self.pc = value as u64,
                66 => {
                    if !matches!(value & 31, 0 | 4 | 5) {
                        return Err(AxError::InvalidInput);
                    }
                    self.pstate = value as u64;
                }
                68 => self.sys[0] = value as u64,
                70 => self.sys[1] = value as u64,
                72 => self.sys[2] = value as u64,
                _ => return Err(AxError::NotFound),
            },
            0x6040_0000_0010_0000 => self.fp[(offset - 84) / 4] = value,
            0x6020_0000_0010_0000 => {
                if offset == 212 {
                    self.fpsr = value as u64
                } else {
                    self.fpcr = value as u64
                }
            }
            SYS => {
                if let Some((_, index)) = SYS_MAP.iter().find(|(key, _)| *key == offset as u16) {
                    self.sys[*index] = value as u64;
                } else {
                    match offset {
                        0xc289 => self.afsr1 = value as u64,
                        0xd000 => self.csselr = value as u64 & 15,
                        0xdf11 => self.ptimer_ctl = value as u64 & 3,
                        0xdf12 => self.ptimer_cval = value as u64,
                        0xdf19 => self.timer_ctl = value as u64 & 3,
                        0xdf02 => self.timer_cval = value as u64,
                        0xdf1a => self.cntvoff = counter().wrapping_sub(value as u64),
                        _ if old[..buf.len()] == *buf => {}
                        _ => return Err(AxError::InvalidInput),
                    }
                }
            }
            _ if old[..buf.len()] == *buf => {}
            _ => return Err(AxError::InvalidInput),
        }
        Ok(())
    }

    pub fn register_ids(&self) -> alloc::vec::Vec<u64> {
        let mut ids = alloc::vec::Vec::new();
        for index in 0..=36 {
            ids.push(CORE | (index * 2));
        }
        for index in 0..32 {
            ids.push(0x6040_0000_0010_0000 | (84 + index * 4));
        }
        ids.extend([0x6020_0000_0010_00d4, 0x6020_0000_0010_00d5]);
        ids.extend(SYS_MAP.iter().map(|(key, _)| SYS | u64::from(*key)));
        for key in [
            0xc289, 0xd000, 0xdf11, 0xdf12, 0xc000, 0xc005, 0xc020, 0xc021, 0xc022, 0xc028, 0xc029,
            0xc030, 0xc031, 0xc032, 0xc038, 0xc039, 0xc03a, 0xc03b, 0xc03c, 0xdf00, 0xdf19, 0xdf02,
            0xdf1a,
        ] {
            ids.push(SYS | key);
        }
        for index in 0..4 {
            ids.push(0x6030_0000_0014_0000 | index);
        }
        ids
    }
}
