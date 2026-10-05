// SPDX-License-Identifier: Apache-2.0
//! Software GICv3 distributor/redistributors. Linux retains the physical GIC.
use alloc::vec::Vec;

use ax_errno::{AxError, AxResult};
use axvm::AxVCpuRef;

#[derive(Clone)]
struct Irq {
    enabled: bool,
    pending: bool,
    level: bool,
    active: bool,
    lr_active: bool,
    lr_pending: bool,
    lr_pending_soft: bool,
    owner: Option<usize>,
    priority: u8,
    edge: bool,
    route: u64,
}
impl Default for Irq {
    fn default() -> Self {
        Self {
            enabled: false,
            pending: false,
            level: false,
            active: false,
            lr_active: false,
            lr_pending: false,
            lr_pending_soft: false,
            owner: None,
            priority: 0xa0,
            edge: false,
            route: 0,
        }
    }
}

pub(super) struct Gic {
    pub dist: Option<u64>,
    pub redist: Option<u64>,
    pub nr_irqs: usize,
    pub cpus: usize,
    pub initialized: bool,
    ctlr: u32,
    spis: Vec<Irq>,
    private: Vec<Vec<Irq>>,
}
impl Gic {
    pub fn new() -> Self {
        Self {
            dist: None,
            redist: None,
            nr_irqs: 128,
            cpus: 1,
            initialized: false,
            ctlr: 0,
            spis: alloc::vec![Irq::default();1024],
            private: (0..8)
                .map(|_| {
                    (0..32)
                        .map(|id| Irq {
                            edge: id < 16,
                            ..Irq::default()
                        })
                        .collect()
                })
                .collect(),
        }
    }
    fn bank(&self, cpu: usize, id: usize) -> &Irq {
        if id < 32 {
            &self.private[cpu][id]
        } else {
            &self.spis[id]
        }
    }
    fn bank_mut(&mut self, cpu: usize, id: usize) -> &mut Irq {
        if id < 32 {
            &mut self.private[cpu][id]
        } else {
            &mut self.spis[id]
        }
    }
    pub fn pulse(&mut self, cpu: usize, id: usize) -> AxResult {
        if cpu >= self.cpus || id >= self.nr_irqs.min(1020) {
            return Err(AxError::InvalidInput);
        }
        self.bank_mut(cpu, id).pending = true;
        Ok(())
    }
    pub fn line(&mut self, cpu: usize, id: usize, level: bool) -> AxResult {
        if cpu >= self.cpus || id >= self.nr_irqs.min(1020) {
            return Err(AxError::InvalidInput);
        }
        let irq = self.bank_mut(cpu, id);
        if irq.edge && level && !irq.level {
            irq.pending = true;
        }
        irq.level = level;
        Ok(())
    }
    pub fn sgi(&mut self, source: usize, value: u64) {
        let id = ((value >> 24) & 15) as usize;
        for cpu in 0..self.cpus {
            let target = if value & (1 << 40) != 0 {
                cpu != source
            } else {
                value & 0x00ff_f0ff_00ff_0000 == 0 && value & (1 << cpu) != 0
            };
            if target {
                self.private[cpu][id].pending = true;
            }
        }
    }
    pub fn feed(&mut self, cpu: usize, vcpu: &AxVCpuRef) {
        let state = vcpu.get_arch_vcpu();
        let timer = state.timer_ctl & 3 == 1
            && super::arm::counter().wrapping_sub(state.cntvoff) >= state.timer_cval;
        self.private[cpu][27].level = timer;
        self.private[cpu][30].level =
            state.ptimer_ctl & 3 == 1 && super::arm::counter() >= state.ptimer_cval;
        let distributor_enabled = self.ctlr & 2 != 0;
        for lr in &mut state.lrs {
            let id = (*lr & 0xffffffff) as usize;
            if *lr >> 62 == 0 || id >= self.nr_irqs {
                continue;
            }
            let irq = self.bank_mut(cpu, id);
            // Pending software events survive disabling. A level source that
            // deasserts before ACK is withdrawn from the hardware LR.
            if *lr >> 62 == 1
                && (!irq.enabled
                    || !distributor_enabled
                    || (!irq.edge && !irq.level && !irq.lr_pending_soft))
            {
                if irq.lr_pending_soft {
                    irq.pending = true;
                }
                *lr = 0;
            } else if *lr >> 62 == 1 {
                *lr = (*lr & !(255u64 << 48)) | (u64::from(irq.priority) << 48);
            }
        }
        self.sync(cpu, vcpu);
        if self.ctlr & 2 == 0 {
            return;
        }
        let state = vcpu.get_arch_vcpu();
        for id in 0..self.nr_irqs {
            let irq = self.bank(cpu, id);
            if !irq.enabled
                || !(irq.pending || (!irq.edge && irq.level))
                || irq.active
                || irq.lr_active
                || irq.owner.is_some()
            {
                continue;
            }
            if id >= 32
                && (if irq.route & (1 << 31) != 0 {
                    cpu != 0
                } else {
                    irq.route & 0xff != cpu as u64
                })
            {
                continue;
            }
            if state
                .lrs
                .iter()
                .any(|lr| *lr >> 62 != 0 && *lr & 0xffffffff == id as u64)
            {
                continue;
            }
            // VTR describes implemented LRs. The profile admits 4..16; use
            // only the guaranteed first four to keep state CPU-migratable.
            let Some(lr) = state.lrs[..4].iter_mut().find(|lr| **lr >> 62 == 0) else {
                break;
            };
            *lr = (1 << 62) | (1 << 60) | (u64::from(irq.priority) << 48) | id as u64;
            let irq = self.bank_mut(cpu, id);
            irq.lr_pending_soft = irq.pending;
            irq.pending = false;
            irq.owner = Some(cpu);
            irq.lr_pending = true;
        }
    }

    pub fn sync(&mut self, cpu: usize, vcpu: &AxVCpuRef) {
        for irq in self.private[cpu]
            .iter_mut()
            .chain(self.spis[32..self.nr_irqs].iter_mut())
        {
            if irq.owner == Some(cpu) {
                irq.owner = None;
                irq.lr_active = false;
                irq.lr_pending = false;
            }
        }
        for lr in &vcpu.get_arch_vcpu().lrs {
            let id = (*lr & 0xffffffff) as usize;
            if *lr >> 62 == 0 || id >= self.nr_irqs {
                continue;
            }
            let irq = self.bank_mut(cpu, id);
            irq.owner = Some(cpu);
            irq.lr_active = *lr & (1 << 63) != 0;
            irq.lr_pending = *lr & (1 << 62) != 0;
            if irq.lr_active {
                irq.lr_pending_soft = false;
            }
        }
        for irq in self.private[cpu]
            .iter_mut()
            .chain(self.spis[32..self.nr_irqs].iter_mut())
        {
            if irq.owner.is_none() {
                irq.lr_pending_soft = false;
            }
        }
    }

    /// Returns None for an address not owned by this VGIC.
    pub fn mmio(&mut self, address: u64, size: usize, write: Option<u64>) -> Option<AxResult<u64>> {
        if !self.initialized {
            return None;
        }
        if let Some(base) = self.dist
            && address >= base
            && address - base < 0x10000
        {
            return Some(self.access(0, false, address - base, size, write));
        }
        if let Some(base) = self.redist
            && address >= base
            && address - base < (self.cpus as u64) * 0x20000
        {
            let offset = address - base;
            let cpu = (offset / 0x20000) as usize;
            let offset = offset % 0x20000;
            if offset < 0x10000 {
                if !matches!(size, 4 | 8) || !offset.is_multiple_of(size as u64) {
                    return Some(Err(AxError::InvalidInput));
                }
                let typer = ((cpu as u64) << 32)
                    | ((cpu as u64) << 8)
                    | if cpu + 1 == self.cpus { 1 << 4 } else { 0 };
                let value = match offset {
                    8 => typer,
                    12 => typer >> 32,
                    4 => 0x43b,
                    0xffe8 => 0x30,
                    _ => 0,
                };
                return Some(Ok(if write.is_some() {
                    0
                } else if size == 4 {
                    value & 0xffffffff
                } else {
                    value
                }));
            }
            return Some(self.access(cpu, true, offset - 0x10000, size, write));
        }
        None
    }
    fn access(
        &mut self,
        cpu: usize,
        private: bool,
        offset: u64,
        size: usize,
        write: Option<u64>,
    ) -> AxResult<u64> {
        if !matches!(size, 1 | 2 | 4 | 8) || !offset.is_multiple_of(size as u64) {
            return Err(AxError::InvalidInput);
        }
        if !private {
            match offset {
                0 => {
                    if let Some(v) = write {
                        self.ctlr = v as u32 & 0x12;
                    }
                    return Ok(u64::from(self.ctlr) | 0x10);
                }
                4 => return Ok(((self.nr_irqs / 32) - 1) as u64 | (9 << 19)),
                8 => return Ok(0x43b),
                0xffe8 => return Ok(0x30),
                _ => {}
            }
        }
        let limit = if private { 32 } else { self.nr_irqs };
        let mut result = 0u64;
        for byte in 0..size {
            let at = offset as usize + byte;
            let incoming = write.map(|v| ((v >> (8 * byte)) & 255) as u8);
            let value = match at {
                0x80..=0xff => 255, // Single non-secure Group 1 profile.
                0x100..=0x3ff => {
                    let group = at & !0x7f;
                    let first = (at & 0x7f) * 8;
                    let mut bits = 0u8;
                    for bit in 0..8 {
                        let id = first + bit;
                        if id >= limit || (!private && id < 32) {
                            continue;
                        }
                        let irq = self.bank_mut(cpu, id);
                        if incoming.is_some_and(|v| v & (1 << bit) != 0) {
                            match group {
                                0x100 => irq.enabled = true,
                                0x180 => irq.enabled = false,
                                0x200 => irq.pending = true,
                                0x280 => irq.pending = false,
                                0x300 => irq.active = true,
                                0x380 => irq.active = false,
                                _ => {}
                            }
                        }
                        let set = match group {
                            0x100 | 0x180 => irq.enabled,
                            0x200 | 0x280 => irq.pending || irq.lr_pending || irq.level,
                            0x300 | 0x380 => irq.active || irq.lr_active,
                            _ => false,
                        };
                        if set {
                            bits |= 1 << bit;
                        }
                    }
                    bits
                }
                0x400..=0x7ff => {
                    let id = at - 0x400;
                    if id < limit && (private || id >= 32) {
                        let irq = self.bank_mut(cpu, id);
                        if let Some(v) = incoming {
                            irq.priority = v;
                        }
                        irq.priority
                    } else {
                        0
                    }
                }
                0xc00..=0xcff => {
                    let first = (at - 0xc00) * 4;
                    let mut bits = 0;
                    for pair in 0..4 {
                        let id = first + pair;
                        if id >= limit || (!private && id < 32) {
                            continue;
                        }
                        let irq = self.bank_mut(cpu, id);
                        if let Some(v) = incoming {
                            irq.edge = id < 16 || v & (2 << (pair * 2)) != 0;
                        }
                        if irq.edge {
                            bits |= 2 << (pair * 2);
                        }
                    }
                    bits
                }
                0x6000..=0x7fff if !private => {
                    let id = (at - 0x6000) / 8;
                    let shift = (at % 8) * 8;
                    if id < limit && id >= 32 {
                        let irq = &mut self.spis[id];
                        if let Some(v) = incoming {
                            irq.route = (irq.route & !(255 << shift)) | (u64::from(v) << shift);
                        }
                        ((irq.route >> shift) & 255) as u8
                    } else {
                        0
                    }
                }
                _ => 0,
            };
            result |= u64::from(value) << (8 * byte);
        }
        Ok(result)
    }
}
