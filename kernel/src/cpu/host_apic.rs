// Copyright (c) 2024 SUSE LLC
//
// Author: Roy Hopkins <roy.hopkins@suse.com>

use crate::error::SvsmError;
use crate::io::{IOPort, DEFAULT_IO_DRIVER};

use super::percpu::current_ghcb;
use super::X86GeneralRegs;

#[derive(Debug, Copy, Clone)]
pub struct HostApic {}

const APIC_ENABLE_MSR: usize = 0x1b;
const APIC_BASE_MSR: usize = 0x800;
const APIC_SPIV: u32 = 0xf0;
const APIC_TASKPRI: u32 = 0x80;
const APIC_EOI: u32 = 0xb0;
const APIC_LVTT: u32 = 0x320;
const APIC_TMICT: u32 = 0x380;

impl HostApic {
    pub fn read_reg(offset: u32) -> Result<u32, SvsmError> {
        let mut regs = X86GeneralRegs {
            rcx: APIC_BASE_MSR + (offset as usize >> 4),
            ..Default::default()
        };
        current_ghcb().rdmsr_regs(&mut regs)?;

        Ok(regs.rax as u32)
    }

    pub fn write_reg(offset: u32, value: u32) -> Result<(), SvsmError> {
        let regs = X86GeneralRegs {
            rcx: APIC_BASE_MSR + (offset as usize >> 4),
            rax: value as usize,
            ..Default::default()
        };
        current_ghcb().wrmsr_regs(&regs)?;
        Ok(())
    }

    pub fn enable() -> Result<(), SvsmError> {
        // Disable PIC
        DEFAULT_IO_DRIVER.outb(0x21, 0xff);
        DEFAULT_IO_DRIVER.outb(0xa1, 0xff);

        // Enable the APIC in X2APIC mode
        let mut regs = X86GeneralRegs {
            rcx: APIC_ENABLE_MSR,
            ..Default::default()
        };
        current_ghcb().rdmsr_regs(&mut regs)?;
        regs.rax |= 0xc00;
        current_ghcb().wrmsr_regs(&regs)?;

        Self::write_reg(APIC_SPIV, 0x1ff)?;

        // Task priority register - accept all interrupts
        Self::write_reg(APIC_TASKPRI, 0x0)?;

        Ok(())
    }

    pub fn eoi() -> Result<(), SvsmError> {
        Self::write_reg(APIC_EOI, 0)
    }

    pub fn enable_timer(interval: u32, periodic: bool) -> Result<(), SvsmError> {
        let periodic = if periodic { 1 << 17 } else { 0 };
        HostApic::write_reg(APIC_LVTT, 0x20 | periodic)?;
        HostApic::write_reg(APIC_TMICT, interval)?;
        Ok(())
    }
}
