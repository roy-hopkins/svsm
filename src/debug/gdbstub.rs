// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

//
// For release builds this module should not be compiled into the
// binary. See the bottom of this file for placeholders that are
// used when the gdb stub is disabled.
//
#[cfg(feature = "enable-gdb")]
pub mod svsm_gdbstub {
    use gdbstub::stub::{ GdbStubBuilder, SingleThreadStopReason};
    use gdbstub::stub::state_machine::GdbStubStateMachine;
    use gdbstub::conn::Connection;
    use gdbstub::target::{ Target, TargetError };
    use gdbstub::target::ext::base::BaseOps;
    use gdbstub::target::ext::base::singlethread::{SingleThreadBase, SingleThreadResumeOps, SingleThreadResume, SingleThreadSingleStepOps, SingleThreadSingleStep};
    use gdbstub::target::ext::breakpoints::{ Breakpoints, SwBreakpoint };
    use gdbstub_arch::x86::X86_64_SSE;
    use core::arch::asm;
    use crate::svsm_console::SVSMIOPort;
    use crate::serial::{ SerialPort, Terminal };
    use crate::cpu::X86Regs;
    use crate::types::VirtAddr;

    const INT3_INSTR: u8 = 0xcc;
    const MAX_BREAKPOINTS: usize = 32;

    pub fn gdbstub_start() -> Result<(), u64> {
        unsafe {
            let mut target = GdbStubTarget::new();
            let gdb = GdbStubBuilder::new(GdbStubConnection::new())
                .with_packet_buffer(&mut PACKET_BUFFER)
                .build()
                .expect("Failed to initialise GDB stub")
                .run_state_machine(&mut target).expect("Failed to start GDB state machine");
            GDB_STATE = Some(SvsmGdbStub { gdb, target });
        }
        init_pf_handler();

        Ok(())
    }

    pub fn handle_debug_pf_exception(regs: &mut X86Regs) -> bool {
        unsafe {
            if HANDLE_PF_FAULT {
                PF_FAULT = true;
                regs.rip = PF_RETURN_ADDR as usize;
                true
            } else {
                false
            }
        }
    }

    pub fn handle_bp_exception(regs: &mut X86Regs) {
        handle_stop(regs, true);
    }

    pub fn handle_db_exception(regs: &mut X86Regs) {
        handle_stop(regs, false);
    }

    pub fn debug_break() {
        log::info!("***********************************");
        log::info!("* Waiting for connection from GDB *");
        log::info!("***********************************");
        unsafe { asm!("int3"); }
    }

    static mut GDB_STATE: Option<SvsmGdbStub> = None;
    static GDB_IO: SVSMIOPort = SVSMIOPort::new();
    static mut GDB_SERIAL: SerialPort = SerialPort { driver: &GDB_IO, port: 0x2f8 };
    static mut PACKET_BUFFER: [u8; 4096] = [0; 4096];
    static mut SINGLE_STEP: bool = false;
    static mut BREAKPOINT_ADDR: [VirtAddr; MAX_BREAKPOINTS] = [ 0; MAX_BREAKPOINTS ];
    static mut BREAKPOINT_INST: [u8; MAX_BREAKPOINTS] = [ 0xcc; MAX_BREAKPOINTS ];

    struct SvsmGdbStub<'a> {
        gdb: GdbStubStateMachine<'a, GdbStubTarget, GdbStubConnection>,
        target: GdbStubTarget
    }

    fn handle_stop(regs: &mut X86Regs, bp_exception: bool) {
        let SvsmGdbStub { gdb, mut target } = unsafe {
            GDB_STATE.take().unwrap_or_else(|| {
                panic!("GDB stub not initialised!");
            })
        };

        target.set_regs(regs);
        
        // If the current address is on a breakpoint then we need to
        // move the IP back by one byte
        if bp_exception && is_breakpoint(regs.rip - 1) {
            regs.rip -= 1;
        }

        let mut new_gdb = match gdb {
            GdbStubStateMachine::Running(gdb_inner) => {
                match gdb_inner.report_stop(&mut target, SingleThreadStopReason::SwBreak(())) {
                    Ok(gdb) => gdb,
                    Err(_) => panic!("Failed to handle software breakpoint")
                }
            }
            _ => {
                gdb
            }
        };

        loop {
            new_gdb = match new_gdb {
                // The first entry into the debugger is via a forced breakpoint during
                // initialisation. The state at this point will be Idle instead of
                // Running.
                GdbStubStateMachine::Idle(mut gdb_inner) => {
                    let byte = gdb_inner.borrow_conn().read().map_err(|_| 1 as u64).expect("Failed to read from GDB port");
                    match gdb_inner.incoming_data(&mut target, byte) {
                        Ok(gdb) => gdb,
                        Err(_) => panic!("GDB disconnected")
                    }
                }
                GdbStubStateMachine::Running(gdb_inner) => {
                    new_gdb = gdb_inner.into();
                    break;
                }
                _ => {
                    log::info!("Invalid GDB state when handling breakpoint interrupt");
                    return;
                }
            };
        }
        if unsafe { SINGLE_STEP } {
            regs.flags |= 0x100;
        } else {
            regs.flags &= !0x100;
        }
        unsafe { GDB_STATE = Some(SvsmGdbStub { gdb: new_gdb, target }) };
    }

    fn is_breakpoint(rip: usize) -> bool {
        unsafe {
            for index in 0..BREAKPOINT_ADDR.len() {
                if (BREAKPOINT_INST[index] != INT3_INSTR) && 
                (BREAKPOINT_ADDR[index] == rip as VirtAddr) {
                    return true;
                }
            }
        }
        false
    }

    static mut HANDLE_PF_FAULT: bool = false;
    static mut PF_RETURN_ADDR: u64 = 0;
    static mut PF_FAULT: bool = false;

    fn init_pf_handler() {
        // Grab the address of the 'try_done' label in the asm
        // section in safe_access_memory(). If a page fault occurs
        // then the handler will check to see if HANDLE_PF_FAULT is
        // set indicating that we are trying to safely access memory.
        // In this case the handler will set rip to try_done to handle
        // the error without panicking.
        unsafe {
            let td: u64;
            asm!(
                "lea try_done(%rip), %rax",
                out("rax") td,
                options(att_syntax)
            );
            PF_RETURN_ADDR = td;
        }
    }

    #[allow(named_asm_labels)]
    pub fn safe_access_memory(addr: VirtAddr, write: bool, value: u8) -> Result<u8, ()> {
        // See comment in init_pf_handler() above for how this works
        let ret = unsafe {
            let mut result: u8 = value;
            let is_write: u8 = if write { 1 } else { 0 };
            PF_FAULT = false;
            HANDLE_PF_FAULT = true;

            asm!(
                "test %cl, %cl",
                "jz 1f",
                "movb %dl, (%rax)",
                "jmp try_done",
                "1:",
                "movb (%rax), %dl",
                "try_done:",
                in("rax") addr as u64,
                in("cl") is_write,
                in("dl") result,
                lateout("dl") result,
            options(att_syntax)
            );
            HANDLE_PF_FAULT = false;
            match PF_FAULT {
                true => Err(()),
                false => Ok(result),
            }
        };
        ret
    }

    struct GdbStubConnection;

    impl GdbStubConnection {
        pub const fn new() -> Self {
            Self { }
        }

        pub fn read(&mut self) -> Result<u8, &'static str> {
            let res = unsafe {
                Ok(GDB_SERIAL.get_byte())
            };
            res
        }
    }

    impl Connection for GdbStubConnection {
        type Error = usize;

        fn write(&mut self, byte: u8) -> Result<(), Self::Error> {
            unsafe {
                GDB_SERIAL.put_byte(byte);
            }
            Ok(())
        }

        fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct GdbStubTarget {
        regs: usize
    }

    impl GdbStubTarget {
        pub const fn new() -> Self {
            Self { regs: 0 }
        }

        pub fn set_regs(&mut self, regs: &X86Regs) {
            self.regs = (regs as *const _) as usize;
        }
    }

    impl Target for GdbStubTarget {
        type Arch = X86_64_SSE;

        type Error = usize;

        fn base_ops(&mut self) -> gdbstub::target::ext::base::BaseOps<'_, Self::Arch, Self::Error> {
            BaseOps::SingleThread(self)
        }

        #[inline(always)]
        fn support_breakpoints(&mut self) -> Option<gdbstub::target::ext::breakpoints::BreakpointsOps<'_, Self>> {
            Some(self)
        }
    }

    impl SingleThreadBase for GdbStubTarget {
        fn read_registers(
            &mut self,
            regs: &mut <Self::Arch as gdbstub::arch::Arch>::Registers,
        ) -> gdbstub::target::TargetResult<(), Self> {
            unsafe {
                let context = (self.regs as *mut X86Regs).as_mut().unwrap();

                regs.rip = context.rip as u64;
                regs.regs = [
                    context.rax as u64,
                    context.rbx as u64,
                    context.rcx as u64,
                    context.rdx as u64,
                    context.rsi as u64,
                    context.rdi as u64,
                    context.rbp as u64,
                    context.rsp as u64,
                    context.r8 as u64,
                    context.r9 as u64,
                    context.r10 as u64,
                    context.r11 as u64,
                    context.r12 as u64,
                    context.r13 as u64,
                    context.r14 as u64,
                    context.r15 as u64
                ];
                regs.eflags = context.flags as u32;
                regs.segments.cs = context.cs as u32;
                regs.segments.ss = context.ss as u32;
            }

            Ok(())
        }

        fn write_registers(&mut self, regs: &<Self::Arch as gdbstub::arch::Arch>::Registers)
            -> gdbstub::target::TargetResult<(), Self> {
            unsafe {
                let context = (self.regs as *mut X86Regs).as_mut().unwrap();
            
                context.rip = regs.rip as usize;
                context.rax = regs.regs[0] as usize;
                context.rbx = regs.regs[1] as usize;
                context.rcx = regs.regs[2] as usize;
                context.rdx = regs.regs[3] as usize;
                context.rsi = regs.regs[4] as usize;
                context.rdi = regs.regs[5] as usize;
                context.rbp = regs.regs[6] as usize;
                context.rsp = regs.regs[7] as usize;
                context.r8 = regs.regs[8] as usize;
                context.r9 = regs.regs[9] as usize;
                context.r10 = regs.regs[10] as usize;
                context.r11 = regs.regs[11] as usize;
                context.r12 = regs.regs[12] as usize;
                context.r13 = regs.regs[13] as usize;
                context.r14 = regs.regs[14] as usize;
                context.r15 = regs.regs[15] as usize;
                context.flags = regs.eflags as usize;
                context.cs = regs.segments.cs as usize;
                context.ss = regs.segments.ss as usize;
            }
            Ok(())
        }

        fn read_addrs(
            &mut self,
            start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
            data: &mut [u8],
        ) -> gdbstub::target::TargetResult<(), Self> {

            for offset in 0..data.len() {
                match safe_access_memory(start_addr as usize + offset, false, 0) {
                    Ok(val) => data[offset] = val,
                    Err(_) => { return Err(TargetError::NonFatal); },
                }
            }
            Ok(())
        }

        fn write_addrs(
            &mut self,
            start_addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
            data: &[u8],
        ) -> gdbstub::target::TargetResult<(), Self> {
            
            for offset in 0..data.len() {
                if safe_access_memory(start_addr as usize + offset, true, data[offset]).is_err() {
                    return Err(TargetError::NonFatal);
                }
            }
            Ok(())
        }

        #[inline(always)]
        fn support_resume(&mut self) -> Option<SingleThreadResumeOps<Self>> {
            Some(self)
        }
    }

    impl SingleThreadResume for GdbStubTarget {
        fn resume(&mut self, _signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
            unsafe { SINGLE_STEP = false; }
            Ok(())
        }

        #[inline(always)]
        fn support_single_step(
            &mut self
        ) -> Option<SingleThreadSingleStepOps<'_, Self>> {
            Some(self)
        }    
    }

    impl SingleThreadSingleStep for GdbStubTarget {
        fn step(&mut self, _signal: Option<gdbstub::common::Signal>) -> Result<(), Self::Error> {
            unsafe { SINGLE_STEP = true; }
            Ok(())
        }
    }

    impl Breakpoints for GdbStubTarget {
        #[inline(always)]
        fn support_sw_breakpoint(&mut self) -> Option<gdbstub::target::ext::breakpoints::SwBreakpointOps<'_, Self>> {
            Some(self)
        }

        #[inline(always)]
        fn support_hw_breakpoint(&mut self) -> Option<gdbstub::target::ext::breakpoints::HwBreakpointOps<'_, Self>> {
            None
        }

        #[inline(always)]
        fn support_hw_watchpoint(&mut self) -> Option<gdbstub::target::ext::breakpoints::HwWatchpointOps<'_, Self>> {
            None
        }
    }

    impl SwBreakpoint for GdbStubTarget {
        fn add_sw_breakpoint(
            &mut self,
            addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
            _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
        ) -> gdbstub::target::TargetResult<bool, Self> {

            unsafe {
                // Find a free breakpoint
                let mut bp_index = BREAKPOINT_ADDR.len();
                for index in 0..BREAKPOINT_ADDR.len() {
                    if BREAKPOINT_INST[index] == 0xcc {
                        bp_index = index;
                        break;
                    }
                }
                if bp_index == BREAKPOINT_ADDR.len() {
                    return Ok(false);
                }
                let Ok(instr) = safe_access_memory(addr as usize, false, 0) else {
                    return Ok(false);
                };
                match safe_access_memory(addr as usize, true, 0xcc) {
                    Ok(_) => {
                        BREAKPOINT_ADDR[bp_index] = addr as VirtAddr;
                        BREAKPOINT_INST[bp_index] = instr;
                        Ok(true)
                    }
                    Err(_) => Ok(false)
                }
            }
        }

        fn remove_sw_breakpoint(
            &mut self,
            addr: <Self::Arch as gdbstub::arch::Arch>::Usize,
            _kind: <Self::Arch as gdbstub::arch::Arch>::BreakpointKind,
        ) -> gdbstub::target::TargetResult<bool, Self> {
            unsafe {
                let mut bp_index = BREAKPOINT_ADDR.len();
                for index in 0..BREAKPOINT_ADDR.len() {
                    if BREAKPOINT_ADDR[index] == addr as VirtAddr {
                        bp_index = index;
                        break;
                    }
                }
                if bp_index == BREAKPOINT_ADDR.len() {
                    return Ok(false);
                }
                match safe_access_memory(addr as usize, true, BREAKPOINT_INST[bp_index]) {
                    Ok(_) => {
                        BREAKPOINT_INST[bp_index] = 0xcc;
                        Ok(true)
                    }
                    Err(_) => Ok(false)
                }
            }
        }
    }
}

#[cfg(not(feature = "enable-gdb"))]
pub mod svsm_gdbstub {
    use crate::cpu::X86Regs;

    pub fn gdbstub_start() -> Result<(), u64> {
        Ok(())
    }

    pub fn handle_debug_pf_exception(_regs: &mut X86Regs) -> bool {
        false
    }

    pub fn handle_bp_exception(_regs: &mut X86Regs) {
    }

    pub fn handle_db_exception(_regs: &mut X86Regs) {
    }

    pub fn debug_break() {
    }
}
