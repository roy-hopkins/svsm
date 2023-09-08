// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>
//
// Other contributors:
//
// Carlos Bilbao <carlos.bilbao@amd.com>
//
use core::{
    arch::asm,
    arch::global_asm,
    ffi::{c_char, CStr},
};

use crate::cpu::{
    efer::{read_efer, write_efer, EFERFlags},
    msr::write_msr,
    percpu::this_cpu,
};
use crate::types::{SVSM_CS, SVSM_USER_CS32};

use super::schedule;

pub enum SyscallRet {
    Ok,
    Unknown,
    Terminate,
}

extern "C" {
    static syscall_entry: u64;
}

const MSR_STAR: u32 = 0xc000_0081;
const MSR_LSTAR: u32 = 0xc000_0082;
const MSR_SFMASK: u32 = 0xc000_0084;

/// SVSM unique system calls should have numbers that don't conflict with
/// POSIX syscall numbers. This allows for (future) implementation of userspace
/// support for things like malloc, mmap, etc.
#[repr(u32)]
#[derive(Debug)]
pub enum SystemCalls {
    Exit = 500,
    Log = 501,
    Sleep = 502,
}

fn map_to_syscall(index: u32) -> Option<SystemCalls> {
    match index {
        1 => Some(SystemCalls::Exit),
        2 => Some(SystemCalls::Log),
        3 => Some(SystemCalls::Sleep),
        _ => None,
    }
}

#[inline]
#[allow(dead_code)]
pub fn syscall0(id: u32) -> u64 {
    let ret: u64;
    // syscall modifies both rcx and r11
    unsafe {
        asm!("syscall",
               inout("rax") id as u64 => ret,
               options(nostack));
    }

    ret
}

#[inline]
#[allow(dead_code)]
pub fn syscall1(id: u32, p1: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!("syscall",
               inout("rax") id as u64 => ret,
               in("rdi") p1,
               options(nostack));
    }

    ret
}

#[inline]
#[allow(dead_code)]
pub fn syscall2(id: u32, p1: u64, p2: u64) -> u64 {
    let ret: u64;
    unsafe {
        asm!("syscall",
               inout("rax") id as u64 => ret,
               in("rdi") p1,
               in("rsi") p2,
               options(nostack));
    }

    ret
}

#[inline]
#[allow(dead_code)]
pub fn syscall3(id: u32, p1: u64, p2: u64, p3: u64) -> u64 {
    let ret: u64;
    // syscall modifies both rcx and r11
    unsafe {
        asm!("syscall",
               inout("rax") id as u64 => ret,
               in("rdi") p1,
               in("rsi") p2,
               in("rdx") p3,
               options(nostack));
    }

    ret
}

// In case of adding system calls with more parameters, this is the order
// in which to fill the registers:
// p4=r10, p5=r8, p6=r9
// We can't pass >6 params without using the stack
// Don't forget to include the call in system_call!() too.

/// System call macro. Example of usage:
/// system_call!(SystemCalls:CALL_ID, param1)
///
#[macro_export]
macro_rules! system_call {
    ($id: expr) => {
        syscall0($id)
    };

    ($id: expr, $param_1:expr) => {
        syscall1($id, $param_1 as u64)
    };
    ($id: expr, $param_1:expr, $param_2:expr) => {
        syscall2($id, $param_1 as u64, $param_2 as u64)
    };

    ($id: expr, $param_1:expr, $param_2:expr, $param_3:expr) => {
        syscall3($id, $param_1 as u64, $param_2 as u64, $param_3 as u64)
    };
}

#[no_mangle]
extern "C" fn syscall_handler(index: u32, param1: u64) -> u64 {
    let ret = match map_to_syscall(index) {
        Some(SystemCalls::Exit) => SyscallRet::Terminate,
        Some(SystemCalls::Log) => {
            unsafe {
                let str = CStr::from_ptr(param1 as *const c_char);
                log::info!("{}", str.to_str().unwrap());
            }
            SyscallRet::Ok
        }
        Some(SystemCalls::Sleep) => SyscallRet::Ok,
        _ => {
            log::info!("Invalid syscall received: {}", index);
            SyscallRet::Unknown
        }
    };
    schedule();
    ret as u64
}

pub fn init_syscall() {
    let mut efer = read_efer();
    efer.insert(EFERFlags::SCE);
    write_efer(efer);

    let sysret_cs = SVSM_USER_CS32 as u64;
    let syscall_cs = SVSM_CS as u64;
    write_msr(MSR_STAR, sysret_cs << 48 | syscall_cs << 32);
    unsafe {
        write_msr(MSR_LSTAR, (&syscall_entry as *const u64) as u64);
    }
    // FIXME: Find correct mask for flags
    write_msr(MSR_SFMASK, 0);
}

#[no_mangle]
extern "C" fn get_kernel_rsp() -> u64 {
    let task_node = this_cpu()
        .runqueue
        .current_task()
        .expect("Invalid current task");
    let rsp = task_node
        .task
        .borrow()
        .user
        .as_ref()
        .expect("Syscall from kernel task")
        .kernel_rsp;
    rsp
}

global_asm!(
    r#"
        .text
    syscall_entry:
        // Switch to the task kernel stack
        push    %rcx            // User-mode return address

        // Syscall arguments
        push    %rsi
        push    %rdi

        call    get_kernel_rsp
        pop     %rdi
        pop     %rsi

        subq    $8, %rax
        movq    %rsp, (%rax)
        mov     %rax, %rsp

        call    syscall_handler

        // Check to see if the task requested termination
        cmp     $2, %rax            // SyscallRet::Terminate
        jne     ret_user

        addq    $8, %rsp            // Skip user mode return address
        // Kernel stack frame should now be within launch_user_entry()
        ret

    ret_user:
        pop     %rsp
        pop     %rcx
        movq    $0x202, %r11
        sysretq
        "#,
    options(att_syntax)
);
