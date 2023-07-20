use crate::cpu::msr::write_msr;
use core::ffi::{c_char, CStr};

pub enum SyscallRet {
    Ok,
    Unknown,
}

pub trait Syscall {
    fn syscall(&self, index: u32, param1: u64) -> u64;
}

pub struct SyscallHandler {}

fn syscall_handler(index: u32, param1: u64) -> u64 {
    match index {
        0 => {
            unsafe {
                let str = CStr::from_ptr(param1 as *const c_char);
                log::info!("{}", str.to_str().unwrap());
            }
            0
        }
        _ => {
            log::info!("Invalid syscall received: {}", index);
            SyscallRet::Unknown as u64
        }
    }
}

impl SyscallHandler {
    pub fn init() -> Self {
        write_msr(0xc0000082, (syscall_handler as *const ()) as u64);
        SyscallHandler {}
    }
}

impl Syscall for SyscallHandler {
    fn syscall(&self, index: u32, param1: u64) -> u64 {
        syscall_handler(index, param1)
    }
}
