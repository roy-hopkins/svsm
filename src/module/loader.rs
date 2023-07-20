// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};

use alloc::string::String;

use crate::error::SvsmError;
use crate::fs::{list_dir, open, FileHandle};
use crate::mm::alloc::ALLOCATOR;
use crate::task::create_elf_task;

pub struct ModuleLoader {}

impl ModuleLoader {
    pub fn enumerate() -> Result<Self, SvsmError> {
        let module_files = list_dir("/modules")?;
        for module in module_files {
            let path = String::from("/modules/") + &module.as_str();
            // Each module is an ELF file
            let module_file = open(path.as_str())?;
            let module = Module::load(&module_file);
            match module {
                Ok(_) => log::info!("Module {} loaded ok", path),
                Err(_) => log::info!("Module {} load failed", path),
            }
        }

        Ok(Self {})
    }
}

pub struct Module {
    layout: Layout,
    mem: *mut u8,
    size: usize,
}

impl Module {
    pub fn load(file: &FileHandle) -> Result<Self, SvsmError> {
        let layout = Layout::from_size_align(file.size(), 4096)
            .unwrap()
            .pad_to_align();
        let mem = unsafe { ALLOCATOR.alloc(layout) };
        let buf = unsafe { core::slice::from_raw_parts_mut(mem, file.size()) };

        let size = match file.read(buf) {
            Ok(s) => s,
            Err(_) => {
                unsafe { ALLOCATOR.dealloc(mem, layout) };
                return Err(SvsmError::Module);
            }
        };
        // Sizes must match or there is something wrong in the filesystem
        assert_eq!(size, file.size());

        let module = Module { layout, mem, size };
        module.initialise()?;

        Ok(module)
    }

    fn initialise(&self) -> Result<(), SvsmError> {
        let buf = unsafe { core::slice::from_raw_parts_mut(self.mem, self.size) };
        let _task = create_elf_task(buf, 0, None);

        Ok(())
    }
}

impl Drop for Module {
    fn drop(&mut self) {
        unsafe { ALLOCATOR.dealloc(self.mem, self.layout) };
    }
}
