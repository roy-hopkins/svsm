// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::error::SvsmError;
use crate::fs::{list_dir, open, FileHandle};
use crate::task::{create_elf_task, TaskPointer};

pub struct ModuleLoader {
    pub modules: Vec<Module>,
}

impl ModuleLoader {
    pub fn enumerate() -> Result<Self, SvsmError> {
        let mut modules: Vec<Module> = Vec::new();

        let module_files = list_dir("/modules")?;
        for module in module_files {
            let path = String::from("/modules/") + &module.as_str();
            // Each module is an ELF file
            let module_file = open(path.as_str())?;
            let module = Module::load(module_file);
            match module {
                Ok(m) => {
                    modules.push(m);
                    log::info!("Module {} loaded ok", path);
                }
                Err(_) => log::info!("Module {} load failed", path),
            }
        }
        Ok(Self { modules })
    }
}

pub struct Module {
    _task: TaskPointer,
    _file: FileHandle,
}

impl Module {
    pub fn load(file: FileHandle) -> Result<Self, SvsmError> {
        let task = create_elf_task(&file, 0, None)?;
        let module = Module {
            _task: task,
            _file: file,
        };
        Ok(module)
    }
}
