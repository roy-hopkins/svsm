// SPDX-License-Identifier: MIT
//
// Copyright (c) 2024 SUSE LLC
//
// Author: Joerg Roedel <jroedel@suse.de>

use crate::address::VirtAddr;
use crate::error::SvsmError;
use crate::fs::FileHandle;
use crate::mm::vm::{Mapping, VMFileMapping, VMFileMappingFlags, VMalloc, VMR};

use core::ops::Deref;

extern crate alloc;
use alloc::sync::Arc;

#[derive(Debug)]
pub struct VMMappingGuard<'a> {
    vmr: &'a VMR,
    start: VirtAddr,
}

impl<'a> VMMappingGuard<'a> {
    pub fn new(vmr: &'a VMR, start: VirtAddr) -> Self {
        VMMappingGuard { vmr, start }
    }
}

impl Deref for VMMappingGuard<'_> {
    type Target = VirtAddr;

    fn deref(&self) -> &VirtAddr {
        &self.start
    }
}

impl Drop for VMMappingGuard<'_> {
    fn drop(&mut self) {
        self.vmr
            .remove(self.start)
            .expect("Fatal error: Failed to unmap region from MappingGuard");
    }
}

pub fn create_file_mapping(
    file: &FileHandle,
    offset: usize,
    size: usize,
    flags: VMFileMappingFlags,
) -> Result<Arc<Mapping>, SvsmError> {
    let file_mapping = VMFileMapping::new(file, offset, size, flags)?;
    Ok(Arc::new(Mapping::new(file_mapping)))
}

pub fn create_anon_mapping(size: usize) -> Result<Arc<Mapping>, SvsmError> {
    let alloc = VMalloc::new(size)?;
    Ok(Arc::new(Mapping::new(alloc)))
}
