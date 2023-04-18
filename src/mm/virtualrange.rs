// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use crate::utils::bitmap_allocator::{BitAlloc, BitAlloc4K};
use crate::types::{VirtAddr, PAGE_SHIFT, PAGE_SIZE, PAGE_SIZE_2M, PAGE_SHIFT_2M};
use crate::locking::SpinLock;
use crate::error::SvsmError;

use super::{SVSM_PERCPU_TEMP_BASE_4K, SVSM_PERCPU_TEMP_END_4K, SVSM_PERCPU_TEMP_BASE_2M, SVSM_PERCPU_TEMP_END_2M};

pub const VIRT_ALIGN_4K: usize = PAGE_SHIFT - 12;
pub const VIRT_ALIGN_2M: usize = PAGE_SHIFT_2M - 12;

pub struct VirtualRange {
    start_virt: VirtAddr,
    page_count: usize,
    bits: BitAlloc4K,
}

impl VirtualRange {
    pub const fn new() -> VirtualRange {
        VirtualRange {
            start_virt: 0,
            page_count: 0,
            bits: BitAlloc4K::DEFAULT
        }
    }

    pub fn map_pages(self: &mut Self, page_count: usize, alignment: usize) -> Result<VirtAddr, SvsmError> {
        match self.bits.alloc_contiguous(page_count, alignment) {
            Some(offset) => Ok(self.start_virt + (offset << PAGE_SHIFT)),
            None => Err(SvsmError::Mem)
        }
    }

    pub fn unmap_pages(self: &mut Self, vaddr: VirtAddr, page_count: usize) {
        let offset = (vaddr - self.start_virt) >> PAGE_SHIFT;
        self.bits.insert(offset..(offset + page_count));
    }
}

static VIRTUAL_MAP_4K: SpinLock<VirtualRange> = SpinLock::new(VirtualRange::new());
static VIRTUAL_MAP_2M: SpinLock<VirtualRange> = SpinLock::new(VirtualRange::new());

pub fn virt_range_init() {
    let mut pm4k = VIRTUAL_MAP_4K.lock();
    let page_count = (SVSM_PERCPU_TEMP_END_4K - SVSM_PERCPU_TEMP_BASE_4K) / PAGE_SIZE;
    if page_count > BitAlloc4K::CAP {
        panic!("Attempted to allocate page map with more than 4K pages");
    }
    pm4k.start_virt = SVSM_PERCPU_TEMP_BASE_4K;
    pm4k.page_count = page_count;
    pm4k.bits.insert(0..page_count);

    let mut pm2m = VIRTUAL_MAP_2M.lock();
    let page_count = (SVSM_PERCPU_TEMP_END_2M - SVSM_PERCPU_TEMP_BASE_2M) / PAGE_SIZE_2M;
    if page_count > BitAlloc4K::CAP {
        panic!("Attempted to allocate page map with more than 4K pages");
    }
    pm2m.start_virt = SVSM_PERCPU_TEMP_BASE_2M;
    pm2m.page_count = page_count;
    pm2m.bits.insert(0..page_count);
}

pub fn virt_alloc_range_4k(size_bytes: usize, alignment: usize) -> Result<VirtAddr, SvsmError> {
    // Each bit in our bitmap represents a 4K page
    if (size_bytes & (PAGE_SIZE - 1)) != 0 {
        return Err(SvsmError::Mem);
    }
    let page_count = size_bytes >> PAGE_SHIFT;
    let mut pm = VIRTUAL_MAP_4K.lock();
    pm.map_pages(page_count, alignment)
}

pub fn virt_free_range_4k(vaddr: VirtAddr, size_bytes: usize) {
    VIRTUAL_MAP_4K.lock().unmap_pages(vaddr, size_bytes >> PAGE_SHIFT);
}

pub fn virt_alloc_range_2m(size_bytes: usize, alignment: usize) -> Result<VirtAddr, SvsmError> {
    // Each bit in our bitmap represents a 2M page
    if (size_bytes & (PAGE_SIZE_2M - 1)) != 0 {
        return Err(SvsmError::Mem);
    }
    let page_count = size_bytes >> PAGE_SHIFT_2M;
    let mut pm = VIRTUAL_MAP_2M.lock();
    pm.map_pages(page_count, alignment)
}

pub fn virt_free_range_2m(vaddr: VirtAddr, size_bytes: usize) {
    VIRTUAL_MAP_2M.lock().unmap_pages(vaddr, size_bytes >> PAGE_SHIFT_2M);
}
