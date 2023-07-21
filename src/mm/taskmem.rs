// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

use crate::{
    address::VirtAddr, cpu::percpu::this_cpu, error::SvsmError, task::TaskError, types::PAGE_SIZE,
};

/**
 * Allocate a virtual address range. The range is not mapped
 * to any physical address.
 */
pub fn valloc(size: usize) -> Result<VirtAddr, SvsmError> {
    // Align size up to next page boundary
    let size = (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let t = this_cpu()
        .runqueue
        .current_task()
        .ok_or(SvsmError::Task(TaskError::NotInitialised))?;
    let result = t.task.borrow_mut().virtual_alloc(size, 0);
    result
}

pub fn vfree(addr: VirtAddr, size: usize) {
    let t = this_cpu()
        .runqueue
        .current_task()
        .expect("The task system has not been initialised");
    t.task.borrow_mut().virtual_free(addr, size);
}
