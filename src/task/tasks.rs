// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use core::arch::{asm, global_asm};
use core::fmt;
use core::mem::size_of;
use core::sync::atomic::{AtomicU32, Ordering};

use alloc::boxed::Box;

use crate::address::{Address, PhysAddr, VirtAddr};
use crate::cpu::msr::{rdtsc, read_flags};
use crate::cpu::percpu::this_cpu;
use crate::cpu::X86GeneralRegs;
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::alloc::{allocate_pages, get_order};
use crate::mm::pagetable::{get_init_pgtable_locked, PageTable, PageTableRef};
use crate::mm::virtualrange::VirtualRange;
use crate::mm::{
    virt_to_phys, PAGE_SIZE, PGTABLE_LVL3_IDX_PERCPU, SVSM_PERTASK_DYNAMIC_MEMORY_BASE,
    SVSM_PERTASK_DYNAMIC_MEMORY_TOP, SVSM_PERTASK_STACK_BASE, SVSM_PERTASK_STACK_TOP,
};
use crate::types::PAGE_SHIFT;
use crate::utils::bitmap_allocator::BitmapAllocator16K;
use crate::utils::zero_mem_region;

use super::schedule::{current_task_terminated, schedule};

pub const INITIAL_TASK_ID: u32 = 1;

const STACK_SIZE: usize = 65536;

type TaskVirtualRange = VirtualRange<BitmapAllocator16K>;

extern "C" {
    static task_entry: u64;
}

#[derive(PartialEq, Debug, Copy, Clone)]
pub enum TaskState {
    RUNNING,
    TERMINATED,
}

#[derive(Clone, Copy, Debug)]
pub enum TaskError {
    /// Attempt to close a non-terminated task
    NotTerminated,
    /// A closed task could not be removed from the task list
    CloseFailed,
    /// The task system has not been initialised
    NotInitialised,
    /// Memory allocation error,
    Alloc,
}

impl From<TaskError> for SvsmError {
    fn from(e: TaskError) -> Self {
        Self::Task(e)
    }
}

#[derive(Debug)]
pub struct TaskStack {
    pub virt_base: VirtAddr,
    pub virt_top: VirtAddr,
    pub phys: PhysAddr,
}

pub const TASK_FLAG_SHARE_PT: u16 = 0x01;

struct TaskIDAllocator {
    next_id: AtomicU32,
}

impl TaskIDAllocator {
    const fn new() -> Self {
        Self {
            next_id: AtomicU32::new(INITIAL_TASK_ID + 1),
        }
    }

    fn next_id(&self) -> u32 {
        let mut id = self.next_id.fetch_add(1, Ordering::Relaxed);
        // Reserve IDs of 0 and 1
        while (id == 0_u32) || (id == INITIAL_TASK_ID) {
            id = self.next_id.fetch_add(1, Ordering::Relaxed);
        }
        id
    }
}

static TASK_ID_ALLOCATOR: TaskIDAllocator = TaskIDAllocator::new();

/// This trait is used to implement the strategy that determines
/// how much CPU time a task has been allocated. The task with the
/// lowest runtime value is likely to be the next scheduled task
pub trait TaskRuntime {
    /// Called when a task is allocated to a CPU just before the task
    /// context is restored. The task should start tracking the CPU
    /// execution allocation at this point.
    fn schedule_in(&mut self);

    /// Called by the scheduler at the point the task is interrupted
    /// and marked for deallocation from the CPU. The task should
    /// update the runtime calculation at this point.
    fn schedule_out(&mut self);

    /// Overrides the calculated runtime value with the given value.
    /// This can be used to set or adjust the runtime of a task.
    fn set(&mut self, runtime: u64);

    /// Returns a value that represents the amount of CPU the task
    /// has been allocated
    fn value(&self) -> u64;
}

/// Tracks task runtime based on the CPU timestamp counter
#[derive(Default, Debug)]
#[repr(transparent)]
pub struct TscRuntime {
    runtime: u64,
}

impl TaskRuntime for TscRuntime {
    fn schedule_in(&mut self) {
        self.runtime = rdtsc();
    }

    fn schedule_out(&mut self) {
        self.runtime += rdtsc() - self.runtime;
    }

    fn set(&mut self, runtime: u64) {
        self.runtime = runtime;
    }

    fn value(&self) -> u64 {
        self.runtime
    }
}

/// Tracks task runtime based on the number of times the task has been
/// scheduled
#[derive(Default, Debug)]
#[repr(transparent)]
pub struct CountRuntime {
    count: u64,
}

impl TaskRuntime for CountRuntime {
    fn schedule_in(&mut self) {
        self.count += 1;
    }

    fn schedule_out(&mut self) {}

    fn set(&mut self, runtime: u64) {
        self.count = runtime;
    }

    fn value(&self) -> u64 {
        self.count
    }
}

// Define which runtime counter to use
type TaskRuntimeImpl = CountRuntime;

#[repr(C)]
#[derive(Default, Debug)]
pub struct TaskContext {
    pub rsp: u64,
    pub regs: X86GeneralRegs,
    pub flags: u64,
    pub ret_addr: u64,
}

#[repr(C)]
pub struct UserTask {
    pub user_rsp: u64,
    pub kernel_rsp: u64,
    pub stack: TaskStack,
}

#[repr(C)]
pub struct Task {
    /// Current kernel stack pointer. This must always be the first entry
    /// in this struct
    pub rsp: u64,

    /// Information about the task stack
    pub stack: TaskStack,

    // For tasks that support user mode this contains the current user mode
    // state. For tasks that are kernel mode only, contains None.
    pub user: Option<UserTask>,

    /// Page table that is loaded when the task is scheduled
    pub page_table: SpinLock<PageTableRef>,

    /// Current state of the task
    pub state: TaskState,

    /// Task affinity
    /// None: The task can be scheduled to any CPU
    /// u32:  The APIC ID of the CPU that the task must run on
    pub affinity: Option<u32>,

    // APIC ID of the CPU that task has been assigned to. If 'None' then
    // the task is not currently assigned to a CPU
    pub allocation: Option<u32>,

    /// ID of the task
    pub id: u32,

    /// Amount of CPU resource the task has consumed
    pub runtime: TaskRuntimeImpl,

    /// Per-task virtual memory allocations
    pub virtual_map: Box<TaskVirtualRange>,
}

impl fmt::Debug for Task {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task")
            .field("rsp", &self.rsp)
            .field("stack", &self.stack)
            .field("state", &self.state)
            .field("affinity", &self.affinity)
            .field("id", &self.id)
            .field("runtime", &self.runtime)
            .finish()
    }
}

impl Task {
    pub fn create(entry: usize, param: u64, flags: u16) -> Result<Box<Task>, SvsmError> {
        let mut pgtable = if (flags & TASK_FLAG_SHARE_PT) != 0 {
            this_cpu().get_pgtable().clone_shared()?
        } else {
            Self::allocate_page_table()?
        };

        let (task_stack, rsp) = Self::allocate_stack(entry, param, &mut pgtable)?;

        // Initialise the virtual memory allocator range
        let page_count =
            (SVSM_PERTASK_DYNAMIC_MEMORY_TOP - SVSM_PERTASK_DYNAMIC_MEMORY_BASE) / PAGE_SIZE;
        assert!(page_count <= TaskVirtualRange::CAPACITY);

        // Allocate the virtual map on the heap as it can be too large for the
        // initial stack
        let mut virtual_map: Box<TaskVirtualRange> = Box::new(TaskVirtualRange::new());
        virtual_map.init(
            VirtAddr::from(SVSM_PERTASK_DYNAMIC_MEMORY_BASE),
            page_count,
            PAGE_SHIFT,
        );

        let task: Box<Task> = Box::new(Task {
            rsp: u64::from(rsp),
            stack: task_stack,
            user: None,
            page_table: SpinLock::new(pgtable),
            state: TaskState::RUNNING,
            affinity: None,
            allocation: None,
            id: TASK_ID_ALLOCATOR.next_id(),
            runtime: TaskRuntimeImpl::default(),
            virtual_map,
        });
        Ok(task)
    }

    pub fn set_current(&mut self, previous_task: *mut Task) {
        // This function is called by one task but returns in the context of
        // another task. The context of the current task is saved and execution
        // can resume at the point of the task switch, effectively completing
        // the function call for the original task.
        let new_task_addr = (self as *mut Task) as u64;

        // Switch to the new task
        unsafe {
            asm!(
                r#"
                    call switch_context
                "#,
                in("rsi") previous_task as u64,
                in("rdi") new_task_addr,
                options(att_syntax));
        }
    }

    pub fn set_affinity(&mut self, affinity: Option<u32>) {
        self.affinity = affinity;
    }

    pub fn virtual_alloc(
        &mut self,
        size_bytes: usize,
        alignment: usize,
    ) -> Result<VirtAddr, SvsmError> {
        // Each bit in our bitmap represents a 4K page
        if (size_bytes & (PAGE_SIZE - 1)) != 0 {
            return Err(SvsmError::Mem);
        }
        let page_count = size_bytes >> PAGE_SHIFT;
        self.virtual_map.alloc(page_count, alignment)
    }

    pub fn virtual_free(&mut self, vaddr: VirtAddr, size_bytes: usize) {
        self.virtual_map.free(vaddr, size_bytes >> PAGE_SHIFT);
    }

    fn allocate_stack(
        entry: usize,
        param: u64,
        pgtable: &mut PageTableRef,
    ) -> Result<(TaskStack, VirtAddr), SvsmError> {
        let stack_size = SVSM_PERTASK_STACK_TOP - SVSM_PERTASK_STACK_BASE;
        let num_pages = 1 << get_order(STACK_SIZE);
        assert!(stack_size == num_pages * PAGE_SIZE);
        let pages = allocate_pages(get_order(STACK_SIZE))?;
        zero_mem_region(pages, pages + stack_size);

        let task_stack = TaskStack {
            virt_base: VirtAddr::from(SVSM_PERTASK_STACK_BASE),
            virt_top: VirtAddr::from(SVSM_PERTASK_STACK_TOP),
            phys: virt_to_phys(pages),
        };

        // We current have a virtual address in SVSM shared memory for the stack. Configure
        // the per-task pagetable to map the stack into the task memory map.
        pgtable.map_region_4k(
            task_stack.virt_base,
            task_stack.virt_top,
            task_stack.phys,
            PageTable::task_data_flags(),
        )?;

        // We need to setup a context on the stack that matches the stack layout
        // defined in switch_context below.
        let stack_pos = pages + stack_size;
        let stack_ptr: *mut u64 = stack_pos.as_mut_ptr();

        // 'Push' the task frame onto the stack
        unsafe {
            // flags
            stack_ptr.offset(-5).write(read_flags());
            // ret_addr
            stack_ptr.offset(-4).write(&task_entry as *const u64 as u64);
            // Parameter to entry point
            stack_ptr.offset(-3).write(param);
            // Entry point
            stack_ptr.offset(-2).write(entry as u64);
            // Task termination handler for when entry point returns
            stack_ptr.offset(-1).write(task_exit as *const () as u64);
        }

        let initial_rsp = VirtAddr::from(
            SVSM_PERTASK_STACK_TOP - (size_of::<TaskContext>() + (3 * size_of::<u64>())),
        );
        Ok((task_stack, initial_rsp))
    }

    fn allocate_page_table() -> Result<PageTableRef, SvsmError> {
        // Base the new task page table on the initial SVSM kernel page table.
        // When the pagetable is schedule to a CPU, the per CPU entry will also
        // be added to the pagetable.
        get_init_pgtable_locked().clone_shared()
    }
}

extern "C" fn task_exit() {
    unsafe {
        current_task_terminated();
    }
    schedule();
}

#[allow(unused)]
#[no_mangle]
extern "C" fn apply_new_context(new_task: *mut Task) -> u64 {
    unsafe {
        let mut pt = (*new_task).page_table.lock();
        pt.copy_entry(&this_cpu().get_pgtable(), PGTABLE_LVL3_IDX_PERCPU);
        pt.cr3_value().bits() as u64
    }
}

global_asm!(
    r#"
        .text

    .globl task_entry
    task_entry:
        pop     %rdi        // Parameter to entry point
        // Next item on the stack is the entry point address
        ret         

    switch_context:
        // Save the current context. The layout must match the TaskContext structure.
        pushfq
        pushq   %rax
        pushq   %rbx
        pushq   %rcx
        pushq   %rdx
        pushq   %rsi
        pushq   %rdi
        pushq   %rbp
        pushq   %r8
        pushq   %r9
        pushq   %r10
        pushq   %r11
        pushq   %r12
        pushq   %r13
        pushq   %r14
        pushq   %r15
        pushq   %rsp
        
        // Save the current stack pointer
        testq   %rsi, %rsi
        jz      1f
        movq    %rsp, (%rsi)

    1:
        // Switch to the new task state
        mov     %rdi, %rbx
        call    apply_new_context
        mov     %rax, %cr3

        // Switch to the new task stack
        movq    (%rbx), %rsp

        // We've already restored rsp
        addq        $8, %rsp

        // Restore the task context
        popq        %r15
        popq        %r14
        popq        %r13
        popq        %r12
        popq        %r11
        popq        %r10
        popq        %r9
        popq        %r8
        popq        %rbp
        popq        %rdi
        popq        %rsi
        popq        %rdx
        popq        %rcx
        popq        %rbx
        popq        %rax
        popfq

        ret
    "#,
    options(att_syntax)
);
