// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use core::cell::RefCell;

use super::Task;
use super::{tasks::TaskRuntime, TaskState, INITIAL_TASK_ID};
use crate::address::{Address, VirtAddr};
use crate::cpu::percpu::{this_cpu, this_cpu_mut};
use crate::elf;
use crate::error::SvsmError;
use crate::locking::SpinLock;
use crate::mm::pagetable::PageTable;
use crate::mm::virt_to_phys;
use alloc::boxed::Box;
use alloc::rc::Rc;
use intrusive_collections::linked_list::Link;
use intrusive_collections::{intrusive_adapter, Bound, KeyAdapter, LinkedList, RBTree, RBTreeLink};

pub type TaskPointer = Rc<TaskNode>;

#[derive(Debug)]
pub struct TaskNode {
    tree_link: RBTreeLink,
    list_link: Link,
    pub task: RefCell<Box<Task>>,
}

intrusive_adapter!(pub TaskTreeAdapter = TaskPointer: TaskNode { tree_link: RBTreeLink });
intrusive_adapter!(pub TaskListAdapter = TaskPointer: TaskNode { list_link: Link });

impl<'a> KeyAdapter<'a> for TaskTreeAdapter {
    type Key = u64;
    fn get_key(&self, node: &'a TaskNode) -> u64 {
        node.task.borrow().runtime.value()
    }
}

/// Task priority tree
/// This contains a set of tasks that are ready to run sorted in
/// order of priority.
#[derive(Debug)]
pub struct RunQueue {
    tree: Option<RBTree<TaskTreeAdapter>>,
    current_task: Option<TaskPointer>,
    terminated_task: Option<TaskPointer>,
}

impl RunQueue {
    pub const fn new() -> Self {
        Self {
            tree: None,
            current_task: None,
            terminated_task: None,
        }
    }

    pub fn tree(&mut self) -> &mut RBTree<TaskTreeAdapter> {
        self.tree
            .get_or_insert_with(|| RBTree::new(TaskTreeAdapter::new()))
    }

    pub fn get_task(&self, id: u32) -> Option<TaskPointer> {
        if let Some(task_tree) = &self.tree {
            let mut cursor = task_tree.front();
            while let Some(task_node) = cursor.get() {
                if task_node.task.borrow().id == id {
                    return cursor.clone_pointer();
                }
                cursor.move_next();
            }
        }
        None
    }

    pub fn current_task(&self) -> Option<TaskPointer> {
        self.current_task.as_ref().cloned()
    }

    pub fn current_task_id(&self) -> u32 {
        self.current_task
            .as_ref()
            .map_or(INITIAL_TASK_ID, |t| t.task.borrow().id)
    }

    // Determine the next task to run on the vCPU that owns this instance.
    // Returns a tuple that contains the next task and the previous task. If both
    // are null then the existing task remains in scope.
    //
    // Note that this function does not actually perform the task switch. This is
    // because it holds a mutable reference to self that must be released before
    // the task switch occurs. Call this function from a global function that releases
    // the reference before performing the task switch.
    pub fn schedule(&mut self) -> (Option<*mut Box<Task>>, *mut Task) {
        // Update the state of the current task. This will change the runtime value which
        // is used as a key in the RB tree therefore we need to remove and reinsert the
        // task.
        let current_task_node = self.update_current_task();

        // Find the task with the lowest runtime. The tree only contains running tasks that
        // are to be scheduled on this vCPU.
        let cursor = self.tree().lower_bound(Bound::Included(&0));

        // The cursor will now be on the next task to schedule. There should always be
        // a candidate task unless the current cpu task terminated. For now, don't support
        // termination of the initial thread which means there will always be a task to schedule
        let next_task_node = cursor.clone_pointer().expect("No task to schedule on CPU");
        self.current_task = Some(next_task_node.clone());

        // Update the task we are switching to. Note that the next task may be
        // the same as the current task so ensure we don't mutably borrow it twice
        // by restricting the scope of the borrow_mut below.
        let next_task_ptr = next_task_node.task.as_ptr();
        let next_task_id = {
            let mut next_task = next_task_node.task.borrow_mut();
            next_task.runtime.schedule_in();
            next_task.id
        };

        let mut task_switch = true;
        let current_task_ptr = current_task_node.map_or(core::ptr::null_mut(), |t| {
            let mut current_task = t.task.borrow_mut();
            task_switch = next_task_id != current_task.id;
            current_task.as_mut() as *mut Task
        });
        if !task_switch {
            (None, core::ptr::null_mut())
        } else {
            (Some(next_task_ptr), current_task_ptr)
        }
    }

    fn update_current_task(&mut self) -> Option<TaskPointer> {
        let task_node = self.current_task.take()?;
        let task_state = {
            let mut task = task_node.task.borrow_mut();
            task.runtime.schedule_out();
            task.state
        };

        if task_state == TaskState::TERMINATED {
            // The current task has terminated. Make sure it doesn't get added back
            // into the runtime tree, but also we need to make sure we keep a
            // reference to the task because the current stack is owned by it.
            // Put it in a holding location which will be cleared by the next
            // active task.
            unsafe {
                self.deallocate(task_node.clone());
            }
            self.terminated_task = Some(task_node);
            None
        } else {
            // Reinsert the node into the tree so the position is updated with the new rutime
            let mut task_cursor = unsafe { self.tree().cursor_mut_from_ptr(task_node.as_ref()) };
            task_cursor.remove();
            self.tree().insert(task_node.clone());
            Some(task_node)
        }
    }

    /// Helper function that determines if a task is a candidate for allocating
    /// to a CPU
    fn is_cpu_candidate(id: u32, t: &Task) -> bool {
        (t.state == TaskState::RUNNING)
            && t.allocation.is_none()
            && t.affinity.map_or(true, |a| a == id)
    }

    /// Iterate through all unallocated tasks and find a suitable candidates
    /// for allocating to this queue
    pub fn allocate(&mut self, id: u32, tl: &mut LinkedList<TaskListAdapter>) {
        let lowest_runtime = if let Some(t) = self.tree().lower_bound(Bound::Included(&0)).get() {
            t.task.borrow().runtime.value()
        } else {
            0
        };
        let mut cursor = tl.cursor_mut();
        while !cursor.peek_next().is_null() {
            cursor.move_next();
            // Filter on running, unallocated tasks that either have no affinity
            // or have an affinity for this CPU ID
            if let Some(task_node) = cursor
                .get()
                .filter(|task_node| Self::is_cpu_candidate(id, task_node.task.borrow().as_ref()))
            {
                {
                    let mut t = task_node.task.borrow_mut();
                    t.allocation = Some(id);
                    t.runtime.set(lowest_runtime);
                }
                self.tree()
                    .insert(cursor.as_cursor().clone_pointer().unwrap());
            }
        }
    }

    /// Deallocate a task from a per CPU runqueue but leave it in the global task list
    /// where it can be reallocated if still in the RUNNING state.
    ///
    /// # Safety
    /// This function is marked as unsafe as it will dereference an invalid pointer if
    /// called with a task_node that is not contained within this queue.
    pub unsafe fn deallocate(&mut self, task_node: TaskPointer) {
        let mut cursor = self.tree().cursor_mut_from_ptr(task_node.as_ref());
        cursor.remove();
        task_node.task.borrow_mut().allocation = None;
    }
}

/// Global task list
/// This contains every task regardless of affinity or run state.
#[derive(Debug)]
pub struct TaskList {
    list: Option<LinkedList<TaskListAdapter>>,
}

impl TaskList {
    pub const fn new() -> Self {
        Self { list: None }
    }

    pub fn list(&mut self) -> &mut LinkedList<TaskListAdapter> {
        self.list
            .get_or_insert_with(|| LinkedList::new(TaskListAdapter::new()))
    }

    pub fn get_task(&self, id: u32) -> Option<TaskPointer> {
        if let Some(task_list) = &self.list {
            let mut cursor = task_list.front();
            while let Some(task_node) = cursor.get() {
                if task_node.task.borrow().id == id {
                    return cursor.clone_pointer();
                }
                cursor.move_next();
            }
        }
        None
    }

    pub fn terminate(&mut self, task_node: TaskPointer) {
        // Set the task state as terminated. If the task being terminated is the
        // current task then the task context will still need to be in scope until
        // the next schedule() has completed. Schedule will keep a reference to this
        // task until some time after the context switch.
        task_node.task.borrow_mut().state = TaskState::TERMINATED;
        let mut cursor = unsafe { self.list().cursor_mut_from_ptr(task_node.as_ref()) };
        cursor.remove();
    }
}

pub static TASKLIST: SpinLock<TaskList> = SpinLock::new(TaskList::new());

pub fn create_task(
    entry: extern "C" fn(),
    flags: u16,
    affinity: Option<u32>,
) -> Result<TaskPointer, SvsmError> {
    let mut task = Task::create(entry as usize, flags)?;
    task.set_affinity(affinity);
    let node = Rc::new(TaskNode {
        tree_link: RBTreeLink::default(),
        list_link: Link::default(),
        task: RefCell::new(task),
    });
    {
        // Ensure the tasklist lock is released before schedule() is called
        // otherwise the lock will be held when switching to a new context
        let mut tl = TASKLIST.lock();
        tl.list().push_front(node.clone());
        // Allocate any unallocated tasks (including the newly created one)
        // to the current CPU
        this_cpu_mut()
            .runqueue
            .allocate(this_cpu().get_apic_id(), tl.list());
    }
    schedule();

    Ok(node)
}

pub fn create_elf_task(
    buf: &[u8],
    flags: u16,
    affinity: Option<u32>,
) -> Result<TaskPointer, SvsmError> {
    let elf = match elf::Elf64File::read(buf) {
        Ok(elf) => elf,
        Err(_) => return Err(SvsmError::Module),
    };
    let default_base = elf.default_base();
    let entry = elf.get_entry(default_base);

    let mut task = Task::create(entry as usize, flags)?;
    task.set_affinity(affinity);

    // Setup the pagetable for the virtual memory ranges described in the file
    for segment in elf.image_load_segment_iter(default_base) {
        let vaddr_start = VirtAddr::from(segment.vaddr_range.vaddr_begin);
        let vaddr_end = VirtAddr::from(segment.vaddr_range.vaddr_end);
        let aligned_vaddr_end = vaddr_end.page_align_up();
        let flags = if segment.flags.contains(elf::Elf64PhdrFlags::EXECUTE) {
            PageTable::exec_flags()
        } else if segment.flags.contains(elf::Elf64PhdrFlags::WRITE) {
            PageTable::data_flags()
        } else {
            PageTable::data_ro_flags()
        };

        let phys = virt_to_phys(VirtAddr::from(
            (&buf[0] as *const u8) as u64 + segment.file_range.offset_begin as u64,
        ));
        task.page_table
            .lock()
            .map_region(vaddr_start, aligned_vaddr_end, phys, flags)
            .expect("Failed to map kernel ELF segment");
    }

    let node = Rc::new(TaskNode {
        tree_link: RBTreeLink::default(),
        list_link: Link::default(),
        task: RefCell::new(task),
    });
    {
        // Ensure the tasklist lock is released before schedule() is called
        // otherwise the lock will be held when switching to a new context
        let mut tl = TASKLIST.lock();
        tl.list().push_front(node.clone());
        // Allocate any unallocated tasks (including the newly created one)
        // to the current CPU
        this_cpu_mut()
            .runqueue
            .allocate(this_cpu().get_apic_id(), tl.list());
    }
    schedule();

    Ok(node)
}

/// Check to see if the task scheduled on the current processor has the given id
pub fn is_current_task(id: u32) -> bool {
    match &this_cpu().runqueue.current_task {
        Some(current_task) => current_task.task.borrow().id == id,
        None => id == INITIAL_TASK_ID,
    }
}

pub unsafe fn current_task_terminated() {
    let task_node = this_cpu_mut()
        .runqueue
        .current_task
        .as_mut()
        .expect("Task termination handler called when there is no current task");
    TASKLIST.lock().terminate(task_node.clone());
}

pub fn schedule() {
    let (next_task, current_task) = this_cpu_mut().runqueue.schedule();
    if let Some(next_task) = next_task {
        unsafe { (*next_task).set_current(current_task) };
    }

    // We're now in the context of the new task. If the previous task had terminated
    // then we can release it's reference here.
    let _ = this_cpu_mut().runqueue.terminated_task.take();
}
