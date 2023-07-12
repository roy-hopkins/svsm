// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use core::cell::RefCell;

use super::Task;
use super::{tasks::TaskRuntime, TaskState, INITIAL_TASK_ID};
use crate::error::SvsmError;
use crate::locking::SpinLock;
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
}

impl RunQueue {
    pub const fn new() -> Self {
        Self {
            tree: None,
            current_task: None,
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
        task_node.task.borrow_mut().runtime.schedule_out();

        // Reinsert the node into the tree so the position is updated with the new rutime
        let mut task_cursor = unsafe { self.tree().cursor_mut_from_ptr(task_node.as_ref()) };
        task_cursor.remove();
        self.tree().insert(task_node.clone());
        Some(task_node)
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
}

pub static TASKLIST: SpinLock<TaskList> = SpinLock::new(TaskList::new());

pub fn create_task(
    entry: extern "C" fn(),
    flags: u16,
    affinity: Option<u32>,
) -> Result<TaskPointer, SvsmError> {
    let mut task = Task::create(entry, flags)?;
    task.set_affinity(affinity);
    let node = Rc::new(TaskNode {
        tree_link: RBTreeLink::default(),
        list_link: Link::default(),
        task: RefCell::new(task),
    });
    TASKLIST.lock().list().push_front(node.clone());
    Ok(node)
}
