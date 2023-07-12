// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Roy Hopkins <rhopkins@suse.de>

extern crate alloc;

use core::cell::RefCell;

use super::Task;
use crate::error::SvsmError;
use crate::locking::SpinLock;
use alloc::boxed::Box;
use alloc::rc::Rc;
use intrusive_collections::linked_list::Link;
use intrusive_collections::{intrusive_adapter, LinkedList};

pub type TaskPointer = Rc<TaskNode>;

#[derive(Debug)]
pub struct TaskNode {
    list_link: Link,
    pub task: RefCell<Box<Task>>,
}

intrusive_adapter!(pub TaskListAdapter = Rc<TaskNode>: TaskNode { list_link: Link });

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
            .get_or_insert_with(|| LinkedList::<TaskListAdapter>::new(TaskListAdapter::new()))
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
        list_link: Link::default(),
        task: RefCell::new(task),
    });
    TASKLIST.lock().list().push_front(node.clone());
    Ok(node)
}
