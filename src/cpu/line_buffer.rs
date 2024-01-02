// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2022-2023 SUSE LLC
//
// Author: Vasant Karasulli <vkarasulli@suse.de>
#[cfg(feature = "enable-console-log")]
use crate::console::_print;

use crate::cpu::percpu::this_cpu_mut;
use crate::log_buffer::log_buffer;
use crate::string::FixedString;
use crate::types::LINE_BUFFER_SIZE;
use crate::utils::immut_after_init::ImmutAfterInitCell;
use core::fmt;
use core::fmt::Write;

#[derive(Debug)]
pub struct LineBuffer {
    buf: FixedString<LINE_BUFFER_SIZE>,
}

impl LineBuffer {
    pub const fn new() -> Self {
        LineBuffer {
            buf: FixedString::new(),
        }
    }

    pub fn write_buffer(&mut self, s: &str) {
        for c in s.chars() {
            self.buf.push(c);
            if c == '\n' || self.buf.length() == LINE_BUFFER_SIZE {
                // when buffer is full or '\n' character is encountered
                log_buffer().write_log(&self.buf);
                self.buf.clear();
            }
        }
    }
}

impl fmt::Write for LineBuffer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_buffer(s);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct BufferLogger {
    component: &'static str,
}

impl BufferLogger {
    fn new(component: &'static str) -> BufferLogger {
        BufferLogger { component }
    }
}

impl log::Log for BufferLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let comp: &'static str = self.component;
        let line_buf: &mut LineBuffer = this_cpu_mut().get_line_buffer();
        // Log format/detail depends on the level.
        let rec_args = record.args();
        let lvl = record.metadata().level().as_str();
        let target = record.metadata().target();
        match record.metadata().level() {
            log::Level::Error | log::Level::Warn => {
                line_buf
                    .write_fmt(format_args!("[{}] {}: {}\n", comp, lvl, rec_args))
                    .unwrap();
                #[cfg(feature = "enable-console-log")]
                {
                    _print(format_args!("[{}] {}: {}\n", comp, lvl, rec_args));
                }
            }

            log::Level::Info => {
                line_buf
                    .write_fmt(format_args!("[{}] {}\n", comp, rec_args))
                    .unwrap();
                #[cfg(feature = "enable-console-log")]
                {
                    _print(format_args!("[{}] {}\n", comp, rec_args));
                }
            }

            log::Level::Debug | log::Level::Trace => {
                line_buf
                    .write_fmt(format_args!("[{}/{}] {} {}\n", comp, target, lvl, rec_args))
                    .unwrap();
                #[cfg(feature = "enable-console-log")]
                {
                    _print(format_args!("[{}/{}] {} {}\n", comp, target, lvl, rec_args));
                }
            }
        }
    }

    fn flush(&self) {}
}

static BUFFER_LOGGER: ImmutAfterInitCell<BufferLogger> = ImmutAfterInitCell::uninit();

pub fn install_buffer_logger(component: &'static str) {
    BUFFER_LOGGER
        .init(&BufferLogger::new(component))
        .expect("already initialized the logger");
    let _ = log::set_logger(&*BUFFER_LOGGER);

    // Log levels are to be configured via the log's library feature configuration.
    log::set_max_level(log::LevelFilter::Trace);
}
