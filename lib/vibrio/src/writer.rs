// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! A simple printing infrastructure for user-space programs.
//! We provide [`core::fmt::Write`] and [`log::Log`].

use core::{fmt, ops};

use log::{Level, Metadata, Record};

/// println macro that uses the logging syscall.
#[macro_export]
macro_rules! sys_println {
	( $($arg:tt)* ) => ({
		use core::fmt::Write;
        use $crate::writer::{Writer};
		let _ = write!(&mut Writer::get(), $($arg)*);
	})
}

/// print macro that uses the logging syscall.
#[macro_export]
macro_rules! sys_print {
	( $($arg:tt)* ) => ({
		use core::fmt::Write;
        use $crate::writer::{WriterNoDrop};
		let _ = write!(&mut WriterNoDrop::get(), $($arg)*);
	})
}

pub struct Writer;

impl Writer {
    /// Obtain a logger for the specified module.
    pub fn get_module(module: &str) -> Writer {
        use core::fmt::Write;
        let mut ret = Writer;
        let _ = write!(&mut ret, "[{}] ", module);
        ret
    }

    pub fn get() -> Writer {
        Writer
    }
}

impl ops::Drop for Writer {
    /// Release the logger.
    fn drop(&mut self) {
        use core::fmt::Write;
        let _ = write!(self, "\r\n");
    }
}

impl fmt::Write for Writer {
    /// Write stuff to serial out.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        crate::syscalls::Process::print(s).expect("Can't write string");
        Ok(())
    }
}

pub struct WriterNoDrop;

impl WriterNoDrop {
    pub fn get() -> WriterNoDrop {
        WriterNoDrop
    }
}

impl fmt::Write for WriterNoDrop {
    /// Write stuff to serial out.
    fn write_str(&mut self, s: &str) -> fmt::Result {
        crate::syscalls::Process::print(s).expect("Can't write string");
        Ok(())
    }
}

#[derive(Debug)]
pub struct ULogger;

pub static mut LOGGER: ULogger = ULogger {};

impl log::Log for ULogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Trace
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            sys_println!(
                "[{}] - {}: {}",
                record.level(),
                record.target(),
                record.args(),
            );
        }
    }

    fn flush(&self) {}
}
