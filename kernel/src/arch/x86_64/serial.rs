// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Print logic and line buffering.
use alloc::format;
use alloc::string::{String, ToString};
use core::cell::RefCell;

use klogger::sprint;

use crate::fallible_string::FallibleString;

/// A thread local print buffer that stores characters temporarily (until they
/// are sent out on the wire).
///
/// # Note
/// The `capacity()` of the initial buffer is empty which means there is no
/// buffering until `set_print_buffer()` is called to replace the buffer (once
/// we have dynamic memory allocation).
#[thread_local]
pub(crate) static PRINT_BUFFER: RefCell<String> = RefCell::new(String::new());

/// Initializes the `PRINT_BUFFER` with a memory buffer.
pub(super) fn init() {
    SerialControl::set_print_buffer(
        String::try_with_capacity(128).expect("Not enough memory to initialize system"),
    );
}

/// Controls interaction with the serial line from a single core.
pub(crate) struct SerialControl;

impl SerialControl {
    /// Stores a print buffer in the thread local storage.
    ///
    /// The client needs to ensure the buffer is empty otherwise this function
    /// will panic. The easiest way to ensure this is to call `set_print_buffer`
    /// only once during init. If at some point we need to replace this
    /// dynamically we need to add a flush method to the `SerialControl` struct.
    fn set_print_buffer(buffer: String) {
        assert_eq!(PRINT_BUFFER.borrow().len(), 0, "print buffer not empty");
        PRINT_BUFFER.replace(buffer);
    }

    /// A poor mans line buffer scheme
    ///
    /// Buffers things until there is a newline in the `buffer` OR we've
    /// exhausted the available `PRINT_BUFFER` space, then print everything out.
    pub(crate) fn buffered_print(buffer: &str) {
        // A poor mans line buffer scheme:
        match PRINT_BUFFER.try_borrow_mut() {
            Ok(mut kbuf) => match buffer.find("\n") {
                Some(idx) => {
                    let (low, high) = buffer.split_at(idx + 1);
                    let _r = klogger::SERIAL_LINE_MUTEX.lock();
                    sprint!("{}{}", kbuf, low);
                    kbuf.clear();

                    // Avoid realloc of the kbuf if capacity can't fit `high`
                    // kbuf.len() will be 0 but we keep it for robustness
                    if high.len() <= kbuf.capacity() - kbuf.len() {
                        kbuf.push_str(high);
                    } else {
                        sprint!("{}", high);
                    }
                }
                None => {
                    // Avoid realloc of the kbuf if capacity can't fit `buffer`
                    if buffer.len() > kbuf.capacity() - kbuf.len() {
                        let _r = klogger::SERIAL_LINE_MUTEX.lock();
                        sprint!("{}{}", kbuf, buffer);
                        kbuf.clear();
                    } else {
                        kbuf.push_str(buffer);
                    }
                }
            },
            // BorrowMutError can happen (e.g., we're in a panic interrupt
            // handler or in the gdb debug handler while we were printing in the
            // kernel code) so we just print the current buffer to have some
            // output which might get mangled with other output but mangled
            // output is still better than no output, am I right?
            Err(_e) => {
                sprint!("{}", buffer);
            }
        }
    }

    /// This is mostly copied from arch/x86_64/serial.rs
    /// A poor mans line buffer scheme
    ///
    /// Buffers things until there is a newline in the `buffer` OR we've
    /// exhausted the available `print_buffer` space, then print everything out.
    /// Returns a string if everything is printed.
    #[allow(unused)]
    pub(crate) fn buffered_print_and_return(buffer: &str) -> Option<String> {
        let mut ret = "".to_string();
        // A poor mans line buffer scheme:
        match PRINT_BUFFER.try_borrow_mut() {
            Ok(mut kbuf) => match buffer.find("\n") {
                Some(idx) => {
                    let (low, high) = buffer.split_at(idx + 1);
                    ret = format!("{}{}", kbuf, low);
                    let _r = klogger::SERIAL_LINE_MUTEX.lock();
                    sprint!("{}{}", kbuf, low);
                    kbuf.clear();

                    // Avoid realloc of the kbuf if capacity can't fit `high`
                    // kbuf.len() will be 0 but we keep it for robustness
                    if high.len() <= kbuf.capacity() - kbuf.len() {
                        kbuf.push_str(high);
                    } else {
                        ret = format!("{}", high);
                        sprint!("{}", high);
                    }
                }
                None => {
                    // Avoid realloc of the kbuf if capacity can't fit `buffer`
                    if buffer.len() > kbuf.capacity() - kbuf.len() {
                        ret = format!("{}{}", kbuf, buffer);
                        let _r = klogger::SERIAL_LINE_MUTEX.lock();
                        sprint!("{}{}", kbuf, buffer);
                        kbuf.clear();
                    } else {
                        kbuf.push_str(buffer);
                    }
                }
            },
            // BorrowMutError can happen (e.g., we're in a panic interrupt
            // handler or in the gdb debug handler while we were printing in the
            // kernel code) so we just print the current buffer to have some
            // output which might get mangled with other output but mangled
            // output is still better than no output, am I right?
            Err(_e) => {
                sprint!("{}", buffer);
            }
        }

        if ret.len() > 0 {
            Some(ret)
        } else {
            None
        }
    }
}
