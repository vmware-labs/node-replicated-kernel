#![feature(no_std)]
#![feature(lang_items)]
#![feature(asm)]
#![feature(core)]
#![no_std]

use core::prelude::*;

#[macro_use]
extern crate core;
#[macro_use]
extern crate x86;

pub mod unwind;
use x86::syscall;

#[no_mangle]
pub fn main() {

    unsafe { syscall!(1, 1); }

    loop {};
}
