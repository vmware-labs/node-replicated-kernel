#![feature(no_std)]
#![feature(lang_items)]
#![feature(asm)]
#![feature(core)]
#![no_std]

use core::prelude::*;

#[macro_use]
extern crate core;

pub mod unwind;

#[no_mangle]
pub fn main() {
    loop {};
}
