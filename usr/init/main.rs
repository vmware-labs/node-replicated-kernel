#![feature(no_std)] //< unwind needs to define lang items
#![feature(lang_items)] //< unwind needs to define lang items
#![feature(asm)]    //< As a kernel, we need inline assembly
#![feature(core)]   //< libcore (see below) is not yet stablized
#![feature(intrinsics)]
#![no_std]  //< Kernels can't use std

use prelude::*;

#[macro_use]
extern crate core;
pub mod unwind;
mod prelude;

#[lang="start"]
#[no_mangle]
pub fn main() {
    loop {};
}
