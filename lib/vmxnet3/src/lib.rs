// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

#![no_std]
#![feature(core_intrinsics, allocator_api)]

extern crate alloc;

pub mod pci;
pub mod reg;
pub mod smoltcp;
pub mod var;
pub mod vmx;

#[derive(Default)]
pub struct BoundedU32<const LOW: u32, const HIGH: u32>(u32);

impl<const LOW: u32, const HIGH: u32> BoundedU32<{ LOW }, { HIGH }> {
    pub const LOW: u32 = LOW;
    pub const HIGH: u32 = HIGH;

    pub fn new(n: u32) -> Self {
        BoundedU32(n.min(Self::HIGH).max(Self::LOW))
    }

    pub fn fallible_new(n: u32) -> Result<Self, &'static str> {
        match n {
            n if n < Self::LOW => Err("Value too low"),
            n if n > Self::HIGH => Err("Value too high"),
            n => Ok(BoundedU32(n)),
        }
    }

    pub fn set(&mut self, n: u32) {
        *self = BoundedU32(n.min(Self::HIGH).max(Self::LOW))
    }
}

impl<const LOW: u32, const HIGH: u32> core::ops::Deref for BoundedU32<{ LOW }, { HIGH }> {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Default)]
pub struct BoundedUSize<const LOW: usize, const HIGH: usize>(usize);

impl<const LOW: usize, const HIGH: usize> BoundedUSize<{ LOW }, { HIGH }> {
    pub const LOW: usize = LOW;
    pub const HIGH: usize = HIGH;

    pub fn new(n: usize) -> Self {
        BoundedUSize(n.min(Self::HIGH).max(Self::LOW))
    }

    pub fn fallible_new(n: usize) -> Result<Self, &'static str> {
        match n {
            n if n < Self::LOW => Err("Value too low"),
            n if n > Self::HIGH => Err("Value too high"),
            n => Ok(BoundedUSize(n)),
        }
    }

    pub fn set(&mut self, n: usize) {
        *self = BoundedUSize(n.min(Self::HIGH).max(Self::LOW))
    }
}

impl<const LOW: usize, const HIGH: usize> core::ops::Deref for BoundedUSize<{ LOW }, { HIGH }> {
    type Target = usize;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
