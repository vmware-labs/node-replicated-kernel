// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(unused)]

use arrayvec::ArrayVec;
use driverkit::pci::{scan_bus, PciDevice};
use lazy_static::lazy_static;
use log::info;
use spin::Mutex;

use crate::kcb;

/// The maximum number of PCI devices we support on the machine.
///
/// This is a constant, and is used to allocate a static array.
/// Maybe this can be dynamic in the future.
const MAX_PCI_DEVICES: usize = 24;

lazy_static! {
    /// All PCI devices found on the machine.
    pub(crate) static ref PCI_DEVICES: ArrayVec<Mutex<Option<PciDevice>>, MAX_PCI_DEVICES> = {
        let mut devices = ArrayVec::new();
        let bus_iter = scan_bus();
        for device in bus_iter {
            info!("PCI: {}", device);
            devices.push(Mutex::new(Some(device)));
        }

        devices
    };
}

/// Takes a device (for use in a driver).
pub(crate) fn claim_device(vendor_id: u16, device_id: u16) -> Option<PciDevice> {
    for device in PCI_DEVICES.iter() {
        let device = &mut *device.lock();
        if let Some(locked_device) = device {
            if locked_device.vendor_id() == vendor_id && locked_device.device_id() == device_id {
                return device.take();
            }
        }
    }
    None
}

pub(crate) fn init() {
    lazy_static::initialize(&PCI_DEVICES);
}
