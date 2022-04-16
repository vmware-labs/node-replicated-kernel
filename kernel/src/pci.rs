use arrayvec::ArrayVec;
use driverkit::pci::{scan_bus, PciDevice};
use lazy_static::lazy_static;
use log::info;

use crate::kcb;

/// The maximum number of PCI devices we support on the machine.
///
/// This is a constant, and is used to allocate a static array.
/// Maybe this can be dynamic in the future.
const MAX_PCI_DEVICES: usize = 24;

lazy_static! {
    /// All PCI devices found on the machine.
    pub static ref PCI_DEVICES: ArrayVec<PciDevice, MAX_PCI_DEVICES> = {
        let mut devices = ArrayVec::new();
        let bus_iter = scan_bus();
        for device in bus_iter {
            info!("PCI: {}", device);

            // TODO(hack): set cross-VM memory region:
            // (Ideally we have a proper driver + device interface for such things)
            const RED_HAT_INC: u16 = 0x1af4;
            const INTER_VM_SHARED_MEM_DEV: u16 = 0x1110;
            if device.vendor_id() == RED_HAT_INC && device.device_id() == INTER_VM_SHARED_MEM_DEV {
                let kcb = kcb::get_kcb();
                kcb.set_ivshmem_device(device);
            }
            else {
                devices.push(device);
            }
        }

        devices
    };
}
