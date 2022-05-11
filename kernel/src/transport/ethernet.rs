// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use fallible_collections::FallibleVecGlobal;
use smoltcp::iface::{Interface, InterfaceBuilder, NeighborCache, Routes};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};
use vmxnet3::pci::BarAccess;
use vmxnet3::smoltcp::DevQueuePhy;
use vmxnet3::vmx::VMXNet3;

use crate::error::KError;
use crate::memory::PAddr;
use crate::pci::claim_device;
use crate::{kcb::Mode, memory::vspace::MapAction};
use kpi::KERNEL_BASE;

#[allow(unused)]
pub fn init_network<'a>() -> Result<Interface<'a, DevQueuePhy>, KError> {
    const VMWARE_INC: u16 = 0x15ad;
    const VMXNET_DEV: u16 = 0x07b0;
    if let Some(vmxnet3_dev) = claim_device(VMWARE_INC, VMXNET_DEV) {
        let addr = vmxnet3_dev.pci_address();
        let pci = BarAccess::new(addr.bus.into(), addr.dev.into(), addr.fun.into());

        // TODO(hack): Map potential vmxnet3 bar addresses XD
        // Do this in kernel space (offset of KERNEL_BASE) so the mapping persists
        let kcb = crate::kcb::get_kcb();
        for &bar in &[pci.bar0 - KERNEL_BASE, pci.bar1 - KERNEL_BASE] {
            kcb.arch
                .init_vspace()
                .map_identity_with_offset(
                    PAddr::from(KERNEL_BASE),
                    PAddr::from(bar),
                    0x1000,
                    MapAction::ReadWriteKernel,
                )
                .expect("Failed to write potential vmxnet3 bar addresses")
        }

        // Create the VMX device
        let mut vmx = VMXNet3::new(pci, 1, 1).unwrap();
        vmx.attach_pre().expect("Failed to vmx.attach_pre()");
        vmx.init();

        // Create the EthernetInterface wrapping the VMX device
        let device = DevQueuePhy::new(vmx).expect("Can't create PHY");
        let neighbor_cache = NeighborCache::new(BTreeMap::new());

        let (ethernet_addr, ip_addrs) = match kcb.cmdline.mode {
            Mode::Client => (
                EthernetAddress([0x56, 0xb4, 0x44, 0xe9, 0x62, 0xdd]),
                [IpCidr::new(IpAddress::v4(172, 31, 0, 12), 24)],
            ),
            _ => {
                // TODO: MAC, IP, and default route should be dynamic
                (
                    EthernetAddress([0x56, 0xb4, 0x44, 0xe9, 0x62, 0xdc]),
                    [IpCidr::new(IpAddress::v4(172, 31, 0, 11), 24)],
                )
            }
        };

        let mut routes = Routes::new(BTreeMap::new());
        routes
            .add_default_ipv4_route(Ipv4Address::new(172, 31, 0, 20))
            .unwrap();

        // Create SocketSet w/ space for 1 socket
        let mut sock_vec = Vec::try_with_capacity(1)?;
        let iface = InterfaceBuilder::new(device, sock_vec)
            .ip_addrs(ip_addrs)
            .hardware_addr(ethernet_addr.into())
            .routes(routes)
            .neighbor_cache(neighbor_cache)
            .finalize();
        Ok(iface)
    } else {
        Err(KError::VMXNet3DeviceNotFound)
    }
}
