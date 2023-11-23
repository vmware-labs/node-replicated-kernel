// Copyright © 2022 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;

use fallible_collections::FallibleVecGlobal;
use lazy_static::lazy_static;
use smoltcp::iface::{Interface, InterfaceBuilder, NeighborCache, Routes};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv4Address};
use spin::Mutex;

use kpi::KERNEL_BASE;
use vmxnet3::pci::BarAccess;
use vmxnet3::smoltcp::DevQueuePhy;
use vmxnet3::vmx::VMXNet3;

use crate::cmdline::Mode;
use crate::error::{KError, KResult};
use crate::memory::vspace::MapAction;
use crate::memory::PAddr;
use crate::pci::claim_device;

lazy_static! {
    pub(crate) static ref ETHERNET_IFACE: Arc<Mutex<Interface<'static, DevQueuePhy>>> =
        init_network().expect("Failed to create ethernet interface");
}

#[allow(unused)]
pub(crate) fn init_network<'a>() -> KResult<Arc<Mutex<Interface<'a, DevQueuePhy>>>> {
    const VMWARE_INC: u16 = 0x15ad;
    const VMXNET_DEV: u16 = 0x07b0;
    if let Some(vmxnet3_dev) = claim_device(VMWARE_INC, VMXNET_DEV) {
        let addr = vmxnet3_dev.pci_address();
        let pci = BarAccess::new(addr.bus.into(), addr.dev.into(), addr.fun.into());

        // TODO(hack): Map potential vmxnet3 bar addresses XD
        {
            let mut kvspace = crate::arch::vspace::INITIAL_VSPACE.lock();
            for &bar in &[pci.bar0 - KERNEL_BASE, pci.bar1 - KERNEL_BASE] {
                kvspace
                    .map_identity_with_offset(
                        PAddr::from(KERNEL_BASE),
                        PAddr::from(bar),
                        0x1000,
                        MapAction::kernel() | MapAction::write(),
                    )
                    .expect("Failed to write potential vmxnet3 bar addresses")
            }
        }

        // Create the VMX device
        let mut vmx = VMXNet3::new(pci, 1, 1).unwrap();
        vmx.attach_pre().expect("Failed to vmx.attach_pre()");
        vmx.init();

        // Create the EthernetInterface wrapping the VMX device
        let device = DevQueuePhy::new(vmx).expect("Can't create PHY");
        let neighbor_cache = NeighborCache::new(BTreeMap::new());
        let mid: u8 = (*crate::environment::MACHINE_ID).try_into().unwrap();

        let (ethernet_addr, ip_addrs) = match crate::CMDLINE.get().map_or(Mode::Native, |c| c.mode)
        {
            Mode::Client => (
                EthernetAddress([0x56, 0xb4, 0x44, 0xe9, 0x62, 0xd0 + mid as u8]),
                [IpCidr::new(IpAddress::v4(172, 31, 0, 11 + mid), 24)],
            ),
            _ => (
                EthernetAddress([0x56, 0xb4, 0x44, 0xe9, 0x62, 0xd0 + mid as u8]),
                [IpCidr::new(IpAddress::v4(172, 31, 0, 11 + mid), 24)],
            ),
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
        Ok(Arc::new(Mutex::new(iface)))
    } else {
        Err(KError::VMXNet3DeviceNotFound)
    }
}

#[cfg(feature = "rpc")]
#[allow(unused)]
pub(crate) fn init_ethernet_rpc(
    server_ip: smoltcp::wire::IpAddress,
    server_port_base: u16,
    num_cores: u64,
    is_dcm: bool,
) -> KResult<Vec<rpc::client::Client>> {
    use crate::arch::rackscale::registration::initialize_client;
    use alloc::boxed::Box;
    use core::hint::spin_loop;
    use core::time::Duration;
    use rpc::client::Client;
    use rpc::transport::TCPTransport;

    let mut clients: Vec<rpc::client::Client> = Vec::new();

    for i in 0..num_cores {
        let offset = i;
        let server_port = server_port_base + offset as u16;

        let rpc_transport = Box::new(
            TCPTransport::new(Some(server_ip), server_port, Arc::clone(&ETHERNET_IFACE))
                .map_err(|err| KError::RackscaleRPCError { err })?,
        );
        let mut client = Client::new(rpc_transport);

        // only send client data on first client registration request
        let send_client_data = if i == 0 { true } else { false };

        client = initialize_client(client, send_client_data, is_dcm)
            .expect("Failed to initialize client");

        // After sending client initialization, allow time for controller to
        // register additional rpc servers before sending more requests
        if send_client_data && !is_dcm {
            unsafe {
                let start = rawtime::Instant::now();
                while start.elapsed() < Duration::from_secs(5) {
                    spin_loop();
                }
            }
        }

        clients.push(client);
    }

    Ok(clients)
}
