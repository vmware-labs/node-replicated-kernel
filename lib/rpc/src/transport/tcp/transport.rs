// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//use core::sync::atomic::Ordering;

use smoltcp::phy::Device;
use smoltcp::wire::IpAddress;

use super::interface_wrapper::{InterfaceWrapper, SocketId, RX_BUF_LEN, TX_BUF_LEN};
use crate::rpc::*;
use crate::transport::Transport;

pub struct TCPTransport<'a, D: for<'d> Device<'d>> {
    interface_wrapper: InterfaceWrapper<'a, D>,
    socket_id: SocketId,
}

impl<'a, D: for<'d> Device<'d>> TCPTransport<'a, D> {
    pub fn new(
        local_port: u16,
        server_address: Option<(IpAddress, u16)>,
        interface_wrapper: InterfaceWrapper<'a, D>,
    ) -> Result<TCPTransport<'a, D>, RPCError> {
        let socket_id = interface_wrapper.add_socket(server_address, local_port)?;
        Ok(TCPTransport {
            interface_wrapper,
            socket_id,
        })
    }
}

impl<'a, D: for<'d> Device<'d>> Transport for TCPTransport<'a, D> {
    fn max_send(&self) -> usize {
        RX_BUF_LEN
    }

    fn max_recv(&self) -> usize {
        TX_BUF_LEN
    }

    fn send_msg(&self, _hdr: &RPCHeader, _payload: &[&[u8]]) -> Result<(), RPCError> {
        log::debug!("send_msg");

        /*
        // Set the send lock
        loop {
            if self
                .interface_wrapper
                .send_lock
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                break;
            } else {
                // TODO: this isn't a great solution
                for _ in 0..5 {
                    core::hint::spin_loop();
                }
            }
        }
        trace!("send_msg - acquired lock");

        if let Err(e) = self.interface_wrapper.send(&unsafe { hdr.as_bytes() }[..]) {
            self.interface_wrapper
                .send_lock
                .store(false, Ordering::SeqCst);
            trace!("send_msg - released lock on failure");
            return Err(e);
        }
        for p in payload {
            trace!("send_msg - sending payload");
            if let Err(e) = self.interface_wrapper.send(p) {
                self.interface_wrapper
                    .send_lock
                    .store(false, Ordering::SeqCst);
                trace!("send_msg - released lock on failure");
                return Err(e);
            }
        }
        self.interface_wrapper
            .send_lock
            .store(false, Ordering::SeqCst);
        debug!("send_msg - done");
        */
        Ok(())
    }

    fn recv_msg(
        &self,
        _hdr: &mut RPCHeader,
        _recipient_id: Option<MsgId>,
        _payload: &mut [&mut [u8]],
    ) -> Result<(), RPCError> {
        log::debug!("recv_msg");
        /*
        self.interface_wrapper
            .internal_recv_msg(hdr, recipient_id, payload)?;
        */
        Ok(())
    }

    fn send_and_recv(
        &self,
        hdr: &mut RPCHeader,
        send_payload: &[&[u8]],
        recv_payload: &mut [&mut [u8]],
    ) -> Result<(), RPCError> {
        self.send_msg(hdr, send_payload)?;
        self.recv_msg(hdr, Some(hdr.msg_id), recv_payload)
    }
}

/*
#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;
    use alloc::sync::Arc;

    use smoltcp::iface::{InterfaceBuilder, NeighborCache};
    use smoltcp::phy::{Loopback, Medium};
    use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};
    use spin::Mutex;

    use crate::rpc::MsgLen;
    use crate::transport::tcp::transport::InterfaceWrapper;
    use crate::transport::RPCHeader;
    use crate::transport::TCPTransport;
    use crate::transport::Transport;

    #[test]
    fn test_initialization() {
        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let mut neighbor_cache_entries = [None; 8];
        let neighbor_cache = NeighborCache::new(&mut neighbor_cache_entries[..]);
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let mut sockets: [_; 2] = Default::default();
        let iface = InterfaceBuilder::new(device, &mut sockets[..])
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();

        let interface_wrapper =
            InterfaceWrapper::new(None, 10111, 10110, Arc::new(Mutex::new(iface)))
                .expect("We should be able to initialize the interface wrapper");
        TCPTransport::new(interface_wrapper)
            .expect("We should be able to initialize the TCP transport");
    }

    #[test]
    fn test_connect() {
        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let neighbor_cache = NeighborCache::new(BTreeMap::new());
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let sock_vec = Vec::with_capacity(1);
        let iface = InterfaceBuilder::new(device, sock_vec)
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();
        let iface_arc = Arc::new(Mutex::new(iface));

        let server_iface = iface_arc.clone();
        let client_iface = iface_arc.clone();

        let server_thread = std::thread::spawn(move || {
            let interface_wrapper = InterfaceWrapper::new(None, 10111, 10110, server_iface)
                .expect("We should be able to initialize the interface wrapper");
            let mut server_transport = TCPTransport::new(interface_wrapper)
                .expect("We should be able to initialize the TCP transport");

            server_transport
                .server_accept()
                .expect("Failed to accept client connection");
        });

        let client_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let interface_wrapper = InterfaceWrapper::new(
                Some(IpAddress::v4(127, 0, 0, 1)),
                10111,
                10110,
                client_iface,
            )
            .expect("We should be able to initialize the interface wrapper");
            let mut client_transport = TCPTransport::new(interface_wrapper)
                .expect("We should be able to initialize the TCP transport");

            client_transport
                .client_connect()
                .expect("Client failed to connect to server");
        });

        client_thread.join().unwrap();
        server_thread.join().unwrap();
    }

    /*
    #[test]
    fn test_send_recv() {
        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let neighbor_cache = NeighborCache::new(BTreeMap::new());
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let sock_vec = Vec::with_capacity(1);
        let iface = InterfaceBuilder::new(device, sock_vec)
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();
        let iface_arc = Arc::new(Mutex::new(iface));

        let server_iface = iface_arc.clone();
        let client_iface = iface_arc.clone();

        let server_thread = std::thread::spawn(move || {
            let interface_wrapper = InterfaceWrapper::new(None, 10111, 10110, server_iface)
                .expect("We should be able to initialize the interface wrapper");

            let mut server_transport =
                TCPTransport::new(interface_wrapper).expect("We should be able to initialize");
            server_transport
                .server_accept()
                .expect("Failed to accept client connection");

            let mut hdr = RPCHeader::default();
            let mut recv_buf = [0; 10];
            for i in 0u8..10 {
                server_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf])
                    .expect("Failed to send message");
                let msg_len = hdr.msg_len;
                assert_eq!(msg_len, 5 as MsgLen);
                for j in 0u8..5 {
                    assert_eq!(recv_buf[j as usize], j * i);
                }
                for j in 5..10 {
                    assert_eq!(recv_buf[j as usize], 0u8);
                }

                hdr.msg_len = 2;
                server_transport
                    .send_msg(&hdr, &[&[i], &[i + 1]])
                    .expect("Failed to send message");
            }
        });

        let client_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let interface_wrapper = InterfaceWrapper::new(
                Some(IpAddress::v4(127, 0, 0, 1)),
                10111,
                10110,
                client_iface,
            )
            .expect("We should be able to initialize the interface wrapper");

            let mut client_transport =
                TCPTransport::new(interface_wrapper).expect("We should be able to initialize");
            client_transport
                .client_connect()
                .expect("Client failed to connect to server");

            let mut hdr = RPCHeader::default();
            let mut recv_buf1 = [0; 1];
            let mut recv_buf2 = [0; 1];
            for i in 0u8..10 {
                hdr.msg_len = 5;
                client_transport
                    .send_msg(&hdr, &[&[0 * i, 1 * i, 2 * i, 3 * i, 4 * i]])
                    .expect("Failed to send message");
                client_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf1, &mut recv_buf2])
                    .expect("Failed to recv message");
                assert_eq!(recv_buf1[0], i);
                assert_eq!(recv_buf2[0], i + 1);
            }
        });

        client_thread.join().unwrap();
        server_thread.join().unwrap();
    }

    #[test]
    fn test_send_and_recv() {
        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let neighbor_cache = NeighborCache::new(BTreeMap::new());
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let sock_vec = Vec::with_capacity(1);
        let iface = InterfaceBuilder::new(device, sock_vec)
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();
        let iface_arc = Arc::new(Mutex::new(iface));

        let server_iface = iface_arc.clone();
        let client_iface = iface_arc.clone();

        let server_thread = std::thread::spawn(move || {
            let interface_wrapper = InterfaceWrapper::new(None, 10111, 10110, server_iface)
                .expect("We should be able to initialize the interface wrapper");
            let mut server_transport =
                TCPTransport::new(interface_wrapper).expect("We should be able to initialize");
            server_transport
                .server_accept()
                .expect("Failed to accept client connection");

            let mut hdr = RPCHeader::default();
            let mut recv_buf = [0; 10];
            for i in 0u8..10 {
                server_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf])
                    .expect("Failed to send message");
                let msg_len = hdr.msg_len;
                assert_eq!(msg_len, 5 as MsgLen);
                for j in 0u8..5 {
                    assert_eq!(recv_buf[j as usize], j * i);
                }
                for j in 5..10 {
                    assert_eq!(recv_buf[j as usize], 0u8);
                }

                hdr.msg_len = 2;
                server_transport
                    .send_msg(&hdr, &[&[i], &[i + 1]])
                    .expect("Failed to send message");
            }
        });

        let client_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let interface_wrapper = InterfaceWrapper::new(
                Some(IpAddress::v4(127, 0, 0, 1)),
                10111,
                10110,
                client_iface,
            )
            .expect("We should be able to initialize the interface wrapper");
            let mut client_transport =
                TCPTransport::new(interface_wrapper).expect("We should be able to initialize");
            client_transport
                .client_connect()
                .expect("Client failed to connect to server");

            let mut hdr = RPCHeader::default();
            let mut recv_buf1 = [0; 1];
            let mut recv_buf2 = [0; 1];
            for i in 0u8..10 {
                hdr.msg_len = 5;
                client_transport
                    .send_and_recv(
                        &mut hdr,
                        &[&[0 * i, 1 * i, 2 * i, 3 * i, 4 * i]],
                        &mut [&mut recv_buf1, &mut recv_buf2],
                    )
                    .expect("Failed to send and recv");
                assert_eq!(recv_buf1[0], i);
                assert_eq!(recv_buf2[0], i + 1);
            }
        });

        client_thread.join().unwrap();
        server_thread.join().unwrap();
    }

    #[test]
    fn test_multi_client_server() {
        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let neighbor_cache = NeighborCache::new(BTreeMap::new());
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let sock_vec = Vec::with_capacity(1);
        let iface = InterfaceBuilder::new(device, sock_vec)
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();
        let iface_arc = Arc::new(Mutex::new(iface));

        let server_iface = iface_arc.clone();
        let client_iface = iface_arc.clone();
        let client2_iface = iface_arc.clone();

        let server_thread = std::thread::spawn(move || {
            let interface_wrapper = InterfaceWrapper::new(None, 10111, 10110, server_iface.clone())
                .expect("We should be able to initialize the interface wrapper");
            let mut server_transport =
                TCPTransport::new(interface_wrapper).expect("We should be able to initialize");

            let interface_wrapper = InterfaceWrapper::new(None, 10113, 10112, server_iface)
                .expect("We should be able to initialize the interface wrapper");
            let mut server2_transport = TCPTransport::new(interface_wrapper).expect(
                "We should be able to initialize a second transport with the same interface",
            );

            server_transport
                .server_accept()
                .expect("Failed to accept client connection");
            println!("Server1 done accepting");
            server2_transport
                .server_accept()
                .expect("Failed to accept client connection");
            println!("Server2 done accepting");

            let mut hdr = RPCHeader::default();
            let mut recv_buf = [0; 10];
            for i in 0u8..10 {
                server_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf])
                    .expect("Failed to send message");

                let msg_len = hdr.msg_len;
                assert_eq!(msg_len, 5 as MsgLen);
                for j in 0u8..5 {
                    assert_eq!(recv_buf[j as usize], j * i);
                }
                for j in 5..10 {
                    assert_eq!(recv_buf[j as usize], 0u8);
                }
                server2_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf])
                    .expect("Failed to send message");

                let msg_len = hdr.msg_len;
                assert_eq!(msg_len, 5 as MsgLen);
                for j in 0u8..5 {
                    assert_eq!(recv_buf[j as usize], 1u8);
                }
                for j in 5..10 {
                    assert_eq!(recv_buf[j as usize], 0u8);
                }

                hdr.msg_len = 2;
                server_transport
                    .send_msg(&hdr, &[&[i], &[i + 1]])
                    .expect("Failed to send message");
                server2_transport
                    .send_msg(&hdr, &[&[i + 1], &[i + 2]])
                    .expect("Failed to send message");
            }
        });

        let client_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let interface_wrapper = InterfaceWrapper::new(
                Some(IpAddress::v4(127, 0, 0, 1)),
                10111,
                10110,
                client_iface,
            )
            .expect("We should be able to initialize the interface wrapper");
            let mut client_transport =
                TCPTransport::new(interface_wrapper).expect("We should be able to initialize");
            client_transport
                .client_connect()
                .expect("Client failed to connect to server");
            println!("Client 1 connected");

            let mut hdr = RPCHeader::default();
            let mut recv_buf1 = [0; 1];
            let mut recv_buf2 = [0; 1];
            for i in 0u8..10 {
                hdr.msg_len = 5;
                println!("Client 1 before send");
                client_transport
                    .send_msg(&hdr, &[&[0 * i, 1 * i, 2 * i, 3 * i, 4 * i]])
                    .expect("Failed to send message");
                println!("Client 1 before recv");
                client_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf1, &mut recv_buf2])
                    .expect("Failed to recv message");
                println!("Client 1 after recv");
                assert_eq!(recv_buf1[0], i);
                assert_eq!(recv_buf2[0], i + 1);
            }
        });

        let client2_thread = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let interface_wrapper = InterfaceWrapper::new(
                Some(IpAddress::v4(127, 0, 0, 1)),
                10113,
                10112,
                client2_iface,
            )
            .expect("We should be able to initialize the interface wrapper");
            let mut client2_transport =
                TCPTransport::new(interface_wrapper).expect("We should be able to initialize");
            client2_transport
                .client_connect()
                .expect("Client failed to connect to server");
            println!("Client 2 connected");

            let mut hdr = RPCHeader::default();
            let mut recv_buf1 = [0; 1];
            let mut recv_buf2 = [0; 1];
            // Send 2, then receive 2
            for i in 0u8..5 {
                hdr.msg_len = 5;
                println!("Client 2 before send1");
                client2_transport
                    .send_msg(&hdr, &[&[1, 1, 1, 1, 1]])
                    .expect("Failed to send message");
                println!("Client 2 before send2");
                client2_transport
                    .send_msg(&hdr, &[&[1, 1, 1, 1, 1]])
                    .expect("Failed to send message");
                println!("Client 2 before recv1");
                client2_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf1, &mut recv_buf2])
                    .expect("Failed to recv message");
                assert_eq!(recv_buf1[0], (i * 2) + 1);
                assert_eq!(recv_buf2[0], (i * 2) + 2);
                println!("Client 2 before recv2");
                client2_transport
                    .recv_msg(&mut hdr, None, &mut [&mut recv_buf1, &mut recv_buf2])
                    .expect("Failed to recv message");
                println!("Client 2 after recv2");
                assert_eq!(recv_buf1[0], (i * 2 + 1) + 1);
                assert_eq!(recv_buf2[0], (i * 2 + 1) + 2);
            }
        });

        client_thread.join().unwrap();
        client2_thread.join().unwrap();
        server_thread.join().unwrap();
    }
    */
}
*/
