// Copyright © 2021 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::sync::Arc;
use core::mem::MaybeUninit;

use smoltcp::phy::Device;
use smoltcp::wire::IpAddress;

use super::interface_wrapper::{InterfaceWrapper, SocketId};
use crate::rpc::*;
use crate::transport::Transport;

pub struct TCPTransport<'a, D: for<'d> Device<'d>> {
    interface_wrapper: Arc<InterfaceWrapper<'a, D>>,
    socket_id: SocketId,
    max_inflight_msgs: MsgId,
}

impl<'a, D: for<'d> Device<'d>> TCPTransport<'a, D> {
    pub fn new(
        server_address: Option<(IpAddress, u16)>,
        local_port: u16,
        interface_wrapper: Arc<InterfaceWrapper<'a, D>>,
        max_inflight_msgs: MsgId,
    ) -> Result<TCPTransport<'a, D>, RPCError> {
        let socket_id =
            interface_wrapper.add_socket(server_address, local_port, max_inflight_msgs as usize)?;
        Ok(TCPTransport {
            interface_wrapper,
            socket_id,
            max_inflight_msgs,
        })
    }
}

impl<'a, D: for<'d> Device<'d>> Transport for TCPTransport<'a, D> {
    fn max_inflight_msgs(&self) -> MsgId {
        self.max_inflight_msgs
    }

    fn send_msg(
        &self,
        hdr: &RPCHeader,
        sender_id: MsgId,
        payload: &[&[u8]],
    ) -> Result<(), RPCError> {
        // Calculate the data length
        let mut data_len = HDR_LEN;
        for p in payload {
            data_len += p.len();
        }

        // Create the arc buffer
        let mut buffer = Arc::<[u8]>::new_uninit_slice(data_len);
        let data = Arc::get_mut(&mut buffer).unwrap(); // not shared yet, no panic!

        // Write the header
        MaybeUninit::write_slice(&mut data[..HDR_LEN], unsafe { &hdr.as_bytes()[..] });

        // Write the payload
        let mut offset = HDR_LEN;
        for p in payload {
            MaybeUninit::write_slice(&mut data[offset..offset + p.len()], p);
            offset += p.len();
        }

        let buffer = unsafe {
            // Safety:
            // - Length == data_len: see above
            // - All initialized: wrote data len by writing to all buffs at offset
            buffer.assume_init()
        };

        self.interface_wrapper
            .send_msg(self.socket_id, sender_id, buffer)
    }

    fn recv_msg(
        &self,
        hdr: &mut RPCHeader,
        recipient_id: MsgId,
        payload: &mut [&mut [u8]],
    ) -> Result<(), RPCError> {
        // Calculate the data length
        let mut data_len = HDR_LEN;
        for i in 0..payload.len() {
            data_len += payload[i].len();
        }

        // Create the arc buffer
        let buffer = Arc::<[u8]>::new_uninit_slice(data_len);
        let buffer = unsafe {
            // Safety:
            // - Length == data_len: see above
            // - All initialized: wrote data len by writing to all buffs at offset
            buffer.assume_init()
        };

        // Receive message
        let recv_buffer = self
            .interface_wrapper
            .recv_msg(self.socket_id, recipient_id, buffer)?;

        // Copy header
        let recv_hdr = RPCHeader::from_bytes(&*recv_buffer);
        hdr.copy_from(recv_hdr);

        log::trace!("Received header from {:?}: {:?}", recipient_id, hdr);

        // Copy data
        let data_to_receive = HDR_LEN + hdr.msg_len as usize;
        let mut data_copied = HDR_LEN;
        for p in payload.iter_mut() {
            let slice_size = core::cmp::min(p.len(), data_to_receive - data_copied);
            p[..slice_size].clone_from_slice(&recv_buffer[data_copied..data_copied + slice_size]);
            data_copied += slice_size;
            if data_copied == data_to_receive {
                break;
            }
        }

        Ok(())
    }

    fn send_and_recv(
        &self,
        hdr: &mut RPCHeader,
        send_payload: &[&[u8]],
        recv_payload: &mut [&mut [u8]],
    ) -> Result<(), RPCError> {
        self.send_msg(hdr, hdr.msg_id, send_payload)?;
        self.recv_msg(hdr, hdr.msg_id, recv_payload)
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use smoltcp::wire::IpAddress;
    use std::thread;

    use crate::rpc::MsgLen;
    use crate::test::setup_test_logging;
    use crate::transport::tcp::test::get_loopback_interface;
    use crate::transport::tcp::transport::InterfaceWrapper;
    use crate::transport::RPCHeader;
    use crate::transport::TCPTransport;
    use crate::transport::Transport;

    #[test]
    fn test_initialization() {
        setup_test_logging();
        log::warn!("Starting test: test_initialization");

        let iface = get_loopback_interface();

        let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));
        TCPTransport::new(None, 10110, interface_wrapper, 1)
            .expect("We should be able to initialize the TCP transport");
    }

    #[test]
    fn test_send_recv() {
        setup_test_logging();
        log::warn!("Starting test: test_send_recv");

        let iface = get_loopback_interface();

        let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));
        let server_interface_wrapper = interface_wrapper.clone();
        let client_interface_wrapper = interface_wrapper.clone();
        thread::scope(|s| {
            s.spawn(move || {
                let server_transport = TCPTransport::new(None, 10110, server_interface_wrapper, 1)
                    .expect("We should be able to initialize");

                let mut hdr = RPCHeader::default();
                let mut recv_buf = [0; 10];
                for i in 0u8..10 {
                    server_transport
                        .recv_msg(&mut hdr, 0, &mut [&mut recv_buf])
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
                        .send_msg(&hdr, 0, &[&[i], &[i + 1]])
                        .expect("Failed to send message");
                }
            });

            s.spawn(move || {
                let client_transport = TCPTransport::new(
                    Some((IpAddress::v4(127, 0, 0, 1), 10110)),
                    10111,
                    client_interface_wrapper,
                    1,
                )
                .expect("We should be able to initialize");

                let mut hdr = RPCHeader::default();
                let mut recv_buf1 = [0; 1];
                let mut recv_buf2 = [0; 1];
                for i in 0u8..10 {
                    hdr.msg_len = 5;
                    client_transport
                        .send_msg(&hdr, 0, &[&[0 * i, 1 * i, 2 * i, 3 * i, 4 * i]])
                        .expect("Failed to send message");
                    client_transport
                        .recv_msg(&mut hdr, 0, &mut [&mut recv_buf1, &mut recv_buf2])
                        .expect("Failed to recv message");
                    assert_eq!(recv_buf1[0], i);
                    assert_eq!(recv_buf2[0], i + 1);
                }
            });
        });
    }

    #[test]
    fn test_send_and_recv() {
        setup_test_logging();
        log::warn!("Starting test: test_send_and_recv");

        let iface = get_loopback_interface();

        let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));
        let server_interface_wrapper = interface_wrapper.clone();
        let client_interface_wrapper = interface_wrapper.clone();
        thread::scope(|s| {
            s.spawn(move || {
                let server_transport = TCPTransport::new(None, 10110, server_interface_wrapper, 1)
                    .expect("We should be able to initialize");
                let mut hdr = RPCHeader::default();
                let mut recv_buf = [0; 10];
                for i in 0u8..10 {
                    server_transport
                        .recv_msg(&mut hdr, 0, &mut [&mut recv_buf])
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
                        .send_msg(&hdr, 0, &[&[i], &[i + 1]])
                        .expect("Failed to send message");
                }
            });

            s.spawn(move || {
                let client_transport = TCPTransport::new(
                    Some((IpAddress::v4(127, 0, 0, 1), 10110)),
                    10111,
                    client_interface_wrapper,
                    1,
                )
                .expect("We should be able to initialize");

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
        });
    }

    #[test]
    fn test_multi_client_server() {
        setup_test_logging();
        log::warn!("Starting test: test_multi_client_server");

        let iface = get_loopback_interface();
        let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));

        let server_iface_wrapper = interface_wrapper.clone();
        let server2_iface_wrapper = interface_wrapper.clone();
        let client_iface_wrapper = interface_wrapper.clone();
        let client2_iface_wrapper = interface_wrapper.clone();

        thread::scope(|s| {
            s.spawn(move || {
                let server_transport = TCPTransport::new(None, 10111, server_iface_wrapper, 1)
                    .expect("We should be able to initialize");

                let mut hdr = RPCHeader::default();
                let mut recv_buf = [0; 10];
                for i in 0u8..10 {
                    server_transport
                        .recv_msg(&mut hdr, 0, &mut [&mut recv_buf])
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
                        .send_msg(&hdr, 0, &[&[i], &[i + 1]])
                        .expect("Failed to send message");
                }
            });

            s.spawn(move || {
                let server2_transport = TCPTransport::new(None, 10113, server2_iface_wrapper, 1)
                    .expect(
                    "We should be able to initialize a second transport with the same interface",
                );

                let mut hdr = RPCHeader::default();
                let mut recv_buf = [0; 10];
                for i in 0u8..10 {
                    server2_transport
                        .recv_msg(&mut hdr, 0, &mut [&mut recv_buf])
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
                    server2_transport
                        .send_msg(&hdr, 0, &[&[i + 1], &[i + 2]])
                        .expect("Failed to send message");
                }
            });

            s.spawn(move || {
                let client_transport = TCPTransport::new(
                    Some((IpAddress::v4(127, 0, 0, 1), 10111)),
                    10110,
                    client_iface_wrapper,
                    1,
                )
                .expect("We should be able to initialize");

                let mut hdr = RPCHeader::default();
                let mut recv_buf1 = [0; 1];
                let mut recv_buf2 = [0; 1];
                for i in 0u8..10 {
                    hdr.msg_len = 5;
                    client_transport
                        .send_msg(&hdr, 0, &[&[0 * i, 1 * i, 2 * i, 3 * i, 4 * i]])
                        .expect("Failed to send message");
                    client_transport
                        .recv_msg(&mut hdr, 0, &mut [&mut recv_buf1, &mut recv_buf2])
                        .expect("Failed to recv message");
                    assert_eq!(recv_buf1[0], i);
                    assert_eq!(recv_buf2[0], i + 1);
                }
            });

            s.spawn(move || {
                let client2_transport = TCPTransport::new(
                    Some((IpAddress::v4(127, 0, 0, 1), 10113)),
                    10112,
                    client2_iface_wrapper,
                    1,
                )
                .expect("We should be able to initialize");

                let mut hdr = RPCHeader::default();
                let mut recv_buf1 = [0; 1];
                let mut recv_buf2 = [0; 1];
                // Send 2, then receive 2
                for i in 0u8..5 {
                    hdr.msg_len = 5;
                    client2_transport
                        .send_msg(&hdr, 0, &[&[1, 1, 1, 1, 1]])
                        .expect("Failed to send message");
                    client2_transport
                        .send_msg(&hdr, 0, &[&[1, 1, 1, 1, 1]])
                        .expect("Failed to send message");
                    client2_transport
                        .recv_msg(&mut hdr, 0, &mut [&mut recv_buf1, &mut recv_buf2])
                        .expect("Failed to recv message");
                    assert_eq!(recv_buf1[0], (i * 2) + 1);
                    assert_eq!(recv_buf2[0], (i * 2) + 2);
                    client2_transport
                        .recv_msg(&mut hdr, 0, &mut [&mut recv_buf1, &mut recv_buf2])
                        .expect("Failed to recv message");
                    assert_eq!(recv_buf1[0], (i * 2 + 1) + 1);
                    assert_eq!(recv_buf2[0], (i * 2 + 1) + 2);
                }
            });
        });
    }

    #[test]
    fn test_multi_client_server_channel() {
        setup_test_logging();
        log::warn!("Starting test: test_multi_client_server_channel");

        let iface = get_loopback_interface();
        let interface_wrapper = Arc::new(InterfaceWrapper::new(iface));

        let server_iface_wrapper = interface_wrapper.clone();
        let server2_iface_wrapper = interface_wrapper.clone();
        let client_iface_wrapper = interface_wrapper.clone();
        let client2_iface_wrapper = interface_wrapper.clone();

        thread::scope(|s| {
            s.spawn(move || {
                let server_transport = TCPTransport::new(None, 10111, server_iface_wrapper, 1)
                    .expect("We should be able to initialize");

                let mut hdr1 = RPCHeader::default();
                let mut recv_buf = [0; 10];
                for i in 0u8..10 {
                    server_transport
                        .recv_msg(&mut hdr1, 0, &mut [&mut recv_buf])
                        .expect("Failed to send message");
                    let msg_len = hdr1.msg_len;
                    assert_eq!(msg_len, 5 as MsgLen);
                    for j in 0u8..5 {
                        assert_eq!(recv_buf[j as usize], j * i);
                    }
                    for j in 5..10 {
                        assert_eq!(recv_buf[j as usize], 0u8);
                    }

                    hdr1.msg_len = 2;
                    hdr1.msg_id = 0;
                    server_transport
                        .send_msg(&hdr1, 0, &[&[i], &[i + 1]])
                        .expect("Failed to send message");
                }
            });

            s.spawn(move || {
                let server2_transport = TCPTransport::new(None, 10113, server2_iface_wrapper, 10)
                    .expect(
                    "We should be able to initialize a second transport with the same interface",
                );
                let mut hdr2 = RPCHeader::default();
                let mut recv_buf = [0; 10];
                for i in 0u8..10 {
                    server2_transport
                        .recv_msg(&mut hdr2, i, &mut [&mut recv_buf])
                        .expect("Failed to send message");
                    let msg_len = hdr2.msg_len;
                    assert_eq!(msg_len, 5 as MsgLen);
                    for j in 0u8..5 {
                        assert_eq!(recv_buf[j as usize], 1u8);
                    }
                    for j in 5..10 {
                        assert_eq!(recv_buf[j as usize], 0u8);
                    }

                    hdr2.msg_len = 2;
                    hdr2.msg_id = i;
                    server2_transport
                        .send_msg(&hdr2, i, &[&[i + 1], &[i + 2]])
                        .expect("Failed to send message");
                }
            });

            s.spawn(move || {
                let client_transport = TCPTransport::new(
                    Some((IpAddress::v4(127, 0, 0, 1), 10111)),
                    10110,
                    client_iface_wrapper,
                    1,
                )
                .expect("We should be able to initialize");

                let mut hdr = RPCHeader::default();
                let mut recv_buf1 = [0; 1];
                let mut recv_buf2 = [0; 1];
                for i in 0u8..10 {
                    hdr.msg_len = 5;
                    client_transport
                        .send_msg(&hdr, 0, &[&[0 * i, 1 * i, 2 * i, 3 * i, 4 * i]])
                        .expect("Failed to send message");
                    client_transport
                        .recv_msg(&mut hdr, 0, &mut [&mut recv_buf1, &mut recv_buf2])
                        .expect("Failed to recv message");
                    assert_eq!(recv_buf1[0], i);
                    assert_eq!(recv_buf2[0], i + 1);
                }
            });

            s.spawn(move || {
                let client2_transport = TCPTransport::new(
                    Some((IpAddress::v4(127, 0, 0, 1), 10113)),
                    10112,
                    client2_iface_wrapper,
                    10,
                )
                .expect("We should be able to initialize");

                let mut hdr = RPCHeader::default();
                let mut recv_buf1 = [0; 1];
                let mut recv_buf2 = [0; 1];
                // Send 2, then receive 2
                for i in 0u8..5 {
                    hdr.msg_len = 5;
                    hdr.msg_id = 2 * i;
                    client2_transport
                        .send_msg(&hdr, 2 * i, &[&[1, 1, 1, 1, 1]])
                        .expect("Failed to send message");
                    hdr.msg_id = 2 * i + 1;
                    client2_transport
                        .send_msg(&hdr, 2 * i + 1, &[&[1, 1, 1, 1, 1]])
                        .expect("Failed to send message");
                    client2_transport
                        .recv_msg(&mut hdr, 2 * i, &mut [&mut recv_buf1, &mut recv_buf2])
                        .expect("Failed to recv message");
                    assert_eq!(recv_buf1[0], (i * 2) + 1);
                    assert_eq!(recv_buf2[0], (i * 2) + 2);
                    client2_transport
                        .recv_msg(&mut hdr, 2 * i + 1, &mut [&mut recv_buf1, &mut recv_buf2])
                        .expect("Failed to recv message");
                    assert_eq!(recv_buf1[0], (i * 2 + 1) + 1);
                    assert_eq!(recv_buf2[0], (i * 2 + 1) + 2);
                }
            });
        });
    }
}
