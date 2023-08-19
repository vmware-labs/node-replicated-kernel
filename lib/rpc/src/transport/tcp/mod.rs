pub mod interface_wrapper;
pub mod transport;

#[cfg(test)]
mod test {
    use alloc::collections::BTreeMap;

    use smoltcp::iface::{Interface, InterfaceBuilder, NeighborCache};
    use smoltcp::phy::{Loopback, Medium};
    use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr};

    pub(crate) fn get_loopback_interface() -> Interface<'static, Loopback> {
        // from smoltcp loopback example
        let device = Loopback::new(Medium::Ethernet);
        let neighbor_cache = NeighborCache::new(BTreeMap::new());
        let ip_addrs = [IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8)];
        let sock_vec = Vec::with_capacity(8);
        let iface = InterfaceBuilder::new(device, sock_vec)
            .hardware_addr(EthernetAddress::default().into())
            .neighbor_cache(neighbor_cache)
            .ip_addrs(ip_addrs)
            .finalize();
        iface
    }
}
