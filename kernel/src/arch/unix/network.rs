use smoltcp::iface::Interface;
use vmxnet3::smoltcp::DevQueuePhy;

pub fn init_network<'a>() -> Interface<'a, DevQueuePhy> {
    unimplemented!("init_network not implemented for unix");
}
