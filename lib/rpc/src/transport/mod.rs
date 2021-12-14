#[cfg(not(any(
    feature = "smoltcp_transport",
    feature = "mpsc_transport",
)))]
compile_error!("You must enable at least one of the following features: smoltcp_transport, mpsc_transport");

#[cfg(feature = "smoltcp_transport")]
pub mod smoltcp;

#[cfg(feature = "mpsc_transport")]
pub mod mpsc;