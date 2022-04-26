#[cfg(not(any(feature = "smoltcp_transport", feature = "mpsc_transport")))]
compile_error!(
    "You must enable at exactly one of the following features: smoltcp_transport, mpsc_transport"
);

/* Doing pairwise checks for duplicate transports is going to get ugly as you add more transports,
 * but I'm not sure if there's a better alternative.
 */
#[cfg(all(feature = "smoltcp_transport", feature = "mpsc_transport"))]
compile_error!(
    "You must enable at exactly one of the following features: smoltcp_transport, mpsc_transport"
);

#[cfg(feature = "smoltcp_transport")]
mod smoltcp;

#[cfg(feature = "mpsc_transport")]
mod mpsc;

mod api;

#[cfg(feature = "shmem_transport")]
mod shmem;

#[cfg(feature = "shmem_transport")]
pub use shmem::transport::ShmemTransport;

pub use api::Transport;

#[cfg(feature = "smoltcp_transport")]
pub use self::smoltcp::TCPTransport;

#[cfg(feature = "mpsc_transport")]
pub use mpsc::MPSCTransport;
