use crate::arch::debug::shutdown;
use crate::ExitReason;

use rpc::rpc::RPCType;
use rpc::rpc_api::RPCServer;
use rpc::rpc_server::DefaultRPCServer;

use crate::arch::exokernel::*;
use crate::arch::network::init_network;

const PORT: u16 = 6970;

/// Test TCP RPC-based controller
#[cfg(target_arch = "x86_64")]
pub fn run() {
    let iface = init_network();
    let mut server = DefaultRPCServer::new(iface, PORT);

    // TODO: register handlers
    let (server, _) = server
        .register(FileIO::Close as RPCType, &CLOSE_HANDLER)
        .unwrap()
        .register(FileIO::Delete as RPCType, &DELETE_HANDLER)
        .unwrap()
        .register(FileIO::GetInfo as RPCType, &GETINFO_HANDLER)
        .unwrap()
        .register(FileIO::MkDir as RPCType, &MKDIR_HANDLER)
        .unwrap()
        .register(FileIO::Open as RPCType, &OPEN_HANDLER)
        .unwrap()
        .register(FileIO::FileRename as RPCType, &RENAME_HANDLER)
        .unwrap()
        .register(FileIO::Write as RPCType, &WRITE_HANDLER)
        .unwrap()
        .register(FileIO::WriteAt as RPCType, &WRITE_HANDLER)
        .unwrap()
        .register(FileIO::Read as RPCType, &READ_HANDLER)
        .unwrap()
        .register(FileIO::ReadAt as RPCType, &READ_HANDLER)
        .unwrap()
        .add_client(&CLIENT_REGISTRAR)
        .unwrap();
    server.run_server().unwrap();

    shutdown(ExitReason::Ok);
}
