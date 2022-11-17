// Copyright © 2022 University of Colorado. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use kpi::system::{GlobalThreadId, NodeId, PackageId};
use rpc::rpc::ClientId;

use crate::arch::rackscale::client::get_num_clients;

pub mod get_hardware_threads;

// Helper functions for CpuThread GlobalThreadId
pub(crate) fn local_to_gtid(gtid: GlobalThreadId, client_id: ClientId) -> GlobalThreadId {
    get_num_clients() as GlobalThreadId * gtid + client_id as GlobalThreadId
}

pub(crate) fn gtid_to_local(gtid: GlobalThreadId, client_id: ClientId) -> GlobalThreadId {
    (gtid - client_id as GlobalThreadId) / get_num_clients() as GlobalThreadId
}

pub(crate) fn is_gtid_local(gtid: GlobalThreadId, client_id: ClientId) -> bool {
    gtid % get_num_clients() as GlobalThreadId == client_id as GlobalThreadId
}

// Helper functions for CpuThread NodeId
pub(crate) fn local_to_node_id(node_id: NodeId, client_id: ClientId) -> NodeId {
    get_num_clients() as NodeId * node_id + client_id as NodeId
}

pub(crate) fn node_id_to_local(node_id: NodeId, client_id: ClientId) -> NodeId {
    (node_id - client_id as NodeId) / get_num_clients() as NodeId
}

pub(crate) fn is_node_id_local(node_id: NodeId, client_id: ClientId) -> bool {
    node_id % get_num_clients() as NodeId == client_id as NodeId
}

// Helper functions for CpuThread PackageId
pub(crate) fn local_to_package_id(package_id: PackageId, client_id: ClientId) -> PackageId {
    get_num_clients() as PackageId * package_id + client_id as PackageId
}

pub(crate) fn package_id_to_local(package_id: PackageId, client_id: ClientId) -> PackageId {
    (package_id - client_id as PackageId) / get_num_clients() as PackageId
}

pub(crate) fn is_package_id_local(package_id: PackageId, client_id: ClientId) -> bool {
    package_id % get_num_clients() as PackageId == client_id as PackageId
}
