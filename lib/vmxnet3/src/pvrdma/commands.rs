// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

///! PVRDMA Commands


use super::PVRDMAError;
use super::dev_api::{PVRDMA_REG_ERR, PVRDMA_REG_REQUEST};
use crate::pci::BarIO;
use super::pci::BarAccess;
use x86::current::paging::IOAddr;

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct SharedReceiveQueueAttr {}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct QueuePairAttr {}

#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct PortAttr {}

/// Represents the PVRDMA comand types / numbers
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum CommandNumber {
    // General queries
    /// Query port command number
    QueryPort = 0,
    /// Query protection key command number
    QueryPkey = 1,

    // page directory management
    /// Create page directory command number
    CreatePageDirectory = 2,
    /// destroy page directory command number
    DestroyPageDirectory = 3,

    // memory region management
    /// Create a memory region command number
    CreateMemoryRegion = 4,
    /// Destory a memory region command number
    DestroyMemoryRegion = 5,

    // completion queue management
    /// Create completion queue command number
    CreateCompletionQueue = 6,
    /// Resize completion queue command number
    ResizeCompletionQueue = 7,
    /// Destroy completion queue command number
    DestroyCompletionQueue = 8,

    // queue pair management
    /// Create queue pair command number
    CreateQueuePair = 9,
    /// Modify queue pair command number
    ModifyQueuePair = 10,
    /// Query queue pair command number
    QueryQueuePair = 11,
    /// Destroy queue pair command number
    DestroyQueuePair = 12,

    // UC (?) management, todo: figure out what this is
    CreateUC = 13,
    DestroyUC = 14,

    // bind management
    /// Create bind command number
    CreateBind = 15,
    /// destroy bind command number
    DestroyBind = 16,

    // shared receive queue management
    /// Create shared receive queue command number
    CreateSharedReceiveQueue = 17,
    /// modify shared receive queue command number
    ModifySharedReceiveQueue = 18,
    /// Query shared receive queue command number
    QuerySharedReceiveQueue = 19,
    /// Destroy shared receive queue command number
    DestroySharedReceiveQueue = 20,
    ///
    Last = 21,
}

/// the first command
const PVRDMA_COMMAND_FIRST: u32 = 0;
/// the maximum comamnd
const PVRDMA_COMMAND_MAX: u32 = 21;

/// Represents the PVRDMA response types / numbers
#[repr(u32)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ResponseNumber {
    // General queries
    /// Query port response number
    QueryPort = PVRDMA_RESPONSE_FIRST + 0,
    /// Query protection key response number
    QueryPkey = PVRDMA_RESPONSE_FIRST + 1,

    // page directory management
    /// Create page directory response number
    CreatePageDirectory = PVRDMA_RESPONSE_FIRST + 2,
    /// destroy page directory response number
    DestroyPageDirectory = PVRDMA_RESPONSE_FIRST + 3,

    // memory Region management
    /// Create a memory region response number
    CreateMemoryRegion = PVRDMA_RESPONSE_FIRST + 4,
    /// Destory a memory region response number
    DestroyMemoryRegion = PVRDMA_RESPONSE_FIRST + 5,

    // completion queue management
    /// Create completion queue response number
    CreateCompletionQueue = PVRDMA_RESPONSE_FIRST + 6,
    /// Resize completion queue response number
    ResizeCompletionQueue = PVRDMA_RESPONSE_FIRST + 7,
    /// Destroy completion queue response number
    DestroyCompletionQueue = PVRDMA_RESPONSE_FIRST + 8,

    // queue pair management
    /// Create queue pair response number
    CreateQueuePair = PVRDMA_RESPONSE_FIRST + 9,
    /// Modify queue pair response number
    ModifyQueuePair = PVRDMA_RESPONSE_FIRST + 10,
    /// Query queue pair response number
    QueryQueuePair = PVRDMA_RESPONSE_FIRST + 11,
    /// Destroy queue pair response number
    DestroyQueuePair = PVRDMA_RESPONSE_FIRST + 12,

    // UC (?) management, todo: figure out what this is
    CreateUC = PVRDMA_RESPONSE_FIRST + 13,
    DestroyUC = PVRDMA_RESPONSE_FIRST + 14,

    // bind management
    /// Create bind response number
    CreateBind = PVRDMA_RESPONSE_FIRST + 15,
    /// destroy bind response number
    DestroyBind = PVRDMA_RESPONSE_FIRST + 16,

    // shared receive queue management
    /// Create shared receive queue response number
    CreateSharedReceiveQueue = PVRDMA_RESPONSE_FIRST + 17,
    /// modify shared receive queue response number
    ModifySharedReceiveQueue = PVRDMA_RESPONSE_FIRST + 18,
    /// Query shared receive queue response number
    QuerySharedReceiveQueue = PVRDMA_RESPONSE_FIRST + 19,
    /// Destroy shared receive queue response number
    DestroySharedReceiveQueue = PVRDMA_RESPONSE_FIRST + 20,
    /// the last command
    Last = PVRDMA_RESPONSE_FIRST + 21,
}

/// the first response number
const PVRDMA_RESPONSE_FIRST: u32 = 1u32 << 31;

/// the last response number
const PVRDMA_RESPONSE_LAST: u32 = PVRDMA_RESPONSE_FIRST + 21;

/// Represents the PVRDMA response error numbers
#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ResponseError {
    Success,
    DefaultError,
}

/// Represents the PVRDMA command header layout
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct CommandHeader {
    /// a handle that will be returned in the response
    pub handle: u64,
    /// the command type
    pub command: CommandNumber,
    /// reserved field
    _reserved: u32,
}

/// implementation for [CommandHeader]
impl CommandHeader {
    /// initializes a new PVRDMA header struct
    pub fn new(command: CommandNumber) -> CommandHeader {
        CommandHeader {
            command,
            handle: 0,
            _reserved: 0,
        }
    }
}

/// implementation of [std::Default] for CommandHeader
impl Default for CommandHeader {
    fn default() -> Self {
        CommandHeader {
            handle: 0, command: CommandNumber::Last, _reserved: 0
        }
    }
}

/// Represents the PVRDMA response header layout
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct ResponseHeader {
    /// the handle set in the command header
    pub handle: u64,
    /// the response type
    pub response: ResponseNumber,
    /// error indicator
    pub err: ResponseError,
    /// reserved fields
    _reserved: [u8; 3usize],
}

/// the implementation for [ResponseHeader]
impl ResponseHeader {
    /// returns true if the response indicates a failure
    pub fn is_err(&self) -> bool {
        // TODO: Fix me!
        self.err != ResponseError::Success
    }
    /// returns true if the response indicates a success
    pub fn is_ok(&self) -> bool {
        !self.is_err()
    }
}

/// implementation of [std::Default] for CommandHeader
impl Default for ResponseHeader {
    fn default() -> Self {
        ResponseHeader {
            handle: 0, response: ResponseNumber::Last, err: ResponseError::Success, _reserved: [0; 3]
        }
    }
}


// Port Query Command / Response

/// Represents the query port command message layout
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct QueryPortCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// the port number to query
    pub port_num: u8,
    /// reserved fields
    _reserved: [u8; 7usize],
}

/// Represents the query port response message layout
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
struct QueryPortResponse {
    /// the response header
    pub hdr: ResponseHeader,
    /// the port attributes
    pub attrs: PortAttr,
}

// Protection Key Command / Response

/// Represents the query protection key command message layout
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct QueryPkeyCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// the port number to query
    pub port_num: u8,
    /// the protection key index
    pub index: u8,
    /// reserved fields
    _reserved: [u8; 6usize],
}

/// Represents the query protection key response message layout
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct QueryPkeyResponse {
    /// the response header
    pub hdr: ResponseHeader,
    /// the returned protection key
    pub pkey: u16,
    /// reserved fields
    _reserved: [u8; 6usize],
}

// Page directory management

/// Represents the create page directory command message layout
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreatePageDirectoryCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// the context handle
    pub ctx_handle: u32,
    /// reserved fields
    _reserved: [u8; 4usize],
}

/// Represents the create page directory response message layout
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreatePageDirectoryResponse {
    /// the response header
    pub hdr: ResponseHeader,
    /// the page directory handle
    pub pd_handle: u32,
    /// reserved fields
    _reserved: [u8; 4usize],
}

/// Represents the destroy page directory command message layout
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct DestroyPageDirectoryCommand {
    pub hdr: CommandHeader,
    /// the handle to be destroyed
    pub pd_handle: u32,
    /// reserved fields
    _reserved: [u8; 4usize],
}

// there is no destroy response message

// memory region management

/// represents the create memory region command layout
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreateMemoryRegionCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// start address of the memory region
    pub start: u64,
    /// length of th ememory region
    pub length: u64,
    /// IO address of the page directory
    pub pd_ioaddr: u64,
    /// the page directory handle
    pub pd_handle: u32,
    /// access flags of the memory region
    pub access_flags: u32,
    /// misc flags
    pub flags: u32,
    /// the number of chunks
    pub nchunks: u32,
}

/// represents the create memory region response layout
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreateMemoryRegionResponse {
    /// the response header
    pub hdr: ResponseHeader,
    /// the handle of the created memory region
    pub mr_handle: u32,
    /// the lkey for the memory region
    pub lkey: u32,
    /// the rkey for the memory region
    pub rkey: u32,
    /// reserved fields
    _reserved: [u8; 4usize],
}

/// represents the destroy memory region command layout
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct DestroyMemoryRegionCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// the memory region to be destroyed
    pub mr_handle: u32,
    /// reserved fields
    _reserved: [u8; 4usize],
}

// there is no destroy response message

// completion queue management

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreateCompletionQueueCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// the ioaddress of the associated page directory
    pub pdir_ioaddr: u64,
    /// the context handle
    pub ctx_handle: u32,
    /// number of requested entries
    pub cqe: u32,
    /// the number of chunks
    pub nchunks: u32,
    /// reserved
    _reserved: [u8; 4usize],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreateCompletionQueueResponse {
    /// response header
    pub hdr: ResponseHeader,
    /// the completion queue handle
    pub cq_handle: u32,
    /// the number of completion queue entries
    pub cqe: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct ResizeCompletionQueueCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// the completion queue handle to modify
    pub cq_handle: u32,
    /// the requested number of completion queue entries
    pub cqe: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct ResizeCompletionQueueResponse {
    /// the response header
    pub hdr: ResponseHeader,
    /// the new number of completion queue entries
    pub cqe: u32,
    /// reserved fields
    _reserved: [u8; 4usize],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct DestroyCompletionQueueCommand {
    // the command header
    pub hdr: CommandHeader,
    /// the completion queue handle to be destroyed
    pub cq_handle: u32,
    /// reserved fields
    _reserved: [u8; 4usize],
}

// there is no destroy response message

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreateQueuePairCommand {
    pub hdr: CommandHeader,
    pub pdir_dma: u64,
    pub pd_handle: u32,
    pub send_cq_handle: u32,
    pub recv_cq_handle: u32,
    pub srq_handle: u32,
    pub max_send_wr: u32,
    pub max_recv_wr: u32,
    pub max_send_sge: u32,
    pub max_recv_sge: u32,
    pub max_inline_data: u32,
    pub lkey: u32,
    pub access_flags: u32,
    pub total_chunks: u16,
    pub send_chunks: u16,
    pub max_atomic_arg: u16,
    pub sq_sig_all: u8,
    pub qp_type: u8,
    pub is_srq: u8,
    pub reserved: [u8; 3usize],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreateQueuePairResponse {
    pub hdr: ResponseHeader,
    pub qpn: u32,
    pub max_send_wr: u32,
    pub max_recv_wr: u32,
    pub max_send_sge: u32,
    pub max_recv_sge: u32,
    pub max_inline_data: u32,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreateQueuePairResponseV2 {
    pub hdr: ResponseHeader,
    pub qpn: u32,
    pub qp_handle: u32,
    pub max_send_wr: u32,
    pub max_recv_wr: u32,
    pub max_send_sge: u32,
    pub max_recv_sge: u32,
    pub max_inline_data: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct ModifyQueuePairCommand {
    pub hdr: CommandHeader,
    pub qp_handle: u32,
    pub attr_mask: u32,
    pub attrs: QueuePairAttr,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct QueryQueuePairCommand {
    pub hdr: CommandHeader,
    pub qp_handle: u32,
    pub attr_mask: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct QueryQueuePairResponse {
    pub hdr: ResponseHeader,
    pub attrs: QueuePairAttr,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct DestroyQueuePairCommand {
    pub hdr: CommandHeader,
    pub qp_handle: u32,
    pub reserved: [u8; 4usize],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct DestroyQueuePairResponse {
    pub hdr: ResponseHeader,
    pub events_reported: u32,
    pub reserved: [u8; 4usize],
}

// UC management

#[repr(C)]
#[derive(Copy, Clone)]
struct CreateUCCommand {
    /// the command header
    pub hdr: CommandHeader,
    pub pfn: u64,
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreateUCResponse {
    pub hdr: ResponseHeader,
    pub ctx_handle: u32,
    pub reserved: [u8; 4usize],
}

#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct DestroyUCCommand {
    pub hdr: CommandHeader,
    pub ctx_handle: u32,
    pub reserved: [u8; 4usize],
}

// bind management commands

/// represents the create bind command layout
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreateBindCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// the mtu to be used
    pub mtu: u32,
    /// the vlan tag
    pub vlan: u32,
    /// the index for the bind
    pub index: u32,
    /// the new gid to set
    pub new_gid: [u8; 16usize],
    /// the gid type
    pub gid_type: u8,
    /// reserved fields
    _reserved: [u8; 3usize],
}

// no create bind response

/// represents the destroy bind command layout
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct DestroyBindCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// the hind index
    pub index: u32,
    /// the destination gid
    pub dest_gid: [u8; 16usize],
    /// resrved field
    _reserved: [u8; 4usize],
}

// no destory bind response

// shared receive queue management

/// represents the layout of the shared receive queue create command
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreateSharedReceiveQueueCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// the ioaddr of the associated page directory
    pub pdir_ioaddr: u64,
    /// the page directory handler
    pub pd_handle: u32,
    /// the number of chunks
    pub nchunks: u32,
    /// the shared receive queue attributes to set
    pub attrs: SharedReceiveQueueAttr,
    /// the shared receive queue type
    pub srq_type: u8,
    /// reserved fields
    _reserved: [u8; 7usize],
}

/// represents the layout of the shared receive queue create response
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct CreateSharedReceiveQueueResponse {
    /// the response header
    pub hdr: ResponseHeader,
    /// returns the shared receive queue number
    pub srqn: u32,
    /// resreved filed
    _reserved: [u8; 4usize],
}

/// represents the layout of the shared receive queue modify command
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct ModifySharedReceiveQueueCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// the shared receive queue handle
    pub srq_handle: u32,
    /// the attribute mask
    pub attr_mask: u32,
    /// the new shared receive queue attributes to set
    pub attrs: SharedReceiveQueueAttr,
}

/// represents the layout of the shared receive queue query command
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct QuerySharedReceiveQueueCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// the
    pub srq_handle: u32,
    pub reserved: [u8; 4usize],
}

/// represents the layout of the shared receive queue query response
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct QuerySharedReceiveQueueResponse {
    pub hdr: ResponseHeader,
    /// the current sahred receive queue attributes
    pub attrs: SharedReceiveQueueAttr,
}

/// represents the layout of the shared receive queue destroy command
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct DestroySharedReceiveQueueCommand {
    /// the command header
    pub hdr: CommandHeader,
    /// the shared receive queue handle to be destroyed
    pub srq_handle: u32,
    /// reserved fields
    _reserved: [u8; 4usize],
}

#[repr(C)]
#[derive(Copy, Clone)]
union Commands {
    pub query_port: QueryPortCommand,
    pub query_pkey: QueryPkeyCommand,
    pub create_uc: CreateUCCommand,
    pub destroy_uc: DestroyUCCommand,
    pub create_pd: CreatePageDirectoryCommand,
    pub destroy_pd: DestroyPageDirectoryCommand,
    pub create_mr: CreateMemoryRegionCommand,
    pub destroy_mr: DestroyMemoryRegionCommand,
    pub create_cq: CreateCompletionQueueCommand,
    pub resize_cq: ResizeCompletionQueueCommand,
    pub destroy_cq: DestroyCompletionQueueCommand,
    pub create_qp: CreateQueuePairCommand,
    pub modify_qp: ModifyQueuePairCommand,
    pub query_qp: QueryQueuePairCommand,
    pub destroy_qp: DestroyQueuePairCommand,
    pub create_bind: CreateBindCommand,
    pub destroy_bind: DestroyBindCommand,
    pub create_srq: CreateSharedReceiveQueueCommand,
    pub modify_srq: ModifySharedReceiveQueueCommand,
    pub query_srq: QuerySharedReceiveQueueCommand,
    pub destroy_srq: DestroySharedReceiveQueueCommand,
}

impl Default for Commands {
    fn default() -> Self {
        unsafe { ::core::mem::zeroed() }
    }
}

use core::mem::size_of;


#[repr(C)]
#[derive(Copy, Clone)]
union Responses {
    pub hdr: ResponseHeader,
    pub query_port: QueryPortResponse,
    pub query_pkey: QueryPkeyResponse,
    pub create_uc: CreateUCResponse,
    pub create_pd: CreatePageDirectoryResponse,
    pub create_mr: CreateMemoryRegionResponse,
    pub create_cq: CreateCompletionQueueResponse,
    pub resize_cq: CreateCompletionQueueResponse,
    pub create_qp: CreateQueuePairResponse,
    pub create_qp_v2: CreateQueuePairResponse,
    pub query_qp: QueryQueuePairResponse,
    pub destroy_qp: DestroyQueuePairResponse,
    pub create_srq: CreateSharedReceiveQueueResponse,
    pub query_srq: QuerySharedReceiveQueueResponse,
}
// pub enum Responses {
//     QueryPort(QueryPortResponse)
//     QueryPkey(QueryPkeyResponse),
//     CreateUc(CreateUCResponse),
//     CreatePd(CreatePageDirectoryResponse),
//     CreateMr(CreateMemoryRegionResponse),
//     CreateCq(CreateCompletionQueueResponse),
//     ResizeCq(CreateCompletionQueueResponse),
//     CreateQp(CreateQueuePairResponse),
//     CreateQp2(CreateQueuePairResponse),
//     QueryQp(QueryQueuePairResponse),
//     DestroyQp(DestroyQueuePairResponse),
//     CreateSrq(CreateSharedReceiveQueueResponse),
//     QuerySrq(QuerySharedReceiveQueueResponse),
// }

impl Responses {
    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                size_of::<Responses>(),
            )
        }
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe {
            core::slice::from_raw_parts_mut(
                self as *mut Self as *mut u8,
                size_of::<Responses>(),
            )
        }
    }
}


impl Default for Responses {
    fn default() -> Self {
        unsafe { ::core::mem::zeroed() }
    }
}


/// represents the commands
pub struct PvrdmaCommands {
    /// registered memory location with the device for commands
    cmd: Commands,
    /// registered memory location with the device for responses
    resp: Responses,
    /// the PCI address
    pci: BarAccess,
}

impl PvrdmaCommands {
    /// initialize the commands
    pub fn new(pci: BarAccess) -> Result<Self, PVRDMAError> {

        // //
        // p = ptr::NonNull::new(
        //     get_pointer_from_c() as *mut YourType
        // ).unwrap();
        // p.as_mut()

        // allocate the memory
        //let cmd_slot = DmaBuffer::<BASE_PAGE_SIZE>::new()?;
        //let resp_slot = DmaBuffer::<BASE_PAGE_SIZE>::new()?;

        // let layout = core::alloc::Layout::from_size_align(4096, 4096).unwrap();
        // let buf = unsafe { alloc::alloc::alloc(layout) };
        // if buf.is_null() {
        //     return Err(PVRDMAError::OutOfMemory);
        // }

        // let p = unsafe {core::ptr::NonNull::new(buf as *mut Commands).unwrap().as_mut()};

        Ok(PvrdmaCommands {
            cmd: Default::default(),  // *p
            resp: Default::default(),
            pci
        })
    }

    /// Query port command number
    pub fn query_port(&mut self, port_num: u8) -> Result<PortAttr, PVRDMAError> {
        // fill in the struct data
        self.cmd.query_port.hdr = CommandHeader::new(CommandNumber::QueryPort);
        self.cmd.query_port.port_num = port_num;
        // now execute the command
        self.cmd_post()?;
        // get the response
        let mut resp: Responses = Default::default();
        self.cmd_result(ResponseNumber::QueryPkey, &mut resp)?;
        unsafe {
            Ok(resp.query_port.attrs)
        }
    }

    pub fn query_pkey(&mut self, port_num: u8, index: u8) -> Result<u16, PVRDMAError> {
        self.cmd.query_pkey.hdr = CommandHeader::new(CommandNumber::QueryPkey);
        self.cmd.query_pkey.port_num = port_num;
        self.cmd.query_pkey.index = index;
        // now execute the command
        self.cmd_post()?;
        // get the response
        let mut resp: Responses = Default::default();
        self.cmd_result(ResponseNumber::QueryPkey, &mut resp)?;
        unsafe {
            Ok(resp.query_pkey.pkey)
        }
    }

    // page directory management

    /// Create page directory command number
    pub fn create_page_directory(&mut self, ctx_handle: u32) -> Result<u32, PVRDMAError> {
        self.cmd.create_pd.hdr = CommandHeader::new(CommandNumber::CreatePageDirectory);
        self.cmd.create_pd.ctx_handle = ctx_handle;
        // now execute the command
        self.cmd_post()?;
        // get the response
        let mut resp: Responses = Default::default();
        self.cmd_result(ResponseNumber::CreatePageDirectory, &mut resp)?;
        unsafe {
            Ok(resp.create_pd.pd_handle)
        }
    }

    /// destroy page directory command numbef
    pub fn destroy_page_directory(&mut self, pd_handle: u32) -> Result<(), PVRDMAError> {
        self.cmd.destroy_pd.hdr = CommandHeader::new(CommandNumber::DestroyPageDirectory);
        self.cmd.destroy_pd.pd_handle = pd_handle;
        // now execute the command
        self.cmd_post()
        // no result
    }

    // memory region management

    /// Create a memory region command number
    pub fn create_memory_region(
        &mut self,
        start: u64,
        length: u64,
        pdir_ioaddr: IOAddr,
        pd_handle: u32,
        access_flags: u32,
        flags: u32,
        nchunks: u32,
    ) -> Result<(u32, u32, u32), PVRDMAError> {
        self.cmd.create_mr.hdr = CommandHeader::new(CommandNumber::CreateMemoryRegion);
        self.cmd.create_mr.start = start;
        self.cmd.create_mr.length = length;
        self.cmd.create_mr.pd_ioaddr = pdir_ioaddr.as_u64();
        self.cmd.create_mr.pd_handle = pd_handle;
        self.cmd.create_mr.access_flags = access_flags;
        self.cmd.create_mr.flags = flags;
        self.cmd.create_mr.nchunks = nchunks;

        // now execute the command
        self.cmd_post()?;
        // get the response
        let mut resp: Responses = Default::default();
        self.cmd_result(ResponseNumber::CreateMemoryRegion, &mut resp)?;
        unsafe {
            Ok((resp.create_mr.mr_handle, resp.create_mr.lkey, resp.create_mr.rkey))
        }
    }

    /// Destory a memory region command number
    pub fn destory_memory_region(&mut self, mr_handle: u32) -> Result<(), PVRDMAError> {
        self.cmd.destroy_mr.hdr = CommandHeader::new(CommandNumber::DestroyMemoryRegion);
        self.cmd.destroy_mr.mr_handle = mr_handle;

        // now execute the command
        self.cmd_post()
        // no result
    }

    // completion queue management

    /// Create completion queue command number
    pub fn create_completion_queue(
        &mut self,
        pdir_ioaddr: IOAddr,
        ctx_handle: u32,
        cqe: u32,
        nchunks: u32,
    ) -> Result<(u32, u32), PVRDMAError> {
        self.cmd.create_cq.hdr = CommandHeader::new(CommandNumber::CreateCompletionQueue);
        self.cmd.create_cq.pdir_ioaddr = pdir_ioaddr.as_u64();
        self.cmd.create_cq.ctx_handle = ctx_handle;
        self.cmd.create_cq.cqe = cqe;
        self.cmd.create_cq.nchunks = nchunks;

        // now execute the command
        self.cmd_post()?;
        // get the response
        let mut resp: Responses = Default::default();
        self.cmd_result(ResponseNumber::CreateCompletionQueue, &mut resp)?;
        unsafe {
            Ok((resp.create_cq.cq_handle, resp.create_cq.cqe))
        }
    }

    /// Resize completion queue command number
    pub fn resize_completion_queue(&mut self, cq_handle: u32, cqe: u32) -> Result<u32, PVRDMAError> {
        self.cmd.resize_cq.hdr = CommandHeader::new(CommandNumber::ResizeCompletionQueue);
        self.cmd.resize_cq.cq_handle = cq_handle;
        self.cmd.resize_cq.cqe = cqe;

        // now execute the command
        self.cmd_post()?;
        // get the response
        let mut resp: Responses = Default::default();
        self.cmd_result(ResponseNumber::ResizeCompletionQueue, &mut resp)?;
        unsafe {
            Ok(resp.resize_cq.cqe)
        }
    }

    /// Destroy completion queue command number
    pub fn destroy_completion_queue(&mut self, cq_handle: u32) -> Result<(), PVRDMAError> {
        self.cmd.destroy_cq.hdr = CommandHeader::new(CommandNumber::DestroyCompletionQueue);
        self.cmd.destroy_cq.cq_handle = cq_handle;

        // now execute the command
        self.cmd_post()
        // no result
    }

    // queue pair management

    /// Create queue pair command number
    pub fn create_queue_pair(&mut self) -> Result<(), PVRDMAError> {
        unimplemented!();
    }

    /// Modify queue pair command number
    pub fn modify_queue_pair(
        &mut self,
        qp_handle: u32,
        attr_mask: u32,
        attrs: QueuePairAttr,
    ) -> Result<(), PVRDMAError> {
        self.cmd.modify_qp.hdr = CommandHeader::new(CommandNumber::ModifyQueuePair);
        self.cmd.modify_qp.qp_handle = qp_handle;
        self.cmd.modify_qp.attr_mask = attr_mask;
        self.cmd.modify_qp.attrs = attrs;

        // now execute the command
        self.cmd_post()
        // no result
    }

    /// Query queue pair command number
    pub fn query_queue_pair(
        &mut self,
        qp_handle: u32,
        attr_mask: u32,
    ) -> Result<QueuePairAttr, PVRDMAError> {
        self.cmd.query_qp.hdr = CommandHeader::new(CommandNumber::QueryQueuePair);
        self.cmd.query_qp.qp_handle = qp_handle;
        self.cmd.query_qp.attr_mask = attr_mask;

        // now execute the command
        self.cmd_post()?;
        // get the response
        let mut resp: Responses = Default::default();
        self.cmd_result(ResponseNumber::CreateCompletionQueue, &mut resp)?;
        unsafe {
            Ok(resp.query_qp.attrs)
        }
    }

    /// Destroy queue pair command number
    pub fn destrory_queue_pair(&mut self, qp_handle: u32) -> Result<u32, PVRDMAError> {
        self.cmd.destroy_qp.hdr = CommandHeader::new(CommandNumber::DestroyQueuePair);
        self.cmd.destroy_qp.qp_handle = qp_handle;

        // now execute the command
        self.cmd_post()?;
        // get the resuult
        let mut resp: Responses = Default::default();
        self.cmd_result(ResponseNumber::DestroyQueuePair, &mut resp)?;
        unsafe {
            Ok(resp.destroy_qp.events_reported)
        }
    }

    // UC (?) management, todo: figure out what this is
    pub fn create_uc(&mut self, pfn: u64) -> Result<u32, PVRDMAError> {
        self.cmd.create_uc.hdr = CommandHeader::new(CommandNumber::CreateUC);
        self.cmd.create_uc.pfn = pfn;

        // now execute the command
        self.cmd_post()?;
        // get the response
        let mut resp: Responses = Default::default();
        self.cmd_result(ResponseNumber::CreateUC, &mut resp)?;
        unsafe {
            Ok(resp.create_uc.ctx_handle)
        }
    }

    pub fn destroy_uc(&mut self, ctx_handle: u32) -> Result<(), PVRDMAError> {
        self.cmd.destroy_uc.hdr = CommandHeader::new(CommandNumber::DestroyUC);
        self.cmd.destroy_uc.ctx_handle = ctx_handle;

        // now execute the command
        self.cmd_post()
        // no result
    }

    // bind management

    /// Create bind command number
    pub fn create_bind(
        &mut self,
        mtu: u32,
        vlan: u32,
        index: u32,
        new_gid: [u8; 16usize],
        gid_type: u8,
    ) -> Result<(), PVRDMAError> {
        self.cmd.create_bind.hdr = CommandHeader::new(CommandNumber::CreateBind);
        self.cmd.create_bind.mtu = mtu;
        self.cmd.create_bind.vlan = vlan;
        self.cmd.create_bind.index = index;
        self.cmd.create_bind.new_gid = new_gid;
        self.cmd.create_bind.gid_type = gid_type;

        // now execute the command
        self.cmd_post()
        // no result
    }

    /// destroy bind command number
    pub fn destroy_bind(&mut self, index: u32, dest_gid: [u8; 16usize]) -> Result<(), PVRDMAError> {
        self.cmd.destroy_bind.hdr = CommandHeader::new(CommandNumber::DestroyBind);
        self.cmd.destroy_bind.index = index;
        self.cmd.destroy_bind.dest_gid = dest_gid;

        // now execute the command
        self.cmd_post()
        // no result
    }

    // shared receive queue management

    /// Create shared receive queue command number
    pub fn create_shared_receive_queue(
        &mut self,
        pdir_ioaddr: IOAddr,
        pd_handle: u32,
        nchunks: u32,
        attrs: SharedReceiveQueueAttr,
        srq_type: u8,
    ) -> Result<u32, PVRDMAError> {
        self.cmd.create_srq.hdr = CommandHeader::new(CommandNumber::CreateSharedReceiveQueue);
        self.cmd.create_srq.pdir_ioaddr = pdir_ioaddr.as_u64();
        self.cmd.create_srq.pd_handle = pd_handle;
        self.cmd.create_srq.nchunks = nchunks;
        self.cmd.create_srq.attrs = attrs;
        self.cmd.create_srq.srq_type = srq_type;

        // now execute the command
        self.cmd_post()?;
        // get the response
        let mut resp: Responses = Default::default();
        self.cmd_result(
            ResponseNumber::CreateSharedReceiveQueue,
            &mut resp,
        )?;
        unsafe {
            Ok(resp.create_srq.srqn)
        }
    }
    /// modify shared receive queue command number
    pub fn modify_shared_receive_queue(
        &mut self,
        srq_handle: u32,
        attr_mask: u32,
        attrs: SharedReceiveQueueAttr,
    ) -> Result<(), PVRDMAError> {
        self.cmd.modify_srq.hdr = CommandHeader::new(CommandNumber::CreateSharedReceiveQueue);
        self.cmd.modify_srq.srq_handle = srq_handle;
        self.cmd.modify_srq.attr_mask = attr_mask;
        self.cmd.modify_srq.attrs = attrs;

        // now execute the command
        self.cmd_post()
        // no result
    }

    /// Query shared receive queue command number
    pub fn query_shared_receive_queue(
        &mut self,
        srq_handle: u32,
    ) -> Result<SharedReceiveQueueAttr, PVRDMAError> {
        self.cmd.query_srq.hdr = CommandHeader::new(CommandNumber::CreateSharedReceiveQueue);
        self.cmd.query_srq.srq_handle = srq_handle;

        // now execute the command
        self.cmd_post()?;
        // get the response
        let mut resp: Responses = Default::default();
        self.cmd_result(ResponseNumber::QuerySharedReceiveQueue, &mut resp)?;
        unsafe {
            Ok(resp.query_srq.attrs)
        }
    }

    /// Destroy shared receive queue command number
    pub fn destroy_shared_receive_queue(&mut self, srq_handle: u32) -> Result<(), PVRDMAError> {
        self.cmd.destroy_srq.hdr = CommandHeader::new(CommandNumber::DestroySharedReceiveQueue);
        self.cmd.destroy_srq.srq_handle = srq_handle;

        // now execute the command
        self.cmd_post()
        // no result
    }

    /// executes the command
    fn cmd_post(&self) -> Result<(), PVRDMAError> {
        // the command is already written in the CMD slot.
        self.pci.write_bar1(PVRDMA_REG_REQUEST, 0);

        // TODO: issue a memory barrier

        // read the response
        match self.pci.read_bar1(PVRDMA_REG_ERR) {
            0 => Ok(()),
            _ => Err(PVRDMAError::CommandFault)
        }
    }

    fn cmd_result(&self, num: ResponseNumber, dst: &mut Responses) -> Result<(), PVRDMAError> {
        // copy from the response slot to the provided buffer
        *dst = self.resp;

        let ack = unsafe { self.resp.hdr.response };
        if ack == num {
            Ok(())
        } else {
            Err(PVRDMAError::CommandFaultResponse)
        }
    }
}
