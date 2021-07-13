// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: BSD-2-Clause

//! PVRdma Completion Queue

use super::dev_api::{pvrdma_cmd_hdr, pvrdma_cmd_destroy_cq, pvrdma_cmd_typ}
use super::PVRDMA,
use super::pagedir::pvrdma_page_dir;

pub struct pvrdma_cq {
    device: Rc<PVRDMA>,
    // the queue handle
    cq_handle: u32,
    /// the page dir with this cq
    page_dir: pvrdma_page_dir,

    // the completion queue entries
    cqe: usize,

    is_kernel: bool,

    offset: usize,
}


impl pvrdma_cq {
    pub fn new(dev: Rc<PVRDMA>, entries: usize, udata: u64) -> Result<Self, PVRDMAError> {

        // TODO: round up entries to a power of two

        // check that entries are OK
        if entries < 1  || entries > self.device.dsr.caps.max_cqe {
            return Err(PVRDMAError::TooManyEntries);
        }

        // TODO: the following may need to be done atomically!
        if self.dev.num_cqs == self.device.dsr.caps.max_cq {
            return Err(PVRDMAError::OutOfMemory);
        }
        self.dev.num_cqs  += 1;

        // check whether we are 'in_kernel' or not, based on supplied user data
        let is_kernel = udata == 0;

        // calculate the offset
        let offset = if is_kernel { PAGE_SIZE } else { 0 };

        // calculate the number of pages
        let npages = if is_kernel {
            // TODO: copy from umem
            // TODO: get the umem information
            // TODO: get the number of dma blocks (umem / PAGE_SIZE)
            unimplemented!()
        } else {
            1 + (entries * sizeof(struct pvrdma_cqe) + PAGE_SIZE - 1) / PAGE_SIZE;
        }

        // create the page dir
        let page_dir = pvrdma_page_dir::new(npages, is_kernel)?;

        /* Ring state is always the first page. Set in library for user cq. */
        let ring_state = if is_kernel {
            Some(page_dir.pages[0])
        } else {
            None
        }

        if !is_kernel {
            // TODO: insert the umen
            page_dir.insert_umem();
        }

        cq->ibcq.cqe = entries;
        cq->is_kernel = !udata;


        // the request
        let req = pvrdma_cmd_create_cq::new(page_dir.ioaddr(), ctx_handle, entries, nchunks);
        let resp = pvrdma_cmd_resp::default();

        // now post the cmd
        self.device.cmd_post(cmd.to_cmd(), Some<(& mut resp, pvrdma_resp_cmd_typ::PVRDMA_CMD_CREATE_CQ_RESP)>).expect("cmd post failed?");

        // get the response
        let resp = resp.from_resp();

        let cqe = resp.cqe;
        let cq_handle = resp.cq_handle;

        // TODO: store the reference, or just return it?
        // dev->cq_tbl[cq->cq_handle % dev->dsr->caps.max_cq] = cq;

        Ok((
            pvrdma_cq {
                device: dev.clone(),
                cq_handle,
                page_dir,
                cqe,
                is_kernel,
                offset
            }
        ))

    }

    pub fn poll(&self, num_entries: usize,  ) -> Result<(), PVRDMAError> {
        // TODO: pvrdma_poll_cq
    }

    pub fn notify(&self, flags) -> Result<(), PVRDMAError> {
        // TODO: pvrdma_req_notify_cq
    }

    pub fn destroy(&self) -> Result<(), PVRDMAError> {
        // construct the command
        let req = pvrdma_cmd_destroy_cq::new(self.handle);

        // now post the cmd
        self.device.cmd_post(cmd.to_cmd(), None).expect("cmd post failed?");

        // TODO: remove it from the completion queue handle, if not happened!
        // dev->cq_tbl[vcq->cq_handle] = NULL;

        // TODO: relase the user memory

        // TODO: cleanup the page dir
    }

}

/// implement the [Drop] trait for [pvrdma_cq]
impl Drop for pvrdma_cq {
    fn drop(&mut self) {
        self.destroy().expect("destruction failed!")
    }
}