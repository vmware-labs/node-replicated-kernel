// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![allow(warnings)]

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryInto;

use fallible_collections::{FallibleVec, FallibleVecGlobal};
use klogger::{sprint, sprintln};
use log::{debug, error, info, trace, warn};
use x86::bits64::paging::{PAddr, VAddr, BASE_PAGE_SIZE, LARGE_PAGE_SIZE};
use x86::bits64::rflags;
use x86::msr::{rdmsr, wrmsr, IA32_EFER, IA32_FMASK, IA32_LSTAR, IA32_STAR};

use kpi::process::FrameId;
use kpi::{
    FileOperation, MemType, ProcessOperation, SystemCall, SystemCallError, SystemOperation,
    VSpaceOperation,
};

use crate::error::KError;
use crate::fs::FileSystem;
use crate::kcb::ArchSpecificKcb;
use crate::memory::vspace::MapAction;
use crate::memory::{Frame, PhysicalPageProvider, KERNEL_BASE};
use crate::process::{userptr_to_str, Pid, ResumeHandle};
use crate::{cnrfs, nr, nrproc};

use super::gdt::GdtTable;
use super::process::{Ring3Process, UserValue};

extern "C" {
    #[no_mangle]
    fn syscall_enter();
}

fn handle_system(arg1: u64, arg2: u64, arg3: u64) -> Result<(u64, u64), KError> {
    let op = SystemOperation::from(arg1);

    match op {
        SystemOperation::GetHardwareThreads => {
            let vaddr_buf = arg2; // buf.as_mut_ptr() as u64
            let vaddr_buf_len = arg3; // buf.len() as u64

            let hwthreads = atopology::MACHINE_TOPOLOGY.threads();
            let num_threads = atopology::MACHINE_TOPOLOGY.num_threads();

            let mut return_threads = Vec::try_with_capacity(num_threads)?;
            for hwthread in hwthreads {
                return_threads.try_push(kpi::system::CpuThread {
                    id: hwthread.id as usize,
                    node_id: hwthread.node_id.unwrap_or(0) as usize,
                    package_id: hwthread.package_id as usize,
                    core_id: hwthread.core_id as usize,
                    thread_id: hwthread.thread_id as usize,
                })?;
            }

            // TODO(dependency): Get rid of serde/serde_cbor, use something sane instead
            let serialized = serde_cbor::to_vec(&return_threads).unwrap();
            if serialized.len() <= vaddr_buf_len as usize {
                let mut user_slice = super::process::UserSlice::new(vaddr_buf, serialized.len());
                user_slice.copy_from_slice(serialized.as_slice());
            }

            Ok((serialized.len() as u64, 0))
        }
        SystemOperation::Stats => {
            let kcb = super::kcb::get_kcb();
            info!("IRQ handler time: {} cycles", kcb.tlb_time);
            Ok((0, 0))
        }
        SystemOperation::GetCoreID => {
            let kcb = super::kcb::get_kcb();
            Ok((kcb.arch.id() as u64, 0))
        }
        SystemOperation::Unknown => Err(KError::InvalidSystemOperation { a: arg1 }),
    }
}

/// System call handler for printing
fn process_print(buf: UserValue<&str>) -> Result<(u64, u64), KError> {
    let mut kcb = super::kcb::get_kcb();
    let buffer: &str = *buf;

    // A poor mans line buffer scheme:
    match &mut kcb.print_buffer {
        Some(kbuf) => match buffer.find("\n") {
            Some(idx) => {
                let (low, high) = buffer.split_at(idx + 1);
                kbuf.push_str(low);
                {
                    let r = klogger::SERIAL_LINE_MUTEX.lock();
                    sprint!("{}", kbuf);
                }
                kbuf.clear();
                kbuf.push_str(high);
            }
            None => {
                kbuf.push_str(buffer);
                if kbuf.len() > 2048 {
                    // Don't let the buffer grow arbitrarily:
                    {
                        let r = klogger::SERIAL_LINE_MUTEX.lock();
                        sprint!("{}", kbuf);
                    }
                    kbuf.clear();
                }
            }
        },
        None => {
            let r = klogger::SERIAL_LINE_MUTEX.lock();
            sprint!("{}", buffer);
        }
    }

    Ok((0, 0))
}

/// System call handler for process exit
fn process_exit(code: u64) -> Result<(u64, u64), KError> {
    debug!("Process got exit, we are done for now...");
    // TODO: For now just a dummy version that exits Qemu
    if code != 0 {
        // When testing we want to indicate to our integration
        // test that our user-space test failed with a non-zero exit
        super::debug::shutdown(crate::ExitReason::UserSpaceError);
    } else {
        super::debug::shutdown(crate::ExitReason::Ok);
    }
}

fn handle_process(arg1: u64, arg2: u64, arg3: u64) -> Result<(u64, u64), KError> {
    let op = ProcessOperation::from(arg1);

    match op {
        ProcessOperation::Log => {
            let buffer: *const u8 = arg2 as *const u8;
            let len: usize = arg3 as usize;

            let user_str = unsafe {
                let slice = core::slice::from_raw_parts(buffer, len);
                core::str::from_utf8_unchecked(slice)
            };

            process_print(UserValue::new(user_str))
        }
        ProcessOperation::GetVCpuArea => unsafe {
            let kcb = super::kcb::get_kcb();

            let vcpu_vaddr = kcb.arch.current_executor()?.vcpu_addr().as_u64();

            Ok((vcpu_vaddr, 0))
        },
        ProcessOperation::AllocateVector => {
            // TODO: missing proper IRQ resource allocation...
            let vector = arg2;
            let core = arg3;
            super::irq::ioapic_establish_route(vector, core);
            Ok((vector, core))
        }
        ProcessOperation::Exit => {
            let exit_code = arg2;
            process_exit(exit_code)
        }
        ProcessOperation::GetProcessInfo => {
            let vaddr_buf = arg2; // buf.as_mut_ptr() as u64
            let vaddr_buf_len = arg3; // buf.len() as u64
            let kcb = super::kcb::get_kcb();

            let pid = kcb.current_pid()?;
            let mut pinfo = nrproc::NrProcess::<Ring3Process>::pinfo(pid)?;
            pinfo.cmdline = kcb.cmdline.init_args;
            pinfo.app_cmdline = kcb.cmdline.app_args;

            let serialized = serde_cbor::to_vec(&pinfo).unwrap();
            if serialized.len() <= vaddr_buf_len as usize {
                let mut user_slice = super::process::UserSlice::new(vaddr_buf, serialized.len());
                user_slice.copy_from_slice(serialized.as_slice());
            }

            Ok((serialized.len() as u64, 0))
        }
        ProcessOperation::RequestCore => {
            let gtid: usize = arg2.try_into().unwrap();
            let entry_point = arg3;
            let kcb = super::kcb::get_kcb();

            let mut affinity = None;
            for thread in atopology::MACHINE_TOPOLOGY.threads() {
                if thread.id == gtid {
                    affinity = Some(thread.node_id.unwrap_or(0));
                }
            }
            let affinity = affinity.ok_or(KError::InvalidGlobalThreadId)?;
            let pid = kcb.current_pid()?;

            let gtid = nr::KernelNode::allocate_core_to_process(
                pid,
                VAddr::from(entry_point),
                Some(affinity),
                Some(gtid),
            )?;

            Ok((arg2, 0))
        }
        ProcessOperation::AllocatePhysical => {
            let page_size: usize = arg2.try_into().unwrap_or(0);
            //let affinity: usize = arg3.try_into().unwrap_or(0);

            // Validate input
            if page_size != BASE_PAGE_SIZE && page_size != LARGE_PAGE_SIZE {
                return Err(KError::InvalidSyscallArgument1 { a: arg2 });
            }

            let kcb = super::kcb::get_kcb();

            // Figure out what memory to allocate
            let (bp, lp) = if page_size == BASE_PAGE_SIZE {
                (1, 0)
            } else {
                (0, 1)
            };
            crate::memory::KernelAllocator::try_refill_tcache(bp, lp, MemType::Mem)?;

            // Allocate the page (need to make sure we drop pamanager again
            // before we go to NR):
            let frame = {
                let mut pmanager = kcb.mem_manager();
                if page_size == BASE_PAGE_SIZE {
                    pmanager.allocate_base_page()?
                } else {
                    pmanager.allocate_large_page()?
                }
            };

            // Associate memory with the process
            let pid = kcb.current_pid()?;
            let fid = nrproc::NrProcess::<Ring3Process>::allocate_frame_to_process(pid, frame)?;

            Ok((fid as u64, frame.base.as_u64()))
        }
        ProcessOperation::SubscribeEvent => Err(KError::InvalidProcessOperation { a: arg1 }),
        ProcessOperation::Unknown => Err(KError::InvalidProcessOperation { a: arg1 }),
    }
}

/// System call handler for vspace operations
fn handle_vspace(arg1: u64, arg2: u64, arg3: u64) -> Result<(u64, u64), KError> {
    let op = VSpaceOperation::from(arg1);
    let base = VAddr::from(arg2);
    let region_size = arg3;
    trace!("handle_vspace {:?} {:#x} {:#x}", op, base, region_size);

    let kcb = super::kcb::get_kcb();
    let mut p = kcb.arch.current_executor()?;

    match op {
        VSpaceOperation::MapMem | VSpaceOperation::MapPMem => unsafe {
            let (bp, lp) = crate::memory::size_to_pages(region_size as usize);
            let mut frames = Vec::try_with_capacity(bp + lp)?;
            let mem_type = match op {
                VSpaceOperation::MapMem => MemType::Mem,
                VSpaceOperation::MapPMem => MemType::PMem,
                _ => unreachable!(), // We already checked before coming here.
            };
            crate::memory::KernelAllocator::try_refill_tcache(20 + bp, lp, mem_type)?;

            // TODO(apihell): This `paddr` is bogus, it will return the PAddr of the
            // first frame mapped but if you map multiple Frames, no chance getting that
            // Better would be a function to request physically consecutive DMA memory
            // or use IO-MMU translation (see also rumpuser_pci_dmalloc)
            // also better to just return what NR replies with...
            let mut paddr = None;
            let mut total_len = 0;
            {
                let mut pmanager = match mem_type {
                    MemType::Mem => kcb.mem_manager(),
                    MemType::PMem => kcb.pmem_manager(),
                    _ => unreachable!(),
                };

                for _i in 0..lp {
                    let mut frame = pmanager
                        .allocate_large_page()
                        .expect("We refilled so allocation should work.");
                    total_len += frame.size;
                    unsafe { frame.zero() };
                    frames
                        .try_push(frame)
                        .expect("Can't fail see `try_with_capacity`");
                    if paddr.is_none() {
                        paddr = Some(frame.base);
                    }
                }
                for _i in 0..bp {
                    let mut frame = pmanager
                        .allocate_base_page()
                        .expect("We refilled so allocation should work.");
                    total_len += frame.size;
                    unsafe { frame.zero() };
                    frames
                        .try_push(frame)
                        .expect("Can't fail see `try_with_capacity`");
                    if paddr.is_none() {
                        paddr = Some(frame.base);
                    }
                }
            }

            nrproc::NrProcess::<Ring3Process>::map_frames(
                p.pid,
                base,
                frames,
                MapAction::ReadWriteUser,
            )
            .expect("Can't map memory");

            Ok((paddr.unwrap().as_u64(), total_len as u64))
        },
        VSpaceOperation::MapDevice => unsafe {
            let paddr = PAddr::from(base.as_u64());
            let size = region_size as usize;

            let frame = Frame::new(paddr, size, kcb.node);

            nrproc::NrProcess::<Ring3Process>::map_device_frame(
                p.pid,
                frame,
                MapAction::ReadWriteUser,
            )
        },
        VSpaceOperation::MapMemFrame => unsafe {
            let base = VAddr::from(arg2);
            let frame_id: FrameId = arg3.try_into().map_err(|_e| KError::InvalidFrameId)?;

            let (paddr, size) = nrproc::NrProcess::<Ring3Process>::map_frame_id(
                p.pid,
                frame_id,
                base,
                MapAction::ReadWriteUser,
            )?;
            Ok((paddr.as_u64(), size as u64))
        },
        VSpaceOperation::UnmapMem | VSpaceOperation::UnmapPMem => {
            let handle = nrproc::NrProcess::<Ring3Process>::unmap(p.pid, base)?;
            let va: u64 = handle.vaddr.as_u64();
            let sz: u64 = handle.frame.size as u64;
            super::tlb::shootdown(handle);

            Ok((va, sz))
        }
        VSpaceOperation::Identify => unsafe {
            trace!("Identify base {:#x}.", base);
            nrproc::NrProcess::<Ring3Process>::resolve(p.pid, base)
        },
        VSpaceOperation::Unknown => {
            error!("Got an invalid VSpaceOperation code.");
            Err(KError::InvalidVSpaceOperation { a: arg1 })
        }
    }
}

/// System call handler for file operations
fn handle_fileio(
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> Result<(u64, u64), KError> {
    let op = FileOperation::from(arg1);

    let kcb = super::kcb::get_kcb();
    let pid = kcb.arch.current_pid()?;

    match op {
        FileOperation::Create => {
            unreachable!("Create is changed to Open with O_CREAT flag in vibrio")
        }
        FileOperation::Open => {
            let pathname = arg2;
            let flags = arg3;
            let modes = arg4;
            let _r = user_virt_addr_valid(pid, pathname, 0)?;

            #[cfg(feature = "exokernel")]
            {
                let filename = userptr_to_str(pathname)?;
                let mut client = kcb.arch.rpc_client.lock();
                return match client
                    .as_mut()
                    .unwrap()
                    .fio_open(pid, filename, flags, modes)
                {
                    Ok(a) => Ok(a),
                    Err(err) => Err(err.into()),
                };
            }

            #[cfg(not(feature = "exokernel"))]
            {
                return cnrfs::MlnrKernelNode::map_fd(pid, pathname, flags, modes);
            }
        }
        FileOperation::Read | FileOperation::Write => {
            let fd = arg2;
            let buffer = arg3;
            let len = arg4;
            let _r = user_virt_addr_valid(pid, buffer, len)?;

            #[cfg(feature = "exokernel")]
            {
                // TODO - chunk writes/reads
                let mut client = kcb.arch.rpc_client.lock();

                if op == FileOperation::Read {
                    let mut userslice = super::process::UserSlice::new(buffer, len as usize);
                    return match client
                        .as_mut()
                        .unwrap()
                        .fio_read(pid, fd, len, &mut userslice)
                    {
                        Ok(a) => Ok(a),
                        Err(err) => Err(err.into()),
                    };
                } else {
                    // write operation
                    let kernslice = crate::process::KernSlice::new(buffer, len as usize);
                    let buff_ptr = kernslice.buffer.clone();
                    return match client
                        .as_mut()
                        .unwrap()
                        .fio_write(pid, fd, buff_ptr.to_vec())
                    {
                        Ok(a) => Ok(a),
                        Err(err) => Err(err.into()),
                    };
                }
            }

            #[cfg(not(feature = "exokernel"))]
            {
                return cnrfs::MlnrKernelNode::file_io(op, pid, fd, buffer, len, -1);
            }
        }
        FileOperation::ReadAt | FileOperation::WriteAt => {
            let fd = arg2;
            let buffer = arg3;
            let len = arg4;
            let offset = arg5 as i64;
            let _r = user_virt_addr_valid(pid, buffer, len)?;

            #[cfg(feature = "exokernel")]
            {
                // TODO - chunk writes/reads
                let mut client = kcb.arch.rpc_client.lock();

                if op == FileOperation::ReadAt {
                    let mut userslice = super::process::UserSlice::new(buffer, len as usize);
                    return match client.as_mut().unwrap().fio_readat(
                        pid,
                        fd,
                        len,
                        offset,
                        &mut userslice,
                    ) {
                        Ok(a) => Ok(a),
                        Err(err) => Err(err.into()),
                    };
                } else {
                    // write_at operation
                    let kernslice = crate::process::KernSlice::new(buffer, len as usize);
                    let buff_ptr = kernslice.buffer.clone();
                    return match client.as_mut().unwrap().fio_writeat(
                        pid,
                        fd,
                        offset,
                        buff_ptr.to_vec(),
                    ) {
                        Ok(a) => Ok(a),
                        Err(err) => Err(err.into()),
                    };
                }
            }

            #[cfg(not(feature = "exokernel"))]
            {
                return cnrfs::MlnrKernelNode::file_io(op, pid, fd, buffer, len, offset);
            }
        }
        FileOperation::Close => {
            let fd = arg2;

            #[cfg(feature = "exokernel")]
            {
                let mut client = kcb.arch.rpc_client.lock();
                return match client.as_mut().unwrap().fio_close(pid, fd) {
                    Ok(a) => Ok(a),
                    Err(err) => Err(err.into()),
                };
            }

            #[cfg(not(feature = "exokernel"))]
            {
                return cnrfs::MlnrKernelNode::unmap_fd(pid, fd);
            }
        }
        FileOperation::GetInfo => {
            let name = arg2;
            let info_ptr = arg3;
            let _r = user_virt_addr_valid(pid, name, 0)?;

            #[cfg(feature = "exokernel")]
            {
                use crate::arch::process::UserPtr;
                use kpi::io::FileInfo;

                let filename = userptr_to_str(name)?;
                let mut client = kcb.arch.rpc_client.lock();
                return match client.as_mut().unwrap().fio_getinfo(pid, filename) {
                    Ok((ftype, fsize)) => {
                        let user_ptr = UserPtr::new(&mut VAddr::from(info_ptr));
                        unsafe {
                            (*user_ptr.as_mut_ptr::<FileInfo>()).ftype = ftype;
                            (*user_ptr.as_mut_ptr::<FileInfo>()).fsize = fsize;
                        }
                        Ok((0, 0))
                    }
                    Err(err) => Err(err.into()),
                };
            }

            #[cfg(not(feature = "exokernel"))]
            {
                return cnrfs::MlnrKernelNode::file_info(pid, name, info_ptr);
            }
        }
        FileOperation::Delete => {
            let name = arg2;
            let _r = user_virt_addr_valid(pid, name, 0)?;

            #[cfg(feature = "exokernel")]
            {
                let filename = userptr_to_str(name)?;
                let mut client = kcb.arch.rpc_client.lock();
                return match client.as_mut().unwrap().fio_delete(pid, filename) {
                    Ok(a) => Ok(a),
                    Err(err) => Err(err.into()),
                };
            }

            #[cfg(not(feature = "exokernel"))]
            {
                return cnrfs::MlnrKernelNode::file_delete(pid, name);
            }
        }
        FileOperation::WriteDirect => {
            let len = arg3;
            let mut offset = arg4 as usize;
            if arg5 == 0 {
                offset = 0;
            }

            #[cfg(feature = "exokernel")]
            {
                // TODO
                unreachable!("FileOperation not allowed");
                return Err(KError::NotSupported);
            }

            #[cfg(not(feature = "exokernel"))]
            {
                let mut kernslice = crate::process::KernSlice::new(arg2, len as usize);
                let mut buffer = unsafe { Arc::get_mut_unchecked(&mut kernslice.buffer) };
                let cnrfs = super::kcb::get_kcb().arch.cnrfs.as_ref().unwrap();
                let len = cnrfs.write(2, &mut buffer, offset)?;
                return Ok((len as u64, 0));
            }
        }

        FileOperation::FileRename => {
            let oldname = arg2;
            let newname = arg3;
            let _r = user_virt_addr_valid(pid, oldname, 0)?;
            let _r = user_virt_addr_valid(pid, newname, 0)?;

            #[cfg(feature = "exokernel")]
            {
                let oldname = userptr_to_str(oldname)?;
                let newname = userptr_to_str(newname)?;
                let mut client = kcb.arch.rpc_client.lock();
                return match client.as_mut().unwrap().fio_rename(pid, oldname, newname) {
                    Ok(a) => Ok(a),
                    Err(err) => Err(err.into()),
                };
            }

            #[cfg(not(feature = "exokernel"))]
            {
                return cnrfs::MlnrKernelNode::file_rename(pid, oldname, newname);
            }
        }
        FileOperation::MkDir => {
            let pathname = arg2;
            let modes = arg3;
            let _r = user_virt_addr_valid(pid, pathname, 0)?;

            #[cfg(feature = "exokernel")]
            {
                // TODO
                let pathname = userptr_to_str(pathname)?;
                let mut client = kcb.arch.rpc_client.lock();
                return match client.as_mut().unwrap().fio_mkdir(pid, pathname, modes) {
                    Ok(a) => Ok(a),
                    Err(err) => Err(err.into()),
                };
            }

            #[cfg(not(feature = "exokernel"))]
            {
                return cnrfs::MlnrKernelNode::mkdir(pid, pathname, modes);
            }
        }
        FileOperation::Unknown => {
            unreachable!("FileOperation not allowed");
            Err(KError::NotSupported)
        }
    }
}

/// TODO: This method makes file-operations slow, improve it to use large page
/// sizes. Or maintain a list of (low, high) memory limits per process and check
/// if (base, size) are within the process memory limits.
fn user_virt_addr_valid(pid: Pid, base: u64, size: u64) -> Result<(u64, u64), KError> {
    let mut base = base;
    let upper_addr = base + size;

    if upper_addr < KERNEL_BASE {
        while base <= upper_addr {
            // Validate addresses for the buffer end.
            if upper_addr - base <= BASE_PAGE_SIZE as u64 {
                let _r = nrproc::NrProcess::<Ring3Process>::resolve(pid, VAddr::from(base))?;
                return nrproc::NrProcess::<Ring3Process>::resolve(
                    pid,
                    VAddr::from(upper_addr - 1),
                );
            }

            let _r = nrproc::NrProcess::<Ring3Process>::resolve(pid, VAddr::from(base))?;
            base += BASE_PAGE_SIZE as u64;
        }
        return Ok((base, size));
    }
    Err(KError::BadAddress)
}

#[allow(unused)]
fn debug_print_syscall(function: u64, arg1: u64, arg2: u64, arg3: u64, arg4: u64, arg5: u64) {
    sprint!("syscall: {:?}", SystemCall::new(function));

    match SystemCall::new(function) {
        SystemCall::System => {
            sprintln!(
                " {:?} {} {} {} {}",
                SystemOperation::from(arg1),
                arg2,
                arg3,
                arg4,
                arg5
            );
        }
        SystemCall::Process => {
            sprintln!(
                " {:?} {} {} {} {}",
                ProcessOperation::from(arg1),
                arg2,
                arg3,
                arg4,
                arg5
            );
        }
        SystemCall::VSpace => {
            sprintln!(
                " {:?} {} {} {} {}",
                VSpaceOperation::from(arg1),
                arg2,
                arg3,
                arg4,
                arg5
            );
        }
        SystemCall::FileIO => {
            sprintln!(
                " {:?} {} {} {} {}",
                FileOperation::from(arg1),
                arg2,
                arg3,
                arg4,
                arg5
            );
        }
        SystemCall::Unknown => unreachable!(),
    }
}

#[inline(never)]
#[no_mangle]
pub extern "C" fn syscall_handle(
    function: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
) -> ! {
    let status: Result<(u64, u64), KError> = match SystemCall::new(function) {
        SystemCall::System => handle_system(arg1, arg2, arg3),
        SystemCall::Process => handle_process(arg1, arg2, arg3),
        SystemCall::VSpace => handle_vspace(arg1, arg2, arg3),
        SystemCall::FileIO => handle_fileio(arg1, arg2, arg3, arg4, arg5),
        _ => Err(KError::InvalidSyscallArgument1 { a: function }),
    };

    let r = {
        let kcb = super::kcb::get_kcb();

        let _retcode = match status {
            Ok((a1, a2)) => {
                kcb.arch.save_area.as_mut().map(|sa| {
                    sa.set_syscall_ret1(a1);
                    sa.set_syscall_ret2(a2);
                    sa.set_syscall_error_code(SystemCallError::Ok);
                });
            }
            Err(status) => {
                error!("System call returned with error: {:?}", status);
                kcb.arch.save_area.as_mut().map(|sa| {
                    sa.set_syscall_error_code(status.into());
                });
            }
        };

        super::process::Ring3Resumer::new_restore(kcb.arch.get_save_area_ptr())
    };

    unsafe { r.resume() }
}

/// Enables syscall/sysret functionality.
pub fn enable_fast_syscalls() {
    let cs_selector = GdtTable::kernel_cs_selector();
    let ss_selector = GdtTable::kernel_ss_selector();

    unsafe {
        let mut star = rdmsr(IA32_STAR);
        star |= (cs_selector.bits() as u64) << 32;
        star |= (ss_selector.bits() as u64) << 48;
        wrmsr(IA32_STAR, star);

        // System call RIP
        let rip = syscall_enter as u64;
        wrmsr(IA32_LSTAR, rip);
        debug!("Set up fast syscalls. `sysenter` will jump to {:#x}.", rip);

        wrmsr(
            IA32_FMASK,
            !(rflags::RFlags::FLAGS_IOPL3 | rflags::RFlags::FLAGS_A1).bits(),
        );

        // Enable fast syscalls
        let efer = rdmsr(IA32_EFER) | 0b1;
        wrmsr(IA32_EFER, efer);
    }
}
