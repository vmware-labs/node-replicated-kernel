use core::mem;

use x86::bits64::paging::{PAddr, VAddr, BASE_PAGE_SIZE};
use x86::bits64::rflags::{self, RFlags};
use x86::msr::{rdmsr, wrmsr, IA32_EFER, IA32_FMASK, IA32_LSTAR, IA32_STAR};
use x86::segmentation::SegmentSelector;
use x86::tlb;
use x86::Ring;

use kpi::arch::{SaveArea, VirtualCpu};
use kpi::*;

use crate::error::KError;

use super::process::{Process, UserPtr, UserValue};
use super::vspace;
use crate::prelude::NoDrop;

extern "C" {
    #[no_mangle]
    fn syscall_enter();
}

/// System call handler for printing
fn process_print(buf: UserValue<&str>) -> Result<(u64, u64), KError> {
    let buffer: &str = *buf;
    sprint!("{}", buffer);
    Ok((0, 0))
}

/// System call handler for process exit
fn process_exit(code: u64) -> Result<(u64, u64), KError> {
    info!("Process got exit, we are done for now...");
    super::debug::shutdown(crate::ExitReason::Ok);
    Ok((0, 0))
}

fn handle_process(arg1: u64, arg2: u64, arg3: u64) -> Result<(u64, u64), KError> {
    let op = ProcessOperation::from(arg1);
    debug!("{:?} {:#x} {:#x}", op, arg2, arg3);

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
        ProcessOperation::InstallVCpuArea => unsafe {
            let kcb = crate::kcb::get_kcb();
            let mut plock = kcb.current_process();

            plock.as_mut().map_or(Err(KError::ProcessNotSet), |p| {
                let cpu_ctl_addr = VAddr::from(arg2);
                p.vspace.map(
                    cpu_ctl_addr,
                    BASE_PAGE_SIZE,
                    vspace::MapAction::ReadWriteUser,
                    0x1000,
                )?;

                x86::tlb::flush_all();

                p.vcpu_ctl = Some(UserPtr::new(cpu_ctl_addr.as_u64() as *mut VirtualCpu));

                warn!("installed vcpu area {:p}", cpu_ctl_addr,);

                Ok((cpu_ctl_addr.as_u64(), 0))
            })
        },
        ProcessOperation::Exit => {
            let exit_code = arg2;
            process_exit(arg1)
        }
        _ => Err(KError::InvalidProcessOperation { a: arg1 }),
    }
}

/// System call handler for vspace operations
fn handle_vspace(arg1: u64, arg2: u64, arg3: u64) -> Result<(u64, u64), KError> {
    let op = VSpaceOperation::from(arg1);
    let base = VAddr::from(arg2);
    let bound = arg3;
    debug!("{:?} {:#x} {:#x}", op, base, bound);

    let kcb = crate::kcb::get_kcb();
    let mut plock = kcb.current_process();

    match op {
        VSpaceOperation::Map => unsafe {
            plock.as_mut().map_or(Err(KError::ProcessNotSet), |p| {
                let (paddr, size) = (*p).vspace.map(
                    base,
                    bound as usize,
                    vspace::MapAction::ReadWriteUser,
                    0x1000,
                )?;

                tlb::flush_all();
                Ok((paddr.as_u64(), size as u64))
            })
        },
        VSpaceOperation::MapDevice => unsafe {
            plock.as_mut().map_or(Err(KError::ProcessNotSet), |p| {
                let paddr = PAddr::from(base.as_u64());
                p.vspace.map_generic(
                    base,
                    (paddr, bound as usize),
                    vspace::MapAction::ReadWriteUser,
                )?;

                tlb::flush_all();
                Ok((paddr.as_u64(), bound))
            })
        },
        VSpaceOperation::Unmap => {
            error!("Can't do VSpaceOperation unmap yet.");
            Err(KError::NotSupported)
        }
        VSpaceOperation::Identify => unsafe {
            trace!("Identify base {:#x}.", base);
            plock.as_mut().map_or(Err(KError::ProcessNotSet), |p| {
                let paddr = p.vspace.resolve_addr(base);

                Ok((paddr.map(|pnum| pnum.as_u64()).unwrap_or(0x0), 0x0))
            })
        },
        VSpaceOperation::Unknown => {
            error!("Got an invalid VSpaceOperation code.");
            Err(KError::InvalidVSpaceOperation { a: arg1 })
        }
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
        SystemCall::Process => handle_process(arg1, arg2, arg3),
        SystemCall::VSpace => handle_vspace(arg1, arg2, arg3),
        _ => Err(KError::InvalidSyscallArgument1 { a: function }),
    };

    let r = {
        let kcb = crate::kcb::get_kcb();

        let retcode = match status {
            Ok((a1, a2)) => {
                kcb.save_area.as_mut().map(|mut sa| {
                    sa.set_syscall_ret1(a1);
                    sa.set_syscall_ret2(a2);
                    sa.set_syscall_error_code(SystemCallError::Ok);
                });
            }
            Err(status) => {
                error!("System call returned with error: {:?}", status);
                kcb.save_area.as_mut().map(|mut sa| {
                    sa.set_syscall_error_code(status.into());
                });
            }
        };

        /*info!(
            "resume from syscall with kcb save area = {:?}",
            kcb.save_area
        );*/

        super::process::ResumeHandle::new_restore(kcb.get_save_area_ptr())
    };

    unsafe { r.resume() }
}

/// Enables syscall/sysret functionality.
pub fn enable_fast_syscalls(cs_selector: SegmentSelector, ss_selector: SegmentSelector) {
    unsafe {
        let mut star = rdmsr(IA32_STAR);
        star |= (cs_selector.bits() as u64) << 32;
        star |= (ss_selector.bits() as u64) << 48;
        wrmsr(IA32_STAR, star);

        // System call RIP
        let rip = syscall_enter as u64;
        wrmsr(IA32_LSTAR, rip);
        info!("syscalls jump to {:#x}", rip);

        wrmsr(
            IA32_FMASK,
            !(rflags::RFlags::FLAGS_IOPL3 | rflags::RFlags::FLAGS_A1 | rflags::RFlags::FLAGS_IF)
                .bits(),
        );

        // Enable fast syscalls
        let efer = rdmsr(IA32_EFER) | 0b1;
        wrmsr(IA32_EFER, efer);
    }

    debug!("Fast syscalls enabled!");
}
