// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::convert::TryInto;

use gdbstub::target::ext::base::SingleRegisterAccess;
use gdbstub::target::{TargetError, TargetResult};
use gdbstub_arch::x86::reg::id::{X86SegmentRegId, X86_64CoreRegId};
use log::{error, trace};

use super::KernelDebugger;

impl SingleRegisterAccess<()> for KernelDebugger {
    fn read_register(
        &mut self,
        _tid: (),
        reg_id: X86_64CoreRegId,
        dst: &mut [u8],
    ) -> TargetResult<usize, Self> {
        trace!("read_register {:?}", reg_id);
        let kcb = super::super::kcb::get_kcb();

        if let Some(saved) = &mut kcb.save_area {
            fn copy_out(dst: &mut [u8], src: &[u8]) -> TargetResult<usize, KernelDebugger> {
                dst.copy_from_slice(src);
                Ok(src.len())
            }

            match reg_id {
                X86_64CoreRegId::Gpr(00) => copy_out(dst, &saved.rax.to_le_bytes()),
                X86_64CoreRegId::Gpr(01) => copy_out(dst, &saved.rbx.to_le_bytes()),
                X86_64CoreRegId::Gpr(02) => copy_out(dst, &saved.rcx.to_le_bytes()),
                X86_64CoreRegId::Gpr(03) => copy_out(dst, &saved.rdx.to_le_bytes()),
                X86_64CoreRegId::Gpr(04) => copy_out(dst, &saved.rsi.to_le_bytes()),
                X86_64CoreRegId::Gpr(05) => copy_out(dst, &saved.rdi.to_le_bytes()),
                X86_64CoreRegId::Gpr(06) => copy_out(dst, &saved.rbp.to_le_bytes()),
                X86_64CoreRegId::Gpr(07) => copy_out(dst, &saved.rsp.to_le_bytes()),
                X86_64CoreRegId::Gpr(08) => copy_out(dst, &saved.r8.to_le_bytes()),
                X86_64CoreRegId::Gpr(09) => copy_out(dst, &saved.r9.to_le_bytes()),
                X86_64CoreRegId::Gpr(10) => copy_out(dst, &saved.r10.to_le_bytes()),
                X86_64CoreRegId::Gpr(11) => copy_out(dst, &saved.r11.to_le_bytes()),
                X86_64CoreRegId::Gpr(12) => copy_out(dst, &saved.r12.to_le_bytes()),
                X86_64CoreRegId::Gpr(13) => copy_out(dst, &saved.r13.to_le_bytes()),
                X86_64CoreRegId::Gpr(14) => copy_out(dst, &saved.r14.to_le_bytes()),
                X86_64CoreRegId::Gpr(15) => copy_out(dst, &saved.r15.to_le_bytes()),
                X86_64CoreRegId::Rip => copy_out(dst, &saved.rip.to_le_bytes()),
                X86_64CoreRegId::Eflags => {
                    let rflags: u32 = saved.rflags.try_into().unwrap();
                    copy_out(dst, &rflags.to_le_bytes())
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::CS) => {
                    let cs: u32 = saved.cs.try_into().unwrap();
                    copy_out(dst, &cs.to_le_bytes())
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::SS) => {
                    let ss: u32 = saved.ss.try_into().unwrap();
                    copy_out(dst, &ss.to_le_bytes())
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::DS) => {
                    return Err(TargetError::NonFatal);
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::ES) => {
                    return Err(TargetError::NonFatal);
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::FS) => {
                    let fs: u32 = saved.fs.try_into().unwrap();
                    copy_out(dst, &fs.to_le_bytes())
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::GS) => {
                    let gs: u32 = saved.gs.try_into().unwrap();
                    copy_out(dst, &gs.to_le_bytes())
                }
                //X86_64CoreRegId::St(u8) => {},
                //X86_64CoreRegId::Fpu(X87FpuInternalRegId) => {},
                //X86_64CoreRegId::Xmm(u8) => {},
                //X86_64CoreRegId::Mxcsr => {},
                missing => {
                    error!("Unimplemented register {:?}", missing);
                    return Err(TargetError::NonFatal);
                }
            }
        } else {
            Err(TargetError::NonFatal)
        }
    }

    fn write_register(
        &mut self,
        _tid: (),
        reg_id: X86_64CoreRegId,
        val: &[u8],
    ) -> TargetResult<(), Self> {
        trace!("write_register {:?} {:?}", reg_id, val);
        let kcb = super::super::kcb::get_kcb();

        if let Some(saved) = &mut kcb.save_area {
            match reg_id {
                X86_64CoreRegId::Gpr(00) => {
                    saved.rax =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(01) => {
                    saved.rbx =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(02) => {
                    saved.rcx =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(03) => {
                    saved.rdx =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(04) => {
                    saved.rsi =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(05) => {
                    saved.rdi =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(06) => {
                    saved.rbp =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(07) => {
                    saved.rsp =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(08) => {
                    saved.r8 =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(09) => {
                    saved.r9 =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(10) => {
                    saved.r10 =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(11) => {
                    saved.r11 =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(12) => {
                    saved.r12 =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(13) => {
                    saved.r13 =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(14) => {
                    saved.r14 =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Gpr(15) => {
                    saved.r15 =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Rip => {
                    assert_eq!(val.len(), 8, "gdbstub/issues/80");
                    saved.rip =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?);
                }
                X86_64CoreRegId::Eflags => {
                    saved.rflags =
                        u32::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?)
                            as u64;
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::CS) => {
                    saved.cs =
                        u32::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?)
                            as u64;
                }

                X86_64CoreRegId::Segment(X86SegmentRegId::SS) => {
                    saved.ss =
                        u32::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?)
                            as u64;
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::DS) => {
                    return Err(TargetError::NonFatal);
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::ES) => {
                    return Err(TargetError::NonFatal);
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::FS) => {
                    saved.fs =
                        u32::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?)
                            as u64;
                }
                X86_64CoreRegId::Segment(X86SegmentRegId::GS) => {
                    saved.gs =
                        u32::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?)
                            as u64;
                }
                //X86_64CoreRegId::St(u8) => {},
                //X86_64CoreRegId::Fpu(X87FpuInternalRegId) => {},
                //X86_64CoreRegId::Xmm(u8) => {},
                X86_64CoreRegId::Mxcsr => {
                    saved.fxsave.mxcsr =
                        u64::from_le_bytes(val.try_into().map_err(|_e| TargetError::NonFatal)?)
                            as u32;
                }
                _ => {
                    error!("Unimplemented register");
                    return Err(TargetError::NonFatal);
                }
            };

            Ok(())
        } else {
            Err(TargetError::NonFatal)
        }
    }
}
