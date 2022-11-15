// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::{arch::global_asm, cell::UnsafeCell, fmt};
use cortex_a::{asm::barrier, registers::*};
use tock_registers::{
    interfaces::{Readable, Writeable},
    registers::InMemoryRegister,
};

use super::halt;
use klogger::sprint;

#[derive(PartialEq, Eq, Clone, Debug)]
pub enum ExnTypes {
    /* undefined exception */
    Aarch64Undefined = 0x00,

    /* current exception level, with EL0 stack */
    Aarch64KernelWithEl0StackSync = 0x01,
    Aarch64KernelWithEl0StackIrq = 0x02,
    Aarch64KernelWithEl0StackFiq = 0x03,
    Aarch64KernelWithEl0StackSerror = 0x04,

    /* current exception level, with own stack */
    Aarch64KernelSync = 0x05,
    Aarch64KernelIrq = 0x06,
    Aarch64KernelFiq = 0x07,
    Aarch64KernelSerror = 0x08,

    /* lower exception level using AARCH64 */
    Aarch64UserSync = 0x09,
    Aarch64UserIrq = 0x0a,
    Aarch64UserFiq = 0x0b,
    Aarch64UserSerror = 0x0c,

    /* lower exception level using AARCH32 */
    Aarch32UserSync = 0x10,
    Aarch32UserIrq = 0x11,
    Aarch32UserFiq = 0x12,
    Aarch32UserSerror = 0x13,
}

impl ExnTypes {
    pub fn is_user_aarch32_exception(&self) -> bool {
        use ExnTypes::*;
        matches!(
            self,
            Aarch32UserFiq | Aarch32UserIrq | Aarch32UserSerror | Aarch32UserSync
        )
    }

    pub fn is_user_aarch64_exception(&self) -> bool {
        use ExnTypes::*;
        matches!(self, |Aarch64UserFiq| Aarch64UserIrq
            | Aarch64UserSerror
            | Aarch64UserSync)
    }

    pub fn is_user_exception(&self) -> bool {
        self.is_user_aarch32_exception() || self.is_user_aarch64_exception()
    }

    pub fn is_kernel_exception_current_stack(&self) -> bool {
        use ExnTypes::*;
        matches!(self, |Aarch64KernelSync| Aarch64KernelIrq
            | Aarch64KernelFiq
            | Aarch64KernelSerror)
    }

    pub fn is_kernel_exception_with_el0_stack(&self) -> bool {
        use ExnTypes::*;
        matches!(
            self,
            Aarch64KernelWithEl0StackFiq
                | Aarch64KernelWithEl0StackIrq
                | Aarch64KernelWithEl0StackSerror
                | Aarch64KernelWithEl0StackSync
        )
    }

    pub fn is_kernel_exception(&self) -> bool {
        self.is_kernel_exception_current_stack() || self.is_kernel_exception_with_el0_stack()
    }
}

impl From<u64> for ExnTypes {
    fn from(val: u64) -> ExnTypes {
        match val {
            0x00 => ExnTypes::Aarch64Undefined,
            0x01 => ExnTypes::Aarch64KernelWithEl0StackSync,
            0x02 => ExnTypes::Aarch64KernelWithEl0StackIrq,
            0x03 => ExnTypes::Aarch64KernelWithEl0StackFiq,
            0x04 => ExnTypes::Aarch64KernelWithEl0StackSerror,
            0x05 => ExnTypes::Aarch64KernelSync,
            0x06 => ExnTypes::Aarch64KernelIrq,
            0x07 => ExnTypes::Aarch64KernelFiq,
            0x08 => ExnTypes::Aarch64KernelSerror,
            0x09 => ExnTypes::Aarch64UserSync,
            0x0a => ExnTypes::Aarch64UserIrq,
            0x0b => ExnTypes::Aarch64UserFiq,
            0x0c => ExnTypes::Aarch64UserSerror,
            0x10 => ExnTypes::Aarch32UserSync,
            0x11 => ExnTypes::Aarch32UserIrq,
            0x12 => ExnTypes::Aarch32UserFiq,
            0x13 => ExnTypes::Aarch32UserSerror,
            _ => panic!("Invalid exception type: {}", val),
        }
    }
}

// define types for the register wrappers
#[repr(transparent)]
pub struct EsrEL1(InMemoryRegister<u64, ESR_EL1::Register>);

/// Hander for unsupported exceptions
///
/// # Argument
// - `epc`    the program counter that caused the exception
// - `spsr`   the sps
// - `esr`    the exception syndrome register value
// - `vector` the exception vector
#[inline(never)]
#[no_mangle]
pub extern "C" fn exceptions_handle_unsupported(
    epc: u64,
    spsr: u64,
    esr: EsrEL1,
    vector: u64,
) -> ! {
    sprint!("\n\n");
    let exn = ExnTypes::from(vector);

    if exn.is_user_aarch32_exception() {
        log::error!("Exceptions from user in AArch32 mode are not supported.");
    }

    if exn.is_user_aarch64_exception() {
        log::error!("BUG: Why did an user exception from AArch64 mode end up here?");
    }

    if exn.is_kernel_exception_with_el0_stack() {
        log::error!("Exceptions from the kernel with EL0 stack are not supported");
    }

    if exn.is_kernel_exception_current_stack() {
        match esr.0.read_as_enum(ESR_EL1::EC) {
            Some(ESR_EL1::EC::Value::DataAbortCurrentEL) => {
                log::error!(
                    "Unhandled exception: DataAbort ({:?}) at 0x{:x} with address 0x{:x}",
                    exn,
                    epc,
                    FAR_EL1.get()
                );
            }
            Some(ESR_EL1::EC::Value::SError) => {
                log::error!(
                    "Unhandled exception: SError ({:?}) at {:x} with address {:x}",
                    exn,
                    epc,
                    FAR_EL1.get()
                );
            }
            Some(ESR_EL1::EC::Value::TrappedFP64) => {
                log::error!(
                    "Unhandled exception: Trapped Foating Point Instruction ({:?}) at {:x}",
                    exn,
                    epc
                );
            }
            Some(ESR_EL1::EC::Value::SPAlignmentFault) => {
                log::error!(
                    "Unhandled exception: Stack Pointer Alignment Fault ({:?}) at {:x}",
                    exn,
                    epc
                );
            }
            Some(ESR_EL1::EC::Value::PCAlignmentFault) => {
                log::error!(
                    "Unhandled exception: Program Counter Alignment Fault ({:?}) at {:x}",
                    exn,
                    epc
                );
            }
            Some(ESR_EL1::EC::Value::InstrAbortCurrentEL) => {
                log::error!(
                    "Unhandled exception: Instruction Abort ({:?}) at {:x} with address {:x}",
                    exn,
                    epc,
                    FAR_EL1.get()
                );
            }
            Some(ESR_EL1::EC::Value::SVC64) => {
                log::error!(
                    "Unhandled exception: System Call from kernel ({:?}) at {:x}",
                    exn,
                    epc
                );
            }
            _ => {
                log::error!("Unhandled exception {:?} at {:x}", exn, epc);
            }
        }
        log::error!("BUG: Exceptions from the kernel shouldn't occur.");
    }

    log::error!("Halting the system\n");
    halt()
}

/// Hander for unsupported exceptions
///
/// # Argument
// - `epc`    the program counter that caused the exception
// - `spsr`   the sps
// - `esr`    the exception syndrome register value
// - `vector` the exception vector
#[inline(never)]
#[no_mangle]
pub extern "C" fn handle_user_fault(epc: u64, spsr: u64, esr: EsrEL1, vector: u64) -> ! {
    sprint!("\n\n");
    let exn = ExnTypes::from(vector);

    if exn.is_user_aarch32_exception() {
        log::error!("BUG: Exceptions from user in AArch32 mode are not supported.");
    }

    if exn.is_kernel_exception_with_el0_stack() {
        log::error!("BUG: Exceptions from the kernel with EL0 stack are not supported");
    }

    match esr.0.read_as_enum(ESR_EL1::EC) {
        Some(ESR_EL1::EC::Value::DataAbortLowerEL) => {
            log::error!(
                "Unhandled user exception: DataAbort ({:?}) at 0x{:x} with address 0x{:x}  (pagefault)",
                exn,
                epc,
                FAR_EL1.get()
            );
        }
        Some(ESR_EL1::EC::Value::SError) => {
            log::error!(
                "Unhandled user exception:  SError ({:?}) at {:x} with address {:x}",
                exn,
                epc,
                FAR_EL1.get()
            );
        }
        Some(ESR_EL1::EC::Value::TrappedFP64) => {
            log::error!(
                "Unhandled user exception: Trapped Foating Point Instruction ({:?}) at {:x}",
                exn,
                epc
            );
        }
        Some(ESR_EL1::EC::Value::SPAlignmentFault) => {
            log::error!(
                "Unhandled user exception:  Stack Pointer Alignment Fault ({:?}) at {:x}",
                exn,
                epc
            );
        }
        Some(ESR_EL1::EC::Value::PCAlignmentFault) => {
            log::error!(
                "Unhandled user exception: Program Counter Alignment Fault ({:?}) at {:x}",
                exn,
                epc
            );
        }
        Some(ESR_EL1::EC::Value::InstrAbortLowerEL) => {
            log::error!(
                "Unhandled user exception: Instruction Abort ({:?}) at {:x} with address {:x}",
                exn,
                epc,
                FAR_EL1.get()
            );
        }
        Some(ESR_EL1::EC::Value::SError) => {
            log::error!(
                "Unhandled user exception:  SError ({:?}) at {:x} with address {:x}",
                exn,
                epc,
                FAR_EL1.get()
            );
        }
        Some(ESR_EL1::EC::Value::SVC64) => {
            log::error!(
                "Unhandled user exception:  System call should not end up here ({:?}) at {:x}",
                exn,
                epc
            );
        }
        Some(x) => {
            log::error!(
                "Unhandled user exception: {:?} ({:b}) at {:x}",
                exn,
                esr.0.read(ESR_EL1::EC),
                epc
            );
        }
        _ => {
            panic!(
                "Unexpected EC code {} ({:?}) at {:x}",
                esr.0.read(ESR_EL1::EC),
                exn,
                epc
            );
        }
    }

    log::error!("Halting the system\n");
    halt()
}
