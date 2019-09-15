//! Functionality to boot application cores on x86.
//!
//! This code is closely intertwingled with the assembly code in `start_ap.S`.

use super::kcb;
use super::vspace::MapAction;
use core::slice;
use x86::apic::{ApicControl, ApicId};
use x86::current::paging::{PAddr, BASE_PAGE_SIZE};

/// The 16-bit segement where our bootstrap code is.
const X86_64_REAL_MODE_SEGMENT: u16 = 0x0600;

/// The page number in real mode (this is what the IPI wants)
const REAL_MODE_PAGE: u8 = (X86_64_REAL_MODE_SEGMENT >> 8) as u8;

/// The offset, what we have to add to get a physical address.
const REAL_MODE_LINEAR_OFFSET: u16 = X86_64_REAL_MODE_SEGMENT << 4;

/// The corresponding 64-bit address (0 + offset in our case).
const REAL_MODE_BASE: usize = REAL_MODE_LINEAR_OFFSET as usize;

/// Return the address range of `start_ap.S` as (start, end)
///
/// # Note
/// The addresses returned are start and end in kernel space
/// (above KERNEL_BASE, within the relocated ELF file). But
/// when we boot we have to copy the code in a lower address region
/// where a 16-bit mode CPU can execute.
fn ap_code_address_range() -> (PAddr, PAddr) {
    extern "C" {
        // The first symbol in `start_ap.S`
        static x86_64_start_ap: *const u8;
        // The very last symbol in `start_ap.S`
        static x86_64_start_ap_end: *const u8;
    }

    unsafe {
        (
            PAddr::from(&x86_64_start_ap as *const _ as u64),
            PAddr::from(&x86_64_start_ap_end as *const _ as u64),
        )
    }
}

/// Calculate the size of the bootstrap code-block in `start_ap.S`
///
/// We do that by taking the difference of the first and last symbol
/// in that file.
fn get_boostrap_code_size() -> usize {
    let (start_address, end_address) = ap_code_address_range();
    let boostrap_code_size = end_address - start_address;
    trace!("boostrap_code_size = {:#x}", boostrap_code_size);

    boostrap_code_size.into()
}

pub unsafe fn copy_bootstrap_code() {
    let (start_address, _end_address) = ap_code_address_range();
    let boot_code_size = get_boostrap_code_size();

    let ap_bootstrap_code: &'static [u8] = get_orignal_bootstrap_code();
    let real_mode_destination: &'static mut [u8] = get_boostrap_code_region();

    let kcb = kcb::get_kcb();
    kcb.init_vspace().map_identity(
        PAddr::from(REAL_MODE_BASE as u64),
        PAddr::from(REAL_MODE_BASE + boot_code_size).align_up_to_base_page(),
        MapAction::ReadWriteExecuteKernel,
    );

    real_mode_destination.copy_from_slice(ap_bootstrap_code);
}

/// Initializes the information passed to the APP core
///
/// This includes the entry rust function, a pointer
/// to the initial address space, a pointer to the
/// initial stack.
///
/// # TODO
/// Should also reset the boostrap code lock...
///
/// # Safety
/// To be safe this function should only be invoked
/// during initialization on the BSP core and after we invoked `copy_bootstrap_code`.
pub unsafe fn setup_boostrap_code(entry_fn: u64, pml4: u64, stack_top: u64) {
    // Symbols from `start_ap.S`
    extern "C" {
        /// Bootstrap code jumps to this address after initialization.
        static x86_64_init_ap_absolute_entry: *mut extern "C" fn();
        /// Bootstrap core switches to this address space during initialization.
        static x86_64_init_ap_init_pml4: *mut extern "C" fn();
        /// Bootstrap core uses this stack address when starting to execute at `x86_64_init_ap_absolute_entry`.
        static x86_64_init_ap_stack_ptr: *mut extern "C" fn();
        /// The ap lock to let us know when the app core currently booting is done
        /// with the initialization code section.
        ///
        /// (And therefore we can reset `x86_64_init_ap_absolute_entry`,
        /// `x86_64_init_ap_init_pml4`, `x86_64_init_ap_stack_ptr` again).
        static x86_64_init_ap_lock: *mut extern "C" fn();
    }

    let (start_addr, _end_addr) = ap_code_address_range();

    let entry_pointer: *mut u64 = core::mem::transmute(
        &x86_64_init_ap_absolute_entry as *const _ as u64 - start_addr.as_u64()
            + REAL_MODE_BASE as u64,
    );
    *entry_pointer = entry_fn;

    let pml4_pointer: *mut u64 = core::mem::transmute(
        &x86_64_init_ap_init_pml4 as *const _ as u64 - start_addr.as_u64() + REAL_MODE_BASE as u64,
    );
    *pml4_pointer = pml4;

    let stack_pointer: *mut u64 = core::mem::transmute(
        &x86_64_init_ap_stack_ptr as *const _ as u64 - start_addr.as_u64() + REAL_MODE_BASE as u64,
    );
    *stack_pointer = stack_top;

    let ap_lock_pointer: *mut u64 = core::mem::transmute(
        &x86_64_init_ap_lock as *const _ as u64 - start_addr.as_u64() + REAL_MODE_BASE as u64,
    );
    *ap_lock_pointer = 0;

    trace!(
        "x86_64_init_ap_absolute_entry is at {:p} and set to {:#x}",
        entry_pointer,
        *entry_pointer
    );
    trace!(
        "x86_64_init_ap_init_pml4 is at {:p} and set to {:#x}",
        pml4_pointer,
        *pml4_pointer
    );
    trace!(
        "x86_64_init_ap_stack_ptr is at {:p} and set to {:#x}",
        stack_pointer,
        *stack_pointer
    );
    trace!(
        "x86_64_init_ap_lock is at {:p} and set to {:#x}",
        ap_lock_pointer,
        *ap_lock_pointer
    );
}

/// Returns a slice to the bootstrap code in the kernel ELF .text section
///
/// Ideally this region of memory shouldn't be modified (it's mapped read-only by
/// default anyways). We first copy it into a low memory region and then do the
/// final adjustments there.
fn get_orignal_bootstrap_code() -> &'static [u8] {
    let (start_address, _end_address) = ap_code_address_range();
    let boot_code_size = get_boostrap_code_size();

    // This is safe since this is in the kernel binary and always only
    // mapped read-only.
    let ap_bootstrap_code: &'static [u8] =
        unsafe { core::slice::from_raw_parts(start_address.as_u64() as *const u8, boot_code_size) };

    ap_bootstrap_code
}

/// Returns a slice to the bootstrap code region from where we boot new cores.
///
/// # Safety
/// Basically this is only safe in the beginning of system initialization
/// and we need to make sure we have memory backing the REAL_MODE_BASE region
/// first.
unsafe fn get_boostrap_code_region() -> &'static mut [u8] {
    let real_mode_destination: &mut [u8] =
        core::slice::from_raw_parts_mut(REAL_MODE_BASE as *mut u8, get_boostrap_code_size());
    real_mode_destination
}

/// Wakes up (resets) a core by sending a sequence of IPIs (INIT, INIT deassert, STARTUP).
///
/// # Notes
/// x86 specification technically requires to sleep between init and startup, but on most
/// modern processors (Xeon Phi being an exception) this is not actually necessary.
///
/// # Safety
/// You're waking up a core that goes off and does random things (if not being careful),
/// so this is pretty bad for memory safety.
pub unsafe fn wakeup_core(core_id: ApicId) {
    let kcb = kcb::get_kcb();

    // x86 core boot protocol, without sleeping:
    kcb.apic().ipi_init(core_id);
    kcb.apic().ipi_init_deassert();
    kcb.apic().ipi_startup(core_id, REAL_MODE_PAGE);
}
