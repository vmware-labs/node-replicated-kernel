// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use alloc::boxed::Box;
use core::pin::Pin;
use core::ptr;

use cortex_a::{asm::barrier, registers::*};
use tock_registers::interfaces::{Readable, Writeable};

use crate::arch::tls::ThreadControlBlock;

use crate::memory::per_core::PerCoreMemory;
use crate::memory::BASE_PAGE_SIZE;
use crate::stack::{OwnedStack, Stack};

//  There are a couple of per-core registers we can use:
//
//   - TPIDR_EL0:   This is the user-level thread id register for user-level TLS data.
//                  we don't use this in the kernel.
//   - TPIDRRO_EL0: This is the read-only version and we can use this for the process control block.
//                  it's read only in user-space
//   - TPIDR_EL1:   This is the kernel-level thread id register for kernel-level TLS data.
//                  and for the KCB etc.
//
//
// In kernel, the TPIDR_EL1 points to the TCB (Thread Control Block) in the following data
// structure.
// *------------------------------------------------------------------------------*
// |  KCB   | tcb | X | tls1 | ... | tlsN | ... | tls_cnt | dtv[1] | ... | dtv[N] |
// *------------------------------------------------------------------------------*
// ^         ^         ^             ^            ^
// td        tp      dtv[1]       dtv[n+1]       dtv

/// Architecture specific core control block.
///
/// Contains the arch-specific hardware state of a given aarch64 core.
/// `repr(C)` because assembly code references entries of this struct.
#[repr(C)]
pub(crate) struct AArch64Kcb {
    /// Pointer to the save area of the core, this is referenced on trap/syscall
    /// entries to save the CPU state into it and therefore has to remain at
    /// offset 0x8 in this struct.
    ///
    /// State from the save_area may be copied into the `current_executor` save
    /// area to handle upcalls (in the general state it is stored/resumed from
    /// here).
    pub(super) save_area: Option<Pin<Box<kpi::arch::SaveArea>>>,

    /// The state of the memory allocator on this core.
    pub(crate) mem: &'static PerCoreMemory,

    /// A handle to the kernel stack memory location.
    ///
    /// This member should probably not be touched from normal code.
    kernel_stack: Option<OwnedStack>,

    /// Pointer to the syscall stack (this is referenced in assembly) and should
    /// therefore always remain at offset 0 of the Kcb struct!
    ///
    /// The memory it points to shouldn't be accessed/modified at any point in
    /// the code (through this pointer).
    pub(super) kernel_stack_top: *mut u8,

    /// The thread control block
    ///
    /// This member must be last in this struct because of the TLS layout.
    pub(crate) tcb: ThreadControlBlock,
}

static_assertions::const_assert_eq!(memoffset::offset_of!(AArch64Kcb, save_area), 0);
static_assertions::const_assert_eq!(memoffset::offset_of!(AArch64Kcb, mem), 8);
static_assertions::const_assert_eq!(memoffset::offset_of!(AArch64Kcb, kernel_stack), 16);
static_assertions::const_assert_eq!(memoffset::offset_of!(AArch64Kcb, kernel_stack_top), 32);
static_assertions::const_assert_eq!(memoffset::offset_of!(AArch64Kcb, tcb), 48);

//     static_assertions::const_assert_eq!(
//         memoffset::offset_of!(AArch64Kcb, kernel_stack_top), 5*8);

static_assertions::const_assert_eq!(
    memoffset::offset_of!(AArch64Kcb, tcb) - memoffset::offset_of!(AArch64Kcb, kernel_stack_top),
    16
);

const STACK_SIZE: usize = 128 * BASE_PAGE_SIZE;

/// Try to retrieve the per-core memory allocator by reading the gs register.
///
/// This may return None if the memory allocators is not yet set (i.e., during
/// initialization).
///
/// # Safety
/// - This gets a handle to PerCoreMemory (ideally, we should ensure that there
///   is no outstanding mut alias to it e.g., during initialization see comments
///   in mod.rs)
pub(crate) fn try_per_core_mem() -> Option<&'static PerCoreMemory> {
    if let Some(kcb) = try_get_kcb() {
        Some(kcb.mem)
    } else {
        None
    }
}

/// Reference to per-core memory state.
///
/// Must only call this after initialization has completed. So basically ok to
/// call in everywhere in the kernel except care must be taken in `arch`,
/// `crate::memory` and some places in `arch::irq`.
///
/// # Panics
/// - If the per-core memory is not yet initialized (only in debug mode).
pub(crate) fn per_core_mem() -> &'static PerCoreMemory {
    // Safety:
    // - Either this will be initialized with PerCoreMemory or panic.
    // - rdgsbase is ok because we enabled the instruction during core init
    // - [`Arch86Kcb::initialize_gs`] made sure that the gs has the right object
    //   / layout for the cast
    // - There should be no mut alias to the per-core memory after init is
    //   complete (this would basically be a #[thread_local] in a regular
    //   program)
    // - And we check/panic that the gs register is not null
    unsafe {
        let kcb = get_kcb();
        kcb.mem
    }
}

/// Retrieve the AArch64Kcb by reading the gs register.
///
///
/// # Panic
/// This will fail in case the KCB is not yet set (i.e., early on during
/// initialization).
pub(crate) fn try_get_kcb<'a>() -> Option<&'a mut AArch64Kcb> {
    unsafe {
        // Safety:
        // - TODO(safety+soundness): not safe, should return a non-mut reference
        //   with mutable stuff (it's just save_area that's left) wrapped in
        //   RefCell or similar (treat the same as a thread-local)
        let kcb_raw = TPIDR_EL1.get();
        if kcb_raw != 0 {
            Some(get_kcb())
        } else {
            None
        }
    }
}

/// Retrieve the AArch64Kcb by reading the gs register.
///
///
/// # Panic
/// This will fail in case the KCB is not yet set (i.e., early on during
/// initialization).
pub(crate) fn get_kcb<'a>() -> &'a mut AArch64Kcb {
    unsafe {
        // Safety:
        // - TODO(safety+soundness): not safe, should return a non-mut reference
        //   with mutable stuff (it's just save_area that's left) wrapped in
        //   RefCell or similar (treat the same as a thread-local)
        let kcb_raw = TPIDR_EL1.get();
        assert!(kcb_raw != 0, "KCB not found in TPIDR_EL1 register.");

        // this pints to the thread control block, so we need to subtract the offset value here
        let kcb = (kcb_raw - memoffset::offset_of!(AArch64Kcb, tcb) as u64) as *mut AArch64Kcb;

        let kptr = ptr::NonNull::new_unchecked(kcb);
        &mut *kptr.as_ptr()
    }
}

use crate::memory::paddr_to_kernel_vaddr;
use crate::memory::VAddr;
use core::alloc::Layout;

impl AArch64Kcb {
    pub(crate) fn new(mem: &'static PerCoreMemory) -> *const AArch64Kcb {
        // get the tls layout
        let tls_layout = super::tls::get_tls_layout();

        let (kcb_layout, _offset) = tls_layout
            .extend(Layout::new::<AArch64Kcb>())
            .expect("Can't append ThreadControlBlock to TLS layout during init");

        if kcb_layout.size() > BASE_PAGE_SIZE {
            panic!("TLS layout {:?} is too large for a single page", kcb_layout);
        }

        let kcb_mem = mem
            .mem_manager()
            .allocate_base_page()
            .expect("Can't allocate KCB memory");

        let kcb_raw = paddr_to_kernel_vaddr(kcb_mem.base).as_ptr::<AArch64Kcb>() as *mut AArch64Kcb;

        log::info!("kcb vaddr: {:p}", kcb_raw);
        log::info!(
            "memoffset::offset_of!(AArch64Kcb, kernel_stack_top) = {}",
            memoffset::offset_of!(AArch64Kcb, kernel_stack_top)
        );

        // initialize the kcb
        unsafe {
            *kcb_raw = Self {
                kernel_stack_top: ptr::null_mut(),
                save_area: None,
                mem,
                kernel_stack: None,
                tcb: ThreadControlBlock::new(),
            };
        }

        let kcb = unsafe { &mut *kcb_raw };

        kcb.tcb.init_tls();
        kcb.initialize_tpidr();
        kcb.set_kernel_stack(OwnedStack::new(STACK_SIZE));
        kcb.set_save_area(Box::pin(kpi::arch::SaveArea::empty()));

        kcb
    }

    fn initialize_tpidr(&mut self) {
        let kcb: ptr::NonNull<AArch64Kcb> = ptr::NonNull::from(self);
        log::debug!("setting tpidr_el1 to kcb {:p}", kcb);

        // the TPIDR_EL1 register must point to the TCB, so add the offset.
        let val = kcb.as_ptr() as u64 + memoffset::offset_of!(AArch64Kcb, tcb) as u64;

        TPIDR_EL1.set(val)
    }

    pub fn get_stack(&self) -> VAddr {
        VAddr::from(self.kernel_stack_top as u64)
    }

    fn set_kernel_stack(&mut self, stack: OwnedStack) {
        log::warn!("Kernel stack: {:p}..{:p}", stack.limit(), stack.base());
        self.kernel_stack_top = stack.base();
        log::warn!("Kernel stack top set to: {:p}", self.kernel_stack_top);
        self.kernel_stack = Some(stack);
    }

    /// Install a CPU register save-area.
    ///
    /// Register are store here in case we get an interrupt/sytem call
    fn set_save_area(&mut self, save_area: Pin<Box<kpi::arch::SaveArea>>) {
        let handle_ptr: *const kpi::arch::SaveArea = &*save_area;
        log::info!("setting save area to {:p}", handle_ptr);

        TPIDRRO_EL0.set(handle_ptr as u64);
        self.save_area = Some(save_area);
    }

    /// Get a pointer to the cores save-area.
    pub(crate) fn get_save_area_ptr(&self) -> *const kpi::arch::SaveArea {
        // TODO(unsafe): this probably doesn't need an unsafe, but I couldn't figure
        // out how to get that pointer out of the Option<Pin<Box>>>

        let save_area_raw = TPIDRRO_EL0.get();
        assert!(
            save_area_raw != 0,
            "SaveArea not found in TPIDRRO_EL0 register."
        );
        save_area_raw as *const kpi::arch::SaveArea
    }
}
