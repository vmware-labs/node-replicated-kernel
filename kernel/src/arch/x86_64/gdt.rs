// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Code to manage and set-up the GDT and TSS.

use core::mem::size_of;

use log::trace;
use x86::bits64::segmentation::{load_cs, Descriptor64};
use x86::bits64::task::*;
use x86::dtables::*;
use x86::segmentation::*;
use x86::task::load_tr;
use x86::Ring;

use crate::stack::{Stack, StaticStack};

/// A temporary, statically allocated stack for interrupts that could happen
/// (by a bug) early in a core initialization.
///
/// After initialization is done and we have memory allocation this
/// should not be used anymore.
///
/// # Note
/// In theory, this stack is shared by all cores on the system during boot-up
/// as long as we boot cores sequentially (or nothing exceptional happens)
/// it shouldn't cause any problems.
static mut EARLY_IRQ_STACK: StaticStack = StaticStack([0; 32 * 4096]);

/// A GDT table that is in use during system initialization only.
///
/// During init, each core sets their own `GDT` that is stored in their
/// respective TLS area. However, before that they can use the `EARLY_GDT` as a
/// simple way to get a Gdt that mostly works without having the Kcb fully
/// initialized.
///
/// # Note
/// This is the 2nd initial Gdt we have, there are two more: One as set-up by
/// UEFI and used early-on in the bootstrap core, and another that is used by
/// the app cores and lives in `start_ap.S`. So technically we could just use
/// those but having a visible Gdt we modify from rust code makes it clearer
/// what's going on.
static mut EARLY_GDT: GdtTable = GdtTable {
    null: Descriptor::NULL,
    code_kernel: Descriptor::NULL,
    stack_kernel: Descriptor::NULL,
    code_user: Descriptor::NULL,
    stack_user: Descriptor::NULL,
    tss_segment: Descriptor64::NULL,
};

/// A TSS that is in use during system initialization only.
///
/// During init, each core sets their own `TSS` that is stored inside their
/// respective TLS area. However, before that cores use the `EARLY_TSS` (through
/// `EARLY_GDT`) and therefore the `EARLY_IRQ_STACK` as a stack for interrupts
/// in case something goes wrong.
static mut EARLY_TSS: TaskStateSegment = TaskStateSegment::new();

#[repr(C, packed)]
pub(crate) struct GdtTable {
    null: Descriptor,
    /// 64 bit code
    code_kernel: Descriptor,
    /// 64 bit stack
    stack_kernel: Descriptor,
    code_user: Descriptor,
    /// 64 bit user stack
    stack_user: Descriptor,
    tss_segment: Descriptor64,
}

impl GdtTable {
    #[allow(dead_code)]
    pub(crate) const NULL_INDEX: u16 = 0;
    pub(crate) const CS_KERNEL_INDEX: u16 = 1;
    pub(crate) const SS_KERNEL_INDEX: u16 = 2;
    //pub(crate) const CS_USER_INDEX: u16 = kpi::arch::CS_USER_GDT_INDEX;
    //pub(crate) const SS_USER_INDEX: u16 = kpi::arch::SS_USER_GDT_INDEX;
    pub(crate) const TSS_INDEX: u16 = 5;

    /// Creates a new GdtTable with a provided TaskStateSegment.
    ///
    /// The other values will be set to x86-64 default values and
    /// should not change.
    pub(crate) fn new(tss: &TaskStateSegment) -> GdtTable {
        GdtTable {
            tss_segment: GdtTable::tss_descriptor(tss),
            ..Default::default()
        }
    }

    /// Installs the GDT on the local core.
    ///
    /// # Safety
    /// This is heavily unsafe, if done wrong it will crash your
    /// system or change memory semantics.
    pub unsafe fn install(&self) {
        let gdtptr = DescriptorTablePointer::new(self);
        lgdt(&gdtptr);

        // We need to re-load the segments when we change the GDT
        GdtTable::reload_segment_selectors();
    }

    /// Reload all segment selectors (typically this has to be done
    /// after a new GDT is installed).
    ///
    /// # Safety
    /// Potential to crash the system if the GDT is malformed.
    unsafe fn reload_segment_selectors() {
        load_ds(SegmentSelector::new(0, Ring::Ring0));
        load_es(SegmentSelector::new(0, Ring::Ring0));
        load_fs(SegmentSelector::new(0, Ring::Ring0));
        load_gs(SegmentSelector::new(0, Ring::Ring0));

        load_cs(GdtTable::kernel_cs_selector());
        load_ss(GdtTable::kernel_ss_selector());
        load_tr(GdtTable::tss_selector());

        trace!("Re-loaded segment selectors.");
    }

    /// Generates a TSS descriptor that can be sticked into the `tss_segment`
    ///
    /// It uses address of the TaskStateSegment. While this is not `unsafe` by
    /// itself, care must be taken as the `tss` should probably be 'static and
    /// not go away during the life-time of the Gdt.
    fn tss_descriptor(tss: &TaskStateSegment) -> Descriptor64 {
        let tss_ptr = tss as *const _ as u64;

        <DescriptorBuilder as GateDescriptorBuilder<u64>>::tss_descriptor(
            tss_ptr as u64,
            size_of::<TaskStateSegment>() as u64,
            true,
        )
        .present()
        .dpl(Ring::Ring0)
        .finish()
    }

    /// Return the selector for the kernel cs (code segment).
    pub(crate) const fn kernel_cs_selector() -> SegmentSelector {
        SegmentSelector::new(GdtTable::CS_KERNEL_INDEX as u16, Ring::Ring0)
    }

    /// Return the selector for the kernel ss (stack segment).
    pub(crate) const fn kernel_ss_selector() -> SegmentSelector {
        SegmentSelector::new(GdtTable::SS_KERNEL_INDEX as u16, Ring::Ring0)
    }

    /// Return the selector for the kernel ss (stack segment).
    pub(crate) const fn user_cs_selector() -> SegmentSelector {
        kpi::arch::CS_SELECTOR
    }

    /// Return the selector for the kernel ss (stack segment).
    pub(crate) const fn user_ss_selector() -> SegmentSelector {
        kpi::arch::SS_SELECTOR
    }

    /// Return the selector for the task segment.
    const fn tss_selector() -> SegmentSelector {
        SegmentSelector::new(GdtTable::TSS_INDEX as u16, Ring::Ring0)
    }
}

impl Default for GdtTable {
    /// Sets-up a default GDT table conform to the format expecte by x86-64 bit mode.
    fn default() -> Self {
        GdtTable {
            null: Descriptor::NULL,
            code_kernel: DescriptorBuilder::code_descriptor(0, 0, CodeSegmentType::ExecuteRead)
                .present()
                .dpl(Ring::Ring0)
                .limit_granularity_4kb()
                .l()
                .finish(),
            stack_kernel: DescriptorBuilder::data_descriptor(0, 0, DataSegmentType::ReadWrite)
                .present()
                .dpl(Ring::Ring0)
                .limit_granularity_4kb()
                .finish(),
            code_user: DescriptorBuilder::code_descriptor(0, 0, CodeSegmentType::ExecuteRead)
                .present()
                .limit_granularity_4kb()
                .l()
                .dpl(Ring::Ring3)
                .finish(),
            stack_user: DescriptorBuilder::data_descriptor(0, 0, DataSegmentType::ReadWrite)
                .present()
                .limit_granularity_4kb()
                .dpl(Ring::Ring3)
                .finish(),
            tss_segment: Descriptor64::NULL,
        }
    }
}

/// Sets-up the `EARLY_GDT` for the system to react to faults,
/// interrupts etc. during initialization.
pub unsafe fn setup_early_gdt() {
    EARLY_TSS.set_rsp(x86::Ring::Ring0, EARLY_IRQ_STACK.base() as u64);

    EARLY_GDT = GdtTable::new(&EARLY_TSS);
    EARLY_GDT.install();

    trace!("Early GDT/TSS set");
}
