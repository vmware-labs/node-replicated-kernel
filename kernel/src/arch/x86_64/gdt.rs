use core::mem::{size_of, transmute};

use x86::bits64::segmentation::{load_cs, Descriptor64};
use x86::bits64::task::*;
use x86::dtables::*;
use x86::segmentation::*;
use x86::task::load_tr;
use x86::Ring;

use super::syscall;

#[derive(Default)]
#[repr(packed)]
struct GdtTable {
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
    const NULL_INDEX: usize = 0;
    const CS_KERNEL_INDEX: usize = 1;
    const SS_KERNEL_INDEX: usize = 2;
    const SS_USER_INDEX: usize = 3;
    const CS_USER_INDEX: usize = 4;
    const TSS_INDEX: usize = 5;
}

static mut GDT: GdtTable = GdtTable {
    null: Descriptor::NULL,
    code_kernel: Descriptor::NULL,
    stack_kernel: Descriptor::NULL,
    code_user: Descriptor::NULL,
    stack_user: Descriptor::NULL,
    tss_segment: Descriptor64::NULL,
};

pub fn get_user_code_selector() -> SegmentSelector {
    SegmentSelector::new(GdtTable::CS_USER_INDEX as u16, Ring::Ring3) | SegmentSelector::TI_GDT
}

pub fn get_user_stack_selector() -> SegmentSelector {
    SegmentSelector::new(GdtTable::SS_USER_INDEX as u16, Ring::Ring3) | SegmentSelector::TI_GDT
}

static mut TSS: TaskStateSegment = TaskStateSegment {
    reserved: 0,
    rsp: [0, 0, 0],
    reserved2: 0,
    ist: [0, 0, 0, 0, 0, 0, 0],
    reserved3: 0,
    reserved4: 0,
    iomap_base: 0,
};

pub fn setup_gdt() {
    // Put these in our new GDT, load the new GDT, then re-load the segments
    unsafe {
        GDT.null = Default::default();
        GDT.code_kernel = DescriptorBuilder::code_descriptor(0, 0, CodeSegmentType::ExecuteRead)
            .present()
            .dpl(Ring::Ring0)
            .limit_granularity_4kb()
            .l()
            .finish();
        GDT.stack_kernel = DescriptorBuilder::data_descriptor(0, 0, DataSegmentType::ReadWrite)
            .present()
            .dpl(Ring::Ring0)
            .limit_granularity_4kb()
            .finish();
        GDT.code_user = DescriptorBuilder::code_descriptor(0, 0, CodeSegmentType::ExecuteRead)
            .present()
            .limit_granularity_4kb()
            .l()
            .dpl(Ring::Ring3)
            .finish();
        GDT.stack_user = DescriptorBuilder::data_descriptor(0, 0, DataSegmentType::ReadWrite)
            .present()
            .limit_granularity_4kb()
            .dpl(Ring::Ring3)
            .finish();

        let gdtptr = DescriptorTablePointer::new(&GDT);
        lgdt(&gdtptr);

        // We need to re-load segments now with a new GDT:
        let cs_selector = SegmentSelector::new(GdtTable::CS_KERNEL_INDEX as u16, Ring::Ring0)
            | SegmentSelector::TI_GDT;
        let ss_selector = SegmentSelector::new(GdtTable::SS_KERNEL_INDEX as u16, Ring::Ring0)
            | SegmentSelector::TI_GDT;

        load_ds(SegmentSelector::new(0, Ring::Ring0));
        load_es(SegmentSelector::new(0, Ring::Ring0));
        load_fs(SegmentSelector::new(0, Ring::Ring0));
        load_gs(SegmentSelector::new(0, Ring::Ring0));
        load_cs(cs_selector);
        load_ss(ss_selector);

        let cs_user_selector = SegmentSelector::new(GdtTable::CS_USER_INDEX as u16, Ring::Ring3)
            | SegmentSelector::TI_GDT;
        syscall::enable_fast_syscalls(cs_selector, cs_user_selector);
    }

    slog!("Segments reloaded");
    setup_tss();
    slog!("TSS enabled");
}

static mut SYSCALL_STACK: [u64; 512] = [0; 512];

fn setup_tss() {
    unsafe {
        // Complete setup of TSS descriptor (by inserting base address of TSS)
        let tss_ptr = transmute::<&TaskStateSegment, u64>(&TSS);
        slog!("tss = 0x{:x}", tss_ptr);

        GDT.tss_segment = <DescriptorBuilder as GateDescriptorBuilder<u64>>::tss_descriptor(
            tss_ptr as u64,
            size_of::<TaskStateSegment>() as u64,
            true,
        ).present()
            .dpl(Ring::Ring0)
            .finish();
        TSS.rsp[0] = transmute::<&[u64; 512], u64>(&SYSCALL_STACK) + 4096;
        slog!("tss.rsp[0] = 0x{:x}", TSS.rsp[0]);

        load_tr(
            SegmentSelector::new(GdtTable::TSS_INDEX as u16, Ring::Ring0) | SegmentSelector::TI_GDT,
        );
    }
}
