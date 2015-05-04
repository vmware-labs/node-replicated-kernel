use core::mem::{transmute, size_of};
use core::fmt;

use x86::segmentation::*;
use x86::dtables::*;
use x86::task::*;

use super::syscall;

const NULL_INDEX: usize = 0;
const CS_KERNEL_INDEX: usize = 1;
const SS_KERNEL_INDEX: usize = 2;
const SS_USER_INDEX: usize = 3;
const CS_USER_INDEX: usize = 4;

const TSS_LOW_INDEX: usize = 5;
const TSS_HIGH_INDEX: usize = 6;

const LDT_LOW_INDEX: usize = 7;
const LDT_HIGH_INDEX: usize = 8;

const GDT_SIZE: usize = 512;

#[no_mangle]
static mut gdt: [u64; GDT_SIZE] = [0; GDT_SIZE ];

pub fn get_user_code_selector() -> SegmentSelector {
    SegmentSelector::new(CS_USER_INDEX as u16) | RPL_3 | TI_GDT
}

pub fn get_user_stack_selector() -> SegmentSelector {
    SegmentSelector::new(SS_USER_INDEX as u16) | RPL_3 | TI_GDT
}

#[no_mangle]
static mut tss: TaskStateSegment = TaskStateSegment{
    reserved: 0,
    rsp: [0,0,0],
    reserved2: 0,
    ist: [0,0,0,0,0,0,0],
    reserved3: 0,
    reserved4: 0,
    iomap_base: 0,
};

pub fn set_up_gdt() {
    // 64 bit code
    let cs = DESC_P | DESC_L | DESC_S | DESC_DPL0 | TYPE_C_ER;
    // 64 bit stack
    let ss = SegmentDescriptor::new(0,0) | DESC_P | DESC_L | DESC_S | DESC_DPL0 | TYPE_D_RW;
    // 64 bit user code
    let cs_user = cs | DESC_DPL3;
    // 64 bit user stack
    let ss_user = ss | DESC_DPL3;

    // Put these in our new GDT, load the new GDT, then re-load the segments
    unsafe {
        gdt[NULL_INDEX] = SegmentDescriptor::new(0,0).bits();
        gdt[CS_KERNEL_INDEX] = cs.bits();
        gdt[SS_KERNEL_INDEX] = ss.bits();
        gdt[CS_USER_INDEX] = cs_user.bits();
        gdt[SS_USER_INDEX] = ss_user.bits();

        let gdtptr = DescriptorTablePointer {
            limit: ((size_of::<u64>() * GDT_SIZE) - 1) as u16,
            base: transmute::<&[u64; GDT_SIZE], u64>(&gdt)
        };
        lgdt(&gdtptr);

        // We need to re-load segments now with a new GDT:
        let cs_selector = SegmentSelector::new(CS_KERNEL_INDEX as u16) | RPL_0 | TI_GDT;
        let ss_selector = SegmentSelector::new(SS_KERNEL_INDEX as u16) | RPL_0 | TI_GDT;

        load_ds(SegmentSelector::new(0));
        load_es(SegmentSelector::new(0));
        load_fs(SegmentSelector::new(0));
        load_gs(SegmentSelector::new(0));
        load_cs(cs_selector);
        load_ss(ss_selector);

        //let cs_user_selector = SegmentSelector::new(CS_USER_INDEX as u16) | RPL_3 | TI_GDT;
        //syscall::enable_fast_syscalls(cs_selector, cs_user_selector);
    }

    log!("Segments reloaded");
    set_up_tss();
    log!("TSS enabled");

}

static mut syscall_stack: [u64; 512] = [0; 512];

pub fn set_up_tss() {
    unsafe {
        // Complete setup of TSS descriptor (by inserting base address of TSS)
        let tss_ptr = transmute::<&TaskStateSegment, u64>(&tss);
        let tss_low_base = transmute::<&TaskStateSegment, u64>(&tss) as u32;
        let tss_high_base = transmute::<&TaskStateSegment, u64>(&tss) >> 32;

        log!("tss = 0x{:x}", tss_ptr);
        log!("tss_low = 0x{:x}", SegmentDescriptor::new(tss_low_base, 0).bits());
        log!("tss_high_base = 0x{:x}", tss_high_base);
        gdt[TSS_LOW_INDEX] = (SegmentDescriptor::new(tss_low_base, size_of::<TaskStateSegment>() as u32) | DESC_P | TYPE_SYS_TSS_AVAILABLE | DESC_DPL0).bits();
        gdt[TSS_HIGH_INDEX] = tss_high_base;

        tss.rsp[0] = transmute::<&[u64; 512], u64>(&syscall_stack) + 4096;
        log!("tss.rsp[0] = 0x{:x}", tss.rsp[0]);

        load_ltr(SegmentSelector::new(TSS_LOW_INDEX as u16) | RPL_0 | TI_GDT );
    }

}