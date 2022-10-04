// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use armv8::aarch64::registers::{
    CnthctlEl2, Currentel, Daif, ElrEl2, HcrEl2, SctlrEl1, SpEl1, SpsrEl2, Ttbr0El1, Ttbr1El1,
    Ttbr1El2,
};

extern "C" {
    /// Switches from this UEFI bootloader to the kernel init function (passes the sysinfo argument),
    /// kernel stack and kernel address space.
    pub fn eret(a0: u64, a1: u64, a2: u64, a3: u64);
}

/// disable the interrupts
pub fn disable_interrupts() {
    Daif::new()
        .d_insert(1)
        .a_insert(1)
        .i_insert(1)
        .f_insert(1)
        .write();
}

pub fn setup_cpu_features() {
    let el = Currentel::el_read();
    if el != 2 {
        panic!("Unsupported EL");
    }

    /* configure the system control register */
    SctlrEl1::new()
        .uci_insert(1) /* Traps EL0 execution of cache maintenance instructions to EL1 */
        .wxn_insert(1) /* write permissions implies execute never */
        .ntwe_insert(1) /* don't trap WFE instructions to EL1 */
        .ntwi_insert(1) /* don't trap WFI instructions to EL1 */
        .uct_insert(1) /* disable Traps EL0 accesses to the CTR_EL0 to EL1*/
        .dze_insert(1) /* disable Traps EL0 execution of DC ZVA to EL1 */
        .i_insert(1) /* enable instruction cache */
        .uma_insert(0) /* trap DAIF modifictations  */
        .naa_1_insert(0) /* trap non-aligned accesses  */
        .cp15ben_1_insert(1) /* Enables accesses to the DMB, DSB, and ISB System */
        .sa0_insert(1) /* SP Alignment check enable for EL0.  */
        .sa_insert(1) /* SP Alignment check enable.  */
        .c_insert(1) /* enable data cachable */
        .a_insert(1) /* enable alignment checks */
        .m_insert(1) /* enable mmu */
        .write();

    /* configure spsr */
    SpsrEl2::new()
        .d_insert(1) /* disable interrupts */
        .a_insert(1) /* disable interrupts */
        .i_insert(1) /* disable interrupts */
        .f_insert(1) /* disable interrupts */
        .m4_insert(0) /* AArch64 execution state. */
        .m30_insert(0b0101) /* EL1h execution state. */
        .write();

    /* configure EL2 traps */
    HcrEl2::new()
        .miocnce_insert(0) /* Mismatched Inner/Outer Cacheable Non-Coherency Enable */
        .rw_1_insert(1) /* The Execution state for EL1 is AArch64.  */
        .hcd_1_insert(1) /* disable hvc instruction */
        .write();

    /* disable timer traps */
    CnthctlEl2::new()
        .el0pten_insert(1) /* EL1 Physical Timer Control Enable */
        .el0vten_insert(1) /* EL1 Physical Timer Control Enable */
        .el0vcten_insert(1) /* EL1 Physical Timer Control Enable */
        .el0pcten_insert(1) /* EL1 Physical Timer Control Enable */
        .el1pten_insert(1)  /* disable traps EL0 and EL1 accesses to the EL1 physical timer registers */
        .el1pcten_insert(1) /* disable Traps EL0 and EL1 accesses to the EL1 physical counter register */
        .write();
}

pub fn set_translation_table(root: u64) {
    Ttbr1El1::new().baddr471_insert(root >> 1).write();
}

/// Make sure the machine supports what we require.
pub fn assert_required_cpu_features() {
    // TODO: add some checks...
    debug!("CPU has all required features, continue");
}

fn drop_to_el1(stack_ptr: u64, kernel_entry: u64, kernel_arg: u64) {}

///
pub fn jump_to_kernel(stack_ptr: u64, kernel_entry: u64, kernel_arg: u64) {
    /* write the stack pointer for EL1 */
    SpEl1::new().val_insert(stack_ptr).write();

    /* Set the jump target */
    ElrEl2::new().val_insert(kernel_entry).write();

    /* call exception return */
    unsafe {
        eret(kernel_arg, 0, 0, 0);
    }
}
