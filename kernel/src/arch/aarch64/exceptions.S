// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT


/* make the symbold global */
.global __exn_vectors_start, __exn_vectors_end, restore_user_context, restore_user_context_from_syscall

// keep in sync with the Aarch64 KCB structure
#define TCB_KERNEL_STACK_OFFSET 16


// Exception types. Keep in sync with the corresponding rust datatype!!

/* undefined exception */
#define EXN_AARCH64__UNDEFINED 0x00

/* current exception level, with EL0 stack */
#define EXN_AARCH64__EL_CURRENT_STACK_EL0_SYNC 0x01
#define EXN_AARCH64__EL_CURRENT_STACK_EL0_IRQ 0x02
#define EXN_AARCH64__EL_CURRENT_STACK_EL0_FIQ 0x03
#define EXN_AARCH64__EL_CURRENT_STACK_EL0_SERROR 0x04

/* current exception level, with own stack */
#define EXN_AARCH64__EL_CURRENT_STACK_CURRENT_SYNC 0x05
#define EXN_AARCH64__EL_CURRENT_STACK_CURRENT_IRQ 0x06
#define EXN_AARCH64__EL_CURRENT_STACK_CURRENT_FIQ 0x07
#define EXN_AARCH64__EL_CURRENT_STACK_CURRENT_SERROR 0x08

/* lower exception level using AARCH64 */
#define EXN_AARCH64__LOWER_EL_SYNC 0x09
#define EXN_AARCH64__LOWER_EL_IRQ 0x0a
#define EXN_AARCH64__LOWER_EL_FIQ 0x0b
#define EXN_AARCH64__LOWER_EL_SERROR 0x0c

/* lower exception level using AARCH32 */
#define EXN_AARCH32__LOWER_EL_SYNC 0x10
#define EXN_AARCH32__LOWER_EL_IRQ 0x11
#define EXN_AARCH32__LOWER_EL_FIQ 0x12
#define EXN_AARCH32__LOWER_EL_SERROR 0x13


////////////////////////////////////////////////////////////////////////////////////////////////////
// Save and Restore Helpers
////////////////////////////////////////////////////////////////////////////////////////////////////

// restores the kernel stack
.macro restore_kernel_stack reg1 reg2
    // restore the kernel stack
    mrs \reg1, tpidr_el1 // get the TCB
    sub \reg1, \reg1, #TCB_KERNEL_STACK_OFFSET  // the kernel stack top is just before the TCB, so subtract 8
    ldr \reg2,  [\reg1]    // read the entry of the kernel stack
    mov sp, \reg2
.endm

// restores the systemcall return values / upcall arguments (x0-x3)
.macro restore_return_arguments savearea
    ldp x2, x3, [\savearea, #(2 * 8)]
    ldp x0, x1, [\savearea, #(0 * 8)]
.endm

// saves the neon registers
.macro save_neon_registers savearea
    stp q0, q1,   [\savearea, #(36 * 8)]
    stp q2, q3,   [\savearea, #(40 * 8)]
    stp q4, q5,   [\savearea, #(44 * 8)]
    stp q6, q7,   [\savearea, #(48 * 8)]
    stp q8, q9,   [\savearea, #(52 * 8)]
    stp q10, q11, [\savearea, #(56 * 8)]
    stp q12, q13, [\savearea, #(60 * 8)]
    stp q14, q15, [\savearea, #(64 * 8)]
    stp q16, q17, [\savearea, #(68 * 8)]
    stp q18, q19, [\savearea, #(72 * 8)]
    stp q20, q21, [\savearea, #(76 * 8)]
    stp q22, q23, [\savearea, #(80 * 8)]
    stp q24, q25, [\savearea, #(84 * 8)]
    stp q26, q27, [\savearea, #(88 * 8)]
    stp q28, q29, [\savearea, #(92 * 8)]
    stp q30, q31, [\savearea, #(96 * 8)]
.endm

// restores the neon registers
.macro restore_neon_registers savearea
    ldp q0, q1,   [\savearea, #(36 * 8)]
    ldp q2, q3,   [\savearea, #(40 * 8)]
    ldp q4, q5,   [\savearea, #(44 * 8)]
    ldp q6, q7,   [\savearea, #(48 * 8)]
    ldp q8, q9,   [\savearea, #(52 * 8)]
    ldp q10, q11, [\savearea, #(56 * 8)]
    ldp q12, q13, [\savearea, #(60 * 8)]
    ldp q14, q15, [\savearea, #(64 * 8)]
    ldp q16, q17, [\savearea, #(68 * 8)]
    ldp q18, q19, [\savearea, #(72 * 8)]
    ldp q20, q21, [\savearea, #(76 * 8)]
    ldp q22, q23, [\savearea, #(80 * 8)]
    ldp q24, q25, [\savearea, #(84 * 8)]
    ldp q26, q27, [\savearea, #(88 * 8)]
    ldp q28, q29, [\savearea, #(92 * 8)]
    ldp q30, q31, [\savearea, #(96 * 8)]
.endm

// saves the callee saved registers (x18-x30)
// r30      LR  The Link Register.
// r29      FP  The Frame Pointer
// r19…r28  Callee-saved registers
// r18      The Platform Register, if needed; otherwise a temporary register. See notes.
.macro save_callee_save_registers savearea
    stp x18, x29, [\savearea, #(18 * 8)]
    stp x20, x21, [\savearea, #(20 * 8)]
    stp x22, x23, [\savearea, #(22 * 8)]
    stp x24, x25, [\savearea, #(24 * 8)]
    stp x26, x27, [\savearea, #(26 * 8)]
    stp x28, x29, [\savearea, #(28 * 8)]
    str x30,      [\savearea, #(30 * 8)]
.endm

// restores the callee saved registers
// r30      LR  The Link Register.
// r29      FP  The Frame Pointer
// r19…r28  Callee-saved registers
// r18      The Platform Register, if needed; otherwise a temporary register. See notes.
.macro restore_callee_save_registers savearea
    ldp x18, x29, [\savearea, #(18 * 8)]
    ldp x20, x21, [\savearea, #(20 * 8)]
    ldp x22, x23, [\savearea, #(22 * 8)]
    ldp x24, x25, [\savearea, #(24 * 8)]
    ldp x26, x27, [\savearea, #(26 * 8)]
    ldp x28, x29, [\savearea, #(28 * 8)]
    ldr x30,      [\savearea, #(30 * 8)]
.endm


// restore the caller saved registers  (x0-x7)
.macro restore_param_result_registers savearea
    ldp  x6,  x7, [\savearea, #(6 * 8)]
    ldp  x4,  x5, [\savearea, #(4 * 8)]
    ldp  x2,  x3, [\savearea, #(2 * 8)]
    ldp  x0,  x1, [\savearea, #(0 * 8)]
.endm

// save the callee saved registers (x0-x7)
.macro save_param_result_registers savearea
    stp  x6,  x7, [\savearea, #(6 * 8)]
    stp  x4,  x5, [\savearea, #(4 * 8)]
    stp  x2,  x3, [\savearea, #(2 * 8)]
    stp  x0,  x1, [\savearea, #(0 * 8)]
.endm


// saves the callee saved registers (sp, pc, spsr, tpidr)
.macro save_context_registers savearea reg1 reg2
    mrs \reg1, sp_el0
    mrs \reg2, elr_el1
    stp \reg1, \reg2, [\savearea, #(31 * 8)]

    mrs \reg1, spsr_el1
    mrs \reg2, tpidr_el0
    stp \reg1, \reg2, [\savearea, #(33 * 8)]
.endm

// saves the callee saved registers (sp, pc, spsr, tpidr)
.macro restore_context_registers savearea reg1 reg2
    ldp \reg1, \reg2, [\savearea, #(31 * 8)]
    msr sp_el0,  \reg1
    msr elr_el1, \reg2

    ldp \reg1, \reg2, [\savearea, #(33 * 8)]
    msr spsr_el1,  \reg1
    msr tpidr_el0, \reg2

.endm


/*
 * This macro branches to the unsupported exception handler
 */
.macro invalid_exception lbl vector
    .align 7
    \lbl:

    /* store spsr and other information */
    mrs x0, elr_el1
    mrs x1, spsr_el1

    /* Exception Syndrome Register */
    mrs x2, esr_el1

    /* Exception vector */
    mov x3, \vector

    /* Arguments: x0 = EPC, x1 = SPSR, x2 = ESR, x3 = vector */
    b exceptions_handle_unsupported
.endm


////////////////////////////////////////////////////////////////////////////////////////////////////
// Exception Vector Table
////////////////////////////////////////////////////////////////////////////////////////////////////

/*
 *
 * there are four exception groups:
 *  1) from the current level, with the EL0 stack
 *  2) from the current level, with our own stack
 *  3) from a lower level, using AArch64
 *  4) from a lower level, using AArch32
 *
 * Each exception group has four different types of exceptions
 *  1) Synchronous exceptions (system calls)
 *  2) Interrupts
 *  3) Fast interupts (higher priority)
 *  4) Synchhonous errors
 *
 * So there are 16 entries in this table, each of which occuping 128B (32 instructions)
 * The table is 2 KiB in size and  needs to be naturally aligned
 *
 */

.align 11
.text
__exn_vectors_start:


/*
 * ==========================================================================
 * Current EL, with EL0 Stack   -   not used
 * ==========================================================================
 */

/* 0x000 - Current EL, SP0 - Synchronous Exception */
invalid_exception el1_sp_el0_sync EXN_AARCH64__EL_CURRENT_STACK_EL0_SYNC

/* 0x080 - Current EL, SP0 - IRQ / vIRQ */
invalid_exception el1_sp_el0_irq EXN_AARCH64__EL_CURRENT_STACK_EL0_IRQ

/* 0x100 - Current EL, SP0 - FIQ / vFIQ */
invalid_exception el1_sp_el0_fiq EXN_AARCH64__EL_CURRENT_STACK_EL0_FIQ

/* 0x180 - Current EL, SP0 - SError / vSError */
invalid_exception el1_sp_el0_serror EXN_AARCH64__EL_CURRENT_STACK_EL0_SERROR


/*
 * ==========================================================================
 * Current EL, with own Stack   -   exceptions from ourselves
 * ==========================================================================
 */

/* 0x200 - Current EL, SPx - Synchronous Exception */
invalid_exception elx_spx_sync EXN_AARCH64__EL_CURRENT_STACK_CURRENT_SYNC

/* 0x280 - Current EL, SPx - IRQ / vIRQ */
invalid_exception elx_spx_irq EXN_AARCH64__EL_CURRENT_STACK_CURRENT_IRQ

/* 0x300 - Current EL, SPx - FIQ / vFIQ */
invalid_exception elx_spx_fiq EXN_AARCH64__EL_CURRENT_STACK_CURRENT_FIQ

/* 0x380 - Current EL, SPx - SError / vSError */
invalid_exception elx_spx_serror EXN_AARCH64__EL_CURRENT_STACK_CURRENT_SERROR


/*
 * ==========================================================================
 * Lower EL using AArch64 - Those are basically SVC calls / IRQ
 * ==========================================================================
 */


/* 0x400 - Lower EL using AArch64  - Synchronous Exception */
.align 7
el_lo_aarch64_sync:
    // disable the interrupts
    msr    daifclr, #3

    // spill a few registers onto the stack.
    // we preserve registers x0-x7 as they will remain and we can access
    // them directly in the syscall hander.
    // Registers x12-x15 are caller saved, so the won't need to be preserved for a syscall.
    stp x12, x13, [sp, #-(2 * 8)]

    // get the save area pointer
    mrs x12, tpidrro_el0

    // 7 instructions, 10 in total up to here.
    save_callee_save_registers x12

    // registers x12, x13, x18-x30 are now available

    // save pc, sp, spsr, tpidr
    // 6 instructions, 16 up to here
    save_context_registers x12, x19, x20

    // get the exception type by reading the esr register
    mrs x13, esr_el1

    // extract bits 26-31 to get the exception class
    ubfx   x19, x13, #26, #6

    // compare with SVC instruction execution in AArch64 state.
    cmp x19, 0b010101

    // if not equal, then this is not an exception
    b.ne  el_lo_aarch64_sync_exn

    // save system call context
    b el_lo_aarch64_sync_syscall


/* 0x480 - Lower EL using AArch64  - IRQ / vIRQ */
.align 7
el_lo_aarch64_irq:
// disable the interrupts
    msr    daifclr, #3

    // spill a few registers onto the stack.
    stp x12, x13, [sp, #-(2 * 8)]

    // get the save area pointer
    mrs x12, tpidrro_el0

    // 7 instructions, 10 in total up to here.
    save_callee_save_registers x12

    // registers x12, x13, x18-x30 are now available

    // save pc, sp, spsr, tpidr
    // 6 instructions, 16 up to here
    save_context_registers x12, x19, x20

    b save_irq_context


/* 0x500 - Lower EL using AArch64  - FIQ / vFIQ */
invalid_exception el_lo_aarch64_fiq EXN_AARCH64__LOWER_EL_FIQ

/* 0x580 - Lower EL using AArch64  - SError / vSError */
invalid_exception el_lo_aarch64_serror EXN_AARCH64__LOWER_EL_SERROR


/*
 * ==========================================================================
 * Lower EL using AArch32   -   not used
 * ==========================================================================
 */

/* 0x600 - Lower EL using AArch32 - Synchronous Exception */
invalid_exception el_lo_aarch32_sync EXN_AARCH32__LOWER_EL_SYNC

/* 0x680 - Lower EL using AArch32  IRQ / vIRQ */
invalid_exception el_lo_aarch32_irq EXN_AARCH32__LOWER_EL_IRQ

/* 0x700 - Lower EL using AArch32 - FIQ / vFIQ */
invalid_exception el_lo_aarch32_fiq EXN_AARCH32__LOWER_EL_FIQ

/* 0x780 - Lower EL using AArch32 - SError / vSError */
invalid_exception el_lo_aarch32_serror EXN_AARCH32__LOWER_EL_SERROR

/* 0x800 - End of Exception Table */
.align 7
__exn_vectors_end:


////////////////////////////////////////////////////////////////////////////////////////////////////
// Saving and Restoring System Call Context
////////////////////////////////////////////////////////////////////////////////////////////////////

/// saves the context for the system call
///
/// x12 = save area pointer
/// callee and contxt registers saved
el_lo_aarch64_sync_syscall:
    // we only need to save the neon registers for the system call
    save_neon_registers x12

    b handle_syscall
// end el_lo_aarch64_sync_syscall

// void restore_user_context_from_syscall(struct savearea *x0)
restore_user_context_from_syscall:

    // set the save area
    // msr tpidrro_el0, x0

    restore_kernel_stack x9 x10

    // restore floating point registers
    restore_neon_registers x0

    // restore pc, sp, spsr, tpidr
    restore_context_registers x0, x19, x20

    // Callee-saved registers
    restore_callee_save_registers x0

    // the other registers are caller saved, so we don't need to restore them

    // the system call return values
    restore_return_arguments x0
    dmb sy

    // return to the caller
    eret
// end restore_user_context_from_syscall


////////////////////////////////////////////////////////////////////////////////////////////////////
// Userfaults / Exceptions
////////////////////////////////////////////////////////////////////////////////////////////////////

/// saves the context for the exception call
///
/// x12 = save area pointer
/// callee and contxt registers saved
//// x12, 13 on the stack
el_lo_aarch64_sync_exn:

    // save the neon registers
    save_neon_registers x12

    // restore x12 and x13 that were spilled onto the stack
    // and store them in the proper location
    ldp x18, x19, [sp, #-(2 * 8)]
    stp x18, x19, [x12, #(12 * 8)]

    // save remaining registers
    stp x16, x17, [x12, #(16 * 8)]
    stp x14, x15, [x12, #(14 * 8)]
    // x12 and x13 are already saved
    stp x10, x11, [x12, #(10 * 8)]
    stp  x8,  x9, [x12, #(8 * 8)]
    stp  x6,  x7, [x12, #(6 * 8)]
    stp  x4,  x5, [x12, #(4 * 8)]
    stp  x2,  x3, [x12, #(2 * 8)]
    stp  x0,  x1, [x12, #(0 * 8)]

    /* store spsr and other information */
    mrs x0, elr_el1
    mrs x1, spsr_el1
    mrs x2, esr_el1
    mrs x3, far_el1

    /* Arguments: x0 = EPC, x1 = SPSR, x2 = ESR, x3 = far */
    b handle_user_fault
// end el_lo_aarch64_sync_err


////////////////////////////////////////////////////////////////////////////////////////////////////
// IRQ
////////////////////////////////////////////////////////////////////////////////////////////////////

/// saves the context for the interrupt call
///
/// x12 = save area pointer
/// callee and contxt registers saved
//// x12, 13 on the stack
save_irq_context:
    // save the neon registers
    save_neon_registers x12

    // restore x12 and x13 that were spilled onto the stack
    // and store them in the proper location
    ldp x18, x19, [sp, #-(2 * 8)]
    stp x18, x19, [x12, #(12 * 8)]

    // save remaining registers
    stp x16, x17, [x12, #(16 * 8)]
    stp x14, x15, [x12, #(14 * 8)]
    // x12 and x13 are already saved
    stp x10, x11, [x12, #(10 * 8)]
    stp  x8,  x9, [x12, #(8 * 8)]
    stp  x6,  x7, [x12, #(6 * 8)]
    stp  x4,  x5, [x12, #(4 * 8)]
    stp  x2,  x3, [x12, #(2 * 8)]
    stp  x0,  x1, [x12, #(0 * 8)]

    b handle_interrupt
// end save_irq_context


////////////////////////////////////////////////////////////////////////////////////////////////////
// Saving and restoring full user-space contexts
////////////////////////////////////////////////////////////////////////////////////////////////////

// restore the full context as saved from user space
//
// void restore_user_context(struct savearea *x0)
restore_user_context:
    // restore the kernel stack, using registers x9 and x10
    restore_kernel_stack x9 x10

    // set the save area
    // msr tpidrro_el0, x0

    // restore floating point registers
    restore_neon_registers x0

    // restore pc, sp, spsr, tpidr
    restore_context_registers x0, x19, x20

    // restore the general purpse registers
    ldr x30, [x0, #(30 * 8)]
    ldp x28, x29, [x0, #(28 * 8)]
    ldp x26, x27, [x0, #(26 * 8)]
    ldp x24, x25, [x0, #(24 * 8)]
    ldp x22, x23, [x0, #(22 * 8)]
    ldp x20, x21, [x0, #(20 * 8)]
    ldp x18, x19, [x0, #(18 * 8)]
    ldp x16, x17, [x0, #(16 * 8)]
    ldp x14, x15, [x0, #(14 * 8)]
    ldp x12, x13, [x0, #(12 * 8)]
    ldp x10, x11, [x0, #(10 * 8)]
    ldp  x8,  x9, [x0, #(8 * 8)]
    ldp  x6,  x7, [x0, #(6 * 8)]
    ldp  x4,  x5, [x0, #(4 * 8)]
    ldp  x2,  x3, [x0, #(2 * 8)]
    ldp  x0,  x1, [x0, #(0 * 8)]

    // go to user space
    eret
// restore_context_full