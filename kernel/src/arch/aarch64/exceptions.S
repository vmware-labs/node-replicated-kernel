// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT


/* make the symbold global */
.global __exn_vectors_start, __exn_vectors_end


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

/*
 * ###############################################################################################
 * EXCEPTION VECTOR TABLE
 * ###############################################################################################
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
 *  4) Syncrhonous errors
 *
 * So there are 16 entries in this table, each of which occuping 128B.
 * The table is 2 KiB in size and  needs to be naturally aligned
 *
 */

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
    // Registers x12-x15 are caller saved, so the won't need to be preserved.

    stp x14, x15, [sp, #-(2 * 8)]!
    stp x12, x13, [sp, #-(2 * 8)]!

    // get the kcb
    mrs x12, tpidr_el1

    // get the exception type by reading the esr register
    mrs x14, esr_el1
    // extract bits 26-31 to get the exception class
    ubfx   x13, x14, #26, #6
    // compare with SVC instruction execution in AArch64 state.
    cmp x13, 0b010101
    // branch off to the abort handler
    b.ne  el_lo_aarch64_sync_err

    // save system call context
    b save_syscall_context


/* 0x480 - Lower EL using AArch64  - IRQ / vIRQ */
invalid_exception el_lo_aarch64_irq EXN_AARCH64__LOWER_EL_IRQ

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


.align 7
el_lo_aarch64_sync_err:

    /* store spsr and other information */
    mrs x0, elr_el1
    mrs x1, spsr_el1

    /* Exception Syndrome Register */
    mrs x2, esr_el1

    /* Exception vector */
    mov x3, EXN_AARCH64__LOWER_EL_SYNC

    /* Arguments: x0 = EPC, x1 = SPSR, x2 = ESR, x3 = vector */
    b handle_user_fault

save_syscall_context:
    b handle_syscall

/*
 * ===============================================================================================
 * Exception Return Function used to drop to lower EL
 * ===============================================================================================
 */

.global eret
.type eret, @function

eret:
    eret
