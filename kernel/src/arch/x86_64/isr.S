// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

.text
.extern handle_generic_exception

/**
 * Generates isr_handlerXX service routines that save the context in
 * the KCB and then call `handle_generic_exception`.
 *
 * This routine excepts that an initialized KCB is installed in the
 * IA32_KERNEL_GSBASE MSR.
 **/
.macro isr_handler ex:req err=0
.global isr_handler\ex
isr_handler\ex:
.if  \err
.else
    pushq $0 /* Dummy error code for this type */
.endif
    // Push exception code on the stack
    pushq $\ex
    // Save original temporarily %rax on the stack because we will overwrite it to
    // hold a reference to the KCB
    pushq %rax

    // Puts address of the KCB in %gs and temporarily store user
    // %gs in MSR IA32_KERNEL_GSBASE
    movq 0x20(%rsp),%rax
    cmpq $0x8,%rax
    je in_kernel\ex
    swapgs

in_kernel\ex:
    // Get the pointer to the kcb.save_area
    movq %gs:0x8, %rax

    // Save process register context
    // We don't save %rax yet since we use it to
    // reference the save_area location
    movq %rbx,  1*8(%rax)
    movq %rcx,  2*8(%rax)
    movq %rdx,  3*8(%rax)
    movq %rsi,  4*8(%rax)
    movq %rdi,  5*8(%rax)
    movq %rbp,  6*8(%rax)
    // We don't save %rsp yet since it is overridden by CPU on irq entry
    movq %r8,   8*8(%rax)
    movq %r9,   9*8(%rax)
    movq %r10, 10*8(%rax)
    movq %r11, 11*8(%rax)
    movq %r12, 12*8(%rax)
    movq %r13, 13*8(%rax)
    movq %r14, 14*8(%rax)
    movq %r15, 15*8(%rax)

    // Save original rax, which we pushed on the stack previously
    popq %r15
    movq %r15, 0*8(%rax)

    // Save `ExceptionArguments` in `save_area` too,
    // not everything is technically needed (except for RIP, RSP)
    // but the rest this is useful during gdb debugging.
    //
    // ExceptionArguments/rsp looks like this:
    //
    // at 00(rsp) => vector (pos 20)
    // at 08(rsp) => exception (pos 21)
    // at 16(rsp) => rip (pos 16)
    // at 24(rsp) => cs (pos 22)
    // at 32(rsp) => rflags (pos 17)
    // at 40(rsp) => rsp (pos 7)
    // at 48(rsp) => ss (pos 23)

    // Save vector of interrupt
    movq 0*8(%rsp), %r15
    movq %r15, 20*8(%rax)

    // Save exception of interrupt
    movq 1*8(%rsp), %r15
    movq %r15, 21*8(%rax)

    // Save RIP were we were at before we got interrupted
    movq 2*8(%rsp), %r15
    movq %r15, 16*8(%rax)

    // Save cs before we got interrupted
    movq 3*8(%rsp), %r15
    movq %r15, 22*8(%rax)

    // Save RFLAGS of interrupted process
    movq 4*8(%rsp), %r15
    movq %r15, 17*8(%rax)

    // Save %rsp of interrupted process
    movq 5*8(%rsp), %r15
    movq %r15, 7*8(%rax)

    // Save ss before we got interrupted
    movq 6*8(%rsp), %r15
    movq %r15, 23*8(%rax)

    // Saves the fs register
    rdfsbase %r15
    movq %r15, 19*8(%rax)

    // Write the fs register of the current core
    // (the TLS area is the first member of the KCB and it lives at 0x10(%gs))
    movq %gs:0x10, %r15
    wrfsbase %r15

    // Save vector registers
    fxsave 28*8(%rax)

    // Ensure 16-byte stack pointer alignment
    // `reserved` in `ExceptionArguments`
    pushq $0x0
    callq handle_generic_exception

    // We should not return from `handle_generic_exception`.
    // In case we do, cause a page-fault to ease debugging
    movq  (0xdeadf), %rax

isr.loop\ex:
	hlt
	jmp isr.loop\ex
.endm

/**
 * Generates isr_handler_earlyXX service routines that save the vector
 * number on the stack then call `handle_generic_exception_early`.
 *
 * Minimal OS setup (i.e., just an IDT and interrupt stack) is required
 * for this to work.
 **/
.macro isr_handler_early ex:req err=0
.global isr_handler_early\ex
isr_handler_early\ex:
.if  \err
.else
    pushq $0 /* Dummy error code for this type */
.endif
    // Push exception code on the stack
    pushq $\ex
    // Ensure 16-byte stack pointer alignment
    // `reserved` in `ExceptionArguments`
    pushq $0x0
    callq handle_generic_exception_early

    // We should not return form handle_generic_exception.
    // In case we do, cause a page-fault to ease debugging
    movq  (0xdeada), %rax

isr_early.loop\ex:
	hlt
	jmp isr_early.loop\ex
.endm

/* x86 Exceptions, early handlers */
isr_handler_early 0
isr_handler_early 1
isr_handler_early 2
isr_handler_early 3
isr_handler_early 4
isr_handler_early 5
isr_handler_early 6
isr_handler_early 7
isr_handler_early 8,1
isr_handler_early 9
isr_handler_early 10,1
isr_handler_early 11,1
isr_handler_early 12,1
isr_handler_early 13,1
isr_handler_early 14,1
/* 15: Reserved */
isr_handler_early 16
isr_handler_early 17,1
isr_handler_early 18
isr_handler_early 19
isr_handler_early 20
/* 21-29: Reserved */
isr_handler_early 30,1
/* 31: Reserved */
isr_handler_early 250
isr_handler_early 251
isr_handler_early 252

/* x86 Exceptions */
isr_handler 0
isr_handler 1
isr_handler 2
isr_handler 3
isr_handler 4
isr_handler 5
isr_handler 6
isr_handler 7
/* Double-fault is always going to isr_handler_early8 */
isr_handler 9
isr_handler 10,1
isr_handler 11,1
isr_handler 12,1
isr_handler 13,1
isr_handler 14,1
/* 15: Reserved */
isr_handler 16
isr_handler 17,1
/* Machine check is always going to isr_handler_early18 */
isr_handler 19
isr_handler 20
/* 21-29: Reserved */
isr_handler 30,1
/* 31: Reserved */

/* Classic PIC interrupts */
isr_handler 32
isr_handler 33
isr_handler 34
isr_handler 35
isr_handler 36
isr_handler 37
isr_handler 38
isr_handler 39
isr_handler 40
isr_handler 41
isr_handler 42
isr_handler 43
isr_handler 44
isr_handler 45
isr_handler 46
isr_handler 47

/* remote TLB work interrupt, used in rackscale build*/
isr_handler 249

/* The MLNR gc interrupt */
isr_handler 250
/* TLB work-queue trigger IPI */
isr_handler 251

/* The APIC timer interrupt */
isr_handler 252
