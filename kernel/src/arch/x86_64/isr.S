.text
.extern handle_generic_exception

/**
 * Generates isr_handler${num} service routines that save the context in
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
    swapgs

    // Get the pointer to the kcb.save_area
    rdgsbase %rax
    movq 0x8(%rax), %rax

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

    // Save %rsp of interrupted process
    movq 5*8(%rsp), %r15
    movq %r15, 7*8(%rax)

    // Save RIP were we were at before we got interrupted
    // This is at rsp+16 (put there by the hardware):
    movq 2*8(%rsp), %r15
    movq %r15, 16*8(%rax)

    // Save RFLAGS of interrupted process
    movq 4*8(%rsp), %r15
    movq %r15, 17*8(%rax)

    // Saves the fs register
    rdfsbase %r15
    movq %r15, 19*8(%rax)

    // Save vector registers
    fxsave 24*8(%rax)

    callq handle_generic_exception

    // We should not return form handle_generic_exception.
    // In case we do, cause a page-fault to ease debugging
    movq  (0xdeadf), %rax

isr.loop\ex:
	hlt
	jmp isr.loop\ex
.endm

/**
 * Generates isr_handler_early${num} service routines that save the vector
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

/* The APIC timer interrupt */
isr_handler 252
