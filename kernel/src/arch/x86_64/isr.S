.text
.extern handle_generic_exception

.macro isr_handler ex:req err=0
.global isr_handler\ex
isr_handler\ex:
.if  \err
.else
    pushq $0 /* Dummy error code for this type */
.endif
    pushq $\ex
    /* Save state in SaveArea */
    pushq %r15
    swapgs
    movabs $CURRENT_SAVE_AREA, %r15
    movq %rax,  0*8(%r15)
    movq %rbx,  1*8(%r15)
    movq %rcx,  2*8(%r15)
    movq %rdx,  3*8(%r15)
    movq %rsi,  4*8(%r15)
    movq %rdi,  5*8(%r15)
    movq %rbp,  6*8(%r15)
    /*movq %rsp,  7*8(%r15)*/
    movq %r8,   8*8(%r15)
    movq %r9,   9*8(%r15)
    movq %r10, 10*8(%r15)
    movq %r11, 11*8(%r15)
    movq %r12, 12*8(%r15)
    movq %r13, 13*8(%r15)
    movq %r14, 14*8(%r15)

    /* Save original r15, pushed on stack previously */
    movq %r15, %rax
    popq %r15
    movq %r15, 15*8(%rax)
    /* Save the pushed RIP */
    movq 2*8(%rsp), %r15
    movq %r15, 16*8(%rax)

    callq handle_generic_exception
    /* We should not return form here, just in case,
       cause a page-fault to ease debugging */
    movq  $0xdeadf, %rax
    movq (%rax), %rax
isr.loop\ex:
	hlt
	jmp isr.loop\ex
.endm

/* x86 Exceptions */
isr_handler 0
isr_handler 1
isr_handler 2
isr_handler 3
isr_handler 4
isr_handler 5
isr_handler 6
isr_handler 7
isr_handler 8,1
isr_handler 9
isr_handler 10,1
isr_handler 11,1
isr_handler 12,1
isr_handler 13,1
isr_handler 14,1
isr_handler 15

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
