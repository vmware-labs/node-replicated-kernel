.text
.extern handle_generic_exception

.macro isr_handler ex:req err=0
.global isr_handler\ex
isr_handler\ex:
.if  \err
.else
    pushq $0                    /* Dummy error code for this type */
.endif
    pushq $\ex
    /* Can we be more efficient here? */
    subq $120, %rsp              /* Make space for 8*15 bytes */
    movq %rax,  0*8(%rsp)
    movq %rcx,  1*8(%rsp)
    movq %rbx,  2*8(%rsp)
    movq %rdx,  3*8(%rsp)
    movq %rsi,  4*8(%rsp)
    movq %rdi,  5*8(%rsp)
    movq %rbp,  6*8(%rsp)
    movq %r8,   7*8(%rsp)
    movq %r9,   8*8(%rsp)
    movq %r10, 9*8(%rsp)
    movq %r11, 10*8(%rsp)
    movq %r12, 11*8(%rsp)
    movq %r13, 12*8(%rsp)
    movq %r14, 13*8(%rsp)
    movq %r15, 14*8(%rsp)
    callq handle_generic_exception
    popq %rax
    popq %rcx
    popq %rbx
    popq %rdx
    popq %rsi
    popq %rdi
    popq %rbp
    popq %r8
    popq %r9
    popq %r10
    popq %r11
    popq %r12
    popq %r13
    popq %r14
    popq %r15
    add $16, %rsp /* Get rid of \ex and dummy error */
    iretq
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
