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
    /* XXX: push to stack, only CPL=0! */
    subq $16*8, %rsp              /* Make space for 16 registers */
    movq %rax,  0*8(%rsp)
    movq %rbx,  1*8(%rsp)
    movq %rcx,  2*8(%rsp)
    movq %rdx,  3*8(%rsp)
    movq %rsi,  4*8(%rsp)
    movq %rdi,  5*8(%rsp)
    movq %rbp,  6*8(%rsp)
    movq %rsp,  7*8(%rsp)
    movq %r8,   8*8(%rsp)
    movq %r9,   9*8(%rsp)
    movq %r10, 10*8(%rsp)
    movq %r11, 11*8(%rsp)
    movq %r12, 12*8(%rsp)
    movq %r13, 13*8(%rsp)
    movq %r14, 14*8(%rsp)
    movq %r15, 15*8(%rsp)

    pushq %r15
    movq $current_process, %r15
    movq %rax,  0*8(%r15)
    movq %rbx,  1*8(%r15)
    movq %rcx,  2*8(%r15)
    movq %rdx,  3*8(%r15)
    movq %rsi,  4*8(%r15)
    movq %rdi,  5*8(%r15)
    movq %rbp,  6*8(%r15)
    movq %rsp,  7*8(%r15)
    movq %r8,   8*8(%r15)
    movq %r9,   9*8(%r15)
    movq %r10, 10*8(%r15)
    movq %r11, 11*8(%r15)
    movq %r12, 12*8(%r15)
    movq %r13, 13*8(%r15)
    movq %r14, 14*8(%r15)
    movq %r15, %rax
    popq %r15
    movq %r15, 15*8(%rsp)

    callq handle_generic_exception
    /* XXX: pop from stack, only if CPL=0 */
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
    /* Get stuff from process save area */
    movq $current_process, %r15
    movq  0*8(%r15), %rax
    movq  1*8(%r15), %rbx
    movq  2*8(%r15), %rcx
    movq  3*8(%r15), %rdx
    movq  4*8(%r15), %rsi
    movq  5*8(%r15), %rdi
    movq  6*8(%r15), %rbp
    movq  7*8(%r15), %rsp
    movq  8*8(%r15), %r8
    movq  9*8(%r15), %r9
    movq 10*8(%r15), %r10
    movq 11*8(%r15), %r11
    movq 12*8(%r15), %r12
    movq 13*8(%r15), %r13
    movq 14*8(%r15), %r14
    movq 15*8(%r15), %r15

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
