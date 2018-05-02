/// Goes from kernel to user-space.
/// This routine (sysretq really) expects
/// %rcx program entry point
/// %r11 RFlags
.global exec
exec:
    movq       $0, %rsi
    movq       $0, %rdx
    movq       $0, %r8
    movq       $0, %r9
    movq       $0, %r10
    movq       $0, %r12
    movq       $0, %r13
    movq       $0, %r14
    movq       $0, %r15
    movq       $0, %rax
    movq       $0, %rbx
    movq       $0, %rbp
    movq       $0, %rsp
    sysretq

/// Resumes a process
/// This routine assumes the following set-up
/// %rbx points to SaveArea
/// %r8 points to ss
/// %r9 points to cs
/// %r10 points to rflags
.global resume
resume:
    movq $CURRENT_PROCESS, %r15
    pushq      %r8                 /* ss */
    pushq      7*8(%r15)           /* rsp */
    pushq      %r10                /* rflags */
    pushq      %r9                 /* cs */
    pushq      16*8(%r15)          /* rip */
    /* restore SaveArea */
    movq  0*8(%r15), %rax
    movq  1*8(%r15), %rbx
    movq  2*8(%r15), %rcx
    movq  3*8(%r15), %rdx
    movq  4*8(%r15), %rsi
    movq  5*8(%r15), %rdi
    movq  6*8(%r15), %rbp
    movq  8*8(%r15), %r8
    movq  9*8(%r15), %r9
    movq 10*8(%r15), %r10
    movq 11*8(%r15), %r11
    movq 12*8(%r15), %r12
    movq 13*8(%r15), %r13
    movq 14*8(%r15), %r14
    movq 15*8(%r15), %r15
    iretq


.extern syscall_handle
.global syscall_enter
syscall_enter:
    movq $syscall_stack, %rsp
    callq syscall_handle

syscall_stack_base:
    .rept 0x1000 * 60
        .byte 0
    .endr
syscall_stack: