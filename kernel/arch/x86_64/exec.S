/// Goes from kernel to user-space.
/// This routine expects program entry point in %rcx
/// and RFlags in %r11
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
resume:
    pushq      %r8                  /* ss */
    pushq       7*8(%rbx)           /* rip */
    pushq      %r10                 /* rflags */
    pushq      %r9                  /* cs */
    pushq      16*8(%rbx)
    movq        0*8(%rbx), %rax
    movq        2*8(%rbx), %rcx
    movq        3*8(%rbx), %rdx
    movq        4*8(%rbx), %rsi
    movq        5*8(%rbx), %rdi
    movq        6*8(%rbx), %rbp
    movq        8*8(%rbx), %r8
    movq        9*8(%rbx), %r9
    movq       10*8(%rbx), %r10
    movq       11*8(%rbx), %r11
    movq       12*8(%rbx), %r12
    movq       13*8(%rbx), %r13
    movq       14*8(%rbx), %r14
    movq       15*8(%rbx), %r15
    movq        1*8(%rbx), %rbx     /* rbx was SaveArea */
    iretq
