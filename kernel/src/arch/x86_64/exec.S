.text
.align 4096

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
    //movq       $0, %rbp
    //movq       $0, %rsp
    sysretq

/// Resumes a process
/// This routine assumes the following set-up
/// %rbx points to SaveArea
/// %r8 points to ss
/// %r9 points to cs
/// %r10 points to rflags
.global resume
resume:
    movabs $CURRENT_PROCESS, %r15
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
    // Get the pointer to the current process
    movabs $CURRENT_PROCESS, %r15
    // Dereference it
    movq (%r15), %r15

    // Save process context
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
    movq %r15, 15*8(%r15)

    // swapgs
    // Prepare kernel stack
    movabs $syscall_stack, %rsp
    movq %rsp, %rbp

    // The architecture saves the user-space RIP
    // in %rcx, but %rcx is also the 4th argument
    // in System V calling conventions, therefore
    // we subsitute %rcx with %r10 when doing system calls
    // and correct our mistake here:
    movq %r10, %rcx

    // Ready to do the system call
    callq syscall_handle

    // Load process pointer (in case we changed it)
    movabs $CURRENT_PROCESS, %r15
    // Dereference it
    movq (%r15), %r15

    // Restore context
    // %rax should contain a return value
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

    // Return from system call
    sysretq

.bss
.align 4096
syscall_stack_base:
    .rept 0x1000 * 60
        .byte 0
    .endr
syscall_stack:

