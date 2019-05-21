.text
.align 4096

// Switch to user-space with initial zeroed registers.
//
// `sysretq` expectations are:
// %rcx Program entry point in Ring 3
// %r11 RFlags
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
    movq       %rsp, %rbp
    sysretq

// Resumes a process
// This routine assumes the following set-up
// %rbx points to SaveArea
// %r8 points to ss
// %r9 points to cs
// %r10 points to rflags
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


// This is the entry point for syscall instruction.
// The architecture knows about it because we loaded
// the address of this symbol into IA32_LSTAR.
// (see syscalls.rs)
.extern syscall_handle
.global syscall_enter
syscall_enter:
    // Get the pointer to the current process
    movabs $CURRENT_PROCESS, %r11
    // Dereference it
    movq (%r11), %r11

    // Save process context
    movq %rax,  0*8(%r11)
    movq %rbx,  1*8(%r11)
    movq %rcx,  2*8(%r11)
    movq %rdx,  3*8(%r11)
    movq %rsi,  4*8(%r11)
    movq %rdi,  5*8(%r11)
    movq %rbp,  6*8(%r11)
    movq %rsp,  7*8(%r11)
    movq %r8,   8*8(%r11)
    movq %r9,   9*8(%r11)
    movq %r10, 10*8(%r11)
    // We don't save %r11 since we
    // use it for CURRENT_PROCESS
    // it's ok since it is a caller-saved
    // register
    movq %r12, 12*8(%r11)
    movq %r13, 13*8(%r11)
    movq %r14, 14*8(%r11)
    movq %r15, 15*8(%r11)
    // fxsave 19*8(%r11)

    // swapgs

    // Prepare kernel stack
    movabs $syscall_stack, %rsp
    movq %rsp, %rbp

    // The syscall instruction saved the user-space RIP
    // in %rcx, but %rcx is also the 4th argument
    // in System V calling conventions, therefore
    // we subsitute %rcx with %r10 when doing
    // system-calls and correct our "mistake" here:
    movq %r10, %rcx

    // Ready to handle the system call (in rust):
    callq syscall_handle

    // Reload the process pointer (in case we changed r11):
    movabs $CURRENT_PROCESS, %r11
    // Dereference it
    movq (%r11), %r11

    // Restore the process context
    // %rax should contain a return value
    // from syscall_handle above
    // (so we don't restore it)
    movq  1*8(%r11), %rbx
    movq  2*8(%r11), %rcx
    movq  3*8(%r11), %rdx
    movq  4*8(%r11), %rsi
    movq  5*8(%r11), %rdi
    movq  6*8(%r11), %rbp
    movq  7*8(%r11), %rsp
    movq  8*8(%r11), %r8
    movq  9*8(%r11), %r9
    movq 10*8(%r11), %r10
    movq 12*8(%r11), %r12
    movq 13*8(%r11), %r13
    movq 14*8(%r11), %r14
    movq 15*8(%r11), %r15
    //fxrstor 19*8(%r11)

    // Clear out %r11 to not leak any information
    movq $0x0, %r11

    // Going back to user-space
    sysretq

.bss
.align 4096
syscall_stack_base:
    .rept 0x1000 * 60
        .byte 0
    .endr
syscall_stack:

