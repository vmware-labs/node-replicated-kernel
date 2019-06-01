.text
.align 4096

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

.extern syscall_handle
.global syscall_enter
syscall_enter:
    // Get the pointer to the current process
    movabs $CURRENT_PROCESS, %rax
    // Dereference it
    movq (%rax), %rax

    // Save process context
    // We don't save %rax since we
    // use it for CURRENT_PROCESS
    // it's ok since it is a caller-saved
    // register
    movq %rbx,  1*8(%rax)
    movq %rcx,  2*8(%rax)
    movq %rdx,  3*8(%rax)
    movq %rsi,  4*8(%rax)
    movq %rdi,  5*8(%rax)
    movq %rbp,  6*8(%rax)
    movq %rsp,  7*8(%rax)
    movq %r8,   8*8(%rax)
    movq %r9,   9*8(%rax)
    movq %r10, 10*8(%rax)
    movq %r11, 11*8(%rax)
    movq %r12, 12*8(%rax)
    movq %r13, 13*8(%rax)
    movq %r14, 14*8(%rax)
    movq %r15, 15*8(%rax)
    // fxsave 19*8(%rax)

    // swapgs

    // Prepare kernel stack
    movabs $syscall_stack, %rsp
    movq %rsp, %rbp

    // The syscall instruction saved the user-space RIP
    // in %rcx, but %rcx is also the 4th argument
    // in System V calling conventions, therefore
    // we substitute %rcx with %r10 when doing
    // system-calls and correct our "mistake" here:
    movq %r10, %rcx

    // Ready to handle the system call (in rust):
    callq syscall_handle

    // Reload the process pointer
    // (we no longer use rax since it now contains our return value):
    movabs $CURRENT_PROCESS, %r10
    // Dereference it
    movq (%r10), %r10

    // Restore the process context
    // %rax should contain a return value
    // from syscall_handle above
    // (so we don't restore it)
    movq  1*8(%r10), %rbx
    movq  2*8(%r10), %rcx
    movq  3*8(%r10), %rdx
    movq  4*8(%r10), %rsi
    movq  5*8(%r10), %rdi
    movq  6*8(%r10), %rbp
    movq  7*8(%r10), %rsp
    movq  8*8(%r10), %r8
    movq  9*8(%r10), %r9
    movq 11*8(%r10), %r11
    movq 12*8(%r10), %r12
    movq 13*8(%r10), %r13
    movq 14*8(%r10), %r14
    movq 15*8(%r10), %r15
    //fxrstor 19*8(%r10)
    // Last one restore r10
    movq 10*8(%r10), %r10

    // Going back to user-space
    // Uses %rcx as address to jump to
    // Uses %r11 to load as RFlags
    sysretq
