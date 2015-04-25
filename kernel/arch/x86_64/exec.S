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

