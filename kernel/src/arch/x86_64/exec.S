// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

.text
.balign 4096

// This is the entry point for syscall instruction.
// The architecture knows about it because we loaded
// the address of this symbol into IA32_LSTAR.
// (see syscalls.rs)
// For SYSCALL, the processor saves RFLAGS into R11 and
// the RIP of the next instruction into RCX
.extern syscall_handle
.global syscall_enter
syscall_enter:
    // Puts address of KCB in %gs and temporarily store user %gs in MSR IA32_KERNEL_GSBASE
    swapgs

    // Get the pointer to the kcb.save_area
    movq %gs:0x8, %rax

    // Save process context:
    // We don't save %rax since we use it to reference the save_area location
    // it's ok since it is a caller-saved register (and used to return the syscall error)
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
    // Save user IP in SaveArea.rip
    movq %rcx, 16*8(%rax)

    // Save vector registers
    fxsave 28*8(%rax)

    // Saves fs register
    rdfsbase %r15
    movq %r15, 19*8(%rax)

    // Write the fs register of the current core
    // (the TLS area is the first member of the KCB and it lives at 0x10(%gs))
    movq %gs:0x10, %r15
    wrfsbase %r15

    // Find the syscall stack of the core (the stack top is the first member
    // of the KCB and it lives at 0x0(%gs)),
    movq %gs:0x0, %rsp
    movq %rsp, %rbp

    // The syscall instruction saved the user-space RIP
    // in %rcx, but %rcx is also the 4th argument
    // in System V calling conventions, therefore
    // we substitute %rcx with %r10 when doing
    // system-calls and correct our "mistake" here:
    movq %r10, %rcx

    // Ready to handle the system call (in rust):
    callq syscall_handle

    // We should not return here form syscall_handle
    // In case we do, cause a page-fault to ease debugging
    movq  $0xdeada, %rax
    movq (%rax), %rax
exec.loop:
	hlt
	jmp exec.loop
