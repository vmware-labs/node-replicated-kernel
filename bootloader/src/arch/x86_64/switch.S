// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

// UEFI uses Windows calling convention:
// ARG1 %rcx
// ARG2 %rdx
// ARG3 %r8

.text
.extern jump_to_kernel
jump_to_kernel: // fn(stack_ptr: u64, kernel_entry: u64, kernel_arg: u64)
    // switch to our new stack
    mov %rcx, %rbp
    mov %rcx, %rsp
    // move the data pointer to the first argument
    // kernel expects sysv64 calling convention so rdi becomes first arg
    mov %r8, %rdi

    // We push 0 as return address in case we do stack backtracing we can
    // abort
    pushq $0

    // absolute jump rather than call to the kernel entry point
    jmp *%rdx
never_return:
	hlt
	jmp never_return
