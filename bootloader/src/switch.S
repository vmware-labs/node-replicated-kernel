// UEFI uses Windows calling convention:
// ARG1 %rcx
// ARG2 %rdx
// ARG3 %r8

.text
.extern jump_to_kernel
jump_to_kernel: // fn(stack_ptr: u64, kernel_entry: u64, kernel_arg: u64)
    //push %rbp
    //mov %rsp, %rbp
    // switch to our new stack
    mov %rcx, %rsp
    mov %rcx, %rbp
    // move the data pointer to the first argument
    // kernel expects sysv64 calling convention so rdi becomes first arg
    mov %r8, %rdi
    // absolute jump to the kernel entry point
    call *%rdx
never_return:
	hlt
	jmp never_return
