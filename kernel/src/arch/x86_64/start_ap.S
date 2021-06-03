// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#define PROT_MODE_ENABLE 1
#define PROT_CS 0x0018
#define PROT_DS 0x0030
#define LONG_MODE_CS 0x0008

#define X86_64_REAL_MODE_OFFSET 0x0
#define X86_64_REAL_MODE_SEGMENT 0x0600
#define X86_64_REAL_MODE_LINEAR_OFFSET (X86_64_REAL_MODE_SEGMENT << 4)
#define MSR_IA32_EFER 0xc0000080

/* Put this code in the data section because we need to modify parts of it and .text will be read-only */
.att_syntax
.data
.balign 4096
.code16
.org X86_64_REAL_MODE_OFFSET

.global x86_64_start_ap
x86_64_start_ap:
    cli
    mov $X86_64_REAL_MODE_SEGMENT,%ax
    mov %ax,%ds
    mov $(gdt_ptr - x86_64_start_ap),%si
    lgdt (%si)

    mov %cr0,%eax
    or $PROT_MODE_ENABLE,%al
    mov %eax,%cr0

    /* jmp $PROT_CS:start_ap_pm */
    .byte 0x66
    .byte 0xea
    .long start_ap_pm - x86_64_start_ap + X86_64_REAL_MODE_LINEAR_OFFSET
    .word PROT_CS

.code32
start_ap_pm:
    /* set up data segment: Memory loads won't work before that is done! */
    mov $PROT_DS,%eax
    mov %eax,%ds

	/* Set up state for long mode */
	/* Enable: PGE (Page Global Enable), PAE (Physical Address Extension), PSE (Page Size Extensions) */
	mov %cr4, %eax
	or $(0x80|0x20|0x10), %eax
	mov %eax, %cr4

	/* Load PML4 */
	mov $(x86_64_init_ap_init_pml4 - x86_64_start_ap + X86_64_REAL_MODE_LINEAR_OFFSET), %eax
    mov (%eax), %eax
	mov %eax, %cr3

	/* Enable IA-32e mode (also enables SYSCALL and NX) */
	mov $0xC0000080, %ecx
	rdmsr
	or $(1 << 11)|(1 << 8)|(1 << 0), %eax
	wrmsr

	/* Enable paging and enter long mode */
	mov %cr0, %eax
	or $0x80010000, %eax      /* PG & WP */
	mov %eax, %cr0

    /* jmp to long-mode to the linear address corresponding the */
    /* real mode segment REAL_MODE_SEGMENT */
    /* jmp LONG_MODE_CS:start_ap_64 */
    .byte 0xea
    .long start_ap_64 - x86_64_start_ap + X86_64_REAL_MODE_LINEAR_OFFSET
    .word LONG_MODE_CS

/* Start the 64bit long-mode code here */
.code64
start_ap_64:
    /* Initialize the bootup stack for long mode */
    lea (x86_64_init_ap_stack_ptr)(%rip), %rcx
    mov (%rcx),%rsp
    mov %rsp, %rbp

    /* Set up arguments 1 and 2 for entry function */
    mov (x86_64_init_ap_arg1 - x86_64_start_ap + X86_64_REAL_MODE_LINEAR_OFFSET), %rdi
    mov (x86_64_init_ap_lock - x86_64_start_ap + X86_64_REAL_MODE_LINEAR_OFFSET), %rsi

    /*
    Jump to the Rust entry point function for ap init.
    with an the address written into x86_64_init_ap_absolute_entry
    by the coreboot driver. The jump is a jump to an absolute address.
    We find the location of x86_64_init_ap_absolute_entry using
    rip relative addressing.
    */
    lea (x86_64_init_ap_absolute_entry)(%rip),%r10
    mov (%r10),%r10
    call *%r10

/* We should not return here after the call */
loop_ap:
    hlt
    /* Cause a page-fault which will (hopefully) make
       debugging easier if we ever come here */
    //mov $999, %rax
    //mov (%rax), %rax
    jmp loop_ap

.align 16
gdt:
.byte 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
.byte 0xff,0xff,0x00,0x00,0x00,0x9a,0xaf,0x00 // 64bit code segment, D _cleared_ => "16bit"
.byte 0xff,0xff,0x00,0x00,0x00,0x92,0xcf,0x00 // data
.byte 0xff,0xff,0x00,0x00,0x00,0x9a,0xcf,0x00 // 32bit code segment for protected-mode
.byte 0xff,0xff,0x00,0x80,0x0b,0x92,0xff,0x00 // screen
.byte 0xff,0xff,0x00,0x60,0x00,0x9a,0xcf,0x00 // segment at linear address 0x6000
.byte 0xff,0xff,0x00,0x00,0x00,0x92,0xaf,0x00 // stack segment in 64bit mode

gdt_ptr:
.word gdt_ptr - gdt
.long gdt - x86_64_start_ap + X86_64_REAL_MODE_LINEAR_OFFSET
.long 0

.align 8
.global x86_64_init_ap_arg1
x86_64_init_ap_arg1:
.quad 0xbeefbeefbeefbe10

.align 8
.global x86_64_init_ap_arg2
x86_64_init_ap_arg2:
.quad 0xbeefbeefbeefbe20

.align 8
.global x86_64_init_ap_arg3
x86_64_init_ap_arg3:
.quad 0xbeefbeefbeefbe30

.align 8
.global x86_64_init_ap_arg4
x86_64_init_ap_arg4:
.quad 0xbeefbeefbeefbe40

.align 64
.global x86_64_init_ap_stack_ptr
x86_64_init_ap_stack_ptr:
.quad 0xbeefbeefbeefbee5

.align 64
.global x86_64_init_ap_absolute_entry
x86_64_init_ap_absolute_entry:
.long 0xbeefbee3
.long 0xbeefbee4

.align 64
.global x86_64_init_ap_lock
x86_64_init_ap_lock:
.quad 0xbeefbeefbeefbeef

.align 64
.global x86_64_init_ap_init_pml4
x86_64_init_ap_init_pml4:
.quad 0xbeefbeefbeefbee2

.global x86_64_start_ap_end
x86_64_start_ap_end: