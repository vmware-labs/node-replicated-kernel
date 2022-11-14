// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

pub fn sp() -> u64 {
    x86::bits64::registers::rsp()
}

/// Resume a `state` that was saved by the kernel on a trap or interrupt.
pub unsafe fn resume(control: &mut kpi::arch::VirtualCpu) -> ! {
    // Enable upcalls (Note: we will remain disabled while the instruction pointer
    // is in this function (i.e., between the `resume` and `resume_end`
    // symbol (see asm! below))
    control.enable_upcalls();
    //debug!("resume enabled_state {:p}", &control.enabled_state);

    const CS_OFF: usize = 27;
    const SS_OFF: usize = 35;
    asm!("
            // Restore the gs register
            //movq 18*8(%rsi), %rdi
            //wrgsbase %rdi

            // Restore the fs register
            movq {fs_offset}(%rsi), %rdi
            wrfsbase %rdi

            // Restore vector registers
            fxrstor {fxsave_offset}(%rsi)

            // Restore CPU registers
            movq  {rax_offset}(%rsi), %rax
            movq  {rbx_offset}(%rsi), %rbx
            movq  {rcx_offset}(%rsi), %rcx
            movq  {rdx_offset}(%rsi), %rdx
            // %rsi: Restore last (see below) to preserve `save_area`
            movq  {rdi_offset}(%rsi), %rdi
            movq  {rbp_offset}(%rsi), %rbp
            // %rsp: Restored through iretq at the end
            movq  {r8_offset}(%rsi), %r8
            movq  {r9_offset}(%rsi), %r9
            movq {r10_offset}(%rsi), %r10
            movq {r11_offset}(%rsi), %r11
            movq {r12_offset}(%rsi), %r12
            movq {r13_offset}(%rsi), %r13
            movq {r14_offset}(%rsi), %r14
            movq {r15_offset}(%rsi), %r15

            //
            // Set-up stack to return from interrupt
            //

            // SS
            pushq ${ss}
            // %rsp register
            pushq {rsp_offset}(%rsi)
            // rflags register
            pushq {rflags_offset}(%rsi)
            // cs register
            pushq ${cs}
            // %rip
            pushq {rip_offset}(%rsi)

            // Restore rsi register last, since it was used to reach `state`
            movq {rsi_offset}(%rsi), %rsi
            iretq
        ",
        rax_offset = const SaveArea::RAX_OFFSET,
        rbx_offset = const SaveArea::RBX_OFFSET,
        rcx_offset = const SaveArea::RCX_OFFSET,
        rdx_offset = const SaveArea::RDX_OFFSET,
        rsi_offset = const SaveArea::RSI_OFFSET,
        rdi_offset = const SaveArea::RDI_OFFSET,
        rbp_offset = const SaveArea::RBP_OFFSET,
        rsp_offset = const SaveArea::RSP_OFFSET,
        r8_offset = const SaveArea::R8_OFFSET,
        r9_offset = const SaveArea::R9_OFFSET,
        r10_offset = const SaveArea::R10_OFFSET,
        r11_offset = const SaveArea::R11_OFFSET,
        r12_offset = const SaveArea::R12_OFFSET,
        r13_offset = const SaveArea::R13_OFFSET,
        r14_offset = const SaveArea::R14_OFFSET,
        r15_offset = const SaveArea::R15_OFFSET,
        rip_offset = const SaveArea::RIP_OFFSET,
        rflags_offset = const SaveArea::RFLAGS_OFFSET,
        fs_offset = const SaveArea::FS_OFFSET,
        fxsave_offset = const SaveArea::FXSAVE_OFFSET,
        cs = const CS_OFF,
        ss = const SS_OFF,
        in("rsi") &control.enabled_state,
        options(att_syntax, noreturn)
    );
}

/// Well, let's just hope the assembler continues to put this immediatly after
/// `resume()` in the binary...
#[no_mangle]
pub unsafe fn resume_end() {
    unreachable!("resume_end")
}
