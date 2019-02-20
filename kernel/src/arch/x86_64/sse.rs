use x86::controlregs;

// Check for OSFXSR feature flag in cr4
fn has_osfxsr() -> bool {
    let cpuid = x86::cpuid::CpuId::new();
    cpuid
        .get_feature_info()
        .map_or(false, |f| f.has_fxsave_fxstor())
}

// Check for SSE
fn has_sse() -> bool {
    let cpuid = x86::cpuid::CpuId::new();
    cpuid.get_feature_info().map_or(false, |f| f.has_sse())
}

pub fn initialize() {
    if has_osfxsr() && has_sse() {
        // Follow the protocol described in Intel SDM, 13.1.3 Initialization of the SSE Extensions
        unsafe {
            let mut cr4 = controlregs::cr4();
            // Operating system provides facilities for saving and restoring SSE state
            // using FXSAVE and FXRSTOR instructions
            cr4 |= controlregs::Cr4::CR4_ENABLE_SSE;

            // The operating system provides a SIMD floating-point exception (#XM) handler
            //cr4 |= x86::controlregs::Cr4::CR4_UNMASKED_SSE;
            controlregs::cr4_write(cr4);

            let mut cr0 = controlregs::cr0();
            // Disables emulation of the x87 FPU
            cr0 &= !controlregs::Cr0::CR0_EMULATE_COPROCESSOR;

            // Required for Intel 64 and IA-32 processors that support the SSE
            cr0 |= controlregs::Cr0::CR0_MONITOR_COPROCESSOR;
            controlregs::cr0_write(cr0);
        }
    //info!("Enabled SSE support");
    } else {
        warn!("SSE not supported, system probably not very useful");
    }
}
