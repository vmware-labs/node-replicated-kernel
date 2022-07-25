// Copyright © 2021 VMware, Inc. All Rights Reserved.
// Copyright © 2022 The University of British Columbia. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use x86;

/// disable the interrupts
pub fn disable_interrupts() {
    unsafe {
        x86::irq::disable();
    }
}

pub fn set_translation_table(root: u64) {
    unsafe {
        x86::controlregs::cr3_write(root);
    }
}

pub fn setup_cpu_features() {
    unsafe {
        // Enable cr4 features
        use x86::controlregs::{cr4, cr4_write, Cr4};
        let old_cr4 = cr4();
        let new_cr4 = Cr4::CR4_ENABLE_SMAP
            | Cr4::CR4_ENABLE_SMEP
            | Cr4::CR4_ENABLE_OS_XSAVE
            | Cr4::CR4_ENABLE_FSGSBASE
            | Cr4::CR4_UNMASKED_SSE
            | Cr4::CR4_ENABLE_SSE
            | Cr4::CR4_ENABLE_GLOBAL_PAGES
            | Cr4::CR4_ENABLE_PAE
            | Cr4::CR4_ENABLE_PSE
            | Cr4::CR4_DEBUGGING_EXTENSIONS
            | Cr4::CR4_ENABLE_MACHINE_CHECK;

        cr4_write(new_cr4);
        if !new_cr4.contains(old_cr4) {
            warn!("UEFI has too many CR4 features enabled, so we disabled some: new cr4 {:?}, uefi cr4 was = {:?}", new_cr4, old_cr4);
        }
        debug!("Switched to new page-table.");

        // Enable NXE bit (11)
        use x86::msr::{rdmsr, wrmsr, IA32_EFER};
        let efer = rdmsr(IA32_EFER) | 1 << 11;
        wrmsr(IA32_EFER, efer);
    }
}

/// Make sure the machine supports what we require.
pub fn assert_required_cpu_features() {
    let cpuid = x86::cpuid::CpuId::new();

    let fi = cpuid.get_feature_info();
    let has_xsave = fi.as_ref().map_or(false, |f| f.has_xsave());
    let has_sse = fi.as_ref().map_or(false, |f| f.has_sse());
    let has_apic = fi.as_ref().map_or(false, |f| f.has_apic());
    let has_x2apic = fi.as_ref().map_or(false, |f| f.has_x2apic());
    let has_tsc = fi.as_ref().map_or(false, |f| f.has_tsc());
    let has_pae = fi.as_ref().map_or(false, |f| f.has_pae());
    let has_pse = fi.as_ref().map_or(false, |f| f.has_pse());
    let has_msr = fi.as_ref().map_or(false, |f| f.has_msr());
    let has_sse3 = fi.as_ref().map_or(false, |f| f.has_sse3());
    let has_osfxsr = fi.as_ref().map_or(false, |f| f.has_fxsave_fxstor());

    let efi = cpuid.get_extended_feature_info();
    let has_smap = efi.as_ref().map_or(false, |f| f.has_smap());
    let has_smep = efi.as_ref().map_or(false, |f| f.has_smep());
    let has_fsgsbase = efi.as_ref().map_or(false, |f| f.has_fsgsbase());

    let efni = cpuid.get_extended_processor_and_feature_identifiers();
    let has_1gib_pages = efni.as_ref().map_or(false, |f| f.has_1gib_pages());
    let has_rdtscp = efni.as_ref().map_or(false, |f| f.has_rdtscp());
    let has_syscall_sysret = efni.as_ref().map_or(false, |f| f.has_syscall_sysret());
    let has_execute_disable = efni.as_ref().map_or(false, |f| f.has_execute_disable());

    let apmi = cpuid.get_advanced_power_mgmt_info();
    let has_invariant_tsc = apmi.as_ref().map_or(false, |f| f.has_invariant_tsc());

    assert!(has_sse3);
    assert!(has_osfxsr);
    assert!(has_smap);
    assert!(has_smep);
    assert!(has_xsave);
    assert!(has_fsgsbase);
    assert!(has_sse);
    assert!(has_apic);
    assert!(has_x2apic); // If you fail here it probably means qemu wasn't running with KVM enabled...
    assert!(has_tsc);
    assert!(has_pae);
    assert!(has_pse);
    assert!(has_msr);
    assert!(has_1gib_pages);
    assert!(has_rdtscp);
    assert!(has_syscall_sysret);
    assert!(has_execute_disable);
    assert!(has_invariant_tsc);

    debug!("CPU has all required features, continue");
}
