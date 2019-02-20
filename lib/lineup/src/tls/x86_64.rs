use x86::bits64::segmentation;

use crate::tls::ThreadLocalStorage;

#[cfg(target_os = "none")]
pub(crate) unsafe fn get_tls<'a>() -> *mut ThreadLocalStorage<'a> {
    segmentation::rdgsbase() as *mut ThreadLocalStorage
}

#[cfg(target_os = "none")]
pub(crate) unsafe fn set_tls(t: *mut ThreadLocalStorage) {
    segmentation::wrgsbase(t as u64)
}

#[test]
fn has_fs_gs_base_instructions() {
    env_logger::init();
    let cpuid = x86::cpuid::CpuId::new();
    assert!(cpuid
        .get_extended_feature_info()
        .map_or(false, |ef| ef.has_fsgsbase()));
    /*debug!("gsbase is {}", unsafe {
        x86::bits64::segmentation::rdgsbase()
    });*/
}
