extern crate cc;
use std::env;

fn main() {
    env::set_var("CC", "gcc");

    // start_ap.S file
    cc::Build::new()
        .flag("-m64")
        .flag("-fno-builtin")
        .flag("-nostdlib")
        .flag("-nostdinc")
        .flag("-U__linux__")
        .flag("-shared")
        .flag("-nostartfiles")
        .flag("-fPIC")
        .file("src/arch/x86_64/start_ap.S")
        .file("src/arch/x86_64/exec.S")
        .pic(true)
        .warnings(true)
        .compile("start_ap");

    // Rumpkernel
    /* println!("cargo:rustc-link-lib=static=rump");
    println!("cargo:rustc-link-lib=static=rumpvfs");
    println!("cargo:rustc-link-lib=static=rumpdev");
    println!("cargo:rustc-link-lib=static=rumpfs_tmpfs");
    println!("cargo:rustc-link-lib=static=rumpnet_config");
    println!("cargo:rustc-link-lib=static=rumpnet");
    println!("cargo:rustc-link-lib=static=rumpdev_bpf");
    println!("cargo:rustc-link-lib=static=rumpdev_vnd");
    println!("cargo:rustc-link-lib=static=rumpdev_rnd");
    //println!("cargo:rustc-link-lib=static=rumprunfs_base");
    println!("cargo:rustc-link-lib=static=rumpnet_netinet");
    println!("cargo:rustc-link-lib=static=rumpnet_net");
    println!("cargo:rustc-link-lib=static=rumpnet_netinet6");
    println!("cargo:rustc-link-lib=static=rumpnet_local");
    println!("cargo:rustc-link-lib=static=rumpfs_ffs");
    println!("cargo:rustc-link-lib=static=rumpfs_cd9660");
    println!("cargo:rustc-link-lib=static=rumpfs_ext2fs");
    println!("cargo:rustc-link-lib=static=rumpdev_disk");
    println!("cargo:rustc-link-lib=static=rumpdev_virtio_if_vioif");
    println!("cargo:rustc-link-lib=static=rumpdev_virtio_ld");
    println!("cargo:rustc-link-lib=static=rumpdev_virtio_viornd");
    println!("cargo:rustc-link-lib=static=rumpdev_pci_virtio");
    println!("cargo:rustc-link-lib=static=rumpdev_pci");
    println!("cargo:rustc-link-lib=static=rumpdev_virtio_vioscsi");
    println!("cargo:rustc-link-lib=static=rumpdev_scsipi");
    println!("cargo:rustc-link-lib=static=rumpdev_audio");
    println!("cargo:rustc-link-lib=static=rumpdev_audio_ac97");
    println!("cargo:rustc-link-lib=static=rumpdev_pci_auich");
    println!("cargo:rustc-link-lib=static=rumpdev_pci_eap");
    println!("cargo:rustc-link-lib=static=rumpdev_pci_hdaudio");
    println!("cargo:rustc-link-lib=static=rumpdev_hdaudio_hdafg");
    println!("cargo:rustc-link-lib=static=rumpdev_pci_if_wm");
    println!("cargo:rustc-link-lib=static=rumpdev_miiphy");
    println!("cargo:rustc-link-lib=static=rumpdev_pci_usbhc");
    println!("cargo:rustc-link-lib=static=rumpdev_usb");
    println!("cargo:rustc-link-lib=static=rumpdev_umass");

    // Linux Kernel:
    println!("cargo:rustc-link-lib=static=linux");*/
}
