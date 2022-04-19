// Copyright © 2021 VMware, Inc. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

fn main() {
    #[cfg(feature = "rumprt")]
    rumprt_dependencies();
}

#[allow(unused)]
fn rumprt_dependencies() {
    let libs = [
        "rump",
        "rumpvfs",
        "rumpdev",
        "rumpfs_tmpfs",
        "rumpnet_config",
        "rumpnet",
        "rumpdev_bpf",
        "rumpdev_vnd",
        "rumpdev_rnd",
        //"rumprunfs_base",
        "rumpnet_netinet",
        "rumpnet_net",
        "rumpnet_netinet6",
        "rumpnet_local",
        "rumpfs_ffs",
        "rumpfs_cd9660",
        "rumpfs_ext2fs",
        "rumpdev_disk",
        "rumpdev_virtio_if_vioif",
        "rumpdev_virtio_ld",
        "rumpdev_virtio_viornd",
        "rumpdev_pci_virtio",
        "rumpdev_pci",
        "rumpdev_virtio_vioscsi",
        "rumpdev_scsipi",
        "rumpdev_audio",
        "rumpdev_audio_ac97",
        "rumpdev_pci_auich",
        "rumpdev_pci_eap",
        "rumpdev_pci_hdaudio",
        "rumpdev_hdaudio_hdafg",
        "rumpdev_pci_if_wm",
        "rumpdev_miiphy",
        "rumpdev_pci_usbhc",
        "rumpdev_usb",
        "rumpdev_umass",
    ];

    for lib in libs {
        println!("cargo:rustc-link-lib=static:+whole-archive={}", lib);
    }
}
