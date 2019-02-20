fn main() {
    println!("cargo:rustc-link-lib=static=rump");
    //println!("cargo:rustc-link-lib=static=rumpdev_bpf");
    //println!("cargo:rustc-link-lib=static=rumpnet_config");
    //println!("cargo:rustc-link-lib=static=rumpnet_netinet");
    //println!("cargo:rustc-link-lib=static=rumpnet_net");
    println!("cargo:rustc-link-lib=static=rumpnet");
    println!("cargo:rustc-link-lib=static=rumpvfs");
    println!("cargo:rustc-link-lib=static=rumpfs_tmpfs");
    println!("cargo:rustc-link-lib=static=rumpfs_kernfs");
    //println!("cargo:rustc-link-lib=static=rumpfs_null");
}
