buildRustKernel{
    target = "kernel",
    rsFile = "main.rs",
    assemblyFiles = { "arch/x86_64/start.S", "arch/x86_64/isr.S", "arch/x86_64/exec.S" },
    addLibraries = {"klogger", "elfloader", "bitflags", "x86", "multiboot", "rlib", "core"},
    architecture = {"x86_64"}
}
