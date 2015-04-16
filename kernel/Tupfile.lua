buildRustKernel{
    target = "kernel",
    rsFile = "main.rs",
    assemblyFiles = { "arch/x86_64/start.S", "arch/x86_64/isr.S" },
    addLibraries = {"klogger", "elfloader", "bitflags", "x86", "multiboot", "raw_cpuid", "rlib", "core"},
    architecture = {"x86_64"}
}

