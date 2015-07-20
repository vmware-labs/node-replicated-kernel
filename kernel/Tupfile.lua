buildRustKernel{
    target = "kernel",
    rsFile = "main.rs",
    assemblyFiles = { "arch/x86_64/start.S", "arch/x86_64/isr.S", "arch/x86_64/exec.S" },
    addLibraries = { "klogger", "elfloader", "bitflags", "raw_cpuid", "x86", "multiboot", "collections", "slabmalloc", "alloc", "rlib", "core"},
    architecture = {"x86_64"}
}
