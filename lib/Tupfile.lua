buildCoreLibrary{
    target = "core",
    rsFile = "core/lib.rs"
}

buildRustLibrary{
    target = "x86",
    rsFile = "x86/src/lib.rs",
    addLibraries = {"core"}
}

buildRustLibrary{
    target = "klogger",
    rsFile = "klogger/src/lib.rs",
    addLibraries = {"core", "x86"}
}

buildRustLibrary{
    target = "cpuid",
    rsFile = "cpuid/src/lib.rs",
    addLibraries = {"core"}
}

buildRustLibrary{
    target = "multiboot",
    rsFile = "multiboot/src/lib.rs",
    addLibraries = {"core"}
}

buildRustLibrary{
    target = "rlib",
    rsFile = "rlib/src/lib.rs",
    addLibraries = {"core"}
}

buildRustLibrary{
    target = "elfloader",
    rsFile = "elfloader/src/lib.rs",
    addLibraries = {"klogger", "x86", "core"}
}