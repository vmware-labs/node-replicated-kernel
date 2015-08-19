
tup.frule{
    input = {TOP.."/"..tup.getconfig("TARGET_FILE")},
    command = "^ ln %o^ ln -s %f %o",
    output = "target.json"
}

buildCoreLibrary{
    target = "core",
    rsFile = "core/lib.rs",
    addRSFlags = {"--cfg", "disable_float"}
}

buildRustLibrary{
    target = "rustc_unicode",
    rsFile = "rustc_unicode/lib.rs",
    addLibraries = {"core"}
}

buildRustLibrary{
    target = "alloc",
    rsFile = "alloc/lib.rs",
    addLibraries = {"core", "rustc_unicode"}
}

buildRustLibrary{
    target = "collections",
    rsFile = "collections/lib.rs",
    addLibraries = {"core", "rustc_unicode", "alloc"}
}

buildRustLibrary{
    target = "bitflags",
    rsFile = "bitflags/src/lib.rs",
    addLibraries = {"core"}
}

buildRustLibrary{
    target = "raw_cpuid",
    rsFile = "cpuid/src/lib.rs",
    addLibraries = {"core", "bitflags"}
}

buildRustLibrary{
    target = "x86",
    rsFile = "x86/src/lib.rs",
    addLibraries = {"core", "bitflags", "raw_cpuid"}
}

buildRustLibrary{
    target = "slabmalloc",
    rsFile = "slabmalloc/src/lib.rs",
    addLibraries = {"core", "x86"}
}

buildRustLibrary{
    target = "klogger",
    rsFile = "klogger/src/lib.rs",
    addLibraries = {"x86", "core"}
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
