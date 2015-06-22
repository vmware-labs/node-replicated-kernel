
tup.frule{
    input = {TOP.."/"..tup.getconfig("TARGET_FILE")},
    command = "^ ln %o^ ln -s %f %o",
    output = "target.json"
}

buildCoreLibrary{
    target = "core",
    rsFile = "core/lib.rs"
}

buildRustLibrary{
    target = "bitflags",
    rsFile = "bitflags/src/lib.rs",
    addLibraries = {"core"}
}

buildRustLibrary{
    target = "x86",
    rsFile = "x86/src/lib.rs",
    addLibraries = {"core", "bitflags"}
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
