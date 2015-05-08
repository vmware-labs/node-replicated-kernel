buildRustApplication{
    target = "init",
    rsFile = "init.rs",
    assemblyFiles = {"crt0.S"},
    addLibraries = {"core", "x86"}
}