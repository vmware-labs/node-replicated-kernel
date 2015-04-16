local function sanityCheck(app)
    if app.target == nil then
        error("The application you want to build does not have a name.")
    end

    if not app.addLibraries then
        app.addLibraries = {}
    elseif type(app.addLibraries) != "table" then
        error("Argument 'addLibraries' must be a table!")
    end

    if not app.addIncludes then
        app.addIncludes = {}
    elseif type(app.addIncludes) != "table" then
        error("Argument 'addIncludes' must be a table!")
    end

    if not app.addRFlags then
        app.addRSFlags = {}
    elseif type(app.addCFlags) != "table" then
        error("Argument 'addCFlags' must be a table!")
    end
end

local function makeRustObjectFile(name, objects, libraries, flags)
    local inputs = {objects}
    inputs.extra_inputs = {TOP.."/<lib>", TOP.."/<libcore>"}
    local outputs = {name..".o"}
    outputs.extra_outputs = {TOP.."/<sbin>"}

    local cmd = {rustcompiler}
    if flags then
        tup.append_table(cmd, flags)
    end
    cmd += "%f"

    for i, lib in ipairs(libraries) do
        libpath = TOP.."/lib/lib"..lib..".rlib"
        inputs.extra_inputs += libpath
        cmd += "--extern "..lib.."="..libpath
    end

    return tup.frule{
        input = inputs,
        command = "^ RUSTC %o^ "..table.concat(cmd, " ").." -o %o ",
        output = outputs
    }
end

local function notSupportedOnArchitecture(app)
    return app.architectures and not table.toSet(app.architectures)[arch]
end

function makeKernelAssemblyFile(source, extra_inputs, group)
    local inputs = {source}
    inputs.extra_inputs = extra_inputs

    local outputs = {"%B.o"}
    outputs.extra_outputs = {group}

    return tup.frule{
        input = inputs,
        command = "^ AS %f^ as -o %o %f",
        output = outputs
    }
end

function buildRustKernel(app)
    if notSupportedOnArchitecture(app) then
        return -- unsupported architecture
    end
    if isBlacklisted(app) then
        return -- blacklisted application
    end
    if isWhitelisted(app) then
        return -- not in whitelist application
    end

    sanityCheck(app)
    local compiler_directives = {"--emit=obj", "-L dependency="..TOP.."/lib/"}
    tup.append_table(compiler_directives, RSFLAGS_KERNEL)
    if app.addRSFlags then
        tup.append_table(compiler_directives, app.addRSFlags)
    end

    all_objects = {}

    -- Build the assembly files
    for i, f in pairs(app.assemblyFiles) do
        all_objects += makeKernelAssemblyFile(f, {})
    end

    -- Build the rust files
    all_objects += makeRustObjectFile(app.target, app.rsFile, app.addLibraries, compiler_directives)

    for i, lib in ipairs(app.addLibraries) do
        libpath = TOP.."/lib/lib"..lib..".rlib"
        all_objects += libpath
    end

    -- Link the object file to 64bit ELF
    cmd = {linker}
    tup.append_table(cmd, LDFLAGS_KERNEL)
    elf64bin = tup.frule{
        input = all_objects,
        command = "^ LD %o^ "..table.concat(cmd, " ").." -o %o %f",
        output = "kernel.bin.elf64"
    }

    -- Make it a fake elf32, that is what multiboot v1 likes
    return tup.frule{
        input = elf64bin,
        command = "^ OBJCOPY %o^ objcopy %f -F elf32-i386 %o",
        output = TOP.."/"..arch.."/sbin/"..app.target
    }

end

local function makeRustLibrary(name, objects, libraries, flags)
    local inputs = {objects}
    inputs.extra_inputs = {TOP.."/<libcore>"}
    local outputs = {TOP.."/lib/"..name..".rlib"}
    outputs.extra_outputs = {TOP.."/<lib>"}

    local cmd = {rustcompiler, "--crate-type=lib", "--emit=link"}
    if flags then
        tup.append_table(cmd, flags)
    end
    cmd += "%f"

    for i, lib in ipairs(libraries) do
        libpath = TOP.."/lib/lib"..lib..".rlib"
        inputs.extra_inputs += libpath
        cmd += "--extern "..lib.."="..libpath
    end
    cmd += "-L dependency="..TOP.."/lib/"

    return tup.frule{
        input = inputs,
        command = ""..table.concat(cmd, " ").." -o %o",
        output = outputs
    }
end

function buildRustLibrary(lib)
    if notSupportedOnArchitecture(lib) then
        return -- unsupported architecture
    end
    if isBlacklisted(lib) then
        return -- blacklisted application
    end

    sanityCheck(lib)

    local compiler_directives = {}
    tup.append_table(compiler_directives, RSFLAGS_KERNEL)
    if lib.addRSFlags then
        tup.append_table(compiler_directives, lib.addRSFlags)
    end
    compiler_directives += "--crate-name "..lib.target

    local name = "lib"..lib.target
    bin = makeRustLibrary(name, lib.rsFile, lib.addLibraries, compiler_directives)
end


local function makeCoreLibrary(name, objects, libraries, flags)
    local inputs = {objects}
    inputs.extra_inputs = {}
    local outputs = {TOP.."/lib/"..name..".rlib"}
    outputs.extra_outputs = {TOP.."/<libcore>"}

    local cmd = {rustcompiler, "--crate-type=lib", "--emit=link"}
    if flags then
        tup.append_table(cmd, flags)
    end
    cmd += "%f"

    for i, lib in ipairs(libraries) do
        libpath = TOP.."/lib/lib"..lib..".rlib"
        inputs.extra_inputs += libpath
        cmd += "--extern "..lib.."="..libpath
    end

    return tup.frule{
        input = inputs,
        command = ""..table.concat(cmd, " ").." -o %o",
        output = outputs
    }
end

function buildCoreLibrary(lib)
    if notSupportedOnArchitecture(lib) then
        return -- unsupported architecture
    end
    if isBlacklisted(lib) then
        return -- blacklisted application
    end

    sanityCheck(lib)

    local compiler_directives = {}
    tup.append_table(compiler_directives, RSFLAGS_KERNEL)
    if lib.addRSFlags then
        tup.append_table(compiler_directives, lib.addRSFlags)
    end

    local name = "lib"..lib.target
    bin = makeCoreLibrary(name, lib.rsFile, lib.addLibraries, compiler_directives)
end
