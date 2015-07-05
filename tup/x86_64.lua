--
-- Platform settings
--
archFamily = "x86"
arch = "x86_64"

tup.include("common.lua")

rustcompiler = "rustc"
ccompiler = "gcc"
cxxcompiler = "g++"
linker = "ld"

--
-- User-space
--
RSFLAGS_USER  = "-O"
RSFLAGS_USER += "--cfg arch__x86_64"
RSFLAGS_USER += "--target=target.json"
RSFLAGS_USER += "-C soft-float"
RSFLAGS_USER += "-C target-feature=-3dnow,-avx,-avx2,-sse,-sse2,-sse3,-sse4.1,-sse4.2,-mmx"
RSFLAGS_USER += "-g"
RSFLAGS_USER += "-L "..TOP.."/lib/"
RSFLAGS_USER += "--extern core="..TOP.."/lib/libcore.rlib"

LDFLAGS_USER = {}

--
-- Kernel-space
--
RSFLAGS_KERNEL  = "-O"
RSFLAGS_KERNEL += "--cfg arch__x86_64"
RSFLAGS_KERNEL += "--target=target.json"
RSFLAGS_KERNEL += "-C soft-float"
RSFLAGS_KERNEL += "-C target-feature=-3dnow,-avx,-avx2,-sse,-sse2,-sse3,-sse4.1,-sse4.2,-mmx"
RSFLAGS_KERNEL += "-g"

LDFLAGS_KERNEL  = "-T arch/x86_64/link.ld"
LDFLAGS_KERNEL += "--gc-sections"
LDFLAGS_KERNEL += "-z max-page-size=0x1000"

LIBS_KERNEL = {}