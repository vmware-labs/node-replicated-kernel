TOP = tup.getcwd()
if tup.getconfig("ARCHITECTURE") == "" then
    error("CONFIG_ARCHITECTURE not set, you must add a variant first (e.g., do tup variant tup/x86_64.config)!")
end
tup.include("tup/whitelist.lua")
tup.include("tup/blacklist.lua")
tup.include("tup/"..tup.getconfig("ARCHITECTURE")..".lua")
