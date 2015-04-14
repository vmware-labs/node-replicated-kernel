allArchitectures = { "x86_64" }
linker = "ld"

function isBlacklisted(app)
    return tup.getconfig("BLACKLISTING_ENABLED") == "y" and blacklist and table.has(blacklist, app.target)
end

function isWhitelisted(app)
    return tup.getconfig("WHITELISTING_ENABLED") == "y" and whitelist and not table.has(whitelist, app.target)
end

tup.include("helpers.lua")
tup.include("rust-lang.lua")