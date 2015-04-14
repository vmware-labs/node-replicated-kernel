-- Only build the applications in this list
-- Note: This is copied into your source base dir by bootstrap.sh
-- and should be edited there (not the template in tools/tup/)
-- Note: blacklist has precedence over whitelist
-- Note: whitelist is only valid for applications atm.
whitelist = {}

tup.include("helpers.lua")


if tup.getconfig("WHITELISTING_ENABLED") == "y" then
end