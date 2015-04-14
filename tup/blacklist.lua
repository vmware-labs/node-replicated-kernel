-- Ban certain targets from being built
-- Note: This is copied into your source base dir by bootstrap.sh
-- and should be edited there (not the template in tools/tup/)
blacklist = {}

if tup.getconfig("BLACKLISTING_ENABLED") == "y" then

end