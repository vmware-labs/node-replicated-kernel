--
-- Generate deployment images based on menu.lst files for ARM boards
--

if tup.getconfig("MENU_LST") == "" then
    error("You must define CONFIG_MENU_LST for deployment.")
end

local menu_lst = TOP.."/"..tup.getconfig("MENU_LST")

if archFamily == "x86" then
    tup.frule{
        input = {menu_lst},
        command = "cp %f %o",
        output = { TOP.."/menu.lst"}
    }
end