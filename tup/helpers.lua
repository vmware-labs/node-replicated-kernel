function table.removevalue(t, val)
    for i, v in ipairs(t) do
        if v == val then
            table.remove(t, i)
            return true
        end
    end

    return false
end

function table.shallow_copy(t)
    local t2 = {}
    for k, v in pairs(t) do
        t2[k] = v
    end
    return t2
end

function table.has(t, val)
    for i, v in ipairs(t) do
        if v == val then
            return true
        end
    end

    return false
end

function table.toSet (list)
    local set = {}
    for _, l in ipairs(list) do
        set[l] = true
    end
    return set
end

function table.intersect(set1, set2)
    local intersection = {}
    for k, v in pairs(set1) do
        if set2[k] then
            intersection[#intersection+1] = k
        end
    end

    return intersection
end

function basedir(file)
    local bd = ""
    if string.find(file, "/") then
        -- a/b/c.c => basedir = a/b
        bd = string.gsub(file, "^(.+)/([^/]+)$", "%1/")
    end
    return bd
end

function map(func, array)
    local new_array = {}
    for i,v in ipairs(array) do
        new_array[i] = func(v)
    end
    return new_array
end

function string.startswith(string, start)
   return string.sub(string,1,string.len(start)) == start
end

function string.split(str, pattern)
    local splits = {}
    for w in str:gmatch(pattern) do
        splits += w
    end
    return splits
end