-- Pure config parsing.
local M = {}

function M.parse(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    -- Parse INI-ish lines.
    local cfg = {}
    for line in content:gmatch("[^\r\n]+") do
        local k, v = line:match("^(%w+)%s*=%s*(.+)$")
        if k then cfg[k] = v end
    end
    return cfg
end

return M
