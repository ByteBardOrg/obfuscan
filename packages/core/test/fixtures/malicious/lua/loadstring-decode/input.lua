-- Defanged: build a string from string.char calls (decode-equivalent in Lua),
-- feed it to loadstring (the canonical Lua dynamic-exec sink).
-- The decoded string is `print('stub')`.
local s = string.char(112,114,105,110,116,40,39,115,116,117,98,39,41)
local f = loadstring(s)
f()
