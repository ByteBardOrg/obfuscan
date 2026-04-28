# lua loadstring-decode

Hand-written. The Lua malware idiom: build code as a sequence of `string.char`
calls (treated as a decoder by the Lua config), feed to `loadstring` / `load`.
The decoded payload is the literal `print('stub')`.
