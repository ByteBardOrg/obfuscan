# vbscript execute-base64

The canonical VBScript loader idiom from Office macro malware. Builds the
payload as a string of Chr() calls (treated as a decoder by the VBScript
config) and feeds it to Execute. Decoded payload is `WScript.Echo "stub"`.
