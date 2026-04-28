; string-array-decoder.scm
;
; Detects the canonical javascript-obfuscator output shape and its analogues
; in other languages: a top-level array literal of N+ string elements, where
; the elements are mostly base64/hex, used by an indirection function that
; takes an integer index. Verbatim shape from the 2026 axios/plain-crypto-js
; compromise (Trend Micro, Microsoft).
;
; The query captures the array literal; the detector
; (b-string-array-decoder.ts) then:
;   - measures element-string entropy/charset to confirm encoded content
;   - confirms there's an index-based call site referencing this array
;   - verifies the array is at module scope (not inside a function)
;
; Per-grammar shim contract:
;   - any "array of string literals" exposes @array

(_ @array)
