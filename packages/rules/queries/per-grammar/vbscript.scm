; vbscript.scm
;
; tree-sitter-vbscript grammar coverage in the open-source ecosystem is thin.
; Where it's unavailable, the regex-based fallbacks in detectors/a-* still
; fire on .vbs/.hta files (entropy, bidi, line length, encoded-array). The
; lang-specific detectors in detectors/lang-specific/vbscript.ts cover the
; high-signal patterns (Execute/ExecuteGlobal/MSScriptControl) directly.
;
; If a tree-sitter-vbscript grammar is loaded, expose:
;   @call, @callee, @first-arg, @decoder, @netcall as best effort.

(call_statement
  procedure: (_) @callee
  arguments: (_)? @first-arg) @call
