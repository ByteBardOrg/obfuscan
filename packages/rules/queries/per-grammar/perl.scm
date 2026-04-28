; perl.scm
;
; tree-sitter-perl exposes function calls as (call_expression function: ...
; arguments: ...). Builtin sinks like `eval`, `system`, `exec` parse as
; identifiers without a function_call wrapper when used in statement form;
; those are matched by lang-specific regex detectors as a fallback.

(call_expression
  function: (_) @callee
  arguments: (_) @first-arg) @call

; Literal node types: string_literal, integer, floating_point, undef
