; python.scm
;
; tree-sitter-python uses (call function: <expr> arguments: (argument_list ...)).
; Attribute callees are (attribute object: ... attribute: <id>).

(call
  function: (_) @callee
  arguments: (argument_list . (_) @first-arg)) @call

(call
  function: (_) @callee
  arguments: (argument_list
    (call function: (_) @decoder)))

(call
  function: (_) @callee
  arguments: (argument_list
    (call function: (_) @netcall)))

; Module-scope list literal of string literals
(module
  (expression_statement
    (assignment
      right: (list
        (string) (string) (string) (string) (string)
        (string) (string) (string) (string) (string)) @array)))

; Literal node types: string, integer, float, true, false, none,
; concatenated_string
