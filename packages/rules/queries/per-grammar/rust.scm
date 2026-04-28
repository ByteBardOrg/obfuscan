; rust.scm
;
; tree-sitter-rust: (call_expression function: ... arguments: (arguments ...)).
; Method calls are (method_call_expression).

(call_expression
  function: (_) @callee
  arguments: (arguments . (_) @first-arg)) @call

(method_call_expression
  receiver: (_)
  method: (_) @callee
  arguments: (arguments . (_) @first-arg)) @call

(call_expression
  function: (_) @callee
  arguments: (arguments
    (call_expression function: (_) @decoder)))

(call_expression
  function: (_) @callee
  arguments: (arguments
    (call_expression function: (_) @netcall)))

; Top-level array literal of string literals
(source_file
  (let_declaration
    value: (array_expression
      (string_literal) (string_literal) (string_literal)
      (string_literal) (string_literal)) @array))

; Literal node types: string_literal, raw_string_literal, char_literal,
; integer_literal, float_literal, boolean_literal
