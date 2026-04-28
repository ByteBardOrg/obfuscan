; java.scm
;
; tree-sitter-java: (method_invocation name: ... arguments: (argument_list ...)).
; Object creation via (object_creation_expression type: ... arguments: ...).

(method_invocation
  name: (_) @callee
  arguments: (argument_list . (_) @first-arg)) @call

(method_invocation
  name: (_) @callee
  arguments: (argument_list
    (method_invocation name: (_) @decoder)))

(method_invocation
  name: (_) @callee
  arguments: (argument_list
    (method_invocation name: (_) @netcall)))

; Class.forName + reflection chains are handled by a dedicated lang-specific
; detector; the FQN list catches simple member-access cases here.

; Literal node types: string_literal, character_literal, decimal_integer_literal,
; hex_integer_literal, decimal_floating_point_literal, true, false, null_literal,
; text_block
