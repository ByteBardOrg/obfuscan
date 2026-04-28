; kotlin.scm
;
; tree-sitter-kotlin: call expressions are (call_expression) with a callable
; reference and (call_suffix) holding (value_arguments).

(call_expression
  (_) @callee
  (call_suffix
    (value_arguments . (value_argument (_) @first-arg)))) @call

(call_expression
  (_) @callee
  (call_suffix
    (value_arguments
      (value_argument
        (call_expression (_) @decoder)))))

(call_expression
  (_) @callee
  (call_suffix
    (value_arguments
      (value_argument
        (call_expression (_) @netcall)))))

; Literal node types: string_literal, character_literal, integer_literal,
; real_literal, boolean_literal, null_literal
