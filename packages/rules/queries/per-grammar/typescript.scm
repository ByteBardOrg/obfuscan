; typescript.scm
;
; tree-sitter-typescript is implemented as an extension of tree-sitter-
; javascript, so the call_expression / arguments / array shapes are identical.
; The same captures apply.

(call_expression
  function: (_) @callee
  arguments: (arguments . (_) @first-arg)) @call

(call_expression
  function: (_) @callee
  arguments: (arguments
    (call_expression
      function: (_) @decoder)))

(call_expression
  function: (_) @callee
  arguments: (arguments
    (call_expression
      function: (_) @netcall)))

(program
  (lexical_declaration
    (variable_declarator
      value: (array
        (string) (string) (string) (string) (string)
        (string) (string) (string) (string) (string)) @array)))

; Literal node types: string, number, true, false, null, undefined,
; regex, template_string
