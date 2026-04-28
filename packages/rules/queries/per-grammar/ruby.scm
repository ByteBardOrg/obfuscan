; ruby.scm
;
; tree-sitter-ruby uses (call method: ... arguments: (argument_list ...))
; and (method_call ...). Method calls without parens parse as (call ...) too.

(call
  method: (_) @callee
  arguments: (argument_list . (_) @first-arg)) @call

(call
  method: (_) @callee
  arguments: (argument_list
    (call method: (_) @decoder)))

(call
  method: (_) @callee
  arguments: (argument_list
    (call method: (_) @netcall)))

; Top-level array of strings
(program
  (assignment
    right: (array
      (string) (string) (string) (string) (string)
      (string) (string) (string) (string) (string)) @array))

; Literal node types: string, integer, float, true, false, nil, symbol,
; regex, heredoc_beginning
