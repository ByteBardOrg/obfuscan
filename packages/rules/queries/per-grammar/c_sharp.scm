; c_sharp.scm
;
; tree-sitter-c-sharp: (invocation_expression function: ... arguments: (argument_list ...)).
; Method invocations on members use (member_access_expression) as the function.

(invocation_expression
  function: (_) @callee
  arguments: (argument_list . (argument (_) @first-arg))) @call

(invocation_expression
  function: (_) @callee
  arguments: (argument_list
    (argument (invocation_expression function: (_) @decoder))))

(invocation_expression
  function: (_) @callee
  arguments: (argument_list
    (argument (invocation_expression function: (_) @netcall))))

; ObjectCreation as a sink-equivalent (`new BinaryFormatter()` etc.) is handled
; by a separate detector that watches type names against a deserializers list.

; Top-level array of strings
(compilation_unit
  (global_statement
    (local_declaration_statement
      (variable_declaration
        (variable_declarator
          (initializer
            (array_creation_expression
              (initializer
                (string_literal) (string_literal) (string_literal)
                (string_literal) (string_literal)) @array)))))))

; Literal node types: string_literal, verbatim_string_literal,
; interpolated_string_expression, integer_literal, real_literal,
; character_literal, boolean_literal, null_literal
