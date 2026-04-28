; go.scm
;
; tree-sitter-go: (call_expression function: ... arguments: (argument_list ...)).

(call_expression
  function: (_) @callee
  arguments: (argument_list . (_) @first-arg)) @call

(call_expression
  function: (_) @callee
  arguments: (argument_list
    (call_expression function: (_) @decoder)))

(call_expression
  function: (_) @callee
  arguments: (argument_list
    (call_expression function: (_) @netcall)))

; Top-level slice of string literals
(source_file
  (var_declaration
    (var_spec
      value: (expression_list
        (composite_literal
          body: (literal_value
            (literal_element (interpreted_string_literal))
            (literal_element (interpreted_string_literal))
            (literal_element (interpreted_string_literal))
            (literal_element (interpreted_string_literal))
            (literal_element (interpreted_string_literal))) @array)))))

; Literal node types: interpreted_string_literal, raw_string_literal,
; int_literal, float_literal, true, false, nil, rune_literal
