; php.scm
;
; tree-sitter-php call shapes:
;   (function_call_expression function: <expr> arguments: (arguments ...))
;   (member_call_expression   object: ... name: <id> arguments: (arguments ...))
;   (scoped_call_expression   scope: ... name: <id> arguments: (arguments ...))

(function_call_expression
  function: (_) @callee
  arguments: (arguments . (argument (_) @first-arg))) @call

(member_call_expression
  name: (_) @callee
  arguments: (arguments . (argument (_) @first-arg))) @call

(scoped_call_expression
  name: (_) @callee
  arguments: (arguments . (argument (_) @first-arg))) @call

; Decoder/network nested
(function_call_expression
  function: (_) @callee
  arguments: (arguments
    (argument
      (function_call_expression function: (_) @decoder))))

(function_call_expression
  function: (_) @callee
  arguments: (arguments
    (argument
      (function_call_expression function: (_) @netcall))))

; Top-level array of strings
(program
  (expression_statement
    (assignment_expression
      right: (array_creation_expression
        (array_element_initializer (string)) (array_element_initializer (string))
        (array_element_initializer (string)) (array_element_initializer (string))
        (array_element_initializer (string))) @array)))

; Literal node types: string, integer, float, boolean, null, encapsed_string,
; heredoc, nowdoc
