; lua.scm
;
; tree-sitter-lua: (function_call (variable_list)/(prefix) (arguments ...)).
; Different forks of the grammar use slightly different shapes; the
; predicate-driven matching is robust to either.

(function_call
  (_) @callee
  (arguments . (_) @first-arg)) @call

(function_call
  (_) @callee
  (arguments
    (function_call (_) @decoder)))

(function_call
  (_) @callee
  (arguments
    (function_call (_) @netcall)))

; Literal node types: string, number, true, false, nil
