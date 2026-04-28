; javascript.scm
;
; Per-grammar shim. tree-sitter-javascript exposes call sites as
; (call_expression function: <expr> arguments: (arguments ...)).
; tree-sitter-typescript inherits this grammar.
;
; Captures normalized for the shared queries:
;   @call       — the call_expression node
;   @callee     — the function/callee child (Identifier or MemberExpression)
;   @first-arg  — the first argument
;   @decoder    — any nested call's callee
;   @netcall    — any nested call's callee (treated as net source by the predicate)
;   @array      — array literal of strings at module/program scope

; ----- call sites with first-arg capture ---------------------------------
(call_expression
  function: (_) @callee
  arguments: (arguments . (_) @first-arg)) @call

; ----- nested call inside an outer call (for decode/network-then-exec) ----
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

; ----- module-scope array literal of string literals ----------------------
(program
  (variable_declaration
    (variable_declarator
      value: (array
        (string) (string) (string) (string) (string)
        (string) (string) (string) (string) (string)) @array)))

(program
  (lexical_declaration
    (variable_declarator
      value: (array
        (string) (string) (string) (string) (string)
        (string) (string) (string) (string) (string)) @array)))

; Literal node types used by #not-literal?:
;   string, number, true, false, null, undefined, regex, template_string
