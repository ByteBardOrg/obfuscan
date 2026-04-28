; dynamic-exec-sink.scm
;
; Match: a call to any name in the language's `dynamic_exec_sinks` list whose
; first argument is not a literal.
;
; Per-grammar shim contract (see per-grammar/*.scm):
;   - the call site is captured as @call
;   - the callee (function expression) is captured as @callee
;   - the first argument node is captured as @first-arg

(_ @call
  (#match-fqn? @callee dynamic_exec_sinks)
  (#not-literal? @first-arg))
