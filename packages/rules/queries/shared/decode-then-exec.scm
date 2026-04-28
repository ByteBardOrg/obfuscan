; decode-then-exec.scm
;
; The single highest-precision detector in the pipeline. Matches the structural
; pattern: a call to any `dynamic_exec_sinks` member whose first argument
; transitively contains (or is data-flow-reachable from) a call to any
; `decoders` member.
;
; Tree-sitter queries are syntactic, not data-flow-aware, so this query
; captures the *syntactic* sub-case where the decoder call appears inside the
; sink argument expression. The data-flow-aware case (decoder result assigned
; to a variable, then variable passed to sink) is handled by the generic
; `walkBackward` flow walker in `core/flow.ts`, which uses this query as a
; seed and chases additional bindings.
;
; Per-grammar shim contract:
;   - the outer sink call is captured as @call
;   - its callee as @callee
;   - its first argument as @first-arg
;   - any nested call inside the argument exposes its callee as @decoder
;
; Predicates:
;   - (#match-fqn? @callee  dynamic_exec_sinks)
;   - (#match-fqn? @decoder decoders)

(_ @call
  (#match-fqn? @callee dynamic_exec_sinks)
  (#match-fqn? @decoder decoders))
