; network-then-exec.scm
;
; Matches the "fetch attacker code at runtime, then execute it" pattern.
; Same structural shape as decode-then-exec, with `network_io` as the source
; instead of `decoders`. Combined-flow case (response → variable → sink) is
; handled by the data-flow walker.
;
; Predicates:
;   - (#match-fqn? @callee  dynamic_exec_sinks)
;   - (#match-fqn? @netcall network_io)

(_ @call
  (#match-fqn? @callee dynamic_exec_sinks)
  (#match-fqn? @netcall network_io))
