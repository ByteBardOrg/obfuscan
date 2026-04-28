; suspicious-io-cluster.scm
;
; Captures any call to a `secrets_io` or `network_io` name. The detector
; (b-suspicious-io.ts) aggregates these per-file: if both kinds appear in the
; same file (or same enclosing function), the score is boosted because the
; combination is the canonical exfiltration shape.
;
; Predicates:
;   - (#match-any-fqn? @callee secrets_io network_io)

(_ @call
  (#match-any-fqn? @callee secrets_io network_io))
