; bash.scm
;
; tree-sitter-bash represents commands as (command name: <word> argument: ...).
; eval/source/. all parse as plain commands. Pipelines are (pipeline) and
; command substitutions are (command_substitution).

(command
  name: (command_name (_) @callee)
  argument: (_) @first-arg) @call

; Pipelines that pipe into eval/source/. — common `curl | sh` shape
(pipeline
  (command name: (command_name (_) @netcall))
  (command name: (command_name (_) @callee))) @call

; Command substitution feeding eval: `eval "$(curl ...)"`
(command
  name: (command_name (_) @callee)
  argument: (string
    (command_substitution
      (command name: (command_name (_) @decoder))))) @call

(command
  name: (command_name (_) @callee)
  argument: (string
    (command_substitution
      (command name: (command_name (_) @netcall))))) @call

; Literal node types: word, string, raw_string, ansi_c_string, number,
; concatenation
