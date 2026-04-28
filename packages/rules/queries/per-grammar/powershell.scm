; powershell.scm
;
; tree-sitter-powershell: command/cmdlet calls parse as (command
; command_name: ...  command_arguments: ...). Pipelines are (pipeline).
; Type-cast / static-method calls (e.g. [System.Convert]::FromBase64String)
; parse as (invokation_expression).
;
; PowerShell obfuscation routinely defeats syntactic FQN matching (backtick
; escapes, format-string sink reconstruction, char-array joins). This shim
; covers the simple cases; the heavy lifting is in
; detectors/lang-specific/powershell.ts.

(command
  command_name: (_) @callee
  command_arguments: (_)? @first-arg) @call

(invokation_expression
  expression: (_)
  member_name: (_) @callee
  arguments: (_)? @first-arg) @call

; Pipeline that pipes any source into IEX / Invoke-Expression
(pipeline
  (command command_name: (_) @netcall)
  (command command_name: (_) @callee)) @call

; Literal node types: integer_literal, real_literal, string_literal,
; expandable_string_literal, verbatim_string_literal, array_literal_expression
