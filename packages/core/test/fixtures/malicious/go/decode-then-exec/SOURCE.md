# go decode-then-exec

Synthesized. Go's most common dynamic-exec surface is `text/template` and `plugin.Open`;
this fixture exercises the `template.Parse` path which is in the Go config's
`dynamic_exec_sinks`. The base64 blob decodes to the literal string `{{ .Cmd }}`.
