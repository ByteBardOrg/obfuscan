// Defanged: base64 decode -> text/template Parse with non-literal -> Execute.
// Real-world Go droppers use plugin.Open or reflect.Value.Call; this uses
// text/template which is in the engine's dynamic_exec_sinks for Go.
package main

import (
	"encoding/base64"
	"text/template"
	"os"
)

func main() {
	blob := "e3sgLkNtZCB9fQ==" // {{ .Cmd }}
	src, _ := base64.StdEncoding.DecodeString(blob)
	t, _ := template.New("x").Parse(string(src))
	t.Execute(os.Stdout, map[string]string{"Cmd": "id"})
}
