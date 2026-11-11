//go:build js && wasm

// Command seaward-wasm is the Seaward engine for the browser demo. It reads a snapshot the page
// hands it and answers with the same report the command line prints with --json. Nothing leaves
// the page: there is no server to send anything to.
package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/gallowforge/seaward/internal/scan"
	"github.com/gallowforge/seaward/internal/snapshot"
)

type answer struct {
	OK      bool         `json:"ok"`
	Error   string       `json:"error,omitempty"`
	Version string       `json:"version"`
	Report  *scan.Report `json:"report,omitempty"`
}

func run(text string) (out answer) {
	out.Version = snapshot.Version
	defer func() {
		if r := recover(); r != nil {
			out = answer{Version: snapshot.Version, Error: fmt.Sprint("seaward could not read this snapshot: ", r)}
		}
	}()
	b, err := snapshot.Parse(text)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	rs, h, err := snapshot.Build(b)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	out.OK, out.Report = true, scan.Run(rs, h)
	return out
}

func main() {
	// seawardScan(snapshot text) returns one JSON string: {ok, error, version, report}.
	js.Global().Set("seawardScan", js.FuncOf(func(_ js.Value, args []js.Value) any {
		text := ""
		if len(args) > 0 && args[0].Type() == js.TypeString {
			text = args[0].String()
		}
		data, err := json.Marshal(run(text))
		if err != nil {
			return `{"ok":false,"error":"the report could not be written"}`
		}
		return string(data)
	}))
	if ready := js.Global().Get("seawardReady"); ready.Type() == js.TypeFunction {
		ready.Invoke()
	}
	select {}
}
