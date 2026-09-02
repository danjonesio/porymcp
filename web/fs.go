package web

import (
	"embed"
	"io/fs"
)

// Built is the Next.js static export. It is compiled into the server binary
// so `go run ./cmd/server` serves the dashboard without a separate npm step.
//
//go:embed all:out
var built embed.FS

func Dist() (fs.FS, error) {
	return fs.Sub(built, "out")
}
