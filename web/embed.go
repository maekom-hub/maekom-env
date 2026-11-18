package web

import "embed"

// Assets holds the embedded web UI static files.
//
//go:embed index.html
var Assets embed.FS
