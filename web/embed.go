package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var assets embed.FS

// DistFS returns the embedded production web UI filesystem rooted at dist/.
func DistFS() (fs.FS, error) {
	return fs.Sub(assets, "dist")
}
