// Package webui holds the embedded default UI templates for the oauth2-proxy. FS is the templates/ subtree
// (Go html/template files); a deployment can replace it by pointing Config.TemplateDir at a directory with
// the same file names.
package webui

import (
	"embed"
	"io/fs"
)

//go:embed templates
var embedded embed.FS

// FS is the default template set (the templates/ directory).
var FS = mustSub(embedded, "templates")

func mustSub(f embed.FS, dir string) fs.FS {
	sub, err := fs.Sub(f, dir)
	if err != nil {
		panic(err)
	}
	return sub
}
