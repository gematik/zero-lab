package proxy

import (
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"os"

	"github.com/gematik/zero-lab/go/pep/proxy/webui"
)

// renderer loads and executes the UI templates. The template set is the embedded default unless a
// TemplateDir is configured (os.DirFS), so a deployment can replace the UI from outside without rebuilding.
type renderer struct {
	tmpl *template.Template
}

func newRenderer(templateDir string) (*renderer, error) {
	var fsys fs.FS = webui.FS
	if templateDir != "" {
		fsys = os.DirFS(templateDir)
	}
	t, err := template.New("").ParseFS(fsys, "*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &renderer{tmpl: t}, nil
}

// render writes the named template (by file name, e.g. "sign_in.html") with the given status + data.
func (r *renderer) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := r.tmpl.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("render template", "name", name, "error", err)
	}
}
