// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

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
