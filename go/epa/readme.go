package epa

import (
	"embed"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"text/template"
)

var (
	//go:embed templates/*.html
	templatesFS embed.FS
)

var tmplReadme *template.Template

func init() {
	tmplReadme = template.Must(template.ParseFS(templatesFS, "templates/README.html"))
}

type ReadmeData struct {
	BaseURL    string
	AuthHeader string
	ProxyInfos []*ProxyInfo
}

// Curl renders a curl command for the given URL with optional header values.
// When any header is present (including a global Authorization header),
// the command is emitted in multi-line form with backslash continuations.
func (d *ReadmeData) Curl(url string, headers ...string) string {
	var all []string
	if d.AuthHeader != "" {
		all = append(all, "Authorization: "+d.AuthHeader)
	}
	all = append(all, headers...)

	if len(all) == 0 {
		return "curl " + strconv.Quote(url)
	}

	var b strings.Builder
	b.WriteString("curl ")
	b.WriteString(strconv.Quote(url))
	for _, h := range all {
		b.WriteString(" \\\n  -H ")
		b.WriteString(strconv.Quote(h))
	}
	return b.String()
}

// URL returns the absolute URL for the given path on this gateway.
func (d *ReadmeData) URL(format string, args ...any) string {
	return d.BaseURL + fmt.Sprintf(format, args...)
}

func HandleReadmeFunc(proxyInfos []*ProxyInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := ReadmeData{
			BaseURL:    "https://epa.t20r.cloud",
			ProxyInfos: proxyInfos,
		}
		data.AuthHeader = r.Header.Get("Authorization")
		tmplReadme.Execute(w, &data)
	}
}
