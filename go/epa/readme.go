package epa

import (
	"embed"
	"net/http"
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
	CurlCommand string
	BaseURL     string
	ProxyInfos  []*ProxyInfo
}

func HandleReadmeFunc(proxyInfos []*ProxyInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := ReadmeData{
			CurlCommand: "curl",
			BaseURL:     "https://epa.t20r.cloud",
			ProxyInfos:  proxyInfos,
		}
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			data.CurlCommand += " -H \"Authorization: " + authHeader + "\""
		}
		tmplReadme.Execute(w, data)
	}
}
