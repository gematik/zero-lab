package portal

import (
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gematik/zero-lab/go/epa"
)

var (
	//go:embed templates
	templatesFS embed.FS
)

// Page describes one navigable page of the developer portal.
type Page struct {
	Slug  string
	Path  string
	Title string
	Group string
}

var pages = []Page{
	{Slug: "index", Path: "/", Title: "Übersicht"},
	{Slug: "status", Path: "/status", Title: "Status", Group: "Middleware"},
	{Slug: "proxies", Path: "/proxies", Title: "Proxies", Group: "Middleware"},
	{Slug: "providers", Path: "/providers", Title: "Provider & VAU", Group: "Middleware"},
	{Slug: "insurants", Path: "/insurants", Title: "Versicherte (KVNR)", Group: "ePA-Dienste"},
	{Slug: "consent", Path: "/consent", Title: "Consent-Entscheidungen", Group: "ePA-Dienste"},
	{Slug: "medication", Path: "/medication", Title: "Medikation", Group: "ePA-Dienste"},
	{Slug: "documents", Path: "/documents", Title: "Dokumente", Group: "ePA-Dienste"},
}

type PageData struct {
	BaseURL    string
	AuthHeader string
	ProxyInfos []*epa.ProxyInfo
	Active     string
	Title      string
	Pages      []Page
	Version    string
}

// Curl renders a curl command for the given URL with optional header values.
// When any header is present (including a global Authorization header),
// the command is emitted in multi-line form with backslash continuations.
func (d *PageData) Curl(url string, headers ...string) string {
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
func (d *PageData) URL(format string, args ...any) string {
	return d.BaseURL + fmt.Sprintf(format, args...)
}

// FirstProxyName returns the name of the first configured proxy, or the
// literal placeholder "{name}" so example commands stay meaningful when no
// proxy is configured.
func (d *PageData) FirstProxyName() string {
	if len(d.ProxyInfos) > 0 {
		return d.ProxyInfos[0].Name
	}
	return "{name}"
}

// Portal serves the developer portal: server-rendered pages plus the
// embedded static assets. It is mounted as catch-all next to the /api routes.
type Portal struct {
	proxyInfos []*epa.ProxyInfo
	mux        *http.ServeMux
	templates  map[string]*template.Template
}

func New(proxyInfos []*epa.ProxyInfo) (*Portal, error) {
	p := &Portal{
		proxyInfos: proxyInfos,
		mux:        http.NewServeMux(),
		templates:  make(map[string]*template.Template, len(pages)),
	}

	for _, page := range pages {
		tmpl, err := template.ParseFS(templatesFS,
			"templates/layout.html",
			"templates/partials.html",
			"templates/pages/"+page.Slug+".html",
		)
		if err != nil {
			return nil, fmt.Errorf("parsing portal page %q: %w", page.Slug, err)
		}
		p.templates[page.Slug] = tmpl
	}

	staticFS, err := fs.Sub(templatesFS, "templates/static")
	if err != nil {
		return nil, fmt.Errorf("locating static assets: %w", err)
	}

	p.mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticFS)))
	p.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		p.renderPage(w, r, "index")
	})
	p.mux.HandleFunc("GET /{page}", func(w http.ResponseWriter, r *http.Request) {
		slug := r.PathValue("page")
		if slug == "index" {
			http.Redirect(w, r, "/", http.StatusMovedPermanently)
			return
		}
		if _, ok := p.templates[slug]; !ok {
			http.NotFound(w, r)
			return
		}
		p.renderPage(w, r, slug)
	})

	return p, nil
}

func (p *Portal) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.mux.ServeHTTP(w, r)
}

func (p *Portal) renderPage(w http.ResponseWriter, r *http.Request, slug string) {
	title := slug
	for _, page := range pages {
		if page.Slug == slug {
			title = page.Title
			break
		}
	}

	data := &PageData{
		BaseURL:    requestBaseURL(r),
		AuthHeader: r.Header.Get("Authorization"),
		ProxyInfos: p.proxyInfos,
		Active:     slug,
		Title:      title,
		Pages:      pages,
		Version:    epa.ResolveVersion(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := p.templates[slug].ExecuteTemplate(w, "layout.html", data); err != nil {
		slog.Error("Failed to render portal page", "page", slug, "error", err)
	}
}

// requestBaseURL reconstructs the externally visible base URL of this
// gateway, honoring reverse-proxy forwarding headers. Used only for display
// in example commands, so the unauthenticated headers are safe to trust.
func requestBaseURL(r *http.Request) string {
	scheme := firstForwarded(r.Header.Get("X-Forwarded-Proto"))
	if scheme == "" {
		if r.TLS != nil {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	host := firstForwarded(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

func firstForwarded(v string) string {
	v, _, _ = strings.Cut(v, ",")
	return strings.TrimSpace(v)
}
