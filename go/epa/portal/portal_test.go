package portal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/gempki"
)

func newTestPortal(t *testing.T, proxyInfos []*epa.ProxyInfo) *Portal {
	t.Helper()
	portal, err := New(proxyInfos)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return portal
}

func TestPortalPages(t *testing.T) {
	proxyInfos := []*epa.ProxyInfo{
		{
			Name:    "1",
			Env:     epa.EnvDev,
			Subject: "Adler ApothekeTEST-ONLY",
			AdmissionStatement: &gempki.AdmissionStatement{
				RegistrationNumber: "3-SMC-B-Testkarte--883110000153440",
			},
		},
	}
	portal := newTestPortal(t, proxyInfos)

	for _, page := range pages {
		t.Run(page.Slug, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, page.Path, nil)
			rec := httptest.NewRecorder()
			portal.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("GET %s: status %d", page.Path, rec.Code)
			}
			body := rec.Body.String()
			if !strings.Contains(body, "ePA Middleware") {
				t.Errorf("GET %s: layout missing", page.Path)
			}
			if !strings.Contains(body, `class="nav-link active"`) {
				t.Errorf("GET %s: no active nav item", page.Path)
			}
		})
	}
}

func TestPortalNoProxies(t *testing.T) {
	portal := newTestPortal(t, nil)

	for _, path := range []string{"/", "/proxies", "/medication", "/insurants"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		portal.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s with no proxies: status %d", path, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/medication", nil)
	rec := httptest.NewRecorder()
	portal.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "{name}") {
		t.Errorf("expected {name} placeholder in curl examples with no proxies")
	}
}

func TestPortalNotFound(t *testing.T) {
	portal := newTestPortal(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rec := httptest.NewRecorder()
	portal.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET /nonexistent: status %d, want 404", rec.Code)
	}
}

func TestPortalStatic(t *testing.T) {
	portal := newTestPortal(t, nil)
	for _, path := range []string{
		"/static/portal.css",
		"/static/portal.js",
		"/static/gematik_logo.svg",
		"/static/vendor/bootstrap.min.css",
		"/static/vendor/bootstrap.bundle.min.js",
		"/static/vendor/highlight.min.js",
		"/static/vendor/github-dark.min.css",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		portal.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s: status %d", path, rec.Code)
		}
	}
}

func TestRequestBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		host    string
		want    string
	}{
		{"plain", nil, "localhost:8082", "http://localhost:8082"},
		{"forwarded", map[string]string{
			"X-Forwarded-Proto": "https",
			"X-Forwarded-Host":  "epa.example.test",
		}, "localhost:8082", "https://epa.example.test"},
		{"forwarded list", map[string]string{
			"X-Forwarded-Proto": "https, http",
			"X-Forwarded-Host":  "epa.example.test, internal",
		}, "localhost:8082", "https://epa.example.test"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Host = tt.host
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			if got := requestBaseURL(req); got != tt.want {
				t.Errorf("requestBaseURL = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBaseURLInPage(t *testing.T) {
	portal := newTestPortal(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/proxies", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "epa.example.test")
	rec := httptest.NewRecorder()
	portal.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "https://epa.example.test") {
		t.Errorf("expected forwarded base URL in curl examples")
	}
}

func TestAuthHeaderInCurl(t *testing.T) {
	portal := newTestPortal(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/proxies", nil)
	req.Header.Set("Authorization", "Bearer test-token-xyz")
	rec := httptest.NewRecorder()
	portal.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "Bearer test-token-xyz") {
		t.Errorf("expected Authorization header in curl examples")
	}
}
