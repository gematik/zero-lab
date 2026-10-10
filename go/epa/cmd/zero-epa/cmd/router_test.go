package cmd

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/epa/epatest"
)

func TestRouterPrecedence(t *testing.T) {
	sf := &epa.SecurityFunctions{Identity: &epatest.Identity{
		SubjectDN: "CN=Test SMC-B",
		Admitted:  &epa.Admission{RegistrationNumber: "test"},
	}}

	proxy, err := epa.NewProxyWithSecurityFunctions(epa.EnvDev, sf, &epatest.Authenticator{Code: "c"}, "test", 5*time.Second, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()

	infos := []*epa.ProxyInfo{{
		Name:               "test",
		Env:                epa.EnvDev,
		Subject:            "Test SMC-B",
		AdmissionStatement: &epa.Admission{RegistrationNumber: "test"},
	}}

	e, err := buildRouter([]*epa.Proxy{proxy}, infos)
	if err != nil {
		t.Fatal(err)
	}

	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}

	// portal catch-all
	if rec := get("/"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "ePA Middleware") {
		t.Errorf("GET /: %d", rec.Code)
	}
	if rec := get("/medication"); rec.Code != 200 {
		t.Errorf("GET /medication: %d", rec.Code)
	}
	if rec := get("/nonexistent"); rec.Code != 404 {
		t.Errorf("GET /nonexistent: %d, want 404", rec.Code)
	}
	if rec := get("/static/portal.css"); rec.Code != 200 {
		t.Errorf("GET /static/portal.css: %d", rec.Code)
	}

	// /api routes must win over the portal catch-all
	if rec := get("/api/proxies"); rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "json") {
		t.Errorf("GET /api/proxies: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec := get("/api/insurants"); rec.Code != 200 || !strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "[") {
		t.Errorf("GET /api/insurants: %d %q", rec.Code, rec.Body.String())
	}
	if rec := get("/api/proxies/test/insurants"); rec.Code != 200 {
		t.Errorf("GET /api/proxies/test/insurants: %d", rec.Code)
	}
	if rec := get("/api/insurants/BOGUS"); rec.Code != 400 || !strings.Contains(rec.Body.String(), "invalid_kvnr") {
		t.Errorf("GET /api/insurants/BOGUS: %d %q", rec.Code, rec.Body.String())
	}
}
