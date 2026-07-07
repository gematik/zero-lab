package cmd

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/gempki"
)

func TestRouterPrecedence(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test SMC-B"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	sf := &epa.SecurityFunctions{
		AuthnSignFunc:           brainpool.SignFuncPrivateKey(key),
		AuthnCertFunc:           func() (*x509.Certificate, error) { return cert, nil },
		ClientAssertionSignFunc: brainpool.SignFuncPrivateKey(key),
		ClientAssertionCertFunc: func() (*x509.Certificate, error) { return cert, nil },
	}

	proxy, err := epa.NewProxyWithSecurityFunctions(epa.EnvDev, sf, "test", 5*time.Second, nil)
	if err != nil {
		t.Skipf("cannot build proxy (likely no network for IDP metadata): %v", err)
	}
	defer proxy.Close()

	infos := []*epa.ProxyInfo{{
		Name:               "test",
		Env:                epa.EnvDev,
		Subject:            "Test SMC-B",
		AdmissionStatement: &gempki.AdmissionStatement{RegistrationNumber: "test"},
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
