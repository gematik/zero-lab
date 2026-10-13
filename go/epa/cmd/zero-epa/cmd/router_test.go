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
