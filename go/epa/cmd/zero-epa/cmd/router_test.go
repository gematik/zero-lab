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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/epa/epatest"
	"github.com/gematik/zero-lab/go/epa/ti"
)

// probeRunner answers `ti probe ENV`: ref has no tool behind it, every other environment
// reports one service that fails, the way the tool does, with exit 1 and a report.
type probeRunner struct{}

func (probeRunner) Run(_ context.Context, _ []byte, args ...string) ([]byte, error) {
	env := args[1]
	if env == string(epa.EnvRef) {
		return nil, errors.New("ti is gone")
	}
	return nil, &ti.Error{ExitCode: 1, Stdout: []byte(`{"schema":1,"environment":"` + env + `","duration_ms":5,
		"counts":{"ok":0,"warn":0,"fail":1},
		"access_paths":[{"access":"internet","available":false,"probes":1}],
		"probes":[{"name":"catalog","access":"internet","status":"fail","detail":"timeout","duration_ms":3}]}`)}
}

func TestProbeAnswersPerEnvironmentOfTheProxies(t *testing.T) {
	infos := []*epa.ProxyInfo{
		{Name: "d1", Env: epa.EnvDev},
		{Name: "d2", Env: epa.EnvDev},
		{Name: "r1", Env: epa.EnvRef},
	}
	rec := httptest.NewRecorder()
	probeHandler(ti.NewProber(probeRunner{}, time.Now), infos).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/probe", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("a failed run must not be an HTTP error: %d %s", rec.Code, rec.Body)
	}

	var got []struct {
		Environment string `json:"environment"`
		Error       string `json:"error"`
		Probes      []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"probes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, rec.Body)
	}
	if len(got) != 2 {
		t.Fatalf("want one entry per environment, in the proxies' order: %s", rec.Body)
	}
	if got[0].Environment != "dev" || got[0].Error != "" || len(got[0].Probes) != 1 || got[0].Probes[0].Status != "fail" {
		t.Errorf("dev: %+v", got[0])
	}
	if got[1].Environment != "ref" || got[1].Error == "" || len(got[1].Probes) != 0 {
		t.Errorf("ref: %+v", got[1])
	}
}

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

	router, err := buildRouter([]*epa.Proxy{proxy}, infos, ti.NewProber(probeRunner{}, time.Now))
	if err != nil {
		t.Fatal(err)
	}

	get := func(path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
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
	if rec := get("/api/probe"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"environment":"dev"`) {
		t.Errorf("GET /api/probe: %d %q", rec.Code, rec.Body.String())
	}
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
