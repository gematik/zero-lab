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

package oidf

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
)

type recordingTransport struct{ last *http.Request }

func (r *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r.last = req
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
}

func TestTheAPIKeyGoesOnlyToTheIntendedHosts(t *testing.T) {
	for target, want := range map[string]string{
		"https://idp.dev.gematik.solutions/x":      "key-value",
		"https://IDP.dev.gematik.solutions:443/x":  "key-value",
		"https://xdev.gematik.solutions/x":         "",
		"https://dev.gematik.solutions.evil.org/x": "",
		"https://dev.gematik.solutions/x":          "",
		"http://idp.dev.gematik.solutions/x":       "",
		"https://example.org/x":                    "",
	} {
		t.Run(target, func(t *testing.T) {
			next := &recordingTransport{}
			req, err := http.NewRequest(http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := AddAPIKeyTransport(next, "key-value").RoundTrip(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if got := next.last.Header.Get("x-authorization"); got != want {
				t.Errorf("x-authorization = %q, want %q", got, want)
			}
			if req.Header.Get("x-authorization") != "" {
				t.Error("the caller's request was changed")
			}
		})
	}
}

func TestALibraryReadsNoAPIKeyFromTheEnvironment(t *testing.T) {
	t.Setenv("PEP_OIDF_DEV_API_KEY", "from-the-environment")
	t.Setenv("PDP_OIDF_DEV_API_KEY", "from-the-environment")
	next := &recordingTransport{}
	req, err := http.NewRequest(http.MethodGet, "https://idp.dev.gematik.solutions/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := AddAPIKeyTransport(next, "").RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := next.last.Header.Get("x-authorization"); got != "" {
		t.Errorf("x-authorization = %q", got)
	}
}

// refusingTransport fails every request and counts them, so a test sees whether a fetch was tried.
type refusingTransport struct{ requests atomic.Int64 }

var errNoNetwork = errors.New("no network in this test")

func (c *refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.requests.Add(1)
	return nil, errNoNetwork
}

func TestServerRule17_AFederationWithAGatedMasterAndNoAPIKeyIsRefusedAtConstruction(t *testing.T) {
	for _, master := range []string{"https://app.dev.gematik.solutions", "https://APP.Dev.Gematik.Solutions:8443"} {
		t.Run(master, func(t *testing.T) {
			transport := &refusingTransport{}
			_, err := NewOpenidFederation(t.Context(), master, keySetOf(newTestKey(t), "master"),
				WithHTTPClient(&http.Client{Transport: transport}), WithDocuments(NewMemoryDocuments(16, nil)))
			if !errors.Is(err, ErrAPIKeyRequired) {
				t.Errorf("err = %v, want ErrAPIKeyRequired", err)
			}
			if n := transport.requests.Load(); n != 0 {
				t.Errorf("%d requests", n)
			}
		})
	}
}

func TestServerRule17_AFederationWithAGatedMasterAndAnAPIKeyIsNotRefusedForTheKey(t *testing.T) {
	transport := &refusingTransport{}
	_, err := NewOpenidFederation(t.Context(), "https://app.dev.gematik.solutions", keySetOf(newTestKey(t), "master"),
		WithHTTPClient(&http.Client{Transport: transport}), WithDocuments(NewMemoryDocuments(16, nil)), WithAPIKey("key-value"))
	if !errors.Is(err, errNoNetwork) {
		t.Errorf("err = %v, want the fetch's error", err)
	}
}

func TestServerRule17_ARelyingPartyWithAGatedMasterAndNoAPIKeyIsRefusedAtConstruction(t *testing.T) {
	for name, change := range map[string]func(*RelyingPartyConfig){
		"fed_master_url": func(cfg *RelyingPartyConfig) { cfg.FedMasterURL = "https://app.dev.gematik.solutions" },
		"fed_master_entity_statement_uri": func(cfg *RelyingPartyConfig) {
			cfg.FedMasterEntityStatementURI = "https://app.dev.gematik.solutions/.well-known/openid-federation"
		},
	} {
		t.Run(name, func(t *testing.T) {
			transport := &refusingTransport{}
			cfg := &RelyingPartyConfig{
				Subject:          "https://rp.example",
				FedMasterJWK:     &Jwk{Key: &keySetOf(newTestKey(t), "master").Keys[0]},
				RelyingParty:     testRelyingPartyMetadata(),
				FederationEntity: testFederationEntity(),
				HTTPClient:       &http.Client{Transport: transport},
				Documents:        NewMemoryDocuments(16, nil),
			}
			change(cfg)
			_, err := New(t.Context(), cfg, newTestKeys(t))
			if !errors.Is(err, ErrAPIKeyRequired) {
				t.Errorf("err = %v, want ErrAPIKeyRequired", err)
			}
			if n := transport.requests.Load(); n != 0 {
				t.Errorf("%d requests", n)
			}
		})
	}
}

// TestALibraryLogsNothingThroughTheDefaultLogger proves go/docs/design.md section 2: a request to a gated host
// without a key goes out unchanged and leaves no trace in the default logger.
func TestALibraryLogsNothingThroughTheDefaultLogger(t *testing.T) {
	var logged bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })
	next := &recordingTransport{}
	req, err := http.NewRequest(http.MethodGet, "https://idp.dev.gematik.solutions/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := AddAPIKeyTransport(next, "").RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if logged.Len() != 0 {
		t.Errorf("logged %q", logged.String())
	}
}

func TestMutualTLSKeepsTheBaseClientsTrust(t *testing.T) {
	roots := x509.NewCertPool()
	verified := false
	base := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:          roots,
		MinVersion:       tls.VersionTLS13,
		VerifyConnection: func(tls.ConnectionState) error { verified = true; return nil },
	}}
	certificate := func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil }
	layered, ok := transportWithClientCertificate(base, certificate).(*http.Transport)
	if !ok {
		t.Fatal("not an http.Transport")
	}
	if layered.TLSClientConfig.RootCAs != roots {
		t.Error("the base client's roots are gone")
	}
	if layered.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d", layered.TLSClientConfig.MinVersion)
	}
	if layered.TLSClientConfig.VerifyConnection == nil || layered.TLSClientConfig.VerifyConnection(tls.ConnectionState{}) != nil || !verified {
		t.Error("the base client's verification is gone")
	}
	if layered.TLSClientConfig.GetClientCertificate == nil {
		t.Error("no client certificate")
	}
	if base.TLSClientConfig.GetClientCertificate != nil {
		t.Error("the base transport was changed")
	}
}
