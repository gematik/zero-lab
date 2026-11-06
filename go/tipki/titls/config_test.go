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

package titls

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type handshakeProfile struct {
	Versions         []string `json:"versions"`
	CipherSuites     []string `json:"cipher_suites"`
	Groups           []string `json:"groups"`
	GroupsAvailable  []string `json:"groups_if_available"`
	SignatureSchemes []string `json:"signature_schemes"`
}

var tls13Names = []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}

func sortedSuiteNames(ids []uint16) []string {
	names := make([]string, len(ids))
	for i, id := range ids {
		names[i] = tls.CipherSuiteName(id)
	}
	slices.Sort(names)
	return names
}

func configs(t *testing.T) map[string]*tls.Config {
	t.Helper()
	ti := NewTiVerifier(NewTrustSource(nil), nil, Options{})
	web := NewWebVerifier(webCorpusCheck(t), Offline{}, Options{})
	return map[string]*tls.Config{"ti": ti.ClientConfig(), "web": web.ClientConfig()}
}

// TLSV-010, TLSV-011 and TLSV-012: each profile's configuration offers the versions, TLS 1.2 suites and groups
// of handshake.json; TLS 1.3's suites, which crypto/tls fixes, include those it lists, and the one it does
// not list is refused once negotiated.
func TestTLSV011TheConfigurationOffersWhatHandshakeJSONLists(t *testing.T) {
	var file struct {
		TI  handshakeProfile `json:"ti"`
		Web handshakeProfile `json:"web"`
	}
	if err := json.Unmarshal(corpusFile(t, "handshake.json"), &file); err != nil {
		t.Fatal(err)
	}
	handshake := map[string]handshakeProfile{"ti": file.TI, "web": file.Web}
	groupIDs := map[string]tls.CurveID{"secp256r1": tls.CurveP256, "secp384r1": tls.CurveP384}
	for profile, config := range configs(t) {
		spec := handshake[profile]
		if !slices.Equal(spec.Versions, []string{"TLSv1.3", "TLSv1.2"}) ||
			config.MinVersion != tls.VersionTLS12 || config.MaxVersion != tls.VersionTLS13 {
			t.Errorf("%s: versions %#04x to %#04x, the spec %q", profile, config.MinVersion, config.MaxVersion, spec.Versions)
		}

		var tls12, tls13 []string
		for _, name := range spec.CipherSuites {
			if slices.Contains(tls13Names, name) {
				tls13 = append(tls13, name)
			} else {
				tls12 = append(tls12, name)
			}
		}
		slices.Sort(tls12)
		if got := sortedSuiteNames(config.CipherSuites); !slices.Equal(got, tls12) {
			t.Errorf("%s: TLS 1.2 suites %q, the spec %q", profile, got, tls12)
		}
		slices.Sort(tls13)
		if got := sortedSuiteNames(tls13Suites); !slices.Equal(got, tls13) {
			t.Errorf("%s: accepted TLS 1.3 suites %q, the spec %q", profile, got, tls13)
		}

		var groups []tls.CurveID
		for _, name := range spec.Groups {
			id, ok := groupIDs[name]
			if !ok {
				t.Fatalf("%s: group %s is not in this table", profile, name)
			}
			groups = append(groups, id)
		}
		if !slices.Equal(config.CurvePreferences, groups) {
			t.Errorf("%s: groups %v, the spec %q", profile, config.CurvePreferences, spec.Groups)
		}
		if config.Renegotiation != tls.RenegotiateNever || config.ClientSessionCache != nil {
			t.Errorf("%s: renegotiation %v, session cache %v", profile, config.Renegotiation, config.ClientSessionCache)
		}
	}
}

// TLSV-010 and TLSV-011: what crypto/tls offers beyond the spec is refused when a server chooses it.
func TestTLSV011WhatTheSpecDoesNotListIsRefusedWhenNegotiated(t *testing.T) {
	for name, cs := range map[string]tls.ConnectionState{
		"ChaCha20-Poly1305": {Version: tls.VersionTLS13, CipherSuite: tls.TLS_CHACHA20_POLY1305_SHA256},
		"CBC in TLS 1.2":    {Version: tls.VersionTLS12, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA},
		"TLS 1.1":           {Version: tls.VersionTLS11, CipherSuite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	} {
		if _, ok := errors.AsType[*RefusedError](negotiated(cs)); !ok {
			t.Errorf("%s is accepted", name)
		}
	}
	for _, suite := range append(slices.Clone(cipherSuites), tls13Suites...) {
		version := uint16(tls.VersionTLS12)
		if slices.Contains(tls13Suites, suite) {
			version = tls.VersionTLS13
		}
		if err := negotiated(tls.ConnectionState{Version: version, CipherSuite: suite}); err != nil {
			t.Errorf("%s: %v", tls.CipherSuiteName(suite), err)
		}
	}
}

// TLSV-002: the web configuration keeps crypto/tls's verification and adds its own; the ti configuration
// verifies everything itself; every refusal ends the handshake with an error carrying the spec's code.
func TestTLSV002EveryConfigurationVerifies(t *testing.T) {
	all := configs(t)
	if web := all["web"]; web.InsecureSkipVerify || web.RootCAs == nil || web.VerifyConnection == nil {
		t.Error("the web configuration does not verify")
	}
	if ti := all["ti"]; ti.VerifyConnection == nil {
		t.Error("the ti configuration does not verify")
	}
	for profile, config := range all {
		err := config.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, ServerName: "svc.ti.test"})
		refused, ok := errors.AsType[*RefusedError](err)
		if !ok || refused.Verdict.Valid() {
			t.Errorf("%s: no certificate, %v", profile, err)
		}
		err = config.VerifyConnection(tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256})
		if refused, ok := errors.AsType[*RefusedError](err); !ok || refused.Verdict.Code != NameMismatch {
			t.Errorf("%s: no server name, %v", profile, err)
		}
	}
}

// TLSV-002: no option skips a rule. crypto/tls's own verification is switched off in exactly one place, the
// ti configuration, which verifies in VerifyConnection instead.
func TestTLSV002OnlyTheTiConfigurationLeavesVerificationToItself(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, name := range sources {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.Lines(string(body)) {
			if strings.Contains(line, "InsecureSkipVerify") && !strings.HasPrefix(strings.TrimSpace(line), "//") {
				found++
				if name != "verifier.go" || !strings.Contains(line, "InsecureSkipVerify: true, //nolint:gosec // G402: ") {
					t.Errorf("%s: %s", name, strings.TrimSpace(line))
				}
			}
		}
	}
	if found != 1 {
		t.Fatalf("InsecureSkipVerify set %d times", found)
	}
}
