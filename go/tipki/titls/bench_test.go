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
	"crypto/x509"
	"testing"
)

// The benchmarks `just tls-bench` holds to their budgets: a verification under each profile on the
// corpus's chains with their OCSP answers stapled, so no network takes part. Cold is a fresh verifier per
// handshake; cached is the same chain and host again.

func benchTi(b *testing.B) (func(Options) *TiVerifier, [][]byte, []byte) {
	b.Helper()
	m := readManifest(b)
	source := NewTrustSource(corpusStore(b, m, "ti"))
	verifier := func(opts Options) *TiVerifier { return NewTiVerifier(source, nil, opts) }
	return verifier, [][]byte{corpusDER(b, "ti-good.pem"), corpusDER(b, "ti-ca.pem")}, corpusFile(b, "ocsp/ti-good-good.der")
}

func benchWeb(b *testing.B) (func(Options) *WebVerifier, [][]byte, []byte) {
	b.Helper()
	check := NewWebCheck([]*x509.Certificate{corpusCert(b, "web-root.pem")})
	verifier := func(opts Options) *WebVerifier { return NewWebVerifier(check, Offline{}, opts) }
	return verifier, [][]byte{corpusDER(b, "web-p256.pem"), corpusDER(b, "web-ca.pem")}, corpusFile(b, "ocsp/web-p256-good.der")
}

func BenchmarkTiCold(b *testing.B) {
	verifier, chain, stapled := benchTi(b)
	v := verifier(Options{CacheSize: -1})
	for b.Loop() {
		if verdict := v.Verify(b.Context(), chain, "svc.ti.test", stapled, at); !verdict.Valid() {
			b.Fatal(verdict.Code, verdict.Detail)
		}
	}
}

func BenchmarkTiCached(b *testing.B) {
	verifier, chain, stapled := benchTi(b)
	v := verifier(Options{})
	v.Verify(b.Context(), chain, "svc.ti.test", stapled, at)
	for b.Loop() {
		if verdict := v.Verify(b.Context(), chain, "svc.ti.test", stapled, at); verdict.Detail != "reused" {
			b.Fatal(verdict.Code, verdict.Detail)
		}
	}
}

func BenchmarkWebCold(b *testing.B) {
	verifier, chain, stapled := benchWeb(b)
	v := verifier(Options{CacheSize: -1})
	for b.Loop() {
		if verdict := v.Verify(b.Context(), chain, "www.web.test", stapled, at); !verdict.Valid() {
			b.Fatal(verdict.Code, verdict.Detail)
		}
	}
}

func BenchmarkWebCached(b *testing.B) {
	verifier, chain, stapled := benchWeb(b)
	v := verifier(Options{})
	v.Verify(b.Context(), chain, "www.web.test", stapled, at)
	for b.Loop() {
		if verdict := v.Verify(b.Context(), chain, "www.web.test", stapled, at); verdict.Detail != "reused" {
			b.Fatal(verdict.Code, verdict.Detail)
		}
	}
}
