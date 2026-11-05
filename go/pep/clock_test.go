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

// Package pep is a policy enforcement point for HTTP resources: Enforcers decide on each request from its
// access token, DPoP proof or session cookie, and a denial becomes an OAuth 2.0 error response.
package pep_test

import (
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/pep"
)

// Decision code takes the time it judges at (docs/architecture.md, goals 3 and 6): an access token valid
// for another hour is refused by a PEP whose clock is two hours ahead.
func TestThePEPJudgesTokensByItsClock(t *testing.T) {
	jwkSet, err := pep.ParseJWKSet([]byte(publicJWSKSet))
	if err != nil {
		t.Fatal(err)
	}
	token, err := createTestAccessToken([]byte(privateJWK1), []string{"read"}, time.Now().Add(time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	build := func(opts ...func(*pep.Builder) *pep.Builder) *pep.PEP {
		b := pep.NewBuilder().Resource("https://example.com").WithJWKSet(jwkSet)
		for _, opt := range opts {
			b = opt(b)
		}
		p, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if _, err := build().VerifyAccessToken(token); err != nil {
		t.Fatalf("the system clock refused a valid token: %v", err)
	}
	later := func(b *pep.Builder) *pep.Builder {
		return b.WithClock(func() time.Time { return time.Now().Add(2 * time.Hour) })
	}
	if _, err := build(later).VerifyAccessToken(token); err == nil {
		t.Error("a clock two hours ahead accepted a token that expires in one")
	}
}
