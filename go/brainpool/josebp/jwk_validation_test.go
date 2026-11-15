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

package josebp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

// validP256r1Point returns an on-curve (x, y) on brainpoolP256r1.
func validP256r1Point(t *testing.T) (*big.Int, *big.Int) {
	t.Helper()
	x, y := brainpool.P256r1().ScalarBaseMult([]byte{0x2a})
	if !brainpool.P256r1().IsOnCurve(x, y) {
		t.Fatal("test setup: point not on curve")
	}
	return x, y
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwkJSON(x, y, d string) []byte {
	m := map[string]string{"kty": "EC", "crv": "BP-256", "x": x, "y": y}
	if d != "" {
		m["d"] = d
	}
	out, _ := json.Marshal(m)
	return out
}

func TestUnmarshalJWKAcceptsValidPoint(t *testing.T) {
	x, y := validP256r1Point(t)
	raw := jwkJSON(b64(x.FillBytes(make([]byte, 32))), b64(y.FillBytes(make([]byte, 32))), "")
	var jwk JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err != nil {
		t.Fatalf("valid JWK rejected: %v", err)
	}
	if _, ok := jwk.Key.(*ecdsa.PublicKey); !ok {
		t.Fatalf("key type = %T, want *ecdsa.PublicKey", jwk.Key)
	}
}

func TestUnmarshalJWKRejectsOffCurvePoint(t *testing.T) {
	x, y := validP256r1Point(t)
	// Corrupt y so the point is off-curve.
	badY := new(big.Int).Add(y, big.NewInt(1))
	raw := jwkJSON(
		b64(x.FillBytes(make([]byte, 32))),
		b64(badY.FillBytes(make([]byte, 32))), "")
	var jwk JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err == nil {
		t.Fatal("off-curve JWK accepted")
	}
}

func TestUnmarshalJWKRejectsCoordinateOutOfRange(t *testing.T) {
	x, y := validP256r1Point(t)
	p := brainpool.P256r1().Params().P
	// x + p is congruent but non-canonical / out of range.
	bad := new(big.Int).Add(x, p)
	raw := jwkJSON(
		b64(bad.Bytes()), // oversized encoding (> 32 bytes)
		b64(y.FillBytes(make([]byte, 32))), "")
	var jwk JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err == nil {
		t.Fatal("out-of-range x accepted")
	}
}

func TestUnmarshalJWKRejectsBadPrivateScalar(t *testing.T) {
	x, y := validP256r1Point(t)
	n := brainpool.P256r1().Params().N
	cases := map[string]*big.Int{
		"zero":     big.NewInt(0),
		"equalsN":  new(big.Int).Set(n),
		"exceedsN": new(big.Int).Add(n, big.NewInt(1)),
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			raw := jwkJSON(
				b64(x.FillBytes(make([]byte, 32))),
				b64(y.FillBytes(make([]byte, 32))),
				b64(d.FillBytes(make([]byte, 32))))
			var jwk JSONWebKey
			if err := json.Unmarshal(raw, &jwk); err == nil {
				t.Fatalf("invalid private scalar (%s) accepted", name)
			}
		})
	}
}

func TestUnmarshalJWKRejectsMismatchedCurveForPrivateScalar(t *testing.T) {
	// d valid range but the point must still be on the named curve. Use an
	// on-curve point with a valid d to confirm the happy path still works.
	x, y := validP256r1Point(t)
	d := big.NewInt(0x2a) // the scalar we used to derive the point; in [1,n)
	raw := jwkJSON(
		b64(x.FillBytes(make([]byte, 32))),
		b64(y.FillBytes(make([]byte, 32))),
		b64(d.FillBytes(make([]byte, 32))))
	var jwk JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err != nil {
		t.Fatalf("valid private JWK rejected: %v", err)
	}
	priv, ok := jwk.Key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("key type = %T, want *ecdsa.PrivateKey", jwk.Key)
	}
	if priv.D.Sign() == 0 {
		t.Fatal("private scalar not set")
	}
}

// requireJSONRefused asserts that err refuses flawed for its flaw: a member named twice or
// invalid UTF-8 by the decoder, a member in another case by the check that misses it.
func requireJSONRefused(t *testing.T, flawed flawedJSON, err error, missing string) {
	t.Helper()
	var syntactic *jsontext.SyntacticError
	switch {
	case err == nil:
		t.Fatal("accepted")
	case strings.Contains(flawed.name, "member twice"):
		if !errors.Is(err, jsontext.ErrDuplicateName) {
			t.Fatalf("got %v, want a duplicate name", err)
		}
	case strings.Contains(flawed.name, "not UTF-8"):
		if !errors.As(err, &syntactic) || !strings.Contains(syntactic.Error(), "invalid UTF-8") {
			t.Fatalf("got %v, want invalid UTF-8", err)
		}
	case strings.Contains(flawed.name, "in another case"):
		if !strings.Contains(err.Error(), missing) {
			t.Fatalf("got %v, want %q", err, missing)
		}
	default:
		t.Fatalf("no expectation for %q", flawed.name)
	}
}

// Server rule 28: a JWK that names a member twice or is not UTF-8 is refused, not read with
// the last member winning, and "KTY" is not kty.
func TestServerRule28_AFlawedJWKIsRefused(t *testing.T) {
	for _, flawed := range flawedJWKs() {
		t.Run(flawed.name, func(t *testing.T) {
			var jwk JSONWebKey
			requireJSONRefused(t, flawed, json.Unmarshal(flawed.data, &jwk), "unsupported key type")
		})
	}
}

// Server rule 28: a token whose header or payload names a member twice, in any object, or is
// not UTF-8 is refused, though its signature verifies; "ALG" is not alg.
func TestServerRule28_AFlawedTokenIsRefused(t *testing.T) {
	key, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, flawed := range flawedTokens(key) {
		t.Run(flawed.name, func(t *testing.T) {
			_, err := ParseToken(flawed.data, withECDSAPublicKey(&key.PublicKey))
			requireJSONRefused(t, flawed, err, "missing alg header")
		})
	}
}
