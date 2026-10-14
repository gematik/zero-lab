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
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

func signedTokenWithAlg(t *testing.T, alg string, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	tok, err := NewJWTBuilder().
		Header("alg", alg).
		Header("typ", "JWT").
		Claim("sub", "test").
		Sign(sha256.New(), brainpool.SignFuncPrivateKey(key))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func TestVerifyRejectsAlgCurveMismatch(t *testing.T) {
	key, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	// alg ES384/BP384R1/ES512 all imply a non-256-bit curve, but the key is
	// brainpoolP256r1. Each must be rejected before signature verification.
	for _, alg := range []string{algES384, algBP384R1, algES512, algBP512R1} {
		tok := signedTokenWithAlg(t, alg, key)
		if _, err := ParseToken(tok, withECDSAPublicKey(&key.PublicKey)); err == nil {
			t.Fatalf("alg %s with P256r1 key was accepted", alg)
		}
	}
}

func TestVerifyAcceptsMatchingAlg(t *testing.T) {
	key, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// Both ES256 and BP256R1 are valid for a 256-bit curve in the gematik stack.
	for _, alg := range []string{AlgorithmNameES256, AlgorithmNameBP256R1} {
		tok := signedTokenWithAlg(t, alg, key)
		if _, err := ParseToken(tok, withECDSAPublicKey(&key.PublicKey)); err != nil {
			t.Fatalf("alg %s with P256r1 key rejected: %v", alg, err)
		}
	}
}

func TestVerifyRejectsSignatureOfWrongLength(t *testing.T) {
	key, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tok := signedTokenWithAlg(t, AlgorithmNameBP256R1, key)
	signingInput := tok[:bytes.LastIndexByte(tok, '.')+1]
	for _, n := range []int{0, 1, 31, 63, 65} {
		forged := base64.RawURLEncoding.AppendEncode(bytes.Clone(signingInput), make([]byte, n))
		if _, err := ParseToken(forged, withECDSAPublicKey(&key.PublicKey)); err == nil {
			t.Errorf("%d-byte signature accepted", n)
		}
	}
}
