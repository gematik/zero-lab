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

package idpd

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/brainpool/josebp"
	"github.com/gematik/zero-lab/go/openid"
)

func encryptDir(t *testing.T, key []byte, alg jose.KeyAlgorithm, enc jose.ContentEncryption, plaintext string) string {
	t.Helper()
	encrypter, err := jose.NewEncrypter(enc, jose.Recipient{Algorithm: alg, Key: key}, (&jose.EncrypterOptions{}).WithContentType("NJWT"))
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := encrypter.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	compact, err := encrypted.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func tokenKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func TestDecryptTokenReturnsTheNestedTokenOfADirA256GCMJWE(t *testing.T) {
	key := tokenKey(t)
	token := encryptDir(t, key, jose.DIRECT, jose.A256GCM, `{"njwt":"inner.token.here"}`)
	inner, err := decryptToken(token, key)
	if err != nil {
		t.Fatal(err)
	}
	if inner != "inner.token.here" {
		t.Errorf("inner = %q", inner)
	}
}

func TestDecryptTokenRefusesOtherKeysAndAlgorithms(t *testing.T) {
	key := tokenKey(t)
	for name, token := range map[string]string{
		"another key":   encryptDir(t, tokenKey(t), jose.DIRECT, jose.A256GCM, `{"njwt":"x"}`),
		"A128CBC-HS256": encryptDir(t, key, jose.DIRECT, jose.A128CBC_HS256, `{"njwt":"x"}`),
		"A256GCMKW":     encryptDir(t, key, jose.A256GCMKW, jose.A256GCM, `{"njwt":"x"}`),
		"not a JWE":     "a.b.c",
		"empty":         "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decryptToken(token, key); err == nil {
				t.Error("accepted")
			}
		})
	}
}

func TestDecryptTokenRefusesAPlaintextThatIsNoNJWT(t *testing.T) {
	key := tokenKey(t)
	if _, err := decryptToken(encryptDir(t, key, jose.DIRECT, jose.A256GCM, "no json"), key); err == nil {
		t.Error("accepted")
	}
}

func newBrainpoolKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := brainpool.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func signIDToken(t *testing.T, key *ecdsa.PrivateKey, alg string, claims map[string]any) string {
	t.Helper()
	builder := josebp.NewJWTBuilder().Header("alg", alg)
	for name, value := range claims {
		builder.Claim(name, value)
	}
	signed, err := builder.Sign(sha256.New(), brainpool.SignFuncPrivateKey(key))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func TestCheckIDToken(t *testing.T) {
	const (
		issuer   = "https://idp.example"
		clientID = "client"
	)
	key := newBrainpoolKey(t)
	public := &josebp.JSONWebKey{Key: &key.PublicKey}
	now := time.Unix(1_700_000_000, 0)
	checks := openid.IDTokenChecks{Nonce: "n", Issuer: issuer, ClientID: clientID, Now: now, Skew: idTokenSkew}
	claims := func(overrides map[string]any) map[string]any {
		all := map[string]any{"iss": issuer, "aud": clientID, "nonce": "n", "exp": now.Add(time.Hour).Unix(), "iat": now.Unix()}
		for name, value := range overrides {
			if value == nil {
				delete(all, name)
			} else {
				all[name] = value
			}
		}
		return all
	}
	at := func(offset time.Duration) int64 { return now.Add(offset).Unix() }

	for _, tc := range []struct {
		name  string
		token string
		want  error
	}{
		{"a valid token passes", signIDToken(t, key, josebp.AlgorithmNameBP256R1, claims(nil)), nil},
		{"another issuer is refused", signIDToken(t, key, josebp.AlgorithmNameBP256R1, claims(map[string]any{"iss": "https://evil.example"})), openid.ErrIssuerMismatch},
		{"another audience is refused", signIDToken(t, key, josebp.AlgorithmNameBP256R1, claims(map[string]any{"aud": "other"})), openid.ErrAudienceMismatch},
		{"a missing nonce is refused", signIDToken(t, key, josebp.AlgorithmNameBP256R1, claims(map[string]any{"nonce": nil})), openid.ErrMissingClaim},
		{"a missing exp is refused", signIDToken(t, key, josebp.AlgorithmNameBP256R1, claims(map[string]any{"exp": nil})), openid.ErrMissingClaim},
		{"exp within five minutes passes", signIDToken(t, key, josebp.AlgorithmNameBP256R1, claims(map[string]any{"exp": at(-idTokenSkew + time.Second)})), nil},
		{"exp five minutes ago is refused", signIDToken(t, key, josebp.AlgorithmNameBP256R1, claims(map[string]any{"exp": at(-idTokenSkew)})), openid.ErrTokenExpired},
		{"iat past the skew is refused", signIDToken(t, key, josebp.AlgorithmNameBP256R1, claims(map[string]any{"iat": at(idTokenSkew + time.Second)})), openid.ErrTokenIssuedInFuture},
		{"nbf past the skew is refused", signIDToken(t, key, josebp.AlgorithmNameBP256R1, claims(map[string]any{"nbf": at(idTokenSkew + time.Second)})), openid.ErrTokenNotYetValid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkIDToken(tc.token, public, checks); !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCheckIDTokenRefusesASignatureThatDoesNotVerify(t *testing.T) {
	key := newBrainpoolKey(t)
	now := time.Unix(1_700_000_000, 0)
	token := signIDToken(t, newBrainpoolKey(t), josebp.AlgorithmNameBP256R1, map[string]any{"iss": "i", "aud": "c", "nonce": "n", "exp": now.Add(time.Hour).Unix()})
	checks := openid.IDTokenChecks{Nonce: "n", Issuer: "i", ClientID: "c", Now: now}
	if err := checkIDToken(token, &josebp.JSONWebKey{Key: &key.PublicKey}, checks); err == nil {
		t.Error("accepted a signature by another key")
	}
}

// ES256 is the case that matters: josebp alone would take it with a 256-bit Brainpool key.
func TestCheckIDTokenRefusesAnyAlgorithmButBP256R1(t *testing.T) {
	key := newBrainpoolKey(t)
	now := time.Unix(1_700_000_000, 0)
	claims := map[string]any{"iss": "i", "aud": "c", "nonce": "n", "exp": now.Add(time.Hour).Unix()}
	checks := openid.IDTokenChecks{Nonce: "n", Issuer: "i", ClientID: "c", Now: now}
	for _, alg := range []string{"ES256", "none", "HS256", ""} {
		token := signIDToken(t, key, alg, claims)
		if err := checkIDToken(token, &josebp.JSONWebKey{Key: &key.PublicKey}, checks); err == nil {
			t.Errorf("accepted alg %q", alg)
		}
	}
}

func TestCheckIDTokenRefusesATokenWithoutAlg(t *testing.T) {
	key := newBrainpoolKey(t)
	builder := josebp.NewJWTBuilder().Claim("iss", "i")
	signed, err := builder.Sign(sha256.New(), brainpool.SignFuncPrivateKey(key))
	if err != nil {
		t.Fatal(err)
	}
	checks := openid.IDTokenChecks{Nonce: "n", Issuer: "i", ClientID: "c", Now: time.Now()}
	err = checkIDToken(string(signed), &josebp.JSONWebKey{Key: &key.PublicKey}, checks)
	if err == nil || !strings.Contains(err.Error(), "alg") {
		t.Errorf("err = %v", err)
	}
}

func TestUnmarshalTokenResponseKeepsTheRawIDToken(t *testing.T) {
	data, err := json.Marshal(map[string]any{"access_token": "a", "id_token": "b", "expires_in": 300})
	if err != nil {
		t.Fatal(err)
	}
	response, err := unmarshalTokenResponse(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	if response.IDTokenRaw != "b" || response.AccessToken != "a" || response.ExpiresIn != 300 {
		t.Errorf("%+v", response)
	}
}
