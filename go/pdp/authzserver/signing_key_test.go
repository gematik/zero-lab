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

package authzserver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/gematik/zero-lab/go/oauth/oidc"
)

// countingSigner stands for a key the process cannot read, as an HSM holds one: the server has
// only this function to sign with.
type countingSigner struct {
	inner crypto.Signer
	calls atomic.Int32
}

func (s *countingSigner) Public() crypto.PublicKey { return s.inner.Public() }

func (s *countingSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	s.calls.Add(1)
	return s.inner.Sign(r, digest, opts)
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return key
}

func writeJWK(t *testing.T, key any, kid string) (dir, name string) {
	t.Helper()
	raw, err := json.Marshal(jose.JSONWebKey{Key: key, KeyID: kid})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	dir = t.TempDir()
	name = "sign.jwk"
	if err := os.WriteFile(filepath.Join(dir, name), raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return dir, name
}

// servers.md rule 17: a server without its key does not start; it never makes one up.
func TestSigningKey_missing_or_unusable_fails_startup(t *testing.T) {
	t.Run("no key at all", func(t *testing.T) {
		if _, err := New(Config{Issuer: testIssuer}); err == nil {
			t.Fatal("a server started without a signing key")
		}
	})
	t.Run("no path", func(t *testing.T) {
		if _, err := (&Config{}).LoadSigningKey(); err == nil {
			t.Fatal("no error without sign_jwk_path")
		}
	})
	t.Run("no file", func(t *testing.T) {
		cfg := Config{BaseDir: t.TempDir(), SignJwkPath: "absent.jwk"}
		if _, err := cfg.LoadSigningKey(); err == nil {
			t.Fatal("no error for a missing file")
		}
	})
	t.Run("not a JWK", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "sign.jwk"), []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := Config{BaseDir: dir, SignJwkPath: "sign.jwk"}
		if _, err := cfg.LoadSigningKey(); err == nil {
			t.Fatal("no error for garbage")
		}
	})
	t.Run("a public key only", func(t *testing.T) {
		dir, name := writeJWK(t, newP256(t).Public(), "")
		cfg := Config{BaseDir: dir, SignJwkPath: name}
		if _, err := cfg.LoadSigningKey(); err == nil {
			t.Fatal("no error for a key that cannot sign")
		}
	})
}

// keys.md rule 5: the key is bound to ES256, whatever a file or a signer holds.
func TestSigningKey_must_be_P256(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for name, signer := range map[string]crypto.Signer{"P-384": p384, "RSA": rsaKey} {
		t.Run(name, func(t *testing.T) {
			_, err := New(Config{Issuer: testIssuer, SigningKey: &SigningKey{Signer: signer}})
			if err == nil || !strings.Contains(err.Error(), "P-256") {
				t.Fatalf("got %v", err)
			}
			dir, file := writeJWK(t, signer, "")
			cfg := Config{BaseDir: dir, SignJwkPath: file}
			if _, err := cfg.LoadSigningKey(); err == nil {
				t.Fatal("no error for the file")
			}
		})
	}
}

// keys.md rule 1: the server holds a function to sign with, and its tokens verify under the keys
// it publishes.
func TestSigningKey_tokens_are_signed_through_the_signer(t *testing.T) {
	signer := &countingSigner{inner: newP256(t)}
	server, err := New(Config{
		Issuer:     testIssuer,
		SigningKey: &SigningKey{Signer: signer, KeyID: "hsm-1"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	raw, err := server.signAccessToken(map[string]any{"sub": "sub"})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if signer.calls.Load() != 1 {
		t.Fatalf("signer called %d times", signer.calls.Load())
	}
	if _, err := oidc.VerifyJWS(raw, server.jwks, oidc.VerifyOptions{RequireKeyAlgorithm: true}); err != nil {
		t.Fatalf("the token does not verify under the published keys: %v", err)
	}
	message, err := jose.ParseSignedCompact(string(raw), []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}
	if kid := message.Signatures[0].Protected.KeyID; kid != "hsm-1" {
		t.Fatalf("kid = %q", kid)
	}
}

// The file's key keeps its kid, or gets its thumbprint; only the public half is published.
func TestSigningKey_from_a_file(t *testing.T) {
	key := newP256(t)
	for _, tc := range []struct{ name, kid string }{{"with kid", "file-kid"}, {"without kid", ""}} {
		t.Run(tc.name, func(t *testing.T) {
			dir, file := writeJWK(t, key, tc.kid)
			cfg := Config{Issuer: testIssuer, BaseDir: dir, SignJwkPath: file}
			loaded, err := cfg.LoadSigningKey()
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if tc.kid != "" && loaded.KeyID != tc.kid {
				t.Fatalf("kid = %q", loaded.KeyID)
			}
			cfg.SigningKey = loaded
			server, err := New(cfg)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if server.signerKeyID == "" {
				t.Fatal("no kid")
			}
			published, err := json.Marshal(server.jwks)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(published), `"d"`) {
				t.Fatalf("private key material published: %s", published)
			}
		})
	}
}
