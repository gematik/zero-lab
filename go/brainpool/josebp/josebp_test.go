package josebp

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

// TestSignVerifyRoundTrip signs a Brainpool key and verifies with stdlib ecdsa — no jwx. Both the
// native BP256R1 alg and the gematik "ES256 over a Brainpool key" case (used by epa's client
// attest) are covered; the curve is always Brainpool.
func TestSignVerifyRoundTrip(t *testing.T) {
	for _, alg := range []string{AlgorithmNameBP256R1, AlgorithmNameES256} {
		t.Run(alg, func(t *testing.T) {
			prk, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			token, err := NewJWTBuilder().
				Header("alg", alg).
				Header("typ", "JWT").
				Claim("iss", "test").
				Sign(sha256.New(), brainpool.SignFuncPrivateKey(prk))
			if err != nil {
				t.Fatalf("sign: %v", err)
			}

			tok, err := ParseToken(token, WithEcdsaPublicKey(&prk.PublicKey))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if tok.Claims["iss"] != "test" {
				t.Fatalf("iss = %v", tok.Claims["iss"])
			}

			// also via WithKey(JSONWebKey)
			if _, err := ParseToken(token, WithKey(&JSONWebKey{Key: &prk.PublicKey})); err != nil {
				t.Fatalf("verify via JSONWebKey: %v", err)
			}

			// tampering must fail
			token[len(token)-1] ^= 0x01
			if _, err := ParseToken(token, WithEcdsaPublicKey(&prk.PublicKey)); err == nil {
				t.Fatal("expected verification failure on tampered token")
			}
		})
	}
}

// TestJWEEncryptRoundTrip encrypts via EncryptECDHES and decrypts manually (no jwx).
func TestJWEEncryptRoundTrip(t *testing.T) {
	prk, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("Hello, Brainpool JWE!")

	jwe, err := NewJWEBuilder().Header("cty", "NJWT").Plaintext(plaintext).EncryptECDHES(&prk.PublicKey)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	parts := strings.Split(string(jwe), ".")
	if len(parts) != 5 {
		t.Fatalf("want 5 compact parts, got %d", len(parts))
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var hdr struct {
		Epk JSONWebKey `json:"epk"`
	}
	if err := json.Unmarshal(headerJSON, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	epk, ok := hdr.Epk.Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("epk is not an ecdsa public key")
	}

	cek, err := DeriveECDHES("A256GCM", []byte{}, []byte{}, prk, epk, 32)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	iv, _ := base64.RawURLEncoding.DecodeString(parts[2])
	ct, _ := base64.RawURLEncoding.DecodeString(parts[3])
	tag, _ := base64.RawURLEncoding.DecodeString(parts[4])
	got, err := decryptAESGCMWithIVAndAAD(cek, iv, tag, ct, []byte(parts[0]))
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("roundtrip mismatch: got %q", got)
	}
}

// TestJSONWebKeyBrainpoolRoundTrip marshals and parses a Brainpool EC public key (crv "BP-256").
// The x5c→certificate path (brainpool.ParseCertificate) is covered end to end by the live gemidp
// SMC-B test, which parses the IDP's real Brainpool certificate.
func TestJSONWebKeyBrainpoolRoundTrip(t *testing.T) {
	prk, err := ecdsa.GenerateKey(brainpool.P256r1(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(&JSONWebKey{Key: &prk.PublicKey})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"crv":"BP-256"`) {
		t.Fatalf("expected crv BP-256 in %s", data)
	}

	var jwk JSONWebKey
	if err := json.Unmarshal(data, &jwk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pub, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("key is not an ecdsa public key")
	}
	if pub.Curve != brainpool.P256r1() {
		t.Fatalf("curve = %s", pub.Curve.Params().Name)
	}
	if pub.X.Cmp(prk.PublicKey.X) != 0 || pub.Y.Cmp(prk.PublicKey.Y) != 0 {
		t.Fatal("public key coordinates did not round-trip")
	}
}
