package josebp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

// TestSignVerifyRoundTrip signs with a software key and verifies with stdlib ecdsa — no jwx.
func TestSignVerifyRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name  string
		curve elliptic.Curve
		alg   string
	}{
		{"BP256R1", brainpool.P256r1(), AlgorithmNameBP256R1},
		{"ES256", elliptic.P256(), AlgorithmNameES256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prk, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			token, err := NewJWTBuilder().
				Header("alg", tc.alg).
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

// TestJSONWebKeyParseBrainpoolX5C parses a real gematik IDP JWK (BP-256 + Brainpool x5c).
func TestJSONWebKeyParseBrainpoolX5C(t *testing.T) {
	const jwkJSON = `{
    "kid": "puk_idp_sig",
    "use": "sig",
    "kty": "EC",
    "crv": "BP-256",
    "x": "pogLhoK59j_BX7OKqZWQ0GkEckCbr2IJ5HZLRLkXyn8",
    "y": "qBNddqxoOK_2Vd5ocnuQtP1q_PuRslxfAQjv4E4dReA",
    "x5c": [
        "MIIC+jCCAqCgAwIBAgICG3wwCgYIKoZIzj0EAwIwgYQxCzAJBgNVBAYTAkRFMR8wHQYDVQQKDBZnZW1hdGlrIEdtYkggTk9ULVZBTElEMTIwMAYDVQQLDClLb21wb25lbnRlbi1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEgMB4GA1UEAwwXR0VNLktPTVAtQ0EyOCBURVNULU9OTFkwHhcNMjEwNTA2MTUyODI5WhcNMjYwNTA1MTUyODI4WjB9MQswCQYDVQQGEwJBVDEoMCYGA1UECgwfUklTRSBHbWJIIFRFU1QtT05MWSAtIE5PVC1WQUxJRDEpMCcGA1UEBRMgMzMyMjUtVjAxSTAwMDFUMjAyMTA1MDYxNDM5NTk0MDYxGTAXBgNVBAMMEG1haW4ucnUuaWRwLnJpc2UwWjAUBgcqhkjOPQIBBgkrJAMDAggBAQcDQgAEpogLhoK59j/BX7OKqZWQ0GkEckCbr2IJ5HZLRLkXyn+oE112rGg4r/ZV3mhye5C0/Wr8+5GyXF8BCO/gTh1F4KOCAQUwggEBMB0GA1UdDgQWBBSsDmRSbs5NJ9mkyg4xsmmYb7osDTAfBgNVHSMEGDAWgBQAajiQ85muIY9S2u7BjG6ArWEiyTBPBggrBgEFBQcBAQRDMEEwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3NwMi10ZXN0cmVmLmtvbXAtY2EudGVsZW1hdGlrLXRlc3Qvb2NzcC9lYzAOBgNVHQ8BAf8EBAMCB4AwIQYDVR0gBBowGDAKBggqghQATASBIzAKBggqghQATASBSzAMBgNVHRMBAf8EAjAAMC0GBSskCAMDBCQwIjAgMB4wHDAaMAwMCklEUC1EaWVuc3QwCgYIKoIUAEwEggQwCgYIKoZIzj0EAwIDSAAwRQIgcVkzvJuJ4y/2wAeYcQaKJyWELB4RuO1AcmbhEaPX2y8CIQCG3d0zgqqbskiLAbmwbxMOjrtClRS6xK2J61BATOj20w=="
    ]
}`
	var jwk JSONWebKey
	if err := json.Unmarshal([]byte(jwkJSON), &jwk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	pub, ok := jwk.Key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("key is not an ecdsa public key")
	}
	if pub.Curve != brainpool.P256r1() {
		t.Fatalf("curve = %s", pub.Curve.Params().Name)
	}
	if len(jwk.Certificates) != 1 {
		t.Fatalf("certificates = %d", len(jwk.Certificates))
	}
}
