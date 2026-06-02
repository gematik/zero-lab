package brainpool_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
)

func TestJose(t *testing.T) {

	sigPrK, _ := parsePEMKey(testKeyBytes)
	sigCert, _ := parsePEMCert(testCertBytes)

	t.Logf("Private Key: %v", sigPrK)

	j, err := brainpool.NewJWTBuilder().
		Header("alg", brainpool.AlgorithmNameBP256R1).
		Header("x5c", []string{base64.StdEncoding.EncodeToString(sigCert.Raw)}).
		Claim("iss", "https://example.com").
		Claim("iat", time.Now().Unix()).
		Claim("exp", time.Now().Add(time.Hour).Unix()).
		Sign(sha256.New(), brainpool.SignFuncPrivateKey(sigPrK))
	if err != nil {
		t.Fatalf("Sign returned an error: %v", err)
	}

	t.Logf("JWT: %v", string(j))

	// try to parse without verifiers
	_, err = brainpool.ParseToken(j)
	if err == nil {
		t.Fatalf("jwt.Parse should return an error")
	}
	t.Log(err)

	// try to parse with verifiers
	verifiedToken, err := brainpool.ParseToken(j, brainpool.WithEcdsaPublicKey(&sigPrK.PublicKey))
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	t.Logf("Verified Token claims: %v", verifiedToken.Claims)

}

/*
// sign with jwx, verify with our jose
func TestCrossVerify(t *testing.T) {
	sigPrK, _ := parsePEMKey(testKeyBytes)

	token, err := jwt.NewBuilder().
		Issuer("https://example.com").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Build()

	if err != nil {
		t.Fatalf("NewBuilder returned an error: %v", err)
	}

	signedToken, err := jwt.Sign(token, jwt.WithKey(jwa.ES256, sigPrK))
	if err != nil {
		t.Fatalf("Sign returned an error: %v", err)
	}

	t.Logf("Signed Token: %v", string(signedToken))

	// verify token using custom jose
	verifiedToken, err := brainpool.ParseToken(signedToken, brainpool.WithEcdsaPublicKey(&sigPrK.PublicKey))
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}

	t.Logf("Verified Token claims: %v", verifiedToken.Claims)

}

// sign with our jose, verify with jwx
func TestCrossSign(t *testing.T) {
	sigPrK, _ := parsePEMKey(testKeyBytes)

	signedToken, err := brainpool.NewJWTBuilder().
		Header("alg", brainpool.AlgorithmNameES256).
		Claim("iss", "https://example.com").
		Claim("iat", time.Now().Unix()).
		Claim("exp", time.Now().Add(time.Hour).Unix()).
		Sign(sha256.New(), brainpool.SignFuncPrivateKey(sigPrK))
	if err != nil {
		t.Fatalf("Sign returned an error: %v", err)
	}

	t.Logf("Signed Token: %v", string(signedToken))

	// verify token using jwx
	verifiedToken, err := jwt.Parse(signedToken, jwt.WithKey(jwa.ES256, &sigPrK.PublicKey))
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}

	t.Logf("Verified Token claims: %v", verifiedToken.Claims)
}

func TestJWK(t *testing.T) {
	jwkString := `{
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
	jwk := new(brainpool.JSONWebKey)
	if err := json.Unmarshal([]byte(jwkString), jwk); err != nil {
		t.Fatalf("Unmarshal returned an error: %v", err)
	}

	t.Logf("JWK: %v", jwk)
}
*/
