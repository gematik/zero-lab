package api

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"testing"

	"github.com/gematik/zero-lab/pkg/util"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func TestSignedMessage(t *testing.T) {
	prkStr := `{"crv":"P-256","d":"RAsLqZOL-WN8-YWrEbxM_cqG_Tmr-6LsfOG7DJMZYac","kty":"EC","x":"X6G6MXf5A0Pn5MkCffwzg5V64UaPUE0t2RahDjGMBrA","y":"uuoTkMVDsT_yF-PCDtDRv1vBniA13KNtMd4pqqM_onc"}`

	prkJwk, _ := jwk.ParseKey([]byte(prkStr))
	pukJwk, _ := prkJwk.PublicKey()
	headers := jws.NewHeaders()
	headers.Set("cty", "x-registration-apple+json")
	headers.Set("jwk", pukJwk)
	headers.Set("nonce", "nonce")
	headers.Set("alg", "ES256")

	thumbprint, _ := pukJwk.Thumbprint(crypto.SHA256)
	t.Log(base64.RawURLEncoding.EncodeToString(thumbprint))

	payload := []byte(`{"payload":"test"}`)

	signedJWS, _ := jws.Sign(payload,
		jws.WithKey(jwa.ES256, prkJwk, jws.WithProtectedHeaders(headers)))
	t.Log(util.JWSToText(string(signedJWS)))

	verifiedMessage, err := ParseSignedMessage(
		signedJWS,
		func(nonce string) error { return nil },
	)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(verifiedMessage.Payload, payload) {
		t.Fatal("payloads do not match")
	}

	if nonce, ok := verifiedMessage.ProtectedHeaders.Get("nonce"); ok && nonce != "nonce" {
		t.Fatal("nonce does not match")
	}

	t.Log(verifiedMessage.ContentType)
}
