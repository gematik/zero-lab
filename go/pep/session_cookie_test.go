package pep

import (
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func TestGuardCookie(t *testing.T) {
	signKey, err := GenerateRandomKey(256)
	if err != nil {
		t.Fatal(err)
	}

	encKey, err := GenerateRandomKey(256)
	if err != nil {
		t.Fatal(err)
	}

	jwsPayload := []byte("Hello, World!")
	signed, err := jws.Sign(jwsPayload, jws.WithKey(jwa.HS256, signKey))
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := jwe.Encrypt([]byte(signed), jwe.WithContentEncryption(jwa.A256GCM), jwe.WithKey(jwa.DIRECT, encKey))
	if err != nil {
		t.Fatal(err)
	}

	t.Log(string(encrypted))

	cookieGuard := SessionCookieGuard{
		CookieName:  "test",
		DecryptFunc: DecryptWithDirectKeyFunc(encKey),
		VerifyFunc:  VerifyWithHS256KeyFunc(signKey),
	}

	httpReq := &http.Request{
		Header: http.Header{},
	}

	httpReq.AddCookie(&http.Cookie{
		Name:  "test",
		Value: string(encrypted),
	})

	guardContext := &GuardContext{}
	cookieGuard.VerifyRequest(guardContext, httpReq)

	if string(guardContext.SessionCookieRaw) != string(jwsPayload) {
		t.Fatalf("expected %s, got %s", jwsPayload, guardContext.SessionCookieRaw)
	}

}
