package bff_test

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gematik/zero-lab/go/bff"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jws"
)

func TestGuardSessionCookie(t *testing.T) {
	signKey := bff.GenerateRandomKey(256)
	encKey := bff.GenerateRandomKey(256)

	cookiePlaintext := []byte("Hello, World!")
	signed, err := jws.Sign(cookiePlaintext, jws.WithKey(jwa.HS256, signKey))
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := jwe.Encrypt([]byte(signed), jwe.WithContentEncryption(jwa.A256GCM), jwe.WithKey(jwa.DIRECT, encKey))
	if err != nil {
		t.Fatal(err)
	}

	// encr<pt with wrong key
	badKey := bff.GenerateRandomKey(256)
	encrptedBad, _ := jwe.Encrypt([]byte(signed), jwe.WithContentEncryption(jwa.A256GCM), jwe.WithKey(jwa.DIRECT, badKey))

	t.Log(string(encrypted))

	b, err := bff.New(bff.Config{
		EncryptKeyString: base64.StdEncoding.EncodeToString(encKey),
		SignKeyString:    base64.StdEncoding.EncodeToString(signKey),
		CookieName:       "test-cookie",
	})

	testserver := httptest.NewServer(b.Protect(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("You are in"))
			t.Log("Someone got in")
		})),
	)
	defer testserver.Close()

	testclient := testserver.Client()
	httpReq, err := http.NewRequest("GET", testserver.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	httpReq.AddCookie(&http.Cookie{
		Name:  "test-cookie",
		Value: string(encrypted),
	})

	resp, err := testclient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	// mage bad request
	httpReq, err = http.NewRequest("GET", testserver.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	httpReq.AddCookie(&http.Cookie{
		Name:  "test-cookie",
		Value: string(encrptedBad),
	})

	resp, err = testclient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected status code %d, got %d", http.StatusUnauthorized, resp.StatusCode)
	}
	resp.Body.Close()
	io.ReadAll(resp.Body)

}
