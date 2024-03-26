package oidf

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/pkg/util"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

const fedMasterJwksRef = `{
	"keys": [
	  {
		"kty": "EC",
		"crv": "P-256",
		"x": "cdIR8dLbqaGrzfgyu365KM5s00zjFq8DFaUFqBvrWLs",
		"y": "XVp1ySJ2kjEInpjTZy0wD59afEXELpck0fk7vrMWrbw",
		"kid": "puk_fedmaster_sig",
		"use": "sig",
		"alg": "ES256"
	  }
	]
  }
`

func TestFederation(t *testing.T) {
	jwks, err := jwk.ParseString(fedMasterJwksRef)
	if err != nil {
		t.Fatal(err)
	}

	f, err := NewOpenidFederation("https://app-ref.federationmaster.de", jwks)
	if err != nil {
		t.Fatal(err)
	}

	es, err := f.FetchEntityStatement("https://gsi.dev.gematik.solutions")
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", es)
}

func TestLogin(t *testing.T) {
	//fedMasterURL := "https://app-test.federationmaster.de"
	fedMasterURL := "https://app-ref.federationmaster.de"
	//idpURL := "https://gsi.dev.gematik.solutions"
	idpURL := "https://idbroker.tk.ru2.nonprod-ehealth-id.de"
	//idpURL := "https://web.waasru.id.digital.barmer.de"
	//idpURL := "https://idbroker.aokno.ru2.nonprod-ehealth-id.de"

	jwks, err := jwk.ParseString(fedMasterJwksRef)
	if err != nil {
		t.Fatal(err)
	}

	f, err := NewOpenidFederation(fedMasterURL, jwks)
	if err != nil {
		t.Fatal(err)
	}

	//es, err := f.FetchEntityStatement("https://web.tu.id.digital.barmer.de/")

	//es, err := f.FetchEntityStatement("https://gsi.dev.gematik.solutions")
	//es, err := f.FetchEntityStatement("https://idbroker.tk.ru2.nonprod-ehealth-id.de")
	es, err := f.FetchEntityStatement(idpURL)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", es)

	cert, err := tls.LoadX509KeyPair("../../secrets/reg/client_cert.pem", "../../secrets/reg/client_prk.pem")
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: util.AddApiKeyTransport(
			&http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
				},
			},
		),
	}

	i, err := f.FetchEntityStatement(idpURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(i.Metadata.OpenidProvider.AuthorizationEndpoint)

	codeVerifier := util.GenerateRandomString(128)

	state := util.GenerateRandomString(64)

	// generate code challenge
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallengeBytes := h.Sum(nil)
	codeChallenge := base64.RawURLEncoding.Strict().EncodeToString(codeChallengeBytes)

	nonce := util.GenerateRandomString(32)

	parData := url.Values{}
	//parData.Add("scope", "urn:telematik:display_name urn:telematik:versicherter openid")
	parData.Add("scope", "openid")
	parData.Add("acr_values", "gematik-ehealth-loa-high")
	parData.Add("response_type", "code")
	parData.Add("state", state)
	// parData.Add("redirect_uri", "https://directory-test.ccs.gematik.solutions/auth/signin-gematik-fed")
	parData.Add("redirect_uri", "https://dms-01.zt.dev.ccs.gematik.solutions/reg/auth/gematik-fed/callback")
	parData.Add("code_challenge_method", "S256")
	parData.Add("nonce", nonce)
	parData.Add("client_id", "https://dms-01.zt.dev.ccs.gematik.solutions")
	//parData.Add("client_id", "https://directory-test.ccs.gematik.solutions")
	parData.Add("code_challenge", codeChallenge)

	parRequest, err := http.NewRequest(
		http.MethodPost,
		es.Metadata.OpenidProvider.PushedAuthorizationRequestEndpoint,
		strings.NewReader(parData.Encode()),
	)
	if err != nil {
		t.Fatal(err)
	}

	parRequest.Header.Add("Accept", "*/*")
	parRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	parResponse, err := client.Do(parRequest)
	if err != nil {
		t.Error("Unable to do PAR request")
		t.Fatal(err)
	}

	defer parResponse.Body.Close()
	body, err := io.ReadAll(parResponse.Body)
	if err != nil {
		t.Error("Unable to read PAR response body")
		t.Fatal(err)
	}

	t.Log("Got response", parResponse.StatusCode)

	t.Logf("%+v", string(body))
}
