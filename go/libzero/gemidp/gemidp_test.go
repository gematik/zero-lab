package gemidp_test

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/libzero/gemidp"
	"github.com/gematik/zero-lab/go/libzero/oauth2"
	"github.com/gematik/zero-lab/go/libzero/util"
	"github.com/spilikin/go-brainpool"
)

// sample keys and certificates from https://github.com/gematik/erp-e2e-testsuite
var testKeyBytes = []byte(`-----BEGIN EC PRIVATE KEY-----
MHgCAQEEID0gGM/y+gETNO9kFWY6vELk9rjq2H/tuZogskG/rpB8oAsGCSskAwMC
CAEBB6FEA0IABGc0iasne1f/tcuTSw4CiRfxZ3LvLsQDuMmbqTO5CuOsXND+n8fV
Q3zyzOv7imMbR7nqdiEFGAHtGNznbsLrU80=
-----END EC PRIVATE KEY-----`)

var testCertBytes = []byte(`-----BEGIN CERTIFICATE-----
MIIDeDCCAx6gAwIBAgIHArLLcBI3KDAKBggqhkjOPQQDAjCBmjELMAkGA1UEBhMC
REUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxSDBGBgNVBAsMP0lu
c3RpdHV0aW9uIGRlcyBHZXN1bmRoZWl0c3dlc2Vucy1DQSBkZXIgVGVsZW1hdGlr
aW5mcmFzdHJ1a3R1cjEgMB4GA1UEAwwXR0VNLlNNQ0ItQ0E1MSBURVNULU9OTFkw
HhcNMjMxMTA5MjMwMDAwWhcNMjgxMTA5MjI1OTU5WjCBhDELMAkGA1UEBhMCREUx
HDAaBgNVBAoMEzEwMjMxMDgwMSBOT1QtVkFMSUQxFTATBgNVBAQMDFJvc2Vuc3Ry
YXVjaDEOMAwGA1UEKgwFQmVybmQxMDAuBgNVBAMMJ0FyenRwcmF4aXMgQmVybmQg
Um9zZW5zdHJhdWNoIFRFU1QtT05MWTBaMBQGByqGSM49AgEGCSskAwMCCAEBBwNC
AARnNImrJ3tX/7XLk0sOAokX8Wdy7y7EA7jJm6kzuQrjrFzQ/p/H1UN88szr+4pj
G0e56nYhBRgB7Rjc527C61PNo4IBYDCCAVwwLAYDVR0fBCUwIzAhoB+gHYYbaHR0
cDovL2VoY2EuZ2VtYXRpay5kZS9jcmwvMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUE
DDAKBggrBgEFBQcDAjAdBgNVHQ4EFgQUshKrzlr5DNSiNzsEXWLuScZAN2wwDAYD
VR0TAQH/BAIwADAfBgNVHSMEGDAWgBQGmOkCVf/Jn1yjZQ7xXeIg9YT7kzA7Bggr
BgEFBQcBAQQvMC0wKwYIKwYBBQUHMAGGH2h0dHA6Ly9laGNhLmdlbWF0aWsuZGUv
ZWNjLW9jc3AwWgYFKyQIAwMEUTBPME0wSzBJMEcwFgwUQmV0cmllYnNzdMOkdHRl
IEFyenQwCQYHKoIUAEwEMhMiMS0yLUFSWlRQUkFYSVMtQmVybmRSb3NlbnN0cmF1
Y2gwMTAgBgNVHSAEGTAXMAoGCCqCFABMBIEjMAkGByqCFABMBE0wCgYIKoZIzj0E
AwIDSAAwRQIgWlSdCIw6Z6alM+dGnA4vfkxDoViIqJMw/PH4U0VUmNsCIQCcX9UW
JnSDBKGp4nZTcuozRPsJK47cBkil0x6Zrkoxkg==
-----END CERTIFICATE-----`)

func TestGemIDP(t *testing.T) {
	t.Log("TestGemIDP")
	cfg := gemidp.ClientConfig{
		Environment: gemidp.EnvironmentReference,
		ClientID:    os.Getenv("GEMIDP_CLIENT_ID"),
		RedirectURI: os.Getenv("GEMIDP_REDIRECT_URI"),
		Scopes:      strings.Split(os.Getenv("GEMIDP_SCOPE"), " "),
	}

	client, err := gemidp.NewClientFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	verifier := oauth2.GenerateCodeVerifier()

	authURL, err := client.AuthCodeURL("state", "nonce", verifier)
	if err != nil {
		t.Fatal(err)
	}

	slog.Info("Auth URL", "url", authURL)

	// load test key and certificate
	softKey, _ := parsePEMKey(testKeyBytes)
	softCert, _ := parsePEMCert(testCertBytes)

	authenticator, err := gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
		Environment: gemidp.EnvironmentReference,
		SignerFunc:  gemidp.SignWithSoftkey(softKey, softCert),
	})
	if err != nil {
		t.Fatal(err)
	}

	codeRedirectURL, err := authenticator.Authenticate(authURL)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("CodeRedirectURL", codeRedirectURL)

	tokenResponse, err := client.Exchange(codeRedirectURL.Code, verifier)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(util.JWSToText(tokenResponse.IDToken))
	fmt.Println(util.JWSToText(tokenResponse.AccessToken))

	idToken, err := client.ParseIDToken(tokenResponse)
	if err != nil {
		t.Fatal(err)
	}

	privateClaims := idToken.PrivateClaims()
	slog.Info("ID Token private claims", "claims", privateClaims)

}

func parsePEMKey(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, nil
	}

	return brainpool.ParseECPrivateKey(pemBlock.Bytes)
}

func parsePEMCert(pemBytes []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, nil
	}

	return brainpool.ParseCertificate(pemBlock.Bytes)
}
