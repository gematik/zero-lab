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

package idpd_test

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/idpd"
	"github.com/gematik/zero-lab/go/oauth"
	"github.com/gematik/zero-lab/go/oauth/oidc"
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

func TestIDPD(t *testing.T) {
	if os.Getenv("IDPD_CLIENT_ID") == "" {
		t.Skip("IDPD_CLIENT_ID not set — skipping gematik IDP test")
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Log("TestIDPD")
	trust := mustLiveTrust(t)
	cfg := idpd.ClientConfig{
		UserAgent:   "zero-lab-testcase",
		Environment: idpd.EnvironmentReference,
		Trust:       trust,
		BaseURL:     os.Getenv("IDPD_BASE_URL"),
		ClientID:    os.Getenv("IDPD_CLIENT_ID"),
		RedirectURI: os.Getenv("IDPD_REDIRECT_URI"),
		Scopes:      strings.Split(os.Getenv("IDPD_SCOPE"), " "),
	}

	client, err := idpd.NewClientFromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}

	verifier := oauth.GenerateVerifier()

	authURL, err := client.AuthenticationURL(t.Context(), oidc.Login{State: "state", Nonce: "nonce", Verifier: verifier})
	if err != nil {
		t.Fatal(err)
	}

	slog.Info("Auth URL", "url", authURL)

	authenticator, err := idpd.NewAuthenticator(idpd.AuthenticatorConfig{
		IDP:        client.IDP,
		Trust:      trust,
		SignerFunc: idpd.SignWithSoftkeyPEM(testKeyBytes, testCertBytes),
	})
	if err != nil {
		t.Fatal(err)
	}

	codeRedirectURL, err := authenticator.Authenticate(authURL)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("CodeRedirectURL", codeRedirectURL)

	tokenResponse, err := client.Exchange(t.Context(), oidc.Login{Nonce: "nonce", Verifier: verifier}, codeRedirectURL.Code)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Printf("Token response: %+v\n", tokenResponse)

	claims := make(map[string]any)
	err = tokenResponse.Claims(&claims)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(claims)
}

// mustLiveTrust uses the mounted bundle when one is named and downloads the material otherwise,
// so a login test needs nothing beyond the IDP client configuration.
func mustLiveTrust(t *testing.T) idpd.CertificateTrust {
	t.Helper()
	if path := os.Getenv("IDPD_TRUST_BUNDLE_PATH"); path != "" {
		trust, err := idpd.NewBundleTrust(idpd.EnvironmentReference, path, http.DefaultClient)
		if err != nil {
			t.Fatalf("IDPD_TRUST_BUNDLE_PATH: %v", err)
		}
		return trust
	}
	trust, err := idpd.NewFetchingTrust(idpd.EnvironmentReference, http.DefaultClient)
	if err != nil {
		t.Fatalf("download trust material: %v", err)
	}
	t.Cleanup(trust.Close)
	return trust
}
