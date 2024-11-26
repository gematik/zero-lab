package epa_test

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/epa"
	"github.com/gematik/zero-lab/go/libzero/gemidp"
	"github.com/gematik/zero-lab/go/libzero/prettylog"
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

var testRecords = []struct {
	providerNumber epa.ProviderNumber
	insurantId     string
}{
	{epa.ProviderNumber1, "X110600196"},
	{epa.ProviderNumber2, "X110611629"},
}

// create the proof of audit evidence function
// using the HMAC key and kid from the environment
func EnvProofOfAuditEvidenceFunc(insurantId string) (string, error) {
	hmacKeyHex := os.Getenv("VSDM_HMAC_KEY")
	if hmacKeyHex == "" {
		return "", fmt.Errorf("VSDM_HMAC_KEY not set")
	}
	hmacKeyKid := os.Getenv("VSDM_HMAC_KID")
	if hmacKeyKid == "" {
		return "", fmt.Errorf("VSDM_HMAC_KID not set")
	}

	proofOfAuditEvidence, err := epa.ProofOfAuditEvidenceHMAC(hmacKeyHex, hmacKeyKid)
	if err != nil {
		return "", err
	}

	return proofOfAuditEvidence(insurantId)
}

func TestConnect(t *testing.T) {

	for _, testRecord := range testRecords {
		t.Run(testRecord.insurantId, func(t *testing.T) {
			providerNumber := testRecord.providerNumber
			insurantId := testRecord.insurantId

			testKey, _ := brainpool.ParsePrivateKeyPEM(testKeyBytes)
			testCert, _ := brainpool.ParseCertificatePEM(testCertBytes)

			logger := slog.New(prettylog.NewHandler(slog.LevelDebug))
			slog.SetDefault(logger)

			session, err := epa.OpenSession(
				epa.EnvDev,
				providerNumber,
				epa.SecurityFunctions{
					AuthnSignFunc:            brainpool.SignFuncPrivateKey(testKey),
					AuthnCertFunc:            func() (*x509.Certificate, error) { return testCert, nil },
					ClientAssertionSignFunc:  brainpool.SignFuncPrivateKey(testKey),
					ClientAssertionCertFunc:  func() (*x509.Certificate, error) { return testCert, nil },
					ProofOfAuditEvidenceFunc: EnvProofOfAuditEvidenceFunc,
				},
				epa.WithInsecureSkipVerify(),
			)
			if err != nil {
				t.Fatalf("Connect returned an error: %v", err)
			}

			clientAttest, err := session.CreateClientAttest()
			if err != nil {
				t.Fatalf("CreateClientAttest returned an error: %v", err)
			}

			authz_uri, err := session.SendAuthorizationRequestSC()
			if err != nil {
				t.Fatalf("SendAuthorizationRequestSC returned an error: %v", err)
			}

			// https://idp-ref.zentral.idp.splitdns.ti-dienste.de
			// https://idp-ref.app.ti-dienste.de/auth?
			// https://idp-ref.zentral.idp.splitdns.ti-dienste.de/auth
			//authz_uri = strings.Replace(authz_uri, "https://idp-ref.app.ti-dienste.de", "https://idp-ref.zentral.idp.splitdns.ti-dienste.de", 1)

			t.Logf("Authorization URI: %v", authz_uri)

			authenticator, err := gemidp.NewAuthenticator(gemidp.AuthenticatorConfig{
				Environment: gemidp.EnvironmentReference,
				SignerFunc:  gemidp.SignWithSoftkey(testKey, testCert),
			})

			codeRedirectURL, err := authenticator.Authenticate(authz_uri)
			if err != nil {
				t.Fatalf("Authenticate returned an error: %v", err)
			}
			t.Logf("CodeRedirectURL: %v", codeRedirectURL)

			err = session.SendAuthCodeSC(epa.SendAuthCodeSCtype{
				AuthorizationCode: codeRedirectURL.Code,
				ClientAttest:      clientAttest,
			})
			if err != nil {
				t.Fatalf("SendAuthCodeSC returned an error: %v", err)
			}

			t.Logf("Session: %v", session)

			exsists, err := session.GetRecordStatus(insurantId)
			if err != nil {
				t.Fatalf("GetRecordStatus returned an error: %v", err)
			}
			t.Logf("Record exists: %v", exsists)

			decisions, err := session.GetConsentDecisionInformation(insurantId)
			if err != nil {
				t.Fatalf("GetConsentDecisionInformation returned an error: %v", err)
			}
			t.Logf("Consent decisions: %v", decisions)

			auditEvidence, err := EnvProofOfAuditEvidenceFunc(insurantId)
			if err != nil {
				t.Fatalf("TestProofOfAuditEvidenceFunc returned an error: %v", err)
			}

			err = session.SetEntitlementPS(insurantId, auditEvidence)
			if err != nil {
				t.Fatalf("SetEntitlementPs returned an error: %v", err)
			}
		})
	}
}
