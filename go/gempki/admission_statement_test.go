package gempki_test

import (
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/gempki"
)

var admissionStatementTests = []struct {
	certPem                    []byte
	expectedRegistrationNumber string
	expectedProfessionOids     []string
}{
	{
		certPem: []byte(`-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`),
		expectedRegistrationNumber: "1-2-ARZTPRAXIS-BerndRosenstrauch01",
		expectedProfessionOids:     []string{"1.2.276.0.76.4.50"},
	},
	{
		certPem: []byte(`-----BEGIN CERTIFICATE-----
MIID6jCCA5CgAwIBAgIHA14Hgui9wTAKBggqhkjOPQQDAjCBmjELMAkGA1UEBhMC
REUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxSDBGBgNVBAsMP0lu
c3RpdHV0aW9uIGRlcyBHZXN1bmRoZWl0c3dlc2Vucy1DQSBkZXIgVGVsZW1hdGlr
aW5mcmFzdHJ1a3R1cjEgMB4GA1UEAwwXR0VNLlNNQ0ItQ0E1MSBURVNULU9OTFkw
HhcNMjMxMDMwMDAwMDAwWhcNMjgxMDI5MjM1OTU5WjCB+zELMAkGA1UEBhMCREUx
EzARBgNVBAgMCkJ1bmRlc2xhbmQxEzARBgNVBAcMClJlZ2Vuc2J1cmcxDjAMBgNV
BBEMBTkzMDU1MRowGAYDVQQJDBFTdWx6ZmVsZHN0cmHDn2UgNzErMCkGA1UECgwi
My1TTUMtQi1UZXN0a2FydGUtLTg4MzExMDAwMDE1MzQ0MDEgMB4GA1UEBRMXMDAu
ODAyNzY4ODMxMTAwMDAxNTM0NDAxETAPBgNVBAQMCEJldXRsw61uMRIwEAYDVQQq
DAlGcmFuY2VzY28xIDAeBgNVBAMMF0FkbGVyIEFwb3RoZWtlVEVTVC1PTkxZMFow
FAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABHFPPEUtzbvsZqmHTNoEqnuYkcSCttE3
HD8o5WbK2YuTBI8euL3C7OI8+yjkgOIGQgKQSSFT1lDfrGAMGOdeDiKjggFbMIIB
VzA4BggrBgEFBQcBAQQsMCowKAYIKwYBBQUHMAGGHGh0dHA6Ly9laGNhLmdlbWF0
aWsuZGUvb2NzcC8wDAYDVR0TAQH/BAIwADAgBgNVHSAEGTAXMAoGCCqCFABMBIEj
MAkGByqCFABMBE0wHwYDVR0jBBgwFoAUBpjpAlX/yZ9co2UO8V3iIPWE+5MwDgYD
VR0PAQH/BAQDAgeAMB0GA1UdDgQWBBSmHxaIHhAqeDFnN14w9K9JRwUVQzATBgNV
HSUEDDAKBggrBgEFBQcDAjCBhQYFKyQIAwMEfDB6pCgwJjELMAkGA1UEBhMCREUx
FzAVBgNVBAoMDmdlbWF0aWsgQmVybGluME4wTDBKMEgwFwwVw5ZmZmVudGxpY2hl
IEFwb3RoZWtlMAkGByqCFABMBDYTIjMtU01DLUItVGVzdGthcnRlLS04ODMxMTAw
MDAxNTM0NDAwCgYIKoZIzj0EAwIDSAAwRQIgNXqGlKIkcEGVR81SbH0OoS9JXSg1
7FFzbqWdmZoQI/cCIQClnlla4ANT3FUvW0uPR2zE0Xt7BGWwyWDj5KcckB1GrA==
-----END CERTIFICATE-----`),
		expectedRegistrationNumber: "3-SMC-B-Testkarte--883110000153440",
		expectedProfessionOids:     []string{"1.2.276.0.76.4.54"},
	},
}

func TestParseAdmissionStatement(t *testing.T) {
	for _, tt := range admissionStatementTests {
		t.Run(tt.expectedRegistrationNumber, func(t *testing.T) {
			cert, err := brainpool.ParseCertificatePEM(tt.certPem)
			if err != nil {
				t.Fatalf("failed to parse certificate: %v", err)
			}
			admissionStatement, err := gempki.ParseAdmissionStatement(cert)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("Admission Statement: %+v", admissionStatement)
			if admissionStatement.RegistrationNumber != tt.expectedRegistrationNumber {
				t.Errorf("expected registration number %s, got %s", tt.expectedRegistrationNumber, admissionStatement.RegistrationNumber)
			}
			if len(admissionStatement.ProfessionOids) != len(tt.expectedProfessionOids) {
				t.Errorf("expected %d profession OIDs, got %d", len(tt.expectedProfessionOids), len(admissionStatement.ProfessionOids))
			} else {
				for i, oid := range admissionStatement.ProfessionOids {
					if oid != tt.expectedProfessionOids[i] {
						t.Errorf("expected profession OID %s, got %s", tt.expectedProfessionOids[i], oid)
					}
				}
			}
		})
	}

}
