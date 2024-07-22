package api

import (
	"bytes"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gematik/zero-lab/pkg/ca"
	"github.com/gematik/zero-lab/pkg/nonce"
	"github.com/gematik/zero-lab/pkg/reg"
	"github.com/labstack/echo/v4"
)

const testJwkData = `{"crv":"P-256","d":"RAsLqZOL-WN8-YWrEbxM_cqG_Tmr-6LsfOG7DJMZYac","kty":"EC","x":"X6G6MXf5A0Pn5MkCffwzg5V64UaPUE0t2RahDjGMBrA","y":"uuoTkMVDsT_yF-PCDtDRv1vBniA13KNtMd4pqqM_onc"}`
const testMessage = "eyJjdHkiOiJ4LXJlZ2lzdHJhdGlvbi1hcHBsZStqc29uIiwiYWxnIjoiRVMyNTYiLCJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJYNkc2TVhmNUEwUG41TWtDZmZ3emc1VjY0VWFQVUUwdDJSYWhEakdNQnJBIiwieSI6InV1b1RrTVZEc1RfeUYtUENEdERSdjF2Qm5pQTEzS050TWQ0cHFxTV9vbmMifSwibm9uY2UiOiJub25jZSJ9.eyJuYW1lIjoiaVBob25lIn0.rihNfwFWNPSSbGehWCEo56ExTqgjkHNgpa2QJUTLzxHesfoC8h2fyBoqvsKRicfXcdOT5k3kkpHnpTnD8z5rSA"
const testAttestation = "o2NmbXRvYXBwbGUtYXBwYXR0ZXN0Z2F0dFN0bXSiY3g1Y4JZAwUwggMBMIICiKADAgECAgYBjbgrJrEwCgYIKoZIzj0EAwIwTzEjMCEGA1UEAwwaQXBwbGUgQXBwIEF0dGVzdGF0aW9uIENBIDExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjQwMjE2MTc0NDEyWhcNMjUwMjA5MTMxMDEyWjCBkTFJMEcGA1UEAwxANjY5ZjhlNzQ0OWQ2ODg2MjkxOTYxNTU1MTZiMzk4MmMxYjJlMjJmZGM3MjZhODUzMTY3ZGI5NDc5OTEwNzIyZTEaMBgGA1UECwwRQUFBIENlcnRpZmljYXRpb24xEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATTNPA2PyCogU5IDWJUA7VEMjUzeL9fAvgZ_K4wx718uDG-J9IpHLU69DaLz0EQSlQMfTiVvfthzJ0rlllqR8z3o4IBCzCCAQcwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCBPAwfwYJKoZIhvdjZAgFBHIwcKQDAgEKv4kwAwIBAb-JMQMCAQC_iTIDAgEBv4kzAwIBAb-JNCAEHkE5Rkw4OVBGRkwuZGUuZ2VtYXRpay56ZXJvLWlvc6UGBARza3Mgv4k2AwIBBb-JNwMCAQC_iTkDAgEAv4k6AwIBAL-JOwMCAQAwMQYJKoZIhvdjZAgHBCQwIr-KeAgEBjE3LjEuMb-IUAcCBQD_____v4p7BwQFMjFCOTEwMwYJKoZIhvdjZAgCBCYwJKEiBCDyryZkIG7QDWCkHs94xxM3zXE8G1MtlhN9Ohpa9no4HjAKBggqhkjOPQQDAgNnADBkAjAyxq4QXO8a7U-lz9RZ-blpmJGxg2EqYsFekaenql91MbLQaD8OC67C6XhsokkPAl4CMBGaKKucR8_d4BlnuNbI-0g9qLEOHwuSxImHgi_UAx9RFafz6dyMgQ9F6CqY0OQP31kCRzCCAkMwggHIoAMCAQICEAm6xeG8QBrZ1FOVvDgaCFQwCgYIKoZIzj0EAwMwUjEmMCQGA1UEAwwdQXBwbGUgQXBwIEF0dGVzdGF0aW9uIFJvb3QgQ0ExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgzOTU1WhcNMzAwMzEzMDAwMDAwWjBPMSMwIQYDVQQDDBpBcHBsZSBBcHAgQXR0ZXN0YXRpb24gQ0EgMTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49AgEGBSuBBAAiA2IABK5bN6B3TXmyNY9A59HyJibxwl_vF4At6rOCalmHT_jSrRUleJqiZgQZEki2PLlnBp6Y02O9XjcPv6COMp6Ac6mF53Ruo1mi9m8p2zKvRV4hFljVZ6-eJn6yYU3CGmbOmaNmMGQwEgYDVR0TAQH_BAgwBgEB_wIBADAfBgNVHSMEGDAWgBSskRBTM72-aEH_pwyp5frq5eWKoTAdBgNVHQ4EFgQUPuNdHAQZqcm0MfiEdNbh4Vdy45swDgYDVR0PAQH_BAQDAgEGMAoGCCqGSM49BAMDA2kAMGYCMQC7voiNc40FAs-8_WZtCVdQNbzWhyw_hDBJJint0fkU6HmZHJrota7406hUM_e2DQYCMQCrOO3QzIHtAKRSw7pE-ZNjZVP-zCl_LrTfn16-WkrKtplcS4IN-QQ4b3gHu1iUObdncmVjZWlwdFkOcjCABgkqhkiG9w0BBwKggDCAAgEBMQ8wDQYJYIZIAWUDBAIBBQAwgAYJKoZIhvcNAQcBoIAkgASCA-gxggQsMCYCAQICAQEEHkE5Rkw4OVBGRkwuZGUuZ2VtYXRpay56ZXJvLWlvczCCAw8CAQMCAQEEggMFMIIDATCCAoigAwIBAgIGAY24KyaxMAoGCCqGSM49BAMCME8xIzAhBgNVBAMMGkFwcGxlIEFwcCBBdHRlc3RhdGlvbiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTI0MDIxNjE3NDQxMloXDTI1MDIwOTEzMTAxMlowgZExSTBHBgNVBAMMQDY2OWY4ZTc0NDlkNjg4NjI5MTk2MTU1NTE2YjM5ODJjMWIyZTIyZmRjNzI2YTg1MzE2N2RiOTQ3OTkxMDcyMmUxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0zTwNj8gqIFOSA1iVAO1RDI1M3i_XwL4GfyuMMe9fLgxvifSKRy1OvQ2i89BEEpUDH04lb37YcydK5ZZakfM96OCAQswggEHMAwGA1UdEwEB_wQCMAAwDgYDVR0PAQH_BAQDAgTwMH8GCSqGSIb3Y2QIBQRyMHCkAwIBCr-JMAMCAQG_iTEDAgEAv4kyAwIBAb-JMwMCAQG_iTQgBB5BOUZMODlQRkZMLmRlLmdlbWF0aWsuemVyby1pb3OlBgQEc2tzIL-JNgMCAQW_iTcDAgEAv4k5AwIBAL-JOgMCAQC_iTsDAgEAMDEGCSqGSIb3Y2QIBwQkMCK_ingIBAYxNy4xLjG_iFAHAgUA_____7-KewcEBTIxQjkxMDMGCSqGSIb3Y2QIAgQmMCShIgQg8q8mZCBu0A1gpB7PeMcTN81xPBtTLZYTfToaWvZ6OB4wCgYIKoZIzj0EAwIDZwAwZAIwMsauEFzvGu1Ppc_UWfm5aZiRsYNhKmLBXpGnp6pfdTGy0Gg_Dguuwul4bKJJDwJeAjARmiirnEfP3eAZZ7jWyPtIPaixDh8LksSJh4Iv1AMfURWn8-ncjIEPRegqmNDkD98wKAIBBAIBAQQgFxQjRnTBrF6TyXzRvWhdxQ2PyJGAbhQH_DvD2ZLHhcwwYAIBBQIBAQRYencxR1ZzeVI3WXAya2RiREFIQi9RU3JXUFQ5dVZhV3JLcTcxd0JZd0pTamdGK0N3ZmY3K2FsaWNQbk1YaWhzTkdNeXZkaklXRkhGQlVUanVRR0xnWmc9PTAOAgEGAgEBBAZBVFRFU1QwDwIBBwIBAQQHc2FuBEhkYm94MCACAQwCAQEEGDIwMjQtMDItMTdUMTc6NDQ6MTIuMjQzWjAgAgEVAgEBBBgyMDI0LTA1LTE3VDE3OjQ0OjEyLjI0M1oAAAAAAACggDCCA60wggNUoAMCAQICEH3NmVEtjH3NFgveDjiBekIwCgYIKoZIzj0EAwIwfDEwMC4GA1UEAwwnQXBwbGUgQXBwbGljYXRpb24gSW50ZWdyYXRpb24gQ0EgNSAtIEcxMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMjMwMzA4MTUyOTE3WhcNMjQwNDA2MTUyOTE2WjBaMTYwNAYDVQQDDC1BcHBsaWNhdGlvbiBBdHRlc3RhdGlvbiBGcmF1ZCBSZWNlaXB0IFNpZ25pbmcxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2pgoZ-9d0imsG72-nHEJ7T_XS6UZeRiwRGwaMi_mVldJ7Pmxu9UEcwJs5pTYHdPICN2Cfh6zy_vx_Sop4n8Q_aOCAdgwggHUMAwGA1UdEwEB_wQCMAAwHwYDVR0jBBgwFoAU2Rf-S2eQOEuS9NvO1VeAFAuPPckwQwYIKwYBBQUHAQEENzA1MDMGCCsGAQUFBzABhidodHRwOi8vb2NzcC5hcHBsZS5jb20vb2NzcDAzLWFhaWNhNWcxMDEwggEcBgNVHSAEggETMIIBDzCCAQsGCSqGSIb3Y2QFATCB_TCBwwYIKwYBBQUHAgIwgbYMgbNSZWxpYW5jZSBvbiB0aGlzIGNlcnRpZmljYXRlIGJ5IGFueSBwYXJ0eSBhc3N1bWVzIGFjY2VwdGFuY2Ugb2YgdGhlIHRoZW4gYXBwbGljYWJsZSBzdGFuZGFyZCB0ZXJtcyBhbmQgY29uZGl0aW9ucyBvZiB1c2UsIGNlcnRpZmljYXRlIHBvbGljeSBhbmQgY2VydGlmaWNhdGlvbiBwcmFjdGljZSBzdGF0ZW1lbnRzLjA1BggrBgEFBQcCARYpaHR0cDovL3d3dy5hcHBsZS5jb20vY2VydGlmaWNhdGVhdXRob3JpdHkwHQYDVR0OBBYEFEzxp58QYYoaOWTMbebbOwdil3a9MA4GA1UdDwEB_wQEAwIHgDAPBgkqhkiG92NkDA8EAgUAMAoGCCqGSM49BAMCA0cAMEQCIHrbZOJ1nE8FFv8sSdvzkCwvESymd45Qggp0g5ysO5vsAiBFNcdgKjJATfkqgWf8l7Zy4AmZ1CmKlucFy-0JcBdQjTCCAvkwggJ_oAMCAQICEFb7g9Qr_43DN5kjtVqubr0wCgYIKoZIzj0EAwMwZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwHhcNMTkwMzIyMTc1MzMzWhcNMzQwMzIyMDAwMDAwWjB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJLOY719hrGrKAo7HOGv-wSUgJGs9jHfpssoNW9ES-Eh5VfdEo2NuoJ8lb5J-r4zyq7NBBnxL0Ml-vS-s8uDfrqjgfcwgfQwDwYDVR0TAQH_BAUwAwEB_zAfBgNVHSMEGDAWgBS7sN6hWDOImqSKmd6-veuv2sskqzBGBggrBgEFBQcBAQQ6MDgwNgYIKwYBBQUHMAGGKmh0dHA6Ly9vY3NwLmFwcGxlLmNvbS9vY3NwMDMtYXBwbGVyb290Y2FnMzA3BgNVHR8EMDAuMCygKqAohiZodHRwOi8vY3JsLmFwcGxlLmNvbS9hcHBsZXJvb3RjYWczLmNybDAdBgNVHQ4EFgQU2Rf-S2eQOEuS9NvO1VeAFAuPPckwDgYDVR0PAQH_BAQDAgEGMBAGCiqGSIb3Y2QGAgMEAgUAMAoGCCqGSM49BAMDA2gAMGUCMQCNb6afoeDk7FtOc4qSfz14U5iP9NofWB7DdUr-OKhMKoMaGqoNpmRt4bmT6NFVTO0CMGc7LLTh6DcHd8vV7HaoGjpVOz81asjF5pKw4WG-gElp5F8rqWzhEQKqzGHZOLdzSjCCAkMwggHJoAMCAQICCC3F_IjSxUuVMAoGCCqGSM49BAMDMGcxGzAZBgNVBAMMEkFwcGxlIFJvb3QgQ0EgLSBHMzEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxEzARBgNVBAoMCkFwcGxlIEluYy4xCzAJBgNVBAYTAlVTMB4XDTE0MDQzMDE4MTkwNloXDTM5MDQzMDE4MTkwNlowZzEbMBkGA1UEAwwSQXBwbGUgUm9vdCBDQSAtIEczMSYwJAYDVQQLDB1BcHBsZSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTETMBEGA1UECgwKQXBwbGUgSW5jLjELMAkGA1UEBhMCVVMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASY6S89QHKk7ZMicoETHN0QlfHFo05x3BQW2Q7lpgUqd2R7X04407scRLV_9R-2MmJdyemEW08wTxFaAP1YWAyl9Q8sTQdHE3Xal5eXbzFc7SudeyA72LlU2V6ZpDpRCjGjQjBAMB0GA1UdDgQWBBS7sN6hWDOImqSKmd6-veuv2sskqzAPBgNVHRMBAf8EBTADAQH_MA4GA1UdDwEB_wQEAwIBBjAKBggqhkjOPQQDAwNoADBlAjEAg-nBxBZeGl00GNnt7_RsDgBGS7jfskYRxQ_95nqMoaZrzsID1Jz1k8Z0uGrfqiMVAjBtZooQytQN1E_NjUM-tIpjpTNu423aF7dkH8hTJvmIYnQ5Cxdby1GoDOgYA-eisigAADGB_jCB-wIBATCBkDB8MTAwLgYDVQQDDCdBcHBsZSBBcHBsaWNhdGlvbiBJbnRlZ3JhdGlvbiBDQSA1IC0gRzExJjAkBgNVBAsMHUFwcGxlIENlcnRpZmljYXRpb24gQXV0aG9yaXR5MRMwEQYDVQQKDApBcHBsZSBJbmMuMQswCQYDVQQGEwJVUwIQfc2ZUS2Mfc0WC94OOIF6QjANBglghkgBZQMEAgEFADAKBggqhkjOPQQDAgRIMEYCIQCaXSivbdvj7z7aiFZdF3WmpSpQ_v7bpYBmwXIh3xrbWQIhAM2ZFr3UrdfZAPqpVx_fzO4133BsQL0TAzQYDFdnG9WRAAAAAAAAaGF1dGhEYXRhWKTz1k7PiIzKOkfZ6j5w_bunS2sLhwPQK5RwzZWZ23TvF0AAAAAAYXBwYXR0ZXN0ZGV2ZWxvcAAgZp-OdEnWiGKRlhVVFrOYLBsuIv3HJqhTFn25R5kQci6lAQIDJiABIVgg0zTwNj8gqIFOSA1iVAO1RDI1M3i_XwL4GfyuMMe9fLgiWCAxvifSKRy1OvQ2i89BEEpUDH04lb37YcydK5ZZakfM9w"

// mock NonceService which always returns the same nonce
type mockNonceService struct {
}

func (m *mockNonceService) Get() (string, error) {
	return "nonce", nil
}

func (m *mockNonceService) Redeem(nonce string) error {
	return nil
}

func (m *mockNonceService) Stats() (*nonce.Stats, error) {
	return nil, nil
}

func TestNewRegistration(t *testing.T) {
	nonceService := &mockNonceService{}
	store := reg.NewMockRegistrationStore()
	ca, _ := ca.NewRandomMockCA()
	regService, _ := reg.NewRegistrationService(nonceService, store, ca)

	api, _ := NewRegistrationAPI(regService)

	form := url.Values{}
	form.Add("message", testMessage)
	form.Add("attestation_data", testAttestation)
	form.Add("attestation_format", "apple-attestation")
	req := httptest.NewRequest("POST", "/registrations", bytes.NewBufferString(form.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)

	rec := httptest.NewRecorder()

	e := echo.New()

	c := e.NewContext(req, rec)

	err := api.parseSignedRequest(api.newRegistration)(c)
	if err != nil {
		t.Fatal(err)
	}

	if rec.Code != 201 {
		t.Fatal(rec.Body)
	}

}