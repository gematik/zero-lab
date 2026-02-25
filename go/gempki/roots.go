package gempki

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
)

type Roots struct {
	ByCommonName map[string]*x509.Certificate
}

const trustAnchorTestBase64 = "MIICyjCCAnKgAwIBAgIBATAKBggqhkjOPQQDAjCBgTELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxGzAZBgNVBAMMEkdFTS5SQ0E4IFRFU1QtT05MWTAeFw0yMzEyMDcxMDE3NTJaFw0zMzEyMDQxMDE3NTJaMIGBMQswCQYDVQQGEwJERTEfMB0GA1UECgwWZ2VtYXRpayBHbWJIIE5PVC1WQUxJRDE0MDIGA1UECwwrWmVudHJhbGUgUm9vdC1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEbMBkGA1UEAwwSR0VNLlJDQTggVEVTVC1PTkxZMFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABDLncr51uoi5aGXoctM3aIm/tjMRXGu+57M1TUjwsy2HhyjEBaMWqlGMBcmcGZhbcKt/lepwcDk3EvGRmDJWGQ2jgdcwgdQwHQYDVR0OBBYEFKG5FDonMHtcZx71MsSx1RqJ/LxTMEoGCCsGAQUFBwEBBD4wPDA6BggrBgEFBQcwAYYuaHR0cDovL29jc3AtdGVzdHJlZi5yb290LWNhLnRpLWRpZW5zdGUuZGUvb2NzcDAOBgNVHQ8BAf8EBAMCAQYwRgYDVR0gBD8wPTA7BggqghQATASBIzAvMC0GCCsGAQUFBwIBFiFodHRwOi8vd3d3LmdlbWF0aWsuZGUvZ28vcG9saWNpZXMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNGADBDAh9GANMYXG7LtOY83ffXG0MB/Hb1cGPV5umiJgyOlkpVAiAL+e32oEH1N625yww+4lgFd0LBg9gcFLQ87rEdlyCq1Q=="
const trustAnchorDevRefBase64 = "MIICzDCCAnGgAwIBAgIBATAKBggqhkjOPQQDAjCBgTELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxGzAZBgNVBAMMEkdFTS5SQ0E3IFRFU1QtT05MWTAeFw0yMzA1MjUxMjIxMzlaFw0zMzA1MjIxMjIxMzlaMIGBMQswCQYDVQQGEwJERTEfMB0GA1UECgwWZ2VtYXRpayBHbWJIIE5PVC1WQUxJRDE0MDIGA1UECwwrWmVudHJhbGUgUm9vdC1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEbMBkGA1UEAwwSR0VNLlJDQTcgVEVTVC1PTkxZMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGv3lzIASzKQHW0YbxoaSIFUlGcgH8c/JEWOifqVVKkJUS81zG1ogcL6skAhGCtkksfdSJKiZnmnKeQ/yAgGZUaOB1zCB1DAdBgNVHQ4EFgQUsvAJPk0L4wgkgJY1bjo2MyvySxowSgYIKwYBBQUHAQEEPjA8MDoGCCsGAQUFBzABhi5odHRwOi8vb2NzcC10ZXN0cmVmLnJvb3QtY2EudGktZGllbnN0ZS5kZS9vY3NwMA4GA1UdDwEB/wQEAwIBBjBGBgNVHSAEPzA9MDsGCCqCFABMBIEjMC8wLQYIKwYBBQUHAgEWIWh0dHA6Ly93d3cuZ2VtYXRpay5kZS9nby9wb2xpY2llczAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCntB3Gck9DDlVADBZQCrT3RU3D9QS5k9bd3NKCexf9LQIhAIG2Qyu9HVlKnz8a8qdSJE6+TTejs15x7CLEvaLouXUk"
const trustAnchorProdBase64 = "MIICmTCCAkCgAwIBAgIBATAKBggqhkjOPQQDAjBtMQswCQYDVQQGEwJERTEVMBMGA1UECgwMZ2VtYXRpayBHbWJIMTQwMgYDVQQLDCtaZW50cmFsZSBSb290LUNBIGRlciBUZWxlbWF0aWtpbmZyYXN0cnVrdHVyMREwDwYDVQQDDAhHRU0uUkNBODAeFw0yMzEyMTIwOTU3MTNaFw0zMzEyMDkwOTU3MTNaMG0xCzAJBgNVBAYTAkRFMRUwEwYDVQQKDAxnZW1hdGlrIEdtYkgxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxETAPBgNVBAMMCEdFTS5SQ0E4MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABIwmqH0yFsDRE7IMfPIRk+Emh2U4ZFVjvFgmr0qSwdyVL32ZfNpLJGvUPhCYiedfMSkDBK+zToDBDU/lmSScDT6jgc8wgcwwHQYDVR0OBBYEFIucDNB6vgBoeq0yjWmPmYByx5ssMEIGCCsGAQUFBwEBBDYwNDAyBggrBgEFBQcwAYYmaHR0cDovL29jc3Aucm9vdC1jYS50aS1kaWVuc3RlLmRlL29jc3AwDgYDVR0PAQH/BAQDAgEGMEYGA1UdIAQ/MD0wOwYIKoIUAEwEgSMwLzAtBggrBgEFBQcCARYhaHR0cDovL3d3dy5nZW1hdGlrLmRlL2dvL3BvbGljaWVzMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgZMA4ldNbm42AaLy/iTkIRbOZ5StBjYbn+asOoN06eWcCIH8na29NzkvzPKwQ1UY4qaPdOCvibXlC07zbTfzLJzkx"

var TrustAnchorDev *x509.Certificate
var TrustAnchorTest *x509.Certificate
var TrustAnchorRef *x509.Certificate
var TrustAnchorProd *x509.Certificate

func init() {
	var err error
	TrustAnchorDev, err = parseBase64Cert(trustAnchorDevRefBase64)
	if err != nil {
		panic(fmt.Sprintf("failed to parse dev/ref trust anchor: %v", err))
	}
	TrustAnchorRef = TrustAnchorDev
	TrustAnchorTest, err = parseBase64Cert(trustAnchorTestBase64)
	if err != nil {
		panic(fmt.Sprintf("failed to parse test trust anchor: %v", err))
	}
	TrustAnchorProd, err = parseBase64Cert(trustAnchorProdBase64)
	if err != nil {
		panic(fmt.Sprintf("failed to parse prod trust anchor: %v", err))
	}
}

func parseBase64Cert(base64Str string) (*x509.Certificate, error) {
	certBytes, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 certificate: %w", err)
	}
	cert, err := brainpool.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

type jsonRoot struct {
	CertRaw              []byte            `json:"cert"`
	Cert                 *x509.Certificate `json:"-"`
	CommonName           string            `json:"cn"`
	Name                 string            `json:"name"`
	SubjectKeyIdentifier string            `json:"ski"`
	NotValidAfter        string            `json:"nva"`
	NotValidBefore       string            `json:"nvb"`
	PrevCertRaw          []byte            `json:"prev"`
	PrevCert             *x509.Certificate `json:"-"`
	NextCertRaw          []byte            `json:"next"`
	NextCert             *x509.Certificate `json:"-"`
}

const urlRootsTest = "https://download-test.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json"
const urlRootsDevRef = "https://download-ref.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json"
const urlRootsProd = "https://download.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json"

func LoadRoots(ctx context.Context, httpClient *http.Client, env Environment) (*Roots, error) {
	var url string
	switch env {
	case EnvTest:
		url = urlRootsTest
	case EnvRef:
		url = urlRootsDevRef
	case EnvDev:
		url = urlRootsDevRef
	case EnvProd:
		url = urlRootsProd
	default:
		return nil, fmt.Errorf("unknown environment: %s", env)
	}

	slog.Info("Loading roots from the internet", "environment", env, "url", url)

	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch roots: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch roots: HTTP %d from %s", resp.StatusCode, url)
	}
	defer resp.Body.Close()

	return parseRoots(env, resp.Body)
}

func ParseRoots(env Environment, input io.Reader) (*Roots, error) {
	return parseRoots(env, input)
}

func parseRoots(env Environment, input io.Reader) (*Roots, error) {
	var jsonRoots []*jsonRoot
	if err := json.NewDecoder(input).Decode(&jsonRoots); err != nil {
		return nil, fmt.Errorf("failed to decode roots JSON: %w", err)
	}

	for i, jsonRoot := range jsonRoots {
		cert, err := brainpool.ParseCertificate(jsonRoot.CertRaw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse root certificate for %s: %w", jsonRoot.CommonName, err)
		}
		jsonRoots[i].Cert = cert
		if len(jsonRoot.PrevCertRaw) != 0 {
			prevCert, err := brainpool.ParseCertificate(jsonRoot.PrevCertRaw)
			if err != nil {
				return nil, fmt.Errorf("failed to parse prev certificate for %s: %w", jsonRoot.CommonName, err)
			}
			jsonRoots[i].PrevCert = prevCert
		}
		if len(jsonRoot.NextCertRaw) != 0 {
			nextCert, err := brainpool.ParseCertificate(jsonRoot.NextCertRaw)
			if err != nil {
				return nil, fmt.Errorf("failed to parse next certificate for %s: %w", jsonRoot.CommonName, err)
			}
			jsonRoots[i].NextCert = nextCert
		}
	}

	var anchor *x509.Certificate
	switch env {
	case EnvTest:
		anchor = TrustAnchorTest
	case EnvRef:
		anchor = TrustAnchorRef
	case EnvDev:
		anchor = TrustAnchorDev
	case EnvProd:
		anchor = TrustAnchorProd
	default:
		return nil, fmt.Errorf("unknown environment: %s", env)
	}

	slog.Info("Verifying roots with trust anchor", "anchor", anchor.Subject.CommonName)

	certs, err := verifyRoots(anchor, jsonRoots)
	if err != nil {
		return nil, fmt.Errorf("failed to verify roots: %w", err)
	}

	byCommonName := make(map[string]*x509.Certificate)
	for _, cert := range certs {
		byCommonName[cert.Subject.CommonName] = cert
	}

	return &Roots{
		ByCommonName: byCommonName,
	}, nil
}

func verifyRoots(anchor *x509.Certificate, jsonRoots []*jsonRoot) ([]*x509.Certificate, error) {
	var anchorJsonRoot *jsonRoot

	for _, jsonRoot := range jsonRoots {
		if jsonRoot.Cert.Equal(anchor) {
			anchorJsonRoot = jsonRoot
			break
		}
	}

	if anchorJsonRoot == nil {
		return nil, fmt.Errorf("anchor certificate %s not found in roots", anchor.Subject.CommonName)
	}

	var trusted []*jsonRoot
	var err error

	if trusted, err = verifyNext(anchorJsonRoot, trusted, jsonRoots); err != nil {
		return nil, err
	}

	if trusted, err = verifyPrev(anchorJsonRoot, trusted, jsonRoots); err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for _, jsonRoot := range trusted {
		certs = append(certs, jsonRoot.Cert)
	}

	return certs, nil
}

func verifyPrev(base *jsonRoot, trusted, all []*jsonRoot) ([]*jsonRoot, error) {
	if base.PrevCert == nil {
		return trusted, nil
	}
	c := base.PrevCert
	// find jsonRoot for c
	var prevJsonRoot *jsonRoot
	for _, jsonRoot := range all {
		if bytes.Equal(jsonRoot.Cert.SubjectKeyId, c.SubjectKeyId) {
			prevJsonRoot = jsonRoot
			break
		}
	}
	if prevJsonRoot == nil {
		return nil, fmt.Errorf("prev certificate with SKI %x not found in roots", c.SubjectKeyId)
	}

	if err := verifyCrossSigned(base.Cert, c, prevJsonRoot.Cert); err != nil {
		// if error ErrVerificationStep2 - expired certificate, we log warning and continue, otherwise we return error
		var ve VerificationError
		if errors.As(err, &ve) && errors.Is(ve, ErrVerificationStep2) {
			slog.Warn("prev has invalid validity period, skipping", "commonName", c.Subject.CommonName, "notBefore", c.NotBefore, "notAfter", c.NotAfter)
			return verifyPrev(prevJsonRoot, trusted, all)
		}
		return nil, fmt.Errorf("failed to verify cross-signed certificate: %w", err)
	}
	trusted = append(trusted, prevJsonRoot)
	return verifyPrev(prevJsonRoot, trusted, all)
}

func verifyNext(base *jsonRoot, trusted, all []*jsonRoot) ([]*jsonRoot, error) {
	trusted = append(trusted, base)
	if base.NextCert == nil {
		return trusted, nil
	}
	c := base.NextCert

	// find jsonRoot for c
	var nextJsonRoot *jsonRoot
	for _, jsonRoot := range all {
		if bytes.Equal(jsonRoot.Cert.SubjectKeyId, c.SubjectKeyId) {
			nextJsonRoot = jsonRoot
			break
		}
	}
	if nextJsonRoot == nil {
		return nil, fmt.Errorf("next certificate with SKI %x not found in roots", c.SubjectKeyId)
	}

	if err := verifyCrossSigned(base.Cert, c, nextJsonRoot.Cert); err != nil {
		return nil, fmt.Errorf("failed to verify cross-signed certificate: %w", err)
	}

	return verifyNext(nextJsonRoot, trusted, all)
}

type VerificationError error

var (
	ErrVerificationStep1 = errors.New("step 1 failed: signature verification against trust anchor")
	ErrVerificationStep2 = errors.New("step 2 failed: certificate validity period")
	ErrVerificationStep3 = errors.New("step 3 failed: common name schema")
	ErrVerificationStep4 = errors.New("step 4 failed: subject key identifier mismatch")
	ErrVerificationStep5 = errors.New("step 5 failed: common name mismatch")
	ErrVerificationStep6 = errors.New("step 6 failed: public key mismatch")
	ErrVerificationStep7 = errors.New("step 7 failed: signature verification against cross-signed certificate")
)

// Implements A_28419
func verifyCrossSigned(anchor, c, s *x509.Certificate) error {
	// 1. prüfen, ob die Signatur von C per Signaturprüfung valide rückführbar ist auf ein schon im System als ein Vertrauensanker vorhandenes Root-CA-Zertifikat.
	if err := c.CheckSignatureFrom(anchor); err != nil {
		return fmt.Errorf("%w: certificate %s is not signed by %s: %w", ErrVerificationStep1, c.Subject.CommonName, anchor.Subject.CommonName, err)
	}

	// 2. prüfen, ob C zum Prüfzeitpunkt/Import-Zeitpunkt zeitlich noch gültig ist.
	now := time.Now()
	if now.Before(c.NotBefore) {
		return fmt.Errorf("%w: certificate %s is not valid yet: notBefore=%s", ErrVerificationStep2, c.Subject.CommonName, c.NotBefore)
	}
	if now.After(c.NotAfter) {
		return fmt.Errorf("%w: certificate %s has expired: notAfter=%s", ErrVerificationStep2, c.Subject.CommonName, c.NotAfter)
	}

	// 3. prüfen, ob der SubjectCommonName der im Cross-Zertifikat bestätigten Identität dem Namensschema "GEM.RCA<natürliche Zahl>" entspricht.
	// use regex GAM.RCA\d+
	if !regexp.MustCompile(`^GEM\.RCA\d+`).MatchString(c.Subject.CommonName) {
		return fmt.Errorf("%w: certificate %s has invalid common name: %s", ErrVerificationStep3, c.Subject.CommonName, c.Subject.CommonName)
	}

	// 4. prüfen, ob der SubjectKeyIdentifier in C gleich dem in S ist.
	if !bytes.Equal(c.SubjectKeyId, s.SubjectKeyId) {
		return fmt.Errorf("%w: certificate %s has mismatched subject key identifier: %x != %x", ErrVerificationStep4, c.Subject.CommonName, c.SubjectKeyId, s.SubjectKeyId)
	}
	// 5. prüfen, ob der SubjectCommonName in C und in S gleich ist.
	if c.Subject.CommonName != s.Subject.CommonName {
		return fmt.Errorf("%w: certificate %s has mismatched common name: %s != %s", ErrVerificationStep5, c.Subject.CommonName, c.Subject.CommonName, s.Subject.CommonName)
	}
	// 6. prüfen, ob bestätigte öffentliche Schlüssel in C gleich dem in S ist.
	// serialize public keys to compare them
	// we use brainpool package if the keys are brainpool, which falls back to x509.MarshalPKIXPublicKey for non-brainpool keys
	cPubKeyBytes, err := brainpool.MarshalPKIXPublicKey(c.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal public key of certificate %s: %w", ErrVerificationStep6, c.Subject.CommonName, err)
	}
	sPubKeyBytes, err := brainpool.MarshalPKIXPublicKey(s.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal public key of certificate %s: %w", ErrVerificationStep6, s.Subject.CommonName, err)
	}
	if !bytes.Equal(cPubKeyBytes, sPubKeyBytes) {
		return fmt.Errorf("%w: certificate %s has mismatched public key", ErrVerificationStep6, c.Subject.CommonName)
	}
	// 7. prüfen, ob die Signatur von S valide per Signaturprüfung mit dem öffentlichen Schlüssel aus C prüfbar ist.
	if err := s.CheckSignatureFrom(c); err != nil {
		return fmt.Errorf("%w: certificate %s is not signed by %s: %w", ErrVerificationStep7, s.Subject.CommonName, c.Subject.CommonName, err)
	}

	return nil
}

func (r Roots) FilterValidSubCAs(tsl *TrustServiceStatusList) []*x509.Certificate {
	var validSubCAs []*x509.Certificate
	// add all CA certificates from TSL which were issued by the roots

	// add all CA certificates from TSL which were issued by the roots
	for _, provider := range tsl.TrustServiceProviderList {
		for _, service := range provider.TSPServices {
			if service.ServiceInformation.ServiceTypeIdentifier == ServiceTypeCaPkc {
				caCert := service.ServiceInformation.ServiceDigitalIdentity.DigitalId.X509Certificate
				root, ok := r.ByCommonName[caCert.Issuer.CommonName]
				if !ok {
					slog.Debug("CA certificate not issued any known root", "ca", caCert.Subject.CommonName)
					continue
				}
				// check if the CA certificate was issued by the matching root
				if err := caCert.CheckSignatureFrom(root); err != nil {
					slog.Error("CA certificate not signed by root", "ca", caCert.Subject.CommonName, "root", root.Subject.CommonName)
					continue
				}
				// check if this is CA certificate
				if !caCert.IsCA {
					slog.Warn("CA certificate is not marked as CA", "ca", caCert.Subject.CommonName)
					continue
				}
				// check time validity of CA certificate
				now := time.Now()
				if now.Before(caCert.NotBefore) {
					slog.Warn("CA certificate not valid yet, skipping", "ca", caCert.Subject.CommonName, "notBefore", caCert.NotBefore)
					continue
				}
				if now.After(caCert.NotAfter) {
					slog.Warn("CA certificate expired, skipping", "ca", caCert.Subject.CommonName, "notAfter", caCert.NotAfter)
					continue
				}

				validSubCAs = append(validSubCAs, caCert)
				slog.Debug("Added valid CA certificate from TSL", "ca", caCert.Subject.CommonName, "issuer", caCert.Issuer.CommonName)
			}
		}
	}
	return validSubCAs
}

func (r Roots) BuildCertPoolWithSubCAs(tsl *TrustServiceStatusList) *x509.CertPool {
	certPool := x509.NewCertPool()
	for _, root := range r.ByCommonName {
		certPool.AddCert(root)
	}

	for _, subCA := range r.FilterValidSubCAs(tsl) {
		certPool.AddCert(subCA)
	}

	return certPool
}
