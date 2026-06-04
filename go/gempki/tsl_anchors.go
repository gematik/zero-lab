package gempki

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"sync"
)

// TSL-Signer-CA trust anchors — distinct from the GEM.RCA<n> Komponenten-PKI
// anchors in truststore_loader.go.
//
// Strategy: vendor ONE TSL-Signer-CA cert per environment. When gematik
// publishes additional reachable TSL-Signer-CAs as standalone roots
// alongside cross-certs from a vendored anchor (e.g. on
// https://download.tsl.ti-dienste.de/ECC/), extend [EmbeddedTSLSignerLoader]
// to walk those cross-certs — the [verifyRootsList] cross-cert walker used
// for GEM.RCA<n> is directly reusable. Currently each gematik environment
// publishes a single TSL-Signer-CA standalone root, so a single-entry walk
// would be empty ceremony; we add the walker the day a real second anchor
// becomes reachable.
//
// The vendored anchors come straight from gematik's distribution endpoint:
//
//	https://download.tsl.ti-dienste.de/ECC/GEM.TSL-CA3.der          (prod)
//	https://download-test.tsl.ti-dienste.de/ECC/GEM.TSL-CA28_TEST-ONLY.der

const (
	// tslAnchorTestB64 — GEM.TSL-CA28 TEST-ONLY (current ECC test anchor).
	// Issued by GEM.RCA4 TEST-ONLY, validity 2020-04-08 → 2028-04-06.
	tslAnchorTestB64 = "MIICwDCCAmagAwIBAgIBETAKBggqhkjOPQQDAjCBgTELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxGzAZBgNVBAMMEkdFTS5SQ0E0IFRFU1QtT05MWTAeFw0yMDA0MDgwOTE1NDdaFw0yODA0MDYwOTE1NDZaMIGCMQswCQYDVQQGEwJERTEfMB0GA1UECgwWZ2VtYXRpayBHbWJIIE5PVC1WQUxJRDExMC8GA1UECwwoVFNMLVNpZ25lci1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEfMB0GA1UEAwwWR0VNLlRTTC1DQTI4IFRFU1QtT05MWTBaMBQGByqGSM49AgEGCSskAwMCCAEBBwNCAARcg9HFYez8wU/bMF2h+j8BvS/bkyba2NYsyaHgdt3PHivQ58jF5CkYD49+Zc1sp0h3tIz1DFV7039BpAm4X7mKo4HKMIHHMB0GA1UdDgQWBBTqUWct00UPblX3NMVz7YyqTNrdVDAfBgNVHSMEGDAWgBRR29lmQrNKKz9XLFSNhXMd51fPfzBKBggrBgEFBQcBAQQ+MDwwOgYIKwYBBQUHMAGGLmh0dHA6Ly9vY3NwLXRlc3RyZWYucm9vdC1jYS50aS1kaWVuc3RlLmRlL29jc3AwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwFQYDVR0gBA4wDDAKBggqghQATASBIzAKBggqhkjOPQQDAgNIADBFAiEAj8RC7GXTW8a/dCprgFfAcJIv62mcTHIpamgmdmp+3d4CIAuuxVnjfdWMG89kb37tDEfwHwv6/LtjQeCYFnLkHnII"

	// tslAnchorDevRefB64 — gematik distributes the same TEST-ONLY anchor on
	// the test and ref endpoints, so dev/ref share it.
	tslAnchorDevRefB64 = tslAnchorTestB64

	// tslAnchorProdB64 — GEM.TSL-CA3 (current ECC prod anchor).
	// Issued by GEM.RCA4, validity 2020-05-27 → 2028-05-25.
	tslAnchorProdB64 = "MIICjDCCAjOgAwIBAgIBBTAKBggqhkjOPQQDAjBtMQswCQYDVQQGEwJERTEVMBMGA1UECgwMZ2VtYXRpayBHbWJIMTQwMgYDVQQLDCtaZW50cmFsZSBSb290LUNBIGRlciBUZWxlbWF0aWtpbmZyYXN0cnVrdHVyMREwDwYDVQQDDAhHRU0uUkNBNDAeFw0yMDA1MjcwNjUwNDhaFw0yODA1MjUwNjUwNDdaMG0xCzAJBgNVBAYTAkRFMRUwEwYDVQQKDAxnZW1hdGlrIEdtYkgxMTAvBgNVBAsMKFRTTC1TaWduZXItQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxFDASBgNVBAMMC0dFTS5UU0wtQ0EzMFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABDPzDlOS6feaAf6QU9F8h9mgjTfsYkSRdAMxn1V9ZsfPCBs3zrpoC91PB0yWoFISKMCT3f8yvv4YAzjZINjILGWjgcIwgb8wHQYDVR0OBBYEFMMsMKxW1CeyxmfnYXwn65ARCcHDMB8GA1UdIwQYMBaAFIBhcBkcOO3ia+ShLqsiPnXJlP59MEIGCCsGAQUFBwEBBDYwNDAyBggrBgEFBQcwAYYmaHR0cDovL29jc3Aucm9vdC1jYS50aS1kaWVuc3RlLmRlL29jc3AwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwFQYDVR0gBA4wDDAKBggqghQATASBIzAKBggqhkjOPQQDAgNHADBEAiAxRlgS0mGX6nIf2LtN/vWz9THU291hq/dwy3ao9RW1zgIgEciAKta15WepEr0A68mv7mCHuv/mtvJ8PWUlpIAjJC8="
)

// tslAnchorCache memoises the parsed TSL anchor per environment, mirroring
// trustAnchorCache in truststore_loader.go.
var tslAnchorCache sync.Map // map[Environment]*cachedAnchor

// EmbeddedTSLSignerAnchor returns the vendored TSL-Signer-CA root for env.
//
// This is the trust anchor for verifying TSL detached signatures, distinct
// from [EmbeddedTrustAnchor] which returns the Komponenten-PKI anchor
// (GEM.RCA<n>) used for SMC-B / HBA / Fachdienst chains. The two
// hierarchies do meet — GEM.TSL-CA<n> is itself issued by GEM.RCA<m> — but
// for TSL signature verification we treat the TSL-Signer-CA as its own
// anchor so callers don't need the full Komponenten-PKI trust store loaded.
//
// Pair with [EmbeddedTSLSignerLoader] when building a [TrustStore] for use
// with [VerifyTSLDetachedSignature].
func EmbeddedTSLSignerAnchor(env Environment) (*x509.Certificate, error) {
	v, _ := tslAnchorCache.LoadOrStore(env, &cachedAnchor{})
	ca := v.(*cachedAnchor)
	ca.once.Do(func() {
		b64, ok := tslAnchorB64For(env)
		if !ok {
			ca.err = fmt.Errorf("gempki: no embedded TSL-Signer-CA anchor for environment %q", env)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			ca.err = fmt.Errorf("gempki: decode TSL-Signer-CA anchor: %w", err)
			return
		}
		c, err := ParseCertificate(raw)
		if err != nil {
			ca.err = fmt.Errorf("gempki: parse TSL-Signer-CA anchor: %w", err)
			return
		}
		ca.cert = c
	})
	return ca.cert, ca.err
}

func tslAnchorB64For(env Environment) (string, bool) {
	switch env {
	case EnvTest:
		return tslAnchorTestB64, true
	case EnvDev, EnvRef:
		return tslAnchorDevRefB64, true
	case EnvProd:
		return tslAnchorProdB64, true
	}
	return "", false
}

// EmbeddedTSLSignerLoader produces a [TrustStore] for verifying TSL detached
// signatures, seeded with the vendored TSL-Signer-CA anchor for the
// configured environment.
//
// When gematik publishes a reachable second TSL-Signer-CA standalone root
// (alongside cross-certs from the current anchor on the distribution
// endpoint), this loader gains an A_28419-style cross-cert walk parallel to
// [EmbeddedLoader] for the Komponenten-PKI roots. Until then, it's a thin
// wrapper around [EmbeddedTSLSignerAnchor] + [NewTrustStore].
type EmbeddedTSLSignerLoader struct {
	Env Environment
}

// Load implements [Loader].
func (l EmbeddedTSLSignerLoader) Load(_ context.Context) (*TrustStore, error) {
	anchor, err := EmbeddedTSLSignerAnchor(l.Env)
	if err != nil {
		return nil, err
	}
	return NewTrustStore([]*x509.Certificate{anchor})
}
