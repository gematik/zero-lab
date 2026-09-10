package gempki

import (
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"fmt"
	"sync"
)

// Environment selects which gematik TI the library talks to: which trust
// anchors, which embedded roots.json, which download endpoints. It is fixed
// when a validator or trust store is built; nothing reconfigures it at
// runtime.
type Environment string

const (
	EnvDev  Environment = "dev"
	EnvRef  Environment = "ref"
	EnvTest Environment = "test"
	EnvProd Environment = "prod"
)

// envData is everything that differs between environments. dev and ref are
// one entry: gematik distributes a single anchor, roots.json and TSL for
// both.
type envData struct {
	rootsAnchorB64 string // GEM.RCA<n> — the Komponenten-PKI anchor taken on faith
	tslAnchorB64   string // GEM.TSL-CA<n> — the TSL-Signer-CA anchor taken on faith
	rootsJSON      []byte // gematik's roots.json, compiled in
	rootsURL       string // where a fresh roots.json is fetched from
}

// The anchors below are the exact DER gematik publishes; if gematik rotates
// one, the constant changes and the library is rebuilt. Every other root
// earns trust by chaining to its anchor through the A_28419 cross-cert walk
// in roots.go. All non-prod material is TEST-ONLY.

//go:embed roots-test.json
var embeddedRootsTest []byte

//go:embed roots-dev-ref.json
var embeddedRootsDevRef []byte

//go:embed roots-prod.json
var embeddedRootsProd []byte

const (
	rootsAnchorTestB64   = "MIICyjCCAnKgAwIBAgIBATAKBggqhkjOPQQDAjCBgTELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxGzAZBgNVBAMMEkdFTS5SQ0E4IFRFU1QtT05MWTAeFw0yMzEyMDcxMDE3NTJaFw0zMzEyMDQxMDE3NTJaMIGBMQswCQYDVQQGEwJERTEfMB0GA1UECgwWZ2VtYXRpayBHbWJIIE5PVC1WQUxJRDE0MDIGA1UECwwrWmVudHJhbGUgUm9vdC1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEbMBkGA1UEAwwSR0VNLlJDQTggVEVTVC1PTkxZMFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABDLncr51uoi5aGXoctM3aIm/tjMRXGu+57M1TUjwsy2HhyjEBaMWqlGMBcmcGZhbcKt/lepwcDk3EvGRmDJWGQ2jgdcwgdQwHQYDVR0OBBYEFKG5FDonMHtcZx71MsSx1RqJ/LxTMEoGCCsGAQUFBwEBBD4wPDA6BggrBgEFBQcwAYYuaHR0cDovL29jc3AtdGVzdHJlZi5yb290LWNhLnRpLWRpZW5zdGUuZGUvb2NzcDAOBgNVHQ8BAf8EBAMCAQYwRgYDVR0gBD8wPTA7BggqghQATASBIzAvMC0GCCsGAQUFBwIBFiFodHRwOi8vd3d3LmdlbWF0aWsuZGUvZ28vcG9saWNpZXMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNGADBDAh9GANMYXG7LtOY83ffXG0MB/Hb1cGPV5umiJgyOlkpVAiAL+e32oEH1N625yww+4lgFd0LBg9gcFLQ87rEdlyCq1Q=="
	rootsAnchorDevRefB64 = "MIICzDCCAnGgAwIBAgIBATAKBggqhkjOPQQDAjCBgTELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxGzAZBgNVBAMMEkdFTS5SQ0E3IFRFU1QtT05MWTAeFw0yMzA1MjUxMjIxMzlaFw0zMzA1MjIxMjIxMzlaMIGBMQswCQYDVQQGEwJERTEfMB0GA1UECgwWZ2VtYXRpayBHbWJIIE5PVC1WQUxJRDE0MDIGA1UECwwrWmVudHJhbGUgUm9vdC1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEbMBkGA1UEAwwSR0VNLlJDQTcgVEVTVC1PTkxZMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGv3lzIASzKQHW0YbxoaSIFUlGcgH8c/JEWOifqVVKkJUS81zG1ogcL6skAhGCtkksfdSJKiZnmnKeQ/yAgGZUaOB1zCB1DAdBgNVHQ4EFgQUsvAJPk0L4wgkgJY1bjo2MyvySxowSgYIKwYBBQUHAQEEPjA8MDoGCCsGAQUFBzABhi5odHRwOi8vb2NzcC10ZXN0cmVmLnJvb3QtY2EudGktZGllbnN0ZS5kZS9vY3NwMA4GA1UdDwEB/wQEAwIBBjBGBgNVHSAEPzA9MDsGCCqCFABMBIEjMC8wLQYIKwYBBQUHAgEWIWh0dHA6Ly93d3cuZ2VtYXRpay5kZS9nby9wb2xpY2llczAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCntB3Gck9DDlVADBZQCrT3RU3D9QS5k9bd3NKCexf9LQIhAIG2Qyu9HVlKnz8a8qdSJE6+TTejs15x7CLEvaLouXUk"
	rootsAnchorProdB64   = "MIICmTCCAkCgAwIBAgIBATAKBggqhkjOPQQDAjBtMQswCQYDVQQGEwJERTEVMBMGA1UECgwMZ2VtYXRpayBHbWJIMTQwMgYDVQQLDCtaZW50cmFsZSBSb290LUNBIGRlciBUZWxlbWF0aWtpbmZyYXN0cnVrdHVyMREwDwYDVQQDDAhHRU0uUkNBODAeFw0yMzEyMTIwOTU3MTNaFw0zMzEyMDkwOTU3MTNaMG0xCzAJBgNVBAYTAkRFMRUwEwYDVQQKDAxnZW1hdGlrIEdtYkgxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxETAPBgNVBAMMCEdFTS5SQ0E4MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABIwmqH0yFsDRE7IMfPIRk+Emh2U4ZFVjvFgmr0qSwdyVL32ZfNpLJGvUPhCYiedfMSkDBK+zToDBDU/lmSScDT6jgc8wgcwwHQYDVR0OBBYEFIucDNB6vgBoeq0yjWmPmYByx5ssMEIGCCsGAQUFBwEBBDYwNDAyBggrBgEFBQcwAYYmaHR0cDovL29jc3Aucm9vdC1jYS50aS1kaWVuc3RlLmRlL29jc3AwDgYDVR0PAQH/BAQDAgEGMEYGA1UdIAQ/MD0wOwYIKoIUAEwEgSMwLzAtBggrBgEFBQcCARYhaHR0cDovL3d3dy5nZW1hdGlrLmRlL2dvL3BvbGljaWVzMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgZMA4ldNbm42AaLy/iTkIRbOZ5StBjYbn+asOoN06eWcCIH8na29NzkvzPKwQ1UY4qaPdOCvibXlC07zbTfzLJzkx"

	// GEM.TSL-CA28 TEST-ONLY, issued by GEM.RCA4 TEST-ONLY, 2020-04-08 → 2028-04-06.
	// gematik serves the same anchor on the test and ref endpoints.
	tslAnchorTestRefB64 = "MIICwDCCAmagAwIBAgIBETAKBggqhkjOPQQDAjCBgTELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxGzAZBgNVBAMMEkdFTS5SQ0E0IFRFU1QtT05MWTAeFw0yMDA0MDgwOTE1NDdaFw0yODA0MDYwOTE1NDZaMIGCMQswCQYDVQQGEwJERTEfMB0GA1UECgwWZ2VtYXRpayBHbWJIIE5PVC1WQUxJRDExMC8GA1UECwwoVFNMLVNpZ25lci1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEfMB0GA1UEAwwWR0VNLlRTTC1DQTI4IFRFU1QtT05MWTBaMBQGByqGSM49AgEGCSskAwMCCAEBBwNCAARcg9HFYez8wU/bMF2h+j8BvS/bkyba2NYsyaHgdt3PHivQ58jF5CkYD49+Zc1sp0h3tIz1DFV7039BpAm4X7mKo4HKMIHHMB0GA1UdDgQWBBTqUWct00UPblX3NMVz7YyqTNrdVDAfBgNVHSMEGDAWgBRR29lmQrNKKz9XLFSNhXMd51fPfzBKBggrBgEFBQcBAQQ+MDwwOgYIKwYBBQUHMAGGLmh0dHA6Ly9vY3NwLXRlc3RyZWYucm9vdC1jYS50aS1kaWVuc3RlLmRlL29jc3AwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwFQYDVR0gBA4wDDAKBggqghQATASBIzAKBggqhkjOPQQDAgNIADBFAiEAj8RC7GXTW8a/dCprgFfAcJIv62mcTHIpamgmdmp+3d4CIAuuxVnjfdWMG89kb37tDEfwHwv6/LtjQeCYFnLkHnII"
	// GEM.TSL-CA3, issued by GEM.RCA4, 2020-05-27 → 2028-05-25.
	tslAnchorProdB64 = "MIICjDCCAjOgAwIBAgIBBTAKBggqhkjOPQQDAjBtMQswCQYDVQQGEwJERTEVMBMGA1UECgwMZ2VtYXRpayBHbWJIMTQwMgYDVQQLDCtaZW50cmFsZSBSb290LUNBIGRlciBUZWxlbWF0aWtpbmZyYXN0cnVrdHVyMREwDwYDVQQDDAhHRU0uUkNBNDAeFw0yMDA1MjcwNjUwNDhaFw0yODA1MjUwNjUwNDdaMG0xCzAJBgNVBAYTAkRFMRUwEwYDVQQKDAxnZW1hdGlrIEdtYkgxMTAvBgNVBAsMKFRTTC1TaWduZXItQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxFDASBgNVBAMMC0dFTS5UU0wtQ0EzMFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABDPzDlOS6feaAf6QU9F8h9mgjTfsYkSRdAMxn1V9ZsfPCBs3zrpoC91PB0yWoFISKMCT3f8yvv4YAzjZINjILGWjgcIwgb8wHQYDVR0OBBYEFMMsMKxW1CeyxmfnYXwn65ARCcHDMB8GA1UdIwQYMBaAFIBhcBkcOO3ia+ShLqsiPnXJlP59MEIGCCsGAQUFBwEBBDYwNDAyBggrBgEFBQcwAYYmaHR0cDovL29jc3Aucm9vdC1jYS50aS1kaWVuc3RlLmRlL29jc3AwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwFQYDVR0gBA4wDDAKBggqghQATASBIzAKBggqhkjOPQQDAgNHADBEAiAxRlgS0mGX6nIf2LtN/vWz9THU291hq/dwy3ao9RW1zgIgEciAKta15WepEr0A68mv7mCHuv/mtvJ8PWUlpIAjJC8="
)

var envTable = map[Environment]*envData{
	EnvTest: {
		rootsAnchorB64: rootsAnchorTestB64,
		tslAnchorB64:   tslAnchorTestRefB64,
		rootsJSON:      embeddedRootsTest,
		rootsURL:       "https://download-test.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json",
	},
	EnvRef: {
		rootsAnchorB64: rootsAnchorDevRefB64,
		tslAnchorB64:   tslAnchorTestRefB64,
		rootsJSON:      embeddedRootsDevRef,
		rootsURL:       "https://download-ref.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json",
	},
	EnvProd: {
		rootsAnchorB64: rootsAnchorProdB64,
		tslAnchorB64:   tslAnchorProdB64,
		rootsJSON:      embeddedRootsProd,
		rootsURL:       "https://download.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json",
	},
}

func init() { envTable[EnvDev] = envTable[EnvRef] }

func dataFor(env Environment) (*envData, error) {
	d, ok := envTable[env]
	if !ok {
		return nil, fmt.Errorf("gempki: unknown environment %q", env)
	}
	return d, nil
}

// anchorCache memoises decoded anchors; the base64 is only ever parsed once
// per (kind, environment).
var anchorCache sync.Map // map[string]*cachedAnchor

type cachedAnchor struct {
	once sync.Once
	cert *x509.Certificate
	err  error
}

func decodeAnchor(key, b64 string) (*x509.Certificate, error) {
	v, _ := anchorCache.LoadOrStore(key, &cachedAnchor{})
	ca := v.(*cachedAnchor)
	ca.once.Do(func() {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			ca.err = fmt.Errorf("gempki: decode anchor %s: %w", key, err)
			return
		}
		ca.cert, ca.err = ParseCertificate(raw)
	})
	return ca.cert, ca.err
}

// embeddedTrustAnchor returns the GEM.RCA<n> anchor compiled in for env.
func embeddedTrustAnchor(env Environment) (*x509.Certificate, error) {
	d, err := dataFor(env)
	if err != nil {
		return nil, err
	}
	return decodeAnchor("roots:"+string(env), d.rootsAnchorB64)
}

// EmbeddedTSLSignerAnchor returns the TSL-Signer-CA root compiled in for env.
//
// It is the anchor for verifying a TSL's detached signature, distinct from
// the Komponenten-PKI anchor used for certificate chains. The two hierarchies
// do meet — GEM.TSL-CA<n> is itself issued by a GEM.RCA<m> — but treating the
// TSL-Signer-CA as its own anchor means a TSL can be verified without the
// full root store loaded. gematik currently publishes one TSL-Signer-CA per
// environment; a cross-cert walk like the one for roots gets added the day a
// reachable second one exists, not before.
func EmbeddedTSLSignerAnchor(env Environment) (*x509.Certificate, error) {
	d, err := dataFor(env)
	if err != nil {
		return nil, err
	}
	return decodeAnchor("tsl:"+string(env), d.tslAnchorB64)
}

// TSLSignerTrustStore returns a [TrustStore] holding env's TSL-Signer-CA
// anchor, for [VerifyTSLDetachedSignature].
func TSLSignerTrustStore(env Environment) (*TrustStore, error) {
	anchor, err := EmbeddedTSLSignerAnchor(env)
	if err != nil {
		return nil, err
	}
	return NewTrustStore([]*x509.Certificate{anchor})
}
