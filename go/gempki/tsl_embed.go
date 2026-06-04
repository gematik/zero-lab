package gempki

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"fmt"
	"sync"
)

// embeddedTestTSL is a snapshot of the gematik test-environment Trust
// Service Status List (sequence 10687, issued 2026-06-02). The snapshot
// lets unit tests exercise the real-world TI wire format without network
// access. Production callers should fetch a fresh TSL via [LoadTSL] —
// embedded data goes stale.
//
// To refresh:
//
//	curl -sS -o testdata/tsl-test.xml \
//	  https://download-test.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-test.xml
//
//go:embed testdata/tsl-test.xml
var embeddedTestTSL []byte

var (
	tslOnce sync.Once
	tslVal  *TrustServiceStatusList
	tslErr  error
)

// EmbeddedTestTSL returns the snapshotted test-environment TSL, parsed.
// Memoised — repeated calls share the same parsed object. The result is
// fully self-contained: no network access on the call path.
//
// TSL signature verification is not performed here (and is not yet
// implemented in [LoadTSL] either); tests that need a trusted view should
// compose this with a [TrustStore] and treat the TSL strictly as a source
// of intermediate-CA candidates.
func EmbeddedTestTSL() (*TrustServiceStatusList, error) {
	tslOnce.Do(func() {
		tslVal, tslErr = ParseTSL(bytes.NewReader(embeddedTestTSL), "embedded:test")
		if tslErr != nil {
			tslErr = fmt.Errorf("gempki: parse embedded TSL: %w", tslErr)
		}
	})
	return tslVal, tslErr
}

// IntermediateCAsFromTSL returns every CA/PKC service certificate the TSL
// lists — the candidate intermediates a Validator can be fed alongside an
// end-entity. Order is the document order from the TSL XML.
//
// Each returned cert was already parsed (and brainpool-handled) by
// [ParseTSL]; callers can pass them straight to [Validator.Validate] or
// [BuildChain] as the intermediates slice.
func IntermediateCAsFromTSL(tsl *TrustServiceStatusList) []*X509FromTSL {
	if tsl == nil {
		return nil
	}
	out := make([]*X509FromTSL, 0, 32)
	for _, prov := range tsl.TrustServiceProviderList {
		for _, svc := range prov.TSPServices {
			info := svc.ServiceInformation
			if info.ServiceTypeIdentifier != ServiceTypeCaPkc {
				continue
			}
			cert := info.ServiceDigitalIdentity.DigitalId.X509Certificate
			if cert == nil {
				continue
			}
			out = append(out, &X509FromTSL{
				Cert:          cert,
				ServiceStatus: info.ServiceStatus,
			})
		}
	}
	return out
}

// X509FromTSL pairs a TSL-sourced intermediate CA certificate with the
// status metadata the TSL carries for it. The Cert is what callers feed
// into chain building; the ServiceStatus is informational — TI consumers
// typically only trust certs in "granted" status, but enforcing that is
// the caller's call.
type X509FromTSL struct {
	Cert          *x509.Certificate
	ServiceStatus string
}
