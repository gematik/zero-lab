// Package testtsl provides a snapshotted gematik test-environment Trust
// Service Status List for the gempki test suite.
//
// The TSL XML is embedded here, not in the main gempki package, so it does
// NOT ship in production binaries — embedding ~580 KB of test data into
// every consumer of gempki would be the wrong default. Tests that need a
// real-world TSL import this package; production callers fetch live data
// via [gempki.LoadTSL] with a caller-supplied http.Client.
//
// This package is internal: not part of gempki's public API.
package testtsl

import (
	"bytes"
	_ "embed"
	"fmt"
	"sync"

	"github.com/gematik/zero-lab/go/gempki"
)

// embeddedTestTSL is the gematik test environment TSL snapshot
// (sequence 10687, issued 2026-06-02). Refresh with:
//
//	curl -sS -o internal/testtsl/testdata/tsl-test.xml \
//	  https://download-test.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-test.xml
//
//go:embed testdata/tsl-test.xml
var embeddedTestTSL []byte

var (
	once     sync.Once
	parsed   *gempki.TrustServiceStatusList
	parseErr error
)

// EmbeddedTSL returns the snapshotted test-environment TSL, parsed and
// memoised. The result is fully offline — no network access on the call
// path. TSL signature verification is not performed (gempki.LoadTSL doesn't
// implement it either yet); tests that need a trusted view should compose
// this with a [gempki.TrustStore] and treat the TSL strictly as a source
// of intermediate-CA candidates.
func EmbeddedTSL() (*gempki.TrustServiceStatusList, error) {
	once.Do(func() {
		parsed, parseErr = gempki.ParseTSL(bytes.NewReader(embeddedTestTSL), "embedded:test")
		if parseErr != nil {
			parseErr = fmt.Errorf("testtsl: parse embedded TSL: %w", parseErr)
		}
	})
	return parsed, parseErr
}
