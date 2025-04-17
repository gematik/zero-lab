package epa_test

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/gematik/zero-lab/go/epa"
	"github.com/stretchr/testify/assert"
)

func TestCalculateHCV(t *testing.T) {
	tests := []struct {
		coverageBegin  string
		streetAddress  string
		expectedHash   string
		expectedBase64 string
	}{
		{"20190212", "", "4885ee8394", "SIXug5Q="},
		{"19981123", "Berliner Straße", "6545491d14", "ZUVJHRQ="},
		{"19841003", "Angermünder Straße", "7cc49e7af4", "fMSeevQ="},
		{"20010119", "Björnsonstraße", "186269e4f7", "GGJp5Pc="},
		{"20040718", "Schönhauser Allee", "353646b5c8", "NTZGtcg="},
	}

	for _, tt := range tests {
		t.Run(tt.coverageBegin+"_"+tt.streetAddress, func(t *testing.T) {
			result, err := epa.CalculateHCV(tt.coverageBegin, tt.streetAddress)
			assert.NoError(t, err)

			resultHex := hex.EncodeToString(result)
			assert.Equal(t, tt.expectedHash, resultHex)

			resultBase64 := base64.StdEncoding.EncodeToString(result)
			assert.Equal(t, tt.expectedBase64, resultBase64)
		})
	}
}
