package gempki_test

import (
	"crypto/x509"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testtsl"
	"github.com/gematik/zero-lab/go/gempki/tsl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLive_OCSPResponderMeetsTUCPKI006 asks the real gematik test
// responder about the fixture SMC-B and holds it to the full TUC_PKI_006
// bar: CertID, mandatory certHash and the 37.5 s window. It needs the
// network, so it runs only with GEMPKI_LIVE_TESTS set.
func TestLive_OCSPResponderMeetsTUCPKI006(t *testing.T) {
	if os.Getenv("GEMPKI_LIVE_TESTS") == "" {
		t.Skip("set GEMPKI_LIVE_TESTS=1 to query the gematik test OCSP responder")
	}
	t.Parallel()

	ee, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBEEPEM))
	require.NoError(t, err)
	ca, err := gempki.ParsePEMCertificates([]byte(fixtureBrainpoolSMCBCA51PEM))
	require.NoError(t, err)
	list, err := testtsl.EmbeddedTSL()
	require.NoError(t, err)
	responders := tsl.OCSPResponders(list)
	tslResponders := make([]*x509.Certificate, 0, len(responders))
	for _, r := range responders {
		tslResponders = append(tslResponders, r.Cert)
	}

	checker := &gempki.OCSPChecker{
		HTTPClient:      &http.Client{Timeout: 15 * time.Second},
		TSLResponders:   tslResponders,
		RequireCertHash: true,
	}
	result, err := checker.Check(t.Context(), ee[0], ca[0])
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusGood, result.Status, "reason=%q", result.Reason)
	t.Logf("responder %s producedAt=%s thisUpdate=%s", result.ResponderName, result.ProducedAt, result.ThisUpdate)
}
