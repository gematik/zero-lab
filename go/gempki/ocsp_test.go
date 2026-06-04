package gempki_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/gematik/zero-lab/go/gempki/internal/testocsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

func TestOCSPChecker_GoodResponse(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	signKey, signCert := pki.SubCAKomp.Key, pki.SubCAKomp.Cert

	resp := testocsp.NewResponder(t, pki.SubCAKomp.Cert, signKey, signCert)
	resp.Set(pki.EEZeta.Cert.SerialNumber, testocsp.Entry{Status: testocsp.StatusGood})

	checker := &gempki.OCSPChecker{
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
		ResponderURL: resp.URL,
	}
	result, err := checker.Check(t.Context(), pki.EEZeta.Cert, pki.SubCAKomp.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusGood, result.Status)
	assert.Equal(t, gempki.RevocationSourceOCSP, result.Source)
}

func TestOCSPChecker_RevokedResponse(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	signKey, signCert := pki.SubCAKomp.Key, pki.SubCAKomp.Cert

	revokedAt := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	resp := testocsp.NewResponder(t, pki.SubCAKomp.Cert, signKey, signCert)
	resp.Set(pki.EEZeta.Cert.SerialNumber, testocsp.Entry{
		Status:    testocsp.StatusRevoked,
		RevokedAt: revokedAt,
		Reason:    ocsp.KeyCompromise,
	})

	checker := &gempki.OCSPChecker{
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
		ResponderURL: resp.URL,
	}
	result, err := checker.Check(t.Context(), pki.EEZeta.Cert, pki.SubCAKomp.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusRevoked, result.Status)
	assert.True(t, result.RevokedAt.Equal(revokedAt))
	assert.Equal(t, "keyCompromise", result.Reason)
}

func TestOCSPChecker_UnknownResponse(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	signKey, signCert := pki.SubCAKomp.Key, pki.SubCAKomp.Cert

	resp := testocsp.NewResponder(t, pki.SubCAKomp.Cert, signKey, signCert)
	// No Set call — responder reports Unknown.

	checker := &gempki.OCSPChecker{
		HTTPClient:   &http.Client{Timeout: 5 * time.Second},
		ResponderURL: resp.URL,
	}
	result, err := checker.Check(t.Context(), pki.EEZeta.Cert, pki.SubCAKomp.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusUnknown, result.Status)
}

func TestOCSPChecker_NoResponderURL(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	// EEZeta has no AIA OCSP server (testca doesn't set one).
	checker := &gempki.OCSPChecker{HTTPClient: http.DefaultClient}
	result, err := checker.Check(t.Context(), pki.EEZeta.Cert, pki.SubCAKomp.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusUnknown, result.Status)
	assert.Contains(t, result.Reason, "no OCSP responder")
}

func TestOCSPChecker_NetworkErrorPropagates(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	checker := &gempki.OCSPChecker{
		HTTPClient:   &http.Client{Timeout: 100 * time.Millisecond},
		ResponderURL: "http://127.0.0.1:1", // unreachable
	}
	_, err = checker.Check(t.Context(), pki.EEZeta.Cert, pki.SubCAKomp.Cert)
	require.Error(t, err, "network failure must propagate so a Composite can fall through")
}

func TestOCSPChecker_HonorsContextCancellation(t *testing.T) {
	t.Parallel()

	hits := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		// Sleep is bounded so the server-side goroutine always terminates,
		// even if the test's client-side cancellation doesn't propagate to
		// the server (httptest.Server.Close waits for in-flight handlers).
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer srv.Close()

	pki, err := testca.New()
	require.NoError(t, err)
	checker := &gempki.OCSPChecker{
		HTTPClient:   &http.Client{},
		ResponderURL: srv.URL,
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := checker.Check(ctx, pki.EEZeta.Cert, pki.SubCAKomp.Cert)
		done <- err
	}()

	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.Equal(t, int32(1), hits.Load())
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.True(t,
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded),
			"expected context error, got %v", err)
	case <-time.After(1 * time.Second):
		t.Fatal("OCSPChecker did not unblock client-side within 1s after context cancellation")
	}
}

func TestOCSPChecker_HonorsCustomHTTPClient(t *testing.T) {
	t.Parallel()

	customCalled := atomic.Int32{}
	custom := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			customCalled.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(http.NoBody),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}

	pki, err := testca.New()
	require.NoError(t, err)
	checker := &gempki.OCSPChecker{
		HTTPClient:   custom,
		ResponderURL: "https://example.invalid/ocsp",
	}
	_, _ = checker.Check(t.Context(), pki.EEZeta.Cert, pki.SubCAKomp.Cert)
	assert.Equal(t, int32(1), customCalled.Load(), "custom RoundTripper must own the OCSP wire")
}

func TestOCSPChecker_MaxResponseAge(t *testing.T) {
	t.Parallel()

	pki, err := testca.New()
	require.NoError(t, err)
	signKey, signCert := pki.SubCAKomp.Key, pki.SubCAKomp.Cert

	resp := testocsp.NewResponder(t, pki.SubCAKomp.Cert, signKey, signCert)
	resp.Set(pki.EEZeta.Cert.SerialNumber, testocsp.Entry{Status: testocsp.StatusGood})

	// Force the clock 48h forward; responder issued ProducedAt=now, so the
	// response is "48h old" from the checker's vantage.
	checker := &gempki.OCSPChecker{
		HTTPClient:     &http.Client{Timeout: 5 * time.Second},
		ResponderURL:   resp.URL,
		MaxResponseAge: 24 * time.Hour,
		Clock:          func() time.Time { return time.Now().Add(48 * time.Hour) },
	}
	result, err := checker.Check(t.Context(), pki.EEZeta.Cert, pki.SubCAKomp.Cert)
	require.NoError(t, err)
	assert.Equal(t, gempki.RevocationStatusUnknown, result.Status)
	assert.Contains(t, result.Reason, "exceeds MaxResponseAge")
}
