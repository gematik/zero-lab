package gempki_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNetworkLoader_HonorsContextCancellation confirms that a Load call
// aborts promptly when the caller-supplied context is cancelled, even if
// the server would otherwise keep the connection open.
//
// This is the canonical test for the "every HTTPS surface must support
// context / interruption" requirement — the same pattern applies to the
// Phase 4 OCSP fetcher and any future network-touching loader.
func TestNetworkLoader_HonorsContextCancellation(t *testing.T) {
	t.Parallel()

	// Server blocks until the request context is cancelled.
	hits := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-r.Context().Done()
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer srv.Close()

	loader := networkLoaderWithBaseURL(t, srv.URL)
	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		_, err := loader.Load(ctx)
		done <- err
	}()

	// Wait until the server reports a hit, then cancel.
	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.Equal(t, int32(1), hits.Load(), "loader should have started a request")
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.True(t,
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded),
			"expected context error, got %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("loader did not unblock after context cancellation")
	}
}

// TestNetworkLoader_HonorsCustomHTTPClient confirms that a caller-supplied
// http.Client is used end-to-end — every request goes through the caller's
// RoundTripper. A real production wire-up would pass a client with TLS
// pinning, proxies, retry middleware, metrics, etc.
func TestNetworkLoader_HonorsCustomHTTPClient(t *testing.T) {
	t.Parallel()

	customCalled := atomic.Int32{}
	resp := []byte("[]")
	custom := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			customCalled.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(resp)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
		Timeout: 5 * time.Second,
	}

	loader := gempki.NetworkLoader{Env: gempki.EnvRef, HTTPClient: custom}
	_, _ = loader.Load(t.Context())
	assert.Equal(t, int32(1), customCalled.Load(), "custom RoundTrip must be the single network surface")
}

// TestNetworkLoader_HonorsClientTimeout confirms that the caller's
// http.Client.Timeout fires when the server is slow, independent of context.
func TestNetworkLoader_HonorsClientTimeout(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	loader := networkLoaderWithBaseURL(t, srv.URL)
	loader.HTTPClient = &http.Client{Timeout: 100 * time.Millisecond}

	start := time.Now()
	_, err := loader.Load(context.Background())
	elapsed := time.Since(start)
	require.Error(t, err)
	assert.Less(t, elapsed, 1*time.Second, "client timeout must bound the call")
}

// networkLoaderWithBaseURL returns a NetworkLoader that intercepts the
// gematik URL via a custom Transport pointed at srvURL. NetworkLoader's
// public field set doesn't expose URL override (the URL is keyed off Env),
// so we install a Transport that rewrites the destination.
func networkLoaderWithBaseURL(t *testing.T, srvURL string) gempki.NetworkLoader {
	t.Helper()
	return gempki.NetworkLoader{
		Env: gempki.EnvRef,
		HTTPClient: &http.Client{
			Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				// Reroute every request to the test server.
				newURL, err := req.URL.Parse(srvURL + req.URL.Path)
				if err != nil {
					return nil, err
				}
				req2 := req.Clone(req.Context())
				req2.URL = newURL
				req2.Host = newURL.Host
				return http.DefaultTransport.RoundTrip(req2)
			}),
		},
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
