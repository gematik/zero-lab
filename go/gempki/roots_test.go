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

// anchorCN pins the GEM.RCA anchor each environment is compiled with; the
// store must contain it whatever the cross-cert walk did or did not reach.
var anchorCN = map[gempki.Environment]string{
	gempki.EnvTest: "GEM.RCA8 TEST-ONLY",
	gempki.EnvRef:  "GEM.RCA7 TEST-ONLY",
	gempki.EnvDev:  "GEM.RCA7 TEST-ONLY",
	gempki.EnvProd: "GEM.RCA8",
}

func TestEmbeddedRoots_AllEnvironments(t *testing.T) {
	t.Parallel()
	for env, cn := range anchorCN {
		t.Run(string(env), func(t *testing.T) {
			t.Parallel()
			ts, err := gempki.EmbeddedRoots(env)
			require.NoError(t, err)
			assert.GreaterOrEqual(t, ts.Len(), 1, "%s must produce at least one root", env)
			_, ok := ts.ByCommonName(cn)
			assert.True(t, ok, "%s: anchor %s must be in the store", env, cn)
		})
	}
}

// The historical GEM.RCA1/2/6 are RSA-keyed and part of the TI trust corpus;
// a roots.json that carries them must load, or cards from those eras cannot
// be validated.
func TestEmbeddedRoots_AcceptsRSAEntries(t *testing.T) {
	t.Parallel()
	for _, env := range []gempki.Environment{gempki.EnvProd, gempki.EnvTest, gempki.EnvRef} {
		ts, err := gempki.EmbeddedRoots(env)
		require.NoError(t, err, "%s: RSA entries in roots.json must not fail the load", env)
		require.GreaterOrEqual(t, ts.Len(), 1)
	}
}

// A cross-cert signed by a sibling rather than the walk position (the test
// roots.json has one) stops that walk direction; it must not fail the load.
func TestEmbeddedRoots_NonTraversableWalkStopsGracefully(t *testing.T) {
	t.Parallel()
	ts, err := gempki.EmbeddedRoots(gempki.EnvTest)
	require.NoError(t, err)
	_, ok := ts.ByCommonName(anchorCN[gempki.EnvTest])
	require.True(t, ok, "the anchor is present even when the walk halts immediately")
}

func TestEmbeddedRoots_UnknownEnvironment(t *testing.T) {
	t.Parallel()
	_, err := gempki.EmbeddedRoots(gempki.Environment("bogus"))
	require.Error(t, err)
}

func TestFetchRoots_RequiresClient(t *testing.T) {
	t.Parallel()
	_, err := gempki.FetchRoots(t.Context(), gempki.EnvRef, nil)
	require.Error(t, err)
}

// reroutingClient sends every request to srvURL instead of the gematik
// endpoint FetchRoots derives from the environment.
func reroutingClient(srvURL string) *http.Client {
	return &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			newURL, err := req.URL.Parse(srvURL + req.URL.Path)
			if err != nil {
				return nil, err
			}
			req2 := req.Clone(req.Context())
			req2.URL = newURL
			req2.Host = newURL.Host
			return http.DefaultTransport.RoundTrip(req2)
		}),
	}
}

func TestFetchRoots_HonorsContextCancellation(t *testing.T) {
	t.Parallel()

	hits := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		<-r.Context().Done()
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := gempki.FetchRoots(ctx, gempki.EnvRef, reroutingClient(srv.URL))
		done <- err
	}()

	deadline := time.Now().Add(2 * time.Second)
	for hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	require.Equal(t, int32(1), hits.Load(), "the request must have started")
	cancel()

	select {
	case err := <-done:
		require.Error(t, err)
		assert.True(t,
			errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded),
			"expected a context error, got %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("FetchRoots did not unblock after context cancellation")
	}
}

func TestFetchRoots_UsesSuppliedClient(t *testing.T) {
	t.Parallel()

	called := atomic.Int32{}
	client := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			called.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader([]byte("[]"))),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}
	_, _ = gempki.FetchRoots(t.Context(), gempki.EnvRef, client)
	assert.Equal(t, int32(1), called.Load(), "the caller's RoundTripper is the only network surface")
}

func TestFetchRoots_HonorsClientTimeout(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	client := reroutingClient(srv.URL)
	client.Timeout = 100 * time.Millisecond

	start := time.Now()
	_, err := gempki.FetchRoots(context.Background(), gempki.EnvRef, client)
	require.Error(t, err)
	assert.Less(t, time.Since(start), time.Second, "the client timeout must bound the call")
}
