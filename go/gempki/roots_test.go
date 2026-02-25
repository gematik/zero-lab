package gempki_test

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustAnchorsNonNil(t *testing.T) {
	if gempki.TrustAnchorTest == nil {
		t.Error("TrustAnchorTest is nil")
	}
	if gempki.TrustAnchorDev == nil {
		t.Error("TrustAnchorDev is nil")
	}
	if gempki.TrustAnchorRef == nil {
		t.Error("TrustAnchorRef is nil")
	}
	if gempki.TrustAnchorProd == nil {
		t.Error("TrustAnchorProd is nil")
	}
}

// TestTrustAnchorCN verifies the expected common name of each trust anchor.
func TestTrustAnchorCN(t *testing.T) {
	tests := []struct {
		name   string
		got    string
		wantCN string
	}{
		{"TrustAnchorTest", gempki.TrustAnchorTest.Subject.CommonName, "GEM.RCA8 TEST-ONLY"},
		{"TrustAnchorDev", gempki.TrustAnchorDev.Subject.CommonName, "GEM.RCA7 TEST-ONLY"},
		{"TrustAnchorRef", gempki.TrustAnchorRef.Subject.CommonName, "GEM.RCA7 TEST-ONLY"},
		{"TrustAnchorProd", gempki.TrustAnchorProd.Subject.CommonName, "GEM.RCA8"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.wantCN {
				t.Errorf("CN = %q, want %q", tc.got, tc.wantCN)
			}
		})
	}
}

// TestTrustAnchorIsCA verifies each trust anchor is a CA certificate.
func TestTrustAnchorIsCA(t *testing.T) {
	for _, tc := range []struct {
		name string
		isCA bool
	}{
		{"TrustAnchorTest", gempki.TrustAnchorTest.IsCA},
		{"TrustAnchorDev", gempki.TrustAnchorDev.IsCA},
		{"TrustAnchorRef", gempki.TrustAnchorRef.IsCA},
		{"TrustAnchorProd", gempki.TrustAnchorProd.IsCA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if !tc.isCA {
				t.Error("IsCA = false, want true")
			}
		})
	}
}

// TestTrustAnchorIssuer verifies the issuer CN of each trust anchor.
// Test and prod anchors (GEM.RCA8) are self-signed; dev/ref (GEM.RCA9 TEST-ONLY)
// is cross-signed by GEM.RCA8 TEST-ONLY.
func TestTrustAnchorIssuer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		issuerCN string
		wantCN   string
	}{
		{"TrustAnchorTest", gempki.TrustAnchorTest.Issuer.CommonName, "GEM.RCA8 TEST-ONLY"},
		{"TrustAnchorDev", gempki.TrustAnchorDev.Issuer.CommonName, "GEM.RCA7 TEST-ONLY"},
		{"TrustAnchorRef", gempki.TrustAnchorRef.Issuer.CommonName, "GEM.RCA7 TEST-ONLY"},
		{"TrustAnchorProd", gempki.TrustAnchorProd.Issuer.CommonName, "GEM.RCA8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.issuerCN != tc.wantCN {
				t.Errorf("issuer CN = %q, want %q", tc.issuerCN, tc.wantCN)
			}
		})
	}
}

// TestTrustAnchorValidity verifies each trust anchor is currently valid.
func TestTrustAnchorValidity(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name      string
		notBefore time.Time
		notAfter  time.Time
	}{
		{"TrustAnchorTest", gempki.TrustAnchorTest.NotBefore, gempki.TrustAnchorTest.NotAfter},
		{"TrustAnchorDev", gempki.TrustAnchorDev.NotBefore, gempki.TrustAnchorDev.NotAfter},
		{"TrustAnchorRef", gempki.TrustAnchorRef.NotBefore, gempki.TrustAnchorRef.NotAfter},
		{"TrustAnchorProd", gempki.TrustAnchorProd.NotBefore, gempki.TrustAnchorProd.NotAfter},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if now.Before(tc.notBefore) {
				t.Errorf("not yet valid: NotBefore = %s", tc.notBefore)
			}
			if now.After(tc.notAfter) {
				t.Errorf("expired: NotAfter = %s", tc.notAfter)
			}
		})
	}
}

// TestDevRefSamePointer verifies TrustAnchorDev and TrustAnchorRef are the same object.
func TestDevRefSamePointer(t *testing.T) {
	if gempki.TrustAnchorDev != gempki.TrustAnchorRef {
		t.Error("TrustAnchorDev and TrustAnchorRef should be the same pointer")
	}
}

// TestTestOnlyLabel verifies dev/ref anchors carry the TEST-ONLY label and
// test/prod anchors do not.
func TestTestOnlyLabel(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cn           string
		wantTestOnly bool
	}{
		{"TrustAnchorTest", gempki.TrustAnchorTest.Subject.CommonName, true},
		{"TrustAnchorDev", gempki.TrustAnchorDev.Subject.CommonName, true},
		{"TrustAnchorRef", gempki.TrustAnchorRef.Subject.CommonName, true},
		{"TrustAnchorProd", gempki.TrustAnchorProd.Subject.CommonName, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hasLabel := strings.Contains(tc.cn, "TEST-ONLY")
			if hasLabel != tc.wantTestOnly {
				t.Errorf("CN %q: TEST-ONLY label present=%v, want %v", tc.cn, hasLabel, tc.wantTestOnly)
			}
		})
	}
}

// roundTripFunc lets a plain function implement http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// --- responseRecorder helpers --------------------------------------------

type responseRecorder struct {
	code   int
	header http.Header
	body   strings.Builder
}

func newResponseRecorder() *responseRecorder {
	return &responseRecorder{code: http.StatusOK, header: make(http.Header)}
}

func (r *responseRecorder) Header() http.Header         { return r.header }
func (r *responseRecorder) WriteHeader(code int)        { r.code = code }
func (r *responseRecorder) Write(b []byte) (int, error) { return r.body.Write(b) }

func (r *responseRecorder) result() *http.Response {
	return &http.Response{
		StatusCode: r.code,
		Header:     r.header,
		Body:       io.NopCloser(strings.NewReader(r.body.String())),
	}
}

// clientServing returns an *http.Client whose every request is answered by
// the given handler, regardless of URL.
func clientServing(handler http.Handler) *http.Client {
	return &http.Client{
		Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			rw := newResponseRecorder()
			handler.ServeHTTP(rw, req)
			return rw.result(), nil
		}),
	}
}

// --- error path tests (no network needed) ---------------------------------

func TestLoadRootsUnknownEnvironment(t *testing.T) {
	_, err := gempki.LoadRoots(context.Background(), http.DefaultClient, "unknown")
	if err == nil {
		t.Error("expected error for unknown environment, got nil")
	}
}

func TestLoadRootsMalformedJSON(t *testing.T) {
	client := clientServing(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "not json {{{")
	}))
	_, err := gempki.LoadRoots(context.Background(), client, gempki.EnvTest)
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestLoadRootsInvalidCertBytes(t *testing.T) {
	// Valid JSON structure but cert field contains garbage bytes.
	client := clientServing(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// []byte in JSON is base64; "AAAA" decodes to 3 zero bytes — not a valid cert.
		io.WriteString(w, `{"roots":[{"cert":"AAAA"}]}`)
	}))
	_, err := gempki.LoadRoots(context.Background(), client, gempki.EnvRef)
	if err == nil {
		t.Error("expected error for invalid cert bytes, got nil")
	}
}

func TestLoadRootsHTTPError(t *testing.T) {
	client := clientServing(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	// LoadRoots doesn't check status codes, so the HTML body will fail JSON decoding.
	_, err := gempki.LoadRoots(context.Background(), client, gempki.EnvTest)
	if err == nil {
		t.Error("expected error when server returns HTTP 500, got nil")
	}
}

func TestLoadRoots(t *testing.T) {
	type testCase struct {
		env gempki.Environment
	}
	tests := []testCase{
		{gempki.EnvTest},
		{gempki.EnvDev},
		{gempki.EnvRef},
		{gempki.EnvProd},
	}
	for _, tc := range tests {
		t.Run(string(tc.env), func(t *testing.T) {
			assert := assert.New(t)
			roots, err := gempki.LoadRoots(context.Background(), http.DefaultClient, tc.env)
			require.NoError(t, err, "LoadRoots failed")
			assert.NotEmpty(roots.ByCommonName, "expected non-empty trusted certificates")
			for _, root := range roots.ByCommonName {
				assert.NotNil(root, "expected non-nil certificate in root")
				assert.NotEmpty(root.Subject.CommonName, "expected non-empty common name in root certificate")
			}
		})
	}
}

func TestCertPoolWithCAs(t *testing.T) {

	tsl, err := gempki.LoadTSL(context.Background(), http.DefaultClient, gempki.URLTrustServiceListRef)
	require.NoError(t, err, "loading TSL failed")

	roots, err := gempki.LoadRootsEmbedded(gempki.EnvRef)
	require.NoError(t, err, "loading embedded roots failed")

	httpClient := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: roots.BuildCertPoolWithSubCAs(tsl),
			},
		},
	}

	resp, err := httpClient.Get("https://epa-as-1.dev.epa4all.de/")
	if err != nil {
		t.Fatalf("sending request to EPA: %v", err)
	}
	t.Logf("Response: %v", resp)

}
