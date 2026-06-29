package gempki_test

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/gematik/zero-lab/go/gempki/internal/testtsl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// sampleTSLBytes is the placeholder "TSL XML" used by these tests. The
// detached-signature wire format treats the signed bytes as opaque, so any
// non-trivial payload works.
var sampleTSLBytes = []byte("<?xml version=\"1.0\"?><FakeTSL>real data goes here</FakeTSL>")

// signerNode returns a testca Node usable as a TSL-Signer: leaf cert under
// SubCAKomp (NIST P-256), digitalSignature key usage.
func signerNode(t *testing.T) (*testca.TestPKI, *testca.Node) {
	t.Helper()
	pki, err := testca.New()
	require.NoError(t, err)
	return pki, pki.EEZeta
}

func TestParseTSLDetachedSignature_HappyPath(t *testing.T) {
	t.Parallel()
	_, signer := signerNode(t)
	sigBytes := testtsl.SignTSL(t, sampleTSLBytes, signer)

	parsed, err := gempki.ParseTSLDetachedSignature(sigBytes)
	require.NoError(t, err)
	require.NotNil(t, parsed.Signer)
	assert.True(t, parsed.Signer.Equal(signer.Cert),
		"embedded signer cert must round-trip")
	assert.Equal(t, sigBytes, parsed.Raw)

	require.NoError(t, parsed.VerifyOver(sampleTSLBytes))
}

func TestParseTSLDetachedSignature_TamperedTSL(t *testing.T) {
	t.Parallel()
	_, signer := signerNode(t)
	sigBytes := testtsl.SignTSL(t, sampleTSLBytes, signer)

	parsed, err := gempki.ParseTSLDetachedSignature(sigBytes)
	require.NoError(t, err)

	tampered := append([]byte(nil), sampleTSLBytes...)
	tampered[10] ^= 0x01
	err = parsed.VerifyOver(tampered)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not verify")
}

func TestParseTSLDetachedSignature_TamperedSignature(t *testing.T) {
	t.Parallel()
	_, signer := signerNode(t)
	sigBytes := testtsl.SignTSL(t, sampleTSLBytes, signer)

	// Flip a byte deep inside — past the AlgorithmIdentifier (12 bytes after
	// the 4-byte outer wrapper = offset ~17), within the ECDSA-Sig-Value.
	tampered := append([]byte(nil), sigBytes...)
	tampered[20] ^= 0xff

	parsed, err := gempki.ParseTSLDetachedSignature(tampered)
	if err != nil {
		// Some byte positions break the SEQUENCE structure outright — that's
		// also a valid failure mode.
		return
	}
	err = parsed.VerifyOver(sampleTSLBytes)
	require.Error(t, err, "tampered signature must not verify")
}

func TestParseTSLDetachedSignature_RSAOIDRejected(t *testing.T) {
	t.Parallel()

	// Hand-construct a minimal .sig file whose AlgorithmIdentifier names
	// id-RSASSA-PSS. The other fields can be junk — the parser must error
	// out at the OID check before touching them.
	rsaPSSAlgID := []byte{
		0x30, 0x0D,
		0x06, 0x09,
		0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0A,
	}
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(rsaPSSAlgID)
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(1)
			b.AddASN1Int64(2)
		})
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes([]byte{0x01, 0x02, 0x03})
		})
	})
	sigBytes, err := b.Bytes()
	require.NoError(t, err)

	_, err = gempki.ParseTSLDetachedSignature(sigBytes)
	require.Error(t, err)
	assert.True(t, errors.Is(err, gempki.ErrRSANotSupported),
		"RSA-PSS AlgorithmIdentifier must yield ErrRSANotSupported, got %v", err)
}

func TestParseTSLDetachedSignature_UnknownAlgorithmRejected(t *testing.T) {
	t.Parallel()

	// AlgorithmIdentifier with an OID we don't recognise (1.2.3.4).
	unknownAlgID := []byte{
		0x30, 0x06,
		0x06, 0x04,
		0x2A, 0x03, 0x04, 0x05, // not even valid as 1.2.3.4 — close enough
	}
	_ = unknownAlgID

	// Build a valid SEQUENCE with the OID 1.2.3 in the algorithm.
	junkOID := asn1.ObjectIdentifier{1, 2, 3}
	oidBytes, err := asn1.Marshal(junkOID)
	require.NoError(t, err)

	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes(oidBytes)
		})
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(1)
			b.AddASN1Int64(2)
		})
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddBytes([]byte{0x01, 0x02})
		})
	})
	sigBytes, err := b.Bytes()
	require.NoError(t, err)

	_, err = gempki.ParseTSLDetachedSignature(sigBytes)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported algorithm")
	assert.False(t, errors.Is(err, gempki.ErrRSANotSupported))
}

func TestParseTSLDetachedSignature_TruncatedContainerRejected(t *testing.T) {
	t.Parallel()
	_, signer := signerNode(t)
	sigBytes := testtsl.SignTSL(t, sampleTSLBytes, signer)

	_, err := gempki.ParseTSLDetachedSignature(sigBytes[:len(sigBytes)-5])
	require.Error(t, err)
}

func TestParseTSLDetachedSignature_WrongOuterTagRejected(t *testing.T) {
	t.Parallel()
	_, signer := signerNode(t)
	sigBytes := testtsl.SignTSL(t, sampleTSLBytes, signer)

	bogus := append([]byte(nil), sigBytes...)
	bogus[0] = 0x31 // SET, not SEQUENCE

	_, err := gempki.ParseTSLDetachedSignature(bogus)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SEQUENCE")
}

func TestParseTSLDetachedSignature_EmptyRejected(t *testing.T) {
	t.Parallel()
	_, err := gempki.ParseTSLDetachedSignature(nil)
	require.Error(t, err)
}

func TestVerifyTSLDetachedSignature_HappyPath(t *testing.T) {
	t.Parallel()
	pki, signer := signerNode(t)
	sigBytes := testtsl.SignTSL(t, sampleTSLBytes, signer)

	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RCA7.Cert})
	require.NoError(t, err)

	parsed, err := gempki.VerifyTSLDetachedSignature(
		t.Context(),
		sampleTSLBytes,
		sigBytes,
		[]*x509.Certificate{pki.SubCAKomp.Cert},
		ts,
		gempki.ValidatePathOptions{},
	)
	require.NoError(t, err)
	assert.True(t, parsed.Signer.Equal(signer.Cert))
}

func TestVerifyTSLDetachedSignature_UntrustedSigner(t *testing.T) {
	t.Parallel()
	pki, signer := signerNode(t)
	sigBytes := testtsl.SignTSL(t, sampleTSLBytes, signer)

	// Trust an unrelated root → signer chain cannot be built.
	ts, err := gempki.NewTrustStore([]*x509.Certificate{pki.RogueRoot.Cert})
	require.NoError(t, err)

	_, err = gempki.VerifyTSLDetachedSignature(
		t.Context(),
		sampleTSLBytes,
		sigBytes,
		[]*x509.Certificate{pki.SubCAKomp.Cert},
		ts,
		gempki.ValidatePathOptions{},
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "chain")
}

func TestLoadTSLDetachedSignature_HappyPath(t *testing.T) {
	t.Parallel()
	_, signer := signerNode(t)
	sigBytes := testtsl.SignTSL(t, sampleTSLBytes, signer)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(sigBytes)
	}))
	defer srv.Close()

	parsed, err := gempki.LoadTSLDetachedSignature(t.Context(), srv.Client(), srv.URL+"/foo.sig")
	require.NoError(t, err)
	require.NoError(t, parsed.VerifyOver(sampleTSLBytes))
}

func TestLoadTSLDetachedSignature_Non200Rejected(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()
	_, err := gempki.LoadTSLDetachedSignature(t.Context(), srv.Client(), srv.URL+"/x.sig")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 404")
}

func TestLoadTSLDetachedSignature_HonorsContextCancellation(t *testing.T) {
	t.Parallel()
	hits := atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusGatewayTimeout)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := gempki.LoadTSLDetachedSignature(ctx, srv.Client(), srv.URL+"/x.sig")
		done <- err
	}()
	for hits.Load() == 0 && time.Now().Before(time.Now().Add(2*time.Second)) {
		time.Sleep(5 * time.Millisecond)
		if hits.Load() > 0 {
			break
		}
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
		t.Fatal("LoadTSLDetachedSignature did not unblock client-side within 1s after cancel")
	}
}

func TestLoadTSLDetachedSignature_HonorsCustomHTTPClient(t *testing.T) {
	t.Parallel()
	_, signer := signerNode(t)
	sigBytes := testtsl.SignTSL(t, sampleTSLBytes, signer)

	called := atomic.Int32{}
	custom := &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			called.Add(1)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytesReader(sigBytes)),
				Header:     make(http.Header),
				Request:    req,
			}, nil
		}),
	}
	parsed, err := gempki.LoadTSLDetachedSignature(t.Context(), custom, "https://example.invalid/x.sig")
	require.NoError(t, err)
	assert.Equal(t, int32(1), called.Load(), "custom RoundTripper must be the network surface")
	require.NoError(t, parsed.VerifyOver(sampleTSLBytes))
}

func TestTSLSignatureURL_ReplacesXmlWithSig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"https://example.com/foo.xml", "https://example.com/foo.sig"},
		{"https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.xml", "https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.sig"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, gempki.TSLSignatureURL(tc.in))
	}
}

// bytesReader is a tiny helper that wraps a byte slice as an io.Reader; we
// avoid pulling in bytes.NewReader at the top of the file to keep imports
// scoped to the cases that actually need them.
func bytesReader(b []byte) io.Reader {
	return &byteSliceReader{b: b}
}

type byteSliceReader struct {
	b []byte
}

func (r *byteSliceReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
