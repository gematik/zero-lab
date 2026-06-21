package gempki

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

// Loader produces a [TrustStore]. Implementations: [EmbeddedLoader],
// [FileLoader], [NetworkLoader], [CompositeLoader].
//
// A Loader's job is to source a list of root candidates and assemble them
// into a verified TrustStore via the A_28419 cross-cert rollover protocol.
// Verification is identical across all loaders — it lives in
// [verifyRootsList] below; only the *source* of bytes differs.
type Loader interface {
	Load(ctx context.Context) (*TrustStore, error)
}

// --- Embedded data ---------------------------------------------------------
//
// We embed the gematik-published roots.json files for each environment so
// callers can bootstrap without network access. The accompanying trust
// anchors are base64-encoded right here for the same reason. Both the JSON
// payloads and the anchors come from gematik's public distribution endpoints;
// treat them as TEST-ONLY for dev/ref/test.

//go:embed roots-test.json
var embeddedRootsTest []byte

//go:embed roots-dev-ref.json
var embeddedRootsDevRef []byte

//go:embed roots-prod.json
var embeddedRootsProd []byte

// Trust anchors — the GEM.RCA<n> root certificates whose authenticity callers
// must accept on faith. Every other root in the JSON payload chains back to
// one of these via A_28419 cross-signing.
const (
	trustAnchorTestB64   = "MIICyjCCAnKgAwIBAgIBATAKBggqhkjOPQQDAjCBgTELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxGzAZBgNVBAMMEkdFTS5SQ0E4IFRFU1QtT05MWTAeFw0yMzEyMDcxMDE3NTJaFw0zMzEyMDQxMDE3NTJaMIGBMQswCQYDVQQGEwJERTEfMB0GA1UECgwWZ2VtYXRpayBHbWJIIE5PVC1WQUxJRDE0MDIGA1UECwwrWmVudHJhbGUgUm9vdC1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEbMBkGA1UEAwwSR0VNLlJDQTggVEVTVC1PTkxZMFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABDLncr51uoi5aGXoctM3aIm/tjMRXGu+57M1TUjwsy2HhyjEBaMWqlGMBcmcGZhbcKt/lepwcDk3EvGRmDJWGQ2jgdcwgdQwHQYDVR0OBBYEFKG5FDonMHtcZx71MsSx1RqJ/LxTMEoGCCsGAQUFBwEBBD4wPDA6BggrBgEFBQcwAYYuaHR0cDovL29jc3AtdGVzdHJlZi5yb290LWNhLnRpLWRpZW5zdGUuZGUvb2NzcDAOBgNVHQ8BAf8EBAMCAQYwRgYDVR0gBD8wPTA7BggqghQATASBIzAvMC0GCCsGAQUFBwIBFiFodHRwOi8vd3d3LmdlbWF0aWsuZGUvZ28vcG9saWNpZXMwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNGADBDAh9GANMYXG7LtOY83ffXG0MB/Hb1cGPV5umiJgyOlkpVAiAL+e32oEH1N625yww+4lgFd0LBg9gcFLQ87rEdlyCq1Q=="
	trustAnchorDevRefB64 = "MIICzDCCAnGgAwIBAgIBATAKBggqhkjOPQQDAjCBgTELMAkGA1UEBhMCREUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxGzAZBgNVBAMMEkdFTS5SQ0E3IFRFU1QtT05MWTAeFw0yMzA1MjUxMjIxMzlaFw0zMzA1MjIxMjIxMzlaMIGBMQswCQYDVQQGEwJERTEfMB0GA1UECgwWZ2VtYXRpayBHbWJIIE5PVC1WQUxJRDE0MDIGA1UECwwrWmVudHJhbGUgUm9vdC1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEbMBkGA1UEAwwSR0VNLlJDQTcgVEVTVC1PTkxZMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEGv3lzIASzKQHW0YbxoaSIFUlGcgH8c/JEWOifqVVKkJUS81zG1ogcL6skAhGCtkksfdSJKiZnmnKeQ/yAgGZUaOB1zCB1DAdBgNVHQ4EFgQUsvAJPk0L4wgkgJY1bjo2MyvySxowSgYIKwYBBQUHAQEEPjA8MDoGCCsGAQUFBzABhi5odHRwOi8vb2NzcC10ZXN0cmVmLnJvb3QtY2EudGktZGllbnN0ZS5kZS9vY3NwMA4GA1UdDwEB/wQEAwIBBjBGBgNVHSAEPzA9MDsGCCqCFABMBIEjMC8wLQYIKwYBBQUHAgEWIWh0dHA6Ly93d3cuZ2VtYXRpay5kZS9nby9wb2xpY2llczAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCntB3Gck9DDlVADBZQCrT3RU3D9QS5k9bd3NKCexf9LQIhAIG2Qyu9HVlKnz8a8qdSJE6+TTejs15x7CLEvaLouXUk"
	trustAnchorProdB64   = "MIICmTCCAkCgAwIBAgIBATAKBggqhkjOPQQDAjBtMQswCQYDVQQGEwJERTEVMBMGA1UECgwMZ2VtYXRpayBHbWJIMTQwMgYDVQQLDCtaZW50cmFsZSBSb290LUNBIGRlciBUZWxlbWF0aWtpbmZyYXN0cnVrdHVyMREwDwYDVQQDDAhHRU0uUkNBODAeFw0yMzEyMTIwOTU3MTNaFw0zMzEyMDkwOTU3MTNaMG0xCzAJBgNVBAYTAkRFMRUwEwYDVQQKDAxnZW1hdGlrIEdtYkgxNDAyBgNVBAsMK1plbnRyYWxlIFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxETAPBgNVBAMMCEdFTS5SQ0E4MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABIwmqH0yFsDRE7IMfPIRk+Emh2U4ZFVjvFgmr0qSwdyVL32ZfNpLJGvUPhCYiedfMSkDBK+zToDBDU/lmSScDT6jgc8wgcwwHQYDVR0OBBYEFIucDNB6vgBoeq0yjWmPmYByx5ssMEIGCCsGAQUFBwEBBDYwNDAyBggrBgEFBQcwAYYmaHR0cDovL29jc3Aucm9vdC1jYS50aS1kaWVuc3RlLmRlL29jc3AwDgYDVR0PAQH/BAQDAgEGMEYGA1UdIAQ/MD0wOwYIKoIUAEwEgSMwLzAtBggrBgEFBQcCARYhaHR0cDovL3d3dy5nZW1hdGlrLmRlL2dvL3BvbGljaWVzMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgZMA4ldNbm42AaLy/iTkIRbOZ5StBjYbn+asOoN06eWcCIH8na29NzkvzPKwQ1UY4qaPdOCvibXlC07zbTfzLJzkx"
)

// Network endpoints published by gematik for live root JSON.
const (
	URLRootsTest   = "https://download-test.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json"
	URLRootsDevRef = "https://download-ref.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json"
	URLRootsProd   = "https://download.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json"
)

// trustAnchorCache memoises the parsed anchor per environment so we don't
// re-decode the base64 + ASN.1 on every loader call.
var trustAnchorCache sync.Map // map[Environment]*cachedAnchor

type cachedAnchor struct {
	once sync.Once
	cert *x509.Certificate
	err  error
}

// EmbeddedTrustAnchor returns the trust anchor certificate compiled into the
// binary for env. Used by [EmbeddedLoader] and [NetworkLoader]; exported so
// callers wiring a [FileLoader] can reuse the same anchors instead of
// shipping their own.
func EmbeddedTrustAnchor(env Environment) (*x509.Certificate, error) {
	v, _ := trustAnchorCache.LoadOrStore(env, &cachedAnchor{})
	ca := v.(*cachedAnchor)
	ca.once.Do(func() {
		b64, ok := trustAnchorB64For(env)
		if !ok {
			ca.err = fmt.Errorf("gempki: no embedded trust anchor for environment %q", env)
			return
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			ca.err = fmt.Errorf("gempki: decode trust anchor: %w", err)
			return
		}
		c, err := ParseCertificate(raw)
		if err != nil {
			ca.err = fmt.Errorf("gempki: parse trust anchor: %w", err)
			return
		}
		ca.cert = c
	})
	return ca.cert, ca.err
}

func trustAnchorB64For(env Environment) (string, bool) {
	switch env {
	case EnvTest:
		return trustAnchorTestB64, true
	case EnvDev, EnvRef:
		return trustAnchorDevRefB64, true
	case EnvProd:
		return trustAnchorProdB64, true
	}
	return "", false
}

func embeddedJSONFor(env Environment) ([]byte, bool) {
	switch env {
	case EnvTest:
		return embeddedRootsTest, true
	case EnvDev, EnvRef:
		return embeddedRootsDevRef, true
	case EnvProd:
		return embeddedRootsProd, true
	}
	return nil, false
}

// --- Loaders ---------------------------------------------------------------

// EmbeddedLoader produces a TrustStore from the compiled-in roots.json and
// trust anchor for the configured Environment.
type EmbeddedLoader struct {
	Env Environment
}

// Load implements [Loader].
func (l EmbeddedLoader) Load(_ context.Context) (*TrustStore, error) {
	anchor, err := EmbeddedTrustAnchor(l.Env)
	if err != nil {
		return nil, err
	}
	data, ok := embeddedJSONFor(l.Env)
	if !ok {
		return nil, fmt.Errorf("gempki: no embedded roots data for environment %q", l.Env)
	}
	return verifyRootsList(anchor, bytes.NewReader(data))
}

// FileLoader reads roots.json from disk. The trust anchor is supplied by the
// caller — this loader is intended for environments where the gematik anchor
// is delivered out-of-band.
type FileLoader struct {
	Path        string
	TrustAnchor *x509.Certificate
}

// Load implements [Loader].
func (l FileLoader) Load(_ context.Context) (*TrustStore, error) {
	if l.TrustAnchor == nil {
		return nil, errors.New("gempki: FileLoader requires a TrustAnchor")
	}
	f, err := os.Open(l.Path)
	if err != nil {
		return nil, fmt.Errorf("gempki: open roots file: %w", err)
	}
	defer f.Close()
	return verifyRootsList(l.TrustAnchor, f)
}

// NetworkLoader fetches roots.json from the gematik distribution endpoint
// for the configured Environment. HTTPClient is optional; nil falls back to
// a bounded default client — production callers should pass a configured client
// with appropriate timeouts.
type NetworkLoader struct {
	Env        Environment
	HTTPClient *http.Client
}

// Load implements [Loader].
func (l NetworkLoader) Load(ctx context.Context) (*TrustStore, error) {
	anchor, err := EmbeddedTrustAnchor(l.Env)
	if err != nil {
		return nil, err
	}
	url, ok := urlRootsFor(l.Env)
	if !ok {
		return nil, fmt.Errorf("gempki: no network endpoint for environment %q", l.Env)
	}
	client := l.HTTPClient
	if client == nil {
		client = defaultHTTPClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("gempki: build roots request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gempki: fetch roots: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gempki: fetch roots: HTTP %d from %s", resp.StatusCode, url)
	}
	return verifyRootsList(anchor, resp.Body)
}

func urlRootsFor(env Environment) (string, bool) {
	switch env {
	case EnvTest:
		return URLRootsTest, true
	case EnvDev, EnvRef:
		return URLRootsDevRef, true
	case EnvProd:
		return URLRootsProd, true
	}
	return "", false
}

// CompositeLoader tries each Loader in order and returns the first success.
// Use to fall back from network → embedded for offline resilience.
type CompositeLoader struct {
	Loaders []Loader
}

// Load implements [Loader].
func (l CompositeLoader) Load(ctx context.Context) (*TrustStore, error) {
	if len(l.Loaders) == 0 {
		return nil, errors.New("gempki: CompositeLoader has no Loaders")
	}
	errs := make([]error, 0, len(l.Loaders))
	for i, ld := range l.Loaders {
		ts, err := ld.Load(ctx)
		if err == nil {
			return ts, nil
		}
		errs = append(errs, fmt.Errorf("loader %d (%T): %w", i, ld, err))
	}
	return nil, errors.Join(errs...)
}

// --- A_28419 walk ----------------------------------------------------------

// rootsJSONEntry mirrors one entry in gematik's roots.json schema.
type rootsJSONEntry struct {
	CertRaw     []byte `json:"cert"`
	CommonName  string `json:"cn"`
	PrevCertRaw []byte `json:"prev,omitempty"`
	NextCertRaw []byte `json:"next,omitempty"`
}

// decodeRootsJSON accepts both schemas gematik ships:
//   - bare array:  [ {…}, {…} ]               (dev/ref/prod)
//   - wrapped:     { "roots": [ {…}, {…} ] }  (test)
func decodeRootsJSON(r io.Reader) ([]*rootsJSONEntry, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("gempki: read roots.json: %w", err)
	}
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, errors.New("gempki: empty roots payload")
	}
	switch trimmed[0] {
	case '[':
		var entries []*rootsJSONEntry
		if err := json.Unmarshal(raw, &entries); err != nil {
			return nil, fmt.Errorf("gempki: decode roots.json (array form): %w", err)
		}
		return entries, nil
	case '{':
		var wrapper struct {
			Roots []*rootsJSONEntry `json:"roots"`
		}
		if err := json.Unmarshal(raw, &wrapper); err != nil {
			return nil, fmt.Errorf("gempki: decode roots.json (object form): %w", err)
		}
		return wrapper.Roots, nil
	}
	return nil, fmt.Errorf("gempki: roots.json does not start with [ or { (got %q)", trimmed[0])
}

type parsedEntry struct {
	entry *rootsJSONEntry
	cert  *x509.Certificate
}

// verifyRootsList decodes roots.json and walks the A_28419 cross-cert chain
// starting at the supplied trust anchor — first forward via "next" links to
// pick up rollover successors, then backward via "prev" links to pick up the
// predecessors that are still within their validity window.
//
// Out-of-validity predecessors are dropped with a warning rather than failing
// the whole load; expired anchors are normal during the long tail of a
// rollover.
func verifyRootsList(anchor *x509.Certificate, r io.Reader) (*TrustStore, error) {
	entries, err := decodeRootsJSON(r)
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("gempki: roots.json is empty")
	}

	// Parse every entry's main cert. Both ECC and RSA root certs are accepted
	// — the historical GEM.RCA1/2/6 are RSA-keyed but still part of the TI
	// trust corpus; rejecting them would break chain validation for cards
	// issued under those eras.
	parsed := make([]parsedEntry, 0, len(entries))
	anchorIdx := -1
	for _, e := range entries {
		c, err := ParseCertificate(e.CertRaw)
		if err != nil {
			return nil, fmt.Errorf("gempki: parse root %q: %w", e.CommonName, err)
		}
		if c.Equal(anchor) {
			anchorIdx = len(parsed)
		}
		parsed = append(parsed, parsedEntry{entry: e, cert: c})
	}
	if anchorIdx == -1 {
		return nil, fmt.Errorf("gempki: trust anchor %q not present in roots.json", anchor.Subject.CommonName)
	}

	trusted := []*x509.Certificate{parsed[anchorIdx].cert}
	now := time.Now()

	// Forward and backward walks through "next" / "prev" cross-cert links.
	// Any verification failure terminates that walk direction with a Debug
	// log — the walker is best-effort, and older roots.json layouts have
	// non-traversable orientations (e.g. RCA8.prev signed by RCA6 instead of
	// by RCA8) that simply can't be followed but should not fail the load.
	cur := anchorIdx
	for len(parsed[cur].entry.NextCertRaw) > 0 {
		nextCross, err := ParseCertificate(parsed[cur].entry.NextCertRaw)
		if err != nil {
			slog.Debug("gempki: forward walk parse failed; stopping",
				"from", parsed[cur].cert.Subject.CommonName, "err", err)
			break
		}
		idx, ok := findBySKI(parsed, nextCross.SubjectKeyId)
		if !ok {
			slog.Debug("gempki: forward walk reached an entry not in roots.json; stopping",
				"ski", fmt.Sprintf("%x", nextCross.SubjectKeyId))
			break
		}
		if err := verifyCrossSignedAt(parsed[cur].cert, nextCross, parsed[idx].cert, now); err != nil {
			slog.Debug("gempki: forward cross-cert verification failed; stopping",
				"at", parsed[idx].cert.Subject.CommonName, "err", err)
			break
		}
		trusted = append(trusted, parsed[idx].cert)
		cur = idx
	}

	cur = anchorIdx
	for len(parsed[cur].entry.PrevCertRaw) > 0 {
		prevCross, err := ParseCertificate(parsed[cur].entry.PrevCertRaw)
		if err != nil {
			slog.Debug("gempki: backward walk parse failed; stopping",
				"from", parsed[cur].cert.Subject.CommonName, "err", err)
			break
		}
		idx, ok := findBySKI(parsed, prevCross.SubjectKeyId)
		if !ok {
			slog.Debug("gempki: backward walk reached an entry not in roots.json; stopping",
				"ski", fmt.Sprintf("%x", prevCross.SubjectKeyId))
			break
		}
		if err := verifyCrossSignedAt(parsed[cur].cert, prevCross, parsed[idx].cert, now); err != nil {
			slog.Debug("gempki: backward cross-cert verification failed; stopping",
				"at", parsed[idx].cert.Subject.CommonName, "err", err)
			break
		}
		trusted = append(trusted, parsed[idx].cert)
		cur = idx
	}

	return NewTrustStore(trusted)
}

func findBySKI(entries []parsedEntry, ski []byte) (int, bool) {
	for i, e := range entries {
		if bytes.Equal(e.cert.SubjectKeyId, ski) {
			return i, true
		}
	}
	return -1, false
}
