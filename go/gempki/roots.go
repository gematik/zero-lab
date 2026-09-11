package gempki

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
)

// EmbeddedRoots assembles env's trust store from the compiled-in roots.json,
// with no network access.
func EmbeddedRoots(env Environment) (*TrustStore, error) {
	d, err := dataFor(env)
	if err != nil {
		return nil, err
	}
	anchor, err := embeddedTrustAnchor(env)
	if err != nil {
		return nil, err
	}
	return verifyRootsList(anchor, bytes.NewReader(d.rootsJSON))
}

// FetchRoots downloads env's current roots.json through client and
// assembles the trust store from it. The anchor is still the compiled-in
// one — a download can only ever add roots that chain to it.
func FetchRoots(ctx context.Context, env Environment, client *http.Client) (*TrustStore, error) {
	if client == nil {
		return nil, errors.New("gempki: FetchRoots requires an HTTP client")
	}
	d, err := dataFor(env)
	if err != nil {
		return nil, err
	}
	anchor, err := embeddedTrustAnchor(env)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.rootsURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("gempki: build roots request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gempki: fetch roots: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gempki: fetch roots: HTTP %d from %s", resp.StatusCode, d.rootsURL)
	}
	return verifyRootsList(anchor, resp.Body)
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

// Cross-certified-root verification per gematik specification A_28419.
//
// The TI root rollover protocol distributes "cross certificates": a SEQUENCE
// of (anchor, subordinate) pairs in which the anchor (an existing trusted
// root) attests the subordinate's identity. Importing a subordinate as a new
// trust anchor requires seven checks.
//
// The English translations of the German step descriptions follow the spec
// wording closely so this file can be diffed against gemSpec_PKI directly.

// errCrossCert wraps every failed step; the message names the step so a
// debug log reads against gemSpec_PKI directly. The loader treats all steps
// alike — an unverifiable candidate is simply not imported.
var errCrossCert = errors.New("gempki: cross-certificate verification failed")

func crossCertStep(step int, what string, args ...any) error {
	return fmt.Errorf("%w: step %d (%s)", errCrossCert, step, fmt.Sprintf(what, args...))
}

var rcaCommonNameRE = regexp.MustCompile(`^GEM\.RCA\d+`)

// verifyCrossSignedAt runs the A_28419 seven-step check at a given instant.
//
//   - anchor: an already-trusted root.
//   - cross:  the cross certificate (subject = subordinate's identity, signed by anchor).
//   - subordinate: the self-signed cert being imported as a new anchor.
//
// On success the subordinate is safe to add to the trust store.
func verifyCrossSignedAt(anchor, cross, subordinate *x509.Certificate, now time.Time) error {
	// Step 1: cross is signed by a known trust anchor.
	if err := verifyCertificateSignature(cross, anchor); err != nil {
		return crossCertStep(1, "cross %q does not chain to anchor %q: %v", cross.Subject.CommonName, anchor.Subject.CommonName, err)
	}

	// Step 2: cross is currently within its validity window.
	if now.Before(cross.NotBefore) {
		return crossCertStep(2, "cross %q not yet valid (notBefore=%s)", cross.Subject.CommonName, cross.NotBefore.Format(time.RFC3339))
	}
	if now.After(cross.NotAfter) {
		return crossCertStep(2, "cross %q expired (notAfter=%s)", cross.Subject.CommonName, cross.NotAfter.Format(time.RFC3339))
	}

	// Step 3: cross's subject CommonName matches GEM.RCA<digit>+.
	if !rcaCommonNameRE.MatchString(cross.Subject.CommonName) {
		return crossCertStep(3, "%q does not match GEM.RCA<n>", cross.Subject.CommonName)
	}

	// Step 4: SKI of cross == SKI of subordinate.
	if !bytes.Equal(cross.SubjectKeyId, subordinate.SubjectKeyId) {
		return crossCertStep(4, "SubjectKeyIdentifier mismatch: cross %x, subordinate %x", cross.SubjectKeyId, subordinate.SubjectKeyId)
	}

	// Step 5: CommonName of cross == CommonName of subordinate.
	if cross.Subject.CommonName != subordinate.Subject.CommonName {
		return crossCertStep(5, "CommonName mismatch: cross %q, subordinate %q", cross.Subject.CommonName, subordinate.Subject.CommonName)
	}

	// Step 6: public key of cross == public key of subordinate.
	// The brainpool helper handles both NIST and Brainpool curves; standard
	// x509.MarshalPKIXPublicKey rejects Brainpool.
	crossPub, err := brainpool.MarshalPKIXPublicKey(cross.PublicKey)
	if err != nil {
		return crossCertStep(6, "marshal cross public key: %v", err)
	}
	subPub, err := brainpool.MarshalPKIXPublicKey(subordinate.PublicKey)
	if err != nil {
		return crossCertStep(6, "marshal subordinate public key: %v", err)
	}
	if !bytes.Equal(crossPub, subPub) {
		return crossCertStep(6, "public key mismatch between cross and subordinate")
	}

	// Step 7: subordinate's signature verifies under cross's public key.
	if err := verifyCertificateSignature(subordinate, cross); err != nil {
		return crossCertStep(7, "subordinate %q does not verify under cross %q: %v", subordinate.Subject.CommonName, cross.Subject.CommonName, err)
	}

	return nil
}
