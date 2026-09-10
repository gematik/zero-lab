package gempki

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
)

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
