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

// Verification step sentinels. They are *not* user-facing — they exist so
// callers can `errors.Is(err, gempki.ErrCrossCertStep2)` to discriminate
// stale-cert warnings from hard failures during root-store updates.
var (
	ErrCrossCertStep1 = errors.New("gempki: cross-cert step 1 failed: signature does not chain to a known anchor")
	ErrCrossCertStep2 = errors.New("gempki: cross-cert step 2 failed: certificate validity period")
	ErrCrossCertStep3 = errors.New("gempki: cross-cert step 3 failed: CommonName does not match GEM.RCA<n>")
	ErrCrossCertStep4 = errors.New("gempki: cross-cert step 4 failed: SubjectKeyIdentifier mismatch")
	ErrCrossCertStep5 = errors.New("gempki: cross-cert step 5 failed: CommonName mismatch")
	ErrCrossCertStep6 = errors.New("gempki: cross-cert step 6 failed: public key mismatch")
	ErrCrossCertStep7 = errors.New("gempki: cross-cert step 7 failed: subordinate signature does not verify under cross cert")
)

var rcaCommonNameRE = regexp.MustCompile(`^GEM\.RCA\d+`)

// VerifyCrossSignedRoot runs the A_28419 seven-step check.
//
//   - anchor: an already-trusted root.
//   - cross:  the cross certificate (subject = subordinate's identity, signed by anchor).
//   - subordinate: the self-signed cert being imported as a new anchor.
//
// On success, the subordinate is safe to add to the trust store. On failure,
// the returned error wraps one of the ErrCrossCertStepN sentinels so callers
// can distinguish "skippable" outcomes (expired cross cert, step 2) from
// hard violations.
func VerifyCrossSignedRoot(anchor, cross, subordinate *x509.Certificate) error {
	return verifyCrossSignedAt(anchor, cross, subordinate, time.Now())
}

// verifyCrossSignedAt is the deterministic core (time injected) used by tests.
func verifyCrossSignedAt(anchor, cross, subordinate *x509.Certificate, now time.Time) error {
	// Step 1: cross is signed by a known trust anchor.
	if err := VerifyCertificateSignature(cross, anchor); err != nil {
		return fmt.Errorf("%w: cross %q under anchor %q: %w",
			ErrCrossCertStep1, cross.Subject.CommonName, anchor.Subject.CommonName, err)
	}

	// Step 2: cross is currently within its validity window.
	if now.Before(cross.NotBefore) {
		return fmt.Errorf("%w: cross %q not yet valid (notBefore=%s)",
			ErrCrossCertStep2, cross.Subject.CommonName, cross.NotBefore.Format(time.RFC3339))
	}
	if now.After(cross.NotAfter) {
		return fmt.Errorf("%w: cross %q expired (notAfter=%s)",
			ErrCrossCertStep2, cross.Subject.CommonName, cross.NotAfter.Format(time.RFC3339))
	}

	// Step 3: cross's subject CommonName matches GEM.RCA<digit>+.
	if !rcaCommonNameRE.MatchString(cross.Subject.CommonName) {
		return fmt.Errorf("%w: %q does not match GEM.RCA<n> pattern",
			ErrCrossCertStep3, cross.Subject.CommonName)
	}

	// Step 4: SKI of cross == SKI of subordinate.
	if !bytes.Equal(cross.SubjectKeyId, subordinate.SubjectKeyId) {
		return fmt.Errorf("%w: cross SKI=%x, subordinate SKI=%x",
			ErrCrossCertStep4, cross.SubjectKeyId, subordinate.SubjectKeyId)
	}

	// Step 5: CommonName of cross == CommonName of subordinate.
	if cross.Subject.CommonName != subordinate.Subject.CommonName {
		return fmt.Errorf("%w: cross CN=%q, subordinate CN=%q",
			ErrCrossCertStep5, cross.Subject.CommonName, subordinate.Subject.CommonName)
	}

	// Step 6: public key of cross == public key of subordinate.
	// The brainpool helper handles both NIST and Brainpool curves; standard
	// x509.MarshalPKIXPublicKey rejects Brainpool.
	crossPub, err := brainpool.MarshalPKIXPublicKey(cross.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: marshal cross public key: %w", ErrCrossCertStep6, err)
	}
	subPub, err := brainpool.MarshalPKIXPublicKey(subordinate.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: marshal subordinate public key: %w", ErrCrossCertStep6, err)
	}
	if !bytes.Equal(crossPub, subPub) {
		return fmt.Errorf("%w: cross/subordinate public key bytes differ", ErrCrossCertStep6)
	}

	// Step 7: subordinate's signature verifies under cross's public key.
	if err := VerifyCertificateSignature(subordinate, cross); err != nil {
		return fmt.Errorf("%w: subordinate %q under cross %q: %w",
			ErrCrossCertStep7, subordinate.Subject.CommonName, cross.Subject.CommonName, err)
	}

	return nil
}
