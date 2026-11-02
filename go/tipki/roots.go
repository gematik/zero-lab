// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package tipki

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// RootsEntry is one root of a roots.json with its cross certificates, still unverified.
type RootsEntry struct {
	Cert *x509.Certificate
	// CN is the entry's own cn field.
	CN   string
	prev []byte
	next []byte
}

// ParseRoots reads a roots.json in either form gematik ships: a bare array, or an object with the
// array under roots (ROOTS-001). Cross certificates are decoded only when the walk reaches them.
func ParseRoots(data []byte) ([]RootsEntry, error) {
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		var wrapped map[string]json.RawMessage
		if json.Unmarshal(data, &wrapped) != nil {
			return nil, fmt.Errorf("tipki: roots.json: %w", err)
		}
		list, ok := wrapped["roots"]
		if !ok || bytes.Equal(list, []byte("null")) {
			return nil, errors.New("tipki: roots.json: neither an array nor an object with roots")
		}
		if err := json.Unmarshal(list, &raw); err != nil {
			return nil, fmt.Errorf("tipki: roots.json: %w", err)
		}
	}
	if len(raw) == 0 {
		return nil, errors.New("tipki: roots.json is empty")
	}
	entries := make([]RootsEntry, len(raw))
	for i, fields := range raw {
		entry, err := parseRootsEntry(fields)
		if err != nil {
			return nil, fmt.Errorf("tipki: roots.json: entry %d: %w", i, err)
		}
		entries[i] = entry
	}
	return entries, nil
}

func parseRootsEntry(fields map[string]json.RawMessage) (RootsEntry, error) {
	var entry RootsEntry
	if fields == nil {
		return entry, errors.New("not an object")
	}
	rawCert, ok := fields["cert"]
	if !ok || bytes.Equal(rawCert, []byte("null")) {
		return entry, errors.New("no cert")
	}
	if rawCN, ok := fields["cn"]; ok {
		if bytes.Equal(rawCN, []byte("null")) {
			return entry, errors.New("cn: null")
		}
		if err := json.Unmarshal(rawCN, &entry.CN); err != nil {
			return entry, fmt.Errorf("cn: %w", err)
		}
	}
	var encoded string
	if err := json.Unmarshal(rawCert, &encoded); err != nil {
		return entry, fmt.Errorf("cert: %w", err)
	}
	der, err := strictBase64(encoded)
	if err != nil {
		return entry, fmt.Errorf("cert: %w", err)
	}
	if entry.Cert, err = ParseCertificate(der); err != nil {
		return entry, err
	}
	if entry.prev, err = crossField(fields, "prev"); err != nil {
		return entry, err
	}
	if entry.next, err = crossField(fields, "next"); err != nil {
		return entry, err
	}
	return entry, nil
}

func crossField(fields map[string]json.RawMessage, name string) ([]byte, error) {
	var encoded *string
	if value, ok := fields[name]; ok {
		if err := json.Unmarshal(value, &encoded); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
	}
	if encoded == nil || *encoded == "" {
		return nil, nil
	}
	der, err := strictBase64(*encoded)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return der, nil
}

func strictBase64(encoded string) ([]byte, error) {
	if strings.ContainsAny(encoded, "\r\n") {
		return nil, errors.New("not base64")
	}
	return base64.StdEncoding.Strict().DecodeString(encoded)
}

// Walk is the result of an A_28419 walk.
type Walk struct {
	// Trusted holds the anchor first, then its successors, then its predecessors.
	Trusted []*x509.Certificate
	// ForwardStop says why the walk towards newer roots stopped early; empty if it ran out of links.
	ForwardStop string
	// BackwardStop says the same for the walk towards older roots.
	BackwardStop string
}

// WalkRoots walks entries from anchor through their cross certificates and imports each root whose
// link passes all seven A_28419 checks at now (ROOTS-002). A link that fails ends that direction
// without failing the load, so a download can only add roots that chain to the anchor. It fails only
// if the anchor is not among the entries.
func WalkRoots(anchor *x509.Certificate, entries []RootsEntry, now time.Time) (Walk, error) {
	start := slices.IndexFunc(entries, func(entry RootsEntry) bool { return entry.Cert.Equal(anchor) })
	if start < 0 {
		return Walk{}, fmt.Errorf("tipki: trust anchor %q not present in roots.json", anchor.Subject.CommonName)
	}
	walk := Walk{Trusted: []*x509.Certificate{entries[start].Cert}}
	walk.ForwardStop = walkDirection(entries, start, func(e RootsEntry) []byte { return e.next }, &walk.Trusted, now)
	walk.BackwardStop = walkDirection(entries, start, func(e RootsEntry) []byte { return e.prev }, &walk.Trusted, now)
	return walk, nil
}

func walkDirection(entries []RootsEntry, start int, link func(RootsEntry) []byte, trusted *[]*x509.Certificate, now time.Time) string {
	current := start
	for {
		crossDER := link(entries[current])
		if crossDER == nil {
			return ""
		}
		from := entries[current].Cert.Subject.CommonName
		cross, err := ParseCertificate(crossDER)
		if err != nil {
			return fmt.Sprintf("cross certificate from %q does not parse: %v", from, err)
		}
		next := slices.IndexFunc(entries, func(entry RootsEntry) bool {
			return len(entry.Cert.SubjectKeyId) > 0 && bytes.Equal(entry.Cert.SubjectKeyId, cross.SubjectKeyId)
		})
		if next < 0 {
			return fmt.Sprintf("cross certificate from %q names a root not in roots.json", from)
		}
		candidate := entries[next].Cert
		if slices.ContainsFunc(*trusted, candidate.Equal) {
			return fmt.Sprintf("cross certificate from %q loops back to %q", from, candidate.Subject.CommonName)
		}
		if err := VerifyCrossSigned(entries[current].Cert, cross, candidate, now); err != nil {
			return fmt.Sprintf("%q not imported: %v", candidate.Subject.CommonName, err)
		}
		*trusted = append(*trusted, candidate)
		current = next
	}
}

// CrossCertError says which A_28419 check failed.
type CrossCertError struct {
	// Step is the failed step, 1 to 7, numbered as in gemSpec_PKI.
	Step   int
	Reason string
}

func (e *CrossCertError) Error() string {
	return fmt.Sprintf("A_28419 step %d: %s", e.Step, e.Reason)
}

// VerifyCrossSigned runs the seven A_28419 checks for importing subordinate as a new root on the
// strength of cross, a certificate for the subordinate's name and key issued by the trusted anchor
// (ROOTS-003). It returns the first that fails as a *[CrossCertError].
func VerifyCrossSigned(anchor, cross, subordinate *x509.Certificate, now time.Time) error {
	fail := func(step int, format string, args ...any) error {
		return &CrossCertError{Step: step, Reason: fmt.Sprintf(format, args...)}
	}
	name := cross.Subject.CommonName
	if err := verifyRootSignature(cross, anchor); err != nil {
		return fail(1, "cross %q is not signed by anchor %q: %v", name, anchor.Subject.CommonName, err)
	}
	if now.Unix() < cross.NotBefore.Unix() {
		return fail(2, "cross %q not yet valid (notBefore %s)", name, cross.NotBefore)
	}
	if now.Unix() > cross.NotAfter.Unix() {
		return fail(2, "cross %q expired (notAfter %s)", name, cross.NotAfter)
	}
	if !isRCAName(name) {
		return fail(3, "%q does not match GEM.RCA<n>", name)
	}
	if len(cross.SubjectKeyId) == 0 || !bytes.Equal(cross.SubjectKeyId, subordinate.SubjectKeyId) {
		return fail(4, "subject key identifier differs from the subordinate's")
	}
	if name != subordinate.Subject.CommonName {
		return fail(5, "common name %q differs from the subordinate's %q", name, subordinate.Subject.CommonName)
	}
	if !bytes.Equal(cross.RawSubjectPublicKeyInfo, subordinate.RawSubjectPublicKeyInfo) {
		return fail(6, "public key differs from the subordinate's")
	}
	if err := verifyRootSignature(subordinate, cross); err != nil {
		return fail(7, "subordinate %q does not verify under the cross certificate: %v", subordinate.Subject.CommonName, err)
	}
	return nil
}

func isRCAName(name string) bool {
	rest, ok := strings.CutPrefix(name, "GEM.RCA")
	return ok && rest != "" && rest[0] >= '0' && rest[0] <= '9'
}

// verifyRootSignature adds RSA to what a chain admits, for the walk alone. The TI's roots alternate
// between ECC and RSA, so the walk from the anchor cannot reach the ECC roots without passing RSA
// ones (GEM.RCA6, GEM.RCA9). Certificate chains stay ECDSA only (PATH-006).
func verifyRootSignature(cert, issuer *x509.Certificate) error {
	key, ok := issuer.PublicKey.(*rsa.PublicKey)
	if !ok {
		return verifySignedBy(cert, issuer)
	}
	if cert.SignatureAlgorithm != x509.SHA256WithRSA {
		return fmt.Errorf("signature algorithm %s is not admitted", cert.SignatureAlgorithm)
	}
	digest := sha256.Sum256(cert.RawTBSCertificate)
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], cert.Signature); err != nil {
		return errors.New("the signature does not verify")
	}
	return nil
}

// TrustedRoots gives the roots a bundle yields for anchorDER at now: the anchor and every root of its
// roots.json the walk reaches (ROOTS-004). The result says where the walk stopped, if it did.
func TrustedRoots(bundle *Bundle, anchorDER []byte, now time.Time) (Walk, error) {
	if err := bundle.CheckAnchor(anchorDER); err != nil {
		return Walk{}, err
	}
	anchor, err := ParseCertificate(anchorDER)
	if err != nil {
		return Walk{}, err
	}
	entries, err := ParseRoots(bundle.Roots)
	if err != nil {
		return Walk{}, err
	}
	return WalkRoots(anchor, entries, now)
}
