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

package titls

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
)

// MaxValidity is TLSV-045's cap: the CA/Browser Forum's longest validity period.
const MaxValidity = 398 * 24 * time.Hour

// MaxStatusReuse is how long the web profile reuses a revocation status at most (TLSV-051).
const MaxStatusReuse = 24 * time.Hour

var oidKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 15}

// WebCheck is spec/pki-validation's web profile over one set of roots: a server on the internet, verified
// against the host system's roots with the requirements gematik and the ZETA SDK add (TLSV-040 to 045). It
// holds no mutable state and may be used concurrently.
type WebCheck struct {
	roots *x509.CertPool
}

// NewWebCheck is the check over roots and only those. A test passes its own root here in place of the
// system's (TLSV-040).
func NewWebCheck(roots []*x509.Certificate) *WebCheck {
	pool := x509.NewCertPool()
	for _, root := range roots {
		pool.AddCert(root)
	}
	return &WebCheck{roots: pool}
}

// SystemWebCheck is the check over the host system's default roots, as crypto/x509 reads them
// (TLSV-040); in a container, the distribution's bundle.
func SystemWebCheck() (*WebCheck, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("titls: system roots: %w", err)
	}
	return &WebCheck{roots: pool}, nil
}

// Verify judges the server that presented chain (DER, end entity first) for a connection to host, at now,
// with the OCSP response it stapled, nil if none; fetch reaches its responder and CRL host, asked only about
// a server that passed everything else.
//
// crypto/x509 may build several paths. TLSV-023 and TLSV-042 depend on the path, the other rules on the end
// entity alone: the first path without a weak signature and whose CAs' keys are admissible is taken, and
// its first CA below the anchor is the issuer revocation asks about. When no path qualifies, the first
// path's finding is the result.
func (c *WebCheck) Verify(ctx context.Context, chain [][]byte, host string, stapled []byte, now time.Time, fetch Fetcher) Verdict {
	if len(chain) == 0 {
		return refuse(ChainIncomplete, "the server sent no certificate")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return refuse(Invalid, "the end entity does not parse: "+err.Error())
	}
	intermediates := x509.NewCertPool()
	var sent []*x509.Certificate
	for _, der := range chain[1:] {
		// TLSV-020: a certificate the path does not need is ignored, one that does not parse too.
		if cert, err := x509.ParseCertificate(der); err == nil {
			intermediates.AddCert(cert)
			sent = append(sent, cert)
		}
	}
	paths, err := leaf.Verify(x509.VerifyOptions{
		Roots:         c.roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		return pathRefusal(err, leaf, sent, c.roots, now)
	}
	firstWeak := weakIn(paths[0])
	paths = slices.DeleteFunc(paths, func(path []*x509.Certificate) bool { return weakIn(path) != "" })
	if len(paths) == 0 {
		return refuse(SignatureAlgorithmNotAllowed, firstWeak)
	}
	if !signs(leaf) {
		return refuse(KeyUsageMismatch, "keyUsage without digitalSignature")
	}
	key := keyOf(leaf)
	if !key.admissibleEndEntity() {
		return refuse(KeyNotAdmissible, "end entity key "+key.String())
	}
	index := slices.IndexFunc(paths, func(path []*x509.Certificate) bool { return inadmissibleCA(path) == nil })
	if index < 0 {
		ca := inadmissibleCA(paths[0])
		return refuse(KeyNotAdmissible, fmt.Sprintf("CA %q key %s", ca.Subject.CommonName, keyOf(ca)))
	}
	path := paths[index]
	if !namesHost(leaf, host) {
		return refuse(NameMismatch, host+" is not a dNSName or iPAddress of the certificate")
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > MaxValidity {
		return refuse(ValidityTooLong, "valid for more than 398 days")
	}
	if len(path) < 2 {
		return refuse(Invalid, "the end entity is itself an anchor; no issuer vouches for its status")
	}
	verdict := revocation(ctx, leaf, path[1], stapled, now, fetch)
	if key.phasedOut() {
		verdict.Warnings = append([]string{WarningKeyPhasedOut}, verdict.Warnings...)
	}
	return verdict
}

// weakIn names the first weak signature below the anchor of path.
func weakIn(path []*x509.Certificate) string {
	for _, cert := range path[:len(path)-1] {
		if name, weak := tipki.WeakSignature(cert); weak {
			return fmt.Sprintf("%q is signed with %s", cert.Subject.CommonName, name)
		}
	}
	return ""
}

// inadmissibleCA is the first CA between the end entity and the anchor whose key TLSV-042 does not admit.
func inadmissibleCA(path []*x509.Certificate) *x509.Certificate {
	if len(path) < 3 {
		return nil
	}
	for _, ca := range path[1 : len(path)-1] {
		if !keyOf(ca).admissibleCA() {
			return ca
		}
	}
	return nil
}

// pathRefusal names what kept crypto/x509 from building a path. An unknown authority hides why each
// candidate failed, so the presented certificates are walked by name from the end entity to find it.
// A weak signature on the way decides only once the walk reaches an anchor (TLSV-020 before TLSV-023);
// crypto/x509 refuses the weak link itself, so the anchor is asked of the first certificate above it.
func pathRefusal(err error, leaf *x509.Certificate, sent []*x509.Certificate, roots *x509.CertPool, now time.Time) Verdict {
	if invalid, ok := errors.AsType[x509.CertificateInvalidError](err); ok {
		switch invalid.Reason {
		case x509.Expired:
			return validityRefusal(invalid.Cert, now, err)
		case x509.IncompatibleUsage:
			return refuse(KeyUsageMismatch, err.Error())
		}
		return refuse(Invalid, err.Error())
	}
	if _, ok := errors.AsType[x509.UnhandledCriticalExtension](err); ok {
		return refuse(UnrecognizedCriticalExtension, err.Error())
	}
	if _, ok := errors.AsType[x509.UnknownAuthorityError](err); !ok {
		return refuse(Invalid, err.Error())
	}
	visited := []*x509.Certificate{leaf}
	weakLink := ""
	for cert := leaf; ; {
		name, weak := tipki.WeakSignature(cert)
		if weak && weakLink == "" {
			weakLink = fmt.Sprintf("%q is signed with %s", cert.Subject.CommonName, name)
		}
		index := slices.IndexFunc(sent, func(candidate *x509.Certificate) bool {
			return string(candidate.RawSubject) == string(cert.RawIssuer) && !slices.Contains(visited, candidate)
		})
		if index < 0 {
			if weakLink != "" && !weak && reachesAnchor(cert, roots, now) {
				return refuse(SignatureAlgorithmNotAllowed, weakLink)
			}
			return refuse(ChainIncomplete, err.Error())
		}
		parent := sent[index]
		if weak {
			visited = append(visited, parent)
			cert = parent
			continue
		}
		if signatureErr := cert.CheckSignatureFrom(parent); signatureErr != nil {
			switch {
			case errors.Is(signatureErr, x509.ErrUnsupportedAlgorithm):
				return refuse(SignatureAlgorithmNotAllowed, signatureErr.Error())
			case !keyOf(parent).admissibleCA():
				return refuse(KeyNotAdmissible, fmt.Sprintf("CA %q key %s", parent.Subject.CommonName, keyOf(parent)))
			}
			if _, insecure := errors.AsType[x509.InsecureAlgorithmError](signatureErr); insecure {
				return refuse(SignatureAlgorithmNotAllowed, signatureErr.Error())
			}
			if _, constraint := errors.AsType[x509.ConstraintViolationError](signatureErr); constraint {
				return refuse(Invalid, signatureErr.Error())
			}
			return refuse(SignatureInvalid, signatureErr.Error())
		}
		if now.Before(parent.NotBefore) || now.After(parent.NotAfter) {
			return validityRefusal(parent, now, err)
		}
		visited = append(visited, parent)
		cert = parent
	}
}

// reachesAnchor reports whether crypto/x509 builds a path from cert to one of roots.
func reachesAnchor(cert *x509.Certificate, roots *x509.CertPool, now time.Time) bool {
	_, err := cert.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err == nil
}

func validityRefusal(cert *x509.Certificate, now time.Time, err error) Verdict {
	if cert != nil && now.Before(cert.NotBefore) {
		return refuse(NotYetValid, err.Error())
	}
	return refuse(Expired, err.Error())
}

// signs is TLSV-022's key usage, where present, with digitalSignature.
func signs(cert *x509.Certificate) bool {
	present := slices.ContainsFunc(cert.Extensions, func(ext pkix.Extension) bool { return ext.Id.Equal(oidKeyUsage) })
	return !present || cert.KeyUsage&x509.KeyUsageDigitalSignature != 0
}

// namesHost is TLSV-043: a dNSName as TLSV-024 compares it, the commonName unread; an IP address only an
// iPAddress of the same bytes.
func namesHost(cert *x509.Certificate, host string) bool {
	host = strings.TrimSuffix(host, ".")
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return false
		}
		return slices.ContainsFunc(cert.IPAddresses, func(named net.IP) bool {
			addr, ok := netip.AddrFromSlice(named)
			return ok && addr == ip
		})
	}
	return slices.ContainsFunc(cert.DNSNames, func(presented string) bool { return tipki.DNSNameMatches(presented, host) })
}

// key is a public key as the web profile judges it: an ECDSA curve by name, or an RSA modulus by length.
type key struct {
	curve string
	bits  int
}

func keyOf(cert *x509.Certificate) key {
	switch public := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		return key{curve: public.Params().Name}
	case *rsa.PublicKey:
		return key{bits: public.N.BitLen()}
	}
	return key{}
}

func (k key) nistCurve() bool { return k.curve == "P-256" || k.curve == "P-384" }

// admissibleEndEntity is TLSV-041: what an end entity may have, RSA from 2048 bits.
func (k key) admissibleEndEntity() bool { return k.nistCurve() || k.bits >= 2048 }

// phasedOut is TLSV-041: an RSA key below A_28976's 3000 bits, admitted with [WarningKeyPhasedOut].
func (k key) phasedOut() bool { return k.bits > 0 && k.bits < 3000 }

// admissibleCA is TLSV-042.
func (k key) admissibleCA() bool { return k.nistCurve() || k.bits >= 2048 }

func (k key) String() string {
	switch {
	case k.curve != "":
		return "ECDSA " + k.curve
	case k.bits > 0:
		return fmt.Sprintf("RSA %d", k.bits)
	}
	return "of a type not admitted"
}

// revocation is TLSV-044: the stapled OCSP response, the responder, the CRL, in that order; the first
// status decides, and without one the server is accepted with [WarningRevocationUnavailable].
func revocation(ctx context.Context, leaf, issuer *x509.Certificate, stapled []byte, now time.Time, fetch Fetcher) Verdict {
	ocsp := func(der []byte) (Verdict, bool) {
		check := tipki.NewResponseCheck(now)
		check.Stapled, check.AllowMissingCertHash = true, true
		status, err := tipki.VerifyResponse(der, leaf, issuer, check)
		if err != nil {
			return Verdict{}, false
		}
		switch status.Status {
		case tipki.RevocationGood:
			return accepted(leaf, now, status.NextUpdate), true
		case tipki.RevocationRevoked:
			return refuse(Revoked, "revoked (OCSP)"), true
		}
		return Verdict{}, false
	}
	if len(stapled) > 0 {
		if verdict, ok := ocsp(stapled); ok {
			return verdict
		}
	}
	if fetch == nil {
		fetch = Offline{}
	}
	if request, err := tipki.OCSPRequest(leaf, issuer); err == nil {
		for _, url := range leaf.OCSPServer {
			if der, err := fetch.OCSP(ctx, url, request); err == nil {
				if verdict, ok := ocsp(der); ok {
					return verdict
				}
			}
		}
	}
	for _, url := range leaf.CRLDistributionPoints {
		der, err := fetch.CRL(ctx, url)
		if err != nil {
			continue
		}
		if revoked, nextUpdate, ok := crlStatus(der, url, leaf, issuer, now); ok {
			if revoked {
				return refuse(Revoked, "revoked (CRL)")
			}
			return accepted(leaf, now, nextUpdate)
		}
	}
	// TLSV-044's deviation: accepted without a status. It rests on none, so it is not reused (TLSV-050)
	// and the next connection asks the sources again.
	return Verdict{
		Code:     Valid,
		Detail:   "valid without a revocation status: no source gave one",
		Warnings: []string{WarningRevocationUnavailable},
	}
}

// accepted is a valid verdict, reusable until the earliest of notAfter, the status's nextUpdate and
// MaxStatusReuse from now (TLSV-050, TLSV-051).
func accepted(leaf *x509.Certificate, now time.Time, nextUpdate time.Time) Verdict {
	until := now.Add(MaxStatusReuse)
	if leaf.NotAfter.Before(until) {
		until = leaf.NotAfter
	}
	if !nextUpdate.IsZero() && nextUpdate.Before(until) {
		until = nextUpdate
	}
	return Verdict{Code: Valid, Detail: "valid", ReusableUntil: until}
}
