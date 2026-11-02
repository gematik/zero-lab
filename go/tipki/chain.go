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
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/gematik/zero-lab/go/tipki/oid"
)

// MaxChainLen is the most certificates a built chain may hold, which bounds what an adversarial
// set of intermediates can make the walk do.
const MaxChainLen = 5

// ErrChainIncomplete says no chain to a root was found.
var ErrChainIncomplete = errors.New("chain_incomplete")

// BuildChain walks issuer references from leaf through intermediates until it reaches one of roots
// and returns the chain leaf first, root last (PATH-001). It looks only at names and key
// identifiers: [ValidatePath] checks signatures and validity on the result. On failure it also returns
// the chain walked so far.
func BuildChain(leaf *x509.Certificate, intermediates, roots []*x509.Certificate) ([]*x509.Certificate, error) {
	chain := []*x509.Certificate{leaf}
	current := leaf
	for len(chain) < MaxChainLen {
		issuer, isRoot := findIssuer(current, intermediates, roots)
		if issuer == nil {
			return chain, fmt.Errorf("%w: no issuer found for %q", ErrChainIncomplete, current.Subject.CommonName)
		}
		if isRoot {
			return append(chain, issuer), nil
		}
		if slices.ContainsFunc(chain, issuer.Equal) {
			return chain, fmt.Errorf("%w: cycle at %q", ErrChainIncomplete, issuer.Subject.CommonName)
		}
		chain = append(chain, issuer)
		current = issuer
	}
	return chain, fmt.Errorf("%w: longer than %d certificates", ErrChainIncomplete, MaxChainLen)
}

func findIssuer(cert *x509.Certificate, intermediates, roots []*x509.Certificate) (*x509.Certificate, bool) {
	hasAKI := len(cert.AuthorityKeyId) > 0
	for _, root := range roots {
		// The key identifier where there is one, which stays precise across a rollover in which
		// two roots share a name. Only the first candidate counts, as in ti-pki.
		var candidate bool
		if hasAKI {
			candidate = slices.Equal(root.SubjectKeyId, cert.AuthorityKeyId)
		} else {
			candidate = root.Subject.CommonName == cert.Issuer.CommonName
		}
		if !candidate {
			continue
		}
		if namesMatch(cert, root) {
			return root, true
		}
		break
	}
	for _, candidate := range intermediates {
		if namesMatch(cert, candidate) && (!hasAKI || slices.Equal(candidate.SubjectKeyId, cert.AuthorityKeyId)) {
			return candidate, false
		}
	}
	return nil, false
}

// namesMatch compares in the string form, so names that differ only in string encoding still match.
func namesMatch(cert, candidate *x509.Certificate) bool {
	issuer, subject := cert.Issuer.String(), candidate.Subject.String()
	if issuer == "" || subject == "" {
		return cert.Issuer.CommonName == candidate.Subject.CommonName
	}
	return issuer == subject
}

// ValidityModel says when a CA's validity counts (gemKPT_PKI_TIP 2.4).
type ValidityModel int

const (
	// ValidityShell has every certificate of the chain valid at the reference time.
	ValidityShell ValidityModel = iota
	// ValidityCompromise has each CA valid when it issued the certificate below it; a CA expired
	// since is a warning.
	ValidityCompromise
)

// ValidityModelFor is the model gemKPT_PKI_TIP 2.4 assigns to a type.
func ValidityModelFor(t CertificateType) ValidityModel {
	switch t {
	case CertHpAut, CertHpEnc, CertHciAut, CertHciEnc, CertHciOsig:
		return ValidityCompromise
	}
	return ValidityShell
}

// PathOptions is what [ValidatePath] checks against.
type PathOptions struct {
	// Now is the instant validity is checked at.
	Now time.Time
	// MaxClockSkew is how far Now may lie outside a validity window before it counts.
	MaxClockSkew time.Duration
	Model        ValidityModel
}

// PathResult holds what [ValidatePath] found; a path is valid only without errors.
type PathResult struct {
	Errors   []Finding
	Warnings []Finding
}

// Valid says whether nothing was found against the path.
func (r PathResult) Valid() bool { return len(r.Errors) == 0 }

// The extensions processed here, the only ones a certificate may mark critical (RFC 5280 §4.2).
// Name and policy constraints are not implemented, so a CA marking them critical is refused
// rather than half-checked.
var processedExtensions = []string{
	"2.5.29.19", "2.5.29.15", extKeyUsageExtension, "2.5.29.32", "2.5.29.17", "2.5.29.35", "2.5.29.14",
	"1.3.6.1.5.5.7.1.1", oid.AdmissionExtension,
}

// ValidatePath checks a chain from [BuildChain] against RFC 5280 §6 (PATH-002 to PATH-006) and collects
// all findings. It does not check revocation or a certificate's profile. A chain of fewer than two
// certificates is an error, since it holds no root.
func ValidatePath(chain []*x509.Certificate, options PathOptions) (PathResult, error) {
	if len(chain) < 2 {
		return PathResult{}, fmt.Errorf("tipki: a chain needs an end entity and a root, got %d", len(chain))
	}
	var result PathResult
	for i, cert := range chain {
		if options.Model == ValidityCompromise && i > 0 {
			checkIssuerValidity(cert, chain[i-1], options, &result)
		} else if finding := checkValidity(cert, options.Now, options.MaxClockSkew); finding != nil {
			result.Errors = append(result.Errors, *finding)
		}
		if i+1 < len(chain) {
			for _, ext := range cert.Extensions {
				if ext.Critical && !slices.Contains(processedExtensions, ext.Id.String()) {
					result.Errors = append(result.Errors, Finding{"unrecognized_critical_extension", cert.Subject.CommonName,
						"critical extension " + oid.Format(ext.Id.String()) + " is not processed (RFC 5280 §4.2)"})
				}
			}
		}
		if i > 0 {
			if finding := checkCAConstraints(cert, i-1); finding != nil {
				result.Errors = append(result.Errors, *finding)
			}
		}
		if i+1 < len(chain) {
			if err := verifySignedBy(cert, chain[i+1]); err != nil {
				result.Errors = append(result.Errors, Finding{"signature_invalid", cert.Subject.CommonName,
					"chain signature verification failed: " + err.Error()})
			}
		}
	}
	return result, nil
}

func checkIssuerValidity(cert, below *x509.Certificate, options PathOptions, result *PathResult) {
	if finding := checkValidity(cert, below.NotBefore, options.MaxClockSkew); finding != nil {
		finding.Message += fmt.Sprintf(" when it issued %q (Kompromissmodell)", below.Subject.CommonName)
		result.Errors = append(result.Errors, *finding)
	} else if checkValidity(cert, options.Now, options.MaxClockSkew) != nil {
		result.Warnings = append(result.Warnings, Finding{"issued_before_ca_expiry", cert.Subject.CommonName,
			fmt.Sprintf("expired, but valid when it issued %q", below.Subject.CommonName)})
	}
}

func checkValidity(cert *x509.Certificate, now time.Time, skew time.Duration) *Finding {
	if now.Add(skew).Unix() < cert.NotBefore.Unix() {
		return &Finding{"not_yet_valid", cert.Subject.CommonName, fmt.Sprintf("notBefore=%s, now=%s", cert.NotBefore, now)}
	}
	if now.Add(-skew).Unix() > cert.NotAfter.Unix() {
		return &Finding{"expired", cert.Subject.CommonName, fmt.Sprintf("notAfter=%s, now=%s", cert.NotAfter, now)}
	}
	return nil
}

func checkCAConstraints(cert *x509.Certificate, intermediatesBelow int) *Finding {
	subject := cert.Subject.CommonName
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return &Finding{"chain_incomplete", subject, "non-root, non-EE certificate is not marked CA"}
	}
	hasKeyUsage := slices.ContainsFunc(cert.Extensions, func(ext pkix.Extension) bool { return ext.Id.String() == "2.5.29.15" })
	if hasKeyUsage && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return &Finding{"key_usage_mismatch", subject, "CA certificate missing KeyUsageCertSign"}
	}
	if (cert.MaxPathLen > 0 || cert.MaxPathLenZero) && intermediatesBelow > cert.MaxPathLen {
		return &Finding{"chain_incomplete", subject, fmt.Sprintf("PathLenConstraint exceeded: max=%d, below=%d", cert.MaxPathLen, intermediatesBelow)}
	}
	return nil
}

// verifySignedBy verifies cert's signature under issuer's key: ECDSA with SHA-256 or SHA-384, on the
// curves of the TI (PATH-006). crypto/x509's own check does not know brainpool.
func verifySignedBy(cert, issuer *x509.Certificate) error {
	key, ok := issuer.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("the issuer's key is not ECDSA")
	}
	if !slices.Contains(admissibleSigningCurves, key.Curve.Params().Name) {
		return fmt.Errorf("curve %s is not admitted", key.Curve.Params().Name)
	}
	var digest []byte
	switch cert.SignatureAlgorithm {
	case x509.ECDSAWithSHA256:
		sum := sha256.Sum256(cert.RawTBSCertificate)
		digest = sum[:]
	case x509.ECDSAWithSHA384:
		sum := sha512.Sum384(cert.RawTBSCertificate)
		digest = sum[:]
	default:
		return fmt.Errorf("signature algorithm %s is not admitted", cert.SignatureAlgorithm)
	}
	if !ecdsa.VerifyASN1(key, digest, cert.Signature) {
		return errors.New("the signature does not verify")
	}
	return nil
}

var admissibleSigningCurves = []string{"P-256", "P-384", "brainpoolP256r1", "brainpoolP384r1"}
