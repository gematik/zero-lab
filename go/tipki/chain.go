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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
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

// verifySignedBy verifies cert's signature under issuer's key, with ti-pki's algorithm set (PATH-006).
// crypto/x509's own check does not know brainpool.
func verifySignedBy(cert, issuer *x509.Certificate) error {
	return verifySignature(issuer.PublicKey, cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature)
}

// verifySignature is PATH-006 for any signed bytes: ECDSA with one hash per curve, RSA PKCS#1 v1.5 and
// RSA-PSS with SHA-256, SHA-384 or SHA-512.
func verifySignature(public any, algorithm x509.SignatureAlgorithm, message, signature []byte) error {
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		return verifyECDSA(key, algorithm, message, signature)
	case *rsa.PublicKey:
		return verifyRSA(key, algorithm, message, signature)
	}
	return fmt.Errorf("a key of type %T is not admitted", public)
}

func verifyECDSA(key *ecdsa.PublicKey, algorithm x509.SignatureAlgorithm, message, signature []byte) error {
	var want x509.SignatureAlgorithm
	switch key.Curve.Params().Name {
	case "P-256", "brainpoolP256r1":
		want = x509.ECDSAWithSHA256
	case "P-384", "brainpoolP384r1":
		want = x509.ECDSAWithSHA384
	default:
		return fmt.Errorf("curve %s is not admitted", key.Curve.Params().Name)
	}
	if algorithm != want {
		return fmt.Errorf("signature algorithm %s is not admitted on curve %s", algorithm, key.Curve.Params().Name)
	}
	var digest []byte
	if want == x509.ECDSAWithSHA256 {
		sum := sha256.Sum256(message)
		digest = sum[:]
	} else {
		sum := sha512.Sum384(message)
		digest = sum[:]
	}
	if !ecdsa.VerifyASN1(key, digest, signature) {
		return errors.New("the signature does not verify")
	}
	return nil
}

func verifyRSA(key *rsa.PublicKey, algorithm x509.SignatureAlgorithm, message, signature []byte) error {
	var hash crypto.Hash
	var pss bool
	switch algorithm {
	case x509.SHA256WithRSA:
		hash = crypto.SHA256
	case x509.SHA384WithRSA:
		hash = crypto.SHA384
	case x509.SHA512WithRSA:
		hash = crypto.SHA512
	case x509.SHA256WithRSAPSS:
		hash, pss = crypto.SHA256, true
	case x509.SHA384WithRSAPSS:
		hash, pss = crypto.SHA384, true
	case x509.SHA512WithRSAPSS:
		hash, pss = crypto.SHA512, true
	default:
		return fmt.Errorf("signature algorithm %s is not admitted", algorithm)
	}
	hasher := hash.New()
	hasher.Write(message)
	digest := hasher.Sum(nil)
	var err error
	if pss {
		err = rsa.VerifyPSS(key, hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: hash})
	} else {
		err = rsa.VerifyPKCS1v15(key, hash, digest, signature)
	}
	if err != nil {
		return errors.New("the signature does not verify")
	}
	return nil
}

// signatureAlgorithmFromID maps the DER contents of an AlgorithmIdentifier to the algorithm it names, byte
// for byte, as ti-pki's set compares them: an encoding of the parameters it does not know names nothing.
func signatureAlgorithmFromID(contents []byte) (x509.SignatureAlgorithm, bool) {
	for algorithm, known := range signatureAlgorithmIDs {
		if bytes.Equal(known, contents) {
			return algorithm, true
		}
	}
	return x509.UnknownSignatureAlgorithm, false
}

var signatureAlgorithmIDs = map[x509.SignatureAlgorithm][]byte{
	x509.ECDSAWithSHA256:  mustHex("06082a8648ce3d040302"),
	x509.ECDSAWithSHA384:  mustHex("06082a8648ce3d040303"),
	x509.SHA256WithRSA:    mustHex("06092a864886f70d01010b0500"),
	x509.SHA384WithRSA:    mustHex("06092a864886f70d01010c0500"),
	x509.SHA512WithRSA:    mustHex("06092a864886f70d01010d0500"),
	x509.SHA256WithRSAPSS: pssID("01", "20"),
	x509.SHA384WithRSAPSS: pssID("02", "30"),
	x509.SHA512WithRSAPSS: pssID("03", "40"),
}

func mustHex(text string) []byte {
	decoded, err := hex.DecodeString(text)
	if err != nil {
		panic(err)
	}
	return decoded
}

// pssID is RSASSA-PSS with one hash for the signature and MGF1, and a salt of the hash's length.
func pssID(hashArc, salt string) []byte {
	hashID := "300d0609608648016503040 2" + hashArc + "0500"
	hashID = strings.ReplaceAll(hashID, " ", "")
	return mustHex("06092a864886f70d01010a" + "3034" + "a00f" + hashID + "a11c" + "301a" + "06092a864886f70d010108" + hashID + "a203" + "0201" + salt)
}
