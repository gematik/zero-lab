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
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// DefaultMaxClockSkew is the skew tolerated in validity checks, as in ti-pki's configuration.
const DefaultMaxClockSkew = 37500 * time.Millisecond

// RSA2048AdmissibleUntil is the end of 2025, the "zulässig bis" of RSA-2048 in gemSpec_Krypt Tab_KRYPT_002.
var RSA2048AdmissibleUntil = time.Unix(1767225599, 0)

// KeyStatus is how gemSpec_Krypt judges a key.
type KeyStatus string

// The statuses.
const (
	KeyAdmissible    KeyStatus = "admissible"
	KeyPhasedOut     KeyStatus = "phased out"
	KeyNotAdmissible KeyStatus = "not admissible"
)

// ClassifyKey judges cert's key as of at, and describes it for messages.
func ClassifyKey(cert *x509.Certificate, at time.Time) (KeyStatus, string) {
	switch key := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		name := key.Curve.Params().Name
		if name == "brainpoolP256r1" || name == "P-256" {
			return KeyAdmissible, "ECDSA " + name
		}
		return KeyNotAdmissible, "ECDSA " + name
	case *rsa.PublicKey:
		bits := key.N.BitLen()
		description := fmt.Sprintf("RSA %d", bits)
		switch {
		case bits < 2048:
			return KeyNotAdmissible, description
		case bits < 3000 && at.Unix() > RSA2048AdmissibleUntil.Unix():
			return KeyPhasedOut, description
		}
		return KeyAdmissible, description
	case ed25519.PublicKey:
		return KeyNotAdmissible, "Ed25519"
	}
	return KeyNotAdmissible, cert.PublicKeyAlgorithm.String()
}

// ChainPosition is where a certificate sits in a chain, named as in ti-pki.
type ChainPosition string

// The positions.
const (
	PositionEndEntity ChainPosition = "end_entity"
	PositionSubCA     ChainPosition = "sub_ca"
	PositionRoot      ChainPosition = "root"
)

// CertResult is what was found about one certificate of a chain.
type CertResult struct {
	Subject  string
	Position ChainPosition
	// Revocation is nil if it was not asked: the root, or a run without revocation.
	Revocation *RevocationResult
}

// ValidationResult is the verdict on a certificate. Only Valid decides, and a warning never does.
type ValidationResult struct {
	Valid       bool
	Chain       []*x509.Certificate
	Errors      []Finding
	Warnings    []Finding
	CertResults []CertResult
}

// Validator is the whole of TUC_PKI_018 as ti-pki runs it, in its order: chain, path and the end entity's
// requirements, the type its profile accepts, key admissibility, CAs the verified list names, the types it
// lets the CA issue, a CA it revoked, revocation, and last the admission roles (A_30046 (4)).
type Validator struct {
	Store *TrustStore
	// Revocation decides what an outcome means; see [ApplyRevocation].
	Revocation RevocationMode
	// SkipSubCARevocation asks only about the end entity.
	SkipSubCARevocation bool
	// AllowExpired turns validity errors into warnings.
	AllowExpired bool
	// MaxClockSkew is the tolerance of validity checks.
	MaxClockSkew time.Duration
	// RequiredKeyUsage are bits that must all be set.
	RequiredKeyUsage x509.KeyUsage
	// AllowedExtKeyUsages are those of which one must be present.
	AllowedExtKeyUsages []x509.OID
	// RequiredPolicies must all be asserted.
	RequiredPolicies []x509.OID
	// RequiredRoleOIDs are those of which one must be in the admission extension.
	RequiredRoleOIDs []x509.OID
	// ExpectedFQDN is what a commonName naming a host must name.
	ExpectedFQDN string
	// CertType is the type validated for; empty means the one detected.
	CertType CertificateType
	// AcceptedTypes are the types a certificate may have, from its profile. One the certificate does not
	// show is an error, and so is showing none. Empty requires nothing.
	AcceptedTypes []CertificateType
}

// NewValidator requires nothing of the end entity beyond RFC 5280, and checks revocation strictly.
func NewValidator(store *TrustStore) *Validator {
	return &Validator{Store: store, Revocation: RevocationHardFail, MaxClockSkew: DefaultMaxClockSkew}
}

// WithTypeBaseline requires of the end entity what gemSpec_PKI requires of every certificate of type t.
func (v *Validator) WithTypeBaseline(t CertificateType) *Validator {
	spec := t.Spec()
	v.CertType, v.RequiredKeyUsage, v.AllowedExtKeyUsages = t, spec.KeyUsage, spec.ExtKeyUsage
	v.RequiredPolicies, v.RequiredRoleOIDs = spec.Policies, spec.RoleOIDs
	return v
}

// RevocationMode gives the mode under a configured one: the configuration's unless the profile is stricter. A
// profile can tighten what an operator configured but never loosen it, and disabled stays disabled.
func (p *Profile) RevocationMode(configured RevocationMode) RevocationMode {
	strictness := map[RevocationMode]int{RevocationDisabled: 0, RevocationSoftFail: 1, RevocationHardFail: 2}
	if configured == RevocationDisabled || strictness[configured] >= strictness[p.Revocation] {
		return configured
	}
	return p.Revocation
}

// Validator is a validator for certificates of type t: the type's baseline, the profile's roles on top, and
// [Profile.RevocationMode] under the configured mode.
func (p *Profile) Validator(store *TrustStore, t CertificateType, configured RevocationMode) *Validator {
	validator := NewValidator(store).WithTypeBaseline(t)
	validator.RequiredRoleOIDs = p.EffectiveRoleOIDs(t)
	validator.Revocation = p.RevocationMode(configured)
	validator.AcceptedTypes = p.AcceptsTypes
	return validator
}

func (v *Validator) endEntityChecks(cert *x509.Certificate) []Finding {
	var findings []Finding
	add := func(finding *Finding) {
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	add(checkPolicies(cert, v.RequiredPolicies))
	add(checkKeyUsage(cert, v.RequiredKeyUsage))
	add(checkExtKeyUsage(cert, v.AllowedExtKeyUsages))
	if v.ExpectedFQDN != "" {
		add(checkFQDN(cert, v.ExpectedFQDN))
	}
	return findings
}

// checkFQDN requires the domain name a commonName leads with to be expected, ignoring case and a trailing
// dot (A_30046 (5)). A commonName that starts with no domain name passes: this covers certificates naming a host.
func checkFQDN(cert *x509.Certificate, expected string) *Finding {
	expected = strings.ToLower(strings.TrimRight(expected, "."))
	named, ok := leadingFQDN(cert.Subject.CommonName)
	if !ok || strings.EqualFold(strings.TrimRight(named, "."), expected) {
		return nil
	}
	return &Finding{CodeFQDNMismatch, cert.Subject.CommonName, fmt.Sprintf("commonName names %s, expected %s", named, expected)}
}

// leadingFQDN is the domain name a commonName starts with: the first word, with at least two labels of letters,
// digits and hyphens, and a last label that is not all digits, which rules out IPv4 addresses.
func leadingFQDN(commonName string) (string, bool) {
	words := strings.Fields(commonName)
	if len(words) == 0 {
		return "", false
	}
	name := words[0]
	labels := strings.Split(strings.TrimRight(name, "."), ".")
	if len(labels) < 2 || len(name) > 254 {
		return "", false
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", false
		}
		for _, b := range []byte(label) {
			if (b < 'a' || b > 'z') && (b < 'A' || b > 'Z') && (b < '0' || b > '9') && b != '-' {
				return "", false
			}
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return "", false
	}
	return name, true
}

// Validate judges certs[0] as the end entity at now, with certs[1:] as candidate intermediates besides the
// store's. Every failure lands in the result; the error is only for no certificate at all. The address of a
// responder is in a certificate an attacker may have made, so it is asked only about a certificate that has
// passed everything else (VALID-004).
func (v *Validator) Validate(ctx context.Context, certs []*x509.Certificate, now time.Time, checker RevocationChecker) (*ValidationResult, error) {
	if len(certs) == 0 {
		return nil, errors.New("tipki: no certificate to validate")
	}
	leaf, candidates := certs[0], slices.Clone(certs[1:])
	var roots []*x509.Certificate
	if v.Store != nil {
		candidates = append(candidates, v.Store.Certificates()...)
		roots = v.Store.Roots
	}
	chain, err := BuildChain(leaf, candidates, roots)
	if err != nil {
		return incompleteResult(chain, err), nil
	}
	certType := v.CertType
	if certType == "" {
		certType, _ = DetectCertificateType(leaf)
	}
	path, err := ValidatePath(chain, PathOptions{
		Now: now, MaxClockSkew: v.MaxClockSkew, Model: ValidityModelFor(certType), EndEntityChecks: v.endEntityChecks,
	})
	if err != nil {
		return nil, err
	}
	result := &ValidationResult{Chain: chain, Errors: path.Errors, Warnings: path.Warnings}
	for i, cert := range chain {
		position := PositionSubCA
		switch i {
		case 0:
			position = PositionEndEntity
		case len(chain) - 1:
			position = PositionRoot
		}
		result.CertResults = append(result.CertResults, CertResult{Subject: cert.Subject.CommonName, Position: position})
	}
	if v.AllowExpired {
		downgradeValidityErrors(result)
	}
	v.checkAcceptedType(chain[0], result)
	checkEndEntityKey(chain[0], now, result)
	v.checkCAsListed(chain, result)
	v.checkTSLType(chain, certType, result)
	v.checkCARevokedInTSL(chain, result)
	if len(result.Errors) == 0 {
		v.checkRevocation(ctx, chain, now, checker, result)
	}
	result.Valid = len(result.Errors) == 0
	if result.Valid && len(v.RequiredRoleOIDs) > 0 {
		if message := missingRole(chain[0], v.RequiredRoleOIDs); message != "" {
			result.Errors = append(result.Errors, Finding{CodeRoleOIDMissing, chain[0].Subject.CommonName, message})
			result.Valid = false
		}
	}
	return result, nil
}

func incompleteResult(partial []*x509.Certificate, err error) *ValidationResult {
	result := &ValidationResult{Chain: partial}
	for i, cert := range partial {
		position := PositionSubCA
		if i == 0 {
			position = PositionEndEntity
		}
		result.CertResults = append(result.CertResults, CertResult{Subject: cert.Subject.CommonName, Position: position})
	}
	last := partial[len(partial)-1].Subject.CommonName
	result.Errors = []Finding{{CodeChainIncomplete, last, err.Error()}}
	return result
}

func downgradeValidityErrors(result *ValidationResult) {
	var rest []Finding
	for _, finding := range result.Errors {
		if finding.Code == CodeExpired || finding.Code == CodeNotYetValid {
			finding.Message += " (expired certificates allowed)"
			result.Warnings = append(result.Warnings, finding)
			continue
		}
		rest = append(rest, finding)
	}
	result.Errors = rest
}

// checkAcceptedType holds the certificate's own type to what its profile accepts. The caller's choice of
// profile says what is wanted; what the certificate shows decides (VALID-005).
func (v *Validator) checkAcceptedType(leaf *x509.Certificate, result *ValidationResult) {
	if len(v.AcceptedTypes) == 0 {
		return
	}
	detected, ok := DetectCertificateType(leaf)
	if ok && slices.Contains(v.AcceptedTypes, detected) {
		return
	}
	shown := "no detectable type"
	if ok {
		shown = "type " + string(detected)
	}
	result.Errors = append(result.Errors, Finding{CodeProfileTypeMismatch, leaf.Subject.CommonName, "the profile does not accept a certificate of " + shown})
}

// checkCAsListed requires, with a verified list, every CA of the chain to be one it names in accord, or revoked
// with a time, under a root: a CA supplied with the certificate gets no standing from its signature alone
// (TIP1-A_2059, VALID-006). Without a verified list there is nothing to check against.
func (v *Validator) checkCAsListed(chain []*x509.Certificate, result *ValidationResult) {
	if v.Store == nil || v.Store.CATypes == nil {
		return
	}
	for _, ca := range chain[1 : len(chain)-1] {
		if _, listed := v.Store.providerOf(ca); !listed {
			result.Errors = append(result.Errors, Finding{
				CodeCANotInTSL, ca.Subject.CommonName,
				fmt.Sprintf("the verified TSL does not name %q as a CA in use", ca.Subject.CommonName),
			})
		}
	}
}

// checkEndEntityKey holds the end entity's key to gemSpec_Krypt. Only the end entity: which CAs may sign is the
// store's business, and historical RSA roots must keep validating the chains under them.
func checkEndEntityKey(leaf *x509.Certificate, now time.Time, result *ValidationResult) {
	status, description := ClassifyKey(leaf, now)
	switch status {
	case KeyNotAdmissible:
		result.Errors = append(result.Errors, Finding{CodeKeyNotAdmissible, leaf.Subject.CommonName, "public key " + description + " is not admissible for a TI certificate"})
	case KeyPhasedOut:
		result.Warnings = append(result.Warnings, Finding{CodeKeyPhasedOut, leaf.Subject.CommonName, "public key " + description + " is past its gemSpec_Krypt admissibility date"})
	}
}

// checkTSLType is TUC_PKI_007 steps 7 to 9: the end entity's type must be among those its CA's entry in the
// verified list states. This is what makes a CA one for components, SMC-B, eGK or HBA, and one with no types stated may issue none
// (VALID-007). Without a verified list nothing is checked.
func (v *Validator) checkTSLType(chain []*x509.Certificate, certType CertificateType, result *ValidationResult) {
	if v.Store == nil || v.Store.CATypes == nil || certType == "" || certType == CertTslSig {
		return
	}
	leaf, issuer := chain[0], chain[1]
	types := v.Store.tslTypesOf(issuer)
	if !containsOID(types, certType.OID()) {
		result.Errors = append(result.Errors, Finding{
			CodeCertTypeCANotAuthorized, leaf.Subject.CommonName,
			fmt.Sprintf("the TSL does not list %s among the types %q may issue", certType, issuer.Subject.CommonName),
		})
	}
}

// checkCARevokedInTSL lets a CA the list revoked vouch for what it issued before (gemSpec_PKI Tab_PKI_271).
func (v *Validator) checkCARevokedInTSL(chain []*x509.Certificate, result *ValidationResult) {
	if v.Store == nil {
		return
	}
	leaf, issuer := chain[0], chain[1]
	revoked := v.Store.revokedSince(issuer)
	if revoked.IsZero() {
		return
	}
	if leaf.NotBefore.Unix() < revoked.Unix() {
		result.Warnings = append(result.Warnings, Finding{
			CodeIssuedBeforeCARevocation, leaf.Subject.CommonName,
			fmt.Sprintf("the TSL lists %q as revoked since %s; issued before", issuer.Subject.CommonName, revoked.UTC().Format(time.RFC3339)),
		})
		return
	}
	result.Errors = append(result.Errors, Finding{
		CodeCARevokedInTSL, leaf.Subject.CommonName,
		fmt.Sprintf("the TSL lists %q as revoked since %s, and the certificate was issued after", issuer.Subject.CommonName, revoked.UTC().Format(time.RFC3339)),
	})
}

func (v *Validator) checkRevocation(ctx context.Context, chain []*x509.Certificate, now time.Time, checker RevocationChecker, result *ValidationResult) {
	if v.Revocation == RevocationDisabled {
		return
	}
	links := len(chain) - 1
	if v.SkipSubCARevocation {
		links = 1
	}
	for i := range links {
		cert, issuer := chain[i], chain[i+1]
		var outcome *RevocationResult
		failure := error(errors.New("no revocation checker configured"))
		if checker != nil {
			outcome, failure = checker.Check(ctx, cert, issuer, v.Store)
		}
		if failure == nil {
			if outcome.Authorization != nil && outcome.Authorization.Kind == "same_tsp_delegate" {
				result.Warnings = append(result.Warnings, Finding{
					CodeOCSPResponderNotRFC6960, cert.Subject.CommonName,
					fmt.Sprintf("OCSP responder %q is not RFC 6960 conform: certified by %q, not by the issuing CA %q; accepted as a delegate of the same TSP %q",
						outcome.ResponderName, outcome.Authorization.CA, issuer.Subject.CommonName, outcome.Authorization.TSP),
				})
			}
			result.CertResults[i].Revocation = outcome
		}
		finding := ApplyRevocation(v.Revocation, cert.Subject.CommonName, outcome, failure, now)
		switch {
		case finding == nil:
		case finding.Warning:
			result.Warnings = append(result.Warnings, finding.Finding)
		default:
			result.Errors = append(result.Errors, finding.Finding)
		}
	}
}
