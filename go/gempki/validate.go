package gempki

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Validator is the entry point for TI-PKI certificate validation: fill in
// the fields, then call [Validator.Validate] per certificate. A [Profile]
// produces one already filled for its use case.
//
// A Validator is configured once and shared across goroutines; do not mutate
// it while Validate calls are in flight.
//
// Validate runs [BuildChain] (topology), [ValidatePath] (RFC 5280 §6 plus the
// end-entity checks below), the gemSpec_Krypt key check ([ClassifyKey]) and
// finally the revocation check, and folds the findings into one
// [ValidationResult].
type Validator struct {
	// TrustStore holds the roots a chain must end in. Required.
	TrustStore *TrustStore

	// TimeFunc is "now" for validity checks. Nil means time.Now; set it to
	// validate as of a signature time.
	TimeFunc func() time.Time

	// RevocationMode and Revocation together define the revocation policy.
	// The zero value is HardFail with no checker, which fails closed: every
	// certificate is rejected with ErrCodeOCSPUnavailable. Set
	// RevocationModeDisabled to skip revocation entirely.
	RevocationMode RevocationMode
	Revocation     RevocationChecker

	// End-entity requirements. A zero value imposes no constraint.
	RequiredKeyUsage    x509.KeyUsage           // every bit must be set
	AllowedExtKeyUsages []x509.ExtKeyUsage      // at least one must be present
	RequiredPolicies    []asn1.ObjectIdentifier // every OID must be asserted
	RequiredRoleOIDs    []asn1.ObjectIdentifier // at least one must be asserted in the admission extension
}

// Validate validates chain[0] as the end entity, using chain[1:] as
// candidate intermediates (from a TLS handshake or a JWS x5c header) and
// extending the chain up to a root in the [TrustStore].
//
// A non-nil error is returned only for shape problems — nil ctx, empty
// chain, no trust store, a checker that failed outside its contract. Every
// policy-level failure lands in result.Errors with result.Valid == false.
func (v *Validator) Validate(ctx context.Context, chain []*x509.Certificate) (*ValidationResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("gempki: Validate requires a non-nil context")
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("gempki: Validate requires a non-empty chain")
	}
	if v.TrustStore == nil {
		return nil, fmt.Errorf("gempki: Validate requires a TrustStore")
	}

	log := slog.Default().With("ee_cn", chain[0].Subject.CommonName)
	log.Debug("validation started")

	fullChain, err := BuildChain(chain[0], chain[1:], v.TrustStore)
	if err != nil {
		// The result carries what BuildChain actually walked before the dead
		// end — not the pile of candidate intermediates the caller passed in,
		// which for a TSL-fed caller is every CA gematik publishes. None of it
		// reached a root, so nothing is positioned as one.
		partial := fullChain
		if len(partial) == 0 {
			partial = chain[:1]
		}
		positions := make([]ChainPosition, len(partial))
		certResults := make([]CertResult, len(partial))
		for i, c := range partial {
			positions[i] = PositionSubCA
			if i == 0 {
				positions[i] = PositionEE
			}
			certResults[i] = CertResult{Subject: c.Subject.CommonName, Position: positions[i]}
		}
		verr, ok := errors.AsType[*ValidationError](err)
		if !ok {
			verr = &ValidationError{Code: ErrCodeChainIncomplete, Subject: chain[0].Subject.CommonName, Message: "chain construction failed", Cause: err}
		}
		log.Info("chain build failed", "err", err)
		return &ValidationResult{
			Valid:       false,
			Chain:       partial,
			Positions:   positions,
			CertResults: certResults,
			Errors:      []*ValidationError{verr},
		}, nil
	}

	result, err := ValidatePath(ctx, fullChain, ValidatePathOptions{
		TimeFunc: v.TimeFunc,
		EEChecks: v.eeChecks(),
	})
	if err != nil {
		return nil, fmt.Errorf("gempki: ValidatePath: %w", err)
	}

	v.checkKey(fullChain[0], result)

	if err := v.checkRevocation(ctx, fullChain, result); err != nil {
		return nil, err
	}

	log.Debug("validation finished",
		"valid", result.Valid,
		"errors", len(result.Errors),
		"warnings", len(result.Warnings))
	return result, nil
}

// eeChecks turns the configured requirements into the check pipeline
// [ValidatePath] runs against the end entity. Every check runs; each failure
// is its own entry in the result.
func (v *Validator) eeChecks() []CertificateCheck {
	var checks []CertificateCheck
	if len(v.RequiredPolicies) > 0 {
		checks = append(checks, CheckCertificatePolicies(v.RequiredPolicies...))
	}
	if len(v.RequiredRoleOIDs) > 0 {
		checks = append(checks, CheckRoleOID(v.RequiredRoleOIDs...))
	}
	if v.RequiredKeyUsage != 0 {
		checks = append(checks, CheckKeyUsage(v.RequiredKeyUsage))
	}
	if len(v.AllowedExtKeyUsages) > 0 {
		checks = append(checks, CheckHasAnyExtKeyUsage(v.AllowedExtKeyUsages...))
	}
	return checks
}

// checkKey holds the end-entity key to gemSpec_Krypt. Only the end entity:
// which CAs may sign is the TSL's and the trust store's business, and the
// historical RSA roots must keep validating chains issued under them.
func (v *Validator) checkKey(ee *x509.Certificate, result *ValidationResult) {
	now := time.Now
	if v.TimeFunc != nil {
		now = v.TimeFunc
	}
	status, desc := ClassifyKey(ee.PublicKey, now())
	switch status {
	case KeyNotAdmissible:
		result.Valid = false
		result.Errors = append(result.Errors, &ValidationError{
			Code:    ErrCodeKeyNotAdmissible,
			Subject: ee.Subject.CommonName,
			Message: "public key " + desc + " is not admissible for a TI certificate (gemSpec_Krypt)",
		})
	case KeyPhasedOut:
		result.Warnings = append(result.Warnings, &ValidationWarning{
			Code:    ErrCodeKeyPhasedOut,
			Subject: ee.Subject.CommonName,
			Message: "public key " + desc + " is past its gemSpec_Krypt admissibility date",
		})
	}
}

// checkRevocation runs the revocation check for the end entity and folds
// the outcome into result. Only the end entity is checked: in the TI a
// SubCA's standing is expressed by the TSL, not by OCSP, and the trust
// anchor has no issuer to ask.
func (v *Validator) checkRevocation(ctx context.Context, chain []*x509.Certificate, result *ValidationResult) error {
	if v.RevocationMode == RevocationModeDisabled {
		return nil
	}
	ee, cn := chain[0], chain[0].Subject.CommonName
	if v.Revocation == nil {
		result.add(&ValidationError{
			Code:    ErrCodeOCSPUnavailable,
			Subject: cn,
			Message: "no revocation checker configured (set RevocationModeDisabled to skip revocation)",
		})
		return nil
	}

	rev, err := v.Revocation.Check(ctx, ee, chain[1])
	if err != nil {
		var ve *ValidationError
		if !errors.As(err, &ve) {
			return fmt.Errorf("gempki: revocation check: %w", err)
		}
	}
	if rev != nil && len(result.CertResults) > 0 {
		result.CertResults[0].Revocation = rev
	}
	ve, vw := applyRevocation(v.RevocationMode, cn, rev, err)
	result.add(ve)
	if vw != nil {
		result.Warnings = append(result.Warnings, vw)
	}
	return nil
}

// ValidatePEM parses one or more PEM-encoded certificates and validates the
// resulting chain, first block as the end entity. Non-CERTIFICATE blocks are
// skipped.
func (v *Validator) ValidatePEM(ctx context.Context, pemBytes []byte) (*ValidationResult, error) {
	certs, err := ParsePEMCertificates(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("gempki: ValidatePEM parse: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("gempki: ValidatePEM found no CERTIFICATE blocks")
	}
	return v.Validate(ctx, certs)
}
