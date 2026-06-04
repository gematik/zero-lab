package gempki

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"log/slog"
	"time"
)

// Validator is the central public entry point for TI-PKI certificate
// validation. Construct one via [NewValidator] with [Option]s, or via a
// [Profile] factory; call [Validator.Validate] (or one of its byte-slice
// siblings) per request.
//
// A Validator is intended to be configured once at process start and shared
// across goroutines. Once constructed it should be treated as immutable —
// mutating fields concurrently with active Validate calls is undefined.
// The exception is hot-swapping the trust store via [TrustStoreHolder],
// which is the dedicated dynamic-reload path.
//
// Layered design — Validator orchestrates the building blocks established
// in earlier phases:
//   - [BuildChain]  / [ValidatePath]  — chain construction + RFC 5280 §6
//   - [EvaluateChain]                 — revocation policy
//   - [CheckRoleOID] / [CheckCertificatePolicies] / [CheckKeyUsage] /
//     [CheckHasAnyExtKeyUsage]        — per-tier predicates
//
// The Validator's job is to wire these together according to the caller's
// policy and fold the results into a single [ValidationResult].
type Validator struct {
	// Trust anchors. Exactly one of TrustStore / TrustStoreHolder is used;
	// when both are set the Holder wins (it represents the dynamic source).
	TrustStore       *TrustStore
	TrustStoreHolder *TrustStoreHolder

	// Chain-building knobs.
	MaxChainLen int              // 0 → DefaultMaxChainLen
	TimeFunc    func() time.Time // nil → time.Now

	// Revocation policy. A zero-value RevocationPolicy means Mode=HardFail
	// with no checkers, which fails closed — use [WithRevocationMode] +
	// [WithRevocationChecker] to wire it up, or [WithRevocationPolicy] for a
	// pre-built one. Mode=Disabled short-circuits the subsystem entirely.
	Revocation RevocationPolicy

	// EE constraint pipeline. Empty fields = no constraint.
	RequiredPolicies    []asn1.ObjectIdentifier
	RequiredRoleOIDs    []asn1.ObjectIdentifier
	RoleOIDExtractor    RoleOIDExtractorFunc
	RequiredKeyUsage    x509.KeyUsage
	AllowedExtKeyUsages []x509.ExtKeyUsage

	// Per-tier custom checks, appended after the built-in pipeline.
	EEChecks    []CertificateCheck
	SubCAChecks []CertificateCheck
	RootChecks  []CertificateCheck

	// Observability.
	Hooks  *ValidationHooks
	Logger *slog.Logger
}

// NewValidator constructs a Validator from Option functions.
func NewValidator(opts ...Option) *Validator {
	v := &Validator{}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Option configures a [Validator] during construction.
type Option func(*Validator)

// WithTrustStore installs ts as the static trust anchor source.
func WithTrustStore(ts *TrustStore) Option { return func(v *Validator) { v.TrustStore = ts } }

// WithTrustStoreHolder installs h as the dynamic trust anchor source.
// When both WithTrustStore and WithTrustStoreHolder are used, the Holder wins.
func WithTrustStoreHolder(h *TrustStoreHolder) Option {
	return func(v *Validator) { v.TrustStoreHolder = h }
}

// WithMaxChainLen overrides the chain-length bound (default
// [DefaultMaxChainLen] from chain.go).
func WithMaxChainLen(n int) Option { return func(v *Validator) { v.MaxChainLen = n } }

// WithTimeFunc overrides the time source used for validity checks.
func WithTimeFunc(f func() time.Time) Option { return func(v *Validator) { v.TimeFunc = f } }

// WithRevocationPolicy installs the full RevocationPolicy at once.
func WithRevocationPolicy(p RevocationPolicy) Option {
	return func(v *Validator) { v.Revocation = p }
}

// WithRevocationMode sets the revocation mode without disturbing other
// policy fields. Use after [WithRevocationChecker] / [WithCache] when
// composing piecewise.
func WithRevocationMode(m RevocationMode) Option {
	return func(v *Validator) { v.Revocation.Mode = m }
}

// WithRevocationChecker appends a [RevocationChecker] to the policy.
func WithRevocationChecker(c RevocationChecker) Option {
	return func(v *Validator) {
		v.Revocation.Checkers = append(v.Revocation.Checkers, c)
	}
}

// WithCache installs a [RevocationCache] on the policy.
func WithCache(c RevocationCache) Option {
	return func(v *Validator) { v.Revocation.Cache = c }
}

// WithCheckSubCAs toggles per-SubCA revocation checking. Default off.
func WithCheckSubCAs(b bool) Option {
	return func(v *Validator) { v.Revocation.CheckSubCAs = b }
}

// WithRequiredPolicies adds required CertificatePolicy OIDs to the EE pipeline.
func WithRequiredPolicies(oids ...asn1.ObjectIdentifier) Option {
	return func(v *Validator) {
		v.RequiredPolicies = append(v.RequiredPolicies, oids...)
	}
}

// WithRequiredRoleOIDs adds allowed role OIDs to the EE pipeline. The EE
// must assert at least one of them in its Admission extension.
func WithRequiredRoleOIDs(oids ...asn1.ObjectIdentifier) Option {
	return func(v *Validator) {
		v.RequiredRoleOIDs = append(v.RequiredRoleOIDs, oids...)
	}
}

// WithRoleOIDExtractor overrides the default Admission-extension extractor.
func WithRoleOIDExtractor(fn RoleOIDExtractorFunc) Option {
	return func(v *Validator) { v.RoleOIDExtractor = fn }
}

// WithRequiredKeyUsage requires every bit in ku to be set on the EE's KeyUsage.
func WithRequiredKeyUsage(ku x509.KeyUsage) Option {
	return func(v *Validator) { v.RequiredKeyUsage |= ku }
}

// WithAllowedExtKeyUsages requires the EE to assert at least one of the
// given ExtKeyUsages.
func WithAllowedExtKeyUsages(ekus ...x509.ExtKeyUsage) Option {
	return func(v *Validator) {
		v.AllowedExtKeyUsages = append(v.AllowedExtKeyUsages, ekus...)
	}
}

// WithEEChecks appends custom CertificateChecks for the end-entity tier.
func WithEEChecks(checks ...CertificateCheck) Option {
	return func(v *Validator) { v.EEChecks = append(v.EEChecks, checks...) }
}

// WithSubCAChecks appends custom CertificateChecks for SubCA tier.
func WithSubCAChecks(checks ...CertificateCheck) Option {
	return func(v *Validator) { v.SubCAChecks = append(v.SubCAChecks, checks...) }
}

// WithRootChecks appends custom CertificateChecks for root tier.
func WithRootChecks(checks ...CertificateCheck) Option {
	return func(v *Validator) { v.RootChecks = append(v.RootChecks, checks...) }
}

// WithHooks installs observation hooks.
func WithHooks(h *ValidationHooks) Option { return func(v *Validator) { v.Hooks = h } }

// WithLogger installs a structured logger; nil falls back to [slog.Default].
func WithLogger(l *slog.Logger) Option { return func(v *Validator) { v.Logger = l } }

// activeTrustStore returns the trust store the Validator should use right
// now: Holder if set, otherwise the static TrustStore field.
func (v *Validator) activeTrustStore() *TrustStore {
	if v.TrustStoreHolder != nil {
		return v.TrustStoreHolder.Current()
	}
	return v.TrustStore
}

func (v *Validator) logger() *slog.Logger {
	if v.Logger != nil {
		return v.Logger
	}
	return slog.Default()
}

// Validate runs the full TI-PKI validation pipeline against a candidate
// chain. chain[0] is treated as the end-entity; chain[1:] are candidate
// intermediates supplied by the caller (typically from a TLS handshake or
// a JWS x5c header). [BuildChain] then resolves the issuer references and
// extends the chain up to a trusted root from the [TrustStore].
//
// Validate always returns a non-nil [ValidationResult] on a non-nil err
// return; err is only non-nil for shape problems (nil ctx, empty chain, no
// configured trust store). All policy-level failures are reflected in
// result.Errors with result.Valid == false.
func (v *Validator) Validate(ctx context.Context, chain []*x509.Certificate) (*ValidationResult, error) {
	if ctx == nil {
		return nil, fmt.Errorf("gempki: Validate requires a non-nil context")
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("gempki: Validate requires a non-empty chain")
	}
	ts := v.activeTrustStore()
	if ts == nil {
		return nil, fmt.Errorf("gempki: Validate requires a TrustStore (set via WithTrustStore or WithTrustStoreHolder)")
	}

	log := v.logger().With("ee_cn", chain[0].Subject.CommonName)
	log.Debug("validation started")

	v.Hooks.fireBeforeChainBuild(ctx, chain[0])
	fullChain, err := BuildChain(chain[0], chain[1:], ts, BuildChainOptions{MaxChainLen: v.MaxChainLen})
	v.Hooks.fireAfterChainBuild(ctx, fullChain, err)
	if err != nil {
		// Positions and CertResults are parallel slices to Chain — callers
		// (CLI renderers, metric pipelines) index Positions[i] while
		// iterating Chain. Keep them in sync even on the failure path so
		// nobody indexes out of bounds.
		positions := make([]ChainPosition, len(chain))
		certResults := make([]CertResult, len(chain))
		for i, c := range chain {
			positions[i] = positionOf(i, len(chain))
			if c != nil {
				certResults[i] = CertResult{Subject: c.Subject.CommonName, Position: positions[i]}
			}
		}
		result := &ValidationResult{
			Valid:       false,
			Chain:       chain,
			Positions:   positions,
			CertResults: certResults,
			Errors: []*ValidationError{{
				Code:    ErrCodeChainIncomplete,
				Subject: chain[0].Subject.CommonName,
				Message: "chain construction failed",
				Cause:   err,
			}},
		}
		v.Hooks.fireOnError(ctx, result.Errors[0])
		log.Info("chain build failed", "err", err)
		return result, nil
	}

	pathOpts := ValidatePathOptions{
		TimeFunc:    v.TimeFunc,
		EEChecks:    v.composeEEChecks(),
		SubCAChecks: v.SubCAChecks,
		RootChecks:  v.RootChecks,
	}
	result, err := ValidatePath(ctx, fullChain, pathOpts)
	if err != nil {
		return nil, fmt.Errorf("gempki: ValidatePath: %w", err)
	}

	v.Hooks.fireBeforeRevocation(ctx, fullChain)
	rev, revErr := EvaluateChain(ctx, fullChain, v.Revocation)
	v.Hooks.fireAfterRevocation(ctx, rev, revErr)
	if revErr != nil {
		ve := &ValidationError{
			Code:    ErrCodeOCSPUnavailable,
			Subject: chain[0].Subject.CommonName,
			Message: "revocation subsystem error",
			Cause:   revErr,
		}
		result.Valid = false
		result.Errors = append(result.Errors, ve)
		v.Hooks.fireOnError(ctx, ve)
	} else if rev != nil {
		if len(rev.Errors) > 0 {
			result.Valid = false
		}
		result.Errors = append(result.Errors, rev.Errors...)
		result.Warnings = append(result.Warnings, rev.Warnings...)
		for i, r := range rev.PerCert {
			if i < len(result.CertResults) && r != nil {
				result.CertResults[i].Revocation = r
			}
		}
	}

	// Fire OnError / OnWarning hooks once for every entry (covers both the
	// path-validation and revocation findings).
	for _, e := range result.Errors {
		v.Hooks.fireOnError(ctx, e)
	}
	for _, w := range result.Warnings {
		v.Hooks.fireOnWarning(ctx, w)
	}

	log.Debug("validation finished",
		"valid", result.Valid,
		"errors", len(result.Errors),
		"warnings", len(result.Warnings))
	return result, nil
}

// composeEEChecks builds the EE check pipeline by concatenating the
// built-in policy/role/KU/EKU checks (when configured) with the caller's
// custom EEChecks. Order matters only for the first-failure semantics —
// each check runs and any *ValidationError it returns is appended.
func (v *Validator) composeEEChecks() []CertificateCheck {
	var checks []CertificateCheck
	if len(v.RequiredPolicies) > 0 {
		checks = append(checks, CheckCertificatePolicies(v.RequiredPolicies...))
	}
	if len(v.RequiredRoleOIDs) > 0 {
		checks = append(checks, CheckRoleOID(v.RoleOIDExtractor, v.RequiredRoleOIDs...))
	}
	if v.RequiredKeyUsage != 0 {
		checks = append(checks, CheckKeyUsage(v.RequiredKeyUsage))
	}
	if len(v.AllowedExtKeyUsages) > 0 {
		checks = append(checks, CheckHasAnyExtKeyUsage(v.AllowedExtKeyUsages...))
	}
	checks = append(checks, v.EEChecks...)
	return checks
}

// ValidatePEM parses one or more PEM-encoded certificates and validates the
// resulting chain. Non-CERTIFICATE PEM blocks are skipped silently.
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

// ValidateDER parses a slice of DER-encoded certificates and validates the
// resulting chain. The first element is treated as the EE.
func (v *Validator) ValidateDER(ctx context.Context, ders [][]byte) (*ValidationResult, error) {
	if len(ders) == 0 {
		return nil, fmt.Errorf("gempki: ValidateDER requires at least one DER blob")
	}
	chain := make([]*x509.Certificate, 0, len(ders))
	for i, der := range ders {
		c, err := ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("gempki: ValidateDER parse %d: %w", i, err)
		}
		chain = append(chain, c)
	}
	return v.Validate(ctx, chain)
}
