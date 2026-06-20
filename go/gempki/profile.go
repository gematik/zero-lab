package gempki

import (
	"encoding/asn1"
	"net/http"
	"slices"
	"sort"
	"time"
)

// Profile is a named, type-aware validation strategy.
//
// A Profile carries the use-case-specific overlay (revocation strictness,
// extra policy assertions, the set of cert types it accepts) and a
// [CertificateType] carries the spec-mandated baseline (KeyUsage, EKUs,
// CertificatePolicies, role OIDs). [Profile.Validator] composes the two
// into a [*Validator] ready for [Validator.Validate].
//
// Profiles are values, not factories: write
//
//	v := gempki.ProfileSmbAuth.Validator(ts, gempki.CertTypeHciAUT)
//
// then mutate v further if needed (install a custom OCSP checker, override
// the revocation mode for dev, attach hooks). The profile sets defaults,
// not a contract.
type Profile struct {
	// Name is the slug used by the CLI (`--profile <name>`) and by the
	// [ProfileRegistry]. Lower-case kebab is the convention.
	Name string

	// RevocationMode is the strictness layer the profile contributes on
	// top of the type baseline.
	RevocationMode RevocationMode

	// ExtraPolicies are CertificatePolicies OIDs the profile mandates
	// on top of the type baseline (`t.Spec().Policies`). Use this for
	// per-use-case policy assertions that aren't part of every cert of
	// the same type.
	ExtraPolicies []asn1.ObjectIdentifier

	// AcceptsTypes is the closed set of [CertificateType]s this profile
	// is meant to validate. A cert whose detected type isn't in this
	// set should never be validated under this profile; callers
	// (typically the CLI) may force it but should emit a warning.
	AcceptsTypes []CertificateType

	// DefaultFor lists the types for which this profile is the
	// auto-mode default. A type may appear in `AcceptsTypes` of
	// several profiles but in `DefaultFor` of at most one — otherwise
	// auto mode must signal ambiguity.
	DefaultFor []CertificateType
}

// Validator builds a fresh [*Validator] for the given [TrustStore] and
// cert type, composing the type's baseline ([CertificateType.Spec]) with
// this profile's overlay. The returned validator has no revocation
// checker wired — callers add one with [WithRevocationChecker] or
// [WithOCSPNetworkChecker] before validating.
//
// Passing a type that isn't in [Profile.AcceptsTypes] is allowed (the
// caller may be deliberately forcing a profile); the resulting
// validator simply applies the type's baseline with this profile's
// overlay, which may or may not be appropriate. The CLI emits a
// warning when this happens.
func (p *Profile) Validator(ts *TrustStore, t CertificateType) *Validator {
	spec := t.Spec()
	policies := append(append([]asn1.ObjectIdentifier{}, spec.Policies...), p.ExtraPolicies...)
	opts := []Option{
		WithTrustStore(ts),
		WithRevocationMode(p.RevocationMode),
	}
	if spec.KeyUsage != 0 {
		opts = append(opts, WithRequiredKeyUsage(spec.KeyUsage))
	}
	if len(spec.EKU) > 0 {
		opts = append(opts, WithAllowedExtKeyUsages(spec.EKU...))
	}
	if len(policies) > 0 {
		opts = append(opts, WithRequiredPolicies(policies...))
	}
	if len(spec.RoleOIDs) > 0 {
		opts = append(opts, WithRequiredRoleOIDs(spec.RoleOIDs...))
	}
	return NewValidator(opts...)
}

// Accepts reports whether t is in p.AcceptsTypes. Convenience for callers
// that want to check before composing a validator.
func (p *Profile) Accepts(t CertificateType) bool {
	return slices.Contains(p.AcceptsTypes, t)
}

// ProfileSmbAuth validates SMC-B-family institution authentication certs
// (C.HCI.AUT today; HSM-B / SMC-B-ORG sibling types added to AcceptsTypes
// when their cert types are defined). SMB is the umbrella ("Oberbegriff")
// for every SMC-B variant.
//
// SoftFail revocation: an unknown OCSP status downgrades to a warning so
// transient OCSP outages don't reject an SMC-B login. Production deployments
// can override to HardFail before validating.
var ProfileSmbAuth = &Profile{
	Name:           "smbauth",
	RevocationMode: RevocationModeSoftFail,
	AcceptsTypes:   []CertificateType{CertTypeHciAUT},
	DefaultFor:     []CertificateType{CertTypeHciAUT},
}

// ProfileEpaVau validates the C.FD.AUT cert that an ePA Aktensystem VAU
// (Vertrauenswürdige Ausführungsumgebung) presents for authenticity.
//
// HardFail revocation: ePA backend access must reject on revocation
// uncertainty.
//
// C.FD.AUT is also accepted by [ProfileIdp]; that's the 1:N case the
// `--profile` flag exists to disambiguate. ProfileEpaVau is *not* the
// default-for C.FD.AUT — auto mode warns and asks the user to pick.
var ProfileEpaVau = &Profile{
	Name:           "epavau",
	RevocationMode: RevocationModeHardFail,
	AcceptsTypes:   []CertificateType{CertTypeFdAUT},
}

// ProfileIdp validates IDP-side certs: discovery-document signing
// (C.FD.SIG) and JWKS / authenticity (C.FD.AUT).
//
// HardFail revocation: IDP key compromise must not be soft-failed.
//
// `DefaultFor` only lists C.FD.SIG because C.FD.AUT is genuinely
// ambiguous between idp and epavau; the user picks.
var ProfileIdp = &Profile{
	Name:           "idp",
	RevocationMode: RevocationModeHardFail,
	AcceptsTypes:   []CertificateType{CertTypeFdSIG, CertTypeFdAUT},
	DefaultFor:     []CertificateType{CertTypeFdSIG},
}

// ProfileRegistry is the canonical name → profile lookup. CLI `--profile
// <name>` and `pki profiles` both read through this map. Add new
// profiles by appending here; the rest of the CLI surface picks them up
// automatically.
var ProfileRegistry = map[string]*Profile{
	ProfileSmbAuth.Name: ProfileSmbAuth,
	ProfileEpaVau.Name:  ProfileEpaVau,
	ProfileIdp.Name:     ProfileIdp,
}

// sortProfilesByName sorts in place by Name for deterministic output.
// Used by [ProfilesForType] and `pki profiles` rendering.
func sortProfilesByName(ps []*Profile) {
	sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
}

// WithOCSPNetworkChecker is a convenience for the most common revocation
// wire-up: an [OCSPChecker] that fetches over HTTPS through the supplied
// http.Client. Most production callers want this together with a profile:
//
//	v := gempki.ProfileSmbAuth.Validator(ts, gempki.CertTypeHciAUT)
//	gempki.WithOCSPNetworkChecker(client, "")(v)         // AIA-driven
//	gempki.WithCache(gempki.NewInMemoryCache(2000))(v)
//
// responderURL is optional; pass "" to read it from each EE's AIA
// extension. MaxResponseAge defaults to 48h.
func WithOCSPNetworkChecker(httpClient *http.Client, responderURL string) Option {
	return WithRevocationChecker(&OCSPChecker{
		HTTPClient:     httpClient,
		ResponderURL:   responderURL,
		MaxResponseAge: 48 * time.Hour,
	})
}
