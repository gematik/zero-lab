package gempki

import (
	"encoding/asn1"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
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
//	v := gempki.ProfileSmbAut.Validator(ts, gempki.CertTypeHciAUT)
//	v.Revocation = &gempki.OCSPChecker{HTTPClient: client}
//
// and adjust the result further if needed. The profile sets defaults, not a
// contract.
type Profile struct {
	// Name is the slug used by the CLI (`--profile <name>`) and by the
	// [ProfileRegistry]. Kebab-case, enforced by [ValidateProfileRegistry].
	Name string

	// Description is the one-line summary the CLI prints in profile
	// listings. Single line, no trailing period — the longer story belongs
	// in the doc comment above each profile var.
	Description string

	// RevocationMode is the strictness layer the profile contributes on
	// top of the type baseline.
	RevocationMode RevocationMode

	// ExtraPolicies are CertificatePolicies OIDs the profile mandates
	// on top of the type baseline (`t.Spec().Policies`). Use this for
	// per-use-case policy assertions that aren't part of every cert of
	// the same type.
	ExtraPolicies []asn1.ObjectIdentifier

	// RequiredRoleOIDs, when non-empty, REPLACES the type baseline's
	// [CertTypeSpec.RoleOIDs] for this profile — see [Profile.EffectiveRoleOIDs].
	// The EE must assert at least one of them (any-of, see [CheckRoleOID]).
	//
	// Replacing rather than adding is deliberate: [WithRequiredRoleOIDs]
	// appends and the check is any-of, so accumulating the two lists would
	// *widen* the accepted set. A profile narrows a type, never the reverse.
	// A profile that genuinely needs "the type's roles AND mine" needs a
	// second [CheckRoleOID] in its own checks, not this field.
	//
	// It doubles as the selection discriminator: a profile that declares
	// role OIDs is only auto-selected for a cert that asserts one of them
	// (see [SelectProfileForCert]).
	RequiredRoleOIDs []asn1.ObjectIdentifier

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

// Validator builds a [*Validator] for the given trust store and certificate
// type: the type's baseline (key usage, EKUs, policies, roles) with this
// profile's overlay on top. No revocation checker is set — callers assign
// [Validator.Revocation] before validating, or set RevocationModeDisabled.
//
// A type outside [Profile.AcceptsTypes] is allowed; the caller may be
// deliberately forcing a profile. The CLI warns when that happens.
func (p *Profile) Validator(ts *TrustStore, t CertificateType) *Validator {
	spec := t.Spec()
	return &Validator{
		TrustStore:          ts,
		RevocationMode:      p.RevocationMode,
		RequiredKeyUsage:    spec.KeyUsage,
		AllowedExtKeyUsages: spec.EKU,
		RequiredPolicies:    append(append([]asn1.ObjectIdentifier{}, spec.Policies...), p.ExtraPolicies...),
		RequiredRoleOIDs:    p.EffectiveRoleOIDs(t),
	}
}

// EffectiveRoleOIDs returns the role-OID set this profile actually enforces
// for t: [Profile.RequiredRoleOIDs] when the profile declares any, otherwise
// the type baseline's. Callers rendering "what does this profile check"
// should read this rather than `t.Spec().RoleOIDs`.
func (p *Profile) EffectiveRoleOIDs(t CertificateType) []asn1.ObjectIdentifier {
	if len(p.RequiredRoleOIDs) > 0 {
		return p.RequiredRoleOIDs
	}
	return t.Spec().RoleOIDs
}

// Accepts reports whether t is in p.AcceptsTypes. Convenience for callers
// that want to check before composing a validator.
func (p *Profile) Accepts(t CertificateType) bool {
	return slices.Contains(p.AcceptsTypes, t)
}

// ProfileSmbAut validates SMC-B-family institution authentication certs
// (C.HCI.AUT today; HSM-B / SMC-B-ORG sibling types added to AcceptsTypes
// when their cert types are defined). SMB is the umbrella ("Oberbegriff")
// for every SMC-B variant.
//
// SoftFail revocation: an unknown OCSP status downgrades to a warning so
// transient OCSP outages don't reject an SMC-B login. Production deployments
// can override to HardFail before validating.
var ProfileSmbAut = &Profile{
	Name:           "smb-aut",
	Description:    "SMC-B institution authentication (SMB = SMC-B / HSM-B / SMC-B-ORG)",
	RevocationMode: RevocationModeSoftFail,
	AcceptsTypes:   []CertificateType{CertTypeHciAUT},
	DefaultFor:     []CertificateType{CertTypeHciAUT},
}

// ProfileEpaVau validates the C.FD.AUT cert an ePA Aktensystem VAU
// (Vertrauenswürdige Ausführungsumgebung) presents for authenticity.
//
// Like [ProfileZetaASL] it is identified by its admission role rather than
// by its cert type: oid_epa_vau also appears on the VAU's C.FD.ENC and
// C.FD.SIG certs, so the pairing of role and type is what names this
// profile — hence `epa-vau-aut`, leaving room for `epa-vau-enc` and
// `epa-vau-sig`.
//
// It claims no [Profile.DefaultFor]: a C.FD.AUT that asserts neither
// oid_epa_vau nor ZETA Guard is something else again (an IDP JWKS cert, for
// one — see the gap on [ProfileIdpSig]), and guessing at it would validate
// it against assertions it was never meant to carry.
//
// HardFail revocation: ePA backend access must reject on revocation
// uncertainty.
var ProfileEpaVau = &Profile{
	Name:             "epa-vau-aut",
	Description:      "ePA Aktensystem VAU backend authenticity",
	RevocationMode:   RevocationModeHardFail,
	AcceptsTypes:     []CertificateType{CertTypeFdAUT},
	RequiredRoleOIDs: []asn1.ObjectIdentifier{OIDTechRoleEpaVAU},
}

// ProfileIdpSig validates the C.FD.SIG certs an IDP signs with: its
// discovery document (puk_disc_sig) and its tokens (puk_idp_sig). Both
// carry oid_idpd, which is what tells them apart from any other
// Fachdienst's signing cert.
//
// HardFail revocation: IDP key compromise must not be soft-failed.
//
// There is deliberately no idp-aut. An IDP publishes no C.FD.AUT at all —
// checked against the RU IDP, whose authenticity keys are C.FD.SIG and
// whose encryption key (puk_idp_enc) ships with no certificate. The
// predecessor `idp` profile claimed C.FD.AUT anyway, and that claim was
// the sole reason every C.FD.AUT counted as ambiguous.
var ProfileIdpSig = &Profile{
	Name:             "idp-sig",
	Description:      "IDP discovery document and token signing",
	RevocationMode:   RevocationModeHardFail,
	AcceptsTypes:     []CertificateType{CertTypeFdSIG},
	RequiredRoleOIDs: []asn1.ObjectIdentifier{OIDTechRoleIDPD},
}

// ProfileZetaASL validates the C.FD.AUT cert a ZETA Guard access service
// layer presents. Named for the role/type pairing like [ProfileEpaVau], and
// after the role rather than the component so the name tracks gemSpec_OID:
// oid_zeta-guard also covers C.FD.TLS-C, which would be
// `zeta-guard-tls-c`.
//
// The cert type alone does not identify it — a ZETA ASL cert is an ordinary
// C.FD.AUT — so the profile requires the ZETA Guard profession OID in the
// admission extension. That role is also what makes the profile
// auto-selectable: [ProfileEpaVau] accepts the same type and is told apart
// the same way, by its own role.
//
// HardFail revocation: ZETA sits in front of the resources it guards.
var ProfileZetaASL = &Profile{
	Name:             "zeta-guard-aut",
	Description:      "ZETA Guard access service layer authenticity",
	RevocationMode:   RevocationModeHardFail,
	AcceptsTypes:     []CertificateType{CertTypeFdAUT},
	RequiredRoleOIDs: []asn1.ObjectIdentifier{OIDTechRoleZETAGuard},
}

// ProfileRegistry is the canonical name → profile lookup. CLI `--profile
// <name>` and `pki profiles` both read through this map. Add new
// profiles by appending here; the rest of the CLI surface picks them up
// automatically. [ValidateProfileRegistry] states what a well-formed
// registry looks like.
var ProfileRegistry = map[string]*Profile{
	ProfileSmbAut.Name:  ProfileSmbAut,
	ProfileEpaVau.Name:  ProfileEpaVau,
	ProfileIdpSig.Name:  ProfileIdpSig,
	ProfileZetaASL.Name: ProfileZetaASL,
}

// Pseudo-values accepted wherever a profile name is: they select a strategy
// rather than a profile. Defined here so callers need not spell them.
const (
	// ProfileAuto picks the profile from the certificate — see
	// [SelectProfileForCert].
	ProfileAuto = "auto"
	// ProfileNone disables profile-driven EE checks (chain-only validation).
	ProfileNone = "none"
)

// ProfileNames returns every registered profile name, sorted.
func ProfileNames() []string {
	out := make([]string, 0, len(ProfileRegistry))
	for name := range ProfileRegistry {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// ProfileSelectorValues returns every legal `--profile` value: the two
// pseudo-values followed by [ProfileNames]. CLIs should build their help,
// completion and error text from this rather than repeating the list.
func ProfileSelectorValues() []string {
	return append([]string{ProfileAuto, ProfileNone}, ProfileNames()...)
}

// LookupProfile resolves a profile name case-insensitively. [ProfileAuto],
// [ProfileNone], "" and unknown names all return (nil, false); callers that
// must tell those apart compare against the constants first.
func LookupProfile(name string) (*Profile, bool) {
	p, ok := ProfileRegistry[strings.ToLower(name)]
	return p, ok
}

// profileNamePattern is the kebab-case shape every profile name must have.
var profileNamePattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// ValidateProfileRegistry reports the first structural problem in
// [ProfileRegistry], or nil when it is well-formed. It exists because two
// of the invariants are otherwise unenforced and fail silently: a type
// claimed as [Profile.DefaultFor] by two profiles makes
// [CertificateType.DefaultProfile] answer arbitrarily, and a DefaultFor
// entry outside AcceptsTypes produces a default that [ProfilesForType]
// won't even list.
//
// Consumers that append their own profiles should call this in a test.
// gempki deliberately does not panic in init: a library has no business
// killing a process over a registry its caller is still assembling.
func ValidateProfileRegistry() error {
	owner := map[CertificateType]string{}
	for key, p := range ProfileRegistry {
		switch {
		case p == nil:
			return fmt.Errorf("gempki: profile registry key %q is nil", key)
		case key != p.Name:
			return fmt.Errorf("gempki: profile registry key %q does not match profile name %q", key, p.Name)
		case !profileNamePattern.MatchString(p.Name):
			return fmt.Errorf("gempki: profile name %q is not kebab-case", p.Name)
		case p.Description == "":
			return fmt.Errorf("gempki: profile %q has no Description", p.Name)
		case strings.ContainsAny(p.Description, "\n\r"):
			return fmt.Errorf("gempki: profile %q Description must be a single line", p.Name)
		case len(p.AcceptsTypes) == 0:
			return fmt.Errorf("gempki: profile %q accepts no certificate types", p.Name)
		}
		for _, t := range p.AcceptsTypes {
			if !IsKnownCertificateType(t) {
				return fmt.Errorf("gempki: profile %q accepts unknown certificate type %q", p.Name, t)
			}
		}
		for _, t := range p.DefaultFor {
			if !slices.Contains(p.AcceptsTypes, t) {
				return fmt.Errorf("gempki: profile %q is DefaultFor %q which it does not accept", p.Name, t)
			}
			if other, dup := owner[t]; dup {
				return fmt.Errorf("gempki: certificate type %q is claimed as DefaultFor by both %q and %q", t, other, p.Name)
			}
			owner[t] = p.Name
		}
	}
	return nil
}

// sortProfilesByName sorts in place by Name for deterministic output.
// Used by [ProfilesForType] and `pki profiles` rendering.
func sortProfilesByName(ps []*Profile) {
	sort.Slice(ps, func(i, j int) bool { return ps[i].Name < ps[j].Name })
}
