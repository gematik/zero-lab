package gempki

import (
	"crypto/x509"
	"sort"
	"strings"
)

// ProfileSelectReason says how [SelectProfileForCert] reached its answer.
type ProfileSelectReason string

const (
	// ProfileSelectedByCert — the profile declared a discriminator that the
	// certificate asserts (today: a role OID).
	ProfileSelectedByCert ProfileSelectReason = "cert"
	// ProfileSelectedByDefault — the profile owns the certificate's type
	// through [Profile.DefaultFor].
	ProfileSelectedByDefault ProfileSelectReason = "default"
	// ProfileSelectAmbiguous — more than one profile applies and none is
	// more specific. The caller must ask the user to name one.
	ProfileSelectAmbiguous ProfileSelectReason = "ambiguous"
	// ProfileSelectNone — nothing claims this certificate: either no profile
	// accepts its type, or the profiles that do all require a role it does
	// not assert. Candidates carries the latter, so a caller can name them.
	ProfileSelectNone ProfileSelectReason = "none"
)

// ProfileSelection is the outcome of [SelectProfileForCert].
type ProfileSelection struct {
	// Type is what [DetectCertificateType] made of the certificate.
	Type CertificateType
	// Profile is the selected profile, nil unless Reason is
	// [ProfileSelectedByCert] or [ProfileSelectedByDefault].
	Profile *Profile
	// Candidates are the profiles the user could name. Set when the
	// selection is ambiguous.
	Candidates []*Profile
	Reason     ProfileSelectReason
	// Detail is a short human-readable note on the deciding evidence, e.g.
	// `asserts role 1.2.276.0.76.4.328 (ZETA Guard)`.
	Detail string
}

// Matches reports whether cert satisfies this profile's selection
// discriminators — the cheap markers that tell two profiles accepting the
// same type apart. Today that means [Profile.RequiredRoleOIDs]: a profile
// declaring none matches any certificate.
//
// This is selection, not validation. True means "this profile is the right
// lens for this certificate", never "this certificate is valid" — the
// answer comes from unauthenticated certificate content, so treat it as a
// routing hint and let [Validator.Validate] do the deciding.
func (p *Profile) Matches(cert *x509.Certificate) bool {
	if len(p.RequiredRoleOIDs) == 0 {
		return true
	}
	if cert == nil {
		return false
	}
	have, err := DefaultRoleOIDExtractor(cert)
	if err != nil {
		// No admission extension, or one we cannot parse: the certificate
		// asserts nothing, so a profile that requires a role does not apply.
		return false
	}
	return oidsIntersect(have, p.RequiredRoleOIDs)
}

// specificity counts the discriminators a profile declares. A profile that
// matched on one outranks a profile that matched on nothing.
func (p *Profile) specificity() int {
	if len(p.RequiredRoleOIDs) > 0 {
		return 1
	}
	return 0
}

func profileNamesOf(ps []*Profile) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.Name
	}
	return out
}

// ProfilesForCert narrows [ProfilesForType] to the profiles whose
// discriminators cert actually satisfies, most specific first, then by name.
// Where [ProfilesForType] answers "what could validate this type",
// ProfilesForCert answers "what applies to this certificate".
func ProfilesForCert(cert *x509.Certificate) []*Profile {
	if cert == nil {
		return nil
	}
	var out []*Profile
	for _, p := range ProfilesForType(DetectCertificateType(cert)) {
		if p.Matches(cert) {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].specificity() != out[j].specificity() {
			return out[i].specificity() > out[j].specificity()
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// SelectProfileForCert picks the profile to validate cert under — the whole
// of what `--profile auto` means, so every caller resolves it identically.
//
// A profile matched on a discriminator outranks one that owns the type by
// default: that is what lets a ZETA Guard C.FD.AUT reach zeta-asl while a
// plain C.FD.AUT reaches epa-vau. Ambiguity is reported, never guessed.
func SelectProfileForCert(cert *x509.Certificate) ProfileSelection {
	t := DetectCertificateType(cert)
	sel := ProfileSelection{Type: t, Reason: ProfileSelectNone}

	byType := ProfilesForType(t)
	if len(byType) == 0 {
		sel.Detail = "no profile accepts type " + string(t)
		return sel
	}

	matched := ProfilesForCert(cert)
	if len(matched) > 0 && matched[0].specificity() > 0 {
		top := matched[:1]
		for _, p := range matched[1:] {
			if p.specificity() != matched[0].specificity() {
				break
			}
			top = append(top, p)
		}
		if len(top) == 1 {
			sel.Profile = top[0]
			sel.Reason = ProfileSelectedByCert
			sel.Detail = "asserts role " + FormatOID(top[0].RequiredRoleOIDs[0])
			return sel
		}
		sel.Reason = ProfileSelectAmbiguous
		sel.Candidates = top
		sel.Detail = "several profiles match the certificate's roles"
		return sel
	}

	if p := t.DefaultProfile(); p != nil {
		sel.Profile = p
		sel.Reason = ProfileSelectedByDefault
		sel.Detail = "default for type " + string(t)
		return sel
	}

	if len(matched) == 1 {
		sel.Profile = matched[0]
		sel.Reason = ProfileSelectedByCert
		sel.Detail = "the only profile that accepts type " + string(t)
		return sel
	}

	if len(matched) == 0 {
		// Every profile for this type is role-discriminated and none of their
		// roles is asserted. That is a definite "not one of these", not an
		// ambiguity for the user to resolve.
		sel.Reason = ProfileSelectNone
		sel.Candidates = byType
		sel.Detail = "type " + string(t) + " is accepted by " + strings.Join(profileNamesOf(byType), ", ") +
			", but the certificate asserts none of their roles"
		return sel
	}
	sel.Reason = ProfileSelectAmbiguous
	sel.Candidates = matched
	sel.Detail = "type " + string(t) + " matches several profiles and none owns it"
	return sel
}
