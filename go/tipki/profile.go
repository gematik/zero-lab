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
	"crypto/x509"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/gematik/zero-lab/go/tipki/oid"
)

// RevocationMode is how strict a use case wants the revocation check to be, named as in ti-pki. This
// package does not check revocation; whoever does reads the mode here.
type RevocationMode string

// The modes a profile can ask for.
const (
	RevocationHardFail RevocationMode = "hard-fail"
	RevocationSoftFail RevocationMode = "soft-fail"
	// RevocationDisabled skips revocation checking. No profile asks for it.
	RevocationDisabled RevocationMode = "disabled"
)

// Profile is a named overlay on a certificate type for one use case.
type Profile struct {
	Name        string
	Description string
	Revocation  RevocationMode
	// RequiredRoleOIDs, when not empty, replace the type's roles. Replacing rather than adding is
	// deliberate: the check is any-of, so adding would widen what is accepted. They also decide
	// selection: such a profile is only selected for a certificate asserting one of them.
	RequiredRoleOIDs []x509.OID
	// AcceptsTypes are the types the profile is meant for.
	AcceptsTypes []CertificateType
	// DefaultFor are the types the profile is the automatic choice for, at most one per type.
	DefaultFor []CertificateType
}

// The profiles of ti-pki's profile module.
var (
	ProfileDipagVauAut = &Profile{
		Name:             "dipag-vau-aut",
		Description:      "Digitale Patientenrechnung VAU authenticity",
		Revocation:       RevocationHardFail,
		RequiredRoleOIDs: []x509.OID{oid.TechRoleDipagVAU},
		AcceptsTypes:     []CertificateType{CertFdAut},
	}
	ProfileEpaVauAut = &Profile{
		Name:             "epa-vau-aut",
		Description:      "ePA Aktensystem VAU backend authenticity",
		Revocation:       RevocationHardFail,
		RequiredRoleOIDs: []x509.OID{oid.TechRoleEpaVAU},
		AcceptsTypes:     []CertificateType{CertFdAut},
	}
	ProfileFdTLSS = &Profile{
		Name:         "fd-tls-s",
		Description:  "Fachdienst TLS server",
		Revocation:   RevocationHardFail,
		AcceptsTypes: []CertificateType{CertFdTLSS},
		DefaultFor:   []CertificateType{CertFdTLSS},
	}
	ProfileHciAut = &Profile{
		Name:         "hci-aut",
		Description:  "Institution authentication, SM-B (SMC-B, HSM-B)",
		Revocation:   RevocationHardFail,
		AcceptsTypes: []CertificateType{CertHciAut},
		DefaultFor:   []CertificateType{CertHciAut},
	}
	ProfileIdpdSig = &Profile{
		Name:             "idpd-sig",
		Description:      "IDP discovery document and token signing",
		Revocation:       RevocationHardFail,
		RequiredRoleOIDs: []x509.OID{oid.TechRoleIDPD},
		AcceptsTypes:     []CertificateType{CertFdSig},
	}
	ProfileTslSig = &Profile{
		Name:         "tsl-sig",
		Description:  "TSL signer",
		Revocation:   RevocationHardFail,
		AcceptsTypes: []CertificateType{CertTslSig},
		DefaultFor:   []CertificateType{CertTslSig},
	}
	ProfileZetaGuardAut = &Profile{
		Name:             "zeta-guard-aut",
		Description:      "ZETA Guard access service layer authenticity",
		Revocation:       RevocationHardFail,
		RequiredRoleOIDs: []x509.OID{oid.TechRoleZETAGuard},
		AcceptsTypes:     []CertificateType{CertFdAut},
	}
)

// Profiles returns every profile, sorted by name.
func Profiles() []*Profile {
	return []*Profile{
		ProfileDipagVauAut, ProfileEpaVauAut, ProfileFdTLSS, ProfileHciAut, ProfileIdpdSig, ProfileTslSig,
		ProfileZetaGuardAut,
	}
}

// LookupProfile finds a profile by name, folded by [FoldName]; nil if there is none.
func LookupProfile(name string) *Profile {
	wanted := FoldName(name)
	for _, p := range Profiles() {
		if FoldName(p.Name) == wanted {
			return p
		}
	}
	return nil
}

// Accepts says whether t is among the types the profile is meant for.
func (p *Profile) Accepts(t CertificateType) bool { return slices.Contains(p.AcceptsTypes, t) }

// EffectiveRoleOIDs are the roles the profile enforces for t: its own if it has any, otherwise the
// type's.
func (p *Profile) EffectiveRoleOIDs(t CertificateType) []x509.OID {
	if len(p.RequiredRoleOIDs) > 0 {
		return p.RequiredRoleOIDs
	}
	return t.Spec().RoleOIDs
}

func (p *Profile) matches(cert *x509.Certificate) bool {
	if len(p.RequiredRoleOIDs) == 0 {
		return true
	}
	admission, err := Admission(cert)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(admission.ProfessionOIDs, func(role x509.OID) bool {
		return containsOID(p.RequiredRoleOIDs, role)
	})
}

// Finding is one requirement a certificate does not meet.
type Finding struct {
	// Code says why; see [ErrorCode].
	Code ErrorCode
	// Subject is the common name of the certificate concerned.
	Subject string
	Message string
}

// Check says what cert lacks for type t under the profile, nil if nothing (PROF-020). It reads only
// the certificate: nil is no verdict on its chain or standing.
func (p *Profile) Check(cert *x509.Certificate, t CertificateType) []Finding {
	spec := t.Spec()
	var findings []Finding
	add := func(finding *Finding) {
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	add(checkPolicies(cert, spec.Policies))
	add(checkKeyUsage(cert, spec.KeyUsage))
	add(checkExtKeyUsage(cert, spec.ExtKeyUsage))
	if roles := p.EffectiveRoleOIDs(t); len(roles) > 0 {
		if message := missingRole(cert, roles); message != "" {
			findings = append(findings, Finding{CodeRoleOIDMissing, cert.Subject.CommonName, message})
		}
	}
	return findings
}

func checkPolicies(cert *x509.Certificate, required []x509.OID) *Finding {
	var missing []x509.OID
	for _, policy := range required {
		if !containsOID(cert.Policies, policy) {
			missing = append(missing, policy)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return &Finding{CodePolicyMismatch, cert.Subject.CommonName, "required CertificatePolicy missing: " + formatOIDs(missing)}
}

func checkKeyUsage(cert *x509.Certificate, required x509.KeyUsage) *Finding {
	if cert.KeyUsage&required == required {
		return nil
	}
	return &Finding{CodeKeyUsageMismatch, cert.Subject.CommonName, fmt.Sprintf("required KeyUsage bits %b, have %b", required, cert.KeyUsage)}
}

func checkExtKeyUsage(cert *x509.Certificate, allowed []x509.OID) *Finding {
	if len(allowed) == 0 {
		return nil
	}
	have := extKeyUsages(cert)
	if slices.ContainsFunc(have, anyExtendedKeyUsage.EqualASN1OID) || slices.ContainsFunc(allowed, func(want x509.OID) bool { return slices.ContainsFunc(have, want.EqualASN1OID) }) {
		return nil
	}
	return &Finding{CodeKeyUsageMismatch, cert.Subject.CommonName, "certificate ExtKeyUsage matches none of: " + dottedOIDs(allowed)}
}

func missingRole(cert *x509.Certificate, roles []x509.OID) string {
	admission, err := Admission(cert)
	switch {
	case errors.Is(err, ErrNoAdmissionStatement):
		return "required role OID missing: no admission extension"
	case err != nil:
		return "role OID extraction failed: " + err.Error()
	}
	if slices.ContainsFunc(admission.ProfessionOIDs, func(role x509.OID) bool { return containsOID(roles, role) }) {
		return ""
	}
	return "required role OID missing: have " + formatOIDs(admission.ProfessionOIDs)
}

func formatOIDs(ids []x509.OID) string {
	formatted := make([]string, len(ids))
	for i, id := range ids {
		formatted[i] = oid.Format(id)
	}
	return strings.Join(formatted, ", ")
}

// SelectReason is how a selection reached its answer.
type SelectReason string

// The reasons, named as in ti-pki.
const (
	// SelectByCert: the certificate asserts the profile's role.
	SelectByCert SelectReason = "cert"
	// SelectByDefault: the profile owns the certificate's type.
	SelectByDefault SelectReason = "default"
	// SelectAmbiguous: several profiles apply and none is more specific.
	SelectAmbiguous SelectReason = "ambiguous"
	// SelectUnclaimed: no profile applies.
	SelectUnclaimed SelectReason = "none"
)

// ProfileSelection is the outcome of [SelectForCert].
type ProfileSelection struct {
	// CertType is what [DetectCertificateType] found; empty if nothing.
	CertType CertificateType
	// Profile is the selected profile, with [SelectByCert] or [SelectByDefault]; otherwise nil.
	Profile *Profile
	// Candidates are the profiles to name when ambiguous, or whose roles an unclaimed certificate lacks.
	Candidates []*Profile
	Reason     SelectReason
	Detail     string
}

// SelectForCert picks the profile for cert (PROF-003): one matched on its role outranks one owning
// the type by default, and ambiguity is reported and never guessed. It reads unauthenticated content
// and only says which profile is the right lens.
func SelectForCert(cert *x509.Certificate) ProfileSelection {
	return selectFrom(Profiles(), cert)
}

func selectFrom(registry []*Profile, cert *x509.Certificate) ProfileSelection {
	selection := ProfileSelection{Reason: SelectUnclaimed}
	t, ok := DetectCertificateType(cert)
	if !ok {
		selection.Detail = "the certificate type is not detected"
		return selection
	}
	selection.CertType = t

	var byType, withRole, matched []*Profile
	for _, p := range registry {
		if !p.Accepts(t) {
			continue
		}
		byType = append(byType, p)
		if p.matches(cert) {
			matched = append(matched, p)
			if len(p.RequiredRoleOIDs) > 0 {
				withRole = append(withRole, p)
			}
		}
	}
	if len(byType) == 0 {
		selection.Detail = fmt.Sprintf("no profile accepts type %s", t)
		return selection
	}
	switch len(withRole) {
	case 0:
	case 1:
		selection.Profile = withRole[0]
		selection.Reason = SelectByCert
		selection.Detail = "asserts role " + oid.Format(withRole[0].RequiredRoleOIDs[0])
		return selection
	default:
		selection.Reason = SelectAmbiguous
		selection.Candidates = withRole
		selection.Detail = "several profiles match the certificate's roles"
		return selection
	}
	for _, p := range registry {
		if slices.Contains(p.DefaultFor, t) {
			selection.Profile = p
			selection.Reason = SelectByDefault
			selection.Detail = fmt.Sprintf("default for type %s", t)
			return selection
		}
	}
	switch len(matched) {
	case 0:
		selection.Candidates = byType
		selection.Detail = fmt.Sprintf("type %s is accepted by profiles, but the certificate asserts none of their roles", t)
	case 1:
		selection.Profile = matched[0]
		selection.Reason = SelectByCert
		selection.Detail = fmt.Sprintf("the only profile that accepts type %s", t)
	default:
		selection.Reason = SelectAmbiguous
		selection.Candidates = matched
		selection.Detail = fmt.Sprintf("type %s matches several profiles and none owns it", t)
	}
	return selection
}
