package gempki

import (
	"crypto/x509"
	"encoding/asn1"
	"net/http"
	"time"
)

// Profile is a named factory that returns a pre-configured [Validator] for
// a specific TI use case. Each profile encodes the required validation
// policy as the corresponding gematik specification mandates it.
//
// Callers may mutate the returned Validator before using it (e.g. swap in
// a custom cache, install hooks, tighten the revocation mode) — the
// profile sets defaults, not a contract.
//
// The base profiles don't wire a network OCSPChecker because that needs a
// caller-supplied *http.Client. Use the *WithOCSP convenience wrappers to
// bundle a checker, or attach one manually via [WithRevocationChecker].
type Profile func(ts *TrustStore) *Validator

// SMC-B institution role OIDs accepted by [ProfileSMCBAuth]. These are the
// institutions that may present an SMC-B for authentication.
var smcbInstitutionRoleOIDs = []asn1.ObjectIdentifier{
	OIDInstArztpraxis,
	OIDInstZahnarztpraxis,
	OIDInstPraxisPsychotherapeut,
	OIDInstKrankenhaus,
	OIDInstOeffentlicheApo,
	OIDInstKrankenhausapotheke,
	OIDInstBundeswehrapotheke,
}

// HBA professional role OIDs accepted by [ProfileQES] for qualified
// signature verification. Restricted to the QES-relevant professions per
// gemSpec_OID Tab_PKI_402.
var hbaQESRoleOIDs = []asn1.ObjectIdentifier{
	OIDProfArzt,
	OIDProfZahnarzt,
	OIDProfApotheker,
	OIDProfPsychotherapeut,
	OIDProfPsPsychotherapeut,
	OIDProfKuJPsychotherapeut,
}

// ProfileSMCBAuth returns a Validator configured for SMC-B-based
// institution authentication (the C.HCI.AUT cert profile).
//
//   - PathValidation:   standard
//   - Revocation:       soft-fail (Unknown becomes a warning, not a failure)
//   - RequiredKeyUsage: digitalSignature
//   - AllowedExtKeyUsages: clientAuth
//   - RequiredRoleOIDs: SMC-B institution OIDs (Tab_PKI_403 subset)
//   - RequiredPolicies: OIDPolicyGemOrCP
func ProfileSMCBAuth(ts *TrustStore) *Validator {
	return NewValidator(
		WithTrustStore(ts),
		WithRevocationMode(RevocationModeSoftFail),
		WithRequiredKeyUsage(x509.KeyUsageDigitalSignature),
		WithAllowedExtKeyUsages(x509.ExtKeyUsageClientAuth),
		WithRequiredRoleOIDs(smcbInstitutionRoleOIDs...),
		WithRequiredPolicies(OIDPolicyGemOrCP),
	)
}

// ProfileQES returns a Validator configured for qualified electronic
// signature verification on HBA-issued certificates (C.HP.QES).
//
//   - PathValidation:   strict
//   - Revocation:       hard-fail (Unknown becomes an error)
//   - RequiredKeyUsage: contentCommitment (nonRepudiation)
//   - RequiredRoleOIDs: HBA professional OIDs (Tab_PKI_402 subset)
//   - RequiredPolicies: OIDPolicyHbaCP + OIDPolicyGemOrCP
func ProfileQES(ts *TrustStore) *Validator {
	return NewValidator(
		WithTrustStore(ts),
		WithRevocationMode(RevocationModeHardFail),
		WithRequiredKeyUsage(x509.KeyUsageContentCommitment),
		WithRequiredRoleOIDs(hbaQESRoleOIDs...),
		WithRequiredPolicies(OIDPolicyHbaCP, OIDPolicyGemOrCP),
	)
}

// ProfileKomponente returns a Validator configured for TI component
// certificates (Fachdienst / ZETA server certs, C.FD.TLS-S et al).
//
//   - PathValidation:    strict
//   - Revocation:        hard-fail
//   - RequiredKeyUsage:  digitalSignature | keyAgreement
//   - AllowedExtKeyUsages: serverAuth
//   - RequiredPolicies:  OIDPolicyGemOrCP
func ProfileKomponente(ts *TrustStore) *Validator {
	return NewValidator(
		WithTrustStore(ts),
		WithRevocationMode(RevocationModeHardFail),
		WithRequiredKeyUsage(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyAgreement),
		WithAllowedExtKeyUsages(x509.ExtKeyUsageServerAuth),
		WithRequiredPolicies(OIDPolicyGemOrCP),
	)
}

// ProfileIDPAuthenticity returns a Validator configured for IDP discovery-
// document and JWKS certificate validation (typically C.FD.SIG / C.FD.TLS-S
// asserting OIDTechRoleIDPD).
//
//   - PathValidation:   strict
//   - Revocation:       hard-fail
//   - RequiredKeyUsage: digitalSignature
//   - RequiredPolicies: OIDPolicyGemOrCP
func ProfileIDPAuthenticity(ts *TrustStore) *Validator {
	return NewValidator(
		WithTrustStore(ts),
		WithRevocationMode(RevocationModeHardFail),
		WithRequiredKeyUsage(x509.KeyUsageDigitalSignature),
		WithRequiredPolicies(OIDPolicyGemOrCP),
	)
}

// WithOCSPNetworkChecker is a convenience for the most common revocation
// wire-up: an [OCSPChecker] that fetches over HTTPS through the supplied
// http.Client. Most production callers want this together with a profile:
//
//	v := gempki.ProfileSMCBAuth(ts)
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
