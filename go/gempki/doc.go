// Package gempki validates X.509 certificates against the rules of the
// gematik Telematikinfrastruktur (TI) PKI: chains built through the
// intermediates the TSL publishes up to gematik's root anchors, RFC 5280
// path checks, OCSP revocation, and the role-OID and certificate-policy
// requirements gemSpec_OID attaches to each certificate type — packaged as
// named profiles for the common TI use cases.
//
// # Quick start
//
//	import (
//		"github.com/gematik/zero-lab/go/gempki"
//		"github.com/gematik/zero-lab/go/gempki/tsl"
//	)
//
//	ts, _ := gempki.EmbeddedRoots(gempki.EnvProd)          // or FetchRoots(ctx, env, client)
//	list, _ := tsl.Load(ctx, client, tsl.URLProd)
//	var intermediates []*x509.Certificate
//	for _, ca := range tsl.IntermediateCAs(list) {
//		intermediates = append(intermediates, ca.Cert)
//	}
//
//	certs, _ := gempki.ParsePEMCertificates(pemBytes)      // leaf first
//	sel := gempki.SelectProfileForCert(certs[0])           // e.g. smb-aut for a C.HCI.AUT
//	v := sel.Profile.Validator(ts, sel.Type)
//	v.Revocation = &gempki.OCSPChecker{HTTPClient: client}
//	result, _ := v.Validate(ctx, append(certs, intermediates...))
//	if !result.Valid {
//		log.Printf("rejected: %v", result.Errors)
//	}
//
// # Trust anchors
//
// Trust starts at one root certificate per environment, compiled into the
// binary in anchors.go: GEM.RCA8 for prod, GEM.RCA7 TEST-ONLY for dev/ref,
// GEM.RCA8 TEST-ONLY for test. They are taken straight from gematik's
// distribution; if gematik rotates one, the constant changes and the
// library is rebuilt. Every other root in a [TrustStore] earns its place
// by chaining back to the anchor through the A_28419 cross-certificate
// protocol — seven checks per candidate, implemented step by step in
// roots.go so the code can be read against gemSpec_PKI. [EmbeddedRoots]
// runs that walk over the compiled-in roots.json; [FetchRoots] runs it
// over a freshly downloaded one, against the same anchor.
//
// The TSL is not a trust source. It names the SubCAs gematik currently
// sanctions and the OCSP responders allowed to answer for them, and that
// is what package tsl extracts; trust still flows from the anchor.
//
// # Validation
//
// A [Validator] is a struct: fill in the trust store, the revocation policy
// and the end-entity requirements, then call [Validator.Validate]. Validate
// runs [BuildChain] (topology only), [ValidatePath] (RFC 5280 §6 plus the
// end-entity checks) and the revocation check, and folds every finding
// into one [ValidationResult] — Valid, Errors with an [ErrorCode] each,
// Warnings, and the built chain with its positions.
//
// Revocation is decided by one table, in revocation.go:
//
//	outcome                          HardFail  SoftFail
//	Good                             —         —
//	Revoked                          error     error
//	Unknown / responder unavailable  error     warning
//	responder untrusted / invalid    error     error
//
// The last row is deliberate: a response that failed authorization or
// signature verification is evidence of something wrong, not of a flaky
// responder, and no mode turns it into a warning. The zero Validator is
// HardFail with no checker, which fails closed.
//
// # Profiles and types
//
// [CertificateType] is the gemSpec_PKI Tab_PKI_405 type — C.HCI.AUT,
// C.FD.SIG and so on — with the baseline every certificate of that type must
// satisfy in [CertificateType.Spec], transcribed from gemSpec_PKI's profile
// tables for all 23 types (ECDSA branch; every value is a floor the checks
// require, never an equality). [DetectCertificateType] reads the type off a
// certificate's policies, falling back to the admission extension; the role
// lists it detects with are the ones the baselines validate with.
//
// A [Profile] is a validation strategy for one TI use case: the types it
// accepts, its revocation strictness, and optionally the admission role
// that identifies it. Four are registered ([Profiles]): smb-aut, idp-sig,
// epa-vau-aut and zeta-guard-aut. [SelectProfileForCert] is what "pick the
// profile automatically" means — a profile matched on its role beats one
// that merely owns the type, and an ambiguous or unclaimed certificate is
// reported as such rather than guessed at.
//
// # Environments
//
// [Environment] selects the anchors, the embedded roots and the download
// endpoints. dev and ref are one entry — gematik distributes a single set
// for both. [DetectTrustDomain] tells prod material from non-prod material
// offline; finer than that a certificate cannot say, since ref and test
// publish the same roots.
//
// # Subpackages
//
//   - oid: the OIDs of gemSpec_OID Tab_PKI_401–406, each declared with the
//     spec's reference name and description ([oid.Lookup], [oid.Format]).
//   - tsl: the Trust Service Status List — schema, loading, the detached
//     signature, and extraction of intermediates and responders.
//
// # Crypto
//
// ECDSA on Brainpool (P-256r1, P-384r1) and NIST (P-256, P-384) curves is
// handled throughout via the sibling brainpool package. RSA is accepted
// too: the historical roots GEM.RCA1/2/6 are RSA-keyed and must remain
// loadable for chains issued under them. The one RSA gap is the TSL
// detached signature, whose RSA-PSS container tsl does not decode.
//
// # Where to look
//
//	anchors.go            Environment, the per-environment table, the compiled-in anchors
//	roots.go              roots.json, the A_28419 cross-cert walk, EmbeddedRoots / FetchRoots
//	truststore.go         TrustStore
//	chain.go              BuildChain, signature verification between links
//	path.go               ValidatePath (RFC 5280 §6)
//	checks.go             CertificateCheck and the key-usage / policy / role checks
//	key.go                ClassifyKey, the gemSpec_Krypt key admissibility tiers
//	validate.go           Validator
//	revocation.go         RevocationChecker, RevocationMode, the mode table
//	ocsp.go               OCSPChecker, including Brainpool responder handling
//	ocsp_certid.go        CertID and certHash verification of a response
//	errors.go             ErrorCode, ValidationError, ValidationResult
//	cert_type.go          CertificateType and its Tab_PKI_405 table
//	cert_type_detect.go   DetectCertificateType
//	admission.go          ParseAdmissionStatement
//	profile.go            Profile and the registry
//	profile_select.go     SelectProfileForCert, ProfilesForCert, ProfilesForType
//	trustdomain.go        DetectTrustDomain
//	parse.go              ParseCertificate, ParsePEMCertificates
package gempki
