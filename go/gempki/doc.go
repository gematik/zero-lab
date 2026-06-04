// Package gempki is a Go validation library for the gematik
// Telematikinfrastruktur (TI) public-key infrastructure.
//
// The library validates X.509 certificate chains against the TI-PKI's
// rules: only ECC (Brainpool P-256r1/P-384r1, NIST P-256/P-384) keys, real
// chain construction through TSL-published intermediates, revocation via
// OCSP and/or hash lists, role-OID and certificate-policy checks per
// gemSpec_OID, and named profiles for the common TI use cases (SMC-B
// authentication, qualified signatures, component certs, IDP authenticity).
//
// # Quick start
//
//	import "github.com/gematik/zero-lab/go/gempki"
//
//	ts, _ := gempki.EmbeddedLoader{Env: gempki.EnvProd}.Load(ctx)
//	v := gempki.ProfileSMCBAuth(ts)
//	result, _ := v.ValidatePEM(ctx, certPEM)
//	if !result.Valid {
//	    log.Printf("rejected: %v", result.Errors)
//	}
//
// # The root-anchor strategy
//
// Trust always starts at a hardcoded anchor. The library accepts exactly
// one root certificate per environment on faith — compiled into the binary
// as a base64-encoded DER constant in truststore_loader.go:
//
//	trustAnchorTestB64   → GEM.RCA8 TEST-ONLY (brainpool P-256r1)
//	trustAnchorDevRefB64 → GEM.RCA7 TEST-ONLY
//	trustAnchorProdB64   → GEM.RCA8 (brainpool P-256r1)
//
// EnvDev and EnvRef share one anchor (gematik distributes a single root for
// both). Test and Prod each have their own. The anchors are taken straight
// from gematik's public distribution; if gematik rotates one, the constant
// is updated and the library is rebuilt — there is no runtime override of
// the anchor itself.
//
// Every other root that ends up in the [TrustStore] earns its place by
// chaining back to the anchor via the gematik A_28419 cross-certificate
// protocol (implemented in crosscert.go's verifyCrossSignedAt). For each
// candidate root, seven checks run against a cross certificate:
//
//  1. cross is signed by a known anchor;
//  2. cross is currently within its validity window;
//  3. cross's subject CommonName matches GEM.RCA<digits>;
//  4. cross's SubjectKeyIdentifier equals the candidate root's;
//  5. cross's CommonName equals the candidate root's;
//  6. cross's public key bytes equal the candidate root's;
//  7. the candidate root's self-signature verifies under the cross cert.
//
// The roots.json file (gematik publishes one per environment) packages a
// list of candidate roots together with these cross certificates. The
// loader walks the anchor's "next" chain forward to absorb rollover
// successors and its "prev" chain backward to absorb the surviving
// predecessors. The result is an immutable [TrustStore] that knows nothing
// the anchor did not implicitly bless.
//
// # ECC-only and what it means for legacy roots
//
// Per gemSpec_Krypt the TI-PKI is ECC-only. The library enforces this
// uniformly: any RSA key, any RSA-based signature algorithm, returns
// [ErrRSANotSupported]. There is no flag to disable the policy.
//
// In practice this interacts with the cross-cert walk in two ways:
//
//   - Legacy RSA roots in roots.json (GEM.RCA1, GEM.RCA2 in the published
//     data) are dropped at parse time and never enter the TrustStore.
//   - When the backward walk reaches a cross certificate signed by an RSA
//     key, the walk stops gracefully. This can leave perfectly valid
//     earlier ECC roots out of reach — RCA5 in the test environment is
//     such a case, isolated from the RCA8 anchor by an RSA-signed bridge.
//
// Callers who need a wider root set than EmbeddedLoader exposes have two
// options. They can build a [TrustStore] directly with [NewTrustStore]
// from a caller-supplied slice of *x509.Certificate (the simplest path for
// airgap deployments that ship their own trust bundle). Or they can
// implement the [Loader] interface and decide what cross-cert acceptance
// means for their use case.
//
// # Loader and Holder
//
// The standard sources of trust-store data are layered:
//
//	┌──────────────────────────────────────────────────────────────────┐
//	│  Loader interface — produces a *TrustStore                       │
//	├──────────────────────────────────────────────────────────────────┤
//	│  EmbeddedLoader    compile-time roots-*.json                     │
//	│  FileLoader        caller-supplied path + caller-supplied anchor │
//	│  NetworkLoader     fetch with caller-supplied *http.Client + ctx │
//	│  CompositeLoader   try in order, first success wins              │
//	└──────────────────────────────────────────────────────────────────┘
//	                             │
//	                             ↓ Load(ctx)
//	                       *TrustStore (immutable)
//	                             │
//	                             ↓ install into
//	                  ┌──────────────────────────┐
//	                  │  *TrustStoreHolder        │
//	                  │   atomic.Pointer swap     │  ← refresh-friendly
//	                  └──────────────────────────┘
//	                             ↑ Current()
//	                       *Validator
//
// [TrustStore] is immutable; concurrent reads from many goroutines are
// free. The dynamic dimension lives in [TrustStoreHolder]: an
// atomic.Pointer that a refresh job swaps whenever [TrustStoreHolder.Reload]
// succeeds. Validators wired with [WithTrustStoreHolder] read through the
// holder on every Validate call, so a successful refresh propagates to
// in-flight callers on the next request.
//
// Failed refresh keeps the existing store. [TrustStoreHolder.Set] rejects
// nil so a botched reload can never silently disarm the validator.
//
// # TSL is not a trust source for end-entity validation
//
// The Trust Service Status List that gematik publishes (~580 KB XML
// listing ~110 SubCAs and their statuses) is consumed via [LoadTSL] +
// [IntermediateCAsFromTSL] and fed to [Validator.Validate] as the
// *intermediates* slice — never to [NewTrustStore]. The TSL says which
// SubCAs gematik currently sanctions; trust still flows from the GEM.RCA<n>
// anchor at the root of the chain.
//
// # TSL signature verification
//
// The TSL XML is double-signed: an inline XMLDSig/XAdES envelope inside the
// XML body AND a separate detached signature in a `.sig` file on the same
// download point. gempki deliberately does NOT support XMLDSig — verifying
// it correctly requires parsing the attacker-controlled XML and threading
// XAdES qualifying properties. Instead, gempki verifies the detached
// signature only ([TSLDetachedSignature], [VerifyTSLDetachedSignature]),
// which uses a custom gematik container (DER SEQUENCE of three elements:
// AlgorithmIdentifier{ecdsaWithSHA256}, ECDSA-Sig-Value, signer cert)
// designed to be safely parseable with fixed offsets.
//
// The TSL-Signer-CA is structurally a SubCA under one of the GEM.RCA<n>
// Komponenten-PKI roots (GEM.TSL-CA3 in prod, for instance, is issued by
// GEM.RCA4). For the purpose of TSL signature verification we treat the
// TSL-Signer-CA as its own trust anchor — vendored separately in
// tsl_anchors.go — so callers don't need the full Komponenten-PKI trust
// store loaded to verify a TSL.
//
// The same "vendor one anchor per environment" strategy used for the
// GEM.RCA<n> roots applies: [EmbeddedTSLSignerAnchor] returns the
// product-provisioned anchor, and [EmbeddedTSLSignerLoader] returns a
// [*TrustStore] suitable for passing to [VerifyTSLDetachedSignature]. When
// gematik publishes additional reachable TSL-Signer-CA standalone roots
// alongside cross-certs (current ECC distribution publishes one per env),
// the same A_28419 cross-cert walker used for the Komponenten-PKI roots
// will extend [EmbeddedTSLSignerLoader] — no additional plumbing needed.
//
// For TSL trust-anchor ROTATION (gematik's TUC_PKI_013 "Import
// TI-Vertrauensanker aus TSL"): the current TSL announces any future
// TSL-Signer-CA inside its body via TSPService entries with
// [ServiceTypeTSLServiceCertChange]. After verifying a TSL's detached
// signature with the currently-trusted anchor, callers may extract those
// announced future anchors via [TSLSignerCertCandidates] and pre-stage
// them for the next TSL update. Verifying the announced anchor from an
// unverified TSL would be an attacker-supplied trust source; ordering
// matters and is the caller's responsibility.
//
// # Environments
//
// [Environment] (EnvDev / EnvRef / EnvTest / EnvProd) is a single switch
// over the data source: which hardcoded anchor, which embedded roots.json,
// which network URL. It is decided at validator construction so an
// EnvTest validator cannot be reconfigured into an EnvProd validator at
// runtime.
//
// # Where to look
//
// Anchor data and accessors:                    truststore_loader.go
// TSL-Signer-CA anchors:                        tsl_anchors.go
// A_28419 cross-cert verification:              crosscert.go
// TrustStore type:                              truststore.go
// Hot-swap holder:                              truststore_holder.go
// Chain construction:                           chain.go
// Path validation (RFC 5280 §6):                path.go
// Revocation orchestration:                     revocation.go
// OCSP / hash list checkers:                    ocsp.go, hashlist.go
// Per-cert checks (KU, EKU, role, policy):      checks.go, roleoid.go, policy.go
// Validator + functional options:               validate.go
// Named profiles:                               profile.go
// Observation hooks:                            hooks.go
// gemSpec_OID constants:                        oids.go
// TSL parsing / fetch:                          tsl.go
// TSL helpers (intermediate extraction):        tsl_helpers.go
// TSL detached signature verify:                tsl_signature.go
package gempki
