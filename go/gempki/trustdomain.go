package gempki

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// TrustDomain is the coarse split between gematik's production TI and its
// non-production environments.
//
// It stops at prod vs non-prod on purpose: dev and ref are one and the same
// trust domain (identical anchor, roots and TSL — see [trustAnchorB64For]), and
// ref and test publish the same GEM.RCA* TEST-ONLY roots, so no amount of
// inspection separates the three. Pinning the environment beyond this needs
// the TSL of a specific environment, which is the caller's business.
type TrustDomain string

const (
	// TrustDomainUnknown means detection found no evidence either way. It is
	// never a synonym for non-prod — see [DetectTrustDomain].
	TrustDomainUnknown TrustDomain = ""
	TrustDomainProd    TrustDomain = "prod"
	TrustDomainNonProd TrustDomain = "nonprod"
)

// TrustDomainMethod names the evidence that decided a [TrustDomainResult].
type TrustDomainMethod string

const (
	MethodNone         TrustDomainMethod = ""
	MethodRootIdentity TrustDomainMethod = "root-identity"
	MethodChain        TrustDomainMethod = "chain"
	MethodMarkers      TrustDomainMethod = "markers"
)

// TrustDomainResult is what [DetectTrustDomain] returns: the verdict, the
// evidence behind it, and a step-by-step trace of everything that was tried.
// The trace is there so a caller can explain a failure without re-running the
// detection itself.
type TrustDomainResult struct {
	Domain TrustDomain
	Method TrustDomainMethod
	// Detail is a one-line description of the deciding evidence, e.g.
	// `root "GEM.RCA8" is a prod trust anchor`.
	Detail string
	Steps  []TrustDomainStep
}

// TrustDomainStep is one attempted detection phase and how it went.
type TrustDomainStep struct {
	Method  TrustDomainMethod
	Outcome string
}

func (r TrustDomainResult) add(m TrustDomainMethod, format string, args ...any) TrustDomainResult {
	r.Steps = append(r.Steps, TrustDomainStep{Method: m, Outcome: fmt.Sprintf(format, args...)})
	return r
}

func (r TrustDomainResult) decide(d TrustDomain, m TrustDomainMethod, format string, args ...any) TrustDomainResult {
	r.Domain = d
	r.Method = m
	r.Detail = fmt.Sprintf(format, args...)
	return r.add(m, "%s", r.Detail)
}

// DetectTrustDomain works out whether certs belong to the production TI or to
// one of the test environments. It is entirely offline: the only trust material
// it consults is the compiled-in roots ([EmbeddedLoader]).
//
// certs is a chain in leaf-first order, as returned by [ParsePEMCertificates];
// supplying the issuing CA alongside the leaf lets the chain phase decide, which
// is stronger evidence than the naming conventions the marker phase falls back
// on.
//
// Three phases, first hit wins:
//
//  1. root identity — any input cert that *is* an embedded root;
//  2. chain — the leaf chains to an embedded root through the supplied
//     intermediates;
//  3. markers — gematik's naming conventions (TEST-ONLY, NOT-VALID) and the
//     OCSP/CRL hostnames in the certificates.
//
// The marker phase is deliberately asymmetric. A TEST-ONLY marker is conclusive
// evidence of non-prod, but the *absence* of one is not evidence of prod: any
// self-signed cert from anywhere would otherwise be read as production TI. Prod
// is concluded only from the roots, or from a TI hostname carrying no non-prod
// marker.
//
// A zero Domain ([TrustDomainUnknown]) means undecidable, not non-prod. Callers
// must treat it as "ask the user", and can render Steps to say what was tried.
func DetectTrustDomain(certs []*x509.Certificate) TrustDomainResult {
	var res TrustDomainResult
	if len(certs) == 0 {
		return res.add(MethodNone, "no certificates supplied")
	}

	prod, nonProd, err := embeddedStores()
	if err != nil {
		// Embedded data is compiled in; a failure here is a build problem, not
		// a user problem. Degrade to the marker phase rather than give up.
		return detectByMarkers(res.add(MethodRootIdentity, "unavailable: %v", err), certs)
	}

	res, decided := detectByRootIdentity(res, certs, prod, nonProd)
	if decided {
		return res
	}
	res, decided = detectByChain(res, certs, prod, nonProd)
	if decided {
		return res
	}
	return detectByMarkers(res, certs)
}

// embeddedStores loads the two trust stores detection compares against. The
// non-prod store merges dev/ref and test: their roots overlap, so a hit in
// either says the same thing.
func embeddedStores() (prod, nonProd *TrustStore, err error) {
	ctx := context.Background()
	prod, err = EmbeddedLoader{Env: EnvProd}.Load(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("prod roots: %w", err)
	}
	devRef, err := EmbeddedLoader{Env: EnvRef}.Load(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("ref roots: %w", err)
	}
	test, err := EmbeddedLoader{Env: EnvTest}.Load(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("test roots: %w", err)
	}
	nonProd, err = NewTrustStore(append(devRef.Roots(), test.Roots()...))
	if err != nil {
		return nil, nil, fmt.Errorf("merging non-prod roots: %w", err)
	}
	return prod, nonProd, nil
}

func detectByRootIdentity(res TrustDomainResult, certs []*x509.Certificate, prod, nonProd *TrustStore) (TrustDomainResult, bool) {
	for _, c := range certs {
		if root, ok := prod.BySKI(c.SubjectKeyId); ok && root.Equal(c) {
			return res.decide(TrustDomainProd, MethodRootIdentity,
				"%q is a prod trust anchor", c.Subject.CommonName), true
		}
		if root, ok := nonProd.BySKI(c.SubjectKeyId); ok && root.Equal(c) {
			return res.decide(TrustDomainNonProd, MethodRootIdentity,
				"%q is a non-prod trust anchor", c.Subject.CommonName), true
		}
	}
	return res.add(MethodRootIdentity, "no input certificate is an embedded root"), false
}

func detectByChain(res TrustDomainResult, certs []*x509.Certificate, prod, nonProd *TrustStore) (TrustDomainResult, bool) {
	leaf, intermediates := certs[0], certs[1:]
	if chain, err := BuildChain(leaf, intermediates, prod, BuildChainOptions{}); err == nil {
		return res.decide(TrustDomainProd, MethodChain,
			"chains to prod root %q", chain[len(chain)-1].Subject.CommonName), true
	}
	chain, err := BuildChain(leaf, intermediates, nonProd, BuildChainOptions{})
	if err == nil {
		return res.decide(TrustDomainNonProd, MethodChain,
			"chains to non-prod root %q", chain[len(chain)-1].Subject.CommonName), true
	}
	if errors.Is(err, ErrChainIncomplete) {
		return res.add(MethodChain, "incomplete: the issuer of %q was not supplied", leaf.Subject.CommonName), false
	}
	return res.add(MethodChain, "failed: %v", err), false
}

// Naming conventions gematik applies to every non-production TI certificate:
// CAs and end entities carry TEST-ONLY in the CommonName and NOT-VALID in the
// Organization, and their OCSP/CRL endpoints sit on -test/-ref hostnames.
const (
	markerTestOnly = "TEST-ONLY"
	markerNotValid = "NOT-VALID"
)

func detectByMarkers(res TrustDomainResult, certs []*x509.Certificate) TrustDomainResult {
	var prodHost string
	for _, c := range certs {
		if m, where := nonProdMarker(c); m {
			return res.decide(TrustDomainNonProd, MethodMarkers, "%s", where)
		}
		if prodHost == "" {
			prodHost = tiHost(c)
		}
	}
	if prodHost != "" {
		return res.decide(TrustDomainProd, MethodMarkers,
			"revocation endpoint %q is a production TI host and no TEST-ONLY marker is present", prodHost)
	}
	return res.add(MethodMarkers, "no TEST-ONLY/NOT-VALID marker and no TI revocation endpoint")
}

// nonProdMarker reports whether c carries a non-prod naming marker, and where.
func nonProdMarker(c *x509.Certificate) (bool, string) {
	if strings.Contains(c.Subject.CommonName, markerTestOnly) {
		return true, fmt.Sprintf("subject CN %q carries %s", c.Subject.CommonName, markerTestOnly)
	}
	if strings.Contains(c.Issuer.CommonName, markerTestOnly) {
		return true, fmt.Sprintf("issuer CN %q carries %s", c.Issuer.CommonName, markerTestOnly)
	}
	for _, o := range c.Subject.Organization {
		if strings.Contains(o, markerNotValid) {
			return true, fmt.Sprintf("subject O %q carries %s", o, markerNotValid)
		}
	}
	for _, o := range c.Issuer.Organization {
		if strings.Contains(o, markerNotValid) {
			return true, fmt.Sprintf("issuer O %q carries %s", o, markerNotValid)
		}
	}
	for _, raw := range revocationURLs(c) {
		if h := hostOf(raw); isNonProdHost(h) {
			return true, fmt.Sprintf("revocation endpoint %q is a test host", h)
		}
	}
	return false, ""
}

// tiHost returns the first revocation hostname under gematik's TI domain, or
// "" when the certificate names none.
func tiHost(c *x509.Certificate) string {
	for _, raw := range revocationURLs(c) {
		if h := hostOf(raw); strings.HasSuffix(h, ".ti-dienste.de") {
			return h
		}
	}
	return ""
}

func revocationURLs(c *x509.Certificate) []string {
	urls := make([]string, 0, len(c.OCSPServer)+len(c.IssuingCertificateURL)+len(c.CRLDistributionPoints))
	urls = append(urls, c.OCSPServer...)
	urls = append(urls, c.IssuingCertificateURL...)
	urls = append(urls, c.CRLDistributionPoints...)
	return urls
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// isNonProdHost matches the hostnames gematik uses for the test environments —
// ocsp-testref.root-ca…, download-ref.crl…, download-test.tsl… — without
// matching a production host that merely contains the letters "test".
func isNonProdHost(host string) bool {
	if !strings.HasSuffix(host, ".ti-dienste.de") {
		return false
	}
	label, _, _ := strings.Cut(host, ".")
	for _, suffix := range []string{"-testref", "-test", "-ref"} {
		if strings.HasSuffix(label, suffix) {
			return true
		}
	}
	return false
}
