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

package titls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"slices"
	"time"

	"github.com/gematik/zero-lab/go/tipki"
)

// TIStatusReuse is OCSP-005's hour: how long a ti verdict rests on its OCSP answer (TLSV-051).
const TIStatusReuse = time.Hour

// DefaultRevocationTimeout bounds the revocation fetches of one handshake unless told otherwise.
const DefaultRevocationTimeout = 10 * time.Second

// Options are what a verifier lets the host choose: the trust material, the OCSP grace period and the
// clock (TLSV-002), and the resources it spends. None of them skips a rule.
type Options struct {
	// Now is the clock; nil means time.Now. The configurations hand it to crypto/tls as well.
	Now func() time.Time
	// RevocationTimeout bounds the OCSP and CRL fetches of one handshake, which crypto/tls gives no
	// context for; zero means [DefaultRevocationTimeout].
	RevocationTimeout time.Duration
	// CacheSize is how many accepted verdicts are kept for reuse; zero means [DefaultCacheSize], a
	// negative size keeps none.
	CacheSize int
	// OCSPGrace is the ti profile's grace period for a stapled response; zero means
	// [tipki.DefaultOCSPGrace]. The web profile ignores it.
	OCSPGrace time.Duration
}

func (o Options) now() func() time.Time {
	if o.Now == nil {
		return time.Now
	}
	return o.Now
}

func (o Options) timeout() time.Duration {
	if o.RevocationTimeout <= 0 {
		return DefaultRevocationTimeout
	}
	return o.RevocationTimeout
}

// TLSV-010 and TLSV-011: what both profiles offer.
var (
	versions = [2]uint16{tls.VersionTLS12, tls.VersionTLS13}
	// cipherSuites are TLS 1.2's; crypto/tls does not let TLS 1.3's be chosen.
	cipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
	tls13Suites = []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384}
	// TLSV-012: crypto/tls has no brainpool groups.
	curves = []tls.CurveID{tls.CurveP256, tls.CurveP384}
)

// negotiated holds a connection to TLSV-010 and TLSV-011 where crypto/tls offers more than they allow:
// TLS 1.3's ChaCha20-Poly1305 suite cannot be left out of the offer, so it is refused when chosen.
func negotiated(cs tls.ConnectionState) error {
	if !slices.Contains(versions[:], cs.Version) {
		return &RefusedError{refuse(Invalid, fmt.Sprintf("TLS version %#04x is not allowed (TLSV-010)", cs.Version))}
	}
	if !slices.Contains(cipherSuites, cs.CipherSuite) && !slices.Contains(tls13Suites, cs.CipherSuite) {
		return &RefusedError{refuse(Invalid, tls.CipherSuiteName(cs.CipherSuite)+" is not allowed (TLSV-011)")}
	}
	return nil
}

// rawChain is the presented chain as the server sent it.
func rawChain(certs []*x509.Certificate) [][]byte {
	chain := make([][]byte, len(certs))
	for i, cert := range certs {
		chain[i] = cert.Raw
	}
	return chain
}

// verifyConnection is the check every configuration runs, on full and on resumed handshakes alike:
// crypto/tls calls VerifyConnection on both.
func verifyConnection(timeout time.Duration, now func() time.Time, verify func(ctx context.Context, chain [][]byte, host string, stapled []byte, now time.Time) Verdict) func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if err := negotiated(cs); err != nil {
			return err
		}
		// TLSV-024: the reference identity is the name the client asked for. crypto/tls reports it without
		// a trailing dot, and not for an IP address, which it sends no SNI for; such a connection has no
		// name to check and is refused.
		if cs.ServerName == "" {
			return &RefusedError{refuse(NameMismatch, "no server name to check the certificate against")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		verdict := verify(ctx, rawChain(cs.PeerCertificates), cs.ServerName, cs.OCSPResponse, now())
		if !verdict.Valid() {
			return &RefusedError{verdict}
		}
		return nil
	}
}

// TiVerifier is the ti profile for TLS: tipki's [tipki.ServerCheck] over the current snapshot of a
// [TrustSource], with reuse of accepted verdicts. Safe for concurrent use.
type TiVerifier struct {
	source    *TrustSource
	responder tipki.RevocationChecker
	grace     time.Duration
	now       func() time.Time
	timeout   time.Duration
	verdicts  *verdictCache
}

// NewTiVerifier is the verifier over source, asking responder when no stapled response holds: usually
// tipki.NewOCSPChecker(OCSPTransport(fetcher)) over the host's HTTP. A nil responder leaves only stapled
// responses.
func NewTiVerifier(source *TrustSource, responder tipki.RevocationChecker, opts Options) *TiVerifier {
	grace := opts.OCSPGrace
	if grace <= 0 {
		grace = tipki.DefaultOCSPGrace
	}
	return &TiVerifier{
		source: source, responder: responder, grace: grace,
		now: opts.now(), timeout: opts.timeout(), verdicts: newVerdictCache(opts.CacheSize),
	}
}

// Verify judges a server as the handshake does: chain is DER, end entity first. A verdict reached with the
// same chain, host and trust snapshot is reused while it may be (TLSV-050, TLSV-051).
func (v *TiVerifier) Verify(ctx context.Context, chain [][]byte, host string, stapled []byte, now time.Time) Verdict {
	snap := v.source.load()
	key := keyFor("ti", snap.generation, host, chain)
	if reused, ok := v.verdicts.reusable(key, now); ok {
		return reused
	}
	certs := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		cert, err := tipki.ParseCertificate(der)
		if err != nil {
			return refuse(Invalid, "a certificate does not parse: "+err.Error())
		}
		certs[i] = cert
	}
	check := &tipki.ServerCheck{Store: snap.store, OCSPGrace: v.grace}
	ti := check.Verify(ctx, certs, host, stapled, now, v.responder)
	verdict := fromTI(ti)
	if verdict.Valid() {
		verdict.ReusableUntil = tiReusableUntil(ti, now)
		v.verdicts.keep(key, verdict, now)
	}
	return verdict
}

// tiReusableUntil is the earliest of notAfter, the status's nextUpdate and OCSP-005's hour after it was
// produced (TLSV-050, TLSV-051).
func tiReusableUntil(ti tipki.Verdict, now time.Time) time.Time {
	produced := ti.ProducedAt
	if produced.IsZero() {
		produced = now
	}
	until := produced.Add(TIStatusReuse)
	for _, bound := range []time.Time{ti.NotAfter, ti.NextUpdate} {
		if !bound.IsZero() && bound.Before(until) {
			until = bound
		}
	}
	return until
}

// ClientConfig is a client configuration for ti servers: the handshake of TLSV-010 to 012, and the whole
// certificate verification in VerifyConnection. The host sets ServerName, or lets net/http set it, and may
// add NextProtos and client certificates; it must not change the verification fields.
func (v *TiVerifier) ClientConfig() *tls.Config {
	// TLSV-010 to 012. crypto/tls resumes no session without a ClientSessionCache, and none is set
	// (TLSV-014).
	return &tls.Config{
		MinVersion:       versions[0],
		MaxVersion:       versions[1],
		CipherSuites:     slices.Clone(cipherSuites),
		CurvePreferences: slices.Clone(curves),
		Renegotiation:    tls.RenegotiateNever,
		Time:             v.now,
		// crypto/x509 cannot verify the brainpool signatures of the TI's CAs, so crypto/tls must not verify
		// the chain itself; VerifyConnection verifies all of it through tipki, on every handshake, resumed
		// ones included, and refuses an empty server name.
		InsecureSkipVerify: true, //nolint:gosec // G402: the ti profile is verified in full in VerifyConnection (TLSV-030).
		VerifyConnection:   verifyConnection(v.timeout, v.now, v.Verify),
	}
}

// WebVerifier is the web profile for TLS: a [WebCheck], its revocation sources through a [Fetcher], and
// reuse of accepted verdicts. Safe for concurrent use.
type WebVerifier struct {
	check    *WebCheck
	fetch    Fetcher
	now      func() time.Time
	timeout  time.Duration
	verdicts *verdictCache
}

// NewWebVerifier is the verifier for check, reaching responders and CRL hosts through fetch.
func NewWebVerifier(check *WebCheck, fetch Fetcher, opts Options) *WebVerifier {
	return &WebVerifier{
		check: check, fetch: fetch, now: opts.now(), timeout: opts.timeout(),
		verdicts: newVerdictCache(opts.CacheSize),
	}
}

// Verify judges a server as the handshake does: chain is DER, end entity first. A verdict reached with the
// same chain and host is reused while it may be (TLSV-050, TLSV-051).
func (v *WebVerifier) Verify(ctx context.Context, chain [][]byte, host string, stapled []byte, now time.Time) Verdict {
	key := keyFor("web", 0, host, chain)
	if reused, ok := v.verdicts.reusable(key, now); ok {
		return reused
	}
	verdict := v.check.Verify(ctx, chain, host, stapled, now, v.fetch)
	v.verdicts.keep(key, verdict, now)
	return verdict
}

// ClientConfig is a client configuration for web servers: the handshake of TLSV-010 to 012, crypto/tls's
// own verification against the check's roots, and the profile's remaining rules and revocation in
// VerifyConnection. The host sets ServerName, or lets net/http set it, and may add NextProtos and client
// certificates; it must not change the verification fields.
func (v *WebVerifier) ClientConfig() *tls.Config {
	// TLSV-010 to 012, as the ti configuration has them.
	return &tls.Config{
		MinVersion:       versions[0],
		MaxVersion:       versions[1],
		CipherSuites:     slices.Clone(cipherSuites),
		CurvePreferences: slices.Clone(curves),
		Renegotiation:    tls.RenegotiateNever,
		Time:             v.now,
		RootCAs:          v.check.roots,
		VerifyConnection: verifyConnection(v.timeout, v.now, v.Verify),
	}
}
