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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// The variables of the listener (servers.md rule 29, naming-and-config.md).
const (
	listenURLEnv         = "PEP_LISTEN_URL"
	listenPlaintextEnv   = "PEP_LISTEN_PLAINTEXT_ACCEPTED"
	listenCertPathEnv    = "PEP_LISTEN_TLS_CERT_PATH"
	listenKeyPathEnv     = "PEP_LISTEN_TLS_KEY_PATH"
	listenCAPathEnv      = "PEP_LISTEN_TLS_CA_PATH"
	listenPeerNameEnv    = "PEP_LISTEN_TLS_PEER_NAME"
	retiredListenAddrEnv = "PEP_ADDR"
	listenURLExamples    = "http://0.0.0.0:4180 with PEP_LISTEN_PLAINTEXT_ACCEPTED=true behind an edge in another pod, https://0.0.0.0:4180 with PEP_LISTEN_TLS_CERT_PATH and PEP_LISTEN_TLS_KEY_PATH, or http://127.0.0.1:4180 behind an edge in the same pod"
)

// listenSpec is how zero-pep-proxy listens: the address to bind, and the TLS configuration when it terminates TLS.
type listenSpec struct {
	address string
	tls     *tls.Config
	// mode is what the start reports (servers.md rule 7): the scheme, and for plaintext who protects it.
	mode string
}

// listenFromEnv reads the listener from the environment as servers.md rule 29 has it: the URL is the mode; http://
// on a loopback address stays inside the pod, http:// elsewhere only once the operator accepts plaintext, https://
// with the server's own certificate and, with a CA bundle, mutual TLS for the identities named. What rule 17 refuses
// stops the start: no URL, the retired PEP_ADDR, a host name instead of an address, an acceptance that is not exactly
// "true" or that accepts nothing, and a certificate that does not match its key or is not valid at now.
func listenFromEnv(getenv func(string) string, now time.Time) (listenSpec, error) {
	if getenv(retiredListenAddrEnv) != "" {
		return listenSpec{}, fmt.Errorf("%s is replaced by %s, the listener as a URL: %s", retiredListenAddrEnv, listenURLEnv, listenURLExamples)
	}
	raw := getenv(listenURLEnv)
	if raw == "" {
		return listenSpec{}, fmt.Errorf("%s is not set: %s", listenURLEnv, listenURLExamples)
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return listenSpec{}, fmt.Errorf("%s is not a listener URL of scheme, address and port: %s", listenURLEnv, listenURLExamples)
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil || port == "" {
		return listenSpec{}, fmt.Errorf("%s names no port: %s", listenURLEnv, listenURLExamples)
	}
	loopback := false
	if host != "" {
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return listenSpec{}, fmt.Errorf("%s binds an address, not a name; the public name is PEP_PUBLIC_URL's: %s", listenURLEnv, listenURLExamples)
		}
		loopback = addr.IsLoopback()
	}
	accepted, err := plaintextAccepted(getenv(listenPlaintextEnv))
	if err != nil {
		return listenSpec{}, err
	}
	spec := listenSpec{address: u.Host}
	switch u.Scheme {
	case "http":
		switch {
		case loopback && accepted:
			return listenSpec{}, fmt.Errorf("%s accepts nothing for a loopback address, which stays inside the pod: unset it", listenPlaintextEnv)
		case loopback:
			spec.mode = "http on loopback, inside the pod"
		case accepted:
			spec.mode = "http, plaintext accepted by the operator (servers.md rule 29)"
		default:
			return listenSpec{}, fmt.Errorf("%s is plaintext outside the pod: the operator accepts it with %s=true (servers.md rule 29), or listens on https or on loopback", listenURLEnv, listenPlaintextEnv)
		}
	case "https":
		if accepted {
			return listenSpec{}, fmt.Errorf("%s accepts plaintext and %s is https: unset it", listenPlaintextEnv, listenURLEnv)
		}
		config, mode, err := serverTLS(getenv, now)
		if err != nil {
			return listenSpec{}, err
		}
		spec.tls, spec.mode = config, mode
	default:
		return listenSpec{}, fmt.Errorf("%s takes http or https: %s", listenURLEnv, listenURLExamples)
	}
	return spec, nil
}

// plaintextAccepted reads the operator's acceptance like a terms-of-service agreement: one exact value, so that
// neither an empty variable nor a "false" or "yes" reads as consent.
func plaintextAccepted(value string) (bool, error) {
	switch value {
	case "":
		return false, nil
	case "true":
		return true, nil
	default:
		return false, fmt.Errorf("%s: true, or not set", listenPlaintextEnv)
	}
}

// The handshake of gemSpec_Krypt that the listener offers, as the egress client does (servers.md rule 29: constants
// in code, not configuration). crypto/tls offers TLS 1.3's ChaCha20-Poly1305 whatever the list says, so
// VerifyConnection refuses it when chosen.
var (
	listenTLS12Suites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	}
	listenTLS13Suites = []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384}
	listenCurves      = []tls.CurveID{tls.CurveP256, tls.CurveP384}
)

// serverTLS builds the listener's TLS from its files, read once at start (servers.md rule 8).
func serverTLS(getenv func(string) string, now time.Time) (*tls.Config, string, error) {
	certPath, keyPath := getenv(listenCertPathEnv), getenv(listenKeyPathEnv)
	if certPath == "" || keyPath == "" {
		return nil, "", fmt.Errorf("https needs %s and %s", listenCertPathEnv, listenKeyPathEnv)
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, "", fmt.Errorf("%s and %s: %w", listenCertPathEnv, listenKeyPathEnv, err)
	}
	leaf := certificate.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(certificate.Certificate[0]); err != nil {
			return nil, "", fmt.Errorf("%s: %w", listenCertPathEnv, err)
		}
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, "", fmt.Errorf("%s is valid from %s to %s", listenCertPathEnv,
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	config := &tls.Config{
		MinVersion:       tls.VersionTLS12,
		MaxVersion:       tls.VersionTLS13,
		CipherSuites:     slices.Clone(listenTLS12Suites),
		CurvePreferences: slices.Clone(listenCurves),
		Certificates:     []tls.Certificate{certificate},
	}
	mode := "https"
	caPath, peerNames := getenv(listenCAPathEnv), getenv(listenPeerNameEnv)
	var allow []string
	switch {
	case caPath == "" && peerNames == "":
	case caPath == "" || peerNames == "":
		// A valid chain under a shared CA does not say which workload calls, so the allowlist is not optional.
		return nil, "", fmt.Errorf("mutual TLS needs %s and %s together", listenCAPathEnv, listenPeerNameEnv)
	default:
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", listenCAPathEnv, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, "", fmt.Errorf("%s holds no certificate", listenCAPathEnv)
		}
		for name := range strings.SplitSeq(peerNames, ",") {
			if name = strings.TrimSpace(name); name != "" {
				allow = append(allow, name)
			}
		}
		if len(allow) == 0 {
			return nil, "", fmt.Errorf("%s names no identity", listenPeerNameEnv)
		}
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = pool
		mode = "https with mutual TLS"
	}
	// crypto/tls runs VerifyConnection on full and resumed handshakes alike, after it verified the client's chain.
	config.VerifyConnection = func(cs tls.ConnectionState) error {
		if cs.Version == tls.VersionTLS13 && !slices.Contains(listenTLS13Suites, cs.CipherSuite) {
			return fmt.Errorf("%s is not offered", tls.CipherSuiteName(cs.CipherSuite))
		}
		if allow == nil {
			return nil
		}
		if len(cs.PeerCertificates) == 0 || !admitted(cs.PeerCertificates[0], allow) {
			return errors.New("the client's identity is not on the allowlist")
		}
		return nil
	}
	return config, mode, nil
}

// admitted reports whether one of the certificate's DNS names or URIs is on allow, compared exactly.
func admitted(certificate *x509.Certificate, allow []string) bool {
	for _, name := range certificate.DNSNames {
		if slices.Contains(allow, name) {
			return true
		}
	}
	for _, uri := range certificate.URIs {
		if slices.Contains(allow, uri.String()) {
			return true
		}
	}
	return false
}

// listen binds spec's address, with TLS when spec terminates it.
func listen(spec listenSpec) (net.Listener, error) {
	l, err := net.Listen("tcp", spec.address)
	if err != nil {
		return nil, err
	}
	if spec.tls != nil {
		return tls.NewListener(l, spec.tls), nil
	}
	return l, nil
}
