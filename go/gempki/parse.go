package gempki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/gematik/zero-lab/go/brainpool"
)

// ParseCertificate parses a single DER-encoded X.509 certificate.
//
// It delegates to the sibling brainpool package's parser, which falls back to
// the standard library when the certificate isn't on a Brainpool curve.
// Any key type the brainpool/stdlib parsers accept is returned; trust comes
// from anchor selection in [TrustStore], not from a parse-time key-type gate.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := brainpool.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("gempki: parse certificate: %w", err)
	}
	return cert, nil
}

// ParsePEMCertificates parses one or more PEM-encoded certificates.
// Non-CERTIFICATE blocks (e.g. EC PRIVATE KEY) are skipped. Empty input or
// input with no CERTIFICATE blocks returns an empty slice and no error —
// callers that require ≥1 certificate must check the result length.
func ParsePEMCertificates(p []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := p
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}
