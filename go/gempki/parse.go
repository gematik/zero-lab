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
// manual ASN.1 parsing when the standard library rejects a Brainpool curve.
// The parsed certificate's public key is then validated against the TI-PKI
// crypto policy: only NIST P-256/P-384 and Brainpool P256r1/P384r1 are
// accepted. RSA keys return [ErrRSANotSupported].
//
// This is the single certificate entrypoint callers should use. Internal code
// that calls [x509.ParseCertificate] directly will silently bypass the curve
// policy and fail downstream with worse error messages.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := brainpool.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("gempki: parse certificate: %w", err)
	}
	if err := assertECC(cert.PublicKey); err != nil {
		return nil, fmt.Errorf("gempki: certificate %q: %w", cert.Subject.CommonName, err)
	}
	return cert, nil
}

// ParseCertificates parses a sequence of concatenated DER-encoded certificates.
// Returns an error if any certificate fails to parse or fails the curve policy.
func ParseCertificates(der []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := der
	for len(rest) > 0 {
		// brainpool.ParseCertificate is single-cert; we walk the buffer by
		// parsing one cert at a time using the stdlib to split the stream.
		// crypto/x509.ParseCertificates handles NIST chains but breaks on
		// brainpool — so we step manually via length-prefixed DER walking.
		c, consumed, err := parseOneCertificate(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		rest = rest[consumed:]
	}
	return out, nil
}

// parseOneCertificate parses the first ASN.1 SEQUENCE from buf as a
// certificate and returns the number of bytes consumed. This is what lets
// ParseCertificates walk a concatenated DER stream containing mixed-curve
// certificates without choking on Brainpool.
func parseOneCertificate(buf []byte) (*x509.Certificate, int, error) {
	if len(buf) < 2 {
		return nil, 0, fmt.Errorf("gempki: truncated certificate stream (%d bytes)", len(buf))
	}
	// ASN.1 DER: tag (1 byte), length (1-5 bytes), value.
	// SEQUENCE tag is 0x30. We need to read the length to know cert size.
	if buf[0] != 0x30 {
		return nil, 0, fmt.Errorf("gempki: expected SEQUENCE tag 0x30, got 0x%02x", buf[0])
	}
	length, lengthLen, err := readASN1Length(buf[1:])
	if err != nil {
		return nil, 0, fmt.Errorf("gempki: read certificate length: %w", err)
	}
	total := 1 + lengthLen + length
	if total > len(buf) {
		return nil, 0, fmt.Errorf("gempki: certificate length %d exceeds buffer %d", total, len(buf))
	}
	cert, err := ParseCertificate(buf[:total])
	if err != nil {
		return nil, 0, err
	}
	return cert, total, nil
}

// readASN1Length decodes the BER/DER length octets starting at buf[0] and
// returns the content length plus the number of length octets consumed.
// Supports short form (≤127) and long form (up to 4 length octets).
func readASN1Length(buf []byte) (length, lengthLen int, err error) {
	if len(buf) == 0 {
		return 0, 0, fmt.Errorf("empty length field")
	}
	b0 := buf[0]
	if b0 < 0x80 {
		return int(b0), 1, nil
	}
	n := int(b0 & 0x7f)
	if n == 0 || n > 4 {
		return 0, 0, fmt.Errorf("unsupported indefinite or oversized length (%d octets)", n)
	}
	if len(buf) < 1+n {
		return 0, 0, fmt.Errorf("truncated long-form length")
	}
	for i := 1; i <= n; i++ {
		length = length<<8 | int(buf[i])
	}
	return length, 1 + n, nil
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
