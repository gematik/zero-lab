package gempki

import (
	"crypto/x509"
	"fmt"
)

// VerifyCertificateSignature checks that child was signed by parent's private key.
//
// Both public keys must be one of the TI-PKI's allowed types (ECDSA on an
// allowed curve, or RSA). The signature itself is verified via the standard
// library, which handles ECDSA (including Brainpool) and RSA / RSA-PSS
// uniformly through [x509.Certificate.CheckSignatureFrom].
func VerifyCertificateSignature(child, parent *x509.Certificate) error {
	if child == nil {
		return fmt.Errorf("gempki: nil child certificate")
	}
	if parent == nil {
		return fmt.Errorf("gempki: nil parent certificate")
	}
	if err := child.CheckSignatureFrom(parent); err != nil {
		return fmt.Errorf("gempki: signature verification failed for %q (issuer %q): %w",
			child.Subject.CommonName, parent.Subject.CommonName, err)
	}
	return nil
}
