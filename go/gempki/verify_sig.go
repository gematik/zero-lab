package gempki

import (
	"crypto/x509"
	"fmt"
)

// VerifyCertificateSignature checks that child was signed by parent's private key.
//
// Three policy gates apply, in order:
//   - both public keys must be ECDSA on an allowed curve ([assertECC]);
//   - child's signature algorithm must be ECDSA — RSA-based algorithms
//     (SHA*WithRSA, SHA*WithRSAPSS) yield [ErrRSANotSupported]. This catches
//     legacy cross-certificates whose subject is ECC but whose issuer signed
//     with RSA;
//   - the signature is verified via the standard library, which is
//     curve-agnostic and handles Brainpool transparently.
//
// Returns [ErrRSANotSupported] (wrapped) for any RSA touchpoint, or a typed
// signature-verification error wrapping the stdlib reason.
func VerifyCertificateSignature(child, parent *x509.Certificate) error {
	if child == nil {
		return fmt.Errorf("gempki: nil child certificate")
	}
	if parent == nil {
		return fmt.Errorf("gempki: nil parent certificate")
	}
	if err := assertECC(child.PublicKey); err != nil {
		return fmt.Errorf("gempki: child %q: %w", child.Subject.CommonName, err)
	}
	if err := assertECC(parent.PublicKey); err != nil {
		return fmt.Errorf("gempki: parent %q: %w", parent.Subject.CommonName, err)
	}
	if isRSASignatureAlgorithm(child.SignatureAlgorithm) {
		return fmt.Errorf("gempki: child %q uses %s signature algorithm: %w",
			child.Subject.CommonName, child.SignatureAlgorithm, ErrRSANotSupported)
	}
	if err := child.CheckSignatureFrom(parent); err != nil {
		return fmt.Errorf("gempki: signature verification failed for %q (issuer %q): %w",
			child.Subject.CommonName, parent.Subject.CommonName, err)
	}
	return nil
}

// isRSASignatureAlgorithm reports whether sigAlg is one of the RSA-based
// signature algorithms defined by [crypto/x509]. Used to stop the cross-cert
// walk when a legacy RSA bridge is encountered.
func isRSASignatureAlgorithm(sigAlg x509.SignatureAlgorithm) bool {
	switch sigAlg {
	case x509.MD2WithRSA,
		x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS,
		x509.SHA384WithRSAPSS,
		x509.SHA512WithRSAPSS:
		return true
	default:
		// ECDSA, DSA, Ed25519, unknown — handled elsewhere (assertECC catches
		// non-ECDSA keys; signature verification flushes out the rest).
		return false
	}
}
