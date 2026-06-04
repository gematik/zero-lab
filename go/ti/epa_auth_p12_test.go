package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"os"
	"testing"
)

// TestP12AuthE2E loads a real PKCS#12 file from disk and exercises the
// SecurityFunctions wiring end-to-end (parse → sign → verify against embedded
// cert). The path is read from TI_TEST_SMCB_P12; without it, the test skips
// cleanly so CI is unaffected.
func TestP12AuthE2E(t *testing.T) {
	path := os.Getenv("TI_TEST_SMCB_P12")
	if path == "" {
		t.Skip("TI_TEST_SMCB_P12 not set; skipping e2e p12 auth test")
	}

	am := newP12AuthMethod(path, authP12AliasDefault, authP12PasswordDefault)
	sf, err := am.SecurityFunctions(context.Background())
	if err != nil {
		t.Fatalf("SecurityFunctions: %v", err)
	}
	if sf.AuthnSignFunc == nil || sf.AuthnCertFunc == nil {
		t.Fatal("AuthnSignFunc and AuthnCertFunc must be set")
	}
	if sf.ProvidePN != nil {
		t.Error("ProvidePN must be nil in v1 (entitlement handled elsewhere)")
	}
	if sf.ProvideHCV != nil {
		t.Error("ProvideHCV must be nil in v1 (entitlement handled elsewhere)")
	}

	cert, err := sf.AuthnCertFunc()
	if err != nil {
		t.Fatalf("AuthnCertFunc: %v", err)
	}
	if cert == nil {
		t.Fatal("nil cert")
	}

	// Sign a fresh hash and verify against the certificate's public key.
	msg := []byte("ti epa auth p12 e2e signing canary")
	digest := sha256.Sum256(msg)
	sig, err := sf.AuthnSignFunc(digest[:])
	if err != nil {
		t.Fatalf("AuthnSignFunc: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("signature is empty")
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("cert public key is %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	// brainpool.SignFunc returns raw R||S (padded to curve byte length), not ASN.1.
	keyBytes := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*keyBytes {
		t.Fatalf("signature length %d, expected %d (raw R||S)", len(sig), 2*keyBytes)
	}
	r := new(big.Int).SetBytes(sig[:keyBytes])
	s := new(big.Int).SetBytes(sig[keyBytes:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("signature did not verify against cert's public key")
	}

	// ClientAssertion uses the same identity in v1.
	caCert, err := sf.ClientAssertionCertFunc()
	if err != nil {
		t.Fatalf("ClientAssertionCertFunc: %v", err)
	}
	if caCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Errorf("ClientAssertion cert serial %s differs from Authn %s",
			caCert.SerialNumber, cert.SerialNumber)
	}
}
