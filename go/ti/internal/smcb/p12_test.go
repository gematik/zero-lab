package smcb

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"os"
	"testing"
)

// TestP12AuthE2E loads a real PKCS#12 file from disk and exercises the
// identity wiring end-to-end (parse → sign → verify against embedded
// cert). The path is read from TI_TEST_SMCB_P12; without it, the test skips
// cleanly so CI is unaffected.
func TestP12AuthE2E(t *testing.T) {
	path := os.Getenv("TI_TEST_SMCB_P12")
	if path == "" {
		t.Skip("TI_TEST_SMCB_P12 not set; skipping e2e p12 auth test")
	}

	id, err := FromP12(path, DefaultAlias, p12Password.Def)
	if err != nil {
		t.Fatalf("FromP12: %v", err)
	}
	if id.Sign == nil || id.Cert == nil {
		t.Fatal("Sign and Cert must be set")
	}

	cert, err := id.Cert()
	if err != nil {
		t.Fatalf("Cert: %v", err)
	}
	if cert == nil {
		t.Fatal("nil cert")
	}

	// Sign a fresh hash and verify against the certificate's public key.
	msg := []byte("ti epa auth p12 e2e signing canary")
	digest := sha256.Sum256(msg)
	sig, err := id.Sign(digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
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

}
