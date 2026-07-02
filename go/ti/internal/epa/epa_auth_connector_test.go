package epa

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"math/big"
	"os"
	"testing"

	"github.com/gematik/zero-lab/go/kon"
	"github.com/gematik/zero-lab/go/ti/internal/common"
)

// TestConnectorAuthE2E exercises the connector auth path end-to-end against a
// real .kon config pointed at a live Konnektor. The path is read from
// TI_TEST_KON_FILE; without it, the test skips so CI stays unaffected.
//
// The test wires global flags `common.ConnectorConfig.Val` (used by common.LoadConnectorConfig
// via the existing `-c` resolution chain) and `authCardFlagVal` (left empty so
// the connector method auto-picks the first SMC-B). It then asks for
// SecurityFunctions, signs a hash via ExternalAuthenticate, and verifies the
// resulting signature against the C.AUT certificate's public key.
func TestConnectorAuthE2E(t *testing.T) {
	konPath := os.Getenv("TI_TEST_KON_FILE")
	if konPath == "" {
		t.Skip("TI_TEST_KON_FILE not set; skipping e2e connector auth test")
	}

	prevConfig := common.ConnectorConfig.Val
	prevCard := authCardFlagVal
	common.ConnectorConfig.Val = konPath
	authCardFlagVal = ""
	t.Cleanup(func() {
		common.ConnectorConfig.Val = prevConfig
		authCardFlagVal = prevCard
	})

	if _, err := kon.ParseDotkon(mustReadFile(t, konPath)); err != nil {
		t.Fatalf("the .kon file at %s does not parse: %v", konPath, err)
	}

	am, err := newConnectorAuthMethod()
	if err != nil {
		t.Fatalf("newConnectorAuthMethod: %v", err)
	}
	sf, err := am.SecurityFunctions(context.Background())
	if err != nil {
		t.Fatalf("SecurityFunctions: %v", err)
	}
	if sf.ProvidePN != nil || sf.ProvideHCV != nil {
		t.Error("ProvidePN and ProvideHCV must be nil in v1")
	}

	cert, err := sf.AuthnCertFunc()
	if err != nil {
		t.Fatalf("AuthnCertFunc: %v", err)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("cert public key is %T; ECC SMC-B expected for this test", cert.PublicKey)
	}

	msg := []byte("ti epa connector auth e2e signing canary")
	digest := sha256.Sum256(msg)
	sig, err := sf.AuthnSignFunc(digest[:])
	if err != nil {
		t.Fatalf("AuthnSignFunc (Konnektor ExternalAuthenticate): %v", err)
	}

	keyBytes := (pub.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*keyBytes {
		t.Fatalf("signature length %d, expected raw R||S = %d", len(sig), 2*keyBytes)
	}
	r := new(big.Int).SetBytes(sig[:keyBytes])
	s := new(big.Int).SetBytes(sig[keyBytes:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("signature did not verify against C.AUT public key")
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return data
}
