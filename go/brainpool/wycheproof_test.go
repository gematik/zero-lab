package brainpool

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// This validates the production verification path — the standard library's
// crypto/ecdsa.Verify over the brainpoolP256r1 curve — against Project
// Wycheproof's 485 edge-case vectors (zero/overflow r,s, malformed DER, etc.).
// See internal/bp256/testdata/wycheproof/PROVENANCE.md for the source.

const wycheproofPath = "internal/bp256/testdata/wycheproof/ecdsa_brainpoolP256r1_sha256_test.json"

type wpFile struct {
	TestGroups []struct {
		PublicKey struct {
			Uncompressed string `json:"uncompressed"`
		} `json:"publicKey"`
		Tests []struct {
			TcID    int    `json:"tcId"`
			Comment string `json:"comment"`
			Msg     string `json:"msg"`
			Sig     string `json:"sig"`
			Result  string `json:"result"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func parseDERSig(der []byte) (r, s *big.Int, ok bool) {
	input := cryptobyte.String(der)
	var inner cryptobyte.String
	r, s = new(big.Int), new(big.Int)
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) || !input.Empty() {
		return nil, nil, false
	}
	if !inner.ReadASN1Integer(r) || !inner.ReadASN1Integer(s) || !inner.Empty() {
		return nil, nil, false
	}
	return r, s, true
}

func TestWycheproofECDSAVerify(t *testing.T) {
	raw, err := os.ReadFile(wycheproofPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var f wpFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}

	curve := P256r1()
	var total, asserted int
	for gi, g := range f.TestGroups {
		pk, err := hex.DecodeString(g.PublicKey.Uncompressed)
		if err != nil || len(pk) != 65 || pk[0] != 0x04 {
			t.Fatalf("group %d: bad uncompressed public key", gi)
		}
		pub := &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(pk[1:33]),
			Y:     new(big.Int).SetBytes(pk[33:]),
		}
		if !curve.IsOnCurve(pub.X, pub.Y) {
			t.Fatalf("group %d: public key not on curve", gi)
		}

		for _, tc := range g.Tests {
			total++
			msg, _ := hex.DecodeString(tc.Msg)
			der, _ := hex.DecodeString(tc.Sig)
			h := sha256.Sum256(msg)

			got := verifyDER(pub, h[:], der)

			switch tc.Result {
			case "valid":
				asserted++
				if !got {
					t.Errorf("tc %d (%s): valid signature rejected", tc.TcID, tc.Comment)
				}
			case "invalid":
				asserted++
				if got {
					t.Errorf("tc %d (%s): invalid signature accepted", tc.TcID, tc.Comment)
				}
			case "acceptable":
				// permissible either way
			}
		}
	}
	t.Logf("wycheproof: %d vectors, %d asserted", total, asserted)
	if asserted == 0 {
		t.Fatal("no vectors asserted")
	}
}

// verifyDER strictly parses a DER ECDSA signature, rejects out-of-range r,s,
// then verifies with stdlib ecdsa.Verify over the brainpool curve.
func verifyDER(pub *ecdsa.PublicKey, hash, der []byte) bool {
	r, s, ok := parseDERSig(der)
	if !ok {
		return false
	}
	n := pub.Curve.Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return false
	}
	return ecdsa.Verify(pub, hash, r, s)
}
