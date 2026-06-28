package bp256

import (
	"encoding/hex"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool/internal/bp256/fiat"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

func point(t *testing.T, xHex, yHex string) *Point {
	t.Helper()
	enc := append([]byte{0x04}, append(mustHex(t, xHex), mustHex(t, yHex)...)...)
	p, err := new(Point).SetBytes(enc)
	if err != nil {
		t.Fatalf("point not on curve: %v", err)
	}
	return p
}

// RFC 7027 Appendix A.1 — brainpoolP256r1 ECDH known-answer vector. Both parties
// must derive the same shared secret x-coordinate Z.
func TestRFC7027ECDHKnownAnswer(t *testing.T) {
	dA := mustHex(t, "81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D")
	qA := point(t,
		"44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5",
		"8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC")
	dB := mustHex(t, "55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3")
	qB := point(t,
		"8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B",
		"990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A")
	wantZ := "89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B"

	zAB, err := ECDH(dA, qB)
	if err != nil {
		t.Fatalf("ECDH(dA, qB): %v", err)
	}
	if got := hex.EncodeToString(zAB); !equalHexFold(got, wantZ) {
		t.Fatalf("ECDH(dA, qB) = %s, want %s", got, wantZ)
	}
	zBA, err := ECDH(dB, qA)
	if err != nil {
		t.Fatalf("ECDH(dB, qA): %v", err)
	}
	if got := hex.EncodeToString(zBA); !equalHexFold(got, wantZ) {
		t.Fatalf("ECDH(dB, qA) = %s, want %s", got, wantZ)
	}
}

// RFC 5639 §3.4 — the generator G this core uses must match the published
// coordinates exactly.
func TestRFC5639GeneratorCoordinates(t *testing.T) {
	g := new(Point).SetGenerator().Bytes()
	wantGx := "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262"
	wantGy := "547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997"
	gotGx := hex.EncodeToString(g[1 : 1+fiat.ElementLen])
	gotGy := hex.EncodeToString(g[1+fiat.ElementLen:])
	if !equalHexFold(gotGx, wantGx) || !equalHexFold(gotGy, wantGy) {
		t.Fatalf("generator = (%s, %s)", gotGx, gotGy)
	}
}

// BSI TR-03111 §3.2.2 — public-key validation must reject points off the curve,
// non-canonical coordinates (≥ p), the point at infinity in uncompressed form,
// and compressed encodings (not used by gematik).
func TestTR03111PublicKeyValidationRejections(t *testing.T) {
	valid := new(Point).SetGenerator().Bytes()

	offCurve := append([]byte(nil), valid...)
	offCurve[len(offCurve)-1] ^= 0x01
	if _, err := new(Point).SetBytes(offCurve); err == nil {
		t.Error("off-curve point accepted")
	}

	// x = p (non-canonical field element) with the generator's y.
	pBytes := mustHex(t, "A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377")
	nonCanonical := append([]byte{0x04}, pBytes...)
	nonCanonical = append(nonCanonical, valid[1+fiat.ElementLen:]...)
	if _, err := new(Point).SetBytes(nonCanonical); err == nil {
		t.Error("non-canonical x = p accepted")
	}

	compressed := append([]byte{0x02}, valid[1:1+fiat.ElementLen]...)
	if _, err := new(Point).SetBytes(compressed); err == nil {
		t.Error("compressed encoding accepted")
	}
}

func equalHexFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'F' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'F' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
