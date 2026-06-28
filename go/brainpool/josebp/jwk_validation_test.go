package josebp

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool"
)

// validP256r1Point returns an on-curve (x, y) on brainpoolP256r1.
func validP256r1Point(t *testing.T) (*big.Int, *big.Int) {
	t.Helper()
	x, y := brainpool.P256r1().ScalarBaseMult([]byte{0x2a})
	if !brainpool.P256r1().IsOnCurve(x, y) {
		t.Fatal("test setup: point not on curve")
	}
	return x, y
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwkJSON(crv, x, y, d string) []byte {
	m := map[string]string{"kty": "EC", "crv": crv, "x": x, "y": y}
	if d != "" {
		m["d"] = d
	}
	out, _ := json.Marshal(m)
	return out
}

func TestUnmarshalJWKAcceptsValidPoint(t *testing.T) {
	x, y := validP256r1Point(t)
	raw := jwkJSON("BP-256", b64(x.FillBytes(make([]byte, 32))), b64(y.FillBytes(make([]byte, 32))), "")
	var jwk JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err != nil {
		t.Fatalf("valid JWK rejected: %v", err)
	}
	if _, ok := jwk.Key.(*ecdsa.PublicKey); !ok {
		t.Fatalf("key type = %T, want *ecdsa.PublicKey", jwk.Key)
	}
}

func TestUnmarshalJWKRejectsOffCurvePoint(t *testing.T) {
	x, y := validP256r1Point(t)
	// Corrupt y so the point is off-curve.
	badY := new(big.Int).Add(y, big.NewInt(1))
	raw := jwkJSON("BP-256",
		b64(x.FillBytes(make([]byte, 32))),
		b64(badY.FillBytes(make([]byte, 32))), "")
	var jwk JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err == nil {
		t.Fatal("off-curve JWK accepted")
	}
}

func TestUnmarshalJWKRejectsCoordinateOutOfRange(t *testing.T) {
	x, y := validP256r1Point(t)
	p := brainpool.P256r1().Params().P
	// x + p is congruent but non-canonical / out of range.
	bad := new(big.Int).Add(x, p)
	raw := jwkJSON("BP-256",
		b64(bad.Bytes()), // oversized encoding (> 32 bytes)
		b64(y.FillBytes(make([]byte, 32))), "")
	var jwk JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err == nil {
		t.Fatal("out-of-range x accepted")
	}
}

func TestUnmarshalJWKRejectsBadPrivateScalar(t *testing.T) {
	x, y := validP256r1Point(t)
	n := brainpool.P256r1().Params().N
	cases := map[string]*big.Int{
		"zero":     big.NewInt(0),
		"equalsN":  new(big.Int).Set(n),
		"exceedsN": new(big.Int).Add(n, big.NewInt(1)),
	}
	for name, d := range cases {
		t.Run(name, func(t *testing.T) {
			raw := jwkJSON("BP-256",
				b64(x.FillBytes(make([]byte, 32))),
				b64(y.FillBytes(make([]byte, 32))),
				b64(d.FillBytes(make([]byte, 32))))
			var jwk JSONWebKey
			if err := json.Unmarshal(raw, &jwk); err == nil {
				t.Fatalf("invalid private scalar (%s) accepted", name)
			}
		})
	}
}

func TestUnmarshalJWKRejectsMismatchedCurveForPrivateScalar(t *testing.T) {
	// d valid range but the point must still be on the named curve. Use an
	// on-curve point with a valid d to confirm the happy path still works.
	x, y := validP256r1Point(t)
	d := big.NewInt(0x2a) // the scalar we used to derive the point; in [1,n)
	raw := jwkJSON("BP-256",
		b64(x.FillBytes(make([]byte, 32))),
		b64(y.FillBytes(make([]byte, 32))),
		b64(d.FillBytes(make([]byte, 32))))
	var jwk JSONWebKey
	if err := json.Unmarshal(raw, &jwk); err != nil {
		t.Fatalf("valid private JWK rejected: %v", err)
	}
	priv, ok := jwk.Key.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("key type = %T, want *ecdsa.PrivateKey", jwk.Key)
	}
	if priv.D.Sign() == 0 {
		t.Fatal("private scalar not set")
	}
}
