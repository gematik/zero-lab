//go:build openssl_cross

// These tests cross-validate the production signing and verification paths
// against the OpenSSL reference implementation. They are gated behind the
// openssl_cross build tag and skip automatically if the openssl CLI is absent:
//
//	go test -tags openssl_cross ./...
package brainpool

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gematik/zero-lab/go/brainpool/internal/bp256"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func opensslBin(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl CLI not found; skipping cross-tests")
	}
	return p
}

func derEncodeSig(r, s *big.Int) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(c *cryptobyte.Builder) {
		c.AddASN1BigInt(r)
		c.AddASN1BigInt(s)
	})
	return b.BytesOrPanic()
}

// our deterministic signature must verify under OpenSSL.
func TestOpenSSLVerifiesOurSignature(t *testing.T) {
	openssl := opensslBin(t)
	dir := t.TempDir()

	keyPEM := filepath.Join(dir, "key.pem")
	run(t, openssl, "genpkey", "-algorithm", "EC", "-pkeyopt",
		"ec_paramgen_curve:brainpoolP256r1", "-out", keyPEM)

	// Extract d and the public point from the OpenSSL key.
	d, pub := readOpenSSLKey(t, openssl, keyPEM)

	msg := []byte("cross-test message for openssl verify")
	h := sha256.Sum256(msg)
	r, s, err := bp256.SignDeterministic(d, h[:])
	if err != nil {
		t.Fatalf("SignDeterministic: %v", err)
	}

	// Sanity: also verifies locally under stdlib.
	if !ecdsa.Verify(pub, h[:], new(big.Int).SetBytes(r), new(big.Int).SetBytes(s)) {
		t.Fatal("our signature failed local stdlib verify")
	}

	sigDER := derEncodeSig(new(big.Int).SetBytes(r), new(big.Int).SetBytes(s))
	sigFile := filepath.Join(dir, "sig.der")
	msgFile := filepath.Join(dir, "msg.bin")
	pubPEM := filepath.Join(dir, "pub.pem")
	write(t, sigFile, sigDER)
	write(t, msgFile, msg)
	run(t, openssl, "pkey", "-in", keyPEM, "-pubout", "-out", pubPEM)

	out, err := exec.Command(openssl, "dgst", "-sha256", "-verify", pubPEM,
		"-signature", sigFile, msgFile).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl verify failed: %v\n%s", err, out)
	}
}

// a signature produced by OpenSSL must verify under our production (stdlib) path.
func TestWeVerifyOpenSSLSignature(t *testing.T) {
	openssl := opensslBin(t)
	dir := t.TempDir()

	keyPEM := filepath.Join(dir, "key.pem")
	run(t, openssl, "genpkey", "-algorithm", "EC", "-pkeyopt",
		"ec_paramgen_curve:brainpoolP256r1", "-out", keyPEM)
	_, pub := readOpenSSLKey(t, openssl, keyPEM)

	msg := []byte("cross-test message for our verify")
	msgFile := filepath.Join(dir, "msg.bin")
	sigFile := filepath.Join(dir, "sig.der")
	write(t, msgFile, msg)
	run(t, openssl, "dgst", "-sha256", "-sign", keyPEM, "-out", sigFile, msgFile)

	der, err := os.ReadFile(sigFile)
	if err != nil {
		t.Fatal(err)
	}
	r, s, ok := parseDERSig(der)
	if !ok {
		t.Fatal("could not parse OpenSSL signature")
	}
	h := sha256.Sum256(msg)
	if !ecdsa.Verify(pub, h[:], r, s) {
		t.Fatal("stdlib verify rejected a valid OpenSSL signature")
	}
}

// readOpenSSLKey returns the 32-byte private scalar and the public key of an
// OpenSSL-generated brainpoolP256r1 key.
func readOpenSSLKey(t *testing.T, openssl, keyPEM string) ([]byte, *ecdsa.PublicKey) {
	t.Helper()
	out := run(t, openssl, "ec", "-in", keyPEM, "-text", "-noout")
	priv := extractHexBlock(string(out), "priv:", "pub:")
	pubHex := extractHexBlock(string(out), "pub:", "ASN1 OID")
	d, err := hex.DecodeString(priv)
	if err != nil {
		t.Fatalf("priv hex: %v", err)
	}
	// Left-pad d to 32 bytes.
	if len(d) < 32 {
		d = append(make([]byte, 32-len(d)), d...)
	}
	pb, err := hex.DecodeString(pubHex)
	if err != nil || len(pb) != 65 || pb[0] != 0x04 {
		t.Fatalf("pub hex: %v (len %d)", err, len(pb))
	}
	pub := &ecdsa.PublicKey{Curve: P256r1(),
		X: new(big.Int).SetBytes(pb[1:33]), Y: new(big.Int).SetBytes(pb[33:])}
	return d, pub
}

func extractHexBlock(text, start, end string) string {
	i := indexOf(text, start)
	if i < 0 {
		return ""
	}
	j := indexOf(text[i:], end)
	if j < 0 {
		j = len(text) - i
	}
	block := text[i+len(start) : i+j]
	out := make([]byte, 0, len(block))
	for _, c := range block {
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
			out = append(out, byte(c))
		}
	}
	return string(out)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func run(t *testing.T, name string, args ...string) []byte {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return out
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}
