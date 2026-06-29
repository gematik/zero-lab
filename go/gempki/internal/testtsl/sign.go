package testtsl

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/gematik/zero-lab/go/gempki/internal/testca"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// SignTSL produces a gematik-format detached-signature container over
// tslBytes, signed by signer's key and embedding signer's certificate.
//
// The output is the raw .sig bytes ready to feed into
// gempki.ParseTSLDetachedSignature: an outer DER SEQUENCE containing
//
//   - AlgorithmIdentifier { OID ecdsaWithSHA256 }   (12 fixed bytes)
//   - ECDSA-Sig-Value SEQUENCE { INTEGER r, INTEGER s }
//   - Certificate (signer.DER)
//
// Wire format spec: gematik examples-TelematikInterfaces,
// tslService/detachedSignature/README.md.
func SignTSL(t *testing.T, tslBytes []byte, signer *testca.Node) []byte {
	t.Helper()
	require.NotNil(t, signer.Key, "signer must have a private key")

	digest := sha256.Sum256(tslBytes)
	sigDER, err := ecdsa.SignASN1(rand.Reader, signer.Key, digest[:])
	require.NoError(t, err)

	// AlgorithmIdentifier { OID ecdsaWithSHA256 (1.2.840.10045.4.3.2) }.
	// The gematik format omits the NULL parameters that some
	// AlgorithmIdentifier encodings carry — element count is exactly 1.
	algIDFixed := []byte{
		0x30, 0x0A,
		0x06, 0x08,
		0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
	}

	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(algIDFixed)
		b.AddBytes(sigDER) // already a DER SEQUENCE { INTEGER r, INTEGER s }
		b.AddBytes(signer.DER)
	})
	out, err := b.Bytes()
	require.NoError(t, err)
	return out
}
