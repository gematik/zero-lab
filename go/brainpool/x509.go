package brainpool

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// id-ecPublicKey (RFC 5480 §2.1.1), as DER-encoded OID content bytes, and the
// sentinel it is swapped for so crypto/x509 sees an algorithm it does not
// know. 1.2.840.10045.2.2 sits in the same X9.62 arc, is unassigned, and
// encodes to the same 7 bytes, so the swap moves no offsets.
var (
	oidECPublicKey        = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	derECPublicKey        = []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}
	derUnknownPublicKey   = []byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x02}
	errNotBrainpoolPublic = errors.New("not a Brainpool public key")
)

// ParseCertificatePEM parses the first PEM block of pemBytes as a certificate.
func ParseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("brainpool: no PEM block found")
	}
	return ParseCertificate(block.Bytes)
}

// ParseCertificate parses a DER certificate, accepting Brainpool public keys
// that crypto/x509 rejects with "unsupported elliptic curve".
//
// crypto/x509 parses every field of a certificate whose public key algorithm
// it does not recognise and leaves PublicKey nil — it only refuses the EC
// algorithm with a curve it does not have. So for a Brainpool certificate the
// SPKI algorithm OID is swapped for an unknown one of the same length, the
// standard library parses the whole certificate, and only the public key is
// decoded here. The Raw* fields are restored from the original bytes.
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	spki, err := locateSPKI(der)
	if err != nil {
		// Not a Brainpool key, or not a certificate at all: the standard
		// library gives the authoritative answer either way.
		return x509.ParseCertificate(der)
	}

	patched := bytes.Clone(der)
	copy(patched[spki.algorithmOID:], derUnknownPublicKey)
	cert, err := x509.ParseCertificate(patched)
	if err != nil {
		return nil, err
	}

	pub, err := parsePoint(spki.curve, spki.point)
	if err != nil {
		return nil, fmt.Errorf("brainpool: subject public key: %w", err)
	}
	cert.PublicKeyAlgorithm = x509.ECDSA
	cert.PublicKey = pub

	// Every Raw* field is a sub-slice of the bytes crypto/x509 was given.
	// Offsets are identical in der and patched, so re-slicing der at the
	// same offsets restores the original encoding, which signature checks
	// and OCSP request builders hash.
	restore := func(sub []byte) []byte {
		off := offsetIn(patched, sub)
		return der[off : off+len(sub)]
	}
	cert.Raw = der
	cert.RawTBSCertificate = restore(cert.RawTBSCertificate)
	cert.RawSubjectPublicKeyInfo = restore(cert.RawSubjectPublicKeyInfo)
	cert.RawSubject = restore(cert.RawSubject)
	cert.RawIssuer = restore(cert.RawIssuer)
	return cert, nil
}

// spkiLocation is what ParseCertificate needs to know about a Brainpool
// SubjectPublicKeyInfo: where the algorithm OID's content bytes start, which
// curve the parameters name, and the encoded point.
type spkiLocation struct {
	algorithmOID int
	curve        elliptic.Curve
	point        []byte
}

// locateSPKI walks the certificate as far as the SubjectPublicKeyInfo and
// returns errNotBrainpoolPublic unless the key is id-ecPublicKey on a
// Brainpool curve. It decodes nothing else; crypto/x509 does that.
func locateSPKI(der []byte) (spkiLocation, error) {
	var loc spkiLocation
	input := cryptobyte.String(der)
	var cert, tbs cryptobyte.String
	if !input.ReadASN1(&cert, cryptobyte_asn1.SEQUENCE) ||
		!cert.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return loc, errors.New("brainpool: malformed certificate")
	}
	var skip cryptobyte.String
	if !tbs.SkipOptionalASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) ||
		!tbs.ReadASN1(&skip, cryptobyte_asn1.INTEGER) || // serialNumber
		!tbs.ReadASN1(&skip, cryptobyte_asn1.SEQUENCE) || // signature
		!tbs.ReadASN1(&skip, cryptobyte_asn1.SEQUENCE) || // issuer
		!tbs.ReadASN1(&skip, cryptobyte_asn1.SEQUENCE) || // validity
		!tbs.ReadASN1(&skip, cryptobyte_asn1.SEQUENCE) { // subject
		return loc, errors.New("brainpool: malformed TBSCertificate")
	}
	var spki, algorithm, oid cryptobyte.String
	if !tbs.ReadASN1(&spki, cryptobyte_asn1.SEQUENCE) ||
		!spki.ReadASN1(&algorithm, cryptobyte_asn1.SEQUENCE) ||
		!algorithm.ReadASN1(&oid, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		return loc, errors.New("brainpool: malformed SubjectPublicKeyInfo")
	}
	if !bytes.Equal(oid, derECPublicKey) {
		return loc, errNotBrainpoolPublic
	}
	var curveOID asn1.ObjectIdentifier
	if !algorithm.ReadASN1ObjectIdentifier(&curveOID) {
		return loc, errors.New("brainpool: malformed EC parameters")
	}
	curve, ok := curveFromOID(curveOID)
	if !ok {
		return loc, errNotBrainpoolPublic
	}
	var point asn1.BitString
	if !spki.ReadASN1BitString(&point) {
		return loc, errors.New("brainpool: malformed subject public key")
	}
	loc.algorithmOID = offsetIn(der, oid)
	loc.curve = curve
	loc.point = point.RightAlign()
	return loc, nil
}

// offsetIn returns where sub starts inside base; sub must be a sub-slice of
// base, which is what cryptobyte and crypto/x509 hand back.
func offsetIn(base, sub []byte) int {
	return cap(base) - cap(sub)
}

// parsePoint decodes a SEC 1 uncompressed point and validates it as a public
// key on curve. Compressed points are not accepted; the TI uses uncompressed
// encoding exclusively.
func parsePoint(curve elliptic.Curve, b []byte) (*ecdsa.PublicKey, error) {
	size := (curve.Params().BitSize + 7) / 8
	if len(b) != 1+2*size || b[0] != 4 {
		return nil, fmt.Errorf("not an uncompressed %s point", curve.Params().Name)
	}
	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(b[1 : 1+size]),
		Y:     new(big.Int).SetBytes(b[1+size:]),
	}
	if err := ValidatePublicKey(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// ValidatePublicKey reports whether pub is a valid affine point on its curve:
// both coordinates canonical in [0, p-1] and the point on the curve, which
// also rejects the point at infinity (SEC 1 §3.2.2.1, BSI TR-03111 §3.2.2).
// Keys that arrive from the network — certificates, JWKs, ECDH peers — go
// through this before any arithmetic touches them.
func ValidatePublicKey(pub *ecdsa.PublicKey) error {
	if pub == nil || pub.Curve == nil || pub.X == nil || pub.Y == nil {
		return errors.New("brainpool: nil public key")
	}
	name, p := pub.Curve.Params().Name, pub.Curve.Params().P
	if pub.X.Sign() < 0 || pub.X.Cmp(p) >= 0 || pub.Y.Sign() < 0 || pub.Y.Cmp(p) >= 0 {
		return fmt.Errorf("brainpool: coordinate out of range for %s", name)
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return fmt.Errorf("brainpool: point is not on %s", name)
	}
	return nil
}

// MarshalPKIXPublicKey is x509.MarshalPKIXPublicKey with Brainpool support:
// the standard library cannot name these curves in an AlgorithmIdentifier.
func MarshalPKIXPublicKey(pub any) ([]byte, error) {
	pk, ok := pub.(*ecdsa.PublicKey)
	if !ok || !isBrainpoolCurve(pk.Curve) {
		return x509.MarshalPKIXPublicKey(pub)
	}
	curveOID, ok := oidForCurve(pk.Curve)
	if !ok {
		return nil, errors.New("brainpool: unsupported curve")
	}
	size := (pk.Curve.Params().BitSize + 7) / 8
	point := make([]byte, 1+2*size)
	point[0] = 4
	pk.X.FillBytes(point[1 : 1+size])
	pk.Y.FillBytes(point[1+size:])
	return asn1.Marshal(struct {
		Algorithm struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}{
		Algorithm: struct {
			Algorithm  asn1.ObjectIdentifier
			Parameters asn1.ObjectIdentifier
		}{oidECPublicKey, curveOID},
		PublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	})
}
