package brainpool

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"errors"
)

// IsBrainpoolCurve checks if the given elliptic curve is one of the brainpool curves.
func IsBrainpoolCurve(curve elliptic.Curve) bool {
	switch curve.Params().Name {
	case "brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1":
		return true
	default:
		return false
	}
}

// IsBrainpoolPublicKey checks if the given public key uses elliptic curve cryptography
// with a brainpool curve.
func IsBrainpoolPublicKey(pub interface{}) bool {
	pk, ok := pub.(*ecdsa.PublicKey)
	return ok && IsBrainpoolCurve(pk.Curve)
}

// IsBrainpoolCertificate checks if the given certificate uses elliptic curve cryptography
// with a brainpool curve.
func IsBrainpoolCertificate(cert *x509.Certificate) bool {
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	return ok && IsBrainpoolCurve(pub.Curve)
}

func MarshalPKIXPublicKey(pub interface{}) ([]byte, error) {
	if pk, ok := pub.(*ecdsa.PublicKey); ok && IsBrainpoolCurve(pk.Curve) {
		return marshalPKIXPublicKeyBrainpool(pk)
	}
	return x509.MarshalPKIXPublicKey(pub)
}

func marshalPKIXPublicKeyBrainpool(pub *ecdsa.PublicKey) ([]byte, error) {
	var curveOID asn1.ObjectIdentifier
	switch pub.Curve.Params().Name {
	case "brainpoolP256r1":
		curveOID = OIDNamedCurveP256r1
	case "brainpoolP384r1":
		curveOID = OIDNamedCurveP384r1
	case "brainpoolP512r1":
		curveOID = OIDNamedCurveP512r1
	default:
		return nil, errors.New("brainpool: unsupported curve")
	}

	type algorithmIdentifier struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.ObjectIdentifier
	}

	type subjectPublicKeyInfo struct {
		Algorithm algorithmIdentifier
		PublicKey asn1.BitString
	}

	// id-ecPublicKey
	oidPublicKeyECDSA := asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

	// Calculate the correct byte length for coordinates based on the curve size
	byteLen := (pub.Curve.Params().BitSize + 7) / 8

	// Ensure X and Y are padded to the correct length
	xBytes := pub.X.Bytes()
	if len(xBytes) < byteLen {
		padding := make([]byte, byteLen-len(xBytes))
		xBytes = append(padding, xBytes...)
	}

	yBytes := pub.Y.Bytes()
	if len(yBytes) < byteLen {
		padding := make([]byte, byteLen-len(yBytes))
		yBytes = append(padding, yBytes...)
	}

	spki := subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier{
			Algorithm:  oidPublicKeyECDSA,
			Parameters: curveOID,
		},
		PublicKey: asn1.BitString{
			Bytes:     append([]byte{4}, append(xBytes, yBytes...)...),
			BitLength: byteLen*8*2 + 8, // uncompressed form 0x04 + X + Y (in bits: 8 + 8*byteLen + 8*byteLen)
		},
	}

	return asn1.Marshal(spki)
}
