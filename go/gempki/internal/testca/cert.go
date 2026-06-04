// Package testca builds an ECC-only test PKI for gempki's unit tests.
//
// The Go standard library's [crypto/x509.CreateCertificate] rejects Brainpool
// keys with "x509: unsupported elliptic curve", so this package builds
// certificates by hand: it constructs the TBSCertificate ASN.1 structure,
// signs it with ECDSA, and assembles the final Certificate DER. NIST and
// Brainpool curves go through the same path.
//
// The output is intentionally minimalist — only the fields gempki tests need
// (validity, key usage, EKU, SAN, basic constraints, authority/subject key
// identifiers, certificate policies, and gematik's Admission extension).
// Everything else from RFC 5280 is omitted.
//
// This package is internal: it is not part of gempki's public API and may
// change without notice.
package testca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
)

// CertOptions configures one certificate built by [CreateCertificate].
// Either Subject xor Template must be set; Template is convenient for cloning
// a [crypto/x509.Certificate] field-by-field.
type CertOptions struct {
	Subject             pkix.Name
	Serial              *big.Int // nil → random 64-bit
	NotBefore           time.Time
	NotAfter            time.Time
	IsCA                bool
	BasicConstraints    bool
	MaxPathLen          int // 0 with MaxPathLenZero=true → pathLenConstraint=0
	MaxPathLenZero      bool
	KeyUsage            x509.KeyUsage
	ExtKeyUsage         []x509.ExtKeyUsage
	DNSNames            []string
	CertificatePolicies []asn1.ObjectIdentifier
	ExtraExtensions     []pkix.Extension // appended verbatim (used for Admission)
}

// CreateCertificate signs a certificate for subjectPub using issuer's key and
// returns its DER encoding.
//
// To self-sign, pass nil for issuer: subject becomes its own issuer and the
// subjectPub key is signed with subjectPriv (which must then be the same
// principal). For an issued cert, subjectPriv may be nil — only signerKey is
// used for signing; subjectPub provides the public-key material to embed.
func CreateCertificate(
	opts CertOptions,
	subjectPub crypto.PublicKey,
	issuer *x509.Certificate,
	signerKey crypto.Signer,
) ([]byte, error) {
	if opts.NotBefore.IsZero() || opts.NotAfter.IsZero() {
		return nil, errors.New("testca: NotBefore and NotAfter are required")
	}
	if signerKey == nil {
		return nil, errors.New("testca: signerKey is required")
	}
	subjectPubECDSA, ok := subjectPub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("testca: subject public key must be *ecdsa.PublicKey, got %T", subjectPub)
	}
	signerPubECDSA, ok := signerKey.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("testca: signer key must be ECDSA, got %T", signerKey.Public())
	}

	serial := opts.Serial
	if serial == nil {
		s, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
		if err != nil {
			return nil, fmt.Errorf("testca: random serial: %w", err)
		}
		serial = s
	}

	sigAlg, hashFunc, sigAlgOID, err := signerAlg(signerPubECDSA.Curve)
	if err != nil {
		return nil, err
	}
	_ = sigAlg // captured in TBS via the OID, kept for clarity

	subjectName, err := asn1.Marshal(opts.Subject.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("testca: marshal subject: %w", err)
	}

	var issuerName []byte
	var issuerPub *ecdsa.PublicKey
	if issuer == nil {
		// Self-signed: issuer name == subject name, AKI uses subjectPub.
		issuerName = subjectName
		issuerPub = subjectPubECDSA
	} else {
		issuerName, err = asn1.Marshal(issuer.Subject.ToRDNSequence())
		if err != nil {
			return nil, fmt.Errorf("testca: marshal issuer: %w", err)
		}
		ip, ok := issuer.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("testca: issuer public key must be *ecdsa.PublicKey, got %T", issuer.PublicKey)
		}
		issuerPub = ip
	}

	spkiDER, err := marshalSPKI(subjectPubECDSA)
	if err != nil {
		return nil, err
	}

	exts, err := buildExtensions(opts, subjectPubECDSA, issuerPub)
	if err != nil {
		return nil, err
	}

	algorithmIdentifier := pkix.AlgorithmIdentifier{Algorithm: sigAlgOID}

	tbs := tbsCertificate{
		Version:            2, // v3
		SerialNumber:       serial,
		SignatureAlgorithm: algorithmIdentifier,
		Issuer:             asn1.RawValue{FullBytes: issuerName},
		Validity:           validity{NotBefore: opts.NotBefore.UTC(), NotAfter: opts.NotAfter.UTC()},
		Subject:            asn1.RawValue{FullBytes: subjectName},
		PublicKey:          asn1.RawValue{FullBytes: spkiDER},
	}
	if len(exts) > 0 {
		tbs.Extensions = exts
	}

	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		return nil, fmt.Errorf("testca: marshal TBS: %w", err)
	}

	h := hashFunc.New()
	h.Write(tbsDER)
	digest := h.Sum(nil)

	sig, err := signerKey.Sign(rand.Reader, digest, hashFunc)
	if err != nil {
		return nil, fmt.Errorf("testca: sign TBS: %w", err)
	}

	cert := certificate{
		TBSCertificate:     asn1.RawValue{FullBytes: tbsDER},
		SignatureAlgorithm: algorithmIdentifier,
		SignatureValue:     asn1.BitString{Bytes: sig, BitLength: len(sig) * 8},
	}
	return asn1.Marshal(cert)
}

// ASN.1 structures for the certificate we emit. RFC 5280 §4.1.

type certificate struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type tbsCertificate struct {
	Version            int `asn1:"explicit,tag:0,default:0"`
	SerialNumber       *big.Int
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Issuer             asn1.RawValue
	Validity           validity
	Subject            asn1.RawValue
	PublicKey          asn1.RawValue
	Extensions         []pkix.Extension `asn1:"explicit,tag:3,optional"`
}

type validity struct {
	NotBefore time.Time `asn1:"utc"`
	NotAfter  time.Time `asn1:"utc"`
}

// OIDs.
var (
	oidPublicKeyECDSA  = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}

	oidBrainpoolP256r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 7}
	oidBrainpoolP384r1 = asn1.ObjectIdentifier{1, 3, 36, 3, 3, 2, 8, 1, 1, 11}
	oidNISTP256        = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNISTP384        = asn1.ObjectIdentifier{1, 3, 132, 0, 34}

	oidExtSubjectKeyID     = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtSubjectAltName   = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtBasicConstraints = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtCertificatePol   = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtAuthorityKeyID   = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtExtKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// signerAlg returns the signature-algorithm OID and a hash for a given curve.
// Brainpool curves use ecdsa-with-SHAxxx OIDs identical to NIST — only the
// public-key curve changes.
func signerAlg(curve elliptic.Curve) (x509.SignatureAlgorithm, crypto.Hash, asn1.ObjectIdentifier, error) {
	switch curve {
	case elliptic.P256(), brainpool.P256r1():
		return x509.ECDSAWithSHA256, crypto.SHA256, oidECDSAWithSHA256, nil
	case elliptic.P384(), brainpool.P384r1():
		return x509.ECDSAWithSHA384, crypto.SHA384, oidECDSAWithSHA384, nil
	}
	return 0, 0, nil, fmt.Errorf("testca: signer curve %q not supported (TI-PKI policy: NIST P-256/P-384 or Brainpool P256r1/P384r1)", curve.Params().Name)
}

func curveOID(curve elliptic.Curve) (asn1.ObjectIdentifier, error) {
	switch curve {
	case elliptic.P256():
		return oidNISTP256, nil
	case elliptic.P384():
		return oidNISTP384, nil
	case brainpool.P256r1():
		return oidBrainpoolP256r1, nil
	case brainpool.P384r1():
		return oidBrainpoolP384r1, nil
	}
	return nil, fmt.Errorf("testca: unsupported curve %q", curve.Params().Name)
}

// marshalSPKI builds a SubjectPublicKeyInfo for an ECDSA public key on any
// supported curve. Uncompressed point encoding (RFC 5480 §2.2).
func marshalSPKI(pub *ecdsa.PublicKey) ([]byte, error) {
	cOID, err := curveOID(pub.Curve)
	if err != nil {
		return nil, err
	}
	paramsBytes, err := asn1.Marshal(cOID)
	if err != nil {
		return nil, fmt.Errorf("testca: marshal curve OID: %w", err)
	}
	// elliptic.Marshal + pub.X/Y are deprecated in Go 1.26 in favour of
	// crypto/ecdh and crypto/x509.MarshalPKIXPublicKey, but neither handles
	// Brainpool curves — we need the raw SEC1 uncompressed point here.
	point := elliptic.Marshal(pub.Curve, pub.X, pub.Y) //nolint:staticcheck
	spki := publicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{
			Algorithm:  oidPublicKeyECDSA,
			Parameters: asn1.RawValue{FullBytes: paramsBytes},
		},
		PublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	}
	return asn1.Marshal(spki)
}

type publicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}
