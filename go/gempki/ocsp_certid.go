package gempki

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // CertID hashes are identifiers, not integrity protection (RFC 6960 §4.1.1)
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/ocsp"
)

// oidCertHash is id-isismtt-at-certHash (Common PKI Part 4 §3.1.2), the
// single-response extension gemSpec_PKI requires from every TI responder:
// the hash of the whole certificate the status is about, so that a
// response cannot be re-purposed for a certificate that merely shares the
// serial number.
var oidCertHash = asn1.ObjectIdentifier{1, 3, 36, 8, 3, 13}

// digestOIDs maps the hash AlgorithmIdentifiers a responder may use in
// CertID and certHash to constructors. The CertID hash is whatever we
// asked with (x/crypto/ocsp requests SHA-1); certHash is SHA-256 in the TI.
var digestOIDs = map[string]func() hash.Hash{
	"1.3.14.3.2.26":          sha1.New,
	"2.16.840.1.101.3.4.2.1": sha256.New,
	"2.16.840.1.101.3.4.2.2": sha512.New384,
	"2.16.840.1.101.3.4.2.3": sha512.New,
}

// ocspCertID is the CertID of the first SingleResponse (RFC 6960 §4.1.1).
type ocspCertID struct {
	hashAlg        asn1.ObjectIdentifier
	issuerNameHash []byte
	issuerKeyHash  []byte
	serial         *big.Int
}

// readCertID extracts the CertID from a tbsResponseData element:
//
//	ResponseData ::= SEQUENCE {
//	    version            [0] EXPLICIT Version DEFAULT v1,
//	    responderID            ResponderID,        -- [1] byName | [2] byKey
//	    producedAt             GeneralizedTime,
//	    responses              SEQUENCE OF SingleResponse, ... }
//	SingleResponse ::= SEQUENCE { certID CertID, ... }
//	CertID ::= SEQUENCE {
//	    hashAlgorithm   AlgorithmIdentifier,
//	    issuerNameHash  OCTET STRING,
//	    issuerKeyHash   OCTET STRING,
//	    serialNumber    CertificateSerialNumber }
//
// x/crypto/ocsp keeps the two hashes to itself, which is why this walk
// exists next to the one in [splitOCSPResponse].
func readCertID(tbs []byte) (ocspCertID, error) {
	var id ocspCertID
	outer := cryptobyte.String(tbs)
	var rd cryptobyte.String
	if !outer.ReadASN1(&rd, cryptobyte_asn1.SEQUENCE) {
		return id, errors.New("malformed tbsResponseData")
	}
	var version cryptobyte.String
	var hasVersion bool
	if !rd.ReadOptionalASN1(&version, &hasVersion, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		return id, errors.New("malformed version")
	}
	var responderID cryptobyte.String
	var responderTag cryptobyte_asn1.Tag
	if !rd.ReadAnyASN1(&responderID, &responderTag) {
		return id, errors.New("missing responderID")
	}
	var producedAt cryptobyte.String
	if !rd.ReadASN1(&producedAt, cryptobyte_asn1.GeneralizedTime) {
		return id, errors.New("missing producedAt")
	}
	var responses, single, certID, hashAlg cryptobyte.String
	if !rd.ReadASN1(&responses, cryptobyte_asn1.SEQUENCE) ||
		!responses.ReadASN1(&single, cryptobyte_asn1.SEQUENCE) ||
		!single.ReadASN1(&certID, cryptobyte_asn1.SEQUENCE) ||
		!certID.ReadASN1(&hashAlg, cryptobyte_asn1.SEQUENCE) {
		return id, errors.New("missing SingleResponse.certID")
	}
	if !hashAlg.ReadASN1ObjectIdentifier(&id.hashAlg) {
		return id, errors.New("malformed certID.hashAlgorithm")
	}
	if !certID.ReadASN1Bytes(&id.issuerNameHash, cryptobyte_asn1.OCTET_STRING) ||
		!certID.ReadASN1Bytes(&id.issuerKeyHash, cryptobyte_asn1.OCTET_STRING) {
		return id, errors.New("malformed certID hashes")
	}
	id.serial = new(big.Int)
	if !certID.ReadASN1Integer(id.serial) {
		return id, errors.New("malformed certID.serialNumber")
	}
	return id, nil
}

// verifyCertID checks that the response's CertID names cert under issuer:
// the same serial, and the issuer name and key hashed with the algorithm
// the responder chose. The key hash covers the subjectPublicKey bits
// without tag, length or unused-bits octet, as RFC 6960 §4.1.1 prescribes.
func verifyCertID(tbs []byte, cert, issuer *x509.Certificate) error {
	id, err := readCertID(tbs)
	if err != nil {
		return err
	}
	newHash, ok := digestOIDs[id.hashAlg.String()]
	if !ok {
		return fmt.Errorf("unsupported CertID hash algorithm %s", id.hashAlg)
	}
	if id.serial.Cmp(cert.SerialNumber) != 0 {
		return fmt.Errorf("CertID serial %s, certificate serial %s", id.serial, cert.SerialNumber)
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return fmt.Errorf("issuer SubjectPublicKeyInfo: %w", err)
	}
	h := newHash()
	h.Write(issuer.RawSubject)
	if !bytes.Equal(h.Sum(nil), id.issuerNameHash) {
		return errors.New("CertID issuerNameHash does not match the issuer")
	}
	h.Reset()
	h.Write(spki.PublicKey.RightAlign())
	if !bytes.Equal(h.Sum(nil), id.issuerKeyHash) {
		return errors.New("CertID issuerKeyHash does not match the issuer's key")
	}
	return nil
}

// verifyCertHash checks the certHash single extension against cert. A
// missing extension is an error only when required; a present one must
// match, whatever the caller's policy.
func verifyCertHash(resp *ocsp.Response, cert *x509.Certificate, required bool) error {
	var ext *pkix.Extension
	for i := range resp.Extensions {
		if resp.Extensions[i].Id.Equal(oidCertHash) {
			ext = &resp.Extensions[i]
			break
		}
	}
	if ext == nil {
		if required {
			return &ValidationError{
				Code:    ErrCodeOCSPResponseInvalid,
				Message: "OCSP response carries no certHash extension",
			}
		}
		return nil
	}
	var certHash struct {
		HashAlgorithm pkix.AlgorithmIdentifier
		Hash          []byte
	}
	if rest, err := asn1.Unmarshal(ext.Value, &certHash); err != nil || len(rest) != 0 {
		return &ValidationError{
			Code:    ErrCodeOCSPResponseInvalid,
			Message: "OCSP certHash extension is malformed",
			Cause:   err,
		}
	}
	newHash, ok := digestOIDs[certHash.HashAlgorithm.Algorithm.String()]
	if !ok {
		return &ValidationError{
			Code:    ErrCodeOCSPResponseInvalid,
			Message: "OCSP certHash uses unsupported hash algorithm " + certHash.HashAlgorithm.Algorithm.String(),
		}
	}
	h := newHash()
	h.Write(cert.Raw)
	if subtle.ConstantTimeCompare(h.Sum(nil), certHash.Hash) != 1 {
		return &ValidationError{
			Code:    ErrCodeOCSPResponseInvalid,
			Message: "OCSP certHash does not match the certificate",
		}
	}
	return nil
}
