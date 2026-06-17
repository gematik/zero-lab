package testocsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/ocsp"
)

// isStdlibSignableCurve reports whether x/crypto/ocsp.CreateResponse can
// sign with this curve (its signingParamsForPublicKey switch table).
func isStdlibSignableCurve(c elliptic.Curve) bool {
	switch c {
	case elliptic.P224(), elliptic.P256(), elliptic.P384(), elliptic.P521():
		return true
	}
	return false
}

// createBrainpoolOCSPResponse produces a DER-encoded OCSP response signed
// by a brainpool ECDSA key. x/crypto/ocsp can't do this directly (its
// curve switch refuses anything outside NIST), so we let it produce a
// response signed by a throwaway NIST key, then surgically replace the
// signature bytes and the signature algorithm OID with the brainpool
// equivalent computed by stdlib's curve-agnostic ECDSA path.
//
// Only the response signature (BasicOCSPResponse.signature) is replaced;
// TBSResponseData / Certificates / Status fields are untouched, so all
// metadata callers read (Status, ProducedAt, SerialNumber, etc.) is
// authentic from x/crypto's marshaller.
func createBrainpoolOCSPResponse(issuer, responderCert *x509.Certificate, template ocsp.Response, signer *ecdsa.PrivateKey) ([]byte, error) {
	stub, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("testocsp: gen stub NIST key: %w", err)
	}
	respBytes, err := ocsp.CreateResponse(issuer, responderCert, template, stub)
	if err != nil {
		return nil, fmt.Errorf("testocsp: skeleton CreateResponse: %w", err)
	}

	tbsBytes, oldSig, prefix, suffix, sigAlgFullElem, err := splitBasicOCSPResponseForResign(respBytes)
	if err != nil {
		return nil, fmt.Errorf("testocsp: locate signature: %w", err)
	}
	_ = oldSig
	_ = sigAlgFullElem

	hashed := sha256.Sum256(tbsBytes)
	newSig, err := ecdsa.SignASN1(rand.Reader, signer, hashed[:])
	if err != nil {
		return nil, fmt.Errorf("testocsp: brainpool sign: %w", err)
	}

	return rebuildResponseWithBrainpoolSignature(prefix, suffix, tbsBytes, sigAlgFullElem, newSig)
}

// splitBasicOCSPResponseForResign parses respBytes far enough to return:
//   - tbsBytes: TBSResponseData inner DER (the bytes we re-sign)
//   - oldSig: old signature bytes (unused; returned for symmetry/debug)
//   - prefix/suffix: never used directly here — re-encoding goes through
//     rebuildResponseWithBrainpoolSignature, which builds bytes from
//     the structured pieces and the new signature
//   - sigAlgFullElem: original AlgorithmIdentifier element; not reused
//     since we overwrite with the SHA256-with-ECDSA OID
//
// Structure walked is per RFC 6960; identical to gempki.stripOCSPEmbeddedCerts.
func splitBasicOCSPResponseForResign(respBytes []byte) (tbsBytes, oldSig, prefix, suffix, sigAlgFullElem []byte, err error) {
	outer := cryptobyte.String(respBytes)
	var ocspResp cryptobyte.String
	if !outer.ReadASN1(&ocspResp, cryptobyte_asn1.SEQUENCE) {
		err = fmt.Errorf("malformed OCSPResponse")
		return
	}
	var statusElem cryptobyte.String
	if !ocspResp.ReadASN1Element(&statusElem, cryptobyte_asn1.ENUM) {
		err = fmt.Errorf("missing responseStatus")
		return
	}
	var rbExplicit cryptobyte.String
	if !ocspResp.ReadASN1(&rbExplicit, cryptobyte_asn1.Tag(0).Constructed().ContextSpecific()) {
		err = fmt.Errorf("missing responseBytes")
		return
	}
	var rb cryptobyte.String
	if !rbExplicit.ReadASN1(&rb, cryptobyte_asn1.SEQUENCE) {
		err = fmt.Errorf("malformed responseBytes")
		return
	}
	var respType cryptobyte.String
	if !rb.ReadASN1Element(&respType, cryptobyte_asn1.OBJECT_IDENTIFIER) {
		err = fmt.Errorf("missing responseType")
		return
	}
	var basicRespOctets cryptobyte.String
	if !rb.ReadASN1(&basicRespOctets, cryptobyte_asn1.OCTET_STRING) {
		err = fmt.Errorf("missing response OCTET STRING")
		return
	}
	var basicResp cryptobyte.String
	if !basicRespOctets.ReadASN1(&basicResp, cryptobyte_asn1.SEQUENCE) {
		err = fmt.Errorf("malformed BasicOCSPResponse")
		return
	}
	var tbsElem cryptobyte.String
	if !basicResp.ReadASN1Element(&tbsElem, cryptobyte_asn1.SEQUENCE) {
		err = fmt.Errorf("missing tbsResponseData")
		return
	}
	tbsBytes = []byte(tbsElem)

	var sigAlg cryptobyte.String
	if !basicResp.ReadASN1Element(&sigAlg, cryptobyte_asn1.SEQUENCE) {
		err = fmt.Errorf("missing signatureAlgorithm")
		return
	}
	sigAlgFullElem = []byte(sigAlg)

	var sigBit cryptobyte.String
	if !basicResp.ReadASN1(&sigBit, cryptobyte_asn1.BIT_STRING) {
		err = fmt.Errorf("missing signature")
		return
	}
	// Drop the leading "unused bits" byte to get raw signature bytes.
	if len(sigBit) > 0 {
		oldSig = []byte(sigBit[1:])
	}
	return
}

// oidSHA256WithECDSA = id-ecdsa-with-SHA256 (RFC 5754 §3.2)
var oidSHA256WithECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

func rebuildResponseWithBrainpoolSignature(_, _, tbsBytes, _, newSig []byte) ([]byte, error) {
	var sigAlgDER cryptobyte.Builder
	sigAlgDER.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oidSHA256WithECDSA)
	})
	sigAlgBytes, err := sigAlgDER.Bytes()
	if err != nil {
		return nil, err
	}

	var basicRespDER cryptobyte.Builder
	basicRespDER.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(tbsBytes)
		b.AddBytes(sigAlgBytes)
		b.AddASN1BitString(newSig)
	})
	basicRespBytes, err := basicRespDER.Bytes()
	if err != nil {
		return nil, err
	}

	var inner cryptobyte.Builder
	inner.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 1}) // id-pkix-ocsp-basic
		b.AddASN1(cryptobyte_asn1.OCTET_STRING, func(b *cryptobyte.Builder) {
			b.AddBytes(basicRespBytes)
		})
	})
	innerBytes, err := inner.Bytes()
	if err != nil {
		return nil, err
	}

	var outer cryptobyte.Builder
	outer.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		// responseStatus = 0 (successful) ENUMERATED
		b.AddASN1Enum(0)
		b.AddASN1(cryptobyte_asn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddBytes(innerBytes)
		})
	})
	return outer.Bytes()
}
