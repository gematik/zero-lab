package brainpool

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidSignatureECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidSignatureECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidSignatureSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSignatureSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSignatureSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
)

var (
	oidExtensionSubjectKeyID        = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionKeyUsage            = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionSubjectAltName      = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionBasicConstraints    = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionNameConstraints     = asn1.ObjectIdentifier{2, 5, 29, 30}
	oidExtensionCRLDistPoints       = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtensionCertificatePolicies = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtensionAuthorityKeyID      = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtensionExtKeyUsage         = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionInhibitAnyPolicy    = asn1.ObjectIdentifier{2, 5, 29, 54}
	oidExtensionAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
)

// RFC 5280, 4.2.1.12  Extended Key Usage
var (
	oidExtKeyUsageAny             = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtKeyUsageServerAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser       = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning     = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
)

var (
	oidAuthorityInfoAccessOcsp    = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
	oidAuthorityInfoAccessIssuers = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 2}
)

func ParseCertificatePEM(pemBytes []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	return ParseCertificate(pemBlock.Bytes)
}

func ParseCertificate(der []byte) (*x509.Certificate, error) {
	return parseCertificate(der)
}

func ParsePrivateKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	switch pemBlock.Type {
	case "PRIVATE KEY":
		// convert pkc8 to der
		key, err := ParsePKCS8PrivateKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, nil
		}
		return ecdsaKey, nil
	case "EC PRIVATE KEY":
		return ParseECPrivateKey(pemBlock.Bytes)
	}
	return nil, fmt.Errorf("unsupported PEM block type: %s", pemBlock.Type)
}

func ParseECPrivateKey(der []byte) (*ecdsa.PrivateKey, error) {
	pk, err := unmarshalPrivateKey(der)
	if err != nil {
		return nil, err
	}

	ok, curve := CurveFromOID(pk.NamedCurveOID)
	if !ok {
		return x509.ParseECPrivateKey(der)
	}

	return constructEcdsaPrivateKey(curve, pk)
}

func unmarshalPrivateKey(der []byte) (*brainpoolPrivateKey, error) {
	pk := new(brainpoolPrivateKey)
	_, err := asn1.Unmarshal(der, pk)
	if err != nil {
		return nil, err
	}
	if pk.Version != 1 {
		return nil, fmt.Errorf("brainpool: unknown EC private key version %d", pk.Version)
	}
	return pk, nil
}

type brainpoolPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func constructEcdsaPrivateKey(curve elliptic.Curve, pk *brainpoolPrivateKey) (*ecdsa.PrivateKey, error) {
	k := new(ecdsa.PrivateKey)
	k.Curve = curve
	k.D = new(big.Int).SetBytes(pk.PrivateKey)
	k.PublicKey.X, k.PublicKey.Y = curve.ScalarBaseMult(pk.PrivateKey)

	return k, nil
}

var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

type pkcs8PrivateKeyInfo struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func ParsePKCS8PrivateKey(der []byte) (any, error) {
	var privKey pkcs8PrivateKeyInfo
	_, err := asn1.Unmarshal(der, &privKey)
	if err != nil {
		return nil, errors.New("x509: failed to parse PKCS#8 private key: " + err.Error())
	}

	if !privKey.Algo.Algorithm.Equal(oidPublicKeyECDSA) {
		return x509.ParsePKCS8PrivateKey(der)
	}

	curveOidBytes := privKey.Algo.Parameters.FullBytes
	curveOid := new(asn1.ObjectIdentifier)
	_, err = asn1.Unmarshal(curveOidBytes, curveOid)
	if err != nil {
		return nil, errors.New("x509: failed to parse PKCS#8 private key curve OID: " + err.Error())
	}

	ok, curve := CurveFromOID(*curveOid)
	if !ok {
		return x509.ParsePKCS8PrivateKey(der)
	}

	pk, err := unmarshalPrivateKey(privKey.PrivateKey)
	if err != nil {
		return nil, err
	}

	return constructEcdsaPrivateKey(curve, pk)
}

func parseCertificate(der []byte) (*x509.Certificate, error) {
	input := cryptobyte.String(der)

	var certSeq cryptobyte.String
	if !input.ReadASN1(&certSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("brainpool: failed to parse certificate: invalid ASN.1 data")
	}

	var tbsCertSeq cryptobyte.String
	if !certSeq.ReadASN1(&tbsCertSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("brainpool: failed to parse tbsCertificate: invalid ASN.1 data")
	}

	var versionBytes cryptobyte.String
	var version int = 0 // Default v1
	if tbsCertSeq.ReadOptionalASN1(&versionBytes, nil, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
		// Inside the explicit tag is the actual Integer
		if !versionBytes.ReadASN1Integer(&version) {
			return nil, errors.New("brainpool: failed to parse certificate version")
		}
	}

	var serial cryptobyte.String
	if !tbsCertSeq.ReadASN1(&serial, cryptobyte_asn1.INTEGER) {
		return nil, errors.New("brainpool: failed to parse serial number")
	}

	var sigAlgSeq cryptobyte.String
	if !tbsCertSeq.ReadASN1(&sigAlgSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("brainpool: failed to parse signature algorithm")
	}

	var issuerSeq cryptobyte.String
	if !tbsCertSeq.ReadASN1(&issuerSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("brainpool: failed to parse issuer")
	}

	var validitySeq cryptobyte.String
	if !tbsCertSeq.ReadASN1(&validitySeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("brainpool: failed to parse validity")
	}

	var subjectSeq cryptobyte.String
	if !tbsCertSeq.ReadASN1(&subjectSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("brainpool: failed to parse subject")
	}

	var spkiSeq cryptobyte.String
	if !tbsCertSeq.ReadASN1(&spkiSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("brainpool: failed to parse SubjectPublicKeyInfo")
	}

	var spkiAlgSeq cryptobyte.String
	if !spkiSeq.ReadASN1(&spkiAlgSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("brainpool: failed to parse AlgorithmIdentifier")
	}

	var spkiAlgOid asn1.ObjectIdentifier
	if !spkiAlgSeq.ReadASN1ObjectIdentifier(&spkiAlgOid) {
		return nil, errors.New("brainpool: failed to read OID")
	}

	if !spkiAlgOid.Equal(oidPublicKeyECDSA) {
		// return fallback to standard parser
		return x509.ParseCertificate(der)
	}

	var curveOid asn1.ObjectIdentifier
	if !spkiAlgSeq.ReadASN1ObjectIdentifier(&curveOid) {
		return nil, errors.New("brainpool: failed to read curve OID")
	}

	ok, curve := CurveFromOID(curveOid)
	if !ok {
		// not a brainpool curve, return fallback to standard parser
		return x509.ParseCertificate(der)
	}

	// it's a brainpool certificate, we need tp parse certificate ourselves
	cert := new(x509.Certificate)
	// set the fields we have parsed already
	cert.Raw = der
	cert.RawIssuer = issuerSeq
	cert.RawSubject = subjectSeq
	cert.RawTBSCertificate = tbsCertSeq
	cert.RawSubjectPublicKeyInfo = spkiSeq
	cert.Version = version + 1
	cert.SerialNumber = new(big.Int).SetBytes(serial)
	// brainpool is only ECDSA
	cert.PublicKeyAlgorithm = x509.ECDSA

	// parse issuer
	issuerRDN, err := parseRDNSequence(&issuerSeq)
	if err != nil {
		return nil, err
	}
	cert.Issuer.FillFromRDNSequence(issuerRDN)

	// parse subject
	subjectRDN, err := parseRDNSequence(&subjectSeq)
	if err != nil {
		return nil, err
	}
	cert.Subject.FillFromRDNSequence(subjectRDN)

	// parse validity
	notBefore, notAfter, err := parseValidity(validitySeq)
	if err != nil {
		return nil, err
	}
	cert.NotBefore = notBefore
	cert.NotAfter = notAfter

	// parse brainpool public key
	var spk asn1.BitString
	if !spkiSeq.ReadASN1BitString(&spk) {
		return nil, errors.New("brainpool: failed to read subject public key")
	}

	var spkDer = cryptobyte.String(spk.RightAlign())

	x, y := elliptic.Unmarshal(curve, spkDer)

	cert.PublicKey = &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	if cert.Version > 1 {
		// Skip optional issuer and subject unique IDs (tags 1 and 2)
		if !tbsCertSeq.ReadOptionalASN1(nil, nil, cryptobyte_asn1.Tag(1).ContextSpecific()) {
			return nil, errors.New("brainpool: failed to parse issuer unique ID")
		}
		if !tbsCertSeq.ReadOptionalASN1(nil, nil, cryptobyte_asn1.Tag(2).ContextSpecific()) {
			return nil, errors.New("brainpool: failed to parse subject unique ID")
		}
		if cert.Version == 3 {
			var extensionsSeq cryptobyte.String
			if tbsCertSeq.ReadOptionalASN1(&extensionsSeq, nil, cryptobyte_asn1.Tag(3).ContextSpecific().Constructed()) {
				var extensions cryptobyte.String
				if !extensionsSeq.ReadASN1(&extensions, cryptobyte_asn1.SEQUENCE) {
					return nil, errors.New("brainpool: failed to parse extensions")
				}
				for !extensions.Empty() {
					var extSeq cryptobyte.String
					if !extensions.ReadASN1(&extSeq, cryptobyte_asn1.SEQUENCE) {
						return nil, errors.New("brainpool: failed to parse extension sequence")
					}
					ext, err := parseExtension(&extSeq)
					if err != nil {
						return nil, err
					}
					cert.Extensions = append(cert.Extensions, *ext)
				}
				if err = processKnownExtensions(cert); err != nil {
					return nil, err
				}
			}
		}
	}

	// read signature algorithm
	var outserAlgSeq cryptobyte.String
	if !certSeq.ReadASN1(&outserAlgSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("brainpool: failed to parse outer signature algorithm")
	}

	if !bytes.Equal(sigAlgSeq, outserAlgSeq) {
		return nil, errors.New("brainpool: signature algorithm mismatch between tbsCertificate and outer certificate")
	}

	sigAlg, err := parseSignatureAlgorithm(&sigAlgSeq)
	if err != nil {
		return nil, err
	}
	cert.SignatureAlgorithm = sigAlg

	// parse signature bytes
	var signature asn1.BitString
	if !certSeq.ReadASN1BitString(&signature) {
		return nil, errors.New("brainpool: failed to read signature")
	}
	cert.Signature = signature.RightAlign()

	return cert, nil
}

func parseSignatureAlgorithm(algSeq *cryptobyte.String) (x509.SignatureAlgorithm, error) {
	var algOID asn1.ObjectIdentifier
	if !algSeq.ReadASN1ObjectIdentifier(&algOID) {
		return x509.UnknownSignatureAlgorithm, errors.New("brainpool: failed to read signature algorithm OID")
	}

	switch {
	case algOID.Equal(oidSignatureECDSAWithSHA256):
		return x509.ECDSAWithSHA256, nil
	case algOID.Equal(oidSignatureECDSAWithSHA384):
		return x509.ECDSAWithSHA384, nil
	case algOID.Equal(oidSignatureECDSAWithSHA512):
		return x509.ECDSAWithSHA512, nil
	case algOID.Equal(oidSignatureSHA256WithRSA):
		return x509.SHA256WithRSA, nil
	case algOID.Equal(oidSignatureSHA384WithRSA):
		return x509.SHA384WithRSA, nil
	case algOID.Equal(oidSignatureSHA512WithRSA):
		return x509.SHA512WithRSA, nil
	}

	return x509.UnknownSignatureAlgorithm, fmt.Errorf("brainpool: unknown signature algorithm OID: %v", algOID)
}

func parseRDNSequence(rdnSeq *cryptobyte.String) (*pkix.RDNSequence, error) {
	var rdn pkix.RDNSequence

	for !rdnSeq.Empty() {
		var setSeq cryptobyte.String
		if !rdnSeq.ReadASN1(&setSeq, cryptobyte_asn1.SET) {
			return nil, errors.New("brainpool: failed to parse RDN set")
		}

		var atvs []pkix.AttributeTypeAndValue
		for !setSeq.Empty() {
			var atvSeq cryptobyte.String
			if !setSeq.ReadASN1(&atvSeq, cryptobyte_asn1.SEQUENCE) {
				return nil, errors.New("brainpool: failed to parse AttributeTypeAndValue sequence")
			}

			var typeOID asn1.ObjectIdentifier
			if !atvSeq.ReadASN1ObjectIdentifier(&typeOID) {
				return nil, errors.New("brainpool: failed to read AttributeType OID")
			}

			var valueRaw cryptobyte.String
			var valueTag cryptobyte_asn1.Tag
			if !atvSeq.ReadAnyASN1(&valueRaw, &valueTag) {
				return nil, errors.New("brainpool: failed to read AttributeValue")
			}

			// Decode the ASN.1 string value based on the tag type
			var value interface{}
			switch valueTag {
			case cryptobyte_asn1.UTF8String, cryptobyte_asn1.PrintableString, cryptobyte_asn1.IA5String:
				value = string(valueRaw)
			default:
				// For other types, use asn1.Unmarshal to decode properly
				var rawVal asn1.RawValue
				// Reconstruct the full DER encoding (tag + length + content) for asn1.Unmarshal
				rawVal.Tag = int(valueTag) & 0x1f
				rawVal.Class = int(valueTag) >> 6
				rawVal.Bytes = []byte(valueRaw)
				rawVal.FullBytes = nil
				value = rawVal
			}

			atvs = append(atvs, pkix.AttributeTypeAndValue{
				Type:  typeOID,
				Value: value,
			})
		}

		rdn = append(rdn, atvs)
	}

	return &rdn, nil
}

func nextTime(der *cryptobyte.String) (time.Time, error) {
	var t time.Time
	switch {
	case der.PeekASN1Tag(cryptobyte_asn1.UTCTime):
		if !der.ReadASN1UTCTime(&t) {
			return t, errors.New("brainpool: malformed UTCTime")
		}
	case der.PeekASN1Tag(cryptobyte_asn1.GeneralizedTime):
		if !der.ReadASN1GeneralizedTime(&t) {
			return t, errors.New("brainpool: malformed GeneralizedTime")
		}
	default:
		return t, errors.New("brainpool: invalid time format")
	}
	return t, nil
}

func parseValidity(validitySeq cryptobyte.String) (notBefore, notAfter time.Time, err error) {
	// parse notBefore
	notBefore, err = nextTime(&validitySeq)
	if err != nil {
		return notBefore, notAfter, err
	}

	// parse notAfter
	notAfter, err = nextTime(&validitySeq)
	if err != nil {
		return notBefore, notAfter, err
	}

	return notBefore, notAfter, nil
}

func parseExtension(extSeq *cryptobyte.String) (*pkix.Extension, error) {
	var ext pkix.Extension

	if !extSeq.ReadASN1ObjectIdentifier(&ext.Id) {
		return nil, errors.New("brainpool: failed to read extension OID")
	}

	if extSeq.PeekASN1Tag(cryptobyte_asn1.BOOLEAN) {
		if !extSeq.ReadASN1Boolean(&ext.Critical) {
			return nil, errors.New("brainpool: failed to read extension critical flag")
		}
	}

	var extValue cryptobyte.String
	if !extSeq.ReadASN1(&extValue, cryptobyte_asn1.OCTET_STRING) {
		return nil, errors.New("brainpool: failed to read extension value")
	}
	ext.Value = extValue

	return &ext, nil
}

func processKnownExtensions(cert *x509.Certificate) (err error) {
	for _, ext := range cert.Extensions {
		switch {
		case ext.Id.Equal(oidExtensionSubjectKeyID):
			val := cryptobyte.String(ext.Value)
			var skid cryptobyte.String
			if !val.ReadASN1(&skid, cryptobyte_asn1.OCTET_STRING) {
				return errors.New("brainpool: failed to parse SubjectKeyId")
			}
			cert.SubjectKeyId = skid
		case ext.Id.Equal(oidExtensionBasicConstraints):
			isCA, maxPathLen, maxPathLenZero, err := parseExtensionBasicConstraints(cryptobyte.String(ext.Value))
			if err != nil {
				return err
			}
			cert.IsCA = isCA
			cert.MaxPathLen = maxPathLen
			cert.MaxPathLenZero = maxPathLenZero
		case ext.Id.Equal(oidExtensionKeyUsage):
			if cert.KeyUsage, err = parseExtensionKeyUsage(ext.Value); err != nil {
				return err
			}
		case ext.Id.Equal(oidExtensionExtKeyUsage):
			if cert.ExtKeyUsage, err = parseExtensionExtKeyUsage(ext.Value); err != nil {
				return err
			}
		case ext.Id.Equal(oidExtensionAuthorityInfoAccess):
			if cert.OCSPServer, cert.IssuingCertificateURL, err = parseExtensionAuthorityInfoAccess(ext.Value); err != nil {
				return err
			}
		case ext.Id.Equal(oidExtensionAuthorityKeyID):
			if cert.AuthorityKeyId, err = parseExtensionAuthorityKeyID(ext.Value); err != nil {
				return err
			}
		case ext.Id.Equal(oidExtensionCertificatePolicies):
			if cert.PolicyIdentifiers, err = parseExtensionCertificatePolicies(ext.Value); err != nil {
				return err
			}
		}
	}

	return nil
}

func parseExtensionKeyUsage(der cryptobyte.String) (x509.KeyUsage, error) {
	var usageBits asn1.BitString
	if !der.ReadASN1BitString(&usageBits) {
		return 0, errors.New("brainpool: failed to read key usage bits")
	}

	var ku x509.KeyUsage
	for i := 0; i < len(usageBits.Bytes)*8; i++ {
		if usageBits.At(i) != 0 {
			ku |= 1 << uint(i)
		}
	}

	return ku, nil
}

func parseExtensionExtKeyUsage(der cryptobyte.String) ([]x509.ExtKeyUsage, error) {
	var extUsages []x509.ExtKeyUsage

	var seq cryptobyte.String
	if !der.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("brainpool: failed to read ext key usage sequence")
	}

	for !seq.Empty() {
		var usageOID asn1.ObjectIdentifier
		if !seq.ReadASN1ObjectIdentifier(&usageOID) {
			return nil, errors.New("brainpool: failed to read ext key usage OID")
		}

		switch {
		case usageOID.Equal(oidExtKeyUsageAny):
			extUsages = append(extUsages, x509.ExtKeyUsageAny)
		case usageOID.Equal(oidExtKeyUsageServerAuth):
			extUsages = append(extUsages, x509.ExtKeyUsageServerAuth)
		case usageOID.Equal(oidExtKeyUsageClientAuth):
			extUsages = append(extUsages, x509.ExtKeyUsageClientAuth)
		case usageOID.Equal(oidExtKeyUsageCodeSigning):
			extUsages = append(extUsages, x509.ExtKeyUsageCodeSigning)
		case usageOID.Equal(oidExtKeyUsageEmailProtection):
			extUsages = append(extUsages, x509.ExtKeyUsageEmailProtection)
		case usageOID.Equal(oidExtKeyUsageIPSECEndSystem):
			extUsages = append(extUsages, x509.ExtKeyUsageIPSECEndSystem)
		case usageOID.Equal(oidExtKeyUsageIPSECTunnel):
			extUsages = append(extUsages, x509.ExtKeyUsageIPSECTunnel)
		case usageOID.Equal(oidExtKeyUsageIPSECUser):
			extUsages = append(extUsages, x509.ExtKeyUsageIPSECUser)
		case usageOID.Equal(oidExtKeyUsageTimeStamping):
			extUsages = append(extUsages, x509.ExtKeyUsageTimeStamping)
		case usageOID.Equal(oidExtKeyUsageOCSPSigning):
			extUsages = append(extUsages, x509.ExtKeyUsageOCSPSigning)
		default:
			return nil, fmt.Errorf("brainpool: unknown ext key usage OID: %v", usageOID)
		}
	}

	return extUsages, nil
}

func parseExtensionBasicConstraints(der cryptobyte.String) (isCA bool, maxPathLen int, maxPathLenZero bool, err error) {
	var bcSeq cryptobyte.String
	if !der.ReadASN1(&bcSeq, cryptobyte_asn1.SEQUENCE) {
		return false, 0, false, errors.New("brainpool: failed to parse BasicConstraints sequence")
	}

	if bcSeq.PeekASN1Tag(cryptobyte_asn1.BOOLEAN) {
		if !bcSeq.ReadASN1Boolean(&isCA) {
			return false, 0, false, errors.New("brainpool: failed to read BasicConstraints cA boolean")
		}
	}

	if bcSeq.Empty() {
		return isCA, 0, false, nil
	}

	var pathLen int64 = -1
	if bcSeq.PeekASN1Tag(cryptobyte_asn1.INTEGER) {
		if !bcSeq.ReadASN1Integer(&pathLen) {
			return false, 0, false, errors.New("brainpool: failed to read BasicConstraints pathLenConstraint")
		}
	}

	return isCA, int(pathLen), false, nil
}

func parseExtensionAuthorityInfoAccess(der cryptobyte.String) (ocspServers []string, issuingURLs []string, err error) {
	var val cryptobyte.String
	if !der.ReadASN1(&val, cryptobyte_asn1.SEQUENCE) {
		return nil, nil, errors.New("brainpool: invalid authority info access")
	}

	for !val.Empty() {
		var aiaDER cryptobyte.String
		if !val.ReadASN1(&aiaDER, cryptobyte_asn1.SEQUENCE) {
			return nil, nil, errors.New("brainpool: invalid authority info access")
		}

		var method asn1.ObjectIdentifier
		if !aiaDER.ReadASN1ObjectIdentifier(&method) {
			return nil, nil, errors.New("brainpool: invalid authority info access")
		}

		if !aiaDER.PeekASN1Tag(cryptobyte_asn1.Tag(6).ContextSpecific()) {
			continue
		}

		if !aiaDER.ReadASN1(&aiaDER, cryptobyte_asn1.Tag(6).ContextSpecific()) {
			return nil, nil, errors.New("brainpool: invalid authority info access")
		}

		switch {
		case method.Equal(oidAuthorityInfoAccessOcsp):
			ocspServers = append(ocspServers, string(aiaDER))
		case method.Equal(oidAuthorityInfoAccessIssuers):
			issuingURLs = append(issuingURLs, string(aiaDER))
		}
	}

	return ocspServers, issuingURLs, nil
}

func parseExtensionAuthorityKeyID(der cryptobyte.String) ([]byte, error) {
	var akidSeq cryptobyte.String
	if !der.ReadASN1(&akidSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("brainpool: failed to parse AuthorityKeyID sequence")
	}

	if akidSeq.PeekASN1Tag(cryptobyte_asn1.Tag(0).ContextSpecific()) {
		var keyIDBytes cryptobyte.String
		if !akidSeq.ReadASN1(&keyIDBytes, cryptobyte_asn1.Tag(0).ContextSpecific()) {
			return nil, errors.New("brainpool: failed to read AuthorityKeyID keyIdentifier")
		}
		return keyIDBytes, nil
	}

	return nil, nil
}

func parseExtensionCertificatePolicies(der cryptobyte.String) (policies []asn1.ObjectIdentifier, err error) {
	var policiesSeq cryptobyte.String
	if !der.ReadASN1(&policiesSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, errors.New("brainpool: failed to parse CertificatePolicies sequence")
	}

	for !policiesSeq.Empty() {
		var policySeq cryptobyte.String
		if !policiesSeq.ReadASN1(&policySeq, cryptobyte_asn1.SEQUENCE) {
			return nil, errors.New("brainpool: failed to parse PolicyInformation sequence")
		}

		var policyOID asn1.ObjectIdentifier
		if !policySeq.ReadASN1ObjectIdentifier(&policyOID) {
			return nil, errors.New("brainpool: failed to read policy OID")
		}

		policies = append(policies, policyOID)

		// skip optional policy qualifiers
		if !policySeq.Empty() {
			var skip cryptobyte.String
			if !policySeq.ReadASN1(&skip, cryptobyte_asn1.SEQUENCE) {
				return nil, errors.New("brainpool: failed to skip policy qualifiers")
			}
		}
	}

	return policies, nil
}
