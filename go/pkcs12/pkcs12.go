// Package pkcs12 implements parsing of PKCS#12 files as defined in RFC 7292.
// It provides structures and functions to parse PKCS#12 without decrypting
// keys and certificates, leaving that to appropriate crypto packages.
package pkcs12

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Common PKCS#12 OIDs as defined in RFC 7292
var (
	// PKCS#7 Content Types
	OIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	// PKCS#12 Bag Types (RFC 7292 Section 4.2.1)
	OIDKeyBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	OIDPKCS8ShroudedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	OIDCertBag             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	OIDCRLBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 4}
	OIDSecretBag           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 5}
	OIDSafeContentsBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}

	// Certificate Types
	OIDX509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	OIDSDSICertificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 2}

	// Attribute OIDs
	OIDFriendlyName = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	OIDLocalKeyID   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}

	// Modern encryption algorithms (PBES2)
	OIDPBES2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	OIDPBKDF2    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	OIDAes128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OIDAes192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	OIDAes256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	// Legacy PKCS#12 algorithms (for reference, but not recommended)
	OIDPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	OIDPBEWithSHAAnd128BitRC2CBC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}

	// HMAC algorithms for integrity
	OIDHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	OIDHMACSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	OIDHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	OIDHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	OIDHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	// NIST hash algorithms (also used for HMAC and MAC)
	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
)

var (
	ErrInvalidPFX           = errors.New("pkcs12: invalid PFX structure")
	ErrUnsupportedAlgorithm = errors.New("pkcs12: unsupported algorithm")
	ErrInvalidMAC           = errors.New("pkcs12: invalid MAC")
	ErrParse                = errors.New("pkcs12: parse error")
)

// PFX represents the PKCS#12 PFX structure (RFC 7292 Section 4)
type PFX struct {
	Version     int
	AuthSafe    ContentInfo
	MacData     *MacData
	RawAuthSafe []byte // Raw authenticated safe contents
}

// ContentInfo represents PKCS#7 ContentInfo (RFC 2315)
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     []byte // Raw content, context-specific [0]
}

// MacData represents MAC data for integrity verification (RFC 7292 Section 4)
type MacData struct {
	Mac        DigestInfo
	MacSalt    []byte
	Iterations int
}

// DigestInfo represents algorithm and digest
type DigestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

// AuthenticatedSafe contains the authenticated safe contents
type AuthenticatedSafe struct {
	ContentInfos []ContentInfo
}

// SafeContents is a sequence of SafeBags
type SafeContents struct {
	Bags []SafeBag
}

// SafeBag represents a bag in PKCS#12 (RFC 7292 Section 4.2)
type SafeBag struct {
	BagID      asn1.ObjectIdentifier
	BagValue   []byte // Raw bag value
	Attributes []PKCS12Attribute
}

// PKCS12Attribute represents attributes attached to bags
type PKCS12Attribute struct {
	ID     asn1.ObjectIdentifier
	Values [][]byte // Raw attribute values
}

// CertBag represents a certificate bag (RFC 7292 Section 4.2.3)
type CertBag struct {
	CertID    asn1.ObjectIdentifier
	CertValue []byte // Raw certificate data
}

// EncryptedPrivateKeyInfo represents encrypted private key (RFC 5208)
type EncryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte // Encrypted data
}

// EncryptionAlgorithm represents parsed encryption algorithm parameters
type EncryptionAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Salt       []byte
	Iterations int
	// For PBES2
	KDF    *PBKDF2Params
	Cipher *CipherParams
}

// PBKDF2Params represents PBKDF2 parameters
type PBKDF2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int
	PRF        asn1.ObjectIdentifier
}

// CipherParams represents cipher algorithm parameters
type CipherParams struct {
	Algorithm asn1.ObjectIdentifier
	IV        []byte
}

// Parse parses a PKCS#12 PFX structure from DER-encoded data
func Parse(data []byte) (*PFX, error) {
	// Validate minimum size
	if len(data) < 10 {
		return nil, fmt.Errorf("%w: file too small (%d bytes)", ErrInvalidPFX, len(data))
	}

	// Check for BER indefinite-length encoding
	if len(data) >= 2 && data[0] == 0x30 && data[1] == 0x80 {
		return nil, fmt.Errorf("%w: BER indefinite-length encoding detected. Use github.com/gematik/zero-lab/go/pkcs12/legacy package", ErrInvalidPFX)
	}

	// Check for valid SEQUENCE tag
	if data[0] != 0x30 {
		return nil, fmt.Errorf("%w: invalid DER structure, expected SEQUENCE tag (0x30), got 0x%02x. "+
			"File may be corrupted or not a PKCS#12 file", ErrInvalidPFX, data[0])
	}

	input := cryptobyte.String(data)

	// PFX ::= SEQUENCE {
	//   version    INTEGER {v3(3)}(v3,...),
	//   authSafe   ContentInfo,
	//   macData    MacData OPTIONAL
	// }
	var pfx PFX
	var seq cryptobyte.String

	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: failed to read PFX SEQUENCE at offset 0. "+
			"File may use unsupported encoding or be corrupted", ErrInvalidPFX)
	}

	if !seq.ReadASN1Integer(&pfx.Version) {
		return nil, fmt.Errorf("%w: failed to read version", ErrInvalidPFX)
	}

	if pfx.Version != 3 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidPFX, pfx.Version)
	}

	// Parse authSafe ContentInfo
	var err error
	pfx.AuthSafe, err = parseContentInfo(&seq)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to parse authSafe: %v", ErrInvalidPFX, err)
	}

	// Parse optional MacData
	if !seq.Empty() {
		macData, err := parseMacData(&seq)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to parse MacData: %v", ErrInvalidPFX, err)
		}
		pfx.MacData = macData
	}

	// Extract raw authenticated safe contents
	if pfx.AuthSafe.ContentType.Equal(OIDData) {
		pfx.RawAuthSafe, err = extractOctetString(pfx.AuthSafe.Content)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to extract authSafe content: %v", ErrParse, err)
		}
	} else {
		pfx.RawAuthSafe = pfx.AuthSafe.Content
	}

	return &pfx, nil
}

// parseContentInfo parses a PKCS#7 ContentInfo structure
func parseContentInfo(s *cryptobyte.String) (ContentInfo, error) {
	var ci ContentInfo
	var seq cryptobyte.String

	if !s.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return ci, fmt.Errorf("%w: failed to read ContentInfo SEQUENCE", ErrParse)
	}

	if !seq.ReadASN1ObjectIdentifier(&ci.ContentType) {
		return ci, fmt.Errorf("%w: failed to read contentType", ErrParse)
	}

	// Content is [0] EXPLICIT ANY DEFINED BY contentType
	var content cryptobyte.String
	if !seq.ReadASN1(&content, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
		return ci, fmt.Errorf("%w: failed to read content", ErrParse)
	}

	ci.Content = []byte(content)
	return ci, nil
}

// parseMacData parses MacData structure
func parseMacData(s *cryptobyte.String) (*MacData, error) {
	var md MacData
	var seq cryptobyte.String

	if !s.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: failed to read MacData SEQUENCE", ErrParse)
	}

	// Parse DigestInfo
	var digestSeq cryptobyte.String
	if !seq.ReadASN1(&digestSeq, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: failed to read DigestInfo", ErrParse)
	}

	// Parse algorithm
	if err := parseAlgorithmIdentifier(&digestSeq, &md.Mac.Algorithm); err != nil {
		return nil, err
	}

	// Parse digest
	if !digestSeq.ReadASN1Bytes(&md.Mac.Digest, cryptobyte_asn1.OCTET_STRING) {
		return nil, fmt.Errorf("%w: failed to read digest", ErrParse)
	}

	// Parse macSalt
	if !seq.ReadASN1Bytes(&md.MacSalt, cryptobyte_asn1.OCTET_STRING) {
		return nil, fmt.Errorf("%w: failed to read macSalt", ErrParse)
	}

	// Parse iterations (default is 1)
	md.Iterations = 1
	if !seq.Empty() {
		if !seq.ReadASN1Integer(&md.Iterations) {
			return nil, fmt.Errorf("%w: failed to read iterations", ErrParse)
		}
	}

	return &md, nil
}

// ParseAuthenticatedSafe parses the authenticated safe contents
func ParseAuthenticatedSafe(data []byte) (*AuthenticatedSafe, error) {
	input := cryptobyte.String(data)
	var authSafe AuthenticatedSafe
	var seq cryptobyte.String

	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: failed to read AuthenticatedSafe SEQUENCE", ErrParse)
	}

	for !seq.Empty() {
		ci, err := parseContentInfo(&seq)
		if err != nil {
			return nil, err
		}
		authSafe.ContentInfos = append(authSafe.ContentInfos, ci)
	}

	return &authSafe, nil
}

// ParseSafeContents parses safe contents (a sequence of SafeBags)
func ParseSafeContents(data []byte) (*SafeContents, error) {
	input := cryptobyte.String(data)
	var sc SafeContents
	var seq cryptobyte.String

	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: failed to read SafeContents SEQUENCE", ErrParse)
	}

	for !seq.Empty() {
		bag, err := parseSafeBag(&seq)
		if err != nil {
			return nil, err
		}
		sc.Bags = append(sc.Bags, bag)
	}

	return &sc, nil
}

// parseSafeBag parses a single SafeBag
func parseSafeBag(s *cryptobyte.String) (SafeBag, error) {
	var bag SafeBag
	var seq cryptobyte.String

	if !s.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return bag, fmt.Errorf("%w: failed to read SafeBag SEQUENCE", ErrParse)
	}

	// Parse bagId
	if !seq.ReadASN1ObjectIdentifier(&bag.BagID) {
		return bag, fmt.Errorf("%w: failed to read bagId", ErrParse)
	}

	// Parse bagValue [0] EXPLICIT
	var bagValue cryptobyte.String
	if !seq.ReadASN1(&bagValue, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
		return bag, fmt.Errorf("%w: failed to read bagValue", ErrParse)
	}
	bag.BagValue = []byte(bagValue)

	// Parse optional attributes [SET OF PKCS12Attribute]
	if !seq.Empty() {
		var attrSet cryptobyte.String
		if !seq.ReadASN1(&attrSet, cryptobyte_asn1.SET) {
			return bag, fmt.Errorf("%w: failed to read attributes SET", ErrParse)
		}

		for !attrSet.Empty() {
			attr, err := parsePKCS12Attribute(&attrSet)
			if err != nil {
				return bag, err
			}
			bag.Attributes = append(bag.Attributes, attr)
		}
	}

	return bag, nil
}

// parsePKCS12Attribute parses a PKCS12Attribute
func parsePKCS12Attribute(s *cryptobyte.String) (PKCS12Attribute, error) {
	var attr PKCS12Attribute
	var seq cryptobyte.String

	if !s.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return attr, fmt.Errorf("%w: failed to read Attribute SEQUENCE", ErrParse)
	}

	if !seq.ReadASN1ObjectIdentifier(&attr.ID) {
		return attr, fmt.Errorf("%w: failed to read attribute ID", ErrParse)
	}

	var valuesSet cryptobyte.String
	if !seq.ReadASN1(&valuesSet, cryptobyte_asn1.SET) {
		return attr, fmt.Errorf("%w: failed to read attribute values SET", ErrParse)
	}

	for !valuesSet.Empty() {
		var value cryptobyte.String
		var tag cryptobyte_asn1.Tag
		if !valuesSet.ReadAnyASN1Element(&value, &tag) {
			return attr, fmt.Errorf("%w: failed to read attribute value", ErrParse)
		}
		attr.Values = append(attr.Values, []byte(value))
	}

	return attr, nil
}

// ParseCertBag parses a CertBag from bag value
func ParseCertBag(data []byte) (*CertBag, error) {
	input := cryptobyte.String(data)
	var cb CertBag
	var seq cryptobyte.String

	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: failed to read CertBag SEQUENCE", ErrParse)
	}

	if !seq.ReadASN1ObjectIdentifier(&cb.CertID) {
		return nil, fmt.Errorf("%w: failed to read certId", ErrParse)
	}

	// certValue [0] EXPLICIT OCTET STRING
	var certValue cryptobyte.String
	if !seq.ReadASN1(&certValue, cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()) {
		return nil, fmt.Errorf("%w: failed to read certValue context", ErrParse)
	}

	if !certValue.ReadASN1Bytes(&cb.CertValue, cryptobyte_asn1.OCTET_STRING) {
		return nil, fmt.Errorf("%w: failed to read certValue OCTET STRING", ErrParse)
	}

	return &cb, nil
}

// ParseEncryptedPrivateKeyInfo parses EncryptedPrivateKeyInfo
func ParseEncryptedPrivateKeyInfo(data []byte) (*EncryptedPrivateKeyInfo, error) {
	input := cryptobyte.String(data)
	var epki EncryptedPrivateKeyInfo
	var seq cryptobyte.String

	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: failed to read EncryptedPrivateKeyInfo SEQUENCE", ErrParse)
	}

	if err := parseAlgorithmIdentifier(&seq, &epki.Algorithm); err != nil {
		return nil, err
	}

	if !seq.ReadASN1Bytes(&epki.Data, cryptobyte_asn1.OCTET_STRING) {
		return nil, fmt.Errorf("%w: failed to read encrypted data", ErrParse)
	}

	return &epki, nil
}

// ParseEncryptionAlgorithm parses encryption algorithm parameters
func ParseEncryptionAlgorithm(alg pkix.AlgorithmIdentifier) (*EncryptionAlgorithm, error) {
	// Handle PBES2 (modern, recommended)
	if alg.Algorithm.Equal(OIDPBES2) {
		return parsePBES2Params(alg.Parameters.FullBytes)
	}

	// Handle legacy PKCS#12 PBE algorithms
	if alg.Algorithm.Equal(OIDPBEWithSHAAnd3KeyTripleDESCBC) ||
		alg.Algorithm.Equal(OIDPBEWithSHAAnd128BitRC2CBC) {
		return parseLegacyPBEParams(alg)
	}

	return nil, fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, alg.Algorithm)
}

// parsePBES2Params parses PBES2 parameters
func parsePBES2Params(data []byte) (*EncryptionAlgorithm, error) {
	input := cryptobyte.String(data)
	var seq cryptobyte.String

	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: failed to read PBES2 params", ErrParse)
	}

	ea := &EncryptionAlgorithm{
		Algorithm: OIDPBES2,
	}

	// Parse KDF AlgorithmIdentifier
	var kdfAlg pkix.AlgorithmIdentifier
	if err := parseAlgorithmIdentifier(&seq, &kdfAlg); err != nil {
		return nil, err
	}

	if !kdfAlg.Algorithm.Equal(OIDPBKDF2) {
		return nil, fmt.Errorf("%w: unsupported KDF: %v", ErrUnsupportedAlgorithm, kdfAlg.Algorithm)
	}

	// Parse PBKDF2 params
	kdfParams, err := parsePBKDF2Params(kdfAlg.Parameters.FullBytes)
	if err != nil {
		return nil, err
	}
	ea.KDF = kdfParams

	// Parse cipher AlgorithmIdentifier
	var cipherAlg pkix.AlgorithmIdentifier
	if err := parseAlgorithmIdentifier(&seq, &cipherAlg); err != nil {
		return nil, err
	}

	// Parse cipher params (typically IV for CBC)
	cipherParams, err := parseCipherParams(cipherAlg)
	if err != nil {
		return nil, err
	}
	ea.Cipher = cipherParams

	return ea, nil
}

// parsePBKDF2Params parses PBKDF2 parameters
func parsePBKDF2Params(data []byte) (*PBKDF2Params, error) {
	input := cryptobyte.String(data)
	var seq cryptobyte.String

	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: failed to read PBKDF2 params", ErrParse)
	}

	params := &PBKDF2Params{}

	// Parse salt (OCTET STRING)
	if !seq.ReadASN1Bytes(&params.Salt, cryptobyte_asn1.OCTET_STRING) {
		return nil, fmt.Errorf("%w: failed to read salt", ErrParse)
	}

	// Parse iteration count
	if !seq.ReadASN1Integer(&params.Iterations) {
		return nil, fmt.Errorf("%w: failed to read iterations", ErrParse)
	}

	// Optional keyLength
	if !seq.Empty() && seq.PeekASN1Tag(cryptobyte_asn1.INTEGER) {
		if !seq.ReadASN1Integer(&params.KeyLength) {
			return nil, fmt.Errorf("%w: failed to read keyLength", ErrParse)
		}
	}

	// Optional PRF (default is HMAC-SHA1)
	params.PRF = OIDHMACSHA1
	if !seq.Empty() {
		var prfAlg pkix.AlgorithmIdentifier
		if err := parseAlgorithmIdentifier(&seq, &prfAlg); err == nil {
			params.PRF = prfAlg.Algorithm
		}
	}

	return params, nil
}

// parseCipherParams parses cipher parameters
func parseCipherParams(alg pkix.AlgorithmIdentifier) (*CipherParams, error) {
	params := &CipherParams{
		Algorithm: alg.Algorithm,
	}

	// For AES-CBC, parameters are IV (OCTET STRING)
	if alg.Algorithm.Equal(OIDAes128CBC) ||
		alg.Algorithm.Equal(OIDAes192CBC) ||
		alg.Algorithm.Equal(OIDAes256CBC) {
		input := cryptobyte.String(alg.Parameters.FullBytes)
		if !input.ReadASN1Bytes(&params.IV, cryptobyte_asn1.OCTET_STRING) {
			return nil, fmt.Errorf("%w: failed to read IV", ErrParse)
		}
	}

	return params, nil
}

// parseLegacyPBEParams parses legacy PKCS#12 PBE parameters
func parseLegacyPBEParams(alg pkix.AlgorithmIdentifier) (*EncryptionAlgorithm, error) {
	ea := &EncryptionAlgorithm{
		Algorithm: alg.Algorithm,
	}

	input := cryptobyte.String(alg.Parameters.FullBytes)
	var seq cryptobyte.String

	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: failed to read PBE params", ErrParse)
	}

	if !seq.ReadASN1Bytes(&ea.Salt, cryptobyte_asn1.OCTET_STRING) {
		return nil, fmt.Errorf("%w: failed to read salt", ErrParse)
	}

	if !seq.ReadASN1Integer(&ea.Iterations) {
		return nil, fmt.Errorf("%w: failed to read iterations", ErrParse)
	}

	return ea, nil
}

// parseAlgorithmIdentifier parses an AlgorithmIdentifier
func parseAlgorithmIdentifier(s *cryptobyte.String, alg *pkix.AlgorithmIdentifier) error {
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) {
		return fmt.Errorf("%w: failed to read AlgorithmIdentifier", ErrParse)
	}

	if !seq.ReadASN1ObjectIdentifier(&alg.Algorithm) {
		return fmt.Errorf("%w: failed to read algorithm OID", ErrParse)
	}

	if !seq.Empty() {
		// Try to read parameters - they could be NULL, SEQUENCE, or other types
		remaining := []byte(seq)
		alg.Parameters = asn1.RawValue{FullBytes: remaining}
	}

	return nil
}

// extractOctetString extracts data from OCTET STRING wrapper
func extractOctetString(data []byte) ([]byte, error) {
	input := cryptobyte.String(data)
	var result []byte
	if !input.ReadASN1Bytes(&result, cryptobyte_asn1.OCTET_STRING) {
		return nil, fmt.Errorf("%w: failed to read OCTET STRING", ErrParse)
	}
	return result, nil
}

// GetFriendlyName extracts friendly name from bag attributes
func GetFriendlyName(attrs []PKCS12Attribute) (string, bool) {
	for _, attr := range attrs {
		if attr.ID.Equal(OIDFriendlyName) && len(attr.Values) > 0 {
			// BMPString encoding
			input := cryptobyte.String(attr.Values[0])
			var bmpString []byte
			if input.ReadASN1Bytes(&bmpString, cryptobyte_asn1.Tag(30)) {
				// Convert BMPString (UTF-16BE) to UTF-8
				if name, err := decodeBMPString(bmpString); err == nil {
					return name, true
				}
			}
		}
	}
	return "", false
}

// GetLocalKeyID extracts local key ID from bag attributes
func GetLocalKeyID(attrs []PKCS12Attribute) ([]byte, bool) {
	for _, attr := range attrs {
		if attr.ID.Equal(OIDLocalKeyID) && len(attr.Values) > 0 {
			input := cryptobyte.String(attr.Values[0])
			var keyID []byte
			if input.ReadASN1Bytes(&keyID, cryptobyte_asn1.OCTET_STRING) {
				return keyID, true
			}
		}
	}
	return nil, false
}

// decodeBMPString decodes a BMPString (UTF-16BE) to UTF-8 string
func decodeBMPString(bmpData []byte) (string, error) {
	if len(bmpData)%2 != 0 {
		return "", fmt.Errorf("invalid BMPString length")
	}

	runes := make([]rune, len(bmpData)/2)
	for i := 0; i < len(bmpData); i += 2 {
		runes[i/2] = rune(bmpData[i])<<8 | rune(bmpData[i+1])
	}

	return string(runes), nil
}
