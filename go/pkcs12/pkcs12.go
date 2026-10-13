// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package pkcs12

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"unicode/utf16"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

var (
	// PKCS#7 content types (RFC 2315 §14).
	OIDData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}

	// PKCS#12 bag types (RFC 7292 §4.2).
	OIDKeyBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 1}
	OIDPKCS8ShroudedKeyBag = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 2}
	OIDCertBag             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 3}
	OIDCRLBag              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 4}
	OIDSecretBag           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 5}
	OIDSafeContentsBag     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 10, 1, 6}

	// Certificate types of a CertBag (RFC 7292 §4.2.3).
	OIDX509Certificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 1}
	OIDSDSICertificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 22, 2}

	// Bag attributes (RFC 7292 §4.2, PKCS#9).
	OIDFriendlyName = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	OIDLocalKeyID   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}

	// PBES2 and its parts (RFC 8018 §6.2, appendix B).
	OIDPBES2     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	OIDPBKDF2    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	OIDAes128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OIDAes192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	OIDAes256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}

	// PKCS#12 password-based encryption (RFC 7292 appendix C), read-only.
	// This package decrypts Triple DES; package legacy decrypts RC2 as well.
	OIDPBEWithSHAAnd3KeyTripleDESCBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	OIDPBEWithSHAAnd128BitRC2CBC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}

	// HMAC pseudo-random functions of PBKDF2 (RFC 8018 §B.1).
	OIDHMACSHA1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	OIDHMACSHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	OIDHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	OIDHMACSHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	OIDHMACSHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}

	// Digest algorithms of the PKCS#12 MAC (RFC 7292 §5).
	OIDSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	OIDSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
)

// Errors returned by this package. Callers test with errors.Is; the wrapped
// message adds the detail.
var (
	// ErrInvalidPFX reports input that is not a PKCS#12 PFX structure.
	ErrInvalidPFX = errors.New("pkcs12: invalid PFX structure")
	// ErrUnsupportedAlgorithm reports an algorithm or mode this package does
	// not implement, e.g. the public-key integrity or privacy mode.
	ErrUnsupportedAlgorithm = errors.New("pkcs12: unsupported algorithm")
	// ErrInvalidMAC is kept for compatibility; a MAC mismatch is
	// ErrAuthentication.
	ErrInvalidMAC = errors.New("pkcs12: invalid MAC")
	// ErrParse reports a part of the structure that does not parse.
	ErrParse = errors.New("pkcs12: parse error")
	// ErrLimitExceeded reports an iteration count above the limit this
	// package accepts, see the package documentation.
	ErrLimitExceeded = errors.New("pkcs12: limit exceeded")
)

// PFX is the top-level PKCS#12 structure (RFC 7292 §4).
type PFX struct {
	Version  int
	AuthSafe ContentInfo
	MacData  *MacData
	// RawAuthSafe holds the octets the MAC covers: the value of the authSafe
	// OCTET STRING, with constructed BER segments joined.
	RawAuthSafe []byte
}

// ContentInfo is a PKCS#7 ContentInfo (RFC 2315 §7).
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	// Content is the DER encoding inside the [0] EXPLICIT wrapper.
	Content []byte
}

// MacData is the integrity part of a PFX (RFC 7292 §4).
type MacData struct {
	Mac        DigestInfo
	MacSalt    []byte
	Iterations int
}

// DigestInfo names the MAC digest algorithm and holds the MAC value.
type DigestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

// AuthenticatedSafe is the sequence of ContentInfos the MAC protects.
type AuthenticatedSafe struct {
	ContentInfos []ContentInfo
}

// SafeContents is a sequence of SafeBags.
type SafeContents struct {
	Bags []SafeBag
}

// SafeBag is one bag of a SafeContents (RFC 7292 §4.2).
type SafeBag struct {
	BagID asn1.ObjectIdentifier
	// BagValue is the DER encoding inside the [0] EXPLICIT wrapper.
	BagValue   []byte
	Attributes []PKCS12Attribute
}

// PKCS12Attribute is a bag attribute; Values holds the DER encoding of each
// value of the attribute's SET.
type PKCS12Attribute struct {
	ID     asn1.ObjectIdentifier
	Values [][]byte
}

// CertBag is the value of a certificate bag (RFC 7292 §4.2.3).
type CertBag struct {
	CertID asn1.ObjectIdentifier
	// CertValue is the content of the certValue OCTET STRING, for X.509 the
	// DER certificate.
	CertValue []byte
}

// EncryptedPrivateKeyInfo is the value of a shrouded key bag (RFC 5958 §3).
type EncryptedPrivateKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Data      []byte
}

// EncryptionAlgorithm is a parsed password-based encryption scheme: either
// PBES2 (KDF and Cipher set) or a PKCS#12 PBE (Salt and Iterations set).
type EncryptionAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Salt       []byte
	Iterations int
	KDF        *PBKDF2Params
	Cipher     *CipherParams
}

// PBKDF2Params are the PBKDF2 parameters of PBES2 (RFC 8018 §A.2).
// KeyLength is 0 when absent; PRF is HMAC-SHA-1 when absent.
type PBKDF2Params struct {
	Salt       []byte
	Iterations int
	KeyLength  int
	PRF        asn1.ObjectIdentifier
}

// CipherParams are the encryption scheme of PBES2 and its IV.
type CipherParams struct {
	Algorithm asn1.ObjectIdentifier
	IV        []byte
}

// Parse decodes the PFX structure of a DER-encoded PKCS#12 file without
// decrypting or verifying anything. BER-encoded files, as Java keystores and
// card vendors write them, are read by package legacy.
func Parse(data []byte) (*PFX, error) {
	if len(data) < 10 {
		return nil, fmt.Errorf("%w: file too small (%d bytes)", ErrInvalidPFX, len(data))
	}
	if data[0] == 0x30 && data[1] == 0x80 {
		return nil, fmt.Errorf("%w: BER indefinite-length encoding; use legacy.Decode of github.com/gematik/zero-lab/go/pkcs12/legacy", ErrInvalidPFX)
	}
	if data[0] != 0x30 {
		return nil, fmt.Errorf("%w: expected SEQUENCE tag (0x30), got 0x%02x; not a PKCS#12 file", ErrInvalidPFX, data[0])
	}

	// PFX ::= SEQUENCE { version INTEGER {v3(3)}, authSafe ContentInfo, macData MacData OPTIONAL }
	input := cryptobyte.String(data)
	var seq cryptobyte.String
	var pfx PFX
	var err error
	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("%w: cannot read the PFX SEQUENCE", ErrInvalidPFX)
	}
	if !seq.ReadASN1Integer(&pfx.Version) {
		return nil, fmt.Errorf("%w: cannot read the version", ErrInvalidPFX)
	}
	if pfx.Version != 3 {
		return nil, fmt.Errorf("%w: unsupported version %d", ErrInvalidPFX, pfx.Version)
	}
	if pfx.AuthSafe, err = parseContentInfo(&seq); err != nil {
		return nil, fmt.Errorf("%w: authSafe: %w", ErrInvalidPFX, err)
	}
	if !seq.Empty() {
		if pfx.MacData, err = parseMacData(&seq); err != nil {
			return nil, fmt.Errorf("%w: macData: %w", ErrInvalidPFX, err)
		}
	}
	if !seq.Empty() {
		return nil, fmt.Errorf("%w: trailing data in the PFX SEQUENCE", ErrInvalidPFX)
	}

	if pfx.AuthSafe.ContentType.Equal(OIDData) {
		if pfx.RawAuthSafe, err = extractOctetString(pfx.AuthSafe.Content); err != nil {
			return nil, fmt.Errorf("%w: authSafe content: %w", ErrParse, err)
		}
	} else {
		// A signed authSafe (public-key integrity mode); ExtractBags rejects it.
		pfx.RawAuthSafe = pfx.AuthSafe.Content
	}
	return &pfx, nil
}

var (
	tagContext0Explicit = cryptobyte_asn1.Tag(0).ContextSpecific().Constructed()
	tagContext0Implicit = cryptobyte_asn1.Tag(0).ContextSpecific()
	tagBMPString        = cryptobyte_asn1.Tag(30)
)

// readSequence reads one SEQUENCE that must make up all of input.
func readSequence(input cryptobyte.String, what string) (cryptobyte.String, error) {
	var seq cryptobyte.String
	if !input.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) || !input.Empty() {
		return nil, fmt.Errorf("%w: cannot read %s", ErrParse, what)
	}
	return seq, nil
}

// ParseAuthenticatedSafe parses an AuthenticatedSafe, the SEQUENCE OF
// ContentInfo in PFX.RawAuthSafe.
func ParseAuthenticatedSafe(data []byte) (*AuthenticatedSafe, error) {
	seq, err := readSequence(cryptobyte.String(data), "AuthenticatedSafe")
	if err != nil {
		return nil, err
	}
	var authSafe AuthenticatedSafe
	for !seq.Empty() {
		ci, err := parseContentInfo(&seq)
		if err != nil {
			return nil, err
		}
		authSafe.ContentInfos = append(authSafe.ContentInfos, ci)
	}
	return &authSafe, nil
}

// ParseSafeContents parses a SafeContents, the SEQUENCE OF SafeBag of a safe
// or of a nested safe contents bag.
func ParseSafeContents(data []byte) (*SafeContents, error) {
	seq, err := readSequence(cryptobyte.String(data), "SafeContents")
	if err != nil {
		return nil, err
	}
	var sc SafeContents
	for !seq.Empty() {
		bag, err := parseSafeBag(&seq)
		if err != nil {
			return nil, err
		}
		sc.Bags = append(sc.Bags, bag)
	}
	return &sc, nil
}

// ParseCertBag parses the value of a certificate bag.
func ParseCertBag(data []byte) (*CertBag, error) {
	seq, err := readSequence(cryptobyte.String(data), "CertBag")
	if err != nil {
		return nil, err
	}
	// CertBag ::= SEQUENCE { certId OBJECT IDENTIFIER, certValue [0] EXPLICIT OCTET STRING }
	var cb CertBag
	var certValue cryptobyte.String
	if !seq.ReadASN1ObjectIdentifier(&cb.CertID) ||
		!seq.ReadASN1(&certValue, tagContext0Explicit) ||
		!certValue.ReadASN1Bytes(&cb.CertValue, cryptobyte_asn1.OCTET_STRING) ||
		!certValue.Empty() || !seq.Empty() {
		return nil, fmt.Errorf("%w: cannot read CertBag", ErrParse)
	}
	return &cb, nil
}

// ParseEncryptedPrivateKeyInfo parses the value of a shrouded key bag.
func ParseEncryptedPrivateKeyInfo(data []byte) (*EncryptedPrivateKeyInfo, error) {
	seq, err := readSequence(cryptobyte.String(data), "EncryptedPrivateKeyInfo")
	if err != nil {
		return nil, err
	}
	var epki EncryptedPrivateKeyInfo
	if err := parseAlgorithmIdentifier(&seq, &epki.Algorithm); err != nil {
		return nil, err
	}
	if !seq.ReadASN1Bytes(&epki.Data, cryptobyte_asn1.OCTET_STRING) || !seq.Empty() {
		return nil, fmt.Errorf("%w: cannot read encryptedData", ErrParse)
	}
	return &epki, nil
}

// ParseEncryptionAlgorithm parses the parameters of a password-based
// encryption scheme: PBES2 or one of the PKCS#12 PBEs.
func ParseEncryptionAlgorithm(alg pkix.AlgorithmIdentifier) (*EncryptionAlgorithm, error) {
	if alg.Algorithm.Equal(OIDPBES2) {
		return parsePBES2Params(alg.Parameters.FullBytes)
	}
	if alg.Algorithm.Equal(OIDPBEWithSHAAnd3KeyTripleDESCBC) || alg.Algorithm.Equal(OIDPBEWithSHAAnd128BitRC2CBC) {
		return parseLegacyPBEParams(alg)
	}
	return nil, fmt.Errorf("%w: encryption scheme %v", ErrUnsupportedAlgorithm, alg.Algorithm)
}

func parseContentInfo(s *cryptobyte.String) (ContentInfo, error) {
	// ContentInfo ::= SEQUENCE { contentType OBJECT IDENTIFIER, content [0] EXPLICIT ANY OPTIONAL }
	var ci ContentInfo
	var seq, content cryptobyte.String
	if !s.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) ||
		!seq.ReadASN1ObjectIdentifier(&ci.ContentType) ||
		!seq.ReadASN1(&content, tagContext0Explicit) ||
		!seq.Empty() {
		return ci, fmt.Errorf("%w: cannot read ContentInfo", ErrParse)
	}
	ci.Content = content
	return ci, nil
}

func parseMacData(s *cryptobyte.String) (*MacData, error) {
	// MacData ::= SEQUENCE { mac DigestInfo, macSalt OCTET STRING, iterations INTEGER DEFAULT 1 }
	var md MacData
	var seq, digestInfo cryptobyte.String
	if !s.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) ||
		!seq.ReadASN1(&digestInfo, cryptobyte_asn1.SEQUENCE) {
		return nil, fmt.Errorf("%w: cannot read MacData", ErrParse)
	}
	if err := parseAlgorithmIdentifier(&digestInfo, &md.Mac.Algorithm); err != nil {
		return nil, err
	}
	if !digestInfo.ReadASN1Bytes(&md.Mac.Digest, cryptobyte_asn1.OCTET_STRING) || !digestInfo.Empty() {
		return nil, fmt.Errorf("%w: cannot read the MAC digest", ErrParse)
	}
	if !seq.ReadASN1Bytes(&md.MacSalt, cryptobyte_asn1.OCTET_STRING) {
		return nil, fmt.Errorf("%w: cannot read macSalt", ErrParse)
	}
	md.Iterations = 1
	if !seq.Empty() && !seq.ReadASN1Integer(&md.Iterations) {
		return nil, fmt.Errorf("%w: cannot read the MAC iterations", ErrParse)
	}
	if !seq.Empty() {
		return nil, fmt.Errorf("%w: trailing data in MacData", ErrParse)
	}
	return &md, nil
}

func parseSafeBag(s *cryptobyte.String) (SafeBag, error) {
	// SafeBag ::= SEQUENCE { bagId OBJECT IDENTIFIER, bagValue [0] EXPLICIT ANY, bagAttributes SET OF PKCS12Attribute OPTIONAL }
	var bag SafeBag
	var seq, value cryptobyte.String
	if !s.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) ||
		!seq.ReadASN1ObjectIdentifier(&bag.BagID) ||
		!seq.ReadASN1(&value, tagContext0Explicit) {
		return bag, fmt.Errorf("%w: cannot read SafeBag", ErrParse)
	}
	bag.BagValue = value

	if !seq.Empty() {
		var attributes cryptobyte.String
		if !seq.ReadASN1(&attributes, cryptobyte_asn1.SET) || !seq.Empty() {
			return bag, fmt.Errorf("%w: cannot read the bag attributes", ErrParse)
		}
		for !attributes.Empty() {
			attr, err := parseAttribute(&attributes)
			if err != nil {
				return bag, err
			}
			bag.Attributes = append(bag.Attributes, attr)
		}
	}
	return bag, nil
}

func parseAttribute(s *cryptobyte.String) (PKCS12Attribute, error) {
	// PKCS12Attribute ::= SEQUENCE { attrId OBJECT IDENTIFIER, attrValues SET OF ANY }
	var attr PKCS12Attribute
	var seq, values cryptobyte.String
	if !s.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) ||
		!seq.ReadASN1ObjectIdentifier(&attr.ID) ||
		!seq.ReadASN1(&values, cryptobyte_asn1.SET) ||
		!seq.Empty() {
		return attr, fmt.Errorf("%w: cannot read an attribute", ErrParse)
	}
	for !values.Empty() {
		var value cryptobyte.String
		if !values.ReadAnyASN1Element(&value, nil) {
			return attr, fmt.Errorf("%w: cannot read an attribute value", ErrParse)
		}
		attr.Values = append(attr.Values, value)
	}
	return attr, nil
}

func parsePBES2Params(data []byte) (*EncryptionAlgorithm, error) {
	// PBES2-params ::= SEQUENCE { keyDerivationFunc AlgorithmIdentifier, encryptionScheme AlgorithmIdentifier }
	seq, err := readSequence(cryptobyte.String(data), "PBES2 parameters")
	if err != nil {
		return nil, err
	}
	var kdf, scheme pkix.AlgorithmIdentifier
	if err := parseAlgorithmIdentifier(&seq, &kdf); err != nil {
		return nil, err
	}
	if err := parseAlgorithmIdentifier(&seq, &scheme); err != nil {
		return nil, err
	}
	if !seq.Empty() {
		return nil, fmt.Errorf("%w: trailing data in PBES2 parameters", ErrParse)
	}
	if !kdf.Algorithm.Equal(OIDPBKDF2) {
		return nil, fmt.Errorf("%w: key derivation function %v", ErrUnsupportedAlgorithm, kdf.Algorithm)
	}
	params, err := parsePBKDF2Params(kdf.Parameters.FullBytes)
	if err != nil {
		return nil, err
	}
	cipherParams, err := parseCipherParams(scheme)
	if err != nil {
		return nil, err
	}
	return &EncryptionAlgorithm{Algorithm: OIDPBES2, KDF: params, Cipher: cipherParams}, nil
}

func parsePBKDF2Params(data []byte) (*PBKDF2Params, error) {
	// PBKDF2-params ::= SEQUENCE { salt OCTET STRING, iterationCount INTEGER,
	//   keyLength INTEGER OPTIONAL, prf AlgorithmIdentifier DEFAULT hmacWithSHA1 }
	// The "otherSource" CHOICE of salt is reserved by RFC 8018 and not accepted.
	seq, err := readSequence(cryptobyte.String(data), "PBKDF2 parameters")
	if err != nil {
		return nil, err
	}
	params := &PBKDF2Params{PRF: OIDHMACSHA1}
	if !seq.ReadASN1Bytes(&params.Salt, cryptobyte_asn1.OCTET_STRING) ||
		!seq.ReadASN1Integer(&params.Iterations) {
		return nil, fmt.Errorf("%w: cannot read PBKDF2 salt and iterations", ErrParse)
	}
	if seq.PeekASN1Tag(cryptobyte_asn1.INTEGER) && !seq.ReadASN1Integer(&params.KeyLength) {
		return nil, fmt.Errorf("%w: cannot read PBKDF2 keyLength", ErrParse)
	}
	if !seq.Empty() {
		var prf pkix.AlgorithmIdentifier
		if err := parseAlgorithmIdentifier(&seq, &prf); err != nil {
			return nil, err
		}
		params.PRF = prf.Algorithm
	}
	if !seq.Empty() {
		return nil, fmt.Errorf("%w: trailing data in PBKDF2 parameters", ErrParse)
	}
	return params, nil
}

// parseCipherParams reads the IV of a CBC encryption scheme. The cipher is
// not checked here, so that package legacy can reuse the parse for ciphers
// this package does not decrypt; DecryptPBES2 rejects them.
func parseCipherParams(alg pkix.AlgorithmIdentifier) (*CipherParams, error) {
	params := &CipherParams{Algorithm: alg.Algorithm}
	input := cryptobyte.String(alg.Parameters.FullBytes)
	if input.PeekASN1Tag(cryptobyte_asn1.OCTET_STRING) &&
		(!input.ReadASN1Bytes(&params.IV, cryptobyte_asn1.OCTET_STRING) || !input.Empty()) {
		return nil, fmt.Errorf("%w: cannot read the IV", ErrParse)
	}
	return params, nil
}

func parseLegacyPBEParams(alg pkix.AlgorithmIdentifier) (*EncryptionAlgorithm, error) {
	// pkcs-12PbeParams ::= SEQUENCE { salt OCTET STRING, iterations INTEGER }
	seq, err := readSequence(cryptobyte.String(alg.Parameters.FullBytes), "PKCS#12 PBE parameters")
	if err != nil {
		return nil, err
	}
	ea := &EncryptionAlgorithm{Algorithm: alg.Algorithm}
	if !seq.ReadASN1Bytes(&ea.Salt, cryptobyte_asn1.OCTET_STRING) ||
		!seq.ReadASN1Integer(&ea.Iterations) || !seq.Empty() {
		return nil, fmt.Errorf("%w: cannot read PKCS#12 PBE salt and iterations", ErrParse)
	}
	return ea, nil
}

func parseAlgorithmIdentifier(s *cryptobyte.String, alg *pkix.AlgorithmIdentifier) error {
	// AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
	var seq cryptobyte.String
	if !s.ReadASN1(&seq, cryptobyte_asn1.SEQUENCE) || !seq.ReadASN1ObjectIdentifier(&alg.Algorithm) {
		return fmt.Errorf("%w: cannot read AlgorithmIdentifier", ErrParse)
	}
	if !seq.Empty() {
		alg.Parameters = asn1.RawValue{FullBytes: seq}
	}
	return nil
}

// parseEncryptedData parses a PKCS#7 EncryptedData (RFC 2315 §13).
func parseEncryptedData(data []byte) (pkix.AlgorithmIdentifier, []byte, error) {
	// EncryptedData ::= SEQUENCE { version INTEGER, encryptedContentInfo EncryptedContentInfo }
	// EncryptedContentInfo ::= SEQUENCE { contentType OBJECT IDENTIFIER,
	//   contentEncryptionAlgorithm AlgorithmIdentifier, encryptedContent [0] IMPLICIT OCTET STRING OPTIONAL }
	var alg pkix.AlgorithmIdentifier
	seq, err := readSequence(cryptobyte.String(data), "EncryptedData")
	if err != nil {
		return alg, nil, err
	}
	var version int
	var info cryptobyte.String
	var contentType asn1.ObjectIdentifier
	if !seq.ReadASN1Integer(&version) ||
		!seq.ReadASN1(&info, cryptobyte_asn1.SEQUENCE) ||
		!info.ReadASN1ObjectIdentifier(&contentType) {
		return alg, nil, fmt.Errorf("%w: cannot read EncryptedData", ErrParse)
	}
	if version != 0 {
		return alg, nil, fmt.Errorf("%w: unsupported EncryptedData version %d", ErrDecryption, version)
	}
	if err := parseAlgorithmIdentifier(&info, &alg); err != nil {
		return alg, nil, err
	}
	content, err := readImplicitOctetString(&info)
	if err != nil {
		return alg, nil, err
	}
	return alg, content, nil
}

// readImplicitOctetString reads encryptedContent [0] IMPLICIT OCTET STRING in
// its DER (primitive) form.
func readImplicitOctetString(s *cryptobyte.String) ([]byte, error) {
	var content []byte
	if !s.ReadASN1Bytes(&content, tagContext0Implicit) {
		return nil, fmt.Errorf("%w: cannot read encryptedContent", ErrParse)
	}
	if !s.Empty() {
		return nil, fmt.Errorf("%w: trailing data in EncryptedContentInfo", ErrParse)
	}
	return content, nil
}

// extractOctetString returns the value of the OCTET STRING that makes up data.
func extractOctetString(data []byte) ([]byte, error) {
	input := cryptobyte.String(data)
	var value []byte
	if !input.ReadASN1Bytes(&value, cryptobyte_asn1.OCTET_STRING) || !input.Empty() {
		return nil, fmt.Errorf("%w: cannot read OCTET STRING", ErrParse)
	}
	return value, nil
}

// GetFriendlyName returns the friendlyName attribute, a BMPString, as UTF-8.
func GetFriendlyName(attrs []PKCS12Attribute) (string, bool) {
	for _, attr := range attrs {
		if !attr.ID.Equal(OIDFriendlyName) || len(attr.Values) == 0 {
			continue
		}
		input := cryptobyte.String(attr.Values[0])
		var bmp []byte
		if input.ReadASN1Bytes(&bmp, tagBMPString) {
			if name, err := decodeBMPString(bmp); err == nil {
				return name, true
			}
		}
	}
	return "", false
}

// GetLocalKeyID returns the localKeyId attribute, an OCTET STRING.
func GetLocalKeyID(attrs []PKCS12Attribute) ([]byte, bool) {
	for _, attr := range attrs {
		if !attr.ID.Equal(OIDLocalKeyID) || len(attr.Values) == 0 {
			continue
		}
		input := cryptobyte.String(attr.Values[0])
		var keyID []byte
		if input.ReadASN1Bytes(&keyID, cryptobyte_asn1.OCTET_STRING) {
			return keyID, true
		}
	}
	return nil, false
}

// decodeBMPString decodes UTF-16BE. Windows writes surrogate pairs into
// friendly names although a BMPString is UCS-2; they are decoded, not refused.
func decodeBMPString(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", fmt.Errorf("%w: BMPString of odd length", ErrParse)
	}
	units := make([]uint16, len(b)/2)
	for i := range units {
		units[i] = uint16(b[2*i])<<8 | uint16(b[2*i+1])
	}
	return string(utf16.Decode(units)), nil
}
