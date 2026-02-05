package pkcs12

import (
	"fmt"
)

// CertificateBag represents a certificate from a PKCS#12 file with metadata
type CertificateBag struct {
	// Raw certificate data (DER-encoded X.509)
	Raw []byte
	
	// FriendlyName is a human-readable name for the certificate
	FriendlyName string
	
	// LocalKeyID links this certificate to its corresponding private key
	LocalKeyID []byte
}

// PrivateKeyBag represents a private key from a PKCS#12 file with metadata
type PrivateKeyBag struct {
	// Raw private key data (DER-encoded PKCS#8)
	Raw []byte
	
	// FriendlyName is a human-readable name for the key
	FriendlyName string
	
	// LocalKeyID links this key to its corresponding certificate
	LocalKeyID []byte
}

// Bags contains all certificates and keys extracted from a PKCS#12 file
type Bags struct {
	Certificates []CertificateBag
	PrivateKeys  []PrivateKeyBag
}

// ExtractBags extracts all certificates and private keys from a PKCS#12 file
// It decrypts encrypted bags using the provided password and returns raw certificate
// and key data along with their metadata (friendlyName, localKeyID).
//
// The returned raw data can be parsed using crypto/x509:
//   - For certificates: x509.ParseCertificate(cert.Raw)
//   - For keys: x509.ParsePKCS8PrivateKey(key.Raw)
//
// Example:
//   pfx, _ := pkcs12.Parse(data)
//   bags, _ := pkcs12.ExtractBags(pfx, password)
//   for _, cert := range bags.Certificates {
//       x509Cert, _ := x509.ParseCertificate(cert.Raw)
//       fmt.Println("Cert:", x509Cert.Subject)
//   }
func ExtractBags(pfx *PFX, password []byte) (*Bags, error) {
	bags := &Bags{
		Certificates: make([]CertificateBag, 0),
		PrivateKeys:  make([]PrivateKeyBag, 0),
	}
	
	// Verify MAC if present
	if err := VerifyMAC(pfx, password); err != nil {
		return nil, fmt.Errorf("MAC verification failed: %w", err)
	}
	
	// Parse authenticated safe
	authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		return nil, fmt.Errorf("failed to parse authenticated safe: %w", err)
	}
	
	// Process each ContentInfo
	for _, ci := range authSafe.ContentInfos {
		var safeContents []byte
		
		if ci.ContentType.Equal(OIDData) {
			// Unencrypted data
			safeContents, err = extractOctetString(ci.Content)
			if err != nil {
				return nil, fmt.Errorf("failed to extract safe contents: %w", err)
			}
		} else if ci.ContentType.Equal(OIDEncryptedData) {
			// Encrypted data - decrypt it
			safeContents, err = DecryptEncryptedData(ci, password)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt safe contents: %w", err)
			}
		} else {
			// Unknown content type - skip
			continue
		}
		
		// Parse safe contents
		sc, err := ParseSafeContents(safeContents)
		if err != nil {
			return nil, fmt.Errorf("failed to parse safe contents: %w", err)
		}
		
		// Extract bags
		if err := extractFromSafeContents(sc, password, bags); err != nil {
			return nil, err
		}
	}
	
	return bags, nil
}

// Decode reads PKCS#12 data and extracts all bags (certificates and private keys).
// This is a convenience function that combines Parse and ExtractBags.
//
// Example:
//
//	data, _ := os.ReadFile("keystore.p12")
//	bags, err := pkcs12.Decode(data, []byte("password"))
//	if err != nil {
//		log.Fatal(err)
//	}
//	for _, certBag := range bags.Certificates {
//		cert, _ := x509.ParseCertificate(certBag.Raw)
//		fmt.Println("Cert:", cert.Subject)
//	}
func Decode(data, password []byte) (*Bags, error) {
	pfx, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#12: %w", err)
	}

	return ExtractBags(pfx, password)
}

// extractFromSafeContents processes SafeContents and extracts certificates and keys
func extractFromSafeContents(sc *SafeContents, password []byte, bags *Bags) error {
	for _, bag := range sc.Bags {
		switch {
		case bag.BagID.Equal(OIDCertBag):
			// Certificate bag
			cert, err := extractCertificate(bag)
			if err != nil {
				return fmt.Errorf("failed to extract certificate: %w", err)
			}
			bags.Certificates = append(bags.Certificates, cert)
			
		case bag.BagID.Equal(OIDPKCS8ShroudedKeyBag):
			// Encrypted private key
			key, err := extractShroudedKey(bag, password)
			if err != nil {
				return fmt.Errorf("failed to extract shrouded key: %w", err)
			}
			bags.PrivateKeys = append(bags.PrivateKeys, key)
			
		case bag.BagID.Equal(OIDKeyBag):
			// Unencrypted private key (PKCS#8)
			key, err := extractKeyBag(bag)
			if err != nil {
				return fmt.Errorf("failed to extract key bag: %w", err)
			}
			bags.PrivateKeys = append(bags.PrivateKeys, key)
			
		case bag.BagID.Equal(OIDSafeContentsBag):
			// Nested safe contents
			nestedSC, err := ParseSafeContents(bag.BagValue)
			if err != nil {
				return fmt.Errorf("failed to parse nested safe contents: %w", err)
			}
			if err := extractFromSafeContents(nestedSC, password, bags); err != nil {
				return err
			}
		}
	}
	
	return nil
}

// extractCertificate extracts a certificate from a CertBag
func extractCertificate(bag SafeBag) (CertificateBag, error) {
	cert := CertificateBag{}
	
	// Parse CertBag
	certBag, err := ParseCertBag(bag.BagValue)
	if err != nil {
		return cert, err
	}
	
	// Only support X.509 certificates
	if !certBag.CertID.Equal(OIDX509Certificate) {
		return cert, fmt.Errorf("%w: unsupported certificate type %v", 
			ErrUnsupportedAlgorithm, certBag.CertID)
	}
	
	// CertValue is already the raw DER-encoded certificate
	cert.Raw = certBag.CertValue
	
	// Extract attributes
	cert.FriendlyName, cert.LocalKeyID = extractAttributes(bag.Attributes)
	
	return cert, nil
}

// extractShroudedKey extracts and decrypts a PKCS8ShroudedKeyBag
func extractShroudedKey(bag SafeBag, password []byte) (PrivateKeyBag, error) {
	key := PrivateKeyBag{}
	
	// Decrypt the shrouded key bag
	decrypted, err := DecryptShroudedKeyBag(bag.BagValue, password)
	if err != nil {
		return key, err
	}
	
	key.Raw = decrypted
	
	// Extract attributes
	key.FriendlyName, key.LocalKeyID = extractAttributes(bag.Attributes)
	
	return key, nil
}

// extractKeyBag extracts an unencrypted KeyBag
func extractKeyBag(bag SafeBag) (PrivateKeyBag, error) {
	key := PrivateKeyBag{
		Raw: bag.BagValue, // Already in PKCS#8 format
	}
	
	// Extract attributes
	key.FriendlyName, key.LocalKeyID = extractAttributes(bag.Attributes)
	
	return key, nil
}

// extractAttributes extracts friendlyName and localKeyID from bag attributes
func extractAttributes(attrs []PKCS12Attribute) (friendlyName string, localKeyID []byte) {
	if name, ok := GetFriendlyName(attrs); ok {
		friendlyName = name
	}
	if keyID, ok := GetLocalKeyID(attrs); ok {
		localKeyID = keyID
	}
	return
}

// FindCertificate finds a certificate by localKeyID
func (b *Bags) FindCertificate(localKeyID []byte) *CertificateBag {
	for i := range b.Certificates {
		if bytesEqual(b.Certificates[i].LocalKeyID, localKeyID) {
			return &b.Certificates[i]
		}
	}
	return nil
}

// FindPrivateKey finds a private key by localKeyID
func (b *Bags) FindPrivateKey(localKeyID []byte) *PrivateKeyBag {
	for i := range b.PrivateKeys {
		if bytesEqual(b.PrivateKeys[i].LocalKeyID, localKeyID) {
			return &b.PrivateKeys[i]
		}
	}
	return nil
}

// FindMatchingPairs returns pairs of certificates and their corresponding private keys
// based on localKeyID matching
func (b *Bags) FindMatchingPairs() []CertKeyPair {
	pairs := make([]CertKeyPair, 0)
	
	for i := range b.Certificates {
		cert := &b.Certificates[i]
		if len(cert.LocalKeyID) > 0 {
			if key := b.FindPrivateKey(cert.LocalKeyID); key != nil {
				pairs = append(pairs, CertKeyPair{
					Certificate: cert,
					PrivateKey:  key,
				})
			}
		}
	}
	
	return pairs
}

// CertKeyPair represents a matched certificate and private key pair
type CertKeyPair struct {
	Certificate *CertificateBag
	PrivateKey  *PrivateKeyBag
}

// bytesEqual compares two byte slices
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
