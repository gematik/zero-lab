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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"slices"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// EncodeOptions configures EncodeWithOptions. Start from
// DefaultEncodeOptions; the zero value has no iterations and fails.
type EncodeOptions struct {
	// KeyEncryption is the PBES2 cipher for private keys: OIDAes128CBC,
	// OIDAes192CBC or OIDAes256CBC.
	KeyEncryption asn1.ObjectIdentifier

	// CertEncryption is the PBES2 cipher for the certificate safe, one of the
	// AES OIDs; nil writes the certificates unencrypted.
	CertEncryption asn1.ObjectIdentifier

	// Iterations is the PBKDF2 and MAC iteration count.
	Iterations int

	// MacAlgorithm is the MAC digest: OIDSHA256, OIDSHA384 or OIDSHA512. The
	// PBKDF2 PRF is HMAC with the same digest.
	MacAlgorithm asn1.ObjectIdentifier

	// KeyPassword and CertPassword encrypt keys and certificates; nil means
	// the password passed to EncodeWithOptions.
	KeyPassword  []byte
	CertPassword []byte

	// IncludeMAC adds the integrity MAC, computed with the main password.
	IncludeMAC bool
}

// DefaultEncodeOptions returns the options of OpenSSL 3's default export:
// PBES2 with AES-256-CBC and PBKDF2-HMAC-SHA-256 for keys and certificates,
// 2048 iterations, an HMAC-SHA-256 MAC.
func DefaultEncodeOptions() *EncodeOptions {
	return &EncodeOptions{
		KeyEncryption:  OIDAes256CBC,
		CertEncryption: OIDAes256CBC,
		Iterations:     2048,
		MacAlgorithm:   OIDSHA256,
		IncludeMAC:     true,
	}
}

// Encode writes bags as a PKCS#12 file with DefaultEncodeOptions.
func Encode(bags *Bags, password []byte) ([]byte, error) {
	return EncodeWithOptions(bags, password, DefaultEncodeOptions())
}

// EncodeWithOptions writes bags as a DER-encoded PKCS#12 file. Salts and IVs
// are random. opts is not modified; nil means DefaultEncodeOptions.
func EncodeWithOptions(bags *Bags, password []byte, opts *EncodeOptions) ([]byte, error) {
	if bags == nil {
		return nil, errors.New("pkcs12: bags is nil")
	}
	o := DefaultEncodeOptions()
	if opts != nil {
		o = new(EncodeOptions)
		*o = *opts
	}
	if o.KeyPassword == nil {
		o.KeyPassword = password
	}
	if o.CertPassword == nil {
		o.CertPassword = password
	}
	p, err := newEncodeParams(o)
	if err != nil {
		return nil, err
	}

	var authSafe cryptobyte.Builder
	authSafe.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if len(bags.PrivateKeys) > 0 {
			keys, err := p.keySafe(bags.PrivateKeys, o.KeyPassword)
			if err != nil {
				b.SetError(err)
				return
			}
			addDataContentInfo(b, keys)
		}
		if len(bags.Certificates) > 0 {
			certs, err := certSafe(bags.Certificates)
			if err != nil {
				b.SetError(err)
				return
			}
			if o.CertEncryption == nil {
				addDataContentInfo(b, certs)
				return
			}
			p.addEncryptedContentInfo(b, certs, o.CertPassword)
		}
	})
	authSafeDER, err := authSafe.Bytes()
	if err != nil {
		return nil, err
	}

	var pfx cryptobyte.Builder
	pfx.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(3)
		addDataContentInfo(b, authSafeDER)
		if o.IncludeMAC {
			p.addMacData(b, authSafeDER, password)
		}
	})
	return pfx.Bytes()
}

// encodeParams are the validated algorithm choices of one encoding.
type encodeParams struct {
	iterations int
	keyCipher  pbes2Cipher
	keyOID     asn1.ObjectIdentifier
	certCipher pbes2Cipher
	certOID    asn1.ObjectIdentifier
	macOID     asn1.ObjectIdentifier
	prfOID     asn1.ObjectIdentifier
}

func encodeCipher(oid asn1.ObjectIdentifier, what string) (pbes2Cipher, error) {
	if c, ok := pbes2CipherFor(oid); ok {
		return c, nil
	}
	return pbes2Cipher{}, fmt.Errorf("%w: %s %v (want AES-CBC)", ErrUnsupportedAlgorithm, what, oid)
}

func newEncodeParams(o *EncodeOptions) (*encodeParams, error) {
	if err := checkIterations(o.Iterations); err != nil {
		return nil, err
	}
	p := &encodeParams{iterations: o.Iterations, keyOID: o.KeyEncryption, certOID: o.CertEncryption}
	var err error
	if p.keyCipher, err = encodeCipher(o.KeyEncryption, "KeyEncryption"); err != nil {
		return nil, err
	}
	if o.CertEncryption != nil {
		if p.certCipher, err = encodeCipher(o.CertEncryption, "CertEncryption"); err != nil {
			return nil, err
		}
	}
	// SHA-1 and SHA-224 remain readable but are not written.
	switch {
	case o.MacAlgorithm.Equal(OIDSHA256):
		p.macOID, p.prfOID = OIDSHA256, OIDHMACSHA256
	case o.MacAlgorithm.Equal(OIDSHA384):
		p.macOID, p.prfOID = OIDSHA384, OIDHMACSHA384
	case o.MacAlgorithm.Equal(OIDSHA512):
		p.macOID, p.prfOID = OIDSHA512, OIDHMACSHA512
	default:
		return nil, fmt.Errorf("%w: MacAlgorithm %v (want SHA-256, SHA-384 or SHA-512)", ErrUnsupportedAlgorithm, o.MacAlgorithm)
	}
	return p, nil
}

// keySafe returns a SafeContents of shrouded key bags.
func (p *encodeParams) keySafe(keys []PrivateKeyBag, password []byte) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, key := range keys {
			var epki cryptobyte.Builder
			epki.AddASN1(cryptobyte_asn1.SEQUENCE, func(e *cryptobyte.Builder) {
				ciphertext, err := p.addPBES2(e, p.keyCipher, p.keyOID, password, key.Raw)
				if err != nil {
					e.SetError(err)
					return
				}
				e.AddASN1OctetString(ciphertext)
			})
			value, err := epki.Bytes()
			if err != nil {
				b.SetError(err)
				return
			}
			if err := addSafeBag(b, OIDPKCS8ShroudedKeyBag, value, key.FriendlyName, key.LocalKeyID); err != nil {
				b.SetError(err)
				return
			}
		}
	})
	return b.Bytes()
}

// certSafe returns a SafeContents of X.509 certificate bags.
func certSafe(certs []CertificateBag) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		for _, cert := range certs {
			var cb cryptobyte.Builder
			cb.AddASN1(cryptobyte_asn1.SEQUENCE, func(c *cryptobyte.Builder) {
				c.AddASN1ObjectIdentifier(OIDX509Certificate)
				c.AddASN1(tagContext0Explicit, func(c *cryptobyte.Builder) {
					c.AddASN1OctetString(cert.Raw)
				})
			})
			value, err := cb.Bytes()
			if err != nil {
				b.SetError(err)
				return
			}
			if err := addSafeBag(b, OIDCertBag, value, cert.FriendlyName, cert.LocalKeyID); err != nil {
				b.SetError(err)
				return
			}
		}
	})
	return b.Bytes()
}

// addSafeBag adds a SafeBag with the friendlyName and localKeyId attributes
// that are set.
func addSafeBag(b *cryptobyte.Builder, id asn1.ObjectIdentifier, value []byte, friendlyName string, localKeyID []byte) error {
	var attributes [][]byte
	if friendlyName != "" {
		attr, err := friendlyNameAttribute(friendlyName)
		if err != nil {
			return err
		}
		attributes = append(attributes, attr)
	}
	if len(localKeyID) > 0 {
		attr, err := attribute(OIDLocalKeyID, func(b *cryptobyte.Builder) { b.AddASN1OctetString(localKeyID) })
		if err != nil {
			return err
		}
		attributes = append(attributes, attr)
	}
	// DER orders the elements of a SET OF by their encoding (X.690 §11.6).
	slices.SortFunc(attributes, bytes.Compare)

	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(id)
		b.AddASN1(tagContext0Explicit, func(b *cryptobyte.Builder) { b.AddBytes(value) })
		if len(attributes) > 0 {
			b.AddASN1(cryptobyte_asn1.SET, func(b *cryptobyte.Builder) {
				for _, attr := range attributes {
					b.AddBytes(attr)
				}
			})
		}
	})
	return nil
}

// attribute encodes a PKCS12Attribute with a single value.
func attribute(id asn1.ObjectIdentifier, value cryptobyte.BuilderContinuation) ([]byte, error) {
	var b cryptobyte.Builder
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(id)
		b.AddASN1(cryptobyte_asn1.SET, value)
	})
	return b.Bytes()
}

// friendlyNameAttribute encodes friendlyName as a BMPString, which is UCS-2:
// characters outside the BMP cannot be written.
func friendlyNameAttribute(name string) ([]byte, error) {
	bmp := make([]byte, 0, 2*len(name))
	for _, r := range name {
		if r > 0xFFFF {
			return nil, fmt.Errorf("pkcs12: friendlyName %q: %q is outside the BMPString character set", name, r)
		}
		bmp = append(bmp, byte(r>>8), byte(r))
	}
	return attribute(OIDFriendlyName, func(b *cryptobyte.Builder) {
		b.AddASN1(tagBMPString, func(b *cryptobyte.Builder) { b.AddBytes(bmp) })
	})
}

// addDataContentInfo adds a ContentInfo of type Data holding content.
func addDataContentInfo(b *cryptobyte.Builder, content []byte) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(OIDData)
		b.AddASN1(tagContext0Explicit, func(b *cryptobyte.Builder) {
			b.AddASN1OctetString(content)
		})
	})
}

// addEncryptedContentInfo adds a ContentInfo of type EncryptedData holding
// content encrypted with PBES2.
func (p *encodeParams) addEncryptedContentInfo(b *cryptobyte.Builder, content, password []byte) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(OIDEncryptedData)
		b.AddASN1(tagContext0Explicit, func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1Int64(0)
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1ObjectIdentifier(OIDData)
					ciphertext, err := p.addPBES2(b, p.certCipher, p.certOID, password, content)
					if err != nil {
						b.SetError(err)
						return
					}
					b.AddASN1(tagContext0Implicit, func(b *cryptobyte.Builder) { b.AddBytes(ciphertext) })
				})
			})
		})
	})
}

// addPBES2 encrypts plaintext with PBES2 and adds its AlgorithmIdentifier.
func (p *encodeParams) addPBES2(b *cryptobyte.Builder, c pbes2Cipher, cipherOID asn1.ObjectIdentifier, password, plaintext []byte) ([]byte, error) {
	salt := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	prf, err := pbkdf2PRF(p.prfOID)
	if err != nil {
		return nil, err
	}
	key, err := pbkdf2.Key(prf, string(password), salt, p.iterations, c.keySize)
	if err != nil {
		return nil, err
	}
	block, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}
	padded := addPKCS7Padding(plaintext, block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	// AlgorithmIdentifier { pbes2, PBES2-params { { pbkdf2, PBKDF2-params }, { cipher, iv } } }
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(OIDPBES2)
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(OIDPBKDF2)
				b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1OctetString(salt)
					b.AddASN1Int64(int64(p.iterations))
					addAlgorithmWithNULL(b, p.prfOID)
				})
			})
			b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(cipherOID)
				b.AddASN1OctetString(iv)
			})
		})
	})
	return ciphertext, nil
}

// addMacData adds the MacData over authSafe.
func (p *encodeParams) addMacData(b *cryptobyte.Builder, authSafe, password []byte) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		b.SetError(err)
		return
	}
	mac, err := computeMAC(p.macOID, password, salt, p.iterations, authSafe)
	if err != nil {
		b.SetError(err)
		return
	}
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
			addAlgorithmWithNULL(b, p.macOID)
			b.AddASN1OctetString(mac)
		})
		b.AddASN1OctetString(salt)
		b.AddASN1Int64(int64(p.iterations))
	})
}

// addAlgorithmWithNULL adds an AlgorithmIdentifier with NULL parameters, the
// form OpenSSL writes for digests and HMAC PRFs.
func addAlgorithmWithNULL(b *cryptobyte.Builder, oid asn1.ObjectIdentifier) {
	b.AddASN1(cryptobyte_asn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		b.AddASN1NULL()
	})
}

func addPKCS7Padding(data []byte, blockSize int) []byte {
	n := blockSize - len(data)%blockSize
	return append(slices.Clip(data), bytes.Repeat([]byte{byte(n)}, n)...)
}
