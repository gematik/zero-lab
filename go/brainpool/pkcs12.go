// Copyright 2015 The Go Authors. All rights reserved.
package brainpool

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

var (
	oidContentTypeData          = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 1})
	oidContentTypeEncryptedData = asn1.ObjectIdentifier([]int{1, 2, 840, 113549, 1, 7, 6})
)

type PFXContent struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"tag:0,explicit,optional"`
}

type PFXData struct {
	Version  int
	AuthSafe PFXContent
	MacData  struct {
		Mac struct {
			Algorithm pkix.AlgorithmIdentifier
			Digest    []byte
		}
		MacSalt    []byte
		Iterations int `asn1:"optional,default:1"`
	} `asn1:"optional"`
}

type PFXEncryptedData struct {
	Version              int
	EncryptedContentInfo struct {
		ContentType                asn1.ObjectIdentifier
		ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
		EncryptedContent           []byte `asn1:"tag:0,optional"`
	}
}

func DecodePKCS12(pfxData []byte, password string) (privateKey interface{}, certificate interface{}, err error) {
	pfx := new(PFXData)
	if _, err := asn1.Unmarshal(pfxData, pfx); err != nil {
		return nil, nil, err
	}

	if !pfx.AuthSafe.ContentType.Equal(oidContentTypeData) {
		return nil, nil, fmt.Errorf("unsupported content type: %v", pfx.AuthSafe.ContentType)
	}

	if _, err := asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &pfx.AuthSafe.Content); err != nil {
		return nil, nil, err
	}

	if len(pfx.MacData.Mac.Algorithm.Algorithm) == 0 {
		return nil, nil, fmt.Errorf("missing MAC algorithm")
	}

	pb, err := bmpStringZeroTerminated(password)
	if err != nil {
		return nil, nil, err
	}

	mac, err := DoMacPBKF(pfx.MacData.Mac.Algorithm, pb, pfx.AuthSafe.Content.Bytes, pfx.MacData.MacSalt, pfx.MacData.Iterations)
	if err != nil {
		return nil, nil, err
	}

	if !hmac.Equal(mac, pfx.MacData.Mac.Digest) {
		return nil, nil, errors.New("MAC verification failed")
	}

	var authenticatedContent []PFXContent

	if _, err := asn1.Unmarshal(pfx.AuthSafe.Content.Bytes, &authenticatedContent); err != nil {
		return nil, nil, err
	}

	for _, content := range authenticatedContent {
		switch {
		case content.ContentType.Equal(oidContentTypeData):
			println("oidContentTypeData")
		case content.ContentType.Equal(oidContentTypeEncryptedData):
			var encryptedData PFXEncryptedData
			if _, err := asn1.Unmarshal(content.Content.Bytes, &encryptedData); err != nil {
				return nil, nil, err
			}
			if encryptedData.Version != 0 {
				return nil, nil, fmt.Errorf("unsupported encrypted data version: %v", encryptedData.Version)
			}

		default:
			return nil, nil, fmt.Errorf("unsupported content type: %v", content.ContentType)
		}
	}

	return nil, nil, errors.New("not implemented")
}

func DoMacPBKF(alg pkix.AlgorithmIdentifier, password []byte, data []byte, salt []byte, iterations int) ([]byte, error) {
	var hashFunc func() hash.Hash
	var key []byte

	// Map AlgorithmIdentifier to a corresponding hash function
	switch alg.Algorithm.String() {
	case "1.3.14.3.2.26": // OID for SHA-1
		hashFunc = crypto.SHA1.New
		key = pbkdf(
			func(data []byte) []byte {
				sum := sha1.Sum(data)
				return sum[:]
			},
			20,
			64,
			salt,
			password,
			iterations,
			3,
			20,
		)
	case "2.16.840.1.101.3.4.2.1": // OID for SHA-256
		hashFunc = crypto.SHA256.New
		key = pbkdf(
			func(data []byte) []byte {
				sum := sha256.Sum256(data)
				return sum[:]
			},
			32,
			64,
			salt,
			password,
			iterations,
			3,
			32,
		)
	case "2.16.840.1.101.3.4.2.3": // OID for SHA-512
		hashFunc = crypto.SHA512.New
		key = pbkdf(
			func(data []byte) []byte {
				sum := sha512.Sum512(data)
				return sum[:]
			},
			64,
			128,
			salt,
			password,
			iterations,
			3,
			64,
		)
	default:
		return nil, errors.New("unsupported hash algorithm")
	}

	mac := hmac.New(hashFunc, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// bmpStringZeroTerminated returns `s` encoded in UCS-2 with a zero terminator.
func bmpStringZeroTerminated(s string) ([]byte, error) {
	// Preallocate memory for the UCS-2 encoding and the null terminator
	// Each character is 2 bytes, and we add 2 bytes for the terminator.
	ret := make([]byte, 0, 2*len(s)+2)

	for _, r := range s {
		// Check if the rune can be encoded in UCS-2
		if r > 0xFFFF { // Non-BMP characters require surrogate pairs and cannot be UCS-2
			return nil, errors.New("pkcs12: string contains characters that cannot be encoded in UCS-2")
		}

		// Append the high and low byte of the rune
		ret = append(ret, byte(r>>8), byte(r&0xFF))
	}

	// Append the UCS-2 null terminator (two zero bytes)
	ret = append(ret, 0, 0)

	return ret, nil
}

func pbkdf(hash func([]byte) []byte, u, v int, salt, password []byte, r int, ID byte, size int) []byte {
	D := make([]byte, v)
	for i := range D {
		D[i] = ID
	}

	S := fillWithRepeats(salt, v)
	P := fillWithRepeats(password, v)
	I := append(S, P...)
	c := (size + u - 1) / u
	A := make([]byte, c*u)

	for i := 0; i < c; i++ {
		Ai := hash(append(D, I...))
		for j := 1; j < r; j++ {
			Ai = hash(Ai)
		}
		copy(A[i*u:], Ai[:])

		if i < c-1 {
			B := repeatUntilLen(Ai, v)
			Bbi := new(big.Int).SetBytes(B)

			for j := 0; j < len(I)/v; j++ {
				Ij := new(big.Int).SetBytes(I[j*v : (j+1)*v])
				Ij.Add(Ij, Bbi).Add(Ij, big.NewInt(1))
				Ijb := padOrTrim(Ij.Bytes(), v)
				copy(I[j*v:(j+1)*v], Ijb)
			}
		}
	}
	return A[:size]
}

func fillWithRepeats(data []byte, length int) []byte {
	if len(data) == 0 {
		return nil
	}
	repeated := make([]byte, 0, length)
	for len(repeated) < length {
		repeated = append(repeated, data...)
	}
	return repeated[:length]
}

func repeatUntilLen(data []byte, length int) []byte {
	repeated := make([]byte, 0, length)
	for len(repeated) < length {
		repeated = append(repeated, data...)
	}
	return repeated[:length]
}

func padOrTrim(data []byte, length int) []byte {
	if len(data) == length {
		return data
	}
	if len(data) > length {
		return data[len(data)-length:]
	}
	padded := make([]byte, length)
	copy(padded[length-len(data):], data)
	return padded
}
