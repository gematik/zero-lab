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

package epa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/text/encoding/charmap"
)

type (
	// ProvidePNFunc returns the Prüfziffer (proof of audit evidence) for an insurant's KVNR, dated now.
	ProvidePNFunc func(insurantID string, now time.Time) (string, error)
	// ProvideHCVFunc returns the hash check value (hcv) for an insurant's KVNR.
	ProvideHCVFunc func(insurantID string) ([]byte, error)
)

// ProvidePNByHMAC returns a provider of version 1 Prüfziffern: KVNR, time, the marker U and
// the key ID, with a truncated HMAC-SHA256 over them. hmacKeyKid has 2 characters.
func ProvidePNByHMAC(hmacKeyHex string, hmacKeyKid string) (ProvidePNFunc, error) {
	hmacKey, err := hex.DecodeString(hmacKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decoding hmac key: %w", err)
	}

	if len(hmacKeyKid) != 2 {
		return nil, errors.New("hmacKeyKid: must be 2 characters long")
	}

	return func(insurantID string, now time.Time) (string, error) {
		if len(insurantID) != 10 {
			return "", errors.New("insurantId must be 10 characters long")
		}

		iat := strconv.FormatInt(now.Unix(), 10)

		proofData := make([]byte, 0, 10+10+2+1+24)
		proofData = append(proofData, []byte(insurantID)...)
		proofData = append(proofData, []byte(iat)...)
		proofData = append(proofData, 'U')
		proofData = append(proofData, []byte(hmacKeyKid)...)
		// str := fmt.Sprintf("%s%sU%s", insurantID, iat, hmacKeyKid)
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(proofData)
		hmacResult := mac.Sum(nil)[:24] // Truncate to 24 bytes

		evidence := base64.StdEncoding.EncodeToString(append(proofData, hmacResult...))

		return evidence, nil
	}, nil
}

// CalculateHCV computes the hcv from the coverage begin and street address of the VSD: the
// leading 40 bits of SHA-256 over their ISO 8859-15 form, with the top bit cleared.
func CalculateHCV(coverageBegin, streetAddress string) ([]byte, error) {
	coverageBegin = strings.ReplaceAll(coverageBegin, " ", "")

	streetAddress = strings.TrimSpace(streetAddress)

	encoder := charmap.ISO8859_15.NewEncoder()
	combined, err := encoder.String(coverageBegin + streetAddress)
	if err != nil {
		return nil, fmt.Errorf("encoding to ISO8859_15: %w", err)
	}

	hash := sha256.Sum256([]byte(combined))

	h40 := hash[:5]

	h40_0 := make([]byte, 5)
	copy(h40_0, h40)
	h40_0[0] &= 0x7F // Set the first bit to 0

	return h40_0, nil
}

func deriveAES128Key(hmacKey []byte) ([]byte, error) {
	derived, err := hkdf.Key(sha256.New, hmacKey, nil, "VSDM+ Version 2 AES/GCM", 16)
	if err != nil {
		return nil, fmt.Errorf("deriving the AES key with HKDF: %w", err)
	}
	return derived, nil
}

// CalculatePNv2 returns a provider of version 2 Prüfziffern (A_27278, A_27323), AES-GCM
// sealed under a key derived from the operator's HMAC key. hmacKeyKid names the operator
// (A to Z) and the key version (0 to 3).
func CalculatePNv2(hmacKeyHex string, hmacKeyKid string, provideHcv ProvideHCVFunc) (ProvidePNFunc, error) {
	hmacKey, err := hex.DecodeString(hmacKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decoding hmac key: %w", err)
	}

	if len(hmacKeyKid) != 2 {
		return nil, errors.New("hmacKeyKid: must be 2 characters long")
	}

	aesKey, err := deriveAES128Key(hmacKey)
	if err != nil {
		return nil, fmt.Errorf("deriving AES key: %w", err)
	}

	return func(insurantID string, now time.Time) (string, error) {
		if len(insurantID) != 10 {
			return "", errors.New("insurantId must be 10 characters long")
		}

		hcv, err := provideHcv(insurantID)
		if err != nil {
			return "", fmt.Errorf("getting HCV: %w", err)
		}

		// A_27323 - VSDM-FD: relative Zeit (Zeit-offset) Prüfziffer Version 2
		const iatOffset = 1735689600
		iat := now.Unix()
		rIAT8 := (iat - iatOffset) >> 3
		rIATBytes := make([]byte, 3)
		rIATBytes[0] = byte((rIAT8 >> 16) & 0xFF)
		rIATBytes[1] = byte((rIAT8 >> 8) & 0xFF)
		rIATBytes[2] = byte(rIAT8 & 0xFF)

		// A_27278 - VSDM-FD: Struktur einer Prüfziffer der Version 2
		proofData := make([]byte, 0, 5+3+10)
		proofData = append(proofData, hcv...)
		proofData = append(proofData, rIATBytes...)
		proofData = append(proofData, []byte(insurantID)...)

		// Encrypt proofData using AES-GCM
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return "", fmt.Errorf("creating AES cipher: %w", err)
		}

		// Generate a 12-byte IV (Initialization Vector)
		iv := make([]byte, 12)
		_, err = rand.Read(iv)
		if err != nil {
			return "", fmt.Errorf("generating random IV: %w", err)
		}

		// seal with GCM
		aesGCM, err := cipher.NewGCM(block)
		if err != nil {
			return "", fmt.Errorf("creating AES-GCM: %w", err)
		}

		ciphertext := aesGCM.Seal(nil, iv, proofData, nil)

		// Calculate Field_1
		const V = 128
		if len(hmacKeyKid) != 2 {
			return "", errors.New("hmacKeyKid must be 2 characters long")
		}
		BK := hmacKeyKid[0]
		if BK < 'A' || BK > 'Z' {
			return "", errors.New("invalid operator identifier (must be 'A' to 'Z')")
		}
		BKD := BK - 'A'
		BKD4 := BKD << 2

		SV := hmacKeyKid[1] - '0'
		if SV >= 4 {
			return "", errors.New("invalid secret/key version (must be 0 to 3)")
		}

		field1 := V + BKD4 + SV

		checksumBytes := make([]byte, 0, 1+12+18+16)
		checksumBytes = append(checksumBytes, field1)
		checksumBytes = append(checksumBytes, iv...)
		checksumBytes = append(checksumBytes, ciphertext...)

		if len(checksumBytes) != 47 {
			return "", fmt.Errorf("invalid length of PZV2 in bytes: %d", len(checksumBytes))
		}

		checksum := base64.StdEncoding.EncodeToString(checksumBytes)

		if len(checksum) != 64 {
			return "", fmt.Errorf("invalid length of PZV2: %d", len(checksum))
		}

		return checksum, nil
	}, nil
}
