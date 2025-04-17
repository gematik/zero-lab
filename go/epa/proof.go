package epa

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"

	"golang.org/x/text/encoding/charmap"
)

type ProvidePNFunc func(insurantId string) (string, error)
type ProvideHCVFunc func(insurantId string) ([]byte, error)

func ProvidePNByHMAC(hmacKeyHex string, hmacKeyKid string) (ProvidePNFunc, error) {
	hmacKey, err := hex.DecodeString(hmacKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decoding hmac key: %w", err)
	}

	if len(hmacKeyKid) != 2 {
		return nil, fmt.Errorf("hmacKeyKid: must be 2 characters long")
	}

	return func(insurantId string) (string, error) {
		if len(insurantId) != 10 {
			return "", fmt.Errorf("insurantId must be 10 characters long")
		}

		iat := strconv.FormatInt(time.Now().Unix(), 10)

		proofData := make([]byte, 0, 10+10+2+1+24)
		proofData = append(proofData, []byte(insurantId)...)
		proofData = append(proofData, []byte(iat)...)
		proofData = append(proofData, 'U')
		proofData = append(proofData, []byte(hmacKeyKid)...)
		//str := fmt.Sprintf("%s%sU%s", insurantId, iat, hmacKeyKid)
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(proofData)
		hmacResult := mac.Sum(nil)[:24] // Truncate to 24 bytes

		evidence := base64.StdEncoding.EncodeToString(append(proofData, hmacResult...))

		return evidence, nil
	}, nil
}

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
	h40_0[0] = h40_0[0] & 0x7F // Set the first bit to 0

	return h40_0, nil
}

func deriveAES128Key(hmacKey []byte) ([]byte, error) {
	hkdf := hkdf.New(sha256.New, hmacKey, nil, []byte("VSDM+ Version 2 AES/GCM"))
	derived := make([]byte, 16)
	_, err := io.ReadFull(hkdf, derived)
	if err != nil {
		return nil, fmt.Errorf("reading from HKDF: %w", err)
	}

	return derived[:16], nil
}

func ProvidePNv2(hmacKeyHex string, hmacKeyKid string, provideHcv ProvideHCVFunc) (ProvidePNFunc, error) {
	hmacKey, err := hex.DecodeString(hmacKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decoding hmac key: %w", err)
	}

	if len(hmacKeyKid) != 2 {
		return nil, fmt.Errorf("hmacKeyKid: must be 2 characters long")
	}

	aesKey, err := deriveAES128Key(hmacKey)
	if err != nil {
		return nil, fmt.Errorf("deriving AES key: %w", err)
	}

	return func(insurantId string) (string, error) {
		if len(insurantId) != 10 {
			return "", fmt.Errorf("insurantId must be 10 characters long")
		}

		hcv, err := provideHcv(insurantId)
		if err != nil {
			return "", fmt.Errorf("getting HCV: %w", err)
		}

		// A_27323 - VSDM-FD: relative Zeit (Zeit-offset) Prüfziffer Version 2
		const iat_offset = 1735689600
		iat := time.Now().Unix()
		r_iat_8 := (iat - iat_offset) >> 3
		r_iat_bytes := make([]byte, 3)
		r_iat_bytes[0] = byte((r_iat_8 >> 16) & 0xFF)
		r_iat_bytes[1] = byte((r_iat_8 >> 8) & 0xFF)
		r_iat_bytes[2] = byte(r_iat_8 & 0xFF)

		//A_27278 - VSDM-FD: Struktur einer Prüfziffer der Version 2
		proofData := make([]byte, 0, 5+3+10)
		proofData = append(proofData, hcv...)
		proofData = append(proofData, r_iat_bytes...)
		proofData = append(proofData, []byte(insurantId)...)

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
			return "", fmt.Errorf("hmacKeyKid must be 2 characters long")
		}
		BK := hmacKeyKid[0]
		if BK < 'A' || BK > 'Z' {
			return "", fmt.Errorf("invalid operator identifier (must be 'A' to 'Z')")
		}
		BK_D := BK - 'A'
		BK_D_4 := BK_D << 2

		SV := hmacKeyKid[1] - '0'
		if SV >= 4 {
			return "", fmt.Errorf("invalid secret/key version (must be 0 to 3)")
		}

		field1 := V + BK_D_4 + SV

		checksum_bytes := make([]byte, 0, 1+12+18+16)
		checksum_bytes = append(checksum_bytes, field1)
		checksum_bytes = append(checksum_bytes, iv...)
		checksum_bytes = append(checksum_bytes, ciphertext...)

		if len(checksum_bytes) != 47 {
			return "", fmt.Errorf("invalid length of PZV2 in bytes: %d", len(checksum_bytes))
		}

		checksum := base64.StdEncoding.EncodeToString(checksum_bytes)

		if len(checksum) != 64 {
			return "", fmt.Errorf("invalid length of PZV2: %d", len(checksum))
		}

		return checksum, nil
	}, nil
}
