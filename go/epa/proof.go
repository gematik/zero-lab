package epa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strconv"
	"time"
)

type ProofOfAuditEvidenceFunc func(insurantId string) (string, error)

func ProofOfAuditEvidenceHMAC(hmacKeyHex string, hmacKeyKid string) (ProofOfAuditEvidenceFunc, error) {
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
