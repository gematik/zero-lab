package epa

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"time"
)

type ProofOfAuditEvidenceFunc func(insurantId string) (string, error)

func TestProofOfAuditEvidenceFunc(insurantId string) (string, error) {
	hmacKeyHex := os.Getenv("VSDM_HMAC_KEY")
	if hmacKeyHex == "" {
		return "", fmt.Errorf("VSDM_HMAC_KEY not set")
	}
	hmacKeyKid := os.Getenv("VSDM_HMAC_KID")
	if hmacKeyKid == "" {
		return "", fmt.Errorf("VSDM_HMAC_KID not set")
	}

	hmacKey, err := hex.DecodeString(hmacKeyHex)
	if err != nil {
		return "", fmt.Errorf("decoding hmac key: %w", err)
	}

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
}
