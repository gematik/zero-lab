package epa

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
)

type EntitlementRequestType struct {
	JWT string `json:"jwt"`
}

func (s *Session) SetEntitlementPs(insurantId string, auditEvidence string) error {
	iat := time.Now().Add(-60 * time.Second)
	jwt, err := brainpool.NewJWTBuilder().
		Header("alg", "ES256").
		Header("typ", "JWT").
		Header("x5c", []string{base64.StdEncoding.EncodeToString(s.AttestCertificate.Raw)}).
		Claim("iat", iat.Unix()).
		Claim("exp", iat.Add(20*time.Minute).Unix()).
		Claim("auditEvidence", auditEvidence).
		Sign(sha256.New(), s.tokenSignFunc)

	entitlement := EntitlementRequestType{
		JWT: string(jwt),
	}

	body, err := json.Marshal(entitlement)
	if err != nil {
		return fmt.Errorf("marshaling body: %w", err)
	}

	req, err := http.NewRequest("POST", s.baseURL+"/epa/basic/api/v1/ps/entitlements", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("x-insurantid", insurantId)
	req.Header.Set("x-useragent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	resp, err := s.channel.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return parseHttpError(resp)
	}

	return nil
}
