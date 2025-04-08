package epa

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gematik/zero-lab/go/brainpool"
)

type EntitlementRequestType struct {
	JWT string `json:"jwt"`
}

// Entitle the current SMC-B (provided by SecuriotyFunctions)
// to access the data of the insurant with the given insurant.
func (s *Session) Entitle(insurantId string) error {
	slog.Debug("Entitling insurant", "env", s.Env, "insurantId", insurantId)
	auditEvidence, err := s.securityFunctions.ProofOfAuditEvidenceFunc(insurantId)
	if err != nil {
		return fmt.Errorf("getting proof of audit evidence: %w", err)
	}

	err = s.SetEntitlementPS(insurantId, auditEvidence)
	if err != nil {
		return fmt.Errorf("setting entitlement PS: %w", err)
	}

	return nil
}

func (s *Session) SetEntitlementPS(insurantId string, auditEvidence string) error {
	iat := time.Now().Add(-60 * time.Second)
	cert, err := s.securityFunctions.AuthnCertFunc()
	if err != nil {
		return fmt.Errorf("getting authn certificate: %w", err)
	}
	jwt, err := brainpool.NewJWTBuilder().
		Header("alg", "ES256").
		Header("typ", "JWT").
		Header("x5c", []string{base64.StdEncoding.EncodeToString(cert.Raw)}).
		Claim("iat", iat.Unix()).
		Claim("exp", iat.Add(20*time.Minute).Unix()).
		Claim("auditEvidence", auditEvidence).
		Sign(sha256.New(), s.securityFunctions.AuthnSignFunc)
	if err != nil {
		return fmt.Errorf("signing JWT: %w", err)
	}

	entitlement := EntitlementRequestType{
		JWT: string(jwt),
	}

	body, err := json.Marshal(entitlement)
	if err != nil {
		return fmt.Errorf("marshaling body: %w", err)
	}

	req, err := http.NewRequest("POST", "/epa/basic/api/v1/ps/entitlements", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("x-insurantid", insurantId)
	req.Header.Set("x-useragent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	slog.Debug("Sending entitlement request", "body", string(body))

	resp, err := s.VAUChannel.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return parseHttpError(resp)
	}

	return nil
}
