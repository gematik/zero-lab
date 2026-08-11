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

	"github.com/gematik/zero-lab/go/brainpool/josebp"
	"github.com/google/uuid"
)

type EntitlementRequestType struct {
	JWT string `json:"jwt"`
}

type EntitlementRequestTypeV2 struct {
	PoPP string `json:"popp"`
}

type ValidToResponseType struct {
	ValidTo time.Time `json:"validTo"`
}

// ProvidePoPPFunc returns a PoPP token (JWS compact, typ vnd.telematik.popp+jwt)
// for the given insurant, exactly as issued by the PoPP Service.
type ProvidePoPPFunc func(insurantId string) (string, error)

// SetEntitlementPN entitles the current SMC-B for the insurant's record via
// setEntitlementPs, using caller-supplied VSDM proof material: the
// Prüfziffer (auditEvidence) and hash check value. The session only signs
// and transports; obtaining the proof is the caller's concern.
func (s *Session) SetEntitlementPN(insurantId string, auditEvidence string, hcv []byte) error {
	if s.securityFunctions == nil || s.securityFunctions.AuthnCertFunc == nil || s.securityFunctions.AuthnSignFunc == nil {
		return fmt.Errorf("no SMC-B authn identity configured")
	}
	if s.VAUChannel == nil {
		return fmt.Errorf("no open VAU channel")
	}

	iat := time.Now().Add(-60 * time.Second)
	cert, err := s.securityFunctions.AuthnCertFunc()
	if err != nil {
		return fmt.Errorf("getting authn certificate: %w", err)
	}

	jwt, err := josebp.NewJWTBuilder().
		Header("alg", "ES256").
		Header("typ", "JWT").
		Header("x5c", []string{base64.StdEncoding.EncodeToString(cert.Raw)}).
		Claim("iat", iat.Unix()).
		Claim("exp", iat.Add(20*time.Minute).Unix()).
		Claim("auditEvidence", auditEvidence).
		Claim("hcv", base64.StdEncoding.EncodeToString(hcv)).
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

// SetEntitlementPoPP entitles the current user for the insurant's record via
// setEntitlementPsV2, using a caller-supplied PoPP token which is passed
// through exactly as received from the PoPP Service. Returns the validTo of
// the registered entitlement.
// A_27671 - the token is single-use: a failed request must not be retried
// with the same token, and the token is never logged.
func (s *Session) SetEntitlementPoPP(insurantId string, poppToken string) (time.Time, error) {
	if s.VAUChannel == nil {
		return time.Time{}, fmt.Errorf("no open VAU channel")
	}

	entitlement := EntitlementRequestTypeV2{
		PoPP: poppToken,
	}

	body, err := json.Marshal(entitlement)
	if err != nil {
		return time.Time{}, fmt.Errorf("marshaling body: %w", err)
	}

	req, err := http.NewRequest("POST", "/epa/basic/api/v2/ps/entitlements", bytes.NewBuffer(body))
	if err != nil {
		return time.Time{}, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("x-insurantid", insurantId)
	req.Header.Set("x-useragent", UserAgent)
	req.Header.Set("x-request-id", uuid.New().String())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))

	slog.Debug("Sending PoPP entitlement request", "insurantId", insurantId)

	resp, err := s.VAUChannel.Do(req)
	if err != nil {
		return time.Time{}, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return time.Time{}, parseHttpError(resp)
	}

	var validTo ValidToResponseType
	if err := json.NewDecoder(resp.Body).Decode(&validTo); err != nil {
		return time.Time{}, fmt.Errorf("unmarshaling response: %w", err)
	}

	return validTo.ValidTo, nil
}
