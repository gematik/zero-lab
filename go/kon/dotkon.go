package kon

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Dotkon represents the .kon configuration file format.
type Dotkon struct {
	Version                 string              `json:"version"`
	URL                     string              `json:"url"`
	RewriteServiceEndpoints bool                `json:"rewriteServiceEndpoints"`
	MandantId               string              `json:"mandantId"`
	WorkplaceId             string              `json:"workplaceId"`
	ClientSystemId          string              `json:"clientSystemId"`
	UserId                  string              `json:"userId"`
Credentials             CredentialsConfig   `json:"-"`
	Env                     string              `json:"env"`
	InsecureSkipVerify      bool                `json:"insecureSkipVerify"`
	ExpectedHost            string              `json:"expectedHost"`
	TrustStore              []string            `json:"trustStore"`
	TrustedCertificates     []*x509.Certificate `json:"-"`
}

var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

// expandEnvVars replaces ${VAR_NAME} patterns with their environment variable values.
func expandEnvVars(data []byte) []byte {
	return envVarPattern.ReplaceAllFunc(data, func(match []byte) []byte {
		varName := envVarPattern.FindSubmatch(match)[1]
		return []byte(os.Getenv(string(varName)))
	})
}

// ParseDotkon parses a .kon configuration file and returns a Dotkon.
// It supports environment variable expansion using ${VAR_NAME} syntax.
func ParseDotkon(data []byte) (*Dotkon, error) {
	expanded := expandEnvVars(data)

	// Unmarshal into intermediate struct to handle raw credentials
	var raw struct {
		Dotkon
		RawCredentials json.RawMessage `json:"credentials"`
	}
	if err := json.Unmarshal(expanded, &raw); err != nil {
		return nil, fmt.Errorf("parsing .kon file: %w", err)
	}

	dk := &raw.Dotkon

	creds, err := parseCredentials(raw.RawCredentials)
	if err != nil {
		return nil, err
	}
	dk.Credentials = creds

	if err := dk.validate(); err != nil {
		return nil, err
	}

	if err := dk.parseTrustStore(); err != nil {
		return nil, fmt.Errorf("parsing .kon trustStore: %w", err)
	}

	return dk, nil
}

func parseCredentials(raw json.RawMessage) (CredentialsConfig, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	var typ struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &typ); err != nil {
		return nil, fmt.Errorf("determining credential type: %w", err)
	}

	if typ.Type == "" {
		return nil, fmt.Errorf("credentials.type is required")
	}

	switch typ.Type {
	case "basic":
		var cred CredentialsConfigBasic
		if err := json.Unmarshal(raw, &cred); err != nil {
			return nil, err
		}
		if err := validateBasicCredentials(cred); err != nil {
			return nil, err
		}
		return cred, nil
	case "pkcs12":
		var cred CredentialsConfigPKCS12
		if err := json.Unmarshal(raw, &cred); err != nil {
			return nil, err
		}
		if cred.Data == "" {
			return nil, fmt.Errorf("credentials.data is required for pkcs12 credentials")
		}
		return cred, nil
	default:
		return nil, fmt.Errorf("unsupported credentials.type: %q (must be basic or pkcs12)", typ.Type)
	}
}

func validateBasicCredentials(cred CredentialsConfigBasic) error {
	var errs []string
	if cred.Username == "" {
		errs = append(errs, "credentials.username is required for basic credentials")
	}
	if cred.Password == "" {
		errs = append(errs, "credentials.password is required for basic credentials")
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid .kon configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

var validEnvValues = map[string]bool{"ru": true, "tu": true, "pu": true}

func (dk *Dotkon) validate() error {
	var errs []string

	if dk.URL == "" {
		errs = append(errs, "\"url\" is required")
	}
	if dk.MandantId == "" {
		errs = append(errs, "\"mandantId\" is required")
	}
	if dk.WorkplaceId == "" {
		errs = append(errs, "\"workplaceId\" is required")
	}
	if dk.ClientSystemId == "" {
		errs = append(errs, "\"clientSystemId\" is required")
	}
	if dk.Env != "" && !validEnvValues[dk.Env] {
		errs = append(errs, fmt.Sprintf("\"env\" must be one of ru, tu, pu (got %q)", dk.Env))
	}
	if dk.Credentials == nil {
		errs = append(errs, "\"credentials\" is required")
	}

	if len(errs) > 0 {
		return fmt.Errorf("invalid .kon configuration:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

func (dk *Dotkon) parseTrustStore() error {
	if len(dk.TrustStore) == 0 {
		return nil
	}
	dk.TrustedCertificates = make([]*x509.Certificate, 0, len(dk.TrustStore))
	for i, s := range dk.TrustStore {
		der, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return fmt.Errorf("decoding certificate at index %d: %w", i, err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parsing certificate at index %d: %w", i, err)
		}
		dk.TrustedCertificates = append(dk.TrustedCertificates, cert)
	}
	return nil
}
