package kon_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/kon"
)

func TestParseDotkonBasic(t *testing.T) {
	data := []byte(`{
		"version": "1.0.0",
		"url": "https://konnektor.example.com:8443",
		"mandantId": "M1",
		"workplaceId": "W1",
		"clientSystemId": "C1",
		"userId": "U1",
"credentials": {
			"type": "basic",
			"username": "user",
			"password": "secret"
		},
		"env": "ru",
		"insecureSkipVerify": true,
		"expectedHost": "konnektor.example.com"
	}`)

	config, err := kon.ParseDotkon(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if config.URL != "https://konnektor.example.com:8443" {
		t.Errorf("URL = %q, want %q", config.URL, "https://konnektor.example.com:8443")
	}
	if config.MandantId != "M1" {
		t.Errorf("MandantId = %q, want %q", config.MandantId, "M1")
	}
	if config.WorkplaceId != "W1" {
		t.Errorf("WorkplaceId = %q, want %q", config.WorkplaceId, "W1")
	}
	if config.ClientSystemId != "C1" {
		t.Errorf("ClientSystemId = %q, want %q", config.ClientSystemId, "C1")
	}
	if config.UserId != "U1" {
		t.Errorf("UserId = %q, want %q", config.UserId, "U1")
	}
	if config.Env != "ru" {
		t.Errorf("Env = %q, want %q", config.Env, "ru")
	}
	if !config.InsecureSkipVerify {
		t.Error("UnsafeSkipVerify = false, want true")
	}
	if config.ExpectedHost != "konnektor.example.com" {
		t.Errorf("ExpectedHost = %q, want %q", config.ExpectedHost, "konnektor.example.com")
	}
	if config.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", config.Version, "1.0.0")
	}
}

func TestParseDotkonEnvExpansion(t *testing.T) {
	os.Setenv("TEST_KON_PASSWORD", "env-secret-123")
	defer os.Unsetenv("TEST_KON_PASSWORD")

	data := []byte(`{
		"version": "1.0.0",
		"url": "https://konnektor.example.com:8443",
		"mandantId": "M1",
		"workplaceId": "W1",
		"clientSystemId": "C1",
		"credentials": {
			"type": "basic",
			"username": "user",
			"password": "${TEST_KON_PASSWORD}"
		}
	}`)

	config, err := kon.ParseDotkon(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cred, ok := config.Credentials.(kon.CredentialsConfigBasic)
	if !ok {
		t.Fatalf("expected CredentialsConfigBasic, got %T", config.Credentials)
	}
	if cred.Password != "env-secret-123" {
		t.Errorf("Password = %q, want %q", cred.Password, "env-secret-123")
	}
}

func TestParseDotkonPKCS12(t *testing.T) {
	data := []byte(`{
		"version": "1.0.0",
		"url": "https://konnektor.example.com:8443",
		"mandantId": "M1",
		"workplaceId": "W1",
		"clientSystemId": "C1",
		"credentials": {
			"type": "pkcs12",
			"data": "dGVzdC1wa2NzMTItZGF0YQ==",
			"password": "test"
		}
	}`)

	config, err := kon.ParseDotkon(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cred, ok := config.Credentials.(kon.CredentialsConfigPKCS12)
	if !ok {
		t.Fatalf("expected CredentialsConfigPKCS12, got %T", config.Credentials)
	}
	if cred.Data != "dGVzdC1wa2NzMTItZGF0YQ==" {
		t.Errorf("Data = %q, want %q", cred.Data, "dGVzdC1wa2NzMTItZGF0YQ==")
	}
	if cred.Password != "test" {
		t.Errorf("UnsafePassword = %q, want %q", cred.Password, "test")
	}
}

func TestParseDotkonValidationRequiredFields(t *testing.T) {
	data := []byte(`{}`)

	_, err := kon.ParseDotkon(data)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}

	errMsg := err.Error()
	for _, field := range []string{"url", "mandantId", "workplaceId", "clientSystemId", "credentials"} {
		if !strings.Contains(errMsg, fmt.Sprintf("%q is required", field)) {
			t.Errorf("expected error to mention %q, got: %s", field, errMsg)
		}
	}
}

func TestParseDotkonValidationInvalidEnv(t *testing.T) {
	data := []byte(`{
		"url": "https://konnektor.example.com:8443",
		"mandantId": "M1",
		"workplaceId": "W1",
		"clientSystemId": "C1",
		"env": "invalid",
		"credentials": {
			"type": "basic",
			"username": "user",
			"password": "pass"
		}
	}`)

	_, err := kon.ParseDotkon(data)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "\"env\" must be one of") {
		t.Errorf("expected env validation error, got: %v", err)
	}
}

func TestParseDotkonValidationBasicCredentials(t *testing.T) {
	data := []byte(`{
		"url": "https://konnektor.example.com:8443",
		"mandantId": "M1",
		"workplaceId": "W1",
		"clientSystemId": "C1",
		"credentials": {
			"type": "basic"
		}
	}`)

	_, err := kon.ParseDotkon(data)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "credentials.username") {
		t.Errorf("expected username validation error, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "credentials.password") {
		t.Errorf("expected password validation error, got: %s", errMsg)
	}
}

func TestParseDotkonValidationPKCS12Data(t *testing.T) {
	data := []byte(`{
		"url": "https://konnektor.example.com:8443",
		"mandantId": "M1",
		"workplaceId": "W1",
		"clientSystemId": "C1",
		"credentials": {
			"type": "pkcs12"
		}
	}`)

	_, err := kon.ParseDotkon(data)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "credentials.data") {
		t.Errorf("expected data validation error, got: %v", err)
	}
}

func TestParseDotkonValidationMissingCredentialType(t *testing.T) {
	data := []byte(`{
		"url": "https://konnektor.example.com:8443",
		"mandantId": "M1",
		"workplaceId": "W1",
		"clientSystemId": "C1",
		"credentials": {}
	}`)

	_, err := kon.ParseDotkon(data)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "credentials.type") {
		t.Errorf("expected type validation error, got: %v", err)
	}
}

func TestParseDotkonUnsupportedCredentials(t *testing.T) {
	data := []byte(`{
		"version": "1.0.0",
		"url": "https://konnektor.example.com:8443",
		"mandantId": "M1",
		"workplaceId": "W1",
		"clientSystemId": "C1",
		"credentials": {
			"type": "unknown"
		}
	}`)

	_, err := kon.ParseDotkon(data)
	if err == nil {
		t.Fatal("expected error for unsupported credentials, got nil")
	}
	if !strings.Contains(err.Error(), "must be basic or pkcs12") {
		t.Errorf("expected helpful error listing valid types, got: %v", err)
	}
}

func TestParseDotkonRewriteServiceEndpoints(t *testing.T) {
	data := []byte(`{
		"version": "1.0.0",
		"url": "https://konnektor.example.com:8443",
		"rewriteServiceEndpoints": true,
		"mandantId": "M1",
		"workplaceId": "W1",
		"clientSystemId": "C1",
		"credentials": {
			"type": "basic",
			"username": "user",
			"password": "pass"
		}
	}`)

	config, err := kon.ParseDotkon(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !config.RewriteServiceEndpoints {
		t.Error("RewriteServiceEndpoints = false, want true")
	}
}
