package ti

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gematik/zero-lab/go/epa/vau"
)

// Verifier checks a VAU's CertData and host keys with `ti pki verify` (the chain to the
// TI roots, profile and environment detected from the certificate) and
// `ti pki verify-signature` (the ECDSA signature over the signed public keys).
type Verifier struct {
	Runner Runner
	// Offline skips the download of trust material and the OCSP checks: cached or
	// embedded roots only; the verdict then says nothing about revocation.
	Offline bool
}

type verifyReport struct {
	Valid       bool `json:"valid"`
	Environment struct {
		Name string `json:"name"`
	} `json:"environment"`
	Profile struct {
		Name *string `json:"name"`
	} `json:"profile"`
	Errors   []finding `json:"errors"`
	Warnings []finding `json:"warnings"`
}

type finding struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail"`
}

func (f finding) String() string {
	switch {
	case f.Detail != "":
		return f.Code + ": " + f.Detail
	case f.Message != "":
		return f.Code + ": " + f.Message
	}
	return f.Code
}

// VerifyVAU implements [vau.CertVerifier].
func (v *Verifier) VerifyVAU(ctx context.Context, certData *vau.CertData, signedPubKeys, signature []byte) (*vau.Verdict, error) {
	dir, err := os.MkdirTemp("", "epa-vau-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	var chain []byte
	for _, der := range append([][]byte{certData.Cert, certData.CA}, certData.RCAChain...) {
		if len(der) == 0 {
			continue
		}
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	files := map[string][]byte{"chain.pem": chain, "keys.bin": signedPubKeys, "sig.bin": signature}
	paths := make(map[string]string, len(files))
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, content, 0o600); err != nil {
			return nil, err
		}
		paths[name] = path
	}

	verdict := &vau.Verdict{}
	args := []string{"pki", "verify", paths["chain.pem"], "--env", "auto"}
	if v.Offline {
		args = append(args, "--offline")
	}
	out, err := v.Runner.Run(ctx, nil, args...)
	if err != nil {
		var tiErr *Error
		// Exit 1 is "not valid" with a full report; anything else is a failure to judge.
		if !errors.As(err, &tiErr) || tiErr.ExitCode != 1 || len(tiErr.Stdout) == 0 {
			return nil, fmt.Errorf("VAU certificate chain: %w", err)
		}
		out = tiErr.Stdout
	}
	var report verifyReport
	if err := json.Unmarshal(out, &report); err != nil {
		return nil, fmt.Errorf("pki verify: %w", err)
	}
	verdict.ChainValid = report.Valid
	verdict.Environment = report.Environment.Name
	if report.Profile.Name != nil {
		verdict.Profile = *report.Profile.Name
	}
	for _, f := range report.Errors {
		verdict.ChainErrors = append(verdict.ChainErrors, f.String())
	}
	for _, f := range report.Warnings {
		verdict.ChainWarnings = append(verdict.ChainWarnings, f.String())
	}

	out, err = v.Runner.Run(ctx, nil, "pki", "verify-signature",
		"--cert", paths["chain.pem"], "--data", paths["keys.bin"], "--signature", paths["sig.bin"])
	if err != nil {
		var tiErr *Error
		if !errors.As(err, &tiErr) || tiErr.ExitCode != 1 || len(tiErr.Stdout) == 0 {
			return nil, fmt.Errorf("VAU host keys signature: %w", err)
		}
		out = tiErr.Stdout
	}
	var sigReport struct {
		Valid  bool   `json:"valid"`
		Format string `json:"signature_format"`
	}
	if err := json.Unmarshal(out, &sigReport); err != nil {
		return nil, fmt.Errorf("pki verify-signature: %w", err)
	}
	verdict.SignatureValid = sigReport.Valid
	verdict.SignatureFormat = sigReport.Format
	return verdict, nil
}
