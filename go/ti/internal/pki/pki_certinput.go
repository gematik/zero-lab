package pki

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
)

// ---- shared input helpers ---------------------------------------------------

// readCertInputBytes reads either FILE or stdin ("-") and returns the raw bytes.
func readCertInputBytes(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// parseCertInput accepts PEM or DER bytes and returns all certificates found.
// Multiple PEM CERTIFICATE blocks are returned in order; single DER blobs are
// returned as a one-element slice.
func parseCertInput(raw []byte) ([]*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty certificate input")
	}
	// PEM heuristic: ASCII begins with "-----BEGIN".
	if isPEM(raw) {
		out, err := gempki.ParsePEMCertificates(raw)
		if err != nil {
			return nil, fmt.Errorf("parse PEM: %w", err)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no CERTIFICATE blocks found in PEM input")
		}
		return out, nil
	}
	cert, err := gempki.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("parse DER: %w", err)
	}
	return []*x509.Certificate{cert}, nil
}

func isPEM(raw []byte) bool {
	const head = "-----BEGIN"
	if len(raw) < len(head) {
		return false
	}
	// Find the first non-whitespace byte; if it starts the PEM marker, it's PEM.
	for i := range raw {
		if raw[i] == ' ' || raw[i] == '\t' || raw[i] == '\r' || raw[i] == '\n' {
			continue
		}
		return strings.HasPrefix(string(raw[i:]), head)
	}
	return false
}

// loadCertChain is the shared input loader for every cert subcommand.
func loadCertChain(path string) ([]*x509.Certificate, error) {
	raw, err := readCertInputBytes(path)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	return parseCertInput(raw)
}

func parseAtFlag(raw string) (*time.Time, error) {
	if raw == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return nil, fmt.Errorf("--at must be RFC3339 (e.g. 2026-01-15T00:00:00Z): %w", err)
	}
	return &t, nil
}
