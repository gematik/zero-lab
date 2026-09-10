package testca

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// WritePEMCert writes node's certificate DER as a PEM file under t.TempDir()
// and returns the absolute path. The file is cleaned up when the test ends.
func WritePEMCert(t *testing.T, name string, node *Node) string {
	t.Helper()
	block := &pem.Block{Type: "CERTIFICATE", Bytes: node.DER}
	return WriteTemp(t, name, pem.EncodeToMemory(block))
}

// WritePEMChain writes the supplied nodes as a single concatenated PEM file
// (one CERTIFICATE block per node, in order). Useful for assembling the
// "-untrusted" file openssl verify wants for intermediate CAs.
func WritePEMChain(t *testing.T, name string, nodes ...*Node) string {
	t.Helper()
	var out []byte
	for _, n := range nodes {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: n.DER})...)
	}
	return WriteTemp(t, name, out)
}

// WriteTemp writes data to a temp file under t.TempDir() and returns the
// absolute path. The file is cleaned up automatically when the test ends.
func WriteTemp(t *testing.T, name string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write temp %s: %v", path, err)
	}
	return path
}
