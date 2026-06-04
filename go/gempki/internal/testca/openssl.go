package testca

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// RequireOpenSSL skips the test if openssl is not in PATH. Use at the top of
// any test that shells out to openssl.
func RequireOpenSSL(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skipf("openssl not found in PATH: %v", err)
	}
}

// RequireOpenSSLBrainpool skips the test unless the installed openssl can
// list at least one brainpool curve. Some distributions ship openssl without
// brainpool support (CentOS 7, certain Alpine variants).
func RequireOpenSSLBrainpool(t *testing.T) {
	t.Helper()
	RequireOpenSSL(t)
	out, err := exec.Command("openssl", "ecparam", "-list_curves").Output()
	if err != nil {
		t.Skipf("openssl ecparam -list_curves failed: %v", err)
	}
	if !strings.Contains(string(out), "brainpool") {
		t.Skipf("openssl does not list brainpool curves — skipping cross-test")
	}
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

// OpenSSLX509Text returns "openssl x509 -in <pemPath> -noout -text" output.
// Useful for human-readable diffing in failure logs.
func OpenSSLX509Text(t *testing.T, pemPath string) string {
	t.Helper()
	RequireOpenSSL(t)
	out, err := exec.Command("openssl", "x509", "-in", pemPath, "-noout", "-text").CombinedOutput()
	if err != nil {
		t.Fatalf("openssl x509 -text: %v\n%s", err, out)
	}
	return string(out)
}

// OpenSSLVerify runs `openssl verify -CAfile <rootPath> [-untrusted <chainPath>] <leafPath>`.
// Returns ok=true and the trimmed stdout when verification succeeded.
// Phase-7 cross-tests will use this to confirm gempki and openssl agree on
// chain validity. chainPath may be empty when no intermediates are needed.
func OpenSSLVerify(t *testing.T, leafPath, chainPath, rootPath string) (bool, string) {
	t.Helper()
	RequireOpenSSL(t)
	args := []string{"verify", "-CAfile", rootPath}
	if chainPath != "" {
		args = append(args, "-untrusted", chainPath)
	}
	args = append(args, leafPath)
	out, err := exec.Command("openssl", args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return false, text
		}
		t.Fatalf("openssl verify: %v\n%s", err, text)
	}
	return strings.Contains(text, ": OK"), text
}
