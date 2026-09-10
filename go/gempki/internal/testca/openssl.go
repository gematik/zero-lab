package testca

import (
	"errors"
	"os/exec"
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

// OpenSSLVerify runs `openssl verify -CAfile <rootPath> [-untrusted <chainPath>] <leafPath>`
// and returns ok=true with the trimmed output when verification succeeded.
// The cross-tests use it to confirm gempki and openssl agree on a chain.
// chainPath may be empty when no intermediates are needed.
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
		if _, ok := errors.AsType[*exec.ExitError](err); ok {
			return false, text
		}
		t.Fatalf("openssl verify: %v\n%s", err, text)
	}
	return strings.Contains(text, ": OK"), text
}
