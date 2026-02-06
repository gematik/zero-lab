// Package legacy provides utilities to convert BER-encoded (legacy) PKCS#12 files to DER format.
//
// The main pkcs12 package requires DER encoding as mandated by RFC 7292. However, many legacy
// PKCS#12 files use BER indefinite-length encoding. This package uses OpenSSL to convert them.
package legacy

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
)

// ConvertWithOpenSSL converts a BER-encoded PKCS#12 file to DER format using OpenSSL.
// This is the most reliable method as it preserves MAC integrity.
//
// Parameters:
//   - data: The BER-encoded PKCS#12 data
//   - password: The PKCS#12 password (empty string for no password)
//
// Returns the DER-encoded PKCS#12 data that can be parsed by the main pkcs12 package.
//
// Requires OpenSSL 3.x with -legacy support.
func ConvertWithOpenSSL(data []byte, password string) ([]byte, error) {
	// Check if OpenSSL is available
	_, err := exec.LookPath("openssl")
	if err != nil {
		return nil, fmt.Errorf("openssl not found in PATH: %w", err)
	}

	// Create temp file for password
	tmpPass, err := os.CreateTemp("", "p12-pass-*.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp password file: %w", err)
	}
	tmpPassPath := tmpPass.Name()
	defer os.Remove(tmpPassPath)

	// Create temp file for input P12
	tmpIn, err := os.CreateTemp("", "p12-in-*.p12")
	if err != nil {
		tmpPass.Close()
		return nil, fmt.Errorf("failed to create temp input file: %w", err)
	}
	tmpInPath := tmpIn.Name()
	defer os.Remove(tmpInPath)

	// Create temp file for intermediate PEM
	tmpPem, err := os.CreateTemp("", "p12-pem-*.pem")
	if err != nil {
		tmpPass.Close()
		tmpIn.Close()
		return nil, fmt.Errorf("failed to create temp PEM file: %w", err)
	}
	tmpPemPath := tmpPem.Name()
	defer os.Remove(tmpPemPath)

	// Create temp file for output P12
	tmpOut, err := os.CreateTemp("", "p12-out-*.p12")
	if err != nil {
		tmpPass.Close()
		tmpIn.Close()
		tmpPem.Close()
		return nil, fmt.Errorf("failed to create temp output file: %w", err)
	}
	tmpOutPath := tmpOut.Name()
	defer os.Remove(tmpOutPath)

	// Write password file
	if _, err := tmpPass.WriteString(password); err != nil {
		tmpPass.Close()
		tmpIn.Close()
		tmpPem.Close()
		tmpOut.Close()
		return nil, fmt.Errorf("failed to write password file: %w", err)
	}
	tmpPass.Close()

	// Write input data
	if _, err := tmpIn.Write(data); err != nil {
		tmpIn.Close()
		tmpPem.Close()
		tmpOut.Close()
		return nil, fmt.Errorf("failed to write input data: %w", err)
	}
	tmpIn.Close()
	tmpPem.Close()
	tmpOut.Close()

	// Step 1: Convert legacy P12 to PEM format
	cmd1 := exec.Command("openssl", "pkcs12",
		"-in", tmpInPath,
		"-out", tmpPemPath,
		"-nodes",
		"-passin", "file:"+tmpPassPath,
		"-legacy",
	)
	var stderr1 bytes.Buffer
	cmd1.Stderr = &stderr1

	if err := cmd1.Run(); err != nil {
		return nil, fmt.Errorf("openssl pkcs12 decode failed: %w\nStderr: %s", err, stderr1.String())
	}

	// Step 2: Convert PEM back to modern P12 (DER format)
	cmd2 := exec.Command("openssl", "pkcs12",
		"-export",
		"-in", tmpPemPath,
		"-out", tmpOutPath,
		"-passout", "file:"+tmpPassPath,
	)
	var stderr2 bytes.Buffer
	cmd2.Stderr = &stderr2

	if err := cmd2.Run(); err != nil {
		return nil, fmt.Errorf("openssl pkcs12 encode failed: %w\nStderr: %s", err, stderr2.String())
	}

	// Read result
	result, err := os.ReadFile(tmpOutPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read output file: %w", err)
	}

	return result, nil
}

// IsBER checks if the data appears to be BER-encoded (indefinite-length).
// Returns true if the data starts with SEQUENCE tag (0x30) followed by indefinite-length marker (0x80).
func IsBER(data []byte) bool {
	return len(data) >= 2 && data[0] == 0x30 && data[1] == 0x80
}
