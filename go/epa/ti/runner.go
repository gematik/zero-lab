// Package ti drives the Rust `ti` command-line tool for the pieces of the TI an ePA client
// needs but Go's standard library does not have: the brainpool SMC-B identity (PKCS#12,
// PEM or a card at the Konnektor), ES256/BP256R1 signatures with it, the IDP-Dienst's
// Authenticator-Modul flow, and the validation of the VAU's certificates and keys.
//
// Every operation is one `ti --format json …` run: the key never enters this process, a
// Rust failure cannot take the Go process down, and the contract is the one `ti agent`
// documents (`"schema": 1`, exit codes, error kinds). The calls happen per start-up,
// session or handshake, where the process start costs nothing noticeable.
package ti

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Schema is the JSON contract version this package speaks; `ti` adds fields within it,
// never changes them.
const Schema = 1

// Runner runs the tool. [*Binary] is the real one; tests substitute their own.
type Runner interface {
	// Run runs `ti --format json args…` with stdin and returns stdout. A non-zero exit
	// comes back as an [*Error] carrying the tool's error kind and, when the tool wrote
	// a report anyway (a verify that found the input not valid), its stdout.
	Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error)
}

// Error is a failed run: what `ti` said on stderr (`error.kind`, `error.message`,
// `error.hint`) and how it exited.
type Error struct {
	Kind     string
	Message  string
	Hint     string
	ExitCode int
	// Stdout is the report the tool wrote before exiting non-zero, if any: a verdict of
	// "not valid" is exit 1 with a full report.
	Stdout []byte
}

func (e *Error) Error() string {
	if e.Kind == "" {
		return fmt.Sprintf("ti exited %d: %s", e.ExitCode, e.Message)
	}
	return fmt.Sprintf("ti: %s (%s)", e.Message, e.Kind)
}

// Binary is the `ti` executable: EPA_TI_BIN, else `ti` on the PATH.
type Binary struct {
	Path string
	// Timeout bounds one run; the IDP flow makes five requests, a verify loads the TSL.
	Timeout time.Duration
	// Verbose passes -v and relays the tool's diagnostics to slog at debug level.
	Verbose bool
}

// DefaultTimeout is generous enough for the IDP-Dienst flow over a slow proxy.
const DefaultTimeout = 60 * time.Second

// envPassthrough is the environment a child gets: what it needs to find its cache,
// configuration and the network, nothing of this process's secrets.
var envPassthrough = []string{
	"PATH", "HOME", "TMPDIR", "USERPROFILE", "LOCALAPPDATA",
	"TI_CACHE_DIR", "TI_CONNECTOR_CONFIG", "TI_CONNECTOR_TIMEOUT", "TI_CARD_TIMEOUT",
	"XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME",
	"HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY",
	"https_proxy", "http_proxy", "all_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",
}

// NewBinary finds the tool: EPA_TI_BIN (an absolute path, preferably), else `ti` on the
// PATH. An error names where it looked.
func NewBinary() (*Binary, error) {
	path := os.Getenv("EPA_TI_BIN")
	if path == "" {
		found, err := exec.LookPath("ti")
		if err != nil {
			return nil, fmt.Errorf("the ti tool is needed (set EPA_TI_BIN or put ti on the PATH): %w", err)
		}
		path = found
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("EPA_TI_BIN %q: %w", path, err)
	}
	if _, err := os.Stat(abs); err != nil {
		return nil, fmt.Errorf("EPA_TI_BIN %q: %w", path, err)
	}
	return &Binary{Path: abs, Timeout: DefaultTimeout}, nil
}

// Run implements [Runner].
func (b *Binary) Run(ctx context.Context, stdin []byte, args ...string) ([]byte, error) {
	timeout := b.Timeout
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	full := make([]string, 0, len(args)+3)
	full = append(full, "--format", "json")
	if b.Verbose {
		full = append(full, "-v")
	}
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, b.Path, full...)
	cmd.Env = childEnv()
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.WaitDelay = 2 * time.Second

	slog.Debug("ti", "args", strings.Join(redact(args), " "))
	err := cmd.Run()
	if b.Verbose {
		for line := range strings.SplitSeq(strings.TrimRight(stderr.String(), "\n"), "\n") {
			if line != "" && !strings.HasPrefix(line, "{") {
				slog.Debug("ti", "diagnostic", line)
			}
		}
	}
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			return nil, fmt.Errorf("running %s: %w", b.Path, err)
		}
		return nil, parseError(exit.ExitCode(), stderr.Bytes(), stdout.Bytes())
	}
	if err := checkSchema(stdout.Bytes()); err != nil {
		return nil, err
	}
	return stdout.Bytes(), nil
}

func childEnv() []string {
	env := make([]string, 0, len(envPassthrough))
	for _, name := range envPassthrough {
		if value, ok := os.LookupEnv(name); ok {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// redact hides the values of options that could carry a secret in a log line; `ti`
// takes passwords by file, but a caller may still pass one.
func redact(args []string) []string {
	out := make([]string, len(args))
	hide := false
	for i, arg := range args {
		switch {
		case hide:
			out[i] = "***"
			hide = false
		case arg == "--p12-password":
			out[i] = arg
			hide = true
		default:
			out[i] = arg
		}
	}
	return out
}

// parseError reads the tool's error document from stderr: its last JSON line.
func parseError(exitCode int, stderr, stdout []byte) *Error {
	err := &Error{ExitCode: exitCode, Stdout: stdout}
	for line := range strings.SplitSeq(strings.TrimSpace(string(stderr)), "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var doc struct {
			Schema int `json:"schema"`
			Error  struct {
				Kind    string `json:"kind"`
				Message string `json:"message"`
				Hint    string `json:"hint"`
			} `json:"error"`
		}
		if json.Unmarshal([]byte(line), &doc) == nil && doc.Error.Kind != "" {
			err.Kind = doc.Error.Kind
			err.Message = doc.Error.Message
			err.Hint = doc.Error.Hint
		}
	}
	if err.Kind == "" {
		err.Message = strings.TrimSpace(string(stderr))
		if err.Message == "" {
			err.Message = "no error document"
		}
	}
	return err
}

func checkSchema(stdout []byte) error {
	var doc struct {
		Schema int `json:"schema"`
	}
	if err := json.Unmarshal(stdout, &doc); err != nil {
		return fmt.Errorf("ti wrote no JSON document: %w", err)
	}
	if doc.Schema != Schema {
		return fmt.Errorf("ti speaks schema %d, this client schema %d", doc.Schema, Schema)
	}
	return nil
}

// Version is what `ti version` reports.
type Version struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
}

// Version asks the tool who it is; the first call a program should make, so a missing or
// foreign binary fails at start-up, not at the first login.
func (b *Binary) Version(ctx context.Context) (*Version, error) {
	out, err := b.Run(ctx, nil, "version")
	if err != nil {
		return nil, err
	}
	var v Version
	if err := json.Unmarshal(out, &v); err != nil {
		return nil, fmt.Errorf("ti version: %w", err)
	}
	return &v, nil
}
