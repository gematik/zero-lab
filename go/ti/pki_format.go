package main

import (
	"fmt"
	"slices"
	"strings"
)

// outputFormat is the user-facing --format flag value space shared across
// every ti pki leaf. Not every leaf accepts every format — see
// supportedFormats for the per-leaf table.
type outputFormat string

const (
	formatText outputFormat = "text"
	formatJSON outputFormat = "json"
	formatPEM  outputFormat = "pem"
	formatXML  outputFormat = "xml"
)

// parseOutputFormat normalises a user-supplied string and validates it
// against the allowed set for the calling subcommand.
func parseOutputFormat(raw string, allowed []outputFormat) (outputFormat, error) {
	f := outputFormat(strings.ToLower(strings.TrimSpace(raw)))
	if slices.Contains(allowed, f) {
		return f, nil
	}
	names := make([]string, len(allowed))
	for i, a := range allowed {
		names[i] = string(a)
	}
	return "", fmt.Errorf("unsupported format %q (allowed: %s)", raw, strings.Join(names, ", "))
}

// formatsCertInspect / Verify / Fingerprint / Admission / Lint capture the
// allowed --format values for each cert subcommand; reused by their flag
// validators and (eventually) their cobra completion.
var (
	formatsCertInspect      = []outputFormat{formatText, formatJSON, formatPEM}
	formatsCertVerify       = []outputFormat{formatText, formatJSON}
	formatsCertLint         = []outputFormat{formatText, formatJSON}
	formatsTSLShow          = []outputFormat{formatText, formatJSON}
	formatsTSLFetch         = []outputFormat{formatXML, formatJSON, formatText}
	formatsTSLVerify        = []outputFormat{formatText, formatJSON}
	formatsTSLProviders     = []outputFormat{formatText, formatJSON}
	formatsTSLIntermediates = []outputFormat{formatText, formatJSON, formatPEM}
	formatsRootsList        = []outputFormat{formatText, formatJSON}
	formatsRootsBundle      = []outputFormat{formatPEM, formatJSON}
	formatsOCSPCheck        = []outputFormat{formatText, formatJSON}
)
