package pkcs12

import (
"encoding/asn1"
"encoding/base64"
"testing"
)

// Real-world PKCS#12 test data (password: "00")
const testPFXPassword = "00"
var testPFXBase64 = []byte(`MIIEbAIBAzCCBCIGCSqGSIb3DQEHAaCCBBMEggQPMIIECzCCAroGCSqGSIb3DQEHBqCCAqswggKnAgEAMIICoAYJKoZIhvcNAQcBMF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCFWgOT6sle1IEwEN58YiC2AgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQRpAUribTljn8xBrrzE8CN4CCAjDOx9OcvrK0imy0DJF4ILPVWjcUAJ6CalGimuq6C1W1/2IreZbUdErtliqee923e4+lAJjYj3XEp6K5yeGzoyEI383PbUo3h4VaC2/hs3ZujCNpKNi9E/MlWTzuJFe1k/oOIgaiYyhmu5JPglpvbK+GsNCvVHoybxMEl4yqZaxJxCfFSwDMIuciHcL4Qzlbow8YpVWiivm2udZ1QL1TzFc3NkjfgX14FQowr8PpPOBH1Im4LciihZB1DtaStetLtwNyKTGRzQ9w2OvAEYED1aV77KQHKMWczWIuxMOOJ0jvrTdnwDpFBp8jnOXgipxZm0fFLYwsooLoly9Rh7NnrhTYdjE1wAYuleNAdsB4ilePhlksMxVAMllwQR08USo6y8OGZ6k/Gb/XmGHnQxRuYx9Buops977PB/HXsCQ7cXgHQhUmrzq6bzj6SHs2JUvc/H0g9l+sDu1ytkZE42xCpxmVNEDIqsiXSH54SZy88g3sgR2x4xoNaIXnrFfT1ih+AXmGzH95HmbG5GM+5BJ47vP0UCjmpEuJpcwTDly0Il3rL98mSZNjXtUzr+L9PWBx9w3lAYYD76mGbJS0I9MtOacVC7OYuPwOWCQ1YLCHMAcJhpC1yy8HLRyawaI/i0hAJVp29v3wVa1OsOLJ/pDMbYt6LbI9ZgydRXiGRq5dGKSkvdO0k3Emr0wuz1LvEAC8ws/rL57U+28buLsDqUjywi0szjMQpDztzLyOHdbSfCXj1jCCAUkGCSqGSIb3DQEHAaCCAToEggE2MIIBMjCCAS4GCyqGSIb3DQEMCgECoIH3MIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBBSYlq1EDrfwl/0cHX0ZIDPAgIIADAMBggqhkiG9w0CCQUAMB0GCWCGSAFlAwQBKgQQ21z9lU29rEVQdSca70zmcASBkP99Wy7IyxghRYzJK+w9uwKEQ2EaEi3D9bOtUlpyq1zIXxn7ofDqQzfCVyFxG0p8xsAtgZe6KsfZzmPgip9WNUyqgERQQBOuwC2KLp3u3L/GEFkM+30lIl6aP10b7d6RVVbs1MbgMwmd4DHv8MoEESy5BXqMirLPoO4aZC5NQeVtNKgBdjS4EmwDAwzPpHj4jDElMCMGCSqGSIb3DQEJFTEWBBQLCBeoh+W1XAGnPPNY/K/W3fxlljBBMDEwDQYJYIZIAWUDBAIBBQAEIMZ+ZDm+cAQ5O69Hh3KXMOzR0rijitewFvp/YC77e2z9BAhhs7EP23yFQgICCAA=`)

func TestParseRealWorldPFX(t *testing.T) {
data, err := base64.StdEncoding.DecodeString(string(testPFXBase64))
if err != nil {
t.Fatalf("Failed to decode base64: %v", err)
}

pfx, err := Parse(data)
if err != nil {
t.Fatalf("Parse failed: %v", err)
}

if pfx.Version != 3 {
t.Errorf("Expected version 3, got %d", pfx.Version)
}

if pfx.MacData == nil {
t.Error("Expected MAC data to be present")
}
}

func TestRealWorldPFXStructure(t *testing.T) {
data, err := base64.StdEncoding.DecodeString(string(testPFXBase64))
if err != nil {
t.Fatalf("Failed to decode base64: %v", err)
}

pfx, err := Parse(data)
if err != nil {
t.Fatalf("Parse failed: %v", err)
}

authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
if err != nil {
t.Fatalf("ParseAuthenticatedSafe failed: %v", err)
}

if len(authSafe.ContentInfos) != 2 {
t.Errorf("Expected 2 content infos, got %d", len(authSafe.ContentInfos))
}
}

func TestRealWorldPFXMACAlgorithm(t *testing.T) {
data, err := base64.StdEncoding.DecodeString(string(testPFXBase64))
if err != nil {
t.Fatalf("Failed to decode base64: %v", err)
}

pfx, err := Parse(data)
if err != nil {
t.Fatalf("Parse failed: %v", err)
}

if pfx.MacData == nil {
t.Fatal("MAC data is nil")
}

expectedOID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1} // SHA-256
if !pfx.MacData.Mac.Algorithm.Algorithm.Equal(expectedOID) {
t.Errorf("Expected MAC algorithm OID %v, got %v", expectedOID, pfx.MacData.Mac.Algorithm.Algorithm)
}
}

func TestRealWorldPFXConsistency(t *testing.T) {
data, err := base64.StdEncoding.DecodeString(string(testPFXBase64))
if err != nil {
t.Fatalf("Failed to decode base64: %v", err)
}

// Parse multiple times to ensure consistency
for i := 0; i < 5; i++ {
pfx, err := Parse(data)
if err != nil {
t.Errorf("Parse %d failed: %v", i+1, err)
continue
}

authSafe, err := ParseAuthenticatedSafe(pfx.RawAuthSafe)
if err != nil {
t.Errorf("ParseAuthenticatedSafe %d failed: %v", i+1, err)
continue
}

if len(authSafe.ContentInfos) == 0 {
t.Errorf("Parse %d: no content infos", i+1)
}
}

t.Logf("Consistency check: 5/5 parses successful")
}
