// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

func verify(corpus string, decoder []string, profile string, coarse bool, timeout time.Duration, markdown, name string) error {
	raw, err := os.ReadFile(filepath.Join(corpus, "expected.json"))
	if err != nil {
		return err
	}
	var expected []Expected
	if err := json.Unmarshal(raw, &expected); err != nil {
		return err
	}

	var rows []string
	failed, total := 0, 0
	for _, e := range expected {
		if profile == "modern" && e.Profile != "modern" {
			continue
		}
		total++
		got, err := run(decoder, filepath.Join(corpus, e.PasswordFile), filepath.Join(corpus, e.File), timeout)
		if err == nil {
			err = compare(e, got, coarse)
		}
		status := "pass"
		if err != nil {
			status = "FAIL"
			failed++
		}
		line := fmt.Sprintf("%-4s %s (%s)", status, e.ID, e.Encoding)
		cell := "✅"
		if err != nil {
			line += ": " + err.Error()
			cell = "❌ " + strings.ReplaceAll(err.Error(), "|", "/")
		}
		fmt.Println(line)
		rows = append(rows, fmt.Sprintf("| %s | %s | %s |", e.ID, e.Encoding, cell))
	}
	fmt.Printf("%d of %d cases pass (profile %s)\n", total-failed, total, profile)

	if markdown != "" {
		mode := "full"
		if coarse {
			mode = "coarse"
		}
		var b strings.Builder
		fmt.Fprintf(&b, "\n### %s (profile %s, %s comparison, %d of %d)\n\n| Case | Encoding | Result |\n|---|---|---|\n", name, profile, mode, total-failed, total)
		b.WriteString(strings.Join(rows, "\n") + "\n")
		f, err := os.OpenFile(markdown, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err := f.WriteString(b.String()); err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d cases fail", failed)
	}
	return nil
}

func run(decoder []string, passwordFile, file string, timeout time.Duration) (Result, error) {
	var r Result
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	args := append(slices.Clone(decoder[1:]), "decode", "--password-file", passwordFile, file)
	//nolint:gosec // G204: running the decoder given on the command line is the purpose of verify.
	cmd := exec.CommandContext(ctx, decoder[0], args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return r, fmt.Errorf("timeout after %s", timeout)
		}
		return r, fmt.Errorf("decoder failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		return r, fmt.Errorf("decoder output is not the contract JSON: %w", err)
	}
	return r, nil
}

func compare(e Expected, got Result, coarse bool) error {
	wantOK := slices.Contains(e.Codes, "ok")
	if coarse {
		// Without result codes, any rejection matches any expected failure.
		wantFailure := slices.ContainsFunc(e.Codes, func(c string) bool { return c != "ok" })
		if (got.Code == "ok" && !wantOK) || (got.Code != "ok" && !wantFailure) {
			return fmt.Errorf("code %q, want %s", got.Code, strings.Join(e.Codes, " or "))
		}
	} else if !slices.Contains(e.Codes, got.Code) {
		return fmt.Errorf("code %q (%s), want %s", got.Code, got.Detail, strings.Join(e.Codes, " or "))
	}
	// Contents are compared when the decoder succeeded and success was
	// expected; a case may also allow a rejection (codes ok and another).
	if !wantOK || got.Code != "ok" {
		return nil
	}

	want := e.Result
	if err := matchItems("certificate", want.Certificates, got.Certificates); err != nil {
		return err
	}
	if err := matchItems("key", want.Keys, got.Keys); err != nil {
		return err
	}
	if len(got.Pairs) != len(want.Pairs) {
		return fmt.Errorf("%d pairs, want %d", len(got.Pairs), len(want.Pairs))
	}
	if !coarse && !equalMAC(got.MAC, want.MAC) {
		return fmt.Errorf("mac %s, want %s", show(got.MAC), show(want.MAC))
	}
	return nil
}

// matchItems compares as multisets: a certificate matches by its SHA-256, a
// key by the SHA-256 of its PKCS#8 or of its public key. An expected friendly
// name must be reported.
func matchItems(kind string, want, got []Item) error {
	if len(got) != len(want) {
		return fmt.Errorf("%d %ss, want %d", len(got), kind, len(want))
	}
	used := make([]bool, len(got))
	for _, w := range want {
		found := false
		for i, g := range got {
			if used[i] || !sameItem(w, g) {
				continue
			}
			if w.FriendlyName != "" && g.FriendlyName != w.FriendlyName {
				return fmt.Errorf("%s %.12s: friendly name %q, want %q", kind, w.SHA256, g.FriendlyName, w.FriendlyName)
			}
			used[i], found = true, true
			break
		}
		if !found {
			return fmt.Errorf("%s %.12s missing", kind, w.SHA256)
		}
	}
	return nil
}

func sameItem(want, got Item) bool {
	if got.SHA256 != "" && got.SHA256 == want.SHA256 {
		return true
	}
	return got.PublicKeySHA256 != "" && got.PublicKeySHA256 == want.PublicKeySHA256
}

func equalMAC(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func show(s *string) string {
	if s == nil {
		return "none"
	}
	return *s
}
