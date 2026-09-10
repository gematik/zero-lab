package pki

import (
	"strings"
	"testing"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// TestCommandTree guards the v0.21 flattening: inspect and profiles live at the
// top level because they ignore the environment, and the per-env subtrees hold
// only commands that actually read one.
func TestCommandTree(t *testing.T) {
	root := NewCmd()

	for _, path := range []string{
		"pki inspect",
		"pki verify",
		"pki profiles list",
		"pki profiles describe",
		"pki cache clear",
		"pki ref verify",
		"pki ref tsl show",
		"pki ref roots list",
		"pki prod verify",
	} {
		if _, err := find(root, path); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}

	for _, path := range []string{
		"pki ref cert",
		"pki ref cert verify",
		"pki ref ocsp",
		"pki ref ocsp check",
		"pki ref inspect",
		"pki ref profiles",
	} {
		if _, err := find(root, path); err == nil {
			t.Errorf("%s still exists; it was removed in v0.21", path)
		}
	}
}

// TestVerifyFlagsMatch keeps `ti pki verify` and `ti pki <env> verify` offering
// the same flags — they run the same validation, so a flag on one that is
// missing on the other is a bug.
func TestVerifyFlagsMatch(t *testing.T) {
	root := NewCmd()
	auto, err := find(root, "pki verify")
	if err != nil {
		t.Fatal(err)
	}
	env, err := find(root, "pki ref verify")
	if err != nil {
		t.Fatal(err)
	}
	autoFlags := flagNames(auto)
	envFlags := flagNames(env)
	if len(autoFlags) != len(envFlags) {
		t.Fatalf("flag sets differ:\n  pki verify:     %v\n  pki ref verify: %v", autoFlags, envFlags)
	}
	for i := range autoFlags {
		if autoFlags[i] != envFlags[i] {
			t.Errorf("flag %d: pki verify has %q, pki ref verify has %q", i, autoFlags[i], envFlags[i])
		}
	}
}

func TestValidateProfileName(t *testing.T) {
	valid := append([]string{""}, gempki.ProfileSelectorValues()...)
	valid = append(valid, strings.ToUpper(gempki.ProfileNames()[0]))
	for _, name := range valid {
		if err := validateProfileName(name); err != nil {
			t.Errorf("validateProfileName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range []string{"xxx", "smbauth", "epavau", "idp", "chain-only"} {
		err := validateProfileName(name)
		if err == nil {
			t.Errorf("validateProfileName(%q) = nil, want an error", name)
			continue
		}
		// The message has to list what is valid, or it just moves the guesswork.
		for _, want := range gempki.ProfileSelectorValues() {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("validateProfileName(%q) error %q does not mention %q", name, err, want)
			}
		}
	}
}

func find(root *cobra.Command, path string) (*cobra.Command, error) {
	parts := strings.Fields(path)
	cmd, _, err := root.Find(parts[1:])
	if err != nil {
		return nil, err
	}
	// Find falls back to the deepest match it did resolve, so confirm we landed
	// on the leaf we asked for rather than its parent.
	if cmd.Name() != parts[len(parts)-1] {
		return nil, errNotFound(path, cmd.Name())
	}
	return cmd, nil
}

type errNotFoundError struct{ path, got string }

func (e errNotFoundError) Error() string {
	return "command " + e.path + " not found (resolved to " + e.got + ")"
}

func errNotFound(path, got string) error { return errNotFoundError{path, got} }

func flagNames(cmd *cobra.Command) []string {
	var names []string
	cmd.Flags().VisitAll(func(f *pflag.Flag) { names = append(names, f.Name) })
	return names
}
