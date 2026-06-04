package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/spf13/cobra"
)

// noCacheFlag is the `--no-cache` persistent flag at `ti pki` level.
var noCacheFlag bool

func newPKICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pki",
		Short: "PKI and certificate trust commands",
	}
	cmd.PersistentFlags().BoolVar(&noCacheFlag, "no-cache", false, "bypass local cache and always fetch from network")
	cmd.AddCommand(newPKICacheCmd())

	addEnvSubcommands(cmd, func(name string, def envDef) *cobra.Command {
		envCmd := &cobra.Command{
			Use:   name,
			Short: fmt.Sprintf("PKI commands for %s environment", name),
		}
		envCmd.AddCommand(newPKICertCmd(def))
		envCmd.AddCommand(newPKITSLCmdGroup(def))
		envCmd.AddCommand(newPKIRootsCmdGroup(def))
		envCmd.AddCommand(newPKIOCSPCmdGroup(def))
		envCmd.AddCommand(newPKIProfilesCmd(def))
		return envCmd
	})

	return cmd
}

// ---- shared types + small helpers used across the per-noun files ----------

// rootCertInfo is the per-root row shape for `roots list --format json`.
type rootCertInfo struct {
	CommonName string    `json:"commonName"`
	Subject    string    `json:"subject"`
	Key        string    `json:"key"`
	NotBefore  time.Time `json:"notBefore"`
	NotAfter   time.Time `json:"notAfter"`
}

// tslName returns a display name from an InternationalNameList, preferring
// German then English then the first available entry.
func tslName(names gempki.InternationalNameList) string {
	var fallback string
	for _, n := range names {
		if fallback == "" {
			fallback = n.Value
		}
		switch n.Lang {
		case "de", "en":
			return n.Value
		}
	}
	return fallback
}

// shortProviderName strips trailing legal-form suffixes (GmbH, AG, SE, …).
func shortProviderName(names gempki.InternationalNameList) string {
	name := tslName(names)
	for _, suffix := range []string{" GmbH", " AG", " SE", " KGaA", " e.V.", " Ltd.", " Inc.", " Corp.", " mbH"} {
		if s, ok := strings.CutSuffix(name, suffix); ok {
			return s
		}
	}
	return name
}

// indentXML lives in get.go.
