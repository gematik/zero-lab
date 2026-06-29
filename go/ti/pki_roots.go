package main

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/spf13/cobra"
)

func newPKIRootsCmdGroup(def envDef) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "roots",
		Short: "Trust anchor (root CA) operations for the env",
	}
	cmd.AddCommand(newPKIRootsListCmd(def))
	cmd.AddCommand(newPKIRootsBundleCmd(def))
	return cmd
}

// ---- list -------------------------------------------------------------------

func newPKIRootsListCmd(def envDef) *cobra.Command {
	var formatRaw string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the TI roots (anchor + verified rollover successors)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, formatsRootsList)
			if err != nil {
				return err
			}
			return runRootsList(cmd.Context(), def, f)
		},
	}
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json")
	return cmd
}

func runRootsList(ctx context.Context, def envDef, f outputFormat) error {
	loader := gempki.NetworkLoader{Env: def.Env, HTTPClient: newHTTPClient()}
	ts, err := loader.Load(ctx)
	if err != nil {
		return err
	}
	certs := ts.Roots()
	sort.Slice(certs, func(i, j int) bool { return certs[i].NotAfter.Before(certs[j].NotAfter) })

	if f == formatJSON {
		infos := make([]rootCertInfo, len(certs))
		for i, c := range certs {
			infos[i] = rootCertInfo{
				CommonName: c.Subject.CommonName,
				Subject:    c.Subject.String(),
				Key:        describePublicKey(c.PublicKey),
				NotBefore:  c.NotBefore,
				NotAfter:   c.NotAfter,
			}
		}
		return printJSON(infos)
	}
	return printTable("CN\tKEY\tNOT BEFORE\tNOT AFTER", func(w io.Writer) {
		for _, c := range certs {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				c.Subject.CommonName,
				describePublicKey(c.PublicKey),
				c.NotBefore.Format("2006-01-02"),
				c.NotAfter.Format("2006-01-02"),
			)
		}
	})
}

// rootCertInfo type lives in pki.go after rewrite; declared there.
// (The legacy declaration is removed by the pki.go rewrite step.)

// ---- bundle -----------------------------------------------------------------

func newPKIRootsBundleCmd(def envDef) *cobra.Command {
	var formatRaw string
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "Emit the env's trust anchors as a concatenated PEM (or JSON)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, formatsRootsBundle)
			if err != nil {
				return err
			}
			return runRootsBundle(cmd.Context(), def, f)
		},
	}
	cmd.Flags().StringVar(&formatRaw, "format", string(formatPEM), "output format: pem, json")
	return cmd
}

func runRootsBundle(ctx context.Context, def envDef, f outputFormat) error {
	loader := gempki.NetworkLoader{Env: def.Env, HTTPClient: newHTTPClient()}
	ts, err := loader.Load(ctx)
	if err != nil {
		return err
	}
	certs := ts.Roots()
	if f == formatJSON {
		out := make([]map[string]any, len(certs))
		for i, c := range certs {
			out[i] = map[string]any{
				"commonName": c.Subject.CommonName,
				"notBefore":  c.NotBefore.Format(time.RFC3339),
				"notAfter":   c.NotAfter.Format(time.RFC3339),
				"key":        describePublicKey(c.PublicKey),
				"pem":        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
			}
		}
		return printJSON(out)
	}
	for _, c := range certs {
		if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return err
		}
	}
	return nil
}
