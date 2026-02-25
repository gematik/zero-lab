package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/gematik/zero-lab/go/gempki"
	"github.com/spf13/cobra"
)

var noCacheFlag bool

func newPKICmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pki",
		Short: "PKI and certificate trust commands",
	}
	cmd.PersistentFlags().BoolVar(&noCacheFlag, "no-cache", false, "bypass local cache and always fetch from network")
	cmd.AddCommand(newPKIClearCacheCmd())

	addEnvSubcommands(cmd, func(name string, def envDef) *cobra.Command {
		envCmd := &cobra.Command{
			Use:   name,
			Short: fmt.Sprintf("PKI commands for %s environment", name),
		}
		envCmd.AddCommand(newPKIRootsCmd(def.Env))
		envCmd.AddCommand(newPKITSLCmd(def))
		return envCmd
	})

	return cmd
}

// ----- roots -----

func newPKIRootsCmd(env gempki.Environment) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "roots",
		Short: "Load and verify root certificates from the TSL download point",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runPKIRoots(cmd.Context(), env)
		},
	}
	cmd.Flags().StringVarP(&outputFlag, "output", "o", "text", "output format: text, json")
	return cmd
}

type rootCertInfo struct {
	CommonName string    `json:"commonName"`
	Subject    string    `json:"subject"`
	Key        string    `json:"key"`
	NotBefore  time.Time `json:"notBefore"`
	NotAfter   time.Time `json:"notAfter"`
}

func runPKIRoots(ctx context.Context, env gempki.Environment) error {
	roots, err := gempki.LoadRoots(ctx, newHTTPClient(), env)
	if err != nil {
		return err
	}

	certs := make([]*x509.Certificate, 0, len(roots.ByCommonName))
	for _, c := range roots.ByCommonName {
		certs = append(certs, c)
	}
	sort.Slice(certs, func(i, j int) bool {
		return certs[i].NotAfter.Before(certs[j].NotAfter)
	})

	if outputFlag == "json" {
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

// ----- tsl -----

func newPKITSLCmd(def envDef) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tsl",
		Short: "Load and display the Trust Service Status List",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runPKITSL(cmd.Context(), def)
		},
	}
	cmd.Flags().StringVarP(&outputFlag, "output", "o", "text", "output format: text, xml, json")
	return cmd
}

func runPKITSL(ctx context.Context, def envDef) error {
	tsl, err := loadTSLCached(ctx, newHTTPClient(), def.TSLURL)
	if err != nil {
		return err
	}
	switch outputFlag {
	case "xml":
		return runPKITSLXML(tsl.Raw)
	case "json":
		return runPKITSLJSON(tsl)
	default:
		return runPKITSLText(tsl, def.TSLURL)
	}
}

func runPKITSLText(tsl *gempki.TrustServiceStatusList, url string) error {
	si := tsl.SchemeInformation
	kv := newKVWriter()
	kv.Section("Trust Service Status List")
	kv.KV("URL", url)
	kv.KV("Hash", tsl.Hash)
	kv.KV("Version", fmt.Sprintf("%d", si.TSLVersionIdentifier))
	kv.KV("Sequence", fmt.Sprintf("%d", si.TSLSequenceNumber))
	kv.KV("Type", si.TSLType)
	kv.KV("Operator", tslName(si.SchemeOperatorName))
	kv.KV("Issued", time.Time(si.ListIssueDateTime).Format("2006-01-02"))
	kv.KV("Next Update", time.Time(si.NextUpdate).Format("2006-01-02"))
	kv.KV("Providers", fmt.Sprintf("%d", len(tsl.TrustServiceProviderList)))

	for i, p := range tsl.TrustServiceProviderList {
		kv.KV(fmt.Sprintf("%d", i+1), shortProviderName(p.TSPInformation.TSPTradeName))
	}

	kv.EndSection()
	return kv.Print()
}

// tslName returns a display name from an InternationalNameList,
// preferring German then English then the first available entry.
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

func runPKITSLXML(raw []byte) error {
	pretty, err := indentXML(raw)
	if err != nil {
		return err
	}
	if isTerminal() {
		return quick.Highlight(os.Stdout, pretty, "xml", "terminal256", "monokai")
	}
	fmt.Print(pretty)
	return nil
}

func runPKITSLJSON(tsl *gempki.TrustServiceStatusList) error {
	data, err := json.MarshalIndent(tsl, "", "  ")
	if err != nil {
		return err
	}
	s := string(data) + "\n"
	if isTerminal() {
		return quick.Highlight(os.Stdout, s, "json", "terminal256", "monokai")
	}
	fmt.Print(s)
	return nil
}
