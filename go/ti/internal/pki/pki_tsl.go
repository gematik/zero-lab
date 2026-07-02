package pki

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/chroma/v2/quick"
	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

func newPKITSLCmdGroup(def common.EnvDef) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tsl",
		Short: "Trust Service Status List operations",
	}
	cmd.AddCommand(newPKITSLShowCmd(def))
	cmd.AddCommand(newPKITSLFetchCmd(def))
	cmd.AddCommand(newPKITSLVerifyCmd(def))
	cmd.AddCommand(newPKITSLProvidersCmd(def))
	cmd.AddCommand(newPKITSLIntermediatesCmd(def))
	return cmd
}

// ---- show -------------------------------------------------------------------

func newPKITSLShowCmd(def common.EnvDef) *cobra.Command {
	var formatRaw string
	cmd := &cobra.Command{
		Use:   "show",
		Short: "Print a human-readable summary of the env's TSL",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, formatsTSLShow)
			if err != nil {
				return err
			}
			tsl, err := common.LoadTSLCached(cmd.Context(), common.NewHTTPClient(), def.TSLURL)
			if err != nil {
				return err
			}
			return runTSLShow(tsl, def.TSLURL, f)
		},
	}
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json")
	return cmd
}

func runTSLShow(tsl *gempki.TrustServiceStatusList, url string, f outputFormat) error {
	if f == formatJSON {
		return common.PrintJSON(tslSummaryJSON(tsl, url))
	}
	si := tsl.SchemeInformation
	kv := common.NewKVWriter()
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

func tslSummaryJSON(tsl *gempki.TrustServiceStatusList, url string) map[string]any {
	si := tsl.SchemeInformation
	providers := make([]string, len(tsl.TrustServiceProviderList))
	for i, p := range tsl.TrustServiceProviderList {
		providers[i] = shortProviderName(p.TSPInformation.TSPTradeName)
	}
	return map[string]any{
		"url":        url,
		"hash":       tsl.Hash,
		"version":    si.TSLVersionIdentifier,
		"sequence":   si.TSLSequenceNumber,
		"type":       si.TSLType,
		"operator":   tslName(si.SchemeOperatorName),
		"issued":     time.Time(si.ListIssueDateTime).Format(time.RFC3339),
		"nextUpdate": time.Time(si.NextUpdate).Format(time.RFC3339),
		"providers":  providers,
	}
}

// ---- fetch ------------------------------------------------------------------

func newPKITSLFetchCmd(def common.EnvDef) *cobra.Command {
	var formatRaw, outPath string
	var withSig bool
	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Download the raw TSL (and optionally its detached signature)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, formatsTSLFetch)
			if err != nil {
				return err
			}
			return runTSLFetch(cmd.Context(), def, f, outPath, withSig)
		},
	}
	cmd.Flags().StringVar(&formatRaw, "format", string(formatXML), "output format: xml, json, text")
	cmd.Flags().StringVar(&outPath, "out", "", "write raw bytes to this file instead of stdout")
	cmd.Flags().BoolVar(&withSig, "with-signature", false, "also fetch the .sig detached signature next to the TSL")
	return cmd
}

func runTSLFetch(ctx context.Context, def common.EnvDef, f outputFormat, outPath string, withSig bool) error {
	tsl, err := common.LoadTSLCached(ctx, common.NewHTTPClient(), def.TSLURL)
	if err != nil {
		return err
	}
	if outPath != "" {
		if err := os.WriteFile(outPath, tsl.Raw, 0o644); err != nil { //nolint:gosec // user-chosen path
			return fmt.Errorf("write TSL: %w", err)
		}
		fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(tsl.Raw), outPath)
	} else {
		if err := emitTSL(tsl, f); err != nil {
			return err
		}
	}
	if withSig {
		sigURL := gempki.TSLSignatureURL(def.TSLURL)
		sig, err := gempki.LoadTSLDetachedSignature(ctx, common.NewHTTPClient(), sigURL)
		if err != nil {
			return fmt.Errorf("fetch signature: %w", err)
		}
		if outPath != "" {
			sigOut := outPath + ".sig"
			if err := os.WriteFile(sigOut, sig.Raw, 0o644); err != nil { //nolint:gosec
				return fmt.Errorf("write signature: %w", err)
			}
			fmt.Fprintf(os.Stderr, "wrote %d bytes to %s\n", len(sig.Raw), sigOut)
		} else {
			fmt.Fprintf(os.Stderr, "fetched detached signature (%d bytes)\n", len(sig.Raw))
		}
	}
	return nil
}

func emitTSL(tsl *gempki.TrustServiceStatusList, f outputFormat) error {
	switch f {
	case formatXML:
		pretty, err := common.IndentXML(tsl.Raw)
		if err != nil {
			return err
		}
		if common.IsTerminal() {
			return quick.Highlight(os.Stdout, pretty, "xml", "terminal256", "monokai")
		}
		fmt.Print(pretty)
		return nil
	case formatJSON:
		data, err := json.MarshalIndent(tsl, "", "  ")
		if err != nil {
			return err
		}
		s := string(data) + "\n"
		if common.IsTerminal() {
			return quick.Highlight(os.Stdout, s, "json", "terminal256", "monokai")
		}
		fmt.Print(s)
		return nil
	default:
		return runTSLShow(tsl, tsl.Url, formatText)
	}
}

// ---- verify -----------------------------------------------------------------

func newPKITSLVerifyCmd(def common.EnvDef) *cobra.Command {
	var formatRaw, sigPath, atRaw string
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the TSL's detached signature against the embedded TSL-Signer-CA",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, formatsTSLVerify)
			if err != nil {
				return err
			}
			at, err := parseAtFlag(atRaw)
			if err != nil {
				return err
			}
			return runTSLVerify(cmd.Context(), def, f, sigPath, at)
		},
	}
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json")
	cmd.Flags().StringVar(&sigPath, "signature", "", "use this local .sig file (default: derive .sig URL from TSL URL)")
	cmd.Flags().StringVar(&atRaw, "at", "", "validate signer at a specific time (RFC3339; default: now)")
	return cmd
}

func runTSLVerify(ctx context.Context, def common.EnvDef, f outputFormat, sigPath string, at *time.Time) error {
	httpClient := common.NewHTTPClient()
	tsl, err := common.LoadTSLCached(ctx, httpClient, def.TSLURL)
	if err != nil {
		return fmt.Errorf("load TSL: %w", err)
	}
	var sigBytes []byte
	if sigPath != "" {
		sigBytes, err = os.ReadFile(sigPath)
		if err != nil {
			return fmt.Errorf("read --signature: %w", err)
		}
	} else {
		sig, err := gempki.LoadTSLDetachedSignature(ctx, httpClient, gempki.TSLSignatureURL(def.TSLURL))
		if err != nil {
			return fmt.Errorf("fetch .sig: %w", err)
		}
		sigBytes = sig.Raw
	}
	ts, err := gempki.EmbeddedTSLSignerLoader{Env: def.Env}.Load(ctx)
	if err != nil {
		return err
	}
	opts := gempki.ValidatePathOptions{}
	if at != nil {
		a := *at
		opts.TimeFunc = func() time.Time { return a }
	}
	parsed, err := gempki.VerifyTSLDetachedSignature(ctx, tsl.Raw, sigBytes, nil, ts, opts)
	verdict := "VALID"
	var reason string
	if err != nil {
		verdict = "INVALID"
		reason = err.Error()
	}
	result := map[string]any{
		"url":     def.TSLURL,
		"verdict": verdict,
	}
	if parsed != nil {
		result["signer"] = parsed.Signer.Subject.CommonName
	}
	if reason != "" {
		result["error"] = reason
	}
	if f == formatJSON {
		return common.PrintJSON(result)
	}
	kv := common.NewKVWriter()
	kv.Section("TSL detached-signature verification")
	kv.KV("URL", def.TSLURL)
	kv.KV("Verdict", verdict)
	if parsed != nil {
		kv.KV("Signer", parsed.Signer.Subject.CommonName)
	}
	if reason != "" {
		kv.KV("Error", reason)
	}
	kv.EndSection()
	return kv.Print()
}

// ---- providers --------------------------------------------------------------

func newPKITSLProvidersCmd(def common.EnvDef) *cobra.Command {
	var formatRaw, sti string
	cmd := &cobra.Command{
		Use:   "providers",
		Short: "List trust-service providers and their services",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, formatsTSLProviders)
			if err != nil {
				return err
			}
			tsl, err := common.LoadTSLCached(cmd.Context(), common.NewHTTPClient(), def.TSLURL)
			if err != nil {
				return err
			}
			return runTSLProviders(tsl, f, sti)
		},
	}
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json")
	cmd.Flags().StringVar(&sti, "service-type", "", "filter to a single ServiceTypeIdentifier URI")
	return cmd
}

func runTSLProviders(tsl *gempki.TrustServiceStatusList, f outputFormat, sti string) error {
	type svc struct {
		Provider    string `json:"provider"`
		ServiceName string `json:"serviceName"`
		ServiceType string `json:"serviceType"`
		Status      string `json:"status"`
		Cert        string `json:"cert"`
	}
	var rows []svc
	for i := range tsl.TrustServiceProviderList {
		p := &tsl.TrustServiceProviderList[i]
		name := shortProviderName(p.TSPInformation.TSPTradeName)
		for j := range p.TSPServices {
			info := &p.TSPServices[j].ServiceInformation
			if sti != "" && info.ServiceTypeIdentifier != sti {
				continue
			}
			cert := ""
			if c := info.ServiceDigitalIdentity.DigitalId.X509Certificate; c != nil {
				cert = c.Subject.CommonName
			}
			rows = append(rows, svc{
				Provider:    name,
				ServiceName: tslName(info.ServiceName),
				ServiceType: shortenSTI(info.ServiceTypeIdentifier),
				Status:      shortenStatus(info.ServiceStatus),
				Cert:        cert,
			})
		}
	}
	if f == formatJSON {
		return common.PrintJSON(rows)
	}
	return common.PrintTable("PROVIDER\tSERVICE\tTYPE\tSTATUS\tCERT", func(w io.Writer) {
		for _, r := range rows {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Provider, r.ServiceName, r.ServiceType, r.Status, r.Cert)
		}
	})
}

func shortenSTI(uri string) string {
	if i := strings.LastIndex(uri, "/"); i >= 0 {
		return uri[i+1:]
	}
	return uri
}

func shortenStatus(uri string) string { return shortenSTI(uri) }

// ---- intermediates ----------------------------------------------------------

func newPKITSLIntermediatesCmd(def common.EnvDef) *cobra.Command {
	var formatRaw string
	cmd := &cobra.Command{
		Use:   "intermediates",
		Short: "List CA/PKC intermediate CAs published in the TSL",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, formatsTSLIntermediates)
			if err != nil {
				return err
			}
			tsl, err := common.LoadTSLCached(cmd.Context(), common.NewHTTPClient(), def.TSLURL)
			if err != nil {
				return err
			}
			return runTSLIntermediates(tsl, f)
		},
	}
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json, pem")
	return cmd
}

func runTSLIntermediates(tsl *gempki.TrustServiceStatusList, f outputFormat) error {
	cas := gempki.IntermediateCAsFromTSL(tsl)
	switch f {
	case formatPEM:
		for _, c := range cas {
			if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: c.Cert.Raw}); err != nil {
				return err
			}
		}
		return nil
	case formatJSON:
		out := make([]map[string]any, len(cas))
		for i, c := range cas {
			out[i] = map[string]any{
				"subject": c.Cert.Subject.String(),
				"issuer":  c.Cert.Issuer.String(),
				"status":  shortenStatus(c.ServiceStatus),
			}
		}
		return common.PrintJSON(out)
	}
	return common.PrintTable("CN\tSTATUS\tNOT AFTER", func(w io.Writer) {
		for _, c := range cas {
			fmt.Fprintf(w, "%s\t%s\t%s\n",
				c.Cert.Subject.CommonName,
				shortenStatus(c.ServiceStatus),
				c.Cert.NotAfter.Format("2006-01-02"),
			)
		}
	})
}

// helper used by emitTSL fall-through, mirrors the existing runPKITSL functions
var _ x509.Certificate
