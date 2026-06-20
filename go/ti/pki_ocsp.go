package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/spf13/cobra"
)

func newPKIOCSPCmdGroup(def envDef) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ocsp",
		Short: "OCSP revocation queries",
	}
	cmd.AddCommand(newPKIOCSPCheckCmd(def))
	return cmd
}

func newPKIOCSPCheckCmd(def envDef) *cobra.Command {
	var formatRaw, issuerPath, responder string
	var maxAge time.Duration
	cmd := &cobra.Command{
		Use:   "check FILE|-",
		Short: "Query OCSP for a certificate's revocation status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, formatsOCSPCheck)
			if err != nil {
				return err
			}
			certs, err := loadCertChain(args[0])
			if err != nil {
				return err
			}
			if len(certs) == 0 {
				return fmt.Errorf("no certificate parsed from input")
			}
			return runOCSPCheck(cmd.Context(), def, certs[0], f, issuerPath, responder, maxAge)
		},
	}
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json")
	cmd.Flags().StringVar(&issuerPath, "issuer", "", "issuer certificate PEM/DER (default: auto from env trust + TSL intermediates)")
	cmd.Flags().StringVar(&responder, "responder", "", "OCSP responder URL (default: cert's AIA)")
	cmd.Flags().DurationVar(&maxAge, "max-age", 48*time.Hour, "reject responses older than this")
	return cmd
}

func runOCSPCheck(ctx context.Context, def envDef, cert *x509.Certificate, f outputFormat, issuerPath, responder string, maxAge time.Duration) error {
	httpClient := newHTTPClient()
	issuer, err := resolveIssuer(ctx, def, cert, issuerPath)
	if err != nil {
		return err
	}
	// Per gemSpec_PKI the TSL publishes OCSP responder certs (TSPServices
	// with ServiceType Certstatus/OCSP). Feed those + the CA/PKC
	// intermediates + env roots so the checker can authorize a delegated
	// responder via the TSL-match path.
	roots, _ := gempki.NetworkLoader{Env: def.Env, HTTPClient: httpClient}.Load(ctx)
	var (
		tslResponders []*x509.Certificate
		intermediates []*x509.Certificate
	)
	if tsl, terr := loadTSLCached(ctx, httpClient, def.TSLURL); terr == nil {
		for _, c := range gempki.OCSPRespondersFromTSL(tsl) {
			if c.Cert != nil {
				tslResponders = append(tslResponders, c.Cert)
			}
		}
		for _, c := range gempki.IntermediateCAsFromTSL(tsl) {
			if c.Cert != nil {
				intermediates = append(intermediates, c.Cert)
			}
		}
	}
	checker := &gempki.OCSPChecker{
		HTTPClient:     httpClient,
		ResponderURL:   responder,
		MaxResponseAge: maxAge,
		TSLResponders:  tslResponders,
		Intermediates:  intermediates,
		Roots:          roots,
	}
	result, err := checker.Check(ctx, cert, issuer)
	if err != nil {
		return fmt.Errorf("OCSP check: %w", err)
	}
	out := map[string]any{
		"subject":   cert.Subject.CommonName,
		"issuer":    issuer.Subject.CommonName,
		"status":    string(result.Status),
		"source":    string(result.Source),
		"checkedAt": result.CheckedAt.Format(time.RFC3339),
	}
	if !result.RevokedAt.IsZero() {
		out["revokedAt"] = result.RevokedAt.Format(time.RFC3339)
	}
	if result.Reason != "" {
		out["reason"] = result.Reason
	}
	if f == formatJSON {
		return printJSON(out)
	}
	kv := newKVWriter()
	kv.Section("OCSP")
	kv.KV("Subject", cert.Subject.CommonName)
	kv.KV("Issuer", issuer.Subject.CommonName)
	kv.KV("Status", string(result.Status))
	kv.KV("Source", string(result.Source))
	kv.KV("Checked At", result.CheckedAt.Format(time.RFC3339))
	if !result.RevokedAt.IsZero() {
		kv.KV("Revoked At", result.RevokedAt.Format(time.RFC3339))
	}
	if result.Reason != "" {
		kv.KV("Reason", result.Reason)
	}
	kv.EndSection()
	return kv.Print()
}

func resolveIssuer(ctx context.Context, def envDef, cert *x509.Certificate, issuerPath string) (*x509.Certificate, error) {
	if issuerPath != "" {
		issuers, err := loadCertChain(issuerPath)
		if err != nil {
			return nil, fmt.Errorf("load --issuer: %w", err)
		}
		if len(issuers) == 0 {
			return nil, fmt.Errorf("--issuer file has no certificates")
		}
		return issuers[0], nil
	}
	httpClient := newHTTPClient()
	ts, err := gempki.NetworkLoader{Env: def.Env, HTTPClient: httpClient}.Load(ctx)
	if err != nil {
		return nil, fmt.Errorf("load roots: %w", err)
	}
	tsl, err := loadTSLCached(ctx, httpClient, def.TSLURL)
	if err != nil {
		return nil, fmt.Errorf("load TSL: %w", err)
	}
	intermediates := make([]*x509.Certificate, 0, 32)
	for _, c := range gempki.IntermediateCAsFromTSL(tsl) {
		intermediates = append(intermediates, c.Cert)
	}
	chain, err := gempki.BuildChain(cert, intermediates, ts, gempki.BuildChainOptions{})
	if err != nil {
		return nil, fmt.Errorf("resolve issuer (chain build): %w", err)
	}
	if len(chain) < 2 {
		return nil, fmt.Errorf("chain too short to identify an issuer")
	}
	return chain[1], nil
}
