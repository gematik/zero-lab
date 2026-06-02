package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
)

type probeTarget struct {
	Label string
	URL   string
}

type probeResult struct {
	Label string
	Host  string
	Err   error
}

func newProbeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "probe",
		Short: "Check connectivity to TI services",
	}

	addEnvSubcommands(cmd, func(name string, def envDef) *cobra.Command {
		return &cobra.Command{
			Use:   name,
			Short: fmt.Sprintf("Probe %s environment", name),
			Args:  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				return runProbe(def)
			},
		}
	})

	return cmd
}

func runProbe(def envDef) error {
	targets := []probeTarget{
		{Label: "IDP", URL: def.IDP},
		{Label: "eRX", URL: def.ERezept},
		{Label: "ePA 1", URL: def.EPAAS1},
		{Label: "ePA 2", URL: def.EPAAS2},
	}

	results := make([]probeResult, len(targets))
	var wg sync.WaitGroup
	wg.Add(len(targets))

	for i, t := range targets {
		go func(idx int, target probeTarget) {
			defer wg.Done()
			u, _ := url.Parse(target.URL)
			results[idx] = probeResult{
				Label: target.Label,
				Host:  u.Host,
				Err:   probeURL(target.URL),
			}
		}(i, t)
	}

	wg.Wait()

	for _, r := range results {
		if r.Err == nil {
			fmt.Printf("%-7s \033[32m✅\033[0m %s\n", r.Label, r.Host)
		} else {
			fmt.Printf("%-7s \033[31m❌\033[0m %s  %s\n", r.Label, r.Host, shortError(r.Err))
		}
	}

	return nil
}

func probeURL(target string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}

	client := clientWithTransport(&http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func shortError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()

	switch {
	case strings.Contains(s, "context deadline exceeded") || strings.Contains(s, "Timeout"):
		return "timeout"
	case strings.Contains(s, "connection refused"):
		return "connection refused"
	case strings.Contains(s, "no such host"):
		return "DNS lookup failed"
	case strings.Contains(s, "certificate") || strings.Contains(s, "tls") || strings.Contains(s, "x509"):
		return "TLS error"
	}

	if idx := strings.LastIndex(s, ": "); idx >= 0 {
		return s[idx+2:]
	}
	return s
}
