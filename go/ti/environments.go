package main

import (
	"fmt"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/spf13/cobra"
)

// envDef holds all per-environment configuration used across commands.
type envDef struct {
	Env     gempki.Environment
	TSLURL  string
	EPAAS1  string
	EPAAS2  string
	IDP     string
	ERezept string
}

// envDefs is the canonical registry of TI environments.
var envDefs = map[string]envDef{
	"dev": {
		Env:     gempki.EnvDev,
		TSLURL:  gempki.URLTrustServiceListRef,
		EPAAS1:  "https://epa-as-1.dev.epa4all.de",
		EPAAS2:  "https://epa-as-2.dev.epa4all.de",
		IDP:     "https://idp-ref.zentral.idp.splitdns.ti-dienste.de",
		ERezept: "https://erp-ref.zentral.erp.splitdns.ti-dienste.de",
	},
	"ref": {
		Env:     gempki.EnvRef,
		TSLURL:  gempki.URLTrustServiceListRef,
		EPAAS1:  "https://epa-as-1.ref.epa4all.de",
		EPAAS2:  "https://epa-as-2.ref.epa4all.de",
		IDP:     "https://idp-ref.zentral.idp.splitdns.ti-dienste.de",
		ERezept: "https://erp-ref.zentral.erp.splitdns.ti-dienste.de",
	},
	"test": {
		Env:     gempki.EnvTest,
		TSLURL:  gempki.URLTrustServiceListTest,
		EPAAS1:  "https://epa-as-1.test.epa4all.de",
		EPAAS2:  "https://epa-as-2.test.epa4all.de",
		IDP:     "https://idp-ref.zentral.idp.splitdns.ti-dienste.de",
		ERezept: "https://erp-test.zentral.erp.splitdns.ti-dienste.de",
	},
	"prod": {
		Env:     gempki.EnvProd,
		TSLURL:  gempki.URLTrustServiceListProd,
		EPAAS1:  "https://epa-as-1.prod.epa4all.de",
		EPAAS2:  "https://epa-as-2.prod.epa4all.de",
		IDP:     "https://idp.zentral.idp.splitdns.ti-dienste.de",
		ERezept: "https://erp.zentral.erp.splitdns.ti-dienste.de",
	},
}

// envNames is the canonical display order of environments.
var envNames = []string{"dev", "ref", "test", "prod"}

// addEnvSubcommands adds one subcommand per environment to parent,
// calling fn(name, def) to produce each subcommand.
func addEnvSubcommands(parent *cobra.Command, fn func(name string, def envDef) *cobra.Command) {
	for _, name := range envNames {
		parent.AddCommand(fn(name, envDefs[name]))
	}
}

// resolveEnv returns the envDef for a given name or an error.
func resolveEnv(name string) (envDef, error) {
	def, ok := envDefs[name]
	if !ok {
		return envDef{}, fmt.Errorf("unknown environment %q (valid: dev, ref, test, prod)", name)
	}
	return def, nil
}
