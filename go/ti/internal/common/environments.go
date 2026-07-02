package common

import (
	"fmt"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/spf13/cobra"
)

// EnvDef holds all per-environment configuration used across commands.
type EnvDef struct {
	Env     gempki.Environment
	TSLURL  string
	EPAAS1  string
	EPAAS2  string
	EPAAS3  string
	IDP     string
	ERezept string
}

// EnvDefs is the canonical registry of TI environments.
var EnvDefs = map[string]EnvDef{
	"dev": {
		Env:     gempki.EnvDev,
		TSLURL:  gempki.URLTrustServiceListRef,
		EPAAS1:  "https://epa-as-1.dev.epa4all.de",
		EPAAS2:  "https://epa-as-2.dev.epa4all.de",
		EPAAS3:  "https://epa-as-3.dev.epa4all.de",
		IDP:     "https://idp-ref.zentral.idp.splitdns.ti-dienste.de",
		ERezept: "https://erp-ref.zentral.erp.splitdns.ti-dienste.de",
	},
	"ref": {
		Env:     gempki.EnvRef,
		TSLURL:  gempki.URLTrustServiceListRef,
		EPAAS1:  "https://epa-as-1.ref.epa4all.de",
		EPAAS2:  "https://epa-as-2.ref.epa4all.de",
		EPAAS3:  "https://epa-as-3.ref.epa4all.de",
		IDP:     "https://idp-ref.zentral.idp.splitdns.ti-dienste.de",
		ERezept: "https://erp-ref.zentral.erp.splitdns.ti-dienste.de",
	},
	"test": {
		Env:     gempki.EnvTest,
		TSLURL:  gempki.URLTrustServiceListTest,
		EPAAS1:  "https://epa-as-1.test.epa4all.de",
		EPAAS2:  "https://epa-as-2.test.epa4all.de",
		EPAAS3:  "https://epa-as-3.test.epa4all.de",
		IDP:     "https://idp-ref.zentral.idp.splitdns.ti-dienste.de",
		ERezept: "https://erp-test.zentral.erp.splitdns.ti-dienste.de",
	},
	"prod": {
		Env:     gempki.EnvProd,
		TSLURL:  gempki.URLTrustServiceListProd,
		EPAAS1:  "https://epa-as-1.prod.epa4all.de",
		EPAAS2:  "https://epa-as-2.prod.epa4all.de",
		EPAAS3:  "https://epa-as-3.prod.epa4all.de",
		IDP:     "https://idp.zentral.idp.splitdns.ti-dienste.de",
		ERezept: "https://erp.zentral.erp.splitdns.ti-dienste.de",
	},
}

// EnvNames is the canonical display order of environments.
var EnvNames = []string{"dev", "ref", "test", "prod"}

// AddEnvSubcommands adds one subcommand per environment to parent,
// calling fn(name, def) to produce each subcommand.
func AddEnvSubcommands(parent *cobra.Command, fn func(name string, def EnvDef) *cobra.Command) {
	for _, name := range EnvNames {
		parent.AddCommand(fn(name, EnvDefs[name]))
	}
}

// ResolveEnv returns the EnvDef for a given name or an error.
func ResolveEnv(name string) (EnvDef, error) {
	def, ok := EnvDefs[name]
	if !ok {
		return EnvDef{}, fmt.Errorf("unknown environment %q (valid: dev, ref, test, prod)", name)
	}
	return def, nil
}
