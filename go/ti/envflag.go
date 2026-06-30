package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// envFlag is a string flag paired with an environment-variable fallback.
// Bundling the flag name, env key and default into one value is the whole
// point: a flag can't be registered without naming its env var, the help text
// is derived from the same fields, and resolution reads the same key — so the
// three can no longer drift apart (which is how --p12-file ended up ignoring
// TI_EPA_P12_FILE). Resolution order is flag → env → default.
type envFlag struct {
	name      string
	shorthand string
	env       string
	def       string
	usage     string

	val string
}

// register binds the flag to cmd, appending the "(env: …, default …)" suffix to
// the usage so help text always advertises the env var.
func (f *envFlag) register(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.val, f.name, f.shorthand, "", f.help())
}

func (f *envFlag) help() string {
	switch {
	case f.env != "" && f.def != "":
		return fmt.Sprintf("%s (env: %s, default %q)", f.usage, f.env, f.def)
	case f.env != "":
		return fmt.Sprintf("%s (env: %s)", f.usage, f.env)
	case f.def != "":
		return fmt.Sprintf("%s (default %q)", f.usage, f.def)
	default:
		return f.usage
	}
}

// envValue returns the env var's value, or "" when no env key is set or it is
// empty. Useful where resolution needs a custom step between env and default
// (e.g. a sticky selection file).
func (f *envFlag) envValue() string {
	if f.env == "" {
		return ""
	}
	return os.Getenv(f.env)
}

// resolve applies flag → env → default and returns the value together with a
// human-readable source label.
func (f *envFlag) resolve() (string, string) {
	if f.val != "" {
		return f.val, "flag"
	}
	if v := f.envValue(); v != "" {
		return v, "env " + f.env
	}
	return f.def, "default"
}
