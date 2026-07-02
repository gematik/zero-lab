package common

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// EnvFlag is a string flag paired with an environment-variable fallback.
// Bundling the flag name, env key and default into one value is the whole
// point: a flag can't be registered without naming its env var, the help text
// is derived from the same fields, and resolution reads the same key — so the
// three can no longer drift apart (which is how --p12-file ended up ignoring
// TI_EPA_P12_FILE). Resolution order is flag → env → default.
type EnvFlag struct {
	Name      string
	Shorthand string
	Env       string
	Def       string
	Usage     string

	Val string
}

// Register binds the flag to cmd, appending the "(env: …, default …)" suffix to
// the usage so help text always advertises the env var.
func (f *EnvFlag) Register(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.Val, f.Name, f.Shorthand, "", f.Help())
}

func (f *EnvFlag) Help() string {
	switch {
	case f.Env != "" && f.Def != "":
		return fmt.Sprintf("%s (env: %s, default %q)", f.Usage, f.Env, f.Def)
	case f.Env != "":
		return fmt.Sprintf("%s (env: %s)", f.Usage, f.Env)
	case f.Def != "":
		return fmt.Sprintf("%s (default %q)", f.Usage, f.Def)
	default:
		return f.Usage
	}
}

// EnvValue returns the env var's value, or "" when no env key is set or it is
// empty. Useful where resolution needs a custom step between env and default
// (e.g. a sticky selection file).
func (f *EnvFlag) EnvValue() string {
	if f.Env == "" {
		return ""
	}
	return os.Getenv(f.Env)
}

// Resolve applies flag → env → default and returns the value together with a
// human-readable source label.
func (f *EnvFlag) Resolve() (string, string) {
	if f.Val != "" {
		return f.Val, "flag"
	}
	if v := f.EnvValue(); v != "" {
		return v, "env " + f.Env
	}
	return f.Def, "default"
}
