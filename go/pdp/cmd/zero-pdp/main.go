// Copyright (Change Date see Readme), gematik GmbH
//
// Licensed under the EUPL, Version 1.2 or - as soon they will be approved by the
// European Commission – subsequent versions of the EUPL (the "Licence").
// You may not use this work except in compliance with the Licence.
//
// You find a copy of the Licence in the "Licence" file or at
// https://joinup.ec.europa.eu/collection/eupl/eupl-text-eupl-12
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the Licence is distributed on an "AS IS" basis,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either expressed or implied.
// In case of changes by gematik find details in the "Readme" file.
//
// See the Licence for the specific language governing permissions and limitations under the Licence.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

// Command zero-pdp runs the Zero Trust Policy Decision Point.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

const usage = `zero-pdp: Zero Trust Policy Decision Point

Usage: zero-pdp [flags] <command> [flags]

Commands:
  start                 start the PDP
  version               print the version
  jose generate-jwk     generate a JWK
  jose generate-jwks N  generate a JWK Set of N keys
  jose public-jwk       read a JWK from stdin, print the public JWK
  jose public-jwks      read a JWK or JWK Set from stdin, print the public JWK Set
  non-prod issue        issue an access token, bypassing client authentication

Flags, also accepted after the command:
  -f, --config-file  config file, or PDP_CONFIG_FILE (default pdp.yaml)
  -w, --workdir      working directory, or PDP_WORKDIR
  -v, --verbose      debug logging, or PDP_VERBOSE
`

// options are the flags every command takes.
type options struct {
	configFile string
	workdir    string
	verbose    bool
}

func (o *options) register(flags *flag.FlagSet) {
	flags.StringVar(&o.configFile, "config-file", o.configFile, "config file")
	flags.StringVar(&o.configFile, "f", o.configFile, "config file")
	flags.StringVar(&o.workdir, "workdir", o.workdir, "working directory")
	flags.StringVar(&o.workdir, "w", o.workdir, "working directory")
	flags.BoolVar(&o.verbose, "verbose", o.verbose, "debug logging")
	flags.BoolVar(&o.verbose, "v", o.verbose, "debug logging")
}

func newFlags(name string, opts *options) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	opts.register(flags)
	return flags
}

// prepare applies what the options ask for, once all flags have been read.
func (o *options) prepare() error {
	if o.workdir != "" {
		if err := os.Chdir(o.workdir); err != nil {
			return fmt.Errorf("change working directory: %w", err)
		}
	}
	level := slog.LevelInfo
	if o.verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(os.Stderr, err)
		}
		os.Exit(1)
	}
}

func run(args []string) error {
	opts := &options{
		configFile: envOr("PDP_CONFIG_FILE", "pdp.yaml"),
		workdir:    os.Getenv("PDP_WORKDIR"),
		verbose:    os.Getenv("PDP_VERBOSE") == "true",
	}
	flags := newFlags("zero-pdp", opts)
	if err := flags.Parse(args); err != nil {
		return err
	}
	args = flags.Args()
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return nil
	}
	command, args := args[0], args[1:]
	switch command {
	case "start":
		return runStart(opts, args)
	case "version":
		return runVersion(opts, args)
	case "jose":
		return runJose(opts, args)
	case "non-prod":
		return runNonProd(opts, args)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

// repeated collects a flag given several times.
type repeated []string

func (r *repeated) String() string { return strings.Join(*r, ",") }

func (r *repeated) Set(value string) error {
	*r = append(*r, value)
	return nil
}
