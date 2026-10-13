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

// Command p12conformance generates the PKCS#12 conformance corpus of
// spec/pkcs12 and checks decoders against it. See ../CONFORMANCE.md.
//
//	p12conformance generate -manifest ../testdata/manifest.json -out DIR
//	p12conformance verify -corpus DIR [-profile legacy|modern] [-coarse] [-timeout 30s] -- DECODER [ARGS...]
//
// The tool uses only the standard library and the openssl command.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "generate":
		fs := flag.NewFlagSet("generate", flag.ExitOnError)
		manifest := fs.String("manifest", "../testdata/manifest.json", "manifest of the cases")
		out := fs.String("out", "", "output directory (created)")
		openssl := fs.String("openssl", "openssl", "openssl command")
		_ = fs.Parse(os.Args[2:])
		if *out == "" {
			usage()
		}
		err = generate(*manifest, *out, *openssl)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		corpus := fs.String("corpus", "", "directory written by generate")
		profile := fs.String("profile", "legacy", "legacy checks every case, modern skips the cases of profile legacy")
		coarse := fs.Bool("coarse", false, "compare only ok versus error, for decoders without result codes")
		timeout := fs.Duration("timeout", 30*time.Second, "time limit per case")
		markdown := fs.String("markdown", "", "append a matrix column as Markdown to this file")
		name := fs.String("name", "", "decoder name for the Markdown output")
		_ = fs.Parse(os.Args[2:])
		if *corpus == "" || fs.NArg() == 0 {
			usage()
		}
		if *profile != "legacy" && *profile != "modern" {
			usage()
		}
		err = verify(*corpus, fs.Args(), *profile, *coarse, *timeout, *markdown, *name)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "p12conformance:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  p12conformance generate -manifest FILE -out DIR [-openssl CMD]
  p12conformance verify -corpus DIR [-profile legacy|modern] [-coarse] [-timeout D] [-markdown FILE -name NAME] -- DECODER [ARGS...]`)
	os.Exit(2)
}
