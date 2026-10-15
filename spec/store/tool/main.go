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

// Command storeconformance generates the corpus of spec/store and checks implementations
// against it. See ../CONFORMANCE.md.
//
//	storeconformance generate [-manifest ../testdata/manifest.json] [-check]
//	storeconformance verify [-manifest FILE] [-timeout 60s] [-strict] [-markdown FILE -name NAME] -- ADAPTER [ARGS...]
//	storeconformance adapter
//
// The tool uses only the standard library.
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
		manifest := fs.String("manifest", "../testdata/manifest.json", "manifest to write")
		check := fs.Bool("check", false, "fail if the manifest on disk differs instead of writing it")
		_ = fs.Parse(os.Args[2:])
		err = generate(*manifest, *check)
	case "verify":
		fs := flag.NewFlagSet("verify", flag.ExitOnError)
		manifest := fs.String("manifest", "../testdata/manifest.json", "manifest of the cases")
		timeout := fs.Duration("timeout", 60*time.Second, "time limit per case")
		strict := fs.Bool("strict", false, "count cases the adapter does not support as failures")
		markdown := fs.String("markdown", "", "append a matrix column as Markdown to this file")
		name := fs.String("name", "", "implementation name for the Markdown output")
		_ = fs.Parse(os.Args[2:])
		if fs.NArg() == 0 {
			usage()
		}
		err = verify(*manifest, fs.Args(), *timeout, *strict, *markdown, *name)
	case "adapter":
		err = serve(os.Stdin, os.Stdout)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "storeconformance:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  storeconformance generate [-manifest FILE] [-check]
  storeconformance verify [-manifest FILE] [-timeout D] [-strict] [-markdown FILE -name NAME] -- ADAPTER [ARGS...]
  storeconformance adapter`)
	os.Exit(2)
}
