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

// Command store-conformance is the spec/store conformance adapter of go/store: it reads
// one request per line on standard input and answers one per line (spec/store
// CONFORMANCE.md). Scenarios on the files backend run in a temporary directory each.
//
//	cd spec/store/tool
//	go run . verify -- go run ../../../go/store/cmd/store-conformance
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/gematik/zero-lab/go/store"
	"github.com/gematik/zero-lab/go/store/filestore"
	"github.com/gematik/zero-lab/go/store/internal/conformance"
)

func backends(name string) (store.Backend, func(), error) {
	if name != "files" {
		return nil, nil, nil
	}
	dir, err := os.MkdirTemp("", "store-conformance-")
	if err != nil {
		return nil, nil, err
	}
	b, err := filestore.Open(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, nil, err
	}
	return b, func() { _ = b.Close(); _ = os.RemoveAll(dir) }, nil
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	out := json.NewEncoder(os.Stdout)
	for sc.Scan() {
		var req struct {
			ID    string          `json:"id"`
			Kind  string          `json:"kind"`
			Input conformance.Obj `json:"input"`
		}
		d := json.NewDecoder(bytes.NewReader(sc.Bytes()))
		d.UseNumber()
		if err := d.Decode(&req); err != nil {
			fmt.Fprintln(os.Stderr, "store-conformance:", err)
			os.Exit(1)
		}
		resp := map[string]any{"id": req.ID}
		code, output, err := conformance.Evaluate(req.Kind, req.Input, backends)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "%s: broken case: %v\n", req.ID, err)
			resp["code"] = "unsupported"
		case code == store.CodeOK:
			resp["code"], resp["output"] = code, output
		default:
			resp["code"] = code
		}
		if err := out.Encode(resp); err != nil {
			os.Exit(1)
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "store-conformance:", err)
		os.Exit(1)
	}
}
