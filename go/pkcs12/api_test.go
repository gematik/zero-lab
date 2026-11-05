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

package pkcs12

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// exportedNames lists what the non-test files of dir export at package level, methods as Type.Method.
func exportedNames(t *testing.T, dir string) []string {
	t.Helper()
	sources, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	fileSet := token.NewFileSet()
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, source, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if !decl.Name.IsExported() {
					continue
				}
				if decl.Recv == nil {
					names = append(names, decl.Name.Name)
					continue
				}
				receiver := decl.Recv.List[0].Type
				if star, ok := receiver.(*ast.StarExpr); ok {
					receiver = star.X
				}
				names = append(names, receiver.(*ast.Ident).Name+"."+decl.Name.Name)
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if spec.Name.IsExported() {
							names = append(names, spec.Name.Name)
						}
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							if name.IsExported() {
								names = append(names, name.Name)
							}
						}
					}
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

// A name in this list is a promise for as long as the major version lasts, so adding one is a decision.
func TestThePublicAPIIsTheDocumentedOne(t *testing.T) {
	for dir, want := range map[string][]string{
		".": {
			"Bags", "Bags.FindCertificate", "Bags.FindMatchingPairs", "Bags.FindPrivateKey", "CertKeyPair", "CertificateBag",
			"ContentInfo", "Decode", "DefaultEncodeOptions", "DigestInfo", "Encode", "EncodeOptions", "EncodeWithOptions",
			"ErrAuthentication", "ErrDecryption", "ErrInvalidPFX", "ErrInvalidPadding", "ErrLimitExceeded",
			"ErrParse", "ErrUnsupportedAlgorithm", "ExtractBags", "MacData", "OIDAes128CBC", "OIDAes192CBC", "OIDAes256CBC",
			"OIDSHA256", "OIDSHA384", "OIDSHA512", "PFX", "Parse", "PrivateKeyBag", "VerifyMAC",
		},
		"legacy": {"Decode", "Parse"},
	} {
		got := exportedNames(t, dir)
		if !slices.Equal(got, want) {
			t.Errorf("%s exports:\n got  %v\n want %v", dir, got, want)
		}
	}
	for _, removed := range []string{"legacy/ber", "legacy/rc2", "ber", "rc2"} {
		if sources, _ := filepath.Glob(filepath.Join(removed, "*.go")); len(sources) != 0 {
			t.Errorf("%s is a public package", removed)
		}
	}
}
