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

package tipki

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// PROF-032: all of ti-pki's codes, not only those the corpus happens to produce.
func TestPROF032TheFindingCodesAreThoseOfTiPki(t *testing.T) {
	var corpus corpusFile
	readJSON(t, corpusDir+"corpus.json", &corpus)
	got := make([]string, 0, len(ErrorCodes()))
	for _, code := range ErrorCodes() {
		got = append(got, string(code))
	}
	if !slices.Equal(got, corpus.Tables.ErrorCodes) {
		t.Errorf("codes differ:\n got  %v\n want %v", got, corpus.Tables.ErrorCodes)
	}
}

// The compiler cannot stop Finding{"typo", ...}, because an untyped literal converts to ErrorCode.
func TestNoFindingIsMadeWithALiteralCode(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fileSet := token.NewFileSet()
	var literals []string
	note := func(expr ast.Expr) {
		if literal, ok := expr.(*ast.BasicLit); ok && literal.Kind == token.STRING {
			text, _ := strconv.Unquote(literal.Value)
			literals = append(literals, text)
		}
	}
	findingFields := func(lit *ast.CompositeLit) {
		if len(lit.Elts) == 0 {
			return
		}
		if field, ok := lit.Elts[0].(*ast.KeyValueExpr); !ok {
			note(lit.Elts[0])
		} else if name, ok := field.Key.(*ast.Ident); ok && name.Name == "Code" {
			note(field.Value)
		}
	}
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, source, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			lit, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			switch kind := lit.Type.(type) {
			case *ast.Ident:
				switch kind.Name {
				case "Finding":
					findingFields(lit)
				case "OCSPError":
					for _, element := range lit.Elts {
						if field, ok := element.(*ast.KeyValueExpr); ok {
							if name, ok := field.Key.(*ast.Ident); ok && name.Name == "Code" {
								note(field.Value)
							}
						}
					}
				}
			case *ast.ArrayType:
				if elem, ok := kind.Elt.(*ast.Ident); ok && elem.Name == "Finding" {
					for _, element := range lit.Elts {
						if inner, ok := element.(*ast.CompositeLit); ok && inner.Type == nil {
							findingFields(inner)
						}
					}
				}
			}
			return true
		})
	}
	if len(literals) != 0 {
		t.Errorf("%d findings made with a literal code: %v", len(literals), literals)
	}
}
