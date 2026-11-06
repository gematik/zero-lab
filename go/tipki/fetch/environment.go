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

package fetch

import (
	"fmt"

	"github.com/gematik/zero-lab/go/tipki"
)

// Environment is a TI environment, by the name ti and its configuration files use.
type Environment string

const (
	// Production is the TI's production environment, under the production anchors.
	Production Environment = "prod"
	// Reference is the reference environment (RU), under the TEST-ONLY anchors.
	Reference Environment = "ref"
	// Test is the test environment (TU), under the TEST-ONLY anchors.
	Test Environment = "test"
	// Development has no material of its own and takes the reference environment's, as Rust's ti-pki does.
	Development Environment = "dev"
)

// ParseEnvironment takes only a named environment. There is no default: with TEST-ONLY anchors in every
// build, a default would be trust nobody chose.
func ParseEnvironment(name string) (Environment, error) {
	switch env := Environment(name); env {
	case Production, Reference, Test, Development:
		return env, nil
	default:
		return "", fmt.Errorf("no TI environment %q: name prod, ref, test or dev", name)
	}
}

// urls are where an environment publishes its trust material. They are fixed, as outbound fetches go only to
// allowlisted hosts (servers.md rule 2).
type urls struct {
	// roots is roots.json, and hash the list's SHA-256, both over HTTPS (A_30044).
	roots, hash string
	// list is the stem of the automated download point of gemSpec_TSL A_21182: .xml, .sig and .ocsp, over
	// plain HTTP as A_21175 mandates. The signature and the hash make it safe.
	list string
}

func urlsFor(env Environment) (urls, error) {
	switch env {
	case Production:
		return urls{
			roots: "https://download.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json",
			hash:  "https://download.tsl.ti-dienste.de/ECC/ECC-RSA_TSL.sha2",
			list:  "http://download.crl.ti-dienste.de/TSL-ECC/ECC-RSA_TSL",
		}, nil
	case Reference, Development:
		return urls{
			roots: "https://download-ref.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json",
			hash:  "https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.sha2",
			list:  "http://download-testref.crl.ti-dienste.de/TSL-ECC-ref/ECC-RSA_TSL-ref",
		}, nil
	case Test:
		return urls{
			roots: "https://download-test.tsl.ti-dienste.de/ECC/ROOT-CA/roots.json",
			hash:  "https://download-test.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-test.sha2",
			list:  "http://download-testref.crl.ti-dienste.de/TSL-ECC-test/ECC-RSA_TSL-test",
		}, nil
	default:
		_, err := ParseEnvironment(string(env))
		return urls{}, err
	}
}

// anchorsFor picks the root anchor and the TSL signer's anchors the environment trusts.
func anchorsFor(env Environment) ([]byte, [][]byte, error) {
	switch env {
	case Production:
		return tipki.AnchorProd, [][]byte{tipki.TSLSignerAnchorProd}, nil
	case Reference, Test, Development:
		return tipki.AnchorNonProd, [][]byte{tipki.TSLSignerAnchorNonProd}, nil
	default:
		_, err := ParseEnvironment(string(env))
		return nil, nil, err
	}
}
