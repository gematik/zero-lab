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
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/gematik/zero-lab/go/brainpool"
)

// ParseCertificate parses a single DER-encoded X.509 certificate. It delegates to go/brainpool's
// parser, which falls back to the standard library for a key not on a brainpool curve. Any key type
// the two accept is returned: parsing grants no trust, and what may sign is decided in [ValidatePath].
func ParseCertificate(der []byte) (*x509.Certificate, error) {
	cert, err := brainpool.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tipki: parse certificate: %w", err)
	}
	return cert, nil
}

// ParsePEMCertificates parses one or more PEM-encoded certificates and skips other blocks, such as a
// private key. Input without a certificate gives an empty result and no error, so a caller that needs
// one checks the length.
func ParsePEMCertificates(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return certs, nil
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
}
