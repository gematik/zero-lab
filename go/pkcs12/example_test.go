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

package pkcs12_test

import (
	"crypto/x509"
	"fmt"
	"log"

	"github.com/gematik/zero-lab/go/pkcs12"
)

func ExampleEncode() {
	certDER, keyDER := exampleIdentity()
	bags := &pkcs12.Bags{
		Certificates: []pkcs12.CertificateBag{{Raw: certDER, FriendlyName: "client", LocalKeyID: []byte{1}}},
		PrivateKeys:  []pkcs12.PrivateKeyBag{{Raw: keyDER, FriendlyName: "client", LocalKeyID: []byte{1}}},
	}
	data, err := pkcs12.Encode(bags, []byte("password"))
	if err != nil {
		log.Fatal(err)
	}
	pfx, err := pkcs12.Parse(data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("version:", pfx.Version, "MAC:", pfx.MacData.Mac.Algorithm.Algorithm.Equal(pkcs12.OIDSHA256))
	// Output: version: 3 MAC: true
}

func ExampleDecode() {
	data := exampleFile()

	bags, err := pkcs12.Decode(data, []byte("password"))
	if err != nil {
		log.Fatal(err)
	}
	for _, pair := range bags.FindMatchingPairs() {
		cert, err := x509.ParseCertificate(pair.Certificate.Raw)
		if err != nil {
			log.Fatal(err)
		}
		key, err := x509.ParsePKCS8PrivateKey(pair.PrivateKey.Raw)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%s: %s with %T\n", pair.Certificate.FriendlyName, cert.Subject.CommonName, key)
	}
	// Output: client: pkcs12 test ec TEST-ONLY with *ecdsa.PrivateKey
}

func ExampleEncodeWithOptions() {
	certDER, keyDER := exampleIdentity()
	bags := &pkcs12.Bags{
		Certificates: []pkcs12.CertificateBag{{Raw: certDER}},
		PrivateKeys:  []pkcs12.PrivateKeyBag{{Raw: keyDER}},
	}
	opts := pkcs12.DefaultEncodeOptions()
	opts.Iterations = 100_000
	opts.MacAlgorithm = pkcs12.OIDSHA512

	data, err := pkcs12.EncodeWithOptions(bags, []byte("password"), opts)
	if err != nil {
		log.Fatal(err)
	}
	pfx, err := pkcs12.Parse(data)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("MAC iterations:", pfx.MacData.Iterations)
	// Output: MAC iterations: 100000
}

func ExampleExtractBags() {
	data := exampleFile()

	pfx, err := pkcs12.Parse(data)
	if err != nil {
		log.Fatal(err)
	}
	if pfx.MacData == nil {
		log.Fatal("file has no integrity protection")
	}
	bags, err := pkcs12.ExtractBags(pfx, []byte("password"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(bags.Certificates), "certificate,", len(bags.PrivateKeys), "key")
	// Output: 1 certificate, 1 key
}

func exampleFile() []byte {
	certDER, keyDER := exampleIdentity()
	data, err := pkcs12.Encode(&pkcs12.Bags{
		Certificates: []pkcs12.CertificateBag{{Raw: certDER, FriendlyName: "client", LocalKeyID: []byte{1}}},
		PrivateKeys:  []pkcs12.PrivateKeyBag{{Raw: keyDER, FriendlyName: "client", LocalKeyID: []byte{1}}},
	}, []byte("password"))
	if err != nil {
		log.Fatal(err)
	}
	return data
}

func exampleIdentity() (certDER, keyDER []byte) {
	certDER, keyDER, err := newIdentity("ec")
	if err != nil {
		log.Fatal(err)
	}
	return certDER, keyDER
}
