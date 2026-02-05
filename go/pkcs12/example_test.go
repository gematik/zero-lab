package pkcs12_test

import (
"crypto/x509"
"fmt"
"log"
"os"

"github.com/gematik/zero-lab/go/pkcs12"
)

// ExampleParse demonstrates basic PKCS#12 file parsing
func ExampleParse() {
// Assume we have PKCS#12 DER-encoded data
var p12Data []byte // load from file

// Parse the PFX structure
pfx, err := pkcs12.Parse(p12Data)
if err != nil {
log.Fatal(err)
}

fmt.Printf("PFX Version: %d\n", pfx.Version)
fmt.Printf("Has MAC: %v\n", pfx.MacData != nil)
}

// ExampleDecode demonstrates the simple high-level decode API
func ExampleDecode() {
// Read PKCS#12 data (from file, HTTP response, embedded data, etc.)
data, err := os.ReadFile("keystore.p12")
if err != nil {
log.Fatal(err)
}

// One-step decode
bags, err := pkcs12.Decode(data, []byte("password"))
if err != nil {
log.Fatal(err)
}

// Use certificates
for _, certBag := range bags.Certificates {
cert, _ := x509.ParseCertificate(certBag.Raw)
fmt.Println("Certificate:", cert.Subject)
}

// Use private keys
for _, keyBag := range bags.PrivateKeys {
key, _ := x509.ParsePKCS8PrivateKey(keyBag.Raw)
fmt.Printf("Key: %T\n", key)
}
}

// ExampleEncode demonstrates creating PKCS#12 data
func ExampleEncode() {
// Assume we have certificate and key DER bytes
var certDER, keyDER []byte

bags := &pkcs12.Bags{
Certificates: []pkcs12.CertificateBag{{
Raw:        certDER,
LocalKeyID: []byte{1, 2, 3, 4},
}},
PrivateKeys: []pkcs12.PrivateKeyBag{{
Raw:        keyDER,
LocalKeyID: []byte{1, 2, 3, 4},
}},
}

// Encode to bytes
p12Data, err := pkcs12.Encode(bags, []byte("password"))
if err != nil {
log.Fatal(err)
}

// Write to file
os.WriteFile("keystore.p12", p12Data, 0600)

fmt.Printf("Encoded %d bytes\n", len(p12Data))
}

// ExampleExtractBags demonstrates extracting certificates and keys with low-level API
func ExampleExtractBags() {
var p12Data []byte // load from file
password := []byte("mypassword")

// Parse the PKCS#12 file
pfx, err := pkcs12.Parse(p12Data)
if err != nil {
log.Fatal(err)
}

// Extract all certificates and keys in one call
bags, err := pkcs12.ExtractBags(pfx, password)
if err != nil {
log.Fatal(err)
}

// Access certificates with metadata
for i, certBag := range bags.Certificates {
fmt.Printf("Certificate %d:\n", i)
fmt.Printf("  FriendlyName: %s\n", certBag.FriendlyName)
fmt.Printf("  LocalKeyID: %x\n", certBag.LocalKeyID)
}

// Access private keys with metadata
for i, keyBag := range bags.PrivateKeys {
fmt.Printf("Private Key %d:\n", i)
fmt.Printf("  FriendlyName: %s\n", keyBag.FriendlyName)
fmt.Printf("  LocalKeyID: %x\n", keyBag.LocalKeyID)
}

// Find matching certificate/key pairs
pairs := bags.FindMatchingPairs()
for i, pair := range pairs {
fmt.Printf("Pair %d: cert and key with LocalKeyID %x\n", 
i, pair.Certificate.LocalKeyID)
}
}

// ExampleEncodeWithOptions demonstrates custom encoding options
func ExampleEncodeWithOptions() {
var certDER, keyDER []byte

bags := &pkcs12.Bags{
Certificates: []pkcs12.CertificateBag{{Raw: certDER}},
PrivateKeys:  []pkcs12.PrivateKeyBag{{Raw: keyDER}},
}

// Customize security parameters
opts := pkcs12.DefaultEncodeOptions()
opts.Iterations = 10000              // Higher iterations for more security
opts.MacAlgorithm = pkcs12.OIDSHA512 // Use SHA-512 for MAC

password := []byte("very-secure-password")

p12Data, err := pkcs12.EncodeWithOptions(bags, password, opts)
if err != nil {
log.Fatal(err)
}

os.WriteFile("secure-keystore.p12", p12Data, 0600)

fmt.Println("PKCS#12 file created with custom security parameters")
}
