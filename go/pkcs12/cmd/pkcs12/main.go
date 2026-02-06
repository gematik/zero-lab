package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"syscall"

	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/legacy"
	"golang.org/x/term"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "info":
		infoCommand(os.Args[2:])
	case "create":
		createCommand(os.Args[2:])
	case "request", "http":
		requestCommand(os.Args[2:])
	case "-h", "--help", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("pkcs12 - PKCS#12 file manipulation tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  pkcs12 info <file.p12>              Display detailed information about a PKCS#12 file")
	fmt.Println("  pkcs12 create [options]             Create a new PKCS#12 file")
	fmt.Println("  pkcs12 request [options] <url>      Make HTTP request with mTLS client certificate")
	fmt.Println()
	fmt.Println("Info command options:")
	fmt.Println("  --password string                   Password (if not provided, will prompt)")
	fmt.Println()
	fmt.Println("Create command options:")
	fmt.Println("  --cert string                       Certificate file (PEM or DER), can be specified multiple times")
	fmt.Println("  --key string                        Private key file (PEM or DER, optional)")
	fmt.Println("  --output string                     Output PKCS#12 file (required)")
	fmt.Println("  --password string                   Password (if not provided, will prompt)")
	fmt.Println("  --name string                       Friendly name for first certificate/key")
	fmt.Println()
	fmt.Println("Request command options:")
	fmt.Println("  --p12 string                        PKCS#12 file with client certificate (required)")
	fmt.Println("  --password string                   Password (if not provided, will prompt)")
	fmt.Println("  --method string                     HTTP method (default: GET)")
	fmt.Println("  --header string                     HTTP header (can be specified multiple times, format: 'Name: Value')")
	fmt.Println("  --body string                       Request body")
	fmt.Println("  --cacert string                     CA certificate file to verify server certificate (PEM format)")
	fmt.Println("  --insecure                          Skip TLS certificate verification")
	fmt.Println("  --verbose                           Show detailed request/response info")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  pkcs12 info keystore.p12")
	fmt.Println("  pkcs12 create --cert cert.pem --key key.pem --output keystore.p12")
	fmt.Println("  pkcs12 create --cert cert.pem --cert ca.pem --key key.pem --output keystore.p12")
	fmt.Println("  pkcs12 create --cert cert.pem --output certs-only.p12")
	fmt.Println("  pkcs12 create --cert chain.pem --key key.pem --output keystore.p12 --password secret")
	fmt.Println("  pkcs12 request --p12 client.p12 https://example.com/api")
	fmt.Println("  pkcs12 request --p12 client.p12 --method POST --body '{\"key\":\"value\"}' https://example.com/api")
}

func infoCommand(args []string) {
	flags := flag.NewFlagSet("info", flag.ExitOnError)
	passwordFlag := flags.String("password", "", "Password for PKCS#12 file")
	flags.Parse(args)

	if flags.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: PKCS#12 file path required")
		fmt.Fprintln(os.Stderr, "Usage: pkcs12 info <file.p12>")
		os.Exit(1)
	}

	p12File := flags.Arg(0)

	// Read PKCS#12 file
	data, err := os.ReadFile(p12File)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}

	// Try to parse - automatically handle legacy BER format
	// Returns the password used (either from flag or prompted during conversion)
	pfx, usedPassword, err := parsePKCS12(data, *passwordFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing PKCS#12: %v\n", err)
		os.Exit(1)
	}

	// If password was used during conversion, remember it
	if usedPassword != "" {
		*passwordFlag = usedPassword
	}

	// Display low-level structure info
	fmt.Println("=== PKCS#12 Structure ===")
	fmt.Printf("File: %s\n", p12File)
	fmt.Printf("Size: %d bytes\n", len(data))
	fmt.Printf("Version: %d\n", pfx.Version)
	fmt.Printf("Has MAC: %v\n", pfx.MacData != nil)

	if pfx.MacData != nil {
		fmt.Printf("\n=== MAC Data ===\n")
		fmt.Printf("Algorithm: %s\n", oidToString(pfx.MacData.Mac.Algorithm.Algorithm))
		fmt.Printf("Iterations: %d\n", pfx.MacData.Iterations)
		fmt.Printf("Salt: %s\n", hex.EncodeToString(pfx.MacData.MacSalt))
		fmt.Printf("MAC Value: %s\n", hex.EncodeToString(pfx.MacData.Mac.Digest))
	}

	// Parse authenticated safe
	authSafe, err := pkcs12.ParseAuthenticatedSafe(pfx.RawAuthSafe)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing authenticated safe: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n=== Authenticated Safe ===\n")
	fmt.Printf("Content Infos: %d\n", len(authSafe.ContentInfos))

	for i, ci := range authSafe.ContentInfos {
		fmt.Printf("\nContentInfo #%d:\n", i+1)
		fmt.Printf("  Type: %s\n", oidToString(ci.ContentType))
		fmt.Printf("  Size: %d bytes\n", len(ci.Content))

		if ci.ContentType.Equal(pkcs12.OIDEncryptedData) {
			fmt.Println("  Status: Encrypted (password required to view contents)")
		}
	}

	// Get password if needed for detailed info
	var password []byte
	if *passwordFlag != "" {
		password = []byte(*passwordFlag)
	} else if pfx.MacData != nil || hasEncryptedData(authSafe) {
		fmt.Print("\nEnter password: ")
		pw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
		password = pw
	}

	// Verify MAC if present
	if pfx.MacData != nil && len(password) > 0 {
		fmt.Printf("\n=== MAC Verification ===\n")
		if err := pkcs12.VerifyMAC(pfx, password); err != nil {
			fmt.Printf("❌ MAC verification failed: %v\n", err)
		} else {
			fmt.Println("✅ MAC verified successfully")
		}
	}

	// Extract bags
	if len(password) > 0 {
		bags, err := pkcs12.ExtractBags(pfx, password)
		if err != nil {
			fmt.Fprintf(os.Stderr, "\nError extracting bags: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("\n=== Certificates (%d) ===\n", len(bags.Certificates))
		for i, certBag := range bags.Certificates {
			fmt.Printf("\nCertificate #%d:\n", i+1)
			if certBag.FriendlyName != "" {
				fmt.Printf("  FriendlyName: %s\n", certBag.FriendlyName)
			}
			if len(certBag.LocalKeyID) > 0 {
				fmt.Printf("  LocalKeyID: %s\n", hex.EncodeToString(certBag.LocalKeyID))
			}

			cert, err := x509.ParseCertificate(certBag.Raw)
			if err != nil {
				fmt.Printf("  Error parsing: %v\n", err)
				continue
			}

			fmt.Printf("  Subject: %s\n", cert.Subject)
			fmt.Printf("  Issuer: %s\n", cert.Issuer)
			fmt.Printf("  Serial: %s\n", cert.SerialNumber)
			fmt.Printf("  Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
			fmt.Printf("  Not After: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
			fmt.Printf("  Key Type: %s\n", publicKeyType(cert.PublicKey))
			if len(cert.DNSNames) > 0 {
				fmt.Printf("  DNS Names: %v\n", cert.DNSNames)
			}
		}

		fmt.Printf("\n=== Private Keys (%d) ===\n", len(bags.PrivateKeys))
		for i, keyBag := range bags.PrivateKeys {
			fmt.Printf("\nPrivate Key #%d:\n", i+1)
			if keyBag.FriendlyName != "" {
				fmt.Printf("  FriendlyName: %s\n", keyBag.FriendlyName)
			}
			if len(keyBag.LocalKeyID) > 0 {
				fmt.Printf("  LocalKeyID: %s\n", hex.EncodeToString(keyBag.LocalKeyID))
			}

			key, err := x509.ParsePKCS8PrivateKey(keyBag.Raw)
			if err != nil {
				fmt.Printf("  Error parsing: %v\n", err)
				continue
			}

			fmt.Printf("  Type: %T\n", key)
			fmt.Printf("  Size: %d bytes (DER)\n", len(keyBag.Raw))
		}

		// Show matching pairs
		pairs := bags.FindMatchingPairs()
		if len(pairs) > 0 {
			fmt.Printf("\n=== Matching Certificate/Key Pairs (%d) ===\n", len(pairs))
			for i, pair := range pairs {
				fmt.Printf("\nPair #%d:\n", i+1)
				fmt.Printf("  LocalKeyID: %s\n", hex.EncodeToString(pair.Certificate.LocalKeyID))
				cert, _ := x509.ParseCertificate(pair.Certificate.Raw)
				if cert != nil {
					fmt.Printf("  Certificate: %s\n", cert.Subject)
				}
			}
		}
	}
}

func createCommand(args []string) {
	flags := flag.NewFlagSet("create", flag.ExitOnError)
	var certFiles stringSliceFlag
	flags.Var(&certFiles, "cert", "Certificate file (PEM or DER), can be specified multiple times")
	keyFile := flags.String("key", "", "Private key file (PEM or DER, optional)")
	outputFile := flags.String("output", "", "Output PKCS#12 file")
	passwordFlag := flags.String("password", "", "Password for PKCS#12 file")
	friendlyName := flags.String("name", "", "Friendly name")
	flags.Parse(args)

	// Validate required arguments
	if len(certFiles) == 0 || *outputFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --cert and --output are required")
		fmt.Fprintln(os.Stderr, "Usage: pkcs12 create --cert <cert.pem> [--cert <cert2.pem>] [--key <key.pem>] --output <file.p12>")
		os.Exit(1)
	}

	// Read and parse certificates
	var certBags []pkcs12.CertificateBag
	localKeyID := []byte{1, 2, 3, 4}

	for i, certFile := range certFiles {
		certData, err := os.ReadFile(certFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading certificate %s: %v\n", certFile, err)
			os.Exit(1)
		}

		// Handle both single cert and PEM chain
		certs := parseCertificates(certData)
		if len(certs) == 0 {
			fmt.Fprintf(os.Stderr, "No valid certificates found in %s\n", certFile)
			os.Exit(1)
		}

		for j, certDER := range certs {
			// Validate certificate
			cert, err := x509.ParseCertificate(certDER)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing certificate from %s: %v\n", certFile, err)
				os.Exit(1)
			}

			// Only first cert gets friendly name and key ID (for key matching)
			name := ""
			keyID := []byte(nil)
			if i == 0 && j == 0 {
				name = *friendlyName
				keyID = localKeyID
			}

			certBags = append(certBags, pkcs12.CertificateBag{
				Raw:          certDER,
				FriendlyName: name,
				LocalKeyID:   keyID,
			})

			if j == 0 {
				fmt.Printf("✓ Loaded certificate: %s\n", cert.Subject)
			} else {
				fmt.Printf("  └─ Chain cert: %s\n", cert.Subject)
			}
		}
	}

	// Read private key if provided
	var keyBags []pkcs12.PrivateKeyBag
	if *keyFile != "" {
		keyData, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading private key: %v\n", err)
			os.Exit(1)
		}

		keyDER := keyData
		if block, _ := pem.Decode(keyData); block != nil {
			keyDER = block.Bytes
		}

		// Parse to validate
		key, err := x509.ParsePKCS8PrivateKey(keyDER)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing private key: %v\n", err)
			fmt.Fprintln(os.Stderr, "Note: Key must be in PKCS#8 format (use 'openssl pkcs8' to convert)")
			os.Exit(1)
		}

		keyBags = append(keyBags, pkcs12.PrivateKeyBag{
			Raw:          keyDER,
			FriendlyName: *friendlyName,
			LocalKeyID:   localKeyID,
		})

		fmt.Printf("✓ Loaded private key: %T\n", key)
	}

	// Get password
	var password []byte
	if *passwordFlag != "" {
		password = []byte(*passwordFlag)
	} else {
		fmt.Print("Enter password for new PKCS#12 file: ")
		pw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
		if len(pw) == 0 {
			fmt.Fprintln(os.Stderr, "Error: Password cannot be empty")
			os.Exit(1)
		}
		password = pw
	}

	// Create bags
	bags := &pkcs12.Bags{
		Certificates: certBags,
		PrivateKeys:  keyBags,
	}

	// Encode
	p12Data, err := pkcs12.Encode(bags, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding PKCS#12: %v\n", err)
		os.Exit(1)
	}

	// Write to file
	if err := os.WriteFile(*outputFile, p12Data, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✅ PKCS#12 file created successfully: %s\n", *outputFile)
	fmt.Printf("   Certificates: %d\n", len(certBags))
	fmt.Printf("   Private Keys: %d\n", len(keyBags))
	fmt.Printf("   Size: %d bytes\n", len(p12Data))
	fmt.Printf("   Encryption: AES-256-CBC\n")
	fmt.Printf("   MAC: SHA-256\n")
}

func hasEncryptedData(authSafe *pkcs12.AuthenticatedSafe) bool {
	for _, ci := range authSafe.ContentInfos {
		if ci.ContentType.Equal(pkcs12.OIDEncryptedData) {
			return true
		}
	}
	return false
}

func oidToString(oid []int) string {
	oidMap := map[string]string{
		"1.2.840.113549.1.7.1":       "Data",
		"1.2.840.113549.1.7.6":       "EncryptedData",
		"1.2.840.113549.1.9.22.1":    "PKCS12-SHA1",
		"2.16.840.1.101.3.4.2.1":     "SHA-256",
		"2.16.840.1.101.3.4.2.2":     "SHA-384",
		"2.16.840.1.101.3.4.2.3":     "SHA-512",
		"1.2.840.113549.2.9":         "HMAC-SHA256",
		"1.2.840.113549.2.10":        "HMAC-SHA384",
		"1.2.840.113549.2.11":        "HMAC-SHA512",
		"1.2.840.113549.1.5.13":      "PBES2",
		"1.2.840.113549.1.5.12":      "PBKDF2",
		"2.16.840.1.101.3.4.1.2":     "AES-128-CBC",
		"2.16.840.1.101.3.4.1.22":    "AES-192-CBC",
		"2.16.840.1.101.3.4.1.42":    "AES-256-CBC",
		"1.2.840.113549.1.12.10.1.3": "CertBag",
		"1.2.840.113549.1.12.10.1.2": "PKCS8ShroudedKeyBag",
		"1.2.840.113549.1.9.20":      "FriendlyName",
		"1.2.840.113549.1.9.21":      "LocalKeyID",
	}

	oidStr := ""
	for i, v := range oid {
		if i == 0 {
			oidStr = fmt.Sprintf("%d", v)
		} else {
			oidStr += fmt.Sprintf(".%d", v)
		}
	}

	if name, ok := oidMap[oidStr]; ok {
		return fmt.Sprintf("%s (%s)", name, oidStr)
	}
	return oidStr
}

func publicKeyType(pub interface{}) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", pub)
	}
}

// stringSliceFlag implements flag.Value for multiple string flags
type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return fmt.Sprintf("%v", *s)
}

func (s *stringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// parseCertificates extracts all certificates from PEM or DER data
func parseCertificates(data []byte) [][]byte {
	var certs [][]byte

	// Try PEM first
	rest := data
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			certs = append(certs, block.Bytes)
		}
		rest = remaining
	}

	// If no PEM certs found, try DER
	if len(certs) == 0 {
		if _, err := x509.ParseCertificate(data); err == nil {
			certs = append(certs, data)
		}
	}

	return certs
}

// parsePKCS12 attempts to parse PKCS#12 data, automatically handling legacy BER format.
// Returns the PFX, the password used (if prompted), and any error.
func parsePKCS12(data []byte, password string) (*pkcs12.PFX, string, error) {
	// Try normal DER parsing first
	pfx, err := pkcs12.Parse(data)
	if err == nil {
		return pfx, password, nil
	}

	// Check if error mentions BER encoding
	if !strings.Contains(err.Error(), "BER") {
		return nil, "", err
	}

	// Confirm it's actually BER format
	if !legacy.IsBER(data) {
		return nil, "", err
	}

	fmt.Fprintf(os.Stderr, "⚠️  Legacy BER-encoded PKCS#12 detected, converting to DER format...\n")

	// Get password if not already provided
	usedPassword := password
	if usedPassword == "" {
		fmt.Fprint(os.Stderr, "Enter password for legacy P12: ")
		pw, pwErr := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if pwErr != nil {
			return nil, "", fmt.Errorf("failed to read password: %w", pwErr)
		}
		usedPassword = string(pw)
	}

	// Convert using OpenSSL
	derData, err := legacy.ConvertWithOpenSSL(data, usedPassword)
	if err != nil {
		return nil, "", fmt.Errorf("legacy conversion failed: %w", err)
	}

	fmt.Fprintf(os.Stderr, "✅ Conversion successful\n\n")

	// Parse converted data
	pfx, err = pkcs12.Parse(derData)
	return pfx, usedPassword, err
}

func requestCommand(args []string) {
	flags := flag.NewFlagSet("request", flag.ExitOnError)
	p12File := flags.String("p12", "", "PKCS#12 file with client certificate")
	passwordFlag := flags.String("password", "", "Password for PKCS#12 file")
	method := flags.String("method", "GET", "HTTP method")
	body := flags.String("body", "", "Request body")
	caCert := flags.String("cacert", "", "CA certificate file (PEM format)")
	insecure := flags.Bool("insecure", false, "Skip TLS certificate verification")
	verbose := flags.Bool("verbose", false, "Show detailed request/response info")
	var headers stringSliceFlag
	flags.Var(&headers, "header", "HTTP header (format: 'Name: Value')")
	flags.Parse(args)

	if *p12File == "" || flags.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Error: --p12 and URL are required")
		fmt.Fprintln(os.Stderr, "Usage: pkcs12 request --p12 <file.p12> [options] <url>")
		os.Exit(1)
	}

	url := flags.Arg(0)

	// Read PKCS#12 file
	data, err := os.ReadFile(*p12File)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading P12 file: %v\n", err)
		os.Exit(1)
	}

	// Parse PKCS#12 (handles legacy format automatically)
	pfx, usedPassword, err := parsePKCS12(data, *passwordFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing PKCS#12: %v\n", err)
		os.Exit(1)
	}

	// Get password if not already available
	var password []byte
	if usedPassword != "" {
		password = []byte(usedPassword)
	} else if *passwordFlag != "" {
		password = []byte(*passwordFlag)
	} else {
		fmt.Print("Enter password: ")
		pw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password: %v\n", err)
			os.Exit(1)
		}
		password = pw
	}

	// Verify MAC
	if pfx.MacData != nil {
		if err := pkcs12.VerifyMAC(pfx, password); err != nil {
			fmt.Fprintf(os.Stderr, "MAC verification failed: %v\n", err)
			os.Exit(1)
		}
	}

	// Extract bags
	bags, err := pkcs12.ExtractBags(pfx, password)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error extracting bags: %v\n", err)
		os.Exit(1)
	}

	// Find a matching certificate/key pair
	pairs := bags.FindMatchingPairs()
	if len(pairs) == 0 {
		fmt.Fprintln(os.Stderr, "Error: No matching certificate/key pair found in P12 file")
		os.Exit(1)
	}

	// Use first pair
	pair := pairs[0]

	// Parse certificate
	cert, err := x509.ParseCertificate(pair.Certificate.Raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing certificate: %v\n", err)
		os.Exit(1)
	}

	// Parse private key
	privKey, err := x509.ParsePKCS8PrivateKey(pair.PrivateKey.Raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing private key: %v\n", err)
		os.Exit(1)
	}

	// Build certificate chain (client cert + any additional certs)
	var certChain [][]byte
	certChain = append(certChain, pair.Certificate.Raw)
	for _, certBag := range bags.Certificates {
		if !bytesEqual(certBag.Raw, pair.Certificate.Raw) {
			certChain = append(certChain, certBag.Raw)
		}
	}

	// Create TLS certificate
	tlsCert := tls.Certificate{
		Certificate: certChain,
		PrivateKey:  privKey,
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: *insecure,
	}

	// Load CA certificate if provided
	if *caCert != "" {
		caCertData, err := os.ReadFile(*caCert)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading CA certificate: %v\n", err)
			os.Exit(1)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCertData) {
			fmt.Fprintln(os.Stderr, "Error: Failed to parse CA certificate (must be PEM format)")
			os.Exit(1)
		}

		tlsConfig.RootCAs = caCertPool

		if *verbose {
			fmt.Printf("✓ Loaded CA certificate from %s\n", *caCert)
		}
	}

	// Create HTTP client
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	if *verbose {
		fmt.Printf("=== Client Certificate ===\n")
		fmt.Printf("Subject: %s\n", cert.Subject)
		fmt.Printf("Issuer: %s\n", cert.Issuer)
		fmt.Printf("Serial: %s\n", cert.SerialNumber)
		fmt.Printf("Not Before: %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
		fmt.Printf("Not After: %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))
		fmt.Printf("\n=== HTTP Request ===\n")
		fmt.Printf("Method: %s\n", *method)
		fmt.Printf("URL: %s\n", url)
		if len(headers) > 0 {
			fmt.Println("Headers:")
			for _, h := range headers {
				fmt.Printf("  %s\n", h)
			}
		}
		if *body != "" {
			fmt.Printf("Body: %s\n", *body)
		}
		fmt.Println()
	}

	// Create request
	var bodyReader io.Reader
	if *body != "" {
		bodyReader = strings.NewReader(*body)
	}

	req, err := http.NewRequest(*method, url, bodyReader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating request: %v\n", err)
		os.Exit(1)
	}

	// Add headers
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error making request: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading response: %v\n", err)
		os.Exit(1)
	}

	// Print response
	if *verbose {
		fmt.Printf("=== HTTP Response ===\n")
		fmt.Printf("Status: %s\n", resp.Status)
		fmt.Println("Headers:")
		for name, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("  %s: %s\n", name, value)
			}
		}
		fmt.Println()
	} else {
		fmt.Printf("Status: %s\n", resp.Status)
	}

	fmt.Println(string(respBody))

	// Exit with error code if not 2xx
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		os.Exit(1)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
