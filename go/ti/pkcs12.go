package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gematik/zero-lab/go/brainpool"
	"github.com/gematik/zero-lab/go/pkcs12"
	"github.com/gematik/zero-lab/go/pkcs12/legacy"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var p12PasswordFlag string

func newPKCS12Cmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pkcs12",
		Short: "Work with PKCS#12 files",
	}

	cmd.PersistentFlags().StringVar(&p12PasswordFlag, "password", "", "PKCS#12 password (env: PKCS12_PASSWORD)")

	cmd.AddCommand(newPKCS12InspectCmd())
	cmd.AddCommand(newPKCS12ConvertCmd())
	cmd.AddCommand(newPKCS12EncodeCmd())

	return cmd
}

func newPKCS12InspectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <file>",
		Short: "Show contents of a PKCS#12 file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runPKCS12Inspect(args[0])
		},
	}
}

func getP12Password() (string, error) {
	if p12PasswordFlag != "" {
		return p12PasswordFlag, nil
	}
	if env := os.Getenv("PKCS12_PASSWORD"); env != "" {
		return env, nil
	}
	fmt.Fprint(os.Stderr, "Password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return string(pw), nil
}

func newPKCS12ConvertCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "convert <input> <output>",
		Short: "Convert legacy BER-encoded PKCS#12 to modern DER format",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runPKCS12Convert(args[0], args[1])
		},
	}
}

func runPKCS12Convert(input, output string) error {
	data, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	if legacy.IsBER(data) {
		password, err := getP12Password()
		if err != nil {
			return err
		}
		converted, err := legacy.ConvertWithOpenSSL(data, password)
		if err != nil {
			return fmt.Errorf("converting legacy BER-encoded PKCS#12: %w", err)
		}
		data = converted
		fmt.Fprintf(os.Stderr, "Converted legacy BER format to modern DER format\n")
	} else {
		fmt.Fprintf(os.Stderr, "File is already in modern format, copying\n")
	}

	if err := os.WriteFile(output, data, 0600); err != nil {
		return fmt.Errorf("writing output file: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Written to %s\n", output)
	return nil
}

func newPKCS12EncodeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "encode <file>",
		Short: "Encode PKCS#12 file as .kon credentials JSON",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runPKCS12Encode(args[0])
		},
	}
}

func runPKCS12Encode(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	if legacy.IsBER(data) {
		password, err := getP12Password()
		if err != nil {
			return err
		}
		converted, err := legacy.ConvertWithOpenSSL(data, password)
		if err != nil {
			return fmt.Errorf("converting legacy BER-encoded PKCS#12: %w", err)
		}
		data = converted
		fmt.Fprintf(os.Stderr, "Converted legacy BER format to modern DER format\n")
	}

	cred := struct {
		Type     string `json:"type"`
		Data     string `json:"data"`
		Password string `json:"password,omitempty"`
	}{
		Type:     "pkcs12",
		Data:     base64.StdEncoding.EncodeToString(data),
		Password: p12PasswordFlag,
	}

	if cred.Password == "" {
		cred.Password = os.Getenv("PKCS12_PASSWORD")
	}

	return printJSON(cred)
}

func runPKCS12Inspect(file string) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("reading file: %w", err)
	}

	password, err := getP12Password()
	if err != nil {
		return err
	}

	if legacy.IsBER(data) {
		converted, err := legacy.ConvertWithOpenSSL(data, password)
		if err != nil {
			return fmt.Errorf("converting legacy BER-encoded PKCS#12: %w", err)
		}
		data = converted
	}

	bags, err := pkcs12.Decode(data, []byte(password))
	if err != nil {
		return fmt.Errorf("decoding PKCS#12: %w", err)
	}

	printKeyValue(func(w io.Writer) {
		fmt.Fprintf(w, "Certificates:\t%d\n", len(bags.Certificates))
		fmt.Fprintf(w, "Private Keys:\t%d\n", len(bags.PrivateKeys))
	})
	fmt.Println()

	for i, cb := range bags.Certificates {
		cert, err := brainpool.ParseCertificate(cb.Raw)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to parse certificate %d: %v\n", i, err)
			continue
		}

		fmt.Println(sectionHeader(fmt.Sprintf("--- Certificate %d ---", i+1)))
		printKeyValue(func(w io.Writer) {
			if cb.FriendlyName != "" {
				fmt.Fprintf(w, "Friendly Name\t%s\n", cb.FriendlyName)
			}
			if len(cb.LocalKeyID) > 0 {
				fmt.Fprintf(w, "Local Key ID\t%s\n", hex.EncodeToString(cb.LocalKeyID))
			}
			fmt.Fprintf(w, "Subject\t%s\n", cert.Subject)
			fmt.Fprintf(w, "Issuer\t%s\n", cert.Issuer)
			fmt.Fprintf(w, "Serial\t%s\n", cert.SerialNumber)
			fmt.Fprintf(w, "Not Before\t%s\n", cert.NotBefore.Format("2006-01-02 15:04:05"))
			fmt.Fprintf(w, "Not After\t%s\n", cert.NotAfter.Format("2006-01-02 15:04:05"))
			fmt.Fprintf(w, "Key Algorithm\t%s\n", cert.PublicKeyAlgorithm)
			if cert.PublicKey != nil {
				fmt.Fprintf(w, "Key Size\t%s\n", describePublicKey(cert.PublicKey))
			}
			if len(cert.DNSNames) > 0 {
				fmt.Fprintf(w, "DNS Names\t%s\n", strings.Join(cert.DNSNames, ", "))
			}
			fmt.Fprintf(w, "Is CA\t%v\n", cert.IsCA)
		})
		fmt.Println()
	}

	for i, kb := range bags.PrivateKeys {
		fmt.Println(sectionHeader(fmt.Sprintf("--- Private Key %d ---", i+1)))
		printKeyValue(func(w io.Writer) {
			if kb.FriendlyName != "" {
				fmt.Fprintf(w, "Friendly Name\t%s\n", kb.FriendlyName)
			}
			if len(kb.LocalKeyID) > 0 {
				fmt.Fprintf(w, "Local Key ID\t%s\n", hex.EncodeToString(kb.LocalKeyID))
			}
			fmt.Fprintf(w, "Key Info\t%s\n", describePrivateKeyBag(kb.Raw))
		})
		fmt.Println()
	}

	return nil
}

func describePublicKey(pub any) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("%d bit", k.N.BitLen())
	case *ecdsa.PublicKey:
		return describeECCurve(k.Curve)
	default:
		return fmt.Sprintf("%T", pub)
	}
}

func describePrivateKeyBag(raw []byte) string {
	// Try parsing as PKCS#8
	if key, err := brainpool.ParseECPrivateKey(raw); err == nil {
		return fmt.Sprintf("EC %s", describeECCurve(key.Curve))
	}
	return fmt.Sprintf("%d bytes", len(raw))
}

func describeECCurve(c elliptic.Curve) string {
	name := c.Params().Name
	if name != "" {
		return name
	}
	return fmt.Sprintf("%d bit EC", c.Params().BitSize)
}
