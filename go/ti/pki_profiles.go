package main

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"strings"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/spf13/cobra"
)

// profileSpec is a small static descriptor of a gempki profile factory.
// We build it by instantiating the profile against a placeholder TrustStore
// so the displayed fields are always whatever the live factory configures —
// not a hand-maintained copy that can drift.
type profileSpec struct {
	Name        string
	Short       string
	Factory     gempki.Profile
}

var availableProfiles = []profileSpec{
	{
		Name:    "smcbauth",
		Short:   "SMC-B institution authentication (C.HCI.AUT)",
		Factory: gempki.ProfileSMCBAuth,
	},
	{
		Name:    "qes",
		Short:   "Qualified electronic signature (HBA, C.HP.QES)",
		Factory: gempki.ProfileQES,
	},
	{
		Name:    "komponente",
		Short:   "TI component certificates (Fachdienst / ZETA server, C.FD.TLS-S)",
		Factory: gempki.ProfileKomponente,
	},
	{
		Name:    "idp",
		Short:   "IDP discovery / JWKS authenticity (C.FD.SIG)",
		Factory: gempki.ProfileIDPAuthenticity,
	},
}

// emptyTrustStore is the placeholder TrustStore passed to profile factories
// so we can inspect the Validator they build. Used only for introspection;
// no validation happens against it.
func emptyTrustStore() *gempki.TrustStore {
	ts, _ := gempki.NewTrustStore(nil)
	return ts
}

func newPKIProfilesCmd(def envDef) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "List or describe the gempki profiles available to cert verify/lint",
	}
	cmd.AddCommand(newPKIProfilesListCmd(def))
	cmd.AddCommand(newPKIProfilesDescribeCmd(def))
	return cmd
}

func newPKIProfilesListCmd(def envDef) *cobra.Command {
	var formatRaw string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List available cert-validation profiles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, []outputFormat{formatText, formatJSON})
			if err != nil {
				return err
			}
			return runProfilesList(f)
		},
	}
	_ = def
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json")
	return cmd
}

func runProfilesList(f outputFormat) error {
	type row struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	rows := make([]row, len(availableProfiles))
	for i, p := range availableProfiles {
		rows[i] = row{Name: p.Name, Description: p.Short}
	}
	if f == formatJSON {
		return printJSON(rows)
	}
	return printTable("NAME\tDESCRIPTION", func(w io.Writer) {
		for _, r := range rows {
			fmt.Fprintf(w, "%s\t%s\n", r.Name, r.Description)
		}
	})
}

func newPKIProfilesDescribeCmd(def envDef) *cobra.Command {
	var formatRaw string
	cmd := &cobra.Command{
		Use:   "describe NAME",
		Short: "Show the configured constraints of a profile",
		Args:  cobra.ExactArgs(1),
		ValidArgs: profileNames(),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, []outputFormat{formatText, formatJSON})
			if err != nil {
				return err
			}
			spec, ok := findProfile(args[0])
			if !ok {
				return fmt.Errorf("unknown profile %q (try `ti pki %s profiles list`)", args[0], "<env>")
			}
			return runProfilesDescribe(spec, f)
		},
	}
	_ = def
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json")
	return cmd
}

func profileNames() []string {
	out := make([]string, len(availableProfiles))
	for i, p := range availableProfiles {
		out[i] = p.Name
	}
	return out
}

func findProfile(name string) (profileSpec, bool) {
	for _, p := range availableProfiles {
		if strings.EqualFold(p.Name, name) {
			return p, true
		}
	}
	return profileSpec{}, false
}

func runProfilesDescribe(spec profileSpec, f outputFormat) error {
	v := spec.Factory(emptyTrustStore())
	detail := describeProfileValidator(spec, v)
	if f == formatJSON {
		return printJSON(detail)
	}
	return renderProfileDescribeText(detail)
}

type profileDetail struct {
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	RevocationMode      string   `json:"revocationMode"`
	RequiredKeyUsage    string   `json:"requiredKeyUsage,omitempty"`
	AllowedExtKeyUsages []string `json:"allowedExtKeyUsages,omitempty"`
	RequiredPolicies    []string `json:"requiredPolicies,omitempty"`
	RequiredRoleOIDs    []string `json:"requiredRoleOIDs,omitempty"`
}

func describeProfileValidator(spec profileSpec, v *gempki.Validator) profileDetail {
	return profileDetail{
		Name:                spec.Name,
		Description:         spec.Short,
		RevocationMode:      revocationModeString(v.Revocation.Mode),
		RequiredKeyUsage:    keyUsageString(v.RequiredKeyUsage),
		AllowedExtKeyUsages: extKeyUsageStrings(v.AllowedExtKeyUsages),
		RequiredPolicies:    asn1OIDStrings(v.RequiredPolicies),
		RequiredRoleOIDs:    asn1OIDStrings(v.RequiredRoleOIDs),
	}
}

func renderProfileDescribeText(d profileDetail) error {
	kv := newKVWriter()
	kv.Section("Profile " + d.Name)
	kv.KV("Description", d.Description)
	kv.KV("Revocation Mode", d.RevocationMode)
	if d.RequiredKeyUsage != "" {
		kv.KV("Required Key Usage", d.RequiredKeyUsage)
	}
	if len(d.AllowedExtKeyUsages) > 0 {
		kv.KV("Allowed Ext Key Usage", strings.Join(d.AllowedExtKeyUsages, ", "))
	}
	if len(d.RequiredPolicies) > 0 {
		kv.Section("Required Certificate Policies")
		for _, p := range d.RequiredPolicies {
			kv.KV("OID", p)
		}
		kv.EndSection()
	}
	if len(d.RequiredRoleOIDs) > 0 {
		kv.Section("Required Role OIDs (at least one must match)")
		for _, p := range d.RequiredRoleOIDs {
			kv.KV("OID", p)
		}
		kv.EndSection()
	}
	kv.EndSection()
	return kv.Print()
}

func revocationModeString(m gempki.RevocationMode) string {
	switch m {
	case gempki.RevocationModeHardFail:
		return "hard-fail"
	case gempki.RevocationModeSoftFail:
		return "soft-fail"
	case gempki.RevocationModeBestEffort:
		return "best-effort"
	case gempki.RevocationModeDisabled:
		return "disabled"
	}
	return fmt.Sprintf("unknown(%d)", m)
}

func keyUsageString(ku x509.KeyUsage) string {
	if ku == 0 {
		return ""
	}
	var parts []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		parts = append(parts, "digitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		parts = append(parts, "contentCommitment(nonRepudiation)")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		parts = append(parts, "keyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		parts = append(parts, "dataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		parts = append(parts, "keyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		parts = append(parts, "keyCertSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		parts = append(parts, "cRLSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		parts = append(parts, "encipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		parts = append(parts, "decipherOnly")
	}
	return strings.Join(parts, " | ")
}

func extKeyUsageStrings(ekus []x509.ExtKeyUsage) []string {
	out := make([]string, len(ekus))
	for i, e := range ekus {
		switch e {
		case x509.ExtKeyUsageAny:
			out[i] = "any"
		case x509.ExtKeyUsageServerAuth:
			out[i] = "id-kp-serverAuth"
		case x509.ExtKeyUsageClientAuth:
			out[i] = "id-kp-clientAuth"
		case x509.ExtKeyUsageCodeSigning:
			out[i] = "id-kp-codeSigning"
		case x509.ExtKeyUsageEmailProtection:
			out[i] = "id-kp-emailProtection"
		case x509.ExtKeyUsageOCSPSigning:
			out[i] = "id-kp-OCSPSigning"
		case x509.ExtKeyUsageTimeStamping:
			out[i] = "id-kp-timeStamping"
		default:
			out[i] = fmt.Sprintf("ExtKeyUsage(%d)", e)
		}
	}
	return out
}

func asn1OIDStrings(oids []asn1.ObjectIdentifier) []string {
	out := make([]string, len(oids))
	for i, o := range oids {
		out[i] = o.String()
	}
	return out
}
