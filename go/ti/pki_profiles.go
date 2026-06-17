package main

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/spf13/cobra"
)

// profileShort returns a short description for a profile, used in the
// list view. Sourced from a small lookup so the list stays one-line
// friendly without dragging gempki package docs into the CLI.
func profileShort(name string) string {
	switch name {
	case "smbauth":
		return "SMC-B-family institution authentication (C.HCI.AUT; SMB = SMC-B / HSM-B / SMC-B-ORG umbrella)"
	case "epavau":
		return "ePA Aktensystem VAU backend authenticity (C.FD.AUT)"
	case "idp":
		return "IDP discovery / JWKS / authenticity (C.FD.SIG, C.FD.AUT)"
	default:
		return ""
	}
}

func sortedProfileNames() []string {
	names := make([]string, 0, len(gempki.ProfileRegistry))
	for n := range gempki.ProfileRegistry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
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
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		RevocationMode string   `json:"revocationMode"`
		AcceptsTypes   []string `json:"acceptsTypes"`
		DefaultFor     []string `json:"defaultFor,omitempty"`
	}
	var rows []row
	for _, name := range sortedProfileNames() {
		p := gempki.ProfileRegistry[name]
		rows = append(rows, row{
			Name:           p.Name,
			Description:    profileShort(p.Name),
			RevocationMode: revocationModeString(p.RevocationMode),
			AcceptsTypes:   certTypeNames(p.AcceptsTypes),
			DefaultFor:     certTypeNames(p.DefaultFor),
		})
	}
	if f == formatJSON {
		return printJSON(rows)
	}
	return printTable("NAME\tREVOCATION\tACCEPTS\tDEFAULT FOR\tDESCRIPTION", func(w io.Writer) {
		for _, r := range rows {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				r.Name,
				r.RevocationMode,
				strings.Join(r.AcceptsTypes, ", "),
				strings.Join(r.DefaultFor, ", "),
				r.Description,
			)
		}
	})
}

func certTypeNames(ts []gempki.CertificateType) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = string(t)
	}
	return out
}

func newPKIProfilesDescribeCmd(def envDef) *cobra.Command {
	var formatRaw string
	cmd := &cobra.Command{
		Use:       "describe NAME",
		Short:     "Show the configured constraints of a profile",
		Args:      cobra.ExactArgs(1),
		ValidArgs: sortedProfileNames(),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, []outputFormat{formatText, formatJSON})
			if err != nil {
				return err
			}
			p, ok := gempki.ProfileRegistry[strings.ToLower(args[0])]
			if !ok {
				return fmt.Errorf("unknown profile %q (try `ti pki <env> profiles list`)", args[0])
			}
			return runProfilesDescribe(p, f)
		},
	}
	_ = def
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json")
	return cmd
}

func runProfilesDescribe(p *gempki.Profile, f outputFormat) error {
	detail := describeProfile(p)
	if f == formatJSON {
		return printJSON(detail)
	}
	return renderProfileDescribeText(detail)
}

type perTypeDetail struct {
	Type                string   `json:"type"`
	RequiredKeyUsage    string   `json:"requiredKeyUsage,omitempty"`
	AllowedExtKeyUsages []string `json:"allowedExtKeyUsages,omitempty"`
	RequiredPolicies    []string `json:"requiredPolicies,omitempty"`
	RequiredRoleOIDs    []string `json:"requiredRoleOIDs,omitempty"`
}

type profileDetail struct {
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	RevocationMode string          `json:"revocationMode"`
	ExtraPolicies  []string        `json:"extraPolicies,omitempty"`
	AcceptsTypes   []string        `json:"acceptsTypes"`
	DefaultFor     []string        `json:"defaultFor,omitempty"`
	PerType        []perTypeDetail `json:"perType,omitempty"`
}

func describeProfile(p *gempki.Profile) profileDetail {
	d := profileDetail{
		Name:           p.Name,
		Description:    profileShort(p.Name),
		RevocationMode: revocationModeString(p.RevocationMode),
		ExtraPolicies:  asn1OIDStrings(p.ExtraPolicies),
		AcceptsTypes:   certTypeNames(p.AcceptsTypes),
		DefaultFor:     certTypeNames(p.DefaultFor),
	}
	for _, t := range p.AcceptsTypes {
		spec := t.Spec()
		d.PerType = append(d.PerType, perTypeDetail{
			Type:                string(t),
			RequiredKeyUsage:    keyUsageString(spec.KeyUsage),
			AllowedExtKeyUsages: extKeyUsageStrings(spec.EKU),
			RequiredPolicies:    asn1OIDStrings(spec.Policies),
			RequiredRoleOIDs:    asn1OIDStrings(spec.RoleOIDs),
		})
	}
	return d
}

func renderProfileDescribeText(d profileDetail) error {
	kv := newKVWriter()
	kv.Section("Profile " + d.Name)
	if d.Description != "" {
		kv.KV("Description", d.Description)
	}
	kv.KV("Revocation Mode", d.RevocationMode)
	kv.KV("Accepts Types", strings.Join(d.AcceptsTypes, ", "))
	if len(d.DefaultFor) > 0 {
		kv.KV("Default For", strings.Join(d.DefaultFor, ", "))
	}
	if len(d.ExtraPolicies) > 0 {
		kv.Section("Extra Policies (added on top of type baseline)")
		for _, p := range d.ExtraPolicies {
			kv.KV("OID", p)
		}
		kv.EndSection()
	}
	for _, pt := range d.PerType {
		kv.Section("Type " + pt.Type)
		if pt.RequiredKeyUsage != "" {
			kv.KV("Required Key Usage", pt.RequiredKeyUsage)
		}
		if len(pt.AllowedExtKeyUsages) > 0 {
			kv.KV("Allowed Ext Key Usage", strings.Join(pt.AllowedExtKeyUsages, ", "))
		}
		if len(pt.RequiredPolicies) > 0 {
			kv.Section("Required Certificate Policies")
			for _, p := range pt.RequiredPolicies {
				kv.KV("OID", p)
			}
			kv.EndSection()
		}
		if len(pt.RequiredRoleOIDs) > 0 {
			kv.Section("Required Role OIDs (at least one must match)")
			for _, oid := range pt.RequiredRoleOIDs {
				kv.KV("OID", oid)
			}
			kv.EndSection()
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
