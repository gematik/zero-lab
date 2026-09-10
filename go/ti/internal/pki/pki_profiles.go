package pki

import (
	"encoding/asn1"
	"fmt"
	"io"
	"strings"

	"github.com/gematik/zero-lab/go/gempki"
	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

// validateProfileName rejects a --profile value that names no profile. Without
// this the unknown name falls through to a chain-only validator and the run
// still reports success, as if a profile of that name had been applied.
func validateProfileName(name string) error {
	switch strings.ToLower(name) {
	case "", gempki.ProfileAuto, gempki.ProfileNone:
		return nil
	}
	if _, ok := gempki.LookupProfile(name); ok {
		return nil
	}
	return fmt.Errorf("unknown profile %q (valid: %s)", name, strings.Join(gempki.ProfileSelectorValues(), ", "))
}

func completeProfile(_ *cobra.Command, _ []string, _ string) ([]string, cobra.ShellCompDirective) {
	return gempki.ProfileSelectorValues(), cobra.ShellCompDirectiveNoFileComp
}

// profileScope renders what a profile applies to: the certificate types it
// accepts, plus the admission role that picks it out among profiles sharing
// a type. Type and role together are the discriminator, so they belong in
// one column — a profile is never selected for a type it does not accept,
// nor for a certificate lacking its role.
func profileScope(p *gempki.Profile) string {
	scope := strings.Join(certTypeNames(p.AcceptsTypes), ", ")
	for _, oid := range p.RequiredRoleOIDs {
		label := oid.String()
		if info, ok := gempki.LookupOID(oid); ok && info.Ref != "" {
			label = info.Ref + " (" + oid.String() + ")"
		}
		scope += " + " + label
	}
	return scope
}

func newPKIProfilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profiles",
		Short: "List or describe the gempki profiles available to `ti pki verify`",
	}
	cmd.AddCommand(newPKIProfilesListCmd())
	cmd.AddCommand(newPKIProfilesDescribeCmd())
	return cmd
}

func newPKIProfilesListCmd() *cobra.Command {
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
		RequiredRoles  []string `json:"requiredRoleOIDs,omitempty"`
		Scope          string   `json:"scope"`
	}
	var rows []row
	for _, name := range gempki.ProfileNames() {
		p := gempki.ProfileRegistry[name]
		rows = append(rows, row{
			Name:           p.Name,
			Description:    p.Description,
			RevocationMode: revocationModeString(p.RevocationMode),
			AcceptsTypes:   certTypeNames(p.AcceptsTypes),
			DefaultFor:     certTypeNames(p.DefaultFor),
			RequiredRoles:  asn1OIDStrings(p.RequiredRoleOIDs),
			Scope:          profileScope(p),
		})
	}
	if f == formatJSON {
		return common.PrintJSON(rows)
	}
	return common.PrintTable("NAME\tSCOPE\tREVOCATION\tDESCRIPTION", func(w io.Writer) {
		for _, r := range rows {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Name, r.Scope, r.RevocationMode, r.Description)
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

func newPKIProfilesDescribeCmd() *cobra.Command {
	var formatRaw string
	cmd := &cobra.Command{
		Use:       "describe NAME",
		Short:     "Show the configured constraints of a profile",
		Args:      cobra.ExactArgs(1),
		ValidArgs: gempki.ProfileNames(),
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			f, err := parseOutputFormat(formatRaw, []outputFormat{formatText, formatJSON})
			if err != nil {
				return err
			}
			p, ok := gempki.LookupProfile(args[0])
			if !ok {
				return fmt.Errorf("unknown profile %q (valid: %s)", args[0], strings.Join(gempki.ProfileNames(), ", "))
			}
			return runProfilesDescribe(p, f)
		},
	}
	cmd.Flags().StringVar(&formatRaw, "format", string(formatText), "output format: text, json")
	return cmd
}

func runProfilesDescribe(p *gempki.Profile, f outputFormat) error {
	detail := describeProfile(p)
	if f == formatJSON {
		return common.PrintJSON(detail)
	}
	return renderProfileDescribeText(detail)
}

type perTypeDetail struct {
	Type                string   `json:"type"`
	RequiredKeyUsage    string   `json:"requiredKeyUsage,omitempty"`
	AllowedExtKeyUsages []string `json:"allowedExtKeyUsages,omitempty"`
	RequiredPolicies    []string `json:"requiredPolicies,omitempty"`
	RequiredRoleOIDs    []string `json:"requiredRoleOIDs,omitempty"`
	// RoleOIDSource is "profile" when the profile replaces the type
	// baseline's role OIDs, "type" when it inherits them.
	RoleOIDSource string `json:"roleOIDSource,omitempty"`
}

type profileDetail struct {
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	RevocationMode string          `json:"revocationMode"`
	ExtraPolicies  []string        `json:"extraPolicies,omitempty"`
	AcceptsTypes   []string        `json:"acceptsTypes"`
	DefaultFor     []string        `json:"defaultFor,omitempty"`
	Scope          string          `json:"scope"`
	PerType        []perTypeDetail `json:"perType,omitempty"`
}

func describeProfile(p *gempki.Profile) profileDetail {
	d := profileDetail{
		Name:           p.Name,
		Description:    p.Description,
		RevocationMode: revocationModeString(p.RevocationMode),
		ExtraPolicies:  asn1OIDStrings(p.ExtraPolicies),
		AcceptsTypes:   certTypeNames(p.AcceptsTypes),
		DefaultFor:     certTypeNames(p.DefaultFor),
		Scope:          profileScope(p),
	}
	for _, t := range p.AcceptsTypes {
		spec := t.Spec()
		// EffectiveRoleOIDs, not spec.RoleOIDs: a profile's own role list
		// replaces the type baseline, and describing the baseline would
		// misstate what this profile checks.
		source := "type"
		if len(p.RequiredRoleOIDs) > 0 {
			source = "profile"
		}
		d.PerType = append(d.PerType, perTypeDetail{
			Type:                string(t),
			RequiredKeyUsage:    common.FormatKeyUsage(spec.KeyUsage),
			AllowedExtKeyUsages: extKeyUsageNamesList(spec.EKU),
			RequiredPolicies:    formatOIDs(spec.Policies),
			RequiredRoleOIDs:    formatOIDs(p.EffectiveRoleOIDs(t)),
			RoleOIDSource:       source,
		})
	}
	return d
}

func renderProfileDescribeText(d profileDetail) error {
	kv := common.NewKVWriter()
	kv.Section("Profile " + d.Name)
	if d.Description != "" {
		kv.KV("Description", d.Description)
	}
	kv.KV("Revocation Mode", d.RevocationMode)
	kv.KV("Scope", d.Scope)
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
			from := "from the " + pt.Type + " baseline"
			if pt.RoleOIDSource == "profile" {
				from = "set by this profile, replacing the " + pt.Type + " baseline"
			}
			kv.Section("Required Role OIDs (at least one must match; " + from + ")")
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

// formatOIDs renders OIDs with their gematik names where gempki knows them.
func formatOIDs(oids []asn1.ObjectIdentifier) []string {
	out := make([]string, len(oids))
	for i, oid := range oids {
		out[i] = gempki.FormatOID(oid)
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
