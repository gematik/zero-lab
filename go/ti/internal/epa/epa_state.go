package epa

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/gematik/zero-lab/go/ti/internal/common"
	"github.com/spf13/cobra"
)

func newEpaStateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "state",
		Short: "Inspect and manage the locally stored ePA data",
	}
	cmd.AddCommand(newEpaStateListCmd())
	cmd.AddCommand(newEpaStateGetCmd())
	cmd.AddCommand(newEpaStateClearCmd())
	return cmd
}

type stateEntryView struct {
	Key       string     `json:"key"`
	CreatedAt time.Time  `json:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Bytes     int        `json:"bytes"`
}

func newEpaStateListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List stored entries with TTL",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			s, err := common.LoadCLIState()
			if err != nil {
				return err
			}
			defer s.Close()
			entries, err := s.Entries()
			if err != nil {
				return err
			}
			views := make([]stateEntryView, 0, len(entries))
			for k, e := range entries {
				if !strings.HasPrefix(k, epaKeyPrefix) {
					continue // the store is shared; `ti pki state` owns the rest
				}
				views = append(views, stateEntryView{
					Key: k, CreatedAt: e.CreatedAt, ExpiresAt: e.ExpiresAt, Bytes: len(e.Value),
				})
			}
			sortStateViews(views)
			if common.OutputFlag == "json" {
				return common.PrintJSON(views)
			}
			return common.PrintTable("KEY\tBYTES\tCREATED\tTTL", func(w io.Writer) {
				for _, v := range views {
					fmt.Fprintf(w, "%s\t%d\t%s\t%s\n",
						v.Key, v.Bytes, v.CreatedAt.Local().Format(time.RFC3339), ttlString(v.ExpiresAt))
				}
			})
		},
	}
}

func sortStateViews(views []stateEntryView) {
	for i := 1; i < len(views); i++ {
		for j := i; j > 0 && views[j-1].Key > views[j].Key; j-- {
			views[j-1], views[j] = views[j], views[j-1]
		}
	}
}

func ttlString(expiresAt *time.Time) string {
	if expiresAt == nil {
		return "never"
	}
	d := time.Until(*expiresAt).Round(time.Second)
	if d <= 0 {
		return "expired"
	}
	return d.String()
}

func newEpaStateGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <key>",
		Short: "Show the value for a single state key",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeStateKeys(toComplete), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			s, err := common.LoadCLIState()
			if err != nil {
				return err
			}
			defer s.Close()
			data, ok, err := s.Get(args[0])
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("key %q not found (or expired)", args[0])
			}
			if common.OutputFlag == "json" {
				return common.PrintJSON(json.RawMessage(data))
			}
			var pretty json.RawMessage = data
			out, err := json.MarshalIndent(&pretty, "", "  ")
			if err != nil {
				return err
			}
			fmt.Println(string(out))
			return nil
		},
	}
}

func newEpaStateClearCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "clear [<key>]",
		Short: "Delete one ePA state key, or all of them when no key is given",
		Args:  cobra.MaximumNArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeStateKeys(toComplete), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			s, err := common.LoadCLIState()
			if err != nil {
				return err
			}
			defer s.Close()
			if len(args) == 1 {
				if err := requireEpaKey(args[0]); err != nil {
					return err
				}
				if err := s.Delete(args[0]); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "deleted %q\n", args[0])
				return nil
			}
			keys, err := s.Keys(epaKeyPrefix)
			if err != nil {
				return err
			}
			for _, k := range keys {
				if err := s.Delete(k); err != nil {
					return err
				}
			}
			fmt.Fprintf(os.Stderr, "deleted %d entries\n", len(keys))
			return nil
		},
	}
}

// requireEpaKey keeps `ti epa state` inside the epa: half of the shared store.
// Without it a key argument reaches PKI entries too, which is `ti pki state`'s
// to manage.
func requireEpaKey(key string) error {
	if !strings.HasPrefix(key, epaKeyPrefix) {
		return fmt.Errorf("%q is not an ePA state key (expected the %s prefix); `ti pki state` manages the rest", key, epaKeyPrefix)
	}
	return nil
}

func completeStateKeys(prefix string) []string {
	s, err := common.LoadCLIState()
	if err != nil {
		return nil
	}
	defer s.Close()
	if !strings.HasPrefix(prefix, epaKeyPrefix) {
		prefix = epaKeyPrefix
	}
	keys, err := s.Keys(prefix)
	if err != nil {
		return nil
	}
	return keys
}
