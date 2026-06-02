package main

import (
	"github.com/spf13/cobra"
)

func newDescribeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "describe",
		Short: "Describe a resource in detail",
	}

	cmd.AddCommand(newDescribeCertificateCmd())
	cmd.AddCommand(newDescribeCardCmd())

	return cmd
}
