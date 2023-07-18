package main

import (
	"os"

	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "key-helper",
		Short: "a simple CLI to import key and certificates to HashiCorp Vault",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}
	rootCmd.AddCommand(importKeyCommand())
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
