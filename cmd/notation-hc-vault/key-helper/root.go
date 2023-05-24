package key_helper

import (
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "key-helper",
	Short: "key-helper - a simple CLI to import key and certificates to HashiCorp Vault",
	Long: `key-helper - a simple CLI to import key and certificates to HashiCorp Vault
   
import key to Vault Transit secrets engine and certificates to Vault KV secrets engine`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("ah")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoops. There was an error while executing your CLI '%s'", err)
		os.Exit(1)
	}
}
