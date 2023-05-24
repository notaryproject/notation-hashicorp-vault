package key_helper

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/google/tink/go/kwp/subtle"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	notationx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/spf13/cobra"
	"io/ioutil"
	"log"
	"os"
	"time"
)

var VAULTADDR, VAULTTOKEN string

func init() {
	rootCmd.AddCommand(importKeyCmd)
	importKeyCmd.PersistentFlags().String("key_path", "", "absolute path to the private key file")
	importKeyCmd.PersistentFlags().String("cert_path", "", "absolute path to the certificate chain file")
	importKeyCmd.PersistentFlags().String("key_name", "", "name of the key")

}

var importKeyCmd = &cobra.Command{
	Use:   "import",
	Short: "import - a simple CLI to import key and certificates to HashiCorp Vault",
	Long: `import - a simple CLI to import key and certificates to HashiCorp Vault
   
import key to Vault Transit secrets engine and certificates to Vault KV secrets engine`,
	Run: func(cmd *cobra.Command, args []string) {
		ctx := context.Background()
		fmt.Println("Import key start")
		keyPath, err := cmd.Flags().GetString("key_path")
		if err != nil {
			fmt.Println(err)
		}
		certPath, err := cmd.Flags().GetString("cert_path")
		if err != nil {
			fmt.Println(err)
		}
		keyName, err := cmd.Flags().GetString("key_name")
		if err != nil {
			fmt.Println(err)
		}
		vaultClient, err := getVaultClient(ctx)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("Successfully got vault client")
		wrappingKey, err := getWrappingKey(ctx, vaultClient)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("Successfully got wrapping key")
		ciphertext, err := wrapPrivateKey(wrappingKey, keyPath)
		if err := importKeyToTransit(ctx, vaultClient, ciphertext, keyName); err != nil {
			fmt.Println(err)
		}
		fmt.Println("Successfully imported key to transit")
		if err := importCertToKV(ctx, vaultClient, certPath, keyName); err != nil {
			fmt.Println(err)
		}
		fmt.Println("Successfully imported cert to kv")
	},
}

func getVaultClient(ctx context.Context) (*vault.Client, error) {
	// read addr and token from environment variables
	VAULTADDR = os.Getenv("VAULT_ADDR")
	if len(VAULTADDR) < 1 {
		log.Fatal("Error loading vault address")
	}

	VAULTTOKEN = os.Getenv("VAULT_TOKEN")
	if len(VAULTTOKEN) < 1 {
		log.Fatal("Error loading vault token")
	}
	// prepare a client with the given base address
	vaultClient, err := vault.New(
		vault.WithAddress(VAULTADDR),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		return nil, err
	}
	if err := vaultClient.SetToken(VAULTTOKEN); err != nil {
		return nil, err
	}

	return vaultClient, nil
}

func getWrappingKey(ctx context.Context, client *vault.Client) (string, error) {
	// get transit SE wrapping key
	resp, err := client.Secrets.TransitReadWrappingKey(ctx)
	if err != nil {
		return "", err
	}
	key := resp.Data["public_key"].(string)
	return key, nil
}

func wrapPrivateKey(wrappingKey string, privateKeyPath string) (string, error) {
	keyBlock, _ := pem.Decode([]byte(wrappingKey))
	privateKey, err := notationx509.ReadPrivateKeyFile(privateKeyPath)
	if err != nil {
		return "", err
	}
	pkcs8PrivateKey, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	parsedKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		return "", err
	}
	ephemeralAESKey := make([]byte, 32)
	_, err = rand.Read(ephemeralAESKey)
	if err != nil {
		return "", err
	}
	wrapKWP, err := subtle.NewKWP(ephemeralAESKey)
	if err != nil {
		return "", err
	}
	wrappedTargetKey, err := wrapKWP.Wrap(pkcs8PrivateKey)
	if err != nil {
		return "", err
	}

	wrappedAESKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		parsedKey.(*rsa.PublicKey),
		ephemeralAESKey,
		[]byte{},
	)
	if err != nil {
		return "", err
	}
	combinedCiphertext := append(wrappedAESKey, wrappedTargetKey...)
	base64Ciphertext := base64.StdEncoding.EncodeToString(combinedCiphertext)

	return base64Ciphertext, nil
}

func importKeyToTransit(ctx context.Context, client *vault.Client, ciphertext string, keyName string) error {

	req := schema.TransitImportKeyRequest{
		AllowPlaintextBackup: false,
		AllowRotation:        false,
		AutoRotatePeriod:     0,
		Ciphertext:           ciphertext,
		Context:              "",
		Derived:              false,
		Exportable:           false,
		HashFunction:         "SHA256",
		Type:                 "rsa-2048",
	}
	_, err := client.Secrets.TransitImportKey(ctx, keyName, req)
	return err
}

func importCertToKV(ctx context.Context, client *vault.Client, certPath string, keyName string) error {
	certFile, err := os.Open(certPath)
	if err != nil {
		log.Fatal(err)
	}
	bytes, err := ioutil.ReadAll(certFile)
	data := make(map[string]interface{})
	data["certificate"] = string(bytes)
	req := schema.KVv2WriteRequest{
		Data:    data,
		Options: nil,
		Version: 0,
	}
	_, err = client.Secrets.KVv2Write(ctx, keyName, req)
	return err
}
