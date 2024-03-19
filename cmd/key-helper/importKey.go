package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/tink/go/kwp/subtle"
	vault "github.com/hashicorp/vault/api"
	notationx509 "github.com/notaryproject/notation-core-go/x509"
	"github.com/spf13/cobra"
)

var vaultAddr string

func importKeyCommand() *cobra.Command {
	importKeyCmd := &cobra.Command{
		Use:   "import --key_path <path_to_private key file> --cert_path <path_to__certificate_chain_file> --key_name <HashiCorp_Vault_key_name>",
		Short: "import private key and certificates to HashiCorp Vault",
		Long:  "import private key to Vault Transit secrets engine and certificates to Vault KV secrets engine",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			fmt.Println("Import key start")
			keyPath, err := cmd.Flags().GetString("key_path")
			if err != nil {
				return err
			}
			certPath, err := cmd.Flags().GetString("cert_path")
			if err != nil {
				return err
			}
			keyName, err := cmd.Flags().GetString("key_name")
			if err != nil {
				return err
			}
			vaultClient, err := getVaultClient(ctx)
			if err != nil {
				return err
			}
			fmt.Println("Successfully got vault client")
			wrappingKey, err := getWrappingKey(ctx, vaultClient)
			if err != nil {
				return err
			}
			fmt.Println("Successfully got wrapping key")
			ciphertext, err := wrapPrivateKey(wrappingKey, keyPath)
			if err != nil {
				return err
			}
			keyType, vaultRSAOAEPHashFunction, err := checkKeyType(keyPath)
			if err != nil {
				return err
			}
			if err := importKeyToTransit(ctx, vaultClient, ciphertext, keyName, keyType, vaultRSAOAEPHashFunction); err != nil {
				return err
			}
			fmt.Println("Successfully imported key to transit")
			if err := importCertToKV(ctx, vaultClient, certPath, keyName); err != nil {
				return err
			}
			fmt.Println("Successfully imported cert to kv")
			return nil
		},
	}
	importKeyCmd.Flags().String("key_path", "", "absolute path to the private key file")
	importKeyCmd.Flags().String("cert_path", "", "absolute path to the certificate chain file")
	importKeyCmd.Flags().String("key_name", "", "name of the key")
	return importKeyCmd
}

func getVaultClient(ctx context.Context) (*vault.Client, error) {
	// read addr and token from environment variables
	vaultAddr = os.Getenv("VAULT_ADDR")
	if len(vaultAddr) < 1 {
		return nil, errors.New("error loading vault address")
	}
	// prepare a client with the given base address
	return vault.NewClient(&vault.Config{
		Address: vaultAddr,
	})
}

func getWrappingKey(ctx context.Context, client *vault.Client) (string, error) {
	// get transit SE wrapping key
	path := "/transit/wrapping_key"
	resp, err := client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return "", err
	}
	key, ok := resp.Data["public_key"].(string)
	if !ok {
		return "", errors.New("failed to get public key from resp.Data")
	}
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

// Checks PrivateKey type and bitlength in EC, PKCS1 and PKCS8 containers
func checkKeyType(keyPath string) (string, string, error) {
	// Key types supported by Notary project specification
	supportedRSAKeys := map[int]string{
		2048: "rsa-2048",
		3072: "rsa-3072",
		4096: "rsa-4096",
	}
	supportedECDSAKeys := map[string]string{
		"P-256": "ecdsa-p256",
		"P-384": "ecdsa-p384",
		"P-521": "ecdsa-p521",
	}
	digestAlgorithm := map[string]string{
		"ecdsa-p256": "SHA256",
		"ecdsa-p384": "SHA384",
		"ecdsa-p521": "SHA512",
		"rsa-2048":   "SHA256",
		"rsa-3072":   "SHA384",
		"rsa-4096":   "SHA512",
	}

	keyString, err := os.ReadFile(keyPath)
	if err != nil {
		return "", "", err
	}
	pemDecoded, _ := pem.Decode([]byte(keyString))

	switch pemDecoded.Type {
	case "EC PRIVATE KEY":
		ecdsaPrivateKey, err := x509.ParseECPrivateKey(pemDecoded.Bytes)
		if err != nil {
			fmt.Println(err)
		}

		curveName := ecdsaPrivateKey.PublicKey.Curve.Params().Name

		keyType, ok := supportedECDSAKeys[curveName]
		if ok {
			return keyType, "", nil
		}
		return "", "", fmt.Errorf("unsupported curve type: `%s`", curveName)

	case "RSA PRIVATE KEY":
		rsaPrivateKey, err := x509.ParsePKCS1PrivateKey(pemDecoded.Bytes)
		if err != nil {
			return "", "", err
		}
		keyLength := rsaPrivateKey.N.BitLen()

		keyType, ok := supportedRSAKeys[keyLength]
		if ok {
			return keyType, digestAlgorithm[keyType], nil
		}
		return "", "", fmt.Errorf("unsupported RSA keylength: %d", keyLength)

	case "PRIVATE KEY":
		key, _ := x509.ParsePKCS8PrivateKey(pemDecoded.Bytes)

		switch key := key.(type) {
		case *ecdsa.PrivateKey:
			curveName := key.PublicKey.Curve.Params().Name
			keyType, ok := supportedECDSAKeys[curveName]

			if ok {
				return keyType, digestAlgorithm[keyType], nil
			}
			return "", "", fmt.Errorf("unsupported curve type: `%s`", curveName)

		case *rsa.PrivateKey:
			keyLength := key.N.BitLen()
			keyType, ok := supportedRSAKeys[keyLength]

			if ok {
				return keyType, digestAlgorithm[keyType], nil
			}
			return "", "", fmt.Errorf("unsupported RSA keylength: %d", keyLength)
		}
	}
	return "", "", fmt.Errorf("your key is incompatible with Notary project signature specification")
}

func importKeyToTransit(ctx context.Context, client *vault.Client, ciphertext string, keyName string, keyType string, hashFunction string) error {
	path := fmt.Sprintf("/transit/keys/%s/import", keyName)
	req := map[string]interface{}{
		"allow_plaintext_backup": false,
		"allow_rotation":         false,
		"auto_rotate_period":     0,
		"ciphertext":             ciphertext,
		"context":                "",
		"derived":                false,
		"exportable":             false,
		"hashFunction":           hashFunction,
		"type":                   keyType,
		"name":                   "keyName",
	}
	_, err := client.Logical().WriteWithContext(ctx, path, req)
	return err
}

func importCertToKV(ctx context.Context, client *vault.Client, certPath string, keyName string) error {
	certFile, err := os.Open(certPath)
	if err != nil {
		return err
	}
	bytes, err := io.ReadAll(certFile)
	if err != nil {
		return err
	}
	data := make(map[string]interface{})
	data["certificate"] = string(bytes)
	_, err = client.KVv2("secret").Put(ctx, keyName, data)
	return err
}
