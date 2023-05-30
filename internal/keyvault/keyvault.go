package keyvault

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/notaryproject/notation-hashicorp-vault/internal/crypto"
	"log"
	"os"
	"strings"
	"time"
)


type VaultClientWrapper struct {
	vaultClient *vault.Client

	keyID string
}

func NewVaultClientFromKeyID(id string) (*VaultClientWrapper, error) {
	// read addr and token from environment variables
	VAULTADDR = os.Getenv("VAULT_ADDR")
	if len(VAULTADDR) < 1 {
		return nil, errors.New("failed to load vault address")
	}

	vaultToken := os.Getenv("VAULT_TOKEN")
	if len(VAULTTOKEN) < 1 {
		log.Fatal("Error loading vault token")
	}

	// prepare a client with the given base address
	client, err := vault.New(
		vault.WithAddress(VAULTADDR),
		vault.WithRequestTimeout(30*time.Second),
	)
	if err != nil {
		log.Fatal(err)
	}

	// authenticate with a root token (insecure)
	if err := client.SetToken(VAULTTOKEN); err != nil {
		log.Fatal(err)
	}

	return &VaultClientWrapper{
		vaultClient: client,
		keyID:       id,
	}, nil
}

func (vw *VaultClientWrapper) GetCertificateChain(ctx context.Context) ([]*x509.Certificate, error) {
	// read a certChain
	secret, err := vw.vaultClient.Secrets.KVv2Read(ctx, vw.keyID)
	if err != nil {
		return nil, err
	}
	//fmt.Println("Successfully got the cert chain from vault")
	certString := secret.Data["data"].(map[string]interface{})["certificate"].(string)
	certBytes := []byte(certString)
	certs, err := ParseCertificates(certBytes)
	return certs, nil
}

func (vw *VaultClientWrapper) SignWithTransit(ctx context.Context, encodedData string, signAlgorithm string) ([]byte, error) {
	// sign with transit SE
	resp, err := vw.vaultClient.Secrets.TransitSign(ctx, vw.keyID, schema.TransitSignRequest{
		Input:               encodedData,
		MarshalingAlgorithm: "asn1",
		KeyVersion:          0,
		Prehashed:           true,
		SaltLength:          "hash",
		SignatureAlgorithm:  signAlgorithm,
	})
	if err != nil {
		return nil, err
	}

	signature := resp.Data["signature"].(string)
	items := strings.Split(signature, ":")
	sigBytes, err := base64.StdEncoding.DecodeString(items[2])
	if err != nil {
		return nil, err
	}
	return sigBytes, nil
}
