package keyvault

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	vault "github.com/hashicorp/vault/api"
	"github.com/notaryproject/notation-hashicorp-vault/internal/crypto"
	"os"
	"strings"
)

type VaultClientWrapper struct {
	vaultClient *vault.Client

	keyID string
}

func NewVaultClientFromKeyID(id string) (*VaultClientWrapper, error) {
	// read addr and token from environment variables
	vaultAddr := os.Getenv("VAULT_ADDR")
	if len(vaultAddr) < 1 {
		return nil, errors.New("failed to load vault address")
	}

	vaultToken := os.Getenv("VAULT_TOKEN")
	if len(vaultToken) < 1 {
		return nil, errors.New("Error loading vault token")
	}

	// prepare a client with the given base address
	client, err := vault.NewClient(&vault.Config{
		Address: vaultAddr,
	})
	if err != nil {
		return nil, err
	}

	return &VaultClientWrapper{
		vaultClient: client,
		keyID:       id,
	}, nil
}

func (vw *VaultClientWrapper) GetCertificateChain(ctx context.Context) ([]*x509.Certificate, error) {
	// read a certChain
	secret, err := vw.vaultClient.KVv2("secret").Get(ctx, vw.keyID)
	if err != nil {
		return nil, err
	}
	certString, ok := secret.Data["certificate"].(string)
	if !ok {
		return nil, errors.New("failed to parse certificate from KV secrets engine")
	}
	certBytes := []byte(certString)
	return crypto.ParseCertificates(certBytes)
}

func (vw *VaultClientWrapper) SignWithTransit(ctx context.Context, encodedData string, signAlgorithm string) ([]byte, error) {
	// sign with transit SE
	transitSignReq := map[string]interface{}{
		"input":                encodedData,
		"marshaling_algorithm": "asn1",
		"prehashed":            true,
		"salt_length":          "hash",
		"signature_algorithm":  signAlgorithm,
	}
	path := "transit/sign/" + vw.keyID
	resp, err := vw.vaultClient.Logical().WriteWithContext(ctx, path, transitSignReq)
	if err != nil {
		return nil, err
	}

	signature, ok := resp.Data["signature"].(string)
	if !ok {
		return nil, errors.New("failed to parse signature from TransitSign response")
	}
	items := strings.Split(signature, ":")
	sigBytes, err := base64.StdEncoding.DecodeString(items[2])
	if err != nil {
		return nil, err
	}
	return sigBytes, nil
}
