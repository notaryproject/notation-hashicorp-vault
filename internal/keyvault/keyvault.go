package keyvault

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"strings"

	vault "github.com/hashicorp/vault/api"
	"github.com/notaryproject/notation-hashicorp-vault/internal/crypto"
)

type VaultClientWrapper struct {
	vaultClient *vault.Client

	keyID             string
	kvEngineName      string
	transitEngineName string
	transitKeyID      string
}

func NewVaultClientFromKeyID(id string, pluginConfig map[string]string) (*VaultClientWrapper, error) {
	// read addr and token from environment variables
	vaultAddr := os.Getenv("VAULT_ADDR")
	if len(vaultAddr) < 1 {
		return nil, errors.New("failed to load vault address")
	}

	// prepare a client with the given base address
	client, err := vault.NewClient(&vault.Config{
		Address: vaultAddr,
	})
	if err != nil {
		return nil, err
	}

	transitName, ok := pluginConfig["transitName"]
	if !ok {
		transitName = "transit"
	}
	kvName, ok := pluginConfig["kvName"]
	if !ok {
		kvName = "secret"
	}
	transitKeyName, ok := pluginConfig["transitKeyName"]
	if !ok {
		transitKeyName = id
	}

	return &VaultClientWrapper{
		vaultClient:       client,
		keyID:             id,
		kvEngineName:      kvName,
		transitEngineName: transitName,
		transitKeyID:      transitKeyName,
	}, nil
}

func (vw *VaultClientWrapper) GetCertificateChain(ctx context.Context) ([]*x509.Certificate, error) {
	// read a certChain
	secret, err := vw.vaultClient.KVv2(vw.kvEngineName).Get(ctx, vw.keyID)
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

func (vw *VaultClientWrapper) SignWithTransit(ctx context.Context, encodedData string, signAlgorithm string, hashAlgorithm string) ([]byte, error) {
	// sign with transit SE
	transitSignReq := map[string]interface{}{
		"input":                encodedData,
		"marshaling_algorithm": "asn1",
		"prehashed":            true,
		"salt_length":          "hash",
		"signature_algorithm":  signAlgorithm,
		"hash_algorithm":       hashAlgorithm,
	}
	path := vw.transitEngineName + "/sign/" + vw.transitKeyID
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
