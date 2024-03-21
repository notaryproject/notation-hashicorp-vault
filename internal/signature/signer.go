package signature

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-hashicorp-vault/internal/keyvault"
)

func Sign(ctx context.Context, req *proto.GenerateSignatureRequest) (*proto.GenerateSignatureResponse, error) {

	// validate request
	if req == nil || req.KeyID == "" || req.KeySpec == "" || req.Hash == "" {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("invalid request input"),
		}
	}

	vaultClient, err := keyvault.NewVaultClientFromKeyID(req.KeyID)
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to get vault client, %v", err),
		}
	}

	// get keySpec
	keySpec, err := proto.DecodeKeySpec(req.KeySpec)
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to get keySpec, %v", err),
		}
	}

	// get hash algorithm and validate hash
	hashAlgorithm, err := proto.HashAlgorithmFromKeySpec(keySpec)
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("failed to get hash algorithm, %v", err),
		}
	}

	if hashAlgorithm != req.Hash {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  fmt.Errorf("keySpec hash: %v mismatch request hash: %v", hashAlgorithm, req.Hash),
		}
	}

	// get signing algorithm
	signAlgorithm := getAlgorithmFromKeySpec(req.KeySpec)
	if signAlgorithm == "" {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeValidation,
			Err:  errors.New("unrecognized key spec: " + string(req.KeySpec)),
		}
	}

	// Notary to OpenBao/Vault hash algorithm naming conversion map
	vaultHashAlgorithms := map[string]string{
		"SHA-256": "sha2-256",
		"SHA-384": "sha2-384",
		"SHA-512": "sha2-512",
	}
	vaultHashAlgorithm := vaultHashAlgorithms[string(req.Hash)]

	// compute hash for the payload
	hashData, err := computeHash(keySpec.SignatureAlgorithm().Hash(), req.Payload)
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to compute hash for the payload, %v", err),
		}
	}
	encodedHash := base64.StdEncoding.EncodeToString(hashData)
	sigBytes, err := vaultClient.SignWithTransit(ctx, encodedHash, signAlgorithm, vaultHashAlgorithm)
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to sign with Transit secret engine, %v", err),
		}
	}

	signatureAlgorithmString, err := proto.EncodeSigningAlgorithm(keySpec.SignatureAlgorithm())
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to encode signing algorithm, %v", err),
		}
	}

	rawCertChain, err := getCertificateChain(ctx, *vaultClient)
	if err != nil {
		return nil, &proto.RequestError{
			Code: proto.ErrorCodeGeneric,
			Err:  fmt.Errorf("failed to get certificate chain, %v", err),
		}
	}

	return &proto.GenerateSignatureResponse{
		KeyID:            req.KeyID,
		Signature:        sigBytes,
		SigningAlgorithm: string(signatureAlgorithmString),
		CertificateChain: rawCertChain,
	}, nil
}

// computeHash computes the digest of the message with the given hash algorithm.
func computeHash(hash crypto.Hash, message []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, errors.New("unavailable hash function: " + hash.String())
	}
	h := hash.New()
	if _, err := h.Write(message); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

func getAlgorithmFromKeySpec(k proto.KeySpec) string {
	switch k {
	case proto.KeySpecRSA2048:
		return "pss"
	case proto.KeySpecRSA3072:
		return "pss"
	case proto.KeySpecRSA4096:
		return "pss"
	default:
		return ""
	}
}

func getCertificateChain(ctx context.Context, vw keyvault.VaultClientWrapper) ([][]byte, error) {
	certs, err := vw.GetCertificateChain(ctx)
	if err != nil {
		return nil, err
	}
	// build raw cert chain
	rawCertChain := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		rawCertChain = append(rawCertChain, cert.Raw)
	}
	return rawCertChain, nil
}
