package main

import (
	"github.com/notaryproject/notation-go/plugin/proto"
	"github.com/notaryproject/notation-hashicorp-vault/internal/version"
)

func runGetMetadata() *proto.GetMetadataResponse {
	return &proto.GetMetadataResponse{
		Name:                      "hc-vault",
		Description:               "Sign artifacts with keys in HashiCorp Vault",
		Version:                   version.GetVersion(),
		URL:                       "https://github.com/OliverShang/notation-hc-vault",
		SupportedContractVersions: []string{proto.ContractVersion},
		Capabilities:              []proto.Capability{proto.CapabilitySignatureGenerator},
	}
}
