package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/notaryproject/notation-hashicorp-vault/internal/version"
	"os"

	"github.com/notaryproject/notation-go/plugin/proto"
)

func main() {
	if len(os.Args) < 2 {
		help()
		return
	}
	ctx := context.Background()
	var err error
	var resp any
	switch proto.Command(os.Args[1]) {
	case proto.CommandGetMetadata:
		resp = runGetMetadata()
	case proto.CommandDescribeKey:
		resp, err = runDescribeKey(ctx, os.Stdin)
	case proto.CommandGenerateSignature:
		resp, err = runSign(ctx, os.Stdin)
	default:
		err = fmt.Errorf("invalid command: %s", os.Args[1])
	}

	// output the response
	if err == nil {
		// ignore the error because the response only contains valid JSON field.
		jsonResp, err2 := json.Marshal(resp)
		if err2 != nil {
			data, _ := json.Marshal(wrapError(err2))
			os.Stderr.Write(data)
			os.Exit(1)
		}
		_, err = os.Stdout.Write(jsonResp)
	}

	// output the error
	if err != nil {
		data, _ := json.Marshal(wrapError(err))
		os.Stderr.Write(data)
		os.Exit(1)
	}
}

func wrapError(err error) *proto.RequestError {
	// already wrapped
	var nerr *proto.RequestError
	if errors.As(err, &nerr) {
		return nerr
	}

	// default error code
	code := proto.ErrorCodeGeneric
	return &proto.RequestError{
		Code: code,
		Err:  err,
	}
}

func help() {
	fmt.Printf(`notation-hc-vault - Notation Hashicorp Vault plugin
Usage:
  notation-hc-vault <command>
Version:
  %s
Commands:
  describe-key         Hashicorp vault key description
  generate-signature   Sign artifacts with keys in Hashicorp Vault
  get-plugin-metadata  Get plugin metadata
`, version.GetVersion())
}
