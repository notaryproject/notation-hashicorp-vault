package main

import (
	"context"
	"encoding/json"
	"fmt"
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
		jsonResp, _ := json.Marshal(resp)
		_, err = os.Stdout.Write(jsonResp)
	}

	// output the error
	if err != nil {
		data, _ := json.Marshal(err)
		os.Stderr.Write(data)
		os.Exit(1)
	}
}

func help() {
	fmt.Print("Help not implemented yet.")
}
