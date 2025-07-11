package main

import (
	"context"
	"fmt"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/provenance-io/provenance/x/smartaccounts/types"
	"google.golang.org/grpc"
)

func init() {
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("tp", "tp"+sdk.PrefixPublic)
	config.Seal()
}

func querySmartAccountAuth(address string) error {
	// Setup encoding config
	//encCfg := testutilmod.MakeTestEncodingConfig(auth.AppModuleBasic{}, smartaccountmodule.AppModuleBasic{})

	// Create gRPC connection
	grpcConn, err := grpc.Dial(
		"127.0.0.1:9090",
		grpc.WithInsecure(),
	)
	if err != nil {
		return err
	}
	defer grpcConn.Close()

	// Create query client
	queryClient := types.NewQueryClient(grpcConn)

	// Create the query request
	req := &types.AccountQueryRequest{
		Address: address,
	}

	// Execute the query
	resp, err := queryClient.SmartAccount(
		context.Background(),
		req,
	)
	if err != nil {
		return err
	}

	// Print the response
	fmt.Printf("Credential for address %s:\n", resp.Provenanceaccount.Address)
	fmt.Printf("UserIdentifier: %d\n", resp.Provenanceaccount.SmartAccountNumber)
	fmt.Printf("Credentials registered size: %d\n", len(resp.Provenanceaccount.Credentials))
	fmt.Printf("Account object: %v\n", resp.Provenanceaccount)

	return nil
}

func main() {
	address := "tp1w40q3q7v26petw6g5stz5dt9xsezgnzalxgw8x" // Replace with the smart account address you want to query
	err := querySmartAccountAuth(address)
	if err != nil {
		fmt.Printf("Error querying smart account: %v\n", err)
	}
}
