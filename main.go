package main

import (
	"context"
	"crypto/tls"
	"fmt"
	marker "github.com/provenance-io/provenance/x/marker/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/cosmos/cosmos-sdk/codec"
	sdk "github.com/cosmos/cosmos-sdk/types"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
)

func queryState() error {
	sdk.GetConfig().SetBech32PrefixForAccount("tp", "tpub")                                 // Set the Bech32 prefix for the account address.
	myAddress, err := sdk.AccAddressFromBech32("tp1h2xyrnnqylg9ualqj50zq9epzn28eg56uz3j4f") // the my_validator or recipient address.
	if err != nil {
		return err
	}

	// Create a connection to the gRPC server.
	grpcConn, err := grpc.Dial(
		//"34.148.39.82:9090", // your gRPC server address.
		"grpc.test.provenance.io:443",
		//grpc.WithInsecure(), // The Cosmos SDK doesn't support any transport security mechanism. (use this with 34.148.39.82:9090, but wont work with grpc.test.provenance.io:443)
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})),
		// This instantiates a general gRPC codec which handles proto bytes. We pass in a nil interface registry
		// if the request/response types contain interface instead of 'nil' you should pass the application specific codec.
		grpc.WithDefaultCallOptions(grpc.ForceCodec(codec.NewProtoCodec(nil).GRPCCodec())),
	)
	if err != nil {
		return err
	}
	defer grpcConn.Close()

	// This creates a gRPC client to query the x/bank service.
	bankClient := banktypes.NewQueryClient(grpcConn)
	bankRes, err := bankClient.Balance(
		context.Background(),
		&banktypes.QueryBalanceRequest{Address: myAddress.String(), Denom: "nhash"},
	)
	if err != nil {
		return err
	}

	fmt.Println(bankRes.GetBalance()) // Prints the account balance

	markerClient := marker.NewQueryClient(grpcConn)
	markerClient.Marker(context.Background(), &marker.QueryMarkerRequest{Id: "nhash"})

	return nil
}

func main() {
	if err := queryState(); err != nil {
		panic(err)
	}
}
