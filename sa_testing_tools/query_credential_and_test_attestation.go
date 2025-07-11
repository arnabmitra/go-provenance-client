package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/provenance-io/provenance/x/smartaccounts/types"
	"google.golang.org/grpc"
	"io"
	"log"
)

// retrieve the user credentials
func init() {
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("tp", "tp"+sdk.PrefixPublic)
	config.Seal()
}

func querySmartAccount(address string) (*types.ProvenanceAccount, error) {
	// Create gRPC connection
	grpcConn, err := grpc.Dial(
		"127.0.0.1:9090",
		grpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
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
		return nil, err
	}

	// Print the response
	fmt.Printf("Credential for address %s:\n", resp.Provenanceaccount.Address)
	fmt.Printf("UserIdentifier: %d\n", resp.Provenanceaccount.SmartAccountNumber)
	fmt.Printf("Credentials registered size: %d\n", len(resp.Provenanceaccount.Credentials))
	fmt.Printf("Account object: %v\n", resp.Provenanceaccount)

	return resp.Provenanceaccount, nil
}

func main() {
	address := "tp1w40q3q7v26petw6g5stz5dt9xsezgnzalxgw8x" // Replace with the smart account address you want to query
	provenanceAccount, err := querySmartAccount(address)
	if err != nil {
		fmt.Printf("Error querying smart account: %v\n", err)
	}

	// verify the attestation from the retrieved credentials
	for _, credential := range provenanceAccount.Credentials {
		//fmt.Printf("Credential ID: %s\n", credential.Id)
		fmt.Printf("Credential Number: %d\n", credential.CredentialNumber)
		fmt.Printf("Credential Public Key: %s\n", credential.PublicKey)
		//fmt.Printf("Credential Public Key: %s\n", credential.RpId)

		assertionResponse := `
{
  "id": "bbcXuKs1MaXovZbLHXIc_Q",
  "type": "public-key",
  "rawId": "bbcXuKs1MaXovZbLHXIc_Q",
  "response": {
    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiTmpoQ1JrVkZRakZCUWpsQ1FUTTJPVGt4TmtZNU5FTkJNVGM1UVRVM1FrSTVPREF4UXpZMFJVRTBNVUUxTWpSRk9ESTNRak00T1VSRE5EZzFNall3T0EiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjE4MDgwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0",
    "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MdAAAAAA",
    "signature": "MEUCIQDZ7WIksZyQYIODa6o8nkPg5Tamh1psEHnQAgPoSw9MJgIgLbEtPzzBIvafT8icnxSexzXfOVvrS1v_AJXgoDrZJis",
    "userHandle": "6-SG3dq4hPbuAQ"
  }
}
							`
		bodyAssertion := io.NopCloser(bytes.NewReader([]byte(assertionResponse)))
		assertionSignature := base64.RawURLEncoding.EncodeToString([]byte(assertionResponse))
		fmt.Printf("the signature is %v \n", assertionSignature)
		par, err := protocol.ParseCredentialRequestResponseBody(bodyAssertion)
		if err != nil {
			log.Fatalf("Failed to parse credential request response: %v", err)
		}

		// Step 5. Let JSONtext be the result of running UTF-8 decode on the value of cData.
		// We don't call it cData but this is Step 5 in the spec.
		if err = json.Unmarshal(par.Raw.AssertionResponse.ClientDataJSON, &par.Response.CollectedClientData); err != nil {
			log.Fatalf("Failed to unmarshal client data JSON: %v", err)
		}
		challenge := base64.RawURLEncoding.EncodeToString([]byte("68BFEEB1AB9BA369916F94CA179A57BB9801C64EA41A524E827B389DC4852608"))
		fmt.Printf("Challenge: %s\n", challenge)
		sigVerificationResult := credential.VerifySignature([]byte(challenge), *par)
		if sigVerificationResult {
			fmt.Printf("Signature verified for credential ID: %s\n", credential.PublicKey)
		} else {
			fmt.Printf("Signature verification failed for credential ID: %s\n", credential.PublicKey)
		}
	}
}
