package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	testutilmod "github.com/cosmos/cosmos-sdk/types/module/testutil"
	txservice "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	"github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/bank"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"google.golang.org/grpc"
	"strings"
)

func init() {
	// Set the Bech32 prefix to "tp"
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("tp", "tp"+sdk.PrefixPublic)
	config.Seal()
}

func GetAccountInfoWebAuthn(grpcConn *grpc.ClientConn, address sdk.AccAddress, cdc codec.Codec) (uint64, uint64, cryptotypes.PubKey, error) {
	authClient := types.NewQueryClient(grpcConn)
	res, err := authClient.Account(context.Background(), &types.QueryAccountRequest{Address: address.String()})
	if err != nil {
		return 0, 0, nil, err
	}

	var acc types.AccountI
	if err := cdc.UnpackAny(res.Account, &acc); err != nil {
		return 0, 0, nil, err
	}

	return acc.GetAccountNumber(), acc.GetSequence(), acc.GetPubKey(), nil
}

func sendTxWebAuthn() error {
	// Choose your codec: Amino or Protobuf. Here, we use Protobuf, given by the
	// following function.
	encCfg := testutilmod.MakeTestEncodingConfig(bank.AppModuleBasic{}, auth.AppModuleBasic{})

	// Create a new TxBuilder.
	txBuilder := encCfg.TxConfig.NewTxBuilder()
	// this is just a test account, for local testing
	priv_key, _ := temp_util.PrivKeyFromHex("f109a351d02607503221102905585f29c01dce1e9fb8a3afcb352f357021d2d7")
	pub := priv_key.PubKey()
	addr := sdk.AccAddress(pub.Address())
	fmt.Printf("the from addres is %s\n", addr)

	msg1 := banktypes.NewMsgSend(addr, sdk.AccAddress("tp1za4sawgx8uqcwdjrds5xytjae044nuuj5lmklw"), sdk.NewCoins(sdk.NewInt64Coin("nhash", 1)))
	err := txBuilder.SetMsgs(msg1)
	if err != nil {
		return err
	}

	// Create a connection to the gRPC server.
	grpcConn, _ := grpc.Dial(
		"127.0.0.1:9090",    // Or your gRPC server address.
		grpc.WithInsecure(), // The Cosmos SDK doesn't support any transport security mechanism.
	)
	defer grpcConn.Close()

	txBuilder.SetGasLimit(2000000)
	txBuilder.SetFeeAmount(sdk.NewCoins(sdk.NewInt64Coin("nhash", 38400000000)))
	// Get account number and sequence dynamically
	accNum, accSeq, _, err := GetAccountInfoWebAuthn(grpcConn, addr, encCfg.Codec)
	if err != nil {
		return err
	}

	privs := []cryptotypes.PrivKey{priv_key}
	accNums := []uint64{accNum}
	accSeqs := []uint64{accSeq}

	var sigsV2 []signing.SignatureV2
	for i, _ := range privs {
		sigV2 := signing.SignatureV2{
			PubKey: nil,
			Data: &signing.SingleSignatureData{
				SignMode:  signing.SignMode_SIGN_MODE_DIRECT,
				Signature: nil,
			},
			Sequence: accSeqs[i],
		}

		sigsV2 = append(sigsV2, sigV2)
	}
	err = txBuilder.SetSignatures(sigsV2...)
	if err != nil {
		return err
	}

	// Second round: all signer infos are set, so each signer can sign.
	sigsV2 = []signing.SignatureV2{}
	for i, _ := range privs {
		signerData := authsigning.SignerData{
			ChainID:       "testing",
			AccountNumber: accNums[i],
			Sequence:      accSeqs[i],
		}
		sigV2, err := SignWithWebAuthnKeyKey(context.TODO(),
			signing.SignMode_SIGN_MODE_DIRECT, signerData,
			txBuilder, encCfg.TxConfig, accSeqs[i])
		if err != nil {
			return err
		}

		sigsV2 = append(sigsV2, sigV2)
	}
	err = txBuilder.SetSignatures(sigsV2...)

	// Generated Protobuf-encoded bytes.
	txBytes, err := encCfg.TxConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return err
	}
	// Compute the SHA-256 hash of the raw bytes.
	hashFinal := sha256.Sum256(txBytes)
	txHashFinal := strings.ToUpper(hex.EncodeToString(hashFinal[:]))
	fmt.Printf("Transaction Hash Of the Signed Payload: %s\n", txHashFinal)

	// Generate a JSON string.
	txJSONBytes, err := encCfg.TxConfig.TxJSONEncoder()(txBuilder.GetTx())
	if err != nil {
		return err
	}
	txJSON := string(txJSONBytes)
	fmt.Printf("the txJSON is %s\n", txJSON)

	// Broadcast the tx via gRPC. We create a new client for the Protobuf Tx
	// service.
	clientCtx := context.Background()
	txSvcClient := txservice.NewServiceClient(grpcConn)
	broadcastEnabled := false // Set to `true` to broadcast the tx.
	//We then call the BroadcastTx method on this client.
	if broadcastEnabled {
		grpcRes, err := txSvcClient.BroadcastTx(
			clientCtx,
			&txservice.BroadcastTxRequest{
				Mode:    txservice.BroadcastMode_BROADCAST_MODE_SYNC,
				TxBytes: txBytes, // Proto-binary of the signed transaction, see previous step.
			},
		)
		if err != nil {
			return err
		}

		fmt.Println(grpcRes.TxResponse.Code) // Should be `0` if the tx is successful
		fmt.Printf("the tx hash is %s\n", grpcRes.TxResponse.TxHash)
	}
	return nil
}

func main() {
	err := sendTxWebAuthn()
	if err != nil {
		panic(err)
	}
}

// SignWithPrivKey signs a given tx with the given webauthn key, and returns the
// corresponding SignatureV2 if the signing is successful.
func SignWithWebAuthnKeyKey(
	ctx context.Context,
	signMode signing.SignMode, signerData authsigning.SignerData,
	txBuilder client.TxBuilder, txConfig client.TxConfig,
	accSeq uint64,
) (signing.SignatureV2, error) {
	var sigV2 signing.SignatureV2

	// Generate the bytes to be signed.
	signBytes, err := authsigning.GetSignBytesAdapter(
		ctx, txConfig.SignModeHandler(), signMode, signerData, txBuilder.GetTx())
	if err != nil {
		return sigV2, err
	}

	// Compute the SHA-256 hash of the raw bytes and then have the user sign it via a FIDO2 device.
	hash := sha256.Sum256(signBytes)
	txHash := strings.ToUpper(hex.EncodeToString(hash[:]))

	fmt.Printf("Transaction Hash in sig bytes to be signed: %s\n", txHash)
	// Sign these bytes using an authenticator.
	signature, err := base64.RawURLEncoding.DecodeString("eyJpZCI6ImJiY1h1S3MxTWFYb3ZaYkxIWEljX1EiLCJ0eXBlIjoicHVibGljLWtleSIsInJhd0lkIjoiYmJjWHVLczFNYVhvdlpiTEhYSWNfUSIsInJlc3BvbnNlIjp7ImNsaWVudERhdGFKU09OIjoiZXlKMGVYQmxJam9pZDJWaVlYVjBhRzR1WjJWMElpd2lZMmhoYkd4bGJtZGxJam9pVFZWUk1FMXFaekZPUkUxNFRrUk9RMUpxWnpGTlJFVjNVWHBCZUZGVlVrUk5WVVV5VVRCSk1VNVZTVE5OVlUwMVVWUlpNMDFVVVhkUFJHUkVVa1ZKTlZKRVFUVk5SRTAwVFVSUk1WSlZXWHBOZWtrMVQxRWlMQ0p2Y21sbmFXNGlPaUpvZEhSd09pOHZiRzlqWVd4b2IzTjBPakU0TURnd0lpd2lZM0p2YzNOUGNtbG5hVzRpT21aaGJITmxmUSIsImF1dGhlbnRpY2F0b3JEYXRhIjoiU1pZTjVZZ09qR2gwTkJjUFpIWmdXNF9rcnJtaWhqTEhtVnp6dW9NZGwyTWRBQUFBQUEiLCJzaWduYXR1cmUiOiJNRVlDSVFETEpjcHJhSG41Z2hzRGUyRGJxWmhDMzlGYTA3SDFFMURKUzBsbE9VNHdLd0loQUxOTU15c3hUZnp0a1NuaHVlVDB1OW8xNURzNEZfTVBaaXo1R3NtX3pZNkkiLCJ1c2VySGFuZGxlIjoiNi1TRzNkcTRoUGJ1QVEifX0")
	if err != nil {
		return sigV2, err
	}

	// Construct the SignatureV2 struct
	sigData := signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: signature,
	}

	sigV2 = signing.SignatureV2{
		PubKey:   nil,
		Data:     &sigData,
		Sequence: accSeq,
	}

	return sigV2, nil
}
