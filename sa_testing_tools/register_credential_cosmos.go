package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/arnabmitra/simple-provenance-client/sa_testing_tools/temp_util"
	"github.com/cosmos/cosmos-sdk/client/tx"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	testutilmod "github.com/cosmos/cosmos-sdk/types/module/testutil"
	txservice "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth"
	xauthsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	"github.com/cosmos/cosmos-sdk/x/bank"
	smartaccountmodule "github.com/provenance-io/provenance/x/smartaccounts/module"
	"github.com/provenance-io/provenance/x/smartaccounts/types"
	"google.golang.org/grpc"
	"log"
	"strings"
)

func init() {
	// Set the Bech32 prefix to "tp"
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("tp", "tp"+sdk.PrefixPublic)
	config.Seal()
}

func broadcastTxCosmos() error {
	// Choose your codec: Amino or Protobuf. Here, we use Protobuf, given by the following function.
	encCfg := testutilmod.MakeTestEncodingConfig(bank.AppModuleBasic{}, auth.AppModuleBasic{}, smartaccountmodule.AppModuleBasic{})

	// Create a new TxBuilder.
	txBuilder := encCfg.TxConfig.NewTxBuilder()
	// this is just a test account, for local testing
	privKey, _ := temp_util.PrivKeyFromHex("f109a351d02607503221102905585f29c01dce1e9fb8a3afcb352f357021d2d7")
	pub := privKey.PubKey()
	addr := sdk.AccAddress(pub.Address())
	fmt.Printf("the from address is %s\n", addr)

	// Generate keys for testing
	privKeyToRegister := secp256k1.GenPrivKey()
	pubKey := privKeyToRegister.PubKey()

	fmt.Printf("Generated private key (hex): %s\n", hex.EncodeToString(privKeyToRegister.Bytes()))

	// Test 1: Register credential for a new smart account
	pubKeyAny, err := codectypes.NewAnyWithValue(pubKey)
	// base64 this proto object and print it

	// Create the MsgRegisterCosmosCredential message
	msg := &types.MsgRegisterCosmosCredential{
		Sender: addr.String(),
		Pubkey: pubKeyAny,
	}

	err = txBuilder.SetMsgs(msg)
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
	accNum, accSeq, err := temp_util.GetAccountInfo(grpcConn, addr, encCfg.Codec)
	if err != nil {
		return err
	}

	privs := []cryptotypes.PrivKey{privKey}
	accNums := []uint64{accNum}
	accSeqs := []uint64{accSeq}

	var sigsV2 []signing.SignatureV2
	for i, priv := range privs {
		sigV2 := signing.SignatureV2{
			PubKey: priv.PubKey(),
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

	txBytes1, err := encCfg.TxConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return err
	}

	// Compute the SHA-256 hash of the raw bytes.
	hash := sha256.Sum256(txBytes1)
	txHash := strings.ToUpper(hex.EncodeToString(hash[:]))

	fmt.Printf("Transaction Hash: %s\n", txHash)

	// Second round: all signer infos are set, so each signer can sign.
	sigsV2 = []signing.SignatureV2{}
	for i, priv := range privs {
		signerData := xauthsigning.SignerData{
			ChainID:       "testing",
			AccountNumber: accNums[i],
			Sequence:      accSeqs[i],
		}
		sigV2, err := tx.SignWithPrivKey(context.TODO(),
			signing.SignMode_SIGN_MODE_DIRECT, signerData,
			txBuilder, priv, encCfg.TxConfig, accSeqs[i])
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
	fmt.Printf("Transaction Hash: %s\n", txHashFinal)

	// Generate a JSON string.
	txJSONBytes, err := encCfg.TxConfig.TxJSONEncoder()(txBuilder.GetTx())
	if err != nil {
		return err
	}
	txJSON := string(txJSONBytes)
	fmt.Printf("the txJSON is %s\n", txJSON)

	// Broadcast the tx via gRPC. We create a new client for the Protobuf Tx service.
	clientCtx := context.Background()
	txSvcClient := txservice.NewServiceClient(grpcConn)
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
	return nil
}

func main() {
	err := broadcastTxCosmos()
	if err != nil {
		log.Fatalf("failed to broadcast transaction: %v", err)
	}
}
