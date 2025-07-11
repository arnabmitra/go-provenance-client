package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/cosmos/cosmos-sdk/client"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/testutil/testdata"
	sdk "github.com/cosmos/cosmos-sdk/types"
	testutilmod "github.com/cosmos/cosmos-sdk/types/module/testutil"
	txservice "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	"github.com/cosmos/cosmos-sdk/x/auth"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
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

func sendTxAlternateCosmos() error {
	// Choose your codec: Amino or Protobuf. Here, we use Protobuf, given by the
	// following function.
	encCfg := testutilmod.MakeTestEncodingConfig(bank.AppModuleBasic{}, auth.AppModuleBasic{})

	// Create a new TxBuilder.
	txBuilder := encCfg.TxConfig.NewTxBuilder()
	var priv_key cryptotypes.PrivKey
	// this is to test a false signing condition
	failToSendBecauseKeyIsNotOnAccount := false
	if failToSendBecauseKeyIsNotOnAccount {
		priv_key, _, _ = testdata.KeyTestPubAddr()
	} else {
		// this is just a test account, for local testing
		priv_key, _ = temp_util.PrivKeyFromHex("0d49a7e76ad2558776a93438892ecee6599995907739cfa644233c8503b13783")

	}
	addr := sdk.MustAccAddressFromBech32("tp1w40q3q7v26petw6g5stz5dt9xsezgnzalxgw8x")
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
	accNum, accSeq, err := temp_util.GetAccountInfo(grpcConn, addr, encCfg.Codec)
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
	for i, priv := range privs {
		signerData := authsigning.SignerData{
			ChainID:       "testing",
			AccountNumber: accNums[i],
			Sequence:      accSeqs[i],
		}
		// Generate the bytes to be signed.
		signBytes, err := authsigning.GetSignBytesAdapter(
			context.TODO(), encCfg.TxConfig.SignModeHandler(), signing.SignMode_SIGN_MODE_DIRECT, signerData, txBuilder.GetTx())
		if err != nil {
			return err
		}

		// Compute the SHA-256 hash of the raw bytes and then have the user sign it via a FIDO2 device.
		hash := sha256.Sum256(signBytes)
		txHash := strings.ToUpper(hex.EncodeToString(hash[:]))
		fmt.Printf("Transaction Hash: %s\n", txHash)

		sigV2, err := SignWithPrivKeyNoPubKeySet(context.TODO(),
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
	//txJSONBytes, err := encCfg.TxConfig.TxJSONEncoder()(txBuilder.GetTx())
	//if err != nil {
	//	return err
	//}
	//txJSON := string(txJSONBytes)
	//fmt.Printf("the txJSON is %s\n", txJSON)

	// Broadcast the tx via gRPC. We create a new client for the Protobuf Tx
	// service.
	clientCtx := context.Background()
	txSvcClient := txservice.NewServiceClient(grpcConn)
	//We then call the BroadcastTx method on this client.
	broadcastEnabled := true // Set to `true` to broadcast the tx.
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
		fmt.Println(grpcRes.TxResponse.Logs)
		fmt.Printf("the tx hash is %s\n", grpcRes.TxResponse.TxHash)
	}
	return nil
}

func main() {
	err := sendTxAlternateCosmos()
	if err != nil {
		panic(err)
	}
}

func SignWithPrivKeyNoPubKeySet(
	ctx context.Context,
	signMode signing.SignMode, signerData authsigning.SignerData,
	txBuilder client.TxBuilder, priv cryptotypes.PrivKey, txConfig client.TxConfig,
	accSeq uint64,
) (signing.SignatureV2, error) {
	var sigV2 signing.SignatureV2

	// Generate the bytes to be signed.
	signBytes, err := authsigning.GetSignBytesAdapter(
		ctx, txConfig.SignModeHandler(), signMode, signerData, txBuilder.GetTx())
	if err != nil {
		return sigV2, err
	}
	// Compute the SHA-256 hash of the raw bytes.
	hashFinal := sha256.Sum256(signBytes)
	txHashFinal := strings.ToUpper(hex.EncodeToString(hashFinal[:]))
	fmt.Printf("Transaction Hash -----: %s\n", txHashFinal)
	// Sign those bytes
	signature, err := priv.Sign(signBytes)
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
