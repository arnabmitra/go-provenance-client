package main

import (
	"context"
	"cosmossdk.io/math"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/arnabmitra/simple-provenance-client/sa_testing_tools/temp_util"
	"github.com/cosmos/cosmos-sdk/client/tx"
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

func broadcastTx() error {
	// Choose your codec: Amino or Protobuf. Here, we use Protobuf, given by the following function.
	encCfg := testutilmod.MakeTestEncodingConfig(bank.AppModuleBasic{}, auth.AppModuleBasic{}, smartaccountmodule.AppModuleBasic{})

	// Create a new TxBuilder.
	txBuilder := encCfg.TxConfig.NewTxBuilder()
	// this is just a test account, for local testing
	privKey, _ := temp_util.PrivKeyFromHex("f109a351d02607503221102905585f29c01dce1e9fb8a3afcb352f357021d2d7")
	pub := privKey.PubKey()
	addr := sdk.AccAddress(pub.Address())
	fmt.Printf("the from address is %s\n", addr)

	// Create the MsgRegisterFido2Credential message
	msg := &types.MsgRegisterFido2Credential{
		Sender: addr.String(),
		//EncodedAttestation: "eyJpZCI6ImJiY1h1S3MxTWFYb3ZaYkxIWEljX1EiLCJyYXdJZCI6ImJiY1h1S3MxTWFYb3ZaYkxIWEljX1EiLCJyZXNwb25zZSI6eyJhdHRlc3RhdGlvbk9iamVjdCI6Im8yTm1iWFJrYm05dVpXZGhkSFJUZEcxMG9HaGhkWFJvUkdGMFlWaVVTWllONVlnT2pHaDBOQmNQWkhaZ1c0X2tycm1paGpMSG1Wenp1b01kbDJOZEFBQUFBT3FialdaTkFSMGhQT1MydEl5MWRkUUFFRzIzRjdpck5UR2w2TDJXeXgxeUhQMmxBUUlESmlBQklWZ2doNUpKTTZQNVpPTm82OFFNbnUybVQzQnBnYUtOUlJERGZkRVpDOEQwclo0aVdDQkR1M2tZUGM3a0o2QnVLTmdvQXMzZjVLdkVWZ0pTZG1LTDJpU1k0cy1pWHciLCJjbGllbnREYXRhSlNPTiI6ImV5SjBlWEJsSWpvaWQyVmlZWFYwYUc0dVkzSmxZWFJsSWl3aVkyaGhiR3hsYm1kbElqb2lUMmhuYWt4cGVEUk9ZV2xGWTJaelIxQnNTMG80Y0RSVFZuQjVhV05WTlZwWlEyeHZjemR1ZG1keVl5SXNJbTl5YVdkcGJpSTZJbWgwZEhBNkx5OXNiMk5oYkdodmMzUTZNVGd3T0RBaWZRIn0sInR5cGUiOiJwdWJsaWMta2V5IiwiYXV0aGVudGljYXRvckF0dGFjaG1lbnQiOiJwbGF0Zm9ybSJ9",
		EncodedAttestation: "eyJpZCI6InAtOTNIaVpmRVpQX0ZYNURNY3dvaGciLCJyYXdJZCI6InAtOTNIaVpmRVpQX0ZYNURNY3dvaGciLCJyZXNwb25zZSI6eyJhdHRlc3RhdGlvbk9iamVjdCI6Im8yTm1iWFJrYm05dVpXZGhkSFJUZEcxMG9HaGhkWFJvUkdGMFlWaVVTWllONVlnT2pHaDBOQmNQWkhaZ1c0X2tycm1paGpMSG1Wenp1b01kbDJOZEFBQUFBT3FialdaTkFSMGhQT1MydEl5MWRkUUFFS2Z2ZHg0bVh4R1RfeFYtUXpITUtJYWxBUUlESmlBQklWZ2dWM2JBbjVaejJ1Z0JuRm9QVXIyR0RIaXZTaE50MjYxWmROaUpuaDVYV00waVdDQmlFblc0MGtzYThreFp6RmkxcV9RN2x0MmU5ZnhnOThXZDN0S0hDZ19tX1EiLCJjbGllbnREYXRhSlNPTiI6ImV5SjBlWEJsSWpvaWQyVmlZWFYwYUc0dVkzSmxZWFJsSWl3aVkyaGhiR3hsYm1kbElqb2lSbTFWVnpaRlVXUnRTMEpOWlMxNlJXRnRaR1ZhYzFOU1lub3RSekZxWWpOellYbDBXVWgxYzJzMlFTSXNJbTl5YVdkcGJpSTZJbWgwZEhBNkx5OXNiMk5oYkdodmMzUTZNVGd3T0RBaWZRIn0sInR5cGUiOiJwdWJsaWMta2V5IiwiYXV0aGVudGljYXRvckF0dGFjaG1lbnQiOiJwbGF0Zm9ybSJ9", // foo6
		//EncodedAttestation: "eyJpZCI6InU0bS03c24zTEhjN0xQRkNHUUZfSDZ3SVRkYyIsInJhd0lkIjoidTRtLTdzbjNMSGM3TFBGQ0dRRl9INndJVGRjIiwicmVzcG9uc2UiOnsiYXR0ZXN0YXRpb25PYmplY3QiOiJvMk5tYlhSa2JtOXVaV2RoZEhSVGRHMTBvR2hoZFhSb1JHRjBZVmlZU1pZTjVZZ09qR2gwTkJjUFpIWmdXNF9rcnJtaWhqTEhtVnp6dW9NZGwyTmRBQUFBQVB2OE1BY1ZUazdNakF0dUFnVlgxNzBBRkx1SnZ1N0o5eXgzT3l6eFFoa0JmeC1zQ0UzWHBRRUNBeVlnQVNGWUlJcnNiZnE3OTRvVGNka09BdzN0VW9RWjdkdmdvUTFzTGFIQUQ4S1VTZHhBSWxnZ2poVWYzSm1acHg4UTg0UlNydzVjWGxhLVZrRFlFMzhUczBCVEc0RkZ6bXMiLCJjbGllbnREYXRhSlNPTiI6ImV5SjBlWEJsSWpvaWQyVmlZWFYwYUc0dVkzSmxZWFJsSWl3aVkyaGhiR3hsYm1kbElqb2lPRzlrVlZWTldFUlRhelpxVFZOcmJuaFBRbGQ1TlhWSlFWVnlSVEYxUlRseGFFMUpVVlpGVUc0NFJTSXNJbTl5YVdkcGJpSTZJbWgwZEhBNkx5OXNiMk5oYkdodmMzUTZNVGd3T0RBaWZRIn0sInR5cGUiOiJwdWJsaWMta2V5IiwiYXV0aGVudGljYXRvckF0dGFjaG1lbnQiOiJwbGF0Zm9ybSJ9", // foo8
		//EncodedAttestation: "eyJpZCI6Ii1oV2VveWlJVDRQYy1ETm53YTdFb3VQWmVVcyIsInJhd0lkIjoiLWhXZW95aUlUNFBjLURObndhN0VvdVBaZVVzIiwicmVzcG9uc2UiOnsiYXR0ZXN0YXRpb25PYmplY3QiOiJvMk5tYlhSa2JtOXVaV2RoZEhSVGRHMTBvR2hoZFhSb1JHRjBZVmlZU1pZTjVZZ09qR2gwTkJjUFpIWmdXNF9rcnJtaWhqTEhtVnp6dW9NZGwyTmRBQUFBQVB2OE1BY1ZUazdNakF0dUFnVlgxNzBBRlBvVm5xTW9pRS1EM1Bnelo4R3V4S0xqMlhsTHBRRUNBeVlnQVNGWUlGdGxXSGNCQ1dDWjh2NWdDMUxJbzNldnVxWG1sM2F2cDlkMHBnSjZieUlfSWxnZ291bFNLWkVnMGRTbEpYS3VzZktJUkFjYkpZeG0wZS1xT2Q5bW1JZUFULVkiLCJjbGllbnREYXRhSlNPTiI6ImV5SjBlWEJsSWpvaWQyVmlZWFYwYUc0dVkzSmxZWFJsSWl3aVkyaGhiR3hsYm1kbElqb2lPVlY1TjNaWlQzY3lXVTlCTlhsaFRUQmlkWFp5UlVVM2JFTkhPR3N5V1VVeGIwODFTSFpCVTFsdk5DSXNJbTl5YVdkcGJpSTZJbWgwZEhBNkx5OXNiMk5oYkdodmMzUTZNVGd3T0RBaWZRIn0sInR5cGUiOiJwdWJsaWMta2V5IiwiYXV0aGVudGljYXRvckF0dGFjaG1lbnQiOiJwbGF0Zm9ybSJ9", // foo12
		//EncodedAttestation: "eyJpZCI6InFnTW1NbGQ3SDhtekFoSzdrSjRHV1Q0UHltSSIsInJhd0lkIjoicWdNbU1sZDdIOG16QWhLN2tKNEdXVDRQeW1JIiwicmVzcG9uc2UiOnsiYXR0ZXN0YXRpb25PYmplY3QiOiJvMk5tYlhSa2JtOXVaV2RoZEhSVGRHMTBvR2hoZFhSb1JHRjBZVmlZU1pZTjVZZ09qR2gwTkJjUFpIWmdXNF9rcnJtaWhqTEhtVnp6dW9NZGwyTmRBQUFBQVB2OE1BY1ZUazdNakF0dUFnVlgxNzBBRktvREpqSlhleF9Kc3dJU3U1Q2VCbGstRDhwaXBRRUNBeVlnQVNGWUlNbVdQSDExY0NfY3FBeFp1ZFJvMERIY01VTHZQeDQ2VXI0cTBtb0Z4dUlnSWxnZ0VTVEJ1S3JBeE1nbmdhLUFHOXc0SmMzclN1YWZ1a084LVFXX3dVQk5xdUUiLCJjbGllbnREYXRhSlNPTiI6ImV5SjBlWEJsSWpvaWQyVmlZWFYwYUc0dVkzSmxZWFJsSWl3aVkyaGhiR3hsYm1kbElqb2lWRVJ0UzJKT1pFRnNjVmhzT1RKR1NWUnhOR3A2T1dwTE1VaGtRMjlLU1dzeGMyNHpWVXgyVkRkNlFTSXNJbTl5YVdkcGJpSTZJbWgwZEhBNkx5OXNiMk5oYkdodmMzUTZNVGd3T0RBaWZRIn0sInR5cGUiOiJwdWJsaWMta2V5IiwiYXV0aGVudGljYXRvckF0dGFjaG1lbnQiOiJwbGF0Zm9ybSJ9", // foo12
		UserIdentifier: "foo6",
	}

	err := txBuilder.SetMsgs(msg)
	if err != nil {
		return err
	}

	// Create a connection to the gRPC server.
	grpcConn, _ := grpc.Dial(
		"127.0.0.1:9090",    // Or your gRPC server address.
		grpc.WithInsecure(), // The Cosmos SDK doesn't support any transport security mechanism.
	)
	defer grpcConn.Close()

	// Broadcast the tx via gRPC. We create a new client for the Protobuf Tx service.
	clientCtx := context.Background()
	txSvcClient := txservice.NewServiceClient(grpcConn)

	// Get account number and sequence dynamically. This is needed for both simulation and signing.
	accNum, accSeq, err := temp_util.GetAccountInfo(grpcConn, addr, encCfg.Codec)
	if err != nil {
		return err
	}

	// To simulate a transaction, we need to build a temporary transaction with a dummy signature.
	// The signature doesn't need to be valid; it just needs to be present with the correct public key
	// and sequence number for the simulation to accurately estimate gas costs.
	simSigV2 := signing.SignatureV2{
		PubKey: pub,
		Data: &signing.SingleSignatureData{
			SignMode:  signing.SignMode_SIGN_MODE_DIRECT,
			Signature: nil, // A nil signature is a valid dummy signature.
		},
		Sequence: accSeq,
	}
	if err := txBuilder.SetSignatures(simSigV2); err != nil {
		return fmt.Errorf("failed to set dummy signature for simulation: %w", err)
	}

	// Encode the transaction with the dummy signature for the simulation request.
	simTxBytes, err := encCfg.TxConfig.TxEncoder()(txBuilder.GetTx())
	if err != nil {
		return fmt.Errorf("failed to encode tx for simulation: %w", err)
	}

	// Run the simulation.
	simRes, err := txSvcClient.Simulate(
		context.Background(),
		&txservice.SimulateRequest{
			TxBytes: simTxBytes,
		},
	)
	if err != nil {
		return fmt.Errorf("transaction simulation failed: %w", err)
	}

	// We'll use the simulated gas used and add a buffer (e.g., 50%) to get our gas limit.
	// This helps prevent "out of gas" errors if the real execution uses slightly more gas.
	const gasAdjustment = 1.5
	gasLimit := uint64(float64(simRes.GasInfo.GasUsed) * gasAdjustment)

	// Define the gas price. This could be a constant or fetched from chain params.
	// For Provenance, a common gas price is 1905nhash.
	gasPrice, err := sdk.ParseCoinNormalized("1nhash")
	if err != nil {
		return fmt.Errorf("failed to parse gas price: %w", err)
	}

	// Calculate the fee by multiplying the gas limit by the gas price.
	feeAmount := gasPrice.Amount.Mul(math.NewInt(int64(gasLimit)))
	fees := sdk.NewCoins(sdk.NewCoin(gasPrice.Denom, feeAmount))

	fmt.Printf("Dynamic Estimation Complete:\n")
	fmt.Printf("  - Gas Used (Simulated): %d\n", simRes.GasInfo.GasUsed)
	fmt.Printf("  - Gas Limit (%.2fx buffer): %d\n", gasAdjustment, gasLimit)
	fmt.Printf("  - Fee Calculated: %s\n", fees.String())

	// Now, set the dynamically estimated gas limit and fee on the transaction builder.
	txBuilder.SetGasLimit(gasLimit)
	txBuilder.SetFeeAmount(fees)

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
	err := broadcastTx()
	if err != nil {
		log.Fatalf("failed to broadcast transaction: %v", err)
	}
}
