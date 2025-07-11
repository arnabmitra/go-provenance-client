package temp_util

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"google.golang.org/grpc"
	"strings"
)

func PrivKeyFromHex(hexKey string) (*secp256k1.PrivKey, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, err
	}
	if len(keyBytes) != secp256k1.PrivKeySize {
		return nil, errors.New("invalid privkey size")
	}
	return &secp256k1.PrivKey{Key: keyBytes}, nil
}

func GetAccountInfo(grpcConn *grpc.ClientConn, address sdk.AccAddress, cdc codec.Codec) (uint64, uint64, error) {
	authClient := authtypes.NewQueryClient(grpcConn)
	res, err := authClient.Account(context.Background(), &authtypes.QueryAccountRequest{Address: address.String()})
	if err != nil {
		return 0, 0, err
	}

	var acc authtypes.AccountI
	if err := cdc.UnpackAny(res.Account, &acc); err != nil {
		return 0, 0, err
	}

	return acc.GetAccountNumber(), acc.GetSequence(), nil
}

func SignWithPrivKey(
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
		PubKey:   priv.PubKey(),
		Data:     &sigData,
		Sequence: accSeq,
	}

	return sigV2, nil
}
