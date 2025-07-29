#!/bin/bash
PROVENANCE_DEV_DIR=~/provenance

COMMON_TX_FLAGS="--gas auto --gas-adjustment 2 --chain-id testing --keyring-backend test --yes -o json  --gas-prices 1nhash "


${PROVENANCE_DEV_DIR}/build/provenanced tx smartaccounts update-params true "15" --title="Update Smart Account Params" --summary="Enable smart accounts and set max credentials to 10" --deposit="1000000000nhash" \
 ${COMMON_TX_FLAGS}  --from validator --home ${PROVENANCE_DEV_DIR}/build/run/provenanced -t

echo "proposal submitted successfully."
