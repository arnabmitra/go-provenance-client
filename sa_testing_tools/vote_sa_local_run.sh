#!/bin/bash
PROVENANCE_DEV_DIR=~/provenance

COMMON_TX_FLAGS="--gas auto --gas-adjustment 2 --chain-id testing --keyring-backend test --yes -o json  --gas-prices 1nhash "

# Vote 'yes' on the newly created proposal
${PROVENANCE_DEV_DIR}/build/provenanced tx -t gov vote 1 yes ${COMMON_TX_FLAGS}  --from validator --home ${PROVENANCE_DEV_DIR}/build/run/provenanced

echo "Vote submitted successfully."
