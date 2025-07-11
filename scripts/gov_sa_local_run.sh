#!/bin/bash
x=1
PROVENANCE_DEV_DIR=~/provenance-priv

COMMON_TX_FLAGS="--gas auto --gas-adjustment 2 --chain-id chain-local --keyring-backend test --yes -o json"



 tx_hash=$(${PROVENANCE_DEV_DIR}/build/provenanced tx gov submit-proposal ./proposal_sa.json \
  --from validator \
  --home ${PROVENANCE_DEV_DIR}/build/run/provenanced \
  --keyring-backend test --chain-id testing --gas auto --gas-adjustment 1.4  --gas-prices 1905nhash  \
  --testnet --yes -o json --broadcast-mode sync| jq -r '.txhash')
  x=$(( x+1 ))

  while true; do
     sleep 3
      status=$(${PROVENANCE_DEV_DIR}/build/provenanced query tx $tx_hash --output json | jq -r '.code')
      if [ -z "$status" ]; then
          echo "Transaction $tx_hash is still pending..."
          sleep 3
      else
          echo "Transaction $tx_hash confirmed in a block!"
          break
      fi
  done
