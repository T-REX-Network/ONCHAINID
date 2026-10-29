#!/usr/bin/env bash
# Deploys the ONCHAINID stack to Base Sepolia and records every address to
# deployments/baseSepolia.json. Requires .env with DEPLOYER_PRIVATE_KEY,
# ALCHEMY_KEY, BASESCAN_API_KEY (see .env.example).
set -euo pipefail
cd "$(dirname "$0")/.."
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1
[ -f .env ] && { set -a; source .env; set +a; }
: "${DEPLOYER_PRIVATE_KEY:?set in .env}"
: "${ALCHEMY_KEY:?set in .env}"
CHAIN_ID=84532

echo "Deploying ONCHAINID to Base Sepolia..."
forge script scripts/DeployOnchainID.s.sol --rpc-url baseSepolia --broadcast --verify

RUN="broadcast/DeployOnchainID.s.sol/$CHAIN_ID/run-latest.json"

addr_for() {
    python3 -c '
import json, sys
name, path = sys.argv[1], sys.argv[2]
d = json.load(open(path))
for tx in d["transactions"]:
    if tx.get("contractName") == name and tx.get("transactionType") == "CREATE":
        print(tx["contractAddress"])
        sys.exit(0)
sys.exit(1)
' "$1" "$RUN"
}

TX_HASH=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["transactions"][0]["hash"])' "$RUN")
BLOCK=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(int(d["receipts"][0]["blockNumber"],16))' "$RUN")

IDENTITY_UTILITIES_IMPL=$(addr_for IdentityUtilities)
IDENTITY_UTILITIES_PROXY=$(addr_for IdentityUtilitiesProxy)
KEY_APPROVAL_MODULE=$(addr_for KeyApprovalModule)
ACCESS_MANAGER=$(addr_for AccessManager)
IDENTITY_FACTORY=$(addr_for IdentityFactory)
REPUTATION_REGISTRY=$(addr_for ReputationRegistry)
ERC734_VALIDATOR=$(addr_for ERC734Validator)
IDENTITY_IMPL=$(addr_for Identity)
WEBAUTHN_VERIFIER=$(addr_for ERC7913WebAuthnVerifier)

# The beacon is deployed inside idFactory.initializeBeacon(...), an internal
BEACON=$(cast call "$IDENTITY_FACTORY" "beacon()(address)" --rpc-url baseSepolia)

mkdir -p deployments
cat > deployments/baseSepolia.json <<JSON
{
  "chainId": $CHAIN_ID,
  "deployer": "$(cast wallet address --private-key "$DEPLOYER_PRIVATE_KEY")",
  "accessManager": "$ACCESS_MANAGER",
  "identityFactory": "$IDENTITY_FACTORY",
  "beacon": "$BEACON",
  "erc734Validator": "$ERC734_VALIDATOR",
  "identityImpl": "$IDENTITY_IMPL",
  "keyApprovalModule": "$KEY_APPROVAL_MODULE",
  "reputationRegistry": "$REPUTATION_REGISTRY",
  "identityUtilitiesImpl": "$IDENTITY_UTILITIES_IMPL",
  "identityUtilitiesProxy": "$IDENTITY_UTILITIES_PROXY",
  "webAuthnVerifier": "$WEBAUTHN_VERIFIER",
  "deployBlock": $BLOCK,
  "txHash": "$TX_HASH"
}
JSON

echo "Wrote deployments/baseSepolia.json"
echo "IdentityFactory: $IDENTITY_FACTORY"
echo "AccessManager:   $ACCESS_MANAGER"
