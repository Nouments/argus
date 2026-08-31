#!/usr/bin/env bash
set -euo pipefail

# Usage: VAULT_ADDR and VAULT_TOKEN must be set in env.
# This script generates a 32-byte hex key and writes it to Vault KV v2 at path secret/data/siem/buffer

if [ -z "${VAULT_ADDR:-}" ] || [ -z "${VAULT_TOKEN:-}" ]; then
  echo "Please set VAULT_ADDR and VAULT_TOKEN"
  exit 1
fi

SECRET_PATH=${1:-secret/data/siem/buffer}
KEY=$(openssl rand -hex 32)

cat <<EOF > /tmp/payload.json
{ "data": { "key": "${KEY}" } }
EOF

curl -sS --header "X-Vault-Token: ${VAULT_TOKEN}" --request POST \
  --data @/tmp/payload.json ${VAULT_ADDR}/v1/${SECRET_PATH}

echo "Wrote key to ${SECRET_PATH} (hex). Keep VAULT_TOKEN secure."
