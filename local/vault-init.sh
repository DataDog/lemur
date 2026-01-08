#!/bin/sh
# Initialize Vault with Lemur secrets

set -e

echo "Waiting for Vault to be ready..."
sleep 5

export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='dev-root-token'

echo "Initializing Vault secrets for Lemur..."

# Enable KV v2 secrets engine
vault secrets enable -version=2 -path=secret kv || echo "KV engine already enabled"

# Create sample secrets for Lemur
vault kv put secret/lemur/database \
  username=lemur \
  password=12345 \
  host=postgres \
  port=5432 \
  database=lemur

vault kv put secret/lemur/jwt \
  secret=bG9jYWwtZGV2LXNlY3JldC1mb3ItdGVzdGluZy1vbmx5LWRvLW5vdC11c2UtaW4tcHJvZA== \
  algorithm=HS256 \
  expiration=3600

vault kv put secret/lemur/encryption \
  keys=2ryT1gsMantc_WigzJvz0EPxZBzKn1aK8WpzWE3RfRk=

# Create policy for Lemur
vault policy write lemur-policy - <<EOF
path "secret/data/lemur/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/lemur/*" {
  capabilities = ["list"]
}
EOF

echo "✅ Vault initialized successfully!"
echo "🔑 Root token: dev-root-token"
echo "🌐 Vault UI: http://localhost:8200/ui"
