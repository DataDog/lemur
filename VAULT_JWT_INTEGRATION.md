# Vault and JWT Integration for Lemur Local Development

This guide explains how to run Lemur locally with HashiCorp Vault for secrets management and enhanced JWT authentication.

## Overview

### What's Included

- **Vault Integration**: HashiCorp Vault for centralized secrets management
- **Enhanced JWT Auth**: Improved JWT token generation and validation
- **Vault Destination**: Store certificates in Vault (optional)
- **Secret Management**: Database credentials, JWT secrets, encryption keys stored in Vault

## Quick Start

### 1. Start Services with Vault

```bash
cd local
docker-compose up -d
```

This starts:
- **PostgreSQL** - Database
- **Redis** - Cache
- **Vault** - Secrets management (http://localhost:8200)
- **Lemur** - Certificate management

### 2. Verify Vault is Running

```bash
# Check Vault status
docker exec -i docker-vault-1 vault status

# Access Vault UI
open http://localhost:8200/ui
# Token: dev-root-token
```

### 3. Initialize Vault Secrets

The Vault container automatically initializes with Lemur secrets:

```bash
# Manually reinitialize if needed
docker exec -i docker-vault-1 sh /vault/init.sh
```

### 4. Test the Integration

```bash
# Test Vault connection and setup
docker exec -i local-lemur python3 /opt/lemur/local/setup_vault_integration.py
```

## Vault Configuration

### Secrets Structure

Vault stores Lemur secrets in the following structure:

```
secret/
└── lemur/
    ├── database/
    │   ├── username
    │   ├── password
    │   ├── host
    │   ├── port
    │   └── database
    ├── jwt/
    │   ├── secret
    │   ├── algorithm
    │   └── expiration
    └── encryption/
        └── keys
```

### Environment Variables

Configured in `local/vault-env`:

```bash
VAULT_ENABLED=True
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=dev-root-token
VAULT_MOUNT=secret
VAULT_PATH=lemur
VAULT_KV_VERSION=v2
```

### Manual Vault Operations

```bash
# Set VAULT environment
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN='dev-root-token'

# Read a secret
vault kv get secret/lemur/database

# Write a secret
vault kv put secret/lemur/custom \
  key1=value1 \
  key2=value2

# List secrets
vault kv list secret/lemur
```

## JWT Authentication

### Enhanced JWT Configuration

JWT settings are configured in `local/src/lemur.conf.py`:

```python
JWT_ENABLED = True
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_DELTA = 3600  # 1 hour
JWT_AUDIENCE = "lemur-local-dev"
JWT_ISSUER = "lemur"
```

### Generate JWT Tokens

#### Simple Token Generation

```bash
# Generate token for default user
python3 local/jwt_auth_helper.py generate

# Generate token with verbose output
python3 local/jwt_auth_helper.py generate --verbose
```

#### Custom Token Generation

```bash
# Custom user and expiration
python3 local/jwt_auth_helper.py generate \
  --user-id 2 \
  --email admin@example.com \
  --hours 24

# Custom roles
python3 local/jwt_auth_helper.py generate \
  --roles admin,operator,security

# Custom claims
python3 local/jwt_auth_helper.py generate \
  --claims '{"department": "security", "level": "senior"}'
```

### Decode and Validate Tokens

```bash
# Decode and verify token
python3 local/jwt_auth_helper.py decode YOUR_TOKEN_HERE

# Decode without verification (debugging)
python3 local/jwt_auth_helper.py decode YOUR_TOKEN_HERE --no-verify
```

### Use JWT Tokens with API

```bash
# Generate token
TOKEN=$(python3 local/jwt_auth_helper.py generate)

# Use in API requests
curl -k -H "Authorization: Bearer $TOKEN" \
  https://localhost:8447/api/1/certificates
```

## Integration Scripts

### `setup_vault_integration.py`

Tests and verifies Vault integration:

```bash
docker exec -i local-lemur python3 /opt/lemur/local/setup_vault_integration.py
```

**What it does:**
- Tests Vault connection
- Reads secrets from Vault
- Verifies JWT configuration
- (Optional) Creates Vault destination in Lemur

### `jwt_auth_helper.py`

Comprehensive JWT token management:

```bash
# Generate tokens
python3 local/jwt_auth_helper.py generate [OPTIONS]

# Decode tokens
python3 local/jwt_auth_helper.py decode TOKEN

# Show help
python3 local/jwt_auth_helper.py --help
```

## Use Cases

### 1. Development with Vault Secrets

```bash
# Start with Vault
cd local && docker-compose up -d

# Generate JWT token
TOKEN=$(python3 jwt_auth_helper.py generate --hours 8)

# Use for API testing
curl -k -H "Authorization: Bearer $TOKEN" \
  https://localhost:8447/api/1/authorities
```

### 2. Testing Different User Roles

```bash
# Admin user
ADMIN_TOKEN=$(python3 local/jwt_auth_helper.py generate --roles admin)

# Operator user
OPERATOR_TOKEN=$(python3 local/jwt_auth_helper.py generate --roles operator)

# Read-only user
READONLY_TOKEN=$(python3 local/jwt_auth_helper.py generate --roles readonly)
```

### 3. Debugging JWT Issues

```bash
# Generate token with verbose output
python3 local/jwt_auth_helper.py generate --verbose

# Decode existing token
python3 local/jwt_auth_helper.py decode YOUR_TOKEN --no-verify
```

### 4. Certificate Creation with Vault

```bash
# Create certificate (destinations will bypass upload)
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py
```

## Vault UI

Access the Vault UI at http://localhost:8200/ui

**Login:**
- **Method:** Token
- **Token:** `dev-root-token`

**Browse Secrets:**
1. Navigate to `secret/` in the UI
2. Browse to `lemur/` folder
3. View/edit secrets as needed

## Configuration Files

### Docker Compose

- **`docker-compose.yml`** - Standard local dev (no Vault)
- **`docker-compose.yml`** - Includes all services (postgres, redis, vault, lemur)

### Environment Files

- **`lemur-env`** - Standard Lemur configuration
- **`vault-env`** - Vault-specific configuration
- **`pgsql-env`** - PostgreSQL configuration

### Scripts

- **`vault-init.sh`** - Initialize Vault with Lemur secrets
- **`setup_vault_integration.py`** - Test and verify integration
- **`jwt_auth_helper.py`** - JWT token management
- **`generate_test_token_constant.py`** - Simple constant tokens (legacy)

## Troubleshooting

### Vault Not Starting

```bash
# Check logs
docker-compose logs vault

# Restart Vault
docker-compose restart vault
```

### JWT Tokens Invalid

```bash
# Verify JWT secret matches
docker exec -i local-lemur env | grep LEMUR_TOKEN_SECRET

# Check Vault secret
vault kv get secret/lemur/jwt

# Regenerate token
python3 local/jwt_auth_helper.py generate --verbose
```

### Lemur Can't Connect to Vault

```bash
# Check Vault is accessible from Lemur container
docker exec -i local-lemur curl http://vault:8200/v1/sys/health

# Verify environment variables
docker exec -i local-lemur env | grep VAULT
```

### Secrets Not Loading

```bash
# Check Vault initialization
docker exec -i docker-vault-1 vault kv list secret/lemur

# Manually initialize
docker exec -i docker-vault-1 sh /vault/init.sh

# Check Lemur logs
docker-compose logs lemur | grep -i vault
```

## Security Notes

⚠️ **FOR LOCAL DEVELOPMENT ONLY**

- Vault runs in `-dev` mode (not for production)
- Root token is hardcoded (`dev-root-token`)
- JWT secrets are simple for testing
- No TLS/SSL on Vault
- All secrets are for local dev only

**For Production:**
- Use Vault in production mode with proper initialization
- Implement proper authentication (AppRole, Kubernetes, etc.)
- Enable TLS
- Use strong, rotated secrets
- Implement proper access policies

## Comparison: With and Without Vault

### Without Vault (Standard)
```bash
cd local
docker-compose up -d
```
- Secrets in environment files
- Simple JWT tokens
- No central secret management

### With Vault (Integrated)
```bash
cd local
docker-compose up -d
```
- Secrets in Vault
- Enhanced JWT with custom claims
- Central secret management
- Vault UI for secret browsing
- Production-like setup

## Next Steps

1. **Explore Vault UI**: http://localhost:8200/ui
2. **Generate Custom Tokens**: Test different roles and claims
3. **Create Certificates**: Use integrated auth tokens
4. **Test Secret Rotation**: Update secrets in Vault dynamically

## See Also

- [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md) - Standard local development
- [INTEGRATION_TESTING.md](INTEGRATION_TESTING.md) - API integration testing
- [HashiCorp Vault Docs](https://www.vaultproject.io/docs)
- [JWT.io](https://jwt.io) - JWT debugging tool
