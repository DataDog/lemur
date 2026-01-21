# Local Development Environment

This directory contains all configuration and scripts for local Lemur development.

## Quick Start

### Standard Setup (No Vault)
```bash
cd local
docker-compose up -d
```

### With Vault Integration
```bash
cd local
docker-compose up -d
```

See [VAULT_JWT_INTEGRATION.md](../VAULT_JWT_INTEGRATION.md) for complete Vault setup.

## Contents

### Certificate Management Scripts
- **`create_cert_with_destinations.py`** - Main script to create certificates with destinations (bypasses plugin upload)
- **`create_default_authority.py`** - Auto-create default authority on container startup

### Authentication Scripts
- **`generate_test_token_constant.py`** - Generate simple JWT tokens for API authentication
- **`jwt_auth_helper.py`** - Enhanced JWT token management with custom claims

### Vault Integration Scripts
- **`setup_vault_integration.py`** - Test and verify Vault integration
- **`vault-init.sh`** - Initialize Vault with Lemur secrets

### Configuration Files
- **`lemur-env`** - Lemur environment variables
- **`vault-env`** - Vault-specific environment variables
- **`pgsql-env`** - PostgreSQL environment variables
- **`src/lemur.conf.py`** - Lemur application configuration (with Vault + JWT)

### Docker Configuration
- **`docker-compose.yml`** - Standard Docker Compose (PostgreSQL, Redis, Lemur)
- **`docker-compose.yml`** - Includes all services (postgres, redis, vault, lemur)
- **`Dockerfile`** - Lemur container image definition
- **`entrypoint`** - Container entrypoint script
- **`supervisor.conf`** - Supervisor process management config

### Other
- **`nginx/`** - Nginx web server configuration
- **`lemur-dev.tar.gz`** - Packaged Lemur source for Docker build

## Usage Examples

### Create Certificate with Destinations
```bash
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py

## Example Tool Usage

The `example_tool.py` demonstrates authentication patterns for tools acting on behalf of users:

```bash
# Interactive login (stores token)
python3 local/example_tool.py login

# Use stored token
python3 local/example_tool.py list-dests
python3 local/example_tool.py create-dest --label "My Destination"

# Service mode with explicit token
TOKEN="eyJhbGci..."
python3 local/example_tool.py --service-token "$TOKEN" list-certs
```

See [SERVICE_AUTHENTICATION.md](../SERVICE_AUTHENTICATION.md) for detailed patterns.
```

### Generate Simple JWT Token
```bash
python3 local/generate_test_token_constant.py
```

### Generate Enhanced JWT Token (with Vault)
```bash
# Basic token
python3 local/jwt_auth_helper.py generate

# Custom user and roles
python3 local/jwt_auth_helper.py generate --user-id 2 --roles admin,security

# Long-lived token
python3 local/jwt_auth_helper.py generate --hours 24
```

### Test Vault Integration
```bash
docker exec -i local-lemur python3 /opt/lemur/local/setup_vault_integration.py
```

## Documentation

- **[../VAULT_JWT_INTEGRATION.md](../VAULT_JWT_INTEGRATION.md)** - Vault and JWT integration guide
- **[../DEVELOPMENT_QUICKSTART.md](../DEVELOPMENT_QUICKSTART.md)** - Quick reference guide
- **[../LOCAL_DEVELOPMENT.md](../LOCAL_DEVELOPMENT.md)** - Complete development guide
- **[../INTEGRATION_TESTING.md](../INTEGRATION_TESTING.md)** - Integration testing guide
