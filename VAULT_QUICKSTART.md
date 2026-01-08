# Vault + JWT Quick Reference

## 🚀 Quick Start (60 seconds)

```bash
# 1. Start services with Vault
cd local && docker-compose up -d

# 2. Wait for initialization (30 seconds)
sleep 30

# 3. Test integration
./test_vault_jwt.sh

# 4. Generate JWT token
python3 jwt_auth_helper.py generate
```

**Done!** 🎉

## 🔑 Access Points

| Service | URL | Credentials |
|---------|-----|-------------|
| Lemur UI | https://localhost:8447 | user / pass |
| Vault UI | http://localhost:8200/ui | Token: `dev-root-token` |
| PostgreSQL | localhost:5432 | lemur / 12345 |

## 💻 Common Commands

### Generate JWT Tokens

```bash
# Simple token
python3 local/jwt_auth_helper.py generate

# With verbose output
python3 local/jwt_auth_helper.py generate --verbose

# Custom user and roles
python3 local/jwt_auth_helper.py generate --user-id 2 --roles admin,security

# Long-lived (24h)
python3 local/jwt_auth_helper.py generate --hours 24

# With custom claims
python3 local/jwt_auth_helper.py generate --claims '{"dept":"security"}'
```

### Use JWT with API

```bash
# Generate and use
TOKEN=$(python3 local/jwt_auth_helper.py generate)
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8447/api/1/certificates

# One-liner
curl -k -H "Authorization: Bearer $(python3 local/jwt_auth_helper.py generate)" \
  https://localhost:8447/api/1/certificates
```

### Vault Operations

```bash
# Set environment
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN='dev-root-token'

# Read secret
vault kv get secret/lemur/jwt

# Write secret
vault kv put secret/lemur/custom key=value

# List secrets
vault kv list secret/lemur
```

### Create Certificates

```bash
# Standard creation
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py

# Custom certificate
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py \
  my-cert.example.com --dest 5 --dest 7
```

## 🔍 Troubleshooting

### Vault Not Starting
```bash
docker-compose logs vault
docker-compose restart vault
```

### JWT Token Issues
```bash
# Check secret
vault kv get secret/lemur/jwt

# Regenerate
python3 local/jwt_auth_helper.py generate --verbose

# Decode existing token
python3 local/jwt_auth_helper.py decode YOUR_TOKEN
```

### Integration Test
```bash
# Run full test suite
./local/test_vault_jwt.sh

# Manual verification
docker exec -i local-lemur python3 /opt/lemur/local/setup_vault_integration.py
```

## 📊 Secret Structure

```
secret/lemur/
├── database/
│   ├── username: lemur
│   ├── password: 12345
│   ├── host: postgres
│   ├── port: 5432
│   └── database: lemur
├── jwt/
│   ├── secret: bG9j...cHJvZA==
│   ├── algorithm: HS256
│   └── expiration: 3600
└── encryption/
    └── keys: 2ryT...fRk=
```

## 🎯 Use Cases

### 1. API Testing
```bash
TOKEN=$(python3 local/jwt_auth_helper.py generate --hours 8)
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8447/api/1/authorities
```

### 2. Different User Roles
```bash
# Admin
ADMIN=$(python3 local/jwt_auth_helper.py generate --roles admin)

# Operator  
OPS=$(python3 local/jwt_auth_helper.py generate --roles operator)

# Custom
CUSTOM=$(python3 local/jwt_auth_helper.py generate --roles security,compliance)
```

### 3. Certificate Creation
```bash
# Generate token
TOKEN=$(python3 local/jwt_auth_helper.py generate --hours 24)

# Create certificate
docker exec -i local-lemur \
  python3 /opt/lemur/local/create_cert_with_destinations.py my-cert.example.com
```

## 📱 Services Status

```bash
# Check all services
docker-compose ps

# Check Vault health
curl -s http://localhost:8200/v1/sys/health | python3 -m json.tool

# Check Lemur health
curl -k -s https://localhost:8447/api/1/healthcheck
```

## 🛑 Stop Services

```bash
# Stop all
cd local && docker-compose down

# Stop and remove volumes
docker-compose down -v
```

## 📚 Full Documentation

- **Complete Guide**: [VAULT_JWT_INTEGRATION.md](VAULT_JWT_INTEGRATION.md)
- **Summary**: [VAULT_INTEGRATION_SUMMARY.md](VAULT_INTEGRATION_SUMMARY.md)
- **Local Dev**: [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md)

---

**Quick Help**: Run `./local/test_vault_jwt.sh` for automated testing and diagnostics
