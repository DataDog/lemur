# Development Quick Start

## TL;DR - Create Certificate with Destinations Locally

### Standard Setup
```bash
# Start environment
cd local && docker-compose up -d

# Create certificate with COA and AWS destinations
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py

# View in browser
open https://localhost:8447
# Login: user / pass
```

### With Vault Integration
```bash
# Start environment with Vault
cd local && docker-compose up -d

# Verify Vault
open http://localhost:8200/ui
# Token: dev-root-token

# Create certificate
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py
```

## Available Scripts

All scripts are located in the `local/` folder.

### `create_cert_with_destinations.py` - Main Script
Create certificates with destinations for local testing (bypasses credential requirements).

```bash
# Auto-discover destinations
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py

# Custom certificate name
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py my-cert.example.com

# Specific destination IDs
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py my-cert.example.com --dest 11 --dest 12

# Show help
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py --help
```

### `generate_test_token_constant.py` - API Authentication
Generate JWT tokens for API requests.

```bash
TOKEN=$(python3 local/generate_test_token_constant.py)
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8447/api/1/certificates
```

### `create_authority.sh` - Create Authority
Create a test certificate authority via API.

```bash
./local/create_authority.sh
```

## Integration Test Connection Info

**Quick Reference for CI/CD:**

```bash
# Endpoint
LEMUR_URL="https://localhost:8447/api/1"

# Constant Token (valid until Jan 2027)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI"

# User Credentials
USERNAME="user"
PASSWORD="pass"

# Test
curl -k -H "Authorization: Bearer $TOKEN" $LEMUR_URL/certificates
```

See [INTEGRATION_TEST_CONNECTION.md](INTEGRATION_TEST_CONNECTION.md) for complete details.

## Documentation

- **[API_CERT_WITH_DESTINATIONS.md](API_CERT_WITH_DESTINATIONS.md)** - Create certs with destinations via curl
- **[JWT_API_USAGE.md](JWT_API_USAGE.md)** - Generate and use JWT tokens via API
- **[SERVICE_AUTHENTICATION.md](SERVICE_AUTHENTICATION.md)** - Auth patterns for tools/services
- **[INTEGRATION_TEST_CONNECTION.md](INTEGRATION_TEST_CONNECTION.md)** - Connection info for tests
- **[VAULT_JWT_INTEGRATION.md](VAULT_JWT_INTEGRATION.md)** - Vault and JWT integration guide
- **[LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md)** - Complete local development guide
- **[INTEGRATION_TESTING.md](INTEGRATION_TESTING.md)** - Integration testing with API
- **[REFACTORING_SUMMARY.md](REFACTORING_SUMMARY.md)** - What was cleaned up and why

## Key Points

✅ **For local dev:** Use Python script (bypasses credential requirements)  
✅ **For production:** Use API endpoints (with proper credentials)  
✅ **For testing:** Use constant JWT tokens  
✅ **Clean codebase:** Removed 7+ failing/obsolete scripts

## Folder Structure

```
local/                          # All local dev files
├── create_cert_with_destinations.py
├── generate_test_token_constant.py  
├── create_authority.sh
├── create_default_authority.py
├── docker-compose.yml
├── Dockerfile
├── lemur-env
└── src/lemur.conf.py
```

See `local/README.md` for complete contents.

## Quick Troubleshooting

**Problem:** Script not found in container  
**Solution:** Copy it: `docker cp local/create_cert_with_destinations.py local-lemur:/opt/lemur/local/`

**Problem:** Permission denied when creating certificate  
**Solution:** Use the Python script inside container, not API endpoints

**Problem:** Container won't start  
**Solution:** `cd local && docker-compose down && docker-compose up -d`

---

*For full details, see [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md)*
