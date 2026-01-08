# Integration Testing with Lemur

This guide explains how to use authentication tokens for integration testing with the local Lemur development environment.

## ⚠️ Security Warning

The tokens and secrets described here are **ONLY for local development and testing**. Never use these in production environments!

## Quick Start

### Option 1: Use a Pre-Generated Constant Token (Recommended for CI/Integration Tests)

The local development environment uses a fixed JWT secret, which allows for constant, reproducible tokens:

```bash
# Generate a token for the default admin user (user ID 1)
TOKEN=$(python3 local/generate_test_token_constant.py)

# Use the token in API requests
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8447/api/1/certificates
```

**Pre-generated constant token for user ID 1 (always the same, valid until Jan 16, 2027):**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI
```

This token uses a **fixed timestamp**, so running `generate_test_token_constant.py` will always produce the same token. This makes it perfect for CI/CD and automated testing where you need reproducible tokens.

### Option 2: Generate a Fresh Token via Login API

For testing the full authentication flow, you can use the login endpoint:

```bash
# Login with the default test user
TOKEN=$(curl -k -s -X POST https://localhost:8447/api/1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}' | python3 -c "import sys, json; print(json.load(sys.stdin)['token'])")

# Use the token
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8447/api/1/certificates
```

## Default Test Resources

The local development environment automatically creates default resources for testing:

### Default Admin User

| Username | Email            | Password | Role  | User ID |
|----------|------------------|----------|-------|---------|
| user     | user@email.com   | pass     | admin | 1       |

### Default Authority

| Name   | Common Name      | Type | Plugin               | Owner          |
|--------|------------------|------|----------------------|----------------|
| TestCA | TestCA Root CA   | root | cryptography-issuer  | user@email.com |

The default authority is automatically created and can be used to issue certificates for testing.

## Token Generation Script

### `generate_test_token_constant.py`

Generates a JWT token using the fixed local development secret.

**Usage:**
```bash
# Generate constant token for default user (ID 1) - always the same
python3 generate_test_token_constant.py

# Generate constant token for a specific user ID
python3 generate_test_token_constant.py 2

# Generate a fresh token with current timestamp (different each time)
python3 generate_test_token_constant.py --dynamic

# Use in a variable
export LEMUR_TOKEN=$(python3 local/generate_test_token_constant.py)
```

**Arguments:**
- `user_id` (optional) - The user ID to generate the token for (default: 1)
- `--dynamic` (optional) - Generate a fresh token with current timestamp instead of fixed timestamp

**Token Details:**
- **Algorithm:** HS256
- **Secret:** Fixed for local dev (see `docker/lemur-env`)
- **Timestamp:** Fixed at Jan 16, 2026 00:00:00 UTC (use `--dynamic` for current time)
- **Expiration:** Jan 16, 2027 00:00:00 UTC (365 days from issued time)
- **Claims:**
  - `iat`: Issued at timestamp (fixed or dynamic)
  - `exp`: Expiration timestamp (fixed or dynamic)
  - `sub`: User ID

## Integration Testing Examples

### Python Integration Test

```python
import requests

# Use the constant token (always the same)
TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI"
BASE_URL = "https://localhost:8447"

# Make authenticated API request
response = requests.get(
    f"{BASE_URL}/api/1/certificates",
    headers={"Authorization": f"Bearer {TOKEN}"},
    verify=False  # Disable SSL verification for local dev
)

print(response.json())
```

### Shell Script Integration Test

```bash
#!/bin/bash
set -e

# Configuration
BASE_URL="https://localhost:8447"
TOKEN=$(python3 generate_test_token_constant.py)

# Test: List certificates
echo "Testing certificate list..."
curl -k -s -H "Authorization: Bearer $TOKEN" \
  "${BASE_URL}/api/1/certificates" | python3 -m json.tool

# Test: Create a destination
echo "Testing destination creation..."
curl -k -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plugin": {"slug": "aws-destination"},
    "label": "test-destination",
    "description": "Test destination for integration tests"
  }' \
  "${BASE_URL}/api/1/destinations" | python3 -m json.tool

echo "All tests passed!"
```

### Docker Compose Test Environment

```yaml
version: '3.8'
services:
  integration-tests:
    image: python:3.10
    environment:
      - LEMUR_URL=https://lemur:443
      - LEMUR_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI
    volumes:
      - ./tests:/tests
    command: pytest /tests/integration/
    depends_on:
      - lemur
```

## Configuration

### Fixed JWT Secret (Local Dev Only)

The fixed JWT secret is configured in `local/lemur-env`:

```env
LEMUR_TOKEN_SECRET=bG9jYWwtZGV2LXNlY3JldC1mb3ItdGVzdGluZy1vbmx5LWRvLW5vdC11c2UtaW4tcHJvZA==
```

This is the base64-encoded string: `"local-dev-secret-for-testing-only-do-not-use-in-prod"`

### Regenerating the Container

After updating the environment configuration, restart the containers:

```bash
cd local
docker-compose down
docker-compose up -d
```

## Troubleshooting

### Token is Invalid

**Problem:** API returns "Token is invalid" error.

**Solutions:**
1. Ensure the container is using the fixed `LEMUR_TOKEN_SECRET` from `local/lemur-env`
2. Regenerate the token: `python3 local/generate_test_token_constant.py`
3. Check that the container was rebuilt after updating the env file

### Token Has Expired

**Problem:** API returns "Token has expired" error.

**Solutions:**
1. The constant token is valid until January 16, 2027
2. Generate a fresh token with current timestamp: `python3 generate_test_token_constant.py --dynamic`
3. If needed, update the fixed timestamp in the script for a new constant token

### User Not Found

**Problem:** API returns "User is not currently active" or similar error.

**Solutions:**
1. Verify the default user was created: `docker exec local-lemur psql -U lemur -d lemur -c "SELECT id, username, email, active FROM users;"`
2. Ensure `LEMUR_CREATE_DEFAULTS=true` is set in `local/lemur-env`
3. Recreate the container to trigger user and authority creation

### Certificate Verification Failed

**Problem:** SSL certificate verification errors when making API requests.

**Solutions:**
1. Disable SSL verification in your client (for local dev only!)
   - Python: `requests.get(..., verify=False)`
   - curl: `curl -k ...`
   - Node.js: `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'`

## Additional Resources

- [Lemur API Documentation](https://lemur.readthedocs.io/en/latest/developer/index.html)
- [JWT.io](https://jwt.io/) - Decode and inspect JWT tokens
- [Lemur GitHub Repository](https://github.com/Netflix/lemur)

## Security Reminders

1. ✅ These tokens are fine for local development
2. ✅ These tokens are fine for CI/CD integration tests in isolated environments
3. ❌ **NEVER** commit these secrets to production configuration
4. ❌ **NEVER** use the fixed JWT secret in production
5. ❌ **NEVER** use these tokens with production data

