# Integration Test Connection Information

**See also:** 
- [JWT_API_USAGE.md](JWT_API_USAGE.md) for generating JWT tokens via API
- [SERVICE_AUTHENTICATION.md](SERVICE_AUTHENTICATION.md) for authentication patterns for tools/services

## Quick Connection Details

### API Endpoint
```
https://localhost:8447
```

### API Base URL
```
https://localhost:8447/api/1
```

### Default User Login
```
Username: user
Password: pass
Email:    user@email.com
User ID:  1
Role:     admin
```

### Constant API Token (Pre-generated)
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI
```
**Valid until**: January 16, 2027  
**User ID**: 1 (default admin user)  
**Algorithm**: HS256  

### JWT Secret (for generating new tokens)
```
bG9jYWwtZGV2LXNlY3JldC1mb3ItdGVzdGluZy1vbmx5LWRvLW5vdC11c2UtaW4tcHJvZA==
```

## Connection Examples

### 1. cURL with Constant Token

```bash
# Set the constant token
export LEMUR_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI"

# List certificates
curl -k -H "Authorization: Bearer $LEMUR_TOKEN" \
  https://localhost:8447/api/1/certificates

# Get specific certificate
curl -k -H "Authorization: Bearer $LEMUR_TOKEN" \
  https://localhost:8447/api/1/certificates/1

# Health check
curl -k https://localhost:8447/api/1/healthcheck
```

### 2. Python Integration Test

```python
import requests

# Connection details
BASE_URL = "https://localhost:8447/api/1"
LEMUR_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI"

# Headers
headers = {
    "Authorization": f"Bearer {LEMUR_TOKEN}",
    "Content-Type": "application/json"
}

# Test connection
response = requests.get(
    f"{BASE_URL}/certificates",
    headers=headers,
    verify=False  # Disable SSL verification for local dev
)

print(f"Status: {response.status_code}")
print(f"Certificates: {len(response.json()['items'])}")
```

### 3. Generate New Token (if needed)

```bash
# Using the token generator
python3 local/generate_test_token_constant.py

# Or with JWT helper (if Vault is running)
python3 local/jwt_auth_helper.py generate
```

### 4. Login via API (Alternative)

```bash
# Login to get a fresh token
TOKEN=$(curl -k -s -X POST https://localhost:8447/api/1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}' | \
  python3 -c "import sys, json; print(json.load(sys.stdin)['token'])")

# Use the token
curl -k -H "Authorization: Bearer $TOKEN" \
  https://localhost:8447/api/1/certificates
```

## Complete Integration Test Script

### Bash Script

```bash
#!/bin/bash
# integration_test.sh

set -e

# Connection details
BASE_URL="https://localhost:8447"
API_URL="${BASE_URL}/api/1"
LEMUR_TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI"

# Test 1: Health check
echo "Testing health check..."
curl -k -f "${API_URL}/healthcheck"
echo "✅ Health check passed"

# Test 2: Authentication
echo "Testing authentication..."
curl -k -f -H "Authorization: Bearer ${LEMUR_TOKEN}" \
  "${API_URL}/certificates" > /dev/null
echo "✅ Authentication passed"

# Test 3: List resources
echo "Testing list certificates..."
CERT_COUNT=$(curl -k -s -H "Authorization: Bearer ${LEMUR_TOKEN}" \
  "${API_URL}/certificates" | python3 -c "import sys, json; print(len(json.load(sys.stdin)['items']))")
echo "✅ Found ${CERT_COUNT} certificates"

# Test 4: Create resource (authority)
echo "Testing create authority..."
curl -k -s -X POST "${API_URL}/authorities" \
  -H "Authorization: Bearer ${LEMUR_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "TestIntegrationCA",
    "owner": "user@email.com",
    "description": "Integration test authority",
    "commonName": "TestIntegrationCA",
    "validityYears": 10,
    "plugin": {"slug": "cryptography-issuer"}
  }' > /dev/null
echo "✅ Authority created"

echo ""
echo "All integration tests passed! ✅"
```

### Python Script

```python
#!/usr/bin/env python3
"""integration_test.py"""

import requests
import json
import sys

# Disable SSL warnings for local dev
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Connection details
BASE_URL = "https://localhost:8447"
API_URL = f"{BASE_URL}/api/1"
LEMUR_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI"

# Default user credentials
USERNAME = "user"
PASSWORD = "pass"
USER_EMAIL = "user@email.com"

headers = {
    "Authorization": f"Bearer {LEMUR_TOKEN}",
    "Content-Type": "application/json"
}

def test_health():
    """Test health check endpoint"""
    response = requests.get(f"{API_URL}/healthcheck", verify=False)
    assert response.status_code == 200
    assert response.text == "ok"
    print("✅ Health check passed")

def test_auth():
    """Test authentication"""
    response = requests.get(
        f"{API_URL}/certificates",
        headers=headers,
        verify=False
    )
    assert response.status_code == 200
    print("✅ Authentication passed")

def test_list_certificates():
    """Test listing certificates"""
    response = requests.get(
        f"{API_URL}/certificates",
        headers=headers,
        verify=False
    )
    assert response.status_code == 200
    data = response.json()
    print(f"✅ Found {len(data['items'])} certificates")

def test_login():
    """Test login endpoint"""
    response = requests.post(
        f"{API_URL}/auth/login",
        json={"username": USERNAME, "password": PASSWORD},
        verify=False
    )
    assert response.status_code == 200
    assert "token" in response.json()
    print("✅ Login successful")

def main():
    print("Running Lemur Integration Tests")
    print("=" * 50)
    
    try:
        test_health()
        test_auth()
        test_list_certificates()
        test_login()
        
        print("=" * 50)
        print("✅ All tests passed!")
        return 0
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
```

## Environment Variables

Create a `.env` file for your tests:

```bash
# .env
LEMUR_URL=https://localhost:8447
LEMUR_API_URL=https://localhost:8447/api/1
LEMUR_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI
LEMUR_USERNAME=user
LEMUR_PASSWORD=pass
LEMUR_USER_EMAIL=user@email.com
```

Load in your tests:
```bash
source .env
curl -k -H "Authorization: Bearer $LEMUR_TOKEN" $LEMUR_API_URL/certificates
```

## Common API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/healthcheck` | GET | Service health |
| `/auth/login` | POST | User login |
| `/certificates` | GET | List certificates |
| `/certificates/{id}` | GET | Get certificate |
| `/certificates` | POST | Create certificate |
| `/authorities` | GET | List authorities |
| `/authorities/{id}` | GET | Get authority |
| `/destinations` | GET | List destinations |
| `/plugins` | GET | List plugins |
| `/users` | GET | List users |
| `/roles` | GET | List roles |

## Full Request Examples

### List All Certificates
```bash
curl -k -s -H "Authorization: Bearer $LEMUR_TOKEN" \
  https://localhost:8447/api/1/certificates | python3 -m json.tool
```

### Get Specific Certificate
```bash
curl -k -s -H "Authorization: Bearer $LEMUR_TOKEN" \
  https://localhost:8447/api/1/certificates/1 | python3 -m json.tool
```

### Create Certificate
```bash
curl -k -s -X POST https://localhost:8447/api/1/certificates \
  -H "Authorization: Bearer $LEMUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "authority": {"id": 1},
    "owner": "user@email.com",
    "commonName": "test.example.com",
    "validityYears": 1,
    "country": "US",
    "state": "California",
    "location": "San Francisco",
    "organization": "Example Inc",
    "organizationalUnit": "IT"
  }' | python3 -m json.tool
```

### List Authorities
```bash
curl -k -s -H "Authorization: Bearer $LEMUR_TOKEN" \
  https://localhost:8447/api/1/authorities | python3 -m json.tool
```

### List Destinations
```bash
curl -k -s -H "Authorization: Bearer $LEMUR_TOKEN" \
  https://localhost:8447/api/1/destinations | python3 -m json.tool
```

## Troubleshooting

### Connection Refused
```bash
# Check if Lemur is running
docker ps | grep lemur

# Check logs
docker logs local-lemur

# Restart if needed
cd local && docker-compose restart lemur
```

### Invalid Token
```bash
# Generate new token
python3 local/generate_test_token_constant.py

# Or use login
curl -k -X POST https://localhost:8447/api/1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"pass"}'
```

### SSL Certificate Errors
```bash
# Use -k flag with curl
curl -k https://localhost:8447/api/1/healthcheck

# In Python, use verify=False
requests.get(url, verify=False)
```

## Quick Copy-Paste Values

**Endpoint:**
```
https://localhost:8447/api/1
```

**Token:**
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI
```

**Username/Password:**
```
user / pass
```

**Complete cURL Command:**
```bash
curl -k -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI" https://localhost:8447/api/1/certificates
```

---

**Security Note**: These credentials are for LOCAL DEVELOPMENT ONLY. Never use in production!
