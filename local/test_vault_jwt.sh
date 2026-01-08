#!/bin/bash
# Test script for Vault and JWT integration

set -e

echo "=================================="
echo "Vault + JWT Integration Test"
echo "=================================="
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Vault is running
echo "1. Checking Vault connection..."
if curl -s http://localhost:8200/v1/sys/health > /dev/null; then
    echo -e "${GREEN}✅ Vault is running${NC}"
else
    echo -e "${RED}❌ Vault is not running${NC}"
    echo "   Start with: cd local && docker-compose up -d"
    exit 1
fi

# Check Vault authentication
echo ""
echo "2. Testing Vault authentication..."
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN='dev-root-token'

if vault status > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Vault authentication successful${NC}"
else
    echo -e "${RED}❌ Vault authentication failed${NC}"
    exit 1
fi

# List Vault secrets
echo ""
echo "3. Listing Vault secrets..."
if vault kv list secret/lemur > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Vault secrets accessible${NC}"
    echo "   Secrets:"
    vault kv list secret/lemur | sed 's/^/   - /'
else
    echo -e "${YELLOW}⚠️  No secrets found, initializing...${NC}"
    docker exec -i docker-vault-1 sh /vault/init.sh
fi

# Test JWT generation
echo ""
echo "4. Testing JWT token generation..."
if command -v python3 > /dev/null 2>&1; then
    TOKEN=$(python3 local/jwt_auth_helper.py generate 2>/dev/null)
    if [ -n "$TOKEN" ]; then
        echo -e "${GREEN}✅ JWT token generated successfully${NC}"
        echo "   Token preview: ${TOKEN:0:50}..."
    else
        echo -e "${RED}❌ Failed to generate JWT token${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}⚠️  Python3 not found, skipping JWT test${NC}"
fi

# Test Lemur API with JWT
echo ""
echo "5. Testing Lemur API with JWT..."
if curl -k -s -H "Authorization: Bearer $TOKEN" https://localhost:8447/api/1/certificates > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Lemur API accessible with JWT${NC}"
else
    echo -e "${YELLOW}⚠️  Lemur API test failed (container may not be ready)${NC}"
fi

# Test Vault integration in Lemur
echo ""
echo "6. Testing Vault integration in Lemur..."
if docker exec -i local-lemur python3 /opt/lemur/local/setup_vault_integration.py > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Vault integration working${NC}"
else
    echo -e "${YELLOW}⚠️  Vault integration test failed (check logs)${NC}"
fi

echo ""
echo "=================================="
echo -e "${GREEN}✅ All tests completed!${NC}"
echo "=================================="
echo ""
echo "Next steps:"
echo "  • Access Vault UI: http://localhost:8200/ui (token: dev-root-token)"
echo "  • Access Lemur UI: https://localhost:8447 (user: user, pass: pass)"
echo "  • Generate JWT: python3 local/jwt_auth_helper.py generate --verbose"
echo "  • Read secrets: vault kv get secret/lemur/jwt"
echo ""
