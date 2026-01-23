#!/bin/bash
# Create a destination and certificate using only the Lemur API
# This demonstrates the complete API workflow for local development

set -e

# Configuration
LEMUR_URL="${LEMUR_URL:-https://localhost:8447}"
API_BASE="${LEMUR_URL}/api/1"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=========================================="
echo "Lemur API: Create Destination & Certificate"
echo "=========================================="
echo ""

# Step 1: Use constant JWT token
echo -e "${BLUE}Step 1: Using JWT token...${NC}"
# Constant token for local development (valid until Jan 2027)
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI"
echo -e "${GREEN}✅ Token ready${NC}"
echo ""

# Step 2: Get the default authority
echo -e "${BLUE}Step 2: Finding default authority (TestCA)...${NC}"
AUTHORITY_RESPONSE=$(curl -k -s -X GET "$API_BASE/authorities" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json")

AUTHORITY_ID=$(echo "$AUTHORITY_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
items = data.get('items', [])
for item in items:
    if item.get('name') == 'TestCA':
        print(item.get('id'))
        break
")

if [ -z "$AUTHORITY_ID" ]; then
    echo -e "${RED}❌ TestCA authority not found${NC}"
    echo "   Run: docker-compose restart lemur (to trigger authority creation)"
    exit 1
fi
echo -e "${GREEN}✅ Found TestCA (ID: $AUTHORITY_ID)${NC}"
echo ""

# Step 3: Create a destination
echo -e "${BLUE}Step 3: Creating destination...${NC}"
DEST_NAME="api-test-dest-$(date +%s)"
DEST_PAYLOAD=$(cat <<EOF
{
  "label": "$DEST_NAME",
  "description": "Test destination created via API",
  "plugin": {
    "slug": "aws-destination",
    "plugin_options": [
      {
        "name": "accountNumber",
        "value": "123456789012",
        "type": "str",
        "required": true
      }
    ]
  }
}
EOF
)

echo "Payload:"
echo "$DEST_PAYLOAD" | python3 -m json.tool
echo ""

DEST_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST "$API_BASE/destinations" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$DEST_PAYLOAD")

DEST_BODY=$(echo "$DEST_RESPONSE" | head -n -1)
DEST_HTTP_STATUS=$(echo "$DEST_RESPONSE" | tail -n 1)

if [ "$DEST_HTTP_STATUS" = "200" ] || [ "$DEST_HTTP_STATUS" = "201" ]; then
    DEST_ID=$(echo "$DEST_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', 'N/A'))")
    echo -e "${GREEN}✅ Destination created (ID: $DEST_ID)${NC}"
else
    echo -e "${RED}❌ Failed to create destination (HTTP $DEST_HTTP_STATUS)${NC}"
    echo "$DEST_BODY" | python3 -m json.tool 2>/dev/null || echo "$DEST_BODY"
    exit 1
fi
echo ""

# Step 4: Create a certificate with the destination
echo -e "${BLUE}Step 4: Creating certificate with destination...${NC}"
CERT_CN="api-test-$(date +%s).example.com"
CERT_PAYLOAD=$(cat <<EOF
{
  "commonName": "$CERT_CN",
  "owner": "user@email.com",
  "authority": {
    "id": $AUTHORITY_ID
  },
  "validityYears": 1,
  "country": "US",
  "state": "California",
  "location": "San Francisco",
  "organization": "Example Inc",
  "organizationalUnit": "IT",
  "description": "Test certificate created via API with destination",
  "destinations": [
    {
      "id": $DEST_ID
    }
  ],
  "extensions": {
    "subAltNames": {
      "names": [
        {
          "nameType": "DNSName",
          "value": "$CERT_CN"
        }
      ]
    }
  }
}
EOF
)

echo "Payload:"
echo "$CERT_PAYLOAD" | python3 -m json.tool
echo ""

CERT_RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST "$API_BASE/certificates" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "$CERT_PAYLOAD")

CERT_BODY=$(echo "$CERT_RESPONSE" | head -n -1)
CERT_HTTP_STATUS=$(echo "$CERT_RESPONSE" | tail -n 1)

echo "HTTP Status: $CERT_HTTP_STATUS"
echo ""

if [ "$CERT_HTTP_STATUS" = "200" ] || [ "$CERT_HTTP_STATUS" = "201" ]; then
    CERT_ID=$(echo "$CERT_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', 'N/A'))")
    CERT_NAME=$(echo "$CERT_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('name', 'N/A'))")
    
    echo -e "${GREEN}✅ Certificate created successfully!${NC}"
    echo ""
    echo "Certificate Details:"
    echo "  ID: $CERT_ID"
    echo "  Name: $CERT_NAME"
    echo "  Common Name: $CERT_CN"
    echo "  Destination: $DEST_NAME (ID: $DEST_ID)"
    echo ""
    echo "View in browser:"
    echo "  Certificate: ${LEMUR_URL}/certificates/${CERT_ID}"
    echo "  Destination: ${LEMUR_URL}/destinations/${DEST_ID}"
else
    echo -e "${RED}❌ Failed to create certificate (HTTP $CERT_HTTP_STATUS)${NC}"
    echo "$CERT_BODY" | python3 -m json.tool 2>/dev/null || echo "$CERT_BODY"
    exit 1
fi

echo ""
echo "=========================================="
echo -e "${GREEN}✅ All operations completed successfully!${NC}"
echo "=========================================="
