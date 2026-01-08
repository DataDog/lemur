#!/bin/bash
# Script to create a new authority in Lemur using the API

set -e

# Configuration
LEMUR_URL="${LEMUR_URL:-https://localhost:8447}"
AUTHORITY_NAME="${1:-TestCA}"
OWNER="${2:-user@email.com}"

# Get the constant token
TOKEN=$(python3 generate_test_token_constant.py)

echo "=== Creating Authority: $AUTHORITY_NAME ==="
echo "Owner: $OWNER"
echo ""

# Create authority JSON payload
PAYLOAD=$(cat <<EOF
{
  "name": "$AUTHORITY_NAME",
  "owner": "$OWNER",
  "description": "Test Certificate Authority for local development",
  "commonName": "$AUTHORITY_NAME Root CA",
  "validityYears": 10,
  "country": "US",
  "state": "California",
  "location": "San Francisco",
  "organization": "Example Inc",
  "organizationalUnit": "IT Department",
  "type": "root",
  "signingAlgorithm": "sha256WithRSA",
  "keyType": "RSA2048",
  "sensitivity": "medium",
  "serialNumber": 1,
  "firstSerial": 1,
  "plugin": {
    "slug": "cryptography-issuer"
  },
  "extensions": {
    "subAltNames": {
      "names": []
    },
    "custom": []
  }
}
EOF
)

echo "Payload:"
echo "$PAYLOAD" | python3 -m json.tool
echo ""

# Make the API request
echo "Creating authority..."
RESPONSE=$(curl -k -s -w "\n%{http_code}" -X POST \
  "$LEMUR_URL/api/1/authorities" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

# Split response and status code
HTTP_BODY=$(echo "$RESPONSE" | head -n -1)
HTTP_STATUS=$(echo "$RESPONSE" | tail -n 1)

echo ""
echo "HTTP Status: $HTTP_STATUS"
echo ""

if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "201" ]; then
  echo "✅ Authority created successfully!"
  echo ""
  echo "$HTTP_BODY" | python3 -m json.tool
  
  # Extract authority ID
  AUTHORITY_ID=$(echo "$HTTP_BODY" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', 'N/A'))")
  echo ""
  echo "Authority ID: $AUTHORITY_ID"
  echo ""
  echo "You can now use this authority to issue certificates!"
  echo "View in UI: $LEMUR_URL/authorities/$AUTHORITY_ID"
else
  echo "❌ Failed to create authority"
  echo "$HTTP_BODY" | python3 -m json.tool 2>/dev/null || echo "$HTTP_BODY"
  exit 1
fi
