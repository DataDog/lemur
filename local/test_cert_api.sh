#!/bin/bash
# Test creating certificates with destinations via curl/API

BASE_URL="https://localhost:8447/api/1"
TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI"

echo "Testing Certificate Creation with Destinations via API"
echo "======================================================"
echo ""

# Step 0: Verify LEMUR_DISABLE_DESTINATION_UPLOADS is set
echo "0. Checking environment configuration..."
DISABLE_FLAG=$(docker exec -i local-lemur python3 << 'EOF'
from lemur.factory import create_app
app = create_app()
with app.app_context():
    flag = app.config.get('LEMUR_DISABLE_DESTINATION_UPLOADS', False)
    print(flag)
EOF
)

if [ "$DISABLE_FLAG" = "True" ]; then
  echo "✓ LEMUR_DISABLE_DESTINATION_UPLOADS: True (ready for API test)"
else
  echo "❌ LEMUR_DISABLE_DESTINATION_UPLOADS: $DISABLE_FLAG"
  echo ""
  echo "⚠️  WARNING: Destination uploads are NOT disabled!"
  echo "   The API call will likely fail with 'permission denied'"
  echo ""
  echo "   To fix, see: API_CERT_WITH_DESTINATIONS.md"
  echo ""
  read -p "Continue anyway? (y/N) " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

echo ""

# Step 1: List available destinations
echo "1. Listing available destinations..."
DESTINATIONS=$(curl -k -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/destinations")

echo "$DESTINATIONS" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    items = data.get('items', [])
    if items:
        for d in items:
            print(f\"  {d['id']:3d}: {d['label']} ({d['plugin']['slug']})\")
    else:
        print('  No destinations found')
except:
    print('  Error parsing destinations')
"

# Get first two destination IDs
DEST_IDS=$(echo "$DESTINATIONS" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    items = data.get('items', [])
    ids = [d['id'] for d in items[:2]]
    print(','.join(map(str, ids)))
except:
    print('')
")

if [ -z "$DEST_IDS" ]; then
  echo ""
  echo "❌ No destinations found! Create some first:"
  echo "   docker exec -i local-lemur python3 /opt/lemur/local/create_test_destinations.py"
  exit 1
fi

# Parse destination IDs
IFS=',' read -r DEST1 DEST2 <<< "$DEST_IDS"

echo ""
echo "2. Creating certificate WITH destinations (IDs: $DEST1, $DEST2)..."
echo ""

# Generate unique common name with timestamp
TIMESTAMP=$(date +%s)
COMMON_NAME="api-test-$TIMESTAMP.example.com"

CERT_RESPONSE=$(curl -k -s -X POST "$BASE_URL/certificates" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"authority\": {\"id\": 1},
    \"owner\": \"user@email.com\",
    \"commonName\": \"$COMMON_NAME\",
    \"description\": \"Certificate with destinations via API\",
    \"validityYears\": 1,
    \"country\": \"US\",
    \"state\": \"California\",
    \"location\": \"San Francisco\",
    \"organization\": \"Example Inc\",
    \"organizationalUnit\": \"IT\",
    \"destinations\": [
      {\"id\": $DEST1},
      {\"id\": $DEST2}
    ]
  }")

# Parse response
CERT_ID=$(echo "$CERT_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', 'error'))" 2>/dev/null)

if [ "$CERT_ID" = "error" ]; then
  echo "❌ Failed to create certificate with destinations"
  echo ""
  
  # Check for specific error
  ERROR_MSG=$(echo "$CERT_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('message', 'unknown error'))" 2>/dev/null)
  
  if [[ "$ERROR_MSG" == *"permission denied"* ]]; then
    echo "Error: permission denied"
    echo ""
    echo "This means LEMUR_DISABLE_DESTINATION_UPLOADS is not working."
    echo "The destination plugin tried to deploy but failed authentication."
    echo ""
    echo "Fix: Apply the runtime patch from API_CERT_WITH_DESTINATIONS.md"
  else
    echo "Error: $ERROR_MSG"
    echo ""
    echo "Full response:"
    echo "$CERT_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$CERT_RESPONSE"
  fi
  
  exit 1
fi

# Success! Verify destinations
DEST_COUNT=$(echo "$CERT_RESPONSE" | python3 -c "import sys, json; print(len(json.load(sys.stdin).get('destinations', [])))" 2>/dev/null)

echo "✅ Certificate created successfully!"
echo "   ID: $CERT_ID"
echo "   Common Name: $COMMON_NAME"
echo "   Destinations: $DEST_COUNT"
echo ""

if [ "$DEST_COUNT" -gt 0 ]; then
  echo "Linked destinations:"
  echo "$CERT_RESPONSE" | python3 -c "
import sys, json
data = json.load(sys.stdin)
for d in data.get('destinations', []):
    print(f\"  ✓ {d['label']} (ID: {d['id']}) - {d['plugin']['slug']}\")
"
  echo ""
  echo "🎉 SUCCESS! Certificate created WITH destinations via API"
else
  echo "⚠️  Certificate created but has NO destinations"
  echo "   This suggests the destinations were not properly linked"
fi

echo ""
echo "🔗 View in UI: https://localhost:8447/#/certificates/$CERT_ID"
echo ""

# Step 3: Verify via GET
echo "3. Verifying via GET request..."
GET_RESPONSE=$(curl -k -s -H "Authorization: Bearer $TOKEN" "$BASE_URL/certificates/$CERT_ID")
VERIFY_DEST_COUNT=$(echo "$GET_RESPONSE" | python3 -c "import sys, json; print(len(json.load(sys.stdin).get('destinations', [])))" 2>/dev/null)

echo "   Confirmed destinations: $VERIFY_DEST_COUNT"

if [ "$VERIFY_DEST_COUNT" -eq "$DEST_COUNT" ]; then
  echo "   ✓ Verification passed"
else
  echo "   ⚠️  Destination count mismatch"
fi
