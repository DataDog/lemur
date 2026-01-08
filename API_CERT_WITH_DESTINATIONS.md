# Creating Certificates with Destinations via API (curl)

## Quick Start

```bash
# Test the API with the automated script
./local/test_cert_api.sh
```

If you get a "permission denied" error, see the [troubleshooting section](#error-permission-denied) below.

## Overview

To create certificates with destinations via curl/API in local development, you need to ensure the `LEMUR_DISABLE_DESTINATION_UPLOADS` flag is working properly to bypass destination plugin deployments.

## Prerequisites

### 1. Verify Environment Variable

```bash
# Check if the flag is set in the container
docker exec -i local-lemur env | grep LEMUR_DISABLE_DESTINATION_UPLOADS

# Should output: LEMUR_DISABLE_DESTINATION_UPLOADS=True
```

### 2. Verify Configuration is Loaded

```bash
docker exec -i local-lemur python3 << 'EOF'
from lemur.factory import create_app
app = create_app()
with app.app_context():
    flag = app.config.get('LEMUR_DISABLE_DESTINATION_UPLOADS', False)
    print(f"LEMUR_DISABLE_DESTINATION_UPLOADS: {flag}")
    if flag:
        print("✅ Destination uploads are disabled")
    else:
        print("❌ Destination uploads are ENABLED - API will fail!")
EOF
```

### 3. Apply Runtime Patch (If Needed)

If the flag is `True` but API still fails, use the automated patch script:

```bash
# Easy way - automated script
./local/apply_upload_bypass_patch.sh
```

This script will:
- Check if the patch is already applied
- Apply the patch to bypass destination uploads
- Automatically restart the container

Or apply manually:

```bash
docker exec -i local-lemur python3 << 'EOF'
import os

models_path = '/opt/lemur/lemur/certificates/models.py'

with open(models_path, 'r') as f:
    content = f.read()

if 'LEMUR_DISABLE_DESTINATION_UPLOADS' in content:
    print("✅ Patch already applied")
else:
    old = '''@event.listens_for(Certificate.destinations, "append")
def update_destinations(target, value, initiator):
    """
    Attempt to upload certificate to the new destination

    :param target:
    :param value:
    :param initiator:
    :return:
    """
    destination_plugin = plugins.get(value.plugin_name)
    status = FAILURE_METRIC_STATUS

    if target.expired:
        return'''
    
    new = '''@event.listens_for(Certificate.destinations, "append")
def update_destinations(target, value, initiator):
    """
    Attempt to upload certificate to the new destination

    :param target:
    :param value:
    :param initiator:
    :return:
    """
    # Check if destination uploads are disabled (for local development)
    if current_app.config.get("LEMUR_DISABLE_DESTINATION_UPLOADS", False):
        current_app.logger.info(
            f"Destination upload disabled for local development. "
            f"Skipping upload for certificate {target.name} to destination {value.label}"
        )
        return
    
    destination_plugin = plugins.get(value.plugin_name)
    status = FAILURE_METRIC_STATUS

    if target.expired:
        return'''
    
    if old in content:
        content = content.replace(old, new)
        with open(models_path, 'w') as f:
            f.write(content)
        print("✅ Patch applied successfully - restart container")
    else:
        print("⚠️  Could not find code to patch")
EOF

# Restart to apply patch
cd local && docker-compose restart lemur
```

## API Usage with curl

### Set Up Environment

```bash
# API endpoint
export LEMUR_API="https://localhost:8447/api/1"

# Authentication token (valid until Jan 2027)
export TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI"
```

### Step 1: List Available Destinations

```bash
# Get all destinations
curl -k -s -H "Authorization: Bearer $TOKEN" \
  "$LEMUR_API/destinations" | python3 -m json.tool

# Find specific destination IDs
curl -k -s -H "Authorization: Bearer $TOKEN" \
  "$LEMUR_API/destinations" | \
  python3 -c "import sys, json; [print(f\"{d['id']}: {d['label']} ({d['plugin']['slug']})\") for d in json.load(sys.stdin)['items']]"
```

### Step 2: Create Certificate WITH Destinations

```bash
curl -k -X POST "$LEMUR_API/certificates" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "authority": {"id": 1},
    "owner": "user@email.com",
    "commonName": "test-with-dest.example.com",
    "description": "Certificate with destinations",
    "validityYears": 1,
    "country": "US",
    "state": "California",
    "location": "San Francisco",
    "organization": "Example Inc",
    "organizationalUnit": "IT",
    "destinations": [
      {"id": 11},
      {"id": 12}
    ]
  }' | python3 -m json.tool
```

### Expected Response (Success)

```json
{
  "id": 15,
  "name": "test-with-dest.example.com-TestCARootCA-20240119-20250119",
  "cn": "test-with-dest.example.com",
  "owner": "user@email.com",
  "destinations": [
    {
      "id": 11,
      "label": "COA-Destination",
      "plugin": {"slug": "cert-orchestration-adapter-dest"}
    },
    {
      "id": 12,
      "label": "AWS-Destination",
      "plugin": {"slug": "aws-destination"}
    }
  ],
  ...
}
```

### Expected Response (Failure - Upload Not Disabled)

```json
{
  "message": "permission denied"
}
```

**Fix**: Apply the runtime patch shown above and restart the container.

## Complete Example

### Automated Test Script

Use the provided test script which handles everything:

```bash
# Run the automated test
./local/test_cert_api.sh
```

This script will:
1. Check if `LEMUR_DISABLE_DESTINATION_UPLOADS` is configured
2. List available destinations
3. Create a certificate with 2 destinations
4. Verify the destinations were linked
5. Provide detailed error messages if something fails

### Manual Example

```bash
#!/bin/bash
# manual_cert_creation.sh

set -e

export LEMUR_API="https://localhost:8447/api/1"
export TOKEN="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE3Njg1MjE2MDAsImV4cCI6MTgwMDA1NzYwMCwic3ViIjoxfQ.sKrQgiwoLzijuEUZEPmf-waTEHfFtDBfYTBwynStWHI"

echo "1. Listing available destinations..."
curl -k -s -H "Authorization: Bearer $TOKEN" \
  "$LEMUR_API/destinations" | \
  python3 -c "import sys, json; [print(f'  {d[\"id\"]}: {d[\"label\"]}') for d in json.load(sys.stdin)['items']]"

echo ""
echo "2. Creating certificate with destinations..."
CERT_RESPONSE=$(curl -k -s -X POST "$LEMUR_API/certificates" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "authority": {"id": 1},
    "owner": "user@email.com",
    "commonName": "multi-dest-api.example.com",
    "description": "Certificate with multiple destinations",
    "validityYears": 1,
    "country": "US",
    "state": "California",
    "location": "San Francisco",
    "organization": "Example Inc",
    "destinations": [{"id": 11}, {"id": 12}]
  }')

# Check if successful
CERT_ID=$(echo "$CERT_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('id', 'error'))" 2>/dev/null)

if [ "$CERT_ID" = "error" ]; then
  echo "❌ Failed to create certificate"
  echo "$CERT_RESPONSE" | python3 -m json.tool
  echo ""
  echo "Possible causes:"
  echo "  1. LEMUR_DISABLE_DESTINATION_UPLOADS not set to True"
  echo "  2. Runtime patch not applied"
  echo "  3. Container needs restart"
  exit 1
else
  echo "✅ Certificate created successfully!"
  echo "   ID: $CERT_ID"
  
  # Get certificate details
  DEST_COUNT=$(echo "$CERT_RESPONSE" | python3 -c "import sys, json; print(len(json.load(sys.stdin).get('destinations', [])))" 2>/dev/null)
  echo "   Destinations: $DEST_COUNT"
  
  # List destinations
  echo "$CERT_RESPONSE" | python3 -c "
import sys, json
for d in json.load(sys.stdin).get('destinations', []):
    print(f\"     - {d['label']} (ID: {d['id']})\")
"
  
  echo ""
  echo "🔗 View in UI: https://localhost:8447/#/certificates/$CERT_ID"
fi
```

## Troubleshooting

### Error: "permission denied"

**Cause**: Destination upload is being attempted but credentials are not available.

**Solution**:

```bash
# 1. Verify flag is set
docker exec -i local-lemur env | grep LEMUR_DISABLE_DESTINATION_UPLOADS

# 2. If not set, add to local/lemur-env and restart
echo "LEMUR_DISABLE_DESTINATION_UPLOADS=True" >> local/lemur-env
cd local && docker-compose restart lemur

# 3. Apply runtime patch (see above)
# 4. Restart container
cd local && docker-compose restart lemur
```

### Error: "Unable to locate credentials"

**Cause**: AWS destination is trying to deploy but AWS credentials are missing.

**Solution**: Same as "permission denied" - ensure upload bypass is working.

### Destinations Not Showing on Certificate

**Check via API**:

```bash
CERT_ID=15  # Your certificate ID
curl -k -s -H "Authorization: Bearer $TOKEN" \
  "$LEMUR_API/certificates/$CERT_ID" | \
  python3 -c "import sys, json; d=json.load(sys.stdin); print(f'Destinations: {len(d.get(\"destinations\", []))}')"
```

### Container Restart Loses Patch

The runtime patch is applied in-memory. After restart, you need to:

1. **Option A**: Rebuild container with patch built-in (see Dockerfile changes)
2. **Option B**: Reapply patch after each restart
3. **Option C**: Make patch permanent by modifying source before building

## Alternative: Use Python Script

If API continues to fail, use the Python script which bypasses the upload event:

```bash
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py my-cert.example.com
```

This works reliably because it links destinations directly in the database.

## Comparison

| Method | Pros | Cons |
|--------|------|------|
| **API (curl)** | Standard approach, mimics production | Requires patch to be applied |
| **Python Script** | Always works, no patch needed | Non-standard, local dev only |

## See Also

- [INTEGRATION_TEST_CONNECTION.md](INTEGRATION_TEST_CONNECTION.md) - API connection info
- [LOCAL_DEVELOPMENT.md](LOCAL_DEVELOPMENT.md) - Local dev guide
- [VAULT_JWT_INTEGRATION.md](VAULT_JWT_INTEGRATION.md) - Vault setup
