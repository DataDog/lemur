# Local Development Guide

## Quick Start

### 1. Start the Environment

```bash
cd local
docker-compose up -d
```

Wait for services to initialize (~30 seconds), then verify:

```bash
curl -k https://localhost:8447/api/1/healthcheck
# Should return: ok
```

### 2. Generate Authentication Token

```bash
# Generate a constant token for API access
TOKEN=$(python3 local/generate_test_token_constant.py)

# Test the token
curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8447/api/1/certificates
```

The default credentials are:
- **Username:** `user`
- **Password:** `pass`
- **Email:** `user@email.com`

### 3. Access the Web UI

Open https://localhost:8447 in your browser and login with the default credentials.

## Creating Certificates with Destinations

### Problem
Destination plugins (COA, AWS, etc.) attempt to deploy certificates immediately, requiring credentials not available in local development. This causes "permission denied" errors.

### Solution
Use the Python script that bypasses plugin uploads by linking destinations at the database level.

### Usage

#### Auto-discover latest COA and AWS destinations:
```bash
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py
```

#### Custom common name:
```bash
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py my-cert.example.com
```

#### Link specific destination IDs:
```bash
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py my-cert.example.com --dest 5 --dest 7
```

### Example Output

```
🎯 Creating certificate: multi-dest.example.com

✓ Found COA destination: COA-Destination (ID: 11)
✓ Found AWS destination: AWS-Destination (ID: 12)

✓ Certificate created: multi-dest.example.com (ID: 15)

🔗 Linking 2 destination(s) (bypassing upload)...
  ✓ Linked: COA-Destination (ID: 11)
  ✓ Linked: AWS-Destination (ID: 12)

✅ Success! Certificate has 2 destination(s):
   • COA-Destination (Plugin: cert-orchestration-adapter-dest)
   • AWS-Destination (Plugin: aws-destination)

🔗 View in UI: https://localhost:8447/#/certificates/15
```

## Configuration

The local development environment has been configured to support destination linking without uploads:

### Environment (`local/lemur-env`)
```bash
LEMUR_DISABLE_DESTINATION_UPLOADS=True
```

### Configuration (`local/src/lemur.conf.py`)
```python
LEMUR_DISABLE_DESTINATION_UPLOADS = os.environ.get("LEMUR_DISABLE_DESTINATION_UPLOADS", "False") == "True"
```

This flag prevents the destination upload event from triggering during certificate creation in local development.

## Useful Scripts

### `generate_test_token_constant.py`
Generates JWT tokens for API authentication using the fixed local dev secret.

```bash
# Default admin user (ID: 1)
python3 local/generate_test_token_constant.py

# Different user ID
python3 local/generate_test_token_constant.py 2

# Fresh token with current timestamp
python3 local/generate_test_token_constant.py --dynamic
```

### `create_cert_with_destinations.py`
Creates certificates with destinations for local testing.

```bash
# Show help
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py --help
```

### `create_authority.sh`
Creates a test certificate authority via API.

```bash
./local/create_authority.sh
```

## Troubleshooting

### "Permission denied" errors
Make sure you're using the Python script inside the Docker container:
```bash
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py
```

API endpoints will still fail with destination uploads because they're not configured for local dev.

### Container won't start
```bash
cd local
docker-compose down
docker-compose up -d
docker-compose logs -f lemur
```

### Token is invalid
Ensure containers were restarted after updating `lemur-env`:
```bash
cd local
docker-compose restart
```

### Need to copy script to container
If the script isn't in the container:
```bash
docker cp local/create_cert_with_destinations.py local-lemur:/opt/lemur/local/
```

## Notes

- The Python script only works inside the Docker container with Flask app context
- The `LEMUR_DISABLE_DESTINATION_UPLOADS` flag is only for local development
- For production, always use API endpoints with proper authentication and credentials
- Default JWT secret is fixed for local dev to enable constant, reproducible tokens

## See Also

- `INTEGRATION_TESTING.md` - Full integration testing guide
- `local/README.md` - Local setup details (if exists)
