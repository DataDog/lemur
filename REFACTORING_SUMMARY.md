# Refactoring Summary - Streamlined Local Development

## What Was Cleaned Up

### Deleted Failing/Obsolete Scripts (7 files)
1. ✅ `create_cert_with_dests_complete.sh` - API-based script that fails with permission errors
2. ✅ `create_destination_and_link.sh` - Example/reference script, no longer needed
3. ✅ `link_coa_to_cert.sh` - API-based linking script that fails locally
4. ✅ `create_cert_and_link_dests_db.py` - Old version, replaced with refactored version
5. ✅ `test_api_token.sh` - Test script, functionality covered by new docs
6. ✅ `test_authority_serialization.py` - Test script, not needed
7. ✅ `patch_destination_upload.py` - One-time patch script, already applied
8. ✅ `CREATE_CERT_WITH_DESTINATIONS_LOCALLY.md` - Replaced with better documentation

### Created Streamlined Solution (3 files)

#### 1. `create_cert_with_destinations.py` (Refactored)
Clean, well-documented Python script with:
- Command-line argument support
- Auto-discovery or manual destination selection
- Clean emoji-based output
- Proper error handling
- Help documentation

**Usage:**
```bash
# Auto-discover latest COA and AWS destinations
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py

# Custom common name
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py my-cert.example.com

# Specific destinations
docker exec -i local-lemur python3 /opt/lemur/local/create_cert_with_destinations.py my-cert.example.com --dest 11 --dest 12
```

#### 2. `LOCAL_DEVELOPMENT.md` (New)
Comprehensive guide covering:
- Quick start steps
- Certificate creation with destinations
- Useful scripts
- Troubleshooting
- Configuration details

#### 3. `INTEGRATION_TESTING.md` (Already existed)
Full integration testing guide with JWT tokens and API examples

### Kept Useful Scripts (2 files)
1. ✅ `generate_test_token_constant.py` - JWT token generation for API auth
2. ✅ `create_authority.sh` - Creates test authorities via API

## Key Improvements

### Before
- Multiple failing shell scripts using API endpoints
- Confusing error messages
- Scattered documentation
- No clear solution for local development
- 7 obsolete/failing files cluttering the repo

### After
- Single, clean Python script that works reliably
- Clear, user-friendly output with emojis
- Consolidated documentation
- Clear separation: Python for local dev, API for production
- Clean, focused codebase

## Technical Solution

### Problem
Destination plugins (COA, AWS) require credentials not available locally, causing "permission denied" errors when using API endpoints.

### Solution
Bypass the plugin upload mechanism by:
1. Creating certificate without destinations
2. Linking destinations directly in database via association table
3. This skips the `update_destinations` event listener that triggers uploads

### Configuration
- `local/lemur-env`: Added `LEMUR_DISABLE_DESTINATION_UPLOADS=True`
- `local/src/lemur.conf.py`: Added config flag support
- Applied patch to `lemur/certificates/models.py` for upload bypass

## Example Output (New Script)

```
🎯 Creating certificate: test-refactored.example.com

✓ Found COA destination: COA-Destination (ID: 17)
✓ Found AWS destination: AWS-Destination (ID: 18)

✓ Certificate created: test-refactored.example.com (ID: 16)

🔗 Linking 2 destination(s) (bypassing upload)...
  ✓ Linked: COA-Destination (ID: 17)
  ✓ Linked: AWS-Destination (ID: 18)

✅ Success! Certificate has 2 destination(s):
   • COA-Destination (Plugin: cert-orchestration-adapter-dest)
   • AWS-Destination (Plugin: aws-destination)

🔗 View in UI: https://localhost:8447/#/certificates/16
```

## Files Summary

### Active Files (3)
- `create_cert_with_destinations.py` - Main script for local dev
- `generate_test_token_constant.py` - Token generation
- `create_authority.sh` - Authority creation

### Documentation (2)
- `LOCAL_DEVELOPMENT.md` - Local dev guide
- `INTEGRATION_TESTING.md` - Integration testing guide

### Configuration (2)
- `local/lemur-env` - Environment variables
- `local/src/lemur.conf.py` - Application config

## Next Steps

For developers:
1. Use `create_cert_with_destinations.py` for local certificate testing
2. See `LOCAL_DEVELOPMENT.md` for setup and usage
3. Use API endpoints (with proper credentials) in production

For production:
- API endpoints work normally with valid credentials
- The `LEMUR_DISABLE_DESTINATION_UPLOADS` flag should remain `False`
