#!/usr/bin/env python3
"""
Generate a constant JWT token for integration tests in local development.

This script creates a JWT token using the fixed LEMUR_TOKEN_SECRET from the local dev environment.
The token is valid for 365 days and uses a FIXED timestamp so it generates the same token every time.

⚠️  WARNING: This token is ONLY for local development. Never use these secrets in production!

Usage:
    python3 generate_test_token_constant.py [user_id] [--dynamic]

Arguments:
    user_id  - Optional user ID (default: 1, which is the default 'user' admin account)
    --dynamic - Generate a new token with current timestamp (default: uses fixed timestamp)

Example:
    # Generate constant token for default admin user (always the same)
    python3 generate_test_token_constant.py
    
    # Generate constant token for user ID 2
    python3 generate_test_token_constant.py 2
    
    # Generate a fresh token with current timestamp
    python3 generate_test_token_constant.py --dynamic
    
    # Use in curl command
    TOKEN=$(python3 generate_test_token_constant.py)
    curl -k -H "Authorization: Bearer $TOKEN" https://localhost:8447/api/1/certificates
"""

import jwt
import sys
from datetime import datetime, timedelta

# Fixed secret for local development (matches docker/lemur-env)
# This is base64 encoded: "local-dev-secret-for-testing-only-do-not-use-in-prod"
LEMUR_TOKEN_SECRET = "bG9jYWwtZGV2LXNlY3JldC1mb3ItdGVzdGluZy1vbmx5LWRvLW5vdC11c2UtaW4tcHJvZA=="

def generate_token(user_id=1, days_valid=365, use_fixed_time=True):
    """
    Generate a JWT token for the specified user.
    
    Args:
        user_id: The user ID to generate the token for (default: 1)
        days_valid: Number of days the token should be valid (default: 365)
        use_fixed_time: If True, uses a fixed timestamp for constant tokens (default: True)
    
    Returns:
        str: The JWT token
    """
    if use_fixed_time:
        # Fixed timestamp: January 16, 2026 00:00:00 UTC
        # This ensures the token is always the same for testing
        issued_at = datetime(2026, 1, 16, 0, 0, 0)
        expiration = datetime(2027, 1, 16, 0, 0, 0)  # Exactly 365 days later
    else:
        # Dynamic timestamp: generates a new token each time
        issued_at = datetime.utcnow()
        expiration = issued_at + timedelta(days=days_valid)
    
    payload = {
        "iat": issued_at,
        "exp": expiration,
        "sub": user_id
    }
    
    # Note: PyJWT 2.x returns a string directly, older versions return bytes
    token = jwt.encode(payload, LEMUR_TOKEN_SECRET, algorithm="HS256")
    
    # Handle both PyJWT 1.x (returns bytes) and 2.x (returns string)
    if isinstance(token, bytes):
        return token.decode('utf-8')
    return token

def main():
    # Get user ID from command line argument or use default
    user_id = 1
    use_fixed_time = True  # Default: generate constant tokens
    
    for arg in sys.argv[1:]:
        if arg == '--dynamic':
            use_fixed_time = False
        elif arg.startswith('--'):
            print(f"Error: Unknown option '{arg}'", file=sys.stderr)
            print("Usage: python3 generate_test_token_constant.py [user_id] [--dynamic]", file=sys.stderr)
            return 1
        else:
            try:
                user_id = int(arg)
            except ValueError:
                print(f"Error: Invalid user ID '{arg}'. Must be an integer.", file=sys.stderr)
                return 1
    
    # Generate and print the token
    token = generate_token(user_id, use_fixed_time=use_fixed_time)
    print(token)
    return 0

if __name__ == '__main__':
    sys.exit(main())


