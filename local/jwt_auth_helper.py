#!/usr/bin/env python3
"""
JWT Authentication Helper for Lemur local development with Vault integration.

This script provides utilities for:
1. Generating JWT tokens with custom claims
2. Validating JWT tokens
3. Creating tokens with Vault-stored secrets
"""
import jwt
import os
import sys
from datetime import datetime, timedelta
import json
import argparse


def get_jwt_secret():
    """Get JWT secret from environment or Vault."""
    secret = os.environ.get('LEMUR_TOKEN_SECRET')
    
    if not secret:
        # Try to get from Vault if enabled
        vault_addr = os.environ.get('VAULT_ADDR')
        vault_token = os.environ.get('VAULT_TOKEN')
        
        if vault_addr and vault_token:
            try:
                import hvac
                client = hvac.Client(url=vault_addr, token=vault_token)
                if client.is_authenticated():
                    response = client.secrets.kv.v2.read_secret_version(
                        path='lemur/jwt',
                        mount_point='secret'
                    )
                    secret = response['data']['data'].get('secret')
                    print("✅ Loaded JWT secret from Vault", file=sys.stderr)
            except Exception as e:
                print(f"⚠️  Could not load JWT secret from Vault: {e}", file=sys.stderr)
    
    if not secret:
        print("❌ Error: LEMUR_TOKEN_SECRET not set and couldn't load from Vault", file=sys.stderr)
        sys.exit(1)
    
    return secret


def generate_jwt_token(user_id=1, email="user@email.com", roles=None, 
                       expiration_hours=1, custom_claims=None):
    """
    Generate a JWT token with custom claims.
    
    Args:
        user_id: User ID for the token
        email: User email
        roles: List of roles for the user
        expiration_hours: Token validity in hours
        custom_claims: Additional custom claims to include
    
    Returns:
        str: The JWT token
    """
    secret = get_jwt_secret()
    algorithm = os.environ.get('JWT_ALGORITHM', 'HS256')
    
    now = datetime.utcnow()
    expiration = now + timedelta(hours=expiration_hours)
    
    # Standard claims
    payload = {
        'iat': int(now.timestamp()),
        'exp': int(expiration.timestamp()),
        'sub': user_id,
        'email': email,
        'iss': os.environ.get('JWT_ISSUER', 'lemur'),
        'aud': os.environ.get('JWT_AUDIENCE', 'lemur-local-dev')
    }
    
    # Add roles
    if roles:
        payload['roles'] = roles
    else:
        payload['roles'] = ['admin']
    
    # Add custom claims
    if custom_claims:
        payload.update(custom_claims)
    
    # Generate token
    token = jwt.encode(payload, secret, algorithm=algorithm)
    
    # Handle both PyJWT 1.x (returns bytes) and 2.x (returns string)
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    
    return token


def decode_jwt_token(token, verify=True):
    """
    Decode and validate a JWT token.
    
    Args:
        token: The JWT token to decode
        verify: Whether to verify the signature
    
    Returns:
        dict: Decoded token payload
    """
    secret = get_jwt_secret()
    algorithm = os.environ.get('JWT_ALGORITHM', 'HS256')
    
    try:
        if verify:
            payload = jwt.decode(
                token,
                secret,
                algorithms=[algorithm],
                audience=os.environ.get('JWT_AUDIENCE', 'lemur-local-dev'),
                issuer=os.environ.get('JWT_ISSUER', 'lemur')
            )
        else:
            payload = jwt.decode(token, options={"verify_signature": False})
        
        return payload
    except jwt.ExpiredSignatureError:
        print("❌ Token has expired", file=sys.stderr)
        return None
    except jwt.InvalidTokenError as e:
        print(f"❌ Invalid token: {e}", file=sys.stderr)
        return None


def main():
    parser = argparse.ArgumentParser(
        description='JWT Authentication Helper for Lemur',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate token for default user
  %(prog)s generate

  # Generate token with custom user ID and email
  %(prog)s generate --user-id 2 --email admin@example.com

  # Generate token with custom expiration (24 hours)
  %(prog)s generate --hours 24

  # Generate token with custom roles
  %(prog)s generate --roles admin,operator

  # Decode and verify a token
  %(prog)s decode TOKEN_STRING

  # Decode token without verification
  %(prog)s decode TOKEN_STRING --no-verify
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Generate command
    gen_parser = subparsers.add_parser('generate', help='Generate a new JWT token')
    gen_parser.add_argument('--user-id', type=int, default=1, help='User ID (default: 1)')
    gen_parser.add_argument('--email', default='user@email.com', help='User email')
    gen_parser.add_argument('--roles', help='Comma-separated list of roles')
    gen_parser.add_argument('--hours', type=float, default=1, help='Token validity in hours')
    gen_parser.add_argument('--claims', help='Additional claims as JSON string')
    gen_parser.add_argument('--verbose', '-v', action='store_true', help='Show token details')
    
    # Decode command
    dec_parser = subparsers.add_parser('decode', help='Decode a JWT token')
    dec_parser.add_argument('token', help='JWT token to decode')
    dec_parser.add_argument('--no-verify', action='store_true', help='Skip signature verification')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == 'generate':
        # Parse roles
        roles = args.roles.split(',') if args.roles else None
        
        # Parse custom claims
        custom_claims = None
        if args.claims:
            try:
                custom_claims = json.loads(args.claims)
            except json.JSONDecodeError:
                print("❌ Error: Invalid JSON for custom claims", file=sys.stderr)
                sys.exit(1)
        
        # Generate token
        token = generate_jwt_token(
            user_id=args.user_id,
            email=args.email,
            roles=roles,
            expiration_hours=args.hours,
            custom_claims=custom_claims
        )
        
        if args.verbose:
            # Decode and display token details
            payload = decode_jwt_token(token, verify=False)
            print("🔐 Generated JWT Token", file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            print(json.dumps(payload, indent=2), file=sys.stderr)
            print("=" * 60, file=sys.stderr)
            print("\nToken:", file=sys.stderr)
        
        print(token)
    
    elif args.command == 'decode':
        payload = decode_jwt_token(args.token, verify=not args.no_verify)
        if payload:
            print(json.dumps(payload, indent=2))
        else:
            sys.exit(1)


if __name__ == "__main__":
    main()
