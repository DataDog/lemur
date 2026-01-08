#!/usr/bin/env python3
"""
Setup Vault integration for Lemur local development.

This script:
1. Tests Vault connection
2. Retrieves secrets from Vault
3. Creates a Vault destination in Lemur
4. Verifies the integration
"""
import os
import sys
import hvac
import json

def test_vault_connection():
    """Test connection to Vault."""
    vault_addr = os.environ.get('VAULT_ADDR', 'http://localhost:8200')
    vault_token = os.environ.get('VAULT_TOKEN', 'dev-root-token')
    
    print(f"🔌 Connecting to Vault at {vault_addr}...")
    
    try:
        client = hvac.Client(url=vault_addr, token=vault_token)
        
        if not client.is_authenticated():
            print("❌ Failed to authenticate with Vault")
            return None
        
        print("✅ Successfully connected to Vault")
        return client
    except Exception as e:
        print(f"❌ Error connecting to Vault: {e}")
        return None


def read_secrets_from_vault(client):
    """Read Lemur secrets from Vault."""
    print("\n📖 Reading secrets from Vault...")
    
    secrets = {}
    paths = ['database', 'jwt', 'encryption']
    
    for path in paths:
        try:
            secret_path = f'secret/data/lemur/{path}'
            response = client.secrets.kv.v2.read_secret_version(path=f'lemur/{path}', mount_point='secret')
            secrets[path] = response['data']['data']
            print(f"  ✓ Read secret: lemur/{path}")
        except Exception as e:
            print(f"  ⚠️  Could not read lemur/{path}: {e}")
    
    return secrets


def create_vault_destination():
    """Create a Vault destination in Lemur."""
    from lemur.factory import create_app
    
    app = create_app()
    
    with app.app_context():
        from lemur.destinations import service as destination_service
        
        # Check if Vault destination already exists
        existing = [d for d in destination_service.get_all() if 'vault' in d.label.lower()]
        if existing:
            print(f"\n✓ Vault destination already exists: {existing[0].label} (ID: {existing[0].id})")
            return existing[0]
        
        # Create new Vault destination
        vault_options = {
            'vault_url': os.environ.get('VAULT_ADDR', 'http://vault:8200'),
            'vault_token': os.environ.get('VAULT_TOKEN', 'dev-root-token'),
            'vault_mount': 'secret',
            'vault_path': 'lemur/certificates',
            'vault_kv_version': 2
        }
        
        try:
            destination = destination_service.create(
                label='Vault-Local-Dev',
                plugin_name='vault_destination',
                description='Local development Vault destination',
                options=vault_options
            )
            print(f"\n✅ Created Vault destination: {destination.label} (ID: {destination.id})")
            return destination
        except Exception as e:
            print(f"\n⚠️  Could not create Vault destination: {e}")
            print("Note: Vault destination plugin may not be installed")
            return None


def verify_jwt_config():
    """Verify JWT configuration."""
    print("\n🔐 Verifying JWT configuration...")
    
    jwt_secret = os.environ.get('LEMUR_TOKEN_SECRET')
    if jwt_secret:
        print(f"  ✓ JWT secret configured")
        print(f"  ✓ Algorithm: {os.environ.get('JWT_ALGORITHM', 'HS256')}")
        print(f"  ✓ Expiration: {os.environ.get('JWT_EXPIRATION_DELTA', '3600')}s")
    else:
        print("  ⚠️  JWT secret not configured")


def main():
    print("=" * 60)
    print("Vault Integration Setup for Lemur")
    print("=" * 60)
    
    # Test Vault connection
    client = test_vault_connection()
    if not client:
        sys.exit(1)
    
    # Read secrets
    secrets = read_secrets_from_vault(client)
    if secrets:
        print(f"\n✅ Retrieved {len(secrets)} secret groups from Vault")
        for key, value in secrets.items():
            print(f"   • {key}: {list(value.keys())}")
    
    # Verify JWT config
    verify_jwt_config()
    
    # Try to create Vault destination (optional)
    try:
        create_vault_destination()
    except Exception as e:
        print(f"\n⚠️  Note: Could not test Vault destination creation: {e}")
        print("   This is expected if running outside the Lemur container")
    
    print("\n" + "=" * 60)
    print("✅ Vault integration setup complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Start services: cd local && docker-compose up -d")
    print("2. Access Vault UI: http://localhost:8200/ui (token: dev-root-token)")
    print("3. Test integration: docker exec -i local-lemur python3 /opt/lemur/local/setup_vault_integration.py")


if __name__ == "__main__":
    main()
