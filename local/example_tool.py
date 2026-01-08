#!/usr/bin/env python3
"""
Example tool demonstrating how to authenticate with Lemur on behalf of a user

This shows the recommended pattern for CLI tools and services to interact
with Lemur's API using JWT authentication.

Usage:
  # First time - interactive login
  python3 example_tool.py login
  
  # List certificates
  python3 example_tool.py list-certs
  
  # Create destination
  python3 example_tool.py create-dest --label "My Destination"
  
  # Service mode - use stored token
  python3 example_tool.py --service-token "eyJhbG..." list-certs
"""

import requests
import json
import sys
import argparse
from pathlib import Path
import getpass
import urllib3

# Disable SSL warnings for local development
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class LemurClient:
    """Client for interacting with Lemur API"""
    
    def __init__(self, base_url, token=None, token_file=None):
        self.base_url = base_url.rstrip('/')
        self.token = token
        self.token_file = token_file or Path.home() / '.lemur-example-tool' / 'token'
    
    def login(self, username=None, password=None):
        """Authenticate with Lemur and store token"""
        if not username:
            username = input('Lemur Username: ')
        if not password:
            password = getpass.getpass('Lemur Password: ')
        
        print(f"🔐 Authenticating with {self.base_url}...")
        
        try:
            response = requests.post(
                f'{self.base_url}/auth/login',
                json={'username': username, 'password': password},
                verify=False,
                timeout=10
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"❌ Login failed: {e}")
            sys.exit(1)
        
        self.token = response.json()['token']
        
        # Save token securely
        self.token_file.parent.mkdir(parents=True, exist_ok=True)
        self.token_file.write_text(self.token)
        self.token_file.chmod(0o600)  # Read/write for owner only
        
        print(f"✅ Logged in successfully")
        print(f"   Token saved to: {self.token_file}")
        return self.token
    
    def _get_token(self):
        """Get token from file or prompt for login"""
        if self.token:
            return self.token
        
        if self.token_file.exists():
            self.token = self.token_file.read_text().strip()
            return self.token
        
        print("⚠️  No saved credentials found. Please login:")
        return self.login()
    
    def _request(self, method, endpoint, **kwargs):
        """Make authenticated request to Lemur API"""
        headers = kwargs.pop('headers', {})
        headers['Authorization'] = f'Bearer {self._get_token()}'
        
        url = f'{self.base_url}/{endpoint.lstrip("/")}'
        
        try:
            response = requests.request(
                method,
                url,
                headers=headers,
                verify=False,
                timeout=30,
                **kwargs
            )
        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed: {e}")
            sys.exit(1)
        
        # Handle token expiration
        if response.status_code == 401:
            print("⚠️  Token expired. Please login again:")
            self.token = None
            if self.token_file.exists():
                self.token_file.unlink()
            return self._request(method, endpoint, **kwargs)
        
        return response
    
    def list_certificates(self):
        """List all certificates"""
        response = self._request('GET', '/certificates')
        response.raise_for_status()
        return response.json()
    
    def get_certificate(self, cert_id):
        """Get certificate by ID"""
        response = self._request('GET', f'/certificates/{cert_id}')
        response.raise_for_status()
        return response.json()
    
    def list_destinations(self):
        """List all destinations"""
        response = self._request('GET', '/destinations')
        response.raise_for_status()
        return response.json()
    
    def create_destination(self, label, description, plugin_slug, options):
        """Create a new destination"""
        response = self._request('POST', '/destinations', json={
            'label': label,
            'description': description,
            'plugin': {'slug': plugin_slug},
            'options': options
        })
        response.raise_for_status()
        return response.json()


def cmd_login(args):
    """Handle login command"""
    client = LemurClient(args.base_url)
    client.login(args.username, args.password)


def cmd_list_certs(args):
    """Handle list-certs command"""
    client = LemurClient(args.base_url, token=args.service_token)
    
    print("📜 Fetching certificates...")
    data = client.list_certificates()
    
    total = data.get('total', 0)
    print(f"\n✅ Found {total} certificate(s):\n")
    
    for cert in data.get('items', [])[:10]:  # Show first 10
        print(f"  • {cert['name']}")
        print(f"    ID: {cert['id']}")
        print(f"    Owner: {cert.get('owner', 'N/A')}")
        print(f"    Not After: {cert.get('notAfter', 'N/A')}")
        print()
    
    if total > 10:
        print(f"  ... and {total - 10} more")


def cmd_list_dests(args):
    """Handle list-dests command"""
    client = LemurClient(args.base_url, token=args.service_token)
    
    print("🎯 Fetching destinations...")
    data = client.list_destinations()
    
    total = data.get('total', 0)
    print(f"\n✅ Found {total} destination(s):\n")
    
    for dest in data.get('items', []):
        print(f"  • {dest['label']} (ID: {dest['id']})")
        print(f"    Plugin: {dest['plugin']['slug']}")
        print(f"    Description: {dest.get('description', 'N/A')}")
        print()


def cmd_create_dest(args):
    """Handle create-dest command"""
    client = LemurClient(args.base_url, token=args.service_token)
    
    print(f"🎯 Creating destination '{args.label}'...")
    
    dest = client.create_destination(
        label=args.label,
        description=args.description or f"Created by example tool",
        plugin_slug=args.plugin,
        options={'accountNumber': args.account_number}
    )
    
    print(f"\n✅ Destination created successfully!")
    print(f"   ID: {dest['id']}")
    print(f"   Label: {dest['label']}")
    print(f"   Plugin: {dest['plugin']['slug']}")


def main():
    parser = argparse.ArgumentParser(
        description='Example tool for interacting with Lemur API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    
    parser.add_argument(
        '--base-url',
        default='https://localhost:8447/api/1',
        help='Lemur API base URL (default: https://localhost:8447/api/1)'
    )
    
    parser.add_argument(
        '--service-token',
        help='Service account token (for non-interactive use)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Login command
    login_parser = subparsers.add_parser('login', help='Login and save credentials')
    login_parser.add_argument('--username', help='Username (will prompt if not provided)')
    login_parser.add_argument('--password', help='Password (will prompt if not provided)')
    login_parser.set_defaults(func=cmd_login)
    
    # List certificates command
    list_certs_parser = subparsers.add_parser('list-certs', help='List certificates')
    list_certs_parser.set_defaults(func=cmd_list_certs)
    
    # List destinations command
    list_dests_parser = subparsers.add_parser('list-dests', help='List destinations')
    list_dests_parser.set_defaults(func=cmd_list_dests)
    
    # Create destination command
    create_dest_parser = subparsers.add_parser('create-dest', help='Create a destination')
    create_dest_parser.add_argument('--label', required=True, help='Destination label')
    create_dest_parser.add_argument('--description', help='Destination description')
    create_dest_parser.add_argument('--plugin', default='aws-destination', help='Plugin slug')
    create_dest_parser.add_argument('--account-number', default='123456789012', help='AWS account number')
    create_dest_parser.set_defaults(func=cmd_create_dest)
    
    args = parser.parse_args()
    
    if not hasattr(args, 'func'):
        parser.print_help()
        sys.exit(1)
    
    # Execute command
    args.func(args)


if __name__ == '__main__':
    main()
