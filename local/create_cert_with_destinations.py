#!/usr/bin/env python3
"""
Create a certificate with destinations in local development.

This script bypasses destination plugin uploads by linking destinations
directly at the database level. This is useful when destination plugins
require credentials not available in local development (e.g., AWS, COA).

Usage:
    python3 create_cert_with_destinations.py [common_name] [--dest DEST_ID ...]

Examples:
    # Auto-find latest COA and AWS destinations
    python3 create_cert_with_destinations.py

    # Use specific common name
    python3 create_cert_with_destinations.py my-cert.example.com

    # Link specific destination IDs
    python3 create_cert_with_destinations.py my-cert.example.com --dest 11 --dest 12
"""
import sys
import argparse
from datetime import datetime, timedelta

from lemur.factory import create_app

app = create_app()


def get_user():
    """Get the default user for certificate creation."""
    from lemur.users import service as user_service
    
    user = user_service.get_by_username("user") or user_service.get_by_username("lemur")
    if not user:
        print("❌ Error: No user found", file=sys.stderr)
        sys.exit(1)
    return user


def get_authority():
    """Get the default authority for certificate creation."""
    from lemur.authorities import service as authority_service
    
    authority = authority_service.get_by_name("TestCA")
    if not authority:
        try:
            authority = authority_service.get(1)
        except Exception:
            print("❌ Error: No authority found", file=sys.stderr)
            sys.exit(1)
    return authority


def find_destinations(dest_ids=None):
    """
    Find destinations to link to certificate.
    
    Args:
        dest_ids: List of specific destination IDs, or None to auto-discover
    
    Returns:
        List of destination objects
    """
    from lemur.destinations import service as destination_service
    
    if dest_ids:
        # Get specific destinations by ID
        destinations = []
        for dest_id in dest_ids:
            try:
                dest = destination_service.get(dest_id)
                if dest:
                    destinations.append(dest)
                    print(f"✓ Found destination: {dest.label} (ID: {dest.id})")
                else:
                    print(f"⚠️  Warning: Destination ID {dest_id} not found", file=sys.stderr)
            except Exception as e:
                print(f"⚠️  Warning: Could not get destination {dest_id}: {e}", file=sys.stderr)
        return destinations
    
    # Auto-discover COA and AWS destinations
    destinations = []
    all_dests = destination_service.get_all()
    
    # Find latest COA destination
    coa_dests = [d for d in all_dests if 'cert-orchestration-adapter' in d.plugin.slug]
    if coa_dests:
        dest = coa_dests[-1]
        destinations.append(dest)
        print(f"✓ Found COA destination: {dest.label} (ID: {dest.id})")
    
    # Find latest AWS destination
    aws_dests = [d for d in all_dests if 'aws' in d.plugin.slug.lower()]
    if aws_dests:
        dest = aws_dests[-1]
        destinations.append(dest)
        print(f"✓ Found AWS destination: {dest.label} (ID: {dest.id})")
    
    return destinations


def create_certificate(common_name, user, authority):
    """Create a certificate without destinations."""
    from lemur.certificates import service as certificate_service
    
    # Check if certificate already exists
    existing = certificate_service.get_by_name(common_name)
    if existing:
        print(f"✓ Certificate '{common_name}' already exists (ID: {existing.id})")
        return existing
    
    certificate_options = {
        "authority": authority,
        "owner": "user@email.com",
        "common_name": common_name,
        "description": f"Certificate with destinations (local dev)",
        "validity_start": datetime.utcnow(),
        "validity_end": datetime.utcnow() + timedelta(days=365),
        "country": "US",
        "state": "California",
        "location": "San Francisco",
        "organization": "Example Inc",
        "organizational_unit": "IT",
        "key_type": "ECCPRIME256V1",
        "creator": user
    }
    
    cert = certificate_service.create(**certificate_options)
    print(f"✓ Certificate created: {common_name} (ID: {cert.id})")
    return cert


def link_destinations(cert, destinations):
    """Link destinations to certificate via database (bypassing upload)."""
    from lemur.database import db
    from lemur.certificates.models import certificate_destination_associations
    
    print(f"\n🔗 Linking {len(destinations)} destination(s) (bypassing upload)...")
    
    linked_count = 0
    for dest in destinations:
        existing_dest_ids = [d.id for d in cert.destinations]
        if dest.id not in existing_dest_ids:
            stmt = certificate_destination_associations.insert().values(
                certificate_id=cert.id,
                destination_id=dest.id
            )
            db.session.execute(stmt)
            print(f"  ✓ Linked: {dest.label} (ID: {dest.id})")
            linked_count += 1
        else:
            print(f"  - Already linked: {dest.label} (ID: {dest.id})")
    
    db.session.commit()
    
    # Refresh certificate to see updated destinations
    db.session.refresh(cert)
    
    print(f"\n✅ Success! Certificate has {len(cert.destinations)} destination(s):")
    for dest in cert.destinations:
        print(f"   • {dest.label} (Plugin: {dest.plugin_name})")
    
    print(f"\n🔗 View in UI: https://localhost:8447/#/certificates/{cert.id}")


def main():
    parser = argparse.ArgumentParser(
        description="Create certificate with destinations (local dev)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-discover latest COA and AWS destinations
  %(prog)s

  # Custom common name
  %(prog)s my-cert.example.com

  # Specific destination IDs
  %(prog)s my-cert.example.com --dest 11 --dest 12
        """
    )
    parser.add_argument(
        'common_name',
        nargs='?',
        default='multi-dest.example.com',
        help='Certificate common name (default: multi-dest.example.com)'
    )
    parser.add_argument(
        '--dest',
        action='append',
        type=int,
        dest='dest_ids',
        help='Destination ID to link (can specify multiple)'
    )
    
    args = parser.parse_args()
    
    with app.app_context():
        try:
            print(f"🎯 Creating certificate: {args.common_name}\n")
            
            # Get resources
            user = get_user()
            authority = get_authority()
            destinations = find_destinations(args.dest_ids)
            
            if not destinations:
                print("\n❌ Error: No destinations found", file=sys.stderr)
                sys.exit(1)
            
            # Create certificate
            print()
            cert = create_certificate(args.common_name, user, authority)
            
            # Link destinations
            link_destinations(cert, destinations)
            
        except Exception as e:
            print(f"\n❌ Error: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            sys.exit(1)


if __name__ == "__main__":
    main()
