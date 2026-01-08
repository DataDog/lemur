#!/usr/bin/env python3
"""
Script to create a default test authority for local development.
This is called by the Docker entrypoint when LEMUR_CREATE_DEFAULTS=true.
"""
import sys
from datetime import datetime, timedelta

# Setup Flask app context
from lemur.factory import create_app
app = create_app()

with app.app_context():
    from lemur.authorities import service as authority_service
    from lemur.users import service as user_service
    from lemur.plugins.base import plugins
    
    # Check if TestCA authority already exists
    existing = authority_service.get_by_name("TestCA")
    if existing:
        print(" # Default authority 'TestCA' already exists")
        sys.exit(0)
    
    # Get the default user to set as creator
    user = user_service.get_by_username("user")
    if not user:
        # If the user doesn't exist yet, use the lemur user
        user = user_service.get_by_username("lemur")
    
    if not user:
        print(" # Error: No user found to set as authority creator")
        sys.exit(1)
    
    # Get the cryptography issuer plugin object
    plugin = plugins.get("cryptography-issuer")
    if not plugin:
        print(" # Error: cryptography-issuer plugin not found")
        sys.exit(1)
    
    # Authority options
    authority_options = {
        "name": "TestCA",
        "owner": "user@email.com",
        "description": "Test Certificate Authority for local development",
        "common_name": "TestCA Root CA",
        "country": "US",
        "state": "California",
        "location": "San Francisco",
        "organization": "Example Inc",
        "organizational_unit": "IT Department",
        "type": "root",
        "signing_algorithm": "sha256WithRSA",
        "key_type": "RSA2048",
        "sensitivity": "medium",
        "serial_number": 1,
        "first_serial": 1,
        "validity_start": datetime(2000, 1, 1),
        "validity_end": datetime(2000, 1, 1) + timedelta(days=36500),  # 100 years from 2000-01-01
        "plugin": {
            "slug": "cryptography-issuer",
            "plugin_object": plugin
        },
        "extensions": {
            "sub_alt_names": {"names": []},
            "custom": []
        },
        "creator": user
    }
    
    try:
        authority = authority_service.create(**authority_options)
        print(f" # Default authority 'TestCA' created successfully (ID: {authority.id})")
        
        # Add the user to the authority roles so they can see and manage it
        from lemur.roles import service as role_service
        from lemur import database
        
        roles_to_add = ["TestCA_admin", "user@email.com"]
        for role_name in roles_to_add:
            role = role_service.get_by_name(role_name)
            if role and user:
                if role not in user.roles:
                    user.roles.append(role)
                    print(f" # Added user '{user.username}' to role '{role_name}'")
                else:
                    print(f" # User '{user.username}' already has role '{role_name}'")
        
        database.commit()
        print(f" # User roles updated successfully")
    except Exception as e:
        print(f" # Error creating default authority: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

