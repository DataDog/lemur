#!/bin/bash
# Apply runtime patch to bypass destination uploads for local development

echo "Applying Destination Upload Bypass Patch"
echo "========================================"
echo ""

docker exec -i local-lemur python3 << 'EOF'
import os
import sys

models_path = '/opt/lemur/lemur/certificates/models.py'

print("📝 Checking current state...")

# Read current content
with open(models_path, 'r') as f:
    content = f.read()

# Check if already patched
if 'LEMUR_DISABLE_DESTINATION_UPLOADS' in content:
    print("✅ Patch already applied - no changes needed")
    sys.exit(0)

print("🔧 Applying patch...")

# Define the patch
old_code = '''@event.listens_for(Certificate.destinations, "append")
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

new_code = '''@event.listens_for(Certificate.destinations, "append")
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

# Apply patch
if old_code in content:
    content = content.replace(old_code, new_code)
    with open(models_path, 'w') as f:
        f.write(content)
    print("✅ Patch applied successfully!")
    print("")
    print("Next step: Restart the container to apply changes")
    print("  cd local && docker-compose restart lemur")
else:
    print("⚠️  Could not find expected code to patch")
    print("   The file may have been modified or is a different version")
    print("")
    print("   Expected to find:")
    print("   @event.listens_for(Certificate.destinations, \"append\")")
    print("   def update_destinations(target, value, initiator):")
    sys.exit(1)
EOF

PATCH_RESULT=$?

if [ $PATCH_RESULT -eq 0 ]; then
  echo ""
  echo "🔄 Restarting Lemur container..."
  cd local && docker-compose restart lemur
  
  echo ""
  echo "✅ Done! You can now test certificate creation with destinations:"
  echo "   ./local/test_cert_api.sh"
else
  echo ""
  echo "❌ Patch failed - see error message above"
  exit 1
fi
