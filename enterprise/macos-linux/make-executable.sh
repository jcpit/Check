#!/bin/bash

# Make all shell scripts executable
# Run this script after downloading/cloning on Unix systems

echo "Making shell scripts executable..."

chmod +x deploy.sh
chmod +x deploy-macos.sh
chmod +x deploy-linux.sh
chmod +x install-managed-preferences.sh
chmod +x verify-policies.sh

echo "Done! Scripts are now executable."
echo ""
echo "Usage examples:"
echo "  ./deploy.sh install               # Universal deployment"
echo "  ./deploy-macos.sh install        # macOS specific"
echo "  ./deploy-linux.sh install       # Linux specific"
echo "  ./install-managed-preferences.sh # Managed preferences only"
echo "  ./verify-policies.sh             # Verify policy installation"
