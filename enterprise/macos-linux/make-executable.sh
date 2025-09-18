#!/bin/bash

# Make all shell scripts executable
# Run this script after downloading/cloning on Unix systems

echo "Making shell scripts executable..."

chmod +x deploy.sh
chmod +x deploy-macos.sh
chmod +x deploy-linux.sh

echo "Done! Scripts are now executable."
echo ""
echo "Usage examples:"
echo "  ./deploy.sh install      # Universal deployment"
echo "  ./deploy-macos.sh install # macOS specific"
echo "  ./deploy-linux.sh install # Linux specific"
