#!/bin/bash

# Quick policy verification script

echo "=== Check Extension Policy Verification ==="
echo

echo "1. Checking managed preference files:"
if [[ -f "/Library/Managed Preferences/com.microsoft.Edge.plist" ]]; then
    echo "✓ Edge managed preferences found"
    echo "  Content preview:"
    sudo plutil -p "/Library/Managed Preferences/com.microsoft.Edge.plist" 2>/dev/null | head -20
else
    echo "✗ Edge managed preferences NOT found"
fi

echo

if [[ -f "/Library/Managed Preferences/com.google.Chrome.plist" ]]; then
    echo "✓ Chrome managed preferences found"
    echo "  Content preview:"
    sudo plutil -p "/Library/Managed Preferences/com.google.Chrome.plist" 2>/dev/null | head -20
else
    echo "✗ Chrome managed preferences NOT found"
fi

echo
echo "2. Checking configuration profiles:"
profiles -P 2>/dev/null | grep -E "(Check|cyberdrain)" || echo "No Check-related profiles found"

echo
echo "3. Manual verification steps:"
echo "   a. Open Edge and go to: edge://policy/"
echo "   b. Look for '3rdparty' section with extension policies"
echo "   c. Open Chrome and go to: chrome://policy/"
echo "   d. Look for '3rdparty' section with extension policies"
echo "   e. Check extensions page: edge://extensions/ or chrome://extensions/"

echo
echo "4. If policies aren't showing:"
echo "   - Completely quit and restart the browsers"
echo "   - Check that the extension is actually installed"
echo "   - Verify the browser is reading managed preferences"

echo
echo "5. Browser restart commands:"
echo "   sudo pkill -f 'Microsoft Edge'"
echo "   sudo pkill -f 'Google Chrome'"