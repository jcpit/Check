# macOS Extension Enterprise Deployment - Clean Repository

This directory contains the working files for deploying the Check Microsoft 365 phishing protection extension in macOS enterprise environments.

## Current Working Files

### Configuration Profiles (.mobileconfig)
- **`chrome-extension-config.mobileconfig`** - Chrome extension installation profile
- **`edge-extension-config.mobileconfig`** - Microsoft Edge extension installation profile

### Managed Policy Files (.json)
- **`chrome-managed-policy.json`** - Chrome browser policies including extension settings
- **`edge-managed-policy.json`** - Microsoft Edge browser policies including extension settings

### Deployment Scripts
- **`deploy-macos.sh`** - Main macOS deployment script (use this)
- **`deploy.sh`** - Universal deployment script that detects OS
- **`deploy-linux.sh`** - Linux-specific deployment
- **`make-executable.sh`** - Makes scripts executable
- **`verify-policies.sh`** - Verifies policy installation

## Quick Deployment

### Method 1: Automated (Recommended)
```bash
# Make scripts executable
./make-executable.sh

# Deploy everything
sudo ./deploy-macos.sh install

# Check status
sudo ./deploy-macos.sh status
```

### Method 2: Manual Configuration Profiles
1. Double-click `chrome-extension-config.mobileconfig` in Finder
2. Double-click `edge-extension-config.mobileconfig` in Finder
3. Install via System Settings → Privacy & Security → Profiles

### Method 3: Manual Managed Preferences
```bash
# Convert JSON policies to binary plists
sudo plutil -convert binary1 chrome-managed-policy.json -o "/Library/Managed Preferences/com.google.Chrome.plist"
sudo plutil -convert binary1 edge-managed-policy.json -o "/Library/Managed Preferences/com.microsoft.Edge.plist"

# Set permissions
sudo chown root:wheel "/Library/Managed Preferences/com.google.Chrome.plist"
sudo chown root:wheel "/Library/Managed Preferences/com.microsoft.Edge.plist"
sudo chmod 644 "/Library/Managed Preferences/com.google.Chrome.plist"
sudo chmod 644 "/Library/Managed Preferences/com.microsoft.Edge.plist"
```

## Verification

After deployment:
1. **Close all browser instances completely**
2. **Open Chrome** → Go to `chrome://policy/` → Click "Reload policies"
3. **Open Edge** → Go to `edge://policy/` → Click "Reload policies"
4. **Check extension settings** in the extension's options page

## Troubleshooting

### Extensions install but don't receive managed settings:
- Verify JSON policies contain `3rdparty.extensions.{extension-id}` sections
- Ensure managed preferences are in `/Library/Managed Preferences/`
- Restart browsers completely after policy changes
- Check browser policy pages for errors

### Configuration profiles won't install:
- Remove any existing profiles first
- Install manually via System Settings if automatic deployment fails
- Check that profiles are properly formatted XML

### Policies don't appear in browsers:
- Clear browser policy cache: `rm -rf "/Library/Application Support/Google/Chrome/Default/Policy"`
- Restart browser completely
- Check file permissions on managed preferences

## File Status

### Working Files (Keep):
- `chrome-extension-config.mobileconfig` ✓
- `edge-extension-config.mobileconfig` ✓
- `chrome-managed-policy.json` ✓
- `edge-managed-policy.json` ✓
- `deploy-macos.sh` ✓
- `deploy.sh` ✓
- `deploy-linux.sh` ✓

### Deprecated/Removed Files:
- MCX-based files (deprecated on modern macOS)
- Separate extension preference files (not used by browsers)
- Failed deployment scripts