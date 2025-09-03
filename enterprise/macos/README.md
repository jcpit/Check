# Check Extension - macOS Enterprise Deployment

This directory contains the necessary files and scripts for deploying the Check extension in macOS enterprise environments using Configuration Profiles and Chrome managed policies.

## Files Overview

- **`check-extension-config.mobileconfig`** - Apple Configuration Profile containing all extension settings
- **`chrome-managed-policy.json`** - Chrome-specific managed policies for extension installation and configuration
- **`deploy-macos.sh`** - Deployment script for installing/uninstalling the configuration
- **`README.md`** - This documentation file

## Prerequisites

- macOS 10.13 or later
- Administrator/root privileges
- Google Chrome installed on target machines
- Valid Chrome extension ID (replace `EXTENSION_ID_HERE` in files)

## Quick Start

1. **Update Extension ID**: Replace `EXTENSION_ID_HERE` in both configuration files with your actual Chrome extension ID
2. **Run deployment script**: `sudo ./deploy-macos.sh install`
3. **Verify installation**: `sudo ./deploy-macos.sh status`

## Detailed Setup

### 1. Prepare Configuration Files

Before deployment, you must update the extension ID in both configuration files:

#### Update Configuration Profile
Edit `check-extension-config.mobileconfig` and replace `EXTENSION_ID_HERE` with your actual extension ID in these locations:
- PayloadContent → ExtensionSettings → (your-extension-id)
- PayloadContent → ExtensionInstallAllowlist

#### Update Chrome Policy
Edit `chrome-managed-policy.json` and replace `EXTENSION_ID_HERE` with your actual extension ID.

### 2. Deployment Methods

#### Method 1: Automated Script (Recommended)
```bash
# Make script executable
chmod +x deploy-macos.sh

# Install configuration
sudo ./deploy-macos.sh install

# Check status
sudo ./deploy-macos.sh status

# Uninstall if needed
sudo ./deploy-macos.sh uninstall
```

#### Method 2: Manual Installation

**Install Configuration Profile:**
```bash
sudo profiles -I -F check-extension-config.mobileconfig
```

**Install Chrome Managed Policy:**
```bash
# Create managed preferences directory
sudo mkdir -p "/Library/Managed Preferences"

# Convert and install policy
sudo plutil -convert binary1 chrome-managed-policy.json -o "/Library/Managed Preferences/com.google.Chrome.plist"

# Set permissions
sudo chown root:wheel "/Library/Managed Preferences/com.google.Chrome.plist"
sudo chmod 644 "/Library/Managed Preferences/com.google.Chrome.plist"
```

### 3. Enterprise Distribution

#### Option A: Profile Manager (macOS Server)
1. Upload `check-extension-config.mobileconfig` to Profile Manager
2. Assign to appropriate device groups or users
3. Deploy Chrome managed policy separately via script

#### Option B: MDM Solution (Jamf, Intune, etc.)
1. Import configuration profile into your MDM
2. Create policy for Chrome managed preferences
3. Deploy to target devices/groups

#### Option C: Manual Distribution
1. Copy files to target machines
2. Run deployment script on each machine
3. Verify installation with status command

## Configuration Options

The Configuration Profile manages these extension settings:

### Security Settings
- **Show Notifications** (`showNotifications`): Display security alerts to users
- **Enable Valid Page Badge** (`enableValidPageBadge`): Show verification badge on safe pages
- **Enable Page Blocking** (`enablePageBlocking`): Block access to malicious pages
- **Enable CIPP Reporting** (`enableCippReporting`): Send security data to CIPP dashboard

### Server Configuration
- **CIPP Server URL** (`cippServerUrl`): Custom CIPP server endpoint
- **Custom Rules URL** (`customRulesUrl`): Alternative rule source
- **Update Interval** (`updateInterval`): Rule update frequency (minutes)

### Logging & Debugging
- **Enable Debug Logging** (`enableDebugLogging`): Detailed logging for troubleshooting

### Branding Options
- **Custom Branding** (`customBranding`): Organization-specific branding
  - Company Name
  - Logo URL
  - Primary/Secondary Colors
  - Contact Information

## Verification

### Check Profile Installation
```bash
# List all profiles
sudo profiles -P

# Check specific profile
sudo profiles -P | grep "com.cyberdrain.check"
```

### Verify Chrome Policy
```bash
# Check policy file exists
ls -la "/Library/Managed Preferences/com.google.Chrome.plist"

# View policy contents
sudo plutil -p "/Library/Managed Preferences/com.google.Chrome.plist"
```

### Test in Chrome
1. Open Chrome and navigate to `chrome://policy`
2. Verify "ExtensionSettings" and "ExtensionInstallAllowlist" policies are present
3. Check extension is automatically installed and configured

## Troubleshooting

### Common Issues

**Profile Installation Fails**
- Ensure running with `sudo`
- Check Configuration Profile syntax with `plutil -lint`
- Verify file permissions are readable

**Chrome Policies Not Applied**
- Restart Chrome completely
- Check file exists at correct path: `/Library/Managed Preferences/com.google.Chrome.plist`
- Verify JSON syntax in source file

**Extension Not Installing**
- Confirm extension ID is correct in both files
- Check Chrome version compatibility
- Verify network access to Chrome Web Store

### Debug Commands

```bash
# Validate Configuration Profile
plutil -lint check-extension-config.mobileconfig

# Validate JSON policy
plutil -lint chrome-managed-policy.json

# Check Chrome policy loading
sudo log stream --predicate 'subsystem == "com.google.Chrome"' --info

# List all installed profiles
sudo profiles -P

# Remove specific profile
sudo profiles -R -p "com.cyberdrain.check.configuration"
```

## Security Considerations

- Configuration profiles are signed and tamper-evident
- Chrome managed policies require administrator privileges
- All settings can be centrally managed and audited
- Users cannot override enterprise policies
- Extension installation is forced and cannot be disabled by users

## Support

For deployment issues:
1. Run `sudo ./deploy-macos.sh status` to check current state
2. Check system logs for profile installation errors
3. Verify Chrome policy syntax and file permissions
4. Test with a single user before organization-wide deployment

## File Structure
```
enterprise/macos/
├── check-extension-config.mobileconfig  # Apple Configuration Profile
├── chrome-managed-policy.json           # Chrome managed policies
├── deploy-macos.sh                      # Deployment script
└── README.md                            # This documentation
```
