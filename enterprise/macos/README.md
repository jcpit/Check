# Check Extension - macOS Enterprise Deployment

This directory contains the necessary files for deploying the Check Microsoft 365 phishing protection extension in macOS enterprise environments using Configuration Profiles and Managed Preferences.

## Files Overview

### Configuration Profiles (.mobileconfig)
- **`chrome-extension-config.mobileconfig`** - Chrome extension configuration profile
- **`edge-extension-config.mobileconfig`** - Microsoft Edge extension configuration profile

### Managed Policies (.json)
- **`chrome-managed-policy.json`** - Chrome browser policies (managed preferences)
- **`edge-managed-policy.json`** - Microsoft Edge browser policies (managed preferences)

### Deployment Script
- **`deploy-macos.sh`** - Automated deployment script for installing/removing configurations

## Quick Start

### Automated Deployment
```bash
# Make the script executable
chmod +x deploy-macos.sh

# Install configuration for both browsers
sudo ./deploy-macos.sh install

# Check installation status
sudo ./deploy-macos.sh status

# Remove configuration
sudo ./deploy-macos.sh uninstall
```

### Manual Deployment

#### Configuration Profiles
```bash
# Install Chrome profile
sudo profiles -I -F chrome-extension-config.mobileconfig

# Install Edge profile  
sudo profiles -I -F edge-extension-config.mobileconfig

# List installed profiles
sudo profiles -P
```

#### Managed Preferences
```bash
# Create directories
sudo mkdir -p "/Library/Managed Preferences"

# Install Chrome policy
sudo plutil -convert binary1 chrome-managed-policy.json -o "/Library/Managed Preferences/com.google.Chrome.plist"

# Install Edge policy
sudo plutil -convert binary1 edge-managed-policy.json -o "/Library/Managed Preferences/com.microsoft.Edge.plist"

# Set permissions
sudo chown root:wheel "/Library/Managed Preferences/com.google.Chrome.plist"
sudo chown root:wheel "/Library/Managed Preferences/com.microsoft.Edge.plist"
sudo chmod 644 "/Library/Managed Preferences/com.google.Chrome.plist"
sudo chmod 644 "/Library/Managed Preferences/com.microsoft.Edge.plist"
```

## Configuration Settings

All settings are based on the managed schema and include:

### Security Settings
- **`showNotifications`** - Display security notifications (default: true)
- **`enableValidPageBadge`** - Show validation badge on legitimate pages (default: true)  
- **`enablePageBlocking`** - Enable blocking of malicious pages (default: true)
- **`enableCippReporting`** - Enable CIPP server reporting (default: false)
- **`enableDebugLogging`** - Enable debug logging (default: false)

### CIPP Integration
- **`cippServerUrl`** - CIPP server URL for reporting
- **`cippTenantId`** - Tenant identifier for multi-tenant environments

### Rule Management
- **`customRulesUrl`** - URL for custom detection rules
- **`updateInterval`** - Rule update interval in hours (default: 24)

### Custom Branding
- **`companyName`** - Company name for white labeling
- **`productName`** - Custom extension name
- **`supportEmail`** - Support contact email
- **`primaryColor`** - Primary theme color (hex format)
- **`logoUrl`** - Company logo URL

## Extension IDs

- **Chrome**: `benimdeioplgkhanklclahllklceahbe`
- **Microsoft Edge**: `knepjpocdagponkonnbggpcnhnaikajg`

## Enterprise Features

### Force Installation
Both configurations include force installation settings that:
- Automatically install the extension
- Prevent users from disabling it
- Enable operation in incognito/private browsing mode
- Allow all permissions and hosts

### Policy Management
The managed preferences approach allows:
- Centralized configuration management
- Real-time policy updates
- Integration with existing MDM solutions
- Granular permission control

## MDM Integration

These configuration files are compatible with:
- **Jamf Pro** - Import .mobileconfig files directly
- **Microsoft Intune** - Convert to .intunemac format
- **VMware Workspace ONE** - Upload as custom settings
- **Kandji** - Use as custom profiles
- **SimpleMDM** - Import configuration profiles

## Troubleshooting

### Verify Installation
```bash
# Check profiles
sudo profiles -P | grep cyberdrain

# Check managed preferences
ls -la "/Library/Managed Preferences/"
plutil -p "/Library/Managed Preferences/com.google.Chrome.plist"
plutil -p "/Library/Managed Preferences/com.microsoft.Edge.plist"
```

### Common Issues
1. **Permission denied** - Ensure running with sudo
2. **Profile installation failed** - Check .mobileconfig syntax
3. **Policy not applied** - Restart browser after installation
4. **Extension not loading** - Verify extension IDs are correct

### Logs
- System logs: `sudo log show --predicate 'process == "profiles"' --last 1h`
- Browser console: Check extension developer tools

## Customization

Before deployment, edit the JSON files to customize:
1. **CIPP Integration** - Set `cippServerUrl` and `cippTenantId`
2. **Custom Rules** - Set `customRulesUrl` to your rules endpoint
3. **Branding** - Configure company name, colors, and logo
4. **Security Settings** - Adjust notification and blocking preferences

## Security Considerations

- Configuration files contain extension policies only
- No sensitive data is stored in profiles
- All settings can be overridden by managed preferences
- Private browsing mode is enabled by default
- Extension has full permissions for threat detection

## Support

For enterprise deployment assistance:
- Review the deployment script logs
- Check browser extension management pages
- Verify network connectivity for rule updates
- Contact CyberDrain support for configuration help
