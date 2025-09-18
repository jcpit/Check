# Check Extension - Enterprise Deployment

This folder contains enterprise deployment resources for the Check Microsoft 365 Phishing Protection extension.

## Contents

- `admx/` - Group Policy Administrative Templates
  - `Check-Extension.admx` - Policy definitions file
  - `en-US/Check-Extension.adml` - English language resources
- `unix/` - Unix-based deployment (macOS & Linux)
  - Configuration Profiles for macOS
  - Browser policy files for Linux
  - Universal deployment scripts
- `Check-Extension-Policy.reg` - Windows registry file for direct policy application
- `Deploy-ADMX.ps1` - PowerShell script for Windows ADMX deployment

## Group Policy Deployment

### Installing the ADMX Templates

1. **Domain Environment (Recommended)**:
   ```powershell
   # Copy to PolicyDefinitions folder on domain controller
   Copy-Item "check.admx" "\\yourdomain.com\SYSVOL\yourdomain.com\Policies\PolicyDefinitions\"
   Copy-Item "en-US\check.adml" "\\yourdomain.com\SYSVOL\yourdomain.com\Policies\PolicyDefinitions\en-US\"
   ```

2. **Local Machine**:
   ```powershell
   # Copy to local PolicyDefinitions folder
   Copy-Item "check.admx" "$env:SystemRoot\PolicyDefinitions\"
   Copy-Item "en-US\check.adml" "$env:SystemRoot\PolicyDefinitions\en-US\"
   ```

### Accessing the Policies

After installing the templates, the policies will be available in the Group Policy Editor at:

```
Computer Configuration > Policies > Administrative Templates > CyberDrain > Check - Microsoft 365 Phishing Protection
```

### Policy Categories

The policies are organized into three categories:

#### Security Settings
- **Show Security Notifications** - Control notification display
- **Show Valid Page Badge** - Display badges on legitimate pages
- **Enable Page Blocking** - Block malicious pages
- **Enable CIPP Reporting** - Report to CIPP servers
- **CIPP Server URL** - Configure CIPP server endpoint
- **Custom Detection Rules URL** - Use custom threat detection rules
- **Detection Rules Update Interval** - Control update frequency

#### Logging & Debugging
- **Enable Debug Logging** - Enable detailed logging for troubleshooting

#### Branding & White Labeling
- **Company Name** - Customize company name display
- **Product Name** - Customize extension name
- **Support Email Address** - Set support contact
- **Primary Theme Color** - Customize interface colors
- **Company Logo URL** - Use custom logo

## Registry Settings

All policies write to the following registry location:
```
HKEY_LOCAL_MACHINE\Software\Policies\CyberDrain\Check
```

Branding settings are stored under:
```
HKEY_LOCAL_MACHINE\Software\Policies\CyberDrain\Check\CustomBranding
```

## Manual Registry Configuration

If Group Policy is not available, you can manually configure settings via registry:

```powershell
# Enable page blocking
New-ItemProperty -Path "HKLM:\Software\Policies\CyberDrain\Check" -Name "enablePageBlocking" -Value 1 -PropertyType DWord -Force

# Set company branding
New-Item -Path "HKLM:\Software\Policies\CyberDrain\Check\CustomBranding" -Force
New-ItemProperty -Path "HKLM:\Software\Policies\CyberDrain\Check\CustomBranding" -Name "companyName" -Value "Your Company" -PropertyType String -Force
New-ItemProperty -Path "HKLM:\Software\Policies\CyberDrain\Check\CustomBranding" -Name "productName" -Value "Your Security Extension" -PropertyType String -Force
```

## Policy Values

### Boolean Policies
- `1` or `Enabled` = True
- `0` or `Disabled` = False

### String Policies
- Text values as entered
- URLs must include protocol (https://)
- Email addresses must be valid format
- Color codes must be in hex format (#RRGGBB or #RGB)

### Numeric Policies
- **Update Interval**: 1-168 hours (integer)

## Troubleshooting

### Verify Policy Application
```powershell
# Check if policies are applied
Get-ItemProperty "HKLM:\Software\Policies\CyberDrain\Check" -ErrorAction SilentlyContinue

# Check branding policies
Get-ItemProperty "HKLM:\Software\Policies\CyberDrain\Check\CustomBranding" -ErrorAction SilentlyContinue
```

### Common Issues

1. **Policies not appearing in GPMC**:
   - Verify ADMX/ADML files are in correct location
   - Ensure files are not blocked (right-click > Properties > Unblock)
   - Refresh Group Policy Editor

2. **Policies not applying to extension**:
   - Check registry values are present
   - Restart browser after policy changes
   - Verify extension has necessary permissions

3. **Custom branding not working**:
   - Verify URLs are accessible via HTTPS
   - Check image formats are supported (PNG, JPG, SVG)
   - Ensure color codes are valid hex format

## Security Considerations

- Always use HTTPS URLs for custom rules and logos
- Regularly update custom detection rules
- Monitor debug logging usage (performance impact)
- Test policies in a lab environment before production deployment

## Support

For enterprise deployment support, contact your CyberDrain representative or visit:
- Documentation: https://github.com/CyberDrain/ProjectX
- Support: support@cyberdrain.com
