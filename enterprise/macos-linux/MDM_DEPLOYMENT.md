# MDM Deployment Guide

This guide provides instructions for deploying the Check extension configuration profiles through Mobile Device Management (MDM) solutions.

## Configuration Profile Details

### Chrome Extension Profile
- **File**: `chrome-extension-config.mobileconfig`
- **Identifier**: `com.cyberdrain.check.chrome.configuration`
- **PayloadType**: `com.google.Chrome`
- **Target**: Chrome browser extension management

### Edge Extension Profile
- **File**: `edge-extension-config.mobileconfig`
- **Identifier**: `com.cyberdrain.check.edge.configuration`
- **PayloadType**: `com.microsoft.Edge`
- **Target**: Microsoft Edge browser extension management

## Supported MDM Solutions

### Jamf Pro
1. Upload the `.mobileconfig` files to Jamf Pro
2. Create a new Configuration Profile
3. Upload the Chrome and Edge configuration files
4. Set scope to target computers/users
5. Deploy the profiles

### Microsoft Intune
1. Navigate to **Devices** > **Configuration profiles**
2. Create a new profile for macOS
3. Select **Custom** profile type
4. Upload the `.mobileconfig` files
5. Assign to appropriate groups

### Apple Business Manager + Apple School Manager
1. Use Apple Configurator 2 to create profiles
2. Import the existing `.mobileconfig` files
3. Deploy through Apple Business/School Manager
4. Assign to devices or users

### Other MDM Solutions
Most enterprise MDM solutions support custom configuration profiles:
- **Kandji**: Custom profiles section
- **SimpleMDM**: Configuration profiles
- **Addigy**: Custom profiles
- **Mosyle**: Custom profiles

## Deployment Considerations

### Extension Installation
The configuration profiles include:
- **Force installation** of the extension
- **Extension settings** and policies
- **Managed preferences** for browsers

### Browser Support
- **Chrome**: Extension ID `benimdeioplgkhanklclahllklceahbe`
- **Edge**: Extension ID `knepjpocdagponkonnbggpcnhnaikajg`

### User Experience
- Extensions will be installed automatically
- Users cannot disable or remove the extension
- Extension settings are managed centrally
- Custom branding can be configured

## Customization

### Modifying Settings
Edit the configuration profiles to customize:
- Company branding information
- CIPP reporting settings
- Custom rules URL
- Debug logging options

### Example Customizations
```xml
<key>customBranding</key>
<dict>
    <key>companyName</key>
    <string>Your Company Name</string>
    <key>productName</key>
    <string>Your Security Solution</string>
    <key>supportEmail</key>
    <string>support@yourcompany.com</string>
    <key>primaryColor</key>
    <string>#YOUR_HEX_COLOR</string>
    <key>logoUrl</key>
    <string>https://your-company.com/logo.png</string>
</dict>
```

## Testing and Validation

### Pre-Deployment Testing
1. Test profiles on a subset of devices
2. Verify extension installation and functionality
3. Check policy application in browsers
4. Validate custom branding appears correctly

### Post-Deployment Verification
1. Check MDM console for successful deployment
2. Verify profiles are installed on target devices
3. Confirm extensions are active in browsers
4. Test phishing detection functionality

### Monitoring Commands
```bash
# Check installed profiles
profiles -P

# Verify Chrome policies
defaults read com.google.Chrome

# Verify Edge policies
defaults read com.microsoft.Edge

# Check extension status
chrome://extensions/
edge://extensions/
```

## Troubleshooting

### Common Issues
1. **Profile installation fails**: Check device enrollment status
2. **Extension not appearing**: Verify browser restart and update
3. **Policies not applied**: Check managed preferences installation
4. **Custom branding not showing**: Verify configuration syntax

### Support Resources
- Check device logs in MDM console
- Review browser policy pages (`chrome://policy/`, `edge://policy/`)
- Use the provided validation scripts
- Reference the TROUBLESHOOTING.md guide

## Security Considerations

### Permissions
- Profiles install with system-level permissions
- Extensions have managed installation rights
- Users cannot modify or remove extensions

### Privacy
- Extension only processes webpage metadata
- No personal data is transmitted by default
- CIPP reporting is disabled by default

### Compliance
- Profiles can be audited through MDM reporting
- Extension activity can be monitored
- Deployment status is tracked centrally