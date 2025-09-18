# Manual Installation Guide for macOS 13+

Since macOS 13.0 (Ventura), Apple has deprecated the command-line installation of configuration profiles. The `profiles` command no longer supports the `-I` (install) flag for security reasons.

## Installation Steps

### Option 1: Double-Click Installation (Recommended)
1. The deployment script has copied the configuration profiles to your Desktop:
   - `Check-Chrome-Extension.mobileconfig`
   - `Check-Edge-Extension.mobileconfig`

2. Double-click each `.mobileconfig` file
3. Follow the installation prompts
4. Enter your administrator password when prompted

### Option 2: System Settings Installation
1. Open **System Settings** (or **System Preferences** on older versions)
2. Navigate to **Privacy & Security** > **Profiles**
3. Click the **"+"** button (Add Profile)
4. Select the configuration profile files:
   - `chrome-extension-config.mobileconfig`
   - `edge-extension-config.mobileconfig`
5. Follow the installation prompts

### Verification
After installation, you can verify the profiles are installed:

1. Go to **System Settings** > **Privacy & Security** > **Profiles**
2. Look for:
   - "Check Extension Configuration"
   - "Check Extension Configuration (Edge)"

### Browser Configuration
The managed policies have been automatically installed to:
- Chrome: `/Library/Managed Preferences/com.google.Chrome.plist`
- Edge: `/Library/Managed Preferences/com.microsoft.Edge.plist`

### Troubleshooting

#### Profile Installation Issues
- Ensure you have administrator privileges
- Check that the profile files aren't corrupted
- Try restarting the system if installation fails

#### Extension Not Appearing
1. Restart Chrome/Edge completely
2. Check `chrome://extensions/` or `edge://extensions/`
3. Verify the extension appears in the managed extensions list
4. Check `chrome://policy/` or `edge://policy/` for applied policies

#### Policy Not Applied
1. Restart the browser
2. Check `chrome://policy/` or `edge://policy/`
3. Look for the "3rdparty" section with Check extension settings
4. Verify the extension has the correct permissions

## Enterprise Deployment

For large-scale enterprise deployment, consider:

1. **MDM Solutions**: Use tools like Jamf, Microsoft Intune, or Kandji
2. **Apple Configurator**: Create and deploy profiles at scale
3. **Script Deployment**: Use the provided deployment scripts in conjunction with MDM

## Support

If you encounter issues:
1. Check the TROUBLESHOOTING.md file
2. Verify system requirements (macOS 10.13+)
3. Ensure you have the latest version of the configuration profiles
4. Contact your system administrator for enterprise deployments