# Check Extension - Enterprise Deployment

This folder contains enterprise deployment resources for the Check Microsoft 365 Phishing Protection extension.

## Contents

- `admx/` - Group Policy Administrative Templates
   - `Check-Extension.admx` - Policy definitions file
   - `en-US` - English language resources
      - `Check-Extension.adml` - XML configuration file for Check
- `unix/` - Unix-based deployment (macOS & Linux)
   - Configuration Profiles for macOS
   - Browser policy files for Linux
   - Universal deployment scripts
- `Check-Extension-Policy.reg` - Windows registry file for direct policy application
- `Deploy-ADMX.ps1` - PowerShell script for Windows ADMX deployment
- `Deply-Windows-Chrome-and-Edge.ps1` PowerShell script for manual Windows deployment also used for RMM deployment

## Security Considerations

- Always use HTTPS URLs for custom rules and logos
- Regularly update custom detection rules
- Monitor debug logging usage (performance impact)
- Test policies in a lab environment before production deployment
