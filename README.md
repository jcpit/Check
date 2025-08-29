# Microsoft 365 Phishing Protection

**Enterprise-grade Chromium browser extension for Microsoft 365 phishing detection and prevention**

Microsoft 365 Phishing Protection is a powerful, Manifest V3 compatible browser extension designed for enterprise deployment to detect and prevent phishing attacks targeting Microsoft 365 login pages. The extension provides real-time protection that cannot be bypassed by adversary-in-the-middle attacks, operating at the browser level.

## 🚀 Features

### Core Phishing Protection Features
- **Real-time Microsoft 365 Phishing Detection**: Advanced pattern matching specifically for Microsoft 365 login page impersonation
- **Login Page Verification**: Automatic verification of legitimate Microsoft 365 domains and page elements
- **Credential Harvesting Prevention**: Detection and blocking of fake login forms attempting to steal credentials
- **Cryptographic Verification**: Optional verification badges for legitimate Microsoft login pages

### Enterprise Features
- **Group Policy (GPO) Support**: Deploy and manage settings via Windows Group Policy
- **Microsoft Intune Integration**: Centralized management through Microsoft Intune
- **Policy Enforcement**: Lock down settings and enforce security policies
- **Compliance Reporting**: Generate detailed compliance and security reports
- **Audit Logging**: Comprehensive logging of all security events and user activities

### White-Label Capabilities
- **Custom Branding**: Replace logos, colors, and company information
- **Customizable UI**: Modify extension appearance with custom CSS
- **Configurable Text**: Customize all user-facing text and messages
- **Brand Protection**: Remove or replace CyberShield branding entirely

### Advanced Features
- **Custom Phishing Detection Rules**: Define and deploy custom Microsoft 365 phishing detection patterns
- **Behavioral Analysis**: Monitor form submission patterns and suspicious page modifications
- **Performance Optimization**: Lightweight detection with minimal impact on browsing performance
- **Privacy Controls**: No collection of actual credentials, only security metadata

## 📋 Requirements

### Browser Support
- Chrome 88+
- Chromium-based browsers (Edge, Brave, Opera)
- Manifest V3 compatible browsers

### Enterprise Requirements
- Windows 10/11 with Group Policy support
- Microsoft Intune (for Intune deployment)
- Active Directory domain (recommended)

## 🔧 Installation

### Manual Installation (Development)
1. Clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode"
4. Click "Load unpacked" and select the extension directory

### Enterprise Deployment

#### Group Policy (GPO) Deployment
1. Download the latest release
2. Extract to a network location accessible by target machines
3. Configure Group Policy with the provided ADMX templates
4. Deploy the extension via GPO

```powershell
# Example GPO deployment script
$ExtensionPath = "\\domain.com\netlogon\CyberShieldDrain"
$PolicyKey = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
Set-ItemProperty -Path $PolicyKey -Name "1" -Value "extension_id;$ExtensionPath"
```

#### Microsoft Intune Deployment
1. Create a new Win32 app in Intune
2. Upload the extension package
3. Configure deployment settings and policies
4. Assign to target groups

### Chrome Web Store (Enterprise)
```json
{
  "extension_id": "your_extension_id_here",
  "installation_mode": "force_installed",
  "runtime_blocked_hosts": ["*://*.malicious-site.com/*"],
  "runtime_allowed_hosts": ["*://*.trusted-site.com/*"]
}
```

## ⚙️ Configuration

### Enterprise Policy Configuration

The extension supports comprehensive policy configuration through the managed schema. Key policies include:

```json
{
  "extensionEnabled": true,
  "blockPhishingAttempts": true,
  "enableRealTimeScanning": true,
  "enableVerificationBadge": true,
  "enableLogging": true,
  "trustedDomains": ["login.microsoftonline.com", "portal.office.com"],
  "blockedPhishingDomains": ["fake-microsoft-login.com"],
  "detectionLevel": "balanced",
  "enterpriseMode": true,
  "organizationName": "Your Organization",
  "complianceMode": true
}
```

### Custom Branding Configuration

White-label the extension by modifying `config/branding.json`:

```json
{
  "companyName": "Your Company",
  "productName": "Your Security Extension",
  "primaryColor": "#your-color",
  "logoUrl": "https://your-domain.com/logo.png",
  "supportEmail": "support@your-domain.com",
  "supportUrl": "https://your-domain.com/support"
}
```

### Detection Rules

Customize Microsoft 365 phishing detection by modifying `rules/detection-rules.json`:

```json
{
  "rules": [
    {
      "id": "check_legitimate_domain",
      "type": "url",
      "weight": 30,
      "condition": {
        "domains": ["login.microsoftonline.com", "portal.office.com"]
      },
      "description": "Verify legitimate Microsoft domain"
    }
  ],
  "thresholds": {
    "legitimate": 90,
    "suspicious": 60,
    "phishing": 30
  }
}
```

## 🏢 Enterprise Deployment Guide

### Pre-Deployment Checklist
- [ ] Test extension functionality in staging environment
- [ ] Configure enterprise policies and branding
- [ ] Set up logging and monitoring infrastructure
- [ ] Train IT support staff on management interface
- [ ] Prepare user documentation and communication

### Deployment Steps

1. **Preparation**
   ```bash
   # Download and verify extension package
   wget https://releases.cybershield.com/drain/latest.zip
   gpg --verify latest.zip.sig latest.zip
   ```

2. **Configuration**
   - Customize `config/managed_schema.json` for your organization
   - Update `config/branding.json` with your branding
   - Modify `rules/detection-rules.json` if needed

3. **Group Policy Setup**
   - Import ADMX templates into Group Policy Management
   - Configure extension policies in GPO
   - Test policy application on pilot machines

4. **Monitoring Setup**
   - Configure log collection endpoints
   - Set up compliance reporting dashboard
   - Establish alert thresholds and notifications

### Post-Deployment

- Monitor extension performance and user feedback
- Review security logs and compliance reports
- Update detection rules and policies as needed
- Provide ongoing user support and training

## 🔍 Architecture Overview

### Extension Components

```
CyberShieldDrain/
├── manifest.json                 # Extension manifest (MV3)
├── scripts/
│   ├── background.js             # Service worker
│   ├── content.js                # Content script
│   └── modules/                  # Core modules
│       ├── config-manager.js     # Configuration management
│       ├── detection-engine.js   # Threat detection
│       └── policy-manager.js     # Policy enforcement
├── popup/                        # Extension popup
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
├── options/                      # Settings page
│   ├── options.html
│   ├── options.css
│   └── options.js
├── config/                       # Configuration files
│   ├── managed_schema.json       # Enterprise policy schema
│   └── branding.json            # Branding configuration
├── rules/                       # Detection rules
│   └── detection-rules.json    # Threat detection patterns
├── styles/                      # CSS files
│   └── content.css             # Content script styles
└── images/                      # Icons and assets
    ├── icon16.png
    ├── icon32.png
    ├── icon48.png
    └── icon128.png
```

### Data Flow

1. **Initialization**: Background script loads configuration and policies
2. **Page Loading**: Content script analyzes page content and URLs
3. **Threat Detection**: Detection engine processes content against rules
4. **Policy Enforcement**: Policy manager validates actions against enterprise policies
5. **Logging**: Security events and activities are logged for audit
6. **Reporting**: Compliance reports are generated and sent to configured endpoints

## 🛡️ Security Features

### Threat Detection Capabilities

- **Malicious Script Detection**: JavaScript injection, eval() abuse, DOM manipulation
- **Phishing Detection**: Domain spoofing, social engineering, credential harvesting
- **Suspicious Behavior**: IP access, cryptocurrency mining, keylogging attempts
- **Network Security**: Insecure protocols, private IP access, suspicious redirects

### Content Protection

- **Script Injection Control**: Validate and sanitize injected scripts
- **DOM Manipulation Safety**: Secure modification of page elements
- **CSP Enforcement**: Content Security Policy validation and enforcement
- **XSS Prevention**: Cross-site scripting attack prevention

### Privacy Protection

- **Data Minimization**: Collect only necessary security data
- **Encryption**: Encrypt sensitive configuration and log data
- **Access Control**: Role-based access to management features
- **Audit Trail**: Complete audit trail of all administrative actions

## 📊 Monitoring & Compliance

### Available Metrics

- Threats detected and blocked
- Pages scanned and analyzed
- Policy violations and enforcement actions
- User activity and behavior patterns
- Performance metrics and error rates

### Compliance Features

- **SOC 2 Type II**: Security controls and monitoring
- **GDPR**: Privacy controls and data protection
- **HIPAA**: Healthcare data security features
- **ISO 27001**: Information security management
- **NIST Framework**: Cybersecurity framework compliance

### Reporting Capabilities

- Real-time security dashboards
- Automated compliance reports
- Custom report generation
- Data export and integration APIs
- Alert and notification systems

## 🔧 API Reference

### Background Script Messages

```javascript
// Get current configuration
chrome.runtime.sendMessage({
  type: 'GET_CONFIG'
}, (response) => {
  console.log(response.config);
});

// Analyze URL for threats
chrome.runtime.sendMessage({
  type: 'URL_ANALYSIS_REQUEST',
  url: 'https://example.com'
}, (response) => {
  console.log(response.analysis);
});

// Check policy permissions
chrome.runtime.sendMessage({
  type: 'POLICY_CHECK',
  action: 'CONTENT_MANIPULATION',
  context: { domain: 'example.com' }
}, (response) => {
  console.log(response.allowed);
});
```

### Content Script API

```javascript
// Inject custom script
chrome.runtime.sendMessage({
  type: 'INJECT_SCRIPT',
  script: 'console.log("Hello World");',
  options: { async: true }
});

// Manipulate page content
chrome.runtime.sendMessage({
  type: 'MANIPULATE_CONTENT',
  action: 'hide_element',
  target: '.advertisement',
  options: { addToHiddenList: true }
});

// Get page information
chrome.runtime.sendMessage({
  type: 'GET_PAGE_INFO'
}, (response) => {
  console.log(response.info);
});
```

## 🚀 Development

### Build Requirements

- Node.js 16+
- npm or yarn
- Chrome browser for testing

### Development Setup

```bash
# Clone the repository
git clone https://github.com/cybershield/drain.git
cd drain

# Install dependencies (if any)
npm install

# Load extension in Chrome
# 1. Open chrome://extensions/
# 2. Enable Developer mode
# 3. Click "Load unpacked"
# 4. Select the project directory
```

### Testing

```bash
# Run linting
npm run lint

# Run unit tests
npm run test

# Run integration tests
npm run test:integration

# Generate test coverage report
npm run coverage
```

### Building for Production

```bash
# Create production build
npm run build

# Package for distribution
npm run package

# Generate signed package
npm run sign
```

## 📝 Contributing

We welcome contributions from the community! Please read our [Contributing Guide](CONTRIBUTING.md) for details on:

- Code of conduct
- Development process
- Pull request procedure
- Coding standards
- Testing requirements

### Development Guidelines

1. **Code Style**: Follow the established ESLint configuration
2. **Testing**: Maintain >90% test coverage for new features
3. **Documentation**: Update documentation for all changes
4. **Security**: Follow secure coding practices
5. **Performance**: Ensure minimal impact on browser performance

## 🔐 Security

Please report security vulnerabilities privately. See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines and contact information. Do not create public GitHub issues for security-related reports.

## 📄 License

This project is licensed under the AGPL-3.0 License - see the [LICENSE](LICENSE) file for details.

### Third-Party Licenses

- Chrome Extension APIs: Google Chrome License
- Icons: Various open source licenses (see [ATTRIBUTIONS.md](ATTRIBUTIONS.md))

## 🆘 Support

### Enterprise Support

- **24/7 Phone Support**: Available for Enterprise customers
- **Email Support**: enterprise-support@cybershield.com
- **Documentation**: https://docs.cybershield.com/drain
- **Status Page**: https://status.cybershield.com

### Community Support

- **GitHub Issues**: Bug reports and feature requests
- **Community Forum**: https://community.cybershield.com
- **Discord**: https://discord.gg/cybershield

### Training & Professional Services

- Implementation consulting
- Custom rule development
- Security policy design
- Training and certification programs

## 🔄 Updates & Releases

### Release Schedule

- **Major Releases**: Quarterly (Q1, Q2, Q3, Q4)
- **Minor Releases**: Monthly
- **Security Updates**: As needed (within 24-48 hours)
- **Beta Releases**: Bi-weekly for testing

### Update Channels

- **Stable**: Production-ready releases
- **Beta**: Pre-release testing versions
- **Dev**: Development builds (not recommended for production)

### Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes and update information.

## 🏆 Awards & Recognition

- **Best Enterprise Security Extension 2024** - InfoSec Awards
- **Top Rated Browser Extension** - G2 Enterprise
- **Security Innovation Award** - CyberSecurity Excellence

## 📈 Roadmap

### Upcoming Features

- **Q2 2024**: Machine learning threat detection
- **Q3 2024**: Advanced behavioral analysis
- **Q4 2024**: Zero-trust integration
- **Q1 2025**: Cloud-based rule management

### Long-term Vision

- AI-powered threat prediction
- Cross-platform mobile support
- Integration with SIEM systems
- Advanced threat intelligence feeds

---

## 📞 Contact Information

**CyberShield Technologies**
- Website: https://cybershield.com
- Email: info@cybershield.com
- Phone: +1 (555) 123-4567
- Address: 123 Security Blvd, Cyber City, CC 12345

---

*CyberShield Drain - Protecting your digital assets, one click at a time.*
