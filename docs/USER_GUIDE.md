# User Guide

## Installation
- Clone the repository or download a release.
- In Chrome, visit `chrome://extensions/` and enable **Developer mode**.
- Choose **Load unpacked** and select the project directory.
- For enterprise deployment, distribute the extension via Group Policy or Intune as described in the README.

## Configuration
- Policy definitions live in `config/managed_schema.json` and can be enforced through managed browser policies.
- Customize branding by editing `config/branding.json`.
- Edit `rules/detection-rules.json` to define custom phishing detection patterns.

## Troubleshooting
- **Extension fails to load**: Ensure Developer mode is enabled and the manifest is valid.
- **Policies not applying**: Confirm the browser received the correct GPO or Intune configuration.
- **Phishing detection not triggering**: Verify rules in the `rules/` directory and check that Microsoft 365 domains are accessible.
