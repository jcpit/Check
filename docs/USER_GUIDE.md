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

## Using the Popup and Options
- Click the extension icon to open the popup. It shows current page status and quick actions such as **Scan Page**, **View Logs** and **Test Rules**.
- The **Test Rules** button exercises the detection engine against sample URLs to confirm rule processing.
- Open **Settings** from the popup or navigate to `chrome-extension://<extension-id>/options/options.html` to edit configuration and branding. Changes are saved through `options/options.js` and immediately applied by the background service worker.

## Troubleshooting
- **Extension fails to load**: Ensure Developer mode is enabled and the manifest is valid.
- **Policies not applying**: Confirm the browser received the correct GPO or Intune configuration.
- **Phishing detection not triggering**: Verify rules in the `rules/` directory and check that Microsoft 365 domains are accessible.

## Security

For information on reporting security vulnerabilities, see [SECURITY.md](../SECURITY.md). Please do not disclose issues publicly until a fix is available.
