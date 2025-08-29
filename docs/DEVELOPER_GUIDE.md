# Developer Guide

## Repository Structure
- `config/` – policy schema and branding assets.
- `scripts/` – background and content scripts plus shared modules.
- `rules/` – phishing detection rules.
- `options/` – options page source.
- `popup/` – popup UI code.
- `styles/` – shared stylesheets.
- `images/` – icons and images used throughout the extension.
- `blocked.html` – page shown when a phishing attempt is blocked.
- `manifest.json` – Chrome extension manifest.

## Build & Packaging
The extension runs directly in the browser without a build step. During development, load the project as an unpacked extension. For distribution, archive the directory (excluding development-only files) and deploy via your preferred mechanism.

## Testing
This repository does not include an automated test suite or npm scripts. Validate changes by loading the extension and exercising features manually.

## Security Reporting

If you encounter a potential security issue while developing or reviewing code, please follow the guidelines in [SECURITY.md](../SECURITY.md) and report it privately.
