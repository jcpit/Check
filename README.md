# Check

An open-source, Manifest V3 browser extension for detecting phishing attacks that
impersonate Microsoft 365 sign-in pages.

## Features 

- **Detection engine** – loads rules from `rules/detection-rules.json` and
  analyses URLs and page content to block or warn about suspicious sites
  targeting Microsoft 365 credentials
- **Configuration management** – merges local settings, branding, and browser
  policies provided through Chrome managed storage (GPO/Intune)
- **Policy enforcement & logging** – loads enterprise policies, tracks
  compliance mode, and records audit events for security reporting
- **Custom branding** – logos, colors, and messaging are defined in
  `config/branding.json` and can be replaced for white‑label deployments
- **Options & popup interfaces** – interactive pages (`options/`, `popup/`) let
  administrators adjust settings and view detection status

## Requirements

- Chrome 88+ or other Chromium-based browsers supporting Manifest V3
- Optional enterprise management via Group Policy or Microsoft Intune for
  policy enforcement

## Installation

### Manual

1. Clone this repository.
2. In Chrome/Edge open `chrome://extensions/` and enable **Developer mode**.
3. Click **Load unpacked** and select the project directory.
4. Verify the extension using `test-extension-loading.html`.

### Enterprise

Package the extension directory (zip) and deploy through your browser’s policy
mechanism. Managed settings follow the schema in `config/managed_schema.json`.

## Configuration

- **Policies** – see `config/managed_schema.json` for available options such as
  URL blocking, logging, and performance controls.
- **Branding** – update `config/branding.json` to change names, logos, and
  colors.
- **Detection rules** – edit `rules/detection-rules.json` or enable remote
  rules using the `detectionRules` section in the policy schema.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. The project uses plain
JavaScript modules and does not include a build system; package the directory
directly for distribution.

## License

Licensed under the AGPL-3.0. See [LICENSE](LICENSE) for details.

