# Firefox (Windows)

Firefox enterprise removal for Check is managed through the Firefox policies file.

## General Removal Steps

1. Remove Check entries from `%ProgramFiles%\\Mozilla Firefox\\distribution\\policies.json`.
2. Remove extension lock and install directives related to Check.
3. Restart Firefox to apply policy changes.

For deployment and policy format details, see [Firefox Deployment](../../deployment/firefox-deployment.md).
