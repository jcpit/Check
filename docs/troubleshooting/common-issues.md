# Common Issues

<details>

<summary>Policies not appearing in Group Policy Management Console</summary>

- Verify ADMX/ADML files are in correct location (see [Windows deployment docs](../deployment/chrome-edge-deployment-instructions/windows/README.md))

* Ensure files are not blocked (right-click > Properties > Unblock)
* Refresh Group Policy Editor

For complete deployment instructions, see [Domain Deployment guide](../deployment/chrome-edge-deployment-instructions/windows/domain-deployment.md).

</details>

<details>

<summary>Policies not applying to extension</summary>

- Check registry values are present (see [Manual Deployment guide](../deployment/chrome-edge-deployment-instructions/windows/manual-deployment.md))
- Restart browser after policy changes
- Verify extension has necessary permissions

For troubleshooting policy deployment, consult the [Windows deployment documentation](../deployment/chrome-edge-deployment-instructions/windows/README.md).

</details>

<details>

<summary>Custom branding not working</summary>

- Verify URLs are accessible via HTTPS
- Check image formats are supported (PNG, JPG, SVG)
- Ensure color codes are valid hex format

</details>
