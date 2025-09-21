# Manual Deployment

{% tabs %}
{% tab title="PowerShell" %}
**Modify the following script and copy it to your RMM's scripting engine or run the script directly on the endpoint to deploy Check:**

{% hint style="info" %}
This script is designed to deploy the extension to both Chrome and Edge. It is recommended to deploy both even if you standardize on one. This will provide you with better protection in the case someone uses the non-favored browser.
{% endhint %}

1. Review the Extension Configuration Settings and Custom Branding Settings variables and update those to your desired values. The current values in the script are the default values. Leaving any unchanged will set the defaults.
2. If you are leveraging a RMM that has the ability to define the variables in the deployment section of scripting, then you may be able to remove this section and enter the variable definitions into the RMM scripting pages.

<a href="https://raw.githubusercontent.com/CyberDrain/Check/refs/heads/main/enterprise/Deploy-Windows-Chrome-and-Edge.ps1" class="button primary">Download the Script from GitHub</a>
{% endtab %}

{% tab title="Side Load" %}
Developers who wish to test their code changes can side load the extension into their browser.&#x20;

1. Fork the repository and clone your fork
2. Open `chrome://extensions` or `edge://extensions`
3. Enable **Developer mode** and choose **Load unpacked**
4. Select the repository root to load the extension. Reload the extension after making changes.
{% endtab %}
{% endtabs %}
