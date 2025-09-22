# Detection Rules

This section controls how Check recognizes and responds to phishing threats. Most users can leave these at default settings, but here's how to manage them.

## Understanding How Detection Works

Check uses a constantly updated list of rules to identify fake Microsoft login pages. Think of it like antivirus definitions - they need to be kept current to protect against new threats.

## Detection Configuration

### **Config URL**

This field allows you to specify a custom URL for fetching detection rules. Leave this field empty to use the default CyberDrain rules. If your organization provides custom detection rules, enter the full HTTPS URL here (e.g., `https://your-company.com/custom-rules.json`).

**For most users:**

1. Leave the "Config URL" field empty or at its default
2. Set "Update Interval" to 24 hours
3. Click "Save Settings"

**For organizations with custom security rules:**

1. Enter your organization's custom rules URL (provided by IT)
2. Custom rules, including allow lists, can be created using [creating-detection-rules.md](../advanced/creating-detection-rules.md "mention").

### **Update Interval (hours)**

Controls how often Check fetches updated detection rules. The default is 24 hours. Set update interval based on your security requirements:

- High security environments: 6-12 hours
- Standard environments: 24 hours
- Limited bandwidth: 48-72 hours

### **URL Allowlist (Regex or URL with wildcards)**

{% hint style="info" %}
**Need to allowlist a phishing training service?**

MSPs and IT departments commonly need to exclude phishing training platforms (like KnowBe4, Proofpoint, etc.) from detection. Check [Advanced → Creating Detection Rules](../advanced/creating-detection-rules.md#exclusions) for technical details.
{% endhint %}

Add URLs or patterns that should be excluded from phishing detection. This is useful for internal company sites or trusted third-party services that might trigger false positives.

**How it works:** Your allowlist patterns are **added to** (not replacing) the default CyberDrain exclusions, providing additional protection without losing baseline coverage.

You can use:

- **Simple URLs with wildcards:** `https://google.com/*` or `https://*.microsoft.com/*`
- **Advanced regex patterns:** `^https://trusted\.example\.com/.*`

**Copy-paste examples (based on existing default exclusions):**

```
https://*.google.com/*
https://*.auth0.com/*
https://*.amazon.com/*
https://*.facebook.com/*
https://training.your-company.com/*
https://*.internal-domain.com/*
```

Enter one pattern per line. These patterns are added to the exclusion rules without replacing the entire ruleset from your Config URL.

### Updating Rules Manually

Sometimes you need to update rules immediately:

1. **When to do this:**
   - You've heard about a new phishing campaign
   - Check isn't detecting a threat it should
   - Your IT department asks you to update
2. **How to do it:**
   - Go to Detection Rules section
   - Click "Update Rules Now"
   - Wait for the "Rules updated successfully" message

## Understanding the Configuration Overview

The Configuration Overview section displays your current detection rules in two viewing modes:

**Formatted View (default):**

- **Version number** - Higher numbers are newer
- **Last Updated** - Should be recent (within your update interval)
- **Total Rules** - More rules generally mean better protection
- **Rule Categories** - Shows breakdown by rule type (exclusions, indicators, etc.)

**Raw JSON View:**

- Click "Show Raw JSON" to view the complete detection rules file
- Useful for advanced users and troubleshooting
- Shows the exact configuration being used by the extension

**If you see problems:**

- Very old "Last Updated" date → Click "Update Rules Now"
- Version shows "Error loading" → Check your internet connection
- No rules showing → Contact support

{% hint style="warning" %}

### What if Settings Are Not Visible?

If some settings do not appear in your version, it means your organization's IT department has set these for you. This is normal in business environments - your IT team wants to make sure everyone has the same security settings. You will also see text indicating that the extension is being managed by policy.

{% endhint %}

## Troubleshooting Rule Updates

### **Problem: Rules won't update**

1. Check your internet connection
2. Try clicking "Update Rules Now" again
3. If using custom rules URL, verify the URL is correct
4. Contact your IT department if the problem persists

### **Problem: Extension seems slow after rule update**

1. Wait 5-10 minutes for the new rules to fully load
2. Restart your browser
3. If still slow, try updating rules again
