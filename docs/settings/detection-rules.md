# Detection Rules

This section controls how Check recognizes and responds to phishing threats. Most users can leave these at default settings, but here's how to manage them.

#### Understanding How Detection Works

Check uses a constantly updated list of rules to identify fake Microsoft login pages. Think of it like antivirus definitions - they need to be kept current to protect against new threats.

### Detection Configuration

#### **For most users:**

1. Leave the "Config URL" field empty or at its default
2. Set "Update Interval" to 24 hours
3. Click "Save Settings"

#### **For organizations with custom security rules:**

{% hint style="warning" %}
#### What if Settings are Grayed Out?

If some settings appear grayed out with a little lock icon, it means your organization's IT department has set these for you. This is normal in business environments - your IT team wants to make sure everyone has the same security settings.
{% endhint %}

1. Enter your organization's custom rules URL (provided by IT)
   1. Custom rules, including allow lists, can be done via [creating-detection-rules.md](../advanced/creating-detection-rules.md "mention").
2. Set update interval based on your security requirements:
   * High security environments: 6-12 hours
   * Standard environments: 24 hours
   * Limited bandwidth: 48-72 hours

#### Updating Rules Manually

Sometimes you need to update rules immediately:

1. **When to do this:**
   * You've heard about a new phishing campaign
   * Check isn't detecting a threat it should
   * Your IT department asks you to update
2. **How to do it:**
   * Go to Detection Rules section
   * Click "Update Rules Now"
   * Wait for the "Rules updated successfully" message

### Understanding the Configuration Overview

You'll see information about your current rules:

**In the formatted view, look for:**

* **Version number** - Higher numbers are newer
* **Last Updated** - Should be recent (within your update interval)
* **Total Rules** - More rules generally mean better protection

**If you see problems:**

* Very old "Last Updated" date → Click "Update Rules Now"
* Version shows "Error loading" → Check your internet connection
* No rules showing → Contact support

### Troubleshooting Rule Updates

#### **Problem: Rules won't update**

1. Check your internet connection
2. Try clicking "Update Rules Now" again
3. If using custom rules URL, verify the URL is correct
4. Contact your IT department if the problem persists

#### **Problem: Extension seems slow after rule update**

1. Wait 5-10 minutes for the new rules to fully load
2. Restart your browser
3. If still slow, try updating rules again
