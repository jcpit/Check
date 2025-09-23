---
description: This is where you control the main features of Check.
---

# General

## Extension Settings

### **Enable Page Blocking**

This is Check's main job - blocking dangerous websites. When this is turned on (which we recommend), Check will stop you from visiting fake Microsoft login pages and show you a warning instead. There are times you need to disable the checkbox for testing purposes. Removing this checkbox removes most of your protection so it's recommended to leave this setting enabled.

### Enable CIPP Reporting

CIPP is a system that IT professionals use to monitor security across multiple organizations. Enabling CIPP monitoring allows you to send detection information from Check directly to CIPP, thus allowing you to alert and report on what's happening with your endpoints. When enabled, you would configure the CIPP Server URL and Tenant ID/Domain below.

View CIPP reporting activity in the [Activity Logs](activity-logs.md) section.

### **CIPP Server URL**

Enter the base URL of your CIPP server for reporting Microsoft 365 logon detections. This should be the full URL to your CIPP instance (e.g., `https://your-cipp-server.com`). This field is only active when CIPP Reporting is enabled.

### **Tenant ID/Domain**

Enter your tenant identifier to include with CIPP alerts for multi-tenant environments. You can use either your tenant GUID or your primary domain (e.g., `contoso.onmicrosoft.com` or the tenant GUID). This helps CIPP identify which tenant the alert belongs to when managing multiple clients.

{% hint style="info" %}
Currently, CIPP displays these alerts in the logbook. Future updates to CIPP are planned to provide additional functionality. Keep an eye on the CIPP release notes for more updates!

You can monitor CIPP reporting status and activity in [Activity Logs](activity-logs.md).
{% endhint %}

## User Interface

### **Show Notifications**&#x20;

When Check blocks a dangerous website or finds something suspicious, it can show you a small popup message to let you know what's going on. We recommend leaving this setting enabled

### **Show Valid Page Badge**

This adds a small green checkmark to real Microsoft login pages. This feature is optional.

{% hint style="warning" %}

### What if Settings Are Not Visible?

If some settings do not appear on my version, it means your organization's IT department has set these for you. This is normal in business environments - your IT team wants to make sure everyone has the same security settings. You will also see text indicating that the extension is being managed by policy.
{% endhint %}
