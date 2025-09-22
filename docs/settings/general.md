---
description: This is where you control the main features of Check.
---

# General

### Extension Settings

#### **Enable Page Blocking**

This is Check's main job - blocking dangerous websites. When this is turned on (which we recommend), Check will stop you from visiting fake Microsoft login pages and show you a warning instead, there are times you need to disable the checkbox for testing purposes. Removing this checkbox removes most of your protection so it's recommended to leave this setting enabled.

#### Enable CIPP Reporting

CIPP is a system that IT professionals use to monitor security across multiple organizations. Enabling the CIPP monitoring allows you to send the information from Check directly to CIPP, thus allowing you to alert and report on what's going on with your endpoints. When enabled, you would configure the CIPP Server URL and Tenant ID/Domain below.

{% hint style="info" %}
Currently, CIPP displays these alerts in the logbook. Future updates to CIPP are planned to provide additional functionality. Keep an eye on the CIPP release notes for more updates!
{% endhint %}

### User Interface

#### **Show Notifications**&#x20;

When Check blocks a dangerous website or finds something suspicious, it can show you a small popup message to let you know what's going on. We recommend leaving this setting enabled

#### **Show Valid Page Badge**

This adds a small green checkmark to real Microsoft login pages. This feature is optional.

{% hint style="warning" %}
#### What if Settings Are Not Visible?

If some settings do not appear on my version, it means your organization's IT department has set these for you. This is normal in business environments - your IT team wants to make sure everyone has the same security settings. You will also see text indicating that the extension is being managed by policy.
{% endhint %}
