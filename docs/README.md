---
icon: hand-wave
layout:
  width: default
  title:
    visible: true
  description:
    visible: false
  tableOfContents:
    visible: true
  outline:
    visible: true
  pagination:
    visible: true
  metadata:
    visible: true
---

# About

## What is Check?

**Check** is an advanced browser extension that provides real-time protection against Microsoft 365 phishing attacks. Designed for enterprises and managed service providers, Check uses sophisticated detection algorithms to identify and block malicious login pages before credentials can be compromised.

The extension integrates seamlessly with existing security workflows, offering centralized management, comprehensive logging, and CIPP integration for MSPs managing multiple Microsoft 365 tenants.&#x20;

Check is completely free, open source, and can be delivered to users completely white-label.

Check is an open source project licensed under AGPL-3. You can contribute to check at [https://github.com/cyberdrain/Check](https://github.com/cyberdrain/Check).&#x20;

## Why was Check created?

Check was created out of a need to have better protection against AITM attacks. During a CyberDrain brainstorming session CyberDrain's lead dev came up with the idea to create a Chrome extension to protect users:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

This led to a hackathon in which the team crafted a proof of concept. This proof of concept led to the creation of Check by CyberDrain. CyberDrain decided to offer Check as a free to use community resource, for everyone.



### What information does Check collect?

Nothing. We're not even kidding, we don't collect any data at all. You can set up a CIPP reporting server if you'd like, but this reports directly to your own environment. CyberDrain doesn't believe in making their users a product. We don't sell or collect any information.



## How does it look?

When a user gets the plugin added, a new icon will appear, this icon is brandable to customize it to your own logo and name.

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

When visiting a page that is suspect, but our certainty if the page is phishing is too low we'll show a banner on the page to warn users, if we're sure about the page being an AITM or phishing attack, we'll block the page entirely:

<figure><img src="broken-reference" alt=""><figcaption></figcaption></figure>

This too is completely brandable, and can be made to match company colours. The Contact Admin button is a mailto: link that contains the information about what page the user tried to visit, including a defanged URL.
