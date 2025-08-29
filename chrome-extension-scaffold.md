# Chrome Extension for Microsoft 365 Phishing Protection - Scaffolding Guide

## Executive Summary
This guide provides a comprehensive scaffolding plan for building a Chrome extension that detects phishing attempts on Microsoft 365 login pages. Based on your technical discussion, the extension will operate at the browser level to provide protection that cannot be bypassed by adversary-in-the-middle attacks.

## Core Requirements

### 1. Extension Architecture Components

#### manifest.json (Manifest V3)
```json
{
  "manifest_version": 3,
  "name": "Microsoft 365 Phishing Protection",
  "version": "1.0.0",
  "description": "Protect against phishing attacks on Microsoft 365 login pages",
  "permissions": [
    "storage",
    "activeTab",
    "webRequest",
    "declarativeNetRequest",
    "scripting"
  ],
  "host_permissions": [
    "<all_urls>"
  ],
  "background": {
    "service_worker": "background/service-worker.js"
  },
  "content_scripts": [{
    "matches": ["<all_urls>"],
    "js": ["content/detection.js"],
    "run_at": "document_start",
    "all_frames": true
  }],
  "action": {
    "default_popup": "popup/popup.html",
    "default_icon": {
      "16": "icons/icon16.png",
      "32": "icons/icon32.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  },
  "options_page": "options/options.html",
  "web_accessible_resources": [{
    "resources": ["assets/*"],
    "matches": ["<all_urls>"]
  }]
}
```

#### File Structure
```
chrome-extension/
├── manifest.json
├── background/
│   └── service-worker.js
├── content/
│   └── detection.js
├── popup/
│   ├── popup.html
│   ├── popup.css
│   └── popup.js
├── options/
│   ├── options.html
│   ├── options.css
│   └── options.js
├── assets/
│   └── warning-bg.png
├── icons/
│   ├── icon16.png
│   ├── icon32.png
│   ├── icon48.png
│   └── icon128.png
└── lib/
    └── crypto-utils.js
```

### 2. Detection Engine Architecture

#### Detection Rules Structure (JSON)
```json
{
  "version": "1.0.0",
  "rules": [
    {
      "id": "check_domain",
      "type": "url",
      "weight": 30,
      "condition": {
        "domains": [
          "login.microsoftonline.com",
          "login.microsoft.com",
          "login.live.com",
          "account.microsoft.com"
        ]
      }
    },
    {
      "id": "check_input_fields",
      "type": "dom",
      "weight": 20,
      "condition": {
        "selectors": [
          "input[type='email'][name='loginfmt']",
          "input[type='password'][name='passwd']"
        ]
      }
    },
    {
      "id": "check_referrer",
      "type": "header",
      "weight": 15,
      "condition": {
        "referrer_pattern": "^https://[^/]*\\.microsoft\\.com/"
      }
    },
    {
      "id": "check_page_hash",
      "type": "content",
      "weight": 25,
      "condition": {
        "hash_elements": [
          "#loginForm",
          ".login-paginated-page"
        ]
      }
    },
    {
      "id": "check_custom_css",
      "type": "css",
      "weight": 10,
      "condition": {
        "css_property": "background-image",
        "expected_pattern": "url\\(.*microsoft.*\\)"
      }
    }
  ],
  "thresholds": {
    "legitimate": 90,
    "suspicious": 60,
    "phishing": 30
  }
}
```

### 3. Core JavaScript Components

#### Service Worker (background/service-worker.js)
```javascript
// Service Worker - Handles background tasks
let detectionRules = null;
const RULES_UPDATE_INTERVAL = 24 * 60 * 60 * 1000; // 24 hours

// Initialize extension
chrome.runtime.onInstalled.addListener(async () => {
  await loadDetectionRules();
  scheduleRulesUpdate();
});

// Load detection rules from GitHub
async function loadDetectionRules() {
  try {
    const response = await fetch(
      'https://raw.githubusercontent.com/[YOUR-ORG]/phishing-detector/main/rules.json'
    );
    const rules = await response.json();
    
    await chrome.storage.local.set({ detectionRules: rules });
    detectionRules = rules;
  } catch (error) {
    console.error('Failed to load rules:', error);
    // Fall back to bundled rules
    const bundledRules = await fetch(chrome.runtime.getURL('rules/default.json'));
    detectionRules = await bundledRules.json();
  }
}

// Schedule periodic rule updates
function scheduleRulesUpdate() {
  chrome.alarms.create('updateRules', {
    periodInMinutes: RULES_UPDATE_INTERVAL / 60000
  });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'updateRules') {
    loadDetectionRules();
  }
});

// Handle messages from content script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'detectPhishing') {
    performDetection(request.data, sender.tab)
      .then(sendResponse)
      .catch(error => sendResponse({ error: error.message }));
    return true; // Async response
  }
});

// Request cryptographic signature for verification badge
async function requestVerificationImage() {
  const timestamp = Date.now();
  const response = await fetch('https://365branding.com/api/generate-badge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ timestamp, extensionId: chrome.runtime.id })
  });
  
  return response.blob();
}
```

#### Content Script (content/detection.js)
```javascript
// Content Script - Runs on every page
(function() {
  'use strict';
  
  // Check if current page might be a Microsoft login page
  if (!isPotentialLoginPage()) {
    return;
  }
  
  // Perform detection
  detectPhishingAttempt();
  
  function isPotentialLoginPage() {
    // Quick preliminary checks
    const hasPasswordField = document.querySelector('input[type="password"]');
    const hasEmailField = document.querySelector('input[type="email"], input[type="text"][name*="login"], input[type="text"][name*="email"]');
    const hasMicrosoftKeywords = document.body.textContent.toLowerCase().includes('microsoft') || 
                                 document.body.textContent.toLowerCase().includes('office 365');
    
    return hasPasswordField && hasEmailField && hasMicrosoftKeywords;
  }
  
  async function detectPhishingAttempt() {
    const pageData = {
      url: window.location.href,
      referrer: document.referrer,
      title: document.title,
      elements: {
        loginForm: !!document.querySelector('#loginForm'),
        emailInput: !!document.querySelector('input[name="loginfmt"]'),
        passwordInput: !!document.querySelector('input[name="passwd"]'),
        nextButton: !!document.querySelector('input[type="submit"][value="Next"]')
      },
      headers: {
        contentType: document.contentType
      }
    };
    
    // Send to service worker for analysis
    const result = await chrome.runtime.sendMessage({
      action: 'detectPhishing',
      data: pageData
    });
    
    if (result.isPhishing) {
      blockPhishingAttempt(result);
    } else if (result.isLegitimate && shouldShowVerification()) {
      showVerificationBadge();
    }
  }
  
  function blockPhishingAttempt(result) {
    // Disable password field
    const passwordFields = document.querySelectorAll('input[type="password"]');
    passwordFields.forEach(field => {
      field.disabled = true;
      field.style.backgroundColor = '#ffcccc';
    });
    
    // Disable submit buttons
    const submitButtons = document.querySelectorAll('input[type="submit"], button[type="submit"]');
    submitButtons.forEach(button => {
      button.disabled = true;
      button.style.opacity = '0.5';
    });
    
    // Show warning message
    const warning = document.createElement('div');
    warning.id = 'phishing-warning';
    warning.style.cssText = `
      position: fixed;
      top: 20px;
      left: 50%;
      transform: translateX(-50%);
      background: #ff0000;
      color: white;
      padding: 15px 25px;
      border-radius: 5px;
      font-weight: bold;
      z-index: 999999;
      box-shadow: 0 4px 8px rgba(0,0,0,0.3);
    `;
    warning.textContent = 'WARNING: Phishing page detected. Do not enter your credentials.';
    document.body.appendChild(warning);
  }
})();
```

### 4. Configuration Options

#### Options Page Structure
```javascript
// options/options.js
const defaultSettings = {
  detectionLevel: 'balanced', // 'strict', 'balanced', 'relaxed'
  showVerificationBadge: false,
  customWarningMessage: '',
  blockingAction: 'disable', // 'disable', 'warn', 'redirect'
  exclusions: [],
  reportingEnabled: true,
  customBrandingUrl: ''
};

// Load and save settings
async function loadSettings() {
  const settings = await chrome.storage.sync.get(defaultSettings);
  populateUI(settings);
}

async function saveSettings() {
  const settings = {
    detectionLevel: document.getElementById('detectionLevel').value,
    showVerificationBadge: document.getElementById('showBadge').checked,
    customWarningMessage: document.getElementById('warningMessage').value,
    blockingAction: document.getElementById('blockingAction').value,
    exclusions: getExclusionList(),
    reportingEnabled: document.getElementById('reporting').checked,
    customBrandingUrl: document.getElementById('brandingUrl').value
  };
  
  await chrome.storage.sync.set(settings);
}
```

### 5. Enterprise Deployment Configuration

#### Intune Policy Configuration
```json
{
  "ExtensionSettings": {
    "[EXTENSION_ID]": {
      "installation_mode": "force_installed",
      "update_url": "https://clients2.google.com/service/update2/crx",
      "toolbar_state": "force_shown",
      "runtime_blocked_hosts": [],
      "runtime_allowed_hosts": ["*"],
      "blocked_permissions": [],
      "allowed_permissions": ["storage", "activeTab", "webRequest"]
    }
  }
}
```

#### Managed Storage Schema (schema.json)
```json
{
  "type": "object",
  "properties": {
    "detectionLevel": {
      "type": "string",
      "enum": ["strict", "balanced", "relaxed"]
    },
    "showVerificationBadge": {
      "type": "boolean"
    },
    "customWarningMessage": {
      "type": "string",
      "maxLength": 200
    },
    "blockingAction": {
      "type": "string",
      "enum": ["disable", "warn", "redirect"]
    },
    "reportingEndpoint": {
      "type": "string",
      "format": "uri"
    },
    "exclusions": {
      "type": "array",
      "items": {
        "type": "string",
        "format": "uri"
      }
    }
  }
}
```

### 6. Cryptographic Verification Service

#### Image Generation Service (Node.js)
```javascript
// server/badge-generator.js
const express = require('express');
const crypto = require('crypto');
const { createCanvas, loadImage } = require('canvas');

const app = express();
const SECRET_KEY = process.env.SECRET_KEY;

app.post('/api/generate-badge', async (req, res) => {
  const { timestamp, extensionId } = req.body;
  
  // Validate timestamp (must be within 5 minutes)
  if (Date.now() - timestamp > 5 * 60 * 1000) {
    return res.status(400).json({ error: 'Invalid timestamp' });
  }
  
  // Generate signature
  const signature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(`${timestamp}:${extensionId}`)
    .digest('hex');
  
  // Create image with embedded signature
  const canvas = createCanvas(100, 30);
  const ctx = canvas.getContext('2d');
  
  // Draw checkmark
  ctx.fillStyle = '#00a651';
  ctx.fillRect(0, 0, 100, 30);
  ctx.fillStyle = 'white';
  ctx.font = '20px Arial';
  ctx.fillText('✓ Verified', 10, 22);
  
  // Embed signature in image metadata
  const buffer = canvas.toBuffer('image/png');
  const metadata = {
    signature,
    timestamp,
    extensionId
  };
  
  // Add metadata to PNG (would use a proper PNG library)
  res.set('Content-Type', 'image/png');
  res.send(buffer);
});

app.get('/api/verify-badge', (req, res) => {
  const { signature, timestamp, extensionId } = req.query;
  
  const expectedSignature = crypto
    .createHmac('sha256', SECRET_KEY)
    .update(`${timestamp}:${extensionId}`)
    .digest('hex');
  
  const isValid = signature === expectedSignature && 
                  (Date.now() - timestamp < 5 * 60 * 1000);
  
  res.json({ valid: isValid });
});
```

### 7. Testing Infrastructure

#### Test Pages Repository
Create a separate repository with test pages:
```
test-pages/
├── legitimate/
│   └── microsoft-login-clone.html
├── phishing/
│   ├── basic-phish.html
│   ├── advanced-phish.html
│   └── adversary-in-middle.html
└── edge-cases/
    ├── partial-match.html
    └── custom-branding.html
```

### 8. Build and Deployment Pipeline

#### Package Script (package.json)
```json
{
  "name": "ms365-phishing-protection",
  "version": "1.0.0",
  "scripts": {
    "build": "node scripts/build.js",
    "package": "node scripts/package.js",
    "test": "jest",
    "lint": "eslint src/**/*.js"
  },
  "devDependencies": {
    "eslint": "^8.0.0",
    "jest": "^29.0.0",
    "terser": "^5.0.0",
    "archiver": "^6.0.0"
  }
}
```

#### Build Script
```javascript
// scripts/build.js
const fs = require('fs-extra');
const terser = require('terser');
const archiver = require('archiver');

async function build() {
  // Clean dist directory
  await fs.emptyDir('./dist');
  
  // Copy static files
  await fs.copy('./src', './dist');
  
  // Minify JavaScript files
  const jsFiles = await glob('./dist/**/*.js');
  for (const file of jsFiles) {
    const code = await fs.readFile(file, 'utf8');
    const minified = await terser.minify(code);
    await fs.writeFile(file, minified.code);
  }
  
  // Create zip for Chrome Web Store
  const output = fs.createWriteStream('./dist/extension.zip');
  const archive = archiver('zip', { zlib: { level: 9 } });
  
  archive.pipe(output);
  archive.directory('./dist', false);
  await archive.finalize();
}
```

## Implementation Timeline

### Phase 1: Core Development (4 hours)
1. **Hour 1**: Set up project structure, create manifest.json
2. **Hour 2**: Implement detection logic and rules engine
3. **Hour 3**: Build UI components (popup, options page)
4. **Hour 4**: Testing with phishing samples

### Phase 2: Enhanced Features
- Cryptographic verification system
- Enterprise deployment configuration
- Advanced detection rules
- Reporting dashboard

## Security Considerations

1. **Content Security Policy**: Strict CSP in manifest to prevent injection attacks
2. **Permissions**: Request minimal permissions required
3. **Secure Communication**: All external requests over HTTPS
4. **Input Validation**: Sanitize all user inputs
5. **Regular Updates**: Automated rule updates from secure source

## Next Steps

1. **Create GitHub Repository**: Set up with proper CI/CD
2. **Google Developer Account**: Register for Chrome Web Store
3. **Testing Environment**: Set up automated testing
4. **Documentation**: Create user and admin guides
5. **Security Review**: Conduct thorough security audit

This scaffolding provides the foundation for building a robust Chrome extension that can effectively detect and prevent phishing attacks on Microsoft 365 login pages.