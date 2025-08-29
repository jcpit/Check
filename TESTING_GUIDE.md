# Check Testing Guide

This guide helps you verify both the Check extension itself and the detection rules it uses. Choose the section that matches what you want to test.

## Extension Testing

### Quick Extension Test
This guide will help you verify that your Check extension is working properly.

### 1. Load the Extension in Chrome

1. Open Chrome browser
2. Navigate to `chrome://extensions/`
3. Enable "Developer mode" (toggle in top right)
4. Click "Load unpacked"
5. Select this project folder: `c:\\Users\\JohnDupreyCyberDrain\\Documents\\GitHub\\ProjectX`
6. The extension should appear in your extensions list

### 2. Run the Extension Loading Test

1. Open the test page: `test-extension-loading.html`
   - Right-click the file in VS Code and select "Open with Live Server"
   - Or navigate to: `file:///c:/Users/JohnDupreyCyberDrain/Documents/GitHub/ProjectX/test-extension-loading.html`

2. The test page will automatically:
   - ✅ Check if extension is installed
   - ✅ Verify content script injection
   - ✅ Test background script communication
   - ✅ Test detection engine functionality
   - ✅ Test configuration loading

### 3. Expected Results

If everything is working properly, you should see:
- **Extension Installation Check**: ✅ Extension is installed and accessible
- **Content Script Injection Test**: ✅ Content script loaded and testing bridge available
- **Background Script Communication Test**: ✅ Background script responding
- **Detection Engine Test**: ✅ Detection engine working: X rules loaded, Y tests completed
- **Configuration Load Test**: ✅ Configuration loaded: ConfigManager, DetectionEngine, PolicyManager modules active
- **Overall Status**: ✅ All tests passed (5/5) - Extension is working properly!

### 4. Test the Popup Interface

1. Click on the Check extension icon in Chrome toolbar
2. The popup should open showing:
   - Extension status
   - Current page information
   - Security controls
   - Testing section with "Test Rules" button

### 5. Test Detection Rules

1. Navigate to: `https://login.microsoftonline.com`
2. The extension should analyze the page
3. Check popup for security status
4. Test detection rules using the testing interface

### 6. Troubleshooting

If tests fail:

#### Extension Not Detected
- Verify extension is loaded in `chrome://extensions/`
- Check for any error messages in extension details
- Reload the extension if needed

#### Content Script Issues
- Check browser console for errors
- Verify manifest.json has proper content script configuration
- Reload the page after loading extension

#### Background Script Issues
- Open extension service worker console:
  - Go to `chrome://extensions/`
  - Find your extension
  - Click "service worker" link
  - Check for initialization errors

#### Detection Engine Issues
- Verify `rules/detection-rules.json` exists and is valid JSON
- Check background script console for module loading errors
- Ensure all module files exist in `scripts/modules/`

### 7. Advanced Testing

For comprehensive testing, use:
- `test-detection-rules-standalone.html` - Tests detection rules without extension
- Popup testing interface - Real-time rule testing
- Browser developer tools - Monitor extension activity

### 8. Manual Verification Steps

1. **Icon Test**: Extension icon should appear in Chrome toolbar
2. **Popup Test**: Clicking icon opens popup interface
3. **Page Analysis**: Navigate to Microsoft login pages and verify detection
4. **Console Test**: No error messages in extension service worker console
5. **Storage Test**: Extension should store configuration in Chrome storage

## PowerShell Commands to Open Test Files

```powershell
# Open extension loading test
Start-Process "chrome.exe" "file:///c:/Users/JohnDupreyCyberDrain/Documents/GitHub/ProjectX/test-extension-loading.html"

# Open Chrome extensions page
Start-Process "chrome.exe" "chrome://extensions/"

# Open standalone detection test
Start-Process "chrome.exe" "file:///c:/Users/JohnDupreyCyberDrain/Documents/GitHub/ProjectX/test-detection-rules-standalone.html"
```

## Expected File Structure for Extension Loading

```
ProjectX/
├── manifest.json ✅
├── scripts/
│   ├── background.js ✅
│   ├── content.js ✅
│   └── modules/
│       ├── config-manager.js ✅
│       ├── detection-engine.js ✅
│       └── policy-manager.js ✅
├── rules/
│   └── detection-rules.json ✅
├── popup/
│   ├── popup.html ✅
│   ├── popup.js ✅
│   └── popup.css ✅
└── images/
    ├── icon16.png ✅
    ├── icon32.png ✅
    ├── icon48.png ✅
    └── icon128.png ✅
```

The extension should be fully functional with all components working together!

## Detection Rules Testing

### 🚀 Quick Start

You now have multiple ways to test your detection rules:

#### Option 1: Standalone Testing (No Extension Required)
1. Open `test-detection-rules-standalone.html` in any browser
2. Click the test buttons to validate detection logic
3. View comprehensive results and pass rates
4. **This works immediately without installing the extension**

#### Option 2: Extension Integration Testing
1. Load the extension in Chrome (Developer mode)
2. Open `test-detection-rules.html` on any webpage
3. The content script will inject testing capabilities
4. Run tests that communicate with the live extension

#### Option 3: Extension Popup Testing
1. Install the extension
2. Click the extension icon to open popup
3. Click "Test Rules" button
4. Run comprehensive tests from within the extension

### 🧪 Test Categories

#### 1. URL Analysis
- ✅ Legitimate Microsoft domains (`login.microsoftonline.com`)
- ❌ Phishing domains (`secure-microsoft-login.com`)
- Tests the `check_legitimate_domain` rule

#### 2. Content Analysis
- ✅ Required elements: `loginfmt`, `idPartnerPL`, `urlMsaSignUp`, `flowToken`
- ✅ Microsoft authentication patterns
- Tests content detection rules

#### 3. Form Analysis
- ✅ Microsoft login form fields
- ✅ Form action validation
- Tests the `detect_idpartnerpl_field` and related rules

#### 4. Referrer Validation
- ✅ Valid referrers from your custom allow list:
  - `https://login.microsoftonline.com`
  - `https://login.microsoft.net`
  - `https://tasks.office.com`
  - etc.
- ❌ Invalid referrers (`https://evil-site.com`)

#### 5. CSP Header Validation
- ✅ Required domains in `content-security-policy-report-only`
- ✅ BeginAuth request validation

### 📊 Expected Results

A properly configured detection engine should achieve:
- **80%+ pass rate** on all test categories
- **100% detection** of legitimate Microsoft URLs
- **100% blocking** of known phishing patterns
- **100% validation** of referrer allow list

### 🔧 Troubleshooting

#### "Extension API not available" Error
- **Solution**: Use `test-detection-rules-standalone.html` instead
- This file works without the extension and tests the same logic

#### Extension Not Responding
1. Check that the extension is loaded in Chrome
2. Verify no console errors in extension background page
3. Try refreshing the test page
4. Use standalone testing as fallback

#### Content Script Not Injecting
1. Ensure `manifest.json` includes proper content script permissions
2. Check the browser console for errors
3. Verify the extension has `<all_urls>` permissions

### 🎯 Success Criteria

Your detection rules are working correctly if:

1. **Standalone tests show 80%+ pass rate**
2. **Extension popup tests complete successfully**
3. **Live page testing works with extension installed**
4. **All required elements are detected in legitimate Microsoft pages**
5. **Phishing indicators correctly flag suspicious content**
6. **Referrer validation enforces your custom allow list**

### 📝 Next Steps

Once testing confirms your rules are working:

1. **Deploy to production** - Rules are ready for real-world use
2. **Monitor performance** - Use the popup statistics to track effectiveness
3. **Refine rules** - Adjust based on false positives/negatives
4. **Add custom rules** - Extend detection for organization-specific threats

### 🆘 Quick Test Command

**Fastest way to verify everything works:**

1. Open `test-detection-rules-standalone.html`
2. Click "Run All Tests"
3. Look for "✅ DETECTION RULES WORKING" in the summary

This will validate all your detection rules in under 30 seconds!

