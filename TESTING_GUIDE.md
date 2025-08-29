# CyberShield Detection Rules Testing Guide

## 🚀 Quick Start

You now have multiple ways to test your detection rules:

### Option 1: Standalone Testing (No Extension Required)
1. Open `test-detection-rules-standalone.html` in any browser
2. Click the test buttons to validate detection logic
3. View comprehensive results and pass rates
4. **This works immediately without installing the extension**

### Option 2: Extension Integration Testing
1. Load the extension in Chrome (Developer mode)
2. Open `test-detection-rules.html` on any webpage
3. The content script will inject testing capabilities
4. Run tests that communicate with the live extension

### Option 3: Extension Popup Testing
1. Install the extension
2. Click the extension icon to open popup
3. Click "Test Rules" button
4. Run comprehensive tests from within the extension

## 🧪 Test Categories

### 1. URL Analysis
- ✅ Legitimate Microsoft domains (`login.microsoftonline.com`)
- ❌ Phishing domains (`secure-microsoft-login.com`)
- Tests the `check_legitimate_domain` rule

### 2. Content Analysis  
- ✅ Required elements: `loginfmt`, `idPartnerPL`, `urlMsaSignUp`, `flowToken`
- ✅ Microsoft authentication patterns
- Tests content detection rules

### 3. Form Analysis
- ✅ Microsoft login form fields
- ✅ Form action validation
- Tests the `detect_idpartnerpl_field` and related rules

### 4. Referrer Validation
- ✅ Valid referrers from your custom allow list:
  - `https://login.microsoftonline.com`
  - `https://login.microsoft.net`
  - `https://tasks.office.com`
  - etc.
- ❌ Invalid referrers (`https://evil-site.com`)

### 5. CSP Header Validation
- ✅ Required domains in `content-security-policy-report-only`
- ✅ BeginAuth request validation

## 📊 Expected Results

A properly configured detection engine should achieve:
- **80%+ pass rate** on all test categories
- **100% detection** of legitimate Microsoft URLs
- **100% blocking** of known phishing patterns
- **100% validation** of referrer allow list

## 🔧 Troubleshooting

### "Extension API not available" Error
- **Solution**: Use `test-detection-rules-standalone.html` instead
- This file works without the extension and tests the same logic

### Extension Not Responding
1. Check that the extension is loaded in Chrome
2. Verify no console errors in extension background page
3. Try refreshing the test page
4. Use standalone testing as fallback

### Content Script Not Injecting
1. Ensure `manifest.json` includes proper content script permissions
2. Check the browser console for errors
3. Verify the extension has `<all_urls>` permissions

## 🎯 Success Criteria

Your detection rules are working correctly if:

1. **Standalone tests show 80%+ pass rate**
2. **Extension popup tests complete successfully**
3. **Live page testing works with extension installed**
4. **All required elements are detected in legitimate Microsoft pages**
5. **Phishing indicators correctly flag suspicious content**
6. **Referrer validation enforces your custom allow list**

## 📝 Next Steps

Once testing confirms your rules are working:

1. **Deploy to production** - Rules are ready for real-world use
2. **Monitor performance** - Use the popup statistics to track effectiveness  
3. **Refine rules** - Adjust based on false positives/negatives
4. **Add custom rules** - Extend detection for organization-specific threats

## 🆘 Quick Test Command

**Fastest way to verify everything works:**

1. Open `test-detection-rules-standalone.html`
2. Click "Run All Tests" 
3. Look for "✅ DETECTION RULES WORKING" in the summary

This will validate all your detection rules in under 30 seconds!
