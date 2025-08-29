# Check Extension Testing Guide

## Quick Extension Test

This guide will help you verify that your Check extension is working properly.

### 1. Load the Extension in Chrome

1. Open Chrome browser
2. Navigate to `chrome://extensions/`
3. Enable "Developer mode" (toggle in top right)
4. Click "Load unpacked"
5. Select this project folder: `c:\Users\JohnDupreyCyberDrain\Documents\GitHub\ProjectX`
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

