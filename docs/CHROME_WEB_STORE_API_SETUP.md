# Chrome Web Store API Setup

This document explains how to set up the Chrome Web Store API credentials needed for automated publishing.

## 🔑 Required GitHub Secrets

The release workflow requires three secrets to be configured in your GitHub repository:

### Setting up Secrets in GitHub:
1. Go to your repository on GitHub
2. Click **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret** for each of the following:

### Required Secrets:

#### `CHROME_CLIENT_ID`
- **Description**: OAuth 2.0 Client ID for Chrome Web Store API
- **How to get**: Follow steps below in "Setting up Chrome Web Store API"

#### `CHROME_CLIENT_SECRET`
- **Description**: OAuth 2.0 Client Secret for Chrome Web Store API  
- **How to get**: Follow steps below in "Setting up Chrome Web Store API"

#### `CHROME_REFRESH_TOKEN`
- **Description**: OAuth 2.0 Refresh Token for Chrome Web Store API
- **How to get**: Follow steps below in "Setting up Chrome Web Store API"

## 🚀 Setting up Chrome Web Store API

### Step 1: Enable Chrome Web Store API

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the **Chrome Web Store API**:
   - Go to **APIs & Services** → **Library**
   - Search for "Chrome Web Store API"
   - Click **Enable**

### Step 2: Create OAuth 2.0 Credentials

1. Go to **APIs & Services** → **Credentials**
2. Click **+ CREATE CREDENTIALS** → **OAuth client ID**
3. If prompted, configure OAuth consent screen:
   - User Type: **External**
   - App name: `Your Extension Name Publisher`
   - User support email: Your email
   - Developer contact: Your email
4. For Application type, select **Desktop application**
5. Name: `Chrome Extension Publisher`
6. Click **Create**
7. **Save the Client ID and Client Secret** - you'll need these for GitHub secrets

### Step 3: Get Refresh Token

You need to get a refresh token by authorizing your application:

#### Option A: Using curl (Manual)

1. **Get Authorization Code**:
   Open this URL in your browser (replace `YOUR_CLIENT_ID`):
   ```
   https://accounts.google.com/o/oauth2/auth?response_type=code&scope=https://www.googleapis.com/auth/chromewebstore&client_id=YOUR_CLIENT_ID&redirect_uri=urn:ietf:wg:oauth:2.0:oob
   ```

2. **Authorize and copy the code** from the response

3. **Exchange code for refresh token**:
   ```bash
   curl "https://accounts.google.com/o/oauth2/token" \
     -d "client_id=YOUR_CLIENT_ID" \
     -d "client_secret=YOUR_CLIENT_SECRET" \
     -d "code=AUTHORIZATION_CODE_FROM_STEP_2" \
     -d "grant_type=authorization_code" \
     -d "redirect_uri=urn:ietf:wg:oauth:2.0:oob"
   ```

4. **Save the refresh_token** from the response

#### Option B: Using Node.js Script

Create this script to get your refresh token:

```javascript
const https = require('https');
const querystring = require('querystring');

// Replace with your credentials
const CLIENT_ID = 'your_client_id_here';
const CLIENT_SECRET = 'your_client_secret_here';

console.log('1. Visit this URL to authorize:');
console.log(`https://accounts.google.com/o/oauth2/auth?response_type=code&scope=https://www.googleapis.com/auth/chromewebstore&client_id=${CLIENT_ID}&redirect_uri=urn:ietf:wg:oauth:2.0:oob`);
console.log('\\n2. Enter the authorization code:');

process.stdin.once('data', (code) => {
  const postData = querystring.stringify({
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    code: code.toString().trim(),
    grant_type: 'authorization_code',
    redirect_uri: 'urn:ietf:wg:oauth:2.0:oob'
  });

  const req = https.request({
    hostname: 'accounts.google.com',
    path: '/o/oauth2/token',
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(postData)
    }
  }, (res) => {
    let data = '';
    res.on('data', (chunk) => data += chunk);
    res.on('end', () => {
      const response = JSON.parse(data);
      console.log('\\n3. Your refresh token:');
      console.log(response.refresh_token);
    });
  });

  req.write(postData);
  req.end();
});
```

### Step 4: Configure GitHub Secrets

Add these three secrets to your GitHub repository:

1. **CHROME_CLIENT_ID**: Your OAuth 2.0 Client ID
2. **CHROME_CLIENT_SECRET**: Your OAuth 2.0 Client Secret  
3. **CHROME_REFRESH_TOKEN**: The refresh token from Step 3

## 🔧 Extension ID Configuration

The workflow uses the extension ID `benimdeioplgkhanklclahllklceahbe` which is already configured. If you need to change this:

1. Update the `EXTENSION_ID` environment variable in `.github/workflows/release.yml`
2. Update the extension ID in `STORE_IDS.md`

## 🚀 Usage

### Automatic Release (Recommended)
```bash
# Create and push a version tag
git tag v1.0.0
git push origin v1.0.0
```

### Manual Release
1. Go to **Actions** tab in GitHub
2. Select **Build and Release Extension**
3. Click **Run workflow**
4. Enter version and choose whether to publish to store
5. Click **Run workflow**

## 🔍 Troubleshooting

### Common Issues:

1. **"Invalid refresh token"**: Regenerate the refresh token using Step 3
2. **"Extension not found"**: Verify the extension ID in the workflow
3. **"Insufficient permissions"**: Ensure the Google Cloud project has Chrome Web Store API enabled
4. **"Package rejected"**: Check manifest.json validation and store policies

### Testing the Setup:

You can test your credentials using curl:

```bash
# Test refresh token
curl "https://accounts.google.com/o/oauth2/token" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "refresh_token=YOUR_REFRESH_TOKEN" \
  -d "grant_type=refresh_token"

# Should return an access_token
```

## 📚 References

- [Chrome Web Store API Documentation](https://developer.chrome.com/docs/webstore/using_webstore_api/)
- [chrome-extension-upload Action](https://github.com/mnao305/chrome-extension-upload)
- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
