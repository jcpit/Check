---
description: >-
  This page will outline the various ways that you can deploy Check to your
  clients' environments
icon: bolt
---

# Chrome/Edge Deployment Instructions

Review the below options for how to deploy Check to your clients' environments. If you use a RMM not featured, please see the [#generic-powershell](chrome-edge-deployment-instructions.md#generic-powershell "mention") option to script the install.

<details>

<summary>Intune</summary>

#### Prepare Your Extension Configuration JSON

You need to generate two JSON strings:

* One for **Chrome**
* One for **Edge**

Each JSON should include the following settings. Please review all settings. Any that you do not set will use the defaults. For more detailed descriptions of what each option is, please see the [#generic-powershell](chrome-edge-deployment-instructions.md#generic-powershell "mention") script.

Chrome:

```json

{
  "benimdeioplgkhanklclahllklceahbe": {
    "installation_mode": "force_installed",
    "update_url": "https://clients2.google.com/service/update2/crx",
    "settings": {
      "showNotifications": true,
      "enableValidPageBadge": false,
      "enablePageBlocking": false,
      "enableCippReporting": true,
      "cippServerUrl": "https://yourserver.com",
      "cippTenantId": "your-tenant-id",
      "customRulesUrl": "https://yourrules.com",
      "updateInterval": 24,
      "enableDebugLogging": false,
      "customBranding": {
        "companyName": "Your Company",
        "productName": "Check",
        "supportEmail": "support@yourcompany.com",
        "primaryColor": "#FF0000",
        "logoUrl": "https://yourcompany.com/logo.png"
      }
    }
  }
}

```

Edge:

```json

{
  "knepjpocdagponkonnbggpcnhnaikajg": {
    "installation_mode": "force_installed",
    "update_url": "https://clients2.google.com/service/update2/crx",
    "settings": {
      "showNotifications": true,
      "enableValidPageBadge": false,
      "enablePageBlocking": false,
      "enableCippReporting": true,
      "cippServerUrl": "https://yourserver.com",
      "cippTenantId": "your-tenant-id",
      "customRulesUrl": "https://yourrules.com",
      "updateInterval": 60,
      "enableDebugLogging": false,
      "customBranding": {
        "companyName": "Your Company",
        "productName": "Check",
        "supportEmail": "support@yourcompany.com",
        "primaryColor": "#FF0000",
        "logoUrl": "https://yourcompany.com/logo.png"
      }
    }
  }
}

```

#### Create a Custom Configuration Profile in Intune for Chrome

1. **Sign in** to Microsoft Intune Admin Center
2. Go to **Devices** > Configuration profiles > Create Profile
3. Choose:
   1. Platform: Windows 10 and later
   2. Profile type: Custom
4. Click Create and fill in:
   1. Name: Chrome Extension - Check
   2. Description: Deploys and configures the Check Chrome extension
5. Under Configuration settings, click Add and enter:
   1. Name: Chrome Extension Settings
   2. Description: Configure Check Chrome extension settings
   3. OMA-URI: ./Device/Vendor/MSFT/Policy/Config/Chrome~~Policy~~googlechrome/ExtensionSettings
   4. Data Type: String
   5. Value: Paste the Chrome JSON created above.
6. Click Next, assign the profile to the appropriate groups, and **Create** the profile

#### Create a Custom Configuration Profile in Intune for Edge

1. Repeat the steps above with the following changes:
   1. Name: Edge Extension - Check
   2. Description: Deploys and configures the Check Edge Extension
   3. OMA-URI: ./Device/Vendor/MSFT/Policy/Config/Edge/ExtensionSettings
   4. Value: Paste the Edge JSON created above

</details>

<details>

<summary>Generic PowerShell</summary>

#### Modify the following script and copy it to your RMM's scripting engine to deploy Check:

{% hint style="info" %}
This script is designed to deploy the extension to both Chrome and Edge. It is recommended to deploy both even if you standardize on one. This will provide you with better protection in the case someone uses the non-favored browser.
{% endhint %}

1. Review the Extension Configuration Settings and Custom Branding Settings variables and update those to your desired values. The current values in the script are the default values. Leaving any unchanged will set the defaults.&#x20;
2. If you are leveraging a RMM that has the ability to define the variables in the deployment section of scripting, then you may be able to remove this section and enter the variable definitions into the RMM scripting pages.

{% code overflow="wrap" lineNumbers="true" fullWidth="true" %}
```powershell
# Define extension details
# Chrome
$chromeExtensionId = "benimdeioplgkhanklclahllklceahbe"
$chromeUpdateUrl = "https://clients2.google.com/service/update2/crx"
$chromeManagedStorageKey = "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$chromeExtensionId\policy"
$chromeExtensionSettingsKey = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionSettings\$chromeExtensionId"

#Edge
$edgeExtensionId = "knepjpocdagponkonnbggpcnhnaikajg"
$edgeUpdateUrl = "https://edge.microsoft.com/extensionwebstorebase/v1/crx"
$edgeManagedStorageKey = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$edgeExtensionId\policy"
$edgeExtensionSettingsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionSettings\$edgeExtensionId"

# Extension Configuration Settings
$showNotifications = 1 # 0 = Unchecked, 1 = Checked (Enabled); default is 1; This will set the "Show Notifications" option in the extension settings.
$enableValidPageBadge = 0 # 0 = Unchecked, 1 = Checked (Enabled); default is 0; This will set the "Show Valid Page Badge" option in the extension settings.
$enablePageBlocking = 1 # 0 = Unchecked, 1 = Checked (Enabled); default is 1; This will set the "Enable Page Blocking" option in the extension settings.
$enableCippReporting = 0 # 0 = Unchecked, 1 = Checked (Enabled); default is 1; This will set the "Enable CIPP Reporting" option in the extension settings.
$cippServerUrl = "" # This will set the "CIPP Server URL" option in the extension settings; default is blank; if you set $enableCippReporting to 1, you must set this to a valid URL.
$cippTenantId = "" # This will set the "Tenant ID/Domain" option in the extension settings; default is blank; if you set $enableCippReporting to 1, you must set this to a valid Tenant ID.
$customRulesUrl = "" # This will set the "Config URL" option in the Detection Configuration settings; default is blank.
$updateInterval = 24 # This will set the "Update Interval" option in the Detection Configuration settings; default is 24 (hours). Range: 1-168 hours (1 hour to 1 week)
$enableDebugLogging = 1 # 0 = Unchecked, 1 = Checked (Enabled); default is 0; This will set the "Enable Debug Logging" option in the Activity Log settings.

# Custom Branding Settings
$companyName = "CyberDrain" # This will set the "Company Name" option in the Custom Branding settings; default is "CyberDrain".
$productName = "Check - Phishing Protection" # This will set the "Product Name" option in the Custom Branding settings; default is "Check - Phishing Protection".
$supportEmail = "onotreply@cyberdrain.com" # This will set the "Support Email" option in the Custom Branding settings; default is blank.
$primaryColor = "#F77F00" # This will set the "Primary Color" option in the Custom Branding settings; default is "#F77F00"; must be a valid hex color code (e.g., #FFFFFF).
$logoUrl = "" # This will set the "Logo URL" option in the Custom Branding settings; default is blank.

# Extension Settings
# These settings control how the extension is installed and what permissions it has. It is recommended to leave these at their default values unless you have a specific need to change them.
$installationMode = "force_installed"

# Function to check and install extension
function Configure-ExtensionSettings {
    param (
        [string]$ExtensionId,
        [string]$UpdateUrl,
        [string]$ManagedStorageKey,
        [string]$ExtensionSettingsKey
    )

    # Create and configure managed storage key
    if (!(Test-Path $ManagedStorageKey)) {
        New-Item -Path $ManagedStorageKey -Force | Out-Null
    }

    # Set extension configuration settings
    New-ItemProperty -Path $ManagedStorageKey -Name "showNotifications" -PropertyType DWord -Value $showNotifications -Force | Out-Null
    New-ItemProperty -Path $ManagedStorageKey -Name "enableValidPageBadge" -PropertyType DWord -Value $enableValidPageBadge -Force | Out-Null
    New-ItemProperty -Path $ManagedStorageKey -Name "enablePageBlocking" -PropertyType DWord -Value $enablePageBlocking -Force | Out-Null
    New-ItemProperty -Path $ManagedStorageKey -Name "enableCippReporting" -PropertyType DWord -Value $enableCippReporting -Force | Out-Null
    New-ItemProperty -Path $ManagedStorageKey -Name "cippServerUrl" -PropertyType String -Value $cippServerUrl -Force | Out-Null
    New-ItemProperty -Path $ManagedStorageKey -Name "cippTenantId" -PropertyType String -Value $cippTenantId -Force | Out-Null
    New-ItemProperty -Path $ManagedStorageKey -Name "customRulesUrl" -PropertyType String -Value $customRulesUrl -Force | Out-Null
    New-ItemProperty -Path $ManagedStorageKey -Name "updateInterval" -PropertyType DWord -Value $updateInterval -Force | Out-Null
    New-ItemProperty -Path $ManagedStorageKey -Name "enableDebugLogging" -PropertyType DWord -Value $enableDebugLogging -Force | Out-Null

    # Create and configure custom branding
    $customBrandingKey = "$ManagedStorageKey\customBranding"
    if (!(Test-Path $customBrandingKey)) {
        New-Item -Path $customBrandingKey -Force | Out-Null
    }

    # Set custom branding settings
    New-ItemProperty -Path $customBrandingKey -Name "companyName" -PropertyType String -Value $companyName -Force | Out-Null
    New-ItemProperty -Path $customBrandingKey -Name "productName" -PropertyType String -Value $productName -Force | Out-Null
    New-ItemProperty -Path $customBrandingKey -Name "supportEmail" -PropertyType String -Value $supportEmail -Force | Out-Null
    New-ItemProperty -Path $customBrandingKey -Name "primaryColor" -PropertyType String -Value $primaryColor -Force | Out-Null
    New-ItemProperty -Path $customBrandingKey -Name "logoUrl" -PropertyType String -Value $logoUrl -Force | Out-Null

    # Create and configure extension settings
    if (!(Test-Path $ExtensionSettingsKey)) {
        New-Item -Path $ExtensionSettingsKey -Force | Out-Null
    }

    # Set extension settings
    New-ItemProperty -Path $ExtensionSettingsKey -Name "installation_mode" -PropertyType String -Value $installationMode -Force | Out-Null
    New-ItemProperty -Path $ExtensionSettingsKey -Name "update_url" -PropertyType String -Value $UpdateUrl -Force | Out-Null

    Write-Output "Configured extension settings for $ExtensionId"
}

# Configure settings for Chrome and Edge
Configure-ExtensionSettings -ExtensionId $chromeExtensionId -UpdateUrl $chromeUpdateUrl -ManagedStorageKey $chromeManagedStorageKey -ExtensionSettingsKey $chromeExtensionSettingsKey

```
{% endcode %}

</details>

<details>

<summary>Group Policy</summary>

1.
   1.
   2.
   3.
2.
3.

![](https://www.gitbook.com/cdn-cgi/image/dpr=2,width=1168,onerror=redirect,format=auto/https%3A%2F%2Ffiles.gitbook.com%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%2FFtDhotz26LyzVUTgqw4L%2Fuploads%2FuWyy3TSDF2HmNzC0Vcms%2Fimage.png%3Falt%3Dmedia%26token%3Da958206c-22a4-4927-8dae-7403661d3c1b)

























[PreviousAbout](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/)[Next - SettingsGeneral](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/settings/general)JO![Brian Simpson](https://www.gitbook.com/cdn-cgi/image/dpr=2,width=256,onerror=redirect,format=auto/https%3A%2F%2Ffiles.gitbook.com%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fusers%2FyXUC8uC4peNqeazDGMwuEPUBG2R2%2Favatars%2FctOqd5c9ZVApNh9d8u90%2Fprofile%20photo.jpg%3Falt%3Dmedia%26token%3D65b2de3d-14f1-4d0c-8171-10266bfc1a02)Last modified 36m ago

</details>

<details>

<summary>Action1</summary>

[https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/\~/changes/30/deployment/quickstart#generic-powershell](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/deployment/quickstart#generic-powershell "mention")

</details>

<details>

<summary>Acronis RMM</summary>

[https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/\~/changes/30/deployment/quickstart#generic-powershell](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/deployment/quickstart#generic-powershell "mention")

</details>

<details>

<summary>ConnectWise Automate</summary>

1.
2.
3.
4. [https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/\~/changes/30/deployment/quickstart#generic-powershell](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/deployment/quickstart#generic-powershell "mention")
5.

</details>

<details>

<summary>Datto RMM</summary>

1.
2.
3. [https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/\~/changes/30/deployment/quickstart#generic-powershell](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/deployment/quickstart#generic-powershell "mention")
4.
5.
6.
7.
8.
9.

</details>

<details>

<summary>Kaseya VSA</summary>

1.
2. [https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/\~/changes/30/deployment/quickstart#generic-powershell](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/deployment/quickstart#generic-powershell "mention")
3.
4.
5.
6.
7.

</details>

<details>

<summary>ManageEngine Endpoint Central</summary>

1.
2.
3.
4.
   1.
   2.
5.
6.
7.
8.
9.
10.

</details>

<details>

<summary>N-able N-Central</summary>

1.
2.
3.
   1.
   2.
4. [https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/\~/changes/30/deployment/quickstart#generic-powershell](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/deployment/quickstart#generic-powershell "mention")
5.
6.
7.
8.
9.
10.
    1.
    2.
    3.
    4.
11.

</details>

<details>

<summary>N-able N-Sight</summary>

1.
2.
3.
4.
5. [https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/\~/changes/30/deployment/quickstart#generic-powershell](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/deployment/quickstart#generic-powershell "mention")
6.
7.
8.
9.
10.
11.
12.
13.
14.
15.
16.

</details>

<details>

<summary>NinjaOne</summary>

1.
2.
3. [https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/\~/changes/30/deployment/quickstart#generic-powershell](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/deployment/quickstart#generic-powershell "mention")
4.
   1.
   2.
   3.
   4.
   5.
   6.
5.
6.
7.
8.
9.
10.
11.
12.

</details>

<details>

<summary>Pulseway</summary>

1.
2.
3.
4.
5.
6.
7. [https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/\~/changes/30/deployment/quickstart#generic-powershell](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/deployment/quickstart#generic-powershell "mention")
8.
9.
10.
11.
12.
13.
14.
15.

</details>

<details>

<summary>SuperOps.ai</summary>

1.
2.
3.
4.
5. [https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/\~/changes/30/deployment/quickstart#generic-powershell](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/deployment/quickstart#generic-powershell "mention")
6.
7.
8.
9.

</details>

<details>

<summary>Syncro</summary>

1.
2.
3.
4.
5.
6. [https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/\~/changes/30/deployment/quickstart#generic-powershell](https://app.gitbook.com/o/zaMrayG0X0xKqQLa8i9S/s/FtDhotz26LyzVUTgqw4L/~/changes/30/deployment/quickstart#generic-powershell "mention")
7.
8.
9.
10.
11.
12.
13.
14.
15.

</details>
