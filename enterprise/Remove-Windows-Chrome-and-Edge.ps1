# Define extension details (same as install-check.ps1)
# Chrome
$chromeExtensionId = "benimdeioplgkhanklclahllklceahbe"
$chromeManagedStorageKey = "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$chromeExtensionId\policy"
$chromeExtensionSettingsKey = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionSettings\$chromeExtensionId"

# Edge
$edgeExtensionId = "knepjpocdagponkonnbggpcnhnaikajg"
$edgeManagedStorageKey = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$edgeExtensionId\policy"
$edgeExtensionSettingsKey = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionSettings\$edgeExtensionId"

# Function to remove extension settings
function Remove-ExtensionSettings {
    param (
        [string]$ExtensionId,
        [string]$ManagedStorageKey,
        [string]$ExtensionSettingsKey
    )

    # Remove properties from managed storage key
    if (Test-Path $ManagedStorageKey) {
        $propertiesToRemove = @(
            "showNotifications",
            "enableValidPageBadge",
            "enablePageBlocking",
            "enableCippReporting",
            "cippServerUrl",
            "cippTenantId",
            "customRulesUrl",
            "updateInterval",
            "enableDebugLogging"
        )

        foreach ($property in $propertiesToRemove) {
            if (Get-ItemProperty -Path $ManagedStorageKey -Name $property -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $ManagedStorageKey -Name $property -Force -ErrorAction SilentlyContinue
                Write-Host "Removed property: $property from $ManagedStorageKey"
            }
        }

        # Remove URL allowlist subkey and all its properties
        $urlAllowlistKey = "$ManagedStorageKey\urlAllowlist"
        if (Test-Path $urlAllowlistKey) {
            # Remove all numbered properties (1, 2, 3, etc.)
            $properties = Get-ItemProperty -Path $urlAllowlistKey -ErrorAction SilentlyContinue
            if ($properties) {
                $properties.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object {
                    Remove-ItemProperty -Path $urlAllowlistKey -Name $_.Name -Force -ErrorAction SilentlyContinue
                    Write-Host "Removed URL allowlist property: $($_.Name) from $urlAllowlistKey"
                }
            }
            # Remove the urlAllowlist subkey if it's empty
            try {
                Remove-Item -Path $urlAllowlistKey -Force -ErrorAction SilentlyContinue
                Write-Host "Removed URL allowlist subkey: $urlAllowlistKey"
            } catch {
                # Key may not be empty or may have been removed already
            }
        }

        # Remove custom branding subkey and all its properties
        $customBrandingKey = "$ManagedStorageKey\customBranding"
        if (Test-Path $customBrandingKey) {
            $brandingPropertiesToRemove = @(
                "companyName",
                "companyURL",
                "productName",
                "supportEmail",
                "primaryColor",
                "logoUrl"
            )

            foreach ($property in $brandingPropertiesToRemove) {
                if (Get-ItemProperty -Path $customBrandingKey -Name $property -ErrorAction SilentlyContinue) {
                    Remove-ItemProperty -Path $customBrandingKey -Name $property -Force -ErrorAction SilentlyContinue
                    Write-Host "Removed custom branding property: $property from $customBrandingKey"
                }
            }

            # Remove the customBranding subkey if it's empty
            try {
                Remove-Item -Path $customBrandingKey -Force -ErrorAction SilentlyContinue
                Write-Host "Removed custom branding subkey: $customBrandingKey"
            } catch {
                # Key may not be empty or may have been removed already
            }
        }

        # Remove the managed storage key if it's empty
        try {
            $remainingProperties = Get-ItemProperty -Path $ManagedStorageKey -ErrorAction SilentlyContinue
            if ($remainingProperties -and $remainingProperties.PSObject.Properties.Count -eq 0) {
                Remove-Item -Path $ManagedStorageKey -Force -ErrorAction SilentlyContinue
                Write-Host "Removed managed storage key: $ManagedStorageKey"
            }
        } catch {
            # Key may not be empty or may have been removed already
        }
    }

    # Remove properties from extension settings key
    if (Test-Path $ExtensionSettingsKey) {
        $extensionPropertiesToRemove = @(
            "installation_mode",
            "update_url"
        )

        # Add browser-specific toolbar properties
        if ($ExtensionId -eq $edgeExtensionId) {
            $extensionPropertiesToRemove += "toolbar_state"
        } elseif ($ExtensionId -eq $chromeExtensionId) {
            $extensionPropertiesToRemove += "toolbar_pin"
        }

        foreach ($property in $extensionPropertiesToRemove) {
            if (Get-ItemProperty -Path $ExtensionSettingsKey -Name $property -ErrorAction SilentlyContinue) {
                Remove-ItemProperty -Path $ExtensionSettingsKey -Name $property -Force -ErrorAction SilentlyContinue
                Write-Host "Removed extension setting property: $property from $ExtensionSettingsKey"
            }
        }

        # Remove the extension settings key if it's empty
        try {
            $remainingProperties = Get-ItemProperty -Path $ExtensionSettingsKey -ErrorAction SilentlyContinue
            if ($remainingProperties -and $remainingProperties.PSObject.Properties.Count -eq 0) {
                Remove-Item -Path $ExtensionSettingsKey -Force -ErrorAction SilentlyContinue
                Write-Host "Removed extension settings key: $ExtensionSettingsKey"
            }
        } catch {
            # Key may not be empty or may have been removed already
        }
    }

    Write-Host "Completed removal of extension settings for $ExtensionId"
}

# Remove settings for Chrome and Edge
Remove-ExtensionSettings -ExtensionId $chromeExtensionId -ManagedStorageKey $chromeManagedStorageKey -ExtensionSettingsKey $chromeExtensionSettingsKey
Remove-ExtensionSettings -ExtensionId $edgeExtensionId -ManagedStorageKey $edgeManagedStorageKey -ExtensionSettingsKey $edgeExtensionSettingsKey
