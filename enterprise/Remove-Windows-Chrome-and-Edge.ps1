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

    # Remove all managed policy values and nested keys created for this extension.
    if (Test-Path $ManagedStorageKey) {
        try {
            Remove-Item -Path $ManagedStorageKey -Recurse -Force -ErrorAction Stop
            Write-Host "Removed managed storage key: $ManagedStorageKey"
        } catch {
            Write-Warning "Failed to remove managed storage key: $ManagedStorageKey. Error: $($_.Exception.Message)"
        }
    } else {
        Write-Host "Managed storage key not found (already removed): $ManagedStorageKey"
    }

    # Remove extension install/settings key for this extension.
    if (Test-Path $ExtensionSettingsKey) {
        try {
            Remove-Item -Path $ExtensionSettingsKey -Recurse -Force -ErrorAction Stop
            Write-Host "Removed extension settings key: $ExtensionSettingsKey"
        } catch {
            Write-Warning "Failed to remove extension settings key: $ExtensionSettingsKey. Error: $($_.Exception.Message)"
        }
    } else {
        Write-Host "Extension settings key not found (already removed): $ExtensionSettingsKey"
    }

    Write-Host "Completed removal of extension settings for $ExtensionId"
}

# Remove settings for Chrome and Edge
Remove-ExtensionSettings -ExtensionId $chromeExtensionId -ManagedStorageKey $chromeManagedStorageKey -ExtensionSettingsKey $chromeExtensionSettingsKey
Remove-ExtensionSettings -ExtensionId $edgeExtensionId -ManagedStorageKey $edgeManagedStorageKey -ExtensionSettingsKey $edgeExtensionSettingsKey
