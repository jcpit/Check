# Update Registry Files with Store Extension IDs
# Run this after getting extension IDs from stores

param(
    [string]$ChromeExtensionId,
    [string]$EdgeExtensionId,
    [string]$FirefoxExtensionId
)

Write-Output "🔄 Updating registry files with store extension IDs..."

if (!$ChromeExtensionId -and !$EdgeExtensionId -and !$FirefoxExtensionId) {
    Write-Output "❌ Please provide at least one extension ID"
    Write-Output "Usage: .\Update-StoreIDs.ps1 -ChromeExtensionId 'abcd...' -EdgeExtensionId 'efgh...'"
    exit 1
}

# Validate extension ID format
function Test-ExtensionId {
    param($Id, $Store)
    
    if ($Store -eq "Firefox" -and $Id -match "^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$") {
        return $true  # Firefox GUID format
    }
    
    if ($Id -match "^[a-z]{32}$") {
        return $true  # Chrome/Edge format
    }
    
    return $false
}

# Update Chrome registry
if ($ChromeExtensionId) {
    if (Test-ExtensionId $ChromeExtensionId "Chrome") {
        $chromeFile = "registry-chrome-store.reg"
        if (Test-Path $chromeFile) {
            $content = Get-Content $chromeFile -Raw
            $content = $content -replace "CHROME_EXTENSION_ID", $ChromeExtensionId
            $content | Set-Content $chromeFile -Encoding UTF8
            Write-Output "✅ Updated Chrome registry: $chromeFile"
        }
    } else {
        Write-Output "❌ Invalid Chrome extension ID format: $ChromeExtensionId"
    }
}

# Update Edge registry
if ($EdgeExtensionId) {
    if (Test-ExtensionId $EdgeExtensionId "Edge") {
        $edgeFile = "registry-edge-store.reg"
        if (Test-Path $edgeFile) {
            $content = Get-Content $edgeFile -Raw
            $content = $content -replace "EDGE_EXTENSION_ID", $EdgeExtensionId
            $content | Set-Content $edgeFile -Encoding UTF8
            Write-Output "✅ Updated Edge registry: $edgeFile"
        }
    } else {
        Write-Output "❌ Invalid Edge extension ID format: $EdgeExtensionId"
    }
}

# Update Firefox registry (if provided)
if ($FirefoxExtensionId) {
    if (Test-ExtensionId $FirefoxExtensionId "Firefox") {
        Write-Output "✅ Firefox extension ID validated: $FirefoxExtensionId"
        # Firefox policies would go in a separate file
    } else {
        Write-Output "❌ Invalid Firefox extension ID format: $FirefoxExtensionId"
    }
}

# Update documentation
$storeIdFile = "STORE_IDS.md"
if (Test-Path $storeIdFile) {
    $content = Get-Content $storeIdFile -Raw
    
    if ($ChromeExtensionId) {
        $content = $content -replace 'CHROME_EXTENSION_ID="will-be-assigned-by-google"', "CHROME_EXTENSION_ID=`"$ChromeExtensionId`""
    }
    
    if ($EdgeExtensionId) {
        $content = $content -replace 'EDGE_EXTENSION_ID="will-be-assigned-by-microsoft"', "EDGE_EXTENSION_ID=`"$EdgeExtensionId`""
    }
    
    if ($FirefoxExtensionId) {
        $content = $content -replace 'FIREFOX_EXTENSION_ID="will-be-assigned-by-mozilla"', "FIREFOX_EXTENSION_ID=`"$FirefoxExtensionId`""
    }
    
    $content | Set-Content $storeIdFile -Encoding UTF8
    Write-Output "✅ Updated store IDs documentation"
}

Write-Output ""
Write-Output "🎉 Registry files updated successfully!"
Write-Output "📋 Next steps:"
Write-Output "1. Import the updated registry files on test machines"
Write-Output "2. Install extensions from stores (will auto-install with force_installed)"
Write-Output "3. Verify managed policies are applied"
Write-Output "4. Deploy to production environments"
