# Store Publication Preparation Script
# Creates a single universal package for both Chrome Web Store and Edge Add-ons

param(
    [string]$Version = '1.1.0',
    [string]$OutputPath = 'store-packages'
)

Write-Host '🏪 Universal Store Package Preparation' -ForegroundColor Cyan

# Create output directory
if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

# Determine source directory based on script location
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$sourceDir = $scriptDir  # Script is in the root directory
$tempDir = Join-Path $env:TEMP 'check-extension-package'

Write-Host '📦 Preparing universal store package...' -ForegroundColor Yellow

# Clean temp directory
if (Test-Path $tempDir) {
    Remove-Item $tempDir -Recurse -Force
}

# Create temp directory
New-Item -ItemType Directory -Path $tempDir | Out-Null

# Copy only the files needed for the extension
$filesToInclude = @(
    'manifest.json',
    'blocked.html',
    'config',
    'images',
    'options',
    'popup',
    'rules',
    'scripts',
    'styles'
)

foreach ($item in $filesToInclude) {
    $sourcePath = Join-Path $sourceDir $item
    if (Test-Path $sourcePath) {
        $destPath = Join-Path $tempDir $item
        if (Test-Path $sourcePath -PathType Container) {
            Copy-Item $sourcePath $destPath -Recurse -Force
        } else {
            Copy-Item $sourcePath $destPath -Force
        }
        Write-Host "✅ Included: $item" -ForegroundColor Green
    } else {
        Write-Host "⚠️  Not found: $item" -ForegroundColor Yellow
    }
}

# Remove any development/debug files from copied directories
$devFilesToRemove = @(
    '*.md',
    '*.log',
    '.DS_Store',
    'Thumbs.db',
    '*.tmp'
)

foreach ($pattern in $devFilesToRemove) {
    Get-ChildItem $tempDir -Name $pattern -Recurse -Force 2>$null | ForEach-Object {
        $fullPath = Join-Path $tempDir $_
        if (Test-Path $fullPath) {
            Remove-Item $fullPath -Force
            Write-Host "Removed dev file: $_" -ForegroundColor Gray
        }
    }
}

# Update manifest.json for store
$manifestPath = Join-Path $tempDir 'manifest.json'
if (Test-Path $manifestPath) {
    $manifest = Get-Content $manifestPath | ConvertFrom-Json

    # Update version
    $manifest.version = $Version

    # Ensure production settings
    $manifest.content_security_policy = @{
        extension_pages = "script-src 'self'; object-src 'self'"
    }

    # Convert back to JSON with proper formatting
    $jsonString = $manifest | ConvertTo-Json -Depth 10
    $jsonString | Set-Content $manifestPath -Encoding UTF8

    Write-Host '✅ Updated manifest.json for stores' -ForegroundColor Green
}

# Update options.js to disable development mode
$optionsPath = Join-Path $tempDir 'options\options.js'
if (Test-Path $optionsPath) {
    $content = Get-Content $optionsPath -Raw
    $content = $content -replace 'const DEVELOPMENT_MODE = true', 'const DEVELOPMENT_MODE = false'
    $content | Set-Content $optionsPath -Encoding UTF8
    Write-Host '✅ Disabled development mode in options.js' -ForegroundColor Green
}

# Create the package
$packageName = "check-extension-v$Version.zip"
$packagePath = Join-Path $OutputPath $packageName

# Remove existing package if it exists
if (Test-Path $packagePath) {
    Remove-Item $packagePath -Force
}

# Create the zip file
Compress-Archive -Path "$tempDir\*" -DestinationPath $packagePath
Write-Host "✅ Created package: $packageName" -ForegroundColor Green

# Clean up temp directory
Remove-Item $tempDir -Recurse -Force

# Get file size
$size = [math]::Round((Get-Item $packagePath).Length / 1MB, 2)

Write-Host ''
Write-Host '🎉 Universal store package created successfully!' -ForegroundColor Green
Write-Host "📁 Location: $OutputPath" -ForegroundColor Cyan
Write-Host "  📦 $packageName ($size MB)" -ForegroundColor White

Write-Host ''
Write-Host '📋 Next Steps:' -ForegroundColor Yellow
Write-Host '1. Submit the SAME package to both stores:' -ForegroundColor White
Write-Host '   📤 Chrome Web Store: https://chrome.google.com/webstore/devconsole' -ForegroundColor Cyan
Write-Host '   📤 Edge Add-ons: https://partner.microsoft.com/dashboard/microsoftedge' -ForegroundColor Cyan
Write-Host '2. Note the assigned extension IDs from each store' -ForegroundColor White
Write-Host '3. Update enterprise registry files with store IDs:' -ForegroundColor White
Write-Host '   .\Update-StoreIDs.ps1 -ChromeID <chrome-id> -EdgeID <edge-id>' -ForegroundColor Gray
Write-Host '4. Test managed policies with store-installed extensions' -ForegroundColor White

Write-Host ''
Write-Host '💡 Remember: Both stores accept the same ZIP file!' -ForegroundColor Yellow
