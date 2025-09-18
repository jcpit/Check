# Check Extension - ADMX Template Deployment Script
# This script installs the Check extension Group Policy templates

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('Domain', 'Local')]
    [string]$Scope = 'Local',

    [Parameter(Mandatory = $false)]
    [string]$DomainName = $env:USERDNSDOMAIN,

    [Parameter(Mandatory = $false)]
    [switch]$Uninstall
)

# Get script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$AdmxPath = Join-Path $ScriptDir 'admx'

# Define source files
$AdmxFile = Join-Path $AdmxPath 'Check-Extension.admx'
$AdmlFile = Join-Path $AdmxPath 'en-US\Check-Extension.adml'

# Validate source files exist
if (-not (Test-Path $AdmxFile)) {
    Write-Error "ADMX file not found: $AdmxFile"
    exit 1
}

if (-not (Test-Path $AdmlFile)) {
    Write-Error "ADML file not found: $AdmlFile"
    exit 1
}

# Determine destination paths
if ($Scope -eq 'Domain') {
    if (-not $DomainName) {
        Write-Error 'Domain name is required for domain deployment. Use -DomainName parameter or ensure machine is domain-joined.'
        exit 1
    }

    $DestAdmxPath = "\\$DomainName\SYSVOL\$DomainName\Policies\PolicyDefinitions"
    $DestAdmlPath = "\\$DomainName\SYSVOL\$DomainName\Policies\PolicyDefinitions\en-US"
} else {
    $DestAdmxPath = "$env:SystemRoot\PolicyDefinitions"
    $DestAdmlPath = "$env:SystemRoot\PolicyDefinitions\en-US"
}

$DestAdmxFile = Join-Path $DestAdmxPath 'Check-Extension.admx'
$DestAdmlFile = Join-Path $DestAdmlPath 'Check-Extension.adml'

Write-Host 'Check Extension ADMX Template Deployment' -ForegroundColor Cyan
Write-Host '=========================================' -ForegroundColor Cyan
Write-Host "Scope: $Scope" -ForegroundColor Yellow
Write-Host "Destination: $DestAdmxPath" -ForegroundColor Yellow

if ($Uninstall) {
    Write-Host "`nUninstalling templates..." -ForegroundColor Red

    # Remove ADMX file
    if (Test-Path $DestAdmxFile) {
        try {
            Remove-Item $DestAdmxFile -Force
            Write-Host "✓ Removed: $DestAdmxFile" -ForegroundColor Green
        } catch {
            Write-Error "Failed to remove ADMX file: $($_.Exception.Message)"
        }
    } else {
        Write-Host '- ADMX file not found (already removed)' -ForegroundColor Gray
    }

    # Remove ADML file
    if (Test-Path $DestAdmlFile) {
        try {
            Remove-Item $DestAdmlFile -Force
            Write-Host "✓ Removed: $DestAdmlFile" -ForegroundColor Green
        } catch {
            Write-Error "Failed to remove ADML file: $($_.Exception.Message)"
        }
    } else {
        Write-Host '- ADML file not found (already removed)' -ForegroundColor Gray
    }

    Write-Host "`nUninstallation complete!" -ForegroundColor Green
    Write-Host 'Note: You may need to refresh the Group Policy Editor to see changes.' -ForegroundColor Yellow

} else {
    Write-Host "`nInstalling templates..." -ForegroundColor Green

    # Ensure destination directories exist
    if (-not (Test-Path $DestAdmxPath)) {
        Write-Host "Creating directory: $DestAdmxPath" -ForegroundColor Yellow
        New-Item -Path $DestAdmxPath -ItemType Directory -Force | Out-Null
    }

    if (-not (Test-Path $DestAdmlPath)) {
        Write-Host "Creating directory: $DestAdmlPath" -ForegroundColor Yellow
        New-Item -Path $DestAdmlPath -ItemType Directory -Force | Out-Null
    }

    # Copy ADMX file
    try {
        Copy-Item $AdmxFile $DestAdmxFile -Force
        Write-Host "✓ Installed: $DestAdmxFile" -ForegroundColor Green
    } catch {
        Write-Error "Failed to copy ADMX file: $($_.Exception.Message)"
        exit 1
    }

    # Copy ADML file
    try {
        Copy-Item $AdmlFile $DestAdmlFile -Force
        Write-Host "✓ Installed: $DestAdmlFile" -ForegroundColor Green
    } catch {
        Write-Error "Failed to copy ADML file: $($_.Exception.Message)"
        exit 1
    }

    Write-Host "`nInstallation complete!" -ForegroundColor Green
    Write-Host "`nThe policies are now available at:" -ForegroundColor Cyan
    Write-Host 'Computer Configuration > Administrative Templates > CyberDrain > Check - Phishing Protection' -ForegroundColor White

    if ($Scope -eq 'Domain') {
        Write-Host "`nDomain deployment notes:" -ForegroundColor Yellow
        Write-Host '- Policies will be available on all domain controllers' -ForegroundColor Gray
        Write-Host '- May take time to replicate across the domain' -ForegroundColor Gray
        Write-Host "- Run 'gpupdate /force' on target machines to apply policies" -ForegroundColor Gray
    } else {
        Write-Host "`nLocal deployment notes:" -ForegroundColor Yellow
        Write-Host '- Policies are only available on this machine' -ForegroundColor Gray
        Write-Host '- You may need to restart the Group Policy Editor' -ForegroundColor Gray
    }
}

Write-Host "`nFor more information, see the README.md file in the enterprise folder." -ForegroundColor Cyan
