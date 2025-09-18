#!/bin/bash

# Check Extension - macOS Configuration Profile Deployment Script
# This script installs or removes the Check extension configuration profiles on macOS

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHROME_PROFILE_FILE="$SCRIPT_DIR/chrome-extension-config.mobileconfig"
EDGE_PROFILE_FILE="$SCRIPT_DIR/edge-extension-config.mobileconfig"
CHROME_POLICY_FILE="$SCRIPT_DIR/chrome-managed-policy.json"
EDGE_POLICY_FILE="$SCRIPT_DIR/edge-managed-policy.json"
CHROME_PROFILE_IDENTIFIER="com.cyberdrain.check.chrome.configuration"
EDGE_PROFILE_IDENTIFIER="com.cyberdrain.check.edge.configuration"
CHROME_POLICY_DIR="/Library/Managed Preferences"
EDGE_POLICY_DIR="/Library/Managed Preferences"
CHROME_POLICY_PATH="$CHROME_POLICY_DIR/com.google.Chrome.plist"
EDGE_POLICY_PATH="$EDGE_POLICY_DIR/com.microsoft.Edge.plist"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${CYAN}Check Extension - macOS Configuration Deployment${NC}"
    echo -e "${CYAN}=================================================${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        echo "Usage: sudo $0 [install|uninstall|status]"
        exit 1
    fi
}

# Function to check system requirements
check_system_requirements() {
    print_info "Checking system requirements..."

    # Check if profiles command exists
    if ! command -v profiles >/dev/null 2>&1; then
        print_error "profiles command not found - this script requires macOS"
        exit 1
    fi

    # Check if plutil command exists
    if ! command -v plutil >/dev/null 2>&1; then
        print_error "plutil command not found - this script requires macOS"
        exit 1
    fi

    # Check macOS version
    local macos_version
    macos_version=$(sw_vers -productVersion 2>/dev/null)
    if [[ $? -eq 0 ]]; then
        print_success "macOS version: $macos_version"

        # Check if version is 10.13 or later (required for configuration profiles)
        local major_version minor_version
        major_version=$(echo "$macos_version" | cut -d. -f1)
        minor_version=$(echo "$macos_version" | cut -d. -f2)

        if [[ $major_version -lt 10 ]] || ([[ $major_version -eq 10 ]] && [[ $minor_version -lt 13 ]]); then
            print_warning "macOS 10.13 or later is recommended for configuration profiles"
        fi

        # Check if version is 13.0 or later (profiles command install deprecated)
        if [[ $major_version -ge 13 ]]; then
            print_warning "macOS 13+ detected - profiles command no longer supports installs"
            print_info "Manual installation through System Settings will be required"
            export MACOS_MANUAL_INSTALL=true
        else
            export MACOS_MANUAL_INSTALL=false
        fi
    else
        print_warning "Could not determine macOS version"
        export MACOS_MANUAL_INSTALL=false
    fi

    print_success "System requirements check passed"
}

# Function to validate JSON file
validate_json() {
    local file="$1"

    # Try python3 first
    if command -v python3 >/dev/null 2>&1; then
        python3 -m json.tool "$file" >/dev/null 2>&1
        return $?
    # Fallback to python
    elif command -v python >/dev/null 2>&1; then
        python -m json.tool "$file" >/dev/null 2>&1
        return $?
    # If no Python, try with plutil (which can handle JSON on newer macOS)
    elif plutil -convert xml1 "$file" -o /dev/null >/dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# Function to validate files exist
validate_files() {
    local files_missing=false

    if [[ ! -f "$CHROME_PROFILE_FILE" ]]; then
        print_error "Chrome configuration profile not found: $CHROME_PROFILE_FILE"
        files_missing=true
    else
        print_info "Validating Chrome configuration profile..."
        if plutil -lint "$CHROME_PROFILE_FILE" >/dev/null 2>&1; then
            print_success "Chrome configuration profile format is valid"
        else
            print_error "Chrome configuration profile has invalid plist format"
            print_info "Run 'plutil -lint $CHROME_PROFILE_FILE' for details"
            files_missing=true
        fi
    fi

    if [[ ! -f "$EDGE_PROFILE_FILE" ]]; then
        print_error "Edge configuration profile not found: $EDGE_PROFILE_FILE"
        files_missing=true
    else
        print_info "Validating Edge configuration profile..."
        if plutil -lint "$EDGE_PROFILE_FILE" >/dev/null 2>&1; then
            print_success "Edge configuration profile format is valid"
        else
            print_error "Edge configuration profile has invalid plist format"
            print_info "Run 'plutil -lint $EDGE_PROFILE_FILE' for details"
            files_missing=true
        fi
    fi

    if [[ ! -f "$CHROME_POLICY_FILE" ]]; then
        print_error "Chrome policy file not found: $CHROME_POLICY_FILE"
        files_missing=true
    else
        print_info "Validating Chrome policy file..."
        if validate_json "$CHROME_POLICY_FILE"; then
            print_success "Chrome policy file format is valid"
        else
            print_error "Chrome policy file has invalid JSON format"
            files_missing=true
        fi
    fi

    if [[ ! -f "$EDGE_POLICY_FILE" ]]; then
        print_error "Edge policy file not found: $EDGE_POLICY_FILE"
        files_missing=true
    else
        print_info "Validating Edge policy file..."
        if validate_json "$EDGE_POLICY_FILE"; then
            print_success "Edge policy file format is valid"
        else
            print_error "Edge policy file has invalid JSON format"
            files_missing=true
        fi
    fi

    if [[ "$files_missing" == "true" ]]; then
        exit 1
    fi
}

# Function to install configuration profile
install_profile() {
    print_info "Installing Check extension configuration profiles..."

    # Check if we need manual installation
    if [[ "${MACOS_MANUAL_INSTALL:-false}" == "true" ]]; then
        print_warning "Automatic profile installation not supported on this macOS version"
        print_info "Configuration profiles must be installed manually through System Settings"
        echo

        # Copy profiles to desktop for easy access
        local desktop_dir="$HOME/Desktop"
        if [[ -n "$SUDO_USER" ]]; then
            desktop_dir=$(eval echo "~$SUDO_USER/Desktop")
        fi

        if [[ -d "$desktop_dir" ]]; then
            cp "$CHROME_PROFILE_FILE" "$desktop_dir/Check-Chrome-Extension.mobileconfig" 2>/dev/null
            cp "$EDGE_PROFILE_FILE" "$desktop_dir/Check-Edge-Extension.mobileconfig" 2>/dev/null

            if [[ -n "$SUDO_USER" ]]; then
                chown "$SUDO_USER" "$desktop_dir/Check-Chrome-Extension.mobileconfig" 2>/dev/null
                chown "$SUDO_USER" "$desktop_dir/Check-Edge-Extension.mobileconfig" 2>/dev/null
            fi

            print_success "Configuration profiles copied to Desktop"
            echo
        fi

        print_info "Manual Installation Instructions:"
        echo "1. Double-click the .mobileconfig files on your Desktop"
        echo "   - Check-Chrome-Extension.mobileconfig"
        echo "   - Check-Edge-Extension.mobileconfig"
        echo "2. Or go to System Settings > Privacy & Security > Profiles"
        echo "3. Click the '+' button and select the .mobileconfig files"
        echo "4. Follow the prompts to install the profiles"
        echo
        print_warning "Note: You may need administrator credentials to install system-wide profiles"
        echo

        # Still install managed policies which work differently
        install_managed_policies
        return $?
    fi

    # Try automatic installation for older macOS versions
    print_info "Attempting automatic profile installation..."

    # Install Chrome configuration profile
    print_info "Installing Chrome configuration profile..."
    if profiles -I -F "$CHROME_PROFILE_FILE" 2>&1; then
        print_success "Chrome configuration profile installed successfully"
    else
        local exit_code=$?
        print_error "Failed to install Chrome configuration profile (exit code: $exit_code)"
        print_info "Attempting to validate the profile file..."

        # Validate the profile file
        if ! plutil -lint "$CHROME_PROFILE_FILE" >/dev/null 2>&1; then
            print_error "Chrome configuration profile has invalid plist format"
            print_info "Run 'plutil -lint $CHROME_PROFILE_FILE' for details"
        else
            print_info "Chrome configuration profile has valid plist format"
            print_info "This might be a permissions or system policy issue"
            print_info "Try manual installation through System Settings > Profiles"
        fi
        return 1
    fi

    # Install Edge configuration profile
    print_info "Installing Edge configuration profile..."
    if profiles -I -F "$EDGE_PROFILE_FILE" 2>&1; then
        print_success "Edge configuration profile installed successfully"
    else
        local exit_code=$?
        print_error "Failed to install Edge configuration profile (exit code: $exit_code)"
        print_info "Attempting to validate the profile file..."

        # Validate the profile file
        if ! plutil -lint "$EDGE_PROFILE_FILE" >/dev/null 2>&1; then
            print_error "Edge configuration profile has invalid plist format"
            print_info "Run 'plutil -lint $EDGE_PROFILE_FILE' for details"
        else
            print_info "Edge configuration profile has valid plist format"
            print_info "This might be a permissions or system policy issue"
            print_info "Try manual installation through System Settings > Profiles"
        fi
        return 1
    fi

    # Install managed policies
    install_managed_policies
    return $?
}

# Function to install managed policies
install_managed_policies() {

    # Install Chrome managed policy
    print_info "Installing Chrome managed policy..."
    mkdir -p "$CHROME_POLICY_DIR"

    if plutil -convert binary1 "$CHROME_POLICY_FILE" -o "$CHROME_POLICY_PATH"; then
        print_success "Chrome managed policy installed: $CHROME_POLICY_PATH"
        chown root:wheel "$CHROME_POLICY_PATH"
        chmod 644 "$CHROME_POLICY_PATH"
        print_success "Chrome policy file permissions set correctly"
    else
        print_error "Failed to install Chrome managed policy"
        return 1
    fi

    # Install Edge managed policy
    print_info "Installing Edge managed policy..."
    mkdir -p "$EDGE_POLICY_DIR"

    if plutil -convert binary1 "$EDGE_POLICY_FILE" -o "$EDGE_POLICY_PATH"; then
        print_success "Edge managed policy installed: $EDGE_POLICY_PATH"
        chown root:wheel "$EDGE_POLICY_PATH"
        chmod 644 "$EDGE_POLICY_PATH"
        print_success "Edge policy file permissions set correctly"
    else
        print_error "Failed to install Edge managed policy"
        return 1
    fi
}

# Function to uninstall configuration profile
uninstall_profile() {
    print_info "Removing Check extension configuration..."

    # Remove Chrome configuration profile
    if profiles -R -p "$CHROME_PROFILE_IDENTIFIER" >/dev/null 2>&1; then
        print_success "Chrome configuration profile removed successfully"
    else
        print_warning "Chrome configuration profile not found or already removed"
    fi

    # Remove Edge configuration profile
    if profiles -R -p "$EDGE_PROFILE_IDENTIFIER" >/dev/null 2>&1; then
        print_success "Edge configuration profile removed successfully"
    else
        print_warning "Edge configuration profile not found or already removed"
    fi

    # Remove Chrome managed policy
    if [[ -f "$CHROME_POLICY_PATH" ]]; then
        rm -f "$CHROME_POLICY_PATH"
        print_success "Chrome managed policy removed"
    else
        print_warning "Chrome managed policy not found or already removed"
    fi

    # Remove Edge managed policy
    if [[ -f "$EDGE_POLICY_PATH" ]]; then
        rm -f "$EDGE_POLICY_PATH"
        print_success "Edge managed policy removed"
    else
        print_warning "Edge managed policy not found or already removed"
    fi

    # Force browsers to reload policies by clearing preferences cache
    print_info "Clearing browser policy cache..."

    # Clear Chrome policy cache
    if command -v defaults >/dev/null 2>&1; then
        defaults delete com.google.Chrome 2>/dev/null || true
        print_info "Chrome preferences cache cleared"
    fi

    # Clear Edge policy cache
    if command -v defaults >/dev/null 2>&1; then
        defaults delete com.microsoft.Edge 2>/dev/null || true
        print_info "Edge preferences cache cleared"
    fi

    # Kill browser processes to force policy reload
    print_info "Forcing browser restart to reload policies..."

    # Kill Chrome processes
    pkill -f "Google Chrome" 2>/dev/null || true
    pkill -f "Chromium" 2>/dev/null || true

    # Kill Edge processes
    pkill -f "Microsoft Edge" 2>/dev/null || true

    print_success "Browser processes terminated - policies will reload on next launch"

    # Clear system policy cache
    print_info "Clearing system policy cache..."
    if command -v mcxrefresh >/dev/null 2>&1; then
        mcxrefresh -n "$USER" 2>/dev/null || true
        print_info "System policy cache refreshed"
    fi

    print_warning "Important: Restart Chrome and Edge to ensure all policies are cleared"
}

# Function to completely clean all extension policies and cache
clean_all() {
    print_info "Performing complete cleanup of Check extension policies..."

    # Run normal uninstall first
    uninstall_profile

    echo
    print_info "Performing deep cleanup..."

    # Remove any remaining profile files from desktop
    local desktop_dir="$HOME/Desktop"
    if [[ -n "$SUDO_USER" ]]; then
        desktop_dir=$(eval echo "~$SUDO_USER/Desktop")
    fi

    if [[ -f "$desktop_dir/Check-Chrome-Extension.mobileconfig" ]]; then
        rm -f "$desktop_dir/Check-Chrome-Extension.mobileconfig"
        print_info "Removed Chrome profile from Desktop"
    fi

    if [[ -f "$desktop_dir/Check-Edge-Extension.mobileconfig" ]]; then
        rm -f "$desktop_dir/Check-Edge-Extension.mobileconfig"
        print_info "Removed Edge profile from Desktop"
    fi

    # Clear all browser data related to extension policies
    print_info "Clearing all browser extension data..."

    # Clear Chrome extension cache
    local chrome_cache_dirs=(
        "/Library/Application Support/Google/Chrome/Default/Local Extension Settings"
        "/Library/Application Support/Google/Chrome/Default/Extensions"
        "/Library/Caches/com.google.Chrome"
    )

    for dir in "${chrome_cache_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -name "*benimdeioplgkhanklclahllklceahbe*" -exec rm -rf {} + 2>/dev/null || true
        fi
    done

    # Clear Edge extension cache
    local edge_cache_dirs=(
        "/Library/Application Support/Microsoft Edge/Default/Local Extension Settings"
        "/Library/Application Support/Microsoft Edge/Default/Extensions"
        "/Library/Caches/com.microsoft.Edge"
    )

    for dir in "${edge_cache_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            find "$dir" -name "*knepjpocdagponkonnbggpcnhnaikajg*" -exec rm -rf {} + 2>/dev/null || true
        fi
    done

    print_success "Deep cleanup completed"
    print_warning "IMPORTANT: You must restart Chrome and Edge browsers completely"
    print_info "After restart, verify cleanup at:"
    echo "  - chrome://policy/ (should show no Check extension policies)"
    echo "  - edge://policy/ (should show no Check extension policies)"
    echo "  - chrome://extensions/ (extension should be gone)"
    echo "  - edge://extensions/ (extension should be gone)"
}

# Function to show status
show_status() {
    print_info "Check extension configuration status:"
    echo

    # Check Chrome configuration profile
    if profiles -P | grep -q "$CHROME_PROFILE_IDENTIFIER"; then
        print_success "Chrome configuration profile is installed"
        echo "Profile identifier: $CHROME_PROFILE_IDENTIFIER"
    else
        print_warning "Chrome configuration profile is not installed"
    fi

    echo

    # Check Edge configuration profile
    if profiles -P | grep -q "$EDGE_PROFILE_IDENTIFIER"; then
        print_success "Edge configuration profile is installed"
        echo "Profile identifier: $EDGE_PROFILE_IDENTIFIER"
    else
        print_warning "Edge configuration profile is not installed"
    fi

    echo

    # Check Chrome managed policy
    if [[ -f "$CHROME_POLICY_PATH" ]]; then
        print_success "Chrome managed policy is installed"
        echo "Policy file: $CHROME_POLICY_PATH"

        if command -v plutil >/dev/null 2>&1; then
            echo
            print_info "Current Chrome policy settings:"
            plutil -p "$CHROME_POLICY_PATH" 2>/dev/null || print_warning "Could not read Chrome policy file"
        fi
    else
        print_warning "Chrome managed policy is not installed"
    fi

    echo

    # Check Edge managed policy
    if [[ -f "$EDGE_POLICY_PATH" ]]; then
        print_success "Edge managed policy is installed"
        echo "Policy file: $EDGE_POLICY_PATH"

        if command -v plutil >/dev/null 2>&1; then
            echo
            print_info "Current Edge policy settings:"
            plutil -p "$EDGE_POLICY_PATH" 2>/dev/null || print_warning "Could not read Edge policy file"
        fi
    else
        print_warning "Edge managed policy is not installed"
    fi

    echo
    print_info "Active configuration profiles:"
    profiles -P 2>/dev/null | grep -E "(com\.cyberdrain|Check|check)" || print_warning "No Check-related profiles found"

    echo
    print_info "Browser policy cache status:"

    # Check Chrome defaults
    if defaults read com.google.Chrome >/dev/null 2>&1; then
        local chrome_policies
        chrome_policies=$(defaults read com.google.Chrome 2>/dev/null | grep -E "(ExtensionSettings|3rdparty)" || echo "")
        if [[ -n "$chrome_policies" ]]; then
            print_success "Chrome has cached policies"
        else
            print_warning "Chrome has no cached extension policies"
        fi
    else
        print_warning "Chrome preferences not found or not accessible"
    fi

    # Check Edge defaults
    if defaults read com.microsoft.Edge >/dev/null 2>&1; then
        local edge_policies
        edge_policies=$(defaults read com.microsoft.Edge 2>/dev/null | grep -E "(ExtensionSettings|3rdparty)" || echo "")
        if [[ -n "$edge_policies" ]]; then
            print_success "Edge has cached policies"
        else
            print_warning "Edge has no cached extension policies"
        fi
    else
        print_warning "Edge preferences not found or not accessible"
    fi

    echo
    print_info "To clear cached policies completely:"
    echo "  1. Run: sudo ./deploy-macos.sh uninstall"
    echo "  2. Restart Chrome and Edge browsers"
    echo "  3. Check chrome://policy/ and edge://policy/ pages"
}

# Function to show help
show_help() {
    print_status
    echo
    echo "Usage: sudo $0 [command]"
    echo
    echo "Commands:"
    echo "  install     Install the Check extension configuration profile and Chrome policy"
    echo "  uninstall   Remove the Check extension configuration profile and Chrome policy"
    echo "  clean       Completely remove all extension policies, cache, and data"
    echo "  status      Show current installation status"
    echo "  help        Show this help message"
    echo
    echo "Files managed by this script:"
    echo "  - Chrome Configuration Profile: $CHROME_PROFILE_FILE"
    echo "  - Edge Configuration Profile: $EDGE_PROFILE_FILE"
    echo "  - Chrome Policy: $CHROME_POLICY_PATH"
    echo "  - Edge Policy: $EDGE_POLICY_PATH"
    echo
    echo "Notes:"
    echo "  - This script must be run with sudo (administrator privileges)"
    echo "  - The configuration will apply to all users on this Mac"
    echo "  - Users may need to restart Chrome and Edge for policies to take effect"
    echo "  - Extension IDs are built-in: Chrome (benimdeioplgkhanklclahllklceahbe), Edge (knepjpocdagponkonnbggpcnhnaikajg)"
}

# Main execution
main() {
    print_status

    case "${1:-help}" in
        install)
            check_root
            check_system_requirements
            validate_files
            echo
            install_profile
            echo
            if [[ "${MACOS_MANUAL_INSTALL:-false}" == "true" ]]; then
                print_success "Setup complete!"
                print_info "Manual steps required:"
                echo "  1. Install configuration profiles from Desktop"
                echo "  2. Restart Chrome and Edge browsers"
                echo "  3. Verify extensions appear in browser extension lists"
            else
                print_success "Installation complete!"
                print_info "Users may need to restart Chrome and Edge for changes to take effect"
            fi
            ;;
        uninstall)
            check_root
            echo
            uninstall_profile
            echo
            print_success "Uninstallation complete!"
            ;;
        clean)
            check_root
            echo
            clean_all
            echo
            print_success "Complete cleanup finished!"
            ;;
        status)
            echo
            show_status
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            print_error "Unknown command: $1"
            echo
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
