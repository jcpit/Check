#!/bin/bash

# Check Extension - macOS Configuration Profile Deployment Script
# This script installs or removes the Check extension configuration profile

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_FILE="$SCRIPT_DIR/check-extension-config.mobileconfig"
CHROME_POLICY_FILE="$SCRIPT_DIR/chrome-managed-policy.json"
PROFILE_IDENTIFIER="com.cyberdrain.check.configuration"
CHROME_POLICY_DIR="/Library/Managed Preferences"
CHROME_POLICY_PATH="$CHROME_POLICY_DIR/com.google.Chrome.plist"

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

# Function to validate files exist
validate_files() {
    if [[ ! -f "$PROFILE_FILE" ]]; then
        print_error "Configuration profile not found: $PROFILE_FILE"
        exit 1
    fi

    if [[ ! -f "$CHROME_POLICY_FILE" ]]; then
        print_error "Chrome policy file not found: $CHROME_POLICY_FILE"
        exit 1
    fi
}

# Function to install configuration profile
install_profile() {
    print_info "Installing Check extension configuration profile..."

    # Install the configuration profile
    if profiles -I -F "$PROFILE_FILE" >/dev/null 2>&1; then
        print_success "Configuration profile installed successfully"
    else
        print_error "Failed to install configuration profile"
        return 1
    fi

    # Install Chrome managed policy
    print_info "Installing Chrome managed policy..."

    # Create managed preferences directory if it doesn't exist
    mkdir -p "$CHROME_POLICY_DIR"

    # Convert JSON to plist and install
    if plutil -convert binary1 "$CHROME_POLICY_FILE" -o "$CHROME_POLICY_PATH"; then
        print_success "Chrome managed policy installed: $CHROME_POLICY_PATH"

        # Set proper permissions
        chown root:wheel "$CHROME_POLICY_PATH"
        chmod 644 "$CHROME_POLICY_PATH"
        print_success "Policy file permissions set correctly"
    else
        print_error "Failed to install Chrome managed policy"
        return 1
    fi
}

# Function to uninstall configuration profile
uninstall_profile() {
    print_info "Removing Check extension configuration..."

    # Remove configuration profile
    if profiles -R -p "$PROFILE_IDENTIFIER" >/dev/null 2>&1; then
        print_success "Configuration profile removed successfully"
    else
        print_warning "Configuration profile not found or already removed"
    fi

    # Remove Chrome managed policy
    if [[ -f "$CHROME_POLICY_PATH" ]]; then
        rm -f "$CHROME_POLICY_PATH"
        print_success "Chrome managed policy removed"
    else
        print_warning "Chrome managed policy not found or already removed"
    fi
}

# Function to show status
show_status() {
    print_info "Check extension configuration status:"
    echo

    # Check configuration profile
    if profiles -P | grep -q "$PROFILE_IDENTIFIER"; then
        print_success "Configuration profile is installed"
        echo "Profile identifier: $PROFILE_IDENTIFIER"
    else
        print_warning "Configuration profile is not installed"
    fi

    echo

    # Check Chrome managed policy
    if [[ -f "$CHROME_POLICY_PATH" ]]; then
        print_success "Chrome managed policy is installed"
        echo "Policy file: $CHROME_POLICY_PATH"

        # Show policy contents if plutil is available
        if command -v plutil >/dev/null 2>&1; then
            echo
            print_info "Current policy settings:"
            plutil -p "$CHROME_POLICY_PATH" 2>/dev/null || print_warning "Could not read policy file"
        fi
    else
        print_warning "Chrome managed policy is not installed"
    fi

    echo
    print_info "Active configuration profiles:"
    profiles -P 2>/dev/null | grep -E "(com\.cyberdrain|Check|check)" || print_warning "No Check-related profiles found"
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
    echo "  status      Show current installation status"
    echo "  help        Show this help message"
    echo
    echo "Files managed by this script:"
    echo "  - Configuration Profile: $PROFILE_FILE"
    echo "  - Chrome Policy: $CHROME_POLICY_PATH"
    echo
    echo "Notes:"
    echo "  - This script must be run with sudo (administrator privileges)"
    echo "  - The configuration will apply to all users on this Mac"
    echo "  - Users may need to restart Chrome for policies to take effect"
    echo "  - Replace EXTENSION_ID_HERE in chrome-managed-policy.json with actual extension ID"
}

# Main execution
main() {
    print_status

    case "${1:-help}" in
        install)
            check_root
            validate_files
            echo
            install_profile
            echo
            print_success "Installation complete!"
            print_info "Users may need to restart Chrome for changes to take effect"
            ;;
        uninstall)
            check_root
            echo
            uninstall_profile
            echo
            print_success "Uninstallation complete!"
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
