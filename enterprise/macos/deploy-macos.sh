#!/bin/bash

# Check Extension - macOS Configuration Profile Deployment Script
# This script installs or removes the Check extension configuration profile

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

# Function to validate files exist
validate_files() {
    local files_missing=false

    if [[ ! -f "$CHROME_PROFILE_FILE" ]]; then
        print_error "Chrome configuration profile not found: $CHROME_PROFILE_FILE"
        files_missing=true
    fi

    if [[ ! -f "$EDGE_PROFILE_FILE" ]]; then
        print_error "Edge configuration profile not found: $EDGE_PROFILE_FILE"
        files_missing=true
    fi

    if [[ ! -f "$CHROME_POLICY_FILE" ]]; then
        print_error "Chrome policy file not found: $CHROME_POLICY_FILE"
        files_missing=true
    fi

    if [[ ! -f "$EDGE_POLICY_FILE" ]]; then
        print_error "Edge policy file not found: $EDGE_POLICY_FILE"
        files_missing=true
    fi

    if [[ "$files_missing" == "true" ]]; then
        exit 1
    fi
}

# Function to install configuration profile
install_profile() {
    print_info "Installing Check extension configuration profiles..."

    # Install Chrome configuration profile
    print_info "Installing Chrome configuration profile..."
    if profiles -I -F "$CHROME_PROFILE_FILE" >/dev/null 2>&1; then
        print_success "Chrome configuration profile installed successfully"
    else
        print_error "Failed to install Chrome configuration profile"
        return 1
    fi

    # Install Edge configuration profile
    print_info "Installing Edge configuration profile..."
    if profiles -I -F "$EDGE_PROFILE_FILE" >/dev/null 2>&1; then
        print_success "Edge configuration profile installed successfully"
    else
        print_error "Failed to install Edge configuration profile"
        return 1
    fi

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
            validate_files
            echo
            install_profile
            echo
            print_success "Installation complete!"
            print_info "Users may need to restart Chrome and Edge for changes to take effect"
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
