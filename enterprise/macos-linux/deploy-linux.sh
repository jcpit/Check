#!/bin/bash

# Check Extension - Linux Configuration Deployment Script
# This script installs or removes the Check extension configuration for Linux distributions

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHROME_POLICY_FILE="$SCRIPT_DIR/chrome-managed-policy.json"
EDGE_POLICY_FILE="$SCRIPT_DIR/edge-managed-policy.json"

# Linux policy directories (system-wide)
CHROME_POLICY_DIR="/etc/opt/chrome/policies/managed"
EDGE_POLICY_DIR="/etc/opt/edge/policies/managed"

# Alternative policy directories for different distributions
CHROME_ALT_DIRS=(
    "/etc/chromium/policies/managed"
    "/etc/chromium-browser/policies/managed"
)

EDGE_ALT_DIRS=(
    "/etc/microsoft-edge/policies/managed"
    "/etc/opt/microsoft/edge/policies/managed"
)

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${CYAN}Check Extension - Linux Configuration Deployment${NC}"
    echo -e "${CYAN}===============================================${NC}"
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
        echo "Usage: sudo $0 [install|uninstall|status|detect]"
        exit 1
    fi
}

# Function to validate files exist
validate_files() {
    local files_missing=false

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

# Function to detect available browsers and their policy directories
detect_browsers() {
    print_info "Detecting available browsers and policy directories..."
    echo

    # Check for Chrome/Chromium
    local chrome_found=false
    if command -v google-chrome >/dev/null 2>&1; then
        print_success "Google Chrome detected"
        chrome_found=true
    elif command -v chromium >/dev/null 2>&1; then
        print_success "Chromium detected"
        chrome_found=true
    elif command -v chromium-browser >/dev/null 2>&1; then
        print_success "Chromium Browser detected"
        chrome_found=true
    else
        print_warning "No Chrome/Chromium installation detected"
    fi

    # Check for Edge
    local edge_found=false
    if command -v microsoft-edge >/dev/null 2>&1; then
        print_success "Microsoft Edge detected"
        edge_found=true
    elif command -v microsoft-edge-stable >/dev/null 2>&1; then
        print_success "Microsoft Edge Stable detected"
        edge_found=true
    else
        print_warning "No Microsoft Edge installation detected"
    fi

    echo

    # Check policy directories
    print_info "Available policy directories:"

    if [[ "$chrome_found" == "true" ]]; then
        echo "Chrome/Chromium:"
        echo "  Primary: $CHROME_POLICY_DIR"
        for dir in "${CHROME_ALT_DIRS[@]}"; do
            echo "  Alternative: $dir"
        done
    fi

    if [[ "$edge_found" == "true" ]]; then
        echo "Microsoft Edge:"
        echo "  Primary: $EDGE_POLICY_DIR"
        for dir in "${EDGE_ALT_DIRS[@]}"; do
            echo "  Alternative: $dir"
        done
    fi

    echo
}

# Function to install policies
install_policies() {
    print_info "Installing Check extension policies for Linux..."
    echo

    # Install Chrome policy
    if command -v google-chrome >/dev/null 2>&1 || command -v chromium >/dev/null 2>&1 || command -v chromium-browser >/dev/null 2>&1; then
        print_info "Installing Chrome/Chromium policy..."

        # Create primary directory
        mkdir -p "$CHROME_POLICY_DIR"
        cp "$CHROME_POLICY_FILE" "$CHROME_POLICY_DIR/check-extension.json"
        chmod 644 "$CHROME_POLICY_DIR/check-extension.json"
        print_success "Chrome policy installed: $CHROME_POLICY_DIR/check-extension.json"

        # Install to alternative directories if they exist
        for dir in "${CHROME_ALT_DIRS[@]}"; do
            if [[ -d "$(dirname "$dir")" ]]; then
                mkdir -p "$dir"
                cp "$CHROME_POLICY_FILE" "$dir/check-extension.json"
                chmod 644 "$dir/check-extension.json"
                print_success "Chrome policy also installed: $dir/check-extension.json"
            fi
        done
    else
        print_warning "Chrome/Chromium not detected, skipping Chrome policy installation"
    fi

    echo

    # Install Edge policy
    if command -v microsoft-edge >/dev/null 2>&1 || command -v microsoft-edge-stable >/dev/null 2>&1; then
        print_info "Installing Microsoft Edge policy..."

        # Create primary directory
        mkdir -p "$EDGE_POLICY_DIR"
        cp "$EDGE_POLICY_FILE" "$EDGE_POLICY_DIR/check-extension.json"
        chmod 644 "$EDGE_POLICY_DIR/check-extension.json"
        print_success "Edge policy installed: $EDGE_POLICY_DIR/check-extension.json"

        # Install to alternative directories if they exist
        for dir in "${EDGE_ALT_DIRS[@]}"; do
            if [[ -d "$(dirname "$dir")" ]]; then
                mkdir -p "$dir"
                cp "$EDGE_POLICY_FILE" "$dir/check-extension.json"
                chmod 644 "$dir/check-extension.json"
                print_success "Edge policy also installed: $dir/check-extension.json"
            fi
        done
    else
        print_warning "Microsoft Edge not detected, skipping Edge policy installation"
    fi
}

# Function to uninstall policies
uninstall_policies() {
    print_info "Removing Check extension policies..."
    echo

    # Remove Chrome policies
    local chrome_files=(
        "$CHROME_POLICY_DIR/check-extension.json"
    )

    for dir in "${CHROME_ALT_DIRS[@]}"; do
        chrome_files+=("$dir/check-extension.json")
    done

    for file in "${chrome_files[@]}"; do
        if [[ -f "$file" ]]; then
            rm -f "$file"
            print_success "Removed Chrome policy: $file"
        fi
    done

    # Remove Edge policies
    local edge_files=(
        "$EDGE_POLICY_DIR/check-extension.json"
    )

    for dir in "${EDGE_ALT_DIRS[@]}"; do
        edge_files+=("$dir/check-extension.json")
    done

    for file in "${edge_files[@]}"; do
        if [[ -f "$file" ]]; then
            rm -f "$file"
            print_success "Removed Edge policy: $file"
        fi
    done
}

# Function to show status
show_status() {
    print_info "Check extension policy status:"
    echo

    # Check Chrome policies
    print_info "Chrome/Chromium policies:"
    local chrome_files=(
        "$CHROME_POLICY_DIR/check-extension.json"
    )

    for dir in "${CHROME_ALT_DIRS[@]}"; do
        chrome_files+=("$dir/check-extension.json")
    done

    local chrome_installed=false
    for file in "${chrome_files[@]}"; do
        if [[ -f "$file" ]]; then
            print_success "Installed: $file"
            chrome_installed=true
        fi
    done

    if [[ "$chrome_installed" == "false" ]]; then
        print_warning "No Chrome policies installed"
    fi

    echo

    # Check Edge policies
    print_info "Microsoft Edge policies:"
    local edge_files=(
        "$EDGE_POLICY_DIR/check-extension.json"
    )

    for dir in "${EDGE_ALT_DIRS[@]}"; do
        edge_files+=("$dir/check-extension.json")
    done

    local edge_installed=false
    for file in "${edge_files[@]}"; do
        if [[ -f "$file" ]]; then
            print_success "Installed: $file"
            edge_installed=true
        fi
    done

    if [[ "$edge_installed" == "false" ]]; then
        print_warning "No Edge policies installed"
    fi
}

# Function to show help
show_help() {
    print_status
    echo
    echo "Usage: sudo $0 [command]"
    echo
    echo "Commands:"
    echo "  install     Install the Check extension policies for detected browsers"
    echo "  uninstall   Remove the Check extension policies"
    echo "  status      Show current installation status"
    echo "  detect      Detect available browsers and policy directories"
    echo "  help        Show this help message"
    echo
    echo "Supported Browsers:"
    echo "  - Google Chrome"
    echo "  - Chromium"
    echo "  - Microsoft Edge"
    echo
    echo "Policy Directories:"
    echo "  Chrome: $CHROME_POLICY_DIR"
    echo "  Edge: $EDGE_POLICY_DIR"
    echo "  (Alternative directories will be used if available)"
    echo
    echo "Notes:"
    echo "  - This script must be run with sudo (administrator privileges)"
    echo "  - Policies apply system-wide to all users"
    echo "  - Users may need to restart browsers for policies to take effect"
    echo "  - Extension IDs are built-in and do not need configuration"
}

# Main execution
main() {
    print_status

    case "${1:-help}" in
        install)
            check_root
            validate_files
            echo
            install_policies
            echo
            print_success "Installation complete!"
            print_info "Users may need to restart browsers for changes to take effect"
            ;;
        uninstall)
            check_root
            echo
            uninstall_policies
            echo
            print_success "Uninstallation complete!"
            ;;
        status)
            echo
            show_status
            ;;
        detect)
            echo
            detect_browsers
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
