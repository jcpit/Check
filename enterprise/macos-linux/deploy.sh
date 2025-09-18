#!/bin/bash

# Check Extension - Universal Unix Deployment Script
# This script detects the operating system and runs the appropriate deployment script

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${CYAN}Check Extension - Universal Unix Deployment${NC}"
    echo -e "${CYAN}===========================================${NC}"
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

# Function to detect operating system
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "freebsd"* ]]; then
        echo "linux"  # FreeBSD can use Linux deployment method
    else
        echo "unknown"
    fi
}

# Function to show help
show_help() {
    print_status
    echo
    echo "Usage: $0 [command]"
    echo
    echo "Commands:"
    echo "  install     Install the Check extension configuration"
    echo "  uninstall   Remove the Check extension configuration"
    echo "  status      Show current installation status"
    echo "  detect      Show OS detection and available deployment methods"
    echo "  help        Show this help message"
    echo
    echo "This script automatically detects your operating system and uses the appropriate deployment method:"
    echo "  - macOS: Configuration Profiles (.mobileconfig) and Managed Preferences"
    echo "  - Linux: Browser policy files in system directories"
    echo
    echo "Supported Platforms:"
    echo "  - macOS 10.13+"
    echo "  - Ubuntu/Debian Linux"
    echo "  - RHEL/CentOS/Fedora"
    echo "  - SUSE Linux"
    echo "  - Arch Linux"
    echo "  - FreeBSD (using Linux method)"
    echo
    echo "Supported Browsers:"
    echo "  - Google Chrome"
    echo "  - Chromium"
    echo "  - Microsoft Edge"
}

# Function to show detection information
show_detection() {
    local os_type=$(detect_os)

    print_info "Operating System Detection:"
    echo "  OS Type: $OSTYPE"
    echo "  Detected: $os_type"
    echo

    case "$os_type" in
        "macos")
            print_success "macOS detected - will use Configuration Profiles and Managed Preferences"
            echo "  Deployment script: deploy-macos.sh"
            echo "  Method: Configuration Profiles (.mobileconfig) + Managed Preferences"
            echo "  Requires: sudo privileges"
            ;;
        "linux")
            print_success "Linux/FreeBSD detected - will use browser policy files"
            echo "  Deployment script: deploy-linux.sh"
            echo "  Method: Browser policy JSON files in system directories"
            echo "  Requires: sudo privileges"
            ;;
        "unknown")
            print_error "Unsupported operating system: $OSTYPE"
            echo "  Supported: macOS, Linux, FreeBSD"
            echo "  Manual deployment may be required"
            return 1
            ;;
    esac
}

# Main execution
main() {
    print_status
    echo

    local os_type=$(detect_os)
    local command="${1:-help}"

    case "$command" in
        "detect")
            show_detection
            exit 0
            ;;
        "help"|"--help"|"-h")
            show_help
            exit 0
            ;;
    esac

    # Validate OS and run appropriate script
    case "$os_type" in
        "macos")
            local macos_script="$SCRIPT_DIR/deploy-macos.sh"
            if [[ ! -f "$macos_script" ]]; then
                print_error "macOS deployment script not found: $macos_script"
                exit 1
            fi

            print_info "Detected macOS - using Configuration Profiles deployment"
            echo
            exec "$macos_script" "$@"
            ;;
        "linux")
            local linux_script="$SCRIPT_DIR/deploy-linux.sh"
            if [[ ! -f "$linux_script" ]]; then
                print_error "Linux deployment script not found: $linux_script"
                exit 1
            fi

            print_info "Detected Linux/FreeBSD - using browser policy deployment"
            echo
            exec "$linux_script" "$@"
            ;;
        "unknown")
            print_error "Unsupported operating system: $OSTYPE"
            echo
            echo "Manual deployment options:"
            echo "  1. For macOS-like systems: use deploy-macos.sh"
            echo "  2. For Linux-like systems: use deploy-linux.sh"
            echo "  3. Copy policy files manually to browser directories"
            echo
            show_help
            exit 1
            ;;
    esac
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
