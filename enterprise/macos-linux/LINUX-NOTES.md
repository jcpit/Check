# Linux-Specific Deployment Notes

This document provides additional details for deploying the Check extension on Linux distributions.

## Browser Policy Directories

### Google Chrome
**Primary Directory:** `/etc/opt/chrome/policies/managed`
- Standard location for Google Chrome on most distributions
- Used by official Google Chrome packages

**Alternative Directories:**
- `/etc/chromium/policies/managed` - Chromium browser (open-source)
- `/etc/chromium-browser/policies/managed` - Ubuntu/Debian Chromium package

### Microsoft Edge
**Primary Directory:** `/etc/opt/edge/policies/managed`
- Standard location for Microsoft Edge on Linux

**Alternative Directories:**
- `/etc/microsoft-edge/policies/managed` - Some distributions
- `/etc/opt/microsoft/edge/policies/managed` - Alternative path

## Distribution-Specific Installation

### Ubuntu/Debian
```bash
# Install browsers if needed
sudo apt update
sudo apt install google-chrome-stable microsoft-edge-stable

# Deploy policies
sudo ./deploy-linux.sh install
```

### RHEL/CentOS/Fedora
```bash
# Install browsers if needed (RHEL 8+/CentOS 8+/Fedora)
sudo dnf install google-chrome-stable microsoft-edge-stable

# Deploy policies
sudo ./deploy-linux.sh install
```

### SUSE/openSUSE
```bash
# Install browsers if needed
sudo zypper install google-chrome-stable microsoft-edge-stable

# Deploy policies
sudo ./deploy-linux.sh install
```

### Arch Linux
```bash
# Install browsers from AUR if needed
yay -S google-chrome microsoft-edge-stable-bin

# Deploy policies
sudo ./deploy-linux.sh install
```

## Manual Policy Installation

### Create Policy Files Manually
```bash
# Create Chrome policy directory
sudo mkdir -p /etc/opt/chrome/policies/managed

# Copy and configure Chrome policy
sudo cp chrome-managed-policy.json /etc/opt/chrome/policies/managed/check-extension.json
sudo chmod 644 /etc/opt/chrome/policies/managed/check-extension.json
sudo chown root:root /etc/opt/chrome/policies/managed/check-extension.json

# Create Edge policy directory
sudo mkdir -p /etc/opt/edge/policies/managed

# Copy and configure Edge policy
sudo cp edge-managed-policy.json /etc/opt/edge/policies/managed/check-extension.json
sudo chmod 644 /etc/opt/edge/policies/managed/check-extension.json
sudo chown root:root /etc/opt/edge/policies/managed/check-extension.json
```

## Verification Commands

### Check Browser Installation
```bash
# Check Chrome/Chromium
which google-chrome google-chrome-stable chromium chromium-browser

# Check Edge
which microsoft-edge microsoft-edge-stable

# Check browser versions
google-chrome --version
microsoft-edge --version
```

### Verify Policy Files
```bash
# List Chrome policy files
ls -la /etc/opt/chrome/policies/managed/
ls -la /etc/chromium/policies/managed/

# List Edge policy files
ls -la /etc/opt/edge/policies/managed/
ls -la /etc/microsoft-edge/policies/managed/

# Check file contents
cat /etc/opt/chrome/policies/managed/check-extension.json
cat /etc/opt/edge/policies/managed/check-extension.json
```

### Test Policy Application
```bash
# Check if browsers recognize policies (run as regular user)
google-chrome --show-managed-ui
microsoft-edge --show-managed-ui

# Check chrome://policy and edge://policy pages in browsers
```

## Troubleshooting

### Policies Not Applied
1. **Check file permissions**: Files must be readable by browsers
   ```bash
   sudo chmod 644 /etc/opt/chrome/policies/managed/*.json
   sudo chmod 644 /etc/opt/edge/policies/managed/*.json
   ```

2. **Verify JSON syntax**: Use `jq` to validate
   ```bash
   sudo apt install jq  # or equivalent for your distribution
   jq . /etc/opt/chrome/policies/managed/check-extension.json
   jq . /etc/opt/edge/policies/managed/check-extension.json
   ```

3. **Check SELinux (RHEL/CentOS)**: Ensure proper context
   ```bash
   sudo restorecon -R /etc/opt/chrome/policies/
   sudo restorecon -R /etc/opt/edge/policies/
   ```

### Browser Not Finding Policies
1. **Try alternative directories**: Some distributions use different paths
2. **Check browser package**: Ensure official packages, not snap/flatpak
3. **Restart browser**: Policies are loaded at startup

### Extension Not Installing
1. **Check extension ID**: Verify correct IDs in policy files
2. **Check internet connectivity**: Extensions download from web stores
3. **Review browser logs**: Check browser console for errors

## Configuration Management Integration

### Ansible Playbook Example
```yaml
---
- name: Deploy Check Extension Policies
  hosts: linux_workstations
  become: yes
  tasks:
    - name: Create Chrome policy directory
      file:
        path: /etc/opt/chrome/policies/managed
        state: directory
        mode: '0755'

    - name: Deploy Chrome policy
      copy:
        src: chrome-managed-policy.json
        dest: /etc/opt/chrome/policies/managed/check-extension.json
        mode: '0644'

    - name: Create Edge policy directory
      file:
        path: /etc/opt/edge/policies/managed
        state: directory
        mode: '0755'

    - name: Deploy Edge policy
      copy:
        src: edge-managed-policy.json
        dest: /etc/opt/edge/policies/managed/check-extension.json
        mode: '0644'
```

### Puppet Manifest Example
```puppet
file { '/etc/opt/chrome/policies/managed':
  ensure => directory,
  mode   => '0755',
}

file { '/etc/opt/chrome/policies/managed/check-extension.json':
  source => 'puppet:///modules/check_extension/chrome-managed-policy.json',
  mode   => '0644',
  require => File['/etc/opt/chrome/policies/managed'],
}

file { '/etc/opt/edge/policies/managed':
  ensure => directory,
  mode   => '0755',
}

file { '/etc/opt/edge/policies/managed/check-extension.json':
  source => 'puppet:///modules/check_extension/edge-managed-policy.json',
  mode   => '0644',
  require => File['/etc/opt/edge/policies/managed'],
}
```

## Security Notes

- Policy files are read-only for browsers (no sensitive data exposure)
- System-wide policies apply to all users on the system
- Regular users cannot override system policies
- Policies are loaded at browser startup
- Extension permissions are managed centrally

## Browser-Specific Notes

### Chrome/Chromium Differences
- Google Chrome uses `/etc/opt/chrome/`
- Chromium (open source) typically uses `/etc/chromium/`
- Some distributions package Chromium as `chromium-browser`

### Edge on Linux
- Microsoft Edge for Linux is relatively new
- Policy support matches Windows version
- Some enterprise features may be limited compared to Windows

### Snap/Flatpak Browsers
- Snap and Flatpak packages may not respect system policies
- Install traditional packages for full policy support
- Check with your distribution's package manager
