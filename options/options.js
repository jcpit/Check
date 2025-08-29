/**
 * CyberShield Drain - Options Page JavaScript
 * Comprehensive settings management and configuration interface
 */

class CyberShieldOptions {
  constructor() {
    this.config = null;
    this.brandingConfig = null;
    this.originalConfig = null;
    this.hasUnsavedChanges = false;
    this.currentSection = 'general';
    
    this.elements = {};
    this.bindElements();
    this.setupEventListeners();
    this.initialize();
  }

  bindElements() {
    // Navigation
    this.elements.menuItems = document.querySelectorAll('.menu-item');
    this.elements.sections = document.querySelectorAll('.settings-section');
    this.elements.pageTitle = document.getElementById('pageTitle');

    // Header actions
    this.elements.saveSettings = document.getElementById('saveSettings');
    this.elements.exportConfig = document.getElementById('exportConfig');
    this.elements.importConfig = document.getElementById('importConfig');

    // General settings
    this.elements.extensionEnabled = document.getElementById('extensionEnabled');
    this.elements.enableContentManipulation = document.getElementById('enableContentManipulation');
    this.elements.enableUrlMonitoring = document.getElementById('enableUrlMonitoring');
    this.elements.showNotifications = document.getElementById('showNotifications');
    this.elements.notificationDuration = document.getElementById('notificationDuration');
    this.elements.notificationDurationValue = document.getElementById('notificationDurationValue');

    // Security settings
    this.elements.blockMaliciousUrls = document.getElementById('blockMaliciousUrls');
    this.elements.blockPhishingAttempts = document.getElementById('blockPhishingAttempts');
    this.elements.whitelistedDomains = document.getElementById('whitelistedDomains');
    this.elements.blacklistedDomains = document.getElementById('blacklistedDomains');

    // Detection settings
    this.elements.enableCustomRules = document.getElementById('enableCustomRules');
    this.elements.customRulesUrl = document.getElementById('customRulesUrl');
    this.elements.updateInterval = document.getElementById('updateInterval');
    this.elements.customRulesEditor = document.getElementById('customRulesEditor');
    this.elements.validateRules = document.getElementById('validateRules');
    this.elements.loadDefaultRules = document.getElementById('loadDefaultRules');

    // Privacy settings
    this.elements.enableLogging = document.getElementById('enableLogging');
    this.elements.logLevel = document.getElementById('logLevel');
    this.elements.maxLogEntries = document.getElementById('maxLogEntries');
    this.elements.respectDoNotTrack = document.getElementById('respectDoNotTrack');
    this.elements.enableIncognitoMode = document.getElementById('enableIncognitoMode');

    // Enterprise settings
    this.elements.enterpriseStatus = document.getElementById('enterpriseStatus');
    this.elements.managementStatus = document.getElementById('managementStatus');
    this.elements.policyList = document.getElementById('policyList');
    this.elements.enableComplianceMode = document.getElementById('enableComplianceMode');
    this.elements.reportingEndpoint = document.getElementById('reportingEndpoint');

    // Logs
    this.elements.logFilter = document.getElementById('logFilter');
    this.elements.clearLogs = document.getElementById('clearLogs');
    this.elements.exportLogs = document.getElementById('exportLogs');
    this.elements.logsList = document.getElementById('logsList');

    // Branding
    this.elements.companyName = document.getElementById('companyName');
    this.elements.productName = document.getElementById('productName');
    this.elements.supportEmail = document.getElementById('supportEmail');
    this.elements.primaryColor = document.getElementById('primaryColor');
    this.elements.logoUrl = document.getElementById('logoUrl');
    this.elements.customCss = document.getElementById('customCss');
    this.elements.brandingPreview = document.getElementById('brandingPreview');
    this.elements.previewLogo = document.getElementById('previewLogo');
    this.elements.previewTitle = document.getElementById('previewTitle');
    this.elements.previewButton = document.getElementById('previewButton');

    // About
    this.elements.aboutVersion = document.getElementById('aboutVersion');
    this.elements.buildDate = document.getElementById('buildDate');
    this.elements.browserInfo = document.getElementById('browserInfo');
    this.elements.osInfo = document.getElementById('osInfo');
    this.elements.supportUrl = document.getElementById('supportUrl');
    this.elements.privacyUrl = document.getElementById('privacyUrl');
    this.elements.termsUrl = document.getElementById('termsUrl');

    // Modal
    this.elements.modalOverlay = document.getElementById('modalOverlay');
    this.elements.modalTitle = document.getElementById('modalTitle');
    this.elements.modalMessage = document.getElementById('modalMessage');
    this.elements.modalCancel = document.getElementById('modalCancel');
    this.elements.modalConfirm = document.getElementById('modalConfirm');

    // Toast container
    this.elements.toastContainer = document.getElementById('toastContainer');
  }

  setupEventListeners() {
    // Navigation
    this.elements.menuItems.forEach(item => {
      item.addEventListener('click', (e) => {
        e.preventDefault();
        const section = item.dataset.section;
        this.switchSection(section);
      });
    });

    // Header actions
    this.elements.saveSettings.addEventListener('click', () => this.saveSettings());
    this.elements.exportConfig.addEventListener('click', () => this.exportConfiguration());
    this.elements.importConfig.addEventListener('click', () => this.importConfiguration());

    // Range slider
    if (this.elements.notificationDuration) {
      this.elements.notificationDuration.addEventListener('input', (e) => {
        this.elements.notificationDurationValue.textContent = (e.target.value / 1000) + 's';
      });
    }

    // Detection rules actions
    this.elements.validateRules?.addEventListener('click', () => this.validateCustomRules());
    this.elements.loadDefaultRules?.addEventListener('click', () => this.loadDefaultDetectionRules());

    // Logs actions
    this.elements.logFilter?.addEventListener('change', () => this.filterLogs());
    this.elements.clearLogs?.addEventListener('click', () => this.clearLogs());
    this.elements.exportLogs?.addEventListener('click', () => this.exportLogs());

    // Branding preview updates
    const brandingInputs = [
      this.elements.companyName,
      this.elements.productName,
      this.elements.primaryColor,
      this.elements.logoUrl
    ];
    
    brandingInputs.forEach(input => {
      if (input) {
        input.addEventListener('input', () => this.updateBrandingPreview());
      }
    });

    // Modal actions
    this.elements.modalCancel?.addEventListener('click', () => this.hideModal());
    this.elements.modalOverlay?.addEventListener('click', (e) => {
      if (e.target === this.elements.modalOverlay) {
        this.hideModal();
      }
    });

    // Change tracking
    this.setupChangeTracking();

    // Handle URL hash changes
    window.addEventListener('hashchange', () => this.handleHashChange());
    
    // Handle beforeunload to warn about unsaved changes
    window.addEventListener('beforeunload', (e) => {
      if (this.hasUnsavedChanges) {
        e.preventDefault();
        e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
      }
    });
  }

  setupChangeTracking() {
    const inputs = document.querySelectorAll('input, select, textarea');
    inputs.forEach(input => {
      if (input.type === 'button' || input.type === 'submit') return;
      
      input.addEventListener('change', () => {
        this.markUnsavedChanges();
      });
    });
  }

  async initialize() {
    try {
      // Load configurations
      await this.loadConfiguration();
      await this.loadBrandingConfiguration();
      
      // Apply branding
      this.applyBranding();
      
      // Populate form fields
      this.populateFormFields();
      
      // Load dynamic content
      await this.loadEnterpriseInfo();
      await this.loadLogs();
      await this.loadSystemInfo();
      
      // Handle initial hash
      this.handleHashChange();
      
      // Update branding preview
      this.updateBrandingPreview();
      
      this.showToast('Settings loaded successfully', 'success');
    } catch (error) {
      console.error('Failed to initialize options page:', error);
      this.showToast('Failed to load settings', 'error');
    }
  }

  async loadConfiguration() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        type: 'GET_CONFIG'
      }, (response) => {
        if (response && response.success) {
          this.config = response.config;
          this.originalConfig = JSON.parse(JSON.stringify(response.config));
        } else {
          this.config = this.getDefaultConfig();
          this.originalConfig = JSON.parse(JSON.stringify(this.config));
        }
        resolve();
      });
    });
  }

  async loadBrandingConfiguration() {
    try {
      const response = await fetch(chrome.runtime.getURL('config/branding.json'));
      this.brandingConfig = await response.json();
    } catch (error) {
      console.log('Using default branding configuration');
      this.brandingConfig = this.getDefaultBrandingConfig();
    }
  }

  getDefaultConfig() {
    return {
      extensionEnabled: true,
      enableContentManipulation: true,
      enableUrlMonitoring: true,
      showNotifications: true,
      notificationDuration: 5000,
      blockMaliciousUrls: true,
      blockPhishingAttempts: true,
      whitelistedDomains: [],
      blacklistedDomains: [],
      enableCustomRules: false,
      customRulesUrl: '',
      updateInterval: 24,
      enableLogging: true,
      logLevel: 'info',
      maxLogEntries: 1000,
      respectDoNotTrack: true,
      enableIncognitoMode: true,
      enableComplianceMode: false,
      reportingEndpoint: ''
    };
  }

  getDefaultBrandingConfig() {
    return {
      companyName: 'CyberDrain',
      productName: 'Microsoft 365 Phishing Protection',
      supportEmail: 'support@cyberdrain.com',
      primaryColor: '#F77F00',
      logoUrl: 'images/icon48.png',
      supportUrl: 'https://support.cyberdrain.com',
      privacyPolicyUrl: 'https://cyberdrain.com/privacy',
      termsOfServiceUrl: 'https://cyberdrain.com/terms'
    };
  }

  applyBranding() {
    // Update sidebar branding
    document.getElementById('sidebarTitle').textContent = this.brandingConfig.productName;
    document.getElementById('sidebarVersion').textContent = `v${chrome.runtime.getManifest().version}`;
    
    // Update about section
    this.elements.aboutVersion.textContent = chrome.runtime.getManifest().version;
    this.elements.buildDate.textContent = new Date().toISOString().split('T')[0];
    
    // Update support links
    if (this.brandingConfig.supportUrl) {
      this.elements.supportUrl.href = this.brandingConfig.supportUrl;
    }
    if (this.brandingConfig.privacyPolicyUrl) {
      this.elements.privacyUrl.href = this.brandingConfig.privacyPolicyUrl;
    }
    if (this.brandingConfig.termsOfServiceUrl) {
      this.elements.termsUrl.href = this.brandingConfig.termsOfServiceUrl;
    }
  }

  populateFormFields() {
    // General settings
    this.elements.extensionEnabled.checked = this.config.extensionEnabled;
    this.elements.enableContentManipulation.checked = this.config.enableContentManipulation;
    this.elements.enableUrlMonitoring.checked = this.config.enableUrlMonitoring;
    this.elements.showNotifications.checked = this.config.showNotifications;
    this.elements.notificationDuration.value = this.config.notificationDuration;
    this.elements.notificationDurationValue.textContent = (this.config.notificationDuration / 1000) + 's';

    // Security settings
    this.elements.blockMaliciousUrls.checked = this.config.blockMaliciousUrls;
    this.elements.blockPhishingAttempts.checked = this.config.blockPhishingAttempts;
    this.elements.whitelistedDomains.value = (this.config.whitelistedDomains || []).join('\n');
    this.elements.blacklistedDomains.value = (this.config.blacklistedDomains || []).join('\n');

    // Detection settings
    this.elements.enableCustomRules.checked = this.config.detectionRules?.enableCustomRules || false;
    this.elements.customRulesUrl.value = this.config.detectionRules?.customRulesUrl || '';
    this.elements.updateInterval.value = (this.config.detectionRules?.updateInterval || 86400000) / 3600000;

    // Privacy settings
    this.elements.enableLogging.checked = this.config.enableLogging;
    this.elements.logLevel.value = this.config.logLevel;
    this.elements.maxLogEntries.value = this.config.maxLogEntries;
    this.elements.respectDoNotTrack.checked = this.config.respectDoNotTrack;
    this.elements.enableIncognitoMode.checked = this.config.enableIncognitoMode;

    // Enterprise settings
    this.elements.enableComplianceMode.checked = this.config.enableComplianceMode || false;
    this.elements.reportingEndpoint.value = this.config.reportingEndpoint || '';

    // Branding settings
    this.elements.companyName.value = this.brandingConfig.companyName;
    this.elements.productName.value = this.brandingConfig.productName;
    this.elements.supportEmail.value = this.brandingConfig.supportEmail;
    this.elements.primaryColor.value = this.brandingConfig.primaryColor;
    this.elements.logoUrl.value = this.brandingConfig.logoUrl;
    this.elements.customCss.value = this.brandingConfig.customCss || '';
  }

  switchSection(sectionName) {
    // Update active menu item
    this.elements.menuItems.forEach(item => {
      item.classList.toggle('active', item.dataset.section === sectionName);
    });

    // Update active section
    this.elements.sections.forEach(section => {
      section.classList.toggle('active', section.id === `${sectionName}-section`);
    });

    // Update page title
    const sectionTitles = {
      general: 'General Settings',
      security: 'Security Settings',
      detection: 'Detection Rules',
      privacy: 'Privacy Settings',
      enterprise: 'Enterprise Settings',
      logs: 'Activity Logs',
      branding: 'Branding & White Labeling',
      about: 'About'
    };

    this.elements.pageTitle.textContent = sectionTitles[sectionName] || 'Settings';
    this.currentSection = sectionName;

    // Update URL hash
    window.location.hash = sectionName;

    // Load section-specific data
    if (sectionName === 'logs') {
      this.loadLogs();
    } else if (sectionName === 'enterprise') {
      this.loadEnterpriseInfo();
    }
  }

  handleHashChange() {
    const hash = window.location.hash.slice(1);
    if (hash && document.getElementById(`${hash}-section`)) {
      this.switchSection(hash);
    }
  }

  async saveSettings() {
    try {
      const newConfig = this.gatherFormData();
      
      // Validate configuration
      const validation = this.validateConfiguration(newConfig);
      if (!validation.valid) {
        this.showToast(validation.message, 'error');
        return;
      }

      // Save configuration
      const response = await this.sendMessage({
        type: 'UPDATE_CONFIG',
        config: newConfig
      });

      if (response.success) {
        this.config = newConfig;
        this.originalConfig = JSON.parse(JSON.stringify(newConfig));
        this.hasUnsavedChanges = false;
        this.updateSaveButton();
        this.showToast('Settings saved successfully', 'success');
      } else {
        throw new Error(response.error || 'Failed to save settings');
      }
    } catch (error) {
      console.error('Failed to save settings:', error);
      this.showToast('Failed to save settings', 'error');
    }
  }

  gatherFormData() {
    return {
      // General settings
      extensionEnabled: this.elements.extensionEnabled.checked,
      enableContentManipulation: this.elements.enableContentManipulation.checked,
      enableUrlMonitoring: this.elements.enableUrlMonitoring.checked,
      showNotifications: this.elements.showNotifications.checked,
      notificationDuration: parseInt(this.elements.notificationDuration.value),

      // Security settings
      blockMaliciousUrls: this.elements.blockMaliciousUrls.checked,
      blockPhishingAttempts: this.elements.blockPhishingAttempts.checked,
      whitelistedDomains: this.elements.whitelistedDomains.value.split('\n').filter(d => d.trim()),
      blacklistedDomains: this.elements.blacklistedDomains.value.split('\n').filter(d => d.trim()),

      // Detection settings
      detectionRules: {
        enableCustomRules: this.elements.enableCustomRules.checked,
        customRulesUrl: this.elements.customRulesUrl.value,
        updateInterval: parseInt(this.elements.updateInterval.value) * 3600000
      },

      // Privacy settings
      enableLogging: this.elements.enableLogging.checked,
      logLevel: this.elements.logLevel.value,
      maxLogEntries: parseInt(this.elements.maxLogEntries.value),
      respectDoNotTrack: this.elements.respectDoNotTrack.checked,
      enableIncognitoMode: this.elements.enableIncognitoMode.checked,

      // Enterprise settings
      enableComplianceMode: this.elements.enableComplianceMode.checked,
      reportingEndpoint: this.elements.reportingEndpoint.value
    };
  }

  validateConfiguration(config) {
    // Basic validation
    if (config.notificationDuration < 1000 || config.notificationDuration > 10000) {
      return { valid: false, message: 'Notification duration must be between 1-10 seconds' };
    }

    if (config.maxLogEntries < 100 || config.maxLogEntries > 10000) {
      return { valid: false, message: 'Max log entries must be between 100-10000' };
    }

    if (config.detectionRules.updateInterval < 3600000 || config.detectionRules.updateInterval > 604800000) {
      return { valid: false, message: 'Update interval must be between 1-168 hours' };
    }

    // URL validation
    if (config.detectionRules.customRulesUrl && !this.isValidUrl(config.detectionRules.customRulesUrl)) {
      return { valid: false, message: 'Custom rules URL is not valid' };
    }

    if (config.reportingEndpoint && !this.isValidUrl(config.reportingEndpoint)) {
      return { valid: false, message: 'Reporting endpoint URL is not valid' };
    }

    return { valid: true };
  }

  isValidUrl(string) {
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  }

  async exportConfiguration() {
    try {
      const config = this.gatherFormData();
      const branding = this.gatherBrandingData();
      
      const exportData = {
        config,
        branding,
        timestamp: new Date().toISOString(),
        version: chrome.runtime.getManifest().version
      };

      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cybershield-config-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      this.showToast('Configuration exported successfully', 'success');
    } catch (error) {
      console.error('Failed to export configuration:', error);
      this.showToast('Failed to export configuration', 'error');
    }
  }

  async importConfiguration() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    
    input.onchange = async (e) => {
      const file = e.target.files[0];
      if (!file) return;

      try {
        const text = await file.text();
        const importData = JSON.parse(text);

        if (importData.config) {
          this.config = { ...this.config, ...importData.config };
          this.populateFormFields();
          this.markUnsavedChanges();
          this.showToast('Configuration imported successfully', 'success');
        } else {
          throw new Error('Invalid configuration file');
        }
      } catch (error) {
        console.error('Failed to import configuration:', error);
        this.showToast('Failed to import configuration', 'error');
      }
    };

    input.click();
  }

  gatherBrandingData() {
    return {
      companyName: this.elements.companyName.value,
      productName: this.elements.productName.value,
      supportEmail: this.elements.supportEmail.value,
      primaryColor: this.elements.primaryColor.value,
      logoUrl: this.elements.logoUrl.value,
      customCss: this.elements.customCss.value
    };
  }

  async validateCustomRules() {
    try {
      const rulesText = this.elements.customRulesEditor.value;
      if (!rulesText.trim()) {
        this.showToast('No rules to validate', 'warning');
        return;
      }

      const rules = JSON.parse(rulesText);
      
      // Basic validation
      if (!rules.malicious && !rules.phishing && !rules.suspicious) {
        throw new Error('Rules must contain at least one category (malicious, phishing, or suspicious)');
      }

      // Validate patterns
      const categories = ['malicious', 'phishing', 'suspicious'];
      for (const category of categories) {
        if (rules[category]) {
          for (const rule of rules[category]) {
            if (!rule.pattern) {
              throw new Error(`Rule in ${category} category missing pattern`);
            }
            try {
              new RegExp(rule.pattern, rule.flags || 'i');
            } catch (e) {
              throw new Error(`Invalid regex pattern in ${category}: ${rule.pattern}`);
            }
          }
        }
      }

      this.showToast('Custom rules are valid', 'success');
    } catch (error) {
      this.showToast(`Validation failed: ${error.message}`, 'error');
    }
  }

  async loadDefaultDetectionRules() {
    try {
      const response = await fetch(chrome.runtime.getURL('rules/detection-rules.json'));
      const defaultRules = await response.json();
      this.elements.customRulesEditor.value = JSON.stringify(defaultRules, null, 2);
      this.showToast('Default rules loaded', 'success');
    } catch (error) {
      console.error('Failed to load default rules:', error);
      this.showToast('Failed to load default rules', 'error');
    }
  }

  async loadEnterpriseInfo() {
    try {
      // Check if extension is managed
      const policies = await chrome.storage.managed.get(null);
      const isManaged = Object.keys(policies).length > 0;

      if (isManaged) {
        this.elements.managementStatus.textContent = 'Managed';
        this.elements.managementStatus.classList.add('managed');
        this.elements.enterpriseStatus.querySelector('.status-description').textContent = 
          'This extension is managed by your organization\'s IT department';

        // Update policy list
        this.updatePolicyList(policies);
      } else {
        this.elements.managementStatus.textContent = 'Not Managed';
        this.elements.managementStatus.classList.remove('managed');
      }
    } catch (error) {
      console.error('Failed to load enterprise info:', error);
    }
  }

  updatePolicyList(policies) {
    this.elements.policyList.innerHTML = '';
    
    const policyNames = {
      extensionEnabled: 'Extension Enabled',
      enableContentManipulation: 'Content Manipulation',
      enableUrlMonitoring: 'URL Monitoring',
      blockMaliciousUrls: 'Block Malicious URLs',
      enableLogging: 'Activity Logging'
    };

    Object.keys(policies).forEach(policyKey => {
      if (policyNames[policyKey]) {
        const item = document.createElement('div');
        item.className = 'policy-item';
        
        const name = document.createElement('span');
        name.className = 'policy-name';
        name.textContent = policyNames[policyKey];
        
        const status = document.createElement('span');
        status.className = 'policy-status enforced';
        status.textContent = 'Enforced';
        
        item.appendChild(name);
        item.appendChild(status);
        this.elements.policyList.appendChild(item);
      }
    });
  }

  async loadLogs() {
    try {
      const result = await chrome.storage.local.get(['securityEvents', 'accessLogs']);
      const securityEvents = result.securityEvents || [];
      const accessLogs = result.accessLogs || [];
      
      // Combine and sort logs
      const allLogs = [
        ...securityEvents.map(event => ({ ...event, category: 'security' })),
        ...accessLogs.map(event => ({ ...event, category: 'access' }))
      ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

      this.displayLogs(allLogs);
    } catch (error) {
      console.error('Failed to load logs:', error);
      this.showToast('Failed to load logs', 'error');
    }
  }

  displayLogs(logs) {
    this.elements.logsList.innerHTML = '';
    
    if (logs.length === 0) {
      const item = document.createElement('div');
      item.className = 'log-entry';
      item.innerHTML = '<span class="log-message" style="grid-column: 1 / -1; text-align: center; color: #9ca3af;">No logs available</span>';
      this.elements.logsList.appendChild(item);
      return;
    }

    logs.slice(0, 100).forEach(log => {
      const item = document.createElement('div');
      item.className = 'log-entry';
      
      const time = document.createElement('span');
      time.className = 'log-time';
      time.textContent = new Date(log.timestamp).toLocaleString();
      
      const type = document.createElement('span');
      type.className = `log-type ${log.category}`;
      type.textContent = log.event?.type || log.type || 'unknown';
      
      const message = document.createElement('span');
      message.className = 'log-message';
      message.textContent = this.formatLogMessage(log);
      
      item.appendChild(time);
      item.appendChild(type);
      item.appendChild(message);
      
      this.elements.logsList.appendChild(item);
    });
  }

  formatLogMessage(log) {
    if (log.event) {
      switch (log.event.type) {
        case 'url_access':
          return `Accessed: ${new URL(log.event.url).hostname}`;
        case 'content_threat_detected':
          return `Threat detected on ${new URL(log.event.url).hostname}`;
        case 'form_submission':
          return `Form submitted to ${log.event.action || 'unknown'}`;
        case 'script_injection':
          return `Script injected on page`;
        default:
          return log.event.type.replace(/_/g, ' ');
      }
    }
    return log.type || 'Unknown event';
  }

  filterLogs() {
    // Implementation for log filtering
    this.loadLogs();
  }

  async clearLogs() {
    const confirmed = await this.showConfirmDialog(
      'Clear All Logs',
      'Are you sure you want to clear all activity logs? This action cannot be undone.'
    );

    if (confirmed) {
      try {
        await chrome.storage.local.remove(['securityEvents', 'accessLogs']);
        this.loadLogs();
        this.showToast('Logs cleared successfully', 'success');
      } catch (error) {
        console.error('Failed to clear logs:', error);
        this.showToast('Failed to clear logs', 'error');
      }
    }
  }

  async exportLogs() {
    try {
      const result = await chrome.storage.local.get(['securityEvents', 'accessLogs']);
      const exportData = {
        securityEvents: result.securityEvents || [],
        accessLogs: result.accessLogs || [],
        timestamp: new Date().toISOString(),
        version: chrome.runtime.getManifest().version
      };

      const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `cybershield-logs-${new Date().toISOString().split('T')[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      this.showToast('Logs exported successfully', 'success');
    } catch (error) {
      console.error('Failed to export logs:', error);
      this.showToast('Failed to export logs', 'error');
    }
  }

  updateBrandingPreview() {
    const companyName = this.elements.companyName.value || this.brandingConfig.companyName;
    const productName = this.elements.productName.value || this.brandingConfig.productName;
    const primaryColor = this.elements.primaryColor.value || this.brandingConfig.primaryColor;
    const logoUrl = this.elements.logoUrl.value || this.brandingConfig.logoUrl;

    this.elements.previewTitle.textContent = productName;
    this.elements.previewButton.style.backgroundColor = primaryColor;
    
    if (logoUrl) {
      this.elements.previewLogo.src = logoUrl.startsWith('http') ? 
        logoUrl : chrome.runtime.getURL(logoUrl);
    }
  }

  async loadSystemInfo() {
    // Browser info
    const browserInfo = `${navigator.appName} ${navigator.appVersion}`;
    this.elements.browserInfo.textContent = browserInfo;

    // OS info
    const platform = navigator.platform;
    this.elements.osInfo.textContent = platform;
  }

  markUnsavedChanges() {
    this.hasUnsavedChanges = true;
    this.updateSaveButton();
  }

  updateSaveButton() {
    if (this.hasUnsavedChanges) {
      this.elements.saveSettings.textContent = 'Save Changes *';
      this.elements.saveSettings.classList.add('unsaved');
    } else {
      this.elements.saveSettings.textContent = 'Save Settings';
      this.elements.saveSettings.classList.remove('unsaved');
    }
  }

  async sendMessage(message) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(message, resolve);
    });
  }

  showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const content = document.createElement('div');
    content.className = 'toast-content';
    
    const messageEl = document.createElement('span');
    messageEl.className = 'toast-message';
    messageEl.textContent = message;
    
    const closeBtn = document.createElement('button');
    closeBtn.className = 'toast-close';
    closeBtn.innerHTML = '&times;';
    closeBtn.onclick = () => toast.remove();
    
    content.appendChild(messageEl);
    content.appendChild(closeBtn);
    toast.appendChild(content);
    
    this.elements.toastContainer.appendChild(toast);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (toast.parentNode) {
        toast.remove();
      }
    }, 5000);
  }

  async showConfirmDialog(title, message) {
    return new Promise((resolve) => {
      this.elements.modalTitle.textContent = title;
      this.elements.modalMessage.textContent = message;
      this.elements.modalOverlay.style.display = 'flex';

      const handleConfirm = () => {
        this.hideModal();
        resolve(true);
        cleanup();
      };

      const handleCancel = () => {
        this.hideModal();
        resolve(false);
        cleanup();
      };

      const cleanup = () => {
        this.elements.modalConfirm.removeEventListener('click', handleConfirm);
        this.elements.modalCancel.removeEventListener('click', handleCancel);
      };

      this.elements.modalConfirm.addEventListener('click', handleConfirm);
      this.elements.modalCancel.addEventListener('click', handleCancel);
    });
  }

  hideModal() {
    this.elements.modalOverlay.style.display = 'none';
  }
}

// Initialize options page when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new CyberShieldOptions();
});
