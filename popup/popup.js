/**
 * CyberShield Drain - Popup JavaScript
 * Handles popup UI interactions and communication with background script
 */

class CyberShieldPopup {
  constructor() {
    this.currentTab = null;
    this.config = null;
    this.brandingConfig = null;
    this.stats = {
      blockedThreats: 0,
      scannedPages: 0,
      securityEvents: 0
    };
    this.activityItems = [];
    this.isLoading = false;
    
    this.elements = {};
    this.bindElements();
    this.setupEventListeners();
    this.initialize();
  }

  bindElements() {
    // Header elements
    this.elements.brandingLogo = document.getElementById('brandingLogo');
    this.elements.brandingTitle = document.getElementById('brandingTitle');
    this.elements.extensionVersion = document.getElementById('extensionVersion');
    this.elements.statusIndicator = document.getElementById('statusIndicator');
    this.elements.statusDot = document.getElementById('statusDot');
    this.elements.statusText = document.getElementById('statusText');

    // Action buttons
    this.elements.toggleExtension = document.getElementById('toggleExtension');
    this.elements.toggleText = document.getElementById('toggleText');
    this.elements.scanCurrentPage = document.getElementById('scanCurrentPage');
    this.elements.viewLogs = document.getElementById('viewLogs');
    this.elements.openSettings = document.getElementById('openSettings');
    this.elements.reportIssue = document.getElementById('reportIssue');

    // Page info
    this.elements.pageInfoSection = document.getElementById('pageInfoSection');
    this.elements.currentUrl = document.getElementById('currentUrl');
    this.elements.securityStatus = document.getElementById('securityStatus');
    this.elements.securityBadge = document.getElementById('securityBadge');
    this.elements.threatSummary = document.getElementById('threatSummary');
    this.elements.threatList = document.getElementById('threatList');

    // Statistics
    this.elements.blockedThreats = document.getElementById('blockedThreats');
    this.elements.scannedPages = document.getElementById('scannedPages');
    this.elements.securityEvents = document.getElementById('securityEvents');

    // Enterprise section
    this.elements.enterpriseSection = document.getElementById('enterpriseSection');
    this.elements.managedBy = document.getElementById('managedBy');
    this.elements.complianceBadge = document.getElementById('complianceBadge');

    // Activity
    this.elements.activityList = document.getElementById('activityList');

    // Footer
    this.elements.supportLink = document.getElementById('supportLink');
    this.elements.privacyLink = document.getElementById('privacyLink');
    this.elements.aboutLink = document.getElementById('aboutLink');
    this.elements.companyBranding = document.getElementById('companyBranding');
    this.elements.companyName = document.getElementById('companyName');

    // Overlay elements
    this.elements.loadingOverlay = document.getElementById('loadingOverlay');
    this.elements.notificationToast = document.getElementById('notificationToast');
    this.elements.notificationText = document.getElementById('notificationText');
    this.elements.notificationClose = document.getElementById('notificationClose');
  }

  setupEventListeners() {
    // Action button listeners
    this.elements.toggleExtension.addEventListener('click', () => this.toggleExtension());
    this.elements.scanCurrentPage.addEventListener('click', () => this.scanCurrentPage());
    this.elements.viewLogs.addEventListener('click', () => this.viewLogs());
    this.elements.openSettings.addEventListener('click', () => this.openSettings());
    this.elements.reportIssue.addEventListener('click', () => this.reportIssue());

    // Footer link listeners
    this.elements.supportLink.addEventListener('click', (e) => this.handleFooterLink(e, 'support'));
    this.elements.privacyLink.addEventListener('click', (e) => this.handleFooterLink(e, 'privacy'));
    this.elements.aboutLink.addEventListener('click', (e) => this.handleFooterLink(e, 'about'));

    // Notification close listener
    this.elements.notificationClose.addEventListener('click', () => this.hideNotification());
  }

  async initialize() {
    try {
      this.showLoading('Initializing...');

      // Get current tab
      this.currentTab = await this.getCurrentTab();

      // Load configuration and branding
      await this.loadConfiguration();
      await this.loadBrandingConfiguration();

      // Apply branding
      this.applyBranding();

      // Load data
      await this.loadStatistics();
      await this.loadCurrentPageInfo();
      await this.loadRecentActivity();
      await this.checkEnterpriseMode();

      // Update UI
      this.updateStatusIndicator();
      this.updateExtensionToggle();

      this.hideLoading();
    } catch (error) {
      console.error('CyberShield Drain: Failed to initialize popup:', error);
      this.showNotification('Failed to initialize extension', 'error');
      this.hideLoading();
    }
  }

  async getCurrentTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0];
  }

  async loadConfiguration() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        type: 'GET_CONFIG'
      }, (response) => {
        if (response && response.success) {
          this.config = response.config;
        } else {
          this.config = this.getDefaultConfig();
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
      enterpriseMode: false
    };
  }

  getDefaultBrandingConfig() {
    return {
      companyName: 'CyberShield',
      productName: 'CyberShield Drain',
      version: '1.0.0',
      primaryColor: '#2563eb',
      logoUrl: 'images/icon32.png',
      supportUrl: 'https://support.cybershield.com',
      privacyPolicyUrl: 'https://cybershield.com/privacy',
      supportEmail: 'support@cybershield.com'
    };
  }

  applyBranding() {
    // Update title and version
    this.elements.brandingTitle.textContent = this.brandingConfig.productName;
    this.elements.extensionVersion.textContent = `v${chrome.runtime.getManifest().version}`;

    // Update logo
    if (this.brandingConfig.logoUrl) {
      this.elements.brandingLogo.src = chrome.runtime.getURL(this.brandingConfig.logoUrl);
    }

    // Update company name
    this.elements.companyName.textContent = this.brandingConfig.companyName;

    // Update link URLs
    if (this.brandingConfig.supportUrl) {
      this.elements.supportLink.href = this.brandingConfig.supportUrl;
    }
    if (this.brandingConfig.privacyPolicyUrl) {
      this.elements.privacyLink.href = this.brandingConfig.privacyPolicyUrl;
    }

    // Apply custom colors if available
    if (this.brandingConfig.primaryColor) {
      document.documentElement.style.setProperty('--primary-color', this.brandingConfig.primaryColor);
    }
  }

  async loadStatistics() {
    try {
      // Get statistics from storage
      const result = await chrome.storage.local.get(['statistics']);
      if (result.statistics) {
        this.stats = { ...this.stats, ...result.statistics };
      }

      // Update UI
      this.elements.blockedThreats.textContent = this.stats.blockedThreats.toLocaleString();
      this.elements.scannedPages.textContent = this.stats.scannedPages.toLocaleString();
      this.elements.securityEvents.textContent = this.stats.securityEvents.toLocaleString();
    } catch (error) {
      console.error('Failed to load statistics:', error);
    }
  }

  async loadCurrentPageInfo() {
    if (!this.currentTab || !this.currentTab.url) {
      this.elements.currentUrl.textContent = 'No active tab';
      return;
    }

    try {
      // Display current URL
      const url = new URL(this.currentTab.url);
      this.elements.currentUrl.textContent = url.hostname + url.pathname;

      // Request page analysis from background
      this.showSecurityBadge('analyzing', 'Analyzing...');
      
      chrome.runtime.sendMessage({
        type: 'URL_ANALYSIS_REQUEST',
        url: this.currentTab.url
      }, (response) => {
        if (response && response.success && response.analysis) {
          this.updateSecurityStatus(response.analysis);
        } else {
          this.showSecurityBadge('safe', 'Analysis unavailable');
        }
      });

      // Get page info from content script
      chrome.tabs.sendMessage(this.currentTab.id, {
        type: 'GET_PAGE_INFO'
      }, (response) => {
        if (response && response.success) {
          this.updatePageInfo(response.info);
        }
      });

    } catch (error) {
      console.error('Failed to load page info:', error);
      this.elements.currentUrl.textContent = 'Invalid URL';
      this.showSecurityBadge('safe', 'Protected');
    }
  }

  updateSecurityStatus(analysis) {
    if (analysis.isBlocked) {
      this.showSecurityBadge('danger', 'Blocked');
      this.showThreats(analysis.threats);
    } else if (analysis.isSuspicious) {
      this.showSecurityBadge('warning', 'Suspicious');
      this.showThreats(analysis.threats);
    } else {
      this.showSecurityBadge('safe', 'Safe');
      this.hideThreats();
    }
  }

  showSecurityBadge(type, text) {
    this.elements.securityBadge.textContent = text;
    this.elements.securityBadge.className = `security-badge ${type}`;
  }

  showThreats(threats) {
    if (threats && threats.length > 0) {
      this.elements.threatSummary.style.display = 'block';
      this.elements.threatList.innerHTML = '';
      
      threats.forEach(threat => {
        const li = document.createElement('li');
        li.textContent = `${threat.type}: ${threat.description}`;
        this.elements.threatList.appendChild(li);
      });
    } else {
      this.hideThreats();
    }
  }

  hideThreats() {
    this.elements.threatSummary.style.display = 'none';
  }

  updatePageInfo(pageInfo) {
    // Could update additional page information here
    console.log('Page info received:', pageInfo);
  }

  async loadRecentActivity() {
    try {
      // Get recent security events
      const result = await chrome.storage.local.get(['securityEvents']);
      const events = result.securityEvents || [];
      
      // Get recent 5 events
      const recentEvents = events.slice(-5).reverse();
      
      if (recentEvents.length === 0) {
        this.elements.activityList.innerHTML = '<div class="activity-item placeholder"><span class="activity-text">No recent activity</span></div>';
        return;
      }

      this.elements.activityList.innerHTML = '';
      recentEvents.forEach(event => {
        this.addActivityItem(event);
      });
    } catch (error) {
      console.error('Failed to load recent activity:', error);
    }
  }

  addActivityItem(event) {
    const item = document.createElement('div');
    item.className = 'activity-item';
    
    const icon = document.createElement('div');
    icon.className = `activity-icon ${this.getActivityIconType(event.event.type)}`;
    icon.textContent = this.getActivityIcon(event.event.type);
    
    const text = document.createElement('span');
    text.className = 'activity-text';
    text.textContent = this.getActivityText(event.event);
    
    const time = document.createElement('span');
    time.className = 'activity-time';
    time.textContent = this.formatTime(new Date(event.timestamp));
    
    item.appendChild(icon);
    item.appendChild(text);
    item.appendChild(time);
    
    this.elements.activityList.appendChild(item);
  }

  getActivityIconType(eventType) {
    if (eventType.includes('block') || eventType.includes('threat')) return 'blocked';
    if (eventType.includes('warning') || eventType.includes('suspicious')) return 'warned';
    return 'scanned';
  }

  getActivityIcon(eventType) {
    if (eventType.includes('block')) return '🛡️';
    if (eventType.includes('warning')) return '⚠️';
    if (eventType.includes('scan')) return '🔍';
    return '📋';
  }

  getActivityText(event) {
    switch (event.type) {
      case 'url_access':
        return `Scanned ${new URL(event.url).hostname}`;
      case 'content_threat_detected':
        return `Threat detected on ${new URL(event.url).hostname}`;
      case 'form_submission':
        return 'Form submission monitored';
      case 'script_injection':
        return 'Script injection executed';
      default:
        return event.type.replace(/_/g, ' ');
    }
  }

  formatTime(date) {
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return 'now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h`;
    return `${Math.floor(diff / 86400000)}d`;
  }

  async checkEnterpriseMode() {
    if (this.config.enterpriseMode) {
      this.elements.enterpriseSection.style.display = 'block';
      
      // Update managed by info
      if (this.config.organizationName) {
        this.elements.managedBy.textContent = this.config.organizationName;
      }
      
      // Update compliance status
      const isCompliant = await this.checkCompliance();
      this.updateComplianceStatus(isCompliant);
    }
  }

  async checkCompliance() {
    // Placeholder for compliance checking logic
    return true;
  }

  updateComplianceStatus(isCompliant) {
    this.elements.complianceBadge.textContent = isCompliant ? 'Compliant' : 'Non-Compliant';
    this.elements.complianceBadge.className = isCompliant ? 'compliance-badge' : 'compliance-badge non-compliant';
  }

  updateStatusIndicator() {
    if (this.config.extensionEnabled) {
      this.elements.statusDot.className = 'status-dot';
      this.elements.statusText.textContent = 'Active';
    } else {
      this.elements.statusDot.className = 'status-dot inactive';
      this.elements.statusText.textContent = 'Disabled';
    }
  }

  updateExtensionToggle() {
    if (this.config.extensionEnabled) {
      this.elements.toggleText.textContent = 'Disable Protection';
      this.elements.toggleExtension.classList.remove('disabled');
    } else {
      this.elements.toggleText.textContent = 'Enable Protection';
      this.elements.toggleExtension.classList.add('disabled');
    }
  }

  async toggleExtension() {
    try {
      const newState = !this.config.extensionEnabled;
      
      // Update configuration
      const response = await this.sendMessage({
        type: 'UPDATE_CONFIG',
        config: { extensionEnabled: newState }
      });

      if (response.success) {
        this.config.extensionEnabled = newState;
        this.updateStatusIndicator();
        this.updateExtensionToggle();
        
        this.showNotification(
          newState ? 'Protection enabled' : 'Protection disabled',
          newState ? 'success' : 'warning'
        );
      } else {
        throw new Error(response.error || 'Failed to update configuration');
      }
    } catch (error) {
      console.error('Failed to toggle extension:', error);
      this.showNotification('Failed to toggle protection', 'error');
    }
  }

  async scanCurrentPage() {
    if (!this.currentTab) return;

    try {
      this.showLoading('Scanning page...');
      
      // Request page scan
      chrome.tabs.sendMessage(this.currentTab.id, {
        type: 'ANALYZE_PAGE'
      }, (response) => {
        this.hideLoading();
        
        if (response && response.success) {
          this.showNotification('Page scan completed', 'success');
          this.updateSecurityStatus(response.analysis);
          
          // Update statistics
          this.stats.scannedPages++;
          this.updateStatistics();
        } else {
          this.showNotification('Page scan failed', 'error');
        }
      });
    } catch (error) {
      this.hideLoading();
      console.error('Failed to scan page:', error);
      this.showNotification('Page scan failed', 'error');
    }
  }

  viewLogs() {
    chrome.tabs.create({
      url: chrome.runtime.getURL('options/options.html#logs')
    });
    window.close();
  }

  openSettings() {
    chrome.tabs.create({
      url: chrome.runtime.getURL('options/options.html')
    });
    window.close();
  }

  reportIssue() {
    if (this.brandingConfig.supportEmail) {
      const subject = encodeURIComponent('CyberShield Drain - Issue Report');
      const body = encodeURIComponent(`
Extension Version: ${chrome.runtime.getManifest().version}
Current URL: ${this.currentTab?.url || 'N/A'}
Browser: ${navigator.userAgent}

Issue Description:
[Please describe the issue you're experiencing]
      `);
      
      window.open(`mailto:${this.brandingConfig.supportEmail}?subject=${subject}&body=${body}`);
    } else if (this.brandingConfig.supportUrl) {
      chrome.tabs.create({ url: this.brandingConfig.supportUrl });
    } else {
      this.showNotification('Support contact not configured', 'warning');
    }
    window.close();
  }

  handleFooterLink(event, linkType) {
    event.preventDefault();
    
    let url = '';
    switch (linkType) {
      case 'support':
        url = this.brandingConfig.supportUrl;
        break;
      case 'privacy':
        url = this.brandingConfig.privacyPolicyUrl;
        break;
      case 'about':
        url = chrome.runtime.getURL('options/options.html#about');
        break;
    }
    
    if (url) {
      chrome.tabs.create({ url });
      window.close();
    }
  }

  async sendMessage(message) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(message, resolve);
    });
  }

  async updateStatistics() {
    try {
      await chrome.storage.local.set({ statistics: this.stats });
      this.elements.scannedPages.textContent = this.stats.scannedPages.toLocaleString();
    } catch (error) {
      console.error('Failed to update statistics:', error);
    }
  }

  showLoading(text = 'Loading...') {
    this.isLoading = true;
    this.elements.loadingOverlay.style.display = 'flex';
    if (this.elements.loadingOverlay.querySelector('.loading-text')) {
      this.elements.loadingOverlay.querySelector('.loading-text').textContent = text;
    }
  }

  hideLoading() {
    this.isLoading = false;
    this.elements.loadingOverlay.style.display = 'none';
  }

  showNotification(text, type = 'info') {
    this.elements.notificationText.textContent = text;
    this.elements.notificationToast.className = `notification-toast ${type}`;
    this.elements.notificationToast.style.display = 'flex';
    
    // Auto-hide after 3 seconds
    setTimeout(() => {
      this.hideNotification();
    }, 3000);
  }

  hideNotification() {
    this.elements.notificationToast.style.display = 'none';
  }
}

// Initialize popup when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  new CyberShieldPopup();
});
