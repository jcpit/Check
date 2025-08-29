/**
 * CyberShield Drain - Background Service Worker
 * Manifest V3 compatible background script for enterprise security
 */

import { ConfigManager } from './modules/config-manager.js';
import { DetectionEngine } from './modules/detection-engine.js';
import { PolicyManager } from './modules/policy-manager.js';

class CyberShieldBackground {
  constructor() {
    this.configManager = new ConfigManager();
    this.detectionEngine = new DetectionEngine();
    this.policyManager = new PolicyManager();
    this.isInitialized = false;
  }

  async initialize() {
    try {
      console.log('CyberShield Drain: Initializing background service worker...');
      
      // Load configuration and policies
      await this.configManager.loadConfig();
      await this.policyManager.loadPolicies();
      await this.detectionEngine.initialize();
      
      this.setupEventListeners();
      this.isInitialized = true;
      
      console.log('CyberShield Drain: Background service worker initialized successfully');
    } catch (error) {
      console.error('CyberShield Drain: Failed to initialize background service worker:', error);
    }
  }

  setupEventListeners() {
    // Handle extension installation/startup
    chrome.runtime.onStartup.addListener(() => {
      this.handleStartup();
    });

    chrome.runtime.onInstalled.addListener((details) => {
      this.handleInstalled(details);
    });

    // Handle tab updates for URL monitoring
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      this.handleTabUpdate(tabId, changeInfo, tab);
    });

    // Handle messages from content scripts
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep message channel open for async responses
    });

    // Handle storage changes (for enterprise policy updates)
    chrome.storage.onChanged.addListener((changes, namespace) => {
      this.handleStorageChange(changes, namespace);
    });

    // Handle web navigation events
    chrome.webNavigation?.onCompleted?.addListener((details) => {
      this.handleNavigationCompleted(details);
    });
  }

  async handleStartup() {
    console.log('CyberShield Drain: Extension startup detected');
    await this.configManager.refreshConfig();
  }

  async handleInstalled(details) {
    console.log('CyberShield Drain: Extension installed/updated:', details.reason);
    
    if (details.reason === 'install') {
      // Set default configuration
      await this.configManager.setDefaultConfig();
      
      // Open options page for initial setup
      chrome.tabs.create({
        url: chrome.runtime.getURL('options/options.html')
      });
    } else if (details.reason === 'update') {
      // Handle extension updates
      await this.configManager.migrateConfig(details.previousVersion);
    }
  }

  async handleTabUpdate(tabId, changeInfo, tab) {
    if (!this.isInitialized || !changeInfo.url) return;

    try {
      // Analyze URL for threats
      const urlAnalysis = await this.detectionEngine.analyzeUrl(changeInfo.url);
      
      if (urlAnalysis.isBlocked) {
        // Block navigation if URL is flagged
        chrome.tabs.update(tabId, {
          url: chrome.runtime.getURL('blocked.html') + '?reason=' + encodeURIComponent(urlAnalysis.reason)
        });
        return;
      }

      // Check if page requires content script injection
      if (urlAnalysis.requiresContentScript) {
        await this.injectContentScript(tabId);
      }

      // Log URL access for audit purposes
      await this.logUrlAccess(tab.url, tabId);
      
    } catch (error) {
      console.error('CyberShield Drain: Error handling tab update:', error);
    }
  }

  async handleMessage(message, sender, sendResponse) {
    try {
      switch (message.type) {
        case 'URL_ANALYSIS_REQUEST':
          const analysis = await this.detectionEngine.analyzeUrl(message.url);
          sendResponse({ success: true, analysis });
          break;

        case 'POLICY_CHECK':
          const policyResult = await this.policyManager.checkPolicy(message.action, message.context);
          sendResponse({ success: true, allowed: policyResult.allowed, reason: policyResult.reason });
          break;

        case 'CONTENT_MANIPULATION_REQUEST':
          const manipulationAllowed = await this.policyManager.checkContentManipulation(message.domain);
          sendResponse({ success: true, allowed: manipulationAllowed });
          break;

        case 'LOG_EVENT':
          await this.logEvent(message.event, sender.tab?.id);
          sendResponse({ success: true });
          break;

        case 'GET_CONFIG':
          const config = await this.configManager.getConfig();
          sendResponse({ success: true, config });
          break;

        default:
          sendResponse({ success: false, error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('CyberShield Drain: Error handling message:', error);
      sendResponse({ success: false, error: error.message });
    }
  }

  async handleStorageChange(changes, namespace) {
    if (namespace === 'managed') {
      // Enterprise policy changes
      console.log('CyberShield Drain: Enterprise policy updated');
      await this.policyManager.loadPolicies();
      await this.configManager.refreshConfig();
    }
  }

  async handleNavigationCompleted(details) {
    if (details.frameId === 0) { // Main frame only
      // Run post-navigation analysis
      await this.detectionEngine.analyzePageContent(details.tabId, details.url);
    }
  }

  async injectContentScript(tabId) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId },
        files: ['scripts/content.js']
      });
    } catch (error) {
      console.error('CyberShield Drain: Failed to inject content script:', error);
    }
  }

  async logUrlAccess(url, tabId) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      url,
      tabId,
      type: 'url_access'
    };

    // Store in local storage for audit
    const logs = await chrome.storage.local.get(['accessLogs']) || { accessLogs: [] };
    logs.accessLogs.push(logEntry);
    
    // Keep only last 1000 entries
    if (logs.accessLogs.length > 1000) {
      logs.accessLogs = logs.accessLogs.slice(-1000);
    }
    
    await chrome.storage.local.set({ accessLogs: logs.accessLogs });
  }

  async logEvent(event, tabId) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      tabId,
      type: 'security_event'
    };

    console.log('CyberShield Drain: Security Event:', logEntry);
    
    // Store security events separately
    const logs = await chrome.storage.local.get(['securityEvents']) || { securityEvents: [] };
    logs.securityEvents.push(logEntry);
    
    // Keep only last 500 security events
    if (logs.securityEvents.length > 500) {
      logs.securityEvents = logs.securityEvents.slice(-500);
    }
    
    await chrome.storage.local.set({ securityEvents: logs.securityEvents });
  }
}

// Initialize the background service worker
const cyberShield = new CyberShieldBackground();
cyberShield.initialize();

// Export for testing purposes
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CyberShieldBackground;
}
