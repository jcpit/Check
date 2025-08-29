/**
 * Microsoft 365 Phishing Protection - Enhanced Background Service Worker
 * Combines robust architecture with focused M365 phishing detection and policy management
 */

import { ConfigManager } from "./modules/config-manager.js";
import { DetectionEngine } from "./modules/detection-engine.js";
import { PolicyManager } from "./modules/policy-manager.js";

// Trusted Microsoft Origins - Core Detection Foundation
const TRUSTED_ORIGINS = new Set([
  "https://login.microsoftonline.com",
  "https://login.microsoft.com",
  "https://login.windows.net", 
  "https://login.microsoftonline.us",
  "https://login.partner.microsoftonline.cn",
  "https://login.live.com"
]);

const DEFAULT_POLICY = {
  BrandingName: "Microsoft 365 Phishing Protection",
  BrandingImage: "",
  ExtraWhitelist: [],
  CIPPReportingServer: "",
  AlertWhenLogon: true,
  ValidPageBadgeImage: "",
  StrictResourceAudit: true,
  RequireMicrosoftAction: true,
  // Enhanced detection settings
  enablePhishingDetection: true,
  lockCredentialsOnPhishing: true,
  preventPhishingSubmission: true,
  showValidPageBadge: true
};

function urlOrigin(u) {
  try { 
    return new URL(u).origin.toLowerCase(); 
  } catch { 
    return ""; 
  }
}

function isTrustedOrigin(u) {
  return TRUSTED_ORIGINS.has(urlOrigin(u));
}

class CheckBackground {
  constructor() {
    this.configManager = new ConfigManager();
    this.detectionEngine = new DetectionEngine();
    this.policyManager = new PolicyManager();
    this.isInitialized = false;
    
    // Policy and verdict management
    this.policy = DEFAULT_POLICY;
    this.extraWhitelist = new Set();

    // Set up message handlers immediately to handle early connections
    this.setupMessageHandlers();
  }

  setupMessageHandlers() {
    // Handle messages from content scripts and popups
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep message channel open for async responses
    });
  }

  async initialize() {
    try {
      console.log("Check: Initializing enhanced background service worker...");

      // Load configuration and policies
      await this.configManager.loadConfig();
      await this.policyManager.loadPolicies();
      await this.detectionEngine.initialize();
      
      // Load enhanced policy configuration
      await this.refreshPolicy();

      this.setupEventListeners();
      this.setupEnhancedFeatures();
      this.isInitialized = true;

      console.log("Check: Enhanced background service worker initialized successfully");
    } catch (error) {
      console.error(
        "Check: Failed to initialize background service worker:",
        error
      );
    }
  }

  async refreshPolicy() {
    try {
      this.policy = await this.loadPolicy();
      this.extraWhitelist = new Set((this.policy.ExtraWhitelist || []).map(s => urlOrigin(s)).filter(Boolean));
      await this.applyBrandingToAction();
    } catch (error) {
      console.error("Check: Error refreshing policy:", error);
    }
  }

  async loadPolicy() {
    try {
      const managed = await chrome.storage.managed.get(null).catch(() => ({}));
      const local = await chrome.storage.sync.get(null).catch(() => ({}));
      return Object.assign({}, DEFAULT_POLICY, managed, local);
    } catch (error) {
      console.error("Check: Error loading policy:", error);
      return DEFAULT_POLICY;
    }
  }

  async applyBrandingToAction() {
    try {
      // Update action title
      await chrome.action.setTitle({ 
        title: this.policy.BrandingName || DEFAULT_POLICY.BrandingName 
      });
      
      // Update icon if custom branding image is provided
      if (this.policy.BrandingImage) {
        try {
          const img = await fetch(this.policy.BrandingImage);
          const blob = await img.blob();
          const bmp = await createImageBitmap(blob);
          const sizes = [16, 32, 48, 128];
          const images = {};
          
          for (const s of sizes) {
            const canvas = new OffscreenCanvas(s, s);
            const ctx = canvas.getContext("2d");
            ctx.clearRect(0, 0, s, s);
            ctx.drawImage(bmp, 0, 0, s, s);
            images[String(s)] = ctx.getImageData(0, 0, s, s);
          }
          
          await chrome.action.setIcon({ imageData: images });
        } catch (e) {
          console.warn("Check: Failed to apply custom branding image:", e);
        }
      }
    } catch (error) {
      console.error("Check: Error applying branding:", error);
    }
  }

  verdictForUrl(url) {
    const origin = urlOrigin(url);
    if (TRUSTED_ORIGINS.has(origin)) return "trusted";
    if (this.extraWhitelist.has(origin)) return "trusted-extra";
    return "unknown";
  }

  async setBadge(tabId, verdict, details = {}) {
    const badgeMap = {
      "trusted":       { text: "MS", color: "#0a5" },
      "trusted-extra": { text: "OK", color: "#0a5" },
      "phishy":        { text: "!",  color: "#d33" },
      "unknown":       { text: "?",  color: "#777" }
    };
    
    const cfg = badgeMap[verdict] || badgeMap.unknown;
    
    try {
      await chrome.action.setBadgeText({ tabId, text: cfg.text });
      await chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color });
    } catch (error) {
      console.warn("Check: Failed to set badge:", error);
    }
  }

  async sendEvent(evt) {
    if (!this.policy.CIPPReportingServer) return;
    
    try {
      const url = this.policy.CIPPReportingServer.replace(/\/+$/, "") + "/events/cyberdrain-phish";
      
      await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.assign({
          ts: new Date().toISOString(),
          ua: navigator.userAgent,
          extensionVersion: chrome.runtime.getManifest().version
        }, evt))
      });
    } catch (error) {
      console.warn("Check: Failed to send event to CIPP:", error);
    }
  }

  setupEventListeners() {
    // Tab update monitoring for phishing detection
    chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
      if (!tab?.url || changeInfo.status !== "complete") return;
      
      const verdict = this.verdictForUrl(tab.url);
      
      // Store verdict in session storage
      await chrome.storage.session.set({ 
        [`verdict:${tabId}`]: { 
          verdict, 
          url: tab.url,
          timestamp: new Date().toISOString()
        } 
      });
      
      await this.setBadge(tabId, verdict);

      // Send trusted page sighting event
      if (verdict === "trusted") {
        await this.sendEvent({ 
          type: "trusted-login-page", 
          url: tab.url,
          tabId 
        });
      }
    });

    // Tab activation handling
    chrome.tabs.onActivated.addListener(async ({ tabId }) => {
      try {
        const data = (await chrome.storage.session.get(`verdict:${tabId}`))[[`verdict:${tabId}`]];
        await this.setBadge(tabId, data?.verdict || "unknown");
      } catch (error) {
        console.warn("Check: Error handling tab activation:", error);
      }
    });

    // Storage change monitoring for policy updates
    chrome.storage.onChanged.addListener((changes, namespace) => {
      if (namespace === 'sync' || namespace === 'managed') {
        this.refreshPolicy();
      }
    });

    // Extension startup
    chrome.runtime.onStartup.addListener(() => {
      this.refreshPolicy();
    });

    // Installation/update handling
    chrome.runtime.onInstalled.addListener((details) => {
      this.handleInstallation(details);
    });
  }

  setupEnhancedFeatures() {
    // Set up alarm for periodic policy refresh
    chrome.alarms.create('policyRefresh', { periodInMinutes: 60 });
    
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === 'policyRefresh') {
        this.refreshPolicy();
      }
    });
  }

  async handleInstallation(details) {
    if (details.reason === 'install') {
      console.log("Check: Extension installed");
      await this.sendEvent({ 
        type: "extension-installed", 
        version: chrome.runtime.getManifest().version 
      });
    } else if (details.reason === 'update') {
      console.log("Check: Extension updated");
      await this.sendEvent({ 
        type: "extension-updated", 
        version: chrome.runtime.getManifest().version,
        previousVersion: details.previousVersion
      });
    }
  }

  async handleMessage(message, sender, sendResponse) {
    try {
      const tabId = sender.tab?.id;

      switch (message.type) {
        case "GET_CONFIG":
          const config = await this.configManager.getConfig();
          const enhancedConfig = {
            ...config,
            ...this.policy,
            enablePhishingDetection: this.policy.enablePhishingDetection !== false,
            strictResourceAudit: this.policy.StrictResourceAudit !== false,
            requireMicrosoftAction: this.policy.RequireMicrosoftAction !== false
          };
          sendResponse({ success: true, config: enhancedConfig });
          break;

        case "REQUEST_POLICY":
          sendResponse({ policy: this.policy });
          break;

        case "FLAG_PHISHY":
          if (tabId) {
            await chrome.storage.session.set({ 
              [`verdict:${tabId}`]: { 
                verdict: "phishy", 
                url: sender.tab.url,
                reason: message.reason,
                details: message.details,
                timestamp: new Date().toISOString()
              } 
            });
            await this.setBadge(tabId, "phishy");
            await this.sendEvent({ 
              type: "phishy-detected", 
              url: sender.tab.url, 
              reason: message.reason || "heuristic",
              details: message.details
            });
          }
          sendResponse({ ok: true });
          break;

        case "FLAG_TRUSTED_BY_REFERRER":
          if (tabId) {
            await chrome.storage.session.set({ 
              [`verdict:${tabId}`]: { 
                verdict: "trusted", 
                url: sender.tab.url, 
                by: "referrer",
                timestamp: new Date().toISOString()
              } 
            });
            await this.setBadge(tabId, "trusted");
            
            if (this.policy.AlertWhenLogon) {
              await this.sendEvent({ 
                type: "user-logged-on", 
                url: sender.tab.url, 
                by: "referrer" 
              });
            }
          }
          sendResponse({ ok: true });
          break;

        case "PING":
          sendResponse({ 
            status: "alive", 
            initialized: this.isInitialized,
            timestamp: new Date().toISOString()
          });
          break;

        case "ANALYZE_PAGE":
          const analysis = await this.detectionEngine.analyzePage(message.pageData || {});
          sendResponse({ success: true, analysis });
          break;

        case "URL_ANALYSIS_REQUEST":
          const urlAnalysis = await this.analyzeUrl(message.url);
          sendResponse({ success: true, analysis: urlAnalysis });
          break;

        case "POLICY_CHECK":
          const policyResult = await this.policyManager.checkPolicy(
            message.action,
            message.context
          );
          sendResponse({
            success: true,
            allowed: policyResult.allowed,
            reason: policyResult.reason,
          });
          break;

        case "LOG_EVENT":
          await this.logSecurityEvent(message.event);
          await this.sendEvent(message.event);
          sendResponse({ success: true });
          break;

        case "GET_THREATS":
          const threats = await this.detectionEngine.getThreats();
          sendResponse({ success: true, threats });
          break;

        case "UPDATE_CONFIG":
          await this.configManager.updateConfig(message.config);
          await this.refreshPolicy();
          sendResponse({ success: true });
          break;

        case "GET_STATS":
          const stats = await this.getExtensionStats();
          sendResponse({ success: true, stats });
          break;

        case "EXPORT_DATA":
          const exportData = await this.exportData();
          sendResponse({ success: true, data: exportData });
          break;

        default:
          console.warn("Check: Unknown message type:", message.type);
          sendResponse({ success: false, error: "Unknown message type" });
      }
    } catch (error) {
      console.error("Check: Error handling message:", error);
      sendResponse({ success: false, error: error.message });
    }
  }

  async analyzeUrl(url) {
    try {
      const origin = urlOrigin(url);
      const isTrusted = TRUSTED_ORIGINS.has(origin) || this.extraWhitelist.has(origin);
      
      // Check against detection engine
      const threatAnalysis = await this.detectionEngine.analyzeUrl(url);
      
      return {
        url,
        origin,
        isTrusted,
        isBlocked: threatAnalysis.isBlocked,
        isSuspicious: threatAnalysis.isSuspicious,
        reason: threatAnalysis.reason,
        threats: threatAnalysis.threats || []
      };
    } catch (error) {
      console.error("Check: Error analyzing URL:", error);
      return {
        url,
        isTrusted: false,
        isBlocked: false,
        isSuspicious: false,
        reason: "Analysis failed",
        threats: []
      };
    }
  }

  async logSecurityEvent(event) {
    try {
      // Store in local storage for analysis
      const eventLog = await chrome.storage.local.get("eventLog") || { eventLog: [] };
      eventLog.eventLog = eventLog.eventLog || [];
      
      // Keep only last 1000 events to prevent storage bloat
      if (eventLog.eventLog.length >= 1000) {
        eventLog.eventLog = eventLog.eventLog.slice(-900);
      }
      
      eventLog.eventLog.push({
        ...event,
        id: crypto.randomUUID(),
        timestamp: event.timestamp || new Date().toISOString()
      });
      
      await chrome.storage.local.set({ eventLog: eventLog.eventLog });
    } catch (error) {
      console.error("Check: Error logging security event:", error);
    }
  }

  async getExtensionStats() {
    try {
      const eventLog = await chrome.storage.local.get("eventLog");
      const events = eventLog.eventLog || [];
      
      const stats = {
        totalEvents: events.length,
        phishingDetected: events.filter(e => e.type === 'phishy-detected').length,
        trustedLogins: events.filter(e => e.type === 'trusted-login-page').length,
        blockedSubmissions: events.filter(e => e.type === 'form_submission' && e.blocked).length,
        lastUpdated: new Date().toISOString()
      };
      
      return stats;
    } catch (error) {
      console.error("Check: Error getting stats:", error);
      return {
        totalEvents: 0,
        phishingDetected: 0,
        trustedLogins: 0,
        blockedSubmissions: 0,
        lastUpdated: new Date().toISOString(),
        error: error.message
      };
    }
  }

  async exportData() {
    try {
      const [eventLog, config, verdicts] = await Promise.all([
        chrome.storage.local.get("eventLog"),
        chrome.storage.sync.get(null),
        chrome.storage.session.get(null)
      ]);
      
      return {
        events: eventLog.eventLog || [],
        configuration: config,
        verdicts: verdicts,
        policy: this.policy,
        exportedAt: new Date().toISOString(),
        version: chrome.runtime.getManifest().version
      };
    } catch (error) {
      console.error("Check: Error exporting data:", error);
      return {
        error: error.message,
        exportedAt: new Date().toISOString()
      };
    }
  }
}

// Initialize the background service worker
const checkBackground = new CheckBackground();

// Initialize when the service worker starts
checkBackground.initialize().catch(error => {
  console.error("Check: Failed to initialize:", error);
});

// Handle service worker lifecycle
self.addEventListener('activate', (event) => {
  console.log('Check: Service worker activated');
  event.waitUntil(checkBackground.initialize());
});

// Export for testing and module use
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { CheckBackground, TRUSTED_ORIGINS, DEFAULT_POLICY };
}
