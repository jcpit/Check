/**
 * Check - Background Service Worker
 * Handles core extension functionality, policy enforcement, and threat detection
 * Enhanced with CyberDrain Microsoft 365 phishing detection
 */

import { ConfigManager } from "./modules/config-manager.js";
import { PolicyManager } from "./modules/policy-manager.js";
import logger from "./utils/logger.js";
import { store as storeLog } from "./utils/background-logger.js";

console.log("Check: Background service worker loaded");
// Initialize logger with default settings before any components use it
logger.init({ level: "info", enabled: true });

// Top-level utility for "respond once" guard
const once = (fn) => {
  let called = false;
  return (...args) => {
    if (!called) {
      called = true;
      fn(...args);
    }
  };
};

// Safe wrapper for chrome.* and fetch operations
async function safe(promise) {
  try {
    return await promise;
  } catch (_) {
    return undefined;
  }
}

// Fetch with timeout and size limits for brand icon fetches
async function fetchWithTimeout(url, ms = 5000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { signal: ctrl.signal });
  } finally {
    clearTimeout(t);
  }
}

class CheckBackground {
  constructor() {
    this.configManager = new ConfigManager();
    this.policyManager = new PolicyManager();
    this.isInitialized = false;
    this.initializationPromise = null;
    this.initializationRetries = 0;
    this.maxInitializationRetries = 3;
    this._retryScheduled = false;
    this._listenersReady = false;

    // CyberDrain integration
    this.policy = null;
    this.extraWhitelist = new Set();
    this.tabHeaders = new Map();
    this.HEADER_CACHE_TTL = 5 * 60 * 1000; // 5 minutes
    this.MAX_HEADER_CACHE_ENTRIES = 100;

    // Error recovery
    this.lastError = null;
    this.errorCount = 0;
    this.maxErrors = 10;

    // Tab event management
    this.tabQueues = new Map(); // tabId -> Promise
    this.tabDebounce = new Map(); // tabId -> timeoutId

    // Storage batching
    this.pendingLocal = { accessLogs: [], securityEvents: [] };
    this.flushScheduled = false;

    // Profile information
    this.profileInfo = null;

    // Register core listeners that must work even if init fails
    this.setupCoreListeners();

    // Set up message handlers immediately to handle early connections
    // Reduce logging verbosity for service worker restarts
    if (!globalThis.checkBackgroundInstance) {
      logger.log("CheckBackground.constructor: registering message handlers");
    }
    this.setupMessageHandlers();
    if (!globalThis.checkBackgroundInstance) {
      logger.log("CheckBackground.constructor: message handlers registered");
    }
  }

  setupCoreListeners() {
    // Register alarm listeners even if init fails
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === "check:init-retry") {
        this._retryScheduled = false;
        this.initialize().catch(() => {});
      } else if (alarm.name === "check:flush") {
        this.flushScheduled = false;
        this._doFlush().catch(() => {});
      }
    });
  }

  setupMessageHandlers() {
    // Handle messages from content scripts and popups with "respond once" guard
    chrome.runtime.onMessage.addListener((msg, sender, sendResponseRaw) => {
      const sendResponse = once(sendResponseRaw);
      (async () => {
        await this.handleMessage(msg, sender, sendResponse);
      })().catch((e) => {
        try {
          sendResponse({ success: false, error: e?.message || String(e) });
        } catch {}
      });
      return true; // Keep message channel open for async responses
    });
  }

  async initialize() {
    // Prevent duplicate initialization during service worker restarts
    if (this.isInitialized) {
      return;
    }

    // Harden initialization flow - prevent parallel retries
    if (this.initializationPromise || this._retryScheduled) {
      return this.initializationPromise;
    }

    this.initializationPromise = this._doInitialize();
    return this.initializationPromise;
  }

  async _doInitialize() {
    // Only log initialization start if this is the first instance
    const isFirstInstance = !globalThis.checkBackgroundInstance;
    if (isFirstInstance) {
      logger.log("CheckBackground.initialize: start");
    }

    try {
      // Load configuration and initialize logger based on settings
      const config = await this.configManager.loadConfig();
      logger.init({
        level: "info",
        enabled: true,
      });

      // Load policies
      await this.policyManager.loadPolicies();

      await this.refreshPolicy();

      // Load profile information
      await this.loadProfileInformation();

      this.setupEventListeners();
      this.isInitialized = true;
      this.initializationRetries = 0; // Reset retry count on success
      this.errorCount = 0; // Reset error count on success

      if (isFirstInstance) {
        logger.log("CheckBackground.initialize: complete");
      }
    } catch (error) {
      logger.error("CheckBackground.initialize: error", error);
      this.lastError = error;
      this.initializationRetries++;

      // Reset promise to allow retry
      this.initializationPromise = null;

      // If we haven't exceeded max retries, schedule a retry
      if (this.initializationRetries < this.maxInitializationRetries) {
        logger.log(
          `CheckBackground.initialize: scheduling retry ${this.initializationRetries}/${this.maxInitializationRetries}`
        );
        // Replace setTimeout with chrome.alarms for service worker safety
        this._retryScheduled = true;
        chrome.alarms.create("check:init-retry", {
          when: Date.now() + 1000 * this.initializationRetries,
        });
      } else {
        logger.error(
          "CheckBackground.initialize: max retries exceeded, entering fallback mode"
        );
        this.enterFallbackMode();
      }

      throw error;
    }
  }

  enterFallbackMode() {
    // Set up minimal functionality when initialization fails
    this.isInitialized = false;
    this.config = this.configManager.getDefaultConfig();
    this.policy = this.getDefaultPolicy();

    logger.log(
      "CheckBackground: entering fallback mode with minimal functionality"
    );
  }

  getDefaultPolicy() {
    return {
      BrandingName: "CyberDrain Check Phishing Protection",
      BrandingImage: "",
      ExtraWhitelist: [],
      CIPPReportingServer: "",
      AlertWhenLogon: true,
      ValidPageBadgeImage: "",
      StrictResourceAudit: true,
      RequireMicrosoftAction: true,
      EnableValidPageBadge: false,
    };
  }

  // CyberDrain integration - Policy management with defensive refresh
  async refreshPolicy() {
    try {
      // Load policy from policy manager
      const policyData = await this.policyManager.getPolicies();
      this.policy = policyData || this.getDefaultPolicy();
      this.extraWhitelist = new Set(
        (this.policy?.ExtraWhitelist || [])
          .map((s) => this.urlOrigin(s))
          .filter(Boolean)
      );
      await this.applyBrandingToAction();
    } catch (error) {
      logger.error(
        "CheckBackground.refreshPolicy: failed, using defaults",
        error
      );
      this.policy = this.getDefaultPolicy();
      this.extraWhitelist = new Set();
    }
  }

  urlOrigin(u) {
    try {
      return new URL(u).origin.toLowerCase();
    } catch {
      return "";
    }
  }

  // CyberDrain integration - Verdict determination
  verdictForUrl(raw) {
    const origin = this.urlOrigin(raw);
    // Load trusted origins from policy or use defaults
    const trustedOrigins =
      this.policy?.trustedOrigins ||
      new Set([
        "https://login.microsoftonline.com",
        "https://login.microsoft.com",
        "https://account.microsoft.com",
      ]);
    if (trustedOrigins.has && trustedOrigins.has(origin)) return "trusted";
    if (this.extraWhitelist.has(origin)) return "trusted-extra";
    return "not-evaluated"; // Changed from "unknown" - don't show badge until we know it's relevant
  }

  // CyberDrain integration - Badge management with safe wrappers
  async setBadge(tabId, verdict) {
    const map = {
      trusted: { text: "MS", color: "#0a5" },
      "trusted-extra": { text: "OK", color: "#0a5" },
      phishy: { text: "!", color: "#d33" },
      "ms-login-unknown": { text: "?", color: "#f90" }, // Yellow/orange for MS login on unknown domain
      "not-evaluated": { text: "", color: "#000" }, // No badge for irrelevant pages
    };
    const cfg = map[verdict] || map["not-evaluated"];
    await safe(chrome.action.setBadgeText({ tabId, text: cfg.text }));
    if (cfg.text) {
      // Only set background color if there's text to display
      await safe(
        chrome.action.setBadgeBackgroundColor({ tabId, color: cfg.color })
      );
    } else {
      // Clear badge entirely for non-relevant pages
      await safe(chrome.action.setBadgeText({ tabId, text: "" }));
    }
  }

  // CyberDrain integration - Notify tab to show valid badge with safe wrappers
  async showValidBadge(tabId) {
    const config = (await safe(this.configManager.getConfig())) || {};
    const enabled =
      this.policy?.EnableValidPageBadge ||
      config?.showValidPageBadge ||
      config?.enableValidPageBadge;
    if (enabled) {
      await safe(
        chrome.tabs.sendMessage(tabId, {
          type: "SHOW_VALID_BADGE",
          image: this.policy?.ValidPageBadgeImage,
          branding: this.policy?.BrandingName,
        })
      );
    }
  }

  // CyberDrain integration - Apply branding to extension action with guards and timeouts
  async applyBrandingToAction() {
    try {
      // Load branding from storage first, then fallback to policy
      const storageResult = await safe(
        chrome.storage.local.get(["brandingConfig"])
      );
      const brandingConfig = storageResult?.brandingConfig || {};

      // Determine title from storage or policy
      const title =
        brandingConfig.productName ||
        this.policy?.BrandingName ||
        this.getDefaultPolicy().BrandingName;

      // Title with safe wrapper
      await safe(chrome.action.setTitle({ title }));
      console.log("Extension title set to:", title);

      // Determine logo URL from storage or policy
      const logoUrl = brandingConfig.logoUrl || this.policy?.BrandingImage;

      // Icon (optional) with platform feature guards and size limits
      if (
        logoUrl &&
        globalThis.OffscreenCanvas &&
        globalThis.createImageBitmap
      ) {
        try {
          console.log("Loading custom extension icon from:", logoUrl);

          // Handle both relative and absolute URLs
          const iconUrl = logoUrl.startsWith("http")
            ? logoUrl
            : chrome.runtime.getURL(logoUrl);

          const img = await fetchWithTimeout(iconUrl);
          if (!img.ok) {
            console.warn("Failed to fetch custom icon:", img.status);
            return;
          }

          const blob = await img.blob();
          if (blob.size > 1_000_000) {
            console.warn("Custom icon too large, skipping");
            return; // Skip huge icons
          }

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
          await safe(chrome.action.setIcon({ imageData: images }));
          console.log("Custom extension icon applied successfully");
        } catch (e) {
          console.warn("Failed to apply custom icon:", e.message);
          // ignore icon errors, just set title
        }
      } else {
        console.log(
          "No custom logo configured or OffscreenCanvas not available"
        );
      }
    } catch (error) {
      console.error("Failed to apply branding to action:", error);
    }
  }

  // CyberDrain integration - Send event to reporting server with timeout and proper POST
  async sendEvent(evt) {
    if (!this.policy?.CIPPReportingServer) return;
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 5000);
      const res = await fetch(
        this.policy.CIPPReportingServer.replace(/\/+$/, "") +
          "/events/cyberdrain-phish",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            ts: new Date().toISOString(),
            ua: navigator.userAgent,
            ...evt,
          }),
          signal: ctrl.signal,
        }
      );
      clearTimeout(t);
      await res.text();
    } catch {
      /* best-effort */
    }
  }

  setupEventListeners() {
    // Prevent duplicate listener registration
    if (this._listenersReady) return;
    this._listenersReady = true;

    // Handle extension installation/startup
    chrome.runtime.onStartup.addListener(() => {
      this.handleStartup();
    });

    chrome.runtime.onInstalled.addListener((details) => {
      this.handleInstalled(details);
    });

    // Handle tab updates with debouncing and serialization
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      this.debouncePerTab(tabId, () => {
        this.enqueue(tabId, async () => {
          await this.handleTabUpdate(tabId, changeInfo, tab);
        });
      });
    });

    // CyberDrain integration - Handle tab activation for badge updates with safe wrappers
    chrome.tabs.onActivated.addListener(async ({ tabId }) => {
      const data = await safe(chrome.storage.session.get("verdict:" + tabId));
      const verdict = data?.["verdict:" + tabId]?.verdict || "not-evaluated";
      this.setBadge(tabId, verdict);
    });

    // Handle storage changes (for enterprise policy updates)
    chrome.storage.onChanged.addListener((changes, namespace) => {
      this.handleStorageChange(changes, namespace);
    });

    // Handle web navigation events with non-blocking heavy work
    chrome.webNavigation?.onCompleted?.addListener((details) => {
      if (details.frameId === 0) {
        // Log navigation for audit purposes
        queueMicrotask(() =>
          this.logUrlAccess(details.url, details.tabId).catch(() => {})
        );
      }
    });

    // Capture response headers with robust caching
    chrome.webRequest.onHeadersReceived.addListener(
      (details) => {
        if (details.tabId < 0 || !details.responseHeaders) return;

        try {
          // Prune before insert to prevent unbounded growth
          if (this.tabHeaders.size >= this.MAX_HEADER_CACHE_ENTRIES) {
            let oldestId = null;
            let oldestTs = Infinity;
            for (const [id, data] of this.tabHeaders) {
              if (data.ts < oldestTs) {
                oldestTs = data.ts;
                oldestId = id;
              }
            }
            if (oldestId !== null) this.tabHeaders.delete(oldestId);
          }

          const headers = {};
          for (const h of details.responseHeaders || []) {
            headers[h.name.toLowerCase()] = h.value;
          }
          this.tabHeaders.set(details.tabId, { headers, ts: Date.now() });
        } catch (error) {
          // Ignore header cache errors
        }
      },
      { urls: ["<all_urls>"], types: ["main_frame"] },
      ["responseHeaders"]
    );

    chrome.tabs.onRemoved.addListener((tabId) => {
      this.tabHeaders.delete(tabId);
      this.tabQueues.delete(tabId);
      clearTimeout(this.tabDebounce.get(tabId));
      this.tabDebounce.delete(tabId);
    });
  }

  // Tab event management utilities
  enqueue(tabId, task) {
    const prev = this.tabQueues.get(tabId) || Promise.resolve();
    const next = prev.finally(task).catch(() => {}); // keep chain alive
    this.tabQueues.set(tabId, next);
  }

  debouncePerTab(tabId, fn, ms = 150) {
    clearTimeout(this.tabDebounce.get(tabId));
    const id = setTimeout(fn, ms);
    this.tabDebounce.set(tabId, id);
  }

  // Storage batching utilities with chrome.alarms for service worker safety
  scheduleFlush() {
    if (this.flushScheduled) return;
    this.flushScheduled = true;
    chrome.alarms.create("check:flush", { when: Date.now() + 2000 });
  }

  async _doFlush() {
    const cur =
      (await safe(
        chrome.storage.local.get(["accessLogs", "securityEvents"])
      )) || {};
    const access = (cur.accessLogs || [])
      .concat(this.pendingLocal.accessLogs)
      .slice(-1000);
    const sec = (cur.securityEvents || [])
      .concat(this.pendingLocal.securityEvents)
      .slice(-500);
    this.pendingLocal.accessLogs.length = 0;
    this.pendingLocal.securityEvents.length = 0;
    const payload = { accessLogs: access, securityEvents: sec };
    if (JSON.stringify(payload).length <= 4 * 1024 * 1024) {
      await safe(chrome.storage.local.set(payload));
    }
  }

  async handleStartup() {
    logger.log("Check: Extension startup detected");
    const config = (await safe(this.configManager.refreshConfig())) || {};
    logger.init({
      level: "info",
      enabled: true,
    });
  }

  async handleInstalled(details) {
    logger.log("Check: Extension installed/updated:", details.reason);

    if (details.reason === "install") {
      // Set default configuration
      await safe(this.configManager.setDefaultConfig());

      // Open options page for initial setup
      await safe(
        chrome.tabs.create({
          url: chrome.runtime.getURL("options/options.html"),
        })
      );
    } else if (details.reason === "update") {
      // Handle extension updates
      await safe(this.configManager.migrateConfig(details.previousVersion));
    }
  }

  async handleTabUpdate(tabId, changeInfo, tab) {
    if (!this.isInitialized) return;

    try {
      // Ignore stale onUpdated payloads after debounce (tab might have navigated again)
      const latest = await safe(chrome.tabs.get(tabId));
      if (!latest || latest.url !== (tab?.url || changeInfo.url)) return; // stale event

      // CyberDrain integration - Handle URL changes and set badges
      if (changeInfo.status === "complete" && tab?.url) {
        const verdict = this.verdictForUrl(tab.url);
        await safe(
          chrome.storage.session.set({
            ["verdict:" + tabId]: { verdict, url: tab.url },
          })
        );
        this.setBadge(tabId, verdict);

        if (verdict === "trusted") {
          // "Valid page" sighting - fire-and-log pattern for non-critical work
          queueMicrotask(() =>
            this.sendEvent({ type: "trusted-login-page", url: tab.url }).catch(
              () => {}
            )
          );
          queueMicrotask(() => this.showValidBadge(tabId).catch(() => {}));
        }
      }

      if (!changeInfo.url) return;

      // Simple URL analysis without DetectionEngine
      const shouldInjectContentScript = this.shouldInjectContentScript(
        changeInfo.url
      );

      if (shouldInjectContentScript) {
        await this.injectContentScript(tabId);
      }

      // Log URL access for audit purposes - fire-and-log pattern
      queueMicrotask(() => this.logUrlAccess(tab.url, tabId).catch(() => {}));
    } catch (error) {
      logger.error("Check: Error handling tab update:", error);
    }
  }

  async handleMessage(message, sender, sendResponse) {
    try {
      // Handle both message.type and message.action for compatibility
      const messageType = message.type || message.action;

      // Always return immediately for "ping" and non-critical queries
      if (messageType === "ping") {
        sendResponse({
          success: true,
          message: "Check background script is running",
          timestamp: new Date().toISOString(),
          initialized: this.isInitialized,
          fallbackMode: !this.isInitialized,
          errorCount: this.errorCount,
          lastError: this.lastError?.message || null,
        });
        return;
      }

      // Ensure initialization before handling most messages
      if (!this.isInitialized) {
        try {
          await this.initialize();
        } catch (error) {
          logger.warn(
            "CheckBackground.handleMessage: initialization failed, using fallback",
            error
          );
          // Continue with fallback mode
        }
      }

      switch (messageType) {
        // CyberDrain integration - Handle phishing detection
        case "FLAG_PHISHY":
          if (sender.tab?.id) {
            const tabId = sender.tab.id;
            await safe(
              chrome.storage.session.set({
                ["verdict:" + tabId]: {
                  verdict: "phishy",
                  url: sender.tab.url,
                },
              })
            );
            this.setBadge(tabId, "phishy");
            sendResponse({ ok: true });
            // Fire-and-log pattern for non-critical work
            queueMicrotask(() =>
              this.sendEvent({
                type: "phishy-detected",
                url: sender.tab.url,
                reason: message.reason || "heuristic",
              }).catch(() => {})
            );
          }
          break;

        case "FLAG_TRUSTED_BY_REFERRER":
          if (sender.tab?.id) {
            const tabId = sender.tab.id;
            await safe(
              chrome.storage.session.set({
                ["verdict:" + tabId]: {
                  verdict: "trusted",
                  url: sender.tab.url,
                  by: "referrer",
                },
              })
            );
            this.setBadge(tabId, "trusted");
            sendResponse({ ok: true });
            // Fire-and-log pattern for non-critical work
            queueMicrotask(() => this.showValidBadge(tabId).catch(() => {}));
            if (this.policy?.AlertWhenLogon) {
              queueMicrotask(() =>
                this.sendEvent({
                  type: "user-logged-on",
                  url: sender.tab.url,
                  by: "referrer",
                }).catch(() => {})
              );
            }
          }
          break;

        case "FLAG_MS_LOGIN_ON_UNKNOWN_DOMAIN":
          if (sender.tab?.id) {
            const tabId = sender.tab.id;
            await safe(
              chrome.storage.session.set({
                ["verdict:" + tabId]: {
                  verdict: "ms-login-unknown",
                  url: sender.tab.url,
                  origin: message.origin,
                  redirectTo: message.redirectTo,
                },
              })
            );
            this.setBadge(tabId, "ms-login-unknown");
            sendResponse({ ok: true });
            // Log Microsoft login detection on unknown domain
            queueMicrotask(() =>
              this.sendEvent({
                type: "ms-login-unknown-domain",
                url: sender.tab.url,
                origin: message.origin,
                redirectTo: message.redirectTo,
                reason: "Microsoft login page detected on non-trusted domain",
              }).catch(() => {})
            );
          }
          break;

        case "REQUEST_POLICY":
          sendResponse({ policy: this.policy });
          break;

        case "ANALYZE_CONTENT_WITH_RULES":
          // DetectionEngine removed - content analysis now handled by content script
          sendResponse({
            success: false,
            error: "Content analysis moved to content script",
          });
          break;

        case "log":
          if (message.level && message.message) {
            await storeLog(message.level, message.message);
          }
          sendResponse({ success: true });
          break;

        case "protection_event":
          // Handle protection events from content script
          try {
            if (message.data) {
              // Use existing logEvent method to ensure proper storage
              await this.logEvent(message.data, sender.tab?.id);
              sendResponse({ success: true });
            } else {
              sendResponse({ success: false, error: "No event data provided" });
            }
          } catch (error) {
            logger.error("Failed to handle protection event:", error);
            sendResponse({ success: false, error: error.message });
          }
          break;

        case "GET_PAGE_HEADERS":
          try {
            const data =
              sender.tab?.id != null
                ? this.tabHeaders.get(sender.tab.id)
                : null;
            if (data && Date.now() - data.ts > this.HEADER_CACHE_TTL) {
              this.tabHeaders.delete(sender.tab.id);
              sendResponse({ success: true, headers: {} });
            } else {
              sendResponse({ success: true, headers: data?.headers || {} });
            }
          } catch (error) {
            sendResponse({ success: false, error: error.message });
          }
          break;

        case "testDetectionEngine":
          // DetectionEngine removed - return simple status
          sendResponse({
            success: true,
            message: "Detection engine functionality moved to content script",
            rulesLoaded: 0,
            engineInitialized: false,
            testsRun: 0,
          });
          break;

        case "testConfiguration":
          try {
            const configTest = {
              configModules: [],
              initialized: this.isInitialized,
            };

            if (this.configManager)
              configTest.configModules.push("ConfigManager");
            // DetectionEngine removed
            if (this.policyManager)
              configTest.configModules.push("PolicyManager");

            sendResponse({
              success: true,
              ...configTest,
            });
          } catch (error) {
            sendResponse({
              success: false,
              error: error.message,
            });
          }
          break;

        case "URL_ANALYSIS_REQUEST":
          // Get detection results from content script
          try {
            if (typeof message.url !== "string") {
              sendResponse({ success: false, error: "Invalid url" });
              return;
            }

            // Check if protection is enabled
            const config = await this.configManager.getConfig();
            const isProtectionEnabled = config?.enablePageBlocking !== false;

            // Try to get detection results from content script
            try {
              const tabs = await chrome.tabs.query({
                active: true,
                currentWindow: true,
              });
              if (tabs.length > 0) {
                const tabId = tabs[0].id;

                // Ask content script for its detection results
                const contentResponse = await chrome.tabs.sendMessage(tabId, {
                  type: "GET_DETECTION_RESULTS",
                });

                if (contentResponse && contentResponse.success) {
                  // Use content script's detection results
                  const analysis = {
                    url: message.url,
                    verdict:
                      contentResponse.verdict ||
                      this.verdictForUrl(message.url),
                    isBlocked: contentResponse.isBlocked || false,
                    isSuspicious: contentResponse.isSuspicious || false,
                    threats: contentResponse.threats || [],
                    reason:
                      contentResponse.reason || "Analysis from content script",
                    protectionEnabled: isProtectionEnabled,
                    timestamp: new Date().toISOString(),
                  };

                  sendResponse({ success: true, analysis });
                  return;
                }
              }
            } catch (contentError) {
              console.log(
                "Check: Content script not available, using basic analysis"
              );
            }

            // Fallback to basic analysis if content script not available
            const analysis = {
              url: message.url,
              verdict: this.verdictForUrl(message.url),
              isBlocked: false,
              isSuspicious: false,
              threats: [],
              reason: "Basic analysis - content script not available",
              protectionEnabled: isProtectionEnabled,
              timestamp: new Date().toISOString(),
            };

            sendResponse({ success: true, analysis });
          } catch (error) {
            sendResponse({ success: false, error: error.message });
          }
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

        case "CONTENT_MANIPULATION_REQUEST":
          const manipulationAllowed =
            await this.policyManager.checkContentManipulation(message.domain);
          sendResponse({ success: true, allowed: manipulationAllowed });
          break;

        case "LOG_EVENT":
          // Validate event input
          if (!message.event || typeof message.event !== "object") {
            sendResponse({ success: false, error: "Invalid event" });
            return;
          }
          await this.logEvent(message.event, sender.tab?.id);
          sendResponse({ success: true });
          break;

        case "GET_CONFIG":
          try {
            const config = await this.configManager.getConfig();
            sendResponse({ success: true, config });
          } catch (error) {
            logger.error("Check: Failed to get config:", error);
            sendResponse({ success: false, error: error.message });
          }
          break;

        case "UPDATE_CONFIG":
          try {
            await this.configManager.updateConfig(message.config);
            sendResponse({ success: true });
          } catch (error) {
            logger.error("Check: Failed to update config:", error);
            sendResponse({ success: false, error: error.message });
          }
          break;

        case "UPDATE_BRANDING":
          try {
            // Apply branding changes immediately
            await this.applyBrandingToAction();
            sendResponse({ success: true });
          } catch (error) {
            logger.error("Check: Failed to update branding:", error);
            sendResponse({ success: false, error: error.message });
          }
          break;

        case "TEST_DETECTION_RULES":
          const testResults = await this.testDetectionRules(message.testData);
          sendResponse({ success: true, results: testResults });
          break;

        case "VALIDATE_DETECTION_ENGINE":
          // DetectionEngine removed - return simple status
          sendResponse({
            success: true,
            validation: {
              message: "Detection engine functionality moved to content script",
              engineInitialized: false,
              detectionEngineStatus: "removed",
            },
          });
          break;

        case "GET_PROFILE_INFO":
          try {
            const profileInfo = await this.getCurrentProfile();
            sendResponse({ success: true, profile: profileInfo });
          } catch (error) {
            logger.error("Check: Failed to get profile info:", error);
            sendResponse({ success: false, error: error.message });
          }
          break;

        case "REFRESH_PROFILE_INFO":
          try {
            const profileInfo = await this.refreshProfileInformation();
            sendResponse({ success: true, profile: profileInfo });
          } catch (error) {
            logger.error("Check: Failed to refresh profile info:", error);
            sendResponse({ success: false, error: error.message });
          }
          break;

        case "RUN_COMPREHENSIVE_TEST":
          const comprehensiveResults = await this.runComprehensiveTest();
          sendResponse({ success: true, tests: comprehensiveResults });
          break;

        default:
          sendResponse({ success: false, error: "Unknown message type" });
      }
    } catch (error) {
      logger.error("Check: Error handling message:", error);
      this.errorCount++;

      // If we've had too many errors, try to reinitialize
      if (this.errorCount > this.maxErrors) {
        logger.warn(
          "CheckBackground: too many errors, attempting reinitialization"
        );
        this.errorCount = 0;
        this.isInitialized = false;
        this.initializationPromise = null;
        this.initialize().catch((err) => {
          logger.error("CheckBackground: reinitialization failed", err);
        });
      }

      sendResponse({ success: false, error: error.message });
    }
  }

  async handleStorageChange(changes, namespace) {
    if (namespace === "managed") {
      // Enterprise policy changes
      logger.log("Check: Enterprise policy updated");
      await safe(this.policyManager.loadPolicies());
      const config = (await safe(this.configManager.refreshConfig())) || {};
      logger.init({
        level: "info",
        enabled: true,
      });
      // CyberDrain integration - Refresh policy with defensive handling
      await this.refreshPolicy();
    }
  }

  async injectContentScript(tabId) {
    try {
      // Shield content script injection - check if tab exists
      const exists = await safe(chrome.tabs.get(tabId));
      if (!exists) return; // tab gone

      const url = exists?.url;
      if (!url) {
        logger.warn("Check: No URL for tab", tabId);
        return;
      }

      let protocol;
      try {
        protocol = new URL(url).protocol;
      } catch {
        logger.warn("Check: Invalid URL, skipping content script:", url);
        return;
      }

      const disallowed = [
        "chrome:",
        "edge:",
        "about:",
        "chrome-extension:",
        "moz-extension:",
        "devtools:",
      ];

      if (disallowed.includes(protocol)) {
        logger.warn(
          "Check: Skipping content script injection for disallowed URL:",
          url
        );
        return;
      }

      await safe(
        chrome.scripting.executeScript({
          target: { tabId },
          files: ["scripts/content.js"],
        })
      );
    } catch (error) {
      logger.error("Check: Failed to inject content script:", error);
    }
  }

  async logUrlAccess(url, tabId) {
    const config = (await safe(this.configManager.getConfig())) || {};

    // Only log if debug logging is enabled or if this is a significant event
    if (!config.enableDebugLogging) {
      // Skip logging routine page scans to avoid log bloat
      return;
    }

    // Get current profile information for logging context
    const profileInfo = await this.getCurrentProfile();

    const logEntry = {
      timestamp: new Date().toISOString(),
      url,
      tabId,
      type: "url_access",
      event: {
        type: "page_scanned",
        url: url,
        threatDetected: false,
      },
      profile: this.sanitizeProfileForLogging(profileInfo),
    };

    // Use batched storage writes
    this.pendingLocal.accessLogs.push(logEntry);
    this.scheduleFlush();
  }

  async logEvent(event, tabId) {
    // Get current profile information for logging context
    const profileInfo = await this.getCurrentProfile();

    const logEntry = {
      timestamp: new Date().toISOString(),
      event: this.enhanceEventForLogging(event),
      tabId,
      type: "security_event",
      profile: this.sanitizeProfileForLogging(profileInfo),
    };

    // Gate noisy logs behind debug config
    const config = await safe(this.configManager.getConfig());
    if (config?.enableDebugLogging) {
      logger.log("Check: Security Event:", logEntry);
    }

    // Use batched storage writes
    this.pendingLocal.securityEvents.push(logEntry);
    this.scheduleFlush();

    // Send to CIPP if enabled
    await this.sendToCipp(logEntry, config);
  }

  enhanceEventForLogging(event) {
    const enhancedEvent = { ...event };

    // Define threat events that should have URLs defanged
    const threatEvents = new Set([
      "content_threat_detected",
      "threat_detected",
      "blocked_page_viewed",
      "threat_blocked",
      "threat_detected_no_action",
    ]);

    // Define legitimate events that should NEVER have URLs defanged
    const legitimateEvents = new Set([
      "legitimate_access",
      "url_access",
      "page_scanned",
      "trusted-login-page",
      "user-logged-on",
      "ms-login-unknown-domain",
    ]);

    // Only defang URLs for confirmed threat events
    const shouldDefangUrl =
      event.url &&
      threatEvents.has(event.type) &&
      !legitimateEvents.has(event.type);

    // Debug logging to track URL defanging decisions
    if (event.url) {
      console.log(
        `[URL Defanging] Event type: ${event.type}, shouldDefang: ${shouldDefangUrl}, URL: ${event.url}`
      );
    }

    if (shouldDefangUrl) {
      enhancedEvent.url = this.defangUrl(event.url);
      enhancedEvent.threatDetected = true;
    }

    // Add more context for different event types
    switch (event.type) {
      case "url_access":
        enhancedEvent.action = event.action || "allowed";
        enhancedEvent.threatLevel = event.threatLevel || "none";
        break;
      case "content_threat_detected":
        enhancedEvent.action = event.action || "blocked";
        enhancedEvent.threatLevel = event.threatLevel || "high";
        enhancedEvent.threatDetected = true;
        break;
      case "threat_detected":
        enhancedEvent.action = event.action || "blocked";
        enhancedEvent.threatLevel = event.threatLevel || "high";
        enhancedEvent.threatDetected = true;
        break;
      case "form_submission":
        enhancedEvent.action = event.action || "blocked";
        enhancedEvent.threatLevel = event.threatLevel || "medium";
        break;
      case "script_injection":
        enhancedEvent.action = event.action || "injected";
        enhancedEvent.threatLevel = event.threatLevel || "info";
        break;
      case "page_scanned":
        enhancedEvent.action = event.action || "scanned";
        enhancedEvent.threatLevel = event.threatLevel || "none";
        break;
      case "blocked_page_viewed":
        enhancedEvent.action = event.action || "viewed";
        enhancedEvent.threatLevel = event.threatLevel || "high";
        enhancedEvent.threatDetected = true;
        break;
      case "threat_blocked":
      case "threat_detected_no_action":
        enhancedEvent.action =
          event.type === "threat_blocked" ? "blocked" : "detected";
        enhancedEvent.threatLevel = event.severity || "high";
        enhancedEvent.threatDetected = true;
        break;
      case "legitimate_access":
        enhancedEvent.action = event.action || "allowed";
        enhancedEvent.threatLevel = event.threatLevel || "none";
        break;
      default:
        if (!enhancedEvent.action) enhancedEvent.action = "logged";
        if (!enhancedEvent.threatLevel) enhancedEvent.threatLevel = "info";
    }

    return enhancedEvent;
  }

  defangUrl(url) {
    try {
      // Check if URL is already defanged to prevent double defanging
      if (url.includes("[:]")) {
        return url; // Already defanged, return as-is
      }

      // Defang URLs by only replacing colons to prevent clickability while keeping readability
      return url.replace(/:/g, "[:]");
    } catch (e) {
      return url; // Return original if defanging fails
    }
  }

  // Detection Rules Testing Methods - simplified without DetectionEngine
  async testDetectionRules(testData = null) {
    const results = {
      timestamp: new Date().toISOString(),
      engineStatus: this.isInitialized,
      rulesLoaded: false, // DetectionEngine removed
      message: "Detection testing moved to content script",
      testResults: [],
      summary: {
        total: 0,
        passed: 0,
        failed: 0,
        warnings: 0,
      },
    };

    return results;
  }

  // Test methods removed - DetectionEngine functionality moved to content script

  // Test methods removed - DetectionEngine functionality moved to content script
  async runComprehensiveTest() {
    return {
      timestamp: new Date().toISOString(),
      message: "Comprehensive testing moved to content script",
      testSuites: [],
    };
  }

  // Helper method for content script injection decision
  shouldInjectContentScript(url) {
    try {
      const urlObj = new URL(url);
      const protocol = urlObj.protocol;

      // Skip disallowed protocols
      const disallowed = [
        "chrome:",
        "edge:",
        "about:",
        "chrome-extension:",
        "moz-extension:",
        "devtools:",
      ];

      if (disallowed.includes(protocol)) {
        return false;
      }

      // Inject content script for all other URLs
      return true;
    } catch (error) {
      logger.warn("Check: Invalid URL for content script injection:", url);
      return false;
    }
  }

  validateComponents() {
    return {
      configManager: this.configManager ? "loaded" : "not_loaded",
      policyManager: this.policyManager ? "loaded" : "not_loaded",
      // DetectionEngine removed
    };
  }

  // Profile Information Management
  async loadProfileInformation() {
    try {
      this.profileInfo = {
        profileId: await this.getOrCreateProfileId(),
        isManaged: await this.checkManagedEnvironment(),
        userInfo: await this.getUserInfo(),
        browserInfo: await this.getBrowserInfo(),
        timestamp: new Date().toISOString(),
      };

      logger.log("Profile information loaded:", this.profileInfo);

      // Store profile info for access by other parts of the extension
      await chrome.storage.local.set({
        currentProfile: this.profileInfo,
      });
    } catch (error) {
      logger.error("Failed to load profile information:", error);
      this.profileInfo = {
        profileId: "unknown",
        isManaged: false,
        userInfo: null,
        browserInfo: null,
        timestamp: new Date().toISOString(),
        error: error.message,
      };
    }
  }

  async getOrCreateProfileId() {
    try {
      const result = await chrome.storage.local.get(["profileId"]);

      if (!result.profileId) {
        // Generate a unique identifier for this profile
        const profileId = crypto.randomUUID();
        await chrome.storage.local.set({ profileId });
        logger.log("Generated new profile ID:", profileId);
        return profileId;
      }

      logger.log("Using existing profile ID:", result.profileId);
      return result.profileId;
    } catch (error) {
      logger.error("Failed to get/create profile ID:", error);
      return "fallback-" + Date.now();
    }
  }

  async checkManagedEnvironment() {
    return new Promise((resolve) => {
      try {
        chrome.storage.managed.get(null, (policies) => {
          if (chrome.runtime.lastError) {
            resolve(false);
          } else {
            const isManaged = policies && Object.keys(policies).length > 0;
            if (isManaged) {
              logger.log(
                "Detected managed environment with policies:",
                policies
              );
            }
            resolve(isManaged);
          }
        });
      } catch (error) {
        logger.error("Error checking managed environment:", error);
        resolve(false);
      }
    });
  }

  async getUserInfo() {
    // Note: This requires "identity" and "identity.email" permissions
    // Works with Google accounts in Chrome and Microsoft accounts in Edge
    return new Promise((resolve) => {
      try {
        if (chrome.identity && chrome.identity.getProfileUserInfo) {
          chrome.identity.getProfileUserInfo(
            { accountStatus: "ANY" },
            (userInfo) => {
              if (chrome.runtime.lastError) {
                logger.log("Chrome identity error:", chrome.runtime.lastError);
                resolve(null);
              } else if (!userInfo) {
                logger.log("No user info returned from chrome.identity");
                resolve(null);
              } else if (!userInfo.email) {
                logger.log("User info available but no email:", userInfo);
                // Return what we have even without email
                resolve({
                  email: null,
                  id: userInfo.id || null,
                  emailNotAvailable: true,
                  reason: "User not signed in or email permission not granted",
                });
              } else {
                // Detect account type based on email domain
                const email = userInfo.email;
                let accountType = "personal";
                let provider = "unknown";

                if (email.includes("@")) {
                  const domain = email.split("@")[1].toLowerCase();
                  if (
                    domain.includes("outlook.com") ||
                    domain.includes("hotmail.com") ||
                    domain.includes("live.com")
                  ) {
                    accountType = "microsoft-personal";
                    provider = "microsoft";
                  } else if (
                    domain.includes("gmail.com") ||
                    domain.includes("googlemail.com")
                  ) {
                    accountType = "google-personal";
                    provider = "google";
                  } else {
                    accountType = "work-school";
                    provider = domain.includes(".onmicrosoft.com")
                      ? "microsoft"
                      : "unknown";
                  }
                }

                logger.log("User info retrieved successfully:", {
                  email: userInfo.email,
                  id: userInfo.id,
                  accountType: accountType,
                  provider: provider,
                });

                resolve({
                  email: userInfo.email,
                  id: userInfo.id,
                  accountType: accountType,
                  provider: provider,
                });
              }
            }
          );
        } else {
          logger.log("chrome.identity API not available");
          resolve(null);
        }
      } catch (error) {
        logger.error("Error getting user info:", error);
        resolve(null);
      }
    });
  }

  async getBrowserInfo() {
    try {
      const userAgent = navigator.userAgent;

      // Detect specific Chromium variant
      let browserType = "chrome"; // default
      let browserVersion = "unknown";

      if (userAgent.includes("Edg/")) {
        browserType = "edge";
        const edgeMatch = userAgent.match(/Edg\/([\d.]+)/);
        browserVersion = edgeMatch ? edgeMatch[1] : "unknown";
      } else if (userAgent.includes("Chrome/")) {
        browserType = "chrome";
        const chromeMatch = userAgent.match(/Chrome\/([\d.]+)/);
        browserVersion = chromeMatch ? chromeMatch[1] : "unknown";
      } else if (userAgent.includes("Chromium/")) {
        browserType = "chromium";
        const chromiumMatch = userAgent.match(/Chromium\/([\d.]+)/);
        browserVersion = chromiumMatch ? chromiumMatch[1] : "unknown";
      }

      const info = {
        userAgent: userAgent,
        browserType: browserType,
        browserVersion: browserVersion,
        platform: navigator.platform,
        language: navigator.language,
        cookieEnabled: navigator.cookieEnabled,
        extensionId: chrome.runtime.id,
        timestamp: new Date().toISOString(),
      };

      // Get extension installation info if management permission available
      if (chrome.management && chrome.management.getSelf) {
        const extensionInfo = await new Promise((resolve) => {
          chrome.management.getSelf((info) => {
            if (chrome.runtime.lastError) {
              resolve(null);
            } else {
              resolve(info);
            }
          });
        });

        if (extensionInfo) {
          info.installType = extensionInfo.installType; // "normal", "development", "sideload", etc.
          info.enabled = extensionInfo.enabled;
          info.version = extensionInfo.version;
        }
      }

      return info;
    } catch (error) {
      logger.error("Error getting browser info:", error);
      return {
        extensionId: chrome.runtime.id,
        timestamp: new Date().toISOString(),
        error: error.message,
      };
    }
  }

  // Get current profile info for other parts of the extension
  async getCurrentProfile() {
    if (!this.profileInfo) {
      await this.loadProfileInformation();
    }
    return this.profileInfo;
  }

  // Refresh profile information (useful for periodic updates)
  async refreshProfileInformation() {
    logger.log("Refreshing profile information");
    await this.loadProfileInformation();
    return this.profileInfo;
  }

  // Prepare profile information for logging (keep email for CIPP actionability)
  sanitizeProfileForLogging(profileInfo) {
    if (!profileInfo) return null;

    const userInfo = profileInfo.userInfo
      ? {
          // Keep actual email for CIPP reporting - needed for actionable intelligence
          email: profileInfo.userInfo.email,
          id: profileInfo.userInfo.id,
          // Include account type and provider info for better analytics
          accountType: profileInfo.userInfo.accountType || "unknown",
          provider: profileInfo.userInfo.provider || "unknown",
          // Include additional info if available
          emailNotAvailable: profileInfo.userInfo.emailNotAvailable || false,
          reason: profileInfo.userInfo.reason || null,
        }
      : null;

    return {
      profileId: profileInfo.profileId,
      isManaged: profileInfo.isManaged,
      userInfo: userInfo,
      browserInfo: {
        browserType: profileInfo.browserInfo?.browserType,
        browserVersion: profileInfo.browserInfo?.browserVersion,
        platform: profileInfo.browserInfo?.platform,
        language: profileInfo.browserInfo?.language,
        installType: profileInfo.browserInfo?.installType,
        version: profileInfo.browserInfo?.version,
        extensionId: profileInfo.browserInfo?.extensionId,
        // Exclude userAgent as it's too detailed for logging
      },
      timestamp: profileInfo.timestamp,
    };
  }

  // Send telemetry data to CIPP
  async sendToCipp(logEntry, config) {
    if (!config?.enableCippReporting || !config?.cippServerUrl) {
      return; // CIPP reporting not enabled
    }

    try {
      const cippPayload = {
        timestamp: logEntry.timestamp,
        source: "microsoft-365-phishing-protection",
        version: chrome.runtime.getManifest().version,
        event: logEntry.event,
        profile: logEntry.profile,
        tabId: logEntry.tabId,
        type: logEntry.type,
      };

      // Add tenant/organization context if available
      if (logEntry.profile?.isManaged) {
        cippPayload.context = "managed";
      }

      const response = await fetch(
        `${config.cippServerUrl}/api/telemetry/extension`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "User-Agent": `Microsoft365PhishingProtection/${
              chrome.runtime.getManifest().version
            }`,
          },
          body: JSON.stringify(cippPayload),
        }
      );

      if (!response.ok) {
        throw new Error(
          `CIPP server responded with ${response.status}: ${response.statusText}`
        );
      }

      logger.log("Successfully sent telemetry to CIPP");
    } catch (error) {
      logger.error("Failed to send telemetry to CIPP:", error);
      // Don't fail the entire logging operation if CIPP is unavailable
    }
  }

  async validateConfiguration() {
    const config = await this.configManager.getConfig();
    return {
      configLoaded: !!config,
      // Simplified validation without DetectionEngine
      basicValidation: true,
    };
  }
}

// Initialize the background service worker with singleton pattern
if (!globalThis.checkBackgroundInstance) {
  globalThis.checkBackgroundInstance = new CheckBackground();
  globalThis.checkBackgroundInstance.initialize().catch((error) => {
    console.error("Failed to initialize CheckBackground:", error);
  });
} else {
  // Service worker restarted, ensure existing instance is initialized
  globalThis.checkBackgroundInstance.initialize().catch((error) => {
    console.error("Failed to re-initialize CheckBackground:", error);
  });
}

const check = globalThis.checkBackgroundInstance;

// Export for testing purposes
if (typeof module !== "undefined" && module.exports) {
  module.exports = CheckBackground;
}
