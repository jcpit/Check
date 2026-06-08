/**
 * Detection Rules Manager for Check
 * Handles remote fetching, caching, and management of detection rules
 */

import { chrome, storage } from "../browser-polyfill.js";
import logger from "../utils/logger.js";

export class DetectionRulesManager {
  constructor(configManager = null, onRulesUpdated = null) {
    this.cachedRules = null;
    this.lastUpdate = 0;
    this.updateInterval = 24 * 60 * 60 * 1000; // Default: 24 hours
    this.cacheKey = "detection_rules_cache";
    this.fallbackUrl = chrome.runtime.getURL("rules/detection-rules.json");
    this.remoteUrl =
      "https://raw.githubusercontent.com/CyberDrain/Check/refs/heads/main/rules/detection-rules.json";
    this.config = null;
    this.configManager = configManager;
    this.initialized = false;
    this.onRulesUpdated = onRulesUpdated;
    this._refreshInFlight = null;
    this._usingFallback = false;
  }

  async initialize() {
    if (this.initialized) return;

    try {
      // Load configuration to get update interval and custom URL
      await this.loadConfiguration();

      // Load cached rules first
      await this.loadFromCache();

      // Check if we need to update
      const now = Date.now();
      if (now - this.lastUpdate > this.updateInterval) {
        // Update in background
        this.updateDetectionRules().catch((error) => {
          logger.warn(
            "Failed to update detection rules in background:",
            error.message
          );
        });
      }

      this.initialized = true;
      logger.log("DetectionRulesManager initialized successfully");
    } catch (error) {
      logger.error(
        "Failed to initialize DetectionRulesManager:",
        error.message
      );
    }
  }

  async loadConfiguration() {
    try {
      // Use ConfigManager if available to get merged configuration (enterprise + local)
      if (this.configManager) {
        this.config = await this.configManager.getConfig();
      } else {
        // Fallback to direct storage access if ConfigManager is not available
        const result = await storage.local.get(["config"]);
        this.config = result?.config || {};
      }

      // Set remote URL from configuration or use default
      if (this.config.customRulesUrl) {
        this.remoteUrl = this.config.customRulesUrl;
      } else if (this.config.detectionRules?.customRulesUrl) {
        this.remoteUrl = this.config.detectionRules.customRulesUrl;
      }

      // Set update interval from configuration
      if (this.config.updateInterval) {
        this.updateInterval = this.config.updateInterval * 60 * 60 * 1000; // Convert hours to milliseconds
      } else if (this.config.detectionRules?.updateInterval) {
        this.updateInterval = this.config.detectionRules.updateInterval;
      }

      logger.log("DetectionRulesManager configuration loaded:", {
        remoteUrl: this.remoteUrl,
        updateInterval: this.updateInterval,
      });
    } catch (error) {
      logger.warn(
        "Failed to load configuration, using defaults:",
        error.message
      );
    }
  }

  async reloadConfiguration() {
    logger.log("DetectionRulesManager: Reloading configuration");
    await this.loadConfiguration();
  }

  async loadFromCache() {
    try {
      const result = await storage.local.get([this.cacheKey]);
      const cached = result?.[this.cacheKey];

      if (cached && cached.rules && cached.lastUpdate) {
        // Check if cache is still valid
        const now = Date.now();
        const cacheAge = now - cached.lastUpdate;

        if (cacheAge < this.updateInterval) {
          this.cachedRules = cached.rules;
          this.lastUpdate = cached.lastUpdate;
          logger.log("Detection rules loaded from cache");
          return true;
        } else {
          logger.log("Cached detection rules expired, will fetch new ones");
        }
      }

      return false;
    } catch (error) {
      logger.warn("Failed to load detection rules from cache:", error.message);
      return false;
    }
  }

  async saveToCache(rules) {
    try {
      const cacheData = {
        rules: rules,
        lastUpdate: Date.now(),
        source: this.remoteUrl,
      };

      await storage.local.set({ [this.cacheKey]: cacheData });
      this.cachedRules = rules;
      this.lastUpdate = cacheData.lastUpdate;

      logger.log("Detection rules saved to cache");
    } catch (error) {
      logger.warn("Failed to save detection rules to cache:", error.message);
    }
  }

  async fetchDetectionRules() {
    let rules = null;

    // Try to fetch from remote URL first
    if (this.remoteUrl && this.remoteUrl !== this.fallbackUrl) {
      try {
        logger.log("Fetching detection rules from remote URL:", this.remoteUrl);

        const response = await fetch(this.remoteUrl, {
          cache: "no-cache",
          headers: {
            "Cache-Control": "no-cache",
          },
        });

        if (!response.ok) {
          throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }

        rules = await response.json();
        logger.log("Successfully fetched detection rules from remote URL");

        // Persist only successful remote fetches so the cache always reflects
        // the true remote state - never poisoned by bundled fallback content.
        this._usingFallback = false;
        await this.saveToCache(rules);
        return rules;
      } catch (error) {
        logger.warn("Failed to fetch rules from remote URL:", error.message);
      }
    }

    // Remote fetch failed (or no remote URL configured): serve the bundled
    // rules in-memory but DO NOT persist them. lastUpdate stays at 0 so the
    // next getDetectionRules() call treats the cache as stale and retries the
    // remote URL - the persistent cache remains a record of remote-only state.
    try {
      logger.log(
        "Falling back to bundled detection rules (in-memory only; will retry remote on next refresh)"
      );
      const response = await fetch(this.fallbackUrl);

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      rules = await response.json();
      logger.log("Loaded bundled detection rules");

      this.cachedRules = rules;
      this.lastUpdate = 0; // Force next access to re-attempt the remote fetch
      this._usingFallback = true;
      return rules;
    } catch (error) {
      logger.error("Failed to load bundled detection rules:", error.message);
      throw error;
    }
  }

  async updateDetectionRules() {
    try {
      const rules = await this.fetchDetectionRules();

      // Notify the background-script wiring so dependent subsystems (e.g. the
      // domain-squatting detector) can re-initialize with the new rules.
      if (typeof this.onRulesUpdated === "function") {
        try {
          await this.onRulesUpdated(rules);
        } catch (callbackError) {
          logger.warn(
            "onRulesUpdated callback threw:",
            callbackError?.message || callbackError
          );
        }
      }

      // Notify other parts of the extension that rules have been updated
      if (
        typeof chrome !== "undefined" &&
        chrome.runtime &&
        chrome.runtime.sendMessage
      ) {
        chrome.runtime
          .sendMessage({
            type: "detection_rules_updated",
            timestamp: Date.now(),
          })
          .catch(() => {
            // Ignore errors if no listeners
          });
      }

      return rules;
    } catch (error) {
      logger.error("Failed to update detection rules:", error.message);
      throw error;
    }
  }

  /**
   * Kick off a non-blocking refresh of the detection rules. Used by
   * getDetectionRules() to trigger a background refresh whenever a page
   * detection requests rules and the cache is past the configured interval,
   * without making the requesting page wait for the network round-trip.
   * Guarded against overlapping in-flight refreshes.
   */
  _scheduleBackgroundRefresh(reason) {
    if (this._refreshInFlight) {
      return this._refreshInFlight;
    }
    logger.log(
      `Scheduling background detection-rules refresh (${reason || "expired"})`
    );
    this._refreshInFlight = this.updateDetectionRules()
      .catch((err) => {
        logger.warn(
          "Background detection-rules refresh failed:",
          err?.message || err
        );
      })
      .finally(() => {
        this._refreshInFlight = null;
      });
    return this._refreshInFlight;
  }

  async getDetectionRules() {
    const now = Date.now();

    // Fast path: in-memory cache exists from a previous successful fetch.
    if (this.cachedRules && this.lastUpdate > 0) {
      const cacheAge = now - this.lastUpdate;

      if (cacheAge < this.updateInterval) {
        // Fresh - return immediately, no network.
        return this.cachedRules;
      }

      // Cache is past the configured refresh interval. Return the (still usable)
      // cached rules immediately so page detection isn't blocked, and kick off
      // a non-blocking remote refresh whose result lands on the NEXT request.
      this._scheduleBackgroundRefresh(
        `cache age ${Math.round(cacheAge / 60000)}m > interval ${Math.round(
          this.updateInterval / 60000
        )}m`
      );
      return this.cachedRules;
    }

    // No usable cache yet (cold start or running on bundled fallback after a
    // remote failure). Block on a real fetch so callers don't get null.
    try {
      return await this.fetchDetectionRules();
    } catch (error) {
      if (this.cachedRules) {
        logger.warn("Using bundled cached rules due to fetch failure");
        return this.cachedRules;
      }
      throw error;
    }
  }

  async forceUpdate() {
    logger.log("Forcing detection rules update");
    await this.reloadConfiguration();
    return await this.updateDetectionRules();
  }

  getCacheInfo() {
    return {
      hasCachedRules: !!this.cachedRules,
      lastUpdate: this.lastUpdate,
      cacheAge: this.lastUpdate ? Date.now() - this.lastUpdate : null,
      updateInterval: this.updateInterval,
      remoteUrl: this.remoteUrl,
      isExpired: this.lastUpdate
        ? Date.now() - this.lastUpdate > this.updateInterval
        : true,
      usingFallback: this._usingFallback,
      refreshInFlight: !!this._refreshInFlight,
    };
  }
}
