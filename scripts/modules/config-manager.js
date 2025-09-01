/**
 * Configuration Manager for Check
 * Handles enterprise configuration, branding, and settings management
 */

import logger from "../utils/logger.js";

export class ConfigManager {
  constructor() {
    this.config = null;
    this.brandingConfig = null;
    this.enterpriseConfig = null;
  }

  async loadConfig() {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try { return await promise; } catch(_) { return {}; }
      };
      
      // Load enterprise configuration from managed storage (GPO/Intune)
      this.enterpriseConfig = await this.loadEnterpriseConfig();

      // Load local configuration with safe wrapper
      const localConfig = await safe(chrome.storage.local.get(["config"]));

      // Load branding configuration
      this.brandingConfig = await this.loadBrandingConfig();

      // Merge configurations with enterprise taking precedence
      this.config = this.mergeConfigurations(
        localConfig?.config,
        this.enterpriseConfig,
        this.brandingConfig
      );

      logger.log("Check: Configuration loaded successfully");
      return this.config;
    } catch (error) {
      logger.error("Check: Failed to load configuration:", error);
      throw error;
    }
  }

  async loadEnterpriseConfig() {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try { return await promise; } catch(_) { return {}; }
      };
      
      // Attempt to load from managed storage (deployed via GPO/Intune)
      const managedConfig = await safe(chrome.storage.managed.get(null));

      if (managedConfig && Object.keys(managedConfig).length > 0) {
        logger.log("Check: Enterprise configuration found");
        return managedConfig;
      }

      return {};
    } catch (error) {
      logger.log("Check: No enterprise configuration available");
      return {};
    }
  }

  async loadBrandingConfig() {
    try {
      // Load branding configuration from config file with timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      
      try {
        const response = await fetch(
          chrome.runtime.getURL("config/branding.json"),
          { signal: controller.signal }
        );
        clearTimeout(timeoutId);
        
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const brandingConfig = await response.json();
        return brandingConfig;
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      logger.log("Check: Using default branding configuration");
      return this.getDefaultBrandingConfig();
    }
  }

  mergeConfigurations(localConfig, enterpriseConfig, brandingConfig) {
    const defaultConfig = this.getDefaultConfig();

    // Merge in order of precedence: enterprise > local > branding > default
    const merged = {
      ...defaultConfig,
      ...brandingConfig,
      ...localConfig,
      ...enterpriseConfig,
    };

    // Ensure enterprise policies cannot be overridden
    if (enterpriseConfig.enforcedPolicies) {
      merged.enforcedPolicies = enterpriseConfig.enforcedPolicies;

      // Lock configuration options that are enterprise-managed
      Object.keys(enterpriseConfig.enforcedPolicies).forEach((policy) => {
        if (enterpriseConfig.enforcedPolicies[policy].locked) {
          merged[policy] = enterpriseConfig[policy];
        }
      });
    }

    return merged;
  }

  getDefaultConfig() {
    return {
      // Extension settings
      extensionEnabled: true,
      debugMode: false,

      // Security settings
      blockMaliciousUrls: true,
      blockPhishingAttempts: true,
      enableContentManipulation: true,
      enableUrlMonitoring: true,

      // Detection settings
      detectionRules: {
        enableCustomRules: true,
        customRulesUrl: "",
        updateInterval: 3600000, // 1 hour
        strictMode: false,
      },

      // UI settings
      showNotifications: true,
      notificationDuration: 5000,

      // Performance settings
      scanDelay: 100,
      maxScanDepth: 10,

      // Whitelist/Blacklist
      whitelistedDomains: [],
      blacklistedDomains: [],

      // Enterprise features
      enterpriseMode: false,
      centralManagement: false,
      reportingEndpoint: "",

      // Feature flags
      features: {
        urlBlocking: true,
        contentInjection: true,
        realTimeScanning: true,
        behaviorAnalysis: false,
      },
    };
  }

  getDefaultBrandingConfig() {
    return {
      // Company branding
      companyName: "Check",
      productName: "Check",
      version: "1.0.0",

      // Visual branding
      primaryColor: "#2563eb",
      secondaryColor: "#64748b",
      logoUrl: "images/logo.png",
      faviconUrl: "images/favicon.ico",

      // Contact information
      supportEmail: "support@check.com",
      supportUrl: "https://support.check.com",
      privacyPolicyUrl: "https://check.com/privacy",
      termsOfServiceUrl: "https://check.com/terms",

      // Customizable text
      welcomeMessage:
        "Welcome to Check - Your Enterprise Web Security Solution",
      blockedPageTitle: "Access Blocked by Check",
      blockedPageMessage:
        "This page has been blocked by your organization's security policy.",

      // Feature customization
      showCompanyBranding: true,

      // License information
      licenseKey: "",
      licensedTo: "",
      licenseExpiry: null,
    };
  }

  async setDefaultConfig() {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try { return await promise; } catch(_) { return undefined; }
      };
      
      const defaultConfig = this.getDefaultConfig();
      await safe(chrome.storage.local.set({ config: defaultConfig }));
      this.config = defaultConfig;
    } catch (error) {
      logger.error("Check: Failed to set default config:", error);
      this.config = this.getDefaultConfig();
    }
  }

  async updateConfig(updates) {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try { return await promise; } catch(_) { return undefined; }
      };
      
      const currentConfig = await this.getConfig();
      const updatedConfig = { ...currentConfig, ...updates };

      // Validate that enterprise-enforced policies are not being modified
      if (this.enterpriseConfig?.enforcedPolicies) {
        Object.keys(this.enterpriseConfig.enforcedPolicies).forEach(
          (policy) => {
            if (
              this.enterpriseConfig.enforcedPolicies[policy]?.locked &&
              updates[policy] !== undefined &&
              updates[policy] !== this.enterpriseConfig[policy]
            ) {
              throw new Error(
                `Policy '${policy}' is locked by enterprise configuration`
              );
            }
          }
        );
      }

      await safe(chrome.storage.local.set({ config: updatedConfig }));
      this.config = updatedConfig;

      // Notify other components of configuration change with safe wrapper
      try {
        chrome.runtime.sendMessage({
          type: "CONFIG_UPDATED",
          config: updatedConfig,
        }, () => {
          if (chrome.runtime.lastError) {
            // Silently handle errors
          }
        });
      } catch (error) {
        // Silently handle errors
      }

      return updatedConfig;
    } catch (error) {
      logger.error("Check: Failed to update configuration:", error);
      throw error;
    }
  }

  async getConfig() {
    if (!this.config) {
      await this.loadConfig();
    }
    return this.config;
  }

  async getBrandingConfig() {
    if (!this.brandingConfig) {
      await this.loadConfig();
    }
    return this.brandingConfig;
  }

  async refreshConfig() {
    this.config = null;
    this.brandingConfig = null;
    this.enterpriseConfig = null;
    return await this.loadConfig();
  }

  async migrateConfig(previousVersion) {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try { return await promise; } catch(_) { return {}; }
      };
      
      logger.log(
        `Check: Migrating configuration from version ${previousVersion}`
      );

      const currentConfig = await safe(chrome.storage.local.get(["config"]));
      if (!currentConfig?.config) return;

      // Add migration logic here for future versions
      // Example:
      // if (this.isVersionLessThan(previousVersion, '1.1.0')) {
      //   // Migration logic for 1.1.0
      // }

      logger.log("Check: Configuration migration completed");
    } catch (error) {
      logger.error("Check: Configuration migration failed:", error);
    }
  }

  isVersionLessThan(version1, version2) {
    const v1Parts = version1.split(".").map(Number);
    const v2Parts = version2.split(".").map(Number);

    for (let i = 0; i < Math.max(v1Parts.length, v2Parts.length); i++) {
      const v1Part = v1Parts[i] || 0;
      const v2Part = v2Parts[i] || 0;

      if (v1Part < v2Part) return true;
      if (v1Part > v2Part) return false;
    }

    return false;
  }

  // Utility methods for enterprise deployment
  async exportConfiguration() {
    const config = await this.getConfig();
    const exportData = {
      config,
      branding: this.brandingConfig,
      timestamp: new Date().toISOString(),
      version: chrome.runtime.getManifest().version,
    };

    return JSON.stringify(exportData, null, 2);
  }

  async importConfiguration(configJson) {
    try {
      const importData = JSON.parse(configJson);

      // Validate import data
      if (!importData.config) {
        throw new Error("Invalid configuration format");
      }

      // Update configuration
      await this.updateConfig(importData.config);

      // Update branding if provided with safe wrapper
      if (importData.branding) {
        const safe = async (promise) => {
          try { return await promise; } catch(_) { return undefined; }
        };
        await safe(chrome.storage.local.set({ branding: importData.branding }));
        this.brandingConfig = importData.branding;
      }

      logger.log("Check: Configuration imported successfully");
      return true;
    } catch (error) {
      logger.error("Check: Failed to import configuration:", error);
      throw error;
    }
  }
}
