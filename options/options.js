/**
 * Check - Options Page JavaScript
 * Comprehensive settings management and configuration interface
 */

class CheckOptions {
  constructor() {
    this.config = null;
    this.brandingConfig = null;
    this.originalConfig = null;
    this.hasUnsavedChanges = false;
    this.currentSection = "general";

    this.elements = {};
    this.bindElements();
    this.setupEventListeners();
    this.initialize();
  }

  bindElements() {
    // Navigation
    this.elements.menuItems = document.querySelectorAll(".menu-item");
    this.elements.sections = document.querySelectorAll(".settings-section");
    this.elements.pageTitle = document.getElementById("pageTitle");
    this.elements.policyBadge = document.getElementById("policyBadge");

    // Header actions
    this.elements.saveSettings = document.getElementById("saveSettings");
    this.elements.exportConfig = document.getElementById("exportConfig");
    this.elements.importConfig = document.getElementById("importConfig");

    // General settings
    this.elements.extensionEnabled =
      document.getElementById("extensionEnabled");
    this.elements.enableContentManipulation = document.getElementById(
      "enableContentManipulation"
    );
    this.elements.enableUrlMonitoring = document.getElementById(
      "enableUrlMonitoring"
    );
    this.elements.showNotifications =
      document.getElementById("showNotifications");
    this.elements.notificationDuration = document.getElementById(
      "notificationDuration"
    );
    this.elements.notificationDurationValue = document.getElementById(
      "notificationDurationValue"
    );
    this.elements.enableValidPageBadge = document.getElementById(
      "enableValidPageBadge"
    );

    // Detection settings
    this.elements.enableCustomRules =
      document.getElementById("enableCustomRules");
    this.elements.customRulesUrl = document.getElementById("customRulesUrl");
    this.elements.updateInterval = document.getElementById("updateInterval");
    this.elements.customRulesEditor =
      document.getElementById("customRulesEditor");
    this.elements.validateRules = document.getElementById("validateRules");
    this.elements.loadDefaultRules =
      document.getElementById("loadDefaultRules");

    // Logging settings (moved from privacy section)
    this.elements.enableDebugLogging =
      document.getElementById("enableDebugLogging");

    // Logs
    this.elements.logFilter = document.getElementById("logFilter");
    this.elements.clearLogs = document.getElementById("clearLogs");
    this.elements.exportLogs = document.getElementById("exportLogs");
    this.elements.logsList = document.getElementById("logsList");

    // Branding
    this.elements.companyName = document.getElementById("companyName");
    this.elements.productName = document.getElementById("productName");
    this.elements.supportEmail = document.getElementById("supportEmail");
    this.elements.primaryColor = document.getElementById("primaryColor");
    this.elements.logoUrl = document.getElementById("logoUrl");
    this.elements.customCss = document.getElementById("customCss");
    this.elements.brandingPreview = document.getElementById("brandingPreview");
    this.elements.previewLogo = document.getElementById("previewLogo");
    this.elements.previewTitle = document.getElementById("previewTitle");
    this.elements.previewButton = document.getElementById("previewButton");

    // Modal
    this.elements.modalOverlay = document.getElementById("modalOverlay");
    this.elements.modalTitle = document.getElementById("modalTitle");
    this.elements.modalMessage = document.getElementById("modalMessage");
    this.elements.modalCancel = document.getElementById("modalCancel");
    this.elements.modalConfirm = document.getElementById("modalConfirm");

    // Toast container
    this.elements.toastContainer = document.getElementById("toastContainer");
  }

  setupEventListeners() {
    // Navigation
    this.elements.menuItems.forEach((item) => {
      item.addEventListener("click", (e) => {
        e.preventDefault();
        const section = item.dataset.section;
        this.switchSection(section);
      });
    });

    // Header actions
    this.elements.saveSettings.addEventListener("click", () =>
      this.saveSettings()
    );
    this.elements.exportConfig.addEventListener("click", () =>
      this.exportConfiguration()
    );
    this.elements.importConfig.addEventListener("click", () =>
      this.importConfiguration()
    );

    // Range slider
    if (this.elements.notificationDuration) {
      this.elements.notificationDuration.addEventListener("input", (e) => {
        this.elements.notificationDurationValue.textContent =
          e.target.value / 1000 + "s";
      });
    }

    // Detection rules actions
    this.elements.validateRules?.addEventListener("click", () =>
      this.validateCustomRules()
    );
    this.elements.loadDefaultRules?.addEventListener("click", () =>
      this.loadDefaultDetectionRules()
    );

    // Logs actions
    this.elements.logFilter?.addEventListener("change", () => this.loadLogs());
    this.elements.clearLogs?.addEventListener("click", () => this.clearLogs());
    this.elements.exportLogs?.addEventListener("click", () =>
      this.exportLogs()
    );

    // Branding preview updates
    const brandingInputs = [
      this.elements.companyName,
      this.elements.productName,
      this.elements.primaryColor,
      this.elements.logoUrl,
    ];

    brandingInputs.forEach((input) => {
      if (input) {
        input.addEventListener("input", () => this.updateBrandingPreview());
      }
    });

    // Modal actions
    this.elements.modalCancel?.addEventListener("click", () =>
      this.hideModal()
    );
    this.elements.modalOverlay?.addEventListener("click", (e) => {
      if (e.target === this.elements.modalOverlay) {
        this.hideModal();
      }
    });

    // Change tracking
    this.setupChangeTracking();

    // Handle URL hash changes
    window.addEventListener("hashchange", () => this.handleHashChange());

    // Handle beforeunload to warn about unsaved changes
    window.addEventListener("beforeunload", (e) => {
      if (this.hasUnsavedChanges) {
        e.preventDefault();
        e.returnValue =
          "You have unsaved changes. Are you sure you want to leave?";
      }
    });
  }

  setupChangeTracking() {
    const inputs = document.querySelectorAll("input, select, textarea");
    inputs.forEach((input) => {
      if (input.type === "button" || input.type === "submit") return;

      input.addEventListener("change", () => {
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
      await this.loadLogs();
      // Handle initial hash
      this.handleHashChange();
      // Update branding preview
      this.updateBrandingPreview();
      this.showToast("Settings loaded successfully", "success");
    } catch (error) {
      console.error("Failed to initialize options page:", error);
      this.showToast(
        "Failed to load some settings - using defaults where possible",
        "warning"
      );
    }
  }

  // Robust communication layer to handle service worker termination
  async ensureServiceWorkerAlive(maxAttempts = 3, initialDelay = 100) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const response = await new Promise((resolve) => {
          chrome.runtime.sendMessage({ type: "ping" }, (response) => {
            if (chrome.runtime.lastError) {
              resolve(null);
            } else {
              resolve(response);
            }
          });
        });

        if (response && response.success) {
          return true;
        }
      } catch (error) {
        console.warn(`Service worker ping attempt ${attempt} failed:`, error);
      }

      if (attempt < maxAttempts) {
        const delay = initialDelay * Math.pow(2, attempt - 1);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    return false;
  }

  async sendMessageWithRetry(message, maxAttempts = 3, initialDelay = 5000) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const response = await new Promise((resolve, reject) => {
          try {
            chrome.runtime.sendMessage(message, (response) => {
              if (chrome.runtime.lastError) {
                // Silently handle runtime errors to avoid Chrome error list
                reject(new Error("Background worker unavailable"));
              } else {
                resolve(response);
              }
            });
          } catch (error) {
            reject(error);
          }
        });

        return response;
      } catch (error) {
        // Silently handle errors on first attempts, only log on final failure
        if (attempt === maxAttempts) {
          // Don't throw error to avoid uncaught exceptions
          return null;
        }

        // Wait 5 seconds before retry
        await new Promise((resolve) => setTimeout(resolve, initialDelay));
      }
    }
    return null;
  }

  async loadConfiguration() {
    const response = await this.sendMessageWithRetry({
      type: "GET_CONFIG",
    });

    if (response && response.success) {
      this.config = response.config;
      this.originalConfig = JSON.parse(JSON.stringify(response.config));
    } else {
      // Use defaults when background script is unavailable
      this.config = this.configManager?.getDefaultConfig() || {
        extensionEnabled: true,
        enableContentManipulation: true,
        enableUrlMonitoring: true,
        showNotifications: true,
        notificationDuration: 5000,
        enableValidPageBadge: false,
        enableCustomRules: false,
        customRulesUrl: "",
        updateInterval: 24,
        enableDebugLogging: false,
      };
      this.originalConfig = JSON.parse(JSON.stringify(this.config));

      // Schedule silent retry in 5 seconds
      setTimeout(() => {
        this.loadConfiguration();
      }, 5000);
    }
  }

  async waitForRuntimeReady(maxAttempts = 5, initialDelay = 100) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        // Check if chrome.runtime and extension context are available
        if (chrome.runtime && chrome.runtime.id) {
          const testUrl = chrome.runtime.getURL("config/branding.json");
          // Validate the URL is properly formed (not undefined or invalid)
          if (
            testUrl &&
            testUrl.startsWith("chrome-extension://") &&
            !testUrl.includes("undefined")
          ) {
            return true;
          }
        }
      } catch (error) {
        console.warn(
          `Runtime readiness check attempt ${attempt} failed:`,
          error
        );
      }

      if (attempt < maxAttempts) {
        const delay = initialDelay * Math.pow(2, attempt - 1);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    throw new Error("Chrome runtime not ready after maximum attempts");
  }

  async loadBrandingConfiguration() {
    try {
      // First try to load from storage (user settings)
      const storageResult = await new Promise((resolve) => {
        chrome.storage.local.get(['brandingConfig'], (result) => {
          resolve(result.brandingConfig);
        });
      });

      if (storageResult) {
        this.brandingConfig = storageResult;
        console.log("Loaded branding from storage:", storageResult);
        return;
      }

      // Fallback to loading from branding.json file
      await this.waitForRuntimeReady();

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      
      try {
        const response = await fetch(
          chrome.runtime.getURL("config/branding.json"),
          { signal: controller.signal }
        );
        clearTimeout(timeoutId);

        if (!response.ok) {
          throw new Error(
            `Failed to load branding config: ${response.status} ${response.statusText}`
          );
        }

        this.brandingConfig = await response.json();
        console.log("Loaded branding from file:", this.brandingConfig);
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      console.warn(
        "Failed to load branding configuration, using defaults:",
        error
      );
      this.brandingConfig = {
        companyName: "CyberDrain",
        productName: "Microsoft 365 Phishing Protection",
        supportEmail: "support@cyberdrain.com",
        primaryColor: "#F77F00",
        logoUrl: "images/icon48.png",
        supportUrl: "https://support.cyberdrain.com",
        privacyPolicyUrl: "https://cyberdrain.com/privacy",
        termsOfServiceUrl: "https://cyberdrain.com/terms",
      };
    }
  }

  applyBranding() {
    // Update sidebar branding
    document.getElementById("sidebarTitle").textContent =
      this.brandingConfig?.productName || "Microsoft 365 Phishing Protection";
    document.getElementById("sidebarVersion").textContent = `v${
      chrome.runtime.getManifest().version
    }`;
    
    // Update sidebar logo
    const sidebarLogo = document.getElementById("sidebarLogo");
    if (sidebarLogo && this.brandingConfig?.logoUrl) {
      console.log("Setting sidebar logo:", this.brandingConfig.logoUrl);
      
      // Handle both relative and absolute URLs
      const logoSrc = this.brandingConfig.logoUrl.startsWith("http") ?
        this.brandingConfig.logoUrl :
        chrome.runtime.getURL(this.brandingConfig.logoUrl);
      
      // Test if logo loads, fallback to default if it fails
      const testImg = new Image();
      testImg.onload = () => {
        console.log("Sidebar logo loaded successfully");
        sidebarLogo.src = logoSrc;
      };
      testImg.onerror = () => {
        console.warn("Failed to load sidebar logo, using default");
        sidebarLogo.src = chrome.runtime.getURL("images/icon48.png");
      };
      testImg.src = logoSrc;
    } else if (sidebarLogo) {
      console.log("No custom logo, using default sidebar logo");
      sidebarLogo.src = chrome.runtime.getURL("images/icon48.png");
    }
  }

  populateFormFields() {
    // Extension settings
    this.elements.enablePageBlocking = document.getElementById("enablePageBlocking");
    this.elements.enableCippReporting = document.getElementById("enableCippReporting");
    this.elements.cippServerUrl = document.getElementById("cippServerUrl");
    
    if (this.elements.enablePageBlocking) {
      this.elements.enablePageBlocking.checked = this.config?.enablePageBlocking !== false;
    }
    if (this.elements.enableCippReporting) {
      this.elements.enableCippReporting.checked = this.config?.enableCippReporting || false;
    }
    if (this.elements.cippServerUrl) {
      this.elements.cippServerUrl.value = this.config?.cippServerUrl || "";
    }
    
    // UI settings
    this.elements.showNotifications.checked = this.config?.showNotifications;
    this.elements.notificationDuration.value =
      this.config?.notificationDuration;
    this.elements.notificationDurationValue.textContent =
      this.config.notificationDuration / 1000 + "s";
    this.elements.enableValidPageBadge.checked =
      this.config.enableValidPageBadge || false;

    // Detection settings
    this.elements.enableCustomRules.checked =
      this.config.detectionRules?.enableCustomRules ||
      this.config.enableCustomRules ||
      false;
    this.elements.customRulesUrl.value =
      this.config.detectionRules?.customRulesUrl ||
      this.config.customRulesUrl ||
      "";
    this.elements.updateInterval.value =
      (this.config.detectionRules?.updateInterval ||
        this.config.updateInterval * 3600000 ||
        86400000) / 3600000;

    // Logging settings
    this.elements.enableDebugLogging.checked =
      this.config.enableDebugLogging || false;

    // Branding settings
    this.elements.companyName.value = this.brandingConfig?.companyName || "";
    this.elements.productName.value = this.brandingConfig?.productName || "";
    this.elements.supportEmail.value = this.brandingConfig?.supportEmail || "";
    this.elements.primaryColor.value = this.brandingConfig?.primaryColor || "#F77F00";
    this.elements.logoUrl.value = this.brandingConfig?.logoUrl || "";
    this.elements.customCss.value = this.brandingConfig?.customCss || "";
  }

  switchSection(sectionName) {
    // Update active menu item
    this.elements.menuItems.forEach((item) => {
      item.classList.toggle("active", item.dataset.section === sectionName);
    });

    // Update active section
    this.elements.sections.forEach((section) => {
      section.classList.toggle(
        "active",
        section.id === `${sectionName}-section`
      );
    });

    // Update page title
    const sectionTitles = {
      general: "General Settings",
      detection: "Detection Rules",
      logs: "Activity Logs",
      branding: "Branding & White Labeling",
      about: "About",
    };

    this.elements.pageTitle.textContent =
      sectionTitles[sectionName] || "Settings";
    this.currentSection = sectionName;

    // Update URL hash
    window.location.hash = sectionName;

    // Load section-specific data
    if (sectionName === "logs") {
      this.loadLogs();
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
      const newBranding = this.gatherBrandingData();

      // Validate configuration
      const validation = this.validateConfiguration(newConfig);
      if (!validation.valid) {
        this.showToast(validation.message, "error");
        return;
      }

      // Save configuration
      const response = await this.sendMessage({
        type: "UPDATE_CONFIG",
        config: newConfig,
      });

      // Save branding configuration separately
      try {
        await new Promise((resolve, reject) => {
          chrome.storage.local.set({ brandingConfig: newBranding }, () => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
            } else {
              resolve();
            }
          });
        });
        
        this.brandingConfig = newBranding;
        console.log("Branding config saved:", newBranding);
      } catch (brandingError) {
        console.error("Failed to save branding config:", brandingError);
        this.showToast("Failed to save branding settings", "warning");
      }

      if (response && response.success) {
        this.config = newConfig;
        this.originalConfig = JSON.parse(JSON.stringify(newConfig));
        this.hasUnsavedChanges = false;
        this.updateSaveButton();
        this.showToast("Settings saved successfully", "success");
      } else {
        throw new Error(response?.error || "Failed to save settings");
      }
    } catch (error) {
      console.error("Failed to save settings:", error);
      this.showToast("Failed to save settings", "error");
    }
  }

  gatherFormData() {
    return {
      // Extension settings
      enablePageBlocking: this.elements.enablePageBlocking?.checked !== false,
      enableCippReporting: this.elements.enableCippReporting?.checked || false,
      cippServerUrl: this.elements.cippServerUrl?.value || "",
      
      // UI settings
      showNotifications: this.elements.showNotifications?.checked || false,
      notificationDuration: parseInt(
        this.elements.notificationDuration?.value || 5000
      ),
      enableValidPageBadge:
        this.elements.enableValidPageBadge?.checked || false,

      // Detection settings
      enableCustomRules: this.elements.enableCustomRules?.checked || false,
      customRulesUrl: this.elements.customRulesUrl?.value || "",
      updateInterval: parseInt(this.elements.updateInterval?.value || 24),

      // Debug logging setting
      enableDebugLogging: this.elements.enableDebugLogging?.checked || false,
    };
  }

  validateConfiguration(config) {
    // Basic validation
    if (
      config.notificationDuration < 1000 ||
      config.notificationDuration > 10000
    ) {
      return {
        valid: false,
        message: "Notification duration must be between 1-10 seconds",
      };
    }

    if (config.updateInterval < 1 || config.updateInterval > 168) {
      return {
        valid: false,
        message: "Update interval must be between 1-168 hours",
      };
    }

    // URL validation
    if (config.customRulesUrl && !this.isValidUrl(config.customRulesUrl)) {
      return { valid: false, message: "Custom rules URL is not valid" };
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
        version: chrome.runtime.getManifest().version,
      };

      const blob = new Blob([JSON.stringify(exportData, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `check-config-${
        new Date().toISOString().split("T")[0]
      }.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      this.showToast("Configuration exported successfully", "success");
    } catch (error) {
      console.error("Failed to export configuration:", error);
      this.showToast("Failed to export configuration", "error");
    }
  }

  async importConfiguration() {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".json";

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
          this.showToast("Configuration imported successfully", "success");
        } else {
          throw new Error("Invalid configuration file");
        }
      } catch (error) {
        console.error("Failed to import configuration:", error);
        this.showToast("Failed to import configuration", "error");
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
      customCss: this.elements.customCss.value,
    };
  }

  async validateCustomRules() {
    try {
      const rulesText = this.elements.customRulesEditor.value;
      if (!rulesText.trim()) {
        this.showToast("No rules to validate", "warning");
        return;
      }

      const rules = JSON.parse(rulesText);

      // Basic validation
      if (!rules.malicious && !rules.phishing && !rules.suspicious) {
        throw new Error(
          "Rules must contain at least one category (malicious, phishing, or suspicious)"
        );
      }

      // Validate patterns
      const categories = ["malicious", "phishing", "suspicious"];
      for (const category of categories) {
        if (rules[category]) {
          for (const rule of rules[category]) {
            if (!rule.pattern) {
              throw new Error(`Rule in ${category} category missing pattern`);
            }
            try {
              new RegExp(rule.pattern, rule.flags || "i");
            } catch (e) {
              throw new Error(
                `Invalid regex pattern in ${category}: ${rule.pattern}`
              );
            }
          }
        }
      }

      this.showToast("Custom rules are valid", "success");
    } catch (error) {
      this.showToast(`Validation failed: ${error.message}`, "error");
    }
  }

  async loadDefaultDetectionRules() {
    try {
      // Add timeout to fetch operations
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);
      
      try {
        const response = await fetch(
          chrome.runtime.getURL("rules/detection-rules.json"),
          { signal: controller.signal }
        );
        clearTimeout(timeoutId);
        
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const defaultRules = await response.json();
        this.elements.customRulesEditor.value = JSON.stringify(
          defaultRules,
          null,
          2
        );
        this.showToast("Default rules loaded", "success");
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      console.error("Failed to load default rules:", error);
      this.showToast("Failed to load default rules", "error");
    }
  }

  async loadLogs() {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try { return await promise; } catch(_) { return {}; }
      };
      
      const result = await safe(chrome.storage.local.get([
        "securityEvents",
        "accessLogs",
        "debugLogs",
      ]));
      const securityEvents = result?.securityEvents || [];
      const accessLogs = result?.accessLogs || [];
      const debugLogs = result?.debugLogs || [];

      // Combine and sort logs
      const allLogs = [
        ...securityEvents.map((event) => ({ ...event, category: "security" })),
        ...accessLogs.map((event) => ({ ...event, category: "access" })),
        ...debugLogs.map((log) => ({ ...log, category: "debug" })),
      ].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

      this.displayLogs(allLogs);
    } catch (error) {
      console.error("Failed to load logs:", error);
      this.showToast("Failed to load logs", "error");
    }
  }

  displayLogs(logs) {
    this.elements.logsList.innerHTML = "";

    if (logs.length === 0) {
      const item = document.createElement("div");
      item.className = "log-entry";
      item.innerHTML =
        '<div class="log-column" style="grid-column: 1 / -1; text-align: center; color: #9ca3af;">No logs available</div>';
      this.elements.logsList.appendChild(item);
      return;
    }

    // Filter logs based on debug logging setting
    const filteredLogs = this.filterLogsForDisplay(logs);

    filteredLogs.slice(0, 100).forEach((log) => {
      const item = document.createElement("div");
      item.className = "log-entry";

      // Timestamp column
      const timestamp = document.createElement("div");
      timestamp.className = "log-column timestamp";
      timestamp.textContent = new Date(log.timestamp).toLocaleString();

      // Event type column
      const eventType = document.createElement("div");
      eventType.className = `log-column event-type ${log.category}`;
      eventType.textContent = this.getEventTypeDisplay(log);

      // URL/Domain column
      const url = document.createElement("div");
      url.className = "log-column url";
      url.textContent = this.getUrlDisplay(log);

      // Threat level column
      const threatLevel = document.createElement("div");
      threatLevel.className = "log-column threat-level";
      threatLevel.textContent = this.getThreatLevelDisplay(log);

      // Action taken column
      const action = document.createElement("div");
      action.className = "log-column action";
      action.textContent = this.getActionDisplay(log);

      // Details column
      const details = document.createElement("div");
      details.className = "log-column details";
      details.textContent = this.formatLogMessage(log);

      item.appendChild(timestamp);
      item.appendChild(eventType);
      item.appendChild(url);
      item.appendChild(threatLevel);
      item.appendChild(action);
      item.appendChild(details);

      this.elements.logsList.appendChild(item);
    });
  }

  filterLogsForDisplay(logs) {
    const debugLoggingEnabled = this.config?.enableDebugLogging || false;

    if (debugLoggingEnabled) {
      return logs; // Show all logs including debug
    } else {
      // Filter out page scan events and debug logs unless they're important
      return logs.filter((log) => {
        if (log.category === "debug" && log.level === "debug") {
          return false; // Hide debug logs
        }
        if (log.event?.type === "page_scanned" && !log.event?.threatDetected) {
          return false; // Hide routine page scans
        }
        return true;
      });
    }
  }

  async loadPolicyInfo() {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try { return await promise; } catch(_) { return {}; }
      };
      
      // Check if extension is managed
      const policies = await safe(chrome.storage.managed.get(null));
      const isManaged = policies && Object.keys(policies).length > 0;

      if (isManaged) {
        // Show policy badge
        if (this.elements.policyBadge) {
          this.elements.policyBadge.style.display = "flex";
        }

        // Disable policy-managed fields
        this.disablePolicyManagedFields(policies);
      } else {
        // Hide policy badge
        if (this.elements.policyBadge) {
          this.elements.policyBadge.style.display = "none";
        }
      }
    } catch (error) {
      console.error("Failed to load policy info:", error);
      // Retry in 5 seconds
      setTimeout(() => {
        this.loadPolicyInfo().catch(() => {
          console.log("Policy info still unavailable");
        });
      }, 5000);
    }
  }

  disablePolicyManagedFields(policies) {
    const policyFieldMap = {
      enablePageBlocking: this.elements.enablePageBlocking,
      enableCippReporting: this.elements.enableCippReporting,
      enableDebugLogging: this.elements.enableDebugLogging,
    };

    Object.keys(policies).forEach((policyKey) => {
      const element = policyFieldMap[policyKey];
      if (element) {
        element.disabled = true;
        element.title = "This setting is managed by your organization's policy";

        // Add visual indicator
        element.classList.add("policy-managed");

        // Add a small lock icon next to the field
        const lockIcon = document.createElement("span");
        lockIcon.className = "material-icons policy-lock";
        lockIcon.textContent = "lock";
        lockIcon.title = "Managed by policy";

        if (element.parentNode) {
          element.parentNode.appendChild(lockIcon);
        }
      }
    });
  }

  getEventTypeDisplay(log) {
    if (log.category === "debug") {
      return log.level.toUpperCase();
    }
    if (log.event?.type) {
      return log.event.type.replace(/_/g, " ").toUpperCase();
    }
    return (log.type || "UNKNOWN").toUpperCase();
  }

  getUrlDisplay(log) {
    try {
      if (log.event?.url) {
        const url = new URL(log.event.url);
        return log.event.threatDetected
          ? url.hostname.replace(/:/g, "[:]")
          : url.hostname;
      }
      if (log.url) {
        const url = new URL(log.url);
        return url.hostname;
      }
    } catch (e) {
      // Invalid URL, try to defang the raw URL if it looks like a threat
      if (
        log.event?.url &&
        (log.event?.threatDetected || log.event?.threatLevel === "high")
      ) {
        return log.event.url.replace(/:/g, "[:]");
      }
    }
    return "-";
  }

  getThreatLevelDisplay(log) {
    if (log.event?.threatLevel) {
      return log.event.threatLevel.toUpperCase();
    }
    if (
      log.event?.type === "threat_detected" ||
      log.event?.type === "content_threat_detected"
    ) {
      return "HIGH";
    }
    if (log.category === "security") {
      return "MEDIUM";
    }
    return "-";
  }

  getActionDisplay(log) {
    if (log.event?.action) {
      return log.event.action.replace(/_/g, " ").toUpperCase();
    }
    if (
      log.event?.type === "content_threat_detected" ||
      log.event?.type === "threat_detected"
    ) {
      return "BLOCKED";
    }
    if (log.event?.type === "url_access") {
      return "ALLOWED";
    }
    return "-";
  }

  formatLogMessage(log) {
    if (log.category === "debug") {
      return log.message || "";
    }
    if (log.event) {
      switch (log.event.type) {
        case "url_access":
          try {
            return `Accessed: ${new URL(log.event.url).hostname}`;
          } catch {
            return `Accessed: ${log.event.url || "unknown"}`;
          }
        case "content_threat_detected":
          let details = `Malicious content detected`;
          if (log.event.reason) {
            details += `: ${log.event.reason}`;
          }
          if (log.event.details) {
            details += `. ${log.event.details}`;
          }
          if (log.event.analysis) {
            const analysis = log.event.analysis;
            const indicators = [];
            if (analysis.aadLike) indicators.push("AAD-like elements");
            if (analysis.formActionFail)
              indicators.push("Non-Microsoft form action");
            if (analysis.nonMicrosoftResources > 0)
              indicators.push(
                `${analysis.nonMicrosoftResources} external resources`
              );
            if (indicators.length > 0) {
              details += ` [${indicators.join(", ")}]`;
            }
          }
          return details;
        case "threat_detected":
          let threatDetails = `Security threat detected`;
          if (log.event.reason) {
            threatDetails += `: ${log.event.reason}`;
          }
          if (log.event.triggeredRules && log.event.triggeredRules.length > 0) {
            const ruleNames = log.event.triggeredRules
              .map((rule) => rule.id || rule.type)
              .join(", ");
            threatDetails += ` [Triggered rules: ${ruleNames}]`;
          } else if (log.event.ruleDetails) {
            threatDetails += ` [${log.event.ruleDetails}]`;
          }
          if (
            log.event.score !== undefined &&
            log.event.threshold !== undefined
          ) {
            threatDetails += ` [Score: ${log.event.score}/${log.event.threshold}]`;
          }
          if (log.event.details) {
            threatDetails += `. ${log.event.details}`;
          }
          return threatDetails;
        case "form_submission":
          let formDetails = `Form submission`;
          if (log.event.action) {
            formDetails += ` to ${log.event.action.replace(/:/g, "[:]")}`;
          }
          if (log.event.reason) {
            formDetails += ` - ${log.event.reason}`;
          }
          return formDetails;
        case "script_injection":
          return `Security script injected to protect user`;
        case "page_scanned":
          return `Page security scan completed`;
        default:
          let defaultMsg =
            log.event.description || log.event.type.replace(/_/g, " ");
          if (log.event.url) {
            defaultMsg += ` on ${log.event.url.replace(/:/g, "[:]")}`;
          }
          if (log.event.reason) {
            defaultMsg += `: ${log.event.reason}`;
          }
          return defaultMsg;
      }
    }
    return log.message || log.type || "Unknown event";
  }

  async clearLogs() {
    const confirmed = await this.showConfirmDialog(
      "Clear All Logs",
      "Are you sure you want to clear all activity logs? This action cannot be undone."
    );

    if (confirmed) {
      try {
        // Safe wrapper for chrome.* operations
        const safe = async (promise) => {
          try { return await promise; } catch(_) { return undefined; }
        };
        
        await safe(chrome.storage.local.remove([
          "securityEvents",
          "accessLogs",
          "debugLogs",
        ]));
        this.loadLogs();
        this.showToast("Logs cleared successfully", "success");
      } catch (error) {
        console.error("Failed to clear logs:", error);
        this.showToast("Failed to clear logs", "error");
      }
    }
  }

  async exportLogs() {
    try {
      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try { return await promise; } catch(_) { return {}; }
      };
      
      const result = await safe(chrome.storage.local.get([
        "securityEvents",
        "accessLogs",
        "debugLogs",
      ]));
      const exportData = {
        securityEvents: result?.securityEvents || [],
        accessLogs: result?.accessLogs || [],
        debugLogs: result?.debugLogs || [],
        timestamp: new Date().toISOString(),
        version: chrome.runtime.getManifest().version,
      };

      const blob = new Blob([JSON.stringify(exportData, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `check-logs-${new Date().toISOString().split("T")[0]}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      this.showToast("Logs exported successfully", "success");
    } catch (error) {
      console.error("Failed to export logs:", error);
      this.showToast("Failed to export logs", "error");
    }
  }

  updateBrandingPreview() {
    const companyName =
      this.elements.companyName.value || this.brandingConfig.companyName;
    const productName =
      this.elements.productName.value || this.brandingConfig.productName;
    const primaryColor =
      this.elements.primaryColor.value || this.brandingConfig.primaryColor;
    const logoUrl = this.elements.logoUrl.value || this.brandingConfig.logoUrl;

    this.elements.previewTitle.textContent = productName;
    this.elements.previewButton.style.backgroundColor = primaryColor;

    if (logoUrl) {
      this.elements.previewLogo.src = logoUrl.startsWith("http")
        ? logoUrl
        : chrome.runtime.getURL(logoUrl);
    }
  }

  markUnsavedChanges() {
    this.hasUnsavedChanges = true;
    this.updateSaveButton();
  }

  updateSaveButton() {
    if (this.hasUnsavedChanges) {
      this.elements.saveSettings.textContent = "Save Changes *";
      this.elements.saveSettings.classList.add("unsaved");
    } else {
      this.elements.saveSettings.textContent = "Save Settings";
      this.elements.saveSettings.classList.remove("unsaved");
    }
  }

  async sendMessage(message) {
    try {
      return await this.sendMessageWithRetry(message);
    } catch (error) {
      console.error("Failed to send message after retries:", error);
      throw error;
    }
  }

  // Add "respond once" guard for options page
  createOnceGuard(fn) {
    let called = false;
    return (...args) => { if (!called) { called = true; fn(...args); } };
  }

  showToast(message, type = "info") {
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;

    const content = document.createElement("div");
    content.className = "toast-content";

    const messageEl = document.createElement("span");
    messageEl.className = "toast-message";
    messageEl.textContent = message;

    const closeBtn = document.createElement("button");
    closeBtn.className = "toast-close";
    closeBtn.innerHTML = "&times;";
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
      this.elements.modalOverlay.style.display = "flex";

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
        this.elements.modalConfirm.removeEventListener("click", handleConfirm);
        this.elements.modalCancel.removeEventListener("click", handleCancel);
      };

      this.elements.modalConfirm.addEventListener("click", handleConfirm);
      this.elements.modalCancel.addEventListener("click", handleCancel);
    });
  }

  hideModal() {
    this.elements.modalOverlay.style.display = "none";
  }
}

// Initialize options page when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  new CheckOptions();
});
