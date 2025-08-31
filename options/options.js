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
    this.elements.enableLogging = document.getElementById("enableLogging");
    this.elements.enableDebugLogging = document.getElementById("enableDebugLogging");
    this.elements.logLevel = document.getElementById("logLevel");
    this.elements.maxLogEntries = document.getElementById("maxLogEntries");

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

    // About
    this.elements.aboutVersion = document.getElementById("aboutVersion");
    this.elements.buildDate = document.getElementById("buildDate");
    this.elements.browserInfo = document.getElementById("browserInfo");
    this.elements.osInfo = document.getElementById("osInfo");
    this.elements.supportUrl = document.getElementById("supportUrl");
    this.elements.privacyUrl = document.getElementById("privacyUrl");
    this.elements.termsUrl = document.getElementById("termsUrl");

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
    this.elements.logFilter?.addEventListener("change", () =>
      this.filterLogs()
    );
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
      // Show initial status
      this.showToast("Connecting to background service...", "info");

      // Load configurations
      await this.loadConfiguration();
      await this.loadBrandingConfiguration();

      // Apply branding
      this.applyBranding();

      // Populate form fields
      this.populateFormFields();

      // Load dynamic content
      await this.loadPolicyInfo();
      await this.loadLogs();
      await this.loadSystemInfo();

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

  async sendMessageWithRetry(message, maxAttempts = 3, initialDelay = 200) {
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        // First ensure service worker is alive
        if (attempt === 1) {
          const serviceWorkerAlive = await this.ensureServiceWorkerAlive();
          if (!serviceWorkerAlive) {
            throw new Error(
              "Service worker not responding after wake-up attempts"
            );
          }
        }

        const response = await new Promise((resolve, reject) => {
          chrome.runtime.sendMessage(message, (response) => {
            if (chrome.runtime.lastError) {
              const error = chrome.runtime.lastError.message;
              if (
                error.includes("Receiving end does not exist") ||
                error.includes("Could not establish connection")
              ) {
                reject(new Error(`Service worker connection failed: ${error}`));
              } else {
                reject(new Error(error));
              }
            } else {
              resolve(response);
            }
          });
        });

        return response;
      } catch (error) {
        console.warn(`Message attempt ${attempt} failed:`, error.message);

        if (attempt === maxAttempts) {
          throw error;
        }

        // Exponential backoff for retries
        const delay = initialDelay * Math.pow(2, attempt - 1);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }

  async loadConfiguration() {
    try {
      const response = await this.sendMessageWithRetry({
        type: "GET_CONFIG",
      });

      if (response && response.success) {
        this.config = response.config;
        this.originalConfig = JSON.parse(JSON.stringify(response.config));
      } else {
        console.warn("Failed to load config from background, using defaults");
        this.config = this.getDefaultConfig();
        this.originalConfig = JSON.parse(JSON.stringify(this.config));
      }
    } catch (error) {
      console.error("Could not communicate with background script:", error);
      this.showToast(
        "Using default settings - background script unavailable",
        "warning"
      );
      this.config = this.getDefaultConfig();
      this.originalConfig = JSON.parse(JSON.stringify(this.config));
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
      // Wait for runtime to be ready before calling chrome.runtime.getURL
      await this.waitForRuntimeReady();

      const response = await fetch(
        chrome.runtime.getURL("config/branding.json")
      );

      if (!response.ok) {
        throw new Error(
          `Failed to load branding config: ${response.status} ${response.statusText}`
        );
      }

      this.brandingConfig = await response.json();
    } catch (error) {
      console.warn(
        "Failed to load branding configuration, using defaults:",
        error
      );
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
      enableValidPageBadge: false,
      enableCustomRules: false,
      customRulesUrl: "",
      updateInterval: 24,
      enableLogging: true,
      enableDebugLogging: false,
      logLevel: "info",
      maxLogEntries: 1000,
    };
  }

  getDefaultBrandingConfig() {
    return {
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

  applyBranding() {
    // Update sidebar branding
    document.getElementById("sidebarTitle").textContent =
      this.brandingConfig.productName;
    document.getElementById("sidebarVersion").textContent = `v${
      chrome.runtime.getManifest().version
    }`;

    // Update about section
    this.elements.aboutVersion.textContent =
      chrome.runtime.getManifest().version;
    this.elements.buildDate.textContent = new Date()
      .toISOString()
      .split("T")[0];

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
    this.elements.enableContentManipulation.checked =
      this.config.enableContentManipulation;
    this.elements.enableUrlMonitoring.checked = this.config.enableUrlMonitoring;
    this.elements.showNotifications.checked = this.config.showNotifications;
    this.elements.notificationDuration.value = this.config.notificationDuration;
    this.elements.notificationDurationValue.textContent =
      this.config.notificationDuration / 1000 + "s";
    this.elements.enableValidPageBadge.checked =
      this.config.enableValidPageBadge || false;

    // Detection settings
    this.elements.enableCustomRules.checked =
      this.config.detectionRules?.enableCustomRules || this.config.enableCustomRules || false;
    this.elements.customRulesUrl.value =
      this.config.detectionRules?.customRulesUrl || this.config.customRulesUrl || "";
    this.elements.updateInterval.value =
      (this.config.detectionRules?.updateInterval || this.config.updateInterval * 3600000 || 86400000) / 3600000;

    // Logging settings
    this.elements.enableLogging.checked = this.config.enableLogging;
    this.elements.enableDebugLogging.checked = this.config.enableDebugLogging || false;
    this.elements.logLevel.value = this.config.logLevel;
    this.elements.maxLogEntries.value = this.config.maxLogEntries;

    // Branding settings
    this.elements.companyName.value = this.brandingConfig.companyName;
    this.elements.productName.value = this.brandingConfig.productName;
    this.elements.supportEmail.value = this.brandingConfig.supportEmail;
    this.elements.primaryColor.value = this.brandingConfig.primaryColor;
    this.elements.logoUrl.value = this.brandingConfig.logoUrl;
    this.elements.customCss.value = this.brandingConfig.customCss || "";
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

      if (response.success) {
        this.config = newConfig;
        this.originalConfig = JSON.parse(JSON.stringify(newConfig));
        this.hasUnsavedChanges = false;
        this.updateSaveButton();
        this.showToast("Settings saved successfully", "success");
      } else {
        throw new Error(response.error || "Failed to save settings");
      }
    } catch (error) {
      console.error("Failed to save settings:", error);
      this.showToast("Failed to save settings", "error");
    }
  }

  gatherFormData() {
    return {
      // General settings
      extensionEnabled: this.elements.extensionEnabled.checked,
      enableContentManipulation:
        this.elements.enableContentManipulation.checked,
      enableUrlMonitoring: this.elements.enableUrlMonitoring.checked,
      showNotifications: this.elements.showNotifications.checked,
      notificationDuration: parseInt(this.elements.notificationDuration.value),
      enableValidPageBadge: this.elements.enableValidPageBadge.checked,

      // Detection settings
      enableCustomRules: this.elements.enableCustomRules.checked,
      customRulesUrl: this.elements.customRulesUrl.value,
      updateInterval: parseInt(this.elements.updateInterval.value),

      // Logging settings
      enableLogging: this.elements.enableLogging.checked,
      enableDebugLogging: this.elements.enableDebugLogging.checked,
      logLevel: this.elements.logLevel.value,
      maxLogEntries: parseInt(this.elements.maxLogEntries.value),
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

    if (config.maxLogEntries < 100 || config.maxLogEntries > 10000) {
      return {
        valid: false,
        message: "Max log entries must be between 100-10000",
      };
    }

    if (
      config.updateInterval < 1 ||
      config.updateInterval > 168
    ) {
      return {
        valid: false,
        message: "Update interval must be between 1-168 hours",
      };
    }

    // URL validation
    if (
      config.customRulesUrl &&
      !this.isValidUrl(config.customRulesUrl)
    ) {
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
      const response = await fetch(
        chrome.runtime.getURL("rules/detection-rules.json")
      );
      const defaultRules = await response.json();
      this.elements.customRulesEditor.value = JSON.stringify(
        defaultRules,
        null,
        2
      );
      this.showToast("Default rules loaded", "success");
    } catch (error) {
      console.error("Failed to load default rules:", error);
      this.showToast("Failed to load default rules", "error");
    }
  }

  async loadEnterpriseInfo() {
    try {
      // Check if extension is managed
      const policies = await chrome.storage.managed.get(null);
      const isManaged = Object.keys(policies).length > 0;

      if (isManaged) {
        this.elements.managementStatus.textContent = "Managed";
        this.elements.managementStatus.classList.add("managed");
        this.elements.enterpriseStatus.querySelector(
          ".status-description"
        ).textContent =
          "This extension is managed by your organization's IT department";

        // Update policy list
        this.updatePolicyList(policies);
      } else {
        this.elements.managementStatus.textContent = "Not Managed";
        this.elements.managementStatus.classList.remove("managed");
      }
    } catch (error) {
      console.error("Failed to load enterprise info:", error);
    }
  }

  updatePolicyList(policies) {
    this.elements.policyList.innerHTML = "";

    const policyNames = {
      extensionEnabled: "Extension Enabled",
      enableContentManipulation: "Content Manipulation",
      enableUrlMonitoring: "URL Monitoring",
      blockMaliciousUrls: "Block Malicious URLs",
      enableLogging: "Activity Logging",
    };

    Object.keys(policies).forEach((policyKey) => {
      if (policyNames[policyKey]) {
        const item = document.createElement("div");
        item.className = "policy-item";

        const name = document.createElement("span");
        name.className = "policy-name";
        name.textContent = policyNames[policyKey];

        const status = document.createElement("span");
        status.className = "policy-status enforced";
        status.textContent = "Enforced";

        item.appendChild(name);
        item.appendChild(status);
        this.elements.policyList.appendChild(item);
      }
    });
  }

  async loadLogs() {
    try {
      const result = await chrome.storage.local.get([
        "securityEvents",
        "accessLogs",
        "debugLogs",
      ]);
      const securityEvents = result.securityEvents || [];
      const accessLogs = result.accessLogs || [];
      const debugLogs = result.debugLogs || [];

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
        '<span class="log-message" style="grid-column: 1 / -1; text-align: center; color: #9ca3af;">No logs available</span>';
      this.elements.logsList.appendChild(item);
      return;
    }

    logs.slice(0, 100).forEach((log) => {
      const item = document.createElement("div");
      item.className = "log-entry";

      const time = document.createElement("span");
      time.className = "log-time";
      time.textContent = new Date(log.timestamp).toLocaleString();

      const type = document.createElement("span");
      type.className = `log-type ${log.category}`;
      type.textContent =
        log.category === "debug"
          ? log.level
          : log.event?.type || log.type || "unknown";

      const message = document.createElement("span");
      message.className = "log-message";
      message.textContent = this.formatLogMessage(log);

      item.appendChild(time);
      item.appendChild(type);
      item.appendChild(message);

      this.elements.logsList.appendChild(item);
    });
  }

  formatLogMessage(log) {
    if (log.category === "debug") {
      return log.message || "";
    }
    if (log.event) {
      switch (log.event.type) {
        case "url_access":
          return `Accessed: ${new URL(log.event.url).hostname}`;
        case "content_threat_detected":
          return `Threat detected on ${new URL(log.event.url).hostname}`;
        case "form_submission":
          return `Form submitted to ${log.event.action || "unknown"}`;
        case "script_injection":
          return `Script injected on page`;
        default:
          return log.event.type.replace(/_/g, " ");
      }
    }
    return log.type || "Unknown event";
  }

  filterLogs() {
    // Implementation for log filtering
    this.loadLogs();
  }

  async clearLogs() {
    const confirmed = await this.showConfirmDialog(
      "Clear All Logs",
      "Are you sure you want to clear all activity logs? This action cannot be undone."
    );

    if (confirmed) {
      try {
        await chrome.storage.local.remove([
          "securityEvents",
          "accessLogs",
          "debugLogs",
        ]);
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
      const result = await chrome.storage.local.get([
        "securityEvents",
        "accessLogs",
        "debugLogs",
      ]);
      const exportData = {
        securityEvents: result.securityEvents || [],
        accessLogs: result.accessLogs || [],
        debugLogs: result.debugLogs || [],
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
