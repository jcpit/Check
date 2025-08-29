/**
 * Check - Popup JavaScript
 * Handles popup UI interactions and communication with background script
 */

class CheckPopup {
  constructor() {
    this.currentTab = null;
    this.config = null;
    this.brandingConfig = null;
    this.stats = {
      blockedThreats: 0,
      scannedPages: 0,
      securityEvents: 0,
    };
    this.activityItems = [];
    this.isLoading = false;
    this.isBlockedRoute = false;

    this.elements = {};
    this.bindElements();
    this.setupEventListeners();
    this.initialize();
  }

  bindElements() {
    // Header elements
    this.elements.brandingLogo = document.getElementById("brandingLogo");
    this.elements.brandingTitle = document.getElementById("brandingTitle");
    this.elements.extensionVersion =
      document.getElementById("extensionVersion");
    this.elements.statusIndicator = document.getElementById("statusIndicator");
    this.elements.statusDot = document.getElementById("statusDot");
    this.elements.statusText = document.getElementById("statusText");

    // Action buttons
    this.elements.scanCurrentPage = document.getElementById("scanCurrentPage");
    this.elements.viewLogs = document.getElementById("viewLogs");
    this.elements.openSettings = document.getElementById("openSettings");
    this.elements.reportIssue = document.getElementById("reportIssue");

    // Page info
    this.elements.pageInfoSection = document.getElementById("pageInfoSection");
    this.elements.currentUrl = document.getElementById("currentUrl");
    this.elements.securityStatus = document.getElementById("securityStatus");
    this.elements.securityBadge = document.getElementById("securityBadge");
    this.elements.threatSummary = document.getElementById("threatSummary");
    this.elements.threatList = document.getElementById("threatList");

    // Blocked notice
    this.elements.blockedNotice = document.getElementById("blockedNotice");
    this.elements.blockedUrl = document.getElementById("blockedUrl");

    // Statistics
    this.elements.blockedThreats = document.getElementById("blockedThreats");
    this.elements.scannedPages = document.getElementById("scannedPages");
    this.elements.securityEvents = document.getElementById("securityEvents");

    // Enterprise section
    this.elements.enterpriseSection =
      document.getElementById("enterpriseSection");
    this.elements.managedBy = document.getElementById("managedBy");
    this.elements.complianceBadge = document.getElementById("complianceBadge");

    // Activity
    this.elements.activityList = document.getElementById("activityList");

    // Footer
    this.elements.supportLink = document.getElementById("supportLink");
    this.elements.privacyLink = document.getElementById("privacyLink");
    this.elements.aboutLink = document.getElementById("aboutLink");
    this.elements.companyBranding = document.getElementById("companyBranding");
    this.elements.companyName = document.getElementById("companyName");

    // Overlay elements
    this.elements.loadingOverlay = document.getElementById("loadingOverlay");
    this.elements.notificationToast =
      document.getElementById("notificationToast");
    this.elements.notificationText =
      document.getElementById("notificationText");
    this.elements.notificationClose =
      document.getElementById("notificationClose");

    // Testing elements
    this.elements.testRules = document.getElementById("testRules");
    this.elements.testingSection = document.getElementById("testingSection");
    this.elements.runComprehensiveTest = document.getElementById(
      "runComprehensiveTest"
    );
    this.elements.validateEngine = document.getElementById("validateEngine");
    this.elements.testResults = document.getElementById("testResults");
    this.elements.testSummary = document.getElementById("testSummary");
    this.elements.testDetails = document.getElementById("testDetails");
  }

  setupEventListeners() {
    // Action button listeners
    this.elements.scanCurrentPage.addEventListener("click", () =>
      this.scanCurrentPage()
    );
    this.elements.viewLogs.addEventListener("click", () => this.viewLogs());
    this.elements.openSettings.addEventListener("click", () =>
      this.openSettings()
    );
    this.elements.reportIssue.addEventListener("click", () =>
      this.reportIssue()
    );

    // Testing button listeners
    this.elements.testRules?.addEventListener("click", () =>
      this.toggleTestingSection()
    );
    this.elements.runComprehensiveTest?.addEventListener("click", () =>
      this.runComprehensiveTest()
    );
    this.elements.validateEngine?.addEventListener("click", () =>
      this.validateDetectionEngine()
    );

    // Footer link listeners
    this.elements.supportLink.addEventListener("click", (e) =>
      this.handleFooterLink(e, "support")
    );
    this.elements.privacyLink.addEventListener("click", (e) =>
      this.handleFooterLink(e, "privacy")
    );
    this.elements.aboutLink.addEventListener("click", (e) =>
      this.handleFooterLink(e, "about")
    );

    // Notification close listener
    this.elements.notificationClose.addEventListener("click", () =>
      this.hideNotification()
    );
  }

  async initialize() {
    try {
      this.showLoading("Initializing...");

      // Wait for background script to be ready
      this.showLoading("Connecting to background script...");
      const backgroundReady = await this.waitForBackgroundScript();

      if (!backgroundReady) {
        console.warn(
          "Check: Background script not available, using fallback mode"
        );
        this.config = this.getDefaultConfig();
        this.brandingConfig = { companyName: "Check", productName: "Check" };
        this.applyBranding();
        this.showNotification("Extension running in limited mode", "warning");
        this.hideLoading();
        return;
      }

      // Get current tab
      this.currentTab = await this.getCurrentTab();
      this.isBlockedRoute = this.currentTab?.url?.includes("blocked.html");

      if (this.isBlockedRoute) {
        this.handleBlockedRoute();
      }

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

      this.hideLoading();
    } catch (error) {
      console.error("Check: Failed to initialize popup:", error);
      this.showNotification("Failed to initialize extension", "error");
      this.hideLoading();
    }
  }

  async getCurrentTab() {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    return tabs[0];
  }

  async loadConfiguration() {
    return new Promise((resolve) => {
      // Add a timeout and retry mechanism
      const attemptConnection = (retryCount = 0) => {
        chrome.runtime.sendMessage(
          {
            type: "GET_CONFIG",
          },
          (response) => {
            // Check for connection errors
            if (chrome.runtime.lastError) {
              console.warn(
                "Check: Background script connection failed:",
                chrome.runtime.lastError.message
              );

              // Retry up to 3 times with increasing delay
              if (retryCount < 3) {
                setTimeout(
                  () => attemptConnection(retryCount + 1),
                  500 * (retryCount + 1)
                );
                return;
              } else {
                console.warn(
                  "Check: Using default configuration after connection failures"
                );
                this.config = this.getDefaultConfig();
                resolve();
                return;
              }
            }

            if (response && response.success) {
              this.config = response.config;
            } else {
              this.config = this.getDefaultConfig();
            }
            resolve();
          }
        );
      };

      attemptConnection();
    });
  }

  async loadBrandingConfiguration() {
    try {
      const response = await fetch(
        chrome.runtime.getURL("config/branding.json")
      );
      this.brandingConfig = await response.json();
    } catch (error) {
      console.log("Using default branding configuration");
      this.brandingConfig = this.getDefaultBrandingConfig();
    }
  }

  getDefaultConfig() {
    return {
      extensionEnabled: true,
      enableContentManipulation: true,
      enableUrlMonitoring: true,
      showNotifications: true,
      enterpriseMode: false,
    };
  }

  getDefaultBrandingConfig() {
    return {
      companyName: "CyberDrain",
      productName: "Microsoft 365 Phishing Protection",
      version: "1.0.0",
      logoUrl: "images/icon32.png",
      supportUrl: "https://support.cyberdrain.com",
      privacyPolicyUrl: "https://cyberdrain.com/privacy",
      supportEmail: "support@cyberdrain.com",
      branding: {
        primaryColor: "#F77F00",
        primaryHover: "#E56F00",
        primaryLight: "rgba(247, 127, 0, 0.1)",
        primaryDark: "#D96800",

        secondaryColor: "#003049",
        secondaryHover: "#004B73",
        secondaryLight: "rgba(0, 48, 73, 0.1)",
        secondaryDark: "#002236",

        accentColor: "#005C63",
        successColor: "#005C63",
        warningColor: "#F77F00",
        errorColor: "#DC2626",

        textPrimary: "#FFFFFF",
        textSecondary: "#9CA3AF",
        textMuted: "#6B7280",
        textInverse: "#003049",

        bgPrimary: "#003049",
        bgSecondary: "rgba(255, 255, 255, 0.05)",
        bgSurface: "rgba(255, 255, 255, 0.03)",

        border: "rgba(255, 255, 255, 0.1)",
        borderHover: "rgba(247, 127, 0, 0.3)",
      },
    };
  }

  applyBranding() {
    // Update title and version
    this.elements.brandingTitle.textContent = this.brandingConfig.productName;
    this.elements.extensionVersion.textContent = `v${
      chrome.runtime.getManifest().version
    }`;

    // Update logo
    if (this.brandingConfig.logoUrl) {
      this.elements.brandingLogo.src = chrome.runtime.getURL(
        this.brandingConfig.logoUrl
      );
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

    // Apply custom theme colors if available
    this.applyThemeColors();
  }

  applyThemeColors() {
    if (!this.brandingConfig || !this.brandingConfig.branding) return;

    const branding = this.brandingConfig.branding;
    const root = document.documentElement;

    // Apply primary theme colors
    if (branding.primaryColor) {
      root.style.setProperty("--theme-primary", branding.primaryColor);
    }
    if (branding.primaryHover) {
      root.style.setProperty("--theme-primary-hover", branding.primaryHover);
    }
    if (branding.primaryLight) {
      root.style.setProperty("--theme-primary-light", branding.primaryLight);
    }
    if (branding.primaryDark) {
      root.style.setProperty("--theme-primary-dark", branding.primaryDark);
    }

    // Apply secondary theme colors
    if (branding.secondaryColor) {
      root.style.setProperty("--theme-secondary", branding.secondaryColor);
    }
    if (branding.secondaryHover) {
      root.style.setProperty(
        "--theme-secondary-hover",
        branding.secondaryHover
      );
    }
    if (branding.secondaryLight) {
      root.style.setProperty(
        "--theme-secondary-light",
        branding.secondaryLight
      );
    }
    if (branding.secondaryDark) {
      root.style.setProperty("--theme-secondary-dark", branding.secondaryDark);
    }

    // Apply supporting colors
    if (branding.accentColor) {
      root.style.setProperty("--theme-accent", branding.accentColor);
    }
    if (branding.successColor) {
      root.style.setProperty("--theme-success", branding.successColor);
    }
    if (branding.warningColor) {
      root.style.setProperty("--theme-warning", branding.warningColor);
    }
    if (branding.errorColor) {
      root.style.setProperty("--theme-error", branding.errorColor);
    }

    // Apply text colors
    if (branding.textPrimary) {
      root.style.setProperty("--theme-text-primary", branding.textPrimary);
    }
    if (branding.textSecondary) {
      root.style.setProperty("--theme-text-secondary", branding.textSecondary);
    }
    if (branding.textMuted) {
      root.style.setProperty("--theme-text-muted", branding.textMuted);
    }
    if (branding.textInverse) {
      root.style.setProperty("--theme-text-inverse", branding.textInverse);
    }

    // Apply background colors
    if (branding.bgPrimary) {
      root.style.setProperty("--theme-bg-primary", branding.bgPrimary);
    }
    if (branding.bgSecondary) {
      root.style.setProperty("--theme-bg-secondary", branding.bgSecondary);
    }
    if (branding.bgSurface) {
      root.style.setProperty("--theme-bg-surface", branding.bgSurface);
    }

    // Apply border colors
    if (branding.border) {
      root.style.setProperty("--theme-border", branding.border);
    }
    if (branding.borderHover) {
      root.style.setProperty("--theme-border-hover", branding.borderHover);
    }
  }

  async loadStatistics() {
    try {
      // Get statistics from storage
      const result = await chrome.storage.local.get(["statistics"]);
      if (result.statistics) {
        this.stats = { ...this.stats, ...result.statistics };
      }

      // Update UI
      this.elements.blockedThreats.textContent =
        this.stats.blockedThreats.toLocaleString();
      this.elements.scannedPages.textContent =
        this.stats.scannedPages.toLocaleString();
      this.elements.securityEvents.textContent =
        this.stats.securityEvents.toLocaleString();
    } catch (error) {
      console.error("Failed to load statistics:", error);
    }
  }

  handleBlockedRoute() {
    this.elements.scanCurrentPage.style.display = "none";
    this.elements.pageInfoSection.style.display = "none";

    try {
      const urlParam = new URL(this.currentTab.url).searchParams.get("url");
      if (urlParam) {
        const originalUrl = decodeURIComponent(urlParam);
        const defanged = originalUrl.replace(/\./g, "[.]");
        this.elements.blockedUrl.textContent = defanged;
        this.elements.blockedNotice.style.display = "block";
      }
    } catch (error) {
      console.warn("Check: Failed to parse blocked URL:", error);
    }
  }

  async loadCurrentPageInfo() {
    if (this.isBlockedRoute) {
      return;
    }

    if (!this.currentTab || !this.currentTab.url) {
      this.elements.currentUrl.textContent = "No active tab";
      return;
    }

    try {
      // Display current URL
      const url = new URL(this.currentTab.url);
      this.elements.currentUrl.textContent = url.hostname + url.pathname;

      // Request page analysis from background
      this.showSecurityBadge("analyzing", "Analyzing...");

      try {
        const response = await this.sendMessage({
          type: "URL_ANALYSIS_REQUEST",
          url: this.currentTab.url,
        });

        if (response && response.success && response.analysis) {
          this.updateSecurityStatus(response.analysis);
        } else {
          this.showSecurityBadge("safe", "Analysis unavailable");
        }
      } catch (error) {
        console.warn("Check: Failed to get URL analysis:", error);
        this.showSecurityBadge("safe", "Analysis unavailable");
      }

      // Get page info from content script
      chrome.tabs.sendMessage(
        this.currentTab.id,
        {
          type: "GET_PAGE_INFO",
        },
        (response) => {
          if (response && response.success) {
            this.updatePageInfo(response.info);
          }
        }
      );
    } catch (error) {
      console.error("Failed to load page info:", error);
      this.elements.currentUrl.textContent = "Invalid URL";
      this.showSecurityBadge("safe", "Protected");
    }
  }

  updateSecurityStatus(analysis) {
    const hasThreats = analysis.threats && analysis.threats.length > 0;
    const isBlocked = analysis.isBlocked;
    const isSuspicious =
      analysis.isSuspicious !== undefined ? analysis.isSuspicious : hasThreats;

    if (isBlocked) {
      this.showSecurityBadge("danger", "Blocked");
      this.showThreats(analysis.threats);
    } else if (isSuspicious) {
      this.showSecurityBadge("warning", "Suspicious");
      this.showThreats(analysis.threats);
    } else {
      this.showSecurityBadge("safe", "Safe");
      this.hideThreats();
    }
  }

  showSecurityBadge(type, text) {
    this.elements.securityBadge.textContent = text;
    this.elements.securityBadge.className = `security-badge ${type}`;
  }

  showThreats(threats) {
    if (threats && threats.length > 0) {
      this.elements.threatSummary.style.display = "block";
      this.elements.threatList.innerHTML = "";

      threats.forEach((threat) => {
        const li = document.createElement("li");
        li.textContent = `${threat.type}: ${threat.description}`;
        this.elements.threatList.appendChild(li);
      });
    } else {
      this.hideThreats();
    }
  }

  hideThreats() {
    this.elements.threatSummary.style.display = "none";
  }

  updatePageInfo(pageInfo) {
    // Could update additional page information here
    console.log("Page info received:", pageInfo);
  }

  async loadRecentActivity() {
    try {
      // Get recent security events
      const result = await chrome.storage.local.get(["securityEvents"]);
      const events = result.securityEvents || [];

      // Get recent 5 events
      const recentEvents = events.slice(-5).reverse();

      if (recentEvents.length === 0) {
        this.elements.activityList.innerHTML =
          '<div class="activity-item placeholder"><span class="activity-text">No recent activity</span></div>';
        return;
      }

      this.elements.activityList.innerHTML = "";
      recentEvents.forEach((event) => {
        this.addActivityItem(event);
      });
    } catch (error) {
      console.error("Failed to load recent activity:", error);
    }
  }

  addActivityItem(event) {
    const item = document.createElement("div");
    item.className = "activity-item";

    const icon = document.createElement("div");
    icon.className = `activity-icon material-icons ${this.getActivityIconType(
      event.event.type
    )}`;
    icon.textContent = this.getActivityIcon(event.event.type);

    const text = document.createElement("span");
    text.className = "activity-text";
    text.textContent = this.getActivityText(event.event);

    const time = document.createElement("span");
    time.className = "activity-time";
    time.textContent = this.formatTime(new Date(event.timestamp));

    item.appendChild(icon);
    item.appendChild(text);
    item.appendChild(time);

    this.elements.activityList.appendChild(item);
  }

  getActivityIconType(eventType) {
    if (eventType.includes("block") || eventType.includes("threat"))
      return "blocked";
    if (eventType.includes("warning") || eventType.includes("suspicious"))
      return "warned";
    return "scanned";
  }

  getActivityIcon(eventType) {
    if (eventType.includes("block")) return "security";
    if (eventType.includes("warning")) return "warning";
    if (eventType.includes("scan")) return "search";
    return "description";
  }

  getActivityText(event) {
    switch (event.type) {
      case "url_access":
        return `Scanned ${new URL(event.url).hostname}`;
      case "content_threat_detected":
        return `Threat detected on ${new URL(event.url).hostname}`;
      case "form_submission":
        return "Form submission monitored";
      case "script_injection":
        return "Script injection executed";
      default:
        return event.type.replace(/_/g, " ");
    }
  }

  formatTime(date) {
    const now = new Date();
    const diff = now - date;

    if (diff < 60000) return "now";
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h`;
    return `${Math.floor(diff / 86400000)}d`;
  }

  async checkEnterpriseMode() {
    if (this.config.enterpriseMode) {
      this.elements.enterpriseSection.style.display = "block";

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
    this.elements.complianceBadge.textContent = isCompliant
      ? "Compliant"
      : "Non-Compliant";
    this.elements.complianceBadge.className = isCompliant
      ? "compliance-badge"
      : "compliance-badge non-compliant";
  }

  updateStatusIndicator() {
    if (this.config.extensionEnabled) {
      this.elements.statusDot.className = "status-dot";
      this.elements.statusText.textContent = "Active";
    } else {
      this.elements.statusDot.className = "status-dot inactive";
      this.elements.statusText.textContent = "Disabled";
    }
  }

  async scanCurrentPage() {
    if (this.isBlockedRoute || !this.currentTab) return;

    try {
      this.showLoading("Scanning page...");

      // Request page scan
      chrome.tabs.sendMessage(
        this.currentTab.id,
        {
          type: "ANALYZE_PAGE",
        },
        (response) => {
          this.hideLoading();

          if (response && response.success) {
            this.showNotification("Page scan completed", "success");
            this.updateSecurityStatus(response.analysis);

            // Update statistics
            this.stats.scannedPages++;
            this.updateStatistics();
          } else {
            this.showNotification("Page scan failed", "error");
          }
        }
      );
    } catch (error) {
      this.hideLoading();
      console.error("Failed to scan page:", error);
      this.showNotification("Page scan failed", "error");
    }
  }

  viewLogs() {
    chrome.tabs.create({
      url: chrome.runtime.getURL("options/options.html#logs"),
    });
    window.close();
  }

  openSettings() {
    chrome.tabs.create({
      url: chrome.runtime.getURL("options/options.html"),
    });
    window.close();
  }

  reportIssue() {
    if (this.brandingConfig.supportEmail) {
      const subject = encodeURIComponent("Check - Issue Report");
      const body = encodeURIComponent(`
Extension Version: ${chrome.runtime.getManifest().version}
Current URL: ${this.currentTab?.url || "N/A"}
Browser: ${navigator.userAgent}

Issue Description:
[Please describe the issue you're experiencing]
      `);

      window.open(
        `mailto:${this.brandingConfig.supportEmail}?subject=${subject}&body=${body}`
      );
    } else if (this.brandingConfig.supportUrl) {
      chrome.tabs.create({ url: this.brandingConfig.supportUrl });
    } else {
      this.showNotification("Support contact not configured", "warning");
    }
    window.close();
  }

  handleFooterLink(event, linkType) {
    event.preventDefault();

    let url = "";
    switch (linkType) {
      case "support":
        url = this.brandingConfig.supportUrl;
        break;
      case "privacy":
        url = this.brandingConfig.privacyPolicyUrl;
        break;
      case "about":
        url = chrome.runtime.getURL("options/options.html#about");
        break;
    }

    if (url) {
      chrome.tabs.create({ url });
      window.close();
    }
  }

  async checkBackgroundScript() {
    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        resolve(false);
      }, 2000); // 2 second timeout

      try {
        chrome.runtime.sendMessage({ type: "ping" }, (response) => {
          clearTimeout(timeout);
          const isAvailable =
            !chrome.runtime.lastError && response && response.success;
          if (chrome.runtime.lastError) {
            console.warn(
              "Check: Background script ping failed:",
              chrome.runtime.lastError.message
            );
          }
          resolve(isAvailable);
        });
      } catch (error) {
        clearTimeout(timeout);
        console.warn("Check: Failed to ping background script:", error);
        resolve(false);
      }
    });
  }

  async waitForBackgroundScript(maxAttempts = 5) {
    for (let i = 0; i < maxAttempts; i++) {
      const isAvailable = await this.checkBackgroundScript();
      if (isAvailable) {
        return true;
      }
      // Wait before next attempt (shorter delay since we have timeout in checkBackgroundScript)
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
    return false;
  }

  async sendMessage(message, retryCount = 0) {
    return new Promise((resolve, reject) => {
      chrome.runtime.sendMessage(message, (response) => {
        // Check for connection errors
        if (chrome.runtime.lastError) {
          console.warn(
            "Check: Background script connection failed:",
            chrome.runtime.lastError.message
          );

          // Retry up to 3 times with increasing delay
          if (retryCount < 3) {
            setTimeout(() => {
              this.sendMessage(message, retryCount + 1)
                .then(resolve)
                .catch(reject);
            }, 500 * (retryCount + 1));
            return;
          } else {
            reject(
              new Error(
                `Connection failed after ${retryCount + 1} attempts: ${
                  chrome.runtime.lastError.message
                }`
              )
            );
            return;
          }
        }

        resolve(response);
      });
    });
  }

  async updateStatistics() {
    try {
      await chrome.storage.local.set({ statistics: this.stats });
      this.elements.scannedPages.textContent =
        this.stats.scannedPages.toLocaleString();
    } catch (error) {
      console.error("Failed to update statistics:", error);
    }
  }

  showLoading(text = "Loading...") {
    this.isLoading = true;
    this.elements.loadingOverlay.style.display = "flex";
    if (this.elements.loadingOverlay.querySelector(".loading-text")) {
      this.elements.loadingOverlay.querySelector(".loading-text").textContent =
        text;
    }
  }

  hideLoading() {
    this.isLoading = false;
    this.elements.loadingOverlay.style.display = "none";
  }

  showNotification(text, type = "info") {
    this.elements.notificationText.textContent = text;
    this.elements.notificationToast.className = `notification-toast ${type}`;
    this.elements.notificationToast.style.display = "flex";

    // Auto-hide after 3 seconds
    setTimeout(() => {
      this.hideNotification();
    }, 3000);
  }

  hideNotification() {
    this.elements.notificationToast.style.display = "none";
  }

  // Testing Methods
  toggleTestingSection() {
    const testingSection = this.elements.testingSection;
    if (testingSection.style.display === "none") {
      testingSection.style.display = "block";
      this.elements.testRules.classList.add("active");
    } else {
      testingSection.style.display = "none";
      this.elements.testRules.classList.remove("active");
    }
  }

  async runComprehensiveTest() {
    this.showLoading("Running comprehensive test...");
    this.elements.testResults.style.display = "none";

    try {
      const response = await this.sendMessage({
        type: "RUN_COMPREHENSIVE_TEST",
      });

      if (response && response.success) {
        this.displayTestResults(response.tests);
        this.showNotification("Comprehensive test completed", "success");
      } else {
        this.showNotification(
          "Test failed: " + (response?.error || "Unknown error"),
          "error"
        );
      }
    } catch (error) {
      console.error("Failed to run comprehensive test:", error);
      this.showNotification("Test execution failed", "error");
    } finally {
      this.hideLoading();
    }
  }

  async validateDetectionEngine() {
    this.showLoading("Validating detection engine...");
    this.elements.testResults.style.display = "none";

    try {
      const response = await this.sendMessage({
        type: "VALIDATE_DETECTION_ENGINE",
      });

      if (response && response.success) {
        this.displayValidationResults(response.validation);
        this.showNotification("Engine validation completed", "success");
      } else {
        this.showNotification(
          "Validation failed: " + (response?.error || "Unknown error"),
          "error"
        );
      }
    } catch (error) {
      console.error("Failed to validate detection engine:", error);
      this.showNotification("Validation execution failed", "error");
    } finally {
      this.hideLoading();
    }
  }

  displayTestResults(testSuites) {
    const summary = this.elements.testSummary;
    const details = this.elements.testDetails;

    // Clear previous results
    summary.innerHTML = "";
    details.innerHTML = "";

    // Calculate overall statistics
    let totalTests = 0;
    let passedTests = 0;
    let failedTests = 0;

    for (const suite of testSuites) {
      const suiteResults = suite.results;
      if (Array.isArray(suiteResults)) {
        totalTests += suiteResults.length;
        passedTests += suiteResults.filter((test) => test.passed).length;
        failedTests += suiteResults.filter((test) => !test.passed).length;
      }
    }

    // Display summary
    const passRate =
      totalTests > 0 ? Math.round((passedTests / totalTests) * 100) : 0;
    summary.innerHTML = `
      <div class="test-summary-stats">
        <div class="test-stat">
          <span class="test-stat-number">${totalTests}</span>
          <span class="test-stat-label">Total Tests</span>
        </div>
        <div class="test-stat success">
          <span class="test-stat-number">${passedTests}</span>
          <span class="test-stat-label">Passed</span>
        </div>
        <div class="test-stat error">
          <span class="test-stat-number">${failedTests}</span>
          <span class="test-stat-label">Failed</span>
        </div>
        <div class="test-stat">
          <span class="test-stat-number">${passRate}%</span>
          <span class="test-stat-label">Pass Rate</span>
        </div>
      </div>
    `;

    // Display detailed results
    let detailsHtml = "";
    for (const suite of testSuites) {
      const suitePassed = Array.isArray(suite.results)
        ? suite.results.filter((test) => test.passed).length
        : 0;
      const suiteTotal = Array.isArray(suite.results)
        ? suite.results.length
        : 0;

      detailsHtml += `
        <div class="test-suite">
          <h4 class="test-suite-title">
            ${suite.suite}
            <span class="test-suite-stats">(${suitePassed}/${suiteTotal})</span>
          </h4>
          <div class="test-suite-results">
      `;

      if (Array.isArray(suite.results)) {
        for (const test of suite.results) {
          const statusIcon = test.passed ? "✓" : "✗";
          const statusClass = test.passed ? "success" : "error";

          detailsHtml += `
            <div class="test-result ${statusClass}">
              <span class="test-status">${statusIcon}</span>
              <span class="test-description">${
                test.url || test.referrer || test.expected || "Test"
              }</span>
              ${
                test.error
                  ? `<span class="test-error">${test.error}</span>`
                  : ""
              }
            </div>
          `;
        }
      }

      detailsHtml += `
          </div>
        </div>
      `;
    }

    details.innerHTML = detailsHtml;
    this.elements.testResults.style.display = "block";
  }

  displayValidationResults(validation) {
    const summary = this.elements.testSummary;
    const details = this.elements.testDetails;

    // Clear previous results
    summary.innerHTML = "";
    details.innerHTML = "";

    // Display validation summary
    const engineStatus = validation.engineInitialized
      ? "Initialized"
      : "Not Initialized";
    const engineClass = validation.engineInitialized ? "success" : "error";

    summary.innerHTML = `
      <div class="validation-summary">
        <div class="validation-item ${engineClass}">
          <span class="validation-label">Detection Engine:</span>
          <span class="validation-value">${engineStatus}</span>
        </div>
        <div class="validation-item">
          <span class="validation-label">Status:</span>
          <span class="validation-value">${
            validation.detectionEngineStatus
          }</span>
        </div>
        <div class="validation-item">
          <span class="validation-label">Timestamp:</span>
          <span class="validation-value">${new Date(
            validation.timestamp
          ).toLocaleString()}</span>
        </div>
      </div>
    `;

    // Display detailed validation results
    let detailsHtml = '<div class="validation-details">';

    // Rules validation
    if (validation.rulesValidation) {
      const rules = validation.rulesValidation;
      detailsHtml += `
        <div class="validation-section">
          <h4>Rules Validation</h4>
          <div class="validation-grid">
            <div class="validation-stat">
              <span class="validation-number">${rules.rulesCount || 0}</span>
              <span class="validation-label">Total Rules</span>
            </div>
            <div class="validation-stat success">
              <span class="validation-number">${rules.validRules || 0}</span>
              <span class="validation-label">Valid Rules</span>
            </div>
            <div class="validation-stat error">
              <span class="validation-number">${rules.invalidRules || 0}</span>
              <span class="validation-label">Invalid Rules</span>
            </div>
          </div>
          ${
            rules.issues && rules.issues.length > 0
              ? `<div class="validation-issues">
              <h5>Issues:</h5>
              <ul>${rules.issues
                .map((issue) => `<li>${issue}</li>`)
                .join("")}</ul>
            </div>`
              : ""
          }
        </div>
      `;
    }

    // Components validation
    if (validation.componentsStatus) {
      const components = validation.componentsStatus;
      detailsHtml += `
        <div class="validation-section">
          <h4>Components Status</h4>
          <div class="component-status">
            <div class="component-item">Config Manager: <span class="${
              components.configManager === "loaded" ? "success" : "error"
            }">${components.configManager}</span></div>
            <div class="component-item">Detection Engine: <span class="${
              components.detectionEngine === "loaded" ? "success" : "error"
            }">${components.detectionEngine}</span></div>
            <div class="component-item">Policy Manager: <span class="${
              components.policyManager === "loaded" ? "success" : "error"
            }">${components.policyManager}</span></div>
            <div class="component-item">Engine Initialized: <span class="${
              components.detectionEngineInitialized ? "success" : "error"
            }">${
        components.detectionEngineInitialized ? "Yes" : "No"
      }</span></div>
          </div>
        </div>
      `;
    }

    // Configuration validation
    if (validation.configurationStatus) {
      const config = validation.configurationStatus;
      detailsHtml += `
        <div class="validation-section">
          <h4>Configuration Status</h4>
          <div class="config-status">
            <div class="config-item">Config Loaded: <span class="${
              config.configLoaded ? "success" : "error"
            }">${config.configLoaded ? "Yes" : "No"}</span></div>
            <div class="config-item">Valid Referrers: <span class="${
              config.hasValidReferrers ? "success" : "warning"
            }">${
        config.hasValidReferrers ? "Configured" : "Not Configured"
      }</span></div>
            <div class="config-item">Whitelist Domains: <span class="${
              config.hasWhitelistDomains ? "success" : "warning"
            }">${
        config.hasWhitelistDomains ? "Configured" : "Not Configured"
      }</span></div>
            <div class="config-item">Detection Enabled: <span class="${
              config.detectionEnabled ? "success" : "error"
            }">${config.detectionEnabled ? "Yes" : "No"}</span></div>
          </div>
        </div>
      `;
    }

    detailsHtml += "</div>";
    details.innerHTML = detailsHtml;
    this.elements.testResults.style.display = "block";
  }
}

// Initialize popup when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  // Add a small delay to ensure background script is ready
  setTimeout(() => {
    new CheckPopup();
  }, 100);
});
