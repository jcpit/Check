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
    this.elements.statusIndicator = document.getElementById("statusIndicator");
    this.elements.statusDot = document.getElementById("statusDot");
    this.elements.statusText = document.getElementById("statusText");

    // Action buttons
    this.elements.openSettings = document.getElementById("openSettings");

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
  }

  setupEventListeners() {
    // Action button listeners
    this.elements.openSettings.addEventListener("click", () =>
      this.openSettings()
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
      console.log("Check: Initializing popup...");
      const backgroundReady = await this.waitForBackgroundScript();
      console.log("Check: Background script ready:", backgroundReady);
      if (!backgroundReady) {
        console.warn(
          "Check: Background script not available, using fallback mode"
        );
        console.log("Check: Using fallback configuration");
        this.config = {
          showNotifications: true,
          enableDebugLogging: false,
        };
        console.log("Still loading");
        this.brandingConfig = { companyName: "Check", productName: "Check" };
        this.applyBranding();
        console.log("Applying default branding");

        // Initialize theme even in fallback mode
        await this.initializeTheme();

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

      // Initialize theme
      await this.initializeTheme();

      // Load data
      await this.loadStatistics();
      await this.loadCurrentPageInfo();
      await this.checkEnterpriseMode();

      this.hideLoading();
    } catch (error) {
      console.error("Check: Failed to initialize popup:", error);
      this.showNotification("Failed to initialize extension", "error");
      this.hideLoading();
    }
  }

  async getCurrentTab() {
    try {
      const tabs = await chrome.tabs.query({
        active: true,
        currentWindow: true,
      });
      return tabs[0];
    } catch (error) {
      console.error("Check: Failed to get current tab:", error);
      return null;
    }
  }

  async loadConfiguration() {
    return new Promise((resolve) => {
      const attemptConnection = (retryCount = 0) => {
        try {
          chrome.runtime.sendMessage({ type: "GET_CONFIG" }, (response) => {
            if (chrome.runtime.lastError) {
              console.warn(
                "Check: Background script connection failed:",
                chrome.runtime.lastError.message
              );

              // Retry up to 3 times with 5-second delay
              if (retryCount < 3) {
                console.log(
                  `Retrying configuration load in 5 seconds... (attempt ${
                    retryCount + 1
                  }/3)`
                );
                setTimeout(() => attemptConnection(retryCount + 1), 5000);
                return;
              } else {
                console.warn(
                  "Check: Using default configuration after all retries failed"
                );
                this.config = {
                  extensionEnabled: true,
                  showNotifications: true,
                  enableDebugLogging: false,
                };
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
          });
        } catch (error) {
          console.error("Check: Error sending message:", error);
          if (retryCount < 3) {
            console.log(
              `Retrying configuration load in 5 seconds... (attempt ${
                retryCount + 1
              }/3)`
            );
            setTimeout(() => attemptConnection(retryCount + 1), 5000);
          } else {
            this.config = {
              extensionEnabled: true,
              showNotifications: true,
              enableDebugLogging: false,
            };
            resolve();
          }
        }
      };

      attemptConnection();
    });
  }

  async loadBrandingConfiguration() {
    try {
      // Get branding configuration from background script (centralized through config manager)
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage(
          { type: "GET_BRANDING_CONFIG" },
          (response) => {
            if (chrome.runtime.lastError) {
              console.warn(
                "Failed to get branding from background:",
                chrome.runtime.lastError.message
              );
              resolve(null);
            } else {
              resolve(response);
            }
          }
        );
      });

      if (response && response.success && response.branding) {
        this.brandingConfig = response.branding;
        console.log(
          "Popup: Loaded branding from background script:",
          this.brandingConfig
        );
        return;
      }

      // Fallback to default branding if background script fails
      console.warn("Popup: Using fallback branding configuration");
      this.brandingConfig = {
        companyName: "CyberDrain",
        productName: "Check",
        logoUrl: "images/icon32.png",
        supportUrl: "https://support.cyberdrain.com",
        privacyPolicyUrl: "https://cyberdrain.com/privacy",
        primaryColor: "#F77F00",
      };
    } catch (error) {
      console.error("Error loading branding configuration:", error);
      this.brandingConfig = {
        companyName: "CyberDrain",
        productName: "Check",
        logoUrl: "images/icon32.png",
        supportUrl: "https://support.cyberdrain.com",
        privacyPolicyUrl: "https://cyberdrain.com/privacy",
        primaryColor: "#F77F00",
      };
    }
  }

  applyBranding() {
    console.log("Applying branding:", this.brandingConfig);

    // Update title
    this.elements.brandingTitle.textContent =
      this.brandingConfig.productName || "Check";

    // Update logo with fallback handling
    if (this.brandingConfig.logoUrl) {
      console.log("Setting custom logo:", this.brandingConfig.logoUrl);

      // Handle both relative and absolute URLs
      const logoSrc = this.brandingConfig.logoUrl.startsWith("http")
        ? this.brandingConfig.logoUrl
        : chrome.runtime.getURL(this.brandingConfig.logoUrl);

      // Test if logo loads, fallback to default if it fails
      const testImg = new Image();
      testImg.onload = () => {
        console.log("Custom logo loaded successfully");
        this.elements.brandingLogo.src = logoSrc;
      };
      testImg.onerror = () => {
        console.warn("Failed to load custom logo, using default");
        this.elements.brandingLogo.src =
          chrome.runtime.getURL("images/icon32.png");
      };
      testImg.src = logoSrc;
    } else {
      console.log("No custom logo, using default");
      this.elements.brandingLogo.src =
        chrome.runtime.getURL("images/icon32.png");
    }

    // Update company name
    this.elements.companyName.textContent =
      this.brandingConfig.companyName || "CyberDrain";

    // Update link URLs with fallbacks
    if (this.brandingConfig.supportUrl) {
      this.elements.supportLink.href = this.brandingConfig.supportUrl;
    }
    if (this.brandingConfig.privacyPolicyUrl) {
      this.elements.privacyLink.href = this.brandingConfig.privacyPolicyUrl;
    }

    // Apply primary color if available
    if (this.brandingConfig.primaryColor) {
      console.log("Applying primary color:", this.brandingConfig.primaryColor);
      const style = document.createElement("style");
      style.id = "custom-branding-css";
      style.textContent = `
        :root {
          --theme-primary: ${this.brandingConfig.primaryColor} !important;
          --theme-primary-hover: ${this.brandingConfig.primaryColor}dd !important;
        }
        .action-btn.primary {
          background-color: ${this.brandingConfig.primaryColor} !important;
        }
        .action-btn.primary:hover {
          background-color: ${this.brandingConfig.primaryColor}dd !important;
        }
      `;
      document.head.appendChild(style);
    }

    // Apply custom theme colors if available (legacy support)
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
      // First try to get statistics from background script
      try {
        const response = await this.sendMessage({ type: "GET_STATISTICS" });
        if (response && response.success && response.statistics) {
          this.stats = {
            blockedThreats: response.statistics.blockedThreats || 0,
            scannedPages: response.statistics.scannedPages || 0,
            securityEvents: response.statistics.securityEvents || 0,
          };

          // Update UI
          this.elements.blockedThreats.textContent =
            this.stats.blockedThreats.toLocaleString();
          this.elements.scannedPages.textContent =
            this.stats.scannedPages.toLocaleString();
          this.elements.securityEvents.textContent =
            this.stats.securityEvents.toLocaleString();

          console.log("Statistics loaded from background script:", this.stats);
          return;
        }
      } catch (backgroundError) {
        console.warn(
          "Failed to get statistics from background script:",
          backgroundError
        );
      }

      // Fallback: calculate statistics from storage directly
      console.log("Using fallback statistics calculation");

      // Safe wrapper for chrome.* operations
      const safe = async (promise) => {
        try {
          return await promise;
        } catch (_) {
          return {};
        }
      };

      // Get logs from storage for fallback calculation
      const result = await safe(
        chrome.storage.local.get(["securityEvents", "accessLogs"])
      );

      const securityEvents = result?.securityEvents || [];
      const accessLogs = result?.accessLogs || [];

      // Calculate statistics manually as fallback
      let blockedThreats = 0;
      let scannedPages = 0;
      let securityEventsCount = securityEvents.length;

      // Count blocked threats
      securityEvents.forEach((entry) => {
        const event = entry.event;
        if (!event) return;

        if (
          event.type === "threat_blocked" ||
          event.type === "threat_detected" ||
          event.type === "content_threat_detected" ||
          (event.action && event.action.includes("blocked")) ||
          (event.threatLevel &&
            ["high", "critical"].includes(event.threatLevel))
        ) {
          blockedThreats++;
        }
      });

      // Count scanned pages
      accessLogs.forEach((entry) => {
        const event = entry.event;
        if (event && event.type === "page_scanned") {
          scannedPages++;
        }
      });

      // Also count legitimate access events as scanned pages
      securityEvents.forEach((entry) => {
        const event = entry.event;
        if (event && event.type === "legitimate_access") {
          scannedPages++;
        }
      });

      this.stats = {
        blockedThreats: blockedThreats,
        scannedPages: scannedPages,
        securityEvents: securityEventsCount,
      };

      // Update UI
      this.elements.blockedThreats.textContent =
        this.stats.blockedThreats.toLocaleString();
      this.elements.scannedPages.textContent =
        this.stats.scannedPages.toLocaleString();
      this.elements.securityEvents.textContent =
        this.stats.securityEvents.toLocaleString();

      console.log("Statistics calculated from fallback method:", this.stats);
    } catch (error) {
      console.error("Failed to load statistics:", error);
      // Show zero values on error
      this.elements.blockedThreats.textContent = "0";
      this.elements.scannedPages.textContent = "0";
      this.elements.securityEvents.textContent = "0";
    }
  }

  handleBlockedRoute() {
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

      // Request page analysis from background with retry
      this.showSecurityBadge("analyzing", "Analyzing...");

      try {
        const response = await this.sendMessage({
          type: "URL_ANALYSIS_REQUEST",
          url: this.currentTab.url,
        });

        if (response && response.success && response.analysis) {
          this.updateSecurityStatus(response.analysis);
        } else {
          this.showSecurityBadge("neutral", "Analysis unavailable");
        }
      } catch (error) {
        console.warn("Check: Failed to get URL analysis after retries:", error);
        this.showSecurityBadge("neutral", "Analysis unavailable");
      }

      // Get page info from content script with safe wrapper
      try {
        chrome.tabs.sendMessage(
          this.currentTab.id,
          { type: "GET_PAGE_INFO" },
          (response) => {
            if (chrome.runtime.lastError) {
              // Silently handle connection errors - don't log to avoid Chrome error list
              // Content script may not be ready yet, which is normal
              return;
            } else if (response && response.success) {
              console.log("Page info processing:", response.info);
              this.updatePageInfo(response.info);
            }
          }
        );
      } catch (error) {
        // Silently handle errors to avoid Chrome error list
      }
    } catch (error) {
      console.error("Failed to load page info:", error);
      this.elements.currentUrl.textContent = "Invalid URL";
      this.showSecurityBadge("neutral", "No Analysis Available");
    }
  }

  updateSecurityStatus(analysis) {
    const hasThreats = analysis.threats && analysis.threats.length > 0;
    const isBlocked = analysis.isBlocked;
    const isSuspicious =
      analysis.isSuspicious !== undefined ? analysis.isSuspicious : hasThreats;
    const isProtectionEnabled = analysis.protectionEnabled !== false;

    // Handle different verdict types with improved status display
    if (isBlocked) {
      this.showSecurityBadge("danger", "Blocked");
      this.showThreats(analysis.threats);
    } else if (isSuspicious) {
      this.showSecurityBadge("warning", "Suspicious");
      this.showThreats(analysis.threats);
    } else if (
      analysis.verdict === "trusted" ||
      analysis.verdict === "trusted-extra"
    ) {
      this.showSecurityBadge("safe", "Trusted Login Domain");
      this.hideThreats();
    } else if (analysis.verdict === "ms-login-unknown") {
      this.showSecurityBadge("warning", "MS Login - Unknown Domain");
      this.hideThreats();
    } else if (analysis.verdict === "not-evaluated") {
      this.showSecurityBadge("neutral", "Not Microsoft Login");
      this.hideThreats();
    } else {
      // For general Microsoft domains or other safe sites - show neutral, no badge
      this.showSecurityBadge("neutral", "No Action Required");
      this.hideThreats();
    }

    // Show protection status separately if disabled
    this.updateProtectionStatus(isProtectionEnabled);
  }

  updateProtectionStatus(isEnabled) {
    // Find or create protection status indicator
    let protectionStatus = document.getElementById("protectionStatus");
    if (!protectionStatus) {
      protectionStatus = document.createElement("div");
      protectionStatus.id = "protectionStatus";
      protectionStatus.className = "protection-status";

      // Insert after security status
      const securityStatusDiv = document.getElementById("securityStatus");
      securityStatusDiv.parentNode.insertBefore(
        protectionStatus,
        securityStatusDiv.nextSibling
      );
    }

    if (!isEnabled) {
      protectionStatus.innerHTML =
        '<span class="protection-badge disabled">⚠️ Protection Disabled</span>';
      protectionStatus.style.display = "block";
    } else {
      protectionStatus.style.display = "none";
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
        const displayName = this.getThreatDisplayName(threat.type);
        li.textContent = `${displayName}: ${threat.description}`;
        this.elements.threatList.appendChild(li);
      });
    } else {
      this.hideThreats();
    }
  }

  getThreatDisplayName(threatType) {
    const threatDisplayNames = {
      // Phishing threats
      phishing_page: "Phishing Page",
      fake_login: "Fake Login Page",
      credential_harvesting: "Credential Harvesting",
      microsoft_impersonation: "Microsoft Impersonation",
      o365_phishing: "Office 365 Phishing",
      login_spoofing: "Login Page Spoofing",

      // Malicious content
      malicious_script: "Malicious Script",
      suspicious_redirect: "Suspicious Redirect",
      unsafe_download: "Unsafe Download",
      malware_detected: "Malware Detected",
      suspicious_form: "Suspicious Form",

      // Domain threats
      typosquatting: "Typosquatting Domain",
      suspicious_domain: "Suspicious Domain",
      homograph_attack: "Homograph Attack",
      punycode_abuse: "Punycode Abuse",

      // Content threats
      suspicious_keywords: "Suspicious Keywords",
      social_engineering: "Social Engineering",
      urgency_tactics: "Urgency Tactics",
      trust_indicators: "Fake Trust Indicators",

      // Technical threats
      dom_manipulation: "DOM Manipulation",
      script_injection: "Script Injection",
      form_tampering: "Form Tampering",
      content_injection: "Content Injection",

      // Behavioral threats
      unusual_behavior: "Unusual Behavior",
      rapid_redirects: "Rapid Redirects",
      clipboard_access: "Clipboard Access",

      // Generic categories
      content_threat_detected: "Content Threat",
      threat_detected: "Security Threat",
      suspicious_activity: "Suspicious Activity",
      policy_violation: "Policy Violation",
    };

    return (
      threatDisplayNames[threatType] ||
      threatType.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())
    );
  }

  hideThreats() {
    this.elements.threatSummary.style.display = "none";
  }

  updatePageInfo(pageInfo) {
    // Could update additional page information here
    console.log("Page info received:", pageInfo);
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
        return `Content threat detected on ${new URL(event.url).hostname}`;
      case "threat_detected":
        return `Security threat detected on ${new URL(event.url).hostname}`;
      case "phishing_page":
        return `Phishing page blocked on ${new URL(event.url).hostname}`;
      case "fake_login":
        return `Fake login page blocked on ${new URL(event.url).hostname}`;
      case "malicious_script":
        return `Malicious script blocked on ${new URL(event.url).hostname}`;
      case "suspicious_redirect":
        return `Suspicious redirect blocked on ${new URL(event.url).hostname}`;
      case "form_submission":
        return "Form submission monitored";
      case "script_injection":
        return "Security script injected";
      case "page_scanned":
        return `Page scanned for threats`;
      case "blocked_page_viewed":
        return `Attempted to view blocked content`;
      case "threat_blocked":
        return `Security threat blocked`;
      case "legitimate_access":
        return `Legitimate page accessed`;
      default:
        // Convert snake_case to Title Case for unknown event types
        return this.getEventDisplayName(event.type);
    }
  }

  getEventDisplayName(eventType) {
    const eventDisplayNames = {
      url_access: "Page Scanned",
      content_threat_detected: "Content Threat Detected",
      threat_detected: "Security Threat Detected",
      form_submission: "Form Monitored",
      script_injection: "Security Script Injected",
      page_scanned: "Page Scanned",
      blocked_page_viewed: "Blocked Content Viewed",
      threat_blocked: "Threat Blocked",
      threat_detected_no_action: "Threat Detected",
      legitimate_access: "Legitimate Access",
      phishing_page: "Phishing Page Blocked",
      fake_login: "Fake Login Blocked",
      credential_harvesting: "Credential Harvesting Blocked",
      microsoft_impersonation: "Microsoft Impersonation Blocked",
      malicious_script: "Malicious Script Blocked",
      suspicious_redirect: "Suspicious Redirect Blocked",
      typosquatting: "Typosquatting Domain Blocked",
      social_engineering: "Social Engineering Blocked",
    };

    return (
      eventDisplayNames[eventType] ||
      eventType.replace(/_/g, " ").replace(/\b\w/g, (l) => l.toUpperCase())
    );
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
      const isCompliant = this.checkCompliance();
      this.updateComplianceStatus(isCompliant);
    }
  }

  checkCompliance() {
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

  openSettings() {
    try {
      chrome.tabs.create(
        {
          url: chrome.runtime.getURL("options/options.html"),
        },
        () => {
          if (chrome.runtime.lastError) {
            console.error(
              "Check: Failed to open settings:",
              chrome.runtime.lastError.message
            );
          } else {
            window.close();
          }
        }
      );
    } catch (error) {
      console.error("Check: Failed to open settings:", error);
    }
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
      try {
        chrome.tabs.create({ url }, () => {
          if (chrome.runtime.lastError) {
            console.error(
              "Check: Failed to open link:",
              chrome.runtime.lastError.message
            );
          } else {
            window.close();
          }
        });
      } catch (error) {
        console.error("Check: Failed to open link:", error);
      }
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
      try {
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
      } catch (error) {
        if (retryCount < 3) {
          setTimeout(() => {
            this.sendMessage(message, retryCount + 1)
              .then(resolve)
              .catch(reject);
          }, 500 * (retryCount + 1));
        } else {
          reject(error);
        }
      }
    });
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

  // Theme Management
  async initializeTheme() {
    try {
      // Get stored theme preference from Chrome storage
      const result = await chrome.storage.local.get(["themeMode"]);
      const stored = result.themeMode;

      let isDarkMode;

      if (stored === "dark") {
        isDarkMode = true;
      } else if (stored === "light") {
        isDarkMode = false;
      } else {
        // Default to system preference
        isDarkMode = window.matchMedia("(prefers-color-scheme: dark)").matches;
      }

      this.applyTheme(isDarkMode);

      // Listen for theme changes from the options page
      chrome.storage.onChanged.addListener((changes, areaName) => {
        if (areaName === "local" && changes.themeMode) {
          const newTheme = changes.themeMode.newValue;
          if (newTheme === "dark") {
            this.applyTheme(true);
          } else if (newTheme === "light") {
            this.applyTheme(false);
          } else {
            // System preference
            const systemDark = window.matchMedia(
              "(prefers-color-scheme: dark)"
            ).matches;
            this.applyTheme(systemDark);
          }
        }
      });
    } catch (error) {
      console.error("Check: Failed to initialize theme:", error);
      // Fallback to system preference
      const systemDark = window.matchMedia(
        "(prefers-color-scheme: dark)"
      ).matches;
      this.applyTheme(systemDark);
    }
  }

  applyTheme(isDarkMode) {
    const html = document.documentElement;

    if (isDarkMode) {
      html.classList.add("dark-theme");
      html.classList.remove("light-theme");
    } else {
      html.classList.remove("dark-theme");
      html.classList.add("light-theme");
    }
  }
}

// Initialize popup when DOM is loaded
document.addEventListener("DOMContentLoaded", () => {
  // Add a small delay to ensure background script is ready
  setTimeout(() => {
    new CheckPopup();
  }, 100);
});
