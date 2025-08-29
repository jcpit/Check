/**
 * Microsoft 365 Phishing Detection - Enhanced Content Script
 * Combines the robust architecture with focused M365 phishing detection
 */

// Trusted Microsoft Origins - Core Detection Foundation
const TRUSTED_ORIGINS = new Set([
  "https://login.microsoftonline.com",
  "https://login.microsoft.com", 
  "https://login.windows.net",
  "https://login.microsoftonline.us",
  "https://login.partner.microsoftonline.cn",
  "https://login.live.com"
]);

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

function isTrustedReferrer(ref) { 
  return ref && TRUSTED_ORIGINS.has(urlOrigin(ref)); 
}

class CheckContent {
  constructor() {
    this.isInitialized = false;
    this.config = null;
    this.observers = [];
    this.securityMonitor = null;
    this.pageAnalyzer = null;
    this.uiManager = null;
    this.phishingDetector = null;
    this.flagged = false;
  }

  async initialize() {
    try {
      console.log("Check: Initializing enhanced content script...");

      // Load configuration from background
      this.config = await this.getConfigFromBackground();

      // Initialize components
      this.securityMonitor = new SecurityMonitor(this.config);
      this.pageAnalyzer = new PageAnalyzer(this.config);
      this.uiManager = new UIManager(this.config);
      this.phishingDetector = new PhishingDetector(this.config);

      // Set up enhanced phishing detection
      this.setupPhishingDetection();

      // Set up page monitoring
      this.setupPageMonitoring();

      // Set up message handling
      this.setupMessageHandling();

      // Perform initial analysis
      await this.performInitialAnalysis();

      this.isInitialized = true;
      console.log("Check: Enhanced content script initialized successfully");
    } catch (error) {
      console.error("Check: Failed to initialize content script:", error);
    }
  }

  async getConfigFromBackground() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        { type: "GET_CONFIG" },
        (response) => {
          if (response && response.success) {
            resolve(response.config);
          } else {
            resolve(this.getDefaultConfig());
          }
        }
      );
    });
  }

  getDefaultConfig() {
    return {
      extensionEnabled: true,
      enableContentManipulation: true,
      enableUrlMonitoring: true,
      showNotifications: true,
      debugMode: false,
      // Enhanced phishing detection settings
      enablePhishingDetection: true,
      strictResourceAudit: true,
      requireMicrosoftAction: true,
      showValidPageBadge: true,
      lockCredentialsOnPhishing: true,
      preventPhishingSubmission: true
    };
  }

  setupPhishingDetection() {
    const origin = location.origin.toLowerCase();

    // 1) Real Microsoft login → show valid badge
    if (isTrustedOrigin(origin)) {
      this.phishingDetector.injectValidBadge();
      this.phishingDetector.enforceMicrosoftActionIfConfigured();
      return;
    }

    // 2) Post-login redirect from real login (no password field) → trusted-by-referrer
    if (isTrustedReferrer(document.referrer) && !this.phishingDetector.hasPassword()) {
      chrome.runtime.sendMessage({ type: "FLAG_TRUSTED_BY_REFERRER" });
      return;
    }

    // 3) Live monitor for SPA/dynamic injection (AAD loads content after doc_end)
    this.setupLivePhishingMonitoring();
  }

  setupLivePhishingMonitoring() {
    const stopAt = Date.now() + 20000; // watch up to 20s
    const observer = new MutationObserver(() => this.evaluatePhishingRisk());
    observer.observe(document.documentElement, { childList: true, subtree: true });
    this.observers.push(observer);
    
    this.evaluatePhishingRisk(); // initial evaluation

    // Stop observing after timeout to reduce overhead
    setTimeout(() => {
      observer.disconnect();
      const index = this.observers.indexOf(observer);
      if (index > -1) this.observers.splice(index, 1);
    }, 20000);
  }

  evaluatePhishingRisk() {
    if (this.flagged || !this.config.enablePhishingDetection) return;

    const origin = location.origin.toLowerCase();
    if (isTrustedOrigin(origin)) return;

    // Core AAD fingerprint detection
    const phishingRisk = this.phishingDetector.detectAADFingerprint();
    
    if (phishingRisk.isPhishing) {
      this.flagged = true;
      this.handlePhishingDetected(phishingRisk);
    }
  }

  handlePhishingDetected(phishingRisk) {
    console.warn("Check: Phishing page detected!", phishingRisk);

    // Inject red warning banner
    this.phishingDetector.injectPhishingWarning(phishingRisk);

    // Lock credential inputs
    if (this.config.lockCredentialsOnPhishing) {
      this.phishingDetector.lockCredentialInputs();
    }

    // Prevent form submission
    if (this.config.preventPhishingSubmission) {
      this.phishingDetector.preventSubmission();
    }

    // Report to background script
    chrome.runtime.sendMessage({ 
      type: "FLAG_PHISHY", 
      reason: phishingRisk.reasons.join(", "),
      details: phishingRisk
    });

    // Stop all observers since we've detected phishing
    this.observers.forEach(observer => observer.disconnect());
    this.observers = [];
  }

  setupPageMonitoring() {
    // Monitor DOM changes
    const domObserver = new MutationObserver((mutations) => {
      this.handleDOMChanges(mutations);
    });

    domObserver.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ["src", "href", "action", "onclick"],
    });

    this.observers.push(domObserver);

    // Monitor form submissions
    document.addEventListener("submit", (event) => {
      this.handleFormSubmission(event);
    });

    // Monitor navigation attempts
    document.addEventListener("click", (event) => {
      this.handleLinkClick(event);
    });

    // Monitor script injections
    this.setupScriptMonitoring();
  }

  setupScriptMonitoring() {
    // Override eval to monitor dynamic script execution
    const originalEval = window.eval;
    window.eval = (code) => {
      this.logSecurityEvent({
        type: "dynamic_script_execution",
        code: code.substring(0, 100),
        url: window.location.href,
        timestamp: new Date().toISOString(),
      });

      if (this.config.blockDynamicScripts) {
        console.warn("Check: Dynamic script execution blocked");
        return null;
      }

      return originalEval.call(window, code);
    };

    // Monitor setTimeout/setInterval with code strings
    const originalSetTimeout = window.setTimeout;
    window.setTimeout = (handler, timeout, ...args) => {
      if (typeof handler === "string") {
        this.logSecurityEvent({
          type: "dynamic_timeout_execution",
          code: handler.substring(0, 100),
          url: window.location.href,
          timestamp: new Date().toISOString(),
        });
      }
      return originalSetTimeout.call(window, handler, timeout, ...args);
    };
  }

  setupMessageHandling() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep message channel open
    });

    // Expose testing interface to page
    this.exposeTestingInterface();
  }

  async handleTestMessage(data) {
    try {
      const response = await new Promise((resolve) => {
        chrome.runtime.sendMessage(
          {
            type: data.type.replace("CHECK_TEST_", ""),
            ...data.payload,
          },
          resolve
        );
      });

      return response;
    } catch (error) {
      throw error;
    }
  }

  exposeTestingInterface() {
    let messageId = 0;
    const pendingMessages = new Map();

    const testingInterface = {
      sendMessage: function (message) {
        return new Promise((resolve, reject) => {
          const id = ++messageId;
          pendingMessages.set(id, { resolve, reject });

          const event = new CustomEvent("checkTestRequest", {
            detail: {
              type: "CHECK_TEST_" + message.type,
              id: id,
              payload: message,
            },
          });
          document.dispatchEvent(event);
        });
      },
    };

    Object.defineProperty(window, "CheckTesting", {
      value: testingInterface,
      writable: false,
      configurable: false,
    });

    document.addEventListener("checkTestRequest", async (event) => {
      try {
        const response = await this.handleTestMessage(event.detail);
        const responseEvent = new CustomEvent("checkTestResponse", {
          detail: {
            id: event.detail.id,
            response: response,
          },
        });
        document.dispatchEvent(responseEvent);
      } catch (error) {
        const errorEvent = new CustomEvent("checkTestResponse", {
          detail: {
            id: event.detail.id,
            error: error.message,
          },
        });
        document.dispatchEvent(errorEvent);
      }
    });

    document.addEventListener("checkTestResponse", (event) => {
      const pending = pendingMessages.get(event.detail.id);
      if (pending) {
        pendingMessages.delete(event.detail.id);
        if (event.detail.error) {
          pending.reject(new Error(event.detail.error));
        } else {
          pending.resolve(event.detail.response);
        }
      }
    });
  }

  async handleMessage(message, sender, sendResponse) {
    try {
      switch (message.type) {
        case "ANALYZE_PAGE":
          const analysis = await this.pageAnalyzer.analyzePage();
          sendResponse({ success: true, analysis });
          break;

        case "INJECT_SCRIPT":
          const injectionResult = await this.injectScript(
            message.script,
            message.options
          );
          sendResponse({ success: true, result: injectionResult });
          break;

        case "MANIPULATE_CONTENT":
          const manipulationResult = await this.manipulateContent(
            message.action,
            message.target,
            message.options
          );
          sendResponse({ success: true, result: manipulationResult });
          break;

        case "GET_PAGE_INFO":
          const pageInfo = this.getPageInfo();
          sendResponse({ success: true, info: pageInfo });
          break;

        case "UPDATE_CONFIG":
          this.config = { ...this.config, ...message.config };
          sendResponse({ success: true });
          break;

        case "SHOW_NOTIFICATION":
          this.uiManager.showNotification(message.notification);
          sendResponse({ success: true });
          break;

        case "BLOCK_PAGE":
          this.blockPage(message.reason);
          sendResponse({ success: true });
          break;

        case "FORCE_PHISHING_CHECK":
          this.evaluatePhishingRisk();
          sendResponse({ success: true });
          break;

        default:
          sendResponse({ success: false, error: "Unknown message type" });
      }
    } catch (error) {
      console.error("Check: Error handling message:", error);
      sendResponse({ success: false, error: error.message });
    }
  }

  async performInitialAnalysis() {
    const analysis = await this.pageAnalyzer.analyzePage();

    // Report analysis to background
    chrome.runtime.sendMessage({
      type: "LOG_EVENT",
      event: {
        type: "page_analysis",
        url: window.location.href,
        analysis,
        timestamp: new Date().toISOString(),
      },
    });

    // Take action based on analysis
    if (analysis.threats && analysis.threats.length > 0) {
      this.handleThreatsDetected(analysis.threats);
    }
  }

  handleDOMChanges(mutations) {
    mutations.forEach((mutation) => {
      if (mutation.type === "childList") {
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            this.checkNewElement(node);
          }
        });
      } else if (mutation.type === "attributes") {
        this.checkAttributeChange(mutation);
      }
    });
  }

  checkNewElement(element) {
    // Check for script elements
    if (element.tagName === "SCRIPT") {
      this.logSecurityEvent({
        type: "dynamic_script_added",
        src: element.src || "inline",
        content: element.innerHTML.substring(0, 100),
        url: window.location.href,
        timestamp: new Date().toISOString(),
      });
    }

    // Check for iframe elements
    if (element.tagName === "IFRAME") {
      this.analyzeIframe(element);
    }

    // Check for form elements
    if (element.tagName === "FORM") {
      this.analyzeForm(element);
    }

    // Recursively check child elements
    element.querySelectorAll("script, iframe, form").forEach((child) => {
      this.checkNewElement(child);
    });
  }

  checkAttributeChange(mutation) {
    const element = mutation.target;
    const attributeName = mutation.attributeName;

    if (["onclick", "onload", "onerror"].includes(attributeName)) {
      this.logSecurityEvent({
        type: "suspicious_attribute_change",
        element: element.tagName,
        attribute: attributeName,
        value: element.getAttribute(attributeName),
        url: window.location.href,
        timestamp: new Date().toISOString(),
      });
    }
  }

  handleFormSubmission(event) {
    const form = event.target;
    const hasPasswordField = form.querySelector('input[type="password"]');
    const hasEmailField = form.querySelector('input[type="email"]');

    if (hasPasswordField || hasEmailField) {
      this.analyzeLoginForm(form, event);
    }

    this.logSecurityEvent({
      type: "form_submission",
      action: form.action,
      method: form.method,
      hasPassword: !!hasPasswordField,
      hasEmail: !!hasEmailField,
      url: window.location.href,
      timestamp: new Date().toISOString(),
    });
  }

  analyzeLoginForm(form, event) {
    const currentDomain = window.location.hostname;
    const formAction = form.action;

    // Enhanced login form analysis using Microsoft domain validation
    if (formAction) {
      const actionOrigin = urlOrigin(formAction);
      if (!isTrustedOrigin(actionOrigin) && actionOrigin !== location.origin) {
        this.logSecurityEvent({
          type: "suspicious_login_form",
          currentDomain,
          formAction,
          actionOrigin,
          reason: "Non-Microsoft form action",
          url: window.location.href,
          timestamp: new Date().toISOString(),
        });

        if (this.config.blockSuspiciousForms) {
          event.preventDefault();
          this.uiManager.showWarning(
            "Suspicious login form detected - submits to non-Microsoft domain"
          );
        }
      }
    }
  }

  handleLinkClick(event) {
    const link = event.target.closest("a");
    if (!link) return;

    const href = link.href;
    if (!href) return;

    this.analyzeLinkSafety(href, event);
  }

  async analyzeLinkSafety(url, event) {
    chrome.runtime.sendMessage(
      {
        type: "URL_ANALYSIS_REQUEST",
        url,
      },
      (response) => {
        if (response && response.success && response.analysis) {
          if (response.analysis.isBlocked) {
            event.preventDefault();
            this.uiManager.showBlockedLinkWarning(
              url,
              response.analysis.reason
            );
          } else if (response.analysis.isSuspicious) {
            this.uiManager.showSuspiciousLinkWarning(
              url,
              response.analysis.reason
            );
          }
        }
      }
    );
  }

  async injectScript(script, options = {}) {
    try {
      const policyCheck = await this.checkPolicy("SCRIPT_INJECTION", {
        domain: window.location.hostname,
        hasCSP: this.hasContentSecurityPolicy(),
      });

      if (!policyCheck.allowed) {
        throw new Error(`Script injection blocked: ${policyCheck.reason}`);
      }

      const scriptElement = document.createElement("script");

      if (options.src) {
        scriptElement.src = options.src;
      } else {
        scriptElement.textContent = script;
      }

      if (options.async) {
        scriptElement.async = true;
      }

      if (options.defer) {
        scriptElement.defer = true;
      }

      document.head.appendChild(scriptElement);

      this.logSecurityEvent({
        type: "script_injection",
        src: options.src || "inline",
        url: window.location.href,
        timestamp: new Date().toISOString(),
      });

      return { success: true };
    } catch (error) {
      console.error("Check: Script injection failed:", error);
      return { success: false, error: error.message };
    }
  }

  async manipulateContent(action, target, options = {}) {
    try {
      const policyCheck = await this.checkPolicy("CONTENT_MANIPULATION", {
        domain: window.location.hostname,
        manipulationType: action,
      });

      if (!policyCheck.allowed) {
        throw new Error(`Content manipulation blocked: ${policyCheck.reason}`);
      }

      let result;

      switch (action) {
        case "hide_element":
          result = this.hideElement(target, options);
          break;
        case "show_element":
          result = this.showElement(target, options);
          break;
        case "modify_text":
          result = this.modifyText(target, options.text);
          break;
        case "inject_css":
          result = this.injectCSS(options.css);
          break;
        case "remove_element":
          result = this.removeElement(target);
          break;
        default:
          throw new Error(`Unknown manipulation action: ${action}`);
      }

      this.logSecurityEvent({
        type: "content_manipulation",
        action,
        target: typeof target === "string" ? target : target.tagName,
        url: window.location.href,
        timestamp: new Date().toISOString(),
      });

      return result;
    } catch (error) {
      console.error("Check: Content manipulation failed:", error);
      return { success: false, error: error.message };
    }
  }

  hideElement(selector, options = {}) {
    const elements =
      typeof selector === "string"
        ? document.querySelectorAll(selector)
        : [selector];

    elements.forEach((element) => {
      if (element) {
        element.style.display = "none";
        if (options.addToHiddenList) {
          element.dataset.checkHidden = "true";
        }
      }
    });

    return { success: true, hiddenCount: elements.length };
  }

  showElement(selector, options = {}) {
    const elements =
      typeof selector === "string"
        ? document.querySelectorAll(selector)
        : [selector];

    elements.forEach((element) => {
      if (element) {
        element.style.display = "";
        delete element.dataset.checkHidden;
      }
    });

    return { success: true, shownCount: elements.length };
  }

  modifyText(selector, newText) {
    const elements =
      typeof selector === "string"
        ? document.querySelectorAll(selector)
        : [selector];

    elements.forEach((element) => {
      if (element) {
        element.textContent = newText;
      }
    });

    return { success: true, modifiedCount: elements.length };
  }

  injectCSS(css) {
    const style = document.createElement("style");
    style.textContent = css;
    style.dataset.checkInjected = "true";
    document.head.appendChild(style);

    return { success: true };
  }

  removeElement(selector) {
    const elements =
      typeof selector === "string"
        ? document.querySelectorAll(selector)
        : [selector];

    elements.forEach((element) => {
      if (element && element.parentNode) {
        element.parentNode.removeChild(element);
      }
    });

    return { success: true, removedCount: elements.length };
  }

  async checkPolicy(action, context) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage(
        {
          type: "POLICY_CHECK",
          action,
          context,
        },
        (response) => {
          if (response && response.success) {
            resolve({
              allowed: response.allowed,
              reason: response.reason,
            });
          } else {
            resolve({ allowed: false, reason: "Policy check failed" });
          }
        }
      );
    });
  }

  getPageInfo() {
    return {
      url: window.location.href,
      title: document.title,
      domain: window.location.hostname,
      protocol: window.location.protocol,
      hasPasswordFields:
        document.querySelectorAll('input[type="password"]').length > 0,
      hasFormsWithAction: document.querySelectorAll("form[action]").length > 0,
      hasExternalScripts:
        document.querySelectorAll('script[src]:not([src^="/"])').length > 0,
      hasIframes: document.querySelectorAll("iframe").length > 0,
      hasMetaRefresh:
        document.querySelector('meta[http-equiv="refresh"]') !== null,
      contentSecurityPolicy: this.getContentSecurityPolicy(),
      // Enhanced phishing-related info
      isTrustedOrigin: isTrustedOrigin(window.location.href),
      trustedReferrer: isTrustedReferrer(document.referrer),
      phishingRisk: this.phishingDetector ? this.phishingDetector.detectAADFingerprint() : null
    };
  }

  hasContentSecurityPolicy() {
    return !!this.getContentSecurityPolicy();
  }

  getContentSecurityPolicy() {
    const cspMeta = document.querySelector(
      'meta[http-equiv="Content-Security-Policy"]'
    );
    return cspMeta ? cspMeta.getAttribute("content") : null;
  }

  analyzeIframe(iframe) {
    this.logSecurityEvent({
      type: "iframe_detected",
      src: iframe.src,
      sandbox: iframe.getAttribute("sandbox"),
      url: window.location.href,
      timestamp: new Date().toISOString(),
    });
  }

  analyzeForm(form) {
    const hasPasswordField = form.querySelector('input[type="password"]');
    const hasFileField = form.querySelector('input[type="file"]');

    this.logSecurityEvent({
      type: "form_detected",
      action: form.action,
      method: form.method,
      hasPassword: !!hasPasswordField,
      hasFileUpload: !!hasFileField,
      url: window.location.href,
      timestamp: new Date().toISOString(),
    });
  }

  handleThreatsDetected(threats) {
    threats.forEach((threat) => {
      if (threat.severity === "high") {
        this.uiManager.showCriticalAlert(threat);
      } else if (threat.severity === "medium") {
        this.uiManager.showWarning(threat);
      } else {
        this.uiManager.showInfo(threat);
      }
    });
  }

  blockPage(reason) {
    const overlay = document.createElement("div");
    overlay.id = "check-block-overlay";
    overlay.innerHTML = `
      <div style="
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(255, 255, 255, 0.95);
        z-index: 999999;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      ">
        <div style="
          background: white;
          padding: 40px;
          border-radius: 8px;
          box-shadow: 0 4px 20px rgba(0, 0, 0, 0.15);
          max-width: 500px;
          text-align: center;
        ">
          <h1 style="color: #dc2626; margin-bottom: 20px;">Access Blocked</h1>
          <p style="color: #374151; margin-bottom: 20px;">${reason}</p>
          <button onclick="window.history.back()" style="
            background: #2563eb;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 4px;
            cursor: pointer;
          ">Go Back</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);
  }

  logSecurityEvent(event) {
    chrome.runtime.sendMessage({
      type: "LOG_EVENT",
      event,
    });
  }

  destroy() {
    this.observers.forEach((observer) => observer.disconnect());
    this.observers = [];

    document
      .querySelectorAll("style[data-check-injected]")
      .forEach((style) => {
        style.remove();
      });

    console.log("Check: Content script destroyed");
  }
}

// Enhanced Phishing Detection Class
class PhishingDetector {
  constructor(config) {
    this.config = config;
  }

  hasPassword() { 
    return !!document.querySelector('input[type="password"]'); 
  }

  detectAADFingerprint() {
    const origin = location.origin.toLowerCase();
    
    // Skip detection on trusted origins
    if (isTrustedOrigin(origin)) {
      return { isPhishing: false, confidence: 0, reasons: [] };
    }

    const reasons = [];
    let confidence = 0;

    // Core AAD UI element detection
    const hasLoginFmt = !!document.querySelector('input[name="loginfmt"], #i0116');
    const hasNextBtn = !!document.querySelector('#idSIButton9'); // "Next"/"Sign in" button on AAD
    const hasPw = this.hasPassword();

    // Text content analysis for Microsoft branding
    const text = (document.body?.innerText || "").slice(0, 25000);
    const brandingHit = /\b(Microsoft\s*365|Office\s*365|Entra\s*ID|Azure\s*AD|Microsoft)\b/i.test(text);
    
    // AAD-like UI detection
    const aadLike = (hasLoginFmt && hasNextBtn) || (brandingHit && (hasLoginFmt || hasPw));

    if (aadLike) {
      reasons.push("AAD-like UI detected");
      confidence += 0.7;
    }

    // Form action validation
    const actionCheck = this.checkFormActions(hasPw);
    if (actionCheck.fail && this.config.requireMicrosoftAction !== false) {
      reasons.push("Non-Microsoft form action");
      confidence += 0.8;
    }

    // Resource audit
    const resourceAudit = this.auditSubresourceOrigins();
    if (resourceAudit.nonMicrosoftCount > 0 && this.config.strictResourceAudit !== false) {
      reasons.push(`${resourceAudit.nonMicrosoftCount} non-Microsoft resources`);
      confidence += 0.3;
    }

    // Password field presence on non-Microsoft domain
    if (hasPw && brandingHit) {
      reasons.push("Password field with Microsoft branding on untrusted domain");
      confidence += 0.5;
    }

    // Determine if this constitutes phishing
    const isPhishing = aadLike && confidence >= 0.7;

    return {
      isPhishing,
      confidence,
      reasons,
      details: {
        hasLoginFmt,
        hasNextBtn,
        hasPw,
        brandingHit,
        aadLike,
        actionCheck,
        resourceAudit
      }
    };
  }

  checkFormActions(requirePw) {
    const forms = Array.from(document.querySelectorAll("form"));
    const offenders = [];
    
    for (const f of forms) {
      if (requirePw && !f.querySelector('input[type="password"]')) continue;
      const act = this.resolveAction(f.getAttribute("action"));
      const actOrigin = urlOrigin(act);
      if (!isTrustedOrigin(actOrigin)) {
        offenders.push({ action: act, actionOrigin: actOrigin });
      }
    }
    
    return offenders.length ? { fail: true, reason: "non-microsoft-form-action", offenders } : { fail: false };
  }

  resolveAction(a) {
    let act = (a || location.href).trim();
    try { 
      act = new URL(act, location.href).href; 
    } catch { 
      act = location.href; 
    }
    return act;
  }

  auditSubresourceOrigins() {
    const origin = location.origin.toLowerCase();
    const nodes = [
      ...document.querySelectorAll('script[src]'),
      ...document.querySelectorAll('link[rel="stylesheet"][href]'),
      ...document.querySelectorAll('img[src]')
    ];
    
    const origins = new Set();
    const nonMs = new Set();
    
    for (const el of nodes) {
      const url = el.src || el.href;
      if (!url) continue;
      
      try {
        const o = urlOrigin(new URL(url, location.href).href);
        if (!o) continue;
        origins.add(o);
        
        // If all assets are on the same fake origin, this may yield 0 — that's fine.
        if (!isTrustedOrigin(o) && o !== origin) {
          nonMs.add(o);
        }
      } catch {
        // Invalid URL, skip
      }
    }
    
    return {
      origins: Array.from(origins),
      nonMicrosoft: Array.from(nonMs),
      nonMicrosoftCount: nonMs.size
    };
  }

  injectValidBadge() {
    const id = "__check_valid_login_badge";
    if (document.getElementById(id)) return;
    
    const wrap = document.createElement("div");
    wrap.id = id;
    wrap.style.cssText = "position:fixed;right:8px;top:8px;z-index:2147483647;pointer-events:none";
    
    if (this.config.validPageBadgeImage) {
      const img = document.createElement("img");
      img.src = this.config.validPageBadgeImage;
      img.alt = "Valid Microsoft login";
      img.style.cssText = "height:40px;width:40px;object-fit:contain;opacity:.9";
      wrap.appendChild(img);
    } else {
      wrap.innerHTML = '<svg viewBox="0 0 24 24" width="40" height="40"><circle cx="12" cy="12" r="11" fill="#0a5"/><path d="M6 12l4 4 8-8" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    }
    
    const label = document.createElement("div");
    label.textContent = (this.config.brandingName || "Check") + " • Valid M365 Login";
    label.style.cssText = "margin-top:4px;background:rgba(0,0,0,.7);color:#fff;padding:4px 6px;border-radius:6px;font:12px system-ui;display:inline-block";
    wrap.appendChild(label);
    
    document.documentElement.appendChild(wrap);
  }

  injectPhishingWarning(phishingRisk) {
    if (document.getElementById("__check_phishing_banner")) return;
    
    const el = document.createElement("div");
    el.id = "__check_phishing_banner";
    el.style.cssText = "position:fixed;z-index:2147483647;left:0;right:0;top:0;padding:10px 16px;background:#d33;color:#fff;font:14px/1.4 system-ui,Segoe UI,Arial;border-bottom:2px solid #a00;box-shadow:0 2px 6px rgba(0,0,0,.2)";
    
    let msg = (this.config.brandingName || "Check") + ": Phishing suspected – Microsoft 365 login UI on an untrusted domain.";
    if (phishingRisk.reasons.length > 0) {
      msg += " (" + phishingRisk.reasons.join(", ") + ")";
    }
    
    el.textContent = msg;
    document.documentElement.appendChild(el);
    
    if (document.body) {
      document.body.style.paddingTop = (parseInt(getComputedStyle(el).height, 10) + 8) + "px";
    }
  }

  lockCredentialInputs() {
    const suspects = [
      'input[type="password"]', 'input[name="passwd"]', 'input[name="Password"]', 'input[name="password"]',
      'input[name="loginfmt"]', '#i0116' // lock username too
    ];
    
    const fields = Array.from(document.querySelectorAll(suspects.join(",")));
    
    for (const el of fields) {
      try {
        el.setAttribute("aria-disabled", "true");
        el.setAttribute("autocomplete", "off");
        el.setAttribute("readonly", "true");
        el.disabled = true;
        el.style.filter = "grayscale(1)";
        el.style.opacity = "0.6";
        el.style.pointerEvents = "none";
      } catch {
        // Ignore errors
      }
    }
    
    const msg = document.createElement("div");
    msg.textContent = "⚠️ Disabled by " + (this.config.brandingName || "Check Phishing Protection");
    msg.style.cssText = "font:13px/1.4 system-ui;color:#a00;margin-top:6px;";
    
    const pw = document.querySelector('input[type="password"]');
    if (pw) {
      pw.insertAdjacentElement("afterend", msg);
    } else if (document.body) {
      document.body.appendChild(msg);
    }
  }

  preventSubmission() {
    document.addEventListener("submit", (e) => {
      e.stopImmediatePropagation();
      e.preventDefault();
      this.showToast("Blocked form submission: not the official Microsoft login domain.");
    }, true);
    
    document.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        const t = e.target;
        if (t && t.tagName === "INPUT") {
          e.stopImmediatePropagation();
          e.preventDefault();
          this.showToast("Blocked: not the official Microsoft login domain.");
        }
      }
    }, true);
  }

  showToast(msg) {
    const t = document.createElement("div");
    t.textContent = msg;
    t.style.cssText = "position:fixed;right:12px;bottom:12px;background:#222;color:#fff;padding:10px 12px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.3);font:13px system-ui;z-index:2147483647";
    
    if (document.body) {
      document.body.appendChild(t);
      setTimeout(() => t.remove(), 3000);
    }
  }

  enforceMicrosoftActionIfConfigured() {
    const requireAction = this.config.requireMicrosoftAction !== false;
    if (!requireAction) return;
    
    const forms = Array.from(document.querySelectorAll("form"));
    const bad = [];
    
    for (const f of forms) {
      const hasPw = !!f.querySelector('input[type="password"]');
      if (!hasPw) continue;
      
      const act = this.resolveAction(f.getAttribute("action"));
      const actOrigin = urlOrigin(act);
      if (!isTrustedOrigin(actOrigin)) {
        bad.push({ action: actOrigin });
      }
    }
    
    if (bad.length) {
      this.showToast("Unusual: password form posts outside Microsoft login.");
    }
  }
}

// Keep existing helper classes with enhancements
class SecurityMonitor {
  constructor(config) {
    this.config = config;
  }
}

class PageAnalyzer {
  constructor(config) {
    this.config = config;
  }

  async analyzePage() {
    const analysis = {
      url: window.location.href,
      title: document.title,
      threats: [],
      hasPasswordFields: document.querySelectorAll('input[type="password"]').length > 0,
      hasFileUploads: document.querySelectorAll('input[type="file"]').length > 0,
      hasExternalResources: this.checkExternalResources(),
      hasSuspiciousScripts: this.checkSuspiciousScripts(),
      hasFormsWithExternalAction: this.checkExternalFormActions(),
      contentSecurityPolicy: this.getCSP(),
      timestamp: new Date().toISOString(),
      // Enhanced phishing analysis
      isTrustedOrigin: isTrustedOrigin(window.location.href),
      trustedReferrer: isTrustedReferrer(document.referrer),
      microsoftBranding: this.checkMicrosoftBranding(),
      aadElements: this.checkAADElements()
    };

    // Enhanced threat detection
    if (analysis.hasSuspiciousScripts) {
      analysis.threats.push({
        type: "suspicious_scripts",
        severity: "medium",
        description: "Potentially malicious JavaScript detected",
      });
    }

    if (analysis.hasFormsWithExternalAction) {
      analysis.threats.push({
        type: "external_form_action",
        severity: "high",
        description: "Form submitting to external domain detected",
      });
    }

    // Microsoft 365 phishing detection
    if (!analysis.isTrustedOrigin && analysis.microsoftBranding && analysis.hasPasswordFields) {
      analysis.threats.push({
        type: "microsoft_phishing_suspected",
        severity: "high",
        description: "Potential Microsoft 365 phishing page detected",
      });
    }

    return analysis;
  }

  checkMicrosoftBranding() {
    const text = (document.body?.innerText || "").slice(0, 25000);
    return /\b(Microsoft\s*365|Office\s*365|Entra\s*ID|Azure\s*AD|Microsoft)\b/i.test(text);
  }

  checkAADElements() {
    return {
      hasLoginFmt: !!document.querySelector('input[name="loginfmt"], #i0116'),
      hasNextBtn: !!document.querySelector('#idSIButton9'),
      hasAADContainer: !!document.querySelector('#lightboxBackgroundContainer, .sign-in-box')
    };
  }

  checkExternalResources() {
    const currentDomain = window.location.hostname;
    const externalResources = document.querySelectorAll(
      "script[src], link[href], img[src]"
    );

    return Array.from(externalResources).some((element) => {
      const src = element.src || element.href;
      if (!src) return false;

      try {
        const url = new URL(src);
        return url.hostname !== currentDomain;
      } catch {
        return false;
      }
    });
  }

  checkSuspiciousScripts() {
    const scripts = document.querySelectorAll("script");
    const suspiciousPatterns = [
      /eval\s*\(/,
      /document\.write\s*\(/,
      /location\.replace\s*\(/,
      /window\.open\s*\(/,
    ];

    return Array.from(scripts).some((script) => {
      return suspiciousPatterns.some((pattern) =>
        pattern.test(script.innerHTML)
      );
    });
  }

  checkExternalFormActions() {
    const currentDomain = window.location.hostname;
    const forms = document.querySelectorAll("form[action]");

    return Array.from(forms).some((form) => {
      try {
        const actionUrl = new URL(form.action, window.location.href);
        return actionUrl.hostname !== currentDomain && !isTrustedOrigin(actionUrl.href);
      } catch {
        return false;
      }
    });
  }

  getCSP() {
    const cspMeta = document.querySelector(
      'meta[http-equiv="Content-Security-Policy"]'
    );
    return cspMeta ? cspMeta.getAttribute("content") : null;
  }
}

class UIManager {
  constructor(config) {
    this.config = config;
    this.notifications = [];
  }

  showNotification(notification) {
    if (!this.config.showNotifications) return;

    const notificationElement = this.createNotificationElement(notification);
    document.body.appendChild(notificationElement);

    setTimeout(() => {
      notificationElement.remove();
    }, notification.duration || this.config.notificationDuration || 5000);
  }

  showWarning(message) {
    this.showNotification({
      type: "warning",
      message: typeof message === "string" ? message : message.description,
      duration: 8000,
    });
  }

  showCriticalAlert(threat) {
    this.showNotification({
      type: "error",
      message: `Critical threat detected: ${threat.description}`,
      duration: 10000,
    });
  }

  showInfo(message) {
    this.showNotification({
      type: "info",
      message: typeof message === "string" ? message : message.description,
      duration: 5000,
    });
  }

  showBlockedLinkWarning(url, reason) {
    this.showNotification({
      type: "error",
      message: `Link blocked: ${reason}`,
      duration: 8000,
    });
  }

  showSuspiciousLinkWarning(url, reason) {
    this.showNotification({
      type: "warning",
      message: `Suspicious link detected: ${reason}`,
      duration: 6000,
    });
  }

  createNotificationElement(notification) {
    const element = document.createElement("div");
    element.style.cssText = `
      position: fixed;
      top: 20px;
      right: 20px;
      background: ${this.getNotificationColor(notification.type)};
      color: white;
      padding: 15px 20px;
      border-radius: 5px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
      z-index: 999999;
      max-width: 350px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      line-height: 1.4;
    `;

    element.textContent = notification.message;
    return element;
  }

  getNotificationColor(type) {
    switch (type) {
      case "error":
        return "#dc2626";
      case "warning":
        return "#d97706";
      case "info":
        return "#2563eb";
      case "success":
        return "#059669";
      default:
        return "#6b7280";
    }
  }
}

// Initialize content script (prevent multiple initializations)
if (!window.checkContentInitialized) {
  window.checkContentInitialized = true;

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
      const check = new CheckContent();
      check.initialize();
    });
  } else {
    const check = new CheckContent();
    check.initialize();
  }
}
