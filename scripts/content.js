
/**
 * Microsoft 365 Phishing Protection - Content Script
 * Reliability-first architecture for consistent phishing detection
 *
 * Design Principles:
 * 1. Single initialization path - no race conditions
 * 2. Fail-safe defaults - always protect when uncertain
 * 3. Graceful degradation - work even when components fail
 * 4. Predictable timing - wait for proper DOM state
 * 5. Resource cleanup - prevent memory leaks
 */

import { ReliableDetectionEngine } from "./modules/reliable-detection-engine.js";

// Global state management
const ContentState = {
  initialized: false,
  initializationAttempts: 0,
  maxInitializationAttempts: 3,
  detectionActive: false,
  errorState: null,
  cleanup: []
};

// Reliable logger with fallback
let logger = {
  log: (...args) => console.log("[M365-Protection]", ...args),
  warn: (...args) => console.warn("[M365-Protection]", ...args),
  error: (...args) => console.error("[M365-Protection]", ...args),
  debug: (...args) => console.debug("[M365-Protection]", ...args)
};

// Initialize enhanced logger if available
(async () => {
  try {
    if (chrome?.runtime?.getURL) {
      const loggerModule = await import(chrome.runtime.getURL("scripts/utils/logger.js"));
      logger = loggerModule.default;
      logger.log("Enhanced logger initialized");
    }
  } catch (error) {
    logger.warn("Using fallback logger:", error.message);
  }
})();

/**
 * Reliable Content Script Manager
 * Single point of control for all content script functionality
 */
class ReliableContentManager {
  constructor() {
    this.state = 'pending';
    this.config = null;
    this.policy = null;
    this.detectionRules = null;
    this.messenger = new ReliableMessenger();
    this.detector = null;
    this.protector = null;
    this.cleanup = [];
  }

  /**
   * Main initialization method - single path, no race conditions
   */
  async initialize() {
    if (ContentState.initialized) {
      logger.debug("Content script already initialized");
      return;
    }

    ContentState.initializationAttempts++;
    logger.log(`Initializing content script (attempt ${ContentState.initializationAttempts})`);

    try {
      // Step 1: Wait for proper DOM state
      await this.waitForDOMReady();
      
      // Step 2: Establish reliable communication
      await this.messenger.connect();
      
      // Step 3: Load essential configuration
      await this.loadEssentialConfig();
      
      // Step 4: Initialize detection components
      await this.initializeDetection();
      
      // Step 5: Set up page protection
      await this.initializeProtection();
      
      // Step 6: Register cleanup handlers
      this.registerCleanupHandlers();
      
      ContentState.initialized = true;
      ContentState.detectionActive = true;
      this.state = 'active';
      
      logger.log("Content script initialized successfully");
      
    } catch (error) {
      await this.handleInitializationError(error);
    }
  }

  /**
   * Wait for DOM to be in a reliable state
   */
  async waitForDOMReady() {
    return new Promise((resolve) => {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', resolve, { once: true });
      } else {
        resolve();
      }
    });
  }

  /**
   * Load essential configuration with fallbacks
   */
  async loadEssentialConfig() {
    try {
      // Load config with timeout
      this.config = await this.messenger.sendMessage({
        type: 'GET_CONFIG'
      }, 3000);
      
      // Load policy with timeout
      this.policy = await this.messenger.sendMessage({
        type: 'REQUEST_POLICY'
      }, 3000);
      
      // Load detection rules with timeout
      this.detectionRules = await this.loadDetectionRules();
      
    } catch (error) {
      logger.warn("Failed to load configuration, using defaults:", error.message);
      this.useDefaultConfig();
    }
  }

  /**
   * Load detection rules with reliable fallback
   */
  async loadDetectionRules() {
    try {
      const response = await fetch(chrome.runtime.getURL("rules/detection-rules.json"), {
        cache: "no-cache"
      });
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      return await response.json();
    } catch (error) {
      logger.warn("Failed to load detection rules, using minimal defaults:", error.message);
      return this.getMinimalDetectionRules();
    }
  }

  /**
   * Initialize detection with reliability focus
   */
  async initializeDetection() {
    this.detector = new ReliableDetectionEngine();
    await this.detector.initialize();
    
    // Start detection process
    await this.scanCurrentPage();
  }

  /**
   * Scan current page for threats
   */
  async scanCurrentPage() {
    try {
      // Quick origin check first
      const currentOrigin = location.origin.toLowerCase();
      if (this.detector.isTrustedOrigin(currentOrigin)) {
        logger.log("Trusted Microsoft domain detected");
        await this.handleTrustedPage();
        return;
      }

      // Analyze page content
      const content = document.documentElement.outerHTML;
      const analysis = await this.detector.analyzeContent(content, {
        origin: currentOrigin,
        url: location.href
      });

      // Take action based on analysis
      if (analysis.threatLevel === 'high') {
        await this.blockPage(analysis);
      } else if (analysis.threatLevel === 'medium') {
        await this.showWarning(analysis);
      }

      // Log the scan result
      await this.logScanResult(analysis);

    } catch (error) {
      logger.error("Page scan failed:", error.message);
      this.showGenericWarning();
    }
  }

  /**
   * Handle trusted Microsoft pages
   */
  async handleTrustedPage() {
    try {
      // Show valid badge if enabled
      if (this.policy?.EnableValidPageBadge) {
        this.showValidBadge();
      }
      
      // Log legitimate access
      await this.messenger.sendMessage({
        type: 'LOG_EVENT',
        event: {
          type: 'legitimate_access',
          url: location.href,
          timestamp: new Date().toISOString()
        }
      });
      
    } catch (error) {
      logger.warn("Failed to handle trusted page:", error.message);
    }
  }

  /**
   * Block page based on analysis
   */
  async blockPage(analysis) {
    try {
      // Create blocking overlay
      const overlay = this.createBlockingOverlay(analysis);
      document.documentElement.appendChild(overlay);
      
      // Disable form submissions
      this.disableFormSubmissions();
      
      // Disable credential inputs
      this.disableCredentialInputs();
      
      logger.log("Page blocked successfully");
      
    } catch (error) {
      logger.error("Failed to block page:", error.message);
      this.showGenericWarning();
    }
  }

  /**
   * Show warning based on analysis
   */
  async showWarning(analysis) {
    try {
      const warning = this.createWarningBanner(analysis);
      document.documentElement.appendChild(warning);
      
      logger.log("Warning displayed successfully");
      
    } catch (error) {
      logger.error("Failed to show warning:", error.message);
      this.showGenericWarning();
    }
  }

  /**
   * Create blocking overlay for analysis results
   */
  createBlockingOverlay(analysis) {
    const overlay = document.createElement('div');
    overlay.id = 'ms365-protection-block';
    overlay.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100% !important;
      height: 100% !important;
      background: rgba(0, 0, 0, 0.95) !important;
      z-index: 2147483647 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      font-family: system-ui, -apple-system, sans-serif !important;
    `;

    const content = document.createElement('div');
    content.style.cssText = `
      background: white !important;
      padding: 40px !important;
      border-radius: 8px !important;
      max-width: 500px !important;
      text-align: center !important;
      box-shadow: 0 8px 32px rgba(0,0,0,0.3) !important;
    `;

    const reason = analysis.aadLike ? 'Microsoft login interface detected on untrusted domain' :
                   'Suspicious Microsoft-related content detected';

    content.innerHTML = `
      <div style="color: #d32f2f; font-size: 48px; margin-bottom: 20px;">🛡️</div>
      <h1 style="color: #d32f2f; margin: 0 0 16px 0; font-size: 24px;">Phishing Site Blocked</h1>
      <p style="color: #333; margin: 0 0 20px 0; line-height: 1.5;">
        ${reason}
        <br><small>Confidence: ${Math.round(analysis.confidence * 100)}%</small>
      </p>
      <button id="ms365-go-back" style="
        background: #1976d2;
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 4px;
        font-size: 16px;
        cursor: pointer;
        margin-right: 12px;
      ">Go Back Safely</button>
      <button id="ms365-continue" style="
        background: #666;
        color: white;
        border: none;
        padding: 12px 24px;
        border-radius: 4px;
        font-size: 16px;
        cursor: pointer;
      ">Continue Anyway</button>
    `;

    overlay.appendChild(content);

    // Add event handlers
    content.querySelector('#ms365-go-back').addEventListener('click', () => {
      window.history.back();
    });

    content.querySelector('#ms365-continue').addEventListener('click', () => {
      overlay.remove();
    });

    return overlay;
  }

  /**
   * Create warning banner for analysis results
   */
  createWarningBanner(analysis) {
    const banner = document.createElement('div');
    banner.id = 'ms365-protection-warning';
    banner.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      right: 0 !important;
      background: #ff9800 !important;
      color: white !important;
      padding: 16px !important;
      text-align: center !important;
      font-family: system-ui, -apple-system, sans-serif !important;
      font-size: 14px !important;
      font-weight: 500 !important;
      z-index: 2147483647 !important;
      box-shadow: 0 2px 8px rgba(0,0,0,0.2) !important;
    `;

    banner.innerHTML = `
      <span>⚠️ ${this.policy?.BrandingName || 'Microsoft 365 Protection'}:
      Suspicious Microsoft login page detected. Verify URL before entering credentials.
      (Confidence: ${Math.round(analysis.confidence * 100)}%)</span>
      <button style="
        background: rgba(255,255,255,0.2);
        border: 1px solid white;
        color: white;
        padding: 4px 12px;
        margin-left: 16px;
        border-radius: 4px;
        cursor: pointer;
      " onclick="this.parentElement.remove()">Dismiss</button>
    `;

    // Auto-remove after 15 seconds
    setTimeout(() => {
      if (banner.parentNode) {
        banner.parentNode.removeChild(banner);
      }
    }, 15000);

    return banner;
  }

  /**
   * Show valid badge for legitimate pages
   */
  showValidBadge() {
    try {
      const badge = document.createElement('div');
      badge.id = 'ms365-valid-badge';
      badge.style.cssText = `
        position: fixed !important;
        top: 20px !important;
        right: 20px !important;
        background: #4caf50 !important;
        color: white !important;
        padding: 12px 16px !important;
        border-radius: 8px !important;
        font-family: system-ui, -apple-system, sans-serif !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        z-index: 2147483647 !important;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2) !important;
        display: flex !important;
        align-items: center !important;
        gap: 8px !important;
      `;

      badge.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="11" fill="currentColor"/>
          <path d="M8 12l3 3 5-5" stroke="white" stroke-width="2" fill="none"/>
        </svg>
        <span>Verified Microsoft Login</span>
      `;

      document.documentElement.appendChild(badge);

      // Auto-remove after 5 seconds
      setTimeout(() => {
        if (badge.parentNode) {
          badge.parentNode.removeChild(badge);
        }
      }, 5000);
      
    } catch (error) {
      logger.error("Failed to show valid badge:", error.message);
    }
  }

  /**
   * Disable form submissions on suspicious pages
   */
  disableFormSubmissions() {
    try {
      const forms = document.querySelectorAll('form');
      
      forms.forEach(form => {
        form.addEventListener('submit', (event) => {
          event.preventDefault();
          event.stopImmediatePropagation();
          this.showSubmissionBlockedMessage();
        }, true);
        
        // Mark form as blocked
        form.setAttribute('data-ms365-blocked', 'true');
        form.classList.add('ms365-protection-blocked');
      });
      
      logger.log(`Disabled ${forms.length} form submissions`);
    } catch (error) {
      logger.error("Failed to disable form submissions:", error.message);
    }
  }

  /**
   * Disable credential inputs on suspicious pages
   */
  disableCredentialInputs() {
    try {
      const inputs = document.querySelectorAll('input[type="password"], input[name="loginfmt"], input[name="passwd"]');
      
      inputs.forEach(input => {
        input.disabled = true;
        input.style.opacity = '0.5';
        input.style.pointerEvents = 'none';
        input.setAttribute('readonly', 'true');
        input.classList.add('ms365-protection-disabled');
      });
      
      logger.log(`Disabled ${inputs.length} credential inputs`);
    } catch (error) {
      logger.error("Failed to disable credential inputs:", error.message);
    }
  }

  /**
   * Show generic warning for error cases
   */
  showGenericWarning() {
    const warning = document.createElement('div');
    warning.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      right: 0 !important;
      background: #d32f2f !important;
      color: white !important;
      padding: 12px !important;
      text-align: center !important;
      font-family: system-ui, -apple-system, sans-serif !important;
      font-size: 14px !important;
      z-index: 2147483647 !important;
    `;
    warning.textContent = '⚠️ Microsoft 365 Protection: Unable to verify page safety - Exercise caution';
    
    document.documentElement.appendChild(warning);
    
    setTimeout(() => {
      if (warning.parentNode) {
        warning.parentNode.removeChild(warning);
      }
    }, 8000);
  }

  /**
   * Log scan result
   */
  async logScanResult(analysis) {
    try {
      await this.messenger.sendMessage({
        type: 'LOG_EVENT',
        event: {
          type: 'page_scanned',
          url: location.href,
          analysis: analysis,
          timestamp: new Date().toISOString()
        }
      });
    } catch (error) {
      logger.warn("Failed to log scan result:", error.message);
    }
  }

  /**
   * Initialize page protection mechanisms
   */
  async initializeProtection() {
    this.protector = new PageProtector(this.config, this.policy);
    await this.protector.initialize();
  }

  /**
   * Handle initialization errors with retry logic
   */
  async handleInitializationError(error) {
    ContentState.errorState = error;
    logger.error(`Initialization failed (attempt ${ContentState.initializationAttempts}):`, error.message);
    
    if (ContentState.initializationAttempts < ContentState.maxInitializationAttempts) {
      const delay = Math.min(1000 * ContentState.initializationAttempts, 5000);
      logger.log(`Retrying initialization in ${delay}ms`);
      
      setTimeout(() => {
        this.initialize();
      }, delay);
    } else {
      logger.error("Max initialization attempts reached, entering fallback mode");
      this.enterFallbackMode();
    }
  }

  /**
   * Fallback mode for when full initialization fails
   */
  enterFallbackMode() {
    this.state = 'fallback';
    logger.log("Entering fallback protection mode");
    
    // Minimal protection - block obvious phishing attempts
    this.setupMinimalProtection();
  }

  /**
   * Minimal protection when full system fails
   */
  setupMinimalProtection() {
    try {
      // Quick check for Microsoft login elements on non-Microsoft domains
      const hasLoginElements = document.querySelector('input[name="loginfmt"]') || 
                              document.querySelector('#i0116') ||
                              document.querySelector('input[type="password"]');
      
      const isMicrosoftDomain = location.hostname.includes('microsoft') || 
                               location.hostname.includes('office') ||
                               location.hostname === 'login.microsoftonline.com';
      
      if (hasLoginElements && !isMicrosoftDomain) {
        this.showFallbackWarning();
      }
    } catch (error) {
      logger.error("Fallback protection failed:", error.message);
    }
  }

  /**
   * Show warning in fallback mode
   */
  showFallbackWarning() {
    const warning = document.createElement('div');
    warning.id = 'ms365-fallback-warning';
    warning.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      right: 0 !important;
      background: #d32f2f !important;
      color: white !important;
      padding: 12px !important;
      text-align: center !important;
      font-family: system-ui, -apple-system, sans-serif !important;
      font-size: 14px !important;
      font-weight: 500 !important;
      z-index: 2147483647 !important;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3) !important;
    `;
    warning.textContent = '⚠️ Microsoft 365 Protection: Suspicious login page detected - Verify URL before entering credentials';
    
    document.documentElement.appendChild(warning);
    
    // Auto-remove after 10 seconds
    setTimeout(() => {
      if (warning.parentNode) {
        warning.parentNode.removeChild(warning);
      }
    }, 10000);
  }

  /**
   * Use default configuration when loading fails
   */
  useDefaultConfig() {
    this.config = {
      extensionEnabled: true,
      enableContentManipulation: true,
      enableUrlMonitoring: true,
      showNotifications: true,
      enableDebugLogging: false
    };
    
    this.policy = {
      BrandingName: "Microsoft 365 Phishing Protection",
      BrandingImage: "",
      ExtraWhitelist: [],
      CIPPReportingServer: "",
      AlertWhenLogon: true,
      ValidPageBadgeImage: "",
      StrictResourceAudit: true,
      RequireMicrosoftAction: true,
      EnableValidPageBadge: false
    };
  }

  /**
   * Minimal detection rules for fallback
   */
  getMinimalDetectionRules() {
    return {
      trusted_origins: [
        "https://login.microsoftonline.com",
        "https://login.microsoft.com",
        "https://login.windows.net",
        "https://login.live.com"
      ],
      thresholds: {
        legitimate: 85,
        suspicious: 55,
        phishing: 25
      }
    };
  }

  /**
   * Register cleanup handlers to prevent memory leaks
   */
  registerCleanupHandlers() {
    const cleanup = () => {
      this.cleanup.forEach(fn => {
        try {
          fn();
        } catch (error) {
          logger.error("Cleanup error:", error.message);
        }
      });
    };

    // Register cleanup on page unload
    window.addEventListener('beforeunload', cleanup);
    window.addEventListener('pagehide', cleanup);
    
    // Store cleanup function for manual cleanup
    this.cleanup.push(() => {
      window.removeEventListener('beforeunload', cleanup);
      window.removeEventListener('pagehide', cleanup);
    });
  }
}

/**
 * Reliable Messenger - handles all background communication
 */
class ReliableMessenger {
  constructor() {
    this.connected = false;
    this.connectionAttempts = 0;
    this.maxConnectionAttempts = 5;
    this.messageQueue = [];
    this.pendingMessages = new Map();
    this.messageId = 0;
  }

  /**
   * Establish reliable connection to background script
   */
  async connect() {
    this.connectionAttempts++;
    
    try {
      const response = await this.sendMessage({ type: 'ping' }, 2000);
      
      if (response && response.success) {
        this.connected = true;
        this.connectionAttempts = 0;
        logger.log("Background connection established");
        
        // Process queued messages
        await this.processMessageQueue();
        return true;
      }
    } catch (error) {
      logger.warn(`Connection attempt ${this.connectionAttempts} failed:`, error.message);
    }

    if (this.connectionAttempts < this.maxConnectionAttempts) {
      const delay = Math.min(1000 * this.connectionAttempts, 5000);
      await new Promise(resolve => setTimeout(resolve, delay));
      return this.connect();
    }

    throw new Error("Failed to establish background connection");
  }

  /**
   * Send message with timeout and retry logic
   */
  async sendMessage(message, timeout = 5000) {
    return new Promise((resolve, reject) => {
      const messageId = ++this.messageId;
      const timeoutId = setTimeout(() => {
        this.pendingMessages.delete(messageId);
        reject(new Error("Message timeout"));
      }, timeout);

      this.pendingMessages.set(messageId, { resolve, reject, timeoutId });

      try {
        chrome.runtime.sendMessage(message, (response) => {
          const pending = this.pendingMessages.get(messageId);
          if (!pending) return; // Already timed out
          
          clearTimeout(pending.timeoutId);
          this.pendingMessages.delete(messageId);

          if (chrome.runtime.lastError) {
            pending.reject(new Error(chrome.runtime.lastError.message));
          } else {
            pending.resolve(response);
          }
        });
      } catch (error) {
        const pending = this.pendingMessages.get(messageId);
        if (pending) {
          clearTimeout(pending.timeoutId);
          this.pendingMessages.delete(messageId);
          pending.reject(error);
        }
      }
    });
  }

  /**
   * Process queued messages after connection is established
   */
  async processMessageQueue() {
    while (this.messageQueue.length > 0) {
      const queuedMessage = this.messageQueue.shift();
      try {
        await this.sendMessage(queuedMessage.message, queuedMessage.timeout);
      } catch (error) {
        logger.warn("Failed to process queued message:", error.message);
      }
    }
  }
}

/**
 * Reliable Detector - simplified detection logic
 */
class ReliableDetector {
  constructor(config, policy, rules) {
    this.config = config;
    this.policy = policy;
    this.rules = rules;
    this.trustedOrigins = new Set(rules?.trusted_origins || []);
    this.scanComplete = false;
  }

  async initialize() {
    logger.log("Initializing reliable detector");
    // Minimal initialization - just prepare trusted origins
    this.trustedOrigins = new Set(this.rules?.trusted_origins || [
      "https://login.microsoftonline.com",
      "https://login.microsoft.com",
      "https://login.windows.net",
      "https://login.live.com"
    ]);
  }

  /**
   * Scan current page for threats - reliability focused
   */
  async scanCurrentPage() {
    if (this.scanComplete) return;
    
    try {
      logger.log("Starting page scan");
      
      // Step 1: Quick origin check
      const currentOrigin = location.origin.toLowerCase();
      if (this.isTrustedOrigin(currentOrigin)) {
        logger.log("Trusted Microsoft domain detected");
        await this.handleTrustedPage();
        return;
      }

      // Step 2: Check for Microsoft login elements
      const hasMicrosoftElements = this.detectMicrosoftElements();
      if (!hasMicrosoftElements) {
        logger.debug("No Microsoft login elements detected");
        this.scanComplete = true;
        return;
      }

      // Step 3: Analyze potential phishing
      logger.log("Microsoft login elements detected on non-Microsoft domain");
      await this.analyzePotentialPhishing();
      
      this.scanComplete = true;
      
    } catch (error) {
      logger.error("Page scan failed:", error.message);
      // In case of error, show warning to be safe
      this.showGenericWarning();
    }
  }

  /**
   * Check if origin is trusted
   */
  isTrustedOrigin(origin) {
    return this.trustedOrigins.has(origin);
  }

  /**
   * Detect Microsoft login elements reliably
   */
  detectMicrosoftElements() {
    try {
      // Check for key Microsoft login indicators
      const indicators = [
        () => document.querySelector('input[name="loginfmt"]'),
        () => document.querySelector('#i0116'),
        () => document.querySelector('input[type="password"]') && 
              (document.body.textContent.includes('Microsoft') || 
               document.body.textContent.includes('Office 365')),
        () => document.querySelector('#idSIButton9'),
        () => document.body.textContent.includes('Sign in to your account')
      ];

      return indicators.some(check => {
        try {
          return check();
        } catch {
          return false;
        }
      });
    } catch (error) {
      logger.error("Element detection failed:", error.message);
      return false;
    }
  }

  /**
   * Handle trusted Microsoft pages
   */
  async handleTrustedPage() {
    try {
      // Show valid badge if enabled
      if (this.policy?.EnableValidPageBadge) {
        this.showValidBadge();
      }
      
      // Log legitimate access
      await this.messenger.sendMessage({
        type: 'LOG_EVENT',
        event: {
          type: 'legitimate_access',
          url: location.href,
          timestamp: new Date().toISOString()
        }
      });
      
    } catch (error) {
      logger.warn("Failed to handle trusted page:", error.message);
    }
  }

  /**
   * Analyze potential phishing with reliable detection
   */
  async analyzePotentialPhishing() {
    try {
      // Check form actions
      const formCheck = this.checkFormActions();
      
      // Check for required Microsoft elements
      const elementCheck = this.checkRequiredElements();
      
      // Determine threat level
      const threatLevel = this.calculateThreatLevel(formCheck, elementCheck);
      
      if (threatLevel === 'high') {
        logger.warn("High threat level detected - blocking page");
        await this.blockPage(formCheck, elementCheck);
      } else if (threatLevel === 'medium') {
        logger.warn("Medium threat level detected - showing warning");
        await this.showWarning(formCheck, elementCheck);
      }
      
      // Log detection event
      await this.logDetectionEvent(threatLevel, formCheck, elementCheck);
      
    } catch (error) {
      logger.error("Phishing analysis failed:", error.message);
      // Fail safe - show warning when analysis fails
      this.showGenericWarning();
    }
  }

  /**
   * Check form actions for suspicious behavior
   */
  checkFormActions() {
    try {
      const forms = document.querySelectorAll('form');
      const suspiciousForms = [];
      
      for (const form of forms) {
        const action = form.getAttribute('action') || location.href;
        const resolvedAction = new URL(action, location.href).href;
        const actionOrigin = new URL(resolvedAction).origin.toLowerCase();
        
        if (!this.isTrustedOrigin(actionOrigin)) {
          suspiciousForms.push({
            action: resolvedAction,
            origin: actionOrigin
          });
        }
      }
      
      return {
        totalForms: forms.length,
        suspiciousForms: suspiciousForms,
        hasSuspiciousForms: suspiciousForms.length > 0
      };
    } catch (error) {
      logger.error("Form action check failed:", error.message);
      return { totalForms: 0, suspiciousForms: [], hasSuspiciousForms: false };
    }
  }

  /**
   * Check for required Microsoft elements
   */
  checkRequiredElements() {
    try {
      const requiredElements = [
        { name: 'loginfmt', selector: 'input[name="loginfmt"], #i0116' },
        { name: 'idPartnerPL', selector: 'input[name="idPartnerPL"]' },
        { name: 'flowToken', check: () => document.body.textContent.includes('flowToken') },
        { name: 'urlMsaSignUp', check: () => document.body.textContent.includes('urlMsaSignUp') }
      ];

      const foundElements = [];
      const missingElements = [];

      for (const element of requiredElements) {
        let found = false;
        
        try {
          if (element.selector) {
            found = !!document.querySelector(element.selector);
          } else if (element.check) {
            found = element.check();
          }
        } catch {
          found = false;
        }

        if (found) {
          foundElements.push(element.name);
        } else {
          missingElements.push(element.name);
        }
      }

      return {
        foundElements,
        missingElements,
        foundCount: foundElements.length,
        totalCount: requiredElements.length,
        legitimacyScore: (foundElements.length / requiredElements.length) * 100
      };
    } catch (error) {
      logger.error("Element check failed:", error.message);
      return { foundElements: [], missingElements: [], foundCount: 0, totalCount: 0, legitimacyScore: 0 };
    }
  }

  /**
   * Calculate threat level based on analysis
   */
  calculateThreatLevel(formCheck, elementCheck) {
    try {
      // High threat: Suspicious forms + low legitimacy
      if (formCheck.hasSuspiciousForms && elementCheck.legitimacyScore < 50) {
        return 'high';
      }
      
      // Medium threat: Either suspicious forms OR very low legitimacy
      if (formCheck.hasSuspiciousForms || elementCheck.legitimacyScore < 25) {
        return 'medium';
      }
      
      // Low threat: Some missing elements but no obvious red flags
      if (elementCheck.legitimacyScore < 75) {
        return 'low';
      }
      
      return 'none';
    } catch (error) {
      logger.error("Threat level calculation failed:", error.message);
      return 'medium'; // Fail safe
    }
  }

  /**
   * Block page with clear messaging
   */
  async blockPage(formCheck, elementCheck) {
    try {
      // Create blocking overlay
      const overlay = this.createBlockingOverlay(formCheck, elementCheck);
      document.documentElement.appendChild(overlay);
      
      // Disable form submissions
      this.disableFormSubmissions();
      
      // Disable credential inputs
      this.disableCredentialInputs();
      
      logger.log("Page blocked successfully");
      
    } catch (error) {
      logger.error("Failed to block page:", error.message);
      this.showGenericWarning();
    }
  }

  /**
   * Show warning without blocking
   */
  async showWarning(formCheck, elementCheck) {
    try {
      const warning = this.createWarningBanner(formCheck, elementCheck);
      document.documentElement.appendChild(warning);
      
      logger.log("Warning displayed successfully");
      
    } catch (error) {
      logger.error("Failed to show warning:", error.message);
      this.showGenericWarning();
    }
  }

  /**
   * Create blocking overlay
   */
  createBlockingOverlay(formCheck, elementCheck) {
    const overlay = document.createElement('div');
    overlay.id = 'ms365-protection-block';
    overlay.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100% !important;
      height: 100% !important;
      background: rgba(0, 0, 0, 0.95) !important;
      z-index: 2147483647 !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      font-family: system-ui, -apple-system, sans-serif !important;
    `;

    const content = document.createElement('div');
    content.style.cssText = `
      background: white !important;
      padding: 40px !important;
      border-radius: 8px !important;
      max-width: 500px !important;
      text-align: center !important;
      box-shadow: 0 8px 32px rgba(0,0,0,0.3) !important;
    `;

    content.innerHTML = `
      <div style="color: #d32f2f; font-size: 48px; margin-bottom: 20px;">🛡️</div>
      <h1 style="color: #d32f2f; margin: 0 0 16px 0; font-size: 24px;">Phishing Site Blocked</h1>
      <p style="color: #333; margin: 0 0 20px 0; line-height: 1.5;">
        This page appears to be impersonating Microsoft 365 login. 
        ${formCheck.hasSuspiciousForms ? 'Forms submit to non-Microsoft servers. ' : ''}
        ${elementCheck.legitimacyScore < 50 ? 'Missing required Microsoft authentication elements. ' : ''}
      </p>
      <button id="ms365-go-back" style="
        background: #1976d2; 
        color: white; 
        border: none; 
        padding: 12px 24px; 
        border-radius: 4px; 
        font-size: 16px; 
        cursor: pointer;
        margin-right: 12px;
      ">Go Back Safely</button>
      <button id="ms365-continue" style="
        background: #666; 
        color: white; 
        border: none; 
        padding: 12px 24px; 
        border-radius: 4px; 
        font-size: 16px; 
        cursor: pointer;
      ">Continue Anyway</button>
    `;

    overlay.appendChild(content);

    // Add event handlers
    content.querySelector('#ms365-go-back').addEventListener('click', () => {
      window.history.back();
    });

    content.querySelector('#ms365-continue').addEventListener('click', () => {
      overlay.remove();
    });

    return overlay;
  }

  /**
   * Create warning banner
   */
  createWarningBanner(formCheck, elementCheck) {
    const banner = document.createElement('div');
    banner.id = 'ms365-protection-warning';
    banner.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      right: 0 !important;
      background: #ff9800 !important;
      color: white !important;
      padding: 16px !important;
      text-align: center !important;
      font-family: system-ui, -apple-system, sans-serif !important;
      font-size: 14px !important;
      font-weight: 500 !important;
      z-index: 2147483647 !important;
      box-shadow: 0 2px 8px rgba(0,0,0,0.2) !important;
    `;

    banner.innerHTML = `
      <span>⚠️ ${this.policy?.BrandingName || 'Microsoft 365 Protection'}: 
      Suspicious Microsoft login page detected. Verify URL before entering credentials.</span>
      <button style="
        background: rgba(255,255,255,0.2); 
        border: 1px solid white; 
        color: white; 
        padding: 4px 12px; 
        margin-left: 16px; 
        border-radius: 4px; 
        cursor: pointer;
      " onclick="this.parentElement.remove()">Dismiss</button>
    `;

    // Auto-remove after 15 seconds
    setTimeout(() => {
      if (banner.parentNode) {
        banner.parentNode.removeChild(banner);
      }
    }, 15000);

    return banner;
  }

  /**
   * Show generic warning for error cases
   */
  showGenericWarning() {
    const warning = document.createElement('div');
    warning.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      right: 0 !important;
      background: #d32f2f !important;
      color: white !important;
      padding: 12px !important;
      text-align: center !important;
      font-family: system-ui, -apple-system, sans-serif !important;
      font-size: 14px !important;
      z-index: 2147483647 !important;
    `;
    warning.textContent = '⚠️ Microsoft 365 Protection: Unable to verify page safety - Exercise caution';
    
    document.documentElement.appendChild(warning);
    
    setTimeout(() => {
      if (warning.parentNode) {
        warning.parentNode.removeChild(warning);
      }
    }, 8000);
  }

  /**
   * Show valid badge for legitimate pages
   */
  showValidBadge() {
    try {
      const badge = document.createElement('div');
      badge.id = 'ms365-valid-badge';
      badge.style.cssText = `
        position: fixed !important;
        top: 20px !important;
        right: 20px !important;
        background: #4caf50 !important;
        color: white !important;
        padding: 12px 16px !important;
        border-radius: 8px !important;
        font-family: system-ui, -apple-system, sans-serif !important;
        font-size: 14px !important;
        font-weight: 500 !important;
        z-index: 2147483647 !important;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2) !important;
        display: flex !important;
        align-items: center !important;
        gap: 8px !important;
      `;

      badge.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none">
          <circle cx="12" cy="12" r="11" fill="currentColor"/>
          <path d="M8 12l3 3 5-5" stroke="white" stroke-width="2" fill="none"/>
        </svg>
        <span>Verified Microsoft Login</span>
      `;

      document.documentElement.appendChild(badge);

      // Auto-remove after 5 seconds
      setTimeout(() => {
        if (badge.parentNode) {
          badge.parentNode.removeChild(badge);
        }
      }, 5000);
      
    } catch (error) {
      logger.error("Failed to show valid badge:", error.message);
    }
  }

  /**
   * Disable form submissions on suspicious pages
   */
  disableFormSubmissions() {
    try {
      const forms = document.querySelectorAll('form');
      
      forms.forEach(form => {
        form.addEventListener('submit', (event) => {
          event.preventDefault();
          event.stopImmediatePropagation();
          this.showSubmissionBlockedMessage();
        }, true);
      });
      
      logger.log(`Disabled ${forms.length} form submissions`);
    } catch (error) {
      logger.error("Failed to disable form submissions:", error.message);
    }
  }

  /**
   * Disable credential inputs on suspicious pages
   */
  disableCredentialInputs() {
    try {
      const inputs = document.querySelectorAll('input[type="password"], input[name="loginfmt"], input[name="passwd"]');
      
      inputs.forEach(input => {
        input.disabled = true;
        input.style.opacity = '0.5';
        input.style.pointerEvents = 'none';
        input.setAttribute('readonly', 'true');
      });
      
      logger.log(`Disabled ${inputs.length} credential inputs`);
    } catch (error) {
      logger.error("Failed to disable credential inputs:", error.message);
    }
  }

  /**
   * Show message when form submission is blocked
   */
  showSubmissionBlockedMessage() {
    try {
      const message = document.createElement('div');
      message.style.cssText = `
        position: fixed !important;
        top: 50% !important;
        left: 50% !important;
        transform: translate(-50%, -50%) !important;
        background: #d32f2f !important;
        color: white !important;
        padding: 20px !important;
        border-radius: 8px !important;
        font-family: system-ui, -apple-system, sans-serif !important;
        font-size: 16px !important;
        font-weight: 500 !important;
        z-index: 2147483647 !important;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3) !important;
        text-align: center !important;
      `;
      message.textContent = '🛡️ Form submission blocked - This appears to be a phishing site';
      
      document.documentElement.appendChild(message);
      
      setTimeout(() => {
        if (message.parentNode) {
          message.parentNode.removeChild(message);
        }
      }, 3000);
      
    } catch (error) {
      logger.error("Failed to show submission blocked message:", error.message);
    }
  }

  /**
   * Log detection event
   */
  async logDetectionEvent(threatLevel, formCheck, elementCheck) {
    try {
      await this.messenger.sendMessage({
        type: 'LOG_EVENT',
        event: {
          type: 'threat_detected',
          url: location.href,
          threatLevel: threatLevel,
          action: threatLevel === 'high' ? 'blocked' : 'warned',
          reason: 'Microsoft 365 phishing page detected',
          details: {
            formCheck: formCheck,
            elementCheck: elementCheck,
            timestamp: new Date().toISOString()
          }
        }
      });
    } catch (error) {
      logger.warn("Failed to log detection event:", error.message);
    }
  }
}

/**
 * Page Protector - handles DOM protection mechanisms
 */
class PageProtector {
  constructor(config, policy) {
    this.config = config;
    this.policy = policy;
    this.protectionActive = false;
  }

  async initialize() {
    logger.log("Initializing page protector");
    this.protectionActive = true;
  }

  /**
   * Apply protection measures
   */
  async protect() {
    if (!this.protectionActive) return;
    
    try {
      // Add protection styles
      this.injectProtectionStyles();
      
      // Set up form monitoring
      this.setupFormMonitoring();
      
      logger.log("Page protection applied");
    } catch (error) {
      logger.error("Failed to apply protection:", error.message);
    }
  }

  /**
   * Inject protection styles
   */
  injectProtectionStyles() {
    const style = document.createElement('style');
    style.id = 'ms365-protection-styles';
    style.textContent = `
      .ms365-protection-disabled {
        opacity: 0.5 !important;
        pointer-events: none !important;
        filter: grayscale(1) !important;
      }
      
      .ms365-protection-warning {
        border: 2px solid #ff9800 !important;
        background: rgba(255, 152, 0, 0.1) !important;
      }
      
      .ms365-protection-blocked {
        border: 2px solid #d32f2f !important;
        background: rgba(211, 47, 47, 0.1) !important;
      }
    `;
    
    document.head.appendChild(style);
  }

  /**
   * Set up form monitoring
   */
  setupFormMonitoring() {
    document.addEventListener('submit', (event) => {
      if (this.shouldBlockSubmission(event.target)) {
        event.preventDefault();
        event.stopImmediatePropagation();
        logger.log("Form submission blocked by protector");
      }
    }, true);
  }

  /**
   * Determine if form submission should be blocked
   */
  shouldBlockSubmission(form) {
    try {
      // Check if form has protection markers
      return form.classList.contains('ms365-protection-blocked') ||
             form.hasAttribute('data-ms365-blocked');
    } catch {
      return false;
    }
  }
}

/**
 * Initialization Controller - manages startup sequence
 */
class InitializationController {
  constructor() {
    this.startTime = Date.now();
    this.initialized = false;
  }

  /**
   * Start the reliable initialization sequence
   */
  async start() {
    // Prevent multiple initializations
    if (window.ms365ProtectionActive) {
      logger.debug("Protection already active");
      return;
    }
    
    window.ms365ProtectionActive = true;
    
    try {
      logger.log("Starting Microsoft 365 Protection initialization");
      
      const manager = new ReliableContentManager();
      await manager.initialize();
      
      const initTime = Date.now() - this.startTime;
      logger.log(`Initialization completed in ${initTime}ms`);
      
      this.initialized = true;
      
    } catch (error) {
      logger.error("Initialization failed:", error.message);
      
      // Fallback protection
      const fallbackManager = new ReliableContentManager();
      fallbackManager.enterFallbackMode();
    }
  }
}

/**
 * Safe startup sequence
 */
function safeStartup() {
  try {
    const controller = new InitializationController();
    
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => {
        controller.start();
      }, { once: true });
    } else {
      // DOM already ready
      controller.start();
    }
    
  } catch (error) {
    logger.error("Startup failed:", error.message);
    
    // Last resort fallback
    setTimeout(() => {
      try {
        const manager = new ReliableContentManager();
        manager.setupMinimalProtection();
      } catch (fallbackError) {
        logger.error("Fallback protection failed:", fallbackError.message);
      }
    }, 1000);
  }
}

// Start the extension
safeStartup();

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  ContentState.cleanup.forEach(fn => {
    try {
      fn();
    } catch (error) {
      logger.error("Cleanup error:", error.message);
    }
  });
});
