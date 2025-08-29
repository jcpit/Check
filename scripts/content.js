/**
 * CyberShield Drain - Content Script
 * Handles page manipulation, monitoring, and security enforcement
 */

class CyberShieldContent {
  constructor() {
    this.isInitialized = false;
    this.config = null;
    this.observers = [];
    this.securityMonitor = null;
    this.pageAnalyzer = null;
    this.uiManager = null;
  }

  async initialize() {
    try {
      console.log('CyberShield Drain: Initializing content script...');
      
      // Load configuration from background
      this.config = await this.getConfigFromBackground();
      
      // Initialize components
      this.securityMonitor = new SecurityMonitor(this.config);
      this.pageAnalyzer = new PageAnalyzer(this.config);
      this.uiManager = new UIManager(this.config);
      
      // Set up page monitoring
      this.setupPageMonitoring();
      
      // Set up message handling
      this.setupMessageHandling();
      
      // Perform initial page analysis
      await this.performInitialAnalysis();
      
      this.isInitialized = true;
      console.log('CyberShield Drain: Content script initialized successfully');
    } catch (error) {
      console.error('CyberShield Drain: Failed to initialize content script:', error);
    }
  }

  async getConfigFromBackground() {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        type: 'GET_CONFIG'
      }, (response) => {
        if (response && response.success) {
          resolve(response.config);
        } else {
          resolve(this.getDefaultConfig());
        }
      });
    });
  }

  getDefaultConfig() {
    return {
      extensionEnabled: true,
      enableContentManipulation: true,
      enableUrlMonitoring: true,
      showNotifications: true,
      debugMode: false
    };
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
      attributeFilter: ['src', 'href', 'action', 'onclick']
    });

    this.observers.push(domObserver);

    // Monitor form submissions
    document.addEventListener('submit', (event) => {
      this.handleFormSubmission(event);
    });

    // Monitor navigation attempts
    document.addEventListener('click', (event) => {
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
        type: 'dynamic_script_execution',
        code: code.substring(0, 100), // Log first 100 chars only
        url: window.location.href,
        timestamp: new Date().toISOString()
      });
      
      // Check if dynamic execution is allowed
      if (this.config.blockDynamicScripts) {
        console.warn('CyberShield Drain: Dynamic script execution blocked');
        return null;
      }
      
      return originalEval.call(window, code);
    };

    // Monitor setTimeout/setInterval with code strings
    const originalSetTimeout = window.setTimeout;
    window.setTimeout = (handler, timeout, ...args) => {
      if (typeof handler === 'string') {
        this.logSecurityEvent({
          type: 'dynamic_timeout_execution',
          code: handler.substring(0, 100),
          url: window.location.href,
          timestamp: new Date().toISOString()
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
  }

  async handleMessage(message, sender, sendResponse) {
    try {
      switch (message.type) {
        case 'ANALYZE_PAGE':
          const analysis = await this.pageAnalyzer.analyzePage();
          sendResponse({ success: true, analysis });
          break;

        case 'INJECT_SCRIPT':
          const injectionResult = await this.injectScript(message.script, message.options);
          sendResponse({ success: true, result: injectionResult });
          break;

        case 'MANIPULATE_CONTENT':
          const manipulationResult = await this.manipulateContent(message.action, message.target, message.options);
          sendResponse({ success: true, result: manipulationResult });
          break;

        case 'GET_PAGE_INFO':
          const pageInfo = this.getPageInfo();
          sendResponse({ success: true, info: pageInfo });
          break;

        case 'UPDATE_CONFIG':
          this.config = { ...this.config, ...message.config };
          sendResponse({ success: true });
          break;

        case 'SHOW_NOTIFICATION':
          this.uiManager.showNotification(message.notification);
          sendResponse({ success: true });
          break;

        case 'BLOCK_PAGE':
          this.blockPage(message.reason);
          sendResponse({ success: true });
          break;

        default:
          sendResponse({ success: false, error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('CyberShield Drain: Error handling message:', error);
      sendResponse({ success: false, error: error.message });
    }
  }

  async performInitialAnalysis() {
    const analysis = await this.pageAnalyzer.analyzePage();
    
    // Report analysis to background
    chrome.runtime.sendMessage({
      type: 'LOG_EVENT',
      event: {
        type: 'page_analysis',
        url: window.location.href,
        analysis,
        timestamp: new Date().toISOString()
      }
    });

    // Take action based on analysis
    if (analysis.threats && analysis.threats.length > 0) {
      this.handleThreatsDetected(analysis.threats);
    }
  }

  handleDOMChanges(mutations) {
    mutations.forEach((mutation) => {
      if (mutation.type === 'childList') {
        // Check for dynamically added scripts
        mutation.addedNodes.forEach((node) => {
          if (node.nodeType === Node.ELEMENT_NODE) {
            this.checkNewElement(node);
          }
        });
      } else if (mutation.type === 'attributes') {
        // Check for suspicious attribute changes
        this.checkAttributeChange(mutation);
      }
    });
  }

  checkNewElement(element) {
    // Check for script elements
    if (element.tagName === 'SCRIPT') {
      this.logSecurityEvent({
        type: 'dynamic_script_added',
        src: element.src || 'inline',
        content: element.innerHTML.substring(0, 100),
        url: window.location.href,
        timestamp: new Date().toISOString()
      });
    }

    // Check for iframe elements
    if (element.tagName === 'IFRAME') {
      this.analyzeIframe(element);
    }

    // Check for form elements
    if (element.tagName === 'FORM') {
      this.analyzeForm(element);
    }

    // Recursively check child elements
    element.querySelectorAll('script, iframe, form').forEach((child) => {
      this.checkNewElement(child);
    });
  }

  checkAttributeChange(mutation) {
    const element = mutation.target;
    const attributeName = mutation.attributeName;
    
    // Check for suspicious attribute changes
    if (['onclick', 'onload', 'onerror'].includes(attributeName)) {
      this.logSecurityEvent({
        type: 'suspicious_attribute_change',
        element: element.tagName,
        attribute: attributeName,
        value: element.getAttribute(attributeName),
        url: window.location.href,
        timestamp: new Date().toISOString()
      });
    }
  }

  handleFormSubmission(event) {
    const form = event.target;
    
    // Analyze form for potential threats
    const formData = new FormData(form);
    const hasPasswordField = form.querySelector('input[type="password"]');
    const hasEmailField = form.querySelector('input[type="email"]');
    
    if (hasPasswordField || hasEmailField) {
      // This might be a login form
      this.analyzeLoginForm(form, event);
    }

    // Log form submission
    this.logSecurityEvent({
      type: 'form_submission',
      action: form.action,
      method: form.method,
      hasPassword: !!hasPasswordField,
      hasEmail: !!hasEmailField,
      url: window.location.href,
      timestamp: new Date().toISOString()
    });
  }

  analyzeLoginForm(form, event) {
    // Check if this is a suspicious login form
    const currentDomain = window.location.hostname;
    const formAction = form.action;
    
    // Check if form submits to different domain
    if (formAction && !formAction.includes(currentDomain)) {
      this.logSecurityEvent({
        type: 'suspicious_login_form',
        currentDomain,
        formAction,
        reason: 'Cross-domain form submission',
        url: window.location.href,
        timestamp: new Date().toISOString()
      });

      // Potentially block or warn user
      if (this.config.blockSuspiciousForms) {
        event.preventDefault();
        this.uiManager.showWarning('Suspicious login form detected. Submission blocked.');
      }
    }
  }

  handleLinkClick(event) {
    const link = event.target.closest('a');
    if (!link) return;

    const href = link.href;
    if (!href) return;

    // Analyze link for potential threats
    this.analyzeLinkSafety(href, event);
  }

  async analyzeLinkSafety(url, event) {
    // Request URL analysis from background
    chrome.runtime.sendMessage({
      type: 'URL_ANALYSIS_REQUEST',
      url
    }, (response) => {
      if (response && response.success && response.analysis) {
        if (response.analysis.isBlocked) {
          event.preventDefault();
          this.uiManager.showBlockedLinkWarning(url, response.analysis.reason);
        } else if (response.analysis.isSuspicious) {
          // Show warning but allow navigation
          this.uiManager.showSuspiciousLinkWarning(url, response.analysis.reason);
        }
      }
    });
  }

  async injectScript(script, options = {}) {
    try {
      // Check if script injection is allowed
      const policyCheck = await this.checkPolicy('SCRIPT_INJECTION', {
        domain: window.location.hostname,
        hasCSP: this.hasContentSecurityPolicy()
      });

      if (!policyCheck.allowed) {
        throw new Error(`Script injection blocked: ${policyCheck.reason}`);
      }

      // Create and inject script element
      const scriptElement = document.createElement('script');
      
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
        type: 'script_injection',
        src: options.src || 'inline',
        url: window.location.href,
        timestamp: new Date().toISOString()
      });

      return { success: true };
    } catch (error) {
      console.error('CyberShield Drain: Script injection failed:', error);
      return { success: false, error: error.message };
    }
  }

  async manipulateContent(action, target, options = {}) {
    try {
      // Check if content manipulation is allowed
      const policyCheck = await this.checkPolicy('CONTENT_MANIPULATION', {
        domain: window.location.hostname,
        manipulationType: action
      });

      if (!policyCheck.allowed) {
        throw new Error(`Content manipulation blocked: ${policyCheck.reason}`);
      }

      let result;
      
      switch (action) {
        case 'hide_element':
          result = this.hideElement(target, options);
          break;
        case 'show_element':
          result = this.showElement(target, options);
          break;
        case 'modify_text':
          result = this.modifyText(target, options.text);
          break;
        case 'inject_css':
          result = this.injectCSS(options.css);
          break;
        case 'remove_element':
          result = this.removeElement(target);
          break;
        default:
          throw new Error(`Unknown manipulation action: ${action}`);
      }

      this.logSecurityEvent({
        type: 'content_manipulation',
        action,
        target: typeof target === 'string' ? target : target.tagName,
        url: window.location.href,
        timestamp: new Date().toISOString()
      });

      return result;
    } catch (error) {
      console.error('CyberShield Drain: Content manipulation failed:', error);
      return { success: false, error: error.message };
    }
  }

  hideElement(selector, options = {}) {
    const elements = typeof selector === 'string' ? 
      document.querySelectorAll(selector) : [selector];
    
    elements.forEach(element => {
      if (element) {
        element.style.display = 'none';
        if (options.addToHiddenList) {
          element.dataset.cyberShieldHidden = 'true';
        }
      }
    });

    return { success: true, hiddenCount: elements.length };
  }

  showElement(selector, options = {}) {
    const elements = typeof selector === 'string' ? 
      document.querySelectorAll(selector) : [selector];
    
    elements.forEach(element => {
      if (element) {
        element.style.display = '';
        delete element.dataset.cyberShieldHidden;
      }
    });

    return { success: true, shownCount: elements.length };
  }

  modifyText(selector, newText) {
    const elements = typeof selector === 'string' ? 
      document.querySelectorAll(selector) : [selector];
    
    elements.forEach(element => {
      if (element) {
        element.textContent = newText;
      }
    });

    return { success: true, modifiedCount: elements.length };
  }

  injectCSS(css) {
    const style = document.createElement('style');
    style.textContent = css;
    style.dataset.cyberShieldInjected = 'true';
    document.head.appendChild(style);

    return { success: true };
  }

  removeElement(selector) {
    const elements = typeof selector === 'string' ? 
      document.querySelectorAll(selector) : [selector];
    
    elements.forEach(element => {
      if (element && element.parentNode) {
        element.parentNode.removeChild(element);
      }
    });

    return { success: true, removedCount: elements.length };
  }

  async checkPolicy(action, context) {
    return new Promise((resolve) => {
      chrome.runtime.sendMessage({
        type: 'POLICY_CHECK',
        action,
        context
      }, (response) => {
        if (response && response.success) {
          resolve({
            allowed: response.allowed,
            reason: response.reason
          });
        } else {
          resolve({ allowed: false, reason: 'Policy check failed' });
        }
      });
    });
  }

  getPageInfo() {
    return {
      url: window.location.href,
      title: document.title,
      domain: window.location.hostname,
      protocol: window.location.protocol,
      hasPasswordFields: document.querySelectorAll('input[type="password"]').length > 0,
      hasFormsWithAction: document.querySelectorAll('form[action]').length > 0,
      hasExternalScripts: document.querySelectorAll('script[src]:not([src^="/"])').length > 0,
      hasIframes: document.querySelectorAll('iframe').length > 0,
      hasMetaRefresh: document.querySelector('meta[http-equiv="refresh"]') !== null,
      contentSecurityPolicy: this.getContentSecurityPolicy()
    };
  }

  hasContentSecurityPolicy() {
    return !!this.getContentSecurityPolicy();
  }

  getContentSecurityPolicy() {
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    return cspMeta ? cspMeta.getAttribute('content') : null;
  }

  analyzeIframe(iframe) {
    this.logSecurityEvent({
      type: 'iframe_detected',
      src: iframe.src,
      sandbox: iframe.getAttribute('sandbox'),
      url: window.location.href,
      timestamp: new Date().toISOString()
    });
  }

  analyzeForm(form) {
    const hasPasswordField = form.querySelector('input[type="password"]');
    const hasFileField = form.querySelector('input[type="file"]');
    
    this.logSecurityEvent({
      type: 'form_detected',
      action: form.action,
      method: form.method,
      hasPassword: !!hasPasswordField,
      hasFileUpload: !!hasFileField,
      url: window.location.href,
      timestamp: new Date().toISOString()
    });
  }

  handleThreatsDetected(threats) {
    threats.forEach(threat => {
      if (threat.severity === 'high') {
        this.uiManager.showCriticalAlert(threat);
      } else if (threat.severity === 'medium') {
        this.uiManager.showWarning(threat);
      } else {
        this.uiManager.showInfo(threat);
      }
    });
  }

  blockPage(reason) {
    // Create overlay to block page content
    const overlay = document.createElement('div');
    overlay.id = 'cybershield-block-overlay';
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
      type: 'LOG_EVENT',
      event
    });
  }

  destroy() {
    // Clean up observers
    this.observers.forEach(observer => observer.disconnect());
    this.observers = [];
    
    // Remove injected styles
    document.querySelectorAll('style[data-cyber-shield-injected]').forEach(style => {
      style.remove();
    });
    
    console.log('CyberShield Drain: Content script destroyed');
  }
}

// Helper classes
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
      timestamp: new Date().toISOString()
    };

    // Detect potential threats
    if (analysis.hasSuspiciousScripts) {
      analysis.threats.push({
        type: 'suspicious_scripts',
        severity: 'medium',
        description: 'Potentially malicious JavaScript detected'
      });
    }

    if (analysis.hasFormsWithExternalAction) {
      analysis.threats.push({
        type: 'external_form_action',
        severity: 'medium',
        description: 'Form submitting to external domain detected'
      });
    }

    return analysis;
  }

  checkExternalResources() {
    const currentDomain = window.location.hostname;
    const externalResources = document.querySelectorAll('script[src], link[href], img[src]');
    
    return Array.from(externalResources).some(element => {
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
    const scripts = document.querySelectorAll('script');
    const suspiciousPatterns = [
      /eval\s*\(/,
      /document\.write\s*\(/,
      /location\.replace\s*\(/,
      /window\.open\s*\(/
    ];

    return Array.from(scripts).some(script => {
      return suspiciousPatterns.some(pattern => 
        pattern.test(script.innerHTML)
      );
    });
  }

  checkExternalFormActions() {
    const currentDomain = window.location.hostname;
    const forms = document.querySelectorAll('form[action]');
    
    return Array.from(forms).some(form => {
      try {
        const actionUrl = new URL(form.action, window.location.href);
        return actionUrl.hostname !== currentDomain;
      } catch {
        return false;
      }
    });
  }

  getCSP() {
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    return cspMeta ? cspMeta.getAttribute('content') : null;
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

    // Auto-remove after duration
    setTimeout(() => {
      notificationElement.remove();
    }, notification.duration || this.config.notificationDuration || 5000);
  }

  showWarning(message) {
    this.showNotification({
      type: 'warning',
      message: typeof message === 'string' ? message : message.description,
      duration: 8000
    });
  }

  showCriticalAlert(threat) {
    this.showNotification({
      type: 'error',
      message: `Critical threat detected: ${threat.description}`,
      duration: 10000
    });
  }

  showInfo(message) {
    this.showNotification({
      type: 'info',
      message: typeof message === 'string' ? message : message.description,
      duration: 5000
    });
  }

  showBlockedLinkWarning(url, reason) {
    this.showNotification({
      type: 'error',
      message: `Link blocked: ${reason}`,
      duration: 8000
    });
  }

  showSuspiciousLinkWarning(url, reason) {
    this.showNotification({
      type: 'warning',
      message: `Suspicious link detected: ${reason}`,
      duration: 6000
    });
  }

  createNotificationElement(notification) {
    const element = document.createElement('div');
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
      case 'error': return '#dc2626';
      case 'warning': return '#d97706';
      case 'info': return '#2563eb';
      case 'success': return '#059669';
      default: return '#6b7280';
    }
  }
}

// Initialize content script
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => {
    const cyberShield = new CyberShieldContent();
    cyberShield.initialize();
  });
} else {
  const cyberShield = new CyberShieldContent();
  cyberShield.initialize();
}
