/**
 * Reliable Detection Engine
 * Simplified, stability-focused detection for Microsoft 365 phishing protection
 * 
 * Design Principles:
 * - Fail-safe defaults
 * - Minimal dependencies
 * - Predictable behavior
 * - Comprehensive error handling
 * - Resource efficiency
 */

import logger from "../utils/logger.js";

export class ReliableDetectionEngine {
  constructor() {
    this.state = 'uninitialized';
    this.trustedOrigins = new Set();
    this.detectionRules = null;
    this.initializationError = null;
    this.lastUpdate = null;
    
    // Performance tracking
    this.detectionCount = 0;
    this.errorCount = 0;
    this.averageDetectionTime = 0;
  }

  /**
   * Initialize with robust error handling
   */
  async initialize() {
    if (this.state === 'initialized') {
      return true;
    }

    if (this.state === 'initializing') {
      // Wait for existing initialization
      return this.waitForInitialization();
    }

    this.state = 'initializing';
    
    try {
      logger.log("ReliableDetectionEngine: Starting initialization");
      
      // Load trusted origins first (most critical)
      await this.loadTrustedOrigins();
      
      // Load detection rules with fallback
      await this.loadDetectionRules();
      
      // Validate configuration
      this.validateConfiguration();
      
      this.state = 'initialized';
      this.lastUpdate = Date.now();
      logger.log("ReliableDetectionEngine: Initialization complete");
      
      return true;
      
    } catch (error) {
      this.state = 'error';
      this.initializationError = error;
      logger.error("ReliableDetectionEngine: Initialization failed:", error.message);
      
      // Use minimal fallback configuration
      this.setupFallbackConfiguration();
      return false;
    }
  }

  /**
   * Wait for existing initialization to complete
   */
  async waitForInitialization(timeout = 5000) {
    const startTime = Date.now();
    
    while (this.state === 'initializing' && (Date.now() - startTime) < timeout) {
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    return this.state === 'initialized';
  }

  /**
   * Load trusted origins with fallback
   */
  async loadTrustedOrigins() {
    try {
      // Default trusted origins (always available)
      const defaultOrigins = [
        "https://login.microsoftonline.com",
        "https://login.microsoft.com",
        "https://login.windows.net",
        "https://login.microsoftonline.us",
        "https://login.partner.microsoftonline.cn",
        "https://login.live.com"
      ];

      this.trustedOrigins = new Set(defaultOrigins);
      
      // Try to load additional origins from storage
      try {
        const stored = await chrome.storage.local.get(['trustedOrigins']);
        if (stored.trustedOrigins && Array.isArray(stored.trustedOrigins)) {
          stored.trustedOrigins.forEach(origin => {
            this.trustedOrigins.add(origin);
          });
        }
      } catch (storageError) {
        logger.warn("Failed to load stored trusted origins:", storageError.message);
      }
      
      logger.log(`Loaded ${this.trustedOrigins.size} trusted origins`);
      
    } catch (error) {
      logger.error("Failed to load trusted origins:", error.message);
      throw new Error("Critical: Cannot load trusted origins");
    }
  }

  /**
   * Load detection rules with comprehensive fallback
   */
  async loadDetectionRules() {
    try {
      // Try to load from cache first
      const cached = await this.loadCachedRules();
      if (cached) {
        this.detectionRules = cached;
        logger.log("Loaded detection rules from cache");
        return;
      }

      // Load from bundled file
      const response = await this.fetchWithTimeout(
        chrome.runtime.getURL("rules/detection-rules.json"),
        3000
      );
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      this.detectionRules = await response.json();
      
      // Cache the rules
      await this.cacheRules(this.detectionRules);
      
      logger.log("Loaded detection rules from bundle");
      
    } catch (error) {
      logger.warn("Failed to load detection rules, using minimal set:", error.message);
      this.detectionRules = this.getMinimalRules();
    }
  }

  /**
   * Load cached rules with validation
   */
  async loadCachedRules() {
    try {
      const result = await chrome.storage.local.get(['cachedRules', 'rulesTimestamp']);
      
      if (!result.cachedRules || !result.rulesTimestamp) {
        return null;
      }
      
      // Check if cache is still valid (24 hours)
      const cacheAge = Date.now() - result.rulesTimestamp;
      const maxCacheAge = 24 * 60 * 60 * 1000; // 24 hours
      
      if (cacheAge > maxCacheAge) {
        logger.log("Cached rules expired");
        return null;
      }
      
      // Validate cached rules structure
      if (this.validateRulesStructure(result.cachedRules)) {
        return result.cachedRules;
      }
      
      logger.warn("Cached rules failed validation");
      return null;
      
    } catch (error) {
      logger.warn("Failed to load cached rules:", error.message);
      return null;
    }
  }

  /**
   * Cache rules for faster loading
   */
  async cacheRules(rules) {
    try {
      await chrome.storage.local.set({
        cachedRules: rules,
        rulesTimestamp: Date.now()
      });
      logger.debug("Detection rules cached successfully");
    } catch (error) {
      logger.warn("Failed to cache rules:", error.message);
    }
  }

  /**
   * Fetch with timeout for reliability
   */
  async fetchWithTimeout(url, timeout = 5000) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
      const response = await fetch(url, {
        signal: controller.signal,
        cache: 'no-cache'
      });
      return response;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Validate rules structure
   */
  validateRulesStructure(rules) {
    try {
      return rules &&
             typeof rules === 'object' &&
             Array.isArray(rules.trusted_origins) &&
             rules.trusted_origins.length > 0 &&
             typeof rules.thresholds === 'object';
    } catch {
      return false;
    }
  }

  /**
   * Get minimal rules for fallback
   */
  getMinimalRules() {
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
      },
      minimal: true
    };
  }

  /**
   * Setup fallback configuration when initialization fails
   */
  setupFallbackConfiguration() {
    this.detectionRules = this.getMinimalRules();
    this.trustedOrigins = new Set(this.detectionRules.trusted_origins);
    this.state = 'fallback';
    logger.log("ReliableDetectionEngine: Using fallback configuration");
  }

  /**
   * Validate current configuration
   */
  validateConfiguration() {
    const issues = [];
    
    if (this.trustedOrigins.size === 0) {
      issues.push("No trusted origins loaded");
    }
    
    if (!this.detectionRules) {
      issues.push("No detection rules loaded");
    }
    
    if (issues.length > 0) {
      throw new Error(`Configuration validation failed: ${issues.join(', ')}`);
    }
    
    logger.log("Configuration validation passed");
  }

  /**
   * Analyze URL with reliability focus
   */
  async analyzeUrl(url) {
    const startTime = Date.now();
    this.detectionCount++;
    
    const analysis = {
      url: url,
      timestamp: new Date().toISOString(),
      isLegitimate: false,
      isSuspicious: false,
      isBlocked: false,
      threatLevel: 'none',
      reason: '',
      confidence: 0,
      detectionTime: 0,
      engineState: this.state
    };

    try {
      // Ensure engine is ready
      if (this.state !== 'initialized' && this.state !== 'fallback') {
        const initialized = await this.initialize();
        if (!initialized) {
          analysis.reason = 'Detection engine not available';
          analysis.confidence = 0;
          return analysis;
        }
      }

      const urlObj = new URL(url);
      const origin = urlObj.origin.toLowerCase();

      // Check trusted origins first
      if (this.isTrustedOrigin(origin)) {
        analysis.isLegitimate = true;
        analysis.reason = 'Trusted Microsoft domain';
        analysis.confidence = 1.0;
        analysis.threatLevel = 'none';
        return analysis;
      }

      // Check for Microsoft-related content in URL
      const microsoftKeywords = ['microsoft', 'office', '365', 'outlook', 'azure', 'msauth'];
      const hasMicrosoftKeywords = microsoftKeywords.some(keyword => 
        url.toLowerCase().includes(keyword)
      );

      if (hasMicrosoftKeywords) {
        analysis.isSuspicious = true;
        analysis.threatLevel = 'medium';
        analysis.reason = 'Microsoft-related keywords in non-Microsoft domain';
        analysis.confidence = 0.7;

        // Check for high-risk patterns
        const highRiskPatterns = [
          /secure-?microsoft/i,
          /microsoft-?login/i,
          /office-?365/i,
          /microsoft-?auth/i
        ];

        if (highRiskPatterns.some(pattern => pattern.test(url))) {
          analysis.isBlocked = true;
          analysis.threatLevel = 'high';
          analysis.reason = 'High-risk Microsoft impersonation pattern';
          analysis.confidence = 0.9;
        }
      }

    } catch (error) {
      this.errorCount++;
      logger.error("URL analysis failed:", error.message);
      
      // Fail-safe: treat unknown URLs as suspicious
      analysis.isSuspicious = true;
      analysis.threatLevel = 'medium';
      analysis.reason = 'Analysis failed - treating as suspicious';
      analysis.confidence = 0.5;
    } finally {
      analysis.detectionTime = Date.now() - startTime;
      this.updatePerformanceMetrics(analysis.detectionTime);
    }

    return analysis;
  }

  /**
   * Analyze page content with reliability focus
   */
  async analyzeContent(content, context = {}) {
    const startTime = Date.now();
    
    const analysis = {
      timestamp: new Date().toISOString(),
      contentLength: content.length,
      context: context,
      aadLike: false,
      hasLoginElements: false,
      hasMicrosoftBranding: false,
      legitimacyScore: 0,
      threatLevel: 'none',
      confidence: 0,
      detectionTime: 0,
      engineState: this.state
    };

    try {
      // Ensure engine is ready
      if (this.state !== 'initialized' && this.state !== 'fallback') {
        await this.initialize();
      }

      // Check for Microsoft login elements
      analysis.hasLoginElements = this.detectLoginElements(content);
      
      // Check for Microsoft branding
      analysis.hasMicrosoftBranding = this.detectMicrosoftBranding(content);
      
      // Calculate AAD-like score
      analysis.aadLike = this.calculateAADLikeness(content);
      
      // Calculate legitimacy score
      analysis.legitimacyScore = this.calculateLegitimacyScore(content);
      
      // Determine threat level
      analysis.threatLevel = this.determineThreatLevel(analysis);
      
      // Calculate confidence
      analysis.confidence = this.calculateConfidence(analysis);

    } catch (error) {
      this.errorCount++;
      logger.error("Content analysis failed:", error.message);
      
      // Fail-safe analysis
      analysis.threatLevel = 'medium';
      analysis.confidence = 0.3;
    } finally {
      analysis.detectionTime = Date.now() - startTime;
      this.updatePerformanceMetrics(analysis.detectionTime);
    }

    return analysis;
  }

  /**
   * Check if origin is trusted
   */
  isTrustedOrigin(origin) {
    try {
      return this.trustedOrigins.has(origin.toLowerCase());
    } catch {
      return false;
    }
  }

  /**
   * Detect login elements in content
   */
  detectLoginElements(content) {
    try {
      const loginPatterns = [
        /input\[name=['"]loginfmt['"]/i,
        /id=['"]i0116['"]/i,
        /input\[type=['"]password['"]/i,
        /#idSIButton9/i,
        /name=['"]passwd['"]/i
      ];

      return loginPatterns.some(pattern => pattern.test(content));
    } catch {
      return false;
    }
  }

  /**
   * Detect Microsoft branding in content
   */
  detectMicrosoftBranding(content) {
    try {
      const brandingPatterns = [
        /Microsoft\s*365/i,
        /Office\s*365/i,
        /Entra\s*ID/i,
        /Azure\s*AD/i,
        /Microsoft/i
      ];

      return brandingPatterns.some(pattern => pattern.test(content));
    } catch {
      return false;
    }
  }

  /**
   * Calculate AAD-like score
   */
  calculateAADLikeness(content) {
    try {
      const aadIndicators = [
        /input\[name=['"]loginfmt['"]/i,
        /#idSIButton9/i,
        /input\[name=['"]idPartnerPL['"]/i,
        /flowToken/i,
        /urlMsaSignUp/i,
        /aadcdn\.msauth\.net/i
      ];

      const matches = aadIndicators.filter(pattern => pattern.test(content)).length;
      return matches >= 2; // At least 2 AAD indicators
    } catch {
      return false;
    }
  }

  /**
   * Calculate legitimacy score
   */
  calculateLegitimacyScore(content) {
    try {
      const legitimateElements = [
        /input\[name=['"]idPartnerPL['"]/i,
        /flowToken/i,
        /urlMsaSignUp/i,
        /aadcdn\.msauth\.net/i,
        /msftauthimages\.net/i
      ];

      const foundElements = legitimateElements.filter(pattern => pattern.test(content)).length;
      return (foundElements / legitimateElements.length) * 100;
    } catch {
      return 0;
    }
  }

  /**
   * Determine threat level based on analysis
   */
  determineThreatLevel(analysis) {
    try {
      // High threat: AAD-like with low legitimacy
      if (analysis.aadLike && analysis.legitimacyScore < 30) {
        return 'high';
      }
      
      // Medium threat: Microsoft branding with login elements but low legitimacy
      if (analysis.hasMicrosoftBranding && analysis.hasLoginElements && analysis.legitimacyScore < 60) {
        return 'medium';
      }
      
      // Low threat: Some indicators but not conclusive
      if (analysis.hasLoginElements && analysis.hasMicrosoftBranding) {
        return 'low';
      }
      
      return 'none';
    } catch {
      return 'medium'; // Fail-safe
    }
  }

  /**
   * Calculate confidence in detection
   */
  calculateConfidence(analysis) {
    try {
      let confidence = 0;
      
      if (analysis.aadLike) confidence += 0.4;
      if (analysis.hasLoginElements) confidence += 0.2;
      if (analysis.hasMicrosoftBranding) confidence += 0.2;
      if (analysis.legitimacyScore > 0) confidence += (analysis.legitimacyScore / 100) * 0.2;
      
      return Math.min(confidence, 1.0);
    } catch {
      return 0.5; // Default confidence
    }
  }

  /**
   * Update performance metrics
   */
  updatePerformanceMetrics(detectionTime) {
    try {
      this.averageDetectionTime = (
        (this.averageDetectionTime * (this.detectionCount - 1)) + detectionTime
      ) / this.detectionCount;
      
      // Log performance issues
      if (detectionTime > 1000) {
        logger.warn(`Slow detection: ${detectionTime}ms`);
      }
      
      if (this.errorCount > 10) {
        logger.warn(`High error rate: ${this.errorCount} errors in ${this.detectionCount} detections`);
      }
    } catch (error) {
      logger.error("Failed to update performance metrics:", error.message);
    }
  }

  /**
   * Get engine status for debugging
   */
  getStatus() {
    return {
      state: this.state,
      trustedOriginsCount: this.trustedOrigins.size,
      hasDetectionRules: !!this.detectionRules,
      detectionCount: this.detectionCount,
      errorCount: this.errorCount,
      averageDetectionTime: this.averageDetectionTime,
      lastUpdate: this.lastUpdate,
      initializationError: this.initializationError?.message || null
    };
  }

  /**
   * Reset engine state for testing
   */
  reset() {
    this.state = 'uninitialized';
    this.trustedOrigins.clear();
    this.detectionRules = null;
    this.initializationError = null;
    this.detectionCount = 0;
    this.errorCount = 0;
    this.averageDetectionTime = 0;
    logger.log("ReliableDetectionEngine: Reset complete");
  }

  /**
   * Validate referrer against trusted list
   */
  validateReferrer(referrer) {
    try {
      if (!referrer) return false;
      
      const referrerOrigin = new URL(referrer).origin.toLowerCase();
      return this.isTrustedOrigin(referrerOrigin);
    } catch {
      return false;
    }
  }

  /**
   * Analyze form for suspicious behavior
   */
  analyzeForm(formElement) {
    const analysis = {
      action: '',
      method: 'GET',
      hasPasswordField: false,
      hasEmailField: false,
      actionOrigin: '',
      isSuspicious: false,
      reason: ''
    };

    try {
      if (!formElement) return analysis;
      
      analysis.action = formElement.getAttribute('action') || location.href;
      analysis.method = formElement.getAttribute('method') || 'GET';
      analysis.hasPasswordField = !!formElement.querySelector('input[type="password"]');
      analysis.hasEmailField = !!formElement.querySelector('input[type="email"]');
      
      // Resolve action URL
      const actionUrl = new URL(analysis.action, location.href);
      analysis.actionOrigin = actionUrl.origin.toLowerCase();
      
      // Check if form action is suspicious
      if (analysis.hasPasswordField && !this.isTrustedOrigin(analysis.actionOrigin)) {
        analysis.isSuspicious = true;
        analysis.reason = 'Password form submits to non-Microsoft domain';
      }
      
    } catch (error) {
      logger.error("Form analysis failed:", error.message);
      analysis.isSuspicious = true;
      analysis.reason = 'Form analysis failed';
    }

    return analysis;
  }
}

export default ReliableDetectionEngine;