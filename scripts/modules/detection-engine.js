/**
 * Detection Engine for Check
 * Handles threat detection, URL analysis, and content scanning
 * Enhanced with CyberDrain Microsoft 365 phishing detection logic
 */

import logger from "../utils/logger.js";

export class DetectionEngine {
  constructor() {
    this.detectionRules = null;
    this.maliciousPatterns = [];
    this.phishingPatterns = [];
    this.suspiciousPatterns = [];
    this.whitelistedDomains = new Set();
    this.blacklistedDomains = new Set();
    this.isInitialized = false;
    
    // CyberDrain integration - Will be loaded from rules
    this.TRUSTED_ORIGINS = new Set();
    this.aadDetectionElements = [];
    this.requiredElements = [];
    this.detectionLogic = null;
    
    // Policy and configuration
    this.policy = null;
    this.extraWhitelist = new Set();
  }

  async initialize() {
    try {
      await this.loadDetectionRules();
      await this.loadDomainLists();
      await this.loadPolicy();
      this.isInitialized = true;
      logger.log("Check: Detection engine initialized successfully");
    } catch (error) {
      logger.error("Check: Failed to initialize detection engine:", error);
      throw error;
    }
  }

  // CyberDrain integration - Policy management
  async loadPolicy() {
    try {
      const managed = await chrome.storage.managed.get(null).catch(() => ({}));
      const local = await chrome.storage.sync.get(null).catch(() => ({}));
      
      this.policy = Object.assign({}, this.getDefaultPolicy(), managed, local);
      this.extraWhitelist = new Set((this.policy.ExtraWhitelist || []).map(s => this.urlOrigin(s)).filter(Boolean));
      
      logger.log("Check: Policy loaded successfully");
    } catch (error) {
      logger.error("Check: Failed to load policy:", error);
      this.policy = this.getDefaultPolicy();
    }
  }

  getDefaultPolicy() {
    return {
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

  // CyberDrain integration - URL origin helper
  urlOrigin(url) {
    try {
      return new URL(url).origin.toLowerCase();
    } catch {
      return "";
    }
  }

  // CyberDrain integration - Check if origin is trusted
  isTrustedOrigin(url) {
    const origin = this.urlOrigin(url);
    return this.TRUSTED_ORIGINS.has(origin);
  }

  // CyberDrain integration - Check if referrer is trusted
  isTrustedReferrer(referrer) {
    if (!referrer) return false;
    const origin = this.urlOrigin(referrer);
    return this.TRUSTED_ORIGINS.has(origin);
  }

  // CyberDrain integration - Verdict determination for URL
  verdictForUrl(url) {
    const origin = this.urlOrigin(url);
    if (this.TRUSTED_ORIGINS.has(origin)) return "trusted";
    if (this.extraWhitelist.has(origin)) return "trusted-extra";
    return "unknown";
  }

  async loadDetectionRules() {
    try {
      // Load built-in detection rules
      const response = await fetch(
        chrome.runtime.getURL("rules/detection-rules.json")
      );
      this.detectionRules = await response.json();

      // CyberDrain integration - Load trusted origins from rules
      if (this.detectionRules.trusted_origins) {
        this.TRUSTED_ORIGINS = new Set(this.detectionRules.trusted_origins);
      }

      // Load AAD detection elements from rules
      this.aadDetectionElements = this.detectionRules.aad_detection_elements || [];
      this.requiredElements = this.detectionRules.required_elements || [];
      this.detectionLogic = this.detectionRules.detection_logic || {};

      // Parse patterns for faster matching
      this.maliciousPatterns = this.compilePatterns(
        this.detectionRules.malicious || []
      );
      this.phishingPatterns = this.compilePatterns(
        this.detectionRules.phishing || []
      );
      this.suspiciousPatterns = this.compilePatterns(
        this.detectionRules.suspicious || []
      );

      logger.log("Check: Detection rules loaded with CyberDrain integration");
    } catch (error) {
      logger.warn("Check: Failed to load detection rules, using defaults");
      this.loadDefaultRules();
    }
  }

  async loadDomainLists() {
    try {
      // Get configuration to load domain lists
      const config = await chrome.storage.local.get(["config"]);

      if (config.config) {
        this.whitelistedDomains = new Set(
          config.config.whitelistedDomains || []
        );
        this.blacklistedDomains = new Set(
          config.config.blacklistedDomains || []
        );
      }
    } catch (error) {
      logger.error("Check: Failed to load domain lists:", error);
    }
  }

  compilePatterns(patterns) {
    return patterns
      .map((pattern) => {
        try {
          return {
            regex: new RegExp(pattern.pattern, pattern.flags || "i"),
            severity: pattern.severity || "medium",
            description: pattern.description || "",
            action: pattern.action || "block",
          };
        } catch (error) {
          logger.warn("Check: Invalid pattern:", pattern.pattern);
          return null;
        }
      })
      .filter(Boolean);
  }

  loadDefaultRules() {
    this.detectionRules = {
      malicious: [
        {
          pattern: "(?:javascript:|data:|vbscript:)",
          flags: "i",
          severity: "high",
          description: "Malicious protocol scheme",
          action: "block",
        },
        {
          pattern:
            "(?:eval\\s*\\(|setTimeout\\s*\\(|setInterval\\s*\\().*(?:location|document\\.cookie)",
          flags: "i",
          severity: "medium",
          description: "Suspicious JavaScript execution",
          action: "warn",
        },
      ],
      phishing: [
        {
          pattern: "(?:secure-?(?:bank|pay|login|account))",
          flags: "i",
          severity: "high",
          description: "Potential phishing domain",
          action: "warn",
        },
        {
          pattern: "(?:verify-?account|suspended-?account|update-?payment)",
          flags: "i",
          severity: "medium",
          description: "Phishing keyword detected",
          action: "warn",
        },
      ],
      suspicious: [
        {
          pattern: "(?:[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})",
          flags: "i",
          severity: "low",
          description: "Direct IP address access",
          action: "monitor",
        },
      ],
    };

    this.maliciousPatterns = this.compilePatterns(
      this.detectionRules.malicious
    );
    this.phishingPatterns = this.compilePatterns(this.detectionRules.phishing);
    this.suspiciousPatterns = this.compilePatterns(
      this.detectionRules.suspicious
    );
  }

  async analyzeUrl(url) {
    if (!this.isInitialized) {
      await this.initialize();
    }

    const analysis = {
      url,
      isBlocked: false,
      isSuspicious: false,
      requiresContentScript: false,
      threats: [],
      reason: "",
      severity: "none",
      timestamp: new Date().toISOString(),
      verdict: "unknown",
      isLegitimate: false,
      threat_level: "none"
    };

    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();

      // CyberDrain integration - Check verdict first
      analysis.verdict = this.verdictForUrl(url);
      
      if (analysis.verdict === "trusted") {
        analysis.isLegitimate = true;
        analysis.reason = "Trusted Microsoft domain";
        analysis.requiresContentScript = true; // Still inject for badge display
        return analysis;
      }
      
      if (analysis.verdict === "trusted-extra") {
        analysis.isLegitimate = true;
        analysis.reason = "Extra whitelisted domain";
        return analysis;
      }

      // Check whitelist first
      if (this.isWhitelisted(domain)) {
        analysis.reason = "Whitelisted domain";
        return analysis;
      }

      // Check blacklist
      if (this.isBlacklisted(domain)) {
        analysis.isBlocked = true;
        analysis.severity = "high";
        analysis.threat_level = "high";
        analysis.reason = "Blacklisted domain";
        analysis.threats.push({
          type: "blacklisted_domain",
          severity: "high",
          description: "Domain is in blacklist",
        });
        return analysis;
      }

      // CyberDrain integration - Enhanced Microsoft phishing detection
      const microsoftThreats = this.detectMicrosoftPhishing(url);
      analysis.threats.push(...microsoftThreats);

      // Run original pattern matching
      const threats = this.detectThreats(url);
      analysis.threats.push(...threats);

      if (analysis.threats.length > 0) {
        const highSeverityThreats = analysis.threats.filter(
          (t) => t.severity === "high" || t.severity === "critical"
        );
        const mediumSeverityThreats = analysis.threats.filter(
          (t) => t.severity === "medium"
        );

        if (highSeverityThreats.length > 0) {
          analysis.isBlocked = true;
          analysis.severity = "high";
          analysis.threat_level = "high";
          analysis.reason = highSeverityThreats[0].description;
        } else if (mediumSeverityThreats.length > 0) {
          analysis.isSuspicious = true;
          analysis.severity = "medium";
          analysis.threat_level = "medium";
          analysis.reason = mediumSeverityThreats[0].description;
        } else {
          analysis.isSuspicious = true;
          analysis.severity = "low";
          analysis.threat_level = "low";
          analysis.reason = analysis.threats[0].description;
        }
      }

      // Determine if content script injection is needed
      analysis.requiresContentScript = this.requiresContentScript(
        url,
        analysis
      );
    } catch (error) {
      logger.error("Check: URL analysis failed:", error);
      analysis.reason = "Analysis failed";
    }

    return analysis;
  }

  // CyberDrain integration - Microsoft-specific phishing detection
  detectMicrosoftPhishing(url) {
    const threats = [];
    
    if (!this.detectionRules?.phishing_indicators) {
      return threats;
    }

    // Check against CyberDrain phishing indicators
    for (const indicator of this.detectionRules.phishing_indicators) {
      try {
        const regex = new RegExp(indicator.pattern, indicator.flags || "i");
        if (regex.test(url)) {
          threats.push({
            type: "microsoft_phishing",
            severity: indicator.severity,
            description: indicator.description,
            action: indicator.action,
            category: indicator.category,
            confidence: indicator.confidence,
            indicator_id: indicator.id
          });
        }
      } catch (error) {
        logger.warn("Check: Invalid phishing indicator pattern:", indicator.id);
      }
    }

    return threats;
  }

  detectThreats(url) {
    const threats = [];
    const allPatterns = [
      ...this.maliciousPatterns.map((p) => ({ ...p, type: "malicious" })),
      ...this.phishingPatterns.map((p) => ({ ...p, type: "phishing" })),
      ...this.suspiciousPatterns.map((p) => ({ ...p, type: "suspicious" })),
    ];

    for (const pattern of allPatterns) {
      if (pattern.regex.test(url)) {
        threats.push({
          type: pattern.type,
          severity: pattern.severity,
          description: pattern.description,
          action: pattern.action,
          pattern: pattern.regex.source,
        });
      }
    }

    return threats;
  }

  isWhitelisted(domain) {
    // Check exact match
    if (this.whitelistedDomains.has(domain)) {
      return true;
    }

    // Check subdomain matches
    for (const whitelistedDomain of this.whitelistedDomains) {
      if (
        whitelistedDomain.startsWith("*.") &&
        domain.endsWith(whitelistedDomain.substring(2))
      ) {
        return true;
      }
    }

    return false;
  }

  isBlacklisted(domain) {
    // Check exact match
    if (this.blacklistedDomains.has(domain)) {
      return true;
    }

    // Check subdomain matches
    for (const blacklistedDomain of this.blacklistedDomains) {
      if (
        blacklistedDomain.startsWith("*.") &&
        domain.endsWith(blacklistedDomain.substring(2))
      ) {
        return true;
      }
    }

    return false;
  }

  requiresContentScript(url, analysis) {
    // Always inject content script for monitoring unless explicitly blocked
    if (analysis.isBlocked) {
      return false;
    }

    // Skip for extension pages and chrome:// URLs
    if (url.startsWith("chrome://") || url.startsWith("chrome-extension://")) {
      return false;
    }

    return true;
  }

  async analyzePageContent(tabId, url) {
    try {
      // Execute content analysis script
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        function: this.contentAnalysisFunction,
      });

      if (results && results[0] && results[0].result) {
        const contentAnalysis = results[0].result;

        // Process content analysis results
        await this.processContentAnalysis(tabId, url, contentAnalysis);
      }
    } catch (error) {
      logger.error("Check: Content analysis failed:", error);
    }
  }

  // Function to be executed in the content context
  contentAnalysisFunction() {
    const inputs = document.querySelectorAll("input");
    const forms = document.querySelectorAll("form");
    const scripts = document.querySelectorAll("script");
    const metas = document.querySelectorAll("meta");

    const analysis = {
      hasPasswordFields: Array.from(inputs).some(
        (el) => el.type === "password"
      ),
      hasLoginFields: Array.from(inputs).some(
        (el) =>
          el.type === "password" ||
          /user|login/i.test(el.name || "") ||
          el.type === "email"
      ),
      hasFormSubmissions: forms.length > 0,
      hasSuspiciousScripts: false,
      hasExternalResources: false,
      documentTitle: document.title,
      metaTags: [],
      suspiciousElements: [],
    };

    // Check for suspicious scripts
    for (const script of scripts) {
      if (script.src && !script.src.startsWith(window.location.origin)) {
        analysis.hasExternalResources = true;
      }

      let code = script.innerHTML || "";
      if (
        !code &&
        script.src &&
        script.src.startsWith("data:text/javascript;base64,")
      ) {
        try {
          code = window.atob(script.src.split(",")[1]);
        } catch {}
      }

      let decoded = "";
      const b64 = code.replace(/\s+/g, "");
      if (/^[A-Za-z0-9+/=]+$/.test(b64) && b64.length % 4 === 0) {
        try {
          decoded = window.atob(b64);
        } catch {}
      }
      const combined = code + decoded;
      const dynamicPattern =
        /eval\s*\(|document\.write\s*\(|setTimeout\s*\(|setInterval\s*\(/i;
      const usesDynamicExecution = dynamicPattern.test(combined);
      const referencesLocation = /location/i.test(combined);
      const referencesCookie = /document\.cookie/i.test(combined);

      if (
        usesDynamicExecution &&
        (referencesCookie || (analysis.hasLoginFields && referencesLocation))
      ) {
        analysis.hasSuspiciousScripts = true;
      }
    }

    // Collect meta tags
    for (const meta of metas) {
      analysis.metaTags.push({
        name: meta.getAttribute("name"),
        content: meta.getAttribute("content"),
        property: meta.getAttribute("property"),
      });
    }

    return analysis;
  }

  async processContentAnalysis(tabId, url, contentAnalysis) {
    const threats = [];

    // Check for login page impersonation
    if (contentAnalysis.hasPasswordFields) {
      const urlAnalysis = await this.analyzeUrl(url);
      if (
        urlAnalysis.isSuspicious ||
        urlAnalysis.threats.some((t) => t.type === "phishing")
      ) {
        threats.push({
          type: "phishing_login",
          severity: "high",
          description: "Suspicious login page detected",
        });
      }
    }

    // Check for suspicious scripts
    if (contentAnalysis.hasSuspiciousScripts) {
      threats.push({
        type: "malicious_script",
        severity: "low",
        description: "Potentially malicious JavaScript detected",
      });
    }

    // Log content analysis results
    if (threats.length > 0) {
      chrome.runtime.sendMessage({
        type: "LOG_EVENT",
        event: {
          type: "content_threat_detected",
          url,
          threats,
          analysis: contentAnalysis,
        },
      });
    }

    return threats;
  }

  async updateDetectionRules(newRules) {
    try {
      this.detectionRules = newRules;
      this.maliciousPatterns = this.compilePatterns(newRules.malicious || []);
      this.phishingPatterns = this.compilePatterns(newRules.phishing || []);
      this.suspiciousPatterns = this.compilePatterns(newRules.suspicious || []);

      // Save to storage
      await chrome.storage.local.set({ detectionRules: newRules });

      logger.log("Check: Detection rules updated");
    } catch (error) {
      logger.error("Check: Failed to update detection rules:", error);
      throw error;
    }
  }

  async addCustomRule(rule) {
    try {
      if (!this.detectionRules.custom) {
        this.detectionRules.custom = [];
      }

      this.detectionRules.custom.push(rule);
      await this.updateDetectionRules(this.detectionRules);

      logger.log("Check: Custom rule added");
    } catch (error) {
      logger.error("Check: Failed to add custom rule:", error);
      throw error;
    }
  }

  async removeCustomRule(ruleId) {
    try {
      if (this.detectionRules.custom) {
        this.detectionRules.custom = this.detectionRules.custom.filter(
          (rule) => rule.id !== ruleId
        );
        await this.updateDetectionRules(this.detectionRules);
        logger.log("Check: Custom rule removed");
      }
    } catch (error) {
      logger.error("Check: Failed to remove custom rule:", error);
      throw error;
    }
  }

  // Testing and Validation Methods
  async analyzeContent(content, context = {}) {
    const analysis = {
      timestamp: new Date().toISOString(),
      content_length: content.length,
      context,
      findings: [],
      legitimacyScore: 0,
      threat_level: "none",
      hasRequiredElements: false,
      // CyberDrain integration
      aadLike: false,
      hasLoginFmt: false,
      hasNextBtn: false,
      hasPw: false,
      brandingHit: false
    };

    try {
      // CyberDrain integration - Core AAD fingerprint detection
      analysis.hasLoginFmt = /input\[name=['"]loginfmt['"]|#i0116/.test(content);
      analysis.hasNextBtn = /#idSIButton9/.test(content);
      analysis.hasPw = /input\[type=['"]password['"]/.test(content);
      analysis.brandingHit = /\b(Microsoft\s*365|Office\s*365|Entra\s*ID|Azure\s*AD|Microsoft)\b/i.test(content.slice(0, 25000));
      
      // CyberDrain AAD-like detection logic
      analysis.aadLike = (analysis.hasLoginFmt && analysis.hasNextBtn) ||
                        (analysis.brandingHit && (analysis.hasLoginFmt || analysis.hasPw));

      // Check for required Microsoft authentication elements
      const requiredElements = [
        { name: "loginfmt", pattern: /name=['"]loginfmt['"]|id=['"]i0116['"]/ },
        { name: "idPartnerPL", pattern: /name=['"]idPartnerPL['"]/ },
        { name: "urlMsaSignUp", pattern: /urlMsaSignUp/ },
        { name: "flowToken", pattern: /flowToken/ },
        {
          name: "aadcdn.msauth.net",
          pattern: /https:\/\/aadcdn\.msauth\.net\//,
        },
      ];

      let foundElements = 0;
      for (const element of requiredElements) {
        if (element.pattern.test(content)) {
          foundElements++;
          analysis.findings.push({
            type: "required_element",
            element: element.name,
            found: true,
          });
        } else {
          analysis.findings.push({
            type: "missing_element",
            element: element.name,
            found: false,
          });
        }
      }

      analysis.hasRequiredElements = foundElements >= 3; // At least 3 required elements
      analysis.legitimacyScore =
        (foundElements / requiredElements.length) * 100;

      // Check for phishing indicators
      if (this.detectionRules?.phishing_indicators) {
        for (const indicator of this.detectionRules.phishing_indicators) {
          const regex = new RegExp(indicator.pattern, indicator.flags || "i");
          if (regex.test(content)) {
            analysis.findings.push({
              type: "phishing_indicator",
              indicator: indicator.id,
              description: indicator.description,
              severity: indicator.severity,
            });

            if (
              indicator.severity === "high" ||
              indicator.severity === "critical"
            ) {
              analysis.threat_level = "high";
            } else if (analysis.threat_level === "none") {
              analysis.threat_level = "medium";
            }
          }
        }
      }

      // CyberDrain integration - Enhanced legitimacy scoring
      if (analysis.aadLike && analysis.hasRequiredElements && analysis.threat_level === "none") {
        analysis.legitimacyLevel = "high";
      } else if (analysis.legitimacyScore >= 60) {
        analysis.legitimacyLevel = "medium";
      } else {
        analysis.legitimacyLevel = "low";
      }
    } catch (error) {
      analysis.error = error.message;
    }

    return analysis;
  }

  // CyberDrain integration - Form action validation
  async analyzeFormActions(content, currentOrigin) {
    const analysis = {
      timestamp: new Date().toISOString(),
      forms: [],
      offenders: [],
      fail: false,
      reason: ""
    };

    try {
      // Extract form actions from content
      const formRegex = /<form[^>]*action=['"]([^'"]*)['"]/gi;
      let match;
      
      while ((match = formRegex.exec(content)) !== null) {
        const action = match[1];
        const resolvedAction = this.resolveAction(action, currentOrigin);
        const actionOrigin = this.urlOrigin(resolvedAction);
        
        analysis.forms.push({
          action: resolvedAction,
          actionOrigin: actionOrigin
        });
        
        // Check if form posts to non-Microsoft domain
        if (!this.isTrustedOrigin(actionOrigin)) {
          analysis.offenders.push({
            action: resolvedAction,
            actionOrigin: actionOrigin
          });
        }
      }
      
      if (analysis.offenders.length > 0) {
        analysis.fail = true;
        analysis.reason = "non-microsoft-form-action";
      }
      
    } catch (error) {
      analysis.error = error.message;
    }

    return analysis;
  }

  // CyberDrain integration - Subresource origin audit
  async auditSubresourceOrigins(content, currentOrigin) {
    const analysis = {
      timestamp: new Date().toISOString(),
      origins: [],
      nonMicrosoft: [],
      nonMicrosoftCount: 0
    };

    try {
      const resourceRegex = /(?:src|href)=['"]([^'"]*)['"]/gi;
      const origins = new Set();
      const nonMs = new Set();
      let match;
      
      while ((match = resourceRegex.exec(content)) !== null) {
        const url = match[1];
        if (!url || url.startsWith('#') || url.startsWith('data:')) continue;
        
        try {
          const fullUrl = new URL(url, currentOrigin);
          const origin = fullUrl.origin.toLowerCase();
          
          if (!origin) continue;
          origins.add(origin);
          
          // If all assets are on the same fake origin, this may yield 0 — that's fine.
          if (!this.isTrustedOrigin(origin) && origin !== currentOrigin.toLowerCase()) {
            nonMs.add(origin);
          }
        } catch (e) {
          // Invalid URL, skip
        }
      }
      
      analysis.origins = Array.from(origins);
      analysis.nonMicrosoft = Array.from(nonMs);
      analysis.nonMicrosoftCount = nonMs.size;
      
    } catch (error) {
      analysis.error = error.message;
    }

    return analysis;
  }

  // CyberDrain integration - Action URL resolver
  resolveAction(action, baseUrl) {
    let act = (action || baseUrl).trim();
    try {
      act = new URL(act, baseUrl).href;
    } catch {
      act = baseUrl;
    }
    return act;
  }

  async analyzeForm(formData) {
    const analysis = {
      timestamp: new Date().toISOString(),
      formData,
      isLegitimate: false,
      findings: [],
      action_url: formData.action || "",
      method: formData.method || "GET",
    };

    try {
      // Check form action URL
      if (analysis.action_url) {
        const urlAnalysis = await this.analyzeUrl(analysis.action_url);
        analysis.url_analysis = urlAnalysis;

        // For legitimate Microsoft forms, action should NOT be login.microsoftonline.com
        if (analysis.action_url.includes("login.microsoftonline.com")) {
          analysis.findings.push({
            type: "suspicious_action",
            message:
              "Form action points to login.microsoftonline.com (potential phishing)",
          });
        }
      }

      // Check for required form fields
      const requiredFields = ["loginfmt", "passwd", "idPartnerPL"];
      let foundFields = 0;

      if (formData.fields) {
        for (const field of requiredFields) {
          if (formData.fields.some((f) => f.name === field)) {
            foundFields++;
            analysis.findings.push({
              type: "required_field",
              field,
              found: true,
            });
          }
        }
      }

      analysis.isLegitimate = foundFields >= 2; // At least 2 required fields
    } catch (error) {
      analysis.error = error.message;
    }

    return analysis;
  }

  async analyzeHeaders(headers) {
    const analysis = {
      timestamp: new Date().toISOString(),
      headers,
      isValid: false,
      findings: [],
      csp_valid: false,
      referrer_valid: false,
    };

    try {
      // Check Content Security Policy
      const cspHeader =
        headers["content-security-policy-report-only"] ||
        headers["Content-Security-Policy-Report-Only"];

      if (cspHeader) {
        analysis.csp_valid = await this.validateCSP(cspHeader);
        analysis.findings.push({
          type: "csp_header",
          valid: analysis.csp_valid,
          header: cspHeader,
        });
      } else {
        analysis.findings.push({
          type: "missing_csp",
          message: "Missing content-security-policy-report-only header",
        });
      }

      // Check referrer
      const referrer = headers["referer"] || headers["Referer"];
      if (referrer) {
        analysis.referrer_valid = await this.validateReferrer(referrer);
        analysis.findings.push({
          type: "referrer",
          valid: analysis.referrer_valid,
          referrer,
        });
      }

      analysis.isValid = analysis.csp_valid && analysis.referrer_valid;
    } catch (error) {
      analysis.error = error.message;
    }

    return analysis;
  }

  async validateReferrer(referrer) {
    try {
      if (!this.detectionRules?.valid_referrers?.referrers) {
        return false;
      }

      const validReferrers = this.detectionRules.valid_referrers.referrers;
      return validReferrers.some((validRef) => {
        // Exact match or starts with the valid referrer
        return referrer === validRef || referrer.startsWith(validRef);
      });
    } catch (error) {
      logger.error("Check: Error validating referrer:", error);
      return false;
    }
  }

  async validateCSP(cspHeader) {
    try {
      if (!this.detectionRules?.legitimate_patterns) {
        return false;
      }

      // Find CSP domains pattern in legitimate patterns
      const cspPattern = this.detectionRules.legitimate_patterns.find(
        (pattern) => pattern.csp_domains
      );

      if (!cspPattern) {
        return false;
      }

      const requiredDomains = cspPattern.csp_domains;
      let validDomains = 0;

      for (const domain of requiredDomains) {
        // Convert wildcard pattern to regex-friendly format
        const domainPattern = domain
          .replace(/\*/g, "[^\\s]*")
          .replace(/\./g, "\\.");

        const regex = new RegExp(domainPattern, "i");
        if (regex.test(cspHeader)) {
          validDomains++;
        }
      }

      // Require at least 80% of domains to be present
      return validDomains / requiredDomains.length >= 0.8;
    } catch (error) {
      logger.error("Check: Error validating CSP:", error);
      return false;
    }
  }

  async runRuleValidation() {
    const validation = {
      timestamp: new Date().toISOString(),
      rules_loaded: !!this.detectionRules,
      validation_results: [],
    };

    if (!this.detectionRules) {
      validation.error = "No detection rules loaded";
      return validation;
    }

    // Validate each rule category
    const categories = [
      "rules",
      "phishing_indicators",
      "legitimate_patterns",
      "suspicious_behaviors",
    ];

    for (const category of categories) {
      if (this.detectionRules[category]) {
        const categoryValidation = {
          category,
          count: Array.isArray(this.detectionRules[category])
            ? this.detectionRules[category].length
            : 0,
          valid: true,
          issues: [],
        };

        if (Array.isArray(this.detectionRules[category])) {
          for (const rule of this.detectionRules[category]) {
            if (!rule.id) {
              categoryValidation.issues.push("Rule missing ID");
              categoryValidation.valid = false;
            }
            if (!rule.description) {
              categoryValidation.issues.push(
                `Rule ${rule.id || "unknown"} missing description`
              );
            }
          }
        }

        validation.validation_results.push(categoryValidation);
      }
    }

    return validation;
  }

  async testRuleEngine() {
    const testResults = {
      timestamp: new Date().toISOString(),
      tests: [],
    };

    // Test URL analysis
    const urlTests = [
      { url: "https://login.microsoftonline.com", expected: "legitimate" },
      { url: "https://fake-microsoft-login.com", expected: "suspicious" },
      { url: "https://secure-office365.phishing.com", expected: "blocked" },
    ];

    for (const test of urlTests) {
      try {
        const result = await this.analyzeUrl(test.url);
        testResults.tests.push({
          type: "url_analysis",
          input: test.url,
          expected: test.expected,
          result,
          passed: this.evaluateTestResult(test.expected, result),
        });
      } catch (error) {
        testResults.tests.push({
          type: "url_analysis",
          input: test.url,
          error: error.message,
          passed: false,
        });
      }
    }

    return testResults;
  }

  evaluateTestResult(expected, actual) {
    switch (expected) {
      case "legitimate":
        return !actual.isBlocked && actual.threat_level === "none";
      case "suspicious":
        return (
          actual.threat_level === "medium" || actual.threat_level === "high"
        );
      case "blocked":
        return actual.isBlocked || actual.threat_level === "high";
      default:
        return false;
    }
  }

  // Rule-driven element detection
  detectElementsFromRules(content) {
    const detected = {};
    
    // Check AAD detection elements from rules
    for (const element of this.aadDetectionElements) {
      detected[element.id] = false;
      
      if (element.selectors) {
        // For DOM-based detection (when we have access to DOM)
        if (typeof document !== 'undefined') {
          for (const selector of element.selectors) {
            if (document.querySelector(selector)) {
              detected[element.id] = true;
              break;
            }
          }
        }
      }
      
      if (element.text_patterns) {
        // For content-based detection
        for (const pattern of element.text_patterns) {
          const regex = new RegExp(pattern, 'i');
          if (regex.test(content)) {
            detected[element.id] = true;
            break;
          }
        }
      }
    }
    
    return detected;
  }

  // Rule-driven AAD-like evaluation
  evaluateAADLikeFromRules(detectedElements) {
    if (!this.detectionLogic?.aad_fingerprint_rules) {
      return false;
    }
    
    for (const rule of this.detectionLogic.aad_fingerprint_rules) {
      if (this.evaluateCondition(rule.condition, detectedElements)) {
        return true;
      }
    }
    
    return false;
  }

  // Simple condition evaluator for rules
  evaluateCondition(condition, context) {
    // Simple condition evaluation - can be enhanced with a proper parser
    const conditions = condition.split(' AND ');
    
    for (const cond of conditions) {
      const trimmed = cond.trim();
      
      if (trimmed.startsWith('NOT ')) {
        const element = trimmed.substring(4);
        if (context[element]) return false;
      } else {
        if (!context[trimmed]) return false;
      }
    }
    
    return true;
  }

  // CyberDrain integration - Rule-driven content analysis
  async analyzeContentWithRules(content, context = {}) {
    const analysis = {
      timestamp: new Date().toISOString(),
      content_length: content.length,
      context,
      findings: [],
      legitimacyScore: 0,
      threat_level: "none",
      hasRequiredElements: false,
      // CyberDrain integration
      aadLike: false,
      detectedElements: {},
      ruleBasedAnalysis: true
    };

    try {
      // Use rule-driven element detection
      analysis.detectedElements = this.detectElementsFromRules(content);
      
      // Use rule-driven AAD-like evaluation
      analysis.aadLike = this.evaluateAADLikeFromRules(analysis.detectedElements);
      
      // Check for required elements based on rules
      const requiredCount = Object.values(analysis.detectedElements).filter(Boolean).length;
      analysis.hasRequiredElements = requiredCount >= (this.detectionLogic?.minimum_required_elements || 3);
      
      // Calculate legitimacy score
      const totalElements = Object.keys(analysis.detectedElements).length;
      analysis.legitimacyScore = totalElements > 0 ? (requiredCount / totalElements) * 100 : 0;
      
      // Check for phishing indicators using rules
      if (this.detectionRules?.phishing_indicators) {
        for (const indicator of this.detectionRules.phishing_indicators) {
          const regex = new RegExp(indicator.pattern, indicator.flags || "i");
          if (regex.test(content)) {
            analysis.findings.push({
              type: "phishing_indicator",
              indicator: indicator.id,
              description: indicator.description,
              severity: indicator.severity,
            });

            if (indicator.severity === "high" || indicator.severity === "critical") {
              analysis.threat_level = "high";
            } else if (analysis.threat_level === "none") {
              analysis.threat_level = "medium";
            }
          }
        }
      }
      
      // Enhanced legitimacy scoring
      if (analysis.aadLike && analysis.hasRequiredElements && analysis.threat_level === "none") {
        analysis.legitimacyLevel = "high";
      } else if (analysis.legitimacyScore >= 60) {
        analysis.legitimacyLevel = "medium";
      } else {
        analysis.legitimacyLevel = "low";
      }
      
    } catch (error) {
      analysis.error = error.message;
    }

    return analysis;
  }
}
