/**
 * Detection Engine for CyberShield Drain
 * Handles threat detection, URL analysis, and content scanning
 */

export class DetectionEngine {
  constructor() {
    this.detectionRules = null;
    this.maliciousPatterns = [];
    this.phishingPatterns = [];
    this.suspiciousPatterns = [];
    this.whitelistedDomains = new Set();
    this.blacklistedDomains = new Set();
    this.isInitialized = false;
  }

  async initialize() {
    try {
      await this.loadDetectionRules();
      await this.loadDomainLists();
      this.isInitialized = true;
      console.log('CyberShield Drain: Detection engine initialized successfully');
    } catch (error) {
      console.error('CyberShield Drain: Failed to initialize detection engine:', error);
      throw error;
    }
  }

  async loadDetectionRules() {
    try {
      // Load built-in detection rules
      const response = await fetch(chrome.runtime.getURL('rules/detection-rules.json'));
      this.detectionRules = await response.json();
      
      // Parse patterns for faster matching
      this.maliciousPatterns = this.compilePatterns(this.detectionRules.malicious || []);
      this.phishingPatterns = this.compilePatterns(this.detectionRules.phishing || []);
      this.suspiciousPatterns = this.compilePatterns(this.detectionRules.suspicious || []);
      
      console.log('CyberShield Drain: Detection rules loaded');
    } catch (error) {
      console.warn('CyberShield Drain: Failed to load detection rules, using defaults');
      this.loadDefaultRules();
    }
  }

  async loadDomainLists() {
    try {
      // Get configuration to load domain lists
      const config = await chrome.storage.local.get(['config']);
      
      if (config.config) {
        this.whitelistedDomains = new Set(config.config.whitelistedDomains || []);
        this.blacklistedDomains = new Set(config.config.blacklistedDomains || []);
      }
    } catch (error) {
      console.error('CyberShield Drain: Failed to load domain lists:', error);
    }
  }

  compilePatterns(patterns) {
    return patterns.map(pattern => {
      try {
        return {
          regex: new RegExp(pattern.pattern, pattern.flags || 'i'),
          severity: pattern.severity || 'medium',
          description: pattern.description || '',
          action: pattern.action || 'block'
        };
      } catch (error) {
        console.warn('CyberShield Drain: Invalid pattern:', pattern.pattern);
        return null;
      }
    }).filter(Boolean);
  }

  loadDefaultRules() {
    this.detectionRules = {
      malicious: [
        {
          pattern: '(?:javascript:|data:|vbscript:)',
          flags: 'i',
          severity: 'high',
          description: 'Malicious protocol scheme',
          action: 'block'
        },
        {
          pattern: '(?:eval\\s*\\(|setTimeout\\s*\\(|setInterval\\s*\\().*(?:location|document\\.cookie)',
          flags: 'i',
          severity: 'high',
          description: 'Suspicious JavaScript execution',
          action: 'block'
        }
      ],
      phishing: [
        {
          pattern: '(?:secure-?(?:bank|pay|login|account))',
          flags: 'i',
          severity: 'high',
          description: 'Potential phishing domain',
          action: 'warn'
        },
        {
          pattern: '(?:verify-?account|suspended-?account|update-?payment)',
          flags: 'i',
          severity: 'medium',
          description: 'Phishing keyword detected',
          action: 'warn'
        }
      ],
      suspicious: [
        {
          pattern: '(?:[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})',
          flags: 'i',
          severity: 'low',
          description: 'Direct IP address access',
          action: 'monitor'
        }
      ]
    };

    this.maliciousPatterns = this.compilePatterns(this.detectionRules.malicious);
    this.phishingPatterns = this.compilePatterns(this.detectionRules.phishing);
    this.suspiciousPatterns = this.compilePatterns(this.detectionRules.suspicious);
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
      reason: '',
      severity: 'none',
      timestamp: new Date().toISOString()
    };

    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();
      
      // Check whitelist first
      if (this.isWhitelisted(domain)) {
        analysis.reason = 'Whitelisted domain';
        return analysis;
      }

      // Check blacklist
      if (this.isBlacklisted(domain)) {
        analysis.isBlocked = true;
        analysis.severity = 'high';
        analysis.reason = 'Blacklisted domain';
        analysis.threats.push({
          type: 'blacklisted_domain',
          severity: 'high',
          description: 'Domain is in blacklist'
        });
        return analysis;
      }

      // Run pattern matching
      const threats = this.detectThreats(url);
      analysis.threats = threats;

      if (threats.length > 0) {
        const highSeverityThreats = threats.filter(t => t.severity === 'high');
        const mediumSeverityThreats = threats.filter(t => t.severity === 'medium');

        if (highSeverityThreats.length > 0) {
          analysis.isBlocked = true;
          analysis.severity = 'high';
          analysis.reason = highSeverityThreats[0].description;
        } else if (mediumSeverityThreats.length > 0) {
          analysis.isSuspicious = true;
          analysis.severity = 'medium';
          analysis.reason = mediumSeverityThreats[0].description;
        } else {
          analysis.isSuspicious = true;
          analysis.severity = 'low';
          analysis.reason = threats[0].description;
        }
      }

      // Determine if content script injection is needed
      analysis.requiresContentScript = this.requiresContentScript(url, analysis);

    } catch (error) {
      console.error('CyberShield Drain: URL analysis failed:', error);
      analysis.reason = 'Analysis failed';
    }

    return analysis;
  }

  detectThreats(url) {
    const threats = [];
    const allPatterns = [
      ...this.maliciousPatterns.map(p => ({ ...p, type: 'malicious' })),
      ...this.phishingPatterns.map(p => ({ ...p, type: 'phishing' })),
      ...this.suspiciousPatterns.map(p => ({ ...p, type: 'suspicious' }))
    ];

    for (const pattern of allPatterns) {
      if (pattern.regex.test(url)) {
        threats.push({
          type: pattern.type,
          severity: pattern.severity,
          description: pattern.description,
          action: pattern.action,
          pattern: pattern.regex.source
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
      if (whitelistedDomain.startsWith('*.') && 
          domain.endsWith(whitelistedDomain.substring(2))) {
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
      if (blacklistedDomain.startsWith('*.') && 
          domain.endsWith(blacklistedDomain.substring(2))) {
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
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')) {
      return false;
    }

    return true;
  }

  async analyzePageContent(tabId, url) {
    try {
      // Execute content analysis script
      const results = await chrome.scripting.executeScript({
        target: { tabId },
        function: this.contentAnalysisFunction
      });

      if (results && results[0] && results[0].result) {
        const contentAnalysis = results[0].result;
        
        // Process content analysis results
        await this.processContentAnalysis(tabId, url, contentAnalysis);
      }
    } catch (error) {
      console.error('CyberShield Drain: Content analysis failed:', error);
    }
  }

  // Function to be executed in the content context
  contentAnalysisFunction() {
    const analysis = {
      hasPasswordFields: document.querySelectorAll('input[type="password"]').length > 0,
      hasFormSubmissions: document.querySelectorAll('form').length > 0,
      hasSuspiciousScripts: false,
      hasExternalResources: false,
      documentTitle: document.title,
      metaTags: [],
      suspiciousElements: []
    };

    // Check for suspicious scripts
    const scripts = document.querySelectorAll('script');
    for (const script of scripts) {
      if (script.src && !script.src.startsWith(window.location.origin)) {
        analysis.hasExternalResources = true;
      }
      
      if (script.innerHTML.includes('eval(') || 
          script.innerHTML.includes('document.write(') ||
          script.innerHTML.includes('setTimeout(')) {
        analysis.hasSuspiciousScripts = true;
      }
    }

    // Collect meta tags
    const metaTags = document.querySelectorAll('meta');
    for (const meta of metaTags) {
      analysis.metaTags.push({
        name: meta.getAttribute('name'),
        content: meta.getAttribute('content'),
        property: meta.getAttribute('property')
      });
    }

    return analysis;
  }

  async processContentAnalysis(tabId, url, contentAnalysis) {
    const threats = [];

    // Check for login page impersonation
    if (contentAnalysis.hasPasswordFields) {
      const urlAnalysis = await this.analyzeUrl(url);
      if (urlAnalysis.isSuspicious || urlAnalysis.threats.some(t => t.type === 'phishing')) {
        threats.push({
          type: 'phishing_login',
          severity: 'high',
          description: 'Suspicious login page detected'
        });
      }
    }

    // Check for suspicious scripts
    if (contentAnalysis.hasSuspiciousScripts) {
      threats.push({
        type: 'malicious_script',
        severity: 'medium',
        description: 'Potentially malicious JavaScript detected'
      });
    }

    // Log content analysis results
    if (threats.length > 0) {
      chrome.runtime.sendMessage({
        type: 'LOG_EVENT',
        event: {
          type: 'content_threat_detected',
          url,
          threats,
          analysis: contentAnalysis
        }
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
      
      console.log('CyberShield Drain: Detection rules updated');
    } catch (error) {
      console.error('CyberShield Drain: Failed to update detection rules:', error);
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
      
      console.log('CyberShield Drain: Custom rule added');
    } catch (error) {
      console.error('CyberShield Drain: Failed to add custom rule:', error);
      throw error;
    }
  }

  async removeCustomRule(ruleId) {
    try {
      if (this.detectionRules.custom) {
        this.detectionRules.custom = this.detectionRules.custom.filter(rule => rule.id !== ruleId);
        await this.updateDetectionRules(this.detectionRules);
        console.log('CyberShield Drain: Custom rule removed');
      }
    } catch (error) {
      console.error('CyberShield Drain: Failed to remove custom rule:', error);
      throw error;
    }
  }
}
