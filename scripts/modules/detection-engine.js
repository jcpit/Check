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

  // Testing and Validation Methods
  async analyzeContent(content, context = {}) {
    const analysis = {
      timestamp: new Date().toISOString(),
      content_length: content.length,
      context,
      findings: [],
      legitimacy_score: 0,
      threat_level: 'none',
      hasRequiredElements: false
    };

    try {
      // Check for required Microsoft authentication elements
      const requiredElements = [
        { name: 'loginfmt', pattern: /name=['"]loginfmt['"]|id=['"]i0116['"]/ },
        { name: 'idPartnerPL', pattern: /name=['"]idPartnerPL['"]/ },
        { name: 'urlMsaSignUp', pattern: /urlMsaSignUp/ },
        { name: 'flowToken', pattern: /flowToken/ },
        { name: 'aadcdn.msauth.net', pattern: /https:\/\/aadcdn\.msauth\.net\// }
      ];

      let foundElements = 0;
      for (const element of requiredElements) {
        if (element.pattern.test(content)) {
          foundElements++;
          analysis.findings.push({
            type: 'required_element',
            element: element.name,
            found: true
          });
        } else {
          analysis.findings.push({
            type: 'missing_element',
            element: element.name,
            found: false
          });
        }
      }

      analysis.hasRequiredElements = foundElements >= 3; // At least 3 required elements
      analysis.legitimacy_score = (foundElements / requiredElements.length) * 100;

      // Check for phishing indicators
      if (this.detectionRules?.phishing_indicators) {
        for (const indicator of this.detectionRules.phishing_indicators) {
          const regex = new RegExp(indicator.pattern, indicator.flags || 'i');
          if (regex.test(content)) {
            analysis.findings.push({
              type: 'phishing_indicator',
              indicator: indicator.id,
              description: indicator.description,
              severity: indicator.severity
            });
            
            if (indicator.severity === 'high' || indicator.severity === 'critical') {
              analysis.threat_level = 'high';
            } else if (analysis.threat_level === 'none') {
              analysis.threat_level = 'medium';
            }
          }
        }
      }

      // Determine overall legitimacy
      if (analysis.legitimacy_score >= 80 && analysis.threat_level === 'none') {
        analysis.legitimacyScore = 'high';
      } else if (analysis.legitimacy_score >= 60) {
        analysis.legitimacyScore = 'medium';
      } else {
        analysis.legitimacyScore = 'low';
      }

    } catch (error) {
      analysis.error = error.message;
    }

    return analysis;
  }

  async analyzeForm(formData) {
    const analysis = {
      timestamp: new Date().toISOString(),
      formData,
      isLegitimate: false,
      findings: [],
      action_url: formData.action || '',
      method: formData.method || 'GET'
    };

    try {
      // Check form action URL
      if (analysis.action_url) {
        const urlAnalysis = await this.analyzeUrl(analysis.action_url);
        analysis.url_analysis = urlAnalysis;
        
        // For legitimate Microsoft forms, action should NOT be login.microsoftonline.com
        if (analysis.action_url.includes('login.microsoftonline.com')) {
          analysis.findings.push({
            type: 'suspicious_action',
            message: 'Form action points to login.microsoftonline.com (potential phishing)'
          });
        }
      }

      // Check for required form fields
      const requiredFields = ['loginfmt', 'passwd', 'idPartnerPL'];
      let foundFields = 0;
      
      if (formData.fields) {
        for (const field of requiredFields) {
          if (formData.fields.some(f => f.name === field)) {
            foundFields++;
            analysis.findings.push({
              type: 'required_field',
              field,
              found: true
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
      referrer_valid: false
    };

    try {
      // Check Content Security Policy
      const cspHeader = headers['content-security-policy-report-only'] || 
                       headers['Content-Security-Policy-Report-Only'];
      
      if (cspHeader) {
        analysis.csp_valid = await this.validateCSP(cspHeader);
        analysis.findings.push({
          type: 'csp_header',
          valid: analysis.csp_valid,
          header: cspHeader
        });
      } else {
        analysis.findings.push({
          type: 'missing_csp',
          message: 'Missing content-security-policy-report-only header'
        });
      }

      // Check referrer
      const referrer = headers['referer'] || headers['Referer'];
      if (referrer) {
        analysis.referrer_valid = await this.validateReferrer(referrer);
        analysis.findings.push({
          type: 'referrer',
          valid: analysis.referrer_valid,
          referrer
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
      return validReferrers.some(validRef => {
        // Exact match or starts with the valid referrer
        return referrer === validRef || referrer.startsWith(validRef);
      });
    } catch (error) {
      console.error('CyberShield Drain: Error validating referrer:', error);
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
        pattern => pattern.csp_domains
      );

      if (!cspPattern) {
        return false;
      }

      const requiredDomains = cspPattern.csp_domains;
      let validDomains = 0;

      for (const domain of requiredDomains) {
        // Convert wildcard pattern to regex-friendly format
        const domainPattern = domain
          .replace(/\*/g, '[^\\s]*')
          .replace(/\./g, '\\.');
        
        const regex = new RegExp(domainPattern, 'i');
        if (regex.test(cspHeader)) {
          validDomains++;
        }
      }

      // Require at least 80% of domains to be present
      return (validDomains / requiredDomains.length) >= 0.8;
    } catch (error) {
      console.error('CyberShield Drain: Error validating CSP:', error);
      return false;
    }
  }

  async runRuleValidation() {
    const validation = {
      timestamp: new Date().toISOString(),
      rules_loaded: !!this.detectionRules,
      validation_results: []
    };

    if (!this.detectionRules) {
      validation.error = 'No detection rules loaded';
      return validation;
    }

    // Validate each rule category
    const categories = ['rules', 'phishing_indicators', 'legitimate_patterns', 'suspicious_behaviors'];
    
    for (const category of categories) {
      if (this.detectionRules[category]) {
        const categoryValidation = {
          category,
          count: Array.isArray(this.detectionRules[category]) ? this.detectionRules[category].length : 0,
          valid: true,
          issues: []
        };

        if (Array.isArray(this.detectionRules[category])) {
          for (const rule of this.detectionRules[category]) {
            if (!rule.id) {
              categoryValidation.issues.push('Rule missing ID');
              categoryValidation.valid = false;
            }
            if (!rule.description) {
              categoryValidation.issues.push(`Rule ${rule.id || 'unknown'} missing description`);
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
      tests: []
    };

    // Test URL analysis
    const urlTests = [
      { url: 'https://login.microsoftonline.com', expected: 'legitimate' },
      { url: 'https://fake-microsoft-login.com', expected: 'suspicious' },
      { url: 'https://secure-office365.phishing.com', expected: 'blocked' }
    ];

    for (const test of urlTests) {
      try {
        const result = await this.analyzeUrl(test.url);
        testResults.tests.push({
          type: 'url_analysis',
          input: test.url,
          expected: test.expected,
          result,
          passed: this.evaluateTestResult(test.expected, result)
        });
      } catch (error) {
        testResults.tests.push({
          type: 'url_analysis',
          input: test.url,
          error: error.message,
          passed: false
        });
      }
    }

    return testResults;
  }

  evaluateTestResult(expected, actual) {
    switch (expected) {
      case 'legitimate':
        return !actual.isBlocked && actual.threat_level === 'none';
      case 'suspicious':
        return actual.threat_level === 'medium' || actual.threat_level === 'high';
      case 'blocked':
        return actual.isBlocked || actual.threat_level === 'high';
      default:
        return false;
    }
  }
}
