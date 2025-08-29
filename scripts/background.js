/**
 * Check - Background Service Worker
 * Handles core extension functionality, policy enforcement, and threat detection
 */

import { ConfigManager } from "./modules/config-manager.js";
import { DetectionEngine } from "./modules/detection-engine.js";
import { PolicyManager } from "./modules/policy-manager.js";

class CheckBackground {
  constructor() {
    this.configManager = new ConfigManager();
    this.detectionEngine = new DetectionEngine();
    this.policyManager = new PolicyManager();
    this.isInitialized = false;
  }

  async initialize() {
    try {
      console.log("Check: Initializing background service worker..."); // Load configuration and policies
      await this.configManager.loadConfig();
      await this.policyManager.loadPolicies();
      await this.detectionEngine.initialize();

      this.setupEventListeners();
      this.isInitialized = true;

      console.log("Check: Background service worker initialized successfully");
    } catch (error) {
      console.error(
        "Check: Failed to initialize background service worker:",
        error
      );
    }
  }

  setupEventListeners() {
    // Handle extension installation/startup
    chrome.runtime.onStartup.addListener(() => {
      this.handleStartup();
    });

    chrome.runtime.onInstalled.addListener((details) => {
      this.handleInstalled(details);
    });

    // Handle tab updates for URL monitoring
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      this.handleTabUpdate(tabId, changeInfo, tab);
    });

    // Handle messages from content scripts
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep message channel open for async responses
    });

    // Handle storage changes (for enterprise policy updates)
    chrome.storage.onChanged.addListener((changes, namespace) => {
      this.handleStorageChange(changes, namespace);
    });

    // Handle web navigation events
    chrome.webNavigation?.onCompleted?.addListener((details) => {
      this.handleNavigationCompleted(details);
    });
  }

  async handleStartup() {
    console.log("Check: Extension startup detected");
    await this.configManager.refreshConfig();
  }

  async handleInstalled(details) {
    console.log("Check: Extension installed/updated:", details.reason);

    if (details.reason === "install") {
      // Set default configuration
      await this.configManager.setDefaultConfig();

      // Open options page for initial setup
      chrome.tabs.create({
        url: chrome.runtime.getURL("options/options.html"),
      });
    } else if (details.reason === "update") {
      // Handle extension updates
      await this.configManager.migrateConfig(details.previousVersion);
    }
  }

  async handleTabUpdate(tabId, changeInfo, tab) {
    if (!this.isInitialized || !changeInfo.url) return;

    try {
      // Analyze URL for threats
      const urlAnalysis = await this.detectionEngine.analyzeUrl(changeInfo.url);

      if (urlAnalysis.isBlocked) {
        // Block navigation if URL is flagged
        chrome.tabs.update(tabId, {
          url:
            chrome.runtime.getURL("blocked.html") +
            "?reason=" +
            encodeURIComponent(urlAnalysis.reason),
        });
        return;
      }

      // Check if page requires content script injection
      if (urlAnalysis.requiresContentScript) {
        await this.injectContentScript(tabId);
      }

      // Log URL access for audit purposes
      await this.logUrlAccess(tab.url, tabId);
    } catch (error) {
      console.error("Check: Error handling tab update:", error);
    }
  }

  async handleMessage(message, sender, sendResponse) {
    try {
      // Handle both message.type and message.action for compatibility
      const messageType = message.type || message.action;

      switch (messageType) {
        case "ping":
          sendResponse({
            success: true,
            message: "Check background script is running",
            timestamp: new Date().toISOString(),
            initialized: this.isInitialized,
          });
          break;

        case "testDetectionEngine":
          try {
            const detectionTest = {
              rulesLoaded: this.detectionEngine?.detectionRules
                ? Object.keys(this.detectionEngine.detectionRules).length
                : 0,
              engineInitialized: this.detectionEngine?.isInitialized || false,
              testsRun: 0,
            };

            if (message.testData) {
              const testResults = await this.testDetectionRules([
                {
                  id: "quick_test",
                  type: "url_analysis",
                  input: { url: message.testData.url },
                  expected: { analyzed: true },
                },
              ]);
              detectionTest.testsRun = testResults.summary.total;
            }

            sendResponse({
              success: true,
              ...detectionTest,
            });
          } catch (error) {
            sendResponse({
              success: false,
              error: error.message,
            });
          }
          break;

        case "testConfiguration":
          try {
            const configTest = {
              configModules: [],
              initialized: this.isInitialized,
            };

            if (this.configManager)
              configTest.configModules.push("ConfigManager");
            if (this.detectionEngine)
              configTest.configModules.push("DetectionEngine");
            if (this.policyManager)
              configTest.configModules.push("PolicyManager");

            sendResponse({
              success: true,
              ...configTest,
            });
          } catch (error) {
            sendResponse({
              success: false,
              error: error.message,
            });
          }
          break;

        case "URL_ANALYSIS_REQUEST":
          const analysis = await this.detectionEngine.analyzeUrl(message.url);
          sendResponse({ success: true, analysis });
          break;

        case "POLICY_CHECK":
          const policyResult = await this.policyManager.checkPolicy(
            message.action,
            message.context
          );
          sendResponse({
            success: true,
            allowed: policyResult.allowed,
            reason: policyResult.reason,
          });
          break;

        case "CONTENT_MANIPULATION_REQUEST":
          const manipulationAllowed =
            await this.policyManager.checkContentManipulation(message.domain);
          sendResponse({ success: true, allowed: manipulationAllowed });
          break;

        case "LOG_EVENT":
          await this.logEvent(message.event, sender.tab?.id);
          sendResponse({ success: true });
          break;

        case "GET_CONFIG":
          const config = await this.configManager.getConfig();
          sendResponse({ success: true, config });
          break;

        case "TEST_DETECTION_RULES":
          const testResults = await this.testDetectionRules(message.testData);
          sendResponse({ success: true, results: testResults });
          break;

        case "VALIDATE_DETECTION_ENGINE":
          const validationResults = await this.validateDetectionEngine();
          sendResponse({ success: true, validation: validationResults });
          break;

        case "RUN_COMPREHENSIVE_TEST":
          const comprehensiveResults = await this.runComprehensiveTest();
          sendResponse({ success: true, tests: comprehensiveResults });
          break;

        default:
          sendResponse({ success: false, error: "Unknown message type" });
      }
    } catch (error) {
      console.error("Check: Error handling message:", error);
      sendResponse({ success: false, error: error.message });
    }
  }

  async handleStorageChange(changes, namespace) {
    if (namespace === "managed") {
      // Enterprise policy changes
      console.log("Check: Enterprise policy updated");
      await this.policyManager.loadPolicies();
      await this.configManager.refreshConfig();
    }
  }

  async handleNavigationCompleted(details) {
    if (details.frameId === 0) {
      // Main frame only
      // Run post-navigation analysis
      await this.detectionEngine.analyzePageContent(details.tabId, details.url);
    }
  }

  async injectContentScript(tabId) {
    try {
      await chrome.scripting.executeScript({
        target: { tabId },
        files: ["scripts/content.js"],
      });
    } catch (error) {
      console.error("Check: Failed to inject content script:", error);
    }
  }

  async logUrlAccess(url, tabId) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      url,
      tabId,
      type: "url_access",
    };

    // Store in local storage for audit
    const result = await chrome.storage.local.get(["accessLogs"]);
    const logs = result.accessLogs || [];
    logs.push(logEntry);

    // Keep only last 1000 entries
    if (logs.length > 1000) {
      logs.splice(0, logs.length - 1000);
    }

    await chrome.storage.local.set({ accessLogs: logs });
  }

  async logEvent(event, tabId) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      tabId,
      type: "security_event",
    };

    console.log("Check: Security Event:", logEntry);

    // Store security events separately
    const result = await chrome.storage.local.get(["securityEvents"]);
    const logs = result.securityEvents || [];
    logs.push(logEntry);

    // Keep only last 500 security events
    if (logs.length > 500) {
      logs.splice(0, logs.length - 500);
    }

    await chrome.storage.local.set({ securityEvents: logs });
  }

  // Detection Rules Testing Methods
  async testDetectionRules(testData = null) {
    const results = {
      timestamp: new Date().toISOString(),
      engineStatus: this.isInitialized,
      rulesLoaded: this.detectionEngine.detectionRules !== null,
      testResults: [],
      summary: {
        total: 0,
        passed: 0,
        failed: 0,
        warnings: 0,
      },
    };

    // Default test cases if none provided
    if (!testData) {
      testData = this.getDefaultTestCases();
    }

    for (const testCase of testData) {
      const testResult = await this.runSingleTest(testCase);
      results.testResults.push(testResult);
      results.summary.total++;

      if (testResult.status === "passed") {
        results.summary.passed++;
      } else if (testResult.status === "failed") {
        results.summary.failed++;
      } else {
        results.summary.warnings++;
      }
    }

    // Log test results
    await this.logEvent({
      type: "detection_rules_test",
      results: results.summary,
    });

    return results;
  }

  async runSingleTest(testCase) {
    const result = {
      testId: testCase.id,
      description: testCase.description,
      type: testCase.type,
      input: testCase.input,
      expected: testCase.expected,
      actual: null,
      status: "unknown",
      message: "",
      timestamp: new Date().toISOString(),
    };

    try {
      switch (testCase.type) {
        case "url_analysis":
          result.actual = await this.detectionEngine.analyzeUrl(
            testCase.input.url
          );
          break;
        case "content_analysis":
          result.actual = await this.detectionEngine.analyzeContent(
            testCase.input.content,
            testCase.input.context
          );
          break;
        case "form_analysis":
          result.actual = await this.detectionEngine.analyzeForm(
            testCase.input.formData
          );
          break;
        case "header_analysis":
          result.actual = await this.detectionEngine.analyzeHeaders(
            testCase.input.headers
          );
          break;
        case "referrer_check":
          result.actual = await this.detectionEngine.validateReferrer(
            testCase.input.referrer
          );
          break;
        default:
          result.status = "failed";
          result.message = `Unknown test type: ${testCase.type}`;
          return result;
      }

      // Compare results
      if (this.compareTestResults(result.expected, result.actual)) {
        result.status = "passed";
        result.message = "Test passed successfully";
      } else {
        result.status = "failed";
        result.message = `Expected: ${JSON.stringify(
          result.expected
        )}, Got: ${JSON.stringify(result.actual)}`;
      }
    } catch (error) {
      result.status = "failed";
      result.message = `Test execution failed: ${error.message}`;
      result.actual = { error: error.message };
    }

    return result;
  }

  async validateDetectionEngine() {
    const validation = {
      timestamp: new Date().toISOString(),
      engineInitialized: this.isInitialized,
      detectionEngineStatus: this.detectionEngine ? "loaded" : "not_loaded",
      rulesValidation: {},
      componentsStatus: {},
      configurationStatus: {},
    };

    try {
      // Validate rules structure
      validation.rulesValidation = await this.validateRulesStructure();

      // Validate components
      validation.componentsStatus = await this.validateComponents();

      // Validate configuration
      validation.configurationStatus = await this.validateConfiguration();
    } catch (error) {
      validation.error = error.message;
    }

    return validation;
  }

  async runComprehensiveTest() {
    const comprehensiveResults = {
      timestamp: new Date().toISOString(),
      testSuites: [],
    };

    // Test Suite 1: Microsoft Authentication Detection
    const msAuthTests = await this.testMicrosoftAuthDetection();
    comprehensiveResults.testSuites.push({
      suite: "Microsoft Authentication Detection",
      results: msAuthTests,
    });

    // Test Suite 2: Phishing Detection
    const phishingTests = await this.testPhishingDetection();
    comprehensiveResults.testSuites.push({
      suite: "Phishing Detection",
      results: phishingTests,
    });

    // Test Suite 3: Referrer Validation
    const referrerTests = await this.testReferrerValidation();
    comprehensiveResults.testSuites.push({
      suite: "Referrer Validation",
      results: referrerTests,
    });

    // Test Suite 4: Content Security Policy
    const cspTests = await this.testCSPValidation();
    comprehensiveResults.testSuites.push({
      suite: "Content Security Policy Validation",
      results: cspTests,
    });

    return comprehensiveResults;
  }

  getDefaultTestCases() {
    return [
      {
        id: "legitimate_microsoft_url",
        description: "Test legitimate Microsoft login URL",
        type: "url_analysis",
        input: {
          url: "https://login.microsoftonline.com/common/oauth2/authorize",
        },
        expected: { isLegitimate: true, threat_level: "none" },
      },
      {
        id: "phishing_microsoft_url",
        description: "Test phishing URL mimicking Microsoft",
        type: "url_analysis",
        input: { url: "https://secure-microsoft-login.com/oauth2/authorize" },
        expected: { isLegitimate: false, threat_level: "high" },
      },
      {
        id: "valid_referrer",
        description: "Test valid referrer from allow list",
        type: "referrer_check",
        input: { referrer: "https://tasks.office.com" },
        expected: { isValid: true },
      },
      {
        id: "invalid_referrer",
        description: "Test invalid referrer not in allow list",
        type: "referrer_check",
        input: { referrer: "https://evil-site.com" },
        expected: { isValid: false },
      },
      {
        id: "legitimate_form_elements",
        description: "Test legitimate Microsoft form elements",
        type: "content_analysis",
        input: {
          content:
            '<input name="loginfmt"><input name="idPartnerPL"><script>var urlMsaSignUp = "...";</script>',
          context: "form_analysis",
        },
        expected: { hasRequiredElements: true, legitimacyScore: "high" },
      },
    ];
  }

  compareTestResults(expected, actual) {
    // Simple comparison logic - can be enhanced based on test requirements
    if (typeof expected === "object" && typeof actual === "object") {
      for (const key in expected) {
        if (expected[key] !== actual[key]) {
          return false;
        }
      }
      return true;
    }
    return expected === actual;
  }

  async validateRulesStructure() {
    const validation = {
      hasRules: false,
      rulesCount: 0,
      validRules: 0,
      invalidRules: 0,
      issues: [],
    };

    try {
      if (!this.detectionEngine.detectionRules) {
        validation.issues.push("Detection rules not loaded");
        return validation;
      }

      const rules = this.detectionEngine.detectionRules;
      validation.hasRules = true;

      if (rules.rules && Array.isArray(rules.rules)) {
        validation.rulesCount = rules.rules.length;

        for (const rule of rules.rules) {
          if (this.validateSingleRule(rule)) {
            validation.validRules++;
          } else {
            validation.invalidRules++;
            validation.issues.push(`Invalid rule: ${rule.id || "unnamed"}`);
          }
        }
      }
    } catch (error) {
      validation.issues.push(`Validation error: ${error.message}`);
    }

    return validation;
  }

  validateSingleRule(rule) {
    const requiredFields = ["id", "type", "weight", "condition", "description"];
    return requiredFields.every((field) => field in rule);
  }

  async validateComponents() {
    return {
      configManager: this.configManager ? "loaded" : "not_loaded",
      detectionEngine: this.detectionEngine ? "loaded" : "not_loaded",
      policyManager: this.policyManager ? "loaded" : "not_loaded",
      detectionEngineInitialized: this.detectionEngine?.isInitialized || false,
    };
  }

  async validateConfiguration() {
    const config = await this.configManager.getConfig();
    return {
      configLoaded: !!config,
      hasValidReferrers: config?.valid_referrers?.referrers?.length > 0,
      hasWhitelistDomains: config?.whitelist_domains?.length > 0,
      detectionEnabled: config?.detection_settings?.enable_real_time_scanning,
    };
  }

  async testMicrosoftAuthDetection() {
    const testCases = [
      "https://login.microsoftonline.com",
      "https://fake-microsoft-login.com",
      "https://login.microsoft.com",
      "https://secure-office365-login.phishing.com",
    ];

    const results = [];
    for (const url of testCases) {
      try {
        const analysis = await this.detectionEngine.analyzeUrl(url);
        results.push({
          url,
          analysis,
          expected:
            url.includes("microsoftonline.com") ||
            url.includes("microsoft.com"),
          passed: this.evaluateMicrosoftAuthResult(url, analysis),
        });
      } catch (error) {
        results.push({
          url,
          error: error.message,
          passed: false,
        });
      }
    }
    return results;
  }

  async testPhishingDetection() {
    const phishingUrls = [
      "https://secure-microsoft365.com/login",
      "https://office-security-update.com",
      "https://microsoft-account-verify.net",
    ];

    const results = [];
    for (const url of phishingUrls) {
      try {
        const analysis = await this.detectionEngine.analyzeUrl(url);
        results.push({
          url,
          analysis,
          expected: "blocked_or_flagged",
          passed: analysis.isBlocked || analysis.threat_level === "high",
        });
      } catch (error) {
        results.push({
          url,
          error: error.message,
          passed: false,
        });
      }
    }
    return results;
  }

  async testReferrerValidation() {
    const validReferrers = [
      "https://login.microsoftonline.com",
      "https://tasks.office.com",
      "https://login.microsoft.net",
    ];

    const invalidReferrers = [
      "https://evil-site.com",
      "https://phishing-microsoft.com",
      "https://fake-office.net",
    ];

    const results = [];

    for (const referrer of validReferrers) {
      const isValid = await this.detectionEngine.validateReferrer(referrer);
      results.push({
        referrer,
        expected: true,
        actual: isValid,
        passed: isValid === true,
      });
    }

    for (const referrer of invalidReferrers) {
      const isValid = await this.detectionEngine.validateReferrer(referrer);
      results.push({
        referrer,
        expected: false,
        actual: isValid,
        passed: isValid === false,
      });
    }

    return results;
  }

  async testCSPValidation() {
    const validCSP =
      "content-security-policy-report-only: default-src 'self'; connect-src https://*.msauth.net/ https://*.microsoft.com/";
    const invalidCSP =
      "content-security-policy-report-only: default-src 'self'; connect-src https://evil-site.com/";

    const results = [];

    try {
      const validResult = await this.detectionEngine.validateCSP(validCSP);
      results.push({
        csp: validCSP,
        expected: true,
        actual: validResult,
        passed: validResult === true,
      });

      const invalidResult = await this.detectionEngine.validateCSP(invalidCSP);
      results.push({
        csp: invalidCSP,
        expected: false,
        actual: invalidResult,
        passed: invalidResult === false,
      });
    } catch (error) {
      results.push({
        error: error.message,
        passed: false,
      });
    }

    return results;
  }

  evaluateMicrosoftAuthResult(url, analysis) {
    const isLegitimateUrl =
      url.includes("microsoftonline.com") || url.includes("microsoft.com");

    if (isLegitimateUrl) {
      return !analysis.isBlocked && analysis.threat_level !== "high";
    } else {
      return analysis.isBlocked || analysis.threat_level === "high";
    }
  }
}

// Initialize the background service worker
const check = new CheckBackground();
check.initialize();

// Export for testing purposes
if (typeof module !== "undefined" && module.exports) {
  module.exports = CheckBackground;
}
