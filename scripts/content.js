/**
 * Check - Final Rule-Driven Content Script
 * 100% rule-driven architecture - NO hardcoded detections
 *
 * Logic Flow (CORRECTED):
 * 1. Load rules and check trusted origins FIRST - immediate exit if trusted
 * 2. Check if page is MS logon page (using rule file requirements)
 * 3. If MS logon page on non-trusted domain, apply blocking rules
 */

// Prevent multiple script execution
if (window.checkExtensionLoaded) {
  console.warn(
    "[M365-Protection] Content script already loaded, skipping re-execution"
  );
} else {
  window.checkExtensionLoaded = true;

  // Global state
  let protectionActive = false;
  let detectionRules = null;
  let trustedLoginPatterns = [];
  let microsoftDomainPatterns = [];
  let domObserver = null;
  let lastScanTime = 0;
  let scanCount = 0;
  let lastDetectionResult = null; // Store last detection analysis
  let developerConsoleLoggingEnabled = false; // Cache for developer console logging setting
  let showingBanner = false; // Flag to prevent DOM monitoring loops when showing banners
  const MAX_SCANS = 10; // Prevent infinite scanning
  const SCAN_COOLDOWN = 1000; // 1 second between scans

  /**
   * Check if a URL matches any pattern in the given pattern array
   * @param {string} url - The URL to check
   * @param {string[]} patterns - Array of regex patterns
   * @returns {boolean} - True if URL matches any pattern
   */
  function matchesAnyPattern(url, patterns) {
    if (!patterns || patterns.length === 0) return false;

    for (const pattern of patterns) {
      try {
        const regex = new RegExp(pattern);
        if (regex.test(url)) {
          logger.debug(`URL "${url}" matches pattern: ${pattern}`);
          return true;
        }
      } catch (error) {
        logger.warn(`Invalid regex pattern: ${pattern}`, error);
      }
    }
    return false;
  }

  /**
   * Check if current URL is from a trusted Microsoft login domain
   * @param {string} url - The URL to check
   * @returns {boolean} - True if trusted login domain
   */
  function isTrustedLoginDomain(url) {
    try {
      const urlObj = new URL(url);
      const origin = urlObj.origin;
      return matchesAnyPattern(origin, trustedLoginPatterns);
    } catch (error) {
      logger.warn("Invalid URL for trusted login domain check:", url);
      return false;
    }
  }

  /**
   * Check if current URL is from a Microsoft domain (but not necessarily login)
   * @param {string} url - The URL to check
   * @returns {boolean} - True if Microsoft domain
   */
  function isMicrosoftDomain(url) {
    try {
      const urlObj = new URL(url);
      const origin = urlObj.origin;
      return matchesAnyPattern(origin, microsoftDomainPatterns);
    } catch (error) {
      logger.warn("Invalid URL for Microsoft domain check:", url);
      return false;
    }
  }

  // Conditional logger that respects developer console logging setting
  const logger = {
    log: (...args) => {
      if (developerConsoleLoggingEnabled) {
        console.log("[M365-Protection]", ...args);
      }
    },
    warn: (...args) => {
      // Always show warnings regardless of developer setting
      console.warn("[M365-Protection]", ...args);
    },
    error: (...args) => {
      // Always show errors regardless of developer setting
      console.error("[M365-Protection]", ...args);
    },
    debug: (...args) => {
      if (developerConsoleLoggingEnabled) {
        console.debug("[M365-Protection]", ...args);
      }
    },
  };

  /**
   * Load developer console logging setting from configuration
   */
  async function loadDeveloperConsoleLoggingSetting() {
    try {
      const config = await new Promise((resolve) => {
        chrome.storage.local.get(["config"], (result) => {
          resolve(result.config || {});
        });
      });

      developerConsoleLoggingEnabled =
        config.enableDeveloperConsoleLogging === true;
    } catch (error) {
      // If there's an error loading settings, default to false
      developerConsoleLoggingEnabled = false;
      console.error(
        "[M365-Protection] Error loading developer console logging setting:",
        error
      );
    }
  }

  /**
   * Load detection rules from the rule file - EVERYTHING comes from here
   * Now uses the detection rules manager for caching and remote loading
   */
  async function loadDetectionRules() {
    try {
      // Try to get rules from background script first (which handles caching)
      try {
        const response = await chrome.runtime.sendMessage({
          type: "get_detection_rules",
        });

        if (response && response.success && response.rules) {
          logger.log("Loaded detection rules from background script cache");

          // Set up trusted login patterns and Microsoft domain patterns from cached rules
          const rules = response.rules;
          if (
            rules.trusted_login_patterns &&
            Array.isArray(rules.trusted_login_patterns)
          ) {
            trustedLoginPatterns = rules.trusted_login_patterns;
            logger.debug(
              `Set up ${trustedLoginPatterns.length} trusted login patterns from cache`
            );
          }
          if (
            rules.microsoft_domain_patterns &&
            Array.isArray(rules.microsoft_domain_patterns)
          ) {
            microsoftDomainPatterns = rules.microsoft_domain_patterns;
            logger.debug(
              `Set up ${microsoftDomainPatterns.length} Microsoft domain patterns from cache`
            );
          }

          return rules;
        }
      } catch (error) {
        logger.warn(
          "Failed to get rules from background script:",
          error.message
        );
      }

      // Fallback to direct loading (with no-cache to ensure fresh data)
      const response = await fetch(
        chrome.runtime.getURL("rules/detection-rules.json"),
        {
          cache: "no-cache",
        }
      );

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const rules = await response.json();

      // Set up trusted login patterns and Microsoft domain patterns from rules ONLY
      if (
        rules.trusted_login_patterns &&
        Array.isArray(rules.trusted_login_patterns)
      ) {
        trustedLoginPatterns = rules.trusted_login_patterns.slice();
        logger.debug(
          `Set up ${trustedLoginPatterns.length} trusted login patterns from direct load`
        );
      } else {
        logger.error(
          "No trusted_login_patterns found in rules or not an array:",
          rules.trusted_login_patterns
        );
      }
      if (
        rules.microsoft_domain_patterns &&
        Array.isArray(rules.microsoft_domain_patterns)
      ) {
        microsoftDomainPatterns = rules.microsoft_domain_patterns.slice();
        logger.debug(
          `Set up ${microsoftDomainPatterns.length} Microsoft domain patterns from direct load`
        );
      }

      logger.log(
        `Loaded detection rules: ${
          trustedLoginPatterns.length
        } trusted login patterns, ${rules.rules?.length || 0} detection rules`
      );
      return rules;
    } catch (error) {
      logger.error("CRITICAL: Failed to load detection rules:", error.message);
      throw error; // Don't continue without rules
    }
  }

  /**
   * Manual test function for debugging detection patterns
   * Call this from browser console: testDetectionPatterns()
   */
  function testDetectionPatterns() {
    console.log("🔍 MANUAL DETECTION TESTING");
    const pageSource = document.documentElement.outerHTML;

    // Test each pattern individually
    const patterns = [
      { name: "idPartnerPL", pattern: "idPartnerPL", type: "source_content" },
      { name: "loginfmt", pattern: "loginfmt", type: "source_content" },
      {
        name: "aadcdn_msauth",
        pattern: "aadcdn\\.msauth\\.net",
        type: "source_content",
      },
      { name: "urlMsaSignUp", pattern: "urlMsaSignUp", type: "source_content" },
      { name: "i0116_element", pattern: "#i0116", type: "source_content" },
      {
        name: "ms_background_cdn",
        pattern: "logincdn\\.msauth\\.net",
        type: "source_content",
      },
      {
        name: "segoe_ui_font",
        pattern: "Segoe\\s+UI(?:\\s+(?:Webfont|Symbol|Historic|Emoji))?",
        type: "source_content",
      },
    ];

    const cssPatterns = [
      "width:\\s*27\\.5rem",
      "height:\\s*21\\.125rem",
      "max-width:\\s*440px",
      "background-color:\\s*#0067b8",
      "display:\\s*grid.*place-items:\\s*center",
    ];

    patterns.forEach((p) => {
      const regex = new RegExp(p.pattern, "i");
      const found = regex.test(pageSource);
      console.log(`${found ? "✅" : "❌"} ${p.name}: ${p.pattern}`);
      if (found) {
        const match = pageSource.match(regex);
        console.log(`   Match: "${match[0]}"`);
      }
    });

    console.log("🎨 CSS PATTERNS:");
    cssPatterns.forEach((pattern, idx) => {
      const regex = new RegExp(pattern, "i");
      const found = regex.test(pageSource);
      console.log(`${found ? "✅" : "❌"} CSS[${idx}]: ${pattern}`);
      if (found) {
        const match = pageSource.match(regex);
        console.log(`   Match: "${match[0]}"`);
      }
    });

    // Check external stylesheets
    console.log("📎 EXTERNAL STYLESHEETS:");
    const styleSheets = Array.from(document.styleSheets);
    styleSheets.forEach((sheet, idx) => {
      try {
        const href = sheet.href || "inline";
        console.log(`   [${idx}] ${href}`);

        // Check if stylesheet URL contains Microsoft patterns
        if (href !== "inline") {
          const msPatterns = [
            "microsoft",
            "msauth",
            "msft",
            "office365",
            "o365",
          ];
          const hasMsPattern = msPatterns.some((pattern) =>
            href.toLowerCase().includes(pattern)
          );
          console.log(
            `      ${hasMsPattern ? "✅" : "❌"} Microsoft-themed URL`
          );
        }

        // Try to check CSS rules (may be blocked by CORS)
        if (sheet.cssRules) {
          const cssText = Array.from(sheet.cssRules)
            .map((rule) => rule.cssText)
            .join(" ");
          const hasSegoeUI = /segoe\s+ui/i.test(cssText);
          const hasMsBlue = /#0067b8/i.test(cssText);
          const has440px = /440px|27\.5rem/i.test(cssText);

          console.log(`      ${hasSegoeUI ? "✅" : "❌"} Segoe UI font`);
          console.log(
            `      ${hasMsBlue ? "✅" : "❌"} Microsoft blue (#0067b8)`
          );
          console.log(`      ${has440px ? "✅" : "❌"} 440px/27.5rem width`);
        }
      } catch (e) {
        console.log(`      ⚠️ Cannot access stylesheet (CORS): ${e.message}`);
      }
    });

    return {
      pageLength: pageSource.length,
      url: window.location.href,
      stylesheets: styleSheets.length,
    };
  }

  // Make it globally available for testing
  window.testDetectionPatterns = testDetectionPatterns;

  /**
   * Debug function to test phishing indicators - call from console
   */
  function testPhishingIndicators() {
    console.log("🔍 TESTING PHISHING INDICATORS");

    if (!detectionRules) {
      console.error("❌ Detection rules not loaded!");
      return;
    }

    if (!detectionRules.phishing_indicators) {
      console.error("❌ No phishing indicators in detection rules!");
      return;
    }

    console.log(
      `📋 Found ${detectionRules.phishing_indicators.length} phishing indicators to test`
    );

    const pageSource = document.documentElement.outerHTML;
    const pageText = document.body?.textContent || "";
    const currentUrl = window.location.href;

    console.log(`📄 Page source length: ${pageSource.length} chars`);
    console.log(`📝 Page text length: ${pageText.length} chars`);
    console.log(`🌐 Current URL: ${currentUrl}`);

    let foundThreats = 0;

    detectionRules.phishing_indicators.forEach((indicator, idx) => {
      try {
        console.log(
          `\n🔍 Testing indicator ${idx + 1}/${
            detectionRules.phishing_indicators.length
          }: ${indicator.id}`
        );
        console.log(`   Pattern: ${indicator.pattern}`);
        console.log(`   Flags: ${indicator.flags || "i"}`);
        console.log(
          `   Severity: ${indicator.severity} | Action: ${indicator.action}`
        );

        const pattern = new RegExp(indicator.pattern, indicator.flags || "i");

        // Test against page source
        let matches = false;
        let matchLocation = "";

        if (pattern.test(pageSource)) {
          matches = true;
          matchLocation = "page source";
          const match = pageSource.match(pattern);
          console.log(`   ✅ MATCH in ${matchLocation}: "${match[0]}"`);
        }
        // Test against visible text
        else if (pattern.test(pageText)) {
          matches = true;
          matchLocation = "page text";
          const match = pageText.match(pattern);
          console.log(`   ✅ MATCH in ${matchLocation}: "${match[0]}"`);
        }
        // Test against URL
        else if (pattern.test(currentUrl)) {
          matches = true;
          matchLocation = "URL";
          const match = currentUrl.match(pattern);
          console.log(`   ✅ MATCH in ${matchLocation}: "${match[0]}"`);
        }

        // Special handling for additional_checks
        if (!matches && indicator.additional_checks) {
          console.log(
            `   🔍 Testing ${indicator.additional_checks.length} additional checks...`
          );
          for (const check of indicator.additional_checks) {
            if (pageSource.includes(check) || pageText.includes(check)) {
              matches = true;
              matchLocation = "additional checks";
              console.log(`   ✅ MATCH in ${matchLocation}: "${check}"`);
              break;
            }
          }
        }

        if (matches) {
          foundThreats++;
          console.log(`   🚨 THREAT DETECTED: ${indicator.description}`);
        } else {
          console.log(`   ❌ No match found`);
        }
      } catch (error) {
        console.error(`   ⚠️ Error testing indicator ${indicator.id}:`, error);
      }
    });

    console.log(
      `\n📊 SUMMARY: ${foundThreats} threats found out of ${detectionRules.phishing_indicators.length} indicators tested`
    );

    // Also test the actual function
    console.log("\n🔧 Testing processPhishingIndicators() function...");
    const result = processPhishingIndicators();
    console.log("Function result:", result);

    return {
      totalIndicators: detectionRules.phishing_indicators.length,
      threatsFound: foundThreats,
      functionResult: result,
    };
  }

  /**
   * Debug function to show current detection rules status
   */
  function debugDetectionRules() {
    console.log("🔍 DETECTION RULES DEBUG");
    console.log("Detection rules loaded:", !!detectionRules);

    if (detectionRules) {
      console.log("Available sections:");
      Object.keys(detectionRules).forEach((key) => {
        const section = detectionRules[key];
        if (Array.isArray(section)) {
          console.log(`  - ${key}: ${section.length} items`);
        } else if (typeof section === "object") {
          console.log(
            `  - ${key}: object with ${Object.keys(section).length} keys`
          );
        } else {
          console.log(`  - ${key}: ${typeof section} = ${section}`);
        }
      });

      if (detectionRules.phishing_indicators) {
        console.log("\nPhishing indicators:");
        detectionRules.phishing_indicators.forEach((indicator, idx) => {
          console.log(
            `  ${idx + 1}. ${indicator.id} (${indicator.severity}/${
              indicator.action
            })`
          );
        });
      }
    }

    return detectionRules;
  }

  // Make debug functions globally available
  window.testPhishingIndicators = testPhishingIndicators;
  window.debugDetectionRules = debugDetectionRules;

  /**
   * Manual trigger function for testing
   */
  window.manualPhishingCheck = function () {
    console.log("🚨 MANUAL PHISHING CHECK TRIGGERED");
    const result = processPhishingIndicators();
    console.log("Manual check result:", result);

    if (result.threats.length > 0) {
      console.log("🚨 THREATS FOUND:");
      result.threats.forEach((threat) => {
        console.log(
          `  - ${threat.id}: ${threat.description} (${threat.severity})`
        );
      });
    } else {
      console.log("✅ No threats detected");
    }

    return result;
  };

  /**
   * Function to re-run the entire protection analysis
   */
  window.rerunProtection = function () {
    console.log("🔄 RE-RUNNING PROTECTION ANALYSIS");
    runProtection(true);
  };

  /**
   * Function to check if detection rules are loaded and show their status
   */
  window.checkRulesStatus = function () {
    console.log("📋 DETECTION RULES STATUS CHECK");
    console.log(`Rules loaded: ${!!detectionRules}`);

    if (!detectionRules) {
      console.error("❌ Detection rules not loaded!");
      console.log("Attempting to reload rules...");

      loadDetectionRules()
        .then(() => {
          console.log("✅ Rules reload attempt completed");
          console.log(`Rules now loaded: ${!!detectionRules}`);
          if (detectionRules?.phishing_indicators) {
            console.log(
              `Phishing indicators available: ${detectionRules.phishing_indicators.length}`
            );
          }
        })
        .catch((error) => {
          console.error("❌ Failed to reload rules:", error);
        });

      return false;
    }

    console.log("✅ Detection rules are loaded");
    if (detectionRules.phishing_indicators) {
      console.log(
        `✅ Phishing indicators: ${detectionRules.phishing_indicators.length} available`
      );
      console.log("Sample indicators:");
      detectionRules.phishing_indicators
        .slice(0, 5)
        .forEach((indicator, idx) => {
          console.log(
            `  ${idx + 1}. ${indicator.id}: ${indicator.description}`
          );
        });
    } else {
      console.error("❌ No phishing_indicators section found!");
    }

    return true;
  };

  /**
   * Manual test function for phishing indicators
   * Call this from browser console: testPhishingIndicators()
   */
  function testPhishingIndicators() {
    console.log("🔍 MANUAL PHISHING INDICATORS TESTING");
    console.log("=".repeat(50));

    if (!detectionRules?.phishing_indicators) {
      console.error("❌ No phishing indicators loaded!");
      console.log("Detection rules:", detectionRules);
      return;
    }

    console.log(
      `✅ Found ${detectionRules.phishing_indicators.length} phishing indicators`
    );

    const pageSource = document.documentElement.outerHTML;
    const pageText = document.body?.textContent || "";
    const currentUrl = window.location.href;

    console.log(`📄 Page source length: ${pageSource.length} chars`);
    console.log(`📝 Page text length: ${pageText.length} chars`);
    console.log(`🌐 Current URL: ${currentUrl}`);
    console.log("");

    // Test each phishing indicator
    detectionRules.phishing_indicators.forEach((indicator, index) => {
      console.log(
        `Testing ${index + 1}/${detectionRules.phishing_indicators.length}: ${
          indicator.id
        }`
      );
      console.log(`  Pattern: ${indicator.pattern}`);
      console.log(`  Flags: ${indicator.flags || "i"}`);

      try {
        const pattern = new RegExp(indicator.pattern, indicator.flags || "i");

        let matched = false;
        let matchLocation = "";

        if (pattern.test(pageSource)) {
          matched = true;
          matchLocation = "page source";
        } else if (pattern.test(pageText)) {
          matched = true;
          matchLocation = "page text";
        } else if (pattern.test(currentUrl)) {
          matched = true;
          matchLocation = "URL";
        }

        // Test additional_checks
        if (!matched && indicator.additional_checks) {
          for (const check of indicator.additional_checks) {
            if (pageSource.includes(check) || pageText.includes(check)) {
              matched = true;
              matchLocation = `additional check: ${check}`;
              break;
            }
          }
        }

        if (matched) {
          console.log(`  ✅ MATCH found in: ${matchLocation}`);
          console.log(
            `  🚨 Severity: ${indicator.severity}, Action: ${indicator.action}`
          );
        } else {
          console.log(`  ❌ No match`);
        }
      } catch (error) {
        console.log(`  💥 Pattern error: ${error.message}`);
      }

      console.log("");
    });

    // Run the actual function
    console.log("Running processPhishingIndicators()...");
    const result = processPhishingIndicators();
    console.log("Result:", result);
  }

  // Make it globally available for testing
  window.testPhishingIndicators = testPhishingIndicators;

  /**
   * Global function to analyze current page - call from browser console: analyzeCurrentPage()
   */
  window.analyzeCurrentPage = function () {
    console.log("🔍 MANUAL PAGE ANALYSIS");
    console.log("=".repeat(50));

    // Check detection rules loading
    console.log("Detection Rules Status:", {
      loaded: !!detectionRules,
      phishingIndicators: detectionRules?.phishing_indicators?.length || 0,
      m365Requirements: !!detectionRules?.m365_detection_requirements,
      blockingRules: detectionRules?.blocking_rules?.length || 0,
    });

    // Check current URL
    console.log("Current URL:", window.location.href);
    console.log("Current Domain:", window.location.hostname);

    // Check if trusted
    const isTrusted = isTrustedOrigin(window.location.href);
    console.log("Is Trusted Domain:", isTrusted);

    // Check M365 detection
    const isMSLogon = isMicrosoftLogonPage();
    console.log("Detected as M365 Login:", isMSLogon);

    // Run phishing indicators
    const phishingResult = processPhishingIndicators();
    console.log("Phishing Analysis:", {
      threatsFound: phishingResult.threats.length,
      totalScore: phishingResult.score,
      threats: phishingResult.threats.map((t) => ({
        id: t.id,
        severity: t.severity,
        category: t.category,
        description: t.description,
        confidence: t.confidence,
      })),
    });

    // Run blocking rules
    const blockingResult = runBlockingRules();
    console.log("Blocking Rules Result:", {
      shouldBlock: blockingResult.shouldBlock,
      reason: blockingResult.reason,
    });

    // Run detection rules
    const detectionResult = runDetectionRules();
    console.log("Detection Rules Result:", {
      score: detectionResult.score,
      threshold: detectionResult.threshold,
      triggeredRules: detectionResult.triggeredRules,
    });

    // Check for forms
    const forms = document.querySelectorAll("form");
    console.log(
      "Forms Found:",
      Array.from(forms).map((form) => ({
        action: form.action || "none",
        method: form.method || "get",
        hasPasswordField: !!form.querySelector('input[type="password"]'),
        hasEmailField: !!form.querySelector(
          'input[type="email"], input[name*="email"], input[id*="email"]'
        ),
      }))
    );

    // Check for suspicious patterns in page source
    const pageSource = document.documentElement.outerHTML;
    const suspiciousPatterns = [
      {
        name: "Microsoft mentions",
        count: (pageSource.match(/microsoft/gi) || []).length,
      },
      {
        name: "Office mentions",
        count: (pageSource.match(/office/gi) || []).length,
      },
      { name: "365 mentions", count: (pageSource.match(/365/gi) || []).length },
      {
        name: "Login mentions",
        count: (pageSource.match(/login/gi) || []).length,
      },
      {
        name: "Password fields",
        count: document.querySelectorAll('input[type="password"]').length,
      },
      {
        name: "Email fields",
        count: document.querySelectorAll('input[type="email"]').length,
      },
    ];
    console.log("Content Analysis:", suspiciousPatterns);

    console.log("=".repeat(50));
    console.log("✅ Analysis complete. Check the results above.");

    return {
      detectionRulesLoaded: !!detectionRules,
      isTrustedDomain: isTrusted,
      isMicrosoftLogin: isMSLogon,
      phishingThreats: phishingResult.threats.length,
      shouldBlock: blockingResult.shouldBlock,
      legitimacyScore: detectionResult.score,
    };
  };

  /**
   * Check if page is Microsoft 365 logon page using categorized detection
   * Requirements: Primary elements are Microsoft-specific, secondary are supporting evidence
   */
  function isMicrosoftLogonPage() {
    try {
      if (!detectionRules?.m365_detection_requirements) {
        logger.error("No M365 detection requirements in rules");
        return false;
      }

      const requirements = detectionRules.m365_detection_requirements;
      const pageSource = document.documentElement.outerHTML;

      let primaryFound = 0;
      let totalWeight = 0;
      let totalElements = 0;
      const foundElementsList = [];
      const missingElementsList = [];

      // Check primary elements (Microsoft-specific)
      const allElements = [
        ...(requirements.primary_elements || []),
        ...(requirements.secondary_elements || []),
      ];

      for (const element of allElements) {
        try {
          let found = false;

          if (element.type === "source_content") {
            const regex = new RegExp(element.pattern, "i");
            found = regex.test(pageSource);
          } else if (element.type === "css_pattern") {
            // Check for CSS patterns in the page source
            found = element.patterns.some((pattern) => {
              const regex = new RegExp(pattern, "i");
              return regex.test(pageSource);
            });

            // Also check external stylesheets if not found in page source
            if (!found) {
              try {
                const styleSheets = Array.from(document.styleSheets);
                found = styleSheets.some((sheet) => {
                  try {
                    if (sheet.cssRules) {
                      const cssText = Array.from(sheet.cssRules)
                        .map((rule) => rule.cssText)
                        .join(" ");
                      return element.patterns.some((pattern) => {
                        const regex = new RegExp(pattern, "i");
                        return regex.test(cssText);
                      });
                    }
                  } catch (corsError) {
                    // CORS blocked - check stylesheet URL for Microsoft patterns
                    if (sheet.href && element.id === "ms_external_css") {
                      const regex = new RegExp(element.patterns[0], "i");
                      return regex.test(sheet.href);
                    }
                  }
                  return false;
                });
              } catch (stylesheetError) {
                logger.debug(
                  `Could not check stylesheets for ${element.id}: ${stylesheetError.message}`
                );
              }
            }
          }

          if (found) {
            totalElements++;
            totalWeight += element.weight || 1;
            if (element.category === "primary") {
              primaryFound++;
            }
            foundElementsList.push(element.id);
            logger.debug(
              `✓ Found ${element.category || "unknown"} element: ${
                element.id
              } (weight: ${element.weight || 1})`
            );
          } else {
            missingElementsList.push(element.id);
            logger.debug(
              `✗ Missing ${element.category || "unknown"} element: ${
                element.id
              }`
            );
          }
        } catch (elementError) {
          logger.warn(
            `Error checking element ${element.id}:`,
            elementError.message
          );
          missingElementsList.push(element.id);
        }
      }

      // New categorized detection logic with flexible thresholds
      const thresholds = requirements.detection_thresholds || {};
      const minPrimary = thresholds.minimum_primary_elements || 1;
      const minWeight = thresholds.minimum_total_weight || 4;
      const minTotal = thresholds.minimum_elements_overall || 3;
      const minSecondaryOnlyWeight =
        thresholds.minimum_secondary_only_weight || 6;
      const minSecondaryOnlyElements =
        thresholds.minimum_secondary_only_elements || 5;

      let isM365Page = false;

      if (primaryFound > 0) {
        // If we have primary elements, use normal thresholds
        isM365Page =
          primaryFound >= minPrimary &&
          totalWeight >= minWeight &&
          totalElements >= minTotal;
      } else {
        // If NO primary elements, require higher secondary evidence
        // This catches phishing simulations while preventing false positives like GitHub
        isM365Page =
          totalWeight >= minSecondaryOnlyWeight &&
          totalElements >= minSecondaryOnlyElements;
      }

      if (primaryFound > 0) {
        logger.log(
          `M365 logon detection (with primary): Primary=${primaryFound}/${minPrimary}, Weight=${totalWeight}/${minWeight}, Total=${totalElements}/${minTotal}`
        );
      } else {
        logger.log(
          `M365 logon detection (secondary only): Weight=${totalWeight}/${minSecondaryOnlyWeight}, Total=${totalElements}/${minSecondaryOnlyElements}`
        );
      }
      logger.log(`Found elements: [${foundElementsList.join(", ")}]`);
      if (missingElementsList.length > 0) {
        logger.log(`Missing elements: [${missingElementsList.join(", ")}]`);
      }

      // Enhanced debugging - show what we're actually looking for
      logger.debug("=== DETECTION DEBUG INFO ===");
      logger.debug(`Page URL: ${window.location.href}`);
      logger.debug(`Page title: ${document.title}`);
      logger.debug(`Page source length: ${pageSource.length} chars`);

      // Debug each pattern individually
      for (const element of allElements) {
        if (element.type === "source_content") {
          const regex = new RegExp(element.pattern, "i");
          const matches = pageSource.match(regex);
          logger.debug(
            `${element.category} pattern "${element.pattern}" -> ${
              matches ? "FOUND" : "NOT FOUND"
            }`
          );
          if (matches) logger.debug(`  Match: "${matches[0]}"`);
        } else if (element.type === "css_pattern") {
          element.patterns.forEach((pattern, idx) => {
            const regex = new RegExp(pattern, "i");
            const matches = pageSource.match(regex);
            logger.debug(
              `${element.category} CSS pattern[${idx}] "${pattern}" -> ${
                matches ? "FOUND" : "NOT FOUND"
              }`
            );
            if (matches) logger.debug(`  Match: "${matches[0]}"`);
          });
        }
      }
      logger.debug("=== END DEBUG INFO ===");

      const resultMessage = isM365Page
        ? "✅ DETECTED as Microsoft 365 logon page"
        : "❌ NOT DETECTED as Microsoft 365 logon page";

      logger.log(`🎯 Detection Result: ${resultMessage}`);

      if (isM365Page) {
        logger.log(
          "📋 Next step: Analyzing if this is legitimate or phishing attempt..."
        );
      } else {
        logger.log(
          "📋 Next step: No further analysis needed - not Microsoft-related"
        );
      }

      return isM365Page;
    } catch (error) {
      logger.error("M365 logon page detection failed:", error.message);
      return false; // Fail closed - don't assume it's MS page if detection fails
    }
  }

  /**
   * Run blocking rules from rule file
   */
  function runBlockingRules() {
    try {
      if (!detectionRules?.blocking_rules) {
        logger.warn("No blocking rules in detection rules");
        return { shouldBlock: false, reason: "No blocking rules available" };
      }

      for (const rule of detectionRules.blocking_rules) {
        try {
          let ruleTriggered = false;
          let reason = "";

          switch (rule.type) {
            case "form_action_validation":
              // Check: form post url is not login.microsoftonline.com -> Block
              const forms = document.querySelectorAll(
                rule.condition?.form_selector || "form"
              );
              for (const form of forms) {
                // Check if form has password field (as specified in condition)
                if (
                  rule.condition?.has_password_field &&
                  !form.querySelector('input[type="password"]')
                ) {
                  continue;
                }

                const action = form.action || location.href;
                const actionContainsMicrosoft = action.includes(
                  rule.condition?.action_must_not_contain || ""
                );

                if (!actionContainsMicrosoft) {
                  ruleTriggered = true;
                  reason = `Form action "${action}" does not contain ${rule.condition?.action_must_not_contain}`;
                  logger.warn(
                    `BLOCKING RULE TRIGGERED: ${rule.id} - ${reason}`
                  );
                  break;
                }
              }
              break;

            case "resource_validation":
              // Check: If "*customcss" is loaded, it must come from https://aadcdn.msftauthimages.net/
              const resourceNodes = document.querySelectorAll(
                "[src], link[rel='stylesheet'][href]"
              );
              for (const node of resourceNodes) {
                const url = node.src || node.href;
                if (!url) continue;

                if (url.includes(rule.condition?.resource_pattern || "")) {
                  const requiredOrigin = rule.condition?.required_origin || "";
                  if (!url.startsWith(requiredOrigin)) {
                    ruleTriggered = true;
                    reason = `Resource "${url}" does not come from required origin "${requiredOrigin}"`;
                    logger.warn(
                      `BLOCKING RULE TRIGGERED: ${rule.id} - ${reason}`
                    );
                    break;
                  }
                }
              }
              break;

            case "css_spoofing_validation":
              // Check: If page has Microsoft CSS patterns but posts to non-Microsoft domain
              const pageSource = document.documentElement.outerHTML;
              let cssMatches = 0;

              // Count CSS indicator matches
              for (const indicator of rule.condition?.css_indicators || []) {
                const regex = new RegExp(indicator, "i");
                if (regex.test(pageSource)) {
                  cssMatches++;
                  logger.debug(`CSS indicator matched: ${indicator}`);
                }
              }

              // Check if we have enough CSS matches
              const minMatches = rule.condition?.minimum_css_matches || 2;
              if (cssMatches >= minMatches) {
                // Check if form posts to non-Microsoft domain
                const credentialForms = document.querySelectorAll("form");
                for (const form of credentialForms) {
                  // Check if form has credential fields
                  if (rule.condition?.has_credential_fields) {
                    const hasEmail = form.querySelector(
                      'input[type="email"], input[name*="email"], input[id*="email"]'
                    );
                    const hasPassword = form.querySelector(
                      'input[type="password"]'
                    );

                    if (!hasEmail && !hasPassword) continue;
                  }

                  const action = form.action || location.href;
                  const actionContainsMicrosoft = action.includes(
                    rule.condition?.form_action_must_not_contain || ""
                  );

                  if (!actionContainsMicrosoft) {
                    ruleTriggered = true;
                    reason = `CSS spoofing detected: ${cssMatches} Microsoft style indicators found, but form posts to "${action}" (not Microsoft)`;
                    logger.warn(
                      `BLOCKING RULE TRIGGERED: ${rule.id} - ${reason}`
                    );
                    break;
                  }
                }
              }
              break;

            default:
              logger.warn(`Unknown blocking rule type: ${rule.type}`);
          }

          if (ruleTriggered) {
            return {
              shouldBlock: true,
              reason: reason,
              rule: rule,
              severity: rule.severity,
            };
          }
        } catch (ruleError) {
          logger.warn(
            `Error processing blocking rule ${rule.id}:`,
            ruleError.message
          );
          // Continue with other rules - don't let one bad rule break everything
        }
      }

      return { shouldBlock: false, reason: "No blocking rules triggered" };
    } catch (error) {
      logger.error("Blocking rules check failed:", error.message);
      // Fail-safe: if we can't check blocking rules, assume we should block
      return {
        shouldBlock: true,
        reason: "Blocking rules check failed - blocking for safety",
        error: error.message,
      };
    }
  }

  /**
   * Setup dynamic script monitoring for obfuscated content
   */
  function setupDynamicScriptMonitoring() {
    try {
      // Override eval to detect dynamic script execution
      const originalEval = window.eval;
      window.eval = function (code) {
        scanDynamicScript(code, "eval");
        return originalEval.call(this, code);
      };

      // Override Function constructor
      const originalFunction = window.Function;
      window.Function = function () {
        const code = arguments[arguments.length - 1];
        scanDynamicScript(code, "Function");
        return originalFunction.apply(this, arguments);
      };

      // Override setTimeout for code execution
      const originalSetTimeout = window.setTimeout;
      window.setTimeout = function (code, delay) {
        if (typeof code === "string") {
          scanDynamicScript(code, "setTimeout");
        }
        return originalSetTimeout.call(this, code, delay);
      };

      // Override setInterval for code execution
      const originalSetInterval = window.setInterval;
      window.setInterval = function (code, delay) {
        if (typeof code === "string") {
          scanDynamicScript(code, "setInterval");
        }
        return originalSetInterval.call(this, code, delay);
      };

      logger.log("🔍 Dynamic script monitoring enabled");
    } catch (error) {
      logger.warn("Failed to setup dynamic script monitoring:", error.message);
    }
  }

  /**
   * Scan dynamically loaded script content using phishing indicators
   */
  function scanDynamicScript(code, source) {
    try {
      if (!code || typeof code !== "string") return;

      // Use phishing indicators to scan dynamic content
      const result = processPhishingIndicators();
      const dynamicResult = {
        threats: [],
        score: 0,
      };

      // Test dynamic code against phishing indicators
      if (detectionRules?.phishing_indicators) {
        for (const indicator of detectionRules.phishing_indicators) {
          try {
            const pattern = new RegExp(
              indicator.pattern,
              indicator.flags || "i"
            );

            if (pattern.test(code)) {
              const threat = {
                id: indicator.id,
                category: indicator.category,
                severity: indicator.severity,
                description: `${indicator.description} (in ${source})`,
                confidence: indicator.confidence,
                action: indicator.action,
                source: source,
              };

              dynamicResult.threats.push(threat);

              logger.warn(
                `🚨 DYNAMIC SCRIPT THREAT: ${indicator.id} detected in ${source}`
              );

              // Take immediate action for critical threats
              if (
                indicator.severity === "critical" &&
                indicator.action === "block"
              ) {
                logger.error(
                  `🛑 Critical dynamic script threat detected - ${indicator.description}`
                );

                // Send alert but don't block as script may already be executing
                showWarningBanner(
                  `CRITICAL: Dynamic script threat detected - ${indicator.description}`,
                  {
                    type: "dynamic_script_threat",
                    severity: "critical",
                    source: source,
                    indicator: indicator.id,
                  }
                );
              }
            }
          } catch (patternError) {
            logger.warn(
              `Error testing dynamic script against ${indicator.id}:`,
              patternError.message
            );
          }
        }
      }

      return dynamicResult;
    } catch (error) {
      logger.warn("Error scanning dynamic script:", error.message);
      return { threats: [], score: 0 };
    }
  }

  /**
   * Check if content contains legitimate SSO patterns
   */
  function checkLegitimateSSO(pageText, pageSource) {
    if (
      !detectionRules?.exclusion_system?.context_indicators
        ?.legitimate_sso_patterns
    ) {
      return false;
    }

    const ssoPatterns =
      detectionRules.exclusion_system.context_indicators
        .legitimate_sso_patterns;
    const combinedText = (pageText + " " + pageSource).toLowerCase();

    return ssoPatterns.some((pattern) =>
      combinedText.includes(pattern.toLowerCase())
    );
  }

  /**
   * Process phishing indicators from detection rules
   */
  function processPhishingIndicators() {
    try {
      // Performance protection: Early exit for major trusted domains to prevent false positives
      const currentUrl = window.location.href;
      const hostname = new URL(currentUrl).hostname.toLowerCase();
      const majorTrustedDomains = [
        'google.com', 'google.co', 'google.ca', 'google.co.uk',
        'bing.com', 'yahoo.com', 'duckduckgo.com', 'ask.com', 'askjeeves.com',
        'baidu.com', 'yandex.com', 'startpage.com', 'searx.org',
        'amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.fr',
        'facebook.com', 'twitter.com', 'x.com', 'linkedin.com', 'instagram.com',
        'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com', 'stackexchange.com',
        'reddit.com', 'wikipedia.org', 'youtube.com', 'youtu.be', 'vimeo.com',
        'apple.com', 'microsoft.com', 'office.com', 'office365.com',
        'dropbox.com', 'slack.com', 'zoom.us', 'teams.microsoft.com', 'discord.com',
        'ebay.com', 'paypal.com', 'stripe.com', 'shopify.com',
        'cnn.com', 'bbc.com', 'nytimes.com', 'theguardian.com', 'reuters.com'
      ];

      for (const domain of majorTrustedDomains) {
        if (hostname.includes(domain)) {
          logger.log(`🚫 Major trusted domain detected (${domain}), skipping phishing indicators`);
          return { threats: [], score: 0 };
        }
      }

      // Debug logging
      logger.log(
        `🔍 processPhishingIndicators: detectionRules available: ${!!detectionRules}`
      );

      if (!detectionRules?.phishing_indicators) {
        logger.warn("No phishing indicators available");
        return { threats: [], score: 0 };
      }

      const threats = [];
      let totalScore = 0;
      const pageSource = document.documentElement.outerHTML;
      const pageText = document.body?.textContent || "";

      // Performance protection: Check for extremely large content that could cause regex hangs
      const LARGE_CONTENT_THRESHOLD = 200000; // 200KB
      const isLargeContent = pageSource.length > LARGE_CONTENT_THRESHOLD || pageText.length > LARGE_CONTENT_THRESHOLD;
      
      if (isLargeContent) {
        logger.log(`⚠️ Large content detected (${pageSource.length} + ${pageText.length} chars), using performance mode`);
      }

      logger.log(
        `🔍 Testing ${detectionRules.phishing_indicators.length} phishing indicators against:`
      );
      logger.log(`   - Page source length: ${pageSource.length} chars`);
      logger.log(`   - Page text length: ${pageText.length} chars`);
      logger.log(`   - Current URL: ${currentUrl}`);
      logger.log(`   - Large content mode: ${isLargeContent}`);

      // Check if current URL matches exclusion patterns
      const isExcludedDomain = checkDomainExclusion(currentUrl);
      const legitimateContext = checkLegitimateContext(pageText, pageSource);

      if (isExcludedDomain && legitimateContext) {
        logger.log(`🚫 Domain excluded from phishing detection: ${currentUrl}`);
        logger.log(
          `📋 Legitimate context detected, skipping phishing indicators`
        );
        return { threats: [], score: 0 };
      }

      // Log first few indicators for debugging
      const firstThree = detectionRules.phishing_indicators.slice(0, 3);
      logger.log("📋 First 3 indicators:");
      firstThree.forEach((ind, i) => {
        logger.log(`   ${i + 1}. ${ind.id}: ${ind.pattern} (${ind.severity})`);
      });

      // Performance protection: Add timeout mechanism
      const startTime = Date.now();
      const PROCESSING_TIMEOUT = isLargeContent ? 1000 : 3000; // Shorter timeout for large content

      for (const indicator of detectionRules.phishing_indicators) {
        // Check if we've exceeded the timeout
        if (Date.now() - startTime > PROCESSING_TIMEOUT) {
          logger.warn(`⏱️ Processing timeout reached after ${Date.now() - startTime}ms, stopping at ${indicator.id}`);
          break;
        }

        try {
          let matches = false;
          let matchDetails = "";
          
          // Performance protection: For large content, use safer detection methods
          if (isLargeContent) {
            // For large content, only test against URL and use simple string matching for content
            const pattern = new RegExp(indicator.pattern, indicator.flags || "i");
            
            // Always test URL (safe)
            if (pattern.test(currentUrl)) {
              matches = true;
              matchDetails = "URL";
            }
            // For large content, use simple string contains instead of regex on content
            else {
              // Extract simple keywords from the pattern for string matching
              const simpleKeywords = extractSimpleKeywords(indicator.pattern);
              for (const keyword of simpleKeywords) {
                if (pageSource.toLowerCase().includes(keyword.toLowerCase()) || 
                    pageText.toLowerCase().includes(keyword.toLowerCase())) {
                  matches = true;
                  matchDetails = "content (simple match)";
                  break;
                }
              }
            }
          } else {
            // Normal processing for smaller content
            const pattern = new RegExp(indicator.pattern, indicator.flags || "i");

            // Test against page source
            if (pattern.test(pageSource)) {
              matches = true;
              matchDetails = "page source";
            }
            // Test against visible text
            else if (pattern.test(pageText)) {
              matches = true;
              matchDetails = "page text";
            }
            // Test against URL
            else if (pattern.test(currentUrl)) {
              matches = true;
              matchDetails = "URL";
            }
          }

          // Special handling for additional_checks (phi_014, phi_015)
          if (!matches && indicator.additional_checks) {
            for (const check of indicator.additional_checks) {
              if (pageSource.includes(check) || pageText.includes(check)) {
                matches = true;
                matchDetails = "additional checks";
                break;
              }
            }
          }

          // Handle context_required field for conditional detection
          if (matches && indicator.context_required) {
            let contextFound = false;

            for (const requiredContext of indicator.context_required) {
              if (
                pageSource
                  .toLowerCase()
                  .includes(requiredContext.toLowerCase()) ||
                pageText.toLowerCase().includes(requiredContext.toLowerCase())
              ) {
                contextFound = true;
                break;
              }
            }

            if (!contextFound) {
              logger.debug(
                `🚫 ${indicator.id} excluded - required context not found`
              );
              matches = false;
            }
          }

          // Apply centralized exclusion logic for social engineering patterns
          if (matches && isExcludedDomain) {
            if (
              indicator.category === "social_engineering" ||
              indicator.category === "brand_impersonation"
            ) {
              // Check if this is legitimate discussion vs actual phishing
              const hasSuspiciousContext = checkSuspiciousContext(pageText);
              const hasCredentialForm = document.querySelector(
                'input[type="password"], input[type="email"]'
              );

              if (
                legitimateContext &&
                !hasSuspiciousContext &&
                !hasCredentialForm
              ) {
                logger.debug(
                  `🚫 ${indicator.id} excluded - legitimate discussion context`
                );
                matches = false;
              }
            }
          }

          // Special handling for Microsoft branding indicators (phi_001_enhanced, phi_002)
          if (
            matches &&
            (indicator.id === "phi_001_enhanced" || indicator.id === "phi_002")
          ) {
            const hasLegitimateSSO = checkLegitimateSSO(pageText, pageSource);

            if (hasLegitimateSSO) {
              logger.debug(
                `🚫 ${indicator.id} excluded - legitimate SSO detected`
              );
              matches = false;
            }
          }

          if (matches) {
            const threat = {
              id: indicator.id,
              category: indicator.category,
              severity: indicator.severity,
              confidence: indicator.confidence,
              description: indicator.description,
              action: indicator.action,
              matchDetails: matchDetails,
            };

            threats.push(threat);

            // Calculate score based on severity and confidence
            let scoreWeight = 0;
            switch (indicator.severity) {
              case "critical":
                scoreWeight = 25;
                break;
              case "high":
                scoreWeight = 15;
                break;
              case "medium":
                scoreWeight = 10;
                break;
              case "low":
                scoreWeight = 5;
                break;
            }

            totalScore += scoreWeight * (indicator.confidence || 0.5);

            logger.warn(
              `🚨 PHISHING INDICATOR DETECTED: ${indicator.id} - ${indicator.description}`
            );
          }
        } catch (error) {
          logger.warn(
            `Error processing phishing indicator ${indicator.id}:`,
            error.message
          );
        }
      }

      const processingTime = Date.now() - startTime;
      logger.log(
        `Phishing indicators check: ${threats.length} threats found, score: ${totalScore} (${processingTime}ms, ${isLargeContent ? 'performance mode' : 'normal mode'})`
      );
      return { threats, score: totalScore };
    } catch (error) {
      logger.error("Error processing phishing indicators:", error.message);
      return { threats: [], score: 0 };
    }
  }

  /**
   * Extract simple keywords from regex patterns for performance-safe matching
   */
  function extractSimpleKeywords(pattern) {
    const keywords = [];
    
    // Extract words that are 3+ characters and not regex operators
    const wordMatches = pattern.match(/[a-zA-Z]{3,}/g);
    if (wordMatches) {
      keywords.push(...wordMatches);
    }
    
    // Extract specific common phishing terms
    const commonTerms = ['microsoft', 'office', 'login', 'secure', 'verify', 'account', 'auth', 'oauth', 'security'];
    for (const term of commonTerms) {
      if (pattern.toLowerCase().includes(term)) {
        keywords.push(term);
      }
    }
    
    // Remove duplicates and return unique keywords
    return [...new Set(keywords)];
  }

  /**
   * Check if domain should be excluded from phishing detection
   */
  function checkDomainExclusion(url) {
    if (!detectionRules?.exclusion_system?.domain_patterns) {
      return false;
    }

    return detectionRules.exclusion_system.domain_patterns.some((pattern) => {
      try {
        const regex = new RegExp(pattern, "i");
        return regex.test(url);
      } catch (error) {
        logger.warn(`Invalid exclusion pattern: ${pattern}`);
        return false;
      }
    });
  }

  /**
   * Check for legitimate context indicators
   */
  function checkLegitimateContext(pageText, pageSource) {
    if (
      !detectionRules?.exclusion_system?.context_indicators?.legitimate_contexts
    ) {
      return false;
    }

    const content = (pageText + " " + pageSource).toLowerCase();
    return detectionRules.exclusion_system.context_indicators.legitimate_contexts.some(
      (context) => {
        return content.includes(context.toLowerCase());
      }
    );
  }

  /**
   * Check for suspicious context indicators that override legitimate exclusions
   */
  function checkSuspiciousContext(pageText) {
    if (
      !detectionRules?.exclusion_system?.context_indicators?.suspicious_contexts
    ) {
      return false;
    }

    const content = pageText.toLowerCase();
    return detectionRules.exclusion_system.context_indicators.suspicious_contexts.some(
      (context) => {
        return content.includes(context.toLowerCase());
      }
    );
  }

  /**
   * Run detection rules from rule file to calculate legitimacy score
   */
  function runDetectionRules() {
    try {
      if (!detectionRules?.rules) {
        logger.warn("No detection rules available");
        return { score: 0, triggeredRules: [], threshold: 85 };
      }

      let score = 0;
      const triggeredRules = [];
      const pageHTML = document.documentElement.outerHTML;

      // Process each rule from the detection rules file
      for (const rule of detectionRules.rules) {
        try {
          let ruleTriggered = false;

          switch (rule.type) {
            case "url":
              if (rule.condition?.domains) {
                ruleTriggered = rule.condition.domains.some(
                  (domain) => location.hostname === domain
                );
              }
              break;

            case "form_action":
              const forms = document.querySelectorAll(
                rule.condition?.form_selector || "form"
              );
              for (const form of forms) {
                const action = form.action || "";
                if (action.includes(rule.condition?.contains || "")) {
                  ruleTriggered = true;
                  break;
                }
              }
              break;

            case "dom":
              if (rule.condition?.selectors) {
                ruleTriggered = rule.condition.selectors.some((selector) => {
                  try {
                    return document.querySelector(selector);
                  } catch {
                    return false;
                  }
                });
              }
              break;

            case "content":
              if (rule.condition?.contains) {
                ruleTriggered = pageHTML.includes(rule.condition.contains);
              }
              break;

            case "network":
              const resourceNodes = document.querySelectorAll(
                "[src], link[rel='stylesheet'][href]"
              );
              for (const node of resourceNodes) {
                const url = node.src || node.href;
                if (!url) continue;

                if (url.includes(rule.condition?.network_pattern || "")) {
                  if (url.startsWith(rule.condition?.required_domain || "")) {
                    ruleTriggered = true;
                  }
                  break;
                }
              }
              break;

            case "referrer_validation":
              if (
                rule.condition?.header_name === "referer" &&
                rule.condition?.validation_method === "pattern_match" &&
                rule.condition?.pattern_source === "microsoft_domain_patterns"
              ) {
                // Check if referrer exists and matches Microsoft domain patterns
                const referrer = document.referrer;
                if (referrer) {
                  ruleTriggered = isMicrosoftDomain(referrer);
                  logger.debug(
                    `Referrer validation: ${referrer} -> ${
                      ruleTriggered ? "VALID" : "INVALID"
                    }`
                  );
                } else {
                  // No referrer header - this could be suspicious for redirected login flows
                  ruleTriggered = false;
                  logger.debug("Referrer validation: No referrer header found");
                }
              }
              break;

            default:
              logger.warn(`Unknown rule type: ${rule.type}`);
          }

          if (ruleTriggered) {
            score += rule.weight || 0;
            triggeredRules.push({
              id: rule.id,
              type: rule.type,
              description: rule.description,
              weight: rule.weight,
            });
            logger.debug(`Rule triggered: ${rule.id} (weight: ${rule.weight})`);
          }
        } catch (ruleError) {
          logger.warn(`Error processing rule ${rule.id}:`, ruleError.message);
          // Continue with other rules - don't let one bad rule break everything
        }
      }

      const threshold = detectionRules.thresholds?.legitimate || 85;

      logger.log(
        `Detection rules: score=${score}, threshold=${threshold}, triggered=${triggeredRules.length} rules`
      );

      return {
        score: score,
        triggeredRules: triggeredRules,
        threshold: threshold,
      };
    } catch (error) {
      logger.error("Detection rules processing failed:", error.message);
      // Fail-safe: return low score (suspicious)
      return {
        score: 0,
        triggeredRules: [],
        threshold: 85,
        error: error.message,
      };
    }
  }

  /**
   * Main protection logic following CORRECTED specification
   */
  async function runProtection(isRerun = false) {
    try {
      logger.log(
        `🚀 Starting protection analysis ${isRerun ? "(re-run)" : "(initial)"}`
      );
      logger.log(
        `📄 Page info: ${document.querySelectorAll("*").length} elements, ${
          document.body?.textContent?.length || 0
        } chars content`
      );

      // Load configuration to check protection settings
      const config = await new Promise((resolve) => {
        chrome.storage.local.get(["config"], (result) => {
          resolve(result.config || {});
        });
      });

      // Check if page blocking is disabled
      const protectionEnabled = config.enablePageBlocking !== false;
      if (!protectionEnabled) {
        logger.log(
          "Page blocking disabled in settings - running analysis only (no protective action)"
        );
      } else {
        logger.log("Page blocking enabled - full protection active");
      }

      // Prevent excessive runs but allow re-runs for DOM changes
      if (protectionActive && !isRerun) {
        logger.debug("Protection already active");
        return;
      }

      // Rate limiting for DOM change re-runs
      if (isRerun) {
        const now = Date.now();
        if (now - lastScanTime < SCAN_COOLDOWN || scanCount >= MAX_SCANS) {
          logger.debug("Scan rate limited or max scans reached");
          return;
        }
        lastScanTime = now;
        scanCount++;
      } else {
        protectionActive = true;
        scanCount = 1;
      }

      logger.log(
        `Starting rule-driven Microsoft 365 protection (scan #${scanCount}), protection ${
          protectionEnabled ? "ENABLED" : "DISABLED"
        }`
      );

      // Clear existing security UI when re-running protection due to DOM changes
      if (isRerun) {
        clearSecurityUI();
      }

      // Step 0: Load developer console logging setting (affects all subsequent logging)
      await loadDeveloperConsoleLoggingSetting();

      // Step 1: Load detection rules (everything comes from here)
      if (!detectionRules) {
        detectionRules = await loadDetectionRules();
      }

      // Safety check: Ensure trusted login patterns are properly loaded
      if (trustedLoginPatterns.length === 0) {
        logger.warn(
          "Trusted login patterns not loaded, reloading detection rules..."
        );
        detectionRules = await loadDetectionRules();
        if (trustedLoginPatterns.length === 0) {
          logger.error(
            "CRITICAL: Failed to load trusted login patterns after reload!"
          );
          logger.error(
            "This will cause all Microsoft login domains to be flagged as non-trusted"
          );
        } else {
          logger.log(
            `✅ Successfully loaded ${trustedLoginPatterns.length} trusted login patterns on retry`
          );
        }
      }

      // Step 2: FIRST CHECK - trusted origins and Microsoft domains
      const currentOrigin = location.origin.toLowerCase();

      // Debug logging for domain detection
      logger.debug(`Checking origin: "${currentOrigin}"`);
      logger.debug(`Trusted login patterns:`, trustedLoginPatterns);
      logger.debug(`Microsoft domain patterns:`, microsoftDomainPatterns);
      logger.debug(
        `Is trusted login domain: ${isTrustedLoginDomain(window.location.href)}`
      );
      logger.debug(
        `Is Microsoft domain: ${isMicrosoftDomain(window.location.href)}`
      );

      // Check for trusted login domains (these get valid badges)
      if (isTrustedLoginDomain(window.location.href)) {
        logger.log(
          "✅ TRUSTED ORIGIN - No phishing possible, exiting immediately"
        );

        // Store initial detection result (may be overridden if rogue app found)
        lastDetectionResult = {
          verdict: "trusted",
          isSuspicious: false,
          isBlocked: false,
          threats: [],
          reason: "Trusted Microsoft domain",
          score: 100,
          threshold: 85,
        };

        try {
          const redirectHostname = extractRedirectHostname(location.href);
          const clientInfo = await extractClientInfo(location.href);

          // Check for rogue apps even on legitimate Microsoft domains
          if (clientInfo.isMalicious) {
            logger.warn(
              `🚨 ROGUE OAUTH APP DETECTED ON LEGITIMATE MICROSOFT DOMAIN: ${clientInfo.reason}`
            );

            // Override detection result for rogue app
            lastDetectionResult = {
              verdict: "rogue-app",
              isSuspicious: true,
              isBlocked: false,
              threats: [
                {
                  type: "rogue-oauth-app",
                  description: `Rogue OAuth application: ${clientInfo.reason}`,
                },
              ],
              reason: `Rogue OAuth application detected: ${clientInfo.reason}`,
              score: 0, // Critical threat gets lowest score
              threshold: 85,
            };

            // Notify background script about rogue app detection
            try {
              const response = await chrome.runtime.sendMessage({
                type: "FLAG_ROGUE_APP",
                clientId: clientInfo.clientId,
                appName: clientInfo.appInfo?.appName || "Unknown",
                reason: clientInfo.reason,
              });

              if (response?.ok) {
                logger.log(
                  "✅ Background script notified about rogue app, badge should update"
                );
              } else {
                logger.warn(
                  "⚠️ Background script rogue app notification failed:",
                  response
                );
              }
            } catch (messageError) {
              logger.warn(
                "Failed to notify background about rogue app:",
                messageError
              );
            }
            const appName = clientInfo.appName || "Unknown Application";
            showWarningBanner(
              `CRITICAL WARNING: Rogue OAuth Application Detected - ${appName}`,
              {
                type: "rogue_app_on_legitimate_domain",
                severity: "critical",
                reason: clientInfo.reason,
                clientId: clientInfo.clientId,
                appInfo: clientInfo.appInfo,
              }
            );

            // Log as a threat event instead of legitimate access
            logProtectionEvent({
              type: "threat_detected",
              action: "warned", // Rogue apps are warned about, not blocked
              url: location.href,
              origin: currentOrigin,
              reason: `Rogue OAuth application detected: ${clientInfo.reason}`,
              severity: "critical",
              redirectTo: redirectHostname,
              clientId: clientInfo.clientId,
              appName: clientInfo.appInfo?.appName || "Unknown",
              ruleType: "rogue_app_detection",
            });

            // Send critical CIPP alert
            sendCippReport({
              type: "critical_rogue_app_detected",
              url: location.href,
              origin: currentOrigin,
              clientId: clientInfo.clientId,
              appName: clientInfo.appInfo?.appName || "Unknown",
              reason: clientInfo.reason,
              severity: "critical",
              redirectTo: redirectHostname,
            });

            return; // Stop processing - do NOT show valid badge for rogue apps
          }

          // Only show valid badge if no rogue app detected
          if (protectionEnabled) {
            // Ask background script to show valid badge (it will check if the setting is enabled)
            chrome.runtime.sendMessage(
              { type: "REQUEST_SHOW_VALID_BADGE" },
              (response) => {
                if (response?.success) {
                  logger.log(
                    "📋 VALID BADGE: Background script will handle badge display"
                  );
                }
              }
            );
          }

          // Normal legitimate access logging if no rogue app detected (only on first run)
          if (!isRerun) {
            logProtectionEvent({
              type: "legitimate_access",
              url: location.href,
              origin: currentOrigin,
              reason: "Trusted Microsoft domain",
              redirectTo: redirectHostname,
              clientId: clientInfo.clientId,
              clientSuspicious: clientInfo.isMalicious,
              clientReason: clientInfo.reason,
            });
          }

          // Send CIPP reporting if enabled
          sendCippReport({
            type: "microsoft_logon_detected",
            url: location.href,
            origin: currentOrigin,
            legitimate: true,
            timestamp: new Date().toISOString(),
          });
        } catch (badgeError) {
          logger.warn("Failed to show valid badge:", badgeError.message);
        }

        // Set up minimal monitoring even on trusted domains
        if (!isRerun) {
          setupDOMMonitoring();
          setupDynamicScriptMonitoring();
        }

        return; // EXIT IMMEDIATELY - can't be phishing on trusted domain
      }

      // Check for general Microsoft domains (non-login pages)
      if (isMicrosoftDomain(window.location.href)) {
        logger.log(
          "ℹ️ MICROSOFT DOMAIN (NON-LOGIN) - No phishing scan needed, no badge shown"
        );

        // Log as legitimate Microsoft access (but not login page)
        logProtectionEvent({
          type: "legitimate_access",
          url: location.href,
          origin: currentOrigin,
          reason: "Legitimate Microsoft domain (non-login page)",
          redirectTo: null,
          clientId: null,
          clientSuspicious: false,
          clientReason: null,
        });

        // Don't show any badge for general Microsoft pages
        // Just exit silently - these are legitimate but not login pages
        return; // EXIT - legitimate Microsoft domain, no scanning needed
      }

      logger.log("❌ NON-TRUSTED ORIGIN - Continuing analysis");
      logger.debug(`Origin "${currentOrigin}" not in trusted login patterns`);
      logger.debug(
        `Expected to match pattern like: "^https://login\\.microsoftonline\\.com$"`
      );
      logger.debug(
        `Trusted login patterns loaded: ${
          trustedLoginPatterns.length > 0 ? "YES" : "NO"
        }`
      );

      // Step 3: Pre-check domain for obvious non-threats only
      // NOTE: We removed the restrictive domain check that was blocking training platforms
      // like KnowBe4. Phishing simulations use legitimate domains but copy Microsoft UI.
      // Let content-based detection handle all cases.
      const currentDomain = new URL(
        window.location.href
      ).hostname.toLowerCase();

      logger.debug(
        `Analyzing domain "${currentDomain}" - proceeding with content-based detection`
      );

      // Step 4: Check if page is an MS logon page (using rule file requirements)
      const isMSLogon = isMicrosoftLogonPage();
      if (!isMSLogon) {
        logger.log(
          "❌ NOT DETECTED as Microsoft logon page - checking for phishing indicators anyway"
        );

        // Even if not detected as Microsoft login page, check for phishing indicators
        // This catches attempts that don't perfectly mimic Microsoft but still contain threats
        const phishingResult = processPhishingIndicators();

        if (phishingResult.threats.length > 0) {
          logger.warn(
            `🚨 PHISHING INDICATORS FOUND on non-Microsoft page: ${phishingResult.threats.length} threats`
          );

          // Check for critical threats that should be blocked regardless
          const criticalThreats = phishingResult.threats.filter(
            (t) => t.severity === "critical" && t.action === "block"
          );

          if (criticalThreats.length > 0) {
            const reason = `Critical phishing indicators detected on non-Microsoft page: ${criticalThreats
              .map((t) => t.id)
              .join(", ")}`;

            // Store detection result
            lastDetectionResult = {
              verdict: "blocked",
              isSuspicious: true,
              isBlocked: protectionEnabled,
              threats: criticalThreats.map((t) => ({
                type: t.category,
                description: t.description,
                confidence: t.confidence,
              })),
              reason: reason,
              score: 0, // Critical threats get lowest score
              threshold: 85,
              phishingIndicators: criticalThreats.map((t) => t.id),
            };

            if (protectionEnabled) {
              logger.error(
                "🛡️ PROTECTION ACTIVE: Blocking page due to critical phishing indicators"
              );
              showBlockingOverlay(reason, {
                threats: criticalThreats,
                score: phishingResult.score,
              });
              disableFormSubmissions();
              disableCredentialInputs();
              stopDOMMonitoring();
            } else {
              logger.warn(
                "⚠️ PROTECTION DISABLED: Would block critical threats but showing warning banner instead"
              );
              showWarningBanner(`CRITICAL THREATS DETECTED: ${reason}`, {
                threats: criticalThreats,
              });
              if (!isRerun) {
                setupDOMMonitoring();
                setupDynamicScriptMonitoring();
              }
            }

            const redirectHostname = extractRedirectHostname(location.href);
            const clientInfo = await extractClientInfo(location.href);

            logProtectionEvent({
              type: protectionEnabled
                ? "threat_blocked"
                : "threat_detected_no_action",
              url: location.href,
              reason: reason,
              severity: "critical",
              protectionEnabled: protectionEnabled,
              redirectTo: redirectHostname,
              clientId: clientInfo.clientId,
              clientSuspicious: clientInfo.isMalicious,
              clientReason: clientInfo.reason,
              phishingIndicators: criticalThreats.map((t) => t.id),
            });

            sendCippReport({
              type: "critical_phishing_blocked",
              url: location.href,
              reason: reason,
              severity: "critical",
              legitimate: false,
              timestamp: new Date().toISOString(),
              phishingIndicators: criticalThreats.map((t) => t.id),
            });

            return;
          }

          // Handle non-critical threats (warnings)
          const warningThreats = phishingResult.threats.filter(
            (t) => t.action === "warn" || t.severity !== "critical"
          );

          if (warningThreats.length > 0) {
            const reason = `Suspicious phishing indicators detected: ${warningThreats
              .map((t) => t.id)
              .join(", ")}`;

            // Store detection result
            lastDetectionResult = {
              verdict: "suspicious",
              isSuspicious: true,
              isBlocked: false,
              threats: warningThreats.map((t) => ({
                type: t.category,
                description: t.description,
                confidence: t.confidence,
              })),
              reason: reason,
              score: 50, // Medium suspicion score
              threshold: 85,
              phishingIndicators: warningThreats.map((t) => t.id),
            };

            logger.warn(
              `⚠️ SUSPICIOUS CONTENT: Showing warning for phishing indicators`
            );
            showWarningBanner(`SUSPICIOUS CONTENT DETECTED: ${reason}`, {
              threats: warningThreats,
            });

            const redirectHostname = extractRedirectHostname(location.href);
            const clientInfo = await extractClientInfo(location.href);

            logProtectionEvent({
              type: "threat_detected_no_action",
              url: location.href,
              reason: reason,
              severity: "medium",
              protectionEnabled: protectionEnabled,
              redirectTo: redirectHostname,
              clientId: clientInfo.clientId,
              clientSuspicious: clientInfo.isMalicious,
              clientReason: clientInfo.reason,
              phishingIndicators: warningThreats.map((t) => t.id),
            });

            sendCippReport({
              type: "suspicious_content_detected",
              url: location.href,
              reason: reason,
              severity: "medium",
              legitimate: false,
              timestamp: new Date().toISOString(),
              phishingIndicators: warningThreats.map((t) => t.id),
            });

            // Continue monitoring for suspicious pages
            if (!isRerun) {
              setupDOMMonitoring();
              setupDynamicScriptMonitoring();
            }

            return;
          }
        }

        // No phishing indicators found - page appears legitimate
        logger.log(
          `✅ Page analysis result: Site appears legitimate (not Microsoft-related, no phishing indicators)`
        );

        // Notify background script that analysis concluded site is safe
        try {
          chrome.runtime.sendMessage({
            type: "UPDATE_VERDICT_TO_SAFE",
            url: location.href,
            origin: location.origin,
            reason:
              "Not a Microsoft login page and no phishing indicators detected",
            analysis: true,
            legitimacyScore: 100,
            threshold: 85,
          });
        } catch (updateError) {
          logger.warn(
            "Failed to update background verdict:",
            updateError.message
          );
        }

        // Set up monitoring in case content loads later
        if (!isRerun) {
          setupDOMMonitoring();
          setupDynamicScriptMonitoring();
        }

        return;
      }

      logger.warn(
        "🚨 MICROSOFT LOGON PAGE DETECTED ON NON-TRUSTED DOMAIN - ANALYZING THREAT"
      );
      logger.log(
        "🔍 Beginning security analysis for potential phishing attempt..."
      );

      // Extract client info and redirect hostname for analysis
      const redirectHostname = extractRedirectHostname(location.href);
      const clientInfo = await extractClientInfo(location.href);

      // Notify background script that this is a Microsoft login page on unknown domain
      try {
        chrome.runtime.sendMessage({
          type: "FLAG_MS_LOGIN_ON_UNKNOWN_DOMAIN",
          url: location.href,
          origin: location.origin,
          redirectTo: redirectHostname,
          clientId: clientInfo.clientId,
          clientSuspicious: clientInfo.isMalicious,
          clientReason: clientInfo.reason,
        });

        // Check for rogue apps even on non-trusted domains with Microsoft login pages
        if (clientInfo.isMalicious) {
          logger.warn(
            `🚨 ROGUE OAUTH APP DETECTED ON MICROSOFT LOGIN PAGE: ${clientInfo.reason}`
          );

          // Notify background script about rogue app detection
          try {
            const response = await chrome.runtime.sendMessage({
              type: "FLAG_ROGUE_APP",
              clientId: clientInfo.clientId,
              appName: clientInfo.appInfo?.appName || "Unknown",
              reason: clientInfo.reason,
            });

            if (response?.ok) {
              logger.log(
                "✅ Background script notified about rogue app, badge should update"
              );
            } else {
              logger.warn(
                "⚠️ Background script rogue app notification failed:",
                response
              );
            }
          } catch (rogueMessageError) {
            logger.warn(
              "Failed to notify background about rogue app:",
              rogueMessageError
            );
          }

          const appName = clientInfo.appName || "Unknown Application";
          showWarningBanner(
            `CRITICAL WARNING: Rogue OAuth Application Detected - ${appName}`,
            {
              type: "rogue_app_on_legitimate_domain",
              severity: "critical",
              reason: clientInfo.reason,
              clientId: clientInfo.clientId,
              appInfo: clientInfo.appInfo,
            }
          );

          // Log as a critical threat event
          logProtectionEvent({
            type: "threat_detected",
            action: "warned", // Rogue apps are warned about, not blocked
            url: location.href,
            origin: location.origin,
            reason: `Rogue OAuth application detected: ${clientInfo.reason}`,
            severity: "critical",
            redirectTo: redirectHostname,
            clientId: clientInfo.clientId,
            clientSuspicious: clientInfo.isMalicious,
            clientReason: clientInfo.reason,
            ruleType: "rogue_app_detection",
          });

          // Send critical CIPP alert
          sendCippReport({
            type: "critical_rogue_app_detected",
            url: location.href,
            origin: location.origin,
            clientId: clientInfo.clientId,
            appName: clientInfo.appInfo?.appName || "Unknown",
            reason: clientInfo.reason,
            severity: "critical",
            redirectTo: redirectHostname,
          });

          // Store detection result as critical threat
          lastDetectionResult = {
            verdict: "rogue-app",
            isSuspicious: true,
            isBlocked: false, // Rogue apps get warnings, not blocks
            threats: [
              {
                type: "rogue-oauth-app",
                description: `Rogue OAuth application: ${clientInfo.reason}`,
              },
            ],
            reason: `Rogue OAuth application detected: ${clientInfo.reason}`,
            score: 0, // Critical threat gets lowest score
            threshold: 85,
          };

          return; // Stop processing as this is now treated as a critical threat
        }
      } catch (messageError) {
        logger.warn(
          "Failed to notify background of MS login detection:",
          messageError.message
        );
      }

      // Step 4: Check blocking rules first (immediate blocking conditions)
      const blockingResult = runBlockingRules();
      if (blockingResult.shouldBlock) {
        logger.error(
          `🛡️ ANALYSIS: Page should be BLOCKED - ${blockingResult.reason}`
        );

        // Store detection result
        lastDetectionResult = {
          verdict: "blocked",
          isSuspicious: true,
          isBlocked: protectionEnabled,
          threats: [
            {
              type: "phishing-detected",
              description: blockingResult.reason,
            },
          ],
          reason: blockingResult.reason,
          score: 0,
          threshold: blockingResult.threshold || 85,
          rule: blockingResult.rule,
        };

        if (protectionEnabled) {
          logger.error(
            "🛡️ PROTECTION ACTIVE: Blocking page and disabling inputs"
          );
          showBlockingOverlay(blockingResult.reason, blockingResult);
          disableFormSubmissions();
          disableCredentialInputs();
          stopDOMMonitoring(); // Stop monitoring once we've blocked
        } else {
          logger.warn(
            "⚠️ PROTECTION DISABLED: Would block but showing warning banner instead"
          );
          showWarningBanner(
            `THREAT DETECTED: ${blockingResult.reason}`,
            blockingResult
          );
          // Continue monitoring even when protection disabled to track changes
          if (!isRerun) {
            setupDOMMonitoring();
            setupDynamicScriptMonitoring();
          }
        }

        const redirectHostname = extractRedirectHostname(location.href);
        const clientInfo = await extractClientInfo(location.href);

        logProtectionEvent({
          type: protectionEnabled
            ? "threat_blocked"
            : "threat_detected_no_action",
          url: location.href,
          reason: blockingResult.reason,
          rule: blockingResult.rule?.id,
          severity: blockingResult.severity,
          protectionEnabled: protectionEnabled,
          redirectTo: redirectHostname,
          clientId: clientInfo.clientId,
          clientSuspicious: clientInfo.isMalicious,
          clientReason: clientInfo.reason,
        });

        // Send CIPP reporting if enabled
        sendCippReport({
          type: "phishing_blocked",
          url: location.href,
          reason: blockingResult.reason,
          rule: blockingResult.rule?.id,
          severity: blockingResult.severity,
          legitimate: false,
          timestamp: new Date().toISOString(),
        });

        // Stop monitoring once we've blocked
        stopDOMMonitoring();
        return;
      }

      // Step 5: Run phishing indicators analysis
      const phishingResult = processPhishingIndicators();

      // Step 6: No immediate blocking - run detection rules for legitimacy scoring
      const detectionResult = runDetectionRules();

      // Combine scores from detection rules and phishing indicators
      const combinedScore = detectionResult.score - phishingResult.score; // Subtract phishing score from legitimacy
      const allThreats = [...phishingResult.threats];

      // Check for critical phishing indicators first
      const criticalThreats = phishingResult.threats.filter(
        (t) => t.severity === "critical" && t.action === "block"
      );

      if (criticalThreats.length > 0) {
        const reason = `Critical phishing indicators detected: ${criticalThreats
          .map((t) => t.id)
          .join(", ")}`;

        // Store detection result
        lastDetectionResult = {
          verdict: "blocked",
          isSuspicious: true,
          isBlocked: protectionEnabled,
          threats: criticalThreats.map((t) => ({
            type: t.category,
            description: t.description,
            confidence: t.confidence,
          })),
          reason: reason,
          score: 0, // Critical threats get lowest score
          threshold: detectionResult.threshold,
          phishingIndicators: criticalThreats.map((t) => t.id),
        };

        if (protectionEnabled) {
          logger.error(
            "🛡️ PROTECTION ACTIVE: Blocking page due to critical phishing indicators"
          );
          showBlockingOverlay(reason, {
            threats: criticalThreats,
            score: phishingResult.score,
          });
          disableFormSubmissions();
          disableCredentialInputs();
          stopDOMMonitoring();
        } else {
          logger.warn(
            "⚠️ PROTECTION DISABLED: Would block critical threats but showing warning banner instead"
          );
          showWarningBanner(`CRITICAL THREATS DETECTED: ${reason}`, {
            threats: criticalThreats,
          });
          if (!isRerun) {
            setupDOMMonitoring();
            setupDynamicScriptMonitoring();
          }
        }

        const redirectHostname = extractRedirectHostname(location.href);
        const clientInfo = await extractClientInfo(location.href);

        logProtectionEvent({
          type: protectionEnabled
            ? "threat_blocked"
            : "threat_detected_no_action",
          url: location.href,
          reason: reason,
          severity: "critical",
          protectionEnabled: protectionEnabled,
          redirectTo: redirectHostname,
          clientId: clientInfo.clientId,
          clientSuspicious: clientInfo.isMalicious,
          clientReason: clientInfo.reason,
          phishingIndicators: criticalThreats.map((t) => t.id),
        });

        sendCippReport({
          type: "critical_phishing_blocked",
          url: location.href,
          reason: reason,
          severity: "critical",
          legitimate: false,
          timestamp: new Date().toISOString(),
          phishingIndicators: criticalThreats.map((t) => t.id),
        });

        return;
      }

      // Determine action based on combined legitimacy score
      if (combinedScore < detectionResult.threshold) {
        const severity =
          combinedScore < detectionResult.threshold * 0.3 ? "high" : "medium";
        const reason = `Low legitimacy score: ${combinedScore}/${
          detectionResult.threshold
        }${
          phishingResult.threats.length > 0
            ? `, phishing indicators: ${phishingResult.threats.length}`
            : ""
        }`;

        // Store detection result
        lastDetectionResult = {
          verdict: severity === "high" ? "blocked" : "suspicious",
          isSuspicious: true,
          isBlocked: protectionEnabled && severity === "high",
          threats: [
            {
              type: severity === "high" ? "high-threat" : "medium-threat",
              description: reason,
            },
            ...allThreats.map((t) => ({
              type: t.category,
              description: t.description,
              confidence: t.confidence,
            })),
          ],
          reason: reason,
          score: combinedScore,
          threshold: detectionResult.threshold,
          triggeredRules: detectionResult.triggeredRules,
          phishingIndicators: phishingResult.threats.map((t) => t.id),
        };

        if (severity === "high") {
          logger.warn(`🚨 ANALYSIS: HIGH THREAT detected - ${reason}`);
          if (protectionEnabled) {
            logger.error(
              "🛡️ PROTECTION ACTIVE: Blocking page due to high threat"
            );
            showBlockingOverlay(reason, detectionResult);
            disableFormSubmissions();
            disableCredentialInputs();
            stopDOMMonitoring(); // Stop monitoring once blocked
          } else {
            logger.warn(
              "⚠️ PROTECTION DISABLED: Would block high threat but showing warning banner instead"
            );
            showWarningBanner(
              `HIGH THREAT DETECTED: ${reason}`,
              detectionResult
            );
            if (!isRerun) {
              setupDOMMonitoring();
              setupDynamicScriptMonitoring();
            }
          }
        } else {
          logger.warn(`⚠️ ANALYSIS: MEDIUM THREAT detected - ${reason}`);
          if (protectionEnabled) {
            logger.warn("🛡️ PROTECTION ACTIVE: Showing warning banner");
            showWarningBanner(reason, detectionResult);
          } else {
            logger.warn(
              "⚠️ PROTECTION DISABLED: Showing warning banner for medium threat"
            );
            showWarningBanner(
              `MEDIUM THREAT DETECTED: ${reason}`,
              detectionResult
            );
          }
          // Continue monitoring for medium threats regardless of protection status
          if (!isRerun) {
            setupDOMMonitoring();
            setupDynamicScriptMonitoring();
          }
        }

        const redirectHostname = extractRedirectHostname(location.href);
        const clientInfo = await extractClientInfo(location.href);

        logProtectionEvent({
          type: protectionEnabled
            ? "threat_detected"
            : "threat_detected_no_action",
          url: location.href,
          threatLevel: severity,
          reason: reason,
          score: detectionResult.score,
          threshold: detectionResult.threshold,
          triggeredRules: detectionResult.triggeredRules,
          protectionEnabled: protectionEnabled,
          redirectTo: redirectHostname,
          clientId: clientInfo.clientId,
          clientSuspicious: clientInfo.isMalicious,
          clientReason: clientInfo.reason,
        });

        // Send CIPP reporting if enabled
        sendCippReport({
          type: "suspicious_logon_detected",
          url: location.href,
          threatLevel: severity,
          reason: reason,
          score: detectionResult.score,
          threshold: detectionResult.threshold,
          legitimate: false,
          timestamp: new Date().toISOString(),
        });
      } else {
        logger.log(
          `✅ ANALYSIS: Legitimacy score acceptable (${detectionResult.score}/${detectionResult.threshold}) - no threats detected`
        );

        // Store detection result
        lastDetectionResult = {
          verdict: "safe",
          isSuspicious: false,
          isBlocked: false,
          threats: [],
          reason: "Legitimacy score acceptable",
          score: detectionResult.score,
          threshold: detectionResult.threshold,
        };

        // Log legitimate access for non-trusted domains that pass analysis (only on first run)
        if (!isRerun) {
          try {
            logProtectionEvent({
              type: "legitimate_access",
              url: location.href,
              origin: location.origin,
              reason: `Microsoft login page on non-trusted domain passed analysis (score: ${detectionResult.score}/${detectionResult.threshold})`,
              redirectTo: redirectHostname,
              clientId: clientInfo.clientId,
              clientSuspicious: clientInfo.isMalicious,
              clientReason: clientInfo.reason,
              legitimacyScore: detectionResult.score,
              threshold: detectionResult.threshold,
            });
          } catch (logError) {
            logger.warn("Failed to log legitimate access:", logError);
          }
        }

        // Send CIPP reporting for legitimate access on non-trusted domain
        sendCippReport({
          type: "microsoft_logon_detected",
          url: location.href,
          origin: location.origin,
          legitimate: true,
          nonTrustedDomain: true,
          legitimacyScore: detectionResult.score,
          threshold: detectionResult.threshold,
          clientId: clientInfo.clientId,
          redirectTo: redirectHostname,
          timestamp: new Date().toISOString(),
        });

        // Notify background script that analysis concluded site is legitimate
        try {
          chrome.runtime.sendMessage({
            type: "UPDATE_VERDICT_TO_SAFE",
            url: location.href,
            origin: location.origin,
            reason: `Passed security analysis (score: ${detectionResult.score}/${detectionResult.threshold})`,
            analysis: true,
            legitimacyScore: detectionResult.score,
            threshold: detectionResult.threshold,
          });
        } catch (updateError) {
          logger.warn(
            "Failed to update background verdict:",
            updateError.message
          );
        }

        // Continue monitoring in case content changes
        if (!isRerun) {
          setupDOMMonitoring();
          setupDynamicScriptMonitoring();
        }
      }
    } catch (error) {
      logger.error("Protection failed:", error.message);

      // Emergency fallback - if we can't load rules but detect MS elements, warn user
      try {
        const hasBasicMSElements =
          document.querySelector('input[name="loginfmt"]') ||
          document.querySelector("#i0116");
        const isNotMSDomain = !location.hostname.includes(
          "microsoftonline.com"
        );

        if (hasBasicMSElements && isNotMSDomain) {
          showFallbackWarning();
        }
      } catch (fallbackError) {
        logger.error("Even fallback protection failed:", fallbackError.message);
      }
    }
  }

  /**
   * Set up DOM monitoring to catch delayed phishing content
   */
  function setupDOMMonitoring() {
    try {
      // Don't set up multiple observers
      if (domObserver) {
        return;
      }

      logger.log("Setting up DOM monitoring for delayed content");
      logger.log(
        `Current page has ${document.querySelectorAll("*").length} elements`
      );
      logger.log(`Page title: "${document.title}"`);
      logger.log(
        `Body content length: ${document.body?.textContent?.length || 0} chars`
      );

      domObserver = new MutationObserver((mutations) => {
        try {
          let shouldRerun = false;
          let newElementsAdded = false;

          // Check if any significant changes occurred
          for (const mutation of mutations) {
            if (mutation.type === "childList") {
              // Check for added forms, inputs, or scripts
              for (const node of mutation.addedNodes) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                  newElementsAdded = true;
                  const tagName = node.tagName?.toLowerCase();
                  if (
                    tagName === "form" ||
                    tagName === "input" ||
                    tagName === "script"
                  ) {
                    shouldRerun = true;
                    logger.debug(
                      `DOM change detected: ${tagName} element added`
                    );
                    break;
                  }

                  // Check for Microsoft-related content being added
                  if (
                    node.textContent &&
                    (node.textContent.includes("loginfmt") ||
                      node.textContent.includes("idPartnerPL") ||
                      node.textContent.includes("Microsoft") ||
                      node.textContent.includes("Office 365"))
                  ) {
                    shouldRerun = true;
                    logger.debug(
                      "DOM change detected: Microsoft-related content added"
                    );
                    break;
                  }
                }
              }
            }

            if (shouldRerun) break;
          }

          if (shouldRerun && !showingBanner) {
            logger.log(
              "🔄 Significant DOM changes detected - re-running protection analysis"
            );
            logger.log(
              `Page now has ${document.querySelectorAll("*").length} elements`
            );
            // Debounce re-runs
            setTimeout(() => {
              runProtection(true);
            }, 500);
          } else if (showingBanner) {
            logger.debug(
              "🚫 Ignoring DOM changes while banner is being displayed"
            );
          } else if (newElementsAdded) {
            logger.debug(
              "🔍 DOM changes detected but not significant enough to re-run analysis"
            );
          }
        } catch (observerError) {
          logger.warn("DOM observer error:", observerError.message);
        }
      });

      // Start observing
      domObserver.observe(document.documentElement, {
        childList: true,
        subtree: true,
        attributes: false, // Don't monitor attributes to reduce noise
      });

      // Fallback: Check periodically for content that might have loaded without triggering observer
      const checkInterval = setInterval(() => {
        if (showingBanner) {
          logger.debug(
            "🚫 Fallback timer skipping check while banner is displayed"
          );
          return;
        }

        const currentElementCount = document.querySelectorAll("*").length;
        const hasSignificantContent = document.body?.textContent?.length > 1000;

        if (hasSignificantContent && currentElementCount > 50) {
          logger.log(
            "⏰ Fallback timer detected significant content - re-running analysis"
          );
          clearInterval(checkInterval);
          runProtection(true);
        }
      }, 2000);

      // Stop monitoring after 30 seconds to prevent resource drain
      setTimeout(() => {
        clearInterval(checkInterval);
        stopDOMMonitoring();
        logger.log("🛑 DOM monitoring timeout reached - stopping");
      }, 30000);
    } catch (error) {
      logger.error("Failed to set up DOM monitoring:", error.message);
    }
  }

  /**
   * Stop DOM monitoring
   */
  function stopDOMMonitoring() {
    try {
      if (domObserver) {
        domObserver.disconnect();
        domObserver = null;
        logger.log("DOM monitoring stopped");
      }
    } catch (error) {
      logger.error("Failed to stop DOM monitoring:", error.message);
    }
  }

  /**
   * Block page by redirecting to Chrome blocking page - NO USER OVERRIDE
   */
  function showBlockingOverlay(reason, analysisData) {
    try {
      logger.log(
        "Redirecting to Chrome blocking page for security - no user override allowed"
      );

      // Create blocking URL with details
      const blockingDetails = {
        reason: reason,
        url: location.href,
        timestamp: new Date().toISOString(),
        rule: analysisData?.rule?.id || "unknown",
        ruleDescription: analysisData?.rule?.description || reason,
        score: analysisData?.score || 0,
        threshold: analysisData?.threshold || 85,
      };

      // Encode the details for the blocking page
      const encodedDetails = encodeURIComponent(
        JSON.stringify(blockingDetails)
      );
      const blockingPageUrl = chrome.runtime.getURL(
        `blocked.html?details=${encodedDetails}`
      );

      // Immediately redirect to blocking page - no user override option
      location.replace(blockingPageUrl);

      logger.log("Redirected to Chrome blocking page");
    } catch (error) {
      logger.error("Failed to redirect to blocking page:", error.message);

      // Fallback: Replace page content entirely if redirect fails
      try {
        document.documentElement.innerHTML = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Site Blocked - Microsoft 365 Protection</title>
          <style>
            body {
              font-family: system-ui, -apple-system, sans-serif;
              background: #f5f5f5;
              margin: 0;
              padding: 40px;
              text-align: center;
            }
            .container {
              max-width: 600px;
              margin: 0 auto;
              background: white;
              padding: 40px;
              border-radius: 8px;
              box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }
            .icon { font-size: 64px; color: #d32f2f; margin-bottom: 24px; }
            h1 { color: #d32f2f; margin: 0 0 16px 0; }
            p { color: #555; line-height: 1.6; }
            .reason { color: #777; font-size: 14px; margin-top: 24px; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="icon">🛡️</div>
            <h1>Phishing Site Blocked</h1>
            <p><strong>Microsoft 365 login page detected on suspicious domain.</strong></p>
            <p>This site may be attempting to steal your credentials and has been blocked for your protection.</p>
            <div class="reason">Reason: ${reason}</div>
            <div class="reason">Blocked by: Check</div>
            <div class="reason">No override available - contact your administrator if this is incorrect</div>
          </div>
        </body>
        </html>
      `;

        logger.log("Fallback page content replacement completed");
      } catch (fallbackError) {
        logger.error(
          "Fallback page replacement failed:",
          fallbackError.message
        );
      }
    }
  }

  /**
   * Clear existing security UI elements
   */
  function clearSecurityUI() {
    try {
      // Remove warning banner
      const warningBanner = document.getElementById("ms365-warning-banner");
      if (warningBanner) {
        warningBanner.remove();
        logger.log("Cleared existing warning banner");
      }

      // Remove valid badge
      const validBadge = document.getElementById("ms365-valid-badge");
      if (validBadge) {
        validBadge.remove();
        logger.log("Cleared existing valid badge");
      }

      // Remove blocking overlay (if any)
      const blockingOverlay = document.getElementById(
        "phishing-blocking-overlay"
      );
      if (blockingOverlay) {
        blockingOverlay.remove();
        logger.log("Cleared existing blocking overlay");
      }
    } catch (error) {
      logger.error("Failed to clear security UI:", error.message);
    }
  }

  /**
   * Show warning banner
   */
  function showWarningBanner(reason, analysisData) {
    try {
      // Set flag to prevent DOM monitoring loops
      showingBanner = true;

      const detailsText = analysisData?.score
        ? ` (Score: ${analysisData.score}/${analysisData.threshold})`
        : "";

      // Determine banner type and styling based on analysis data
      let bannerTitle = "Suspicious Microsoft 365 Login Page";
      let bannerIcon = "⚠️";
      let bannerColor = "linear-gradient(135deg, #ff9800, #f57c00)"; // Orange for warnings

      // Check for rogue app detection
      if (
        analysisData?.type === "rogue_app_on_legitimate_domain" ||
        reason.toLowerCase().includes("rogue oauth") ||
        reason.toLowerCase().includes("rogue app")
      ) {
        bannerTitle = "🚨 CRITICAL SECURITY THREAT";
        bannerIcon = "🛡️";
        bannerColor = "linear-gradient(135deg, #f44336, #d32f2f)"; // Red for critical threats
      } else if (analysisData?.severity === "critical") {
        bannerTitle = "Critical Security Warning";
        bannerIcon = "🚨";
        bannerColor = "linear-gradient(135deg, #f44336, #d32f2f)"; // Red for critical
      } else if (analysisData?.severity === "high") {
        bannerTitle = "High Risk Security Warning";
        bannerIcon = "⚠️";
        bannerColor = "linear-gradient(135deg, #ff5722, #d84315)"; // Orange-red for high risk
      }

      const bannerContent = `
      <div style="display: flex; align-items: center; justify-content: center; gap: 16px; position: relative; padding-right: 48px;">
        <span style="font-size: 24px;">${bannerIcon}</span>
        <div>
          <strong>${bannerTitle}</strong><br>
          <small>${reason}${detailsText}</small>
        </div>
        <button onclick="this.parentElement.parentElement.remove(); document.body.style.marginTop = '0';" title="Dismiss" style="
          position: absolute; right: 16px; top: 50%; transform: translateY(-50%);
          background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.3);
          color: white; padding: 0; border-radius: 4px; cursor: pointer;
          width: 24px; height: 24px; min-width: 24px; min-height: 24px; max-width: 24px; max-height: 24px;
          display: flex; align-items: center; justify-content: center;
          font-size: 14px; font-weight: bold; line-height: 1; box-sizing: border-box;
          font-family: monospace;
        ">×</button>
      </div>
    `;

      // Check if banner already exists
      let banner = document.getElementById("ms365-warning-banner");

      if (banner) {
        // Update existing banner content and color
        banner.innerHTML = bannerContent;
        banner.style.background = bannerColor;

        // Ensure page content is still pushed down
        const bannerHeight = banner.offsetHeight || 64;
        document.body.style.marginTop = `${bannerHeight}px`;

        logger.log("Warning banner updated with new analysis");
        return;
      }

      // Create new banner
      banner = document.createElement("div");
      banner.id = "ms365-warning-banner";
      banner.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100% !important;
      background: ${bannerColor} !important;
      color: white !important;
      padding: 16px !important;
      z-index: 2147483646 !important;
      font-family: system-ui, -apple-system, sans-serif !important;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3) !important;
      text-align: center !important;
    `;

      banner.innerHTML = bannerContent;
      document.body.appendChild(banner);

      // Push page content down to avoid covering login header
      const bannerHeight = banner.offsetHeight || 64; // fallback height
      document.body.style.marginTop = `${bannerHeight}px`;

      logger.log("Warning banner displayed");

      // Clear flag after a short delay to allow banner to fully render
      setTimeout(() => {
        showingBanner = false;
        logger.debug("🟢 Banner display complete - DOM monitoring resumed");
      }, 1000);
    } catch (error) {
      logger.error("Failed to show warning banner:", error.message);
      showingBanner = false; // Make sure flag is cleared on error
    }
  }

  /**
   * Show valid badge for trusted domains
   */
  function showValidBadge() {
    try {
      // Check if badge already exists - for valid badge, we don't need to update content
      // since it's always the same, but we ensure it's still visible
      if (document.getElementById("ms365-valid-badge")) {
        logger.log("Valid badge already displayed");
        return;
      }

      // Check if mobile using media query (more conservative breakpoint)
      const isMobile = window.matchMedia("(max-width: 480px)").matches;

      logger.debug(
        "Screen width:",
        window.innerWidth,
        "Media query matches:",
        isMobile
      ); // Debug log

      const badge = document.createElement("div");
      badge.id = "ms365-valid-badge";

      if (isMobile) {
        // Mobile: Banner style
        badge.style.cssText = `
        position: fixed !important;
        top: 0 !important;
        left: 0 !important;
        width: 100% !important;
        background: linear-gradient(135deg, #4caf50, #2e7d32) !important;
        color: white !important;
        padding: 16px !important;
        z-index: 2147483646 !important;
        font-family: system-ui, -apple-system, sans-serif !important;
        box-shadow: 0 2px 8px rgba(0,0,0,0.3) !important;
        text-align: center !important;
      `;

        badge.innerHTML = `
        <div style="display: flex; align-items: center; justify-content: center; gap: 16px; position: relative; padding-right: 48px;">
          <span style="font-size: 24px;">✅</span>
          <div>
            <strong>Verified Microsoft Domain</strong><br>
            <small>This is an authentic Microsoft login page</small>
          </div>
          <button onclick="this.parentElement.parentElement.remove(); document.body.style.marginTop = '0';" title="Dismiss" style="
            position: absolute; right: 16px; top: 50%; transform: translateY(-50%);
            background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.3);
            color: white; padding: 0; border-radius: 4px; cursor: pointer;
            width: 24px; height: 24px; min-width: 24px; min-height: 24px; max-width: 24px; max-height: 24px;
            display: flex; align-items: center; justify-content: center;
            font-size: 14px; font-weight: bold; line-height: 1; box-sizing: border-box;
            font-family: monospace;
          ">×</button>
        </div>
      `;

        // Push page content down
        document.body.appendChild(badge);
        const bannerHeight = badge.offsetHeight || 64;
        document.body.style.marginTop = `${bannerHeight}px`;
      } else {
        // Desktop: Badge style (original)
        badge.style.cssText = `
        position: fixed !important;
        top: 20px !important;
        right: 20px !important;
        background: linear-gradient(135deg, #4caf50, #2e7d32) !important;
        color: white !important;
        padding: 12px 16px !important;
        border-radius: 8px !important;
        z-index: 2147483646 !important;
        font-family: system-ui, -apple-system, sans-serif !important;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2) !important;
        font-size: 14px !important;
        font-weight: 500 !important;
      `;

        badge.innerHTML = `
        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="font-size: 16px;">✅</span>
          <span>Verified Microsoft Domain</span>
        </div>
      `;

        document.body.appendChild(badge);
      }

      logger.log("Valid badge displayed");
    } catch (error) {
      logger.error("Failed to show valid badge:", error.message);
    }
  }

  /**
   * Show fallback warning when rules fail to load
   */
  function showFallbackWarning() {
    try {
      if (document.getElementById("ms365-fallback-warning")) return;

      const warning = document.createElement("div");
      warning.id = "ms365-fallback-warning";
      warning.style.cssText = `
      position: fixed !important;
      top: 0 !important;
      left: 0 !important;
      width: 100% !important;
      background: #d32f2f !important;
      color: white !important;
      padding: 16px !important;
      z-index: 2147483646 !important;
      font-family: system-ui, -apple-system, sans-serif !important;
      text-align: center !important;
    `;

      warning.innerHTML = `
      <div>
        <strong>⚠️ Security Warning</strong><br>
        <small>Microsoft login elements detected on non-Microsoft domain. Protection system unavailable.</small>
      </div>
    `;

      document.body.appendChild(warning);

      logger.log("Fallback warning displayed");
    } catch (error) {
      logger.error("Failed to show fallback warning:", error.message);
    }
  }

  /**
   * Disable form submissions
   */
  function disableFormSubmissions() {
    try {
      const forms = document.querySelectorAll("form");
      for (const form of forms) {
        form.addEventListener(
          "submit",
          (e) => {
            e.preventDefault();
            e.stopPropagation();
            logger.warn("Form submission blocked");
            return false;
          },
          true
        );

        // Also disable the form element
        form.setAttribute("disabled", "true");
      }

      logger.log(`Disabled ${forms.length} forms`);
    } catch (error) {
      logger.error("Failed to disable form submissions:", error.message);
    }
  }

  /**
   * Disable credential inputs
   */
  function disableCredentialInputs() {
    try {
      const inputs = document.querySelectorAll(
        'input[type="password"], input[type="email"], input[name*="user"], input[name*="login"], input[name*="email"]'
      );
      for (const input of inputs) {
        input.disabled = true;
        input.style.backgroundColor = "#ffebee";
        input.placeholder = "Input disabled for security";
      }

      logger.log(`Disabled ${inputs.length} credential inputs`);
    } catch (error) {
      logger.error("Failed to disable credential inputs:", error.message);
    }
  }

  /**
   * Extract hostname from redirect_uri parameter for cleaner logging
   */
  function extractRedirectHostname(url) {
    try {
      const urlObj = new URL(url);
      const redirectUri = urlObj.searchParams.get("redirect_uri");

      if (redirectUri) {
        try {
          const redirectUrl = new URL(decodeURIComponent(redirectUri));
          return redirectUrl.hostname;
        } catch (e) {
          // If redirect_uri isn't a valid URL, return it as-is (truncated)
          return (
            redirectUri.substring(0, 100) +
            (redirectUri.length > 100 ? "..." : "")
          );
        }
      }
      return null;
    } catch (e) {
      return null;
    }
  }

  /**
   * Check if a URL is from a trusted origin (legacy function - now uses trusted login domain check)
   */
  function isTrustedOrigin(url) {
    return isTrustedLoginDomain(url);
  }

  /**
   * Extract client_id parameter and check against known malicious client IDs
   */
  async function extractClientInfo(url) {
    try {
      const urlObj = new URL(url);
      const clientId = urlObj.searchParams.get("client_id");

      if (!clientId) {
        return {
          clientId: null,
          isMalicious: false,
          reason: null,
          appInfo: null,
        };
      }

      // Check against rogue apps from detection rules
      const rogueAppCheck = await checkRogueApp(clientId);
      if (rogueAppCheck.isMalicious) {
        return {
          clientId: clientId,
          isMalicious: true,
          reason: `Rogue App: ${rogueAppCheck.appName}`,
          appName: rogueAppCheck.appName,
          appInfo: rogueAppCheck.appInfo,
        };
      }

      return {
        clientId: clientId,
        isMalicious: false,
        reason: null,
      };
    } catch (e) {
      return { clientId: null, isMalicious: false, reason: null };
    }
  }

  /**
   * Check if client_id matches known rogue applications from Huntress data
   */
  async function checkRogueApp(clientId) {
    try {
      // Query background script's RogueAppsManager
      const response = await chrome.runtime.sendMessage({
        type: "CHECK_ROGUE_APP",
        clientId: clientId,
      });

      if (response && response.isRogue) {
        return {
          isMalicious: true,
          appName: response.appName,
          appInfo: {
            description: response.description,
            tags: response.tags,
            risk: response.risk,
            references: response.references,
          },
        };
      }

      return { isMalicious: false };
    } catch (e) {
      logger.warn("Error checking rogue app:", e.message);
      return { isMalicious: false };
    }
  }

  /**
   * Log protection events to background script
   */
  function logProtectionEvent(eventData) {
    try {
      chrome.runtime
        .sendMessage({
          type: "protection_event",
          data: {
            timestamp: new Date().toISOString(),
            url: eventData.url || location.href, // Use provided URL or fallback to current
            userAgent: navigator.userAgent,
            ...eventData,
          },
        })
        .catch((error) => {
          logger.warn("Failed to log protection event:", error.message);
        });
    } catch (error) {
      logger.warn("Failed to send protection event:", error.message);
    }
  }

  /**
   * Send CIPP reporting if enabled
   */
  async function sendCippReport(reportData) {
    try {
      // Only send reports for high/critical severity threats to prevent CIPP spam
      const severity = reportData.severity || reportData.threatLevel;
      const isCriticalThreat = severity === "critical" || severity === "high";
      const isRogueApp = reportData.type === "critical_rogue_app_detected";
      const isPhishingBlocked = reportData.type === "phishing_blocked";

      // Allow critical/high threats and rogue apps, skip informational reports
      if (!isCriticalThreat && !isRogueApp && !isPhishingBlocked) {
        logger.debug(
          `CIPP reporting skipped for ${reportData.type} - only high/critical threats are reported`
        );
        return;
      }

      // Get CIPP configuration from storage
      const result = await new Promise((resolve) => {
        chrome.storage.local.get(["config"], (result) => {
          resolve(result.config || {});
        });
      });

      const config = result;

      // Check if CIPP reporting is enabled and URL is configured
      if (!config.enableCippReporting || !config.cippServerUrl) {
        logger.debug("CIPP reporting disabled or no server URL configured");
        return;
      }

      // Prepare base CIPP report payload (background script will inject user profile and build URL)
      const baseCippPayload = {
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        extensionVersion: chrome.runtime.getManifest().version,
        source: "CheckExtension",
        ...reportData,
      };

      logger.log(
        `Sending high/critical CIPP report via background script (${
          reportData.type
        }, severity: ${severity || "N/A"})`
      );
      if (config.cippTenantId) {
        logger.debug(
          `Including tenant ID in CIPP report: ${config.cippTenantId}`
        );
      }

      // Send CIPP report via background script (content scripts can't make external requests)
      // Background script will inject user profile data and build the full URL automatically
      try {
        const response = await chrome.runtime.sendMessage({
          type: "send_cipp_report",
          payload: baseCippPayload,
        });

        if (response && response.success) {
          logger.log("✅ CIPP report sent successfully via background script");
        } else {
          logger.warn(
            "⚠️ CIPP report failed:",
            response?.error || "Unknown error"
          );
        }
      } catch (messageError) {
        logger.error(
          "Failed to send CIPP report via background script:",
          messageError.message
        );
      }
    } catch (error) {
      logger.warn("Failed to send CIPP report:", error.message);
    }
  }

  /**
   * Apply primary color from branding configuration
   */
  async function applyBrandingColors() {
    try {
      // Get branding configuration from storage
      const result = await new Promise((resolve) => {
        chrome.storage.local.get(["brandingConfig"], (result) => {
          resolve(result.brandingConfig || {});
        });
      });

      if (result.primaryColor) {
        // Remove existing branding styles
        const existingStyle = document.getElementById(
          "content-branding-colors"
        );
        if (existingStyle) {
          existingStyle.remove();
        }

        // Create new style element with primary color
        const style = document.createElement("style");
        style.id = "content-branding-colors";
        style.textContent = `
        :root {
          --check-primary-color: ${result.primaryColor} !important;
          --check-primary-hover: ${result.primaryColor}dd !important;
        }
      `;
        document.head.appendChild(style);

        logger.log("Applied branding primary color:", result.primaryColor);
      }
    } catch (error) {
      logger.warn("Failed to apply branding colors:", error.message);
    }
  }

  /**
   * Initialize protection when DOM is ready
   */
  function initializeProtection() {
    try {
      logger.log("Initializing Check");

      // Apply branding colors first
      applyBrandingColors();

      // Setup dynamic script monitoring early to catch any immediate script execution
      setupDynamicScriptMonitoring();

      if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", () => {
          setTimeout(runProtection, 100); // Small delay to ensure DOM is stable
        });
      } else {
        // DOM already ready
        setTimeout(runProtection, 100);
      }
    } catch (error) {
      logger.error("Failed to initialize protection:", error.message);
    }
  }

  // Start protection
  initializeProtection();

  /**
   * Message listener for popup communication
   */
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "SHOW_VALID_BADGE") {
      try {
        logger.log("📋 VALID BADGE: Received request to show valid page badge");
        showValidBadge();
        sendResponse({ success: true });
      } catch (error) {
        logger.error("Failed to show valid badge:", error);
        sendResponse({ success: false, error: error.message });
      }
      return true;
    }

    if (message.type === "REMOVE_VALID_BADGE") {
      try {
        logger.log(
          "📋 VALID BADGE: Received request to remove valid page badge"
        );
        const validBadge = document.getElementById("ms365-valid-badge");
        if (validBadge) {
          validBadge.remove();
          logger.log("📋 VALID BADGE: Badge removed successfully");
        }
        sendResponse({ success: true });
      } catch (error) {
        logger.error("Failed to remove valid badge:", error);
        sendResponse({ success: false, error: error.message });
      }
      return true;
    }

    if (message.type === "GET_DETECTION_RESULTS") {
      try {
        // Use stored detection results if available
        if (lastDetectionResult) {
          logger.log(
            `📊 POPUP REQUEST: Returning stored detection results - ${lastDetectionResult.verdict}`
          );
          sendResponse({
            success: true,
            verdict: lastDetectionResult.verdict,
            isBlocked: lastDetectionResult.isBlocked,
            isSuspicious: lastDetectionResult.isSuspicious,
            threats: lastDetectionResult.threats,
            reason: lastDetectionResult.reason,
            score: lastDetectionResult.score,
            threshold: lastDetectionResult.threshold,
            url: window.location.href,
          });
        } else {
          // Fallback to basic detection if no stored results
          const currentUrl = window.location.href;
          const isBlocked =
            document.getElementById("phishing-blocking-overlay") !== null;
          const hasWarning =
            document.getElementById("phishing-warning-banner") !== null;

          let verdict = "unknown";
          let isSuspicious = false;
          let threats = [];
          let reason = "No analysis performed yet";

          if (isBlocked) {
            verdict = "blocked";
            isSuspicious = true;
            threats = [
              { type: "phishing-detected", description: "Page blocked" },
            ];
            reason = "Page blocked by protection";
          } else if (hasWarning) {
            verdict = "suspicious";
            isSuspicious = true;
            threats = [
              { type: "suspicious-content", description: "Warning displayed" },
            ];
            reason = "Suspicious content detected";
          } else if (isTrustedOrigin(currentUrl)) {
            verdict = "trusted";
            reason = "Trusted Microsoft domain";
          }

          logger.log(`📊 POPUP REQUEST: Using fallback detection - ${verdict}`);
          sendResponse({
            success: true,
            verdict: verdict,
            isBlocked: isBlocked,
            isSuspicious: isSuspicious,
            threats: threats,
            reason: reason,
            url: currentUrl,
          });
        }
      } catch (error) {
        sendResponse({
          success: false,
          error: error.message,
        });
      }
      return true; // Keep message channel open for async response
    }
  });

  // Cleanup on page unload
  window.addEventListener("beforeunload", () => {
    try {
      stopDOMMonitoring();
      protectionActive = false;
    } catch (error) {
      logger.error("Cleanup failed:", error.message);
    }
  });
} // End of script execution guard
