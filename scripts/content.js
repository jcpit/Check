/**
 * Microsoft 365 Phishing Protection - Final Rule-Driven Content Script
 * 100% rule-driven architecture - NO hardcoded detections
 *
 * Logic Flow (CORRECTED):
 * 1. Load rules and check trusted origins FIRST - immediate exit if trusted
 * 2. Check if page is MS logon page (using rule file requirements)
 * 3. If MS logon page on non-trusted domain, apply blocking rules
 */

// Simple, reliable logger
const logger = {
  log: (...args) => console.log("[M365-Protection]", ...args),
  warn: (...args) => console.warn("[M365-Protection]", ...args),
  error: (...args) => console.error("[M365-Protection]", ...args),
  debug: (...args) => console.debug("[M365-Protection]", ...args),
};

// Global state
let protectionActive = false;
let detectionRules = null;
let trustedOrigins = new Set();
let domObserver = null;
let lastScanTime = 0;
let scanCount = 0;
let lastDetectionResult = null; // Store last detection analysis
const MAX_SCANS = 10; // Prevent infinite scanning
const SCAN_COOLDOWN = 1000; // 1 second between scans

/**
 * Load detection rules from the rule file - EVERYTHING comes from here
 */
async function loadDetectionRules() {
  try {
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

    // Set up trusted origins from rules ONLY
    if (rules.trusted_origins && Array.isArray(rules.trusted_origins)) {
      trustedOrigins = new Set(
        rules.trusted_origins.map((origin) => origin.toLowerCase())
      );
    }

    logger.log(
      `Loaded detection rules: ${trustedOrigins.size} trusted origins, ${
        rules.rules?.length || 0
      } detection rules`
    );
    return rules;
  } catch (error) {
    logger.error("CRITICAL: Failed to load detection rules:", error.message);
    throw error; // Don't continue without rules
  }
}

/**
 * Check if page is Microsoft 365 logon page using ONLY rule file requirements
 * Requirements: idPartnerPL, loginfmt, aadcdn.msauth.net, urlMsaSignUp, #i0116 (2 of 5 needed)
 */
function isMicrosoftLogonPage() {
  try {
    if (!detectionRules?.m365_detection_requirements) {
      logger.error("No M365 detection requirements in rules");
      return false;
    }

    const requirements = detectionRules.m365_detection_requirements;
    const pageSource = document.documentElement.outerHTML;
    let foundElements = 0;
    const foundElementsList = [];
    const missingElementsList = [];

    // Check each required element from the rule file
    for (const element of requirements.required_elements) {
      try {
        let found = false;

        if (element.type === "source_content") {
          const regex = new RegExp(element.pattern, "i");
          found = regex.test(pageSource);
        }

        if (found) {
          foundElements++;
          foundElementsList.push(element.id);
          logger.debug(`✓ Found required element: ${element.id}`);
        } else {
          missingElementsList.push(element.id);
          logger.debug(`✗ Missing required element: ${element.id}`);
        }
      } catch (elementError) {
        logger.warn(
          `Error checking element ${element.id}:`,
          elementError.message
        );
        missingElementsList.push(element.id);
      }
    }

    const isM365Page = requirements.all_must_be_present
      ? foundElements === requirements.required_elements.length
      : foundElements >= (requirements.minimum_required || 2); // Changed to 2 of 5 elements

    logger.log(
      `M365 logon detection: ${foundElements}/${
        requirements.required_elements.length
      } elements found (need ${requirements.minimum_required || 2})`
    );
    logger.log(`Found: [${foundElementsList.join(", ")}]`);
    if (missingElementsList.length > 0) {
      logger.log(`Missing: [${missingElementsList.join(", ")}]`);
    }
    logger.log(`Result: ${isM365Page ? "IS" : "NOT"} Microsoft 365 logon page`);

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
                logger.warn(`BLOCKING RULE TRIGGERED: ${rule.id} - ${reason}`);
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

    // Step 1: Load detection rules (everything comes from here)
    if (!detectionRules) {
      detectionRules = await loadDetectionRules();
    }

    // Step 2: FIRST CHECK - trusted origins (immediate exit if trusted)
    const currentOrigin = location.origin.toLowerCase();
    if (trustedOrigins.has(currentOrigin)) {
      logger.log(
        "✅ TRUSTED ORIGIN - No phishing possible, exiting immediately"
      );

      // Store detection result
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
        if (protectionEnabled) {
          showValidBadge();
        }
        const redirectHostname = extractRedirectHostname(location.href);
        const clientInfo = await extractClientInfo(location.href);

        // Check for rogue apps even on legitimate Microsoft domains
        if (clientInfo.isMalicious) {
          logger.warn(
            `🚨 ROGUE OAUTH APP DETECTED ON LEGITIMATE MICROSOFT DOMAIN: ${clientInfo.reason}`
          );

          // Notify background script about rogue app detection
          try {
            chrome.runtime.sendMessage({
              type: "FLAG_ROGUE_APP",
              clientId: clientInfo.clientId,
              appName: clientInfo.appInfo?.appName || "Unknown",
              reason: clientInfo.reason,
            });
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
            url: location.href,
            origin: currentOrigin,
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
            origin: currentOrigin,
            clientId: clientInfo.clientId,
            appName: clientInfo.appInfo?.appName || "Unknown",
            reason: clientInfo.reason,
            severity: "critical",
            redirectTo: redirectHostname,
          });

          return; // Stop processing as this is now treated as a threat
        }

        // Normal legitimate access logging if no rogue app detected
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
      }

      return; // EXIT IMMEDIATELY - can't be phishing on trusted domain
    }

    logger.log("❌ NON-TRUSTED ORIGIN - Continuing analysis");

    // Step 3: Check if page is an MS logon page (using rule file requirements)
    const isMSLogon = isMicrosoftLogonPage();
    if (!isMSLogon) {
      logger.debug("Not a Microsoft logon page - no protection needed");

      // Set up monitoring in case content loads later
      if (!isRerun) {
        setupDOMMonitoring();
      }

      return;
    }

    logger.warn(
      "🚨 MICROSOFT LOGON PAGE ON NON-TRUSTED DOMAIN - ANALYZING THREAT"
    );

    // Notify background script that this is a Microsoft login page on unknown domain
    try {
      const redirectHostname = extractRedirectHostname(location.href);
      const clientInfo = await extractClientInfo(location.href);

      chrome.runtime.sendMessage({
        type: "FLAG_MS_LOGIN_ON_UNKNOWN_DOMAIN",
        url: location.href,
        origin: location.origin,
        redirectTo: redirectHostname,
        clientId: clientInfo.clientId,
        clientSuspicious: clientInfo.isMalicious,
        clientReason: clientInfo.reason,
      });
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

    // Step 5: No immediate blocking - run detection rules for legitimacy scoring
    const detectionResult = runDetectionRules();

    // Determine action based on legitimacy score from rules
    if (detectionResult.score < detectionResult.threshold) {
      const severity =
        detectionResult.score < detectionResult.threshold * 0.3
          ? "high"
          : "medium";
      const reason = `Low legitimacy score: ${detectionResult.score}/${detectionResult.threshold}`;

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
        ],
        reason: reason,
        score: detectionResult.score,
        threshold: detectionResult.threshold,
        triggeredRules: detectionResult.triggeredRules,
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
          showWarningBanner(`HIGH THREAT DETECTED: ${reason}`, detectionResult);
          if (!isRerun) {
            setupDOMMonitoring();
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

      // Continue monitoring in case content changes
      if (!isRerun) {
        setupDOMMonitoring();
      }
    }
  } catch (error) {
    logger.error("Protection failed:", error.message);

    // Emergency fallback - if we can't load rules but detect MS elements, warn user
    try {
      const hasBasicMSElements =
        document.querySelector('input[name="loginfmt"]') ||
        document.querySelector("#i0116");
      const isNotMSDomain = !location.hostname.includes("microsoftonline.com");

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
                  logger.debug(`DOM change detected: ${tagName} element added`);
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

        if (shouldRerun) {
          logger.log(
            "Significant DOM changes detected - re-running protection"
          );
          // Debounce re-runs
          setTimeout(() => {
            runProtection(true);
          }, 500);
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

    // Stop monitoring after 30 seconds to prevent resource drain
    setTimeout(() => {
      stopDOMMonitoring();
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
    const encodedDetails = encodeURIComponent(JSON.stringify(blockingDetails));
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
            <div class="reason">Blocked by: Microsoft 365 Phishing Protection</div>
            <div class="reason">No override available - contact your administrator if this is incorrect</div>
          </div>
        </body>
        </html>
      `;

      logger.log("Fallback page content replacement completed");
    } catch (fallbackError) {
      logger.error("Fallback page replacement failed:", fallbackError.message);
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
    const detailsText = analysisData?.score
      ? ` (Score: ${analysisData.score}/${analysisData.threshold})`
      : "";

    const bannerContent = `
      <div style="display: flex; align-items: center; justify-content: center; gap: 16px;">
        <span style="font-size: 24px;">⚠️</span>
        <div>
          <strong>Suspicious Microsoft 365 Login Page</strong><br>
          <small>${reason}${detailsText}</small>
        </div>
        <button onclick="this.parentElement.parentElement.remove();" style="
          background: rgba(255,255,255,0.2); border: 1px solid rgba(255,255,255,0.3);
          color: white; padding: 8px 16px; border-radius: 4px; cursor: pointer;
        ">Dismiss</button>
      </div>
    `;

    // Check if banner already exists
    let banner = document.getElementById("ms365-warning-banner");

    if (banner) {
      // Update existing banner content
      banner.innerHTML = bannerContent;
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
      background: linear-gradient(135deg, #ff9800, #f57c00) !important;
      color: white !important;
      padding: 16px !important;
      z-index: 2147483646 !important;
      font-family: system-ui, -apple-system, sans-serif !important;
      box-shadow: 0 2px 8px rgba(0,0,0,0.3) !important;
      text-align: center !important;
    `;

    banner.innerHTML = bannerContent;
    document.body.appendChild(banner);

    logger.log("Warning banner displayed");
  } catch (error) {
    logger.error("Failed to show warning banner:", error.message);
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

    const badge = document.createElement("div");
    badge.id = "ms365-valid-badge";
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

    // Prepare CIPP report payload
    const cippPayload = {
      timestamp: new Date().toISOString(),
      userAgent: navigator.userAgent,
      extensionVersion: chrome.runtime.getManifest().version,
      ...reportData,
    };

    // Send POST request to CIPP server
    const cippUrl =
      config.cippServerUrl.replace(/\/+$/, "") + "/api/PublicExecCheck";

    logger.log(`Sending CIPP report to: ${cippUrl}`);

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

    try {
      const response = await fetch(cippUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(cippPayload),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (response.ok) {
        logger.log("CIPP report sent successfully");
      } else {
        logger.warn(
          `CIPP report failed: ${response.status} ${response.statusText}`
        );
      }
    } finally {
      clearTimeout(timeoutId);
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
      const existingStyle = document.getElementById("content-branding-colors");
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
    logger.log("Initializing Microsoft 365 phishing protection");

    // Apply branding colors first
    applyBrandingColors();

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
