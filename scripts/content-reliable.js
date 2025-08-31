/**
 * Microsoft 365 Phishing Protection - Rule-Driven Content Script
 * 100% rule-driven architecture - NO hardcoded detections
 * 
 * Logic Flow (as specified):
 * 1. Check if page is MS logon page (using rule file requirements)
 * 2. Check if URL is in allowed list (from rule file) - if so, ignore
 * 3. If not allowed, check for markers from rule file and apply blocking rules
 */

// Simple, reliable logger
const logger = {
  log: (...args) => console.log("[M365-Protection]", ...args),
  warn: (...args) => console.warn("[M365-Protection]", ...args),
  error: (...args) => console.error("[M365-Protection]", ...args),
  debug: (...args) => console.debug("[M365-Protection]", ...args)
};

// Global state
let protectionActive = false;
let detectionRules = null;
let trustedOrigins = new Set();

/**
 * Load detection rules from the rule file - EVERYTHING comes from here
 */
async function loadDetectionRules() {
  try {
    const response = await fetch(chrome.runtime.getURL("rules/detection-rules.json"), {
      cache: "no-cache"
    });
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    
    const rules = await response.json();
    
    // Set up trusted origins from rules ONLY
    if (rules.trusted_origins && Array.isArray(rules.trusted_origins)) {
      trustedOrigins = new Set(rules.trusted_origins.map(origin => origin.toLowerCase()));
    }
    
    logger.log(`Loaded detection rules: ${trustedOrigins.size} trusted origins, ${rules.rules?.length || 0} detection rules`);
    return rules;
    
  } catch (error) {
    logger.error("CRITICAL: Failed to load detection rules:", error.message);
    throw error; // Don't continue without rules
  }
}

/**
 * Check if page is Microsoft 365 logon page using ONLY rule file requirements
 * Requirements from rule file: idPartnerPL, loginfmt, aadcdn.msauth.net, urlMsaSignUp, #i0116
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

    // Check each required element from the rule file
    for (const element of requirements.required_elements) {
      try {
        let found = false;

        if (element.type === "source_content") {
          const regex = new RegExp(element.pattern, 'i');
          found = regex.test(pageSource);
        }

        if (found) {
          foundElements++;
          foundElementsList.push(element.id);
          logger.debug(`Found required element: ${element.id}`);
        } else {
          logger.debug(`Missing required element: ${element.id}`);
        }
      } catch (elementError) {
        logger.warn(`Error checking element ${element.id}:`, elementError.message);
      }
    }

    const isM365Page = requirements.all_must_be_present ? 
      foundElements === requirements.required_elements.length :
      foundElements >= (requirements.minimum_required || 3);

    logger.log(`M365 logon detection: ${foundElements}/${requirements.required_elements.length} elements found [${foundElementsList.join(', ')}], result: ${isM365Page}`);
    
    return isM365Page;

  } catch (error) {
    logger.error("M365 logon page detection failed:", error.message);
    return false; // Fail closed - don't assume it's MS page if detection fails
  }
}

/**
 * Check if current URL is in allowed list from rule file
 */
function isAllowedUrl() {
  try {
    const currentOrigin = location.origin.toLowerCase();
    const currentHostname = location.hostname.toLowerCase();
    
    // Check trusted origins from rule file
    if (trustedOrigins.has(currentOrigin)) {
      return true;
    }
    
    // Check allow rules from rule file
    if (detectionRules?.allow_rules) {
      for (const rule of detectionRules.allow_rules) {
        try {
          if (rule.condition?.url_equals && currentHostname === rule.condition.url_equals) {
            logger.log(`URL allowed by rule: ${rule.id}`);
            return true;
          }
        } catch (ruleError) {
          logger.warn(`Error processing allow rule ${rule.id}:`, ruleError.message);
        }
      }
    }
    
    return false;
  } catch (error) {
    logger.error("URL allow check failed:", error.message);
    return false; // Fail closed
  }
}

/**
 * Run blocking rules from rule file
 */
function runBlockingRules() {
  try {
    if (!detectionRules?.blocking_rules) {
      logger.warn("No blocking rules in detection rules");
      return { shouldBlock: false, reason: 'No blocking rules available' };
    }

    const pageSource = document.documentElement.outerHTML;
    
    for (const rule of detectionRules.blocking_rules) {
      try {
        let ruleTriggered = false;
        let reason = '';

        switch (rule.type) {
          case "form_action_validation":
            // Check: form post url is not login.microsoftonline.com -> Block
            const forms = document.querySelectorAll(rule.condition?.form_selector || "form");
            for (const form of forms) {
              // Check if form has password field (as specified in condition)
              if (rule.condition?.has_password_field && !form.querySelector('input[type="password"]')) {
                continue;
              }
              
              const action = form.action || location.href;
              const actionContainsMicrosoft = action.includes(rule.condition?.action_must_not_contain || "");
              
              if (!actionContainsMicrosoft) {
                ruleTriggered = true;
                reason = `Form action "${action}" does not contain ${rule.condition?.action_must_not_contain}`;
                break;
              }
            }
            break;

          case "resource_validation":
            // Check: If "*customcss" is loaded, it must come from https://aadcdn.msftauthimages.net/
            const resourceNodes = document.querySelectorAll("[src], link[rel='stylesheet'][href]");
            for (const node of resourceNodes) {
              const url = node.src || node.href;
              if (!url) continue;
              
              if (url.includes(rule.condition?.resource_pattern || "")) {
                const requiredOrigin = rule.condition?.required_origin || "";
                if (!url.startsWith(requiredOrigin)) {
                  ruleTriggered = true;
                  reason = `Resource "${url}" does not come from required origin "${requiredOrigin}"`;
                  break;
                }
              }
            }
            break;

          default:
            logger.warn(`Unknown blocking rule type: ${rule.type}`);
        }

        if (ruleTriggered) {
          logger.warn(`Blocking rule triggered: ${rule.id} - ${reason}`);
          return {
            shouldBlock: true,
            reason: reason,
            rule: rule,
            severity: rule.severity
          };
        }

      } catch (ruleError) {
        logger.warn(`Error processing blocking rule ${rule.id}:`, ruleError.message);
        // Continue with other rules - don't let one bad rule break everything
      }
    }

    return { shouldBlock: false, reason: 'No blocking rules triggered' };

  } catch (error) {
    logger.error("Blocking rules check failed:", error.message);
    // Fail-safe: if we can't check blocking rules, assume we should block
    return { 
      shouldBlock: true, 
      reason: 'Blocking rules check failed - blocking for safety',
      error: error.message 
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
              ruleTriggered = rule.condition.domains.some(domain => 
                location.hostname === domain
              );
            }
            break;

          case "form_action":
            const forms = document.querySelectorAll(rule.condition?.form_selector || "form");
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
              ruleTriggered = rule.condition.selectors.some(selector => {
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
            const resourceNodes = document.querySelectorAll("[src], link[rel='stylesheet'][href]");
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
            weight: rule.weight
          });
          logger.debug(`Rule triggered: ${rule.id} (weight: ${rule.weight})`);
        }

      } catch (ruleError) {
        logger.warn(`Error processing rule ${rule.id}:`, ruleError.message);
        // Continue with other rules - don't let one bad rule break everything
      }
    }

    const threshold = detectionRules.thresholds?.legitimate || 85;
    
    logger.log(`Detection rules: score=${score}, threshold=${threshold}, triggered=${triggeredRules.length} rules`);
    
    return {
      score: score,
      triggeredRules: triggeredRules,
      threshold: threshold
    };

  } catch (error) {
    logger.error("Detection rules processing failed:", error.message);
    // Fail-safe: return low score (suspicious)
    return {
      score: 0,
      triggeredRules: [],
      threshold: 85,
      error: error.message
    };
  }
}

/**
 * Main protection logic following exact specification
 */
async function runProtection() {
  try {
    // Prevent multiple runs
    if (protectionActive) {
      logger.debug("Protection already active");
      return;
    }
    
    protectionActive = true;
    logger.log("Starting rule-driven Microsoft 365 protection");

    // Step 1: Load detection rules (everything comes from here)
    if (!detectionRules) {
      detectionRules = await loadDetectionRules();
    }

    // Step 2: Check if page is an MS logon page (using rule file requirements)
    const isMSLogon = isMicrosoftLogonPage();
    if (!isMSLogon) {
      logger.debug("Not a Microsoft logon page - no protection needed");
      return;
    }

    logger.log("Microsoft logon page detected");

    // Step 3: Check if URL is in allowed list (from rule file)
    if (isAllowedUrl()) {
      logger.log("URL is in allowed list - showing valid badge");
      
      try {
        showValidBadge();
        logProtectionEvent({
          type: 'legitimate_access',
          url: location.href,
          reason: 'URL in allowed list'
        });
      } catch (badgeError) {
        logger.warn("Failed to show valid badge:", badgeError.message);
      }
      
      return;
    }

    // Step 4: Page is MS logon but not allowed - check blocking rules first
    logger.warn("Microsoft logon page on non-allowed URL - checking blocking rules");
    
    const blockingResult = runBlockingRules();
    if (blockingResult.shouldBlock) {
      logger.error(`BLOCKING PAGE: ${blockingResult.reason}`);
      
      showBlockingOverlay(blockingResult.reason, blockingResult);
      disableFormSubmissions();
      disableCredentialInputs();
      
      logProtectionEvent({
        type: 'threat_blocked',
        url: location.href,
        reason: blockingResult.reason,
        rule: blockingResult.rule?.id,
        severity: blockingResult.severity
      });
      
      return;
    }

    // Step 5: No blocking rules triggered - run detection rules for scoring
    const detectionResult = runDetectionRules();
    
    // Determine action based on legitimacy score from rules
    if (detectionResult.score < detectionResult.threshold) {
      const severity = detectionResult.score < (detectionResult.threshold * 0.3) ? 'high' : 'medium';
      const reason = `Low legitimacy score: ${detectionResult.score}/${detectionResult.threshold}`;
      
      if (severity === 'high') {
        logger.warn("HIGH THREAT: Very low legitimacy score - blocking");
        showBlockingOverlay(reason, detectionResult);
        disableFormSubmissions();
        disableCredentialInputs();
      } else {
        logger.warn("MEDIUM THREAT: Low legitimacy score - warning");
        showWarningBanner(reason, detectionResult);
      }
      
      logProtectionEvent({
        type: 'threat_detected',
        url: location.href,
        threatLevel: severity,
        reason: reason,
        score: detectionResult.score,
        threshold: detectionResult.threshold,
        triggeredRules: detectionResult.triggeredRules
      });
    } else {
      logger.log("Legitimacy score acceptable - no action needed");
    }

  } catch (error) {
    logger.error("Protection failed:", error.message);
    
    // Emergency fallback - if we can't load rules but detect MS elements, warn user
    try {
      const hasBasicMSElements = document.querySelector('input[name="loginfmt"]') || 
                                document.querySelector('#i0116');
      const isNotMSDomain = !location.hostname.includes('microsoftonline.com');
      
      if (hasBasicMSElements && isNotMSDomain) {
        showFallbackWarning();
      }
    } catch (fallbackError) {
      logger.error("Even fallback protection failed:", fallbackError.message);
    }
  }
}

/**
 * Show blocking overlay
 */
function showBlockingOverlay(reason, analysisData) {
  try {
    if (document.getElementById('ms365-block-overlay')) return;

    const overlay = document.createElement('div');
    overlay.id = 'ms365-block-overlay';
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
      border-radius: 12px !important;
      max-width: 600px !important;
      text-align: center !important;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4) !important;
    `;

    const detailsText = analysisData?.rule ? 
      `<br><small>Rule: ${analysisData.rule.id}</small>` :
      analysisData?.triggeredRules?.length > 0 ? 
      `<br><small>Score: ${analysisData.score}/${analysisData.threshold}</small>` : '';

    content.innerHTML = `
      <div style="color: #d32f2f; font-size: 64px; margin-bottom: 24px;">🛡️</div>
      <h1 style="color: #d32f2f; margin: 0 0 16px 0; font-size: 28px; font-weight: 600;">Phishing Site Blocked</h1>
      <p style="color: #555; margin: 0 0 24px 0; line-height: 1.6; font-size: 16px;">
        <strong>Microsoft 365 login page detected on untrusted domain</strong>
        <br><br>
        ${reason}
        ${detailsText}
      </p>
      <div style="display: flex; gap: 12px; justify-content: center;">
        <button id="ms365-go-back" style="
          background: #1976d2; 
          color: white; 
          border: none; 
          padding: 14px 28px; 
          border-radius: 6px; 
          font-size: 16px; 
          font-weight: 500;
          cursor: pointer;
        ">Go Back Safely</button>
        <button id="ms365-continue" style="
          background: #757575; 
          color: white; 
          border: none; 
          padding: 14px 28px; 
          border-radius: 6px; 
          font-size: 16px; 
          font-weight: 500;
          cursor: pointer;
        ">Continue Anyway</button>
      </div>
    `;

    overlay.appendChild(content);

    // Add event handlers
    content.querySelector('#ms365-go-back').addEventListener('click', () => {
      try {
        window.history.back();
      } catch {
        window.close();
      }
    });

    content.querySelector('#ms365-continue').addEventListener('click', () => {
      overlay.remove();
    });

    document.documentElement.appendChild(overlay);
    logger.log("Blocking overlay displayed");
    
  } catch (error) {
    logger.error("Failed to show blocking overlay:", error.message);
    showFallbackWarning();
  }
}

/**
 * Show warning banner
 */
function showWarningBanner(reason, analysisData) {
  try {
    if (document.getElementById('ms365-warning-banner')) return;

    const banner = document.createElement('div');
    banner.id = 'ms365-warning-banner';
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
      font-size: 15px !important;
      font-weight: 500 !important;
      z-index: 2147483647 !important;
      box-shadow: 0 4px 12px rgba(0,0,0,0.2) !important;
      display: flex !important;
      align-items: center !important;
      justify-content: center !important;
      gap: 16px !important;
    `;

    const scoreText = analysisData?.score !== undefined ? 
      ` (Score: ${analysisData.score}/${analysisData.threshold})` : '';

    banner.innerHTML = `
      <span>⚠️ Microsoft 365 Protection: ${reason}${scoreText} - Verify URL before entering credentials</span>
      <button style="
        background: rgba(255,255,255,0.2); 
        border: 1px solid white; 
        color: white; 
        padding: 6px 16px; 
        border-radius: 4px; 
        cursor: pointer;
        font-size: 14px;
        font-weight: 500;
      " onclick="this.parentElement.remove()">Dismiss</button>
    `;

    document.documentElement.appendChild(banner);

    // Auto-remove after 20 seconds
    setTimeout(() => {
      if (banner.parentNode) {
        banner.parentNode.removeChild(banner);
      }
    }, 20000);

    logger.log("Warning banner displayed");
    
  } catch (error) {
    logger.error("Failed to show warning banner:", error.message);
    showFallbackWarning();
  }
}

/**
 * Show valid badge for legitimate Microsoft pages
 */
function showValidBadge() {
  try {
    if (document.getElementById('ms365-valid-badge')) return;

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

    // Auto-remove after 6 seconds
    setTimeout(() => {
      if (badge.parentNode) {
        badge.parentNode.removeChild(badge);
      }
    }, 6000);

    logger.log("Valid badge displayed");
    
  } catch (error) {
    logger.error("Failed to show valid badge:", error.message);
  }
}

/**
 * Fallback warning for critical errors
 */
function showFallbackWarning() {
  try {
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
      font-weight: 500 !important;
      z-index: 2147483647 !important;
    `;
    warning.textContent = '⚠️ Microsoft 365 Protection: Suspicious login page detected - Verify URL before entering credentials';
    
    document.documentElement.appendChild(warning);
    
    setTimeout(() => {
      if (warning.parentNode) {
        warning.parentNode.removeChild(warning);
      }
    }, 10000);
    
  } catch (error) {
    // Last resort - console error
    console.error("Microsoft 365 Protection: Critical error - unable to display warning");
  }
}

/**
 * Disable form submissions
 */
function disableFormSubmissions() {
  try {
    const forms = document.querySelectorAll('form');
    let disabledCount = 0;
    
    forms.forEach(form => {
      try {
        // Add submit event blocker
        form.addEventListener('submit', (event) => {
          event.preventDefault();
          event.stopImmediatePropagation();
          showSubmissionBlockedMessage();
        }, true);
        
        // Visual indication
        form.style.opacity = '0.6';
        form.style.pointerEvents = 'none';
        form.setAttribute('data-ms365-blocked', 'true');
        
        disabledCount++;
      } catch {
        // Skip problematic forms but continue with others
      }
    });
    
    logger.log(`Disabled ${disabledCount} form submissions`);
  } catch (error) {
    logger.error("Failed to disable form submissions:", error.message);
  }
}

/**
 * Disable credential inputs
 */
function disableCredentialInputs() {
  try {
    const selectors = [
      'input[type="password"]',
      'input[name="loginfmt"]', 
      'input[name="passwd"]',
      'input[name="Password"]',
      '#i0116'
    ];
    
    let disabledCount = 0;
    
    selectors.forEach(selector => {
      try {
        const inputs = document.querySelectorAll(selector);
        inputs.forEach(input => {
          input.disabled = true;
          input.readOnly = true;
          input.style.opacity = '0.5';
          input.style.pointerEvents = 'none';
          input.style.filter = 'grayscale(1)';
          disabledCount++;
        });
      } catch {
        // Skip problematic selectors but continue with others
      }
    });
    
    logger.log(`Disabled ${disabledCount} credential inputs`);
  } catch (error) {
    logger.error("Failed to disable credential inputs:", error.message);
  }
}

/**
 * Show form submission blocked message
 */
function showSubmissionBlockedMessage() {
  try {
    const message = document.createElement('div');
    message.style.cssText = `
      position: fixed !important;
      top: 50% !important;
      left: 50% !important;
      transform: translate(-50%, -50%) !important;
      background: #d32f2f !important;
      color: white !important;
      padding: 24px !important;
      border-radius: 8px !important;
      font-family: system-ui, -apple-system, sans-serif !important;
      font-size: 18px !important;
      font-weight: 600 !important;
      z-index: 2147483647 !important;
      box-shadow: 0 8px 24px rgba(0,0,0,0.4) !important;
      text-align: center !important;
    `;
    message.textContent = '🛡️ Form submission blocked - This appears to be a phishing site';
    
    document.documentElement.appendChild(message);
    
    setTimeout(() => {
      if (message.parentNode) {
        message.parentNode.removeChild(message);
      }
    }, 4000);
    
  } catch (error) {
    logger.error("Failed to show submission blocked message:", error.message);
  }
}

/**
 * Log protection event to background script
 */
function logProtectionEvent(eventData) {
  try {
    chrome.runtime.sendMessage({
      type: 'LOG_EVENT',
      event: {
        ...eventData,
        timestamp: new Date().toISOString()
      }
    }, (response) => {
      if (chrome.runtime.lastError) {
        // Silent handling - logging is not critical for protection
      }
    });
  } catch (error) {
    // Silent handling - logging failures shouldn't break protection
  }
}

/**
 * Initialize protection when DOM is ready
 */
function initializeProtection() {
  try {
    if (protectionActive) {
      return;
    }
    
    logger.log("Initializing rule-driven Microsoft 365 protection");
    
    // Small delay to let page stabilize
    setTimeout(() => {
      runProtection().catch(error => {
        logger.error("Protection initialization failed:", error.message);
        // Show fallback warning if initialization fails
        showFallbackWarning();
      });
    }, 100);
    
  } catch (error) {
    logger.error("Failed to initialize protection:", error.message);
    showFallbackWarning();
  }
}

/**
 * Start protection based on document state
 */
function startProtection() {
  try {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', initializeProtection, { once: true });
    } else {
      initializeProtection();
    }
  } catch (error) {
    logger.error("Failed to start protection:", error.message);
    
    // Last resort - try again after delay
    setTimeout(() => {
      try {
        initializeProtection();
      } catch (fallbackError) {
        logger.error("Fallback initialization failed:", fallbackError.message);
        showFallbackWarning();
      }
    }, 1000);
  }
}

// Start the protection system
startProtection();

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
  protectionActive = false;
});
