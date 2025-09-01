/**
 * Blocked Page JavaScript - CSP Compliant External Script
 * Handles URL defanging, branding, and user interactions for blocked pages
 */

// Parse URL parameters to get block details with enhanced defanging
function parseUrlParams() {
  console.log("parseUrlParams called");
  console.log("Current URL:", window.location.href);
  
  const urlParams = new URLSearchParams(window.location.search);
  console.log("URL params:", urlParams.toString());
  console.log("All URL params:");
  for (const [key, value] of urlParams.entries()) {
    console.log(`  ${key}: ${value}`);
  }

  // Parse details from the new format (from content script)
  const detailsParam = urlParams.get("details");
  console.log("Details param:", detailsParam);
  
  if (detailsParam) {
    try {
      const details = JSON.parse(decodeURIComponent(detailsParam));
      console.log("Parsed details:", details);
      
      // Update blocked URL with defanging
      if (details.url) {
        console.log("Setting blocked URL to:", details.url);
        const defangedUrl = defangUrl(details.url);
        console.log("Defanged URL:", defangedUrl);
        document.getElementById("blockedUrl").textContent = defangedUrl;
      } else {
        console.log("No URL in details, using fallback");
        const fallbackUrl = document.referrer || "Unknown URL";
        document.getElementById("blockedUrl").textContent = defangUrl(fallbackUrl);
      }
      
      // Update block reason
      if (details.reason) {
        console.log("Setting block reason to:", details.reason);
        document.getElementById("blockReason").textContent = details.reason;
      }
      
      // Update threat category based on rule or score
      if (details.rule) {
        document.getElementById("threatCategory").textContent = `Rule: ${details.rule}`;
      } else if (details.score !== undefined) {
        document.getElementById("threatCategory").textContent = `Score: ${details.score}/${details.threshold}`;
      }
      
    } catch (error) {
      console.warn("Failed to parse block details:", error);
      console.log("Error details:", error.message);
      // Fallback to legacy URL parsing
      const blockedUrl = urlParams.get("url") || document.referrer || "Unknown URL";
      console.log("Using fallback URL:", blockedUrl);
      document.getElementById("blockedUrl").textContent = defangUrl(blockedUrl);
    }
  } else {
    console.log("No details param, using legacy parsing");
    // Legacy URL parsing for backward compatibility
    const blockedUrl = urlParams.get("url") || document.referrer || "Unknown URL";
    console.log("Legacy blocked URL:", blockedUrl);
    document.getElementById("blockedUrl").textContent = defangUrl(blockedUrl);
    
    const reason = urlParams.get("reason");
    if (reason) {
      console.log("Legacy reason:", reason);
      document.getElementById("blockReason").textContent = decodeURIComponent(reason);
    }
  }
  
  console.log("Final blocked URL element text:", document.getElementById("blockedUrl").textContent);
}

function defangUrl(url) {
  if (!url || url === "about:blank" || url.includes("chrome-extension://")) {
    return "Unknown URL";
  }
  
  // Defang the URL by replacing only colons (less aggressive)
  let defanged = url.replace(/:/g, "[:]");   // Replace colons only
  
  // Truncate if too long
  if (defanged.length > 80) {
    defanged = defanged.substring(0, 77) + "...";
  }
  
  return defanged;
}

function truncateUrl(url) {
  if (url.length > 50) {
    return url.substring(0, 47) + "...";
  }
  return url;
}

function goBack() {
  if (window.history.length > 1) {
    window.history.back();
  } else {
    window.location.href = "about:blank";
  }
}

function contactAdmin() {
  console.log("contactAdmin function called");
  
  // Try to get support email from storage, with fallback
  try {
    if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['brandingConfig'], (result) => {
        console.log("Storage result:", result);
        const supportEmail = result.brandingConfig?.supportEmail || 'support@cyberdrain.com';
        console.log("Using support email:", supportEmail);
        openMailto(supportEmail);
      });
    } else {
      console.log("Chrome storage not available, using default email");
      openMailto('support@cyberdrain.com');
    }
  } catch (error) {
    console.error("Error accessing storage:", error);
    openMailto('support@cyberdrain.com');
  }
}

function openMailto(supportEmail) {
  const blockedUrl = document.getElementById("blockedUrl").textContent;
  const reason = document.getElementById("blockReason").textContent;
  
  // Create subject with defanged URL
  const subject = encodeURIComponent(`Blocked page: ${blockedUrl}`);
  
  const body = encodeURIComponent(`I am requesting access to a website that was blocked by Microsoft 365 Protection.

Blocked URL: ${blockedUrl}
Block Reason: ${reason}
Time: ${new Date().toLocaleString()}

I believe this website should be accessible for business purposes. Please review and whitelist if appropriate.

Additional context:
[Please provide any additional business justification]`);
  
  const mailtoUrl = `mailto:${supportEmail}?subject=${subject}&body=${body}`;
  console.log("Opening mailto URL:", mailtoUrl);
  
  try {
    window.location.href = mailtoUrl;
  } catch (error) {
    console.error("Error opening mailto:", error);
    // Fallback: try using window.open
    try {
      window.open(mailtoUrl);
    } catch (openError) {
      console.error("Error with window.open:", openError);
      alert(`Please contact your IT administrator at: ${supportEmail}`);
    }
  }
}

// Load branding configuration with proper async handling
async function loadBranding() {
  console.log("loadBranding function called");
  
  try {
    // Load branding from extension storage with Promise wrapper
    const storageResult = await new Promise((resolve) => {
      if (typeof chrome !== "undefined" && chrome.storage && chrome.storage.local) {
        chrome.storage.local.get(['brandingConfig'], (result) => {
          console.log("Storage get result:", result);
          resolve(result.brandingConfig || null);
        });
      } else {
        console.log("Chrome storage not available");
        resolve(null);
      }
    });
    
    console.log("Storage branding config:", storageResult);
    
    if (storageResult) {
      // Apply branding from storage
      const companyName = storageResult.companyName || storageResult.productName || "Check";
      console.log("Setting company name from storage to:", companyName);
      document.getElementById("companyName").textContent = companyName;
      document.title = `Access Blocked - ${companyName}`;
      
      // Update product name if available
      if (storageResult.productName) {
        console.log("Setting product name:", storageResult.productName);
        document.querySelector('h1').textContent = `Access Blocked by ${storageResult.productName}`;
      }
      
      // Handle custom logo - replace shield with logo
      if (storageResult.logoUrl) {
        console.log("Setting custom logo as main icon:", storageResult.logoUrl);
        const customLogo = document.getElementById("customLogo");
        const defaultIcon = document.getElementById("defaultIcon");
        
        if (customLogo && defaultIcon) {
          // Try to load the logo
          const logoSrc = storageResult.logoUrl.startsWith("http") ? 
            storageResult.logoUrl : 
            chrome.runtime.getURL(storageResult.logoUrl);
          
          console.log("Loading logo from:", logoSrc);
          
          customLogo.src = logoSrc;
          customLogo.style.width = "80px";
          customLogo.style.height = "80px";
          customLogo.style.borderRadius = "50%";
          customLogo.style.objectFit = "contain";
          customLogo.style.background = storageResult.primaryColor || "#f77f00";
          customLogo.style.padding = "10px";
          
          customLogo.onload = () => {
            console.log("Custom logo loaded successfully - replacing shield");
            customLogo.style.display = "block";
            defaultIcon.style.display = "none";
          };
          customLogo.onerror = () => {
            console.warn("Failed to load custom logo, using default shield icon");
            customLogo.style.display = "none";
            defaultIcon.style.display = "flex";
          };
        }
      } else {
        console.log("No custom logo in storage, using default shield icon");
        const customLogo = document.getElementById("customLogo");
        const defaultIcon = document.getElementById("defaultIcon");
        if (customLogo && defaultIcon) {
          customLogo.style.display = "none";
          defaultIcon.style.display = "flex";
        }
      }
      
      // Update primary color if available
      if (storageResult.primaryColor) {
        console.log("Applying primary color:", storageResult.primaryColor);
        const style = document.createElement('style');
        style.textContent = `
          .icon { background: ${storageResult.primaryColor} !important; }
          h1 { color: ${storageResult.primaryColor} !important; }
          .btn-primary { background: ${storageResult.primaryColor} !important; }
          .btn-primary:hover { background: ${storageResult.primaryColor}dd !important; }
        `;
        document.head.appendChild(style);
      }
      
      // Load custom CSS if available
      if (storageResult.customCss) {
        console.log("Loading custom CSS");
        const customStyle = document.createElement('style');
        customStyle.id = 'custom-branding-css';
        customStyle.textContent = storageResult.customCss;
        document.head.appendChild(customStyle);
      }
      
      return; // Exit early if we loaded from storage
    }
    
    // Fallback: try to load from branding.json file
    console.log("No storage config, trying branding.json file");
    try {
      const response = await fetch(chrome.runtime.getURL("config/branding.json"));
      if (response.ok) {
        const brandingConfig = await response.json();
        console.log("Loaded branding from file:", brandingConfig);
        
        const companyName = brandingConfig.companyName || "Check";
        console.log("Setting company name from file to:", companyName);
        document.getElementById("companyName").textContent = companyName;
        document.title = `Access Blocked - ${companyName}`;
      }
    } catch (fetchError) {
      console.warn("Could not load branding.json:", fetchError);
    }
    
  } catch (error) {
    console.error("Could not load branding configuration:", error);
  }
  
  // Final fallback - ensure something is always set
  const currentCompanyName = document.getElementById("companyName").textContent;
  if (!currentCompanyName || currentCompanyName.trim() === "") {
    console.log("No company name set, using final fallback");
    document.getElementById("companyName").textContent = "Check";
    document.title = "Access Blocked - Check";
  }
  
  console.log("Final company name:", document.getElementById("companyName").textContent);
}

// Initialize page with CSP-compliant event handlers
document.addEventListener("DOMContentLoaded", () => {
  console.log("DOM loaded, initializing page");
  
  // Add event listeners for buttons (CSP compliant)
  document.getElementById("goBackBtn").addEventListener("click", goBack);
  document.getElementById("contactAdminBtn").addEventListener("click", contactAdmin);
  
  // Parse URL parameters and load branding
  parseUrlParams();
  loadBranding();
  
  // Debug: Check if URL was set properly
  setTimeout(() => {
    console.log("After 1 second - URL element:", document.getElementById("blockedUrl").textContent);
  }, 1000);
});

// Handle keyboard shortcuts
document.addEventListener("keydown", (e) => {
  // ESC key to go back
  if (e.key === "Escape") {
    goBack();
  }
  // Ctrl+R or F5 to go back (prevent refresh on blocked page)
  if ((e.ctrlKey && e.key === "r") || e.key === "F5") {
    e.preventDefault();
    goBack();
  }
});

// Prevent right-click context menu on blocked page
document.addEventListener("contextmenu", (e) => {
  e.preventDefault();
});

// Log page view for analytics
if (typeof chrome !== "undefined" && chrome.runtime) {
  chrome.runtime.sendMessage({
    type: "LOG_EVENT",
    event: {
      type: "blocked_page_viewed",
      url: new URLSearchParams(window.location.search).get("url"),
      timestamp: new Date().toISOString(),
    },
  });
}