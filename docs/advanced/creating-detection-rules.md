# Creating Detection Rules

The extension uses a rule-driven architecture where all detection logic is defined in [`rules/detection-rules.json`](https://github.com/CyberDrain/Check/blob/main/rules/detection-rules.json). This file contains:

* **Trusted domain patterns** - Microsoft domains that are always trusted
* **Exclusion system** - Domains that should never be scanned
* **Phishing indicators** - Patterns that detect malicious content
* **Detection requirements** - Elements that identify Microsoft 365 login pages
* **Blocking rules** - Conditions that immediately block pages
* **Rogue apps detection** - Dynamic detection of known malicious OAuth applications

Each of these rules has their own schema. You can create a custom rules file and host it anywhere publicly (e.g. your own fork of Check's GitHub repo, as an Azure Blob file, etc.). By default, Check loads the CyberDrain rule set from our repository every 24 hours (configurable). Custom rules URLs must be CORS-accessible and return valid JSON matching the schema.

**Important:** After updating rules via the UI or changing custom URLs, reload any open tabs for changes to take effect on those pages. The extension loads rules at startup and on the configured interval.

Contributions to our rules can be done via [https://github.com/CyberDrain/Check/blob/main/rules/detection-rules.json](https://github.com/CyberDrain/Check/blob/main/rules/detection-rules.json)

## Rule Configuration and Updates

Rules are managed by the [`DetectionRulesManager`](https://github.com/CyberDrain/Check/blob/main/scripts/modules/detection-rules-manager.js) class. It's job is to:

* Load rules at extension startup
* Check for updates based on the configured interval (default: 24 hours)
* Cache rules locally in browser storage for offline use
* Fall back to local rules ([`rules/detection-rules.json`](https://github.com/CyberDrain/Check/blob/main/rules/detection-rules.json)) if remote fetch fails

**Update Process:**

1. Rules are fetched from the configured URL (remote or fallback to local)
2. New rules are cached locally and immediately applied
3. A message is sent to notify other extension components of the update
4. Open tabs require reload to apply the new rules

## Exclusions

{% hint style="info" %}
**For simple exclusions:** Most users should use the [Settings → Detection Rules](../settings/detection-rules.md#url-allowlist-regex-or-url-with-wildcards) UI field, which supports both wildcards and regex patterns. This section is for advanced users creating custom rule files.
{% endhint %}

To exclude domains from all scanning (complete bypass), add them to the `exclusion_system.domain_patterns` array:

```json
{
  "exclusion_system": {
    "domain_patterns": [
      "^https://[^/]*\\.yourdomain\\.com(/.*)?$",
      "^https://[^/]*\\.trusted-site\\.org(/.*)?$"
    ]
  }
}
```

### Pattern Format

Use regex patterns that match the full URL:

* `^https://` - Must start with HTTPS
* `[^/]*` - Match any subdomain
* `\\.` - Escaped dot for literal dot matching
* `(/.*)?$` - Optional path at the end

### Trusted Domains

These domains get immediate trusted status with valid badges:

```json
"trusted_login_patterns": [
  "^https://login\\.microsoftonline\\.(com|us)$",
  "^https://login\\.microsoft\\.com$"
]
```

### Indicators

```json
{
  "id": "custom_indicator_001",
  "pattern": "(?:suspicious-pattern-here)",
  "flags": "i",
  "severity": "high",
  "description": "Description of what this detects",
  "action": "block",
  "category": "custom_category",
  "confidence": 0.85
}
```

### Pattern Properties

* **id**: Unique identifier for the rule
* **pattern**: Regex pattern to match against page content
* **flags**: Regex flags (`i` for case-insensitive)
* **severity**: `critical`, `high`, `medium`, `low`
* **action**: `block`, `warn`, `monitor`
* **category**: Grouping category for the rule
* **confidence**: Confidence level (0.0 to 1.0)

### Severity Levels

* **Critical** (25 points): Immediate blocking threats
* **High** (15 points): Serious threats requiring attention
* **Medium** (10 points): Moderate threats for warnings
* **Low** (5 points): Minor suspicious indicators

### Context Requirements

Only trigger if specific context is present:

```json
{
  "id": "context_example",
  "pattern": "malicious-pattern",
  "context_required": ["(?:microsoft|office|365|login|password|credential)"]
}
```

### Microsoft 365 Login Page Detection

Configure what elements identify a legitimate Microsoft 365 login page:

```json
"m365_detection_requirements": {
  "primary_elements": [
    {
      "id": "custom_primary",
      "type": "source_content",
      "pattern": "your-pattern-here",
      "description": "Custom primary element",
      "weight": 3,
      "category": "primary"
    }
  ],
  "secondary_elements": [
    {
      "id": "custom_secondary",
      "type": "css_pattern",
      "patterns": ["css-pattern-here"],
      "description": "Custom secondary element",
      "weight": 1,
      "category": "secondary"
    }
  ]
}
```

### Element Types

* **source_content**: Match against page HTML source
* **css_pattern**: Match against CSS styles
* **url_pattern**: Match against the URL
* **text_content**: Match against visible text

## Rogue Apps Detection

Check includes dynamic detection of known rogue OAuth applications that attempt to steal Microsoft 365 credentials. This feature:

* Automatically fetches the latest list of rogue apps from the [Huntress Labs repository](https://github.com/huntresslabs/rogueapps)
* Updates every 12 hours by default (configurable in `rogue_apps_detection` section)
* Warns users when they encounter known malicious OAuth applications
* Caches data locally for offline protection

The rogue apps detection is configured in the `rogue_apps_detection` section of the detection rules:

```json
"rogue_apps_detection": {
  "enabled": true,
  "source_url": "https://raw.githubusercontent.com/huntresslabs/rogueapps/refs/heads/main/public/rogueapps.json",
  "cache_duration": 86400000,
  "update_interval": 43200000,
  "detection_action": "warn",
  "severity": "high",
  "auto_update": true
}
```

## Browser Console Testing

Use these functions in the browser console to test your rules:

```javascript
// Test detection patterns
testDetectionPatterns();

// Test phishing indicators
testPhishingIndicators();

// Check rules status
checkRulesStatus();

// Analyze current page
analyzeCurrentPage();

// Manual phishing check
manualPhishingCheck();

// Re-run protection
rerunProtection();
```

**Note:** These console functions are available when the extension is loaded and debug logging is enabled. Use the browser's Developer Tools (F12) to access the console.
