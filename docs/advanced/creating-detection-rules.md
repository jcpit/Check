# Creating Detection Rules

The extension uses a rule-driven architecture where all detection logic is defined in `rules/detection-rules.json`. This file contains:

* **Trusted domain patterns** - Microsoft domains that are always trusted
* **Exclusion system** - Domains that should never be scanned
* **Phishing indicators** - Patterns that detect malicious content
* **Detection requirements** - Elements that identify Microsoft 365 login pages
* **Blocking rules** - Conditions that immediately block pages

Each of these rules has their own schema. You can create a custom rules file and host it anywhere publicly (e.g. your own fork of Check's GitHub repo, as an Azure Blob file, etc.), by default Check will always load the CyberDrain rule set from our repository. Sometimes you have custom pages, or specific logon pages that have a pattern that must be added, you can add these exclusions in your own configuration file, or contribute to the primary repository.

Contributions to our pages can be done via [https://github.com/CyberDrain/Check/blob/main/rules/detection-rules.json](../../rules/detection-rules.json)

### Exclusions

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

#### Pattern Format

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

#### Pattern Properties

* **id**: Unique identifier for the rule
* **pattern**: Regex pattern to match against page content
* **flags**: Regex flags (`i` for case-insensitive)
* **severity**: `critical`, `high`, `medium`, `low`
* **action**: `block`, `warn`, `monitor`
* **category**: Grouping category for the rule
* **confidence**: Confidence level (0.0 to 1.0)

#### Severity Levels

* **Critical** (25 points): Immediate blocking threats
* **High** (15 points): Serious threats requiring attention
* **Medium** (10 points): Moderate threats for warnings
* **Low** (5 points): Minor suspicious indicators

### **Context Requirements**

Only trigger if specific context is present:

```json
{
  "id": "context_example",
  "pattern": "malicious-pattern",
  "context_required": [
    "(?:microsoft|office|365|login|password|credential)"
  ]
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

#### Element Types

* **source\_content**: Match against page HTML source
* **css\_pattern**: Match against CSS styles
* **url\_pattern**: Match against the URL
* **text\_content**: Match against visible text

### Browser Console Testing

Use these functions in the browser console to test your rules:

```javascript
// Test detection patterns
testDetectionPatterns()

// Test phishing indicators
testPhishingIndicators()

// Check rules status
checkRulesStatus()

// Analyze current page
analyzeCurrentPage()

// Manual phishing check
manualPhishingCheck()

// Re-run protection
rerunProtection()
```
