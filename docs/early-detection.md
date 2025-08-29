# Early Detection Flow

The content script runs a lightweight scan before full initialization. Rules are loaded from `chrome.storage` if cached, falling back to `rules/detection-rules.json` bundled with the extension.

The early scan evaluates `url`, `form_action`, `dom`, `content`, `network`, and `header` rule types. Header data is sourced from the background service worker via the `GET_PAGE_HEADERS` message, which serves cached headers per tab for up to five minutes and purges entries when tabs close.

This pass quickly flags suspicious pages while the full `DetectionEngine` performs deeper analysis afterward.
