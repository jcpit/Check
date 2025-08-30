import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { DetectionEngine } from '../scripts/modules/detection-engine.js';

function setupDom(html) {
  const dom = new JSDOM(html);
  global.window = dom.window;
  global.document = dom.window.document;
}

// Stub chrome runtime used by the detection engine
global.chrome = { runtime: { sendMessage: () => {}, lastError: null } };

test('setTimeout navigation without login is not flagged', async () => {
  setupDom('<script>setTimeout(()=>{window.location.href="/next";},1000);</script>');
  const engine = new DetectionEngine();
  engine.analyzeUrl = async () => ({ isSuspicious: false, threats: [] });
  const analysis = engine.contentAnalysisFunction();
  const threats = await engine.processContentAnalysis(1, 'http://example.com', analysis);
  assert.equal(threats.length, 0);
});

test('setTimeout UI update is not flagged', async () => {
  setupDom('<div id="d"></div><script>setTimeout(()=>{document.getElementById("d").textContent="hi";},1000);</script>');
  const engine = new DetectionEngine();
  engine.analyzeUrl = async () => ({ isSuspicious: false, threats: [] });
  const analysis = engine.contentAnalysisFunction();
  const threats = await engine.processContentAnalysis(1, 'http://example.com', analysis);
  assert.equal(threats.length, 0);
});

test('setTimeout navigation with password field triggers alert', async () => {
  setupDom('<input type="password"><script>setTimeout(()=>{window.location.href="/next";},1000);</script>');
  const engine = new DetectionEngine();
  engine.analyzeUrl = async () => ({ isSuspicious: false, threats: [] });
  const analysis = engine.contentAnalysisFunction();
  const threats = await engine.processContentAnalysis(1, 'http://example.com', analysis);
  assert.equal(threats.length, 1);
  assert.equal(threats[0].type, 'malicious_script');
  assert.equal(threats[0].severity, 'low');
});

  setupDom(`<script src="data:text/javascript;base64,${payload}"></script>`);
  const engine = new DetectionEngine();
  engine.analyzeUrl = async () => ({ isSuspicious: false, threats: [] });
  const analysis = engine.contentAnalysisFunction();
  const threats = await engine.processContentAnalysis(1, 'http://example.com', analysis);
  assert.equal(threats.length, 1);
  assert.equal(threats[0].type, 'malicious_script');
});
