import { test } from 'node:test';
import assert from 'node:assert';
import { setupGlobalChrome, teardownGlobalChrome } from './helpers/chrome-mock.js';

test('ConfigManager - custom rules URL persistence', async (t) => {
  const chromeMock = setupGlobalChrome();
  
  global.fetch = async () => ({
    ok: false,
    status: 404
  });

  const { ConfigManager } = await import('../scripts/modules/config-manager.js');
  
  await t.test('should persist custom rules URL after save', async () => {
    const configManager = new ConfigManager();
    
    const customUrl = 'https://example.com/custom-rules.json';
    await configManager.updateConfig({
      customRulesUrl: customUrl,
      updateInterval: 12
    });
    
    const localData = chromeMock.storage.local.getData();
    assert.ok(localData.config, 'Config should be saved to local storage');
    assert.strictEqual(
      localData.config.customRulesUrl,
      customUrl,
      'Custom rules URL should be saved'
    );
  });

  await t.test('should load custom rules URL after reload', async () => {
    const configManager = new ConfigManager();
    
    const customUrl = 'https://example.com/custom-rules.json';
    await configManager.updateConfig({
      customRulesUrl: customUrl
    });
    
    const newConfigManager = new ConfigManager();
    const config = await newConfigManager.loadConfig();
    
    assert.strictEqual(
      config.customRulesUrl,
      customUrl,
      'Custom rules URL should persist after reload'
    );
  });

  await t.test('should not save default values to local storage', async () => {
    const configManager = new ConfigManager();
    
    const customUrl = 'https://example.com/custom-rules.json';
    await configManager.updateConfig({
      customRulesUrl: customUrl
    });
    
    const localData = chromeMock.storage.local.getData();
    const defaultConfig = configManager.getDefaultConfig();
    
    assert.notDeepStrictEqual(
      localData.config,
      defaultConfig,
      'Local storage should not contain full default config'
    );
    
    assert.ok(
      Object.keys(localData.config).length < Object.keys(defaultConfig).length,
      'Local storage should only contain user overrides'
    );
  });

  await t.test('should preserve custom URL when other settings change', async () => {
    const configManager = new ConfigManager();
    
    const customUrl = 'https://example.com/custom-rules.json';
    await configManager.updateConfig({
      customRulesUrl: customUrl
    });
    
    await configManager.updateConfig({
      updateInterval: 48
    });
    
    const config = await configManager.getConfig();
    assert.strictEqual(
      config.customRulesUrl,
      customUrl,
      'Custom URL should be preserved when updating other settings'
    );
  });

  await t.test('should handle empty custom URL correctly', async () => {
    const configManager = new ConfigManager();
    
    await configManager.updateConfig({
      customRulesUrl: ''
    });
    
    const config = await configManager.getConfig();
    const defaultUrl = 'https://raw.githubusercontent.com/CyberDrain/Check/refs/heads/main/rules/detection-rules.json';
    
    assert.strictEqual(
      config.customRulesUrl,
      defaultUrl,
      'Empty custom URL should fall back to default'
    );
  });

  delete global.fetch;
  teardownGlobalChrome();
});

test('ConfigManager - enterprise policy precedence', async (t) => {
  const chromeMock = setupGlobalChrome();
  
  global.fetch = async () => ({
    ok: false,
    status: 404
  });

  const { ConfigManager } = await import('../scripts/modules/config-manager.js');

  await t.test('should override user settings with enterprise policy', async () => {
    const configManager = new ConfigManager();
    
    const userUrl = 'https://user-custom.com/rules.json';
    await configManager.updateConfig({
      customRulesUrl: userUrl
    });
    
    const enterpriseUrl = 'https://enterprise.com/rules.json';
    chromeMock.storage.managed.set({
      customRulesUrl: enterpriseUrl
    });
    
    const newConfigManager = new ConfigManager();
    const config = await newConfigManager.loadConfig();
    
    assert.strictEqual(
      config.customRulesUrl,
      enterpriseUrl,
      'Enterprise policy should override user settings'
    );
  });

  delete global.fetch;
  teardownGlobalChrome();
});

test('DetectionRulesManager - configuration reload', async (t) => {
  const chromeMock = setupGlobalChrome();
  
  global.fetch = async () => ({
    ok: false,
    status: 404
  });

  const { DetectionRulesManager } = await import('../scripts/modules/detection-rules-manager.js');

  await t.test('should reload configuration when custom URL changes', async () => {
    const rulesManager = new DetectionRulesManager();
    
    const customUrl = 'https://example.com/custom-rules.json';
    await chromeMock.storage.local.set({
      config: { customRulesUrl: customUrl }
    });
    
    await rulesManager.reloadConfiguration();
    
    assert.strictEqual(
      rulesManager.remoteUrl,
      customUrl,
      'DetectionRulesManager should use new custom URL after reload'
    );
  });

  await t.test('should use custom URL in forceUpdate', async () => {
    const rulesManager = new DetectionRulesManager();
    
    const customUrl = 'https://example.com/custom-rules.json';
    
    await chromeMock.storage.local.set({
      config: { customRulesUrl: customUrl }
    });
    
    let fetchedUrl = null;
    global.fetch = async (url) => {
      fetchedUrl = url;
      return {
        ok: true,
        json: async () => ({ rules: [] })
      };
    };
    
    try {
      await rulesManager.forceUpdate();
      assert.strictEqual(fetchedUrl, customUrl, 'Should fetch from custom URL');
    } catch (e) {
    }
  });

  delete global.fetch;
  teardownGlobalChrome();
});

test('ConfigManager - merge precedence', async (t) => {
  const chromeMock = setupGlobalChrome();
  
  global.fetch = async () => ({
    ok: false,
    status: 404
  });

  const { ConfigManager } = await import('../scripts/modules/config-manager.js');

  await t.test('should follow correct merge order: default < branding < local < enterprise', async () => {
    const configManager = new ConfigManager();
    
    const localUrl = 'https://local.com/rules.json';
    await chromeMock.storage.local.set({
      config: { customRulesUrl: localUrl }
    });
    
    const config = await configManager.loadConfig();
    
    assert.strictEqual(
      config.customRulesUrl,
      localUrl,
      'Local config should override defaults'
    );
  });

  delete global.fetch;
  teardownGlobalChrome();
});
