export class ChromeMock {
  constructor() {
    this.storage = {
      local: new LocalStorageMock(),
      managed: new ManagedStorageMock(),
      session: new SessionStorageMock()
    };
    this.runtime = new RuntimeMock();
  }

  reset() {
    this.storage.local.clear();
    this.storage.managed.clear();
    this.storage.session.clear();
    this.runtime.reset();
  }
}

class LocalStorageMock {
  constructor() {
    this.data = {};
  }

  get(keys) {
    return new Promise((resolve) => {
      if (typeof keys === 'string') {
        resolve({ [keys]: this.data[keys] });
      } else if (Array.isArray(keys)) {
        const result = {};
        keys.forEach(key => {
          if (key in this.data) {
            result[key] = this.data[key];
          }
        });
        resolve(result);
      } else if (keys === null || keys === undefined) {
        resolve({ ...this.data });
      } else {
        resolve({});
      }
    });
  }

  set(items) {
    return new Promise((resolve) => {
      Object.assign(this.data, items);
      resolve();
    });
  }

  remove(keys) {
    return new Promise((resolve) => {
      const keyArray = Array.isArray(keys) ? keys : [keys];
      keyArray.forEach(key => delete this.data[key]);
      resolve();
    });
  }

  clear() {
    this.data = {};
    return Promise.resolve();
  }

  getData() {
    return { ...this.data };
  }
}

class ManagedStorageMock {
  constructor() {
    this.data = {};
  }

  get(keys) {
    return new Promise((resolve) => {
      if (keys === null || keys === undefined) {
        resolve({ ...this.data });
      } else if (typeof keys === 'string') {
        resolve({ [keys]: this.data[keys] });
      } else if (Array.isArray(keys)) {
        const result = {};
        keys.forEach(key => {
          if (key in this.data) {
            result[key] = this.data[key];
          }
        });
        resolve(result);
      } else {
        resolve({});
      }
    });
  }

  set(items) {
    Object.assign(this.data, items);
  }

  clear() {
    this.data = {};
  }
}

class SessionStorageMock {
  constructor() {
    this.data = {};
  }

  get(keys) {
    return new Promise((resolve) => {
      if (typeof keys === 'string') {
        resolve({ [keys]: this.data[keys] });
      } else if (Array.isArray(keys)) {
        const result = {};
        keys.forEach(key => {
          if (key in this.data) {
            result[key] = this.data[key];
          }
        });
        resolve(result);
      } else {
        resolve({});
      }
    });
  }

  set(items) {
    return new Promise((resolve) => {
      Object.assign(this.data, items);
      resolve();
    });
  }

  clear() {
    this.data = {};
  }
}

class RuntimeMock {
  constructor() {
    this.manifest = {
      version: '1.0.5',
      name: 'Check'
    };
    this.id = 'test-extension-id';
    this.lastError = null;
    this.messageListeners = [];
  }

  getManifest() {
    return this.manifest;
  }

  getURL(path) {
    return `chrome-extension://${this.id}/${path}`;
  }

  sendMessage(message, callback) {
    setTimeout(() => {
      if (callback) {
        callback({ success: true });
      }
    }, 0);
  }

  onMessage = {
    addListener: (listener) => {
      this.messageListeners.push(listener);
    }
  };

  reset() {
    this.lastError = null;
    this.messageListeners = [];
  }
}

export function setupGlobalChrome() {
  const chromeMock = new ChromeMock();
  global.chrome = chromeMock;
  return chromeMock;
}

export function teardownGlobalChrome() {
  delete global.chrome;
}
