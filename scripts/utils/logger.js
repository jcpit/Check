const levels = { error: 0, warn: 1, info: 2, debug: 3 };

let config = {
  level: "info",
  enabled: true,
  output: console,
};

export function init({ level = "info", enabled = true, output = console } = {}) {
  config.level = level;
  config.enabled = enabled;
  config.output = output || console;
}

function shouldLog(level) {
  return config.enabled && levels[level] <= levels[config.level];
}

async function store(level, args) {
  try {
    const result = await chrome.storage.local.get(["debugLogs"]);
    const logs = result.debugLogs || [];
    const message = args
      .map((arg) => {
        if (arg instanceof Error) {
          return arg.stack || arg.message;
        }
        if (typeof arg === "object") {
          try {
            return JSON.stringify(arg);
          } catch {
            return String(arg);
          }
        }
        return String(arg);
      })
      .join(" ");

    logs.push({ level, message, timestamp: new Date().toISOString() });
    if (logs.length > 1000) {
      logs.splice(0, logs.length - 1000);
    }

    await chrome.storage.local.set({ debugLogs: logs });
  } catch (e) {
    console.error("Failed to store log:", e);
  }
}

export function error(...args) {
  if (shouldLog("error")) {
    config.output.error(...args);
    store("error", args);
  }
}

export function warn(...args) {
  if (shouldLog("warn")) {
    config.output.warn(...args);
    store("warn", args);
  }
}

export function log(...args) {
  if (shouldLog("info")) {
    config.output.log(...args);
    store("info", args);
  }
}

export function debug(...args) {
  if (shouldLog("debug")) {
    if (typeof config.output.debug === "function") {
      config.output.debug(...args);
    } else {
      config.output.log(...args);
    }
    store("debug", args);
  }
}

export default {
  init,
  log,
  warn,
  error,
  debug,
};
