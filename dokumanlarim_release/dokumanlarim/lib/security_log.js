const fs = require('fs');
const path = require('path');

function safeString(x, max = 2000) {
  const s = String(x == null ? '' : x);
  return s.length > max ? s.slice(0, max) + '…' : s;
}

function getSecurityLogPath() {
  return path.join(__dirname, '..', 'data', 'security.log');
}

function logSecurityEvent(event, meta = {}) {
  try {
    const line = {
      ts: new Date().toISOString(),
      event,
      ...meta,
    };
    // Avoid huge / unsafe values.
    for (const k of Object.keys(line)) {
      if (typeof line[k] === 'string') line[k] = safeString(line[k]);
    }
    fs.appendFile(getSecurityLogPath(), JSON.stringify(line) + '\n', () => {});
  } catch {
    // Never throw from logging
  }
}

module.exports = { logSecurityEvent, getSecurityLogPath };
