const crypto = require('crypto');
const { nanoid } = require('nanoid');

function nowISO() {
  return new Date().toISOString();
}

function safeId(prefix) {
  return `${prefix}_${nanoid(12)}`;
}

function randomToken(len = 32) {
  // URL-safe token
  return crypto.randomBytes(len).toString('base64url');
}

function clampInt(n, min, max) {
  const x = parseInt(n, 10);
  if (Number.isNaN(x)) return min;
  return Math.max(min, Math.min(max, x));
}

function isLocalhost(host) {
  return host.startsWith('localhost') || host.startsWith('127.0.0.1');
}

function getBaseUrl(req) {
  // İstek context'i varsa onu tercih et.
  // (Yanlış BASE_URL env yüzünden e-posta linklerinin app.* gibi olmayan bir subdomain'e gitmesini engeller.)
  if (req && req.headers) {
    const protoHeader = String(req.headers['x-forwarded-proto'] || req.protocol || 'http');
    const proto = protoHeader.split(',')[0].trim();
    const host = String(req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
    if (host) return stripTrailingSlash(`${proto}://${host}`);
  }

  const fromEnv = (process.env.BASE_URL || '').trim();
  if (fromEnv) return stripTrailingSlash(fromEnv);

  // Fallback (yerel/dev)
  const proto = req && req.protocol ? req.protocol : 'http';
  const host = req && req.headers && req.headers.host ? req.headers.host : `localhost:${process.env.PORT || 3000}`;
  return stripTrailingSlash(`${proto}://${host}`);
}

function hmacSha256Base64(secret, data) {
  return crypto.createHmac('sha256', secret).update(data).digest('base64');
}

function formatBytes(bytes) {
  const n = Number(bytes || 0);
  if (n < 1024) return `${n} B`;
  const kb = n / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB`;
  const mb = kb / 1024;
  if (mb < 1024) return `${mb.toFixed(1)} MB`;
  const gb = mb / 1024;
  return `${gb.toFixed(1)} GB`;
}

module.exports = {
  nowISO,
  safeId,
  randomToken,
  clampInt,
  isLocalhost,
  getBaseUrl,
  hmacSha256Base64,
  formatBytes,
};
