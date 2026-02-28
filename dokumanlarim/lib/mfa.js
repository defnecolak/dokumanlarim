const crypto = require('crypto');

// Minimal TOTP (RFC 6238) implementation without extra deps.
// - Secret: Base32 (RFC 4648) without padding (common in authenticators)
// - Digits: 6
// - Time step: 30s

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function normalizeCode(code) {
  return String(code || '').replace(/\s+/g, '').replace(/-/g, '');
}

function base32Decode(base32) {
  const s = String(base32 || '').toUpperCase().replace(/=+$/g, '').replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of s) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function generateBase32Secret(bytes = 20) {
  const buf = crypto.randomBytes(bytes);
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

function hotp(secretBase32, counter, digits = 6, algo = 'sha1') {
  const key = base32Decode(secretBase32);
  const buf = Buffer.alloc(8);
  // counter is 64-bit, big endian
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    buf[i] = Number(c & 0xffn);
    c >>= 8n;
  }

  const hmac = crypto.createHmac(algo, key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binCode =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  const otp = binCode % 10 ** digits;
  return String(otp).padStart(digits, '0');
}

function totp(secretBase32, timeStepSeconds = 30, digits = 6, algo = 'sha1', now = Date.now()) {
  const counter = Math.floor(now / 1000 / timeStepSeconds);
  return hotp(secretBase32, counter, digits, algo);
}

function verifyTotp(code, secretBase32, window = 1, timeStepSeconds = 30, digits = 6, algo = 'sha1') {
  const candidate = normalizeCode(code);
  if (!candidate || candidate.length < digits) return false;
  const now = Date.now();
  for (let w = -window; w <= window; w++) {
    const t = now + w * timeStepSeconds * 1000;
    if (totp(secretBase32, timeStepSeconds, digits, algo, t) === candidate) return true;
  }
  return false;
}

function makeOtpAuthUrl({ issuer, accountName, secretBase32 }) {
  const label = encodeURIComponent(`${issuer}:${accountName}`);
  const issuerEnc = encodeURIComponent(issuer);
  const accountEnc = encodeURIComponent(accountName);
  return `otpauth://totp/${label}?secret=${secretBase32}&issuer=${issuerEnc}&account=${accountEnc}&digits=6&period=30`;
}

function generateBackupCodes(n = 10) {
  const codes = [];
  for (let i = 0; i < n; i++) {
    // 10 bytes => 80 bits of entropy; encode to base32-ish with only A-Z2-7 (human friendly)
    const raw = generateBase32Secret(10);
    // Group as XXXX-XXXX-XXXX for readability
    const formatted = raw.slice(0, 4) + '-' + raw.slice(4, 8) + '-' + raw.slice(8, 12);
    codes.push(formatted);
  }
  return codes;
}

function hashBackupCode({ code, userId, pepper }) {
  const norm = normalizeCode(code).toUpperCase();
  const h = crypto.createHash('sha256');
  h.update(String(userId || ''));
  h.update(':');
  h.update(norm);
  h.update(':');
  h.update(String(pepper || ''));
  return h.digest('hex');
}

function timingSafeEqualHex(a, b) {
  try {
    const ba = Buffer.from(String(a || ''), 'hex');
    const bb = Buffer.from(String(b || ''), 'hex');
    if (ba.length !== bb.length) return false;
    return crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

module.exports = {
  generateBase32Secret,
  verifyTotp,
  makeOtpAuthUrl,
  generateBackupCodes,
  hashBackupCode,
  timingSafeEqualHex,
  normalizeCode,
};
