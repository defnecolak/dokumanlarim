#!/usr/bin/env node

/**
 * Production secret generator.
 *
 * Prints recommended .env lines.
 * - SESSION_SECRETS supports key rotation: key1,key2
 * - CAPTCHA_SIGNING_SECRET signs the math-CAPTCHA challenge payload
 *
 * Notes:
 * - Do NOT commit these values.
 * - Prefer adding them as environment variables in your host (Render, Fly, etc.)
 */

const crypto = require('crypto');

function hex(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

const session1 = hex(32);
const session2 = hex(32);
const captcha = hex(32);

console.log('# --- Dökümanlarım secure secrets (GENERATED) ---');
console.log(`# SESSION_SECRETS supports rotation: key1,key2`);
console.log(`SESSION_SECRETS=${session1},${session2}`);
console.log('');
console.log('# Optional (recommended)');
console.log(`CAPTCHA_SIGNING_SECRET=${captcha}`);
console.log('');
console.log('# If you are behind a reverse proxy (Cloudflare/Render), also set:');
console.log('# TRUST_PROXY=1');
console.log('# FORCE_HTTPS=1');
console.log('# COOKIE_SECURE=1');
