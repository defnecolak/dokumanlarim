#!/usr/bin/env node
require('dotenv').config();

const fs = require('fs');
const path = require('path');

const pkg = require('../package.json');

const NODE_ENV = (process.env.NODE_ENV || 'development').trim();
const IS_PROD = NODE_ENV === 'production';
const STRICT = String(process.env.DOCTOR_STRICT || '0') === '1';

function icon(kind) {
  if (kind === 'ok') return '✅';
  if (kind === 'warn') return '⚠️';
  return '🔥';
}

function line(kind, title, detail) {
  const d = detail ? ` — ${detail}` : '';
  console.log(`${icon(kind)} ${title}${d}`);
}

function isTruthy(v) {
  const s = String(v || '').trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

function check() {
  const blockers = [];
  const warns = [];

  console.log(`\nDökümanlarım Launch Doctor v${pkg.version} (env=${NODE_ENV})\n`);

  // --- Core environment ---
  line('ok', 'Node env', NODE_ENV);

  const baseUrl = (process.env.BASE_URL || '').trim();
  if (IS_PROD) {
    if (!baseUrl) {
      blockers.push('BASE_URL boş (prod domain için gerekli)');
      line('fail', 'BASE_URL', 'boş (prod için https://domainin.com olmalı)');
    } else if (!baseUrl.startsWith('https://')) {
      blockers.push('BASE_URL https:// ile başlamıyor');
      line('fail', 'BASE_URL', `${baseUrl} (https:// olmalı)`);
    } else {
      line('ok', 'BASE_URL', baseUrl);
    }
  } else {
    line('warn', 'BASE_URL', baseUrl || '(boş) — local testte sorun değil');
  }

  const TRUST_PROXY = isTruthy(process.env.TRUST_PROXY);
  const FORCE_HTTPS = isTruthy(process.env.FORCE_HTTPS);
  const COOKIE_SECURE = isTruthy(process.env.COOKIE_SECURE);

  if (IS_PROD) {
    if (!TRUST_PROXY) {
      warns.push('TRUST_PROXY=1 önerilir (Cloudflare/Nginx arkasında gerçek IP ve https tespiti için)');
      line('warn', 'TRUST_PROXY', '0 (öneri: 1)');
    } else {
      line('ok', 'TRUST_PROXY', '1');
    }

    if (!FORCE_HTTPS) {
      warns.push('FORCE_HTTPS=1 önerilir (http → https redirect)');
      line('warn', 'FORCE_HTTPS', '0 (öneri: 1)');
    } else {
      line('ok', 'FORCE_HTTPS', '1');
    }

    if (!COOKIE_SECURE) {
      blockers.push('COOKIE_SECURE=1 değil (prod cookie Secure olmalı)');
      line('fail', 'COOKIE_SECURE', '0 (prod için 1 olmalı)');
    } else {
      line('ok', 'COOKIE_SECURE', '1');
    }
  } else {
    line('ok', 'TRUST_PROXY', TRUST_PROXY ? '1' : '0');
    line('ok', 'FORCE_HTTPS', FORCE_HTTPS ? '1' : '0');
    line('ok', 'COOKIE_SECURE', COOKIE_SECURE ? '1' : '0');
  }

  // --- Session secrets ---
  const raw = (process.env.SESSION_SECRETS || process.env.SESSION_SECRET || '').trim();
  const keys = raw.split(',').map(s => s.trim()).filter(Boolean);
  const primary = keys[0] || '';
  const weak = (!primary || primary.length < 24 || primary.includes('change-me') || primary.includes('dev-secret'));

  if (weak) {
    blockers.push('SESSION_SECRETS/SESSION_SECRET zayıf veya boş');
    line('fail', 'Session secret', '24+ karakter random olmalı (tercihen SESSION_SECRETS=key1,key2). İpucu: npm run gen:secrets');
  } else {
    line('ok', 'Session secret', `primary length=${primary.length}, keys=${keys.length}`);
    if (keys.length < 2) {
      warns.push('SESSION_SECRETS key rotation için 2+ anahtar önerilir');
      line('warn', 'Key rotation', 'SESSION_SECRETS=key1,key2 önerilir');
    } else {
      line('ok', 'Key rotation', `${keys.length} anahtar`);
    }
  }

  // --- Email / SMTP ---
  const smtpHost = (process.env.SMTP_HOST || '').trim();
  const smtpFrom = (process.env.SMTP_FROM || '').trim();
  if (!smtpHost) {
    const msg = 'SMTP_HOST boş (e-posta daveti/hatırlatma çalışmaz)';
    if (STRICT || (IS_PROD && isTruthy(process.env.EMAIL_FEATURES_REQUIRED))) {
      blockers.push(msg);
      line('fail', 'SMTP', msg);
    } else {
      warns.push(msg);
      line('warn', 'SMTP', msg);
    }
  } else {
    line('ok', 'SMTP', smtpHost);
    if (!smtpFrom) {
      warns.push('SMTP_FROM boş (deliverability için domain’li From önerilir)');
      line('warn', 'SMTP_FROM', 'boş');
    } else {
      line('ok', 'SMTP_FROM', smtpFrom);
    }
  }

  // --- Turnstile / CAPTCHA ---
  const tsSite = (process.env.TURNSTILE_SITE_KEY || '').trim();
  const tsSecret = (process.env.TURNSTILE_SECRET_KEY || '').trim();
  if (IS_PROD && (!tsSite || !tsSecret)) {
    warns.push('Turnstile kapalı (signup abuse artabilir). TURNSTILE_SITE_KEY + TURNSTILE_SECRET_KEY önerilir.');
    line('warn', 'Turnstile', 'kapalı');
  } else {
    line('ok', 'Turnstile', (tsSite && tsSecret) ? 'açık' : 'kapalı');
  }

  // --- Central alert webhook ---
  const alertWebhook = (process.env.SECURITY_ALERT_WEBHOOK_URL || '').trim();
  if (!alertWebhook) {
    warns.push('SECURITY_ALERT_WEBHOOK_URL boş (kritik olaylarda alarm gelmez)');
    line('warn', 'Security alert webhook', 'kapalı');
  } else {
    line('ok', 'Security alert webhook', 'açık');
  }

  // --- Storage ---
  const provider = (process.env.STORAGE_PROVIDER || 'local').trim();
  if (provider === 's3') {
    const bucket = (process.env.S3_BUCKET || '').trim();
    if (!bucket) {
      blockers.push('STORAGE_PROVIDER=s3 ama S3_BUCKET boş');
      line('fail', 'Storage', 's3 ama S3_BUCKET boş');
    } else {
      line('ok', 'Storage', `s3 bucket=${bucket}`);
    }
  } else {
    line('warn', 'Storage', 'local (prod’da backup/restore + disk alarmı şart)');
  }

  // --- Writable dirs ---
  const root = path.join(__dirname, '..');
  const dirs = ['data', 'uploads', 'backups'];
  for (const d of dirs) {
    const full = path.join(root, d);
    try {
      fs.mkdirSync(full, { recursive: true });
      fs.accessSync(full, fs.constants.W_OK);
      line('ok', `Write check`, d);
    } catch (e) {
      blockers.push(`${d} yazılabilir değil (${e.message})`);
      line('fail', `Write check`, `${d} yazılabilir değil`);
    }
  }

  console.log('\n--- Özet ---');
  if (blockers.length) {
    line('fail', 'Launch blocker', `${blockers.length} adet`);
    blockers.forEach((b) => console.log(`  - ${b}`));
  } else {
    line('ok', 'Launch blocker', 'yok');
  }

  if (warns.length) {
    line('warn', 'Öneriler', `${warns.length} adet`);
    warns.forEach((w) => console.log(`  - ${w}`));
  } else {
    line('ok', 'Öneriler', 'yok');
  }

  console.log('\nSonraki adım: docs/LAUNCH_GATE.md + docs/TEST_PLAN.md\n');

  process.exit(blockers.length ? 1 : 0);
}

check();
