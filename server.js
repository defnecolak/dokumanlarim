require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const cookieSession = require('cookie-session');
const multer = require('multer');
const yazl = require('yazl');
const nodemailer = require('nodemailer');
const mime = require('mime-types');
const cron = require('node-cron');
const crypto = require('crypto');
const dns = require('dns');


const { readDB, withDB } = require('./lib/db');
const { nowISO, safeId, randomToken, getBaseUrl, formatBytes } = require('./lib/utils');
const { hashPassword, verifyPassword, requireAuth, requireAuthLoose, requireOwner } = require('./lib/auth');
const { ensureCsrf, verifyCsrf } = require('./lib/csrf');
const { PLANS, getPlanForTenant } = require('./lib/plans');
const { getStorage } = require('./lib/storage');
const { iyzicoEnabled, getIyzicoConfig, initializeSubscriptionCheckout, retrieveSubscriptionCheckout, verifyAndRetrieveCheckout } = require('./lib/iyzico');

const { builtinTemplates, getAllTemplatesForTenant, findTemplateById, normalizeDocDef } = require('./lib/templates');
const { sendTenantNotifications, sendSecurityAlert } = require('./lib/notify');
const { logSecurityEvent } = require('./lib/security_log');
const {
  generateSecretBase32,
  totpVerify,
  makeOtpauthURL,
  generateBackupCodes,
  hashBackupCode,
  timingSafeEqualStr,
} = require('./lib/mfa');
const { t, getLocale, LANGUAGES } = require('./lib/i18n');
const { addNotification, getUnreadCount, getNotifications, markAsRead, markAllAsRead, deleteOldNotifications } = require('./lib/notifications');
const emailTemplates = require('./lib/emailTemplates');



function maskUrl(url) {
  if (!url) return url;
  // Mask vendor tokens in URLs like /v/<token>
  return String(url).replace(/\/v\/([A-Za-z0-9_-]{12,})/g, (m, token) => {
    const start = token.slice(0, 4);
    const end = token.slice(-4);
    return `/v/${start}…${end}`;
  });
}

const app = express();

// --- Config / Safety ---
const PORT = parseInt(process.env.PORT || '3000', 10);
const NODE_ENV = (process.env.NODE_ENV || 'development').trim();
const IS_PROD = NODE_ENV === 'production';

// --- Security hardening knobs ---
// Global request rate limit (per IP). Keep generous to avoid false positives.
// Tune with GLOBAL_RATE_LIMIT_MAX.
const GLOBAL_RATE_LIMIT_MAX = parseInt(process.env.GLOBAL_RATE_LIMIT_MAX || (IS_PROD ? '600' : '2000'), 10);

// Account lockout (per user) on repeated wrong password attempts.
const LOGIN_LOCK_MAX_FAILS = parseInt(process.env.LOGIN_LOCK_MAX_FAILS || '10', 10);
const LOGIN_LOCK_MINUTES = parseInt(process.env.LOGIN_LOCK_MINUTES || '30', 10);

// Enable a basic Content-Security-Policy for most pages.
// (We skip CSP for Iyzico checkout pages because their embed snippet can include inline JS.)
const CSP_ENABLED = String(process.env.CSP_ENABLED || '1') === '1';
const CSP_REPORT_ONLY = String(process.env.CSP_REPORT_ONLY || '0') === '1';
const TRUST_PROXY = String(process.env.TRUST_PROXY || (IS_PROD ? '1' : '0')) === '1';
const FORCE_HTTPS = String(process.env.FORCE_HTTPS || (IS_PROD ? '1' : '0')) === '1';
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || (IS_PROD ? '1' : '0')) === '1';
const COOKIE_DOMAIN = (process.env.COOKIE_DOMAIN || '').trim();
const ENABLE_CSV_EXPORT = String(process.env.ENABLE_CSV_EXPORT || '0') === '1';
const COOKIE_SAMESITE = (process.env.COOKIE_SAMESITE || 'lax').trim();

const APP_NAME = process.env.APP_NAME || 'Dökümanlarım';
// Public launch default support email
const SUPPORT_EMAIL = (() => {
  const v = (process.env.SUPPORT_EMAIL || '').trim();
  if (v && v !== 'support@example.com') return v;
  return 'ceylanatay@dokumanlarim.com';
})();

const TURNSTILE_SITE_KEY = (process.env.TURNSTILE_SITE_KEY || '').trim();
const TURNSTILE_SECRET_KEY = (process.env.TURNSTILE_SECRET_KEY || '').trim();

// Used to sign lightweight math-captcha tokens (dev fallback)
const CAPTCHA_SIGNING_SECRET = (process.env.CAPTCHA_SIGNING_SECRET || process.env.SESSION_SECRET || 'dev-secret-change-me');

const EMAIL_VERIFY_TTL_HOURS = Math.max(1, Math.min(168, parseInt(process.env.EMAIL_VERIFY_TTL_HOURS || '24', 10) || 24));
const PASSWORD_RESET_TTL_MINUTES = Math.max(10, Math.min(24 * 60, parseInt(process.env.PASSWORD_RESET_TTL_MINUTES || '60', 10) || 60));

function isEmailVerificationRequired() {
  const v = (process.env.EMAIL_VERIFICATION_REQUIRED || '').trim();
  if (v === '0' || v.toLowerCase() === 'false' || v.toLowerCase() === 'no') return false;
  if (v === '1' || v.toLowerCase() === 'true' || v.toLowerCase() === 'yes') return true;
  // Default: required in production
  return IS_PROD;
}

const APP_VERSION = require('./package.json').version;

const FILE_MAX_MB = parseFloat(process.env.FILE_MAX_MB || '15');
const MAX_BYTES = Math.floor(FILE_MAX_MB * 1024 * 1024);

// Upload allow-list (frontend accept + backend validation)
const UPLOAD_ALLOWED_EXT = ['.pdf', '.jpg', '.jpeg', '.png', '.webp', '.doc', '.docx', '.xls', '.xlsx', '.txt'];
const UPLOAD_ALLOWED_MIME = [
  'application/pdf',
  'image/jpeg',
  'image/png',
  'image/webp',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.ms-excel',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'text/plain',
];
// Used in <input accept=...>. Extensions work best across OS file pickers.
const UPLOAD_ACCEPT_ATTR = UPLOAD_ALLOWED_EXT.join(',');


if (NODE_ENV === 'production') {
  // In production, require a strong session signing key.
  // Prefer rotation: SESSION_SECRETS=key1,key2,... (first key signs new cookies; all are accepted).
  const raw = (process.env.SESSION_SECRETS || process.env.SESSION_SECRET || '').trim();
  const keys = raw.split(',').map(s => s.trim()).filter(Boolean);
  const primary = keys[0] || '';
  const weak = (!primary || primary.length < 24 || primary.includes('change-me') || primary.includes('dev-secret'));
  if (weak) {
    console.error('❌ SESSION_SECRETS/SESSION_SECRET zayıf. Production için en az 24+ karakter rastgele bir değer verin (tercihen 2+ anahtar).');
    process.exit(1);
  }
  if (keys.length < 2) {
    console.warn('⚠️ SESSION_SECRETS tek anahtar görünüyor. Key rotation için 2+ anahtar önerilir: SESSION_SECRETS=key1,key2');
  }
}

if (TRUST_PROXY) app.set('trust proxy', 1);

// Hide framework fingerprinting header.
app.disable('x-powered-by');

// Correlation / trace id for logs & security events
app.use((req, res, next) => {
  req.requestId = crypto.randomBytes(8).toString('hex');
  res.setHeader('X-Request-Id', req.requestId);
  next();
});

// Global rate limit (DoS / brute force baseline). More granular limits exist for auth/vendor endpoints.
const globalLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: GLOBAL_RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/health' || req.path.startsWith('/public'),
});
app.use(globalLimiter);

app.use(helmet({
  contentSecurityPolicy: false, // iyzico checkout html/script için
  // Token tabanlı linkler (/v/...) üçüncü taraf sitelere referer olarak sızmasın.
  referrerPolicy: { policy: 'same-origin' },
}));

// Basic CSP for most HTML pages (skip Iyzico checkout pages that include inline JS).
app.use((req, res, next) => {
  if (!CSP_ENABLED) return next();
  if (req.path.startsWith('/public')) return next();

  // iyzico checkout pages get a relaxed but still present CSP
  const isIyzicoPage = req.path.startsWith('/app/billing') || req.path.startsWith('/billing/iyzico');
  if (isIyzicoPage) {
    const iyzicoCSP = [
      "default-src 'self'",
      "base-uri 'self'",
      "object-src 'none'",
      "frame-ancestors 'none'",
      "script-src 'self' 'unsafe-inline' https://*.iyzipay.com https://*.iyzico.com",
      "style-src 'self' 'unsafe-inline' https://*.iyzipay.com https://*.iyzico.com",
      "frame-src 'self' https://*.iyzipay.com https://*.iyzico.com",
      "img-src 'self' data: https://*.iyzipay.com https://*.iyzico.com",
      "connect-src 'self' https://*.iyzipay.com https://*.iyzico.com",
      "form-action 'self' https://*.iyzipay.com https://*.iyzico.com",
    ].join('; ');
    res.setHeader('Content-Security-Policy', iyzicoCSP);
    return next();
  }

  // Nonce-based CSP: allows our intentional inline scripts while blocking injected ones.
  const nonce = crypto.randomBytes(16).toString('base64');
  res.locals.cspNonce = nonce;

  // Note: Many pages contain inline *styles* (style="...") so we allow 'unsafe-inline' for style.
  // We keep script-src strict to make XSS much harder.
  const csp = [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
    `script-src 'self' https://challenges.cloudflare.com 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self' https://challenges.cloudflare.com",
    "frame-src 'self' https://challenges.cloudflare.com",
    "report-uri /csp-report", 
  ].join('; ');

  res.setHeader(CSP_REPORT_ONLY ? 'Content-Security-Policy-Report-Only' : 'Content-Security-Policy', csp);
  next();
});
app.use(morgan('tiny'));
app.use(express.urlencoded({ extended: true, limit: '256kb', parameterLimit: 200 }));
app.use(express.json({ limit: '256kb' }));

// CSP violation reporting endpoint (optional, enabled when CSP_ENABLED=1).
// Note: Browsers send these reports without CSRF tokens; we keep this endpoint unauthenticated and minimal.
app.post('/csp-report', express.json({
  limit: '200kb',
  type: ['application/csp-report', 'application/json', 'application/reports+json']
}), (req, res) => {
  try {
    logSecurityEvent('csp_violation', {
      ip: req.ip,
      ua: req.get('user-agent') || '',
      requestId: req.requestId || '',
      report: req.body || {},
    });
  } catch (e) {}
  res.status(204).end();
});

// Common locals for all views
app.use((req, res, next) => {
  res.locals.appName = APP_NAME;
  res.locals.appVersion = APP_VERSION;
  res.locals.supportEmail = SUPPORT_EMAIL;
  res.locals.cspNonce = res.locals.cspNonce || '';
  res.locals.uploadAccept = UPLOAD_ACCEPT_ATTR;
  res.locals.uploadAllowedExtCsv = UPLOAD_ALLOWED_EXT.join(',');
  res.locals.maskUrl = maskUrl;

  // Prevent leaking tokenized URLs via the Referer header to any 3rd-party requests.
  res.setHeader('Referrer-Policy', 'no-referrer');

  // Restrict browser features the app doesn't need
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()');

  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // Prevent page from being loaded in iframes (clickjacking)
  res.setHeader('X-Frame-Options', 'DENY');

  // HSTS header (only in production with HTTPS)
  if (IS_PROD && COOKIE_SECURE) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }

  // Cross-Origin isolation headers
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

  next();
});


app.use(cookieSession({
  name: '__Host-sess',
  // Session key rotation: set SESSION_SECRETS=key1,key2,... (first used to sign new cookies; all accepted to verify)
  keys: (() => {
    const raw = (process.env.SESSION_SECRETS || process.env.SESSION_SECRET || 'dev-secret-change-me');
    return raw.split(',').map(s => s.trim()).filter(Boolean);
  })(),
  httpOnly: true,
  secure: COOKIE_SECURE,
  sameSite: IS_PROD ? 'strict' : COOKIE_SAMESITE,
  domain: COOKIE_DOMAIN || undefined,
  maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days (was 30)
  path: '/',
}));

// optional https redirect
app.use((req, res, next) => {
  if (!FORCE_HTTPS) return next();
  const proto = (req.headers['x-forwarded-proto'] || req.protocol || 'http').toString();
  if (proto !== 'https') return res.redirect(301, 'https://' + req.get('host') + req.originalUrl);
  next();
});

// rate limit login and vendor endpoints
const loginLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 8, standardHeaders: true, legacyHeaders: false });
const mfaLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });
const vendorLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 60, standardHeaders: true, legacyHeaders: false });
const signupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false });
// Limit sensitive utility actions (like sending test emails) to reduce abuse.
const emailTestLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, standardHeaders: true, legacyHeaders: false });

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use('/public', express.static(path.join(__dirname, 'public'), {
  maxAge: IS_PROD ? '1h' : 0,
  etag: true,
  setHeaders: (res) => {
    if (!IS_PROD) res.setHeader('Cache-Control', 'no-store');
  },
}));

// Browsers request /favicon.ico from the site root. To avoid broken / invalid ico files
// causing noisy 500s in production, serve a tiny built-in SVG icon when needed.
app.get('/favicon.ico', (req, res) => {
  try {
    const svgPath = path.join(__dirname, 'public', 'favicon.svg');
    const icoPath = path.join(__dirname, 'public', 'favicon.ico');
    res.setHeader('Cache-Control', 'public, max-age=86400');
    if (fs.existsSync(icoPath)) return res.sendFile(icoPath);
    if (fs.existsSync(svgPath)) {
      res.type('image/svg+xml');
      return res.sendFile(svgPath);
    }
    return res.status(204).end();
  } catch (e) {
    return res.status(204).end();
  }
});

// cache control for sensitive routes
function noStore(req, res, next) {
  res.setHeader('Cache-Control', 'no-store');
  next();
}

app.use(ensureCsrf);

// If a user has passed password check but still needs MFA (verify or setup),
// keep them inside the MFA flow and prevent access to the rest of the app.
app.use((req, res, next) => {
  if (!req.session) return next();
  if (req.session.userId) return next();
  if (!req.session.mfaPendingUserId) return next();

  const p = req.path || '';
  if (p.startsWith('/mfa')) return next();
  if (p.startsWith('/public')) return next();
  if (p.startsWith('/v/')) return next(); // vendor portal should keep working
  if (p === '/health') return next();

  return res.redirect(req.session.mfaSetupRequired ? '/mfa/setup' : '/mfa');
});
function ensureDbShape() {
  try {
    withDB(db => {
      db.meta = db.meta || { version: '1.12.0', createdAt: nowISO() };
      db.tenants = db.tenants || [];
      db.users = db.users || [];
      db.requests = db.requests || [];
      db.audit = db.audit || [];
      db.billing = db.billing || [];
      db.invites = db.invites || [];

      const defaultDays = (process.env.REMINDER_DEFAULT_DAYS || '3,1').trim();
      // tenant defaults
      db.tenants = db.tenants.map(t => ({
        ...t,
        security: {
          // Tenant seviyesinde MFA zorunluluğu (opsiyonel)
          requireMfa: !!(t.security && t.security.requireMfa),
          ...(t.security || {}),
        },
        remindersEnabled: t.remindersEnabled !== undefined ? t.remindersEnabled : true,
        reminderDays: (t.reminderDays || defaultDays).trim(),
        notifyEmail: (t.notifyEmail || '').trim(),
        nextRequestSeq: Number.isFinite(parseInt(t.nextRequestSeq, 10)) && parseInt(t.nextRequestSeq, 10) > 0
          ? parseInt(t.nextRequestSeq, 10)
          : 1,
      }));

      // user defaults (MFA + login lock)
      db.users = db.users.map(u => ({
        ...u,
        mfaEnabled: !!u.mfaEnabled,
        mfaSecret: typeof u.mfaSecret === 'string' ? u.mfaSecret : (u.mfaSecret ? String(u.mfaSecret) : ''),
        mfaBackup: Array.isArray(u.mfaBackup) ? u.mfaBackup : [],
        failedLoginCount: Number.isFinite(parseInt(u.failedLoginCount, 10)) ? parseInt(u.failedLoginCount, 10) : 0,
        lockedUntil: u.lockedUntil || null,
        lastLoginAt: u.lastLoginAt || null,
        lastLoginIp: u.lastLoginIp || null,
      }));

      // ensure human-friendly request publicId per tenant
      const pad6 = (n) => String(n).padStart(6, '0');
      const parsePublicSeq = (pid) => {
        const m = String(pid || '').match(/^TLP-(\d{1,12})$/i);
        return m ? parseInt(m[1], 10) : null;
      };

      for (const t of db.tenants) {
        const rsAll = (db.requests || []).filter(r => r.tenantId === t.id);
        let maxSeq = 0;
        for (const r of rsAll) {
          const n = parsePublicSeq(r.publicId);
          if (Number.isFinite(n) && n > maxSeq) maxSeq = n;
        }
        let seq = Math.max(1, parseInt(t.nextRequestSeq || 1, 10) || 1, maxSeq + 1);

        const rs = rsAll.slice().sort((a, b) => String(a.createdAt || '').localeCompare(String(b.createdAt || '')));
        for (const r of rs) {
          if (!r.publicId) {
            r.publicId = `TLP-${pad6(seq)}`;
            seq += 1;
          }
        }
        t.nextRequestSeq = seq;
      }

      db.meta.version = '1.12.0';
      db.meta.updatedAt = nowISO();
    });
  } catch (e) {
    console.warn('DB shape ensure failed:', e.message);
  }
}
ensureDbShape();


// --- Helpers ---
const STATUS = ['open', 'submitted', 'approved', 'rejected', 'archived'];
function statusLabel(s) {
  const map = {
    open: 'Açık',
    submitted: 'Gönderildi',
    approved: 'Onaylandı',
    rejected: 'Reddedildi',
    archived: 'Arşivlendi',
  };
  return map[s] || s;
}

function parseYmd(str) {
  const s = String(str || '').trim();
  if (!s) return null;
  // Expect YYYY-MM-DD
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (!m) return null;
  const d = new Date(`${m[1]}-${m[2]}-${m[3]}T00:00:00`);
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

function startOfToday() {
  const d = new Date();
  d.setHours(0,0,0,0);
  return d;
}

function daysDiff(a, b) {
  // days from b -> a
  const ms = a.getTime() - b.getTime();
  return Math.floor(ms / (24 * 3600 * 1000));
}

function getDocState(reqItem, doc) {
  const u = (reqItem.uploads || {})[doc.id] || null;
  const state = {
    uploaded: !!u,
    complete: false,
    errors: [],
    warnings: [],
    expiryDaysLeft: null,
    expired: false,
    expiringSoon: false,
    signatureVerified: !!u?.signatureVerified,
    u,
  };

  if (!u) {
    if (doc.required) state.errors.push('Eksik');
    return state;
  }

  if (doc.requireSignature && !u.signedConfirmed) {
    state.errors.push('İmza bilgisi eksik');
  }

  if (doc.issueDateRequired && !u.issueDate) {
    state.errors.push('Düzenleme tarihi eksik');
  }

  if (doc.expiryRequired) {
    if (!u.expiryDate) {
      state.errors.push('Geçerlilik tarihi eksik');
    } else {
      const exp = parseYmd(u.expiryDate);
      if (!exp) {
        state.errors.push('Geçerlilik tarihi geçersiz');
      } else {
        const left = daysDiff(exp, startOfToday());
        state.expiryDaysLeft = left;
        if (left < 0) {
          state.expired = true;
          state.errors.push('Süresi dolmuş');
        } else {
          const warnDays = Math.max(1, Math.min(365, parseInt(doc.expiryWarnDays || 30, 10) || 30));
          if (left <= warnDays) {
            state.expiringSoon = true;
            state.warnings.push(`Yakında doluyor (${left} gün)`);
          }
        }
      }
    }
  }

  state.complete = state.uploaded && state.errors.length === 0;
  return state;
}

function computeProgress(reqItem) {
  const required = reqItem.docs.filter(d => d.required);
  const done = required.filter(d => getDocState(reqItem, d).complete).length;
  return { done, required: required.length, total: reqItem.docs.length };
}

function computeHealth(reqItem) {
  let errors = 0;
  let warnings = 0;
  for (const d of (reqItem.docs || [])) {
    const st = getDocState(reqItem, d);
    errors += st.errors.length;
    warnings += st.warnings.length;
  }
  return { errors, warnings };
}

function flash(req, type, message) {
  req.session.flash = { type, message };
}

function addFlash(req, message, type = 'ok') {
  flash(req, type, message);
}

function consumeFlash(req) {
  const f = req.session.flash;
  delete req.session.flash;
  return f || null;
}

function getMailer() {
  const host = (process.env.SMTP_HOST || '').trim();
  if (!host) return null;
  const port = parseInt(process.env.SMTP_PORT || '587', 10);
  const user = (process.env.SMTP_USER || '').trim();
  const pass = (process.env.SMTP_PASS || '').trim();
  return nodemailer.createTransport({
    host, port, secure: port === 465,
    auth: user ? { user, pass } : undefined,
  });
}

function sha256hex(str) {
  return crypto.createHash('sha256').update(String(str || '')).digest('hex');
}

function escapeHtml(s) {
  return String(s || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}


function wantsJson(req) {
  const accept = String((req.headers && req.headers.accept) || '');
  if (accept.includes('application/json')) return true;
  const xrw = String((req.headers && req.headers['x-requested-with']) || '');
  if (xrw.toLowerCase() === 'xmlhttprequest') return true;
  return false;
}

function isTurnstileEnabled() {
  return !!(TURNSTILE_SITE_KEY && TURNSTILE_SECRET_KEY);
}

async function verifyTurnstileResponse(req) {
  if (!isTurnstileEnabled()) return { ok: true, bypass: true };
  const respToken = (req.body && (req.body['cf-turnstile-response'] || req.body.turnstileResponse)) || '';
  if (!respToken) return { ok: false, reason: 'missing' };

  try {
    const body = new URLSearchParams();
    body.set('secret', TURNSTILE_SECRET_KEY);
    body.set('response', respToken);
    // remoteip is optional but can help with abuse signals
    if (req.ip) body.set('remoteip', req.ip);

    const r = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body,
    });
    const data = await r.json();
    if (data && data.success) return { ok: true };
    return { ok: false, reason: 'invalid', data };
  } catch (e) {
    console.error('Turnstile verify failed', e.message);
    return { ok: false, reason: 'error' };
  }
}

async function sendSystemEmail({ to, subject, html, text }) {
  const mailer = getMailer();
  if (!mailer) return { ok: false, reason: 'smtp_disabled' };
  try {
    await mailer.sendMail({
      from: process.env.SMTP_FROM || `Dökümanlarım <noreply@example.com>`,
      to,
      subject,
      text,
      html,
    });
    return { ok: true };
  } catch (e) {
    console.error('send mail failed', e.message);
    return { ok: false, reason: 'send_failed' };
  }
}

function buildVerifyEmailLink(req, token) {
  return `${getBaseUrl(req)}/verify-email?token=${encodeURIComponent(token)}`;
}

function buildResetPasswordLink(req, token) {
  return `${getBaseUrl(req)}/reset-password?token=${encodeURIComponent(token)}`;
}

function issueSignupCaptcha(req) {
  if (isTurnstileEnabled()) {
    return { mode: 'turnstile', turnstileSiteKey: TURNSTILE_SITE_KEY };
  }

  // Lightweight math captcha fallback (dev-friendly). Not as strong as a real CAPTCHA.
  const a = Math.floor(Math.random() * 8) + 2; // 2..9
  const b = Math.floor(Math.random() * 8) + 2;
  const ans = String(a + b);
  const issuedAt = Date.now();

  // Also keep in session for backward compatibility
  req.session.signupCaptcha = { ans, issuedAt };

  // Signed token fallback to avoid false negatives if session is lost/restarted
  const payload = `${issuedAt}.${ans}`;
  const sig = crypto.createHmac('sha256', CAPTCHA_SIGNING_SECRET).update(payload).digest('hex');
  const captchaToken = `${payload}.${sig}`;

  return { mode: 'math', mathQuestion: `${a} + ${b} = ?`, captchaToken };
}

function verifySignupCaptcha(req) {
  if (isTurnstileEnabled()) return { ok: true, mode: 'turnstile' }; // verified separately

  const provided = String((req.body && req.body.captchaAnswer) || '').trim();
  const token = String((req.body && req.body.captchaToken) || '').trim();

  // Prefer signed token verification (more robust than session)
  if (token) {
    const parts = token.split('.');
    if (parts.length === 3) {
      const issuedAt = parseInt(parts[0], 10);
      const ans = parts[1];
      const sig = parts[2];

      if (Number.isFinite(issuedAt) && ans) {
        // expire after 30 minutes
        if (Date.now() - issuedAt > 30 * 60 * 1000) {
          return { ok: false, reason: 'expired' };
        }
        const payload = `${issuedAt}.${ans}`;
        const expectedSig = crypto.createHmac('sha256', CAPTCHA_SIGNING_SECRET).update(payload).digest('hex');
        try {
          const a = Buffer.from(expectedSig, 'utf8');
          const b = Buffer.from(sig, 'utf8');
          if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
            return { ok: false, reason: 'bad_sig' };
          }
        } catch {
          return { ok: false, reason: 'bad_sig' };
        }
        if (!provided || provided !== ans) return { ok: false, reason: 'wrong' };
        return { ok: true };
      }
    }
  }

  // Fallback to session-based check
  const stored = req.session.signupCaptcha;
  if (!stored || !stored.ans) return { ok: false, reason: 'missing' };
  if (stored.issuedAt && Date.now() - stored.issuedAt > 30 * 60 * 1000) {
    return { ok: false, reason: 'expired' };
  }
  if (!provided || provided !== stored.ans) return { ok: false, reason: 'wrong' };
  return { ok: true };
}

function getTenantOwnerEmail(db, tenantId) {
  const owner = (db.users || []).find(u => u.tenantId === tenantId && u.role === 'owner');
  return (owner?.email || '').trim();
}

function getTenantNotifyEmail(db, tenantId) {
  const tenant = (db.tenants || []).find(t => t.id === tenantId);
  const tmail = (tenant?.notifyEmail || '').trim();
  if (tmail) return tmail;
  return getTenantOwnerEmail(db, tenantId);
}

function parseDaysList(str) {
  return String(str || '')
    .split(',')
    .map(s => parseInt(s.trim(), 10))
    .filter(n => Number.isFinite(n) && n >= 0 && n <= 3650);
}

// --- Signed callback state for iyzico (prevent tenant ID tampering) ---
function getCallbackSigningKey() {
  const raw = (process.env.SESSION_SECRETS || process.env.SESSION_SECRET || 'dev-secret-change-me').trim();
  return raw.split(',')[0].trim();
}

function signCallbackState(tenantId) {
  const payload = `${tenantId}:${Date.now()}`;
  const sig = crypto.createHmac('sha256', getCallbackSigningKey()).update(payload).digest('base64url');
  return `${payload}:${sig}`;
}

function verifyCallbackState(state, maxAgeMs = 2 * 60 * 60 * 1000) {
  if (!state || typeof state !== 'string') return null;
  const parts = state.split(':');
  if (parts.length < 3) return null;
  const sig = parts.pop();
  const payload = parts.join(':');
  const expected = crypto.createHmac('sha256', getCallbackSigningKey()).update(payload).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  // Check age
  const ts = parseInt(parts[parts.length - 1], 10);
  if (!Number.isFinite(ts) || Date.now() - ts > maxAgeMs) return null;
  // tenantId is everything before the last ':'
  parts.pop(); // remove timestamp
  return parts.join(':');
}

// --- Password complexity ---
function isPasswordStrong(pw) {
  if (!pw || pw.length < 8) return false;
  if (pw.length > 128) return false;
  // Must have lowercase, uppercase, and digit
  if (!/[a-z]/.test(pw)) return false;
  if (!/[A-Z]/.test(pw)) return false;
  if (!/[0-9]/.test(pw)) return false;
  return true;
}

const PASSWORD_POLICY_MSG = 'Şifre en az 8 karakter, büyük harf, küçük harf ve rakam içermeli.';

// --- Session fingerprinting ---
// Bind sessions to the user-agent to detect stolen cookies.
// We use a hash so the actual UA string is not stored in the cookie.
function sessionFingerprint(req) {
  const ua = req.get('user-agent') || '';
  return crypto.createHash('sha256').update(ua).digest('base64url').slice(0, 16);
}

function stampSession(req) {
  req.session._fp = sessionFingerprint(req);
  req.session._at = Date.now();
}

// --- Email validation ---
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  if (email.length > 254) return false;
  // RFC 5322 simplified — good enough for registration
  return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
}

// --- Open redirect protection ---
function safeRedirectUrl(url) {
  if (!url || typeof url !== 'string') return '/app/requests';
  // Only allow relative paths starting with /
  if (!url.startsWith('/')) return '/app/requests';
  // Block protocol-relative URLs (//evil.com)
  if (url.startsWith('//')) return '/app/requests';
  // Block data: and javascript: in encoded form
  const lower = url.toLowerCase();
  if (lower.includes('javascript:') || lower.includes('data:')) return '/app/requests';
  return url;
}

// --- File upload hardening ---
function isSafeFilename(name) {
  if (!name || typeof name !== 'string') return false;
  // Block null bytes (path traversal via null byte injection)
  if (name.includes('\0') || name.includes('\x00')) return false;
  // Block double extensions like file.php.jpg
  const dangerousExts = ['.php', '.jsp', '.asp', '.aspx', '.exe', '.bat', '.cmd', '.sh', '.cgi', '.pl', '.py', '.rb', '.js', '.html', '.htm', '.svg'];
  const lower = name.toLowerCase();
  for (const ext of dangerousExts) {
    if (lower.includes(ext + '.') || lower.endsWith(ext)) return false;
  }
  // Block path separators
  if (name.includes('/') || name.includes('\\') || name.includes('..')) return false;
  return true;
}

function dateAtStartOfDay(d) {
  const x = new Date(d);
  x.setHours(0, 0, 0, 0);
  return x;
}

function diffDays(ymd) {
  // ymd: YYYY-MM-DD
  const due = dateAtStartOfDay(new Date(ymd + 'T00:00:00'));
  const today = dateAtStartOfDay(new Date());
  const ms = due.getTime() - today.getTime();
  return Math.round(ms / (1000 * 60 * 60 * 24));
}

function sanitizeFilename(name) {
  return name.replace(/[^\w.\-()+ ]+/g, '_').slice(0, 160);
}

const fileStorage = getStorage();
const STORAGE_PROVIDER = fileStorage.provider;

// --- Multer upload ---
const multerStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    // vendor upload uses req.vendorRequest from middleware
    const r = req.vendorRequest;
    if (STORAGE_PROVIDER === 's3') {
      const dir = fileStorage.tmpDir || path.join(__dirname, 'uploads_tmp');
      fs.mkdirSync(dir, { recursive: true });
      return cb(null, dir);
    }
    const dir = path.join(__dirname, 'uploads', r.tenantId, r.id);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const docId = req.params.docId;
    const safe = sanitizeFilename(file.originalname || 'file');
    cb(null, `${docId}__${Date.now()}__${safe}`);
  }
});

const upload = multer({
  storage: multerStorage,
  limits: { fileSize: MAX_BYTES },
  fileFilter: (req, file, cb) => {
    // Not: Bazı tarayıcılar/OS'ler dosyayı "application/octet-stream" veya farklı PDF mime'ları ile
    // gönderebiliyor. Bu yüzden filtre biraz toleranslı; asıl güvenlik "magic bytes" kontrolünde.
    const allowedMimes = new Set([
      ...UPLOAD_ALLOWED_MIME,
      // Tolerate a few common variants some clients send
      'application/x-pdf',
      'application/octet-stream',
      'image/jpg',
    ].map((m) => String(m).toLowerCase()));

    const allowedExt = new Set(UPLOAD_ALLOWED_EXT.map((e) => String(e).toLowerCase()));

    const ext = (path.extname(file.originalname || '') || '').toLowerCase();
    const mime = (file.mimetype || '').toLowerCase();

    const ok = allowedMimes.has(mime) || allowedExt.has(ext);

    // Block dangerous filenames (null bytes, double extensions, path traversal)
    if (!isSafeFilename(file.originalname || '')) {
      const err = new Error('Dosya adı güvenlik kontrolünden geçemedi.');
      err.code = 'UNSUPPORTED_FILE_TYPE';
      err.status = 415;
      return cb(err, false);
    }

    if (ok) return cb(null, true);

    const err = new Error('Bu dosya türüne izin verilmiyor. İzinli türler: PDF, JPG, PNG, WEBP, DOC/DOCX, XLS/XLSX, TXT.');
    err.code = 'UNSUPPORTED_FILE_TYPE';
    err.status = 415;
    return cb(err, false);
  }
});


// Extra defense: verify basic "magic bytes" for common types. MIME can be spoofed.
// Not: Bazı istemciler dosyayı application/octet-stream ile gönderebiliyor.
// Bu fonksiyon uzantı + mime ipuçlarını birleştirip mümkün olduğunca doğrulama yapar.
function validateFileSignature(filePath, mime, originalName) {
  try {
    const ext = path.extname(originalName || '').toLowerCase();
    const extToMime = {
      '.pdf': 'application/pdf',
      '.png': 'image/png',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.webp': 'image/webp',
      '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      '.doc': 'application/msword',
      '.xls': 'application/vnd.ms-excel',
      '.txt': 'text/plain',
    };

    const normalizeMime = (m) => {
      const s = (m || '').toLowerCase().trim();
      if (s === 'application/x-pdf') return 'application/pdf';
      if (s === 'image/jpg') return 'image/jpeg';
      return s;
    };

    const hintedByExt = extToMime[ext] || '';
    const hintedByMime = normalizeMime(mime);
    let expected = hintedByExt || hintedByMime;
    if (expected === 'application/octet-stream') expected = hintedByExt || '';

    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(16);
    fs.readSync(fd, buf, 0, buf.length, 0);
    fs.closeSync(fd);

    const startsWith = (bytes) => buf.slice(0, bytes.length).equals(bytes);
    const isPDF = buf.slice(0, 5).toString('ascii') === '%PDF-';
    const isPNG = startsWith(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]));
    const isJPG = startsWith(Buffer.from([0xff, 0xd8, 0xff]));
    const isWEBP = buf.slice(0, 4).toString('ascii') === 'RIFF' && buf.slice(8, 12).toString('ascii') === 'WEBP';
    const isZIP = startsWith(Buffer.from([0x50, 0x4b, 0x03, 0x04]))
      || startsWith(Buffer.from([0x50, 0x4b, 0x05, 0x06]))
      || startsWith(Buffer.from([0x50, 0x4b, 0x07, 0x08]));
    const isOLE = startsWith(Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]));

    // Hiç ipucu yoksa (uzantı yok + mime boş/octet-stream), sadece net güvenli tipleri
    // (PDF + resimler) imzadan tanıyıp kabul ediyoruz.
    if (!expected) {
      return isPDF || isPNG || isJPG || isWEBP;
    }

    if (expected === 'application/pdf') return isPDF;
    if (expected === 'image/png') return isPNG;
    if (expected === 'image/jpeg') return isJPG;
    if (expected === 'image/webp') return isWEBP;

    // Office Open XML containers (.docx/.xlsx) are ZIP-based.
    if (
      expected === 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' ||
      expected === 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    ) {
      return isZIP;
    }

    // Legacy Office (OLE CF) best-effort check
    if (expected === 'application/msword' || expected === 'application/vnd.ms-excel') {
      return isOLE;
    }

    // Plain text: no reliable magic bytes; allow.
    if (expected === 'text/plain') return true;

    return false;
  } catch (e) {
    return false;
  }
}

function canonicalMimeFromUpload(mime, originalName) {
  const ext = path.extname(originalName || '').toLowerCase();
  const extToMime = {
    '.pdf': 'application/pdf',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp',
    '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    '.doc': 'application/msword',
    '.xls': 'application/vnd.ms-excel',
    '.txt': 'text/plain',
  };
  const m = (mime || '').toLowerCase().trim();
  if (m === 'application/x-pdf') return 'application/pdf';
  if (m === 'image/jpg') return 'image/jpeg';
  if (!m || m === 'application/octet-stream') {
    return extToMime[ext] || (m || 'application/octet-stream');
  }
  return m;
}

// Prevent path traversal if a stored filename is ever tampered with.
function safeJoin(baseDir, ...paths) {
  const base = path.resolve(baseDir) + path.sep;
  const target = path.resolve(baseDir, ...paths);
  if (!target.startsWith(base)) {
    throw new Error('path_traversal');
  }
  return target;
}

// --- Public routes ---
app.get('/', (req, res) => {
  res.render('layout', {
    title: 'Ana Sayfa',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: null,
    tenant: null,
    plan: null,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: false,
    body: render('index', { csrfToken: res.locals.csrfToken, supportEmail: SUPPORT_EMAIL }),
  });
});

app.get('/health', (req, res) => res.json({ ok: true, at: nowISO(), app: APP_NAME, version: APP_VERSION }));

// Basic security disclosure file for public SaaS hygiene.
// Note: BASE_URL may be empty in dev. Don't crash on /security.txt.
function renderSecurityTxt(req) {
  const expiry = new Date(Date.now() + 180 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const envBase = (process.env.BASE_URL || '').trim();
  const base = (envBase ? envBase : getBaseUrl(req)).replace(/\/$/, '');
  return [
    `Contact: mailto:${SUPPORT_EMAIL}`,
    `Expires: ${expiry}`,
    `Preferred-Languages: tr, en`,
    `Canonical: ${base}/.well-known/security.txt`,
  ].join('\n');
}

app.get('/.well-known/security.txt', (req, res) => {
  res.type('text/plain; charset=utf-8').send(renderSecurityTxt(req));
});
app.get('/security.txt', (req, res) => {
  res.type('text/plain; charset=utf-8').send(renderSecurityTxt(req));
});

// RFC 9116: /.well-known/change-password
// A single canonical path for browsers/password managers.
app.get('/.well-known/change-password', (req, res) => {
  res.redirect(302, '/forgot-password');
});

app.get('/robots.txt', (req, res) => {
  res.type('text/plain; charset=utf-8').send([
    'User-agent: *',
    'Disallow: /app',
    'Disallow: /admin',
    'Disallow: /v',
  ].join('\n'));
});
app.get('/ready', (req, res) => {
  // basic check: data path readable
  try {
    fs.accessSync(path.join(__dirname, 'data', 'db.json'), fs.constants.R_OK);
    res.json({ ok: true, at: nowISO() });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'db_not_readable' });
  }
});

app.get('/legal/privacy', (req, res) => {
  res.render('layout', {
    title: 'Gizlilik',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: null, tenant: null, plan: null,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: false,
    body: render('legal_privacy', { supportEmail: SUPPORT_EMAIL }),
  });
});

app.get('/legal/terms', (req, res) => {
  res.render('layout', {
    title: 'Şartlar',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: null, tenant: null, plan: null,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: false,
    body: render('legal_terms', { supportEmail: SUPPORT_EMAIL }),
  });
});

// --- Auth routes ---
app.get('/login', noStore, (req, res) => {
  if (req.session.userId) return res.redirect('/app/requests');
  res.render('layout', {
    title: 'Giriş',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: null, tenant: null, plan: null,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('login', { csrfToken: res.locals.csrfToken }),
  });
});

app.post('/login', noStore, loginLimiter, verifyCsrf, async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const rememberMe = req.body.remember === '1';
  const savedReturnTo = req.session.returnTo || null;
  const db = readDB();
  const user = db.users.find(u => u.email === email);
  // Timing noise: if user doesn't exist, still run bcrypt to reduce enumeration via timing.
  if (!user) {
    try {
      await verifyPassword(password, '$2a$10$9e0kYxkLhM3W4LrGQF3qvO/5L3yDg0aY9y0Qb0z5zR3cY2C7nL7S2');
    } catch (_) {}
    flash(req, 'err', 'E-posta veya şifre hatalı.');
    return res.redirect('/login');
  }

  // Account lockout (brute-force mitigation)
  if (user.loginLockedUntil) {
    const until = Date.parse(user.loginLockedUntil);
    if (!Number.isNaN(until) && Date.now() < until) {
      logSecurityEvent('auth.login_locked', {
        requestId: req.requestId,
        email,
        ip: req.ip,
        path: req.originalUrl,
        ua: req.get('user-agent') || '',
      });
      flash(req, 'err', `Çok fazla hatalı deneme. Lütfen ${LOGIN_LOCK_MINUTES} dakika sonra tekrar deneyin.`);
      return res.redirect('/login');
    }
  }
  const ok = await verifyPassword(password, user.passHash);
  if (!ok) {
    // Update lock counters
    const fails = (user.loginFailCount || 0) + 1;
    const lockoutCount = (user.lockoutCount || 0); // how many times locked out
    user.loginFailCount = fails;
    if (fails >= LOGIN_LOCK_MAX_FAILS) {
      user.loginFailCount = 0;
      // Exponential backoff: 30min, 60min, 120min, 240min, max 24h
      const backoffMultiplier = Math.min(Math.pow(2, lockoutCount), 48);
      const lockMinutes = LOGIN_LOCK_MINUTES * backoffMultiplier;
      user.lockoutCount = lockoutCount + 1;
      user.loginLockedUntil = new Date(Date.now() + lockMinutes * 60 * 1000).toISOString();

      logSecurityEvent('auth.login_lockout_triggered', {
        requestId: req.requestId,
        userId: user.id,
        tenantId: user.tenantId,
        email,
        ip: req.ip,
        ua: req.get('user-agent') || '',
      });
      // Optional: global security alert (SIEM/Slack)
      sendSecurityAlert({
        event: 'auth.login_lockout_triggered',
        title: `${APP_NAME} güvenlik uyarısı: Login lockout`,
        text: `E-posta: ${email}\nIP: ${req.ip}\nTenant: ${user.tenantId}\nUser: ${user.id}`,
        severity: 'warn',
        baseUrl: getBaseUrl(req),
        meta: { requestId: req.requestId },
      }).catch(() => {});
    }
    writeDB(db);
    logSecurityEvent('auth.login_failed', {
      requestId: req.requestId,
      email,
      userId: user.id,
      tenantId: user.tenantId,
      ip: req.ip,
      ua: req.get('user-agent') || '',
    });
    flash(req, 'err', 'E-posta veya şifre hatalı.');
    return res.redirect('/login');
  }

  // Successful login resets lock counters
  if (user.loginFailCount || user.loginLockedUntil || user.lockoutCount) {
    user.loginFailCount = 0;
    user.loginLockedUntil = null;
    user.lockoutCount = 0;
    writeDB(db);
  }
  // Email doğrulama (public SaaS standardı)
  if (isEmailVerificationRequired() && user.emailVerified === false) {
    const token = randomToken(24);
    const tokenHash = sha256hex(token);
    const expiresAt = new Date(Date.now() + EMAIL_VERIFY_TTL_HOURS * 60 * 60 * 1000).toISOString();

    withDB(db => {
      const u = (db.users || []).find(x => x.id === user.id);
      if (!u) return;
      u.verifyTokenHash = tokenHash;
      u.verifyTokenExpiresAt = expiresAt;
      u.emailVerified = false;
    });

    const link = buildVerifyEmailLink(req, token);
    const { subject, text, html } = emailTemplates.verifyEmail({ appName: APP_NAME, firstName: user.firstName, link, ttlHours: EMAIL_VERIFY_TTL_HOURS });
    const mailRes = await sendSystemEmail({ to: user.email, subject, text, html });
    if (!mailRes.ok && !IS_PROD) {
      req.session.devVerifyLink = link;
    }

    flash(req, 'err', 'Giriş başarılı, fakat e-posta doğrulaması gerekiyor. Linki yeniden gönderdik.');
    return res.redirect('/verify-needed');
  }

  // "Beni hatırla" seçiliyse session süresini 30 güne uzat
  if (rememberMe) {
    req.session.maxAge = 1000 * 60 * 60 * 24 * 30; // 30 gün
  }

  const loginRedirect = safeRedirectUrl(savedReturnTo) || '/app/requests';

  // MFA (TOTP) – en yüksek kaldıraç güvenlik katmanı
  const tenant = db.tenants.find(t => t.id === user.tenantId) || null;
  const tenantRequiresMfa = !!(tenant && tenant.security && tenant.security.requireMfa);

  // If tenant enforces MFA but user hasn't enabled yet: force setup.
  if (tenantRequiresMfa && !user.mfaEnabled) {
    req.session.mfaPendingUserId = user.id;
    req.session.mfaSetupRequired = true;
    req.session.postLoginRedirect = loginRedirect;
    flash(req, 'err', 'Güvenlik için MFA zorunlu. Devam etmek için MFA kurulumunu tamamla.');
    return res.redirect('/mfa/setup');
  }

  if (user.mfaEnabled) {
    req.session.mfaPendingUserId = user.id;
    req.session.postLoginRedirect = loginRedirect;
    flash(req, 'ok', 'Giriş başarılı. MFA kodunu gir.');
    return res.redirect('/mfa');
  }

  req.session.userId = user.id;
  req.session.returnTo = null;
  stampSession(req);
  flash(req, 'ok', 'Giriş başarılı.');
  return res.redirect(loginRedirect);
});

// ----------------------------
// MFA (TOTP + backup codes)
// ----------------------------

app.get('/mfa', noStore, (req, res) => {
  if (req.session.userId) return res.redirect('/app/requests');
  if (!req.session.mfaPendingUserId) return res.redirect('/login');
  if (req.session.mfaSetupRequired) return res.redirect('/mfa/setup');

  const db = readDB();
  const user = db.users.find(u => u.id === req.session.mfaPendingUserId);
  if (!user) {
    req.session.mfaPendingUserId = null;
    req.session.mfaSetupRequired = null;
    flash(req, 'err', 'Oturum bulunamadı. Lütfen tekrar giriş yap.');
    return res.redirect('/login');
  }

  return res.render('layout', {
    title: 'MFA Doğrulama',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: null,
    tenant: null,
    plan: null,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('mfa_verify', {
      csrfToken: res.locals.csrfToken,
      email: user.email,
    }),
  });
});

app.post('/mfa', noStore, mfaLimiter, verifyCsrf, (req, res) => {
  if (req.session.userId) return res.redirect('/app/requests');
  if (!req.session.mfaPendingUserId) return res.redirect('/login');
  if (req.session.mfaSetupRequired) return res.redirect('/mfa/setup');

  const codeRaw = String(req.body.code || '');
  const code = codeRaw.replace(/\s+/g, '').replace(/-/g, '');
  const db = readDB();
  const user = db.users.find(u => u.id === req.session.mfaPendingUserId);
  if (!user || !user.mfaEnabled || !user.mfaSecret) {
    logSecurityEvent('mfa.verify.missing', {
      ip: req.ip,
      ua: req.headers['user-agent'],
      requestId: req.requestId,
    });
    flash(req, 'err', 'MFA bulunamadı. Lütfen tekrar giriş yap.');
    req.session.mfaPendingUserId = null;
    req.session.mfaSetupRequired = null;
    return res.redirect('/login');
  }

  // Try TOTP first
  let ok = totpVerify(user.mfaSecret, code, { window: 1 });

  // Fallback: backup code
  if (!ok && Array.isArray(user.mfaBackup) && user.mfaBackup.length) {
    const expected = hashBackupCode(code, String(user.id));
    const idx = user.mfaBackup.findIndex(h => timingSafeEqualStr(h, expected));
    if (idx !== -1) {
      ok = true;
      // consume used backup code
      user.mfaBackup.splice(idx, 1);
      writeDB(db);
      logSecurityEvent('mfa.backup.used', {
        userId: user.id,
        tenantId: user.tenantId,
        ip: req.ip,
        requestId: req.requestId,
      });
    }
  }

  if (!ok) {
    req.session.mfaFailCount = Number(req.session.mfaFailCount || 0) + 1;
    logSecurityEvent('mfa.verify.fail', {
      userId: user.id,
      tenantId: user.tenantId,
      ip: req.ip,
      ua: req.headers['user-agent'],
      count: req.session.mfaFailCount,
      requestId: req.requestId,
    });
    if (req.session.mfaFailCount >= 10) {
      // Hard fail: require fresh password
      sendSecurityAlert({
        title: 'MFA bruteforce şüphesi',
        text: `10+ hatalı MFA denemesi. userId=${user.id} ip=${req.ip}`,
        severity: 'warn',
        baseUrl: getBaseUrl(req),
        meta: { userId: user.id, ip: req.ip },
      }).catch(() => {});
      req.session.mfaPendingUserId = null;
      req.session.mfaSetupRequired = null;
      req.session.mfaFailCount = 0;
      flash(req, 'err', 'Çok fazla hatalı deneme. Lütfen tekrar giriş yap.');
      return res.redirect('/login');
    }
    flash(req, 'err', 'Kod yanlış. Tekrar dene.');
    return res.redirect('/mfa');
  }

  // Success
  req.session.userId = user.id;
  stampSession(req);
  req.session.mfaPendingUserId = null;
  req.session.mfaSetupRequired = null;
  req.session.mfaFailCount = 0;
  logSecurityEvent('mfa.verify.ok', {
    userId: user.id,
    tenantId: user.tenantId,
    ip: req.ip,
    requestId: req.requestId,
  });

  const redirectTo = req.session.postLoginRedirect || '/app/requests';
  req.session.postLoginRedirect = null;
  req.session.returnTo = null;
  flash(req, 'ok', 'MFA doğrulandı.');
  return res.redirect(redirectTo);
});

app.get('/mfa/setup', noStore, (req, res) => {
  if (req.session.userId) {
    // Logged-in user enabling MFA from settings
    // (Allow using the same setup screen, but keep them authenticated.)
  }
  if (!req.session.mfaPendingUserId && !req.session.userId) return res.redirect('/login');

  const db = readDB();
  const uid = req.session.mfaPendingUserId || req.session.userId;
  const user = db.users.find(u => u.id === uid);
  if (!user) {
    flash(req, 'err', 'Oturum bulunamadı.');
    return res.redirect('/login');
  }

  // Generate a temporary secret for this session if needed
  if (!req.session.mfaTempSecret) {
    req.session.mfaTempSecret = generateSecretBase32(20);
  }

  const label = `${APP_NAME}:${user.email}`;
  const otpauth = makeOtpauthURL({
    secretBase32: req.session.mfaTempSecret,
    label,
    issuer: APP_NAME,
  });

  return res.render('layout', {
    title: 'MFA Kurulumu',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: null,
    tenant: null,
    plan: null,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('mfa_setup', {
      csrfToken: res.locals.csrfToken,
      email: user.email,
      secret: req.session.mfaTempSecret,
      otpauth,
      mandatory: !!req.session.mfaSetupRequired,
    }),
  });
});

app.post('/mfa/setup', noStore, mfaLimiter, verifyCsrf, (req, res) => {
  const uid = req.session.mfaPendingUserId || req.session.userId;
  if (!uid) return res.redirect('/login');
  const code = String(req.body.code || '').replace(/\s+/g, '').replace(/-/g, '');
  const secret = req.session.mfaTempSecret;
  if (!secret) {
    flash(req, 'err', 'Kurulum oturumu süresi doldu. Lütfen tekrar dene.');
    return res.redirect('/mfa/setup');
  }

  if (!totpVerify(secret, code, { window: 1 })) {
    logSecurityEvent('mfa.setup.fail', {
      userId: uid,
      ip: req.ip,
      ua: req.headers['user-agent'],
      requestId: req.requestId,
    });
    flash(req, 'err', 'Kod yanlış. Tekrar dene.');
    return res.redirect('/mfa/setup');
  }

  const db = readDB();
  const user = db.users.find(u => u.id === uid);
  if (!user) {
    flash(req, 'err', 'Kullanıcı bulunamadı.');
    return res.redirect('/login');
  }

  const backupCodes = generateBackupCodes(10);
  user.mfaEnabled = true;
  user.mfaSecret = secret;
  user.mfaBackup = backupCodes.map(c => hashBackupCode(c, String(user.id)));
  user.mfaEnabledAt = nowISO();
  writeDB(db);

  req.session.userId = user.id;
  req.session.mfaPendingUserId = null;
  req.session.mfaSetupRequired = null;
  req.session.mfaTempSecret = null;
  req.session.mfaFailCount = 0;
  req.session.mfaNewBackupCodes = backupCodes;

  logSecurityEvent('mfa.setup.ok', {
    userId: user.id,
    tenantId: user.tenantId,
    ip: req.ip,
    requestId: req.requestId,
  });
  sendSecurityAlert({
    title: 'MFA etkinleştirildi',
    text: `userId=${user.id} tenantId=${user.tenantId} ip=${req.ip}`,
    severity: 'info',
    baseUrl: getBaseUrl(req),
    meta: { userId: user.id, tenantId: user.tenantId },
  }).catch(() => {});

  flash(req, 'ok', 'MFA kuruldu. Yedek kodları kaydet.');
  return res.redirect('/mfa/done');
});

app.get('/mfa/done', noStore, (req, res) => {
  if (!req.session.userId) return res.redirect('/login');
  const codes = req.session.mfaNewBackupCodes;
  if (!codes || !Array.isArray(codes) || !codes.length) {
    return res.redirect('/app/requests');
  }
  const db = readDB();
  const user = db.users.find(u => u.id === req.session.userId);
  return res.render('layout', {
    title: 'Yedek Kodlar',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: null,
    tenant: null,
    plan: null,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('mfa_done', {
      csrfToken: res.locals.csrfToken,
      email: user ? user.email : '',
      codes,
    }),
  });
});

app.post('/mfa/done', noStore, verifyCsrf, (req, res) => {
  // Clear backup codes from session (they are already stored hashed in DB)
  req.session.mfaNewBackupCodes = null;
  flash(req, 'ok', 'Tamamdır.');
  return res.redirect('/app/requests');
});

app.get('/signup', noStore, (req, res) => {
  if (req.session.userId) return res.redirect('/app/requests');
  // Preserve form values on validation/CAPTCHA errors (do not store password)
  const draft = req.session.signupDraft || null;
  const captcha = issueSignupCaptcha(req);
  res.render('layout', {
    title: 'Kayıt',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: null, tenant: null, plan: null,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('signup', { csrfToken: res.locals.csrfToken, captcha, draft }),
  });
});

app.post('/signup', noStore, signupLimiter, verifyCsrf, async (req, res) => {
  const tenantName = (req.body.tenantName || '').trim();
  const firstName = (req.body.firstName || '').trim();
  const lastName = (req.body.lastName || '').trim();
  const email = (req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  // Keep a non-sensitive draft so validation/CAPTCHA errors don't wipe the form.
  // (Never store password in session.)
  req.session.signupDraft = { tenantName, firstName, lastName, email, at: Date.now() };

  if (!tenantName || !firstName || !lastName || !email || !isValidEmail(email) || !isPasswordStrong(password)) {
    const msg = !tenantName || !firstName || !lastName ? 'Lütfen tüm alanları doldurun.' : !email || !isValidEmail(email) ? 'Geçerli bir e-posta adresi girin.' : PASSWORD_POLICY_MSG;
    flash(req, 'err', msg);
    return res.redirect('/signup');
  }

  // CAPTCHA (signup) – Turnstile varsa onu zorunlu tut
  if (isTurnstileEnabled()) {
    const v = await verifyTurnstileResponse(req);
    if (!v.ok) {
      flash(req, 'err', 'İnsan doğrulaması başarısız. Lütfen tekrar dene.');
      return res.redirect('/signup');
    }
  } else {
    const v = verifySignupCaptcha(req);
    if (!v.ok) {
      flash(req, 'err', 'İnsan doğrulaması başarısız. Lütfen soruyu doğru cevapla.');
      return res.redirect('/signup');
    }
  }

  // One-time use
  delete req.session.signupCaptcha;

  const needsVerify = isEmailVerificationRequired();
  let verifyToken = null;
  let verifyTokenHash = null;
  let verifyTokenExpiresAt = null;
  if (needsVerify) {
    verifyToken = randomToken(24);
    verifyTokenHash = sha256hex(verifyToken);
    verifyTokenExpiresAt = new Date(Date.now() + EMAIL_VERIFY_TTL_HOURS * 60 * 60 * 1000).toISOString();
  }

  const passHash = await hashPassword(password);

  try {
    const result = withDB(db => {
      if (db.users.some(u => u.email === email)) {
        return { ok: false, reason: 'email_exists' };
      }
      const tenantId = safeId('tnt');
      const userId = safeId('usr');
      db.tenants.push({
        id: tenantId,
        name: tenantName,
        notifyEmail: email,
        remindersEnabled: true,
        reminderDays: (process.env.REMINDER_DEFAULT_DAYS || '3,1').trim(),
        nextRequestSeq: 1,
        createdAt: nowISO(),
      });
      db.users.push({
        id: userId,
        tenantId,
        email,
        firstName,
        lastName,
        role: 'owner',
        passHash,
        emailVerified: needsVerify ? false : true,
        verifyTokenHash: needsVerify ? verifyTokenHash : undefined,
        verifyTokenExpiresAt: needsVerify ? verifyTokenExpiresAt : undefined,
        createdAt: nowISO(),
      });
      db.billing.push({
        id: safeId('bill'),
        tenantId,
        provider: 'none',
        plan: 'free',
        status: 'active',
        updatedAt: nowISO(),
      });
      return { ok: true, userId };
    });

    if (!result.ok) {
      flash(req, 'err', 'Bu e-posta zaten kayıtlı.');
      return res.redirect('/signup');
    }
    req.session.userId = result.userId;
    // Signup successful -> clear draft
    delete req.session.signupDraft;

    if (needsVerify) {
      const link = buildVerifyEmailLink(req, verifyToken);
      const { subject, text, html } = emailTemplates.verifyEmail({ appName: APP_NAME, firstName, link, ttlHours: EMAIL_VERIFY_TTL_HOURS });
      const mailRes = await sendSystemEmail({ to: email, subject, text, html });
      if (!mailRes.ok && !IS_PROD) req.session.devVerifyLink = link;
      flash(req, 'ok', 'Hesap oluşturuldu. E-posta doğrulama linki gönderildi.');
      return res.redirect('/verify-needed');
    }

    flash(req, 'ok', 'Hesap oluşturuldu.');
    return res.redirect('/app/requests');
  } catch (e) {
    console.error(e);
    flash(req, 'err', 'Kayıt sırasında hata oluştu.');
    return res.redirect('/signup');
  }
});

// --- Email verification / Password reset ---
app.get('/verify-needed', noStore, requireAuthLoose, (req, res) => {
  // Already verified -> app
  if (req.user && req.user.emailVerified !== false) return res.redirect('/app/requests');
  const db = readDB();
  const plan = req.tenant ? getPlanForTenant(db, req.tenant.id) : null;
  const emailEnabled = !!getMailer();
  const devVerifyLink = (!IS_PROD ? (req.session.devVerifyLink || null) : null);
  res.render('layout', {
    title: 'E-posta doğrulama',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('verify_needed', {
      csrfToken: res.locals.csrfToken,
      user: req.user,
      emailEnabled,
      devVerifyLink,
    }),
  });
});

app.post('/verify-email/resend', noStore, requireAuthLoose, loginLimiter, verifyCsrf, async (req, res) => {
  if (!req.user) return res.redirect('/login');
  if (req.user.emailVerified !== false) return res.redirect('/app/requests');

  const token = randomToken(24);
  const tokenHash = sha256hex(token);
  const expiresAt = new Date(Date.now() + EMAIL_VERIFY_TTL_HOURS * 60 * 60 * 1000).toISOString();

  withDB(db => {
    const u = (db.users || []).find(x => x.id === req.user.id);
    if (!u) return;
    u.verifyTokenHash = tokenHash;
    u.verifyTokenExpiresAt = expiresAt;
    u.emailVerified = false;
  });

  const link = buildVerifyEmailLink(req, token);
  const { subject, text, html } = emailTemplates.verifyEmail({ appName: APP_NAME, firstName: req.user.firstName, link, ttlHours: EMAIL_VERIFY_TTL_HOURS });
  const mailRes = await sendSystemEmail({ to: req.user.email, subject, text, html });
  if (!mailRes.ok && !IS_PROD) req.session.devVerifyLink = link;

  flash(req, 'ok', 'Doğrulama linki yeniden gönderildi.');
  return res.redirect('/verify-needed');
});

app.get('/verify-email', noStore, (req, res) => {
  const token = (req.query.token || '').trim();
  if (!token) {
    flash(req, 'err', 'Doğrulama linki geçersiz.');
    return res.redirect('/login');
  }
  const tokenHash = sha256hex(token);

  const result = withDB(db => {
    const u = (db.users || []).find(x => x.verifyTokenHash === tokenHash);
    if (!u) return { ok: false, reason: 'not_found' };
    if (u.verifyTokenExpiresAt) {
      const exp = new Date(u.verifyTokenExpiresAt).getTime();
      if (Number.isFinite(exp) && Date.now() > exp) return { ok: false, reason: 'expired' };
    }
    u.emailVerified = true;
    delete u.verifyTokenHash;
    delete u.verifyTokenExpiresAt;
    return { ok: true, userId: u.id };
  });

  if (!result.ok) {
    const msg = result.reason === 'expired'
      ? 'Doğrulama linkinin süresi dolmuş. Lütfen yeniden gönder.'
      : 'Doğrulama linki geçersiz.';
    flash(req, 'err', msg);
    return res.redirect('/login');
  }

  req.session.userId = result.userId;
  flash(req, 'ok', 'E-posta doğrulandı. Hoş geldin!');
  return res.redirect('/app/requests');
});

app.get('/forgot-password', noStore, (req, res) => {
  if (req.session.userId) return res.redirect('/app/requests');
  res.render('layout', {
    title: 'Şifre sıfırlama',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: null, tenant: null, plan: null,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('forgot_password', { csrfToken: res.locals.csrfToken }),
  });
});

app.post('/forgot-password', noStore, loginLimiter, verifyCsrf, async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  // Always respond the same to prevent email enumeration
  const generic = 'Eğer bu e-posta sistemde kayıtlıysa şifre sıfırlama linki gönderildi.';

  if (!email) {
    flash(req, 'err', 'Lütfen e-posta gir.');
    return res.redirect('/forgot-password');
  }

  const token = randomToken(28);
  const tokenHash = sha256hex(token);
  const expiresAt = new Date(Date.now() + PASSWORD_RESET_TTL_MINUTES * 60 * 1000).toISOString();

  const found = withDB(db => {
    const u = (db.users || []).find(x => x.email === email);
    if (!u) return { ok: false };
    u.resetTokenHash = tokenHash;
    u.resetTokenExpiresAt = expiresAt;
    return { ok: true, userId: u.id, firstName: u.firstName || '' };
  });

  if (found.ok) {
    const link = buildResetPasswordLink(req, token);
    const { subject, text, html } = emailTemplates.resetPassword({ appName: APP_NAME, link, ttlMinutes: PASSWORD_RESET_TTL_MINUTES });
    const mailRes = await sendSystemEmail({ to: email, subject, text, html });
    if (!mailRes.ok && !IS_PROD) {
      req.session.devResetLink = link;
    }
  }

  flash(req, 'ok', generic + (!IS_PROD && req.session.devResetLink ? ` (DEV: ${req.session.devResetLink})` : ''));
  return res.redirect('/login');
});

app.get('/reset-password', noStore, (req, res) => {
  const token = (req.query.token || '').trim();
  if (!token) {
    flash(req, 'err', 'Şifre sıfırlama linki geçersiz.');
    return res.redirect('/forgot-password');
  }
  const tokenHash = sha256hex(token);
  const db = readDB();
  const u = (db.users || []).find(x => x.resetTokenHash === tokenHash);
  if (!u) {
    flash(req, 'err', 'Şifre sıfırlama linki geçersiz veya kullanılmış.');
    return res.redirect('/forgot-password');
  }
  if (u.resetTokenExpiresAt) {
    const exp = new Date(u.resetTokenExpiresAt).getTime();
    if (Number.isFinite(exp) && Date.now() > exp) {
      flash(req, 'err', 'Şifre sıfırlama linkinin süresi dolmuş.');
      return res.redirect('/forgot-password');
    }
  }
  res.render('layout', {
    title: 'Yeni şifre',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: null, tenant: null, plan: null,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('reset_password', { csrfToken: res.locals.csrfToken, token }),
  });
});

app.post('/reset-password', noStore, loginLimiter, verifyCsrf, async (req, res) => {
  const token = String(req.body.token || '').trim();
  const password = String(req.body.password || '');
  const password2 = String(req.body.password2 || '');
  if (!token) {
    flash(req, 'err', 'Şifre sıfırlama linki geçersiz.');
    return res.redirect('/forgot-password');
  }
  if (!isPasswordStrong(password) || password !== password2) {
    flash(req, 'err', password !== password2 ? 'Şifreler eşleşmiyor.' : PASSWORD_POLICY_MSG);
    return res.redirect(`/reset-password?token=${encodeURIComponent(token)}`);
  }

  const tokenHash = sha256hex(token);
  const passHash = await hashPassword(password);

  const result = withDB(db => {
    const u = (db.users || []).find(x => x.resetTokenHash === tokenHash);
    if (!u) return { ok: false, reason: 'not_found' };
    if (u.resetTokenExpiresAt) {
      const exp = new Date(u.resetTokenExpiresAt).getTime();
      if (Number.isFinite(exp) && Date.now() > exp) return { ok: false, reason: 'expired' };
    }
    u.passHash = passHash;
    delete u.resetTokenHash;
    delete u.resetTokenExpiresAt;
    // NOT: Password reset, email doğrulaması sayılMAZ.
    // Kullanıcı ayrıca email doğrulaması yapmalı.
    // (Eski davranış: reset = verify. Bu güvenlik açığı kapatıldı.)
    return { ok: true, userId: u.id };
  });

  if (!result.ok) {
    const msg = result.reason === 'expired'
      ? 'Şifre sıfırlama linkinin süresi dolmuş.'
      : 'Şifre sıfırlama linki geçersiz veya kullanılmış.';
    flash(req, 'err', msg);
    return res.redirect('/forgot-password');
  }

  req.session.userId = result.userId;
  flash(req, 'ok', 'Şifre güncellendi.');
  return res.redirect('/app/requests');
});

app.post('/logout', verifyCsrf, (req, res) => {
  req.session = null;
  res.redirect('/');
});

// --- User invite (team) ---
function isInviteValid(inv) {
  if (!inv) return false;
  if (inv.acceptedAt) return false;
  if (inv.expiresAt) {
    const exp = new Date(inv.expiresAt).getTime();
    if (Number.isFinite(exp) && Date.now() > exp) return false;
  }
  return true;
}

app.get('/invite/:token', noStore, (req, res) => {
  const token = (req.params.token || '').trim();
  const db = readDB();
  const inv = (db.invites || []).find(i => i.token === token);
  if (!isInviteValid(inv)) return res.status(404).send('not_found');
  const tenant = (db.tenants || []).find(t => t.id === inv.tenantId);
  if (!tenant) return res.status(404).send('not_found');

  res.render('layout', {
    title: 'Davet',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: null,
    tenant,
    plan: null,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('invite_accept', { csrfToken: res.locals.csrfToken, invite: inv, tenant }),
  });
});

app.post('/invite/:token', noStore, loginLimiter, verifyCsrf, async (req, res) => {
  const token = (req.params.token || '').trim();
  const firstName = (req.body.firstName || '').trim();
  const lastName = (req.body.lastName || '').trim();
  const password = String(req.body.password || '');
  const password2 = String(req.body.password2 || '');

  if (!firstName || !lastName || !isPasswordStrong(password) || password !== password2) {
    const msg = !firstName || !lastName ? 'Ad ve soyad zorunlu.' : password !== password2 ? 'Şifreler eşleşmiyor.' : PASSWORD_POLICY_MSG;
    flash(req, 'err', msg);
    return res.redirect(`/invite/${token}`);
  }

  const passHash = await hashPassword(password);

  const result = withDB(db => {
    const inv = (db.invites || []).find(i => i.token === token);
    if (!isInviteValid(inv)) return { ok: false, reason: 'invalid' };

    const email = (inv.email || '').trim().toLowerCase();
    if ((db.users || []).some(u => u.email === email)) return { ok: false, reason: 'email_exists' };

    const plan = getPlanForTenant(db, inv.tenantId);
    const usersCount = (db.users || []).filter(u => u.tenantId === inv.tenantId).length;
    if (usersCount >= plan.maxUsers) return { ok: false, reason: 'plan_limit' };

    const userId = safeId('usr');
    db.users.push({
      id: userId,
      tenantId: inv.tenantId,
      email,
      firstName,
      lastName,
      role: inv.role || 'member',
      passHash,
      createdAt: nowISO(),
    });

    inv.acceptedAt = nowISO();

    db.audit.push({
      id: safeId('aud'),
      tenantId: inv.tenantId,
      requestId: null,
      actor: email,
      action: 'team_invite_accepted',
      detail: {},
      at: nowISO(),
    });

    return { ok: true, userId };
  });

  if (!result.ok) {
    const msg = {
      invalid: 'Davet linki geçersiz veya süresi dolmuş.',
      email_exists: 'Bu e-posta zaten kayıtlı.',
      plan_limit: 'Plan kullanıcı limiti dolu. Owner plan yükseltmeli.',
    }[result.reason] || 'Davet kabul edilemedi.';
    flash(req, 'err', msg);
    return res.redirect(`/invite/${token}`);
  }

  req.session.userId = result.userId;
  flash(req, 'ok', 'Hoş geldin! Hesabın oluşturuldu.');
  return res.redirect('/app/requests');
});

// --- Vendor token middleware ---
function loadVendorRequest(req, res, next) {
  const token = (req.params.token || '').trim();
  const db = readDB();

  const reqItem = (db.requests || []).find(r =>
    r.token === token || ((r.participants || []).some(p => p.token === token))
  );

  if (!reqItem) return res.status(404).send('not_found');

  // Check if request is archived or expired
  if (reqItem.status === 'archived') return res.status(410).send('archived');

  // Token expiration: vendor links expire 90 days after creation (or dueDate + 30 days, whichever is later)
  const VENDOR_TOKEN_MAX_DAYS = parseInt(process.env.VENDOR_TOKEN_MAX_DAYS || '90', 10);
  const createdMs = new Date(reqItem.createdAt || 0).getTime();
  const dueMs = reqItem.dueDate ? new Date(reqItem.dueDate + 'T23:59:59').getTime() : 0;
  const expiryMs = Math.max(
    createdMs + VENDOR_TOKEN_MAX_DAYS * 86400000,
    dueMs + 30 * 86400000
  );
  if (Number.isFinite(expiryMs) && Date.now() > expiryMs) {
    return res.status(410).send('link_expired');
  }

  let participant = (reqItem.participants || []).find(p => p.token === token) || null;
  if (!participant) {
    // Legacy request (no participants stored yet)
    participant = {
      id: 'vp_legacy',
      token: reqItem.token,
      role: 'yetkili',
      name: reqItem.vendor?.name || '',
      email: reqItem.vendor?.email || '',
      canSubmit: true,
    };
  }

  req.vendorRequest = reqItem;
  req.vendorTenant = (db.tenants || []).find(t => t.id === reqItem.tenantId) || null;
  req.vendorParticipant = participant;
  req.vendorAccessToken = token;

  next();
}

app.get('/v/:token', vendorLimiter, loadVendorRequest, noStore, (req, res) => {
  const reqItem = req.vendorRequest;
  const participant = req.vendorParticipant;
  const progress = computeProgress(reqItem);
  const canSubmit = (progress.done === progress.required) && (participant?.canSubmit !== false);

  // update last seen (best-effort)
  if (participant && participant.id && participant.id !== 'vp_legacy') {
    try {
      withDB(db => {
        const r = (db.requests || []).find(x => x.id === reqItem.id);
        if (!r || !r.participants) return;
        const p = r.participants.find(pp => pp.id === participant.id);
        if (p) p.lastSeenAt = nowISO();
      });
    } catch {}
  }

  res.render('layout', {
    title: 'Belge Yükleme',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: null,
    tenant: req.vendorTenant,
    plan: null,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('vendor', {
      csrfToken: res.locals.csrfToken,
      reqItem,
      participant,
      accessToken: req.vendorAccessToken,
      canSubmit,
      progress,
      docsWithState: (reqItem.docs || []).map(d => ({ ...d, _state: getDocState(reqItem, d) })),
      statusLabel,
      supportEmail: SUPPORT_EMAIL,
      emailEnabled: !!getMailer(),
    }),
  });
});

// NOTE: Multipart (multer) must run BEFORE CSRF verification so req.body._csrf exists.
// Otherwise vendor uploads can fail with "CSRF token hatalı.".
app.get('/v/:token/upload/:docId', vendorLimiter, loadVendorRequest, (req, res) => {
  // Bu endpoint sadece POST (multipart) ile kullanılmalı.
  addFlash(req, 'Dosya yüklemek için önce ilgili satırdan dosya seçmelisin.', 'err');
  return res.redirect(`/v/${req.params.token}`);
});

app.get('/v/:token/upload', vendorLimiter, loadVendorRequest, (req, res) => {
  addFlash(req, 'Dosya yüklemek için önce ilgili satırdan dosya seçmelisin.', 'err');
  return res.redirect(`/v/${req.params.token}`);
});

app.post('/v/:token/upload/:docId', vendorLimiter, loadVendorRequest, upload.single('file'), verifyCsrf, async (req, res) => {
  const reqItem = req.vendorRequest;
  const accessToken = req.vendorAccessToken;
  const participant = req.vendorParticipant;

  const docId = req.params.docId;
  const doc = reqItem.docs.find(d => d.id === docId);
  if (!doc) return res.status(404).send('doc_not_found');

  const file = req.file;
  if (!file) {
    const payload = { ok: false, error: 'Dosya seçilmedi.' };
    if (wantsJson(req) || String(req.get('x-auto-upload') || '').trim() === '1') return res.status(400).json(payload);
    flash(req, 'err', payload.error);
    return res.redirect(`/v/${accessToken}`);
  }

	  // MIME can be spoofed; validate a few common formats by their file signatures.
	  if (!validateFileSignature(file.path, (file.mimetype || '').toLowerCase(), file.originalname)) {
	    try { fs.unlinkSync(file.path); } catch {}
	    const payload = { ok: false, error: 'Dosya türü doğrulanamadı. Lütfen PDF / görsel / Office dosyası yükleyin.' };
	    if (wantsJson(req) || String(req.get('x-auto-upload') || '').trim() === '1') return res.status(415).json(payload);
	    flash(req, 'err', payload.error);
	    return res.redirect(`/v/${accessToken}`);
	  }

  // Optional meta fields (submitted with the upload form)
  const issueDateRaw = (req.body.issueDate || '').trim();
  const expiryDateRaw = (req.body.expiryDate || '').trim();
  const signedConfirmed = (req.body.signed === 'on' || req.body.signed === 'true');

  const issueDate = parseYmd(issueDateRaw) ? issueDateRaw : null;
  const expiryDate = parseYmd(expiryDateRaw) ? expiryDateRaw : null;

	const storedName = path.basename(file.path);
	const canonicalMime = canonicalMimeFromUpload(file.mimetype, file.originalname);
  let storageMeta = { provider: 'local' };

  try {
	    const meta = await fileStorage.putFromPath({
      tenantId: reqItem.tenantId,
      requestId: reqItem.id,
      storedName,
      filePath: file.path,
	      contentType: canonicalMime,
    });
    storageMeta = meta.provider === 'local' ? { provider: 'local' } : meta;

    // cleanup tmp file if needed (S3 mode)
    if (STORAGE_PROVIDER === 's3') {
      try { fs.unlinkSync(file.path); } catch {}
    }
  } catch (e) {
    console.error('storage upload failed', e.message);
    const payload = { ok: false, error: 'Dosya yüklenemedi. Storage ayarlarını kontrol edin.' };
    if (wantsJson(req) || String(req.get('x-auto-upload') || '').trim() === '1') return res.status(500).json(payload);
    flash(req, 'err', payload.error);
    return res.redirect(`/v/${accessToken}`);
  }

  // Save metadata in db
  withDB(db => {
    const r = db.requests.find(x => x.id === reqItem.id);
    if (!r.uploads) r.uploads = {};
    r.uploads[docId] = {
      storage: storageMeta,
      storedName,
      originalName: file.originalname,
      size: file.size,
	      mime: canonicalMime,
      uploadedAt: nowISO(),
      issueDate,
      expiryDate,
      signedConfirmed: !!signedConfirmed,
      signatureVerified: false,
      datesVerified: false,
      uploadedBy: participant?.id || null,
      uploadedByRole: participant?.role || null,
      uploadedByEmail: participant?.email || null,
    };
    r.updatedAt = nowISO();
    db.audit.push({
      id: safeId('aud'),
      tenantId: r.tenantId,
      requestId: r.id,
      actor: participant ? `vendor:${participant.role}:${participant.email || participant.id}` : 'vendor',
      action: 'upload',
      detail: {
        docId,
        docLabel: doc.label,
        size: file.size,
	        mime: canonicalMime,
        provider: storageMeta.provider,
        issueDate,
        expiryDate,
        signedConfirmed: !!signedConfirmed,
      },
      at: nowISO(),
    });
  });

  // Notifications
  try {
    const dbNow = readDB();
    const tenantNow = (dbNow.tenants || []).find(t => t.id === reqItem.tenantId);
    const rNow = (dbNow.requests || []).find(x => x.id === reqItem.id);
    const docNow = (rNow?.docs || []).find(d => d.id === docId);
    const st = (rNow && docNow) ? getDocState(rNow, docNow) : null;
    const baseUrl = getBaseUrl(req);

    sendTenantNotifications({
      tenant: tenantNow,
      event: 'vendor.uploaded',
      baseUrl,
      payload: {
        tenant: { id: tenantNow?.id, name: tenantNow?.name },
        request: { id: rNow?.id, status: rNow?.status, vendor: rNow?.vendor, dueDate: rNow?.dueDate || null },
        doc: {
          id: docId,
          label: docNow?.label || doc.label,
          state: st ? (st.errors.length ? `Hata: ${st.errors.join(' / ')}` : (st.warnings.length ? `Uyarı: ${st.warnings.join(' / ')}` : 'OK')) : 'OK',
        },
        actor: participant ? { role: participant.role, email: participant.email || null, name: participant.name || null } : null,
        links: { request: `${baseUrl}/app/requests/${reqItem.id}` },
      },
    }).catch(e => console.warn('notify vendor.uploaded failed', e.message));

    // In-app notification
    addNotification({
      tenantId: tenantNow?.id,
      userId: null,
      type: 'doc_uploaded',
      title: 'Yeni belge yüklendi',
      message: (docNow?.label || doc.label) + ' — ' + (rNow?.vendor?.name || ''),
      link: '/app/requests/' + encodeURIComponent(rNow?.publicId || reqItem.id),
    });
  } catch (e) {}

  const wantsJson = String(req.get('accept') || '').includes('application/json');
  if (wantsJson) {
    return res.json({ ok: true });
  }

  flash(req, 'ok', 'Yüklendi.');
  res.redirect(`/v/${accessToken}`);
});

app.post('/v/:token/meta/:docId', vendorLimiter, loadVendorRequest, verifyCsrf, (req, res) => {
  const reqItem = req.vendorRequest;
  const accessToken = req.vendorAccessToken;
  const participant = req.vendorParticipant;

  const docId = req.params.docId;
  const doc = (reqItem.docs || []).find(d => d.id === docId);
  if (!doc) return res.status(404).send('doc_not_found');

  const issueDateRaw = (req.body.issueDate || '').trim();
  const expiryDateRaw = (req.body.expiryDate || '').trim();
  const signedConfirmed = (req.body.signed === 'on' || req.body.signed === 'true');

  const issueDate = issueDateRaw ? (parseYmd(issueDateRaw) ? issueDateRaw : null) : null;
  const expiryDate = expiryDateRaw ? (parseYmd(expiryDateRaw) ? expiryDateRaw : null) : null;

  withDB(db => {
    const r = (db.requests || []).find(x => x.id === reqItem.id);
    if (!r || !r.uploads || !r.uploads[docId]) return;

    const u = r.uploads[docId];
    if (doc.issueDateRequired) u.issueDate = issueDate;
    if (doc.expiryRequired) u.expiryDate = expiryDate;
    if (doc.requireSignature) u.signedConfirmed = !!signedConfirmed;

    // vendor changed metadata -> re-verify
    u.datesVerified = false;

    r.updatedAt = nowISO();
    db.audit.push({
      id: safeId('aud'),
      tenantId: r.tenantId,
      requestId: r.id,
      actor: participant ? `vendor:${participant.role}:${participant.email || participant.id}` : 'vendor',
      action: 'meta_updated',
      detail: { docId, issueDate: u.issueDate || null, expiryDate: u.expiryDate || null, signedConfirmed: !!u.signedConfirmed },
      at: nowISO(),
    });
  });

  flash(req, 'ok', 'Bilgiler güncellendi.');
  res.redirect(`/v/${accessToken}`);
});

app.post('/v/:token/participants/invite', vendorLimiter, loadVendorRequest, verifyCsrf, async (req, res) => {
  const reqItem = req.vendorRequest;
  const accessToken = req.vendorAccessToken;
  const participant = req.vendorParticipant;

  if (participant && participant.canSubmit === false) {
    flash(req, 'err', 'Bu link ile kişi davet edemezsiniz.');
    return res.redirect(`/v/${accessToken}`);
  }

  const roleRaw = (req.body.role || '').trim();
  const role = ['mali_musavir', 'yetkili', 'diger'].includes(roleRaw) ? roleRaw : 'diger';
  const name = (req.body.name || '').trim();
  const email = (req.body.email || '').trim();

  const token = randomToken(24);
  const pid = safeId('vp');
  const canSubmit = role === 'yetkili';

  withDB(db => {
    const r = (db.requests || []).find(x => x.id === reqItem.id);
    if (!r) return;
    if (!r.participants) {
      // migrate legacy request
      r.participants = [{
        id: safeId('vp'),
        token: r.token,
        role: 'yetkili',
        name: r.vendor?.name || '',
        email: r.vendor?.email || '',
        canSubmit: true,
        createdAt: nowISO(),
        lastSeenAt: null,
      }];
    }
    r.participants.push({
      id: pid,
      token,
      role,
      name,
      email,
      canSubmit,
      createdAt: nowISO(),
      lastSeenAt: null,
    });
    r.updatedAt = nowISO();
    db.audit.push({
      id: safeId('aud'),
      tenantId: r.tenantId,
      requestId: r.id,
      actor: participant ? `vendor:${participant.role}:${participant.email || participant.id}` : 'vendor',
      action: 'participant_invited',
      detail: { pid, role, email: email || null },
      at: nowISO(),
    });
  });

  const link = `${getBaseUrl(req)}/v/${token}`;
  const mailer = getMailer();

  if (mailer && email) {
    try {
      const tpl = emailTemplates.participantInvite({ name, role, vendorName: reqItem.vendor.name, link, canSubmit });
      await mailer.sendMail({
        from: process.env.SMTP_FROM || `${APP_NAME} <noreply@example.com>`,
        to: email,
        subject: tpl.subject,
        text: tpl.text,
      });
    } catch (e) {
      console.warn('vendor participant email failed', e.message);
    }
  }

  flash(req, 'ok', `Davet linki oluşturuldu: ${link}`);
  res.redirect(`/v/${accessToken}`);
});



app.post('/v/:token/submit', vendorLimiter, loadVendorRequest, verifyCsrf, async (req, res) => {
  const reqItem = req.vendorRequest;
  const accessToken = req.vendorAccessToken;
  const participant = req.vendorParticipant;

  if (participant && participant.canSubmit === false) {
    flash(req, 'err', 'Bu link ile “Gönder” işlemi yapılamaz. Lütfen yetkili linkini kullanın.');
    return res.redirect(`/v/${accessToken}`);
  }

  const progress = computeProgress(reqItem);
  const canSubmit = progress.done === progress.required;
  if (!canSubmit) {
    flash(req, 'err', 'Zorunlu belgeler tamamlanmadan gönderemezsiniz. (İmza/geçerlilik kontrolleri de dahil)');
    return res.redirect(`/v/${accessToken}`);
  }

  const updated = withDB(db => {
    const r = db.requests.find(x => x.id === reqItem.id);
    r.status = 'submitted';
    r.submittedAt = nowISO();
    r.submittedBy = participant ? { id: participant.id, role: participant.role, email: participant.email || null, name: participant.name || null } : { role: 'vendor' };
    r.updatedAt = nowISO();
    db.audit.push({
      id: safeId('aud'),
      tenantId: r.tenantId,
      requestId: r.id,
      actor: participant ? `vendor:${participant.role}:${participant.email || participant.id}` : 'vendor',
      action: 'submitted',
      detail: {},
      at: nowISO(),
    });
    return r;
  });

  // optional notify tenant (notifyEmail veya owner) + (isteğe bağlı) global ADMIN_NOTIFY_EMAIL
  const dbNow = readDB();
  const notifyTo = getTenantNotifyEmail(dbNow, updated.tenantId);
  const globalNotify = (process.env.ADMIN_NOTIFY_EMAIL || '').trim(); // SaaS owner istersen
  const mailer = getMailer();
  const toList = [notifyTo, globalNotify].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i);

  if (mailer && toList.length) {
    try {
      const tpl = emailTemplates.vendorSubmitted({ tenantName: (dbNow.tenants.find(t => t.id === updated.tenantId)?.name) || '', reqItem: updated, baseUrl: getBaseUrl(req) });
      await mailer.sendMail({
        from: process.env.SMTP_FROM || `${APP_NAME} <noreply@example.com>`,
        to: toList.join(','),
        subject: tpl.subject,
        text: tpl.text,
      });
    } catch (e) {
      console.warn('notify mail failed', e.message);
    }
  }

  // Webhook/Slack/Teams notifications
  try {
    const tenantNow = (dbNow.tenants || []).find(t => t.id === updated.tenantId);
    const baseUrl = getBaseUrl(req);
    sendTenantNotifications({
      tenant: tenantNow,
      event: 'vendor.submitted',
      baseUrl,
      payload: {
        tenant: { id: tenantNow?.id, name: tenantNow?.name },
        request: { id: updated.id, status: updated.status, vendor: updated.vendor, dueDate: updated.dueDate || null },
        actor: updated.submittedBy || null,
        links: { request: `${baseUrl}/app/requests/${updated.id}` },
      },
    }).catch(e => console.warn('notify vendor.submitted failed', e.message));

    // In-app notification
    addNotification({
      tenantId: updated.tenantId,
      userId: null,
      type: 'request_submitted',
      title: 'Talep gönderildi',
      message: (updated.vendor?.name || '') + ' tüm belgeleri gönderdi',
      link: '/app/requests/' + encodeURIComponent(updated.publicId || updated.id),
    });
  } catch (e) {}

  flash(req, 'ok', 'Gönderildi. Teşekkürler.');
  res.redirect(`/v/${accessToken}`);
});

// --- App routes ---

// Templates (Şablonlar)
app.get('/app/templates', requireAuth, requireOwner, noStore, (req, res) => {
  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);

  const builtins = builtinTemplates();
  const tenantTemplates = (db.templates || []).filter(t => t.tenantId === req.tenant.id)
    .sort((a,b) => (b.updatedAt||'').localeCompare(a.updatedAt||''));

  res.render('layout', {
    title: 'Şablonlar',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('app_templates', {
      cspNonce: res.locals.cspNonce,
      csrfToken: res.locals.csrfToken,
      builtins,
      tenantTemplates,
      defaultTemplateId: req.tenant.defaultTemplateId || '',
    }),
  });
});

app.get('/app/templates/new', requireAuth, requireOwner, noStore, (req, res) => {
  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);
  const from = (req.query.from || '').trim();
  const fromTpl = from ? findTemplateById(db, req.tenant.id, from) : null;

  res.render('layout', {
    title: 'Yeni Şablon',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('app_template_edit', {
      cspNonce: res.locals.cspNonce,
      csrfToken: res.locals.csrfToken,
      mode: 'new',
      template: {
        id: '',
        name: fromTpl?.name ? `${fromTpl.name} (Kopya)` : '',
        industry: fromTpl?.industry || '',
        docs: fromTpl?.docs || [],
      },
      templates: getAllTemplatesForTenant(db, req.tenant.id),
    }),
  });
});

app.post('/app/templates', requireAuth, requireOwner, verifyCsrf, (req, res) => {
  const name = (req.body.name || '').trim();
  const industry = (req.body.industry || '').trim();

  if (!name) {
    flash(req, 'err', 'Şablon adı zorunlu.');
    return res.redirect('/app/templates/new');
  }

  const docs = [];
  for (let i = 0; i < 200; i++) {
    const lbl = (req.body[`docLabel_${i}`] || '').trim();
    if (!lbl) break;
    const required = req.body[`docRequired_${i}`] === 'on';
    const requireSignature = req.body[`docSignature_${i}`] === 'on';
    const issueDateRequired = req.body[`docIssueDate_${i}`] === 'on';
    const expiryRequired = req.body[`docExpiry_${i}`] === 'on';
    const expiryWarnDaysRaw = (req.body[`docWarnDays_${i}`] || '').trim();
    const expiryWarnDays = expiryRequired ? Math.max(1, Math.min(365, parseInt(expiryWarnDaysRaw || '30', 10) || 30)) : 0;

    docs.push({ label: lbl, required, requireSignature, issueDateRequired, expiryRequired, expiryWarnDays });
  }

  if (docs.length === 0) {
    flash(req, 'err', 'En az 1 belge ekleyin veya bir şablon seçin.');
    return res.redirect('/app/templates/new');
  }

  const templateId = safeId('tpl');
  withDB(db => {
    if (!db.templates) db.templates = [];
    db.templates.push({
      id: templateId,
      tenantId: req.tenant.id,
      name,
      industry,
      docs,
      createdAt: nowISO(),
      updatedAt: nowISO(),
    });
    db.audit.push({
      id: safeId('aud'),
      tenantId: req.tenant.id,
      requestId: null,
      actor: req.user.email,
      action: 'template_created',
      detail: { templateId, name, docs: docs.length },
      at: nowISO(),
    });
  });

  flash(req, 'ok', 'Şablon oluşturuldu.');
  res.redirect(`/app/templates/${templateId}/edit`);
});

app.get('/app/templates/:id/edit', requireAuth, requireOwner, noStore, (req, res) => {
  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);
  // UX: Some users may land on /app/templates/default/edit (or a stale link).
  // Treat it as an alias to the current default template when possible.
  if (String(req.params.id) === 'default') {
    const ten = (db.tenants || []).find(x => x.id === req.tenant.id);
    const defId = (ten?.defaultTemplateId || '').trim();
    if (defId) return res.redirect(`/app/templates/${defId}/edit`);
  }

  const t = (db.templates || []).find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
  if (!t) {
    flash(req, 'err', 'Şablon bulunamadı.');
    return res.redirect('/app/templates');
  }

  res.render('layout', {
    title: 'Şablon Düzenle',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('app_template_edit', {
      cspNonce: res.locals.cspNonce,
      csrfToken: res.locals.csrfToken,
      mode: 'edit',
      template: t,
      templates: getAllTemplatesForTenant(db, req.tenant.id),
    }),
  });
});

app.post('/app/templates/:id', requireAuth, requireOwner, verifyCsrf, (req, res, next) => {
  // Reserved static routes like /app/templates/default and /app/templates/copy
  // must not be swallowed by the generic update route. Let Express continue
  // to the explicit handlers defined below.
  if (req.params.id === 'default' || req.params.id === 'copy') return next('route');

  const name = (req.body.name || '').trim();
  const industry = (req.body.industry || '').trim();
  if (!name) {
    flash(req, 'err', 'Şablon adı zorunlu.');
    return res.redirect(`/app/templates/${req.params.id}/edit`);
  }

  const docs = [];
  for (let i = 0; i < 200; i++) {
    const lbl = (req.body[`docLabel_${i}`] || '').trim();
    if (!lbl) break;
    const required = req.body[`docRequired_${i}`] === 'on';
    const requireSignature = req.body[`docSignature_${i}`] === 'on';
    const issueDateRequired = req.body[`docIssueDate_${i}`] === 'on';
    const expiryRequired = req.body[`docExpiry_${i}`] === 'on';
    const expiryWarnDaysRaw = (req.body[`docWarnDays_${i}`] || '').trim();
    const expiryWarnDays = expiryRequired ? Math.max(1, Math.min(365, parseInt(expiryWarnDaysRaw || '30', 10) || 30)) : 0;

    docs.push({ label: lbl, required, requireSignature, issueDateRequired, expiryRequired, expiryWarnDays });
  }

  if (docs.length === 0) {
    flash(req, 'err', 'En az 1 belge ekleyin veya bir şablon seçin.');
    return res.redirect(`/app/templates/${req.params.id}/edit`);
  }

  withDB(db => {
    const t = (db.templates || []).find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
    if (!t) return;
    t.name = name;
    t.industry = industry;
    t.docs = docs;
    t.updatedAt = nowISO();
    db.audit.push({
      id: safeId('aud'),
      tenantId: req.tenant.id,
      requestId: null,
      actor: req.user.email,
      action: 'template_updated',
      detail: { templateId: t.id, docs: docs.length },
      at: nowISO(),
    });
  });

  flash(req, 'ok', 'Kaydedildi.');
  res.redirect(`/app/templates/${req.params.id}/edit`);
});

app.post('/app/templates/:id/delete', requireAuth, requireOwner, verifyCsrf, (req, res) => {
  withDB(db => {
    db.templates = (db.templates || []).filter(t => !(t.id === req.params.id && t.tenantId === req.tenant.id));
    // unset default if it was this template
    const ten = (db.tenants || []).find(t => t.id === req.tenant.id);
    if (ten && ten.defaultTemplateId === req.params.id) ten.defaultTemplateId = '';
    db.audit.push({
      id: safeId('aud'),
      tenantId: req.tenant.id,
      requestId: null,
      actor: req.user.email,
      action: 'template_deleted',
      detail: { templateId: req.params.id },
      at: nowISO(),
    });
  });
  flash(req, 'ok', 'Şablon silindi.');
  res.redirect('/app/templates');
});

app.post('/app/templates/default', requireAuth, requireOwner, verifyCsrf, (req, res) => {
  const templateId = (req.body.templateId || '').trim();
  const db = readDB();
  const t = findTemplateById(db, req.tenant.id, templateId);
  if (!t) {
    const wantsJson = String(req.headers.accept || '').includes('application/json');
    if (wantsJson) return res.status(404).json({ ok: false, error: 'Şablon bulunamadı.' });
    flash(req, 'err', 'Şablon bulunamadı.');
    return res.redirect('/app/templates');
  }

  withDB(db2 => {
    const ten = (db2.tenants || []).find(x => x.id === req.tenant.id);
    if (ten) ten.defaultTemplateId = templateId;
    db2.audit.push({
      id: safeId('aud'),
      tenantId: req.tenant.id,
      requestId: null,
      actor: req.user.email,
      action: 'template_default_set',
      detail: { templateId },
      at: nowISO(),
    });
  });

  const wantsJson = String(req.headers.accept || '').includes('application/json');
  if (wantsJson) return res.json({ ok: true, defaultTemplateId: templateId });

  flash(req, 'ok', 'Varsayılan şablon ayarlandı.');
  res.redirect('/app/templates');
});

app.post('/app/templates/copy', requireAuth, requireOwner, verifyCsrf, (req, res) => {
  const from = String(req.body.from || req.body.templateId || req.query.from || '').trim();
  const wants = wantsJson(req);
  const db = readDB();

  const builtin = builtinTemplates().find(t => t.id === from) || null;
  const tpl = builtin || findTemplateById(db, req.tenant.id, from);
  if (!tpl) {
    const msg = 'Kopyalanacak şablon bulunamadı.';
    if (wants) return res.status(404).json({ ok: false, error: msg });
    flash(req, 'err', msg);
    return res.redirect('/app/templates');
  }

  // If the tenant already copied/customized this builtin, just reuse it.
  const existing = builtin
    ? (db.templates || []).find(t => t.tenantId === req.tenant.id && t.sourceBuiltinId === builtin.id)
    : null;
  if (existing) {
    const msg = 'Bu hazır şablon zaten şirket şablonlarına kopyalandı.';
    if (wants) return res.json({ ok: true, id: existing.id, existing: true, redirect: '/app/templates' });
    flash(req, 'ok', msg);
    return res.redirect('/app/templates');
  }

  const id = safeId('tpl');
  withDB(db2 => {
    if (!db2.templates) db2.templates = [];
    db2.templates.push({
      id,
      tenantId: req.tenant.id,
      name: `${tpl.name} (Özel)`,
      industry: tpl.industry || '',
      sourceBuiltinId: builtin ? builtin.id : (tpl.sourceBuiltinId || ''),
      docs: (tpl.docs || []).map(d => ({ ...d })),
      createdAt: nowISO(),
      updatedAt: nowISO(),
    });
    db2.audit.push({
      id: safeId('aud'),
      tenantId: req.tenant.id,
      requestId: null,
      actor: req.user.email,
      action: 'template_copied',
      detail: { from, to: id },
      at: nowISO(),
    });
  });

  if (wants) return res.json({ ok: true, id, redirect: '/app/templates' });
  flash(req, 'ok', 'Şablon kopyalandı. Şirket şablonlarında hazır.');
  res.redirect('/app/templates');
});


app.post('/app/templates/builtin/edit', requireAuth, requireOwner, verifyCsrf, (req, res) => {
  const from = (req.body.from || '').trim();
  const db = readDB();
  const tpl = findTemplateById(db, req.tenant.id, from);
  if (!tpl || tpl.builtin !== true) {
    flash(req, 'err', 'Düzenlenecek hazır şablon bulunamadı.');
    return res.redirect('/app/templates');
  }

  // If this tenant already has a customized copy for this builtin, open it.
  const existing = (db.templates || []).find(t => t.tenantId === req.tenant.id && t.sourceBuiltinId === from);
  if (existing) {
    return res.redirect(`/app/templates/${existing.id}/edit`);
  }

  const id = safeId('tpl');
  withDB(db2 => {
    if (!db2.templates) db2.templates = [];
    db2.templates.push({
      id,
      tenantId: req.tenant.id,
      sourceBuiltinId: from,
      name: `${tpl.name} (Özel)`,
      industry: tpl.industry || '',
      docs: (tpl.docs || []).map(d => ({ ...d })),
      createdAt: nowISO(),
      updatedAt: nowISO(),
    });

    // If the builtin was set as default, automatically switch default to the customized copy.
    const ten = (db2.tenants || []).find(x => x.id === req.tenant.id);
    if (ten && ten.defaultTemplateId === from) ten.defaultTemplateId = id;

    db2.audit.push({
      id: safeId('aud'),
      tenantId: req.tenant.id,
      requestId: null,
      actor: req.user.email,
      action: 'template_customized_from_builtin',
      detail: { from, to: id },
      at: nowISO(),
    });
  });

  flash(req, 'ok', 'Hazır şablon özelleştirme modunda açıldı.');
  res.redirect(`/app/templates/${id}/edit`);
});



app.get('/app', requireAuth, (req, res) => res.redirect('/app/dashboard'));

// ============================
// DASHBOARD
// ============================
app.get('/app/dashboard', requireAuth, noStore, (req, res) => {
  const db = readDB();
  const lang = getLocale(req);
  const plan = getPlanForTenant(db, req.tenant.id);
  const tenantRequests = (db.requests || []).filter(r => r.tenantId === req.tenant.id);

  const activeRequests = tenantRequests.filter(r => r.status === 'open' || r.status === 'submitted').length;
  let pendingDocs = 0;
  let completedDocs = 0;
  let totalRequired = 0;
  const expiringDocs = [];

  for (const r of tenantRequests) {
    for (const d of (r.docs || [])) {
      const st = getDocState(r, d);
      if (d.required) {
        totalRequired++;
        if (st.complete) completedDocs++;
        else pendingDocs++;
      }
      if (st.expiringSoon || st.expired) {
        expiringDocs.push({
          requestId: r.publicId || r.id,
          vendorName: r.vendor?.name || '-',
          docLabel: d.label,
          expiryDate: (r.uploads || {})[d.id]?.expiryDate || '-',
          daysLeft: st.expiryDaysLeft,
        });
      }
    }
  }

  expiringDocs.sort((a, b) => (a.daysLeft || 999) - (b.daysLeft || 999));

  const vendorSet = new Set(tenantRequests.map(r => r.vendor?.email || r.vendor?.name).filter(Boolean));
  const completionRate = totalRequired > 0 ? Math.round((completedDocs / totalRequired) * 100) : 0;

  // Avg completion days (from created to submitted/approved)
  const completedReqs = tenantRequests.filter(r => r.status === 'approved' || r.status === 'archived');
  let avgCompletionDays = 0;
  if (completedReqs.length) {
    const totalDays = completedReqs.reduce((sum, r) => {
      const created = new Date(r.createdAt).getTime();
      const done = new Date(r.updatedAt || r.createdAt).getTime();
      return sum + Math.max(0, Math.ceil((done - created) / (24*3600*1000)));
    }, 0);
    avgCompletionDays = Math.round(totalDays / completedReqs.length);
  }

  const recentActivity = (db.audit || [])
    .filter(a => a.tenantId === req.tenant.id)
    .sort((a, b) => (b.at || '').localeCompare(a.at || ''))
    .slice(0, 15);

  const stats = {
    totalRequests: tenantRequests.length,
    activeRequests,
    pendingDocs,
    completedDocs,
    expiringSoon: expiringDocs.length,
    completionRate,
    totalVendors: vendorSet.size,
    avgCompletionDays,
  };

  const notifCount = getUnreadCount(req.tenant.id, req.user.id);

  res.render('layout', {
    title: t(lang, 'dashboard.title'),
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    notifCount,
    lang,
    body: render('app_dashboard', {
      csrfToken: res.locals.csrfToken,
      stats,
      recentActivity,
      expiringDocs: expiringDocs.slice(0, 10),
      t, lang, notifCount,
    }),
  });
});

// ============================
// NOTIFICATIONS
// ============================
app.get('/app/notifications', requireAuth, noStore, (req, res) => {
  const lang = getLocale(req);
  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);
  const page = Math.max(1, parseInt(req.query.page || '1', 10) || 1);
  const limit = 20;
  const offset = (page - 1) * limit;
  const unreadOnly = req.query.unread === '1';
  const notifications = getNotifications(req.tenant.id, req.user.id, { limit, offset, unreadOnly });
  const notifCount = getUnreadCount(req.tenant.id, req.user.id);

  res.render('layout', {
    title: t(lang, 'notifications.title'),
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    notifCount,
    lang,
    body: render('app_notifications', {
      csrfToken: res.locals.csrfToken,
      notifications, notifCount, page, unreadOnly, t, lang,
    }),
  });
});

app.post('/app/notifications/read/:id', requireAuth, verifyCsrf, (req, res) => {
  markAsRead(req.params.id);
  const wantsJson = (req.get('accept') || '').includes('json');
  if (wantsJson) return res.json({ ok: true });
  res.redirect('/app/notifications');
});

app.post('/app/notifications/read-all', requireAuth, verifyCsrf, (req, res) => {
  markAllAsRead(req.tenant.id, req.user.id);
  flash(req, 'ok', 'Tüm bildirimler okundu olarak işaretlendi.');
  res.redirect('/app/notifications');
});

// ============================
// REPORTS
// ============================
app.get('/app/reports', requireAuth, requireOwner, noStore, (req, res) => {
  const lang = getLocale(req);
  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);
  const notifCount = getUnreadCount(req.tenant.id, req.user.id);
  const tenantRequests = (db.requests || []).filter(r => r.tenantId === req.tenant.id);

  // Date range filter
  const from = req.query.from || '';
  const to = req.query.to || '';

  let filteredRequests = tenantRequests;
  if (from) filteredRequests = filteredRequests.filter(r => (r.createdAt || '') >= from);
  if (to) filteredRequests = filteredRequests.filter(r => (r.createdAt || '') <= to + 'T23:59:59');

  // Compute report data
  const statusCounts = {};
  for (const r of filteredRequests) {
    statusCounts[r.status] = (statusCounts[r.status] || 0) + 1;
  }

  // Vendor performance
  const vendorMap = {};
  for (const r of filteredRequests) {
    const vKey = r.vendor?.email || r.vendor?.name || 'unknown';
    if (!vendorMap[vKey]) vendorMap[vKey] = { name: r.vendor?.name || vKey, company: r.vendor?.company || '', total: 0, completed: 0, avgDays: 0, totalDays: 0 };
    vendorMap[vKey].total++;
    if (r.status === 'approved' || r.status === 'archived') {
      vendorMap[vKey].completed++;
      const days = Math.max(0, Math.ceil((new Date(r.updatedAt || r.createdAt) - new Date(r.createdAt)) / (24*3600*1000)));
      vendorMap[vKey].totalDays += days;
    }
  }
  const vendorPerformance = Object.values(vendorMap).map(v => ({
    ...v,
    complianceRate: v.total > 0 ? Math.round((v.completed / v.total) * 100) : 0,
    avgDays: v.completed > 0 ? Math.round(v.totalDays / v.completed) : '-',
  })).sort((a, b) => b.total - a.total);

  // Monthly breakdown
  const monthlyData = {};
  for (const r of filteredRequests) {
    const month = (r.createdAt || '').slice(0, 7);
    if (!monthlyData[month]) monthlyData[month] = { created: 0, completed: 0 };
    monthlyData[month].created++;
    if (r.status === 'approved' || r.status === 'archived') monthlyData[month].completed++;
  }

  // Doc completion stats
  let totalDocs = 0, completedDocs = 0, expiredDocs = 0;
  for (const r of filteredRequests) {
    for (const d of (r.docs || [])) {
      if (d.required) {
        totalDocs++;
        const st = getDocState(r, d);
        if (st.complete) completedDocs++;
        if (st.expired) expiredDocs++;
      }
    }
  }

  res.render('layout', {
    title: t(lang, 'reports.title'),
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    notifCount,
    lang,
    body: render('app_reports', {
      csrfToken: res.locals.csrfToken,
      statusCounts,
      vendorPerformance,
      monthlyData,
      totalDocs, completedDocs, expiredDocs,
      from, to,
      totalRequests: filteredRequests.length,
      t, lang,
    }),
  });
});

app.get('/app/reports/export.csv', requireAuth, requireOwner, (req, res) => {
  const db = readDB();
  const tenantRequests = (db.requests || []).filter(r => r.tenantId === req.tenant.id);
  const rows = [['ID', 'Vendor', 'Company', 'Status', 'Created', 'Due Date', 'Required Docs', 'Completed Docs', 'Completion %'].join(',')];
  for (const r of tenantRequests) {
    const prog = computeProgress(r);
    const pct = prog.required > 0 ? Math.round((prog.done / prog.required) * 100) : 100;
    rows.push([
      r.publicId || r.id,
      '"' + (r.vendor?.name || '').replace(/"/g, '""') + '"',
      '"' + (r.vendor?.company || '').replace(/"/g, '""') + '"',
      r.status,
      (r.createdAt || '').slice(0, 10),
      r.dueDate || '',
      prog.required,
      prog.done,
      pct + '%',
    ].join(','));
  }
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="rapor.csv"');
  res.send('\uFEFF' + rows.join('\n'));
});

// ============================
// ACTIVITY TIMELINE
// ============================
app.get('/app/activity', requireAuth, noStore, (req, res) => {
  const lang = getLocale(req);
  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);
  const notifCount = getUnreadCount(req.tenant.id, req.user.id);
  const page = Math.max(1, parseInt(req.query.page || '1', 10) || 1);
  const limit = 50;
  const offset = (page - 1) * limit;
  const actionFilter = (req.query.action || '').trim();

  let allAudit = (db.audit || [])
    .filter(a => a.tenantId === req.tenant.id)
    .sort((a, b) => (b.at || '').localeCompare(a.at || ''));

  if (actionFilter) {
    allAudit = allAudit.filter(a => a.action === actionFilter);
  }

  const totalCount = allAudit.length;
  const auditPage = allAudit.slice(offset, offset + limit);

  // Unique action types for filter dropdown
  const actionTypes = [...new Set((db.audit || []).filter(a => a.tenantId === req.tenant.id).map(a => a.action))].sort();

  res.render('layout', {
    title: 'Aktivite Geçmişi',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    notifCount,
    lang,
    body: render('app_activity', {
      csrfToken: res.locals.csrfToken,
      audit: auditPage,
      page, totalCount, limit, actionFilter, actionTypes,
      t, lang,
    }),
  });
});

// ============================
// LANGUAGE SWITCHER
// ============================
app.post('/app/set-lang', requireAuth, verifyCsrf, (req, res) => {
  const lang = (req.body.lang || 'tr').trim();
  if (['tr', 'en'].includes(lang)) {
    req.session.lang = lang;
  }
  const returnTo = req.body.returnTo || '/app/dashboard';
  res.redirect(returnTo);
});

// ============================
// BULK OPERATIONS
// ============================
app.post('/app/requests/bulk', requireAuth, verifyCsrf, (req, res) => {
  const ids = req.body.ids;
  const idList = Array.isArray(ids) ? ids : (ids || '').split(',').filter(Boolean);
  const action = (req.body.action || '').trim();

  if (!idList.length || !action) {
    flash(req, 'err', 'Lütfen en az bir talep seçin ve işlem belirleyin.');
    return res.redirect('/app/requests');
  }

  const validActions = ['approve', 'reject', 'archive', 'remind'];
  if (!validActions.includes(action)) {
    flash(req, 'err', 'Geçersiz toplu işlem.');
    return res.redirect('/app/requests');
  }

  const statusMap = { approve: 'approved', reject: 'rejected', archive: 'archived' };
  let count = 0;

  withDB(db => {
    for (const id of idList) {
      const r = (db.requests || []).find(x => (x.publicId === id || x.id === id) && x.tenantId === req.tenant.id);
      if (!r) continue;
      if (action === 'remind') {
        // Just mark for reminder (actual email sent separately)
        count++;
        continue;
      }
      const newStatus = statusMap[action];
      if (newStatus && r.status !== newStatus) {
        r.status = newStatus;
        r.updatedAt = nowISO();
        db.audit.push({
          id: safeId('aud'),
          tenantId: req.tenant.id,
          requestId: r.id,
          actor: req.user.email,
          action: 'status_changed_bulk',
          detail: { from: r.status, to: newStatus },
          detailText: 'Toplu: ' + statusLabel(newStatus),
          at: nowISO(),
        });
        count++;
      }
    }
  });

  flash(req, 'ok', count + ' talep güncellendi.');
  res.redirect('/app/requests');
});


// Team
app.get('/app/team', requireAuth, requireOwner, noStore, (req, res) => {
  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);
  const baseUrl = getBaseUrl(req);

  const users = (db.users || []).filter(u => u.tenantId === req.tenant.id)
    .sort((a,b) => (a.email||'').localeCompare(b.email||''));

  const invites = (db.invites || [])
    .filter(i => i.tenantId === req.tenant.id && isInviteValid(i))
    .sort((a,b) => (b.createdAt||'').localeCompare(a.createdAt||''))
    .map(i => ({ ...i, link: `${baseUrl}/invite/${i.token}` }));

  res.render('layout', {
    title: 'Ekip',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('app_team', { csrfToken: res.locals.csrfToken, users, invites, user: req.user, tenant: req.tenant, plan }),
  });
});

app.get('/app/team/invite', requireAuth, requireOwner, noStore, (req, res) => {
  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);
  const usersCount = (db.users || []).filter(u => u.tenantId === req.tenant.id).length;

  const inviteLink = req.session.inviteLink || null;
  delete req.session.inviteLink;

  res.render('layout', {
    title: 'Kullanıcı Davet',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('app_team_invite', { csrfToken: res.locals.csrfToken, plan, usersCount, inviteLink }),
  });
});

app.post('/app/team/invite', requireAuth, requireOwner, verifyCsrf, async (req, res) => {
  const email = (req.body.email || '').trim().toLowerCase();
  const role = (req.body.role || 'member').trim();
  if (!email || !email.includes('@')) {
    flash(req, 'err', 'E-posta geçersiz.');
    return res.redirect('/app/team/invite');
  }
  if (!['member','admin'].includes(role)) {
    flash(req, 'err', 'Rol geçersiz.');
    return res.redirect('/app/team/invite');
  }

  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);
  const usersCount = (db.users || []).filter(u => u.tenantId === req.tenant.id).length;
  if (usersCount >= plan.maxUsers) {
    flash(req, 'err', `Plan kullanıcı limiti dolu (${plan.maxUsers}). Plan yükseltin.`);
    return res.redirect('/app/billing');
  }
  if ((db.users || []).some(u => u.email === email)) {
    flash(req, 'err', 'Bu e-posta zaten kayıtlı.');
    return res.redirect('/app/team/invite');
  }
  if ((db.invites || []).some(i => i.tenantId === req.tenant.id && i.email === email && isInviteValid(i))) {
    flash(req, 'err', 'Bu e-posta için zaten bekleyen bir davet var.');
    return res.redirect('/app/team');
  }

  const token = randomToken(24);
  const inviteId = safeId('inv');
  const baseUrl = getBaseUrl(req);
  const link = `${baseUrl}/invite/${token}`;

  withDB(db2 => {
    db2.invites = db2.invites || [];
    db2.invites.push({
      id: inviteId,
      tenantId: req.tenant.id,
      email,
      role,
      token,
      createdAt: nowISO(),
      expiresAt: new Date(Date.now() + 14*24*60*60*1000).toISOString(),
      acceptedAt: null,
      invitedBy: req.user.email,
    });
    db2.audit.push({
      id: safeId('aud'),
      tenantId: req.tenant.id,
      requestId: null,
      actor: req.user.email,
      action: 'team_invite_created',
      detail: { email, role },
      at: nowISO(),
    });
  });

  const mailer = getMailer();
  if (mailer) {
    try {
      const tpl = emailTemplates.teamInvite({ appName: APP_NAME, tenantName: req.tenant.name, link });
      await mailer.sendMail({
        from: process.env.SMTP_FROM || `${APP_NAME} <noreply@example.com>`,
        to: email,
        subject: tpl.subject,
        text: tpl.text,
      });
      flash(req, 'ok', 'Davet e-postası gönderildi.');
      return res.redirect('/app/team');
    } catch (e) {
      console.warn('team invite mail failed', e.message);
      // fall through -> show link
    }
  }

  req.session.inviteLink = link;
  flash(req, 'ok', 'Davet oluşturuldu. SMTP yoksa linki kopyalayın.');
  return res.redirect('/app/team/invite');
});

app.post('/app/team/revoke/:id', requireAuth, requireOwner, verifyCsrf, (req, res) => {
  const id = req.params.id;
  withDB(db => {
    db.invites = (db.invites || []).filter(i => !(i.id === id && i.tenantId === req.tenant.id));
    db.audit.push({
      id: safeId('aud'),
      tenantId: req.tenant.id,
      requestId: null,
      actor: req.user.email,
      action: 'team_invite_revoked',
      detail: { id },
      at: nowISO(),
    });
  });
  flash(req, 'ok', 'Davet iptal edildi.');
  res.redirect('/app/team');
});

app.post('/app/team/remove/:userId', requireAuth, requireOwner, verifyCsrf, (req, res) => {
  const userId = req.params.userId;
  const db = readDB();
  const u = (db.users || []).find(x => x.id === userId && x.tenantId === req.tenant.id);
  if (!u) return res.status(404).send('not_found');
  if (u.role === 'owner') {
    flash(req, 'err', 'Owner silinemez.');
    return res.redirect('/app/team');
  }
  if (u.id === req.user.id) {
    flash(req, 'err', 'Kendinizi silemezsiniz.');
    return res.redirect('/app/team');
  }
  withDB(db2 => {
    db2.users = (db2.users || []).filter(x => !(x.id === userId && x.tenantId === req.tenant.id));
    db2.audit.push({
      id: safeId('aud'),
      tenantId: req.tenant.id,
      requestId: null,
      actor: req.user.email,
      action: 'team_member_removed',
      detail: { userId, email: u.email },
      at: nowISO(),
    });
  });
  flash(req, 'ok', 'Kullanıcı kaldırıldı.');
  res.redirect('/app/team');
});


app.get('/app/requests', requireAuth, noStore, (req, res) => {
  const db = readDB();
  const lang = getLocale(req);
  const plan = getPlanForTenant(db, req.tenant.id);
  const notifCount = getUnreadCount(req.tenant.id, req.user.id);
  const statusFilter = (req.query.status || '').trim();
  const q = (req.query.q || '').trim().toLowerCase();
  const sortBy = (req.query.sort || 'newest').trim();

  let requests = db.requests.filter(r => r.tenantId === req.tenant.id);

  // Status filter
  if (statusFilter && STATUS.includes(statusFilter)) requests = requests.filter(r => r.status === statusFilter);

  // Search filter
  if (q) {
    requests = requests.filter(r => {
      const vendorName = (r.vendor?.name || '').toLowerCase();
      const vendorCompany = (r.vendor?.company || '').toLowerCase();
      const vendorEmail = (r.vendor?.email || '').toLowerCase();
      const publicId = (r.publicId || r.id || '').toLowerCase();
      return vendorName.includes(q) || vendorCompany.includes(q) || vendorEmail.includes(q) || publicId.includes(q);
    });
  }

  // Sort
  switch (sortBy) {
    case 'oldest':
      requests.sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));
      break;
    case 'due':
      requests.sort((a, b) => (a.dueDate || 'z').localeCompare(b.dueDate || 'z'));
      break;
    case 'vendor':
      requests.sort((a, b) => (a.vendor?.name || '').localeCompare(b.vendor?.name || '', 'tr'));
      break;
    default:
      requests.sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
  }

  const normalized = requests.map(r => ({
    ...r,
    progress: computeProgress(r),
    health: computeHealth(r),
  }));

  res.render('layout', {
    title: 'Talepler',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    notifCount,
    lang,
    body: render('app_requests', {
      csrfToken: res.locals.csrfToken,
      requests: normalized,
      statusLabel,
      q, statusFilter, sortBy,
    }),
  });
});

const DEFAULT_DOCS = [];
// Yeni talep ekranı varsayılan olarak BOS başlar. (Şablon seçilirse şablondan dolar)


app.get('/app/requests/new', requireAuth, noStore, (req, res) => {
  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);

  const templates = getAllTemplatesForTenant(db, req.tenant.id);

  // Optional template override from querystring:
  //   /app/requests/new?tpl=builtin_insaat
  //   /app/requests/new?tpl=none  -> force generic defaults (no template)
  const tplOverride = String((req.query.tpl || '')).trim();

  let initialTemplateId = '';
  if (tplOverride === 'none') {
    initialTemplateId = '';
  } else if (tplOverride) {
    initialTemplateId = tplOverride;
  } else {
    initialTemplateId = ''; // Public launch: yeni talep BOS başlar; default şablon otomatik uygulanmaz
  }

  const initialTemplate = initialTemplateId ? findTemplateById(db, req.tenant.id, initialTemplateId) : null;
  const defaultDocs = (initialTemplate && initialTemplate.docs && initialTemplate.docs.length) ? initialTemplate.docs : DEFAULT_DOCS;

  res.render('layout', {
    title: 'Yeni Talep',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('app_new_request', {
      cspNonce: res.locals.cspNonce,
      csrfToken: res.locals.csrfToken,
      plan,
      defaultDocs,
      templates,
      initialTemplateId: initialTemplateId || '',
      tenantId: req.tenant.id,
      userId: req.user.id,
    }),
  });
});

app.post('/app/requests', requireAuth, verifyCsrf, (req, res) => {
  const vendorName = (req.body.vendorName || '').trim();
  const vendorCompany = (req.body.vendorCompany || '').trim();
  const vendorEmail = (req.body.vendorEmail || '').trim();
  const dueDate = (req.body.dueDate || '').trim();
  const vendorMessage = (req.body.vendorMessage || '').trim();

  if (!vendorName) {
    flash(req, 'err', 'Tedarikçi adı zorunlu.');
    return res.redirect('/app/requests/new');
  }

  // collect docs from form
  const docs = [];
  for (let i = 0; i < 200; i++) {
    const lbl = (req.body[`docLabel_${i}`] || '').trim();
    if (!lbl) break;
    const required = req.body[`docRequired_${i}`] === 'on';
    const requireSignature = req.body[`docSignature_${i}`] === 'on';
    const issueDateRequired = req.body[`docIssueDate_${i}`] === 'on';
    const expiryRequired = req.body[`docExpiry_${i}`] === 'on';
    const expiryWarnDaysRaw = (req.body[`docWarnDays_${i}`] || '').trim();
    const expiryWarnDays = expiryRequired ? Math.max(1, Math.min(365, parseInt(expiryWarnDaysRaw || '30', 10) || 30)) : 0;

    docs.push({
      id: safeId('doc'),
      label: lbl,
      required,
      requireSignature,
      issueDateRequired,
      expiryRequired,
      expiryWarnDays,
    });
  }

  if (docs.length === 0) {
    flash(req, 'err', 'En az 1 belge ekleyin veya bir şablon seçin.');
    return res.redirect('/app/requests/new');
  }

  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);
  if (docs.length > plan.maxDocsPerRequest) {
    flash(req, 'err', `Plan limit: Talep başına en fazla ${plan.maxDocsPerRequest} belge.`);
    return res.redirect('/app/requests/new');
  }

  const activeCount = db.requests.filter(r => r.tenantId === req.tenant.id && r.status !== 'archived').length;
  if (activeCount >= plan.maxActiveRequests) {
    flash(req, 'err', `Plan limit: Aktif talep limiti (${plan.maxActiveRequests}). Lütfen plan yükseltin.`);
    return res.redirect('/app/billing');
  }

  const requestId = safeId('req');
  const token = randomToken(24);
  let publicId = null;

  const primaryParticipant = {
    id: safeId('vp'),
    token,
    role: 'yetkili',
    name: vendorName,
    email: vendorEmail,
    canSubmit: true,
    createdAt: nowISO(),
    lastSeenAt: null,
  };
  const participants = [primaryParticipant];

  withDB(db2 => {
    const t = (db2.tenants || []).find(x => x.id === req.tenant.id);
    const seq = Math.max(1, parseInt(t?.nextRequestSeq || 1, 10) || 1);
    publicId = `TLP-${String(seq).padStart(6,'0')}`;
    if (t) t.nextRequestSeq = seq + 1;

    db2.requests.push({
      id: requestId,
      publicId,
      tenantId: req.tenant.id,
      token,
      vendor: { name: vendorName, company: vendorCompany, email: vendorEmail },
      participants,
      dueDate: dueDate || null,
      vendorMessage: vendorMessage || null,
      status: 'open',
      docs,
      uploads: {},
      note: '',
      createdAt: nowISO(),
      updatedAt: nowISO(),
    });
    db2.audit.push({
      id: safeId('aud'),
      tenantId: req.tenant.id,
      requestId,
      actor: req.user.email,
      action: 'created',
      detail: { docs: docs.length },
      at: nowISO(),
    });
  });

  // Notifications (webhook/slack/teams) — fire-and-forget
  try {
    const baseUrl = getBaseUrl(req);
    const tenantNow = readDB().tenants.find(t => t.id === req.tenant.id);
    sendTenantNotifications({
      tenant: tenantNow,
      event: 'request.created',
      baseUrl,
      payload: {
        tenant: { id: req.tenant.id, name: req.tenant.name },
        request: { id: requestId, publicId, vendor: { name: vendorName, company: vendorCompany, email: vendorEmail }, dueDate: dueDate || null },
        links: { request: `${baseUrl}/app/requests/${encodeURIComponent(publicId || requestId)}` },
      },
    }).catch(e => console.warn('notify request.created failed', e.message));
  } catch (e) {}

  flash(req, 'ok', 'Talep oluşturuldu.');
  // Use human-friendly Talep No in the URL for a cleaner address bar.
  res.redirect(`/app/requests/${encodeURIComponent(publicId || requestId)}`);
});

function maskId(s) {
  const str = String(s || '');
  if (!str) return '';
  if (str.length <= 10) return str;
  return `${str.slice(0, 4)}…${str.slice(-4)}`;
}

function redactDetailValue(key, value) {
  const k = String(key || '').toLowerCase();
  if (value == null) return value;

  // Never show secrets/tokens in UI
  if (k.includes('token') || k.includes('secret') || k.includes('password') || k.includes('pass')) {
    return '[redacted]';
  }

  if (typeof value === 'string') {
    const v = value;
    // common internal ids (mask)
    if (v.startsWith('vp_') || v.startsWith('doc_') || v.startsWith('TLP-') || v.length > 32) return maskId(v);
    return v;
  }

  return value;
}

function redactDetailObject(obj) {
  if (obj == null) return obj;
  if (Array.isArray(obj)) return obj.map((x) => redactDetailObject(x));
  if (typeof obj !== 'object') return obj;

  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    out[k] = (typeof v === 'object') ? redactDetailObject(v) : redactDetailValue(k, v);
  }
  return out;
}

function formatAuditDetail(a) {
  const d = a && a.detail ? a.detail : {};
  const action = a ? a.action : '';

  if (action === 'created') {
    const docs = (d && typeof d.docs !== 'undefined') ? d.docs : undefined;
    return docs != null ? `Talep oluşturuldu (belge: ${docs})` : 'Talep oluşturuldu';
  }

  if (action === 'status_changed') {
    const from = d && d.from ? d.from : '?';
    const to = d && d.to ? d.to : '?';
    return `Durum: ${from} → ${to}`;
  }

  if (action === 'participant_added') {
    const role = d && d.role ? d.role : '?';
    const email = d && d.email ? d.email : '';
    const pid = d && d.pid ? maskId(d.pid) : '';
    return `Katılımcı eklendi: ${role}${email ? ` · ${email}` : ''}${pid ? ` · ${pid}` : ''}`;
  }

  if (action === 'participant_removed') {
    const role = d && d.role ? d.role : '?';
    const email = d && d.email ? d.email : '';
    const pid = d && d.pid ? maskId(d.pid) : '';
    return `Katılımcı kaldırıldı: ${role}${email ? ` · ${email}` : ''}${pid ? ` · ${pid}` : ''}`;
  }

  if (action === 'upload') {
    const label = d && d.docLabel ? d.docLabel : (d && d.docId ? maskId(d.docId) : 'Belge');
    const size = d && d.size ? formatBytes(d.size) : '';
    const mime = d && d.mime ? String(d.mime).split('/').pop().toUpperCase() : '';
    const provider = d && d.provider ? d.provider : '';
    const parts = [];
    if (size) parts.push(size);
    if (mime) parts.push(mime);
    if (provider) parts.push(provider);
    return `Yüklendi: ${label}${parts.length ? ` (${parts.join(', ')})` : ''}`;
  }

  if (action === 'download') {
    const label = d && d.docLabel ? d.docLabel : (d && d.docId ? maskId(d.docId) : 'Belge');
    return `İndirildi: ${label}`;
  }

  if (action === 'link_created') {
    const role = d && d.role ? d.role : 'tedarikçi';
    const sent = d && d.sent ? ' (e-posta gönderildi)' : '';
    return `Link oluşturuldu: ${role}${sent}`;
  }

  // Fallback: show redacted JSON (single line)
  const redacted = redactDetailObject(d || {});
  try {
    const s = JSON.stringify(redacted);
    return s === '{}' ? '—' : s;
  } catch (_) {
    return '—';
  }
}

app.get('/app/requests/:id', requireAuth, noStore, (req, res) => {
  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);
  const slug = String(req.params.id || '').trim();

  // Accept either internal requestId (req_...) or public Talep No (TLP-000123)
  let reqItem = db.requests.find(r => r.id === slug && r.tenantId === req.tenant.id);
  if (reqItem && reqItem.publicId) {
    // Canonicalize: if internal id was used, redirect to the public id route
    return res.redirect(`/app/requests/${encodeURIComponent(reqItem.publicId)}`);
  }

  if (!reqItem) {
    const slugUpper = slug.toUpperCase();
    reqItem = db.requests.find(r => (r.publicId || '').toUpperCase() === slugUpper && r.tenantId === req.tenant.id);
  }

  if (!reqItem) return res.status(404).send('not_found');

  const progress = computeProgress(reqItem);
  const health = computeHealth(reqItem);
  const baseUrl = getBaseUrl(req);

  const participants = (reqItem.participants && reqItem.participants.length)
    ? reqItem.participants
    : [{
      id: 'vp_legacy',
      token: reqItem.token,
      role: 'yetkili',
      name: reqItem.vendor?.name || '',
      email: reqItem.vendor?.email || '',
      canSubmit: true,
    }];

  const participantsWithLinks = participants.map(p => ({
    ...p,
    link: `${baseUrl}/v/${p.token}`,
  }));

  const vendorLink = participantsWithLinks[0]?.link || `${baseUrl}/v/${reqItem.token}`;
  const audit = db.audit.filter(a => a.requestId === reqItem.id && a.tenantId === req.tenant.id)
    .sort((a,b) => (b.at||'').localeCompare(a.at||''))
    .map(a => ({ ...a, detailText: formatAuditDetail(a) }));

  res.render('layout', {
    title: 'Talep',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('app_request_detail', {
      csrfToken: res.locals.csrfToken,
      reqItem,
      vendorLink,
      participants: participantsWithLinks,
      progress,
      health,
      docsWithState: (reqItem.docs || []).map(d => ({ ...d, _state: getDocState(reqItem, d) })),
      statuses: STATUS,
      statusLabel,
      audit,
      emailEnabled: !!getMailer(),
    }),
  });
});

// E-posta şablonları lib/emailTemplates.js'e taşındı.

// Vendor email actions
app.post('/app/requests/:id/email/invite', requireAuth, verifyCsrf, async (req, res) => {
  const db = readDB();
  const r = db.requests.find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
  if (!r) return res.status(404).send('not_found');

  const plan = getPlanForTenant(db, req.tenant.id);
  if (plan.code === 'free') {
    flash(req, 'err', 'Bu özellik ücretli planlarda aktif (Başlangıç ve üzeri).');
    return res.redirect('/app/billing');
  }

  const mailer = getMailer();
  if (!mailer) {
    flash(req, 'err', 'SMTP ayarlı değil. E-posta özellikleri kapalı.');
    return res.redirect(`/app/requests/${r.id}`);
  }
  const to = (r.vendor?.email || '').trim();
  if (!to) {
    flash(req, 'err', 'Tedarikçi e-postası boş.');
    return res.redirect(`/app/requests/${r.id}`);
  }

  const baseUrl = getBaseUrl(req);
  const vendorLink = `${baseUrl}/v/${r.token}`;
  const tenant = db.tenants.find(t => t.id === req.tenant.id) || req.tenant;

  try {
    const tpl = emailTemplates.vendorInvite({ tenantName: tenant.name, reqItem: r, vendorLink });
    await mailer.sendMail({
      from: process.env.SMTP_FROM || `${APP_NAME} <noreply@example.com>`,
      to,
      subject: tpl.subject,
      text: tpl.text,
    });

    withDB(db2 => {
      const rr = db2.requests.find(x => x.id === r.id && x.tenantId === req.tenant.id);
      if (rr) {
        rr.emailInviteSentAt = nowISO();
        rr.updatedAt = nowISO();
      }
      db2.audit.push({
        id: safeId('aud'),
        tenantId: req.tenant.id,
        requestId: r.id,
        actor: req.user.email,
        action: 'email_invite_sent',
        detail: { to },
        at: nowISO(),
      });
    });

    flash(req, 'ok', 'Davet e-postası gönderildi.');
    return res.redirect(`/app/requests/${r.id}`);
  } catch (e) {
    console.warn('invite email failed', e.message);
    flash(req, 'err', 'E-posta gönderilemedi. SMTP ayarlarını kontrol edin.');
    return res.redirect(`/app/requests/${r.id}`);
  }
});

app.post('/app/requests/:id/email/remind', requireAuth, verifyCsrf, async (req, res) => {
  const db = readDB();
  const r = db.requests.find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
  if (!r) return res.status(404).send('not_found');

  const plan = getPlanForTenant(db, req.tenant.id);
  if (plan.code === 'free') {
    flash(req, 'err', 'Bu özellik ücretli planlarda aktif (Başlangıç ve üzeri).');
    return res.redirect('/app/billing');
  }

  const mailer = getMailer();
  if (!mailer) {
    flash(req, 'err', 'SMTP ayarlı değil. E-posta özellikleri kapalı.');
    return res.redirect(`/app/requests/${r.id}`);
  }
  const to = (r.vendor?.email || '').trim();
  if (!to) {
    flash(req, 'err', 'Tedarikçi e-postası boş.');
    return res.redirect(`/app/requests/${r.id}`);
  }

  const baseUrl = getBaseUrl(req);
  const vendorLink = `${baseUrl}/v/${r.token}`;
  const tenant = db.tenants.find(t => t.id === req.tenant.id) || req.tenant;

  try {
    const tplR = emailTemplates.vendorReminder({ tenantName: tenant.name, reqItem: r, vendorLink });
    await mailer.sendMail({
      from: process.env.SMTP_FROM || `${APP_NAME} <noreply@example.com>`,
      to,
      subject: tplR.subject,
      text: tplR.text,
    });

    withDB(db2 => {
      const rr = db2.requests.find(x => x.id === r.id && x.tenantId === req.tenant.id);
      if (rr) {
        rr.emailReminderSentAt = nowISO();
        rr.updatedAt = nowISO();
        rr.remindersSent = rr.remindersSent || [];
        rr.remindersSent.push({ days: null, at: nowISO(), manual: true });
      }
      db2.audit.push({
        id: safeId('aud'),
        tenantId: req.tenant.id,
        requestId: r.id,
        actor: req.user.email,
        action: 'email_reminder_sent',
        detail: { to },
        at: nowISO(),
      });
    });

    flash(req, 'ok', 'Hatırlatma gönderildi.');
    return res.redirect(`/app/requests/${r.id}`);
  } catch (e) {
    console.warn('reminder email failed', e.message);
    flash(req, 'err', 'E-posta gönderilemedi. SMTP ayarlarını kontrol edin.');
    return res.redirect(`/app/requests/${r.id}`);
  }
});


// Vendor participants (çoklu kişi)
app.post('/app/requests/:id/participants', requireAuth, verifyCsrf, async (req, res) => {
  const roleRaw = (req.body.role || '').trim();
  const role = ['mali_musavir', 'yetkili', 'diger'].includes(roleRaw) ? roleRaw : 'diger';
  const name = (req.body.name || '').trim();
  const email = (req.body.email || '').trim();

  const db = readDB();
  const r = (db.requests || []).find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
  if (!r) return res.status(404).send('not_found');

  const token = randomToken(24);
  const pid = safeId('vp');
  const canSubmit = role === 'yetkili';

  withDB(db2 => {
    const rr = (db2.requests || []).find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
    if (!rr) return;

    if (!rr.participants) {
      rr.participants = [{
        id: safeId('vp'),
        token: rr.token,
        role: 'yetkili',
        name: rr.vendor?.name || '',
        email: rr.vendor?.email || '',
        canSubmit: true,
        createdAt: nowISO(),
        lastSeenAt: null,
      }];
    }

    rr.participants.push({
      id: pid,
      token,
      role,
      name,
      email,
      canSubmit,
      createdAt: nowISO(),
      lastSeenAt: null,
    });
    rr.updatedAt = nowISO();

    db2.audit.push({
      id: safeId('aud'),
      tenantId: rr.tenantId,
      requestId: rr.id,
      actor: req.user.email,
      action: 'participant_added',
      detail: { pid, role, email: email || null },
      at: nowISO(),
    });
  });

  const link = `${getBaseUrl(req)}/v/${token}`;
  const mailer = getMailer();
  if (mailer && email) {
    try {
      const tplP = emailTemplates.participantLink({ name, role, vendorName: r.vendor.name, link, canSubmit });
      await mailer.sendMail({
        from: process.env.SMTP_FROM || `${APP_NAME} <noreply@example.com>`,
        to: email,
        subject: tplP.subject,
        text: tplP.text,
      });
    } catch (e) {
      console.warn('participant add email failed', e.message);
    }
  }

  flash(req, 'ok', `Kişi eklendi. Link: ${link}`);
  res.redirect(`/app/requests/${req.params.id}`);
});

app.post('/app/requests/:id/participants/:pid/email', requireAuth, verifyCsrf, async (req, res) => {
  const db = readDB();
  const r = (db.requests || []).find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
  if (!r) return res.status(404).send('not_found');

  const p = (r.participants || []).find(x => x.id === req.params.pid);
  if (!p || !p.email) {
    flash(req, 'err', 'E-posta bulunamadı.');
    return res.redirect(`/app/requests/${r.id}`);
  }

  const mailer = getMailer();
  if (!mailer) {
    flash(req, 'err', 'SMTP ayarlı değil.');
    return res.redirect(`/app/requests/${r.id}`);
  }

  const link = `${getBaseUrl(req)}/v/${p.token}`;

  try {
    const tplPR = emailTemplates.participantLink({ name: p.name, role: p.role, vendorName: r.vendor.name, link, canSubmit: p.canSubmit });
    await mailer.sendMail({
      from: process.env.SMTP_FROM || `${APP_NAME} <noreply@example.com>`,
      to: p.email,
      subject: tplPR.subject,
      text: tplPR.text,
    });

    withDB(db2 => {
      const rr = (db2.requests || []).find(x => x.id === r.id);
      const pp = (rr?.participants || []).find(x => x.id === p.id);
      if (pp) pp.emailSentAt = nowISO();
      db2.audit.push({
        id: safeId('aud'),
        tenantId: r.tenantId,
        requestId: r.id,
        actor: req.user.email,
        action: 'participant_email_sent',
        detail: { pid: p.id, to: p.email },
        at: nowISO(),
      });
    });

    flash(req, 'ok', 'E-posta gönderildi.');
    return res.redirect(`/app/requests/${r.id}`);
  } catch (e) {
    console.warn('participant email failed', e.message);
    flash(req, 'err', 'E-posta gönderilemedi.');
    return res.redirect(`/app/requests/${r.id}`);
  }
});

app.post('/app/requests/:id/participants/:pid/delete', requireAuth, verifyCsrf, (req, res) => {
  withDB(db2 => {
    const r = (db2.requests || []).find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
    if (!r || !r.participants) return;

    const p = r.participants.find(x => x.id === req.params.pid);
    if (!p) return;

    // Do not delete primary token
    if (p.token === r.token) return;

    r.participants = r.participants.filter(x => x.id !== req.params.pid);
    r.updatedAt = nowISO();

    db2.audit.push({
      id: safeId('aud'),
      tenantId: r.tenantId,
      requestId: r.id,
      actor: req.user.email,
      action: 'participant_deleted',
      detail: { pid: req.params.pid },
      at: nowISO(),
    });
  });

  flash(req, 'ok', 'Kişi kaldırıldı.');
  res.redirect(`/app/requests/${req.params.id}`);
});

app.post('/app/requests/:id/status', requireAuth, verifyCsrf, (req, res) => {
  const status = (req.body.status || '').trim();
  if (!STATUS.includes(status)) {
    flash(req, 'err', 'Durum geçersiz.');
    return res.redirect(`/app/requests/${req.params.id}`);
  }

  const result = withDB(db => {
    const r = db.requests.find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
    if (!r) return null;
    const from = r.status;
    r.status = status;
    r.updatedAt = nowISO();
    db.audit.push({
      id: safeId('aud'),
      tenantId: r.tenantId,
      requestId: r.id,
      actor: req.user.email,
      action: 'status_changed',
      detail: { from, to: status },
      at: nowISO(),
    });
    return { r: { ...r }, from, to: status };
  });

  // Notifications
  if (result) {
    try {
      const dbNow = readDB();
      const tenantNow = (dbNow.tenants || []).find(t => t.id === req.tenant.id);
      const baseUrl = getBaseUrl(req);
      sendTenantNotifications({
        tenant: tenantNow,
        event: 'request.status_changed',
        baseUrl,
        payload: {
          tenant: { id: tenantNow?.id, name: tenantNow?.name },
          request: { id: result.r.id, status: result.r.status, vendor: result.r.vendor, dueDate: result.r.dueDate || null },
          statusChange: { from: result.from, to: result.to },
          actor: { email: req.user.email, role: req.user.role },
          links: { request: `${baseUrl}/app/requests/${result.r.id}` },
        },
      }).catch(e => console.warn('notify request.status_changed failed', e.message));

      // In-app notification
      addNotification({
        tenantId: req.tenant.id,
        userId: null,
        type: result.to === 'approved' ? 'request_approved' : result.to === 'rejected' ? 'request_rejected' : 'status_changed',
        title: 'Talep durumu değişti',
        message: (result.r.vendor?.name || '') + ': ' + statusLabel(result.from) + ' → ' + statusLabel(result.to),
        link: '/app/requests/' + encodeURIComponent(result.r.publicId || result.r.id),
      });
    } catch (e) {}
  }

  flash(req, 'ok', 'Kaydedildi.');
  res.redirect(`/app/requests/${req.params.id}`);
});

app.post('/app/requests/:id/note', requireAuth, verifyCsrf, (req, res) => {
  const note = (req.body.note || '').toString().slice(0, 5000);
  withDB(db => {
    const r = db.requests.find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
    if (!r) return;
    r.note = note;
    r.updatedAt = nowISO();
    db.audit.push({
      id: safeId('aud'),
      tenantId: r.tenantId,
      requestId: r.id,
      actor: req.user.email,
      action: 'note_updated',
      detail: {},
      at: nowISO(),
    });
  });
  flash(req, 'ok', 'Kaydedildi.');
  res.redirect(`/app/requests/${req.params.id}`);
});

app.post('/app/requests/:id/docs/:docId/signature', requireAuth, verifyCsrf, (req, res) => {
  const docId = (req.params.docId || '').trim();

  const result = withDB(db => {
    const r = (db.requests || []).find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
    if (!r || !r.uploads || !r.uploads[docId]) return null;

    const u = r.uploads[docId];
    u.signatureVerified = !u.signatureVerified;
    u.signatureVerifiedAt = nowISO();
    u.signatureVerifiedBy = req.user.email;
    r.updatedAt = nowISO();

    db.audit.push({
      id: safeId('aud'),
      tenantId: r.tenantId,
      requestId: r.id,
      actor: req.user.email,
      action: 'signature_verified_toggled',
      detail: { docId, signatureVerified: !!u.signatureVerified },
      at: nowISO(),
    });

    return { r: { ...r }, u: { ...u } };
  });

  if (!result) {
    flash(req, 'err', 'Belge bulunamadı.');
    return res.redirect(`/app/requests/${req.params.id}`);
  }

  flash(req, 'ok', 'İmza doğrulama güncellendi.');
  res.redirect(`/app/requests/${req.params.id}`);
});

app.post('/app/requests/:id/docs/:docId/dates', requireAuth, verifyCsrf, (req, res) => {
  const docId = (req.params.docId || '').trim();

  const result = withDB(db => {
    const r = (db.requests || []).find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
    if (!r || !r.uploads || !r.uploads[docId]) return null;

    const u = r.uploads[docId];
    u.datesVerified = !u.datesVerified;
    u.datesVerifiedAt = nowISO();
    u.datesVerifiedBy = req.user.email;
    r.updatedAt = nowISO();

    db.audit.push({
      id: safeId('aud'),
      tenantId: r.tenantId,
      requestId: r.id,
      actor: req.user.email,
      action: 'dates_verified_toggled',
      detail: { docId, datesVerified: !!u.datesVerified },
      at: nowISO(),
    });

    return { r: { ...r }, u: { ...u } };
  });

  if (!result) {
    flash(req, 'err', 'Belge bulunamadı.');
    return res.redirect(`/app/requests/${req.params.id}`);
  }

  flash(req, 'ok', 'Tarih doğrulama güncellendi.');
  res.redirect(`/app/requests/${req.params.id}`);
});

app.get('/app/requests/:id/download/:docId', requireAuth, async (req, res) => {
  const db = readDB();
  const r = db.requests.find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
  if (!r) return res.status(404).send('not_found');
  const u = (r.uploads || {})[req.params.docId];
  if (!u) return res.status(404).send('file_not_found');

  // S3/R2
  if (u.storage && u.storage.provider === 's3') {
    try {
      const stream = await fileStorage.getStream(u.storage);
      res.setHeader('Content-Type', u.mime || 'application/octet-stream');
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(u.originalName || 'document')}"`);
      stream.on('error', () => res.status(500).end('stream_error'));
      return stream.pipe(res);
    } catch (e) {
      console.error('s3 download failed', e.message);
      return res.status(404).send('file_missing');
    }
  }

  // Local (path traversal safe)
  const baseDir = path.join(__dirname, 'uploads', r.tenantId, r.id);
  let filePath;
  try {
    filePath = safeJoin(baseDir, u.storedName);
  } catch {
    return res.status(400).send('bad_path');
  }
  if (!fs.existsSync(filePath)) return res.status(404).send('file_missing');
  res.download(filePath, u.originalName || u.storedName);
});


app.get('/app/requests/:id/download-all.zip', requireAuth, async (req, res) => {
  const db = readDB();
  const r = db.requests.find(x => x.id === req.params.id && x.tenantId === req.tenant.id);
  if (!r) return res.status(404).send('not_found');

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="${r.id}.zip"`);

  const zipfile = new yazl.ZipFile();

  // Client abort / connection close
  let ended = false;
  const safeEnd = () => {
    if (ended) return;
    ended = true;
    try { zipfile.end(); } catch {}
  };


  res.on('close', () => {
    // In case the client aborts, stop producing output.
    try { safeEnd(); } catch {}
  });

  zipfile.outputStream.on('error', (err) => {
    console.error('zip error', err && err.message ? err.message : err);
    try { res.status(500).end('zip_error'); } catch {}
    try { safeEnd(); } catch {}
  });

  zipfile.outputStream.pipe(res);

  const uploads = r.uploads || {};
  for (const d of r.docs) {
    const u = uploads[d.id];
    if (!u) continue;

    const ext = mime.extension(u.mime || '') ? ('.' + mime.extension(u.mime || '')) : '';
    const safeName = sanitizeFilename(d.label || d.id) + ext;

    if (u.storage && u.storage.provider === 's3') {
      try {
        const stream = await fileStorage.getStream(u.storage);
        stream.on('error', (e) => {
          console.warn('zip skip (s3 stream error)', e && e.message ? e.message : e);
        });
        zipfile.addReadStream(stream, safeName);
      } catch (e) {
        console.warn('zip skip (s3 missing)', e && e.message ? e.message : e);
      }
    } else {
      const baseDir = path.join(__dirname, 'uploads', r.tenantId, r.id);
      try {
        const filePath = safeJoin(baseDir, u.storedName);
        if (fs.existsSync(filePath)) {
          zipfile.addFile(filePath, safeName);
        }
      } catch {
        // Skip invalid paths (defensive)
      }
    }
  }

  safeEnd();
});

app.post('/app/requests/:id/delete', requireAuth, verifyCsrf, async (req, res) => {
  const id = req.params.id;
  const db = readDB();
  const r = db.requests.find(x => x.id === id && x.tenantId === req.tenant.id);
  if (!r) return res.status(404).send('not_found');

  // Remove files (local + S3)
  const uploads = r.uploads || {};
  for (const docId of Object.keys(uploads)) {
    const u = uploads[docId];
    if (u && u.storage && u.storage.provider === 's3') {
      try { await fileStorage.delete(u.storage); } catch {}
    }
  }
  const dir = path.join(__dirname, 'uploads', r.tenantId, r.id);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}

  withDB(db2 => {
    db2.requests = (db2.requests || []).filter(x => !(x.id === id && x.tenantId === req.tenant.id));
    db2.audit.push({
      id: safeId('aud'),
      tenantId: req.tenant.id,
      requestId: id,
      actor: req.user.email,
      action: 'deleted',
      detail: {},
      at: nowISO(),
    });
  });

  flash(req, 'ok', 'Silindi.');
  res.redirect('/app/requests');
});


// CSV export for a single request
app.get('/app/requests/:id/export.csv', requireAuth, (req, res) => {
  flash(req, 'err', 'CSV dışa aktarma kaldırıldı.');
  return res.redirect(`/app/requests/${req.params.id}`);
});

function csv(s) {
  const x = String(s ?? '');
  if (x.includes(',') || x.includes('"') || x.includes('\n')) {
    return '"' + x.replaceAll('"', '""') + '"';
  }
  return x;
}

// Billing
app.get('/app/billing', requireAuth, requireOwner, noStore, (req, res) => {
  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);
  const usage = {
    usersCount: (db.users || []).filter(u => u.tenantId === req.tenant.id).length,
    activeRequests: (db.requests || []).filter(r => r.tenantId === req.tenant.id && r.status !== 'archived').length,
  };
  const bills = db.billing.filter(b => b.tenantId === req.tenant.id)
    .sort((a,b) => (b.updatedAt||'').localeCompare(a.updatedAt||''));

  res.render('layout', {
    title: 'Plan/Ödeme',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('app_billing', {
      csrfToken: res.locals.csrfToken,
      plan,
      bills,
      usage,
      storageProvider: STORAGE_PROVIDER,
      billingEnabled: iyzicoEnabled(),
      manualSecret: (process.env.BILLING_ADMIN_SECRET || '').trim(),
      user: req.user,
    }),
  });
});

app.post('/app/billing/manual', requireAuth, requireOwner, verifyCsrf, (req, res) => {
  const secret = (req.body.secret || '').trim();
  const plan = (req.body.plan || '').trim();
  const expected = (process.env.BILLING_ADMIN_SECRET || '').trim();
  if (!expected || secret !== expected) {
    flash(req, 'err', 'Secret hatalı.');
    return res.redirect('/app/billing');
  }
  if (!PLANS[plan]) {
    flash(req, 'err', 'Plan geçersiz.');
    return res.redirect('/app/billing');
  }
  withDB(db => {
    db.billing.push({
      id: safeId('bill'),
      tenantId: req.tenant.id,
      provider: 'manual',
      plan,
      status: 'active',
      updatedAt: nowISO(),
    });
  });
  flash(req, 'ok', 'Plan güncellendi.');
  res.redirect('/app/billing');
});

app.post('/app/billing/start', requireAuth, requireOwner, verifyCsrf, async (req, res) => {
  if (!iyzicoEnabled()) {
    flash(req, 'err', 'Ödeme kapalı veya iyzico ayarları eksik.');
    return res.redirect('/app/billing');
  }

  // Idempotency: prevent duplicate pending checkouts (max 1 pending per tenant within 5 min)
  const db0 = readDB();
  const recentPending = (db0.billing || []).find(b =>
    b.tenantId === req.tenant.id && b.status === 'pending' &&
    (Date.now() - new Date(b.updatedAt || 0).getTime()) < 5 * 60 * 1000
  );
  if (recentPending) {
    flash(req, 'err', 'Zaten devam eden bir ödeme işlemi var. Lütfen birkaç dakika bekleyin.');
    return res.redirect('/app/billing');
  }

  const planCode = (req.body.plan || '').trim();
  if (!['starter','team','pro'].includes(planCode)) {
    flash(req, 'err', 'Plan seçimi geçersiz.');
    return res.redirect('/app/billing');
  }
  const planRef = {
    starter: (process.env.IYZICO_PLAN_STARTER_REF || '').trim(),
    team: (process.env.IYZICO_PLAN_TEAM_REF || '').trim(),
    pro: (process.env.IYZICO_PLAN_PRO_REF || '').trim(),
  }[planCode];
  if (!planRef) {
    flash(req, 'err', 'iyzico plan referansı eksik (.env).');
    return res.redirect('/app/billing');
  }

  const firstName = (req.body.firstName || '').trim();
  const lastName = (req.body.lastName || '').trim();
  const email = (req.body.email || '').trim();
  const gsmNumber = (req.body.gsmNumber || '').trim();
  const address = (req.body.address || '').trim();

  const baseUrl = getBaseUrl(req);
  // Sign the tenant ID so the callback can't be tampered with
  const callbackState = signCallbackState(req.tenant.id);
  const callbackUrl = `${baseUrl}/billing/iyzico/callback?state=${encodeURIComponent(callbackState)}`;

  const payload = {
    locale: 'tr',
    conversationId: safeId('conv'),
    pricingPlanReferenceCode: planRef,
    subscriptionInitialStatus: 'ACTIVE',
    callbackUrl,
    customer: {
      name: firstName,
      surname: lastName,
      email,
      gsmNumber: gsmNumber || undefined,
      billingAddress: address ? {
        contactName: `${firstName} ${lastName}`.trim(),
        city: '—',
        country: 'Türkiye',
        address,
        zipCode: '00000',
      } : undefined,
    },
  };

  try {
    const init = await initializeSubscriptionCheckout(payload);
    const token = init.token || init.checkoutFormToken || null;
    const html = init.checkoutFormContent || init.htmlContent || init.raw || null;

    if (!token || !html) {
      console.warn('iyzico init response', init);
      flash(req, 'err', 'iyzico yanıtı beklenenden farklı. Loglara bakın.');
      return res.redirect('/app/billing');
    }

    // record pending
    withDB(db => {
      db.billing.push({
        id: safeId('bill'),
        tenantId: req.tenant.id,
        provider: 'iyzico',
        plan: planCode,
        status: 'pending',
        checkoutToken: token,
        updatedAt: nowISO(),
      });
    });

    res.render('layout', {
      title: 'Ödeme',
      appName: APP_NAME,
      supportEmail: SUPPORT_EMAIL,
      user: req.user,
      tenant: req.tenant,
      plan: PLANS[planCode],
      csrfToken: res.locals.csrfToken,
      flash: consumeFlash(req),
      noindex: true,
      body: render('app_checkout', { csrfToken: res.locals.csrfToken, checkoutHtml: html }),
    });
  } catch (e) {
    console.error('iyzico init error', e.status, e.payload || e.message);
    flash(req, 'err', 'iyzico başlatılamadı. Anahtar/plan/callback ayarlarını kontrol edin.');
    return res.redirect('/app/billing');
  }
});

const billingCallbackLimiter = rateLimit({ windowMs: 10 * 60 * 1000, max: 20, standardHeaders: true, legacyHeaders: false });

app.get('/billing/iyzico/callback', billingCallbackLimiter, noStore, async (req, res) => {
  // Verify signed state (tamper-proof tenant ID)
  const state = (req.query.state || '').trim();
  const tenantId = verifyCallbackState(state);

  // Fallback: accept legacy ?tenant= param but only if it matches an existing pending bill
  const legacyTenantId = !tenantId ? (req.query.tenant || '').trim() : null;

  const effectiveTenantId = tenantId || legacyTenantId;
  const token = (req.query.token || req.query.checkoutFormToken || req.query.checkoutToken || '').toString().trim();
  if (!effectiveTenantId || !token) return res.status(400).send('bad_request');

  if (!iyzicoEnabled()) return res.status(500).send('billing_disabled');

  // Extra validation: token must exist as a pending billing record for this tenant
  const db0 = readDB();
  const pendingBill = (db0.billing || []).find(b => b.tenantId === effectiveTenantId && b.checkoutToken === token && b.status === 'pending');
  if (!pendingBill) {
    logSecurityEvent('billing.callback_invalid', { tenantId: effectiveTenantId, token: token.slice(0, 8) + '...', ip: req.ip });
    return res.status(400).send('invalid_callback');
  }

  try {
    // Server-side verify payment with iyzico API (don't trust client-side callback alone)
    const data = await verifyAndRetrieveCheckout(token);
    const status = (data.paymentStatus || data.status || '').toString().toLowerCase();
    const success = status === 'success' || status === 'active' || status === 'paid';

    withDB(db => {
      // mark previous pending with same token as completed/failed
      db.billing = db.billing.map(b => {
        if (b.tenantId === effectiveTenantId && b.checkoutToken === token && b.status === 'pending') {
          return {
            ...b,
            status: success ? 'active' : 'failed',
            subscriptionRef: data.subscriptionReferenceCode || data.referenceCode || null,
            updatedAt: nowISO(),
            raw: { status: data.status, paymentStatus: data.paymentStatus },
          };
        }
        return b;
      });
    });

    // Redirect user to login -> app
    // (We cannot guarantee user session here; they might have it. So just show a page.)
    return res.send(`
      <html><head><meta charset="utf-8"><meta http-equiv="refresh" content="2;url=/app/billing"/></head>
      <body style="font-family:system-ui;padding:24px">
        <h2>${success ? 'Ödeme başarılı' : 'Ödeme tamamlanamadı'}</h2>
        <p>2 saniye içinde portala yönlendirileceksiniz.</p>
        <p><a href="/app/billing">Devam</a></p>
      </body></html>
    `);
  } catch (e) {
    console.error('iyzico retrieve error', e.status, e.payload || e.message);
    return res.status(500).send('retrieve_failed');
  }
});

// Settings
app.get('/app/settings', requireAuth, noStore, (req, res) => {
  const db = readDB();
  const plan = getPlanForTenant(db, req.tenant.id);
  res.render('layout', {
    title: 'Ayarlar',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    plan,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('app_settings', {
      csrfToken: res.locals.csrfToken,
      user: req.user,
      tenant: req.tenant,
      emailEnabled: !!getMailer(),
    }),
  });
});

// Security center
app.get('/app/security', requireAuth, noStore, (req, res) => {
  const db = readDB();
  const tenant = db.tenants.find(t => t.id === req.user.tenantId) || req.tenant;
  const user = db.users.find(u => u.id === req.user.id) || req.user;
  res.render('layout', {
    title: 'Güvenlik',
    appName: APP_NAME,
    supportEmail: SUPPORT_EMAIL,
    user: req.user,
    tenant: req.tenant,
    csrfToken: res.locals.csrfToken,
    flash: consumeFlash(req),
    noindex: true,
    body: render('app_security', {
      csrfToken: res.locals.csrfToken,
      user,
      tenant,
    }),
  });
});


// --- Launch Center (removed) ---
// Eski launch center kaldırıldı. Bookmark'lar için yönlendirme korunuyor.
app.get('/app/launch', requireAuth, requireOwner, noStore, (req, res) => {
  return res.redirect('/app/settings');
});
app.get('/app/launch/report.json', requireAuth, requireOwner, noStore, (req, res) => {
  return res.status(404).json({ ok: false, error: 'Not Found' });
});
app.post('/app/security/mfa/start', requireAuth, verifyCsrf, (req, res) => {
  // Start MFA setup while logged in
  req.session.mfaPendingUserId = req.user.id;
  req.session.mfaSetupRequired = true;
  req.session.mfaReturnTo = '/app/security';
  return res.redirect('/mfa/setup');
});

app.post('/app/security/mfa/backup-regenerate', requireAuth, verifyCsrf, (req, res) => {
  const db = readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user || !user.mfaEnabled) {
    flash(req, 'err', 'Önce MFA etkin olmalı.');
    return res.redirect('/app/security');
  }
  const codes = generateBackupCodes(10);
  const hashes = codes.map(c => hashBackupCode(c, user.id));
  withDB(db2 => {
    const u = db2.users.find(x => x.id === user.id);
    if (!u) return;
    u.mfaBackup = hashes;
    u.mfaBackupGeneratedAt = nowISO();
    db2.audit.push({
      id: safeId('aud'),
      tenantId: u.tenantId,
      requestId: null,
      actor: u.email,
      action: 'mfa_backup_regenerated',
      detail: {},
      at: nowISO(),
    });
  });
  req.session.mfaNewBackupCodes = codes;
  req.session.mfaNewBackupCodesForUser = user.id;
  req.session.mfaReturnTo = '/app/security';
  flash(req, 'ok', 'Yeni yedek kodlar oluşturuldu.');
  return res.redirect('/mfa/done');
});

app.post('/app/security/mfa/disable', requireAuth, verifyCsrf, async (req, res) => {
  const password = String(req.body.password || '');
  const code = String(req.body.code || '');
  const db = readDB();
  const user = db.users.find(u => u.id === req.user.id);
  if (!user || !user.mfaEnabled) {
    flash(req, 'err', 'MFA zaten kapalı.');
    return res.redirect('/app/security');
  }
  const passOk = await verifyPassword(password, user.passHash);
  if (!passOk) {
    flash(req, 'err', 'Şifre hatalı.');
    return res.redirect('/app/security');
  }
  const codeNorm = code.replace(/\s+/g, '').replace(/-/g, '');
  const okTotp = totpVerify(user.mfaSecret, codeNorm, { window: 1 });
  let okBackup = false;
  const hash = hashBackupCode(codeNorm, String(user.id));
  if (Array.isArray(user.mfaBackup) && user.mfaBackup.length) {
    const idx = user.mfaBackup.findIndex(h => timingSafeEqualStr(h, hash));
    if (idx >= 0) okBackup = true;
  }
  if (!okTotp && !okBackup) {
    flash(req, 'err', 'Doğrulama kodu hatalı.');
    return res.redirect('/app/security');
  }

  withDB(db2 => {
    const u = db2.users.find(x => x.id === user.id);
    if (!u) return;
    u.mfaEnabled = false;
    u.mfaSecret = '';
    u.mfaBackup = [];
    u.mfaBackupGeneratedAt = null;
    db2.audit.push({
      id: safeId('aud'),
      tenantId: u.tenantId,
      requestId: null,
      actor: u.email,
      action: 'mfa_disabled',
      detail: {},
      at: nowISO(),
    });
  });

  logSecurityEvent('mfa.disabled', {
    userId: user.id,
    tenantId: user.tenantId,
    email: user.email,
    ip: req.ip,
    requestId: req.requestId,
  });

  flash(req, 'ok', 'MFA kapatıldı.');
  return res.redirect('/app/security');
});

app.post('/app/security/tenant', requireAuth, requireOwner, verifyCsrf, (req, res) => {
  const requireMfa = req.body.requireMfa === 'on';
  withDB(db => {
    const t = db.tenants.find(x => x.id === req.tenant.id);
    if (!t) return;
    t.security = t.security || {};
    t.security.requireMfa = requireMfa;
    db.audit.push({
      id: safeId('aud'),
      tenantId: t.id,
      requestId: null,
      actor: req.user.email,
      action: 'tenant_security_updated',
      detail: { requireMfa },
      at: nowISO(),
    });
  });
  flash(req, 'ok', 'Güvenlik ayarları güncellendi.');
  return res.redirect('/app/security');
});

app.post('/app/settings/tenant', requireAuth, requireOwner, verifyCsrf, (req, res) => {
  const tenantName = (req.body.tenantName || '').trim().slice(0, 120);
  const notifyEmail = (req.body.notifyEmail || '').trim().toLowerCase().slice(0, 200);
  const remindersEnabled = req.body.remindersEnabled === 'on';
  const reminderDays = (req.body.reminderDays || '').trim().slice(0, 50);

  const webhookUrl = (req.body.webhookUrl || '').trim().slice(0, 500);
  const webhookSecret = (req.body.webhookSecret || '').trim().slice(0, 200);
  const slackWebhookUrl = (req.body.slackWebhookUrl || '').trim().slice(0, 500);
  const teamsWebhookUrl = (req.body.teamsWebhookUrl || '').trim().slice(0, 500);

  const notifyOnVendorSubmitted = req.body.notifyOnVendorSubmitted === 'on';
  const notifyOnVendorUpload = req.body.notifyOnVendorUpload === 'on';
  const notifyOnStatusChange = req.body.notifyOnStatusChange === 'on';
  const notifyOnRequestCreated = req.body.notifyOnRequestCreated === 'on';

  if (!tenantName) {
    flash(req, 'err', 'Şirket adı boş olamaz.');
    return res.redirect('/app/settings');
  }

  withDB(db => {
    const t = (db.tenants || []).find(x => x.id === req.tenant.id);
    if (!t) return;

    t.name = tenantName;
    t.notifyEmail = notifyEmail;
    t.remindersEnabled = remindersEnabled;
    t.reminderDays = reminderDays || (process.env.REMINDER_DEFAULT_DAYS || '3,1').trim();

    t.webhookUrl = webhookUrl;
    t.webhookSecret = webhookSecret;
    t.slackWebhookUrl = slackWebhookUrl;
    t.teamsWebhookUrl = teamsWebhookUrl;

    if (!t.notify) t.notify = {};
    t.notify.onVendorSubmitted = notifyOnVendorSubmitted;
    t.notify.onVendorUpload = notifyOnVendorUpload;
    t.notify.onStatusChange = notifyOnStatusChange;
    t.notify.onRequestCreated = notifyOnRequestCreated;

    db.audit.push({
      id: safeId('aud'),
      tenantId: t.id,
      requestId: null,
      actor: req.user.email,
      action: 'tenant_settings_updated',
      detail: { webhook: !!webhookUrl, slack: !!slackWebhookUrl, teams: !!teamsWebhookUrl },
      at: nowISO(),
    });
  });

  flash(req, 'ok', 'Şirket ayarları güncellendi.');
  res.redirect('/app/settings');
});


app.post('/app/settings/test-notifications', requireAuth, requireOwner, verifyCsrf, async (req, res) => {
  const db = readDB();
  const tenantNow = (db.tenants || []).find(t => t.id === req.tenant.id);
  const baseUrl = getBaseUrl(req);

  try {
    const r = await sendTenantNotifications({
      tenant: tenantNow,
      event: 'test',
      baseUrl,
      payload: {
        tenant: { id: tenantNow?.id, name: tenantNow?.name },
        actor: { email: req.user.email, role: req.user.role },
        message: 'Test bildirimi',
        links: { dashboard: `${baseUrl}/app/requests` },
      },
    });

    if (!r.sent) {
      flash(req, 'err', 'Test bildirimi gönderilemedi (URL tanımlı değil ya da hata oldu).');
    } else {
      flash(req, 'ok', `Test bildirimi gönderildi. (başarılı: ${r.sent})`);
    }
  } catch (e) {
    flash(req, 'err', 'Test bildirimi hata verdi.');
  }

  res.redirect('/app/settings');
});

app.post('/app/settings/password', requireAuth, verifyCsrf, async (req, res) => {
  const currentPassword = String(req.body.currentPassword || '');
  const newPassword = String(req.body.newPassword || '');
  if (!isPasswordStrong(newPassword)) {
    flash(req, 'err', PASSWORD_POLICY_MSG);
    return res.redirect('/app/settings');
  }
  const db = readDB();
  const u = db.users.find(x => x.id === req.user.id);
  if (!u) {
    req.session = null;
    return res.redirect('/login');
  }
  const ok = await verifyPassword(currentPassword, u.passHash);
  if (!ok) {
    flash(req, 'err', 'Mevcut şifre hatalı.');
    return res.redirect('/app/settings');
  }
  const passHash = await hashPassword(newPassword);
  withDB(db2 => {
    const uu = db2.users.find(x => x.id === req.user.id);
    if (uu) uu.passHash = passHash;
  });
  flash(req, 'ok', 'Şifre güncellendi.');
  res.redirect('/app/settings');
});

// --- Render helper for partial templates ---
function render(view, locals) {
  const ejs = require('ejs');
  const file = path.join(__dirname, 'views', view + '.ejs');
  const tpl = fs.readFileSync(file, 'utf-8');
  return ejs.render(tpl, {
    // Make sure common view locals exist for partials.
    // If a route forgets to pass one, the page should still render instead of 500'ing.
    cspNonce: '',
    uploadAccept: UPLOAD_ACCEPT_ATTR,
    uploadAllowedExtCsv: UPLOAD_ALLOWED_EXT.join(','),
    ...locals,
    statusLabel,
    formatBytes,
    maskUrl,
    t,
    getLocale,
    LANGUAGES,
  });
}

// --- Background jobs (cron) ---
let reminderRunning = false;
async function runReminderJob() {
  if (reminderRunning) return;
  reminderRunning = true;
  try {
    const mailer = getMailer();
    if (!mailer) return;

    const db = readDB();
    const baseUrl = (process.env.BASE_URL || '').trim();
    if (!baseUrl) {
      // Email içindeki linkin çalışması için BASE_URL şart.
      return;
    }

    const updates = [];
    for (const tenant of (db.tenants || [])) {
      const plan = getPlanForTenant(db, tenant.id);
      if (plan.code === 'free') continue;
      if (!tenant.remindersEnabled) continue;
      const daysList = parseDaysList(tenant.reminderDays || process.env.REMINDER_DEFAULT_DAYS || '3,1');
      if (!daysList.length) continue;

      const reqs = (db.requests || []).filter(r => r.tenantId === tenant.id && r.status === 'open' && r.dueDate && (r.vendor?.email || '').trim());
      for (const r of reqs) {
        const daysLeft = diffDays(r.dueDate);
        if (!daysList.includes(daysLeft)) continue;

        const already = (r.remindersSent || []).some(x => x && x.days === daysLeft);
        if (already) continue;

        const vendorLink = `${baseUrl.replace(/\/$/, '')}/v/${r.token}`;
        try {
          const tplCron = emailTemplates.vendorReminder({ tenantName: tenant.name, reqItem: r, vendorLink });
          await mailer.sendMail({
            from: process.env.SMTP_FROM || `${APP_NAME} <noreply@example.com>`,
            to: (r.vendor.email || '').trim(),
            subject: tplCron.subject,
            text: tplCron.text,
          });
          updates.push({ tenantId: tenant.id, requestId: r.id, daysLeft, to: (r.vendor.email || '').trim() });
        } catch (e) {
          console.warn('auto reminder mail failed', e.message);
        }
      }
    }

    if (updates.length) {
      withDB(db2 => {
        for (const u of updates) {
          const rr = (db2.requests || []).find(x => x.id === u.requestId && x.tenantId === u.tenantId);
          if (!rr) continue;
          rr.remindersSent = rr.remindersSent || [];
          rr.remindersSent.push({ days: u.daysLeft, at: nowISO(), manual: false });
          rr.emailReminderSentAt = nowISO();
          rr.updatedAt = nowISO();

          db2.audit.push({
            id: safeId('aud'),
            tenantId: u.tenantId,
            requestId: u.requestId,
            actor: 'system',
            action: 'auto_reminder_sent',
            detail: { to: u.to, days: u.daysLeft },
            at: nowISO(),
          });
        }
      });
      console.log(`⏰ Auto reminder sent: ${updates.length}`);
    }
  } finally {
    reminderRunning = false;
  }
}

function truthy(v) {
  return String(v || '').trim() === '1' || String(v || '').trim().toLowerCase() === 'true';
}

let cleanupRunning = false;
async function runCleanupJob() {
  if (cleanupRunning) return;
  cleanupRunning = true;
  try {
    const db = readDB();
    const now = Date.now();

    const deletions = [];
    for (const r of (db.requests || [])) {
      if (r.status !== 'archived') continue;
      const plan = getPlanForTenant(db, r.tenantId);
      const retentionMs = (plan.retentionDays || 30) * 24 * 60 * 60 * 1000;
      const t = new Date(r.updatedAt || r.createdAt || 0).getTime();
      if (!Number.isFinite(t) || t <= 0) continue;
      if (now - t > retentionMs) deletions.push(r);
    }

    // Delete files first
    for (const r of deletions) {
      const uploads = r.uploads || {};
      for (const docId of Object.keys(uploads)) {
        const u = uploads[docId];
        if (u && u.storage && u.storage.provider === 's3') {
          try { await fileStorage.delete(u.storage); } catch {}
        }
      }
      const dir = path.join(__dirname, 'uploads', r.tenantId, r.id);
      try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
    }

    // Prune expired invites
    const nowISO2 = nowISO();
    withDB(db2 => {
      if (deletions.length) {
        const delIds = new Set(deletions.map(r => r.id));
        db2.requests = (db2.requests || []).filter(r => !delIds.has(r.id));
        db2.audit = (db2.audit || []).filter(a => !a.requestId || !delIds.has(a.requestId));
      }
      db2.invites = (db2.invites || []).filter(i => {
        if (i.acceptedAt) return false; // keep clean
        if (!i.expiresAt) return true;
        const exp = new Date(i.expiresAt).getTime();
        return !(Number.isFinite(exp) && now > exp);
      });
      db2.meta = db2.meta || {};
      db2.meta.lastCleanupAt = nowISO2;
    });

    if (deletions.length) console.log(`🧹 Cleanup: deleted ${deletions.length} archived requests`);
  } finally {
    cleanupRunning = false;
  }
}

// schedule jobs
try {
  const rcron = (process.env.REMINDER_CRON || '7 * * * *').trim();
  cron.schedule(rcron, () => runReminderJob().catch(e => console.warn('reminder job error', e.message)));
} catch (e) {
  console.warn('REMINDER_CRON invalid', e.message);
}

if (truthy(process.env.CLEANUP_ENABLED || '1')) {
  try {
    const ccron = (process.env.CLEANUP_CRON || '15 3 * * *').trim();
    cron.schedule(ccron, () => runCleanupJob().catch(e => console.warn('cleanup job error', e.message)));
  } catch (e) {
    console.warn('CLEANUP_CRON invalid', e.message);
  }
}


// --- Expiry reminder cron job ---
let expiryReminderRunning = false;
async function runExpiryReminderJob() {
  if (expiryReminderRunning) return;
  expiryReminderRunning = true;
  try {
    const db = readDB();
    const today = startOfToday();
    const warnDaysList = [30, 14, 7, 3, 1]; // Days before expiry to warn

    for (const tenant of (db.tenants || [])) {
      const reqs = (db.requests || []).filter(r => r.tenantId === tenant.id && (r.status === 'open' || r.status === 'submitted'));
      for (const r of reqs) {
        for (const d of (r.docs || [])) {
          if (!d.expiryRequired) continue;
          const u = (r.uploads || {})[d.id];
          if (!u || !u.expiryDate) continue;
          const exp = parseYmd(u.expiryDate);
          if (!exp) continue;
          const daysLeft = daysDiff(exp, today);
          if (daysLeft < 0 || !warnDaysList.includes(daysLeft)) continue;

          // Check if we already sent this specific warning
          const alreadyKey = 'expiry_' + d.id + '_' + daysLeft;
          r._expiryReminders = r._expiryReminders || [];
          if (r._expiryReminders.includes(alreadyKey)) continue;

          // Add notification
          addNotification({
            tenantId: tenant.id,
            userId: null,
            type: 'doc_expiring',
            title: daysLeft === 0 ? 'Belge bugün sona eriyor!' : 'Belge ' + daysLeft + ' gün içinde sona eriyor',
            message: d.label + ' - ' + (r.vendor?.name || ''),
            link: '/app/requests/' + encodeURIComponent(r.publicId || r.id),
          });

          // Mark as sent
          withDB(db2 => {
            const rr = (db2.requests || []).find(x => x.id === r.id);
            if (!rr) return;
            rr._expiryReminders = rr._expiryReminders || [];
            rr._expiryReminders.push(alreadyKey);
          });
        }
      }
    }
  } catch (e) {
    console.warn('expiry reminder job error', e.message);
  } finally {
    expiryReminderRunning = false;
  }
}

// Schedule expiry check daily at 8am
try {
  cron.schedule('0 8 * * *', () => runExpiryReminderJob().catch(e => console.warn('expiry job err', e.message)));
} catch (e) {
  console.warn('Expiry reminder cron invalid', e.message);
}

// Clean old notifications weekly
try {
  cron.schedule('0 4 * * 0', () => {
    try {
      const db = readDB();
      for (const tenant of (db.tenants || [])) {
        deleteOldNotifications(tenant.id, 90);
      }
    } catch (e) {
      console.warn('notification cleanup error', e.message);
    }
  });
} catch (e) {
  console.warn('Notification cleanup cron invalid', e.message);
}

// 404
app.use((req, res) => {
  res.status(404).render('layout', {
    title: 'Bulunamadı',
    pageTitle: 'Bulunamadı',
    appName: APP_NAME,
    appVersion: APP_VERSION,
    supportEmail: SUPPORT_EMAIL,
    user: null,
    tenant: null,
    plan: null,
    flash: consumeFlash(req),
    csrfToken: res.locals.csrfToken,
    cspNonce: res.locals.cspNonce || '',
    body: render('error', {
      status: 404,
      message: 'Sayfa bulunamadı.',
      requestId: req.requestId,
      supportEmail: SUPPORT_EMAIL
    })
  });
});

// Error handler (prod-safe)
app.use((err, req, res, next) => {
  const isProd = process.env.NODE_ENV === 'production';
  const requestId = req.requestId;

  // Normalize message/status for user (avoid leaking internals)
  let status = (err && (err.status || err.statusCode)) ? (err.status || err.statusCode) : 500;
  let message = 'Bir hata oluştu.';

  if (err && (err.code === 'EBADCSRFTOKEN' || err.message === 'CSRF token hatalı.' || /CSRF token/i.test(err.message || ''))) {
    status = 403;
    message = 'Güvenlik doğrulaması başarısız. Sayfayı yenileyip tekrar deneyin.';
  } else if (err && err.code === 'LIMIT_FILE_SIZE') {
    status = 413;
    message = `Dosya çok büyük. Maksimum ${FILE_MAX_MB} MB.`;
  } else if (err && err.code === 'UNSUPPORTED_FILE_TYPE') {
    status = 415;
    message = err.message || 'Bu dosya türüne izin verilmiyor.';
  }

  // Log server-side (with request id)
  try {
    const safePath = (req.originalUrl || '').replace(/\/v\/[^/]+/g, '/v/:token');
    logSecurityEvent('server_error', {
      requestId,
      method: req.method,
      path: safePath,
      status,
      userId: (req.session && req.session.userId) ? req.session.userId : null,
      ip: req.ip,
      ua: req.headers['user-agent'] || ''
    });
  } catch (_) {}

  // Vendor upload UX: redirect back with toast instead of blank stack page
  if ((req.originalUrl || '').startsWith('/v/') && (req.originalUrl || '').includes('/upload')) {
    const m = (req.originalUrl || '').match(/^\/v\/([^/]+)/);
    const token = (req.params && req.params.token) || (m ? m[1] : null);
    if (token) {
      const wantsVendorJson = wantsJson(req) || String(req.get('x-auto-upload') || '').trim() === '1';
      if (wantsVendorJson) return res.status(status).json({ ok: false, error: message, requestId });
      flash(req, 'err', message);
      return res.redirect(303, `/v/${token}`);
    }
  }

  res.status(status);

  // JSON clients
  const isJsonClient = req.accepts('json') && !req.accepts('html');
  if (isJsonClient) {
    return res.json({ ok: false, error: message, requestId });
  }

  return res.render('layout', {
    title: status === 500 ? 'Hata' : 'Uyarı',
    pageTitle: status === 500 ? 'Hata' : 'Uyarı',
    appName: APP_NAME,
    appVersion: APP_VERSION,
    supportEmail: SUPPORT_EMAIL,
    user: null,
    tenant: null,
    plan: null,
    flash: consumeFlash(req),
    csrfToken: res.locals.csrfToken,
    cspNonce: res.locals.cspNonce || '',
    body: render('error', {
      status,
      message,
      requestId,
      supportEmail: SUPPORT_EMAIL,
      showStack: !isProd && Boolean(process.env.SHOW_ERROR_STACK),
      stack: err && err.stack ? String(err.stack) : ''
    })
  });
});

app.listen(PORT, () => {
  console.log(`✅ ${APP_NAME} çalışıyor: http://localhost:${PORT}`);
  if (NODE_ENV !== 'production') {
    console.log(`   - .env: PORT=${PORT} FILE_MAX_MB=${FILE_MAX_MB}`);
  }
});
