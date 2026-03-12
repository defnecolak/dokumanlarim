const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { readDB } = require('./db');
const { logSecurityEvent } = require('./security_log');

const SALT_ROUNDS = (() => {
  const raw = (process.env.BCRYPT_ROUNDS || '').trim();
  const n = parseInt(raw, 10);
  if (Number.isFinite(n) && n >= 10 && n <= 15) return n;
  // A reasonable default for public SaaS; adjust if you need faster hashing.
  return 12;
})();

function isEmailVerificationRequired() {
  const v = (process.env.EMAIL_VERIFICATION_REQUIRED || '').trim();
  if (v === '0' || v.toLowerCase() === 'false' || v.toLowerCase() === 'no') return false;
  if (v === '1' || v.toLowerCase() === 'true' || v.toLowerCase() === 'yes') return true;
  // Default: required in production, optional in development.
  return (process.env.NODE_ENV || 'development') === 'production';
}

async function hashPassword(password) {
  const salt = await bcrypt.genSalt(SALT_ROUNDS);
  return bcrypt.hash(password, salt);
}

async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

function requireAuthLoose(req, res, next) {
  if (!req.session || !req.session.userId) return res.redirect('/login');

  // Session fingerprint check: detect potential session hijacking
  if (req.session._fp) {
    const currentFp = crypto.createHash('sha256').update(req.get('user-agent') || '').digest('base64url').slice(0, 16);
    if (req.session._fp !== currentFp) {
      logSecurityEvent('auth.session_fingerprint_mismatch', {
        userId: req.session.userId,
        ip: req.ip,
        ua: (req.get('user-agent') || '').slice(0, 200),
      });
      req.session = null;
      return res.redirect('/login');
    }
  }

  const db = readDB();
  const user = (db.users || []).find(u => u.id === req.session.userId);
  if (!user) {
    req.session = null;
    return res.redirect('/login');
  }
  const tenant = (db.tenants || []).find(t => t.id === user.tenantId);
  if (!tenant) {
    req.session = null;
    return res.redirect('/login');
  }
  req.user = user;
  req.tenant = tenant;
  next();
}

function requireAuth(req, res, next) {
  return requireAuthLoose(req, res, () => {
    // Backward compatible: missing field counts as verified.
    if (isEmailVerificationRequired() && req.user.emailVerified === false) {
      return res.redirect('/verify-needed');
    }
    next();
  });
}

function requireAdmin(req, res, next) {
  if (!req.user) return res.redirect('/login');
  if (req.user.role !== 'owner' && req.user.role !== 'admin') {
    return res.status(403).send('Bu işlem için yetkin yok.');
  }
  next();
}

function requireOwner(req, res, next) {
  if (!req.user) return res.redirect('/login');
  if (req.user.role !== 'owner') return res.status(403).send('Bu işlem için yetkin yok.');
  next();
}

module.exports = {
  hashPassword,
  verifyPassword,
  requireAuth,
  requireAuthLoose,
  requireAdmin,
  requireOwner,
};
