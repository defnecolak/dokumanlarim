const crypto = require('crypto');
const fs = require('fs');
const { logSecurityEvent } = require('./security_log');

function timingSafeEqualStr(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

function tryCleanupUploadedFiles(req) {
  try {
    if (req && req.file && req.file.path) {
      fs.unlink(req.file.path, () => {});
    }
    // Best-effort cleanup for potential multiple uploads.
    if (req && Array.isArray(req.files)) {
      for (const f of req.files) {
        if (f && f.path) fs.unlink(f.path, () => {});
      }
    }
  } catch (_) {
    // ignore
  }
}

function ensureCsrf(req, res, next) {
  if (!req.session) return next();
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(24).toString('base64url');
  }
  res.locals.csrfToken = req.session.csrfToken;
  next();
}

function verifyCsrf(req, res, next) {
  // Only for state-changing methods
  const method = (req.method || '').toUpperCase();
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) return next();
  const token = (req.body && req.body._csrf) || req.get('x-csrf-token');
  if (!req.session || !req.session.csrfToken) {
    tryCleanupUploadedFiles(req);
    logSecurityEvent('csrf.missing', {
      method,
      path: req.path,
      ip: req.ip,
      ua: req.headers['user-agent'],
      requestId: req.requestId,
    });
		const err = new Error('CSRF token yok.');
		err.status = 403;
		err.code = 'EBADCSRFTOKEN';
		return next(err);
  }
  if (!token || !timingSafeEqualStr(token, req.session.csrfToken)) {
    tryCleanupUploadedFiles(req);
    logSecurityEvent('csrf.invalid', {
      method,
      path: req.path,
      ip: req.ip,
      ua: req.headers['user-agent'],
      requestId: req.requestId,
    });
		const err = new Error('CSRF token hatalı.');
		err.status = 403;
		err.code = 'EBADCSRFTOKEN';
		return next(err);
  }
  next();
}

module.exports = { ensureCsrf, verifyCsrf };
