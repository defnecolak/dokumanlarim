#!/usr/bin/env node
require('dotenv').config();

const pkg = require('../package.json');

const BASE = (process.env.SMOKE_BASE_URL || process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`).replace(/\/$/, '');
const EMAIL = (process.env.SMOKE_EMAIL || '').trim();
const PASS = (process.env.SMOKE_PASSWORD || '').trim();

async function closeHttpDispatcher() {
  // Node's fetch typically uses undici. On some Node/Windows combos, forcing process.exit()
  // after fetch traffic can trigger libuv assertions. Best effort: close the dispatcher and
  // let Node exit naturally (via exitCode).
  try {
    const undici = require('undici');
    const dispatcher = undici.getGlobalDispatcher?.();
    if (dispatcher && typeof dispatcher.close === 'function') {
      await dispatcher.close();
    }
  } catch (_) {
    // ignore
  }
}

async function finish(code) {
  process.exitCode = code;
  await closeHttpDispatcher();
}

function ok(msg) { console.log('✅', msg); }
function warn(msg) { console.log('⚠️', msg); }
function fail(msg) { console.log('🔥', msg); }

function pickSetCookies(res) {
  // Node's fetch (undici) supports getSetCookie() in newer versions.
  const h = res.headers;
  if (typeof h.getSetCookie === 'function') return h.getSetCookie();
  const sc = h.get('set-cookie');
  return sc ? [sc] : [];
}

function parseCookies(setCookieHeaders) {
  const out = {};
  for (const sc of setCookieHeaders || []) {
    const part = String(sc).split(';')[0];
    const idx = part.indexOf('=');
    if (idx <= 0) continue;
    const k = part.slice(0, idx).trim();
    const v = part.slice(idx + 1).trim();
    if (!k) continue;
    out[k] = v;
  }
  return out;
}

function mergeJar(jar, newCookies) {
  for (const [k, v] of Object.entries(newCookies || {})) jar[k] = v;
  return jar;
}

function jarHeader(jar) {
  return Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
}

async function http(path, { method = 'GET', headers = {}, body = null, jar = null, redirect = 'follow' } = {}) {
  const url = path.startsWith('http') ? path : `${BASE}${path}`;
  const h = { ...headers };
  if (jar && Object.keys(jar).length) h['cookie'] = jarHeader(jar);

  const res = await fetch(url, { method, headers: h, body, redirect });
  const setCookies = parseCookies(pickSetCookies(res));
  return { res, setCookies };
}

async function main() {
  console.log(`\nDökümanlarım Smoke Test v${pkg.version}`);
  console.log(`Base: ${BASE}\n`);

  let failed = 0;

  // 1) /health
  try {
    const { res } = await http('/health');
    const j = await res.json();
    if (res.status === 200 && j && j.ok) {
      ok(`/health OK (version=${j.version || '?'})`);
    } else {
      failed++; fail(`/health beklenmeyen çıktı: status=${res.status}`);
    }
  } catch (e) {
    failed++; fail(`/health hata: ${e.message}`);
  }

  // 2) /ready
  try {
    const { res } = await http('/ready');
    const j = await res.json();
    if (res.status === 200 && j && j.ok) ok('/ready OK');
    else { failed++; fail(`/ready beklenmeyen: status=${res.status}`); }
  } catch (e) {
    failed++; fail(`/ready hata: ${e.message}`);
  }

  // 3) security.txt
  try {
    const { res } = await http('/.well-known/security.txt');
    const t = await res.text();
    if (res.status === 200 && /Contact:/i.test(t)) ok('security.txt OK');
    else { failed++; fail('security.txt beklenmeyen'); }
  } catch (e) {
    failed++; fail(`security.txt hata: ${e.message}`);
  }

  // 4) robots
  try {
    const { res } = await http('/robots.txt');
    const t = await res.text();
    if (res.status === 200 && /Disallow:\s*\/app/i.test(t)) ok('robots.txt OK');
    else { failed++; fail('robots.txt beklenmeyen'); }
  } catch (e) {
    failed++; fail(`robots.txt hata: ${e.message}`);
  }

  // 5) Legal pages
  for (const p of ['/legal/privacy', '/legal/terms']) {
    try {
      const { res } = await http(p);
      if (res.status === 200) ok(`${p} OK`);
      else { failed++; fail(`${p} status=${res.status}`); }
    } catch (e) {
      failed++; fail(`${p} hata: ${e.message}`);
    }
  }

  // 6) Static
  try {
    const { res } = await http('/public/styles.css', { method: 'HEAD' });
    if (res.status === 200) ok('static styles.css OK');
    else { failed++; fail(`styles.css status=${res.status}`); }
  } catch (e) {
    failed++; fail(`styles.css hata: ${e.message}`);
  }

  // Optional: login test
  if (EMAIL && PASS) {
    console.log('\nLogin smoke…');
    const jar = {};
    try {
      const g = await http('/login', { jar, redirect: 'manual' });
      mergeJar(jar, g.setCookies);
      const html = await g.res.text();
      const m = html.match(/name="_csrf"\s+value="([^"]+)"/);
      const csrf = m ? m[1] : '';
      if (!csrf) throw new Error('csrf token bulunamadı');

      const body = new URLSearchParams();
      body.set('_csrf', csrf);
      body.set('email', EMAIL);
      body.set('password', PASS);

      const p = await http('/login', {
        method: 'POST',
        jar,
        redirect: 'manual',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });
      mergeJar(jar, p.setCookies);

      const loc = p.res.headers.get('location') || '';
      if (![302, 303].includes(p.res.status)) {
        const txt = await p.res.text();
        throw new Error(`login redirect olmadı (status=${p.res.status}) snippet=${txt.slice(0,120)}`);
      }

      const nextPath = loc.startsWith('http') ? loc : loc || '/app/requests';
      const a = await http(nextPath, { jar });
      if (a.res.status === 200) ok('Login + /app/requests OK');
      else { failed++; fail(`Login sonrası /app/requests status=${a.res.status}`); }
    } catch (e) {
      failed++; fail(`Login smoke başarısız: ${e.message}`);
    }
  } else {
    warn('Login smoke atlandı (SMOKE_EMAIL / SMOKE_PASSWORD set edilmemiş)');
  }

  console.log('\n--- Sonuç ---');
  if (failed) {
    fail(`${failed} test başarısız`);
    console.log('Detaylı plan: docs/TEST_PLAN.md');
    await finish(1);
    return;
  }
  ok('Tüm smoke testler geçti');
  await finish(0);
}

main().catch(async (e) => {
  console.error('🔥 smoke test fatal:', e);
  await finish(1);
});
