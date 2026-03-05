const crypto = require('crypto');
const { hmacSha256Base64 } = require('./utils');

function iyzicoEnabled() {
  return String(process.env.BILLING_ENABLED || '0') === '1'
    && String(process.env.BILLING_PROVIDER || 'iyzico') === 'iyzico'
    && (process.env.IYZICO_API_KEY || '').trim()
    && (process.env.IYZICO_SECRET_KEY || '').trim()
    && (process.env.IYZICO_BASE_URL || '').trim();
}

function getIyzicoConfig() {
  return {
    baseUrl: (process.env.IYZICO_BASE_URL || '').trim().replace(/\/+$/, ''),
    apiKey: (process.env.IYZICO_API_KEY || '').trim(),
    secretKey: (process.env.IYZICO_SECRET_KEY || '').trim(),
  };
}

function buildAuthHeaders(uriPath, bodyJson) {
  const { apiKey, secretKey } = getIyzicoConfig();
  const rnd = `${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  const body = bodyJson ? JSON.stringify(bodyJson) : '';
  const signature = hmacSha256Base64(secretKey, rnd + uriPath + body);
  const authorization = `IYZWSv2 ${apiKey}:${rnd}:${signature}`;
  return {
    'Content-Type': 'application/json',
    'x-iyzi-rnd': rnd,
    'Authorization': authorization,
  };
}

async function iyzicoRequest(method, uriPath, bodyJson) {
  const { baseUrl } = getIyzicoConfig();
  const url = baseUrl + uriPath;
  const headers = buildAuthHeaders(uriPath, bodyJson);
  const res = await fetch(url, {
    method,
    headers,
    body: bodyJson ? JSON.stringify(bodyJson) : undefined,
  });
  const text = await res.text();
  let json;
  try { json = JSON.parse(text); } catch { json = { raw: text }; }
  if (!res.ok) {
    const err = new Error(`iyzico HTTP ${res.status}`);
    err.status = res.status;
    err.payload = json;
    throw err;
  }
  return json;
}

// Subscription Checkout Form
async function initializeSubscriptionCheckout(payload) {
  return iyzicoRequest('POST', '/v2/subscription/checkoutform/initialize', payload);
}

async function retrieveSubscriptionCheckout(token) {
  // iyzico dokümantasyonunda token path ile retrieve var. Bazı ortamlarda GET/POST farkı olabiliyor.
  try {
    return await iyzicoRequest('POST', `/v2/subscription/checkoutform/${encodeURIComponent(token)}`, {});
  } catch (e) {
    // fallback GET
    return iyzicoRequest('GET', `/v2/subscription/checkoutform/${encodeURIComponent(token)}`, null);
  }
}

module.exports = {
  iyzicoEnabled,
  initializeSubscriptionCheckout,
  retrieveSubscriptionCheckout,
};
