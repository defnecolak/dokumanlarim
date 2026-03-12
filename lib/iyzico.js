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

/**
 * Verify iyzico callback authenticity by re-retrieving the checkout result
 * from iyzico API using the token. This is the recommended approach since
 * iyzico does not sign callbacks with HMAC — instead, we server-side verify
 * the payment status directly from their API.
 */
async function verifyAndRetrieveCheckout(token) {
  if (!token || typeof token !== 'string' || token.length < 8 || token.length > 512) {
    throw new Error('invalid_token_format');
  }
  const data = await retrieveSubscriptionCheckout(token);
  // Validate the response has expected structure
  if (!data || typeof data !== 'object') {
    throw new Error('invalid_iyzico_response');
  }
  return data;
}

module.exports = {
  iyzicoEnabled,
  getIyzicoConfig,
  initializeSubscriptionCheckout,
  retrieveSubscriptionCheckout,
  verifyAndRetrieveCheckout,
};
