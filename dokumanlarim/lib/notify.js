
const { hmacSha256Base64 } = require('./utils');

async function postJson(url, payload, headers = {}, timeoutMs = 6000) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...headers },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    const text = await res.text().catch(() => '');
    return { ok: res.ok, status: res.status, text: text.slice(0, 500) };
  } finally {
    clearTimeout(t);
  }
}

function buildSlackText(event, payload) {
  // Kısa, okunur, Türkçe.
  const t = payload?.tenant?.name || payload?.tenantName || payload?.tenantId || '';
  const vendor = payload?.request?.vendor?.name || payload?.vendorName || '';
  const rid = payload?.request?.id || payload?.requestId || '';
  const base = payload?.baseUrl || '';
  const link = payload?.links?.request || (base && rid ? `${base}/app/requests/${rid}` : '');

  const lines = [];
  lines.push(`*${event}*`);
  if (t) lines.push(`Şirket: *${t}*`);
  if (vendor) lines.push(`Vendor: *${vendor}*`);
  if (rid) lines.push(`Talep: \`${rid}\``);
  if (payload?.doc?.label) lines.push(`Belge: ${payload.doc.label}`);
  if (payload?.doc?.state) lines.push(`Durum: ${payload.doc.state}`);
  if (link) lines.push(`Panel: ${link}`);
  return lines.join('\n');
}

function buildTeamsPayload(text) {
  // Teams incoming webhook genelde { text } kabul eder.
  return { text };
}

function buildWebhookPayload(event, payload) {
  return {
    event,
    at: new Date().toISOString(),
    ...payload,
  };
}

async function sendTenantNotifications({ tenant, event, payload, baseUrl }) {
  if (!tenant) return { sent: 0 };
  const notify = tenant.notify || {};
  const enabledForEvent =
    (event === 'vendor.submitted' && notify.onVendorSubmitted !== false) ||
    (event === 'vendor.uploaded' && notify.onVendorUpload === true) ||
    (event === 'request.status_changed' && notify.onStatusChange !== false) ||
    (event === 'request.created' && notify.onRequestCreated === true) ||
    (event === 'test' && true);

  if (!enabledForEvent) return { sent: 0 };

  const urls = [];
  if (tenant.webhookUrl) urls.push({ kind: 'webhook', url: tenant.webhookUrl });
  if (tenant.slackWebhookUrl) urls.push({ kind: 'slack', url: tenant.slackWebhookUrl });
  if (tenant.teamsWebhookUrl) urls.push({ kind: 'teams', url: tenant.teamsWebhookUrl });

  if (urls.length === 0) return { sent: 0 };

  const results = [];
  const secret = (tenant.webhookSecret || '').trim();
  const base = baseUrl || '';

  for (const u of urls) {
    try {
      if (u.kind === 'webhook') {
        const body = buildWebhookPayload(event, { ...payload, baseUrl: base });
        const raw = JSON.stringify(body);
        const sig = secret ? `sha256=${hmacSha256Base64(secret, raw)}` : '';
        const headers = {
          'user-agent': 'Dokumanlarim/1.10.0',
          'x-portal-event': event,
          'x-portal-tenant-id': tenant.id || '',
        };
        if (sig) headers['x-portal-signature'] = sig;

        const r = await postJson(u.url, body, headers);
        results.push({ kind: u.kind, ...r });
      } else if (u.kind === 'slack') {
        const text = buildSlackText(event, payload);
        const r = await postJson(u.url, { text });
        results.push({ kind: u.kind, ...r });
      } else if (u.kind === 'teams') {
        const text = buildSlackText(event, payload);
        const r = await postJson(u.url, buildTeamsPayload(text));
        results.push({ kind: u.kind, ...r });
      }
    } catch (e) {
      results.push({ kind: u.kind, ok: false, status: 0, text: String(e?.message || e) });
    }
  }

  return { sent: results.filter(r => r.ok).length, results };
}

// Tenant bağımsız (global) güvenlik alarmı.
// Kurulum: SECURITY_ALERT_WEBHOOK_URL=https://... (Slack incoming webhook da olur).
// İsteyen prod'da WAF / SIEM tarafına buradan olay akıtabilir.
async function sendSecurityAlert({ event = 'security.alert', title, text, severity = 'warn', baseUrl, meta = {} }) {
  const url = (process.env.SECURITY_ALERT_WEBHOOK_URL || '').trim();
  if (!url) return { ok: false, skipped: true };

  const payload = {
    event,
    severity,
    title: title || 'Güvenlik uyarısı',
    text: text || '',
    baseUrl: baseUrl || '',
    meta,
    at: new Date().toISOString(),
  };

  // Slack webhook: { text }
  const isSlackStyle = url.includes('hooks.slack.com');
  if (isSlackStyle) {
    const slackText = [`*${payload.title}*`, payload.text, payload.baseUrl ? `Base: ${payload.baseUrl}` : '']
      .filter(Boolean)
      .join('\n');
    return await postJson(url, { text: slackText });
  }

  return await postJson(url, payload, { 'user-agent': 'Dokumanlarim/1.10.0' });
}

module.exports = {
  sendTenantNotifications,
  sendSecurityAlert,
  buildSlackText,
  postJson,
};
