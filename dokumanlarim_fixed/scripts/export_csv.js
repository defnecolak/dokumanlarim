const fs = require('fs');
const path = require('path');
const { readDB } = require('../lib/db');

function csv(s) {
  const x = String(s ?? '');
  if (x.includes(',') || x.includes('"') || x.includes('\n')) return '"' + x.replaceAll('"', '""') + '"';
  return x;
}

const db = readDB();
const lines = [];
lines.push('tenant,request_id,status,vendor_name,vendor_company,vendor_email,created_at,updated_at,required_done,required_total,total_docs');

for (const r of db.requests) {
  const uploads = r.uploads || {};
  const required = r.docs.filter(d => d.required);
  const done = required.filter(d => uploads[d.id]).length;
  lines.push([
    csv(r.tenantId),
    csv(r.id),
    csv(r.status),
    csv(r.vendor?.name || ''),
    csv(r.vendor?.company || ''),
    csv(r.vendor?.email || ''),
    csv(r.createdAt || ''),
    csv(r.updatedAt || ''),
    done,
    required.length,
    r.docs.length,
  ].join(','));
}

const out = path.join(__dirname, '..', 'exports');
fs.mkdirSync(out, { recursive: true });
const outFile = path.join(out, `requests_${Date.now()}.csv`);
fs.writeFileSync(outFile, lines.join('\n'), 'utf-8');
console.log('✅ CSV hazır:', outFile);
