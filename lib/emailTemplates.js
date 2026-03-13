'use strict';

/**
 * Merkezi e-posta şablonları.
 * Her fonksiyon { subject, text, html? } döner.
 * html opsiyonel: yoksa mailer sadece text gönderir.
 */

const escapeHtml = (s) =>
  String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

// ─── 1. Email Doğrulama ───
function verifyEmail({ appName, firstName, link, ttlHours }) {
  const subject = `${appName}: E-postanı doğrula`;
  const text = `Merhaba ${firstName || ''},\n\nHesabını doğrulamak için: ${link}\n\nBu link ${ttlHours} saat geçerlidir.`;
  const html = `<p>Merhaba ${escapeHtml(firstName)},</p><p>Hesabını doğrulamak için:</p><p><a href="${link}">${link}</a></p><p>Bu link <b>${ttlHours} saat</b> geçerlidir.</p>`;
  return { subject, text, html };
}

// ─── 2. Şifre Sıfırlama ───
function resetPassword({ appName, link, ttlMinutes }) {
  const subject = `${appName}: Şifre sıfırlama`;
  const text = `Şifre sıfırlama linki: ${link}\n\nBu link ${ttlMinutes} dakika geçerlidir.`;
  const html = `<p>Şifreni sıfırlamak için aşağıdaki linki kullan:</p><p><a href="${link}">${link}</a></p><p>Bu link <b>${ttlMinutes} dakika</b> geçerlidir.</p>`;
  return { subject, text, html };
}

// ─── 3. Ekip Daveti ───
function teamInvite({ appName, tenantName, link }) {
  const subject = `Davet — ${tenantName}`;
  const text = `Merhaba,\n\n${tenantName} şirketi sizi ${appName} uygulamasına davet etti.\n\nDavet linki:\n${link}\n\nBu link 14 gün geçerlidir.\n`;
  return { subject, text };
}

// ─── 4. Vendor Davet E-postası ───
function vendorInvite({ tenantName, reqItem, vendorLink }) {
  const lines = [];
  lines.push(`Merhaba ${reqItem.vendor.name || ''},`);
  lines.push('');
  lines.push(`${tenantName} adına sizden aşağıdaki belgeleri yüklemenizi rica ediyoruz.`);
  if (reqItem.dueDate) lines.push(`Son tarih: ${reqItem.dueDate}`);
  lines.push('');
  lines.push('Belge listesi:');
  for (const d of reqItem.docs || []) {
    lines.push(`- ${d.label}${d.required ? ' (zorunlu)' : ''}`);
  }
  if (reqItem.vendorMessage) {
    lines.push('');
    lines.push('Not:');
    lines.push(reqItem.vendorMessage);
  }
  lines.push('');
  lines.push('Yükleme linki:');
  lines.push(vendorLink);
  lines.push('');
  lines.push('Teşekkürler.');
  const subject = `Belge Talebi — ${tenantName}`;
  return { subject, text: lines.join('\n') };
}

// ─── 5. Vendor Hatırlatma E-postası ───
function vendorReminder({ tenantName, reqItem, vendorLink }) {
  const uploads = reqItem.uploads || {};
  const missingRequired = (reqItem.docs || []).filter(d => d.required && !uploads[d.id]);
  const lines = [];
  lines.push(`Merhaba ${reqItem.vendor.name || ''},`);
  lines.push('');
  lines.push(`${tenantName} belge talebiniz için hatırlatma.`);
  if (reqItem.dueDate) lines.push(`Son tarih: ${reqItem.dueDate}`);
  lines.push('');
  if (missingRequired.length) {
    lines.push('Eksik zorunlu belgeler:');
    for (const d of missingRequired) lines.push(`- ${d.label}`);
  } else {
    lines.push('Zorunlu belgeler tamam görünüyor.');
  }
  lines.push('');
  lines.push('Yükleme linki:');
  lines.push(vendorLink);
  lines.push('');
  lines.push('Teşekkürler.');
  const subject = `Hatırlatma — ${tenantName}`;
  return { subject, text: lines.join('\n') };
}

// ─── 6. Vendor Belge Gönderim Bildirimi (tenant'a) ───
function vendorSubmitted({ tenantName, reqItem, baseUrl }) {
  const subject = `Tedarikçi belgeleri gönderdi: ${reqItem.vendor.name}`;
  const text = `Şirket: ${tenantName}
Talep: ${reqItem.id}
Durum: Gönderildi
Gönderen: ${reqItem.submittedBy?.role || 'vendor'} ${reqItem.submittedBy?.email || ''}

Panel: ${baseUrl}/app/requests/${reqItem.id}
`;
  return { subject, text };
}

// ─── 7. Participant Davet (yeni kişi ekleme) ───
function participantInvite({ name, role, vendorName, link, canSubmit }) {
  const subject = `Belge yükleme daveti (${role.replace('_', ' ')}) — ${vendorName}`;
  const text = `Merhaba${name ? ' ' + name : ''},

Bu link ile belge yükleyebilirsiniz:
${link}

Not: ${canSubmit ? 'Bu link ile belgeleri gönderebilirsiniz (Yetkili).' : 'Bu link ile sadece belge yükleyebilirsiniz. "Gönder" için yetkili linki gerekir.'}

`;
  return { subject, text };
}

// ─── 8. Participant Link Gönderimi (mevcut kişiye) ───
function participantLink({ name, role, vendorName, link, canSubmit }) {
  const subject = `Belge yükleme linki (${(role || '').replace('_', ' ')}) — ${vendorName}`;
  const text = `Merhaba${name ? ' ' + name : ''},

Bu link ile belge yükleyebilirsiniz:
${link}

Not: ${canSubmit ? 'Bu link ile belgeleri gönderebilirsiniz (Yetkili).' : 'Bu link ile sadece belge yükleyebilirsiniz. "Gönder" için yetkili linki gerekir.'}

`;
  return { subject, text };
}

module.exports = {
  verifyEmail,
  resetPassword,
  teamInvite,
  vendorInvite,
  vendorReminder,
  vendorSubmitted,
  participantInvite,
  participantLink,
};
