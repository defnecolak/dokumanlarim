#!/usr/bin/env node
require('dotenv').config();

const nodemailer = require('nodemailer');
const pkg = require('../package.json');

const to = (process.argv[2] || process.env.SMTP_TEST_TO || '').trim();
if (!to || !to.includes('@')) {
  console.error('Kullanım: npm run smtp:test -- mail@ornek.com  (veya SMTP_TEST_TO env)');
  process.exit(1);
}

const host = (process.env.SMTP_HOST || '').trim();
if (!host) {
  console.error('SMTP_HOST boş. Önce .env içine SMTP ayarlarını girin.');
  process.exit(1);
}

const port = parseInt(process.env.SMTP_PORT || '587', 10);
const user = (process.env.SMTP_USER || '').trim();
const pass = (process.env.SMTP_PASS || '').trim();

const transport = nodemailer.createTransport({
  host,
  port,
  secure: port === 465,
  auth: user ? { user, pass } : undefined,
});

(async () => {
  try {
    const from = process.env.SMTP_FROM || `Dökümanlarım <noreply@example.com>`;
    const info = await transport.sendMail({
      from,
      to,
      subject: `✅ Dökümanlarım SMTP Test (v${pkg.version})`,
      text: `Merhaba!\n\nBu bir test e-postasıdır.\n\nSürüm: ${pkg.version}\nTarih: ${new Date().toISOString()}\n\nBu mail geldiyse SMTP çalışıyor.\n`,
    });

    console.log('✅ Gönderildi:', to);
    console.log('   messageId:', info.messageId || '(yok)');
    process.exit(0);
  } catch (e) {
    console.error('❌ SMTP test başarısız:', e.message);
    process.exit(1);
  }
})();
