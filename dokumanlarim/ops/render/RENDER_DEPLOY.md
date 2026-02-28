# Render + Cloudflare ile Prod Deploy (dokumanlarim.com)

Bu doküman, Dökümanlarım’ı **Render** üzerinde çalıştırıp, domain’i **Cloudflare** üzerinden yönlendirmek için pratik bir yol haritasıdır.

> Amaç: "Launch Doctor" ekranında kırmızıları yeşile çevirmek + e-posta deliverability + güvenlik + gözlemlenebilirlik.

## 1) Render tarafı (origin)

### Servis tipi
- Basit başlangıç için: **Render Web Service** (Node)
- Daha kontrollü: Docker ile (ama şart değil)

### Build / Start
- Build command: `npm ci` (veya `npm install`)
- Start command: `npm start`

### Disk / Storage
Uygulama local storage kullanabiliyor. Prod’da:
- **Persistent Disk** ekle (örnek: `/var/data`)
- Aşağıdaki klasörleri bu diske taşı:
  - `data/`
  - `uploads/`
  - `backups/`

> Alternatif: S3 (ileride). Şimdilik tek instance + persistent disk ile hızlı launch mümkün.

### Environment variables (minimum prod)
Render → Environment bölümüne **commit etmeden** gir.

Zorunlu / kritik:
- `NODE_ENV=production`
- `BASE_URL=https://dokumanlarim.com`
- `TRUST_PROXY=1`  (Cloudflare/Render arkasında gerçek IP için)
- `FORCE_HTTPS=1`
- `COOKIE_SECURE=1`
- `SESSION_SECRETS=...,...`  (aşağıda nasıl)

Üretim için önerilen ekler:
- `SUPPORT_EMAIL=ceylanatay@dokumanlarim.com`
- `SECURITY_ALERT_WEBHOOK_URL=...` (Slack/Teams/Discord webhook)
- `TURNSTILE_SITE_KEY=...`
- `TURNSTILE_SECRET_KEY=...`

SMTP (davet / hatırlatma için):
- `SMTP_HOST=...`
- `SMTP_PORT=587`
- `SMTP_USER=...`
- `SMTP_PASS=...`
- `MAIL_FROM="Dökümanlarım <noreply@dokumanlarim.com>"`

### Session secret üretimi
Local’da:
- `npm run gen:secrets`

Çıktıdaki `SESSION_SECRETS=...,...` satırını Render env’e yapıştır.

## 2) Cloudflare tarafı (edge)

### DNS
- `dokumanlarim.com` ve `www` için Render origin’e yönlendirme yap.
- Cloudflare proxy (turuncu bulut) **açık**.

### SSL/TLS
- Mode: **Full (strict)**
- "Always Use HTTPS": açık
- HSTS: Cloudflare veya uygulama üzerinden (ikisi de olur)

### WAF / Rate limit
`ops/cloudflare/WAF_RULES.md` içindeki temel kuralları uygula.

Minimum set:
- `*/login`, `*/signup`, `*/forgot-password` için rate limit (bot saldırılarına karşı)
- `/app/*` için "bot fight" / managed challenge (opsiyonel)

### IP / gerçek client
Prod’da `TRUST_PROXY=1` olmazsa rate-limit gerçek IP yerine Cloudflare IP’sine bakar ve saçma davranır.

## 3) E-posta deliverability (SPF/DKIM/DMARC)

SMTP provider’a göre değişir (Resend / Postmark / Mailgun / Sendgrid vs).

Yapman gerekenler:
- SPF: provider’ın istediği TXT
- DKIM: provider’ın verdiği selector TXT/CNAME
- DMARC: `_dmarc.dokumanlarim.com` TXT

> Launch ekranında DMARC "eksik" görüyorsan, mail’ler spam’e düşebilir.

## 4) Son kontrol

- `npm run doctor` → blocker kalmasın
- `npm run smoke` → hepsi geçsin
- `/app/launch` → kırmızı badge kalmasın

