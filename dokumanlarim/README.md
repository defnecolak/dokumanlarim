# Dökümanlarım (Tedarikçi Onboarding) — SaaS Public Launch v1.12.0

Bu paket **public launch** için hazır SaaS iskeletidir:

- ✅ **Multi-tenant** (her şirket ayrı workspace)
- ✅ **Ekip daveti** (kullanıcı ekleme / davet linki)
- ✅ **Tedarikçi portalı** (tokenlı link) + belge yükleme + “gönder”
- ✅ **Tedarikçi e-posta daveti** (SMTP varsa) + **otomatik hatırlatma** (cron)
- ✅ **ZIP indir** + CSV export
- ✅ **iyzico abonelik** (Subscription Checkout Form — opsiyonel)
- ✅ **Public launch güvenlik paketleri** (helmet, rate limit, CSRF, CSP nonce, no-store, robots, legal sayfalar)
- ✅ **MFA (Authenticator / TOTP) + yedek kodlar**
- ✅ **Güvenlik olayları log'u** (`data/security.log`) + opsiyonel global webhook alarmı
- ✅ **Yedekleme scripti** (data/ + uploads/ zip)
- ✅ **Opsiyonel S3/R2 storage** (STORAGE_PROVIDER=s3)

## Kurulum (Windows / PowerShell)

```powershell
npm install
copy .env.example .env
npm start
```

Aç:
- Ana sayfa: http://localhost:3000
- Uygulama: http://localhost:3000/app

Port çakışıyorsa:
```powershell
$env:PORT=3333; npm start
```

> Tedarikçi linkleri için `.env` içindeki `BASE_URL` prod ortamında **https://domainin.com** olmalı.

## Launch Kontrol + Self-test

- UI: **/app/launch** (sadece Owner)
- CLI:

```bash
npm run doctor
npm run smoke
```

Detaylı plan: `docs/LAUNCH_GATE.md` ve `docs/TEST_PLAN.md`
> Lokal testte boş bırakabilirsin; uygulama host/port'u otomatik algılar.

## Ekip (kullanıcı daveti)
- Uygulama → **Ekip** menüsü (sadece Owner)
- “Kullanıcı davet et” → e-posta gönderilir (SMTP yoksa link ekranda gösterilir)
- Davet linkinden kullanıcı ad/soyad + şifre belirleyerek katılır.

Plan limitleri:
- Ücretsiz: 1 kullanıcı
- Başlangıç: 3 kullanıcı
- Takım: 10 kullanıcı
- Pro: 30 kullanıcı

## Tedarikçi e-posta daveti + otomatik hatırlatma
SMTP ayarlıysa talep detayından:
- “Tedarikçiye davet e-postası gönder”
- “Hatırlatma gönder” (eksik belgelere göre)

Otomatik hatırlatma:
- `REMINDER_DEFAULT_DAYS=3,1` gibi ayarlanır (son tarihe 3 gün ve 1 gün kala)
- Cron: `REMINDER_CRON=7 * * * *` (saat başı)

## Storage (S3/R2)
Varsayılan local disk:
- `uploads/<tenantId>/<requestId>/...`

S3/R2 için:
- `.env`: `STORAGE_PROVIDER=s3`
- `S3_BUCKET`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`
- R2 için ayrıca `S3_ENDPOINT` ve `S3_REGION=auto` kullan.

## Prod önerisi (özet)
- Reverse proxy + HTTPS (Caddy/Nginx/Cloudflare)
- `.env`:
  - NODE_ENV=production
  - TRUST_PROXY=1
  - FORCE_HTTPS=1
  - COOKIE_SECURE=1
  - BASE_URL=https://domainin.com
  - SESSION_SECRET=uzun-rastgele

### MFA (Çok faktörlü doğrulama)

- Kullanıcı bazlı MFA: **/app/security**
- Tenant bazlı “MFA zorunlu” (Owner): **/app/security**
  - Açık olduğunda, kullanıcılar girişten sonra MFA kurmadan uygulamaya geçemez.

Yedek kodlar:
- MFA kurulumunda 10 adet tek kullanımlık yedek kod üretilir.
- Kodlar sadece 1 kez gösterilir (sonra session'dan silinir).

### Güvenlik olayları / alarm

- Uygulama kritik olayları `data/security.log` içine JSON satırları olarak yazar.
- Prod'da stdout'a da log alıp (Docker/PM2) merkezi log sistemine (Loki, ELK, Datadog) akıtman önerilir.

Opsiyonel global webhook alarmı:
- `.env`: `SECURITY_ALERT_WEBHOOK_URL=<webhook>`
- Örnek: brute force lockout, MFA brute force vb. olaylarda tek bir merkezi Slack kanalına düşürmek için.

### WAF (en yüksek kaldıraç)

Uygulama içi rate-limit iyi bir temel ama public SaaS için en iyi pratik:
- Cloudflare (veya AWS WAF) önüne koy
- Bot / DDoS koruma aç
- Rate limiting (özellikle `/login`, `/signup`, `/v/*`)
- Geo/ASN block (gerekliyse)
- “Cache everything” değil, dinamik sayfaları bypass

Bu app tarafında:
- `TRUST_PROXY=1` ve reverse proxy'nin gerçek IP header'ını doğru ilettiğinden emin ol.

## Yedek
```bash
npm run backup
```

Çıktı: `backups/backup_YYYY-MM-DD_HH-mm-ss.zip`



## v1.6.0 – Yeni özellikler (Launch)

- **Şirket şablonları (sektöre göre checklist):** /app/templates
  - Hazır şablonlar (read-only) + şirket şablonları (özelleştirilebilir)
  - Varsayılan şablon seçimi
- **Tedarikçi tarafında çoklu kişi:** Talep detayında “Tedarikçi Ekibi” bölümünden rol bazlı link oluştur.
  - Örn: *Mali müşavir* linki (yükleyebilir), *Yetkili* linki (yükleyebilir + gönder)
- **İmza / tarih / geçerlilik kontrolleri:**
  - Belge bazlı “İmza gerekli”, “Düzenleme tarihi”, “Geçerlilik tarihi”
  - Süresi dolmuş belge ile “Gönder” engellenir
  - “Yakında doluyor” uyarıları (warn days)
  - Panelde “İmza doğrula” toggle
- **Webhook / Slack / Teams bildirimleri:**
  - Ayarlar > Webhook/Slack/Teams URL’leri
  - Olaylar: request.created, vendor.uploaded, vendor.submitted, request.status_changed (+ test)
  - Genel webhook için `x-portal-signature` (HMAC) opsiyonel
