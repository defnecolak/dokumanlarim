# Dökümanlarım — Public Launch Gate (GO / NO‑GO)

Bu doküman “public launch” öncesi yapılması gerekenleri ikiye ayırır:

- **Uygulama içinde/repoda eklenebilenler:** bu pakette zaten var (Launch Kontrol + doctor + smoke).
- **Altyapı/operasyon gerektirenler:** senin deploy ortamında yapman gerekir (HTTPS, WAF, backup/restore, DNS kayıtları vb.).

> Kural: Public internet + gerçek müşteri = *saldırı + hata + veri kaybı* ihtimali. “Çalışıyor” yetmez; “geri dönebilir + izleyebilir + sınırlayabilir” olmalı.

---

## 1) En hızlı kontrol (5 dk)

1) Owner hesabınla giriş yap
2) **Launch Kontrol** sayfasına gir:

- `/app/launch`

Orada kırmızı (GEREKLİ/ZAYIF) gördüğün şeyler launch blocker.

Ek olarak CLI:

```bash
npm run doctor
npm run smoke
```

Deploy notları (Render + Cloudflare örneği):

- `ops/render/RENDER_DEPLOY.md`

---

## 2) Prod için zorunlu .env ayarları (minimum)

```env
NODE_ENV=production
TRUST_PROXY=1
FORCE_HTTPS=1
COOKIE_SECURE=1
BASE_URL=https://app.dokumanlarim.com

# Session signing (en az 24+ karakter random). Rotation önerilir.
SESSION_SECRETS=key1-çok-uzun-random,key2-çok-uzun-random

# Dosya limiti
FILE_MAX_MB=15

# Signup abuse azaltmak için
TURNSTILE_SITE_KEY=...
TURNSTILE_SECRET_KEY=...

# Alarm (opsiyonel ama çok yüksek kaldıraç)
SECURITY_ALERT_WEBHOOK_URL=https://hooks.slack.com/...
```

---

## 3) HTTPS / Reverse proxy (Launch blocker)

- Uygulama **mutlaka** HTTPS arkasında çalışmalı.
- Cloudflare / Nginx / Caddy olabilir.

Kontrol:

```bash
curl -I https://app.dokumanlarim.com/health
```

Beklenen:
- `200`
- `Content-Security-Policy` (çoğu sayfada)
- `X-Content-Type-Options: nosniff`

---

## 4) WAF (Cloudflare) — en yüksek kaldıraç

**Mutlaka**: Cloudflare Managed Rules + Bot koruma + rate limit.

Kural önerileri repoda:
- `ops/cloudflare/WAF_RULES.md`

Doğrulama:
- `/login` endpointine kısa sürede çok istek atınca `429` veya challenge görmelisin.

---

## 5) E‑posta (deliverability)

Uygulama SMTP ile mail atar. Ama “mail gidiyor” = “mail inbox’a düşüyor” değildir.

### SMTP test

- UI: `/app/launch` → “SMTP test gönder”
- CLI: `npm run smtp:test -- mail@ornek.com`

### SPF / DMARC kontrol

Launch Kontrol sayfası SPF/DMARC TXT kayıtlarını DNS’ten okumayı dener.

> DKIM provider’a göre değişir (selector gerekir). DKIM’i mail provider panelinden alırsın.

---

## 6) Backup + Restore (Launch blocker)

Backup almak yetmez; **restore edebiliyor musun?**

### Backup

```bash
npm run backup
```

### Restore testi (öneri)

1) `backups/` içindeki zip’i güvenli yere kopyala
2) Test ortamında:
   - `data/` ve `uploads/` klasörlerini farklı bir yere taşı
   - backup zip’i açıp aynı yerlere geri koy
3) Uygulama açılıyor mu? Talepler ve dosyalar görünüyor mu?

Bu testi en az ayda 1 yap.

---

## 7) Tenant izolasyonu (IDOR) — kritik güvenlik testi

Manuel test:

1) **Tenant A** ile bir talep oluştur.
2) Talep detay URL’sini kopyala.
3) Çıkış yap.
4) **Tenant B** ile giriş yap.
5) Tenant A URL’sini aç.

Beklenen:
- `404` veya erişim engeli (kesinlikle veri görünmemeli).

---

## 8) Merkezi log / alarm

Minimum:
- `data/security.log` ve `data/access.log` toplanmalı.

Loki/Grafana quick setup:
- `docs/OBSERVABILITY.md`

Alarm önerileri:
- 5 dk’da 10+ account lock
- 5 dk’da 20+ CSRF fail
- upload_rejected spike

---

## 9) GO / NO‑GO

**GO** için en az:
- HTTPS + COOKIE_SECURE=1
- Session secret güçlü
- Backup + restore test
- Tenant izolasyonu test
- Upload testi (PDF + yasak tip)
- Basic WAF + rate limit

