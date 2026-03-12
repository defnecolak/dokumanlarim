# Dökümanlarım — “Hepsi” Güvenlik Checklist’i (Prod)

Bu proje, uygulama katmanında zaten ciddi hardening içeriyor (CSRF, CSP nonce, MFA, brute-force lockout, rate-limit, upload imza kontrolü, audit log, security log, vb.).

Buradaki checklist, *public SaaS* standardına yaklaşmak için altyapı + operasyon katmanında yapılması gerekenleri “copy/paste” seviyesinde toplar.

> Not: “Hack edilemez” diye bir şey yok. Ama maliyeti/riski saldırgan için astronomik seviyeye çekebiliriz.

## 1) Zorunlu (Launch öncesi)

### TLS / HTTPS
- [ ] HTTPS zorunlu (Cloudflare / reverse proxy ile)
- [ ] HSTS aktif (min 6 ay), preload’a girmeden önce domain/subdomain stratejini netleştir
- [ ] `COOKIE_SECURE=1` ve `BASE_URL=https://...`

### Secret yönetimi
- [ ] `SESSION_SECRETS` (en az 2 anahtar) ile session key rotation
- [ ] `CSRF_SECRET`, `TOKEN_SECRET`, `COOKIE_SIGNING_SECRET` vb. uzun, rastgele
- [ ] Secrets’lar `.env` ile değil, prod’da secret manager ile (Render/DO/AWS/GCP) verilsin

### Yedek / geri dönüş
- [ ] `/data` dizini (db.json + uploads + log’lar) düzenli yedekleniyor
- [ ] Yedek geri yükleme prosedürü test edildi (ayda 1)

### Gözlemleme (minimum)
- [ ] Security log (JSONL) saklama politikası (örn 30–90 gün)
- [ ] Slack/Teams webhook ile security alert aktif (`SECURITY_ALERT_WEBHOOK_URL`)

## 2) Çok yüksek kaldıraç (1–2 gün)

### WAF (Cloudflare önerisi)
- [ ] Managed WAF kuralları (OWASP / Cloudflare Managed)
- [ ] Bot mitigation (Bot Fight Mode / Super Bot Fight)
- [ ] Rate-limit kuralları (login/signup/upload endpointleri)
- [ ] Geo / ASN kısıtları (opsiyonel, müşteri profilin uygunsa)

Detay: `ops/cloudflare/WAF_RULES.md`

### Merkezi log + alarm
- [ ] Loki/Grafana/Promtail veya eşdeğer (Better Stack, Datadog, ELK)
- [ ] Alarm: kısa sürede çok fazla `login_failed`, `account_lockout`, `csrf_failed`, `upload_rejected` olayı

Detay: `ops/observability/README.md`

## 3) Kurumsal seviye (isteğe bağlı ama “çok safe”)

- [ ] MFA zorunlu (en azından owner/admin için)
- [ ] Passkey/WebAuthn (parola yerine)
- [ ] Admin aksiyonları için step-up auth (yeniden parola / MFA)
- [ ] IP allowlist (özellikle admin panel)
- [ ] DLP / AV tarama (ClamAV veya bulut AV)
- [ ] S3/R2 tarafında SSE (server-side encryption) + kısa süreli signed URL
- [ ] SIEM entegrasyonu (Splunk / Sentinel)

## 4) Süreç (çok önemli)

- [ ] Responsible disclosure (security.txt + e-posta) aktif
- [ ] Dependabot / Renovate ile otomatik dependency PR
- [ ] CI’da `npm audit` + basit e2e smoke test
- [ ] En az yılda 1 pentest / dış denetim

