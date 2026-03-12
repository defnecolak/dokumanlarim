# Dökümanlarım — Test Planı (Public Launch)

Bu plan 3 seviyeli:

1) **Otomatik (5 dk)**
2) **Manuel ürün testleri (15–30 dk)**
3) **Güvenlik / kötü senaryo testleri (30–60 dk)**

---

## 1) Otomatik testler

### 1.1 Launch Doctor

```bash
npm run doctor
```

Beklenen:
- `🔥` yok
- `⚠️` varsa, prod’da risk azaltmak için yapılacaklar listelenir.

### 1.2 Smoke Test

```bash
npm run smoke
```

Login testini de çalıştırmak istersen:

```bash
# Varsayılan base: http://localhost:3000
SMOKE_BASE_URL=http://localhost:3333 npm run smoke

# Login smoke (opsiyonel)
SMOKE_BASE_URL=http://localhost:3333 SMOKE_EMAIL=owner@firma.com SMOKE_PASSWORD=... npm run smoke
```

**Windows PowerShell** (env set etme şekli farklı):

```powershell
$env:SMOKE_BASE_URL = "http://localhost:3333"
$env:SMOKE_EMAIL    = "owner@firma.com"
$env:SMOKE_PASSWORD = "..."
npm run smoke
```

Notlar:
- Login smoke için **gerçek bir kullanıcı** oluşturman gerekir (signup).
- Node tarafında en sorunsuz hat, **LTS sürümü** (örn. Node 20/22). Yeni major'larda (özellikle Windows) fetch/exit etkileşiminde tuhaflıklar olabiliyor.

---

## 2) Manuel ürün testleri

### 2.1 Signup → Verify → Login
- Kayıt ol
- E‑posta doğrulama (prod’da zorunlu)
- Login
- MFA kur (owner için öneri: zorunlu)

### 2.2 Yeni talep → Vendor upload → Submit
1) Yeni talep oluştur (en az 3 belge)
2) Vendor linki aç
3) PDF yükle
4) (Varsa) imza/tarih alanlarını doldur
5) “Gönder” yap
6) Admin panelde durum değişti mi?

Beklenen:
- Upload hatalarında stack trace yok
- Vendor sayfasında net hata mesajı var

### 2.3 ZIP indir + CSV export
- Talep detayından ZIP indir
- CLI ile CSV:

```bash
npm run export:csv
```

---

## 3) Güvenlik / kötü senaryo testleri

### 3.1 Tenant izolasyonu (IDOR)
1) Tenant A talep oluştur.
2) URL’yi kopyala.
3) Tenant B ile giriş yap.
4) Tenant A URL’sini aç.

Beklenen:
- 404 / erişim yok

### 3.2 Brute-force / lockout
Yanlış şifreyle ardışık dene:
- 10 kez yanlış şifre → account lock

Beklenen:
- Kilitlenme süresi var
- security.log’a olay düşer

### 3.3 CSRF
- Başka sekmede sayfayı açık bırak
- Uzun süre bekle
- Form gönder

Beklenen:
- 403 + “Güvenlik doğrulaması başarısız”
- Veri silinmemeli

### 3.4 Upload saldırı yüzeyi
- `.exe` yüklemeyi dene
- “PDF gibi görünen ama PDF olmayan” dosya dene

Beklenen:
- Reddedilir + dosya diske yazılmaz

### 3.5 Security headers

```bash
curl -I https://app.dokumanlarim.com/login
```

Beklenen (örnek):
- `Content-Security-Policy` veya `...Report-Only`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options`/`frame-ancestors` (CSP)

### 3.6 WAF / rate-limit doğrulama

Login’e kısa sürede çok istek:

```bash
for i in $(seq 1 60); do curl -s -o /dev/null -w "%{http_code}\n" https://app.dokumanlarim.com/login; done
```

Beklenen:
- Bir noktada `429` veya Cloudflare challenge

---

## 4) E‑posta deliverability testleri

### 4.1 SMTP test
- `/app/launch` içinden test gönder
- veya:

```bash
npm run smtp:test -- ceylanatay@dokumanlarim.com
```

### 4.2 SPF/DMARC
- `/app/launch` sayfasında SPF/DMARC durumunu gör

> DKIM için provider panelinden selector alıp DNS’e eklemek gerekir.

---

## 5) Backup/Restore testi (en önemli prod testi)

1) Backup al:

```bash
npm run backup
```

2) Test ortamında `data/` ve `uploads/` klasörlerini boşalt
3) Backup zip’i açıp geri koy
4) Uygulama ayağa kalkıyor mu? Talepler + dosyalar görünüyor mu?

---

## 6) “Her şey tamam” kriteri

- Otomatik testler geçiyor
- Tenant izolasyonu doğrulandı
- Upload + submit akışı sorunsuz
- Backup restore yapıldı
- WAF + rate limit aktif

