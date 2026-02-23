# Cloudflare WAF / Rate Limit (Öneri Seti)

Amaç: Bot trafiğini, brute-force denemelerini ve istek fırtınalarını daha uygulamaya gelmeden kırpmak.

> Not: Bu kurallar “kopyala-yapıştır” başlangıç seti. Prod’da önce **Log** modunda deneyip, false-positive yoksa **Block/Challenge** yap.

## 1) Managed WAF (aç/kapa önerisi)

- **Managed Rules**: OWASP Core Ruleset (genelde “Medium” veya “High” sensitivity)
- **Bot Fight Mode / Super Bot Fight Mode**: mümkünse açık
- **DDoS**: default açık

## 2) Firewall Rule örnekleri

### 2.1 Admin / auth yollarında challenge

**Expression:**

```
(http.request.uri.path in {"/login" "/signup" "/reset" "/mfa"} or starts_with(http.request.uri.path, "/app"))
and (cf.client.bot)
```

**Action:** Managed Challenge

### 2.2 Şüpheli user-agent / boş UA (agresif botlar)

```
(len(http.user_agent) lt 6)
```

**Action:** Challenge

### 2.3 Kötü metodlar (bu uygulamada gereksiz)

```
(http.request.method in {"TRACE" "TRACK" "CONNECT"})
```

**Action:** Block

## 3) Rate Limiting (asıl kaldıraç)

> Cloudflare arayüzünde “Rate limiting rules” ile yapılır.

### 3.1 Login brute-force

- **Path**: `/login`
- **Method**: POST
- **Threshold**: 10 istek / 1 dakika (IP başı)
- **Action**: Managed Challenge (veya Block)

### 3.2 Signup abuse

- **Path**: `/signup`
- **Method**: POST
- **Threshold**: 5 istek / 5 dakika (IP başı)
- **Action**: Managed Challenge

### 3.3 Vendor upload flood

- **Path contains**: `/upload/`
- **Method**: POST
- **Threshold**: 60 istek / 10 dakika (IP başı)
- **Action**: Block

### 3.4 Genel API/HTML scrape

- **Path starts_with**: `/app`
- **Threshold**: 600 istek / 10 dakika (IP başı)
- **Action**: Challenge

## 4) “Sadece Türkiye” gibi coğrafi kısıtlama

SaaS hedefin TR ise (ve yabancı trafik istemiyorsan):

```
(ip.geoip.country ne "TR") and starts_with(http.request.uri.path, "/app")
```

**Action:** Block veya Challenge

> Not: VPN kullanan gerçek kullanıcıları da etkileyebilir.

## 5) Logpush / analiz

- WAF “block/challenge” loglarını sakla.
- Uygulama tarafındaki `data/security.log` ile korelasyon kur.


**Action:** Block veya Challenge

> Dikkat: Vendor linkleri (tokenlı `/v/...`) TR dışından da kullanılabilir. Eğer coğrafi engel koyarsan, vendor tarafı için istisna tanımla.

## 5) İstisnalar (allowlist) — vendor linkleri için

Vendor linkleri genellikle `GET /v/:token` ve `POST /v/:token/upload/:docId` şeklinde.

- Eğer “country block” koyacaksan, `/v/` yollarını *hariç tut*.
- Eğer agresif bot filtresi koyacaksan, `/health` gibi endpoint’lere dokunma.

Örnek: `/v/` hariç TR kısıt

```
(ip.geoip.country ne "TR")
and starts_with(http.request.uri.path, "/app")
```

## 6) Cloudflare ayarları (küçük ama etkili)

- **Always Use HTTPS**: Aç
- **HSTS**: Aç (preload için dikkat: geri dönüşü zor)
- **Minimum TLS Version**: 1.2 (mümkünse 1.3)
- **Cache**: `/public/*` için cache, diğerleri no-cache

