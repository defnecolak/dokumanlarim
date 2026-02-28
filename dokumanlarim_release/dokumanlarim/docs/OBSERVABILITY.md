# Observability (Log + Alert) — Hızlı Kurulum

Dökümanlarım iki ana log üretir:

- `data/security.log` → güvenlik olayları (JSON satırlar)
- `data/access.log` → erişim logları (morgan combined)

Prod’da bunları bir “merkez”e akıtmak, saldırı/arıza tespitinde **en yüksek kaldıraç** işlerdendir.

## Seçenek A: Lokal Loki + Grafana (demo / küçük prod)

Repoda hazır bir compose var:

- `ops/observability/docker-compose.loki.yml`

Kurulum:

1) Uygulamanın `data/` klasörü kalıcı olsun (Docker’da volume).
2) `ops/observability` dizinine gir:

```bash
cd ops/observability
docker compose -f docker-compose.loki.yml up -d
```

3) Grafana: `http://localhost:3001` (admin/admin).
4) Explore → Loki → sorgu örnekleri:

- Son 15 dk güvenlik olayları:

```
{job="dokumanlarim", stream="security"}
```

- MFA hataları:

```
{job="dokumanlarim", stream="security"} | json | event="mfa_failed"
```

## Seçenek B: Grafana Cloud / Datadog / Elastic

- Logları stdout JSON veya dosya olarak üret (bu projede ikisi de var).
- Agent ile ship et (promtail/vector/fluent-bit).
- Alarm kur: `account_locked`, `csrf_failed`, `vendor_token_invalid`, `upload_rejected` gibi olayların spike ettiği durumlar.

## Minimum alarm önerisi

- **5 dakikada 10+ “account_locked”** → brute-force ihtimali
- **5 dakikada 20+ “csrf_failed”** → bot/otomasyon
- **upload_rejected** artışı → dosya bazlı saldırı denemesi
- **mfa_failed** artışı → credential stuffing
