# Observability (Loki/Grafana) — hızlı kurulum

Bu klasör, “merkezi log” için sıfırdan bir başlangıç sağlar.

## 1) Logların nereye yazıldığını bil

Uygulama `DATA_DIR` altına log yazar:

- `security.log` (JSON satırlar)
- `access.log` (JSON satırlar)

Docker ile çalıştırıyorsan genellikle şu şekilde mount ediyorsun:

- host `./data` -> container `/app/data`

Bu stack, host tarafındaki `data/` klasörünü `promtail` içine `../../data` olarak bağlıyor.

## 2) Çalıştır

```
cd ops/observability
docker compose -f docker-compose.loki.yml up -d
```

Grafana: `http://localhost:3001` (admin/admin)

## 3) Grafana'da hızlı query örnekleri

- Security eventleri:
  - `{job="dokumanlarim", stream="security"}`

- Sık login denemeleri:
  - `{job="dokumanlarim", stream="security"} |= "login_failed"`

## 4) Alert fikirleri (Grafana UI'dan)

- 5 dakikada `account_locked` > 3
- 1 dakikada `csrf_fail` > 20
- 10 dakikada `mfa_failed` > 10

(Prod'da eşikler tenant bazlı değişebilir.)
