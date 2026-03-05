# Yapılan Düzeltmeler

## Düzeltilen ana hata
- Vendor portalı (`/v/:token`) açılırken 500 hatası veriyordu.
- Neden: `views/vendor.ejs` içinde kullanılan `uploadAccept` ve `uploadAllowedExtCsv` değişkenleri partial render helper tarafından geçilmiyordu.
- Çözüm: `server.js` içindeki `render()` helper'ına bu ortak view değişkenleri eklendi.

## Ek sağlamlaştırma
- Hata sayfası render edilirken `tenant` / `plan` eksik olduğunda ikinci bir render hatası oluşabiliyordu.
- Çözüm:
  - error handler içinde `tenant: null` ve `plan: null` verildi.
  - `views/layout.ejs` içindeki `tenant`, `plan`, `user`, `flash` kontrolleri daha dayanıklı hale getirildi.

## Doğrulanan akış
- signup
- login
- yeni talep oluşturma
- talep detay sayfası
- vendor linkinin açılması
- vendor tarafından PDF yükleme
- vendor tarafından gönderme
- eksik CSRF ile hata sayfasının düzgün render edilmesi
