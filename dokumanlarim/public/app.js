document.documentElement.classList.add("js");
async function copyToClipboard(txt) {
  // Modern API
  try {
    await navigator.clipboard.writeText(txt);
    return true;
  } catch (e) {
    // ignore
  }

  // Fallback
  try {
    const ta = document.createElement('textarea');
    ta.value = txt;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    ta.style.left = '-1000px';
    document.body.appendChild(ta);
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    const ok = document.execCommand('copy');
    document.body.removeChild(ta);
    return !!ok;
  } catch (e) {
    return false;
  }
}

function copyText(id){
  const el = document.getElementById(id);
  if(!el) return;
  const txt = el.value || el.textContent || '';
  copyToClipboard(txt).then((ok)=>{
    toast(ok ? 'Kopyalandı' : 'Kopyalanamadı');
  });
}
function toast(msg){
  const t = document.createElement('div');
  t.className = 'flash ok';
  t.style.position='fixed'; t.style.bottom='20px'; t.style.left='50%'; t.style.transform='translateX(-50%)';
  t.style.zIndex='9999'; t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 1800);
}


// Auto-upload: dosya seçince otomatik gönder (vendor ekranı)
// - required tarih alanları boşsa göndermez.
// - invalid format seçilirse upload denemez.
async function maybeAutoUpload(form, fileInput) {
  if (!form || form.dataset.submitting === '1') return;
  if (!fileInput || !(fileInput instanceof HTMLInputElement)) return;
  if (!fileInput.files || !fileInput.files.length) return;

  // required meta alanları dolu mu?
  const requiredMeta = Array.from(form.querySelectorAll('input[required]')).filter((el) => el !== fileInput);
  const missing = requiredMeta.find((el) => !el.value);

  const id = fileInput.id;
  const ind = id ? document.querySelector(`.fileChosen[data-for="${id}"]`) : null;

  if (missing) {
    const label = (missing.previousElementSibling && missing.previousElementSibling.tagName === 'LABEL')
      ? missing.previousElementSibling.textContent.trim()
      : 'Gerekli alan';
    if (ind) ind.textContent = `${label} gerekli`;
    missing.focus();
    return;
  }

  // Frontend dosya tipi kontrolü (backend yine de kontrol ediyor)
  const allowedCsv = (fileInput.dataset.allowedExt || '').trim();
  if (allowedCsv) {
    const allowed = allowedCsv.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
    const fileName = (fileInput.files[0] && fileInput.files[0].name) ? String(fileInput.files[0].name) : '';
    const ext = fileName.includes('.') ? ('.' + fileName.split('.').pop()).toLowerCase() : '';
    if (allowed.length && ext && !allowed.includes(ext)) {
      const msg = `Geçersiz dosya türü: ${ext}. İzin verilenler: ${allowed.join(' ')}`;
      if (ind) ind.textContent = 'Geçersiz format';
      toast(msg);
      fileInput.value = '';
      return;
    }
  }

  form.dataset.submitting = '1';
  if (ind) ind.textContent = 'Yükleniyor…';

  try {
    const fd = new FormData(form);
    const resp = await fetch(form.action, {
      method: (form.method || 'POST').toUpperCase(),
      body: fd,
      credentials: 'same-origin',
      headers: {
        'Accept': 'application/json',
      },
    });

    const data = await resp.json().catch(() => null);

    if (resp.ok && data && data.ok) {
      if (ind) ind.textContent = '✓';
      toast('Yüklendi');
      // Sayfayı yenile: durum/eksik sayacı güncellensin.
      window.location.reload();
      return;
    }

    const errMsg = (data && data.error) ? String(data.error) : 'Yükleme başarısız.';
    if (ind) ind.textContent = 'Hata';
    toast(errMsg);
    fileInput.value = '';
  } catch (err) {
    if (ind) ind.textContent = 'Hata';
    toast('Yükleme sırasında bağlantı hatası.');
    fileInput.value = '';
  } finally {
    form.dataset.submitting = '0';
  }
}

// CSP-friendly UI helpers (no inline onclick/onsubmit)
document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-copy]');
  if (!btn) return;
  e.preventDefault();
  const id = btn.getAttribute('data-copy');
  if (id) copyText(id);
});

document.addEventListener('submit', (e) => {
  const form = e.target;
  if (!(form instanceof HTMLFormElement)) return;
  const msg = form.getAttribute('data-confirm');
  if (!msg) return;
  if (!confirm(msg)) e.preventDefault();
}, true);

// Vendor upload: hide native "No file chosen" text by using a hidden input + label button.
// Add a small ✓ indicator when a file is selected.
document.addEventListener('change', (e) => {
  const el = e.target;
  if (!(el instanceof HTMLInputElement)) return;

  // 1) Dosya seçimi: ✓ göster + otomatik upload
  if (el.classList.contains('fileInput')) {
    const id = el.id;
    const hasFile = !!(el.files && el.files.length);
    const ind = document.querySelector(`.fileChosen[data-for="${id}"]`);
    if (ind) {
      ind.textContent = hasFile ? '✓' : '';
      ind.classList.toggle('ok', hasFile);
    }

    const form = el.closest('form');
    if (hasFile && form && form.getAttribute('data-auto-upload') === '1') {
      maybeAutoUpload(form, el);
    }
    return;
  }

  // 2) Tarih alanı: dosya zaten seçiliyse otomatik upload
  if (el.type === 'date') {
    const form = el.closest('form');
    if (!form || form.getAttribute('data-auto-upload') !== '1') return;
    const fileInput = form.querySelector('input[type="file"].fileInput');
    if (fileInput && fileInput.files && fileInput.files.length) {
      maybeAutoUpload(form, fileInput);
    }
  }
});
