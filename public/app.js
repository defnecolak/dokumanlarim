function copyText(id){
  const el = document.getElementById(id);
  if(!el) return;
  const txt = el.value || el.textContent || '';
  navigator.clipboard.writeText(txt).then(()=>{
    toast('Kopyalandı');
  }).catch(()=>{});
}
function toast(msg){
  const t = document.createElement('div');
  t.className = 'flash ok';
  t.style.position='fixed'; t.style.bottom='20px'; t.style.left='50%'; t.style.transform='translateX(-50%)';
  t.style.zIndex='9999'; t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(()=>t.remove(), 1800);
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
  if (!el.classList.contains('fileInput')) return;
  const id = el.id;
  const hasFile = !!(el.files && el.files.length);
  const ind = document.querySelector(`.fileChosen[data-for="${id}"]`);
  if (ind) {
    ind.textContent = hasFile ? '✓' : '';
    ind.classList.toggle('ok', hasFile);
  }
});
