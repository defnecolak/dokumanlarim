
function builtinTemplates() {
  // Built-ins are read-only templates shipped with the app.
  // Docs schema:
  // { label, required, requireSignature, issueDateRequired, expiryRequired, expiryWarnDays }
  return [
    {
      id: 'builtin_yazilim',
      name: 'Yazılım / SaaS Tedarikçisi',
      industry: 'Yazılım',
      builtin: true,
      docs: [
        { label: 'Ticaret Sicil Gazetesi', required: true },
        { label: 'Vergi Levhası', required: true, issueDateRequired: true },
        { label: 'İmza Sirküleri', required: true },
        { label: 'IBAN / Banka Bilgisi', required: true },
        { label: 'KVKK Taahhütnamesi (İmzalı)', required: true, requireSignature: true },
        { label: 'Gizlilik Sözleşmesi (NDA) (İmzalı)', required: false, requireSignature: true },
        { label: 'ISO 27001 Sertifikası (varsa)', required: false, expiryRequired: true, expiryWarnDays: 30 },
      ],
    },
    {
      id: 'builtin_lojistik',
      name: 'Lojistik / Taşımacılık',
      industry: 'Lojistik',
      builtin: true,
      docs: [
        { label: 'Ticaret Sicil Gazetesi', required: true },
        { label: 'Vergi Levhası', required: true, issueDateRequired: true },
        { label: 'İmza Sirküleri', required: true },
        { label: 'K Yetki Belgesi (K1/K2)', required: true, expiryRequired: true, expiryWarnDays: 30 },
        { label: 'Trafik Sigortası Poliçesi', required: true, expiryRequired: true, expiryWarnDays: 15 },
        { label: 'Araç Listesi / Ruhsatlar', required: false },
        { label: 'KVKK Taahhütnamesi (İmzalı)', required: false, requireSignature: true },
      ],
    },
    {
      id: 'builtin_insaat',
      name: 'İnşaat Alt Yüklenici',
      industry: 'İnşaat',
      builtin: true,
      docs: [
        { label: 'Ticaret Sicil Gazetesi', required: true },
        { label: 'Vergi Levhası', required: true, issueDateRequired: true },
        { label: 'İmza Sirküleri', required: true },
        { label: 'SGK Borcu Yoktur', required: true, issueDateRequired: true, expiryRequired: true, expiryWarnDays: 7 },
        { label: 'Vergi Borcu Yoktur', required: true, issueDateRequired: true, expiryRequired: true, expiryWarnDays: 7 },
        { label: 'İş Deneyim / İş Bitirme Belgesi', required: false },
        { label: 'İSG Belgeleri (varsa)', required: false, expiryRequired: true, expiryWarnDays: 30 },
      ],
    },
    {
      id: 'builtin_danismanlik',
      name: 'Danışmanlık / Hizmet',
      industry: 'Hizmet',
      builtin: true,
      docs: [
        { label: 'Ticaret Sicil Gazetesi', required: true },
        { label: 'Vergi Levhası', required: true, issueDateRequired: true },
        { label: 'İmza Sirküleri', required: true },
        { label: 'Hizmet Sözleşmesi (İmzalı)', required: true, requireSignature: true },
        { label: 'KVKK Taahhütnamesi (İmzalı)', required: true, requireSignature: true },
        { label: 'Referans Listesi', required: false },
      ],
    },
    {
      id: 'builtin_gida',
      name: 'Gıda / Catering',
      industry: 'Gıda',
      builtin: true,
      docs: [
        { label: 'Ticaret Sicil Gazetesi', required: true },
        { label: 'Vergi Levhası', required: true, issueDateRequired: true },
        { label: 'İmza Sirküleri', required: true },
        { label: 'İşletme Kayıt Belgesi', required: true, expiryRequired: true, expiryWarnDays: 30 },
        { label: 'Hijyen Sertifikası', required: false, expiryRequired: true, expiryWarnDays: 30 },
        { label: 'Ürün / Menü Listesi', required: false },
      ],
    },
    {
      id: 'builtin_temizlik_guvenlik',
      name: 'Temizlik / Güvenlik Hizmeti',
      industry: 'Hizmet',
      builtin: true,
      docs: [
        { label: 'Ticaret Sicil Gazetesi', required: true },
        { label: 'Vergi Levhası', required: true, issueDateRequired: true },
        { label: 'İmza Sirküleri', required: true },
        { label: 'SGK Borcu Yoktur', required: true, issueDateRequired: true, expiryRequired: true, expiryWarnDays: 7 },
        { label: 'Vergi Borcu Yoktur', required: true, issueDateRequired: true, expiryRequired: true, expiryWarnDays: 7 },
        { label: 'Personel Listesi', required: false },
      ],
    },
  ];
}

function normalizeDocDef(d) {
  return {
    label: String(d.label || '').trim(),
    required: !!d.required,
    requireSignature: !!d.requireSignature,
    issueDateRequired: !!d.issueDateRequired,
    expiryRequired: !!d.expiryRequired,
    expiryWarnDays: d.expiryWarnDays ? Math.max(1, Math.min(365, parseInt(d.expiryWarnDays, 10) || 30)) : (d.expiryRequired ? 30 : 0),
  };
}

function normalizeTemplate(t) {
  return {
    id: String(t.id || '').trim(),
    name: String(t.name || '').trim(),
    industry: String(t.industry || '').trim(),
    builtin: !!t.builtin,
    tenantId: t.tenantId || null,
    docs: (t.docs || []).map(normalizeDocDef).filter(x => x.label),
    createdAt: t.createdAt || null,
    updatedAt: t.updatedAt || null,
  };
}

function getTenantTemplates(db, tenantId) {
  return (db.templates || [])
    .filter(t => t.tenantId === tenantId)
    .map(normalizeTemplate);
}

function getAllTemplatesForTenant(db, tenantId) {
  const builtins = builtinTemplates().map(normalizeTemplate);
  const tenant = getTenantTemplates(db, tenantId);
  return [...builtins, ...tenant];
}

function findTemplateById(db, tenantId, templateId) {
  const id = String(templateId || '').trim();
  if (!id) return null;
  const built = builtinTemplates().find(t => t.id === id);
  if (built) return normalizeTemplate(built);
  const t = (db.templates || []).find(x => x.id === id && x.tenantId === tenantId);
  if (t) return normalizeTemplate(t);
  return null;
}

module.exports = {
  builtinTemplates,
  getTenantTemplates,
  getAllTemplatesForTenant,
  findTemplateById,
  normalizeDocDef,
  normalizeTemplate,
};
